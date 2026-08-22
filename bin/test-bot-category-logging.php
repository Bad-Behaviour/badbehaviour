<?php
/**
 * bin/test-bot-category-logging.php
 *
 * Regression test for the bug where bot_category and bot_verified columns
 * were empty in the bad_behaviour log table because Result::allow() did
 * not accept metadata, causing BotDetector to silently drop the
 * identification info for verified bots.
 *
 * === WHAT THIS TESTS ===
 *
 *   1. Result::allow() accepts metadata
 *   2. BotDetector populates bot_category + bot_verified on ALLOW
 *   3. BotDetector populates bot_category + bot_verified on LOG_ONLY
 *   4. BotDetector populates bot_category + bot_verified on BLOCK
 *   5. BotDetector populates bot_category + bot_verified on CHALLENGE
 *   6. Cloud-infrastructure fast path carries bot_category metadata
 *   7. Cached results preserve metadata (rebuild_result fix)
 *   8. monitored_from() preserves metadata through demotion
 *   9. Adapter actually writes both fields into the log SQL
 *
 * === USAGE ===
 *
 *   php bin/test-bot-category-logging.php
 *
 * Adapter selection via env var:
 *   BB_ADAPTER=wacko     (default)
 *   BB_ADAPTER=mediawiki
 *   BB_ADAPTER=generic
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — one or more checks failed
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Adapter\MediaWikiAdapter;
use BadBehaviour\Adapter\WackoWikiAdapter;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Util\ErrorReporter;

$tests_passed = 0;
$tests_failed = 0;
$check_num = 0;

function check(bool $cond, string $msg, int &$passed, int &$failed): void
{
    global $check_num;
    $check_num++;
    if ($cond) {
        $passed++;
        echo "  ✓ $msg\n";
        return;
    }
    $failed++;
    echo "  ✗ FAIL: $msg\n";
}

function header_line(string $s): void
{
    echo "\n=== $s ===\n";
}

if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', sys_get_temp_dir() . '/badbehaviour_test_cache');
}

// =============================================================================
// Adapter construction helpers
// =============================================================================

/**
 * Build a stub DB object compatible with WackoWikiAdapter.
 * The stub captures every ll_query() call so we can inspect the SQL.
 */
function make_wacko_db(): object
{
    return new class {
        public string $table_prefix = 'wacko_';
        public string $abuse_email = 'admin@example.com';
        public array $queries = [];

        public function q(string $value): string
        {
            return "'" . addslashes($value) . "'";
        }

        public function ll_query(string $sql)
        {
            $this->queries[] = $sql;
            return true;
        }

        public function is_sqlite(): bool
        {
            return false;
        }
    };
}

/**
 * Build a stub DB object compatible with MediaWikiAdapter.
 */
function make_mediawiki_db(): object
{
    return new class {
        public function tableName(string $name): string
        {
            return $name;
        }

        public function insert(string $table, array $rows, string $fname): bool
        {
            return true;
        }

        public function query(string $sql): bool
        {
            return true;
        }
    };
}

/**
 * Build the adapter selected via env var. Uses an intermediate variable
 * so PHP's strict return-type checker accepts the union of match arms.
 */
function build_adapter(string $which): AdapterInterface
{
    $adapter = match ($which) {
        'generic'   => new GenericAdapter(),
        'wacko'     => new WackoWikiAdapter(make_wacko_db()),
        'mediawiki' => new MediaWikiAdapter(make_mediawiki_db(), '', 'admin@example.com', '/'),
        default     => throw new \InvalidArgumentException("Unknown adapter: {$which}"),
    };
    return $adapter;
}

/**
 * Pull the underlying stub DB off a WackoWikiAdapter so we can inspect
 * the queries it executed during the test.
 *
 * Returns null for non-Wacko adapters.
 */
function get_wacko_db_queries(AdapterInterface $adapter): ?array
{
    $ref = new \ReflectionClass($adapter);
    if (!$ref->hasProperty('db')) {
        return null;
    }
    $db_prop = $ref->getProperty('db');
    $db_prop->setAccessible(true);
    $db = $db_prop->getValue($adapter);
    if (!is_object($db) || !property_exists($db, 'queries')) {
        return null;
    }
    return $db->queries;
}

$adapter_choice = strtolower(getenv('BB_ADAPTER') ?: 'wacko');
echo "Using adapter: {$adapter_choice}\n";
echo "(override with: BB_ADAPTER=wacko|mediawiki|generic php {$argv[0]})\n";

try {
    $adapter = build_adapter($adapter_choice);
} catch (\Throwable $e) {
    fwrite(STDERR, "FATAL: failed to build adapter: {$e->getMessage()}\n");
    exit(1);
}

ErrorReporter::reset();

// =============================================================================
// Build configuration in 'normal' strictness with verbose=true so ALLOWED
// results get logged (this is the evaluation-mode scenario).
// =============================================================================

$config = Configuration::from_array([
    'preset'     => 'full',
    'strictness' => 'normal',
    'logging'    => true,
    'verbose'    => true,
], $adapter);

$bb = new BadBehaviour($config);

// =============================================================================
// Test 1: Result::allow() accepts metadata
// =============================================================================
header_line('Test 1: Result::allow() accepts metadata');

$package = RequestPackage::create_for_test(
    user_agent: 'TestBrowser/1.0',
    ip: '203.0.113.1',
);

$allow_with_metadata = Result::allow($package, [
    'bot_category' => BotCategory::SEARCH_ENGINE->value,
    'bot_verified' => true,
    'bot_name'     => 'Googlebot',
]);

check(
    $allow_with_metadata->metadata['bot_category'] === 'search_engine',
    "Result::allow() preserves metadata['bot_category']",
    $tests_passed,
    $tests_failed
);

check(
    $allow_with_metadata->metadata['bot_verified'] === true,
    "Result::allow() preserves metadata['bot_verified']",
    $tests_passed,
    $tests_failed
);

check(
    $allow_with_metadata->metadata['bot_name'] === 'Googlebot',
    "Result::allow() preserves metadata['bot_name']",
    $tests_passed,
    $tests_failed
);

// Backward-compat: allow() with no metadata must still work
$allow_no_metadata = Result::allow($package);
check(
    $allow_no_metadata->code === ResultCode::ALLOWED,
    "Result::allow() with no metadata still works (backward compat)",
    $tests_passed,
    $tests_failed
);
check(
    is_array($allow_no_metadata->metadata),
    "Result::allow() with no metadata returns array (not null)",
    $tests_passed,
    $tests_failed
);

// =============================================================================
// Test 2: BotDetector populates metadata on ALLOW
// =============================================================================
header_line('Test 2: BotDetector populates metadata on ALLOW');

// Real Googlebot UA from a documented Google IP range (66.249.64.0/19)
$googlebot_package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    ip: '66.249.66.1',
);

$result = $bb->run_test_package($googlebot_package);

echo "  Result code: {$result->code->value}\n";
echo "  Metadata: " . json_encode($result->metadata) . "\n";

check(
    $result->code === ResultCode::ALLOWED,
    "verified Googlebot produces ALLOWED result",
    $tests_passed,
    $tests_failed
);

check(
    ($result->metadata['bot_category'] ?? null) === 'search_engine',
    "ALLOWED result carries metadata.bot_category = 'search_engine'",
    $tests_passed,
    $tests_failed
);

check(
    ($result->metadata['bot_verified'] ?? null) === true,
    "ALLOWED result carries metadata.bot_verified = true",
    $tests_passed,
    $tests_failed
);

check(
    ($result->metadata['bot_name'] ?? null) === 'Googlebot',
    "ALLOWED result carries metadata.bot_name = 'Googlebot'",
    $tests_passed,
    $tests_failed
);

check(
    ($result->metadata['bot_id'] ?? null) === 'googlebot',
    "ALLOWED result carries metadata.bot_id = 'googlebot'",
    $tests_passed,
    $tests_failed
);

// =============================================================================
// Test 3: BotDetector populates metadata on LOG_ONLY
// =============================================================================
header_line('Test 3: BotDetector populates metadata on LOG_ONLY');

// Security scanners default to LOG_ONLY. Use a Shodan UA with a fake IP.
$shodan_package = RequestPackage::create_for_test(
    user_agent: 'Shodan (https://www.shodan.io/)',
    ip: '198.51.100.42',
);

$result = $bb->run_test_package($shodan_package);

echo "  Result code: {$result->code->value}\n";
echo "  Metadata: " . json_encode($result->metadata) . "\n";

// LOG_ONLY in BotDetector produces Result::allow() with metadata.
// It must NOT fall through to BlacklistDetector (which would produce
// blocked.malicious_ua for unknown UA-only matches).
check(
    $result->code === ResultCode::ALLOWED,
    "Shodan (LOG_ONLY) produces ALLOWED result (got: {$result->code->value})",
    $tests_passed,
    $tests_failed
);

if ($result->code === ResultCode::ALLOWED) {
    check(
        ($result->metadata['bot_category'] ?? null) === 'security_scanner',
        "LOG_ONLY result carries metadata.bot_category = 'security_scanner'",
        $tests_passed,
        $tests_failed
    );

    check(
        array_key_exists('bot_verified', $result->metadata),
        "LOG_ONLY result carries metadata.bot_verified key",
        $tests_passed,
        $tests_failed
    );

    check(
        ($result->metadata['bot_name'] ?? null) === 'Shodan (Internet Scanner)',
        "LOG_ONLY result carries metadata.bot_name = 'Shodan (Internet Scanner)'",
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// Test 4: BotDetector populates metadata on BLOCK
// =============================================================================
header_line('Test 4: BotDetector populates metadata on BLOCK');

// Bright Data (residential proxy, default BLOCK). Use a fake IP so
// IP-range matching fails and DNS verification fails too.
$brightdata_package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 BrightData/1.0',
    ip: '203.0.113.99',
);

$result = $bb->run_test_package($brightdata_package);

echo "  Result code: {$result->code->value}\n";
echo "  Metadata: " . json_encode($result->metadata) . "\n";

$is_block = str_starts_with($result->code->value, 'blocked.')
    || str_starts_with($result->code->value, 'monitored.');

check(
    $is_block,
    "Bright Data produces block/monitored result (got: {$result->code->value})",
    $tests_passed,
    $tests_failed
);

if ($is_block) {
    check(
        ($result->metadata['bot_category'] ?? null) === 'residential_proxy',
        "BLOCK result carries metadata.bot_category = 'residential_proxy'",
        $tests_passed,
        $tests_failed
    );

    check(
        array_key_exists('bot_verified', $result->metadata),
        "BLOCK result carries metadata.bot_verified key",
        $tests_passed,
        $tests_failed
    );

    check(
        str_contains($result->metadata['bot_name'] ?? '', 'Bright Data'),
        "BLOCK result carries metadata.bot_name containing 'Bright Data'",
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// Test 5: BotDetector populates metadata on CHALLENGE
// =============================================================================
header_line('Test 5: BotDetector populates metadata on CHALLENGE');

// GPTBot from an unverified IP → challenge (not block) by default in 'normal' strictness
$gptbot_package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)',
    ip: '203.0.113.55',
);

$result = $bb->run_test_package($gptbot_package);

echo "  Result code: {$result->code->value}\n";
echo "  Metadata: " . json_encode($result->metadata) . "\n";

$is_challenge = $result->code === ResultCode::CHALLENGE_REQUIRED
    || $result->code === ResultCode::MONITORED_CHALLENGE;

check(
    $is_challenge,
    "GPTBot from unverified IP produces CHALLENGE (got: {$result->code->value})",
    $tests_passed,
    $tests_failed
);

if ($is_challenge) {
    check(
        ($result->metadata['bot_category'] ?? null) === 'ai_crawler',
        "CHALLENGE result carries metadata.bot_category = 'ai_crawler'",
        $tests_passed,
        $tests_failed
    );

    check(
        array_key_exists('bot_verified', $result->metadata),
        "CHALLENGE result carries metadata.bot_verified key",
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// Test 6: Cloud-infrastructure fast path carries metadata
// =============================================================================
header_line('Test 6: Cloud-infrastructure fast path carries metadata');

$cloudflare_probe = RequestPackage::create_for_test(
    user_agent: 'Cloudflare-Healthcheck/1.0',
    ip: '198.41.128.1',
);

$result = $bb->run_test_package($cloudflare_probe);

echo "  Result code: {$result->code->value}\n";
echo "  Metadata: " . json_encode($result->metadata) . "\n";

check(
    ($result->metadata['bot_category'] ?? null) === 'cloud_infrastructure',
    "Cloud Infrastructure UA produces metadata.bot_category = 'cloud_infrastructure'",
    $tests_passed,
    $tests_failed
);

check(
    ($result->metadata['bot_verified'] ?? null) === true,
    "Cloud Infrastructure match produces metadata.bot_verified = true",
    $tests_passed,
    $tests_failed
);

// =============================================================================
// Test 7: Cached results preserve metadata (rebuild_result)
// =============================================================================
header_line('Test 7: Cached results preserve metadata');

// First call — populate cache
$first = $bb->run_test_package($googlebot_package);
$first_metadata = $first->metadata;

// Second call — should hit the in-process result_cache
$second = $bb->run_test_package($googlebot_package);

check(
    $second->code === ResultCode::ALLOWED,
    "cached Googlebot result is ALLOWED",
    $tests_passed,
    $tests_failed
);

check(
    ($second->metadata['bot_category'] ?? null) === ($first_metadata['bot_category'] ?? null),
    "cached result preserves bot_category (first: '" . ($first_metadata['bot_category'] ?? '(null)')
    . "', second: '" . ($second->metadata['bot_category'] ?? '(null)') . "')",
    $tests_passed,
    $tests_failed
);

check(
    ($second->metadata['bot_verified'] ?? null) === ($first_metadata['bot_verified'] ?? null),
    "cached result preserves bot_verified (first: "
    . var_export($first_metadata['bot_verified'] ?? null, true)
    . ", second: " . var_export($second->metadata['bot_verified'] ?? null, true) . ")",
    $tests_passed,
    $tests_failed
);

// =============================================================================
// Test 8: monitored_from() preserves metadata through demotion
// =============================================================================
header_line('Test 8: monitored_from() preserves metadata through demotion');

// monitor-only mode forces demotion. Build a fresh BB in that mode.
$monitor_adapter = build_adapter($adapter_choice);
$monitor_config = Configuration::from_array([
    'preset'     => 'full',
    'strictness' => 'monitor-only',
    'logging'    => true,
    'verbose'    => true,
], $monitor_adapter);

$monitor_bb = new BadBehaviour($monitor_config);

// GPTBot in monitor-only → detection runs, but challenge is demoted to monitored
$gptbot_monitor = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)',
    ip: '203.0.113.55',
);

$monitor_result = $monitor_bb->run_test_package($gptbot_monitor);

echo "  Result code: {$monitor_result->code->value}\n";
echo "  Metadata: " . json_encode($monitor_result->metadata) . "\n";

check(
    str_starts_with($monitor_result->code->value, 'monitored.'),
    "monitor-only mode demotes challenge to monitored.* (got: {$monitor_result->code->value})",
    $tests_passed,
    $tests_failed
);

check(
    ($monitor_result->metadata['bot_category'] ?? null) === 'ai_crawler',
    "monitored result STILL carries metadata.bot_category",
    $tests_passed,
    $tests_failed
);

check(
    array_key_exists('bot_verified', $monitor_result->metadata),
    "monitored result STILL carries metadata.bot_verified",
    $tests_passed,
    $tests_failed
);

check(
    ($monitor_result->metadata['monitor_only'] ?? null) === true,
    "monitored result carries metadata.monitor_only = true",
    $tests_passed,
    $tests_failed
);

check(
    ($monitor_result->metadata['original_code'] ?? null) !== null,
    "monitored result carries metadata.original_code",
    $tests_passed,
    $tests_failed
);

// =============================================================================
// Test 9: Adapter actually writes both fields into the log SQL
// =============================================================================
header_line('Test 9: Adapter writes bot_category and bot_verified to log SQL');

// Build a fresh adapter with its own stub DB so we can inspect queries.
$log_adapter = build_adapter($adapter_choice);
$queries_before = get_wacko_db_queries($log_adapter) ?? [];

$log_config = Configuration::from_array([
    'preset'     => 'full',
    'strictness' => 'normal',
    'logging'    => true,
    'verbose'    => true,
], $log_adapter);

$log_bb = new BadBehaviour($log_config);
$log_bb->run_test_package($googlebot_package);
$log_bb->run_test_package($shodan_package);
$log_bb->run_test_package($brightdata_package);

$queries_after = get_wacko_db_queries($log_adapter) ?? [];
$new_queries = array_slice($queries_after, count($queries_before));

echo "  Adapter executed " . count($new_queries) . " SQL statements during test\n";

if ($adapter_choice === 'wacko') {
    // For Wacko: log_request() runs ll_query() with INSERT INTO
    $inserts = array_values(array_filter(
        $new_queries,
        fn($q) => stripos($q, 'INSERT INTO') !== false
    ));

    echo "  Captured " . count($inserts) . " INSERT statements\n";

    check(
        count($inserts) >= 3,
        "WackoAdapter executed at least 3 INSERTs (3 packages + verbose=true → ALLOWED logged)",
        $tests_passed,
        $tests_failed
    );

    if (count($inserts) > 0) {
        echo "  Sample INSERT: " . substr($inserts[0], 0, 400) . "...\n";

        // The column list must include bot_category and bot_verified
        check(
            str_contains($inserts[0], '`bot_category`'),
            "INSERT column list includes `bot_category`",
            $tests_passed,
            $tests_failed
        );

        check(
            str_contains($inserts[0], '`bot_verified`'),
            "INSERT column list includes `bot_verified`",
            $tests_passed,
            $tests_failed
        );

        // Googlebot row must contain 'search_engine'
        $has_googlebot_value = false;
        $has_googlebot_verified_1 = false;
        foreach ($inserts as $sql) {
            if (str_contains($sql, "'search_engine'")) {
                $has_googlebot_value = true;
                // For verified bot, bot_verified column should be 1
                // The exact position depends on column order; look for
                // any ",1," or ",1)" near 'search_engine'.
                $pos = strpos($sql, "'search_engine'");
                if ($pos !== false) {
                    $tail = substr($sql, $pos, 200);
                    // The bot_verified column immediately follows bot_category
                    // in the WackoAdapter INSERT; look for ",1," after the value.
                    if (preg_match("/'search_engine',1[,)]/", $tail)) {
                        $has_googlebot_verified_1 = true;
                    }
                }
            }
        }

        check(
            $has_googlebot_value,
            "at least one INSERT contains 'search_engine' (Googlebot row populated)",
            $tests_passed,
            $tests_failed
        );

        check(
            $has_googlebot_verified_1,
            "Googlebot INSERT contains bot_verified=1 immediately after 'search_engine'",
            $tests_passed,
            $tests_failed
        );

        // Shodan row must contain 'security_scanner'
        $has_shodan_value = false;
        foreach ($inserts as $sql) {
            if (str_contains($sql, "'security_scanner'")) {
                $has_shodan_value = true;
                break;
            }
        }

        check(
            $has_shodan_value,
            "at least one INSERT contains 'security_scanner' (Shodan row populated)",
            $tests_passed,
            $tests_failed
        );

        // Bright Data row must contain 'residential_proxy'
        $has_brightdata_value = false;
        foreach ($inserts as $sql) {
            if (str_contains($sql, "'residential_proxy'")) {
                $has_brightdata_value = true;
                break;
            }
        }

        check(
            $has_brightdata_value,
            "at least one INSERT contains 'residential_proxy' (Bright Data row populated)",
            $tests_passed,
            $tests_failed
        );
    }
} else {
    // GenericAdapter doesn't persist; MediaWiki stub doesn't capture
    // INSERTs by default. Just confirm log_request() was reachable.
    echo "  (SQL inspection skipped — {$adapter_choice} adapter doesn't expose query capture)\n";
    echo "  Test 9 reduced to: log_request() was called without throwing\n";
    check(
        true,
        "log_request() invocations completed without error",
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// Summary
// =============================================================================
echo "\n=== Summary ===\n";
echo "  Total checks: {$check_num}\n";
echo "  Passed:       {$tests_passed}\n";
echo "  Failed:       {$tests_failed}\n";

if ($tests_failed > 0) {
    echo "\n✗ {$tests_failed} check(s) FAILED.\n";
    echo "\nThe bot_category / bot_verified metadata wiring is broken.\n";
    echo "Re-apply the fix:\n";
    echo "  1. src/Core/Result.php — Result::allow(?RequestPackage \\$package, array \\$metadata = [])\n";
    echo "  2. src/Detection/BotDetector.php — build \\$bot_metadata, pass to every match branch\n";
    echo "  3. src/Detection/BotDetector.php — rebuild_result() preserves metadata\n";
    echo "\nDiagnostic query to run after fixing:\n";
    echo "  SELECT bot_category, bot_verified, COUNT(*) AS hits\n";
    echo "  FROM bad_behaviour\n";
    echo "  WHERE status_code = 'allowed'\n";
    echo "    AND bot_category IS NOT NULL AND bot_category <> ''\n";
    echo "  GROUP BY bot_category, bot_verified\n";
    echo "  ORDER BY hits DESC;\n";
    exit(1);
}

echo "\n✓ All metadata-wiring checks passed.\n";
echo "\nYour log table should now show non-empty bot_category and bot_verified.\n";
exit(0);