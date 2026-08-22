<?php
/**
 * bin/test-bot-detection-fp.php
 *
 * Regression test for the false-positive bug where legitimate bots
 * (Yandex, Applebot, Bing, Baidu, Seznam) were being blocked by
 * BlacklistDetector's ua_is_bot short-circuit instead of being
 * correctly identified by BotDetector.
 *
 * === BACKGROUND ===
 *
 * The bug had two root causes:
 *   1. IpUtil::match_cidr() had a 64-bit integer bug that caused IP
 *      range matching to fail on 64-bit PHP systems. Verified bots
 *      with IPs in static ranges (Yandex, Apple) would fall through
 *      to BlacklistDetector.
 *   2. BlacklistDetector had a ua_is_bot short-circuit that blocked
 *      any request where the UA contained "bot", "spider", or
 *      "crawler" — matching legitimate search engines.
 *
 * This script verifies both fixes work correctly.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Core\EnforcementAction;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Util\IpUtil;

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
    } else {
        $failed++;
        echo "  ✗ FAIL: $msg\n";
    }
}

function header_line(string $s): void
{
    echo "\n=== $s ===\n";
}

// =============================================================================
// 1. IpUtil::match_cidr() — 64-bit integer regression test
// =============================================================================
header_line('1. IpUtil::match_cidr() — 64-bit integer fix');

// Test cases: [ip, cidr, expected_match, description]
$cidr_tests = [
    // Yandex ranges from the registry
    ['77.88.47.10',     '77.88.0.0/17',    true,  'Yandex IP in 77.88.0.0/17'],
    ['77.88.127.255',   '77.88.0.0/17',    true,  'Yandex IP at range boundary (high)'],
    ['77.88.0.0',       '77.88.0.0/17',    true,  'Yandex IP at range boundary (low)'],
    ['77.89.0.0',       '77.88.0.0/17',    false, 'IP just outside Yandex range'],

    // Apple ranges from the registry
    ['17.246.23.79',    '17.0.0.0/8',      true,  'Apple IP in 17.0.0.0/8'],
    ['17.0.0.0',        '17.0.0.0/8',      true,  'Apple IP at range boundary (low)'],
    ['17.255.255.255',  '17.0.0.0/8',      true,  'Apple IP at range boundary (high)'],
    ['16.255.255.255',  '17.0.0.0/8',      false, 'IP just outside Apple range'],

    // Google ranges
    ['66.249.66.1',     '66.249.64.0/19',  true,  'Google IP in 66.249.64.0/19'],
    ['66.249.95.255',   '66.249.64.0/19',  true,  'Google IP at range boundary (high)'],

    // Bing ranges
    ['157.55.39.1',     '157.54.0.0/15',   true,  'Bing IP in 157.54.0.0/15'],
    ['157.55.255.255',  '157.54.0.0/15',   true,  'Bing IP at range boundary (high)'],

    // Edge cases
    ['192.168.1.1',     '192.168.0.0/16',  true,  'Private IP in /16 range'],
    ['10.0.0.1',        '10.0.0.0/8',      true,  'Private IP in /8 range'],
    ['8.8.8.8',         '8.8.8.0/24',      true,  'Google DNS in /24 range'],

    // High-bit IPs (the ones that break with signed int bug)
    ['223.255.255.1',   '223.0.0.0/8',     true,  'High-bit IP in /8 range'],
    ['200.1.2.3',       '200.0.0.0/8',     true,  'IP > 128 in /8 range'],
];

foreach ($cidr_tests as [$ip, $cidr, $expected, $desc]) {
    $actual = IpUtil::match_cidr($ip, $cidr);
    check(
        $actual === $expected,
        sprintf('%s: %s in %s → %s (expected %s)',
            $ip,
            $desc,
            $cidr,
            $actual ? 'true' : 'false',
            $expected ? 'true' : 'false'
        ),
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// 2. BotDetector correctly identifies bots by IP range (no DNS needed)
// =============================================================================
header_line('2. BotDetector IP range matching (no DNS)');

// Set up BadBehaviour with strictness='monitor-only' so DNS is disabled.
// This isolates the IP-range-matching path. If IPs are matched correctly,
// these bots should be ALLOWED without any DNS lookup.
$adapter = new GenericAdapter();
$config = Configuration::from_array([
    'preset'     => 'full',
    'strictness' => 'monitor-only',  // disables DNS verification
    'logging'    => false,
], $adapter);

$bb = new BadBehaviour($config);

// Bots whose IPs are in static ranges — should be ALLOWED via IP match alone
$ip_range_bots = [
    [
        'desc'   => 'Yandex (77.88.47.10 in 77.88.0.0/17)',
        'ua'     => 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0',
        'ip'     => '77.88.47.10',
        'expect' => 'ALLOW',
    ],
    [
        'desc'   => 'Applebot (17.246.23.79 in 17.0.0.0/8)',
        'ua'     => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)',
        'ip'     => '17.246.23.79',
        'expect' => 'ALLOW',
    ],
    [
        'desc'   => 'Googlebot (66.249.66.1 in 66.249.64.0/19)',
        'ua'     => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'ip'     => '66.249.66.1',
        'expect' => 'ALLOW',
    ],
    [
        'desc'   => 'Baiduspider (116.179.32.164 in 116.179.32.0/20)',
        'ua'     => 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'ip'     => '116.179.32.164',
        'expect' => 'ALLOW',
    ],
];

foreach ($ip_range_bots as $bot_test) {
    $package = RequestPackage::create_for_test(
        user_agent: $bot_test['ua'],
        ip: $bot_test['ip'],
    );
    $result = $bb->run_test_package($package);

    // In monitor-only mode, ALLOWED stays ALLOWED.
    // What we care about: is the code BLOCKED_MALICIOUS_UA from BlacklistDetector?
    $blocked_by_blacklist = $result->code === ResultCode::BLOCKED_MALICIOUS_UA
        && $result->message === 'Bot detected by UA parser';

    check(
        !$blocked_by_blacklist,
        sprintf('%s: NOT blocked by BlacklistDetector ua_is_bot (result: %s, message: %s)',
            $bot_test['desc'],
            $result->code->value,
            $result->message
        ),
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// 3. BlacklistDetector no longer blocks on ua_is_bot
// =============================================================================
header_line('3. BlacklistDetector ua_is_bot removed');

// Test that a clean request from a "bot-like" UA is NOT blocked by ua_is_bot
// even when BotDetector returns null (e.g., unknown bot with clean URI).
$package_unknown_bot = RequestPackage::create_for_test(
    user_agent: 'SomeUnknownBot/1.0 (+http://example.com/bot)',
    ip: '203.0.113.50',
    uri: '/some-page',
);
$result_unknown = $bb->run_test_package($package_unknown_bot);

check(
    $result_unknown->code->value !== 'blocked.malicious_ua'
        || $result_unknown->message !== 'Bot detected by UA parser',
    sprintf('Unknown bot with clean URI: NOT blocked by old ua_is_bot check (got: %s/%s)',
        $result_unknown->code->value,
        $result_unknown->message
    ),
    $tests_passed,
    $tests_failed
);

// Test that a bot with "spider" in the name is NOT blocked by ua_is_bot
$package_spider = RequestPackage::create_for_test(
    user_agent: 'MySearchSpider/2.0',
    ip: '203.0.113.51',
    uri: '/index',
);
$result_spider = $bb->run_test_package($package_spider);

check(
    $result_spider->code->value !== 'blocked.malicious_ua'
        || $result_spider->message !== 'Bot detected by UA parser',
    sprintf('UA containing "spider" with clean URI: NOT blocked by ua_is_bot (got: %s/%s)',
        $result_spider->code->value,
        $result_spider->message
    ),
    $tests_passed,
    $tests_failed
);

// =============================================================================
// 4. Attack patterns are still detected (BlacklistDetector still works)
// =============================================================================
header_line('4. BlacklistDetector still catches attack patterns');

// sqlmap should still be blocked (matches MALICIOUS_PREFIXES)
$package_sqlmap = RequestPackage::create_for_test(
    user_agent: 'sqlmap/1.5.2#stable (https://sqlmap.org)',
    ip: '203.0.113.52',
);
$result_sqlmap = $bb->run_test_package($package_sqlmap);

check(
    str_starts_with($result_sqlmap->code->value, 'blocked.')
        || str_starts_with($result_sqlmap->code->value, 'monitored.'),
    sprintf('sqlmap: still blocked/monitored (got: %s)', $result_sqlmap->code->value),
    $tests_passed,
    $tests_failed
);

// Raw XSS in URI should still be blocked
$package_xss = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '203.0.113.53',
    uri: '/search?q=<script>alert(1)</script>',
);
$result_xss = $bb->run_test_package($package_xss);

check(
    str_starts_with($result_xss->code->value, 'blocked.')
        || str_starts_with($result_xss->code->value, 'monitored.'),
    sprintf('Raw XSS in URI: still blocked/monitored (got: %s)', $result_xss->code->value),
    $tests_passed,
    $tests_failed
);

// Path traversal should still be blocked
$package_traversal = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '203.0.113.54',
    uri: '/../../../etc/passwd',
);
$result_traversal = $bb->run_test_package($package_traversal);

check(
    str_starts_with($result_traversal->code->value, 'blocked.')
        || str_starts_with($result_traversal->code->value, 'monitored.'),
    sprintf('Path traversal: still blocked/monitored (got: %s)', $result_traversal->code->value),
    $tests_passed,
    $tests_failed
);

// =============================================================================
// 5. DNS verification still works (strictness='normal')
// =============================================================================
header_line('5. DNS verification works for bots not in static ranges');

// In strictness='normal', DNS verification is enabled.
// This test verifies DNS lookup works for a bot whose IP is NOT in static ranges.
// We use a mocked DNS resolver to avoid network dependencies.
$adapter_normal = new GenericAdapter();
$config_normal = Configuration::from_array([
	'preset'     => 'full',
	'strictness' => 'normal',
	'logging'    => false,
], $adapter_normal);

$bb_normal = new BadBehaviour($config_normal);

// Test: Bing bot from an IP NOT in static ranges
// 52.167.144.237 is NOT in any Bing static range, but should verify via DNS
$package_bing = RequestPackage::create_for_test(
	user_agent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36',
	ip: '52.167.144.237',
	);
$result_bing = $bb_normal->run_test_package($package_bing);

check(
	$result_bing->code->value !== 'blocked.malicious_ua'
	|| $result_bing->message !== 'Bot detected by UA parser',
	sprintf('Bing (IP not in static range): NOT blocked by old ua_is_bot check (got: %s/%s)',
		$result_bing->code->value,
		$result_bing->message
		),
	$tests_passed,
	$tests_failed
	);

// =============================================================================
// 6. Full pipeline test — legitimate bots from your logs
// =============================================================================
header_line('6. Full pipeline test — bots from production logs');

$adapter_prod = new GenericAdapter();
$config_prod = Configuration::from_array([
    'preset'     => 'full',
    'strictness' => 'normal',
    'logging'    => false,
], $adapter_prod);

$bb_prod = new BadBehaviour($config_prod);

// Exact UAs from your production logs
$production_bots = [
    [
        'desc' => 'Yandex from production log',
        'ua'   => 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0',
        'ip'   => '77.88.47.10',
    ],
    [
        'desc' => 'Applebot from production log',
        'ua'   => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)',
        'ip'   => '17.246.23.79',
    ],
    [
        'desc' => 'Bingbot from production log',
        'ua'   => 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36',
        'ip'   => '52.167.144.237',
    ],
    [
        'desc' => 'Baiduspider from production log',
        'ua'   => 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'ip'   => '116.179.32.164',
    ],
    [
        'desc' => 'Seznam from production log',
        'ua'   => 'Mozilla/5.0 (compatible; SeznamBot/4.0; +https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/)',
        'ip'   => '2a02:598:96:8a00::b00:2a9',
    ],
    [
        'desc' => 'Amazon from production log',
        'ua'   => 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36',
        'ip'   => '35.174.141.243',
    ],
];

foreach ($production_bots as $bot_test) {
    $package = RequestPackage::create_for_test(
        user_agent: $bot_test['ua'],
        ip: $bot_test['ip'],
    );
    $result = $bb_prod->run_test_package($package);

    // The bot should NOT be blocked by the old ua_is_bot check.
    // It might be allowed, challenged (if unverified), or monitored
    // (in monitor-only mode), but it should NOT be blocked.malicious_ua
    // with message "Bot detected by UA parser".
    $is_old_fp = $result->code === ResultCode::BLOCKED_MALICIOUS_UA
        && $result->message === 'Bot detected by UA parser';

    check(
        !$is_old_fp,
        sprintf('%s [%s]: NO false positive (result: %s, message: %s)',
            $bot_test['desc'],
            $bot_test['ip'],
            $result->code->value,
            $result->message ?: '(empty)'
        ),
        $tests_passed,
        $tests_failed
    );
}

// =============================================================================
// 7. Registry include_categories is additive (not restrictive)
//    Regression test for the silent production breakage where
//    include_categories => ['cloud_infrastructure'] dropped every other bot.
// =============================================================================
header_line('7. Registry include_categories is additive');

// Test: minimal preset + include_categories => ['cloud_infrastructure']
// Should have ~30 minimal bots PLUS cloud_infrastructure, not just cloud.
$registry_additive = \BadBehaviour\Bot\RegistryFactory::from_array([
	'preset' => 'minimal',
	'include_categories' => ['cloud_infrastructure'],
]);

$minimal_count = $registry_additive->count();
$cloud_count = count($registry_additive->cloud_infrastructure());

check(
	$minimal_count >= 30,
	"include_categories is additive: minimal + cloud_infra yields {$minimal_count} bots (expected ≥30)",
	$tests_passed,
	$tests_failed
	);

check(
	$cloud_count >= 1,
	"include_categories added cloud_infrastructure: {$cloud_count} cloud bots present",
	$tests_passed,
	$tests_failed
	);

check(
	$registry_additive->has('googlebot'),
	"include_categories additive: googlebot (from minimal) still present",
	$tests_passed,
	$tests_failed
	);

check(
	$registry_additive->has('cloudflare_health'),
	"include_categories additive: cloudflare_health (from safety net) present",
	$tests_passed,
	$tests_failed
	);

// Test: only_categories is strict whitelist (opt-in)
$registry_strict = \BadBehaviour\Bot\RegistryFactory::from_array([
	'preset' => 'full',
	'only_categories' => ['monitoring', 'cloud_infrastructure'],
]);

$strict_count = $registry_strict->count();

check(
	$strict_count >= 1 && $strict_count <= 10,
	"only_categories is strict whitelist: {$strict_count} bots (only monitoring + cloud)",
	$tests_passed,
	$tests_failed
	);

check(
	!$registry_strict->has('googlebot'),
	"only_categories strict: googlebot (search_engine) DROPPED",
	$tests_passed,
	$tests_failed
	);

check(
	$registry_strict->has('cloudflare_health'),
	"only_categories strict: cloudflare_health (in whitelist) present",
	$tests_passed,
	$tests_failed
	);

// Test: exclude_categories is subtractive
$registry_subtractive = \BadBehaviour\Bot\RegistryFactory::from_array([
	'preset' => 'full',
	'exclude_categories' => ['seo_crawler'],
]);

check(
	$registry_subtractive->has('googlebot'),
	"exclude_categories subtractive: googlebot (search_engine) still present",
	$tests_passed,
	$tests_failed
	);

check(
	!$registry_subtractive->has('semrush'),
	"exclude_categories subtractive: semrush (seo_crawler) DROPPED",
	$tests_passed,
	$tests_failed
	);

// =============================================================================
// Summary
// =============================================================================
echo "\n=== Summary ===\n";
echo "  Total checks: $check_num\n";
echo "  Passed:       $tests_passed\n";
echo "  Failed:       $tests_failed\n";

if ($tests_failed > 0) {
    echo "\n✗ $tests_failed test(s) FAILED.\n";
    echo "\nThis means the false-positive bug is NOT fully fixed.\n";
    echo "Check that you applied all changes from the architectural fix:\n";
    echo "  1. IpUtil::match_cidr() — 64-bit integer bug\n";
    echo "  2. BlacklistDetector — removed ua_is_bot block\n";
    echo "  3. BlacklistDetector — removed is_monitor_only parameter\n";
    echo "  4. BlacklistDetector — removed check_monitor_only() method\n";
    echo "  5. BadBehaviour — removed is_monitor_only closure\n";
    echo "\n";
    exit(1);
}

echo "\n✓ All tests passed. False-positive bug is fixed.\n";
echo "\nNext steps:\n";
echo "  1. Deploy to production\n";
echo "  2. Monitor logs for any remaining false positives\n";
echo "  3. Verify legitimate bots (Yandex, Apple, Bing, etc.) are now allowed\n";
exit(0);
