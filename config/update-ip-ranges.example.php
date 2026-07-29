<?php
/**
 * Bad Behaviour 3.0 — Dynamic IP Range Feed Refresh (Example)
 *
 * This is a documented variant of bin/update-ip-ranges.php showing how to:
 *   - Use a custom cache backend
 *   - Override feed URLs (e.g., behind a corporate proxy)
 *   - Select a subset of feeds to refresh
 *   - Run in dry-run mode (no writes)
 *   - Schedule via cron (see comments at bottom)
 *
 * Copy to bin/update-ip-ranges.php and customize.
 *
 * Usage:
 *   php bin/update-ip-ranges.php                 # Full refresh, all feeds
 *   php bin/update-ip-ranges.php --dry-run       # Fetch but don't cache
 *   php bin/update-ip-ranges.php --feeds=google,anthropic  # Subset only
 *   php bin/update-ip-ranges.php --ttl=43200     # Override cache TTL (12h)
 *
 * Exit codes:
 *   0 — Success (all feeds fetched or stale cache used)
 *   1 — Partial failure (some feeds failed)
 *   2 — Total failure (no feeds fetched, no cache)
 *
 * Recommended cron (refresh every 6 hours):
 *   0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php >> /var/log/badbehaviour-feeds.log 2>&1
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Feeds\FeedRegistry;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Cache\FileCache;

// ============================================================
// CLI ARGUMENT PARSING
// ============================================================

$opts = getopt('', ['dry-run', 'feeds::', 'ttl::', 'cache-dir::', 'help']);

if (isset($opts['help'])) {
    echo <<<HELP
Bad Behaviour IP Range Feed Refresh

Usage:
  php bin/update-ip-ranges.php [options]

Options:
  --dry-run          Fetch and parse, but don't write to cache
  --feeds=LIST       Comma-separated subset of feed names to refresh
                     (google, bing, anthropic, apple, gptbot, chatgpt-user,
                      oai-searchbot, perplexity, duckduckgo, amazon,
                      cloudflare-v4, cloudflare-v6, cloudflare, google-user)
  --ttl=SECONDS      Override cache TTL (default: 86400 = 24h)
  --cache-dir=DIR    Override cache directory (default: system temp)
  --help             Show this help

Exit codes:
  0 — Success
  1 — Partial failure
  2 — Total failure

HELP;
    exit(0);
}

$dry_run = isset($opts['dry-run']);
$feed_filter = isset($opts['feeds']) ? array_filter(array_map('trim', explode(',', $opts['feeds']))) : null;
$ttl_override = isset($opts['ttl']) ? (int)$opts['ttl'] : null;
$cache_dir = isset($opts['cache-dir']) ? $opts['cache-dir'] : null;

// ============================================================
// ADAPTER & CACHE SETUP
// ============================================================

try {
    $adapter = new GenericAdapter();

    // Optionally swap in a different cache implementation:
    //   - FileCache (default, per-adapter)
    //   - APCu (for single-server)
    //   - Redis (for multi-server — see MediaWikiAdapter for example)
    //   - Your custom CacheInterface
    $cache = $cache_dir
        ? new FileCache($cache_dir)
        : $adapter;  // GenericAdapter implements CacheInterface

    $registry = new FeedRegistry($cache);
} catch (\Throwable $e) {
    fwrite(STDERR, "FATAL: Failed to initialize: {$e->getMessage()}\n");
    exit(2);
}

// ============================================================
// FEED SELECTION
// ============================================================

$all_status = $registry->get_feed_status();
$selected = [];

foreach ($all_status as $name => $info) {
    if ($feed_filter === null || in_array($name, $feed_filter, true)) {
        $selected[$name] = $info;
    }
}

if ($feed_filter !== null && empty($selected)) {
    fwrite(STDERR, "ERROR: No feeds matched filter: " . implode(',', $feed_filter) . "\n");
    fwrite(STDERR, "Available: " . implode(', ', array_keys($all_status)) . "\n");
    exit(2);
}

echo "[" . date('c') . "] Refreshing " . count($selected) . " feed(s)" .
     ($dry_run ? ' [DRY RUN]' : '') . "...\n";

// ============================================================
// FETCH LOOP
// ============================================================

$start = microtime(true);
$max_total = 30.0;  // Total script timeout (seconds)
$merged = [];
$failures = [];

// Iterate only the selected feeds. We use reflection to access the
// private $feeds property of FeedRegistry (alternatively, expose a method).
$reflection = new \ReflectionClass($registry);
$feeds_prop = $reflection->getProperty('feeds');
$feeds_prop->setAccessible(true);
$all_feeds = $feeds_prop->getValue($registry);

foreach ($selected as $name => $info) {
    if (!isset($all_feeds[$name])) {
        echo "  [skip] {$name}: not in registry\n";
        continue;
    }

    if (microtime(true) - $start > $max_total) {
        echo "  [skip] {$name}: global timeout reached\n";
        $failures[] = $name;
        continue;
    }

    try {
        $feed = $all_feeds[$name];
        $data = $feed->fetch();

        if (empty($data)) {
            echo "  [empty] {$name}: no data returned\n";
            $failures[] = $name;
            continue;
        }

        foreach ($data as $bot_id => $cidrs) {
            $merged[$bot_id] = array_merge($merged[$bot_id] ?? [], $cidrs);
        }

        $total_cidrs = array_sum(array_map('count', $data));
        echo "  [ok]    {$name}: {$total_cidrs} CIDRs\n";
    } catch (\Throwable $e) {
        echo "  [fail]  {$name}: " . $e->getMessage() . "\n";
        $failures[] = $name;
    }
}

$elapsed = round(microtime(true) - $start, 2);
$total_unique = array_sum(array_map('count', array_map('array_unique', $merged)));

if (empty($merged)) {
    echo "\nFATAL: No feeds returned data. Falling back to stale cache.\n";
    exit(2);
}

// ============================================================
// CACHE WRITE (unless dry-run)
// ============================================================

if ($dry_run) {
    echo "\n[DRY RUN] Would cache {$total_unique} unique CIDRs (TTL: " .
         ($ttl_override ?? 86400) . "s)\n";
    echo "Success (dry run) in {$elapsed}s\n";
    exit(0);
}

$cache_payload = [
    'data'    => array_map('array_unique', $merged),
    'fetched' => time(),
    'source'  => 'cli:bin/update-ip-ranges.php',
];

$ttl = $ttl_override ?? 86400;
$cache->set('bb:ip_ranges:merged', $cache_payload, $ttl);

echo "\nCached {$total_unique} unique CIDRs (TTL: {$ttl}s) in {$elapsed}s\n";

// ============================================================
// SUMMARY
// ============================================================

if (!empty($failures)) {
    echo "WARNING: " . count($failures) . " feed(s) failed: " . implode(', ', $failures) . "\n";
    echo "Stale cache may be used by the application.\n";
    exit(1);
}

echo "Success.\n";
exit(0);

// ============================================================
// CRON SETUP
// ============================================================
//
// Recommended: refresh every 6 hours to stay current with vendor changes
// without hammering the feed endpoints.
//
//   # /etc/cron.d/badbehaviour-feeds
//   0 */6 * * * www-data php /var/www/badbehaviour/bin/update-ip-ranges.php >> /var/log/badbehaviour-feeds.log 2>&1
//
// Or via crontab -e (as the web server user):
//
//   0 */6 * * * php /var/www/badbehaviour/bin/update-ip-ranges.php >> /var/log/badbehaviour-feeds.log 2>&1
//
// Verify it's running:
//
//   $ tail -f /var/log/badbehaviour-feeds.log
//   [2024-01-15T10:00:00+00:00] Refreshing 13 feed(s)...
//     [ok]    google: 47 CIDRs
//     [ok]    bing: 23 CIDRs
//     [ok]    anthropic: 8 CIDRs
//     ...
//   Cached 1247 unique CIDRs (TTL: 86400s) in 4.32s
//   Success.
//
// ============================================================
// TROUBLESHOOTING
// ============================================================
//
// 1. "FATAL: No feeds returned data"
//    - Check network connectivity from the cron host
//    - Check CA bundle: see docs/CONFIGURATION.md → CACHE_DIR / CA bundles
//    - Test a single feed:
//        php bin/update-ip-ranges.php --feeds=google --dry-run
//
// 2. "Stale cache may be used"
//    - The application will use stale cache if fresh fetch fails
//    - Check vendor URLs haven't changed (compare against src/Feeds/Adapters/)
//
// 3. Multi-server deployments
//    - File cache doesn't share between hosts
//    - Use Redis-backed cache or run the script on each host
//    - Or share the cache via NFS (not recommended)
//
// ============================================================