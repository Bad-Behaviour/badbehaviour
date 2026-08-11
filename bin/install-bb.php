<?php

declare(strict_types=1);

/**
 * Bad Behaviour — install-time IP range cache seeder.
 *
 * Runs ONCE at install / upgrade time. Pre-populates the on-demand IP
 * range cache so the site has warm data from the very first request —
 * no "first ~1000 requests run with stale data" cold-start window.
 *
 * === WHEN TO RUN ===
 *
 *   - After `bin/install-bb.php` (table creation) — or instead of it,
 *     this script handles both jobs if the table doesn't exist.
 *   - Once is enough. Subsequent installs are no-ops when the cache
 *     already exists and is fresh (use `--force` to override).
 *   - Recommended for operators enabling `on_demand_ip_refresh`.
 *     Without seeding, the first user request after install has empty
 *     dynamic ranges until the probability gate fires and a background
 *     refresh completes.
 *
 * === USAGE ===
 *
 *   php bin/install-bb.php              # seed cache (skip if fresh)
 *   php bin/install-bb.php --force      # always re-seed
 *   php bin/install-bb.php --dry-run    # show what would happen
 *   php bin/install-bb.php --verbose    # per-feed progress output
 *
 * === EXIT CODES ===
 *
 *   0  — success (cache seeded, or already fresh and not --force)
 *   1  — configuration error (no cache backend, etc.)
 *   2  — partial failure (some feeds errored; cache written with what we got)
 *   3  — total failure (no feeds succeeded; cache NOT written)
 *
 * === DEPENDENCIES ===
 *
 *   - BadBehaviour autoloader (composer install / vendor/autoload.php)
 *   - Configuration accessible (config/bb_config.php or equivalent)
 *   - Cache backend reachable
 *   - Outbound HTTPS to feed endpoints (Google, OpenAI, etc.)
 */

require_once __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Feeds\CloudIpRangeProvider;
use BadBehaviour\Feeds\FeedRegistry;
use BadBehaviour\Feeds\OnDemandRefresher;
use BadBehaviour\Feeds\RefreshResult;
use BadBehaviour\Util\ErrorReporter;

// === Argument parsing ===

$opts = getopt('', ['force', 'dry-run', 'verbose', 'help']);

if (isset($opts['help'])) {
    fwrite(STDOUT, <<<HELP
Usage: php bin/install-bb.php [options]

Options:
  --force      Re-seed even if cache already exists and is fresh
  --dry-run    Don't write cache; just show what would happen
  --verbose    Per-feed progress output (default: summary only)
  --help       Show this message

Exit codes:
  0  Success
  1  Configuration error
  2  Partial failure (cache written with available data)
  3  Total failure (cache NOT written)

HELP
    );
    exit(0);
}

$force   = isset($opts['force']);
$dry_run = isset($opts['dry-run']);
$verbose = isset($opts['verbose']);

// === Bootstrap configuration ===

fwrite(STDOUT, "[install-bb] Bootstrapping BadBehaviour...\n");

try {
    // Try MediaWiki first (most common install path); fall back to
    // WackoWiki; fall back to Generic. In practice, host applications
    // should call Configuration::from_file() with their adapter.
    $adapter = new GenericAdapter();
    $config = Configuration::from_array(
        $adapter->get_settings(),
        $adapter
    );
} catch (\Throwable $e) {
    fwrite(STDERR, "[install-bb] Configuration load failed: {$e->getMessage()}\n");
    exit(1);
}

// Verify on_demand_ip_refresh is configured sensibly. If the operator
// is running this script, they almost certainly want refresh enabled.
// Don't auto-flip their config, but warn loudly.

if (!$config->on_demand_ip_refresh_enabled) {
    fwrite(STDERR, <<<WARN

[install-bb] WARNING: on_demand_ip_refresh is currently disabled in your
config. This script seeds the cache that on-demand refresh reads from.
With refresh disabled, the seed will be written but ignored.

To enable on-demand refresh, set in config/bb_config.php:
    'on_demand_ip_refresh' => ['enabled' => true],

Continuing anyway — the cache will be populated, but nothing will
refresh it later. Run `bin/update-ip-ranges.php` via cron instead, or
enable on-demand refresh in your config.

WARN
    );
}

// === Resolve cache backend ===

$cache = $config->cache;
if ($cache === null) {
    // Adapter might implement CacheInterface too (WackoWikiAdapter,
    // MediaWikiAdapter, GenericAdapter all do).
    if ($adapter instanceof \BadBehaviour\Core\Interfaces\CacheInterface) {
        $cache = $adapter;
    } else {
        fwrite(STDERR, <<<ERR

[install-bb] No cache backend available. Pass a CacheInterface via
\$config->cache, or use an adapter that implements CacheInterface.

ERR
        );
        exit(1);
    }
}

// === Check if cache already exists and is fresh ===

if (!$force) {
    $cached = $cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
    if ($cached !== null && is_array($cached) && isset($cached['fetched'])) {
        $age = time() - (int)$cached['fetched'];
        $floor = $config->on_demand_ip_refresh_min_age_seconds;
        if ($age < $floor) {
            fwrite(STDOUT, sprintf(
                "[install-bb] Cache is fresh (%d seconds old, floor=%d). Skipping.\n"
                . "[install-bb] Use --force to re-seed anyway.\n",
                $age,
                $floor
            ));
            exit(0);
        }
        fwrite(STDOUT, sprintf(
            "[install-bb] Cache exists but is stale (%d seconds old). Re-seeding.\n",
            $age
        ));
    } else {
        fwrite(STDOUT, "[install-bb] Cache absent or malformed. Seeding fresh.\n");
    }
} else {
    fwrite(STDOUT, "[install-bb] --force: re-seeding regardless of cache state.\n");
}

// === Build the refresher and run the fetch ===

if ($dry_run) {
    fwrite(STDOUT, "[install-bb] --dry-run: building refresher but skipping do_refresh().\n");
}

$refresher = null;
try {
    $registry = new FeedRegistry($cache);
    $cloud = new CloudIpRangeProvider($cache);

    $refresher = new OnDemandRefresher(
        cache: $cache,
        registry: $registry,
        cloud: $cloud,
        options: [
            // Use generous timeouts for install-time — no per-request
            // latency budget here, but we don't want to hang forever
            // either if a feed is broken.
            'probability_denominator' => 1,
            'min_age_seconds'         => $config->on_demand_ip_refresh_min_age_seconds,
            'lock_ttl'                => $config->on_demand_ip_refresh_lock_ttl,
            'cache_ttl'               => $config->on_demand_ip_refresh_cache_ttl,
            'feed_timeout_seconds'    => 10,           // generous vs. runtime 5s
            'bot_ids'                 => $config->on_demand_ip_refresh_bot_ids ?: null,
            'cloud_providers'         => $config->on_demand_ip_refresh_cloud_providers ?: null,
        ],
    );
} catch (\Throwable $e) {
    fwrite(STDERR, "[install-bb] Refresher construction failed: {$e->getMessage()}\n");
    exit(1);
}

// Always acquire the lock before doing the work — if another worker
// happens to be refreshing right now (extremely unlikely at install time,
// but possible if the operator is testing), respect the lock.

$decision = $refresher->maybe_refresh();
if (!$decision->should_schedule && !$dry_run) {
    // Cache fresh OR another worker holds the lock. Either way,
    // --force would have bypassed the freshness check; the cooldown
    // path means we lost a race.
    fwrite(STDOUT, "[install-bb] Refresher declined: reason={$decision->reason}\n");
    if (!$force) {
        exit(0);
    }
    // --force bypassed freshness but the lock is held. Bail.
    fwrite(STDERR, "[install-bb] Another worker is refreshing. Try again later.\n");
    exit(1);
}

if ($dry_run) {
    fwrite(STDOUT, "[install-bb] --dry-run complete. No cache written.\n");
    exit(0);
}

// === Run the fetch synchronously (no shutdown function — we ARE the shutdown) ===

$start = microtime(true);
$result = $refresher->do_refresh();
$elapsed = microtime(true) - $start;

// === Report ===

if ($verbose) {
    fwrite(STDOUT, "\n[install-bb] Per-feed status:\n");
    foreach ($result->feed_status as $name => $status) {
        $st = $status['status'] ?? '?';
        $extra = '';
        if ($st === 'ok') {
            $extra = sprintf(
                ' (bots=%s cidrs=%s)',
                $status['bot_count'] ?? '?',
                $status['cidr_count'] ?? '?'
            );
        } elseif ($st === 'error') {
            $extra = ' — ' . ($status['error'] ?? 'unknown error');
        } elseif ($st === 'skipped') {
            $extra = ' — ' . ($status['reason'] ?? 'unknown reason');
        }
        fwrite(STDOUT, "  - {$name}: {$st}{$extra}\n");
    }
    fwrite(STDOUT, "\n");
}

fwrite(STDOUT, sprintf(
    "[install-bb] Result: %s, %d bots, %d CIDRs, %.2fs elapsed\n",
    $result->success ? 'success' : ($result->partial ? 'partial' : 'failure'),
    $result->bot_count,
    $result->cidr_count,
    $result->elapsed_seconds
));

if ($result->cache_written) {
    $payload = $cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
    $fetched_at = is_array($payload) ? ($payload['fetched'] ?? '?') : '?';
    fwrite(STDOUT, "[install-bb] Cache written (fetched_at={$fetched_at}).\n");
} else {
    fwrite(STDOUT, "[install-bb] Cache NOT written (no data to write).\n");
}

exit(match (true) {
    $result->success          => 0,
    $result->partial          => 2,
    default                   => 3,
});