#!/usr/bin/env php
<?php
// bin/update-ip-ranges.php - with CloudIpRangeProvider

require_once __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Feeds\FeedRegistry;
use BadBehaviour\Feeds\CloudIpRangeProvider;
use BadBehaviour\Adapter\GenericAdapter;

try {
    $adapter = new GenericAdapter();
    $registry = new FeedRegistry($adapter);
    $cloud_provider = new CloudIpRangeProvider($adapter);

    echo "[" . date('c') . "] Refreshing IP range feeds...\n\n";

    $start = microtime(true);
    $merged = [];
    $failures = [];

    // === Existing feeds (Google, Bing, OpenAI, Anthropic, etc.) ===
    echo "Bot-specific feeds:\n";
    foreach ($registry->get_feed_status() as $name => $info) {
        try {
            // We use reflection here to access the private feeds array,
            // OR you can add a public method to FeedRegistry.
            $reflection = new \ReflectionClass($registry);
            $feeds_prop = $reflection->getProperty('feeds');
            $feeds_prop->setAccessible(true);
            $all_feeds = $feeds_prop->getValue($registry);

            if (!isset($all_feeds[$name])) continue;

            $data = $all_feeds[$name]->fetch();
            foreach ($data as $bot_id => $cidrs) {
                $merged[$bot_id] = array_merge($merged[$bot_id] ?? [], $cidrs);
            }
            $count = array_sum(array_map('count', $data));
            echo sprintf("  [ok] %-20s %d CIDRs\n", $name, $count);
        } catch (\Throwable $e) {
            echo sprintf("  [FAIL] %-18s %s\n", $name, $e->getMessage());
            $failures[] = $name;
        }
    }

    // === NEW: Cloud infrastructure feeds ===
    echo "\nCloud infrastructure feeds:\n";
    foreach (['aws', 'cloudflare', 'fastly', 'gcp'] as $provider) {
        try {
            $cidrs = $cloud_provider->ranges($provider);
            if (!empty($cidrs)) {
                // Tag with bot IDs that should match these ranges
                foreach (Registry::cloud_infrastructure() as $bot_id => $def) {
                    // Heuristic: merge AWS into aws_elb_health, CF into cloudflare_health, etc.
                    if ($thisProviderMatchesBot($provider, $bot_id)) {
                        $merged[$bot_id] = array_merge($merged[$bot_id] ?? [], $cidrs);
                    }
                }
                echo sprintf("  [ok] %-20s %d CIDRs\n", $provider, count($cidrs));
            }
        } catch (\Throwable $e) {
            echo sprintf("  [FAIL] %-18s %s\n", $provider, $e->getMessage());
            $failures[] = $provider;
        }
    }

    $elapsed = round(microtime(true) - $start, 2);

    if (empty($merged)) {
        echo "\nFATAL: No ranges fetched\n";
        exit(2);
    }

    $merged = array_map('array_values', array_map('array_unique', $merged));

    $adapter->set('bb:ip_ranges:merged', [
        'data'    => $merged,
        'fetched' => time(),
    ], 86400);

    $total = array_sum(array_map('count', $merged));
    echo sprintf("\n✓ Cached %d total CIDRs across %d bots in %.2fs\n",
        $total, count($merged), $elapsed);

    if (!empty($failures)) {
        echo "WARNING: " . count($failures) . " feed(s) failed: " . implode(', ', $failures) . "\n";
        echo "Stale cache may be used by the application.\n";
        exit(1);
    }

    exit(0);

} catch (\Throwable $e) {
    echo "FATAL: " . $e->getMessage() . "\n";
    error_log("[BadBehaviour] CLI IP fetch failed: " . $e->getMessage());
    exit(2);
}

function thisProviderMatchesBot(string $provider, string $bot_id): bool
{
    return match(true) {
        str_contains($bot_id, 'cloudflare') => $provider === 'cloudflare',
        str_contains($bot_id, 'aws') || str_contains($bot_id, 'elb') => $provider === 'aws',
        str_contains($bot_id, 'google_cloud') || str_contains($bot_id, 'gcp') => $provider === 'gcp',
        str_contains($bot_id, 'azure') => $provider === 'azure', // not yet implemented
        str_contains($bot_id, 'fastly') => $provider === 'fastly',
        default => false,
    };
}