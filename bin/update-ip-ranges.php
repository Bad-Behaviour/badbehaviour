#!/usr/bin/env php
<?php
/**
 * Bad Behaviour 3.0 — Dynamic IP range feed refresh.
 *
 * Fetches IP ranges from official cloud provider feeds and writes them
 * to the Bad Behaviour cache. Run via cron every 6-24 hours:
 *
 *   0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php >> /var/log/bb-feeds.log 2>&1
 *
 * Exit codes:
 *   0 — Success
 *   1 — Partial failure (some feeds failed; stale cache may be used)
 *   2 — Total failure (no fresh data, no cache)
 *
 * @see config/bb_config.example.php → dynamic_ip_ranges
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Feeds\CloudIpRangeProvider;
use BadBehaviour\Feeds\FeedRegistry;

$start = microtime(true);
$max_total = 30.0;

try {
	$adapter = new GenericAdapter();

	$config = null;
	$config_paths = [
		__DIR__ . '/../config/bb_config.php',
		getenv('BB_CONFIG_PATH') ?: null,
	];

	foreach (array_filter($config_paths) as $path) {
		if (file_exists($path)) {
			$raw = require $path;
			$config = is_array($raw) ? Configuration::from_array($raw, $adapter) : null;
			break;
		}
	}

	if ($config === null) {
		$config = new Configuration(adapter: $adapter);
	}

	if (!$config->dynamic_ip_ranges_enabled) {
		echo "[" . date('c') . "] dynamic_ip_ranges.enabled is false. Exiting.\n";
		echo "Set 'dynamic_ip_ranges.enabled' => true in config/bb_config.php to enable.\n";
		exit(0);
	}

	$feed_registry = new FeedRegistry($adapter);
	$cloud_provider = new CloudIpRangeProvider($adapter, $config->dynamic_ip_ranges_ttl);

	echo "[" . date('c') . "] Refreshing IP range feeds...\n\n";

	$merged = [];
	$failures = [];

	echo "Bot-specific feeds:\n";
	$reflection = new \ReflectionClass($feed_registry);
	$feeds_prop = $reflection->getProperty('feeds');
	$feeds_prop->setAccessible(true);
	$all_feeds = $feeds_prop->getValue($feed_registry);

	foreach ($all_feeds as $name => $feed) {
		if (microtime(true) - $start > $max_total) {
			echo "  [skip] {$name}: global timeout reached\n";
			$failures[] = $name;
			continue;
		}

		try {
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
			echo sprintf("  [ok]	%-20s %d CIDRs\n", $name, $total_cidrs);
		} catch (\Throwable $e) {
			echo sprintf("  [fail]  %-18s %s\n", $name, $e->getMessage());
			$failures[] = $name;
		}
	}

	echo "\nCloud infrastructure feeds:\n";
	foreach ($config->dynamic_ip_ranges_feeds as $provider) {
		if (microtime(true) - $start > $max_total) {
			echo "  [skip] {$provider}: global timeout reached\n";
			$failures[] = $provider;
			continue;
		}

		try {
			$cidrs = $cloud_provider->ranges($provider);

			if (empty($cidrs)) {
				echo "  [empty] {$provider}: no data returned\n";
				$failures[] = $provider;
				continue;
			}

			$target_bot_ids = match ($provider) {
				'aws'		=> ['aws_elb_health'],
				'cloudflare' => ['cloudflare_health'],
				'fastly'	 => ['fastly_health'],
				'gcp'		=> ['google_cloud_health'],
				default	  => [],
			};

			foreach ($target_bot_ids as $bot_id) {
				$merged[$bot_id] = array_merge($merged[$bot_id] ?? [], $cidrs);
			}

			echo sprintf("  [ok]	%-20s %d CIDRs (→ %s)\n",
				$provider, count($cidrs), implode(', ', $target_bot_ids) ?: '(no mapping)');
		} catch (\Throwable $e) {
			echo sprintf("  [fail]  %-18s %s\n", $provider, $e->getMessage());
			$failures[] = $provider;
		}
	}

	$elapsed = round(microtime(true) - $start, 2);

	if (empty($merged)) {
		echo "\nFATAL: No ranges fetched from any feed.\n";
		exit(2);
	}

	$merged = array_map('array_values', array_map('array_unique', $merged));

	$adapter->set('bb:ip_ranges:merged', [
		'data'	=> $merged,
		'fetched' => time(),
	], $config->dynamic_ip_ranges_ttl);

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
