<?php
/**
 * bin/diagnose-config-merge.php
 *
 * Diagnoses why partial 'dynamic_ip_ranges' or 'on_demand_ip_refresh'
 * arrays cause logging to break.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;

$adapter = new GenericAdapter();

// User's problematic config (partial arrays)
$user_config = [
    'preset'     => 'full',
    'strictness' => 'normal',
    'logging'    => true,
    'verbose'    => true,
    'dynamic_ip_ranges' => [
        'enabled' => true,
    ],
    'on_demand_ip_refresh' => [
        'enabled' => true,
    ],
];

echo "=== User config (partial arrays) ===\n";
echo json_encode($user_config, JSON_PRETTY_PRINT) . "\n\n";

// Step 1: Flatten user config
$flat_user = \BadBehaviour\Config\Schema::flatten($user_config);
echo "=== Flattened user config ===\n";
echo json_encode($flat_user, JSON_PRETTY_PRINT) . "\n\n";

// Step 2: Flatten defaults
$flat_default = \BadBehaviour\Config\Schema::flatten(Configuration::get_defaults());
echo "=== Flattened defaults (dynamic_ip_ranges + on_demand_ip_refresh only) ===\n";
$defaults_subset = array_filter($flat_default, function($k) {
    return str_starts_with($k, 'dynamic_ip_ranges') || str_starts_with($k, 'on_demand_ip_refresh');
}, ARRAY_FILTER_USE_KEY);
echo json_encode($defaults_subset, JSON_PRETTY_PRINT) . "\n\n";

// Step 3: Flatten strictness overrides
$flat_overrides = \BadBehaviour\Config\Schema::flatten(
    Configuration::strictness_overrides('normal')
);
echo "=== Flattened strictness overrides (dynamic_ip_ranges + on_demand_ip_refresh only) ===\n";
$overrides_subset = array_filter($flat_overrides, function($k) {
    return str_starts_with($k, 'dynamic_ip_ranges') || str_starts_with($k, 'on_demand_ip_refresh');
}, ARRAY_FILTER_USE_KEY);
echo json_encode($overrides_subset, JSON_PRETTY_PRINT) . "\n\n";

// Step 4: Merge all three
$flat = array_merge($flat_default, $flat_overrides, $flat_user);
echo "=== Merged flat config (dynamic_ip_ranges + on_demand_ip_refresh only) ===\n";
$merged_subset = array_filter($flat, function($k) {
    return str_starts_with($k, 'dynamic_ip_ranges') || str_starts_with($k, 'on_demand_ip_refresh');
}, ARRAY_FILTER_USE_KEY);
echo json_encode($merged_subset, JSON_PRETTY_PRINT) . "\n\n";

// Step 5: Check which keys are MISSING from the merge
$required_keys = [
    'dynamic_ip_ranges.enabled',
    'dynamic_ip_ranges.ttl',
    'dynamic_ip_ranges.feeds',
    'on_demand_ip_refresh.enabled',
    'on_demand_ip_refresh.probability_denominator',
    'on_demand_ip_refresh.min_age_seconds',
    'on_demand_ip_refresh.lock_ttl',
    'on_demand_ip_refresh.cache_ttl',
    'on_demand_ip_refresh.feed_timeout_seconds',
];

echo "=== Required keys check ===\n";
foreach ($required_keys as $key) {
    $exists = array_key_exists($key, $flat);
    $value = $flat[$key] ?? 'MISSING';
    echo sprintf("  %s: %s (value: %s)\n",
        $key,
        $exists ? 'EXISTS' : 'MISSING',
        is_array($value) ? json_encode($value) : var_export($value, true)
    );
}
echo "\n";

echo "=== Registry filter keys ===\n";

$registry_keys = [
	'include_categories' => 'ADDITIVE merge from full registry (safety net pattern)',
	'exclude_categories' => 'Subtractive — drops these categories from preset',
	'only_categories'    => 'STRICT whitelist — drops everything else (rare)',
	'exclude_bots'       => 'Subtractive — drops specific bot IDs',
	'additions'          => 'Custom bots merged on top',
];

foreach ($registry_keys as $key => $description) {
	$exists = array_key_exists($key, $flat);
	$value = $flat[$key] ?? 'NOT SET';
	$marker = $exists ? '✓ SET' : '  --';
	echo sprintf("  %s  %-20s %s\n", $marker, $key, $description);
	if ($exists && $key === 'include_categories') {
		echo "      → include_categories is ADDITIVE (merges bots from full registry).\n";
		echo "        Common use: 'include_categories' => ['cloud_infrastructure']\n";
		echo "        to add back cloud probes after aggressive filtering.\n";
	}
}

echo "\n=== Required keys check ===\n";
foreach ($required_keys as $key) {
	$exists = array_key_exists($key, $flat);
	$value = $flat[$key] ?? 'MISSING';
	echo sprintf("  %s: %s (value: %s)\n",
		$key,
		$exists ? 'EXISTS' : 'MISSING',
		is_array($value) ? json_encode($value) : var_export($value, true)
		);
}

// Step 6: Construct Configuration and inspect
echo "=== Configuration object state ===\n";
try {
    $config = Configuration::from_array($user_config, $adapter);
    echo "  logging: " . var_export($config->logging, true) . "\n";
    echo "  verbose: " . var_export($config->verbose, true) . "\n";
    echo "  dynamic_ip_ranges_enabled: " . var_export($config->dynamic_ip_ranges_enabled, true) . "\n";
    echo "  dynamic_ip_ranges_ttl: " . var_export($config->dynamic_ip_ranges_ttl, true) . "\n";
    echo "  dynamic_ip_ranges_feeds: " . json_encode($config->dynamic_ip_ranges_feeds) . "\n";
    echo "  on_demand_ip_refresh_enabled: " . var_export($config->on_demand_ip_refresh_enabled, true) . "\n";
    echo "  on_demand_ip_refresh_probability_denominator: " . var_export($config->on_demand_ip_refresh_probability_denominator, true) . "\n";
    echo "  on_demand_ip_refresh_min_age_seconds: " . var_export($config->on_demand_ip_refresh_min_age_seconds, true) . "\n";
    echo "  on_demand_ip_refresh_lock_ttl: " . var_export($config->on_demand_ip_refresh_lock_ttl, true) . "\n";
    echo "  on_demand_ip_refresh_cache_ttl: " . var_export($config->on_demand_ip_refresh_cache_ttl, true) . "\n";
    echo "  on_demand_ip_refresh_feed_timeout_seconds: " . var_export($config->on_demand_ip_refresh_feed_timeout_seconds, true) . "\n";
    echo "  on_demand_ip_refresh_bot_ids: " . json_encode($config->on_demand_ip_refresh_bot_ids) . "\n";
    echo "  on_demand_ip_refresh_cloud_providers: " . json_encode($config->on_demand_ip_refresh_cloud_providers) . "\n";
} catch (\Throwable $e) {
    echo "  ERROR constructing Configuration: " . $e->getMessage() . "\n";
    echo "  File: " . $e->getFile() . "\n";
    echo "  Line: " . $e->getLine() . "\n";
}
echo "\n";

// Step 7: Check what adapter->get_settings() returns
echo "=== Adapter get_settings() (with logging check) ===\n";
$settings = $adapter->get_settings();
echo "  Has 'logging' key: " . (array_key_exists('logging', $settings) ? 'YES' : 'NO') . "\n";
echo "  logging value: " . var_export($settings['logging'] ?? 'NOT SET', true) . "\n";
echo "  Has 'verbose' key: " . (array_key_exists('verbose', $settings) ? 'YES' : 'NO') . "\n";
echo "  verbose value: " . var_export($settings['verbose'] ?? 'NOT SET', true) . "\n";
echo "  Has 'dynamic_ip_ranges' key: " . (array_key_exists('dynamic_ip_ranges', $settings) ? 'YES' : 'NO') . "\n";
if (array_key_exists('dynamic_ip_ranges', $settings)) {
    echo "  dynamic_ip_ranges: " . json_encode($settings['dynamic_ip_ranges']) . "\n";
}
echo "\n";