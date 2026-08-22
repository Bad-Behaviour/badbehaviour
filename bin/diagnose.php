<?php
/**
 * bin/diagnose.php
 *
 * Bad Behaviour 3.0 — Diagnostics + Smoke Test
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Config\Diagnostics;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;

$adapter = new GenericAdapter();
$all_passed = true;
$check_num = 0;

function check(bool $cond, string $msg): bool
{
	global $all_passed, $check_num;
	$check_num++;
	if ($cond) {
		echo "  ✓ $msg\n";
		return true;
	}
	echo "  ✗ FAIL: $msg\n";
	$all_passed = false;
	return false;
}

function header_line(string $s): void
{
	echo "\n=== $s ===\n";
}

// =============================================================================
// 1. bot_categories round-trip
// =============================================================================
header_line('1. bot_categories round-trip');

$config = Configuration::from_array([
	'preset'		 => 'full',
	'bot_categories' => [
		'blocked'   => ['malicious'],
		'challenge' => ['social_crawler'],
		'log_only'  => ['security_scanner'],
		'allowed'   => ['feed_reader'],
	],
], $adapter);

$expected = [
	'blocked'   => ['malicious'],
	'challenge' => ['social_crawler'],
	'log_only'  => ['security_scanner'],
	'allowed'   => ['feed_reader'],
];

$actual = [
	'blocked'   => $config->blocked_bot_categories,
	'challenge' => $config->challenge_bot_categories,
	'log_only'  => $config->log_only_bot_categories,
	'allowed'   => $config->allowed_bot_categories,
];

foreach ($expected as $key => $want) {
	check($actual[$key] === $want, "property $key = " . json_encode($want));
}

$round_tripped = $config->to_array()['bot_categories'] ?? [];
foreach ($expected as $key => $want) {
	check(
		($round_tripped[$key] ?? null) === $want,
		"to_array() bot_categories.$key = " . json_encode($want)
	);
}

// =============================================================================
// 2. Strictness propagation (dynamic_ip_ranges fix)
// =============================================================================
header_line('2. Strictness propagation (dynamic_ip_ranges fix)');

$mo = Configuration::from_array(['strictness' => 'monitor-only']);
check(
	$mo->dynamic_ip_ranges_enabled === false,
	"strictness='monitor-only' → dynamic_ip_ranges_enabled = false (was: true)"
);
check(
	$mo->dns_verification_enabled === false,
	"strictness='monitor-only' → dns_verification_enabled = false (was: true)"
);
check(
	$mo->rate_limit_enabled === false,
	"strictness='monitor-only' → rate_limit_enabled = false"
);
check(
	$mo->block_unverified_ai === false,
	"strictness='monitor-only' → block_unverified_ai = false"
);
check(
	$mo->dnsbl_enabled === false,
	"strictness='monitor-only' → dnsbl_enabled = false"
);

// =============================================================================
// 3. Typo detection
// =============================================================================
header_line('3. Typo detection');

Diagnostics::reset();

Configuration::from_array([
	'preset'		   => 'minimal',
	'dynamc_ip_ranges' => ['enabled' => true],
	'strictness'	   => 'monitor-only',
]);

$unknown = Diagnostics::unknown_keys();
check(
	isset($unknown['dynamc_ip_ranges.enabled']),
	"typo 'dynamc_ip_ranges.enabled' flagged"
);

if (!empty($unknown)) {
	echo "  Unknown keys detected:\n";
	foreach (array_keys($unknown) as $key) {
		echo "	- '$key'\n";
	}
}

Diagnostics::reset();

// =============================================================================
// 4. Library diagnostics
// =============================================================================
header_line('4. Library diagnostics');

$config_path = __DIR__ . '/../config/bb_config.php';
$user_config = [];
if (file_exists($config_path)) {
	$user_config = require $config_path;
	if (!is_array($user_config)) {
		$user_config = [];
		echo "  ⚠ bb_config.php did not return an array; using defaults\n";
	}
}

$adapter_settings = $adapter->get_settings();
$merged = is_array($adapter_settings) ? array_merge($adapter_settings, $user_config) : $user_config;

$diag_config = Configuration::from_array($merged, $adapter);
$bb		  = new BadBehaviour($diag_config);

echo json_encode($bb->diagnostics(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

// =============================================================================
// 5. Feature flags
// =============================================================================
header_line('5. Feature flags');

$flags = [
	'dns_verification_enabled'	  => $diag_config->dns_verification_enabled,
	'dynamic_ip_ranges_enabled'	 => $diag_config->dynamic_ip_ranges_enabled,
	'rate_limit_enabled'			=> $diag_config->rate_limit_enabled,
	'dnsbl_enabled'				 => $diag_config->dnsbl_enabled,
	'httpbl_key set'				=> $diag_config->httpbl_key !== '',
	'geoip_enabled'				 => $diag_config->geoip_enabled,
	'challenge_enabled'			 => $diag_config->challenge_enabled,
	'enable_fingerprinting'		 => $diag_config->enable_fingerprinting,
	'enable_behavioral_analysis'	=> $diag_config->enable_behavioral_analysis,
	'enable_client_hints_validation'=> $diag_config->enable_client_hints_validation,
	'enable_agentic_detection'	  => $diag_config->enable_agentic_detection,
	'enable_head_request_detection' => $diag_config->enable_head_request_detection,
	'enable_asset_scraping_detection' => $diag_config->enable_asset_scraping_detection,
	'block_unverified_ai'		   => $diag_config->block_unverified_ai,
	'strict_search_engines'		 => $diag_config->strict_search_engines,
];

$enabled_count = 0;
$disabled_count = 0;
foreach ($flags as $name => $value) {
	$marker = $value ? '🟢 ON ' : '⚫ OFF';
	echo sprintf("  %s  %s\n", $marker, $name);
	$value ? $enabled_count++ : $disabled_count++;
}

echo "\n  Total: $enabled_count enabled, $disabled_count disabled\n";

// =============================================================================
// 6. Bot category overrides
// =============================================================================
header_line('6. Bot category overrides');

$overrides = [
	'blocked'   => $diag_config->blocked_bot_categories,
	'challenge' => $diag_config->challenge_bot_categories,
	'log_only'  => $diag_config->log_only_bot_categories,
	'allowed'   => $diag_config->allowed_bot_categories,
];

$has_any = false;
foreach ($overrides as $action => $cats) {
	if (empty($cats)) continue;
	$has_any = true;
	echo "  $action: " . implode(', ', $cats) . "\n";
}
if (!$has_any) {
	echo "  (no category overrides configured — using defaults)\n";
}

// =============================================================================
// 7. Bot registry
// =============================================================================
header_line('7. Bot registry');

$registry = $bb->get_registry();
echo "  Bot count: " . $registry->count() . "\n";

// =============================================================================
// 8. Safe-mode safe string handling (regression for geoip_database_path array bug)
// =============================================================================
header_line('8. Safe-mode string property handling');

$safe = \BadBehaviour\Configuration::from_array(
	\BadBehaviour\Util\SafeMode::settings('test_table')
	);

check(
	is_string($safe->geoip_database_path),
	"safe-mode → geoip_database_path is string (not array)"
	);
check(
	$safe->geoip_database_path === '',
	"safe-mode → geoip_database_path = ''"
	);

// =============================================================================
// Summary
// =============================================================================
echo "\n=== Summary ===\n";
echo "  Checks run: $check_num\n";
echo "  Result:	 " . ($all_passed ? "✓ PASS" : "✗ FAIL") . "\n";

if (!$all_passed) {
	echo "\nOne or more smoke tests failed.\n";
	echo "Run 'php bin/test-config-schema.php' for detailed schema checks.\n";
	exit(1);
}

echo "\n✓ All smoke tests passed.\n";
exit(0);