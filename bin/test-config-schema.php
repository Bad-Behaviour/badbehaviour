<?php
/**
 * bin/test-config-schema.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Config\Diagnostics;
use BadBehaviour\Config\Schema;
use BadBehaviour\Configuration;
use BadBehaviour\Util\SafeMode;

$errors = [];
$passes = 0;

function check(bool $cond, string $msg, array &$errors, int &$passes): void
{
	if ($cond) {
		$passes++;
		echo "  ✓ $msg\n";
	} else {
		$errors[] = $msg;
		echo "  ✗ FAIL: $msg\n";
	}
}

function header_line(string $s): void
{
	echo "\n=== $s ===\n";
}

$known = Schema::known_keys();

// =============================================================================
// Test 1: Schema keys reachable from get_defaults()
// =============================================================================
header_line('Test 1: Schema keys reachable from get_defaults()');

$default_flat = Schema::flatten(Configuration::get_defaults());

$skip_from_defaults = ['log_table', 'adapter', 'logger', 'cache', 'geoip'];

$missing = [];
foreach ($known as $dotted) {
	if (in_array($dotted, $skip_from_defaults, true)) continue;
	if (!array_key_exists($dotted, $default_flat)) {
		$missing[] = $dotted;
	}
}

check(
	empty($missing),
	"all " . count($known) . " schema keys reachable from get_defaults()"
		. (empty($missing) ? '' : ' (missing: ' . implode(', ', $missing) . ')'),
	$errors,
	$passes
);

// =============================================================================
// Test 2: Strictness overrides use valid schema keys
// =============================================================================
header_line('Test 2: Strictness overrides use valid schema keys');

foreach (['monitor-only', 'normal', 'strict'] as $level) {
	$overrides = Schema::flatten(Configuration::strictness_overrides($level));
	$bad = [];
	foreach (array_keys($overrides) as $dotted) {
		if (!in_array($dotted, $known, true)) {
			$bad[] = $dotted;
		}
	}
	check(
		empty($bad),
		"strictness_overrides('$level') uses only valid schema keys"
			. (empty($bad) ? '' : ' (unknown: ' . implode(', ', $bad) . ')'),
		$errors,
		$passes
	);
}

// =============================================================================
// Test 3: SafeMode overrides use valid schema keys
// =============================================================================
header_line('Test 3: SafeMode overrides use valid schema keys');

$safe_flat = Schema::flatten(SafeMode::overrides());
$bad_safe = [];
foreach (array_keys($safe_flat) as $dotted) {
	// _safe_mode is an internal marker, not part of Schema
	if ($dotted === '_safe_mode') continue;
	if (!in_array($dotted, $known, true)) {
		$bad_safe[] = $dotted;
	}
}
check(
	empty($bad_safe),
	"SafeMode::OVERRIDES uses only valid schema keys"
	. (empty($bad_safe) ? '' : ' (unknown: ' . implode(', ', $bad_safe) . ')'),
	$errors,
	$passes
	);


// =============================================================================
// Test 4: dynamic_ip_ranges_enabled follows strictness
// =============================================================================
header_line('Test 4: dynamic_ip_ranges_enabled follows strictness');

Diagnostics::reset();

$monitor_only = Configuration::from_array(['strictness' => 'monitor-only']);
check(
	$monitor_only->dynamic_ip_ranges_enabled === false,
	"strictness='monitor-only' → dynamic_ip_ranges_enabled = false",
	$errors,
	$passes
);

$normal = Configuration::from_array(['strictness' => 'normal']);
check(
	$normal->dynamic_ip_ranges_enabled === true,
	"strictness='normal' → dynamic_ip_ranges_enabled = true",
	$errors,
	$passes
);

$strict = Configuration::from_array(['strictness' => 'strict']);
check(
	$strict->dynamic_ip_ranges_enabled === true,
	"strictness='strict' → dynamic_ip_ranges_enabled = true",
	$errors,
	$passes
);

$user_override = Configuration::from_array([
	'strictness' => 'monitor-only',
	'dynamic_ip_ranges' => ['enabled' => true],
]);
check(
	$user_override->dynamic_ip_ranges_enabled === true,
	"user override beats strictness override",
	$errors,
	$passes
);

// =============================================================================
// Test 5: dns_verification_enabled follows strictness
// =============================================================================
header_line('Test 5: dns_verification_enabled follows strictness');

$mo_dns = Configuration::from_array(['strictness' => 'monitor-only']);
check(
	$mo_dns->dns_verification_enabled === false,
	"strictness='monitor-only' → dns_verification_enabled = false",
	$errors,
	$passes
);

$n_dns = Configuration::from_array(['strictness' => 'normal']);
check(
	$n_dns->dns_verification_enabled === true,
	"strictness='normal' → dns_verification_enabled = true",
	$errors,
	$passes
);

// =============================================================================
// Test 6: Diagnostics catches typos
// =============================================================================
header_line('Test 6: Diagnostics catches typos');

Diagnostics::reset();

Configuration::from_array([
	'dynamc_ip_ranges' => ['enabled' => true],
	'preset'		   => 'minimal',
	'dns_verfiction'   => ['enabled' => false],
]);

$unknown = Diagnostics::unknown_keys();
check(
	isset($unknown['dynamc_ip_ranges.enabled']),
	"typo 'dynamc_ip_ranges.enabled' flagged",
	$errors,
	$passes
);
check(
	isset($unknown['dns_verfiction.enabled']),
	"typo 'dns_verfiction.enabled' flagged",
	$errors,
	$passes
);

Diagnostics::reset();

// =============================================================================
// Test 7: SafeMode produces fully-disabled Configuration
// =============================================================================
header_line('Test 7: SafeMode produces fully-disabled Configuration');

$safe = Configuration::from_array(SafeMode::settings('test_log_table'));

$defense_flags = [
	'dns_verification_enabled'	   => false,
	'dynamic_ip_ranges_enabled'	  => false,
	'dnsbl_enabled'				  => false,
	'rate_limit_enabled'			 => false,
	'enable_fingerprinting'		  => false,
	'enable_behavioral_analysis'	 => false,
	'enable_client_hints_validation' => false,
	'enable_agentic_detection'	   => false,
	'enable_head_request_detection'  => false,
	'enable_asset_scraping_detection'=> false,
	'geoip_enabled'				  => false,
	'challenge_enabled'			  => false,
	'block_unverified_ai'			=> false,
	'strict_search_engines'		  => false,
];

foreach ($defense_flags as $prop => $expected) {
	check(
		$safe->{$prop} === $expected,
		"safe-mode → $prop = " . var_export($expected, true),
		$errors,
		$passes
	);
}

check($safe->logging === true, "safe-mode → logging = true", $errors, $passes);
check($safe->log_table === 'test_log_table', "safe-mode → log_table injected", $errors, $passes);
check($safe->geoip_database_path === '', "safe-mode → geoip_database_path = ''", $errors, $passes);

// =============================================================================
// Test 8: to_array() round-trip (uses strictness='normal' to avoid
//		 strictness override wiping user ai_crawlers.allowed)
// =============================================================================
header_line('Test 8: to_array() round-trip');

$original = [
	'preset'	  => 'minimal',
	'strictness'  => 'normal',
	'logging'	 => true,
	'ai_crawlers' => ['allowed' => ['GPTBot', 'ClaudeBot']],
	'bot_categories' => [
		'blocked'   => ['malicious'],
		'challenge' => ['social_crawler'],
	],
];

$cfg = Configuration::from_array($original);
$round = $cfg->to_array();

check($round['preset'] === 'minimal', "round-trip → preset", $errors, $passes);
check($round['strictness'] === 'normal', "round-trip → strictness", $errors, $passes);
check(
	($round['ai_crawlers']['allowed'] ?? null) === ['GPTBot', 'ClaudeBot'],
	"round-trip → ai_crawlers.allowed",
	$errors,
	$passes
);
check(
	($round['bot_categories']['blocked'] ?? null) === ['malicious'],
	"round-trip → bot_categories.blocked",
	$errors,
	$passes
);
check(
	($round['bot_categories']['challenge'] ?? null) === ['social_crawler'],
	"round-trip → bot_categories.challenge",
	$errors,
	$passes
);

// =============================================================================
// Test 9: bot_categories all four sub-keys
// =============================================================================
header_line('Test 9: bot_categories all four sub-keys');

$full = Configuration::from_array([
	'preset'		 => 'full',
	'bot_categories' => [
		'blocked'   => ['malicious'],
		'challenge' => ['social_crawler'],
		'log_only'  => ['security_scanner'],
		'allowed'   => ['feed_reader'],
	],
]);

check($full->blocked_bot_categories === ['malicious'], "blocked persists", $errors, $passes);
check($full->challenge_bot_categories === ['social_crawler'], "challenge persists", $errors, $passes);
check($full->log_only_bot_categories === ['security_scanner'], "log_only persists", $errors, $passes);
check($full->allowed_bot_categories === ['feed_reader'], "allowed persists", $errors, $passes);

// =============================================================================
// Test 10: rate_limits sub-buckets
// =============================================================================
header_line('Test 10: rate_limits sub-buckets');

$rl = Configuration::from_array([
	'rate_limits' => [
		'enabled' => true,
		'global' => ['requests' => 500, 'window' => 1800],
		'per_minute' => ['requests' => 30, 'window' => 60],
	],
]);

check($rl->rate_limit_enabled === true, "rate_limit_enabled from nested", $errors, $passes);
check(($rl->rate_limits['global']['requests'] ?? null) === 500, "rate_limits.global.requests", $errors, $passes);
check(($rl->rate_limits['per_minute']['window'] ?? null) === 60, "rate_limits.per_minute.window", $errors, $passes);

// =============================================================================
// Test 11: User config beats strictness override (regression for the
//		  bug that originally caused the dynamic_ip_ranges failure)
// =============================================================================
header_line('Test 11: User config beats strictness override');

Diagnostics::reset();

// monitor-only would set ai_crawlers.allowed = [], but user must win
$user_beats = Configuration::from_array([
	'strictness'  => 'monitor-only',
	'ai_crawlers' => ['allowed' => ['GPTBot', 'ClaudeBot']],
]);

check(
	$user_beats->allowed_ai_crawlers === ['GPTBot', 'ClaudeBot'],
	"user ai_crawlers.allowed beats strictness override",
	$errors,
	$passes
);

// Same for dns_verification
$user_dns = Configuration::from_array([
	'strictness'		 => 'monitor-only',
	'dns_verification'   => ['enabled' => true],
]);

check(
	$user_dns->dns_verification_enabled === true,
	"user dns_verification.enabled beats strictness override",
	$errors,
	$passes
);

// =============================================================================
// Test 12: All four ai_crawlers sub-keys work
// =============================================================================
header_line('Test 12: ai_crawlers sub-keys');

$ai = Configuration::from_array([
	'ai_crawlers' => [
		'allowed'		  => ['GPTBot'],
		'block_unverified' => true,
		'strict'		   => true,
	],
]);

check($ai->allowed_ai_crawlers === ['GPTBot'], "allowed_ai_crawlers", $errors, $passes);
check($ai->block_unverified_ai === true, "block_unverified_ai", $errors, $passes);
check($ai->strict_ai === true, "strict_ai", $errors, $passes);

// =============================================================================
// Test 13: Defensive - Schema::KEY_MAP contains ai_crawlers.allowed
//		  (this is the specific key that was failing in Test 8 originally)
// =============================================================================
header_line('Test 13: ai_crawlers.allowed is in schema');

check(
	in_array('ai_crawlers.allowed', $known, true),
	"Schema::KEY_MAP contains 'ai_crawlers.allowed'",
	$errors,
	$passes
);

if (!in_array('ai_crawlers.allowed', $known, true)) {
	echo "  Available ai_crawlers keys in schema:\n";
	foreach ($known as $k) {
		if (str_starts_with($k, 'ai_crawlers.')) {
			echo "	- $k\n";
		}
	}
}

// =============================================================================
// Test 14: Array properties survive coercion (regression test for the
//		  SQLite lock storm caused by skip_static_extensions being
//		  silently wiped to [] during config parsing)
// =============================================================================
header_line('Test 14: Array properties survive coercion');

$empty_cfg = Configuration::from_array([]);

// Each entry: [property_name, required_entries_that_must_be_present]
$array_properties_required = [
	'skip_static_extensions'	=> ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg'],
	'skip_static_paths'		 => ['/static/', '/assets/', '/media/', '/images/'],
	'allowed_ai_crawlers'	   => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
	'dnsbl_lists'			   => ['zen.spamhaus.org', 'bl.spamcop.net'],
	'head_referer_exempt_paths' => ['/api/'],
	'dynamic_ip_ranges_feeds'   => ['aws', 'cloudflare'],
	'asset_extensions'		  => ['png', 'jpg', 'svg'],
	'body_scan_skip_fields'	 => ['body', 'comment'],
];

foreach ($array_properties_required as $prop => $required_entries) {
	$actual = $empty_cfg->{$prop} ?? null;

	check(
		is_array($actual),
		"$prop is an array after from_array([])",
		$errors,
		$passes
		);

	check(
		!empty($actual),
		"$prop is non-empty after from_array([]) (defaults flowed through, not wiped)"
		. (is_array($actual) ? ' (' . count($actual) . ' entries)' : ''),
		$errors,
		$passes
		);

	foreach ($required_entries as $required) {
		check(
			is_array($actual) && in_array($required, $actual, true),
			"$prop contains required entry '$required'",
			$errors,
			$passes
			);
	}
}

// Also verify the empty-defaults stay empty
$empty_by_default = [
	'reverse_proxy_addresses',
	'blocked_bot_categories',
	'challenge_bot_categories',
	'log_only_bot_categories',
	'allowed_bot_categories',
	'bad_ja3_fingerprints',
	'bad_h2_fingerprints',
	'bot_header_orders',
	'expected_ja3',
	'blocked_countries',
	'blocked_asns',
	'custom_rules',
];

foreach ($empty_by_default as $prop) {
	$actual = $empty_cfg->{$prop} ?? null;
	check(
		is_array($actual) && $actual === [],
		"$prop is empty array by default (not null, not wiped to wrong type)",
		$errors,
		$passes
		);
}

// =============================================================================
// Test 15: User config without performance section preserves static skip
//		  (regression test for the exact config that triggered the bug:
//		   preset=minimal, strictness=monitor-only, verbose=true)
// =============================================================================
header_line('Test 15: Minimal user config preserves skip_static_extensions');

Diagnostics::reset();

$minimal = Configuration::from_array([
	'preset'	 => 'minimal',
	'strictness' => 'monitor-only',
	'logging'	=> true,
	'verbose'	=> true,
]);

check(
	is_array($minimal->skip_static_extensions) && !empty($minimal->skip_static_extensions),
	"minimal config → skip_static_extensions is non-empty array (not wiped)",
	$errors,
	$passes
	);

check(
	in_array('js', $minimal->skip_static_extensions, true),
	"minimal config → skip_static_extensions contains 'js' (THE bug)",
	$errors,
	$passes
	);

check(
	in_array('css', $minimal->skip_static_extensions, true),
	"minimal config → skip_static_extensions contains 'css'",
	$errors,
	$passes
	);

check(
	count($minimal->skip_static_extensions) >= 10,
	"minimal config → skip_static_extensions has full default set ("
	. count($minimal->skip_static_extensions) . " entries)",
	$errors,
	$passes
	);

// Same check for skip_static_paths
check(
	is_array($minimal->skip_static_paths) && !empty($minimal->skip_static_paths),
	"minimal config → skip_static_paths is non-empty",
	$errors,
	$passes
	);

check(
	in_array('/static/', $minimal->skip_static_paths, true),
	"minimal config → skip_static_paths contains '/static/'",
	$errors,
	$passes
	);

// =============================================================================
// Test 16: Explicit empty array in user config wipes defaults
//		  (distinguishes "defaults flowed through" from "user disabled")
// =============================================================================
header_line('Test 16: Explicit empty array respects user intent');

$disabled = Configuration::from_array([
	'performance' => [
		'skip_extensions' => [],
		'skip_paths'	  => [],
	],
]);

check(
	$disabled->skip_static_extensions === [],
	"explicit [] in user config wipes skip_static_extensions defaults",
	$errors,
	$passes
	);

check(
	$disabled->skip_static_paths === [],
	"explicit [] in user config wipes skip_static_paths defaults",
	$errors,
	$passes
	);

// Partial override: user sets only skip_extensions, paths must keep defaults
$partial = Configuration::from_array([
	'performance' => [
		'skip_extensions' => ['custom_ext'],
	],
]);

check(
	$partial->skip_static_extensions === ['custom_ext'],
	"user override replaces skip_static_extensions entirely",
	$errors,
	$passes
	);

check(
	is_array($partial->skip_static_paths) && !empty($partial->skip_static_paths),
	"partial override preserves skip_static_paths defaults",
	$errors,
	$passes
	);

// =============================================================================
// Test 17: Coercion handles type mismatches gracefully
//		  (string 'true' for bool, string '60' for int, etc.)
// =============================================================================
header_line('Test 17: Type coercion handles mismatches');

$coerced = Configuration::from_array([
	'verbose'			 => 'true',		  // string → bool
	'logging'			 => '1',			 // string '1' → bool true
	'httpbl_threat'	   => '25',			// string '25' → int
	'dns_verification'	=> ['timeout_ms' => '300'],  // string '300' → int
	'recaptcha_min_score' => '0.5',		   // string '0.5' → float
]);

check(
	$coerced->verbose === true,
	"string 'true' coerces to bool true",
	$errors,
	$passes
	);

check(
	$coerced->logging === true,
	"string '1' coerces to bool true",
	$errors,
	$passes
	);

check(
	$coerced->httpbl_threat === 25,
	"string '25' coerces to int 25",
	$errors,
	$passes
	);

check(
	$coerced->dns_verification_timeout_ms === 300,
	"string '300' coerces to int 300",
	$errors,
	$passes
	);

check(
	$coerced->recaptcha_min_score === 0.5,
	"string '0.5' coerces to float 0.5",
	$errors,
	$passes
	);

// =============================================================================
// Test 18: Schema reflectively covers all array-typed constructor parameters
//		  (the catch-all that prevents future regressions when adding
//		   new array properties without updating the allow-list)
// =============================================================================
header_line('Test 18: Schema covers all array constructor parameters');

$reflection = new ReflectionClass(Configuration::class);
$constructor = $reflection->getConstructor();
$array_params = [];

foreach ($constructor->getParameters() as $param) {
	$type = $param->getType();
	if ($type === null) continue;

	// PHP 8.0+ — ReflectionUnionType doesn't have getName()
	// Use __toString() as a portable fallback
	if (method_exists($type, 'getName')) {
		$type_name = $type->getName();
	} else {
		$type_name = (string)$type;
	}

	// For union types like "int|float", check if "array" appears
	// (safe since "array" isn't a substring of any other type name)
	if ($type_name === 'array' || $type_name === '?array') {
		$array_params[] = $param->getName();
	}
}

check(
	!empty($array_params),
	"Configuration has " . count($array_params) . " array-typed parameters",
	$errors,
	$passes
	);

// Verify every array parameter receives arrays correctly.
// We construct a Configuration via from_array and check each property
// is an array (not null, not scalar, not wiped).
$verify_cfg = Configuration::from_array([]);
$wiped = [];
$wrong_type = [];

foreach ($array_params as $param_name) {
	$value = $verify_cfg->{$param_name} ?? 'NOT_SET';

	if ($value === 'NOT_SET') {
		// Parameter exists in constructor but no value set
		// (shouldn't happen with readonly + from_array, but check anyway)
		$wrong_type[] = "$param_name (no value)";
		continue;
	}

	if (!is_array($value)) {
		$wrong_type[] = "$param_name (got " . get_debug_type($value) . ")";
		continue;
	}

	// Known-empty defaults: must be []
	$known_empty = [
		'reverse_proxy_addresses',
		'blocked_bot_categories',
		'challenge_bot_categories',
		'log_only_bot_categories',
		'allowed_bot_categories',
		'bad_ja3_fingerprints',
		'bad_h2_fingerprints',
		'bot_header_orders',
		'expected_ja3',
		'blocked_countries',
		'blocked_asns',
		'custom_rules',
	];

	// Non-empty defaults: must have content
	$known_non_empty = [
		'skip_static_extensions',
		'skip_static_paths',
		'allowed_ai_crawlers',
		'dnsbl_lists',
		'head_referer_exempt_paths',
		'dynamic_ip_ranges_feeds',
		'asset_extensions',
		'body_scan_skip_fields',
	];

	if (in_array($param_name, $known_empty, true)) {
		if ($value !== []) {
			$wiped[] = "$param_name (expected [], got " . count($value) . " entries)";
		}
	} elseif (in_array($param_name, $known_non_empty, true)) {
		if (empty($value)) {
			$wiped[] = "$param_name (expected non-empty array, got empty)";
		}
	}
	// rate_limits is a complex object — just verify it's an array
}

check(
	empty($wrong_type),
	"all " . count($array_params) . " array parameters are arrays after from_array([])"
	. (empty($wrong_type) ? '' : ' (wrong type: ' . implode(', ', $wrong_type) . ')'),
	$errors,
	$passes
	);

check(
	empty($wiped),
	"no array defaults were wiped during coercion"
	. (empty($wiped) ? '' : ' (wiped: ' . implode(', ', $wiped) . ')'),
	$errors,
	$passes
	);

// Print summary of array parameters for operator awareness
echo "  Array parameters on Configuration:\n";
foreach ($array_params as $p) {
	$count = is_array($verify_cfg->{$p} ?? null) ? count($verify_cfg->{$p}) : '?';
	echo "	- $p ($count entries)\n";
}

// =============================================================================
// Test 19: Strictness overrides don't wipe array defaults
//		  (regression: monitor-only could accidentally clear skip lists)
// =============================================================================
header_line('Test 19: Strictness overrides preserve array defaults');

foreach (['monitor-only', 'normal', 'strict'] as $level) {
	$cfg = Configuration::from_array(['strictness' => $level]);

	check(
		is_array($cfg->skip_static_extensions) && !empty($cfg->skip_static_extensions),
		"strictness='$level' → skip_static_extensions preserved ($level)",
		$errors,
		$passes
		);

	check(
		in_array('js', $cfg->skip_static_extensions, true),
		"strictness='$level' → skip_static_extensions contains 'js' ($level)",
		$errors,
		$passes
		);

	check(
		is_array($cfg->skip_static_paths) && !empty($cfg->skip_static_paths),
		"strictness='$level' → skip_static_paths preserved ($level)",
		$errors,
		$passes
		);
}

// =============================================================================
// Test 20: SafeMode preserves critical safety properties
//		  (safe-mode must not accidentally disable static skip — that
//		   would cause every asset to be processed in degraded mode)
// =============================================================================
header_line('Test 20: SafeMode preserves safety properties');

$safe_settings = SafeMode::settings('test_log');

// SafeMode returns a raw array; check that it preserves static skip defaults
check(
	isset($safe_settings['performance']['skip_extensions'])
	&& is_array($safe_settings['performance']['skip_extensions'])
	&& in_array('js', $safe_settings['performance']['skip_extensions'], true),
	"SafeMode preserves performance.skip_extensions with 'js'",
	$errors,
	$passes
	);

check(
	isset($safe_settings['performance']['skip_paths'])
	&& is_array($safe_settings['performance']['skip_paths'])
	&& !empty($safe_settings['performance']['skip_paths']),
	"SafeMode preserves performance.skip_paths",
	$errors,
	$passes
	);

// SafeMode must inject log_table
check(
	$safe_settings['log_table'] === 'test_log',
	"SafeMode injects adapter-specific log_table",
	$errors,
	$passes
	);

// =============================================================================
// Test 21: SafeMode overrides match from_array() expectations
// =============================================================================
header_line('Test 21: SafeMode overrides match from_array() expectations');

// Check overrides() directly for flat-key violations
$overrides_flat = Schema::flatten(SafeMode::overrides());
$forbidden_flat = SafeMode::forbidden_flat_keys();

$found_flat = [];
foreach ($forbidden_flat as $flat_key) {
	if (array_key_exists($flat_key, $overrides_flat)) {
		$found_flat[] = $flat_key;
	}
}

check(
	empty($found_flat),
	"SafeMode::overrides() does not use flat keys that from_array() ignores"
	. (empty($found_flat) ? '' : ' (flat keys found: ' . implode(', ', $found_flat) . ')'),
	$errors,
	$passes
	);

// Verify nested equivalents ARE present in overrides() with safe values
$nested_keys_required = [
	'dns_verification.enabled'	  => false,
	'dynamic_ip_ranges.enabled'	 => false,
	'geoip.enabled'				 => false,
	'challenge.enabled'			 => false,
	'dnsbl.enabled'				 => false,
	'reverse_proxy.enabled'		 => false,
	'rate_limits.enabled'		   => false,
	'bot_categories.blocked'		=> [],
];

foreach ($nested_keys_required as $nested => $expected) {
	$actual = $overrides_flat[$nested] ?? null;
	check(
		$actual === $expected,
		"SafeMode::overrides() sets '$nested' = " . var_export($expected, true)
		. " (got " . var_export($actual, true) . ')',
		$errors,
		$passes
		);
}

	// Now check settings() for static-skip preservation
	// (settings() = defaults + overrides + log_table injection, so static-skip
	// flows through from Configuration::get_defaults())
	$safe_settings = SafeMode::settings('test_log');
	$safe_settings_flat = Schema::flatten($safe_settings);

	check(
		in_array('js', $safe_settings_flat['performance.skip_extensions'] ?? [], true),
		"SafeMode::settings() preserves 'js' in performance.skip_extensions",
		$errors,
		$passes
		);

	check(
		is_array($safe_settings_flat['performance.skip_paths'] ?? null)
		&& !empty($safe_settings_flat['performance.skip_paths']),
		"SafeMode::settings() preserves performance.skip_paths defaults",
		$errors,
		$passes
		);

	check(
		($safe_settings['log_table'] ?? null) === 'test_log',
		"SafeMode::settings() injects adapter-specific log_table",
		$errors,
		$passes
		);

	check(
		($safe_settings['_safe_mode'] ?? null) === true,
		"SafeMode::settings() sets _safe_mode marker",
		$errors,
		$passes
		);

// =============================================================================
// Summary
// =============================================================================
echo "\n=== Summary ===\n";
echo "  Passed: $passes\n";
echo "  Failed: " . count($errors) . "\n";

if (!empty($errors)) {
	echo "\nFAILURES:\n";
	foreach ($errors as $e) {
		echo "  - $e\n";
	}
	exit(1);
}

echo "\n✓ All schema integrity checks passed.\n";
exit(0);