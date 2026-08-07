<?php
/**
 * Bad Behaviour 3.0 — Diagnostics + Smoke Test
 *
 * Dumps the effective library state and verifies that Configuration
 * round-trips all four bot_categories sub-keys correctly.
 *
 * Usage:
 *   php bin/diagnose.php
 *
 * Exit codes:
 *   0 — All checks passed
 *   1 — Smoke test failed (configuration did not round-trip as expected)
 *
 * Output sections:
 *   1. Smoke test: bot_categories round-trip (Option A verification)
 *   2. Library diagnostics: safe_mode, monitor-only, active detectors, etc.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;

// ============================================================================
// 1. SMOKE TEST: bot_categories round-trip (Option A verification)
// ============================================================================
//
// Verifies that all four documented sub-keys actually persist from input
// config → Configuration properties → to_array() output. Prior to Option A
// only `blocked[]` was read; `challenge[]`, `log_only[]`, and `allowed[]`
// were silently dropped on parse.

echo "=== Smoke Test: bot_categories round-trip ===\n";

$adapter = new GenericAdapter();

$config = Configuration::from_array([
	'preset'         => 'full',
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

$all_passed = true;
foreach ($expected as $key => $want) {
	$got = $actual[$key];
	$passed = ($got === $want);
	$marker = $passed ? '✓' : '✗';
	echo sprintf(
		"  %s %-10s expected=%s  got=%s\n",
		$marker,
		$key . ':',
		json_encode($want),
		json_encode($got)
		);
	if (!$passed) {
		$all_passed = false;
	}
}

// Also verify to_array() round-trip — what you put in must come back out
$round_tripped = $config->to_array()['bot_categories'] ?? [];
foreach ($expected as $key => $want) {
	$got = $round_tripped[$key] ?? null;
	$passed = ($got === $want);
	$marker = $passed ? '✓' : '✗';
	echo sprintf(
		"  %s to_array  %-7s expected=%s  got=%s\n",
		$marker,
		$key . ':',
		json_encode($want),
		json_encode($got)
		);
	if (!$passed) {
		$all_passed = false;
	}
}

if ($all_passed) {
	echo "\n  ✓ All 4 sub-keys round-tripped correctly\n\n";
} else {
	echo "\n  ✗ FAIL: Configuration is dropping documented keys. "
		. "Re-apply Option A changes to src/Configuration.php.\n\n";
}

echo "=== Smoke Test: BotDetector::determine_action() honors overrides ===\n";

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Detection\BotDetector;

// Build a minimal test registry with one bot per category we want to test
$registry = new InMemoryRegistry([
	'test_malicious'   => new BotDefinition(
		id: 'test_malicious', name: 'Test Malicious',
		user_agent_patterns: ['TestMalicious'], host_patterns: [],
		ip_ranges: [], category: BotCategory::MALICIOUS,
		default_action: BotAction::ALLOW, // would normally allow — but blocked[] overrides
		),
	'test_social'      => new BotDefinition(
		id: 'test_social', name: 'Test Social',
		user_agent_patterns: ['TestSocial'], host_patterns: [],
		ip_ranges: [], category: BotCategory::SOCIAL_CRAWLER,
		default_action: BotAction::ALLOW, // would normally allow — but challenge[] overrides
		),
	'test_security'    => new BotDefinition(
		id: 'test_security', name: 'Test Security',
		user_agent_patterns: ['TestSecurity'], host_patterns: [],
		ip_ranges: [], category: BotCategory::SECURITY_SCANNER,
		default_action: BotAction::BLOCK, // would normally block — but log_only[] overrides
		),
	'test_cloud'       => new BotDefinition(
		id: 'test_cloud', name: 'Test Cloud Infra',
		user_agent_patterns: ['TestCloud'], host_patterns: [],
		ip_ranges: [], category: BotCategory::CLOUD_INFRASTRUCTURE,
		default_action: BotAction::BLOCK, // should be IGNORED — safety override wins
		),
]);

$detector = new BotDetector($config, $adapter, $registry);

// Use reflection to call the private determine_action() method
$reflection = new ReflectionMethod(BotDetector::class, 'determine_action');
$reflection->setAccessible(true);

$cases = [
	['test_malicious',  BotAction::BLOCK,    'blocked[]   overrides ALLOW'],
	['test_social',     BotAction::CHALLENGE,'challenge[] overrides ALLOW'],
	['test_security',   BotAction::LOG_ONLY, 'log_only[]  overrides BLOCK'],
	['test_cloud',      BotAction::ALLOW,    'CLOUD_INFRASTRUCTURE safety override ALWAYS wins'],
];

$runtime_passed = true;
foreach ($cases as [$bot_id, $expected_action, $description]) {
	$def = $registry->get($bot_id);
	$actual_action = $reflection->invoke($detector, $def, false);
	$passed = ($actual_action === $expected_action);
	$marker = $passed ? '✓' : '✗';
	echo sprintf(
		"  %s %-15s expected=%-9s got=%-9s (%s)\n",
		$marker,
		$bot_id . ':',
		$expected_action->value,
		$actual_action->value,
		$description
		);
	if (!$passed) {
		$runtime_passed = false;
	}
}

if (!$runtime_passed) {
	$all_passed = false;
	echo "\n  ✗ FAIL: BotDetector::determine_action() is not honoring overrides.\n";
	echo "    Re-apply Option A changes to src/Detection/BotDetector.php.\n\n";
}

// ============================================================================
// 2. Library diagnostics: full state dump
// ============================================================================

echo "=== Library Diagnostics ===\n";

// Use the bb_config.php if present, otherwise fall back to defaults
$config_path = __DIR__ . '/../config/bb_config.php';
$diag_adapter = new GenericAdapter();

// ALWAYS trigger adapter's config tracking — even if file is missing,
// this populates is_safe_mode() / is_config_loaded() correctly.
$adapter_settings = $diag_adapter->get_settings();

// Merge user config over adapter settings (preserves log_table etc.)
$user_config = [];
if (file_exists($config_path)) {
	$user_config = require $config_path;
	if (!is_array($user_config)) {
		$user_config = [];
	}
}
$merged = array_merge($adapter_settings, $user_config);

$diag_config = Configuration::from_array($merged, $diag_adapter);
$bb          = new BadBehaviour($diag_config);

echo json_encode($bb->diagnostics(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

exit($all_passed ? 0 : 1);
