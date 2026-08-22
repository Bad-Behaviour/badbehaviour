<?php
// tests/Unit/Config/SchemaTest.php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Config;

use BadBehaviour\Config\Schema;
use BadBehaviour\Configuration;
use BadBehaviour\Util\SafeMode;
use PHPUnit\Framework\TestCase;

class SchemaTest extends TestCase
{

	// =====================================================================
	// flatten() / nest() — round-trip
	// =====================================================================

	/**
	 * flatten() converts nested array to dotted-key form.
	 * ['a' => ['b' => 1]] → ['a.b' => 1]
	 */
	public function test_flatten_converts_nested_to_dotted(): void
	{
		$nested = [
			'a' => [
				'b' => 1,
				'c' => 2
			],
			'd' => 'simple'
		];

		$flat = Schema::flatten($nested);

		$this->assertSame(1, $flat['a.b']);
		$this->assertSame(2, $flat['a.c']);
		$this->assertSame('simple', $flat['d']);
	}

	/**
	 * nest() converts dotted-key form back to nested.
	 * ['a.b' => 1] → ['a' => ['b' => 1]]
	 */
	public function test_nest_converts_dotted_to_nested(): void
	{
		$flat = [
			'a.b' => 1,
			'a.c' => 2,
			'd' => 'simple'
		];

		$nested = Schema::nest($flat);

		$this->assertSame(1, $nested['a']['b']);
		$this->assertSame(2, $nested['a']['c']);
		$this->assertSame('simple', $nested['d']);
	}

	/**
	 * flatten() and nest() are inverses: flatten(nest(x)) === x
	 * for any well-formed input.
	 */
	public function test_flatten_and_nest_are_inverses(): void
	{
		$original = [
			'a' => [
				'b' => [
					'c' => 'deep'
				]
			],
			'simple' => 'value',
			'list' => [
				1,
				2,
				3
			]
		];

		$round_trip = Schema::nest(Schema::flatten($original));

		$this->assertSame($original, $round_trip);
	}

	/**
	 * flatten() must handle lists (numeric-keyed arrays) — they stay
	 * as values at the parent level, NOT recursed into dotted keys.
	 */
	public function test_flatten_preserves_lists_at_parent_level(): void
	{
		$nested = [
			'ai_crawlers' => [
				'allowed' => [
					'GPTBot',
					'ClaudeBot'
				] // list
			]
		];

		$flat = Schema::flatten($nested);

		$this->assertArrayHasKey('ai_crawlers.allowed', $flat);
		$this->assertSame([
			'GPTBot',
			'ClaudeBot'
		], $flat['ai_crawlers.allowed']);
	}

	/**
	 * flatten() with empty array must not recurse into empty parents.
	 * ['a' => []] → ['a' => []] (not ['a.0' => null])
	 */
	public function test_flatten_handles_empty_arrays(): void
	{
		$nested = [
			'a' => [],
			'b' => [
				'c' => 1
			]
		];

		$flat = Schema::flatten($nested);

		$this->assertArrayHasKey('a', $flat);
		$this->assertSame([], $flat['a']);
		$this->assertArrayHasKey('b.c', $flat);
	}

	// =====================================================================
	// known_keys() / unknown_keys()
	// =====================================================================

	/**
	 * known_keys() returns every dotted key in KEY_MAP.
	 */
	public function test_known_keys_returns_all_map_keys(): void
	{
		$known = Schema::known_keys();

		$this->assertIsArray($known);
		$this->assertNotEmpty($known);
		$this->assertGreaterThan(50, count($known), 'must have substantial key count');

		// Spot-check: critical keys must be present
		$this->assertContains('preset', $known);
		$this->assertContains('strictness', $known);
		$this->assertContains('dns_verification.enabled', $known);
		$this->assertContains('bot_categories.blocked', $known);
	}

	/**
	 * unknown_keys() finds dotted keys not in KEY_MAP (typo detection).
	 */
	public function test_unknown_keys_finds_typos(): void
	{
		$flat = [
			'preset' => 'minimal', // valid
			'strictness' => 'normal', // valid
			'dynamc_ip_ranges.enabled' => true, // typo
			'dns_verfiction.enabled' => false // typo
		];

		$unknown = Schema::unknown_keys($flat);

		$this->assertContains('dynamc_ip_ranges.enabled', $unknown);
		$this->assertContains('dns_verfiction.enabled', $unknown);
		$this->assertNotContains('preset', $unknown);
		$this->assertNotContains('strictness', $unknown);
	}

	/**
	 * unknown_keys() returns empty for valid config.
	 */
	public function test_unknown_keys_empty_for_valid_config(): void
	{
		$flat = Schema::flatten(Configuration::get_defaults());
		$unknown = Schema::unknown_keys($flat);

		$this->assertEmpty($unknown, 'get_defaults() flattened must produce zero unknown keys. Got: ' . implode(', ', $unknown));
	}

	/**
	 * unknown_keys() does not include internal/private keys that are
	 * intentionally not in KEY_MAP (like '_safe_mode').
	 */
	public function test_unknown_keys_handles_internal_markers(): void
	{
		$flat = [
			'_safe_mode' => true
		];

		$unknown = Schema::unknown_keys($flat);

		$this->assertContains('_safe_mode', $unknown, '_safe_mode is not in KEY_MAP (correctly — it is internal)');
	}

	// =====================================================================
	// property_for()
	// =====================================================================

	/**
	 * property_for() returns the constructor property name for a
	 * known dotted key.
	 */
	public function test_property_for_returns_property_name(): void
	{
		$this->assertSame('preset', Schema::property_for('preset'));
		$this->assertSame('logging', Schema::property_for('logging'));
		$this->assertSame('dns_verification_enabled', Schema::property_for('dns_verification.enabled'));
		$this->assertSame('reverse_proxy', Schema::property_for('reverse_proxy.enabled'));
	}

	/**
	 * property_for() returns null for collapsible sub-keys — they
	 * collapse into a parent array property, not a constructor param.
	 */
	public function test_property_for_returns_null_for_collapsible(): void
	{
		// bot_categories.* are collapsible
		$this->assertNull(Schema::property_for('bot_categories.blocked'), 'bot_categories.blocked is collapsible (collapses into bot_categories array)');
		$this->assertNull(Schema::property_for('bot_categories.allowed'), 'bot_categories.allowed is collapsible');

		// rate_limits.* sub-keys are collapsible (into rate_limits array)
		$this->assertNull(Schema::property_for('rate_limits.global.requests'), 'rate_limits.global.requests is collapsible');

		// geoip.blocked_* are collapsible
		$this->assertNull(Schema::property_for('geoip.blocked_countries'), 'geoip.blocked_countries is collapsible');
	}

	/**
	 * property_for() returns null for unknown keys.
	 */
	public function test_property_for_returns_null_for_unknown(): void
	{
		$this->assertNull(Schema::property_for('not.a.real.key'));
		$this->assertNull(Schema::property_for('dynamc_ip_ranges.enabled'));
	}

	// =====================================================================
	// Schema completeness — every nested default key must be in KEY_MAP
	// =====================================================================

	/**
	 * Every dotted key reachable from Configuration::get_defaults()
	 * must be in Schema::KEY_MAP (unless it's a known internal key).
	 *
	 * This is the architectural invariant: if you add a default value
	 * to get_defaults(), you MUST add the corresponding key to KEY_MAP,
	 * or from_array() will not know how to process it.
	 */
	public function test_all_default_keys_are_in_schema(): void
	{
		$known = Schema::known_keys();
		$defaults_flat = Schema::flatten(Configuration::get_defaults());

		// Keys that exist in defaults but are intentionally NOT in schema
		// (injected dependencies, not user-facing config)
		$injected = [
			'adapter',
			'logger',
			'cache',
			'geoip',
			'log_table'
		];

		$missing = [];
		foreach (array_keys($defaults_flat) as $dotted) {
			if (in_array($dotted, $injected, true))
				continue;
			if (! in_array($dotted, $known, true)) {
				$missing[] = $dotted;
			}
		}

		$this->assertEmpty($missing, 'All default keys must be in Schema::KEY_MAP. Missing: ' . implode(', ', $missing));
	}

	/**
	 * Every key in strictness_overrides() must be in Schema::KEY_MAP.
	 * Catches the flat/nested mismatch regression class.
	 */
	public function test_strictness_override_keys_in_schema(): void
	{
		$known = Schema::known_keys();

		foreach ([
			'monitor-only',
			'normal',
			'strict'
		] as $level) {
			$overrides = Schema::flatten(Configuration::strictness_overrides($level));
			$unknown = [];

			foreach (array_keys($overrides) as $dotted) {
				if (! in_array($dotted, $known, true)) {
					$unknown[] = $dotted;
				}
			}

			$this->assertEmpty($unknown, "strictness_overrides('$level') must use known schema keys. " . 'Unknown: ' . implode(', ', $unknown));
		}
	}

	/**
	 * Every key in SafeMode::overrides() must be in Schema::KEY_MAP,
	 * except internal markers like _safe_mode.
	 */
	public function test_safemode_override_keys_in_schema(): void
	{
		$known = Schema::known_keys();
		$safe_flat = Schema::flatten(SafeMode::overrides());

		$unknown = [];
		foreach (array_keys($safe_flat) as $dotted) {
			// _safe_mode is internal
			if ($dotted === '_safe_mode')
				continue;
			if (! in_array($dotted, $known, true)) {
				$unknown[] = $dotted;
			}
		}

		$this->assertEmpty($unknown, 'SafeMode::overrides() must use known schema keys. ' . 'Unknown: ' . implode(', ', $unknown));
	}

	// =====================================================================
	// is_list() helper (private, but testable via flatten behavior)
	// =====================================================================

	/**
	 * Lists (numeric keys 0..n) must be preserved as values, not
	 * recursed into individual dotted keys.
	 */
	public function test_lists_in_nested_values_are_preserved(): void
	{
		$nested = [
			'dnsbl' => [
				'lists' => [
					'zen.spamhaus.org',
					'bl.spamcop.net'
				] // list
			],
			'blocked_bot_categories' => [
				'malicious',
				'seo_crawler'
			] // list at top
		];

		$flat = Schema::flatten($nested);

		$this->assertSame([
			'zen.spamhaus.org',
			'bl.spamcop.net'
		], $flat['dnsbl.lists'], 'list inside nested section must be preserved as value');
		$this->assertArrayHasKey('blocked_bot_categories', $flat, 'top-level list must stay at parent (not become blocked_bot_categories.0)');
		$this->assertArrayNotHasKey('blocked_bot_categories.0', $flat, 'list elements must NOT become individual dotted keys');
	}
}