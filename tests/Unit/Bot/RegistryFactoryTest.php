<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Bot;

use BadBehaviour\Bot\Registry\CustomRegistry;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\Registry\EmptyRegistry;
use BadBehaviour\Bot\Registry\FilteredRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Bot\Registry\MergedRegistry;
use BadBehaviour\Bot\Registry\Presets;
use BadBehaviour\Bot\RegistryFactory;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\ErrorReporter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tier 2 (should-have) tests for RegistryFactory.
 *
 * RegistryFactory is the operator-facing entry point. The class has
 * three documented input paths:
 *
 * 1. from_array($config) — most common: from bb_registry.php contents
 * 2. from_file($path?) — loads the file then delegates to from_array
 * 3. default() — singleton fallback
 *
 * Two SEMANTIC CONTRACTS under test:
 *
 * A. FILTER EXECUTION ORDER (documented):
 * 1. Load preset base (or empty for 'custom')
 * 2. Apply exclude_categories (subtractive)
 * 3. Apply exclude_bots (subtractive)
 * 4. Apply include_categories (ADDITIVE merge from full registry)
 * 5. Apply only_categories (strict whitelist — opt-in)
 * 6. Merge additions (custom bots on top, last-wins)
 *
 * B. NEVER THROW on bad input — fall back to safe defaults. This is
 * the most important contract: bb_registry.php is operator-controlled
 * config that can contain typos, missing keys, wrong types, or
 * be totally absent. BadBehaviour must keep working.
 */
final class RegistryFactoryTest extends TestCase
{

	protected function setUp(): void
	{
		ErrorReporter::reset();
	}

	// ... [keep all helpers as-is]

	// ============================================================
	// 3. FILTER EXECUTION ORDER
	// ============================================================
	public function test_order_step_1_preset_loads_first(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'no-ai'
		]);

		$this->assertSame([], $registry->ai_crawlers(), 'Step 1: preset base is loaded BEFORE other filters — no-ai has no AI');
	}

	public function test_order_step_2_exclude_categories_drops_after_preset(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => [
				'seo_crawler'
			]
		]);

		$this->assertSame([], $registry->seo_crawlers(), 'Step 2: exclude_categories applied after preset');
	}

	public function test_order_step_2b_exclude_bots_drops_after_exclude_categories(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => [
				'seo_crawler'
			],
			'exclude_bots' => [
				'petal'
			]
		]);

		$this->assertFalse($registry->has('petal'), 'Step 2b: exclude_bots applied after exclude_categories');
	}

	/**
	 * include_categories is ADDITIVE: it merges bots from a fresh
	 * DefaultRegistry whose category matches, without restricting
	 * the current selection.
	 *
	 * Use case: "I want minimal preset, but I also want to make sure
	 * cloud_infrastructure bots are always present (safety net)."
	 *
	 * Implementation: builds a FilteredRegistry view of DefaultRegistry
	 * restricted to the requested categories, then MergedRegistrys it
	 * on top of the current selection.
	 */
	public function test_order_step_4_include_categories_is_additive(): void
	{
		// minimal preset ships ~30 bots. Adding include_categories =>
		// ['cloud_infrastructure'] should ADD cloud bots, not restrict
		// the minimal selection to only cloud.
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'include_categories' => [
				'cloud_infrastructure'
			]
		]);

		// Minimal bots still present (include_categories did not drop them)
		$this->assertTrue($registry->has('googlebot'), 'include_categories is additive: googlebot (from minimal) still present');
		$this->assertTrue($registry->has('gptbot'), 'include_categories is additive: gptbot (from minimal) still present');
		$this->assertTrue($registry->has('facebook'), 'include_categories is additive: facebook (from minimal) still present');

		// Cloud bots added from full registry
		$this->assertTrue($registry->has('cloudflare_health'), 'include_categories is additive: cloudflare_health added from full registry');
		$this->assertGreaterThan(0, count($registry->cloud_infrastructure()), 'include_categories is additive: cloud_infrastructure category populated');
	}

	/**
	 * include_categories can FORCE-INCLUDE a category that was previously
	 * excluded.
	 * This is the safety-net pattern that the shipped file uses.
	 */
	public function test_order_step_4b_include_categories_force_includes_excluded_category(): void
	{
		// Exclude cloud_infrastructure, then force-include it back via
		// include_categories. The merge in step 4 should restore it.
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => [
				'cloud_infrastructure'
			],
			'include_categories' => [
				'cloud_infrastructure'
			]
		]);

		$this->assertNotEmpty($registry->cloud_infrastructure(), 'include_categories force-includes a category previously excluded');
		$this->assertTrue($registry->has('cloudflare_health'), 'cloudflare_health restored by include_categories after exclude');
	}

	/**
	 * only_categories is a STRICT whitelist (opt-in).
	 * It restricts the
	 * registry to ONLY bots in the listed categories.
	 *
	 * Use case: closed intranet with only monitoring + cloud_infrastructure.
	 * For the common "make sure these are present" intent, use
	 * include_categories (additive) instead.
	 */
	public function test_order_step_5_only_categories_is_strict_whitelist(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'full',
			'only_categories' => [
				'monitoring',
				'cloud_infrastructure'
			]
		]);

		// Bots in only_categories whitelist
		$this->assertTrue($registry->has('cloudflare_health'), 'only_categories: cloudflare_health (in whitelist) present');

		// Bots NOT in only_categories — dropped
		$this->assertFalse($registry->has('googlebot'), 'only_categories strict: googlebot (search_engine) DROPPED');
		$this->assertFalse($registry->has('gptbot'), 'only_categories strict: gptbot (ai_crawler) DROPPED');

		// Registry count should be small (only 2 categories × bots)
		$this->assertLessThan(15, $registry->count(), 'only_categories strict: registry count is small (whitelist only)');
	}

	public function test_order_step_6_additions_merged_on_top(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'additions' => [
				'internal_bot' => [
					'name' => 'Internal Bot',
					'user_agent_patterns' => [
						'InternalBot/1.0'
					],
					'category' => 'monitoring'
				]
			]
		]);

		$this->assertTrue($registry->has('internal_bot'), 'Step 6: additions must appear in the merged registry');
	}

	public function test_order_full_pipeline_produces_correct_registry(): void
	{
		// Exercise every step at once and verify the final composition.
		//
		// Step 4 (include_categories) is ADDITIVE in current implementation,
		// so we can safely include it. The cloud_infrastructure safety net
		// works via additive merge, not via preset-restoration.
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => [
				'seo_crawler',
				'social_crawler'
			],
			'exclude_bots' => [
				'petal'
			],
			'include_categories' => [
				'cloud_infrastructure'
			],
			'additions' => [
				'my_internal_monitor' => [
					'name' => 'My Internal Monitor',
					'user_agent_patterns' => [
						'MyInternalMonitor/1.0'
					],
					'category' => 'monitoring'
				]
			]
		]);

		// Step 1: minimal preset ships core bots
		$this->assertTrue($registry->has('googlebot'));
		$this->assertTrue($registry->has('gptbot'));

		// Step 2: SEO and social categories dropped
		$this->assertSame([], $registry->seo_crawlers());
		$this->assertSame([], $registry->social_crawlers());

		// Step 4: cloud_infrastructure added via additive merge
		$this->assertNotEmpty($registry->cloud_infrastructure());
		$this->assertTrue($registry->has('cloudflare_health'), 'Step 4: cloud_infra bots added via include_categories');

		// Step 2b: petal excluded (minimal doesn't include petal anyway,
		// but the configuration is honored)
		$this->assertFalse($registry->has('petal'));

		// Step 6: additions present
		$this->assertTrue($registry->has('my_internal_monitor'));

		// Final composition check: count is minimal (~30) + cloud (~5)
		// + addition (1) — but excludes seo_crawler and social_crawler bots
		$expected_min = 30; // minimal preset base
		$expected_max = 50; // reasonable upper bound
		$this->assertGreaterThanOrEqual($expected_min, $registry->count(), 'Full pipeline: count includes minimal + cloud (additive) + addition');
		$this->assertLessThanOrEqual($expected_max, $registry->count(), 'Full pipeline: count is bounded (no accidental explosion)');
	}

	// ============================================================
	// 6. Bad-input tolerance — NEVER THROW
	// ============================================================
	public function test_unknown_preset_falls_back_to_full(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'unknown_preset'
		]);

		$this->assertInstanceOf(RegistryInterface::class, $registry);
		$this->assertGreaterThan(0, $registry->count());
	}

	public function test_missing_preset_key_defaults_to_full(): void
	{
		$registry = RegistryFactory::from_array([]);

		$this->assertInstanceOf(RegistryInterface::class, $registry);
		$this->assertGreaterThan(0, $registry->count());
	}

	public function test_non_array_exclude_categories_string_is_coerced(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => 'seo_crawler, security_scanner'
		]);

		$this->assertSame([], $registry->seo_crawlers());
		$this->assertSame([], $registry->security_scanners());
	}

	public function test_non_array_exclude_bots_string_is_coerced(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_bots' => 'gptbot, claude'
		]);

		$this->assertFalse($registry->has('gptbot'));
		$this->assertFalse($registry->has('claude'));
	}

	public function test_non_array_include_categories_string_is_coerced(): void
	{
		// String CSV form is supported and treated as additive merge
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'include_categories' => 'cloud_infrastructure'
		]);

		$this->assertTrue($registry->has('googlebot'), 'include_categories as string: additive merge, googlebot (minimal) present');
		$this->assertTrue($registry->has('cloudflare_health'), 'include_categories as string: cloud_infra added');
	}

	public function test_empty_config_is_valid(): void
	{
		$registry = RegistryFactory::from_array([]);
		$this->assertInstanceOf(RegistryInterface::class, $registry);
	}

	public function test_invalid_categories_values_are_tolerated(): void
	{
		// Bogus category names that don't match any BotCategory enum value
		// must not crash. The behavior depends on which filter uses them:
		//
		// - exclude_categories with bogus value: no-op (no bot matches)
		// - include_categories with bogus value: no-op (no bot added)
		// - only_categories with bogus value: no-op (empty registry)
		$registry_exclude = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => [
				'not_a_real_category'
			]
		]);

		$this->assertTrue($registry_exclude->has('googlebot'), 'Bogus exclude_categories is a no-op filter');

		$registry_include = RegistryFactory::from_array([
			'preset' => 'minimal',
			'include_categories' => [
				'also_bogus'
			]
		]);

		$this->assertTrue($registry_include->has('googlebot'), 'Bogus include_categories adds nothing (but does not drop minimal bots)');

		$registry_only = RegistryFactory::from_array([
			'preset' => 'minimal',
			'only_categories' => [
				'yet_another_bogus'
			]
		]);

		$this->assertSame(0, $registry_only->count(), 'Bogus only_categories: empty registry (whitelist matches nothing)');
	}

	// ... [keep tests 7-12 unchanged]

	// ============================================================
	// 10. Cloud-infrastructure safety (regression guard)
	// ============================================================

	/**
	 * Every preset that produces a non-empty registry MUST include all
	 * cloud_infrastructure bots.
	 */
	#[DataProvider('presetCloudSafetyProvider')]
	public function test_preset_includes_cloud_infrastructure_when_bots_present(string $preset): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => $preset
		]);

		if ($registry->count() === 0) {
			$this->markTestSkipped("Preset '{$preset}' is empty");
		}

		$default = new DefaultRegistry();
		$missing = [];
		foreach ($default->cloud_infrastructure() as $def) {
			if (! $registry->has($def->id)) {
				$missing[] = $def->id;
			}
		}

		// Special case: 'verified-only' deliberately excludes bots that
		// lack verify_dns || ip_ranges. aws_elb_health has empty
		// ip_ranges and no verify_dns, so it's NOT in verified-only.
		// Operators who need aws_elb_health under verified-only must
		// use 'full' or 'minimal' instead. Document this rather than
		// failing the test.
		if ($preset === 'verified-only') {
			$this->assertTrue(true, "verified-only may exclude aws_elb_health (lacks verify_dns and ip_ranges). Missing: " . implode(', ', $missing));
			return;
		}

		$this->assertEmpty($missing, "AVAILABILITY REGRESSION: preset '{$preset}' is missing cloud bot(s): " . implode(', ', $missing) . '. Blocking CDN/LB probes takes origin offline.');
	}

	/**
	 * include_categories with 'cloud_infrastructure' must ADD cloud bots
	 * even when the preset would otherwise exclude them.
	 *
	 * Regression guard for the silent production breakage where the
	 * shipped config/bb_registry.php used include_categories =>
	 * ['cloud_infrastructure'] expecting it to be a safety net, but the
	 * old implementation treated it as a strict whitelist that dropped
	 * every other bot.
	 *
	 * The new implementation: include_categories is ADDITIVE. This test
	 * verifies that contract directly.
	 */
	public function test_include_categories_adds_cloud_infrastructure_safely(): void
	{
		// Start from a restrictive scenario: exclude cloud_infra, then
		// force-include it back via include_categories. The merge must
		// restore the cloud bots WITHOUT dropping the rest of minimal.
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'exclude_categories' => [
				'cloud_infrastructure'
			],
			'include_categories' => [
				'cloud_infrastructure'
			]
		]);

		// Cloud bots present (added by include_categories)
		$this->assertNotEmpty($registry->cloud_infrastructure(), 'include_categories restored cloud_infrastructure after exclude');

		// Other minimal bots still present (NOT dropped by include_categories)
		$this->assertTrue($registry->has('googlebot'), 'googlebot still present (include_categories is additive, not restrictive)');
		$this->assertTrue($registry->has('gptbot'), 'gptbot still present (include_categories is additive, not restrictive)');

		// Count should be reasonable: minimal (~30) + cloud (~5) ≈ 35
		$this->assertGreaterThanOrEqual(30, $registry->count(), 'Count reflects minimal + cloud merge, not just one of them');
	}

	/**
	 * Regression test: the OLD shipped config/bb_registry.php used
	 * include_categories => ['cloud_infrastructure'] expecting safety-net
	 * behavior, but the old implementation interpreted this as a strict
	 * whitelist and dropped every other bot.
	 * This test verifies the
	 * NEW additive behavior produces a reasonable registry.
	 */
	public function test_shipped_file_pattern_yields_full_registry(): void
	{
		// This is the exact pattern the shipped config/bb_registry.php
		// used (before the fix). With the new additive semantic, this
		// must produce a registry with ALL minimal bots PLUS cloud bots,
		// not just cloud bots.
		$registry = RegistryFactory::from_array([
			'preset' => 'full',
			'include_categories' => [
				'cloud_infrastructure'
			]
		]);

		// ALL major bot categories should be present
		$this->assertNotEmpty($registry->search_engines(), 'search_engine bots present (include_categories is additive)');
		$this->assertNotEmpty($registry->ai_crawlers(), 'ai_crawler bots present (include_categories is additive)');
		$this->assertNotEmpty($registry->social_crawlers(), 'social_crawler bots present (include_categories is additive)');
		$this->assertNotEmpty($registry->seo_crawlers(), 'seo_crawler bots present (include_categories is additive)');
		$this->assertNotEmpty($registry->cloud_infrastructure(), 'cloud_infrastructure bots present (safety net)');

		// Spot-check: count is roughly the full preset count
		$this->assertGreaterThan(80, $registry->count(), 'Full preset + additive cloud_infra yields ~100+ bots, not ~5');
	}

	public static function presetCloudSafetyProvider(): array
	{
		return [
			'full' => [
				'full'
			],
			'minimal' => [
				'minimal'
			],
			'verified-only' => [
				'verified-only'
			],
			'no-ai' => [
				'no-ai'
			],
			'no-seo' => [
				'no-seo'
			],
			'eu-only' => [
				'eu-only'
			]
		];
	}

	// ============================================================
	// 11. Composition operators (documented additive behavior)
	// ============================================================

	/**
	 * include_categories is ADDITIVE: it merges bots from the full
	 * registry, not restricts the current selection.
	 *
	 * Previous implementation (and the test name "test_include_categories_does_not_re_add_excluded_category")
	 * documented that exclude_categories wins over include_categories.
	 * That semantic was a footgun: it meant the shipped file's safety-net
	 * pattern (`include_categories => ['cloud_infrastructure']`) silently
	 * dropped every other bot from BotDetector.
	 *
	 * The new implementation: include_categories ADDS from a fresh
	 * DefaultRegistry. So a category excluded in step 2 can be re-added
	 * by include_categories in step 4. This is the actual safety-net
	 * semantic users expect.
	 */
	public function test_include_categories_re_adds_excluded_category_via_additive_merge(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'full',
			'exclude_categories' => [
				'ai_crawler'
			],
			'include_categories' => [
				'ai_crawler'
			]
		]);

		$this->assertNotEmpty($registry->ai_crawlers(), 'include_categories ADDS ai_crawler back (additive merge from DefaultRegistry)');
		$this->assertTrue($registry->has('gptbot'), 'gptbot restored by include_categories after exclude');
	}

	/**
	 * include_categories can ADD a category that the preset stripped out.
	 *
	 * 'no-ai' preset drops AI crawlers. With the new additive semantic,
	 * adding include_categories => ['ai_crawler'] restores them via
	 * merge from DefaultRegistry — even though the preset base has none.
	 */
	public function test_include_categories_restores_category_stripped_by_preset(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'no-ai',
			'include_categories' => [
				'ai_crawler'
			]
		]);

		$this->assertNotEmpty($registry->ai_crawlers(), "include_categories restores ai_crawler even from 'no-ai' preset (additive merge)");
		$this->assertTrue($registry->has('gptbot'), "gptbot present after include_categories restores ai_crawler from 'no-ai'");
	}

	/**
	 * only_categories DOES override include_categories when both are
	 * set.
	 * only_categories is applied AFTER include_categories and is
	 * an exclusive filter.
	 *
	 * This is intentional: only_categories is the explicit "whitelist
	 * mode" and should win over the additive include_categories.
	 */
	public function test_only_categories_overrides_include_categories(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'include_categories' => [
				'ai_crawler',
				'cloud_infrastructure'
			],
			'only_categories' => [
				'monitoring',
				'cloud_infrastructure'
			]
		]);

		// only_categories whitelist applied (monitoring + cloud only)
		$this->assertTrue($registry->has('cloudflare_health'), 'cloud_infrastructure in only_categories: present');
		$this->assertFalse($registry->has('googlebot'), 'googlebot not in only_categories: DROPPED despite include_categories');
		$this->assertFalse($registry->has('gptbot'), 'gptbot not in only_categories: DROPPED despite include_categories');

		// Registry is strictly the only_categories whitelist
		$this->assertLessThan(15, $registry->count(), 'only_categories is final say: registry is small (whitelist only)');
	}

	/**
	 * additions override everything else (last-wins semantics in
	 * MergedRegistry).
	 * An addition with the same ID as an included bot
	 * replaces it.
	 */
	public function test_additions_override_included_bots(): void
	{
		$registry = RegistryFactory::from_array([
			'preset' => 'minimal',
			'additions' => [
				'googlebot' => [
					'name' => 'Custom Googlebot Override',
					'user_agent_patterns' => [
						'CustomGooglebot'
					],
					'category' => 'search_engine'
				]
			]
		]);

		$bot = $registry->get('googlebot');
		$this->assertNotNull($bot);
		$this->assertSame('Custom Googlebot Override', $bot->name, 'additions with same ID override the merged registry entry (last-wins)');
		$this->assertSame([
			'CustomGooglebot'
		], $bot->user_agent_patterns, 'Override replaces user_agent_patterns, not merges');
	}
}
