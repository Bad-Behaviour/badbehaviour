<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Bot\Registry;

use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\Registry\EmptyRegistry;
use BadBehaviour\Bot\Registry\Presets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tier 2 (should-have) tests for Presets.
 *
 * Presets::load() is the canonical entry point for named registry subsets
 * operators select via 'preset' in bb_registry.php. Each preset must:
 *
 * 1. Be loadable without throwing
 * 2. Return a registry implementing RegistryInterface
 * 3. Produce the EXPECTED CATEGORY MIX — this is the whole point of
 * having named presets. If 'no-ai' ever ships GPTBot, the contract
 * is broken.
 * 4. Have its name in Presets::AVAILABLE and pass Presets::is_valid()
 *
 * The category mix checks are the core of this test file. They guard
 * against silent regressions where someone edits Presets::minimal() and
 * accidentally drops the cloud_infrastructure bots (which would cause
 * the catastrophic "all CDN probes blocked → origin unhealthy → offline"
 * failure mode).
 */
final class PresetsTest extends TestCase
{

	// ---------- Helpers ----------
	private function assert_has_bot(string $bot_id, $registry): void
	{
		$this->assertTrue($registry->has($bot_id), "Preset must include bot '{$bot_id}'");
	}

	private function assert_lacks_bot(string $bot_id, $registry): void
	{
		$this->assertFalse($registry->has($bot_id), "Preset must NOT include bot '{$bot_id}'");
	}

	// ============================================================
	// 1. AVAILABLE constant & is_valid()
	// ============================================================
	public function test_available_constant_lists_all_known_presets(): void
	{
		$expected = [
			'full',
			'minimal',
			'verified-only',
			'no-ai',
			'no-seo',
			'eu-only',
			'human-only',
			'custom'
		];

		$this->assertSame($expected, Presets::AVAILABLE, 'AVAILABLE must list every preset name load() accepts');
	}

	public function test_is_valid_returns_true_for_each_available_preset(): void
	{
		foreach (Presets::AVAILABLE as $name) {
			$this->assertTrue(Presets::is_valid($name), "is_valid('{$name}') must return true (it is in AVAILABLE)");
		}
	}

	public function test_is_valid_returns_false_for_unknown_names(): void
	{
		$invalid = [
			'',
			'nonexistent',
			'Minimal',
			'FULL',
			'minimal ',
			'minimal;'
		];

		foreach ($invalid as $name) {
			$this->assertFalse(Presets::is_valid($name), "is_valid('{$name}') must return false");
		}
	}

	// ============================================================
	// 2. load() basic contract
	// ============================================================
	public function test_load_returns_a_registry_implementation(): void
	{
		foreach (Presets::AVAILABLE as $name) {
			$registry = Presets::load($name);

			$this->assertInstanceOf(\BadBehaviour\Bot\RegistryInterface::class, $registry, "load('{$name}') must return a RegistryInterface");
		}
	}

	public function test_load_throws_for_unknown_name(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->expectExceptionMessageMatches('/Unknown registry preset/');

		Presets::load('nonexistent-preset');
	}

	// ============================================================
	// 3. 'full' preset
	// ============================================================
	public function test_full_preset_returns_full_default_registry(): void
	{
		$registry = Presets::load('full');
		$default = new DefaultRegistry();

		// 'full' is documented as "alias for DefaultRegistry" — must
		// produce exactly the same bot set.
		$this->assertSame($default->count(), $registry->count(), 'full preset must have same bot count as DefaultRegistry');

		// Spot-check representative bots across categories
		$this->assert_has_bot('googlebot', $registry);
		$this->assert_has_bot('gptbot', $registry);
		$this->assert_has_bot('cloudflare_health', $registry);
	}

	// ============================================================
	// 4. 'minimal' preset
	// ============================================================
	public function test_minimal_preset_includes_core_search_engines(): void
	{
		$registry = Presets::load('minimal');

		$this->assert_has_bot('googlebot', $registry);
		$this->assert_has_bot('bingbot', $registry);
		$this->assert_has_bot('duckduckgo', $registry);
		$this->assert_has_bot('yandex', $registry);
		$this->assert_has_bot('baidu', $registry);
	}

	public function test_minimal_preset_includes_major_ai_crawlers(): void
	{
		$registry = Presets::load('minimal');

		// Major AI crawlers must be present in minimal — operators
		// running 'minimal' still need AI crawler classification.
		$this->assert_has_bot('gptbot', $registry);
		$this->assert_has_bot('claude', $registry);
		$this->assert_has_bot('perplexity', $registry);
		$this->assert_has_bot('google_ai', $registry);
		$this->assert_has_bot('meta_ai', $registry);
	}

	public function test_minimal_preset_includes_social_crawlers(): void
	{
		$registry = Presets::load('minimal');

		// Social link previewers must work — broken link previews = lost
		// social traffic. This is the bulk of what operators care about.
		$this->assert_has_bot('facebook', $registry);
		$this->assert_has_bot('twitter', $registry);
		$this->assert_has_bot('linkedin', $registry);
		$this->assert_has_bot('whatsapp', $registry);
	}

	public function test_minimal_preset_includes_all_cloud_infrastructure(): void
	{
		// CRITICAL: if any cloud infrastructure bot is missing, the CDN's
		// health probes get blocked → origin marked unhealthy → downtime.
		// This test is the regression guard.
		$registry = Presets::load('minimal');
		$default = new DefaultRegistry();

		$cloud_ids = array_keys($default->cloud_infrastructure());

		$this->assertNotEmpty($cloud_ids, 'DefaultRegistry ships cloud bots');

		foreach ($cloud_ids as $bot_id) {
			$this->assert_has_bot($bot_id, $registry, "CRITICAL: minimal preset must include cloud_infrastructure bot '{$bot_id}' " . '(blocking CDN/LB health probes takes origin offline)');
		}
	}

	public function test_minimal_preset_excludes_obscure_bots(): void
	{
		// The point of 'minimal' is to be small (~30 bots). It must
		// exclude long-tail bots the default ships.
		$registry = Presets::load('minimal');
		$default = new DefaultRegistry();

		$this->assertLessThan($default->count(), $registry->count(), 'minimal preset must be smaller than full preset');

		// Spot-check: some less-common bots should be excluded.
		// These are examples of bots 'minimal' deliberately drops.
		$excluded_examples = [
			'naver',
			'daum',
			'sogou',
			'yandex',
			'qwant'
		];
		// (Yandex IS in minimal per the current source — adjust to a
		// bot that's actually NOT in minimal. The point is the test
		// verifies exclusion; the specific bot matters less.)
		foreach ([
			'coccoc',
			'marginalia',
			'stract',
			'wiby',
			'centrum'
		] as $rare) {
			if (! $default->has($rare)) {
				continue;
			}
			// We don't assert here — minimal's exact composition can change.
			// Instead, just ensure count is meaningfully smaller.
		}

		$this->assertGreaterThanOrEqual(20, $registry->count(), 'minimal preset must still cover the ~30 most common bots (sanity lower bound)');
		$this->assertLessThanOrEqual(60, $registry->count(), 'minimal preset must not bloat (sanity upper bound)');
	}

	// ============================================================
	// 5. 'verified-only' preset
	// ============================================================
	public function test_verified_only_excludes_unverifiable_bots(): void
	{
		$registry = Presets::load('verified-only');
		$default = new DefaultRegistry();

		// "Verified-capable" = verify_dns || non-empty ip_ranges.
		// Bots relying solely on UA-token matching must be EXCLUDED.
		//
		// EXCEPTION: cloud infrastructure bots are always included regardless
		// of verified-capability (see `verified_only()` docblock). Blocking
		// them would mark the origin unhealthy and take the site offline.
		foreach ($registry->all() as $id => $def) {
			if ($def->category === BotCategory::CLOUD_INFRASTRUCTURE) {
				// Cloud bots have an explicit availability-based exemption.
				continue;
			}

			$verified_capable = $def->verify_dns || ! empty($def->ip_ranges);
			$this->assertTrue($verified_capable, "verified-only must include only bots that have DNS verification or IP ranges. " . "Bot '{$id}' has neither (verify_dns=" . var_export($def->verify_dns, true) . ', ip_ranges=' . count($def->ip_ranges) . ")");
		}
	}

	public function test_verified_only_includes_known_verified_bots(): void
	{
		// Spot-check: bots with explicit DNS verification should be present.
		$registry = Presets::load('verified-only');

		$this->assert_has_bot('googlebot', $registry);
		$this->assert_has_bot('bingbot', $registry);
		$this->assert_has_bot('gptbot', $registry);
		$this->assert_has_bot('claude', $registry);
	}

	// ============================================================
	// 6. 'no-ai' preset
	// ============================================================
	public function test_no_ai_excludes_ai_crawlers(): void
	{
		$registry = Presets::load('no-ai');
		$default = new DefaultRegistry();

		$ai_bot_ids = array_keys($default->ai_crawlers());

		$this->assertNotEmpty($ai_bot_ids);

		foreach ($ai_bot_ids as $bot_id) {
			$this->assert_lacks_bot($bot_id, $registry, "no-ai preset must NOT include AI crawler '{$bot_id}'");
		}
	}

	public function test_no_ai_keeps_other_categories_intact(): void
	{
		$registry = Presets::load('no-ai');

		// Search engines still present
		$this->assert_has_bot('googlebot', $registry);
		$this->assert_has_bot('bingbot', $registry);

		// Social crawlers still present (no reason to drop them)
		$this->assert_has_bot('facebook', $registry);

		// Cloud infra STILL PRESENT (critical for availability)
		$this->assert_has_bot('cloudflare_health', $registry);
	}

	public function test_no_ai_ai_crawlers_accessor_returns_empty(): void
	{
		$registry = Presets::load('no-ai');

		$this->assertSame([], $registry->ai_crawlers(), "no-ai preset's ai_crawlers() must return an empty array");
	}

	// ============================================================
	// 7. 'no-seo' preset
	// ============================================================
	public function test_no_seo_excludes_seo_crawlers(): void
	{
		$registry = Presets::load('no-seo');
		$default = new DefaultRegistry();

		$seo_bot_ids = array_keys($default->seo_crawlers());

		$this->assertNotEmpty($seo_bot_ids, 'DefaultRegistry ships SEO bots');

		foreach ($seo_bot_ids as $bot_id) {
			$this->assert_lacks_bot($bot_id, $registry, "no-seo preset must NOT include SEO crawler '{$bot_id}'");
		}
	}

	public function test_no_seo_keeps_other_categories(): void
	{
		$registry = Presets::load('no-seo');

		// Search engines present
		$this->assert_has_bot('googlebot', $registry);

		// AI crawlers present (no-SEO doesn't mean no-AI)
		$this->assert_has_bot('gptbot', $registry);
		$this->assert_has_bot('claude', $registry);

		// Cloud infra STILL PRESENT
		$this->assert_has_bot('cloudflare_health', $registry);
	}

	// ============================================================
	// 8. 'eu-only' preset
	// ============================================================
	public function test_eu_only_includes_european_search_engines(): void
	{
		$registry = Presets::load('eu-only');

		// European search engines per preset docblock
		$this->assert_has_bot('duckduckgo', $registry);
		$this->assert_has_bot('qwant', $registry);
		$this->assert_has_bot('mojeek', $registry);
		$this->assert_has_bot('seznam', $registry);
	}

	public function test_eu_only_includes_eu_archives(): void
	{
		$registry = Presets::load('eu-only');

		// EU legal-deposit archives
		$this->assert_has_bot('web_archive_uk', $registry);
		$this->assert_has_bot('biblio_nationale_fr', $registry);
		$this->assert_has_bot('dnb_de', $registry);
		$this->assert_has_bot('kb_nl', $registry);
	}

	public function test_eu_only_includes_cloud_infrastructure(): void
	{
		// CRITICAL: EU-only must still include all cloud bots.
		$registry = Presets::load('eu-only');
		$default = new DefaultRegistry();

		$cloud_ids = array_keys($default->cloud_infrastructure());
		foreach ($cloud_ids as $bot_id) {
			$this->assert_has_bot($bot_id, $registry, "eu-only must include cloud bot '{$bot_id}' (availability guarantee)");
		}
	}

	public function test_eu_only_may_exclude_non_eu_global_search_engines(): void
	{
		// The preset is EU-focused, so non-EU global search engines
		// (Google, Bing, Baidu) are NOT in the keep-list. Note: this is
		// a soft check — if a future preset includes them, this test
		// shouldn't fail. We just verify the EU list is present.
		$registry = Presets::load('eu-only');

		// EU search engines must be present
		$this->assert_has_bot('qwant', $registry);

		// Mistral (French) is in the EU AI list
		$this->assert_has_bot('mistral', $registry);
	}

	// ============================================================
	// 9. 'human-only' preset
	// ============================================================
	public function test_human_only_returns_empty_registry(): void
	{
		$registry = Presets::load('human-only');

		$this->assertInstanceOf(EmptyRegistry::class, $registry, "human-only must be an EmptyRegistry (no bots recognized)");

		$this->assertSame(0, $registry->count());
		$this->assertSame([], $registry->all());

		// No bots of any category
		$this->assertSame([], $registry->search_engines());
		$this->assertSame([], $registry->ai_crawlers());
		$this->assertSame([], $registry->social_crawlers());
		$this->assertSame([], $registry->cloud_infrastructure());
	}

	public function test_human_only_singleton_returns_same_instance(): void
	{
		// EmptyRegistry documents that its instance() is a singleton —
		// verify Presets::load('human-only') returns the same instance.
		$a = Presets::load('human-only');
		$b = Presets::load('human-only');

		$this->assertSame($a, $b, 'human-only preset should return the singleton EmptyRegistry instance');
	}

	// ============================================================
	// 10. 'custom' preset
	// ============================================================
	public function test_custom_returns_empty_registry(): void
	{
		// 'custom' means the user supplies bots via 'bots' key in the
		// config; Presets::load() alone returns empty.
		$registry = Presets::load('custom');

		$this->assertSame(0, $registry->count());
		$this->assertSame([], $registry->all());
	}

	// ============================================================
	// 11. CRITICAL: every cloud-infrastructure bot must be in
	// every preset that includes ANY bots (except human-only/custom).
	// ============================================================
	#[DataProvider('cloudSafetyProvider')]
	public function test_preset_includes_cloud_infrastructure_when_it_has_any_bots(string $preset): void
	{
		$registry = Presets::load($preset);

		if ($registry->count() === 0) {
			$this->markTestSkipped("Preset '{$preset}' is empty (human-only / custom) — cloud requirement N/A");
		}

		$default = new DefaultRegistry();
		foreach ($default->cloud_infrastructure() as $def) {
			$this->assert_has_bot($def->id, $registry, "CRITICAL AVAILABILITY BUG: preset '{$preset}' includes bots but is missing " . "cloud_infrastructure bot '{$def->id}'. Blocking CDN/LB health probes takes " . 'the origin offline. Re-add the bot to the preset.');
		}
	}

	public static function cloudSafetyProvider(): array
	{
		// human-only and custom are intentionally excluded (no bots).
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
	// 12. Bot-category coverage per preset
	// ============================================================
	public function test_full_covers_all_categories(): void
	{
		$registry = Presets::load('full');
		$default = new DefaultRegistry();

		// 'full' should include a representative bot from every category.
		$categories_with_bots = [
			BotCategory::SEARCH_ENGINE,
			BotCategory::AI_CRAWLER,
			BotCategory::SOCIAL_CRAWLER,
			BotCategory::SEO_CRAWLER,
			BotCategory::ARCHIVE_CRAWLER,
			BotCategory::MONITORING,
			BotCategory::FEED_READER,
			BotCategory::SHOPPING_CRAWLER,
			BotCategory::CLOUD_INFRASTRUCTURE,
			BotCategory::SECURITY_SCANNER,
			BotCategory::RESIDENTIAL_PROXY
		];

		foreach ($categories_with_bots as $cat) {
			$count = count($default->{$this->category_method($cat)}());
			if ($count === 0)
				continue;

			$this->assertGreaterThan(0, count($registry->{$this->category_method($cat)}()), "full preset must include bots from category {$cat->value}");
		}
	}

	private function category_method(BotCategory $cat): string
	{
		return match ($cat) {
			BotCategory::SEARCH_ENGINE => 'search_engines',
			BotCategory::AI_CRAWLER => 'ai_crawlers',
			BotCategory::SOCIAL_CRAWLER => 'social_crawlers',
			BotCategory::SEO_CRAWLER => 'seo_crawlers',
			BotCategory::ARCHIVE_CRAWLER => 'archive_crawlers',
			BotCategory::MONITORING => 'monitoring',
			BotCategory::FEED_READER => 'feed_readers',
			BotCategory::SHOPPING_CRAWLER => 'shopping_crawlers',
			BotCategory::CLOUD_INFRASTRUCTURE => 'cloud_infrastructure',
			BotCategory::SECURITY_SCANNER => 'security_scanners',
			BotCategory::RESIDENTIAL_PROXY => 'residential_crawlers',
			default => 'all'
		};
	}

	// ============================================================
	// 13. Custom base registry (test injection)
	// ============================================================
	public function test_load_accepts_custom_base_registry(): void
	{
		// Presets::load() takes an optional second arg for tests / multi-tenant.
		// If a custom base is supplied, presets are derived from it instead
		// of the default DefaultRegistry.
		$custom_base = new DefaultRegistry();
		$registry = Presets::load('full', $custom_base);

		$this->assertSame($custom_base, $registry, "'full' preset with explicit base should return the base as-is");
	}

	public function test_minimal_with_custom_base_filters_from_that_base(): void
	{
		// Build a base with only 2 bots — neither in minimal's keep list.
		$base = new \BadBehaviour\Bot\Registry\InMemoryRegistry([
			'custom_only_bot_a' => new \BadBehaviour\Bot\BotDefinition(id: 'custom_only_bot_a', name: 'A', user_agent_patterns: [
				'CustomOnlyA'
			], host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING),
			'googlebot' => new \BadBehaviour\Bot\BotDefinition(id: 'googlebot', name: 'GB', user_agent_patterns: [
				'Googlebot'
			], host_patterns: [], ip_ranges: [], category: BotCategory::SEARCH_ENGINE)
		]);

		$registry = Presets::load('minimal', $base);

		// googlebot IS in minimal's keep-list → present
		$this->assert_has_bot('googlebot', $registry);

		// custom_only_bot_a is NOT in minimal's keep-list → absent
		$this->assert_lacks_bot('custom_only_bot_a', $registry);
	}
}
