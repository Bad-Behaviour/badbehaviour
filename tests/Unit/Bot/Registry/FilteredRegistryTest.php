<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Bot\Registry;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\Registry\EmptyRegistry;
use BadBehaviour\Bot\Registry\FilteredRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Bot\RegistryInterface;
use PHPUnit\Framework\TestCase;

/**
 * Tier 2 (should-have) tests for FilteredRegistry.
 *
 * FilteredRegistry wraps another registry and applies four filter dimensions:
 *
 *   1. keep_bots (whitelist by bot ID)
 *   2. exclude_bots (blacklist by bot ID)
 *   3. include_categories (STRICT whitelist by category — opt-in only)
 *   4. exclude_categories (blacklist by category)
 *
 * === SEMANTICS ===
 *
 * include_categories is a STRICT WHITELIST when used directly with
 * FilteredRegistry. If you set include_categories to ['cloud_infrastructure'],
 * every bot NOT in that category is dropped — including Googlebot, GPTBot,
 * etc.
 *
 * For the common "make sure these categories are present" intent (the
 * safety-net pattern), use RegistryFactory::from_array() with the
 * `include_categories` config key, which performs an ADDITIVE merge
 * via MergedRegistry instead of strict whitelisting.
 *
 * === PRECEDENCE ===
 *
 *   keep_bots  →  exclude_bots  →  include_categories  →  exclude_categories
 *
 * A bot must pass ALL active filters to appear in the filtered registry.
 *
 * These tests exercise every combination plus the precedence interactions,
 * including the static factory helpers (by_bot_ids, by_category) and the
 * inner-registry accessor used by diagnostics tools.
 */
final class FilteredRegistryTest extends TestCase
{
	// ---------- Helpers ----------

	/**
	 * Build a registry covering every BotCategory so tests don't have to
	 * reach into DefaultRegistry's exact bot list (which may grow over time).
	 *
	 * Returns the same shape as DefaultRegistry::all() but with one
	 * representative bot per category.
	 *
	 * @return array<string, BotDefinition>
	 */
	private function sample_bots(): array
	{
		$mk = static function (
			string $id,
			BotCategory $cat,
			array $ua_patterns = [],
			BotAction $default_action = BotAction::ALLOW,
		): BotDefinition {
			return new BotDefinition(
				id: $id,
				name: 'Sample ' . $id,
				user_agent_patterns: $ua_patterns ?: ['Sample' . ucfirst($id)],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: $cat,
				default_action: $default_action,
			);
		};

		return [
			// SEARCH_ENGINE
			'googlebot'   => $mk('googlebot',   BotCategory::SEARCH_ENGINE,       ['Googlebot'],         BotAction::BLOCK),
			'bingbot'     => $mk('bingbot',     BotCategory::SEARCH_ENGINE,       ['bingbot'],           BotAction::BLOCK),
			// AI_CRAWLER
			'gptbot'      => $mk('gptbot',      BotCategory::AI_CRAWLER,          ['GPTBot'],            BotAction::CHALLENGE),
			'claude'      => $mk('claude',      BotCategory::AI_CRAWLER,          ['ClaudeBot'],         BotAction::CHALLENGE),
			// SOCIAL_CRAWLER
			'facebook'    => $mk('facebook',    BotCategory::SOCIAL_CRAWLER,      ['facebookexternalhit']),
			'twitter'     => $mk('twitter',     BotCategory::SOCIAL_CRAWLER,      ['Twitterbot']),
			// SEO_CRAWLER
			'semrush'     => $mk('semrush',     BotCategory::SEO_CRAWLER,         ['SemrushBot'],        BotAction::CHALLENGE),
			'ahrefs'      => $mk('ahrefs',      BotCategory::SEO_CRAWLER,         ['AhrefsBot'],         BotAction::CHALLENGE),
			// ARCHIVE_CRAWLER
			'internet_archive' => $mk('internet_archive', BotCategory::ARCHIVE_CRAWLER, ['ia_archiver']),
			// FEED_READER
			'feedly'      => $mk('feedly',      BotCategory::FEED_READER,         ['FeedlyBot']),
			// SHOPPING_CRAWLER
			'google_shopping' => $mk('google_shopping', BotCategory::SHOPPING_CRAWLER, ['Googlebot-Shopping']),
			// CLOUD_INFRASTRUCTURE
			'cloudflare_health' => $mk('cloudflare_health', BotCategory::CLOUD_INFRASTRUCTURE, ['Cloudflare-Healthcheck']),
			'aws_elb_health'    => $mk('aws_elb_health',    BotCategory::CLOUD_INFRASTRUCTURE, ['ELB-HealthChecker']),
			// MONITORING
			'uptimerobot' => $mk('uptimerobot', BotCategory::MONITORING,         ['UptimeRobot']),
			// SECURITY_SCANNER
			'shodan'      => $mk('shodan',      BotCategory::SECURITY_SCANNER,    ['Shodan'],            BotAction::LOG_ONLY),
			// RESIDENTIAL_PROXY
			'brightdata'  => $mk('brightdata',  BotCategory::RESIDENTIAL_PROXY,   ['BrightData'],        BotAction::BLOCK),
			// UNKNOWN / MALICIOUS (rare in real registries but valid)
			'unknown_bot' => $mk('unknown_bot', BotCategory::UNKNOWN,             ['MysteryBot']),
		];
	}

	private function make_inner(array $bot_overrides = []): RegistryInterface
	{
		return new InMemoryRegistry(array_merge($this->sample_bots(), $bot_overrides));
	}

	// ============================================================
	// 1. Default behavior (no filters)
	// ============================================================

	public function test_no_filters_passes_all_bots_through(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry($inner);

		$this->assertSame($inner->count(), $filtered->count(),
			'With no filters, count() must match inner count exactly');
		$this->assertSame(
			sortAndKey($inner->all()),
			sortAndKey($filtered->all()),
			'With no filters, all() must return the same bot set as inner'
		);
	}

	public function test_empty_filter_arrays_are_inert(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			keep_bots: [],
			exclude_bots: [],
			include_categories: null,
			exclude_categories: [],
		);

		$this->assertSame($inner->count(), $filtered->count());
	}

	// ============================================================
	// 2. Keep-list (whitelist)
	// ============================================================

	public function test_keep_list_keeps_only_specified_bots(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			keep_bots: ['googlebot', 'bingbot'],
		);

		$this->assertCount(2, $filtered->all());
		$this->assertTrue($filtered->has('googlebot'));
		$this->assertTrue($filtered->has('bingbot'));
		$this->assertFalse($filtered->has('gptbot'),
			'Bots not in keep_bots must be dropped, regardless of category');
		$this->assertFalse($filtered->has('facebook'));
	}

	public function test_keep_list_is_strict_inclusion_only(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry($inner, keep_bots: ['googlebot']);

		// Even bots from the same category as the keep-listed bot must be
		// excluded — keep_bots is per-ID, not per-category.
		$this->assertFalse($filtered->has('bingbot'),
			'Bingbot is in SEARCH_ENGINE but NOT in keep_bots → must be filtered out');
	}

	public function test_keep_list_with_unknown_id_is_silently_ignored(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			keep_bots: ['googlebot', 'does_not_exist'],
		);

		// Unknown IDs don't crash, just have no effect.
		$this->assertCount(1, $filtered->all());
		$this->assertTrue($filtered->has('googlebot'));
		$this->assertFalse($filtered->has('does_not_exist'));
	}

	// ============================================================
	// 3. Exclude-list (blacklist)
	// ============================================================

	public function test_exclude_list_drops_specified_bots(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['brightdata', 'shodan'],
		);

		$this->assertFalse($filtered->has('brightdata'));
		$this->assertFalse($filtered->has('shodan'));
		$this->assertTrue($filtered->has('googlebot'));
		$this->assertTrue($filtered->has('gptbot'));
		$this->assertSame($inner->count() - 2, $filtered->count());
	}

	public function test_exclude_list_works_without_keep_list(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			keep_bots: [],
			exclude_bots: ['brightdata'],
		);

		$this->assertFalse($filtered->has('brightdata'));
		$this->assertSame($inner->count() - 1, $filtered->count());
	}

	// ============================================================
	// 4. Category include-filter (STRICT WHITELIST)
	// ============================================================

	public function test_include_categories_keeps_only_listed_categories(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			include_categories: ['search_engine', 'ai_crawler'],
		);

		$this->assertTrue($filtered->has('googlebot'));
		$this->assertTrue($filtered->has('bingbot'));
		$this->assertTrue($filtered->has('gptbot'));
		$this->assertTrue($filtered->has('claude'));
		$this->assertFalse($filtered->has('facebook'), 'social_crawler not in include list');
		$this->assertFalse($filtered->has('semrush'), 'seo_crawler not in include list');
		$this->assertFalse($filtered->has('shodan'),  'security_scanner not in include list');
		$this->assertCount(4, $filtered->all());
	}

	public function test_include_categories_null_means_no_filter(): void
	{
		// null is the sentinel value that disables the include filter
		// (vs. an empty array, which would mean "include NOTHING").
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry($inner, include_categories: null);

		$this->assertSame($inner->count(), $filtered->count());
	}

	public function test_include_categories_empty_array_means_keep_none(): void
	{
		// [] is semantically different from null — it means "no category
		// is in the include list", so EVERY bot fails the include test.
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry($inner, include_categories: []);

		$this->assertCount(0, $filtered->all(),
			'include_categories=[] must produce an empty registry (allowlist contains nothing)');
	}

	/**
	 * Documents the strict-whitelist semantic of include_categories when
	 * used directly with FilteredRegistry.
	 *
	 * This is the CORRECT behavior for FilteredRegistry in isolation —
	 * include_categories is a gate, not a merge.
	 *
	 * For the additive merge semantic, use RegistryFactory::from_array()
	 * with the include_categories config key. See RegistryFactoryTest.
	 */
	public function test_include_categories_drops_everything_not_listed_strict_whitelist(): void
	{
		$inner = $this->make_inner();

		// Only cloud_infrastructure in the whitelist
		$filtered = new FilteredRegistry(
			$inner,
			include_categories: ['cloud_infrastructure'],
		);

		// ONLY cloud bots pass
		$this->assertTrue($filtered->has('cloudflare_health'));
		$this->assertTrue($filtered->has('aws_elb_health'));
		$this->assertCount(2, $filtered->all(),
			'Strict whitelist: only 2 cloud bots, every other bot dropped');

		// Every non-cloud bot is dropped — this is the documented semantic
		$this->assertFalse($filtered->has('googlebot'),
			'Strict whitelist semantic: googlebot (search_engine) DROPPED');
		$this->assertFalse($filtered->has('gptbot'),
			'Strict whitelist semantic: gptbot (ai_crawler) DROPPED');
		$this->assertFalse($filtered->has('semrush'),
			'Strict whitelist semantic: semrush (seo_crawler) DROPPED');
	}

	// ============================================================
	// 5. Category exclude-filter
	// ============================================================

	public function test_exclude_categories_drops_only_listed_categories(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_categories: ['seo_crawler', 'security_scanner'],
		);

		$this->assertFalse($filtered->has('semrush'), 'seo_crawler → excluded');
		$this->assertFalse($filtered->has('ahrefs'),  'seo_crawler → excluded');
		$this->assertFalse($filtered->has('shodan'),  'security_scanner → excluded');
		$this->assertTrue($filtered->has('googlebot'), 'search_engine → kept');
		$this->assertTrue($filtered->has('gptbot'),    'ai_crawler → kept');
		$this->assertTrue($filtered->has('facebook'),  'social_crawler → kept');
		$this->assertSame($inner->count() - 3, $filtered->count(),
			'Three bots in the excluded categories should be dropped');
	}

	// ============================================================
	// 6. Filter precedence (documented order)
	// ============================================================

	/**
	 * Filter precedence, as documented in the class docblock:
	 *   1. keep_bots  → bot MUST be in this list
	 *   2. exclude_bots → bot must NOT be in this list
	 *   3. include_categories → bot's category MUST be in this list
	 *   4. exclude_categories → bot's category must NOT be in this list
	 *
	 * These tests prove each ordering rule individually.
	 */

	public function test_keep_list_overrides_exclude_list_with_same_id(): void
	{
		// keep_bots runs FIRST, so it gates everything else.
		// If 'brightdata' is in keep_bots but also in exclude_bots,
		// keep_bots lets it through and exclude_bots never gets to drop it.
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			keep_bots: ['brightdata'],
			exclude_bots: ['brightdata'],
		);

		$this->assertTrue($filtered->has('brightdata'),
			'keep_bots runs first → bot passes through even if also in exclude_bots');
	}

	public function test_exclude_list_overrides_category_include(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['googlebot'],
			include_categories: ['search_engine'],
		);

		// googlebot passes category include (SEARCH_ENGINE ∈ include list)
		// but is then dropped by exclude_bots.
		$this->assertFalse($filtered->has('googlebot'),
			'exclude_bots runs before category include → bot must be dropped');
		$this->assertTrue($filtered->has('bingbot'),
			'Other SEARCH_ENGINE bot must pass');
	}

	public function test_category_exclude_overrides_category_include(): void
	{
		// include_categories and exclude_categories are category-level filters.
		// Both run; exclude wins because dropping is safer than keeping for
		// misconfigured policies.
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			include_categories: ['search_engine', 'ai_crawler', 'seo_crawler'],
			exclude_categories: ['seo_crawler'],
		);

		$this->assertTrue($filtered->has('googlebot'), 'search_engine → kept');
		$this->assertTrue($filtered->has('gptbot'),    'ai_crawler → kept');
		$this->assertFalse($filtered->has('semrush'),  'seo_crawler in both → exclude wins');
		$this->assertFalse($filtered->has('ahrefs'),   'seo_crawler in both → exclude wins');
	}

	// ============================================================
	// 7. Per-category accessors
	// ============================================================

	public function test_per_category_accessors_apply_filters(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['semrush'],
		);

		// ai_crawlers() should drop semrush... no, semrush is seo_crawler.
		$this->assertCount(2, $filtered->ai_crawlers(),
			'ai_crawlers() reflects the filter — semrush is not in AI, so this is unaffected');

		// seo_crawlers() should drop semrush.
		$seo = $filtered->seo_crawlers();
		$this->assertCount(1, $seo);
		$this->assertArrayNotHasKey('semrush', $seo);
		$this->assertArrayHasKey('ahrefs', $seo);
	}

	public function test_per_category_accessors_with_category_filter(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_categories: ['seo_crawler', 'security_scanner'],
		);

		$this->assertSame([], $filtered->seo_crawlers(),
			'seo_crawlers() must return empty when category is excluded');
		$this->assertSame([], $filtered->security_scanners(),
			'security_scanners() must return empty when category is excluded');
		$this->assertNotEmpty($filtered->ai_crawlers(),
			'ai_crawlers() is unaffected by seo/security exclusion');
	}

	public function test_per_category_accessors_with_keep_list(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			keep_bots: ['googlebot'],
		);

		// googlebot is in SEARCH_ENGINE — that category returns 1 bot.
		$this->assertCount(1, $filtered->search_engines());
		// All other categories return 0 — their bots aren't in keep_bots.
		$this->assertCount(0, $filtered->ai_crawlers());
		$this->assertCount(0, $filtered->social_crawlers());
		$this->assertCount(0, $filtered->seo_crawlers());
	}

	public function test_per_category_accessors_with_strict_include_whitelist(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			include_categories: ['search_engine'],
		);

		// search_engines() returns the 2 search engine bots
		$this->assertCount(2, $filtered->search_engines());

		// All other category accessors return empty (strict whitelist)
		$this->assertCount(0, $filtered->ai_crawlers());
		$this->assertCount(0, $filtered->social_crawlers());
		$this->assertCount(0, $filtered->seo_crawlers());
		$this->assertCount(0, $filtered->cloud_infrastructure());
	}

	// ============================================================
	// 8. find_by_ua / find_by_tokens are filter-aware
	// ============================================================

	public function test_find_by_ua_respects_filters(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['gptbot', 'claude'],
		);

		// UA 'GPTBot/1.0' would normally match both gptbot and claude
		// (token overlap), but with exclude_bots the filtered registry
		// must not return them.
		$matches = $filtered->find_by_ua('GPTBot/1.0 (compatible)');

		$this->assertNotContains('gptbot', $matches);
		$this->assertNotContains('claude', $matches,
			'Excluded bots must be absent from find_by_ua results');
	}

	public function test_find_by_tokens_respects_filters(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_categories: ['ai_crawler'],
		);

		$matches = $filtered->find_by_tokens('GPTBot/2.0 (compatible)');

		$this->assertNotContains('gptbot', $matches);
		$this->assertNotContains('claude', $matches);
	}

	public function test_find_by_ua_respects_strict_whitelist(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			include_categories: ['cloud_infrastructure'],
		);

		// UA matching googlebot/facebook should return NOTHING because
		// those bots are filtered out by the strict whitelist
		$matches = $filtered->find_by_ua('Mozilla/5.0 (compatible; Googlebot/2.1)');
		$this->assertEmpty($matches,
			'Strict whitelist: find_by_ua returns nothing for non-whitelisted bots');

		// UA matching cloudflare_health should return it
		$matches = $filtered->find_by_ua('Cloudflare-Healthcheck/1.0');
		$this->assertContains('cloudflare_health', $matches,
			'Strict whitelist: find_by_ua returns whitelisted bots');
	}

	// ============================================================
	// 9. has() / get() filter-aware
	// ============================================================

	public function test_has_returns_false_for_filtered_out_bots(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['brightdata'],
		);

		$this->assertTrue($inner->has('brightdata'),
			'Sanity: inner registry still has brightdata');
		$this->assertFalse($filtered->has('brightdata'),
			'Filtered registry must NOT report filtered-out bots');
	}

	public function test_get_returns_null_for_filtered_out_bots(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['brightdata'],
		);

		$this->assertNotNull($inner->get('brightdata'));
		$this->assertNull($filtered->get('brightdata'),
			'Filtered registry must return null for filtered-out bots');
	}

	// ============================================================
	// 10. Static factories
	// ============================================================

	public function test_by_bot_ids_factory_creates_keep_list_filter(): void
	{
		$inner = $this->make_inner();
		$filtered = FilteredRegistry::by_bot_ids($inner, keep: ['gptbot', 'claude']);

		$this->assertCount(2, $filtered->all());
		$this->assertTrue($filtered->has('gptbot'));
		$this->assertTrue($filtered->has('claude'));
	}

	public function test_by_bot_ids_factory_creates_exclude_list_filter(): void
	{
		$inner = $this->make_inner();
		$filtered = FilteredRegistry::by_bot_ids($inner, exclude: ['brightdata', 'shodan']);

		$this->assertFalse($filtered->has('brightdata'));
		$this->assertFalse($filtered->has('shodan'));
		$this->assertSame($inner->count() - 2, $filtered->count());
	}

	public function test_by_category_factory_creates_category_filter(): void
	{
		$inner = $this->make_inner();
		$filtered = FilteredRegistry::by_category($inner, include: ['ai_crawler']);

		$this->assertCount(2, $filtered->all());
		$this->assertTrue($filtered->has('gptbot'));
		$this->assertTrue($filtered->has('claude'));
	}

	public function test_by_category_factory_with_exclude_only(): void
	{
		$inner = $this->make_inner();
		$filtered = FilteredRegistry::by_category($inner, exclude: ['seo_crawler']);

		$this->assertFalse($filtered->has('semrush'));
		$this->assertFalse($filtered->has('ahrefs'));
		$this->assertTrue($filtered->has('googlebot'),
			'Other categories unaffected by category exclude');
	}

	// ============================================================
	// 11. inner-registry accessor (diagnostics)
	// ============================================================

	public function test_get_inner_returns_the_wrapped_registry(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry($inner, exclude_bots: ['brightdata']);

		$this->assertSame($inner, $filtered->get_inner(),
			'get_inner() must return the exact wrapped registry instance');
	}

	// ============================================================
	// 12. Integration: Real DefaultRegistry survives filter
	// ============================================================

	public function test_real_default_registry_excludes_categories_correctly(): void
	{
		$default = new DefaultRegistry();
		$seo_count = count($default->seo_crawlers());

		// Sanity precondition
		$this->assertGreaterThan(0, $seo_count,
			'DefaultRegistry should ship with multiple SEO crawlers');

		$filtered = new FilteredRegistry(
			$default,
			exclude_categories: ['seo_crawler'],
		);

		$this->assertSame(0, count($filtered->seo_crawlers()),
			'Filtered SEO crawlers must be empty');
		$this->assertSame(
			$default->count() - $seo_count,
			$filtered->count(),
			'Filtered total = total - seo_crawlers count'
		);
	}

	public function test_filtering_empty_registry_is_safe(): void
	{
		$empty = new EmptyRegistry();
		$filtered = new FilteredRegistry(
			$empty,
			exclude_bots: ['anything'],
			exclude_categories: ['any_category'],
		);

		$this->assertCount(0, $filtered->all());
		$this->assertSame(0, $filtered->count());
		$this->assertNull($filtered->get('anything'));
		$this->assertFalse($filtered->has('anything'));
		$this->assertSame([], $filtered->find_by_ua('GPTBot'));
	}

	// ============================================================
	// 13. Determinism / caching of filtered results
	// ============================================================

	public function test_all_returns_same_array_on_repeated_calls(): void
	{
		$inner = $this->make_inner();
		$filtered = new FilteredRegistry(
			$inner,
			exclude_bots: ['brightdata'],
		);

		$first = $filtered->all();
		$second = $filtered->all();

		$this->assertSame(sortAndKey($first), sortAndKey($second),
			'all() must be deterministic across calls (internal cache is stable)');
	}

	// ============================================================
	// 14. Strict-whitelist footgun documentation
	// ============================================================

	/**
	 * Documents the failure mode that motivated the RegistryFactory change.
	 *
	 * The shipped config/bb_registry.php used:
	 *   include_categories => ['cloud_infrastructure']
	 * expecting a "safety net" that ADDED cloud bots to whatever the
	 * preset selected. But FilteredRegistry's include_categories is a
	 * STRICT WHITELIST — it DROPS every bot not in the list.
	 *
	 * Result: BotDetector's registry contained only 5 cloud bots instead
	 * of ~100. Production deployments saw almost nothing blocked.
	 *
	 * This test encodes the strict-whitelist semantic so anyone who tries
	 * to use FilteredRegistry directly for a safety-net pattern will see
	 * a clear test failure pointing to RegistryFactory::from_array().
	 *
	 * See RegistryFactoryTest::test_shipped_file_pattern_yields_full_registry()
	 * for the RegistryFactory-level test that verifies the FIX.
	 */
	public function test_direct_filtered_registry_with_only_cloud_yields_empty_real_registry(): void
	{
		$default = new DefaultRegistry();
		$real_count = $default->count();

		$filtered = new FilteredRegistry(
			$default,
			include_categories: ['cloud_infrastructure'],
		);

		// Direct use of FilteredRegistry with include_categories is the
		// footgun pattern. Registry count drops to ~5 (cloud only).
		$this->assertLessThan(10, $filtered->count(),
			'Direct FilteredRegistry with include_categories=[cloud_infra] yields ~5 bots (footgun)');
		$this->assertGreaterThan($filtered->count(), $real_count,
			'Inner registry has many more bots than the filtered strict whitelist');
	}
}

/**
 * Helper: produce a canonical (sorted) form of an array-of-definitions
 * suitable for value comparison with assertSame().
 *
 * @param array<string, BotDefinition> $bots
 * @return array<string, true>
 */
function sortAndKey(array $bots): array
{
	ksort($bots);
	$out = [];
	foreach ($bots as $id => $def) {
		$out[$id] = true;
	}
	return $out;
}