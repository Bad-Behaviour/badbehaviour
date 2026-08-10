<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Bot\Registry;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\Registry\EmptyRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Bot\Registry\MergedRegistry;
use BadBehaviour\Bot\RegistryInterface;
use PHPUnit\Framework\TestCase;

/**
 * Tier 2 (should-have) tests for MergedRegistry.
 *
 * MergedRegistry composes multiple registries into one virtual view.
 * Its semantics matter because operators extend behavior by composing:
 *
 *   $merged = new MergedRegistry([
 *       DefaultRegistry(),                  // shipped bots
 *       new CustomRegistry($my_internal),   // my bots
 *   ]);
 *
 * Key contracts under test:
 *
 *   1. LAST-WINS for duplicate bot IDs
 *      - Bot definitions for the same ID across registries — the one
 *        declared LATER wins. This lets operators override shipped bots.
 *      - Applies in all(), get(), category accessors, find_by_ua,
 *        find_by_tokens.
 *
 *   2. ID UNIQUENESS within the merged result
 *      - The merged set has unique bot IDs; duplicates collapse to the
 *        last occurrence.
 *
 *   3. get_registries() exposes the input list
 *      - Used by diagnostics tools and tests to introspect the
 *        composition.
 *
 *   4. find_by_ua/find_by_tokens operate on the merged set
 *      - Cross-registry UA matching works without leaking source names.
 */
final class MergedRegistryTest extends TestCase
{
	// ---------- Helpers ----------

	/**
	 * Build a single-bot registry.
	 */
	private function registry_with(
		BotDefinition $def,
		?array $additional = null,
	): RegistryInterface {
		$bots = [$def->id => $def];
		if ($additional !== null) {
			$bots = array_merge($bots, $additional);
		}
		return new InMemoryRegistry($bots);
	}

	/**
	 * Build a registry with several bots covering one category.
	 *
	 * @return array<string, BotDefinition>
	 */
	private function bots_in_category(BotCategory $category, array $specs): array
	{
		$out = [];
		foreach ($specs as [$id, $ua]) {
			$out[$id] = new BotDefinition(
				id: $id,
				name: 'Bot ' . $id,
				user_agent_patterns: [$ua],
				host_patterns: [],
				ip_ranges: [],
				category: $category,
				default_action: BotAction::ALLOW,
			);
		}
		return $out;
	}

	// ============================================================
	// 1. Construction & validation
	// ============================================================

	public function test_constructor_rejects_non_registry_entries(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->expectExceptionMessageMatches('/RegistryInterface/');

		/** @phpstan-ignore-next-line — intentional type violation for test */
		new MergedRegistry([
			'not_a_registry',
		]);
	}

	public function test_constructor_accepts_empty_array(): void
	{
		$merged = new MergedRegistry([]);

		$this->assertSame(0, $merged->count());
		$this->assertSame([], $merged->all());
		$this->assertSame([], $merged->get_registries());
	}

	public function test_constructor_accepts_single_registry(): void
	{
		$registry = new InMemoryRegistry([
			'solo' => new BotDefinition(
				id: 'solo',
				name: 'Solo',
				user_agent_patterns: ['SoloBot'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::MONITORING,
			),
		]);
		$merged = new MergedRegistry([$registry]);

		$this->assertSame(1, $merged->count());
		$this->assertTrue($merged->has('solo'));
	}

	// ============================================================
	// 2. Last-wins semantics (THE central contract)
	// ============================================================

	public function test_later_registry_overrides_earlier_for_same_bot_id(): void
	{
		$original = new BotDefinition(
			id: 'googlebot',
			name: 'Original Googlebot',
			user_agent_patterns: ['Googlebot'],
			host_patterns: ['googlebot.com'],
			ip_ranges: ['66.249.64.0/19'],
			category: BotCategory::SEARCH_ENGINE,
			default_action: BotAction::BLOCK,   // intentionally contradictory
		);
		$override = new BotDefinition(
			id: 'googlebot',
			name: 'Overridden Googlebot',
			user_agent_patterns: ['Googlebot', 'Googlebot-Override'],
			host_patterns: [],
			ip_ranges: [],
			category: BotCategory::SEARCH_ENGINE,
			default_action: BotAction::ALLOW,    // the operator's choice
		);

		$merged = new MergedRegistry([
			$this->registry_with($original),
			$this->registry_with($override),
		]);

		$def = $merged->get('googlebot');

		$this->assertNotNull($def);
		$this->assertSame('Overridden Googlebot', $def->name,
			'Later registry must win the name');
		$this->assertSame(BotAction::ALLOW, $def->default_action,
			'Later registry must win the default_action');
		$this->assertSame(['Googlebot', 'Googlebot-Override'], $def->user_agent_patterns,
			'Later registry must win the UA patterns');
		$this->assertCount(1, $merged->all(),
			'Merged set must not duplicate googlebot');
	}

	public function test_three_way_override_last_wins(): void
	{
		$mk = static fn(string $tag): BotDefinition => new BotDefinition(
			id: 'shared',
			name: "Bot {$tag}",
			user_agent_patterns: ["Bot/{$tag}"],
			host_patterns: [],
			ip_ranges: [],
			category: BotCategory::MONITORING,
		);

		$merged = new MergedRegistry([
			$this->registry_with($mk('first')),
			$this->registry_with($mk('second')),
			$this->registry_with($mk('third')),
		]);

		$this->assertSame('Bot third', $merged->get('shared')->name);
		$this->assertCount(1, $merged->all());
	}

	public function test_earlier_registry_loses_when_later_omits_bot(): void
	{
		// Later registry doesn't define 'googlebot' — earlier's version
		// must still win (because there IS no override).
		$earlier = new InMemoryRegistry([
			'googlebot' => new BotDefinition(
				id: 'googlebot',
				name: 'From earlier',
				user_agent_patterns: ['Googlebot'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::SEARCH_ENGINE,
			),
		]);
		$later = new InMemoryRegistry([
			'bingbot' => new BotDefinition(
				id: 'bingbot',
				name: 'From later',
				user_agent_patterns: ['bingbot'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::SEARCH_ENGINE,
			),
		]);

		$merged = new MergedRegistry([$earlier, $later]);

		$this->assertSame('From earlier', $merged->get('googlebot')->name,
			'No override present → earlier definition is the merged definition');
	}

	public function test_override_only_takes_effect_when_later_registry_actually_has_bot(): void
	{
		// Earlier registry has 'gptbot' as a search engine.
		// Later registry also has 'gptbot' but re-categorized as ai_crawler.
		// The merged 'gptbot' must be the AI crawler (last wins).
		$earlier = new InMemoryRegistry([
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'Old GPT',
				user_agent_patterns: ['GPTBot'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::SEARCH_ENGINE,
			),
		]);
		$later = new InMemoryRegistry([
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'New GPT',
				user_agent_patterns: ['GPTBot'],
				host_patterns: ['openai.com'],
				ip_ranges: [],
				category: BotCategory::AI_CRAWLER,
				verify_dns: true,
				dns_suffixes: ['openai.com'],
			),
		]);

		$merged = new MergedRegistry([$earlier, $later]);
		$def = $merged->get('gptbot');

		$this->assertSame(BotCategory::AI_CRAWLER, $def->category);
		$this->assertTrue($def->verify_dns);
		$this->assertSame(['openai.com'], $def->dns_suffixes);
	}

	// ============================================================
	// 3. get_registries() — introspection
	// ============================================================

	public function test_get_registries_returns_input_in_order(): void
	{
		$r1 = $this->registry_with(new BotDefinition(
			id: 'a', name: 'A', user_agent_patterns: ['A'],
			host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING,
		));
		$r2 = new EmptyRegistry();
		$r3 = $this->registry_with(new BotDefinition(
			id: 'b', name: 'B', user_agent_patterns: ['B'],
			host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING,
		));

		$merged = new MergedRegistry([$r1, $r2, $r3]);

		$list = $merged->get_registries();

		$this->assertCount(3, $list);
		$this->assertSame($r1, $list[0]);
		$this->assertSame($r2, $list[1]);
		$this->assertSame($r3, $list[2]);
	}

	public function test_get_registries_returns_empty_for_empty_input(): void
	{
		$merged = new MergedRegistry([]);

		$this->assertSame([], $merged->get_registries());
	}

	// ============================================================
	// 4. all() — the merged view
	// ============================================================

	public function test_all_unions_unique_bot_ids(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry($this->bots_in_category(BotCategory::SEARCH_ENGINE, [
				['googlebot', 'Googlebot'],
				['bingbot', 'bingbot'],
			])),
			new InMemoryRegistry($this->bots_in_category(BotCategory::AI_CRAWLER, [
				['gptbot', 'GPTBot'],
				['claude', 'ClaudeBot'],
			])),
		]);

		$this->assertCount(4, $merged->all());
		$this->assertArrayHasKey('googlebot', $merged->all());
		$this->assertArrayHasKey('bingbot', $merged->all());
		$this->assertArrayHasKey('gptbot', $merged->all());
		$this->assertArrayHasKey('claude', $merged->all());
	}

	public function test_all_is_deduplicated_across_overlapping_registries(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry([
				'gptbot' => new BotDefinition(
					id: 'gptbot', name: 'A', user_agent_patterns: ['A'],
					host_patterns: [], ip_ranges: [], category: BotCategory::AI_CRAWLER,
				),
				'claude' => new BotDefinition(
					id: 'claude', name: 'B', user_agent_patterns: ['B'],
					host_patterns: [], ip_ranges: [], category: BotCategory::AI_CRAWLER,
				),
			]),
			new InMemoryRegistry([
				'gptbot' => new BotDefinition(
					id: 'gptbot', name: 'A2', user_agent_patterns: ['A'],
					host_patterns: [], ip_ranges: [], category: BotCategory::AI_CRAWLER,
				),
			]),
		]);

		$this->assertCount(2, $merged->all());
		$this->assertSame('A2', $merged->get('gptbot')->name);
	}

	// ============================================================
	// 5. Per-category accessors respect overrides
	// ============================================================

	public function test_category_accessors_collect_across_registries(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry($this->bots_in_category(BotCategory::SEARCH_ENGINE, [
				['googlebot', 'Googlebot'],
			])),
			new InMemoryRegistry($this->bots_in_category(BotCategory::SEARCH_ENGINE, [
				['bingbot', 'bingbot'],
			])),
			new InMemoryRegistry($this->bots_in_category(BotCategory::AI_CRAWLER, [
				['gptbot', 'GPTBot'],
			])),
		]);

		$this->assertCount(2, $merged->search_engines());
		$this->assertCount(1, $merged->ai_crawlers());
		$this->assertCount(0, $merged->social_crawlers());
		$this->assertCount(0, $merged->seo_crawlers());
		$this->assertCount(0, $merged->cloud_infrastructure());
	}

	public function test_category_override_changes_merged_category_view(): void
	{
		// If a later registry re-categorizes a bot, that bot should move
		// to the new category in the merged view.
		$earlier = new InMemoryRegistry([
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'GPT',
				user_agent_patterns: ['GPTBot'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::SEARCH_ENGINE, // wrong category
			),
		]);
		$later = new InMemoryRegistry([
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'GPT',
				user_agent_patterns: ['GPTBot'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::AI_CRAWLER,    // corrected
			),
		]);

		$merged = new MergedRegistry([$earlier, $later]);

		$this->assertCount(0, $merged->search_engines(),
			'Corrected gptbot must NOT appear under SEARCH_ENGINE');
		$this->assertCount(1, $merged->ai_crawlers(),
			'Corrected gptbot MUST appear under AI_CRAWLER');
	}

	public function test_category_accessors_handle_empty_registries(): void
	{
		$merged = new MergedRegistry([
			new EmptyRegistry(),
			new InMemoryRegistry($this->bots_in_category(BotCategory::AI_CRAWLER, [
				['gptbot', 'GPTBot'],
			])),
			new EmptyRegistry(),
		]);

		$this->assertCount(1, $merged->ai_crawlers());
		$this->assertSame([], $merged->search_engines());
	}

	// ============================================================
	// 6. has() / get() with overrides
	// ============================================================

	public function test_has_resolves_to_later_definition(): void
	{
		$merged = new MergedRegistry([
			$this->registry_with(new BotDefinition(
				id: 'a', name: 'A', user_agent_patterns: ['A'],
				host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING,
			)),
			$this->registry_with(new BotDefinition(
				id: 'a', name: 'A2', user_agent_patterns: ['A2'],
				host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING,
			)),
		]);

		$this->assertTrue($merged->has('a'));
		$this->assertSame('A2', $merged->get('a')->name);
	}

	public function test_get_returns_null_for_unknown_id(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry([]),
			new InMemoryRegistry([]),
		]);

		$this->assertNull($merged->get('not_there'));
		$this->assertFalse($merged->has('not_there'));
	}

	public function test_count_matches_unique_merged_set(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry([
				'a' => $this->mkBot('a', BotCategory::MONITORING, ['A']),
				'b' => $this->mkBot('b', BotCategory::MONITORING, ['B']),
			]),
			new InMemoryRegistry([
				// 'a' is a duplicate
				'a' => $this->mkBot('a', BotCategory::MONITORING, ['A']),
				// 'c' is unique
				'c' => $this->mkBot('c', BotCategory::MONITORING, ['C']),
			]),
		]);

		$this->assertSame(3, $merged->count(),
			'Duplicates must not be double-counted (3 unique bots: a, b, c)');
	}

	// ============================================================
	// 7. find_by_ua / find_by_tokens operate on the merged set
	// ============================================================

	public function test_find_by_ua_finds_bots_across_registries(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry($this->bots_in_category(BotCategory::SEARCH_ENGINE, [
				['googlebot', 'Googlebot'],
			])),
			new InMemoryRegistry($this->bots_in_category(BotCategory::AI_CRAWLER, [
				['gptbot', 'GPTBot'],
			])),
		]);

		// UA "Googlebot/2.1 (compatible)" must hit googlebot from registry 1
		$matches = $merged->find_by_ua('Googlebot/2.1 (compatible)');
		$this->assertContains('googlebot', $matches);

		// UA "GPTBot/1.0 (compatible)" must hit gptbot from registry 2
		$matches = $merged->find_by_ua('GPTBot/1.0 (compatible)');
		$this->assertContains('gptbot', $matches);
	}

	public function test_find_by_ua_after_override_uses_overridden_patterns(): void
	{
		// After override, only the new UA pattern should match — the old
		// one is gone (BotDefinition is the union, not intersection, of
		// UA patterns — and "last wins" means later BotDefinition replaces
		// earlier completely).
		$earlier = new InMemoryRegistry([
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'Old GPT',
				user_agent_patterns: ['OldTokenGPT'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::AI_CRAWLER,
			),
		]);
		$later = new InMemoryRegistry([
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'New GPT',
				user_agent_patterns: ['NewTokenGPT'],
				host_patterns: [],
				ip_ranges: [],
				category: BotCategory::AI_CRAWLER,
			),
		]);
		$merged = new MergedRegistry([$earlier, $later]);

		$matches = $merged->find_by_ua('NewTokenGPT/1.0');
		$this->assertContains('gptbot', $matches);

		$matches_old = $merged->find_by_ua('OldTokenGPT/1.0');
		$this->assertNotContains('gptbot', $matches_old,
			'Old UA pattern must NOT match after override (replacement, not merge)');
	}

	public function test_find_by_tokens_finds_across_registries(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry([]),
			new InMemoryRegistry($this->bots_in_category(BotCategory::MONITORING, [
				['unique_marker_bot', 'UniqueMarker77'],
			])),
		]);

		$matches = $merged->find_by_tokens('Mozilla compatible UniqueMarker77/1.0');
		$this->assertContains('unique_marker_bot', $matches);
	}

	// ============================================================
	// 8. Integration with DefaultRegistry + additions
	// ============================================================

	public function test_default_plus_additions_pattern(): void
	{
		// The canonical "extend shipped registry" pattern.
		$my_bot = new BotDefinition(
			id: 'internal_monitor',
			name: 'Internal Monitor',
			user_agent_patterns: ['InternalMonitor/1.0'],
			host_patterns: [],
			ip_ranges: ['10.0.0.0/8'],
			category: BotCategory::MONITORING,
			default_action: BotAction::ALLOW,
		);

		$merged = new MergedRegistry([
			new DefaultRegistry(),
			new InMemoryRegistry(['internal_monitor' => $my_bot]),
		]);

		// Shipped bots present
		$this->assertTrue($merged->has('googlebot'));
		$this->assertTrue($merged->has('gptbot'));
		$this->assertTrue($merged->has('cloudflare_health'));

		// My addition present
		$this->assertTrue($merged->has('internal_monitor'));
		$this->assertSame(
			$my_bot,
			$merged->get('internal_monitor'),
			'Additions must be retrievable from the merged view'
		);

		// Count is reasonable (DefaultRegistry ships ~100 bots + 1)
		$this->assertGreaterThan(50, $merged->count(),
			'DefaultRegistry should contribute many bots');
		$this->assertGreaterThanOrEqual(
			(new DefaultRegistry())->count() + 1,
			$merged->count(),
			'Merged count must include DefaultRegistry + additions'
		);
	}

	public function test_three_registries_compose_correctly(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry([
				'a' => $this->mkBot('a', BotCategory::MONITORING, ['A']),
			]),
			new InMemoryRegistry([
				'b' => $this->mkBot('b', BotCategory::MONITORING, ['B']),
			]),
			new InMemoryRegistry([
				'c' => $this->mkBot('c', BotCategory::MONITORING, ['C']),
			]),
		]);

		$this->assertSame(3, $merged->count());
		$this->assertTrue($merged->has('a'));
		$this->assertTrue($merged->has('b'));
		$this->assertTrue($merged->has('c'));
	}

	// ============================================================
	// 9. Override wins even when earlier registry was larger
	// ============================================================

	public function test_override_with_smaller_later_registry(): void
	{
		$merged = new MergedRegistry([
			new InMemoryRegistry([
				'a' => $this->mkBot('a', BotCategory::MONITORING, ['A']),
				'b' => $this->mkBot('b', BotCategory::MONITORING, ['B']),
				'c' => $this->mkBot('c', BotCategory::MONITORING, ['C']),
			]),
			new InMemoryRegistry([
				// Only an override for 'a' — 'b' and 'c' stay from earlier.
				'a' => $this->mkBot('a', BotCategory::AI_CRAWLER, ['A2']),
			]),
		]);

		$this->assertCount(3, $merged->all());
		$this->assertSame(BotCategory::AI_CRAWLER, $merged->get('a')->category,
			'Ovevride category wins');
		$this->assertSame(['A2'], $merged->get('a')->user_agent_patterns,
			'Override UA patterns win');
		$this->assertSame(BotCategory::MONITORING, $merged->get('b')->category,
			'Untouched bot retains original category');
	}

	// ============================================================
	// Helpers (private)
	// ============================================================

	private function mkBot(
		string $id,
		BotCategory $category,
		array $ua_patterns,
	): BotDefinition {
		return new BotDefinition(
			id: $id,
			name: "Bot {$id}",
			user_agent_patterns: $ua_patterns,
			host_patterns: [],
			ip_ranges: [],
			category: $category,
			default_action: BotAction::ALLOW,
		);
	}
}
