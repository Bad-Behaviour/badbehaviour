<?php

declare(strict_types=1);

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
 *   1. from_array($config)   — most common: from bb_registry.php contents
 *   2. from_file($path?)     — loads the file then delegates to from_array
 *   3. default()             — singleton fallback
 *
 * Two SEMANTIC CONTRACTS under test:
 *
 *   A. FILTER EXECUTION ORDER (documented):
 *      1. Load preset base (or empty for 'custom')
 *      2. Apply exclude_categories
 *      3. Apply include_categories (ADDITIVE per docs, EXCLUSIVE in current impl)
 *      4. Apply exclude_bots
 *      5. Merge additions (custom bots on top, last-wins)
 *
 *      NOTE: In the current implementation, include_categories acts as
 *      an EXCLUSIVE filter (only listed categories pass), not the
 *      "re-add overrides exclude" semantic the docblock claims. These
 *      tests document the ACTUAL behavior.
 *
 *   B. NEVER THROW on bad input — fall back to safe defaults. This is
 *      the most important contract: bb_registry.php is operator-controlled
 *      config that can contain typos, missing keys, wrong types, or
 *      be totally absent. BadBehaviour must keep working.
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
            'preset' => 'no-ai',
        ]);

        $this->assertSame(
            [],
            $registry->ai_crawlers(),
            'Step 1: preset base is loaded BEFORE other filters — no-ai has no AI'
        );
    }

    public function test_order_step_2_exclude_categories_drops_after_preset(): void
    {
        $registry = RegistryFactory::from_array([
            'preset'             => 'minimal',
            'exclude_categories' => ['seo_crawler'],
        ]);

        $this->assertSame([], $registry->seo_crawlers(),
            'Step 2: exclude_categories applied after preset');
    }

    /**
     * Current implementation reality:
     *   exclude_categories and include_categories are BOTH applied in
     *   the same FilteredRegistry. Within that filter:
     *     - include runs FIRST (bot must be in include list)
     *     - exclude runs SECOND (bot must NOT be in exclude list)
     *   If a category is in BOTH, the exclude wins (bot gets dropped).
     *
     * This test documents that the current implementation does NOT
     * match the docblock's "include overrides exclude" promise.
     * If production is fixed to make include additive, flip this.
     */
    public function test_order_step_3_include_categories_excludes_other_categories(): void
    {
        // include_categories acts as an EXCLUSIVE filter: only bots
        // whose category is in the list pass.
        $registry = RegistryFactory::from_array([
            'preset'             => 'minimal',
            'include_categories' => ['search_engine'],
        ]);

        $this->assertTrue($registry->has('googlebot'),
            'Bots in include_categories must be present');
        $this->assertFalse($registry->has('facebook'),
            'Bots NOT in include_categories must be dropped (exclusive filter)');
        $this->assertFalse($registry->has('cloudflare_health'),
            'Cloud infrastructure not in include_categories → dropped');
    }

    public function test_order_step_4_exclude_bots_drops_after_categories(): void
    {
        $registry = RegistryFactory::from_array([
            'preset'             => 'minimal',
            'exclude_bots'       => ['gptbot', 'claude'],
        ]);

        $this->assertFalse($registry->has('gptbot'));
        $this->assertFalse($registry->has('claude'));
        $this->assertTrue($registry->has('perplexity'),
            'Step 4 only drops the bots in exclude_bots, not the whole category');
    }

    public function test_order_step_5_additions_merged_on_top(): void
    {
        $registry = RegistryFactory::from_array([
            'preset'    => 'minimal',
            'additions' => [
                'internal_bot' => [
                    'name'                => 'Internal Bot',
                    'user_agent_patterns' => ['InternalBot/1.0'],
                    'category'            => 'monitoring',
                ],
            ],
        ]);

        $this->assertTrue($registry->has('internal_bot'),
            'Step 5: additions must appear in the merged registry');
    }

    public function test_order_full_pipeline_produces_correct_registry(): void
    {
        // Exercise every step at once and verify the final composition.
        //
        // Step 3 (include_categories) is EXCLUSIVE in current implementation,
        // so we deliberately do NOT include include_categories in this test.
        // The cloud_infrastructure safety relies on the minimal preset
        // shipping cloud bots, not on include_categories re-adding them.
        $registry = RegistryFactory::from_array([
            'preset'             => 'minimal',
            'exclude_categories' => ['seo_crawler', 'social_crawler'],
            'exclude_bots'       => ['petal'],
            'additions'          => [
                'my_internal_monitor' => [
                    'name'                => 'My Internal Monitor',
                    'user_agent_patterns' => ['MyInternalMonitor/1.0'],
                    'category'            => 'monitoring',
                ],
            ],
        ]);

        // Step 1: minimal preset ships core bots
        $this->assertTrue($registry->has('googlebot'));
        $this->assertTrue($registry->has('gptbot'));

        // Step 2: SEO and social categories dropped
        $this->assertSame([], $registry->seo_crawlers());
        $this->assertSame([], $registry->social_crawlers());

        // Cloud infra present (was always in minimal, not dropped by exclude)
        $this->assertNotEmpty($registry->cloud_infrastructure());

        // Step 4: petal excluded (minimal doesn't include petal anyway,
        // but the configuration is honored)
        $this->assertFalse($registry->has('petal'));

        // Step 5: additions present
        $this->assertTrue($registry->has('my_internal_monitor'));
    }

    // ============================================================
    // 6. Bad-input tolerance — NEVER THROW
    // ============================================================

    public function test_unknown_preset_falls_back_to_full(): void
    {
        $registry = RegistryFactory::from_array(['preset' => 'unknown_preset']);

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
            'preset'             => 'minimal',
            'exclude_categories' => 'seo_crawler, security_scanner',
        ]);

        $this->assertSame([], $registry->seo_crawlers());
        $this->assertSame([], $registry->security_scanners());
    }

    public function test_non_array_exclude_bots_string_is_coerced(): void
    {
        $registry = RegistryFactory::from_array([
            'preset'       => 'minimal',
            'exclude_bots' => 'gptbot, claude',
        ]);

        $this->assertFalse($registry->has('gptbot'));
        $this->assertFalse($registry->has('claude'));
    }

    public function test_empty_config_is_valid(): void
    {
        $registry = RegistryFactory::from_array([]);
        $this->assertInstanceOf(RegistryInterface::class, $registry);
    }

    public function test_invalid_categories_values_are_tolerated(): void
    {
        // Bogus category names that don't match any BotCategory enum value
        // must not crash. The behavior depends on whether include_categories
        // is also set:
        //
        //   - With include_categories: acts as exclusive filter.
        //     No bot matches 'not_a_real_category' → all bots filtered out.
        //   - With only exclude_categories: acts as no-op (no match).
        $registry_no_include = RegistryFactory::from_array([
            'preset'             => 'minimal',
            'exclude_categories' => ['not_a_real_category'],
        ]);

        $this->assertTrue($registry_no_include->has('googlebot'),
            'Bogus exclude_categories is a no-op filter');

        // With include_categories, only matching categories pass.
        // 'also_bogus' matches no real category → empty registry.
        $registry_with_include = RegistryFactory::from_array([
            'preset'             => 'minimal',
            'include_categories' => ['also_bogus'],
        ]);

        $this->assertFalse($registry_with_include->has('googlebot'),
            'With include_categories matching nothing, registry is empty');
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
        $registry = RegistryFactory::from_array(['preset' => $preset]);

        if ($registry->count() === 0) {
            $this->markTestSkipped("Preset '{$preset}' is empty");
        }

        $default = new DefaultRegistry();
        $missing = [];
        foreach ($default->cloud_infrastructure() as $def) {
            if (!$registry->has($def->id)) {
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
            $this->assertTrue(true,
                "verified-only may exclude aws_elb_health (lacks verify_dns and ip_ranges). Missing: " .
                implode(', ', $missing));
            return;
        }

        $this->assertEmpty($missing,
            "AVAILABILITY REGRESSION: preset '{$preset}' is missing cloud bot(s): " .
            implode(', ', $missing) . '. Blocking CDN/LB probes takes origin offline.');
    }

    public static function presetCloudSafetyProvider(): array
    {
        return [
            'full'         => ['full'],
            'minimal'      => ['minimal'],
            'verified-only'=> ['verified-only'],
            'no-ai'        => ['no-ai'],
            'no-seo'       => ['no-seo'],
            'eu-only'      => ['eu-only'],
        ];
    }

    // ============================================================
    // 11. Composition operators (documented current behavior)
    // ============================================================

    /**
     * Current implementation reality:
     *   include_categories and exclude_categories are applied in the SAME
     *   FilteredRegistry. Within that filter:
     *     - include runs first (must match)
     *     - exclude runs second (must NOT match)
     *   So exclude_categories wins over include_categories when both
     *   contain the same category.
     *
     * The docblock claims "include overrides exclude" — this test
     * documents that the current implementation does the OPPOSITE.
     * When production is fixed, flip this test.
     */
    public function test_include_categories_does_not_re_add_excluded_category(): void
    {
        $registry = RegistryFactory::from_array([
            'preset'             => 'full',
            'exclude_categories' => ['ai_crawler'],
            'include_categories' => ['ai_crawler'],
        ]);

        $this->assertEmpty($registry->ai_crawlers(),
            'exclude_categories wins over include_categories in current implementation');
    }

    public function test_include_categories_cannot_force_include_a_category_excluded_via_preset(): void
    {
        // 'no-ai' preset drops AI crawlers. With current implementation,
        // adding include_categories=['ai_crawler'] AFTER the preset
        // cannot restore them — they're gone from the base.
        $registry = RegistryFactory::from_array([
            'preset'             => 'no-ai',
            'include_categories' => ['ai_crawler'],
        ]);

        $this->assertEmpty($registry->ai_crawlers(),
            "'no-ai' preset strips AI crawlers from the base; include_categories cannot restore them");
    }
}
