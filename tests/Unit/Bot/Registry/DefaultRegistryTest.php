<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Bot\Registry;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Util\IpUtil;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tier 3 (defense-in-depth) tests for DefaultRegistry.
 *
 * DefaultRegistry is the shipped registry of ~100 verified bots. Every
 * entry must satisfy FOUR invariants:
 *
 * 1. USER-AGENT PATTERNS — at least one non-empty pattern (≥4 chars
 * to match the matching threshold), and every pattern is a string.
 *
 * 2. VALID CATEGORY — the category is one of the BotCategory enum
 * values. Bots with INVALID categories can't be matched to a
 * per-category action in BotDetector::determine_action().
 *
 * 3. PARSEABLE CIDRs — every entry in ip_ranges, if any, must be
 * parseable by IpUtil::match_cidr(). A malformed CIDR breaks
 * BotDetector's static range check.
 *
 * 4. ID UNIQUENESS across the entire registry. Duplicate IDs cause
 * last-wins semantics where only one definition is reachable,
 * silently dropping the other.
 *
 * These tests are intentionally broad and "low specificity" — they
 * don't assert specific bots, just that the registry's STRUCTURE is
 * valid. A bot being added/removed is fine; a bot with a broken CIDR
 * or invalid category is a P0 bug.
 *
 * === KNOWN PRODUCTION QUIRKS (documented in tests) ===
 *
 * - 'iabot' lives in utility_bots() but is categorized as
 * ARCHIVE_CRAWLER. It does not appear in any per-category accessor
 * method. Tests skip it for partition checks.
 *
 * - 'aws_elb_health' has empty ip_ranges and verify_dns=false —
 * matches by UA pattern only. The cloud-infra safety for this
 * specific bot depends on the UA matching working (it always does,
 * since 'ELB-HealthChecker' is in the UA patterns). Tests skip it
 * for the ip_ranges check.
 */
final class DefaultRegistryTest extends TestCase
{

	// ---------- Helpers ----------
	private function get_default(): DefaultRegistry
	{
		return new DefaultRegistry();
	}

	private function all_bot_ids(DefaultRegistry $registry): array
	{
		return array_keys($registry->all());
	}

	// ============================================================
	// 1. Sanity
	// ============================================================
	public function test_default_registry_is_non_empty(): void
	{
		$registry = $this->get_default();
		$this->assertGreaterThan(0, $registry->count());
	}

	public function test_default_registry_ships_a_substantial_number_of_bots(): void
	{
		$count = $this->get_default()->count();
		$this->assertGreaterThanOrEqual(50, $count, "DefaultRegistry should ship at least 50 bots (got {$count})");
	}

	// ============================================================
	// 2. ID uniqueness
	// ============================================================
	public function test_all_bot_ids_are_unique(): void
	{
		$registry = $this->get_default();
		$ids = $this->all_bot_ids($registry);
		$this->assertSame(count($ids), count(array_unique($ids)));
	}

	public function test_no_empty_bot_ids(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertNotEmpty($id);
			$this->assertIsString($id);
		}
	}

	public function test_bot_id_matches_definition_id(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertSame($id, $def->id);
		}
	}

	// ============================================================
	// 3. User-Agent patterns
	// ============================================================
	public function test_every_bot_has_at_least_one_user_agent_pattern(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertNotEmpty($def->user_agent_patterns, "Bot '{$id}' has no user_agent_patterns");
		}
	}

	public function test_every_user_agent_pattern_is_a_string(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			foreach ($def->user_agent_patterns as $i => $pattern) {
				$this->assertIsString($pattern, "Bot '{$id}' has non-string UA pattern at index {$i}");
			}
		}
	}

	public function test_every_user_agent_pattern_is_non_empty(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			foreach ($def->user_agent_patterns as $i => $pattern) {
				$this->assertNotEmpty(trim((string) $pattern), "Bot '{$id}' has empty UA pattern at index {$i}");
			}
		}
	}

	public function test_every_user_agent_pattern_meets_minimum_length(): void
	{
		$registry = $this->get_default();
		$min_useful_length = 4;

		foreach ($registry->all() as $id => $def) {
			$has_long_enough = false;
			foreach ($def->user_agent_patterns as $pattern) {
				if (strlen((string) $pattern) >= $min_useful_length) {
					$has_long_enough = true;
					break;
				}
			}
			$this->assertTrue($has_long_enough, "Bot '{$id}' has no UA patterns ≥{$min_useful_length} chars");
		}
	}

	// ============================================================
	// 4. Valid categories
	// ============================================================
	public function test_every_bot_has_a_valid_category(): void
	{
		$registry = $this->get_default();
		$valid_categories = array_column(BotCategory::cases(), 'value');

		foreach ($registry->all() as $id => $def) {
			$this->assertContains($def->category->value, $valid_categories, "Bot '{$id}' has invalid category '{$def->category->value}'");
		}
	}

	public function test_every_bot_category_is_a_botcategory_enum_instance(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertInstanceOf(BotCategory::class, $def->category, "Bot '{$id}' category is not a BotCategory enum");
		}
	}

	public function test_all_category_accessors_return_only_that_category(): void
	{
		$registry = $this->get_default();
		$accessors = [
			'search_engines',
			'ai_crawlers',
			'social_crawlers',
			'seo_crawlers',
			'archive_crawlers',
			'monitoring',
			'feed_readers',
			'shopping_crawlers',
			'cloud_infrastructure',
			'security_scanners',
			'residential_crawlers'
		];

		foreach ($registry->all() as $id => $def) {
			// KNOWN LIMITATION: 'iabot' is in utility_bots() but is
			// categorized as ARCHIVE_CRAWLER. It does not appear in
			// archive_crawlers() because that accessor iterates the
			// archive_crawlers() definition list, not all().
			if ($id === 'iabot') {
				continue;
			}

			$appearances = 0;
			foreach ($accessors as $method) {
				if (isset($registry->$method()[$id])) {
					$appearances ++;
				}
			}
			$this->assertSame(1, $appearances, "Bot '{$id}' appears in {$appearances} category accessors (must be exactly 1)");
		}
	}

	// ============================================================
	// 5. CIDR validity
	// ============================================================
	public function test_every_ip_range_is_a_non_empty_string(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			foreach ($def->ip_ranges as $i => $cidr) {
				$this->assertIsString($cidr, "Bot '{$id}' has non-string IP range at index {$i}");
				$this->assertNotEmpty(trim($cidr), "Bot '{$id}' has empty IP range at index {$i}");
			}
		}
	}

	public function test_every_ip_range_is_parseable_by_iputil(): void
	{
		$registry = $this->get_default();

		$failures = [];
		foreach ($registry->all() as $id => $def) {
			foreach ($def->ip_ranges as $cidr) {
				if (! $this->cidr_is_parseable((string) $cidr)) {
					$failures[] = "Bot '{$id}' has unparseable CIDR '{$cidr}'";
				}
			}
		}

		$this->assertEmpty($failures, "DefaultRegistry contains invalid CIDRs:\n  " . implode("\n  ", $failures));
	}

	private function cidr_is_parseable(string $cidr): bool
	{
		if (! str_contains($cidr, '/')) {
			return false;
		}

		[
			$network,
			$mask
		] = explode('/', $cidr, 2);
		$network = trim($network);
		$mask = (int) trim($mask);

		$is_ipv6 = filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
		if ($is_ipv6) {
			if ($mask < 0 || $mask > 128)
				return false;
		} else {
			if ($mask < 0 || $mask > 32)
				return false;
		}

		return IpUtil::match_cidr($network, $cidr);
	}

	// ============================================================
	// 6. Cloud infrastructure safety
	// ============================================================
	public function test_cloud_infrastructure_bots_are_present(): void
	{
		$registry = $this->get_default();
		$cloud = $registry->cloud_infrastructure();

		$this->assertNotEmpty($cloud, 'DefaultRegistry must ship cloud_infrastructure bots');
	}

	#[DataProvider('expectedCloudBotProvider')]
	public function test_expected_cloud_bot_is_present(string $bot_id): void
	{
		$registry = $this->get_default();
		$this->assertTrue($registry->has($bot_id), "DefaultRegistry must ship cloud_infrastructure bot '{$bot_id}'");
	}

	public static function expectedCloudBotProvider(): array
	{
		return [
			'Cloudflare' => [
				'cloudflare_health'
			],
			'AWS ELB' => [
				'aws_elb_health'
			],
			'GCP LB' => [
				'google_cloud_health'
			],
			'Azure LB' => [
				'azure_health'
			],
			'Fastly' => [
				'fastly_health'
			]
		];
	}

	public function test_cloud_infrastructure_bots_have_ip_ranges(): void
	{
		$registry = $this->get_default();

		foreach ($registry->cloud_infrastructure() as $id => $def) {
			// KNOWN LIMITATION: aws_elb_health has empty ip_ranges and
			// verify_dns=false. It matches by UA pattern only ('ELB-HealthChecker').
			// This is technically not as robust as IP-range matching, but
			// the UA pattern is distinctive enough.
			if ($id === 'aws_elb_health') {
				continue;
			}

			$this->assertNotEmpty($def->ip_ranges, "Cloud bot '{$id}' has no ip_ranges");
		}
	}

	public function test_cloud_infrastructure_bots_have_default_action_allow(): void
	{
		$registry = $this->get_default();
		foreach ($registry->cloud_infrastructure() as $id => $def) {
			$this->assertSame(BotAction::ALLOW, $def->default_action, "Cloud bot '{$id}' has default_action={$def->default_action->value}, expected ALLOW");
		}
	}

	// ============================================================
	// 7. Required key population
	// ============================================================
	public function test_every_bot_has_a_name(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertNotEmpty($def->name, "Bot '{$id}' has an empty name");
		}
	}

	public function test_every_bot_has_a_default_action_enum(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertInstanceOf(BotAction::class, $def->default_action, "Bot '{$id}' default_action is not a BotAction enum");
		}
	}

	public function test_every_bot_host_patterns_is_array(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertIsArray($def->host_patterns, "Bot '{$id}' host_patterns must be an array");
		}
	}

	public function test_every_bot_dns_suffixes_is_array(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			$this->assertIsArray($def->dns_suffixes, "Bot '{$id}' dns_suffixes must be an array");
		}
	}

	// ============================================================
	// 8. Cross-field consistency
	// ============================================================
	public function test_verify_dns_true_bots_have_dns_suffixes(): void
	{
		$registry = $this->get_default();
		$violations = [];
		foreach ($registry->all() as $id => $def) {
			if ($def->verify_dns && empty($def->dns_suffixes)) {
				$violations[] = $id;
			}
		}
		$this->assertEmpty($violations, 'Bots with verify_dns=true but empty dns_suffixes: ' . implode(', ', $violations));
	}

	public function test_robots_txt_token_is_string_or_null(): void
	{
		$registry = $this->get_default();
		foreach ($registry->all() as $id => $def) {
			if ($def->robots_txt_token !== null) {
				$this->assertIsString($def->robots_txt_token, "Bot '{$id}' robots_txt_token must be null or string");
			}
		}
	}

	// ============================================================
	// 9. RegistryInterface contract
	// ============================================================
	public function test_has_returns_true_for_known_bot(): void
	{
		$registry = $this->get_default();
		$ids = $this->all_bot_ids($registry);
		$this->assertNotEmpty($ids);
		$this->assertTrue($registry->has($ids[0]));
	}

	public function test_has_returns_false_for_unknown_bot(): void
	{
		$registry = $this->get_default();
		$this->assertFalse($registry->has('not_a_real_bot_definitely_not_in_registry'));
	}

	public function test_get_returns_definition_for_known_bot(): void
	{
		$registry = $this->get_default();
		$ids = $this->all_bot_ids($registry);

		$def = $registry->get($ids[0]);
		$this->assertInstanceOf(BotDefinition::class, $def);
		$this->assertSame($ids[0], $def->id);
	}

	public function test_get_returns_null_for_unknown_bot(): void
	{
		$registry = $this->get_default();
		$this->assertNull($registry->get('not_in_registry_xyz'));
	}

	public function test_all_returns_definitions_for_every_bot(): void
	{
		$registry = $this->get_default();
		$all = $registry->all();

		$this->assertIsArray($all);
		$this->assertSame($registry->count(), count($all));

		foreach ($all as $id => $def) {
			$this->assertInstanceOf(BotDefinition::class, $def);
		}
	}

	// ============================================================
	// 10. find_by_ua / find_by_tokens
	// ============================================================
	public function test_find_by_ua_finds_googlebot_in_googlebot_ua(): void
	{
		$registry = $this->get_default();
		$matches = $registry->find_by_ua('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
		$this->assertContains('googlebot', $matches);
	}

	public function test_find_by_ua_returns_empty_for_clean_browser_ua(): void
	{
		$registry = $this->get_default();
		$matches = $registry->find_by_ua('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
		$this->assertEmpty($matches, 'A clean Chrome UA must not match any bot');
	}

	public function test_find_by_ua_returns_empty_for_empty_string(): void
	{
		$registry = $this->get_default();
		$this->assertSame([], $registry->find_by_ua(''));
	}

	public function test_find_by_tokens_returns_empty_for_empty_string(): void
	{
		$registry = $this->get_default();
		$this->assertSame([], $registry->find_by_tokens(''));
	}

	public function test_find_by_tokens_finds_known_bot_token(): void
	{
		$registry = $this->get_default();
		$matches = $registry->find_by_tokens('Mozilla compatible GPTBot/1.0');
		$this->assertContains('gptbot', $matches);
	}

	// ============================================================
	// 11. Per-category accessor integrity
	// ============================================================
	public function test_per_category_accessors_partition_the_registry(): void
	{
		$registry = $this->get_default();

		$accessors = [
			'search_engines',
			'ai_crawlers',
			'social_crawlers',
			'seo_crawlers',
			'archive_crawlers',
			'monitoring',
			'feed_readers',
			'shopping_crawlers',
			'cloud_infrastructure',
			'security_scanners',
			'residential_crawlers'
		];

		$total_from_accessors = 0;
		foreach ($accessors as $method) {
			$total_from_accessors += count($registry->$method());
		}

		// KNOWN LIMITATION: 'iabot' lives in utility_bots() (defined
		// alongside other helpers, not in archive_crawlers()). It's
		// counted in all() but not in any category accessor. So the
		// accessor sum is (total - 1).
		$this->assertSame($registry->count() - 1, $total_from_accessors, "Sum of per-category counts should equal total - 1 " . "('iabot' is in utility_bots(), not in any category accessor)");
	}

	// ============================================================
	// 12. Spot-check: well-known bots
	// ============================================================
	#[DataProvider('expectedBotProvider')]
	public function test_expected_bot_is_present(string $bot_id, string $expected_category): void
	{
		$registry = $this->get_default();
		$this->assertTrue($registry->has($bot_id), "DefaultRegistry should ship '{$bot_id}'");

		$def = $registry->get($bot_id);
		$this->assertSame($expected_category, $def->category->value, "Bot '{$bot_id}' has wrong category '{$def->category->value}' (expected '{$expected_category}')");
	}

	public static function expectedBotProvider(): array
	{
		return [
			'googlebot' => [
				'googlebot',
				'search_engine'
			],
			'bingbot' => [
				'bingbot',
				'search_engine'
			],
			'yandex' => [
				'yandex',
				'search_engine'
			],
			'duckduckgo' => [
				'duckduckgo',
				'search_engine'
			],
			'gptbot' => [
				'gptbot',
				'ai_crawler'
			],
			'claude' => [
				'claude',
				'ai_crawler'
			],
			'perplexity' => [
				'perplexity',
				'ai_crawler'
			],
			'google_ai' => [
				'google_ai',
				'ai_crawler'
			],
			'meta_ai' => [
				'meta_ai',
				'ai_crawler'
			],
			'facebook' => [
				'facebook',
				'social_crawler'
			],
			'twitter' => [
				'twitter',
				'social_crawler'
			],
			'linkedin' => [
				'linkedin',
				'social_crawler'
			],
			'semrush' => [
				'semrush',
				'seo_crawler'
			],
			'ahrefs' => [
				'ahrefs',
				'seo_crawler'
			],
			'uptimerobot' => [
				'uptimerobot',
				'monitoring'
			],
			'brightdata' => [
				'brightdata',
				'residential_proxy'
			]
		];
	}
}
