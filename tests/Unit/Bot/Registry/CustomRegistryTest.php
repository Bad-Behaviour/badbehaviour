<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Bot\Registry;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\CustomRegistry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tier 2 (should-have) tests for CustomRegistry.
 *
 * CustomRegistry is the bridge between config-style arrays (the shape
 * operators write in bb_config.php → bb_registry.php) and typed
 * BotDefinition objects. Its validation surface is large:
 *
 * - required: name, user_agent_patterns (≥1 entry, each ≥3 chars), category
 * - optional: host_patterns, ip_ranges, verify_dns, dns_suffixes,
 * robots_txt_token, default_action, description
 * - constraint: category must be a valid BotCategory enum value
 * - constraint: default_action must be a valid BotAction enum value
 * - constraint: ip_ranges must be valid CIDR-shaped strings
 * - constraint: dns_suffixes must be non-empty strings
 *
 * Two key contracts under test:
 *
 * 1. INVALID ENTRIES ARE NOT THROWN — they're recorded via get_errors()
 * and has_errors(); valid entries still load. The registry must
 * never crash the host application on bad config.
 *
 * 2. add() bypasses validation (programmatic insertion path). It must
 * still WORK when called with a valid BotDefinition, even though
 * it doesn't check its inputs.
 *
 * === KNOWN LIMITATION ===
 *
 * The CIDR validator uses a loose regex `^[\d\.:a-fA-F]+/\d+$` that
 * accepts malformed CIDRs like `10.0.0.0/999` (mask out of range)
 * or `10.0.0.a/24` (invalid IPv4 octet). These tests document what
 * the current regex ACTUALLY rejects, not what it ideally should.
 */
final class CustomRegistryTest extends TestCase
{

	// ---------- Helpers ----------
	private function valid_bot(string $id = 'test_bot'): array
	{
		return [
			'name' => 'Test Bot',
			'user_agent_patterns' => [
				'TestBot/1.0'
			],
			'category' => 'search_engine'
		];
	}

	private function full_bot(string $id = 'full_bot'): array
	{
		return [
			'name' => 'Full Bot',
			'user_agent_patterns' => [
				'FullBot',
				'FullBot/2.0'
			],
			'host_patterns' => [
				'fullbot.example.com'
			],
			'ip_ranges' => [
				'192.0.2.0/24'
			],
			'verify_dns' => true,
			'dns_suffixes' => [
				'fullbot.example.com'
			],
			'category' => 'ai_crawler',
			'robots_txt_token' => 'FullBot',
			'default_action' => 'challenge',
			'description' => 'A test bot exercising every field'
		];
	}

	// ============================================================
	// 1. Happy path
	// ============================================================
	public function test_minimal_valid_bot_loads_cleanly(): void
	{
		$registry = new CustomRegistry([
			'minimal_bot' => $this->valid_bot('minimal_bot')
		]);

		$this->assertFalse($registry->has_errors());
		$this->assertSame([], $registry->get_errors());
		$this->assertCount(1, $registry->all());
		$this->assertTrue($registry->has('minimal_bot'));
	}

	public function test_full_bot_loads_cleanly(): void
	{
		$registry = new CustomRegistry([
			'full_bot' => $this->full_bot()
		]);

		$this->assertFalse($registry->has_errors());
		$this->assertSame([], $registry->get_errors());
		$this->assertCount(1, $registry->all());

		$def = $registry->get('full_bot');
		$this->assertNotNull($def);
		$this->assertSame('full_bot', $def->id);
		$this->assertSame('Full Bot', $def->name);
		$this->assertSame([
			'FullBot',
			'FullBot/2.0'
		], $def->user_agent_patterns);
		$this->assertSame(BotCategory::AI_CRAWLER, $def->category);
		$this->assertSame('FullBot', $def->robots_txt_token);
		$this->assertSame(BotAction::CHALLENGE, $def->default_action);
	}

	public function test_from_array_factory_is_an_alias_for_constructor(): void
	{
		$a = new CustomRegistry([
			'bot_a' => $this->valid_bot('bot_a')
		]);
		$b = CustomRegistry::from_array([
			'bot_a' => $this->valid_bot('bot_a')
		]);

		$this->assertSame($a->count(), $b->count());
		$this->assertTrue($a->has('bot_a') && $b->has('bot_a'));
	}

	public function test_default_action_defaults_to_allow_when_omitted(): void
	{
		$registry = new CustomRegistry([
			'no_action' => [
				'name' => 'No Action',
				'user_agent_patterns' => [
					'NoActionBot'
				],
				'category' => 'monitoring'
			]
		]);

		$this->assertFalse($registry->has_errors());
		$def = $registry->get('no_action');
		$this->assertNotNull($def);
		$this->assertSame(BotAction::ALLOW, $def->default_action, 'Omitted default_action must default to ALLOW');
	}

	// ============================================================
	// 2. Required-field rejections
	// ============================================================
	public function test_missing_name_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => [
				'user_agent_patterns' => [
					'Bot'
				],
				'category' => 'search_engine'
			]
		]);

		$this->assertTrue($registry->has_errors());
		$this->assertCount(0, $registry->all());
		$this->assertStringContainsString('name', $registry->get_errors()[0]['error']);
	}

	public function test_empty_name_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'name' => ''
			])
		]);

		$this->assertTrue($registry->has_errors());
		$this->assertFalse($registry->has('bot'));
	}

	public function test_non_string_name_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'name' => [
					'nope'
				]
			])
		]);

		$this->assertTrue($registry->has_errors());
		$this->assertFalse($registry->has('bot'));
	}

	public function test_missing_user_agent_patterns_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => [
				'name' => 'Bot',
				'category' => 'search_engine'
			]
		]);

		$this->assertTrue($registry->has_errors());
		$this->assertStringContainsString('user_agent_patterns', $registry->get_errors()[0]['error']);
	}

	public function test_empty_user_agent_patterns_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'user_agent_patterns' => []
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public function test_missing_category_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => [
				'name' => 'Bot',
				'user_agent_patterns' => [
					'Bot'
				]
			]
		]);

		$this->assertTrue($registry->has_errors());
		$this->assertStringContainsString('category', $registry->get_errors()[0]['error']);
	}

	public function test_non_string_category_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'category' => 42
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	// ============================================================
	// 3. user_agent_patterns granularity
	// ============================================================
	#[DataProvider('tooShortPatternProvider')]
	public function test_user_agent_patterns_shorter_than_three_chars_is_rejected(string $pattern): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'user_agent_patterns' => [
					$pattern
				]
			])
		]);

		$this->assertTrue($registry->has_errors(), "UA pattern '{$pattern}' must be rejected");
		$this->assertFalse($registry->has('bot'));
	}

	public static function tooShortPatternProvider(): array
	{
		return [
			'one char' => [
				'B'
			],
			'two chars' => [
				'Bo'
			]
		];
	}

	public function test_empty_string_pattern_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'user_agent_patterns' => [
					''
				]
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public function test_non_string_pattern_entry_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'user_agent_patterns' => [
					'Valid',
					123,
					'AlsoValid'
				]
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public function test_at_least_one_valid_pattern_in_mixed_list_rejects_whole_entry(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'user_agent_patterns' => [
					'GoodBot',
					'B'
				]
			])
		]);

		$this->assertTrue($registry->has_errors(), 'One invalid pattern must drop the entire bot definition');
		$this->assertFalse($registry->has('bot'));
	}

	// ============================================================
	// 4. Category enum validation
	// ============================================================
	#[DataProvider('invalidCategoryProvider')]
	public function test_invalid_category_is_rejected(string $category): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'category' => $category
			])
		]);

		$this->assertTrue($registry->has_errors());
		$this->assertStringContainsString('category', $registry->get_errors()[0]['error']);
	}

	public static function invalidCategoryProvider(): array
	{
		return [
			'not_an_enum' => [
				'not_a_real_category'
			],
			'capitalized' => [
				'Search_Engine'
			],
			'with_typo' => [
				'serch_engine'
			],
			'empty_string' => [
				''
			]
		];
	}

	public function test_all_bot_category_values_are_accepted(): void
	{
		foreach (BotCategory::cases() as $cat) {
			$registry = new CustomRegistry([
				"bot_{$cat->value}" => array_merge($this->valid_bot(), [
					'category' => $cat->value
				])
			]);

			$this->assertFalse($registry->has_errors(), "BotCategory::{$cat->name} ('{$cat->value}') must be a valid category value");
			$this->assertTrue($registry->has("bot_{$cat->value}"));
		}
	}

	// ============================================================
	// 5. default_action enum validation
	// ============================================================
	#[DataProvider('invalidActionProvider')]
	public function test_invalid_default_action_is_rejected(string $action): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'default_action' => $action
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public static function invalidActionProvider(): array
	{
		return [
			'wrong_word' => [
				'reject'
			],
			'capitalized' => [
				'BLOCK'
			],
			'with_typo' => [
				'chalenge'
			],
			'empty_string' => [
				''
			]
		];
	}

	public function test_all_bot_action_values_are_accepted(): void
	{
		foreach (BotAction::cases() as $action) {
			$registry = new CustomRegistry([
				"bot_{$action->value}" => array_merge($this->valid_bot(), [
					'default_action' => $action->value
				])
			]);

			$this->assertFalse($registry->has_errors(), "BotAction::{$action->name} ('{$action->value}') must be a valid default_action");

			$def = $registry->get("bot_{$action->value}");
			$this->assertSame($action, $def->default_action);
		}
	}

	// ============================================================
	// 6. CIDR validation
	// ============================================================
	public function test_valid_ipv4_cidrs_are_accepted(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'ip_ranges' => [
					'10.0.0.0/8',
					'192.0.2.0/24',
					'172.16.0.0/12'
				]
			])
		]);

		$this->assertFalse($registry->has_errors());
	}

	public function test_valid_ipv6_cidrs_are_accepted(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'ip_ranges' => [
					'2001:db8::/32',
					'fe80::/10'
				]
			])
		]);

		$this->assertFalse($registry->has_errors());
	}

	/**
	 * The CIDR validator regex is `^[\d\.:a-fA-F]+/\d+$`.
	 * These are the
	 * CIDR strings the regex ACTUALLY rejects.
	 */
	#[DataProvider('invalidCidrProvider')]
	public function test_invalid_cidrs_are_rejected(string $cidr): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'ip_ranges' => [
					$cidr
				]
			])
		]);

		$this->assertTrue($registry->has_errors(), "CIDR '{$cidr}' must be rejected");
		$this->assertStringContainsString('ip_ranges', $registry->get_errors()[0]['error']);
	}

	public static function invalidCidrProvider(): array
	{
		return [
			// === Cases the regex ACTUALLY rejects ===
			'no_mask' => [
				'10.0.0.0'
			], // no '/' at all
			'just_ip' => [
				'192.168.1.1'
			], // no '/' at all
			'non_numeric_mask' => [
				'10.0.0.0/abc'
			], // non-digits after '/'
			'negative_mask' => [
				'10.0.0.0/-1'
			], // '-' not in [\d]
			'empty_mask' => [
				'10.0.0.0/'
			], // no digits after '/'
			'comma_separator' => [
				'10,0,0,0/24'
			], // ',' not in [\d\.:a-fA-F]
			'space_in_ip' => [
				'10.0.0. 0/24'
			], // ' ' not in [\d\.:a-fA-F]
			'slash_at_start' => [
				'/24'
			], // no IP part
			'multiple_slashes' => [
				'10.0.0.0/24/extra'
			] // extra '/' breaks $

		// === Cases the regex ACCEPTS but ideally should reject ===
		// Documented as known limitations — these are FALSE NEGATIVES
		// in the validator. They are listed here so any future fix
		// to the regex can be detected by changing these to expect
		// errors:
		// 'out_of_range' => ['10.0.0.0/64'], // mask > 32 for IPv4
		// 'giant_mask' => ['10.0.0.0/999'], // mask way too large
		// 'contains_letter' => ['10.0.0.a/24'], // 'a' is hex (a-f) → accepted
		];
	}

	public function test_non_string_cidr_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'ip_ranges' => [
					42
				]
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public function test_ip_ranges_not_array_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'ip_ranges' => '10.0.0.0/8'
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	// ============================================================
	// 7. dns_suffixes validation
	// ============================================================
	public function test_dns_suffixes_array_of_strings_is_accepted(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'dns_suffixes' => [
					'bot.example.com',
					'cdn.example.net'
				]
			])
		]);

		$this->assertFalse($registry->has_errors());
	}

	public function test_empty_dns_suffix_entry_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'dns_suffixes' => [
					'bot.example.com',
					''
				]
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public function test_non_string_dns_suffix_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'dns_suffixes' => [
					123
				]
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	public function test_dns_suffixes_not_array_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'dns_suffixes' => 'bot.example.com'
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	// ============================================================
	// 8. robots_txt_token validation
	// ============================================================
	public function test_string_robots_txt_token_is_accepted(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'robots_txt_token' => 'MyBot'
			])
		]);

		$this->assertFalse($registry->has_errors());
		$this->assertSame('MyBot', $registry->get('bot')->robots_txt_token);
	}

	public function test_null_robots_txt_token_is_accepted(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'robots_txt_token' => null
			])
		]);

		$this->assertFalse($registry->has_errors());
		$this->assertNull($registry->get('bot')->robots_txt_token);
	}

	public function test_non_string_robots_txt_token_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'robots_txt_token' => 123
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	// ============================================================
	// 9. host_patterns validation
	// ============================================================
	public function test_host_patterns_array_is_accepted(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'host_patterns' => [
					'bot.example.com',
					'cdn.example.net'
				]
			])
		]);

		$this->assertFalse($registry->has_errors());
	}

	public function test_host_patterns_not_array_is_rejected(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'host_patterns' => 'bot.example.com'
			])
		]);

		$this->assertTrue($registry->has_errors());
	}

	// ============================================================
	// 10. Partial failures
	// ============================================================
	public function test_invalid_entries_do_not_block_valid_entries(): void
	{
		$registry = new CustomRegistry([
			'good_bot' => $this->valid_bot('good_bot'),
			'missing_name' => [
				'user_agent_patterns' => [
					'MissingName'
				],
				'category' => 'search_engine'
			],
			'bad_category' => array_merge($this->valid_bot('bad_category'), [
				'category' => 'not_real'
			]),
			'another_good' => $this->valid_bot('another_good'),
			'too_short_ua' => array_merge($this->valid_bot('too_short_ua'), [
				'user_agent_patterns' => [
					'X'
				]
			])
		]);

		$this->assertCount(3, $registry->get_errors());
		$this->assertTrue($registry->has_errors());

		$this->assertCount(2, $registry->all());
		$this->assertTrue($registry->has('good_bot'));
		$this->assertTrue($registry->has('another_good'));

		$this->assertFalse($registry->has('missing_name'));
		$this->assertFalse($registry->has('bad_category'));
		$this->assertFalse($registry->has('too_short_ua'));
	}

	public function test_get_errors_returns_bot_id_and_reason(): void
	{
		$registry = new CustomRegistry([
			'broken' => [
				'user_agent_patterns' => [
					'BrokenBot'
				],
				'category' => 'search_engine'
			]
		]);

		$errors = $registry->get_errors();
		$this->assertCount(1, $errors);
		$this->assertSame('broken', $errors[0]['bot_id']);
		$this->assertNotEmpty($errors[0]['error']);
		$this->assertStringContainsString('name', $errors[0]['error']);
	}

	public function test_has_errors_is_false_when_all_valid(): void
	{
		$registry = new CustomRegistry([
			'a' => $this->valid_bot('a'),
			'b' => $this->valid_bot('b')
		]);

		$this->assertFalse($registry->has_errors());
		$this->assertSame([], $registry->get_errors());
	}

	// ============================================================
	// 11. add() — programmatic insertion
	// ============================================================
	public function test_add_accepts_valid_botdefinition(): void
	{
		$registry = new CustomRegistry();
		$def = new BotDefinition(id: 'added_bot', name: 'Added Bot', user_agent_patterns: [
			'AddedBot'
		], host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING);

		$registry->add($def);

		$this->assertTrue($registry->has('added_bot'));
		$this->assertSame($def, $registry->get('added_bot'));
		$this->assertFalse($registry->has_errors(), 'add() must not pollute get_errors() — it does not run validation');
	}

	public function test_add_bypasses_validation_entirely(): void
	{
		$registry = new CustomRegistry();

		$def = new BotDefinition(id: 'unusual_bot', name: 'Unusual', user_agent_patterns: [], host_patterns: [], ip_ranges: [], category: BotCategory::UNKNOWN);

		$registry->add($def);

		$this->assertTrue($registry->has('unusual_bot'), 'add() must accept any BotDefinition without validation');
	}

	public function test_add_overwrites_existing_bot_with_same_id(): void
	{
		$registry = new CustomRegistry([
			'slot' => $this->valid_bot('slot')
		]);

		$override = new BotDefinition(id: 'slot', name: 'Overridden', user_agent_patterns: [
			'OverriddenBot'
		], host_patterns: [], ip_ranges: [], category: BotCategory::MONITORING);

		$registry->add($override);

		$this->assertCount(1, $registry->all());
		$this->assertSame('Overridden', $registry->get('slot')->name);
	}

	// ============================================================
	// 12. find_by_ua / find_by_tokens
	// ============================================================
	public function test_find_by_ua_matches_added_bots(): void
	{
		$registry = new CustomRegistry([
			'gptbot' => array_merge($this->valid_bot('gptbot'), [
				'category' => 'ai_crawler',
				'user_agent_patterns' => [
					'GPTBot'
				]
			]),
			'claude' => array_merge($this->valid_bot('claude'), [
				'category' => 'ai_crawler',
				'user_agent_patterns' => [
					'ClaudeBot'
				]
			])
		]);

		$matches = $registry->find_by_ua('GPTBot/1.0 (compatible)');

		$this->assertContains('gptbot', $matches);
		$this->assertNotContains('claude', $matches);
	}

	public function test_find_by_tokens_uses_dedicated_index(): void
	{
		$registry = new CustomRegistry([
			'unique_token_bot' => array_merge($this->valid_bot('unique_token_bot'), [
				'user_agent_patterns' => [
					'UniqueMarker77'
				]
			])
		]);

		$matches = $registry->find_by_tokens('UniqueMarker77/1.0');

		$this->assertContains('unique_token_bot', $matches);
	}

	public function test_find_by_tokens_filters_short_and_noise_tokens(): void
	{
		$registry = new CustomRegistry([
			'short_token_bot' => array_merge($this->valid_bot('short_token_bot'), [
				'user_agent_patterns' => [
					'bot'
				]
			])
		]);

		$matches = $registry->find_by_tokens('Mozilla bot (Mozilla compatible)');

		$this->assertNotContains('short_token_bot', $matches, 'Tokens shorter than MIN_TOKEN_LENGTH (5) must be filtered out');
	}

	// ============================================================
	// 13. Per-category accessors
	// ============================================================
	public function test_search_engines_returns_only_search_engine_bots(): void
	{
		$registry = new CustomRegistry([
			'a' => array_merge($this->valid_bot('a'), [
				'category' => 'search_engine'
			]),
			'b' => array_merge($this->valid_bot('b'), [
				'category' => 'ai_crawler'
			]),
			'c' => array_merge($this->valid_bot('c'), [
				'category' => 'search_engine'
			])
		]);

		$engines = $registry->search_engines();

		$this->assertCount(2, $engines);
		$this->assertArrayHasKey('a', $engines);
		$this->assertArrayHasKey('c', $engines);
		$this->assertArrayNotHasKey('b', $engines);
	}

	public function test_cloud_infrastructure_category_accessor(): void
	{
		$registry = new CustomRegistry([
			'cf' => array_merge($this->valid_bot('cf'), [
				'category' => 'cloud_infrastructure',
				'user_agent_patterns' => [
					'Cloudflare-Healthcheck'
				]
			])
		]);

		$ci = $registry->cloud_infrastructure();

		$this->assertCount(1, $ci);
		$this->assertArrayHasKey('cf', $ci);
	}

	public function test_residential_crawlers_category_accessor(): void
	{
		$registry = new CustomRegistry([
			'rdp' => array_merge($this->valid_bot('rdp'), [
				'category' => 'residential_proxy',
				'user_agent_patterns' => [
					'BrightData'
				]
			])
		]);

		$this->assertCount(1, $registry->residential_crawlers());
	}

	public function test_all_category_accessors_return_empty_when_no_match(): void
	{
		$registry = new CustomRegistry([
			'x' => $this->valid_bot('x')
		]);

		$this->assertSame([], $registry->ai_crawlers());
		$this->assertSame([], $registry->social_crawlers());
		$this->assertSame([], $registry->cloud_infrastructure());
	}

	// ============================================================
	// 14. Edge cases
	// ============================================================
	public function test_empty_registry_loads_cleanly(): void
	{
		$registry = new CustomRegistry([]);

		$this->assertFalse($registry->has_errors());
		$this->assertSame([], $registry->get_errors());
		$this->assertCount(0, $registry->all());
		$this->assertSame(0, $registry->count());
	}

	public function test_description_field_is_preserved(): void
	{
		$registry = new CustomRegistry([
			'bot' => array_merge($this->valid_bot(), [
				'description' => 'Detailed explanation here'
			])
		]);

		$this->assertSame('Detailed explanation here', $registry->get('bot')->description);
	}

	public function test_description_defaults_to_empty_string(): void
	{
		$registry = new CustomRegistry([
			'bot' => $this->valid_bot()
		]);

		$this->assertSame('', $registry->get('bot')->description);
	}

	public function test_count_reflects_valid_bots_only(): void
	{
		$registry = new CustomRegistry([
			'a' => $this->valid_bot('a'),
			'b' => [
				'name' => 'B'
			],
			'c' => $this->valid_bot('c')
		]);

		$this->assertSame(2, $registry->count(), 'count() counts only successfully validated bots');
	}

	public function test_count_is_zero_for_empty_registry(): void
	{
		$registry = new CustomRegistry();
		$this->assertSame(0, $registry->count());
	}
}
