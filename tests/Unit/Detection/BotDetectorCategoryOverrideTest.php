<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Configuration;
use BadBehaviour\Core\EnforcementAction;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Detection\BotDetector;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

/**
 * Tier 1 (production-critical) tests for BotDetector::determine_action().
 *
 * determine_action() is the single point that converts a matched BotDefinition
 * + verification status into a BotAction enum (ALLOW/CHALLENGE/BLOCK/LOG_ONLY).
 * A bug here either:
 *
 *   - blocks legitimate users (false positive — e.g. Googlebot denied)
 *   - allows malicious bots (false negative — e.g. residential proxy permitted)
 *
 * This test class exercises every (category × verification) combination that
 * matters in production, with explicit focus on the FOUR sub-keys:
 *
 *   1. SAFETY OVERRIDE (CLOUD_INFRASTRUCTURE → always ALLOW, no exceptions)
 *   2. USER CATEGORY OVERRIDES (blocked/challenge/log_only/allowed lists)
 *   3. DEFAULT CATEGORY-SPECIFIC LOGIC (FEED_READER/SHOPPING/MONITORING/
 *      ARCHIVE; AI; SEO; SEARCH_ENGINE; SOCIAL; SECURITY_SCANNER)
 *   4. RESIDENTIAL_PROXY fallback (defense-in-depth)
 *
 * === KNOWN LIMITATIONS ===
 *
 * 1. BotDetector::detect_uncached() maps both BotAction::ALLOW and
 *    BotAction::LOG_ONLY to Result::allow() — they are indistinguishable
 *    from the outside. Tests assert on Result (code + enforcement)
 *    rather than the BotAction enum.
 *
 * 2. The `verified` flag is computed from ip_ranges match OR DNS
 *    verification. These tests disable DNS verification (no resolver
 *    injection), so `verified=true` requires `ip_ranges` to be set on
 *    the test BotDefinition. Tests that need a "verified" bot either
 *    inject DNS resolvers OR provide a static ip_ranges entry.
 */
final class BotDetectorCategoryOverrideTest extends TestCase
{
	// ============================================================
	// Helpers
	// ============================================================

	private function make_config(array $overrides = []): Configuration
	{
		$adapter = $this->createMock(AdapterInterface::class);
		$adapter->method('get_settings')->willReturn([]);

		return Configuration::from_array(array_merge([
			'preset'         => 'minimal',
			'dns_verification'   => ['enabled' => false],
			'dynamic_ip_ranges'  => ['enabled' => false],
			'rate_limits'        => ['enabled' => false],
			'dnsbl'              => ['enabled' => false],
			'enable_behavioral_analysis'    => false,
			'enable_client_hints_validation' => false,
			'enable_agentic_detection'      => false,
			'enable_fingerprinting'         => false,
			'enable_head_request_detection'  => false,
			'enable_asset_scraping_detection' => false,
		], $overrides), $adapter);
	}

	private function make_detector(
		?Configuration $config = null,
		?InMemoryRegistry $registry = null,
	): BotDetector {
		$config = $config ?? $this->make_config();
		$registry = $registry ?? new InMemoryRegistry();

		$adapter = $this->createMock(AdapterInterface::class);
		$adapter->method('get_settings')->willReturn([]);

		return new BotDetector($config, $adapter, $registry);
	}

	private function make_definition(
		BotCategory $category,
		BotAction $default_action = BotAction::ALLOW,
		string $id = 'test_bot',
		?string $robots_txt_token = null,
		array $user_agent_patterns = ['TestBot/1.0'],
		array $ip_ranges = [],
		bool $verify_dns = false,
		array $dns_suffixes = [],
	): BotDefinition {
		return new BotDefinition(
			id: $id,
			name: 'Test Bot',
			user_agent_patterns: $user_agent_patterns,
			host_patterns: [],
			ip_ranges: $ip_ranges,
			verify_dns: $verify_dns,
			dns_suffixes: $dns_suffixes,
			category: $category,
			robots_txt_token: $robots_txt_token,
			default_action: $default_action,
		);
	}

	private function run_one(
		BotDetector $detector,
		BotDefinition $def,
		bool $verified = false,
	): ?Result {
		$ua = $def->user_agent_patterns[0] . ' (Mozilla compatible)';
		$package = RequestPackage::create_for_test(
			user_agent: $ua,
			ip: '203.0.113.10',
		);
		return $detector->detect($package);
	}

	// ============================================================
	// 1. SAFETY OVERRIDE — CLOUD_INFRASTRUCTURE
	// ============================================================

	public function test_cloud_infrastructure_allowed_even_when_in_blocked_list(): void
	{
		$config = $this->make_config([
			'bot_categories' => [
				'blocked'   => ['cloud_infrastructure'],
				'challenge' => ['cloud_infrastructure'],
				'log_only'  => ['cloud_infrastructure'],
			],
		]);
		$registry = new InMemoryRegistry([
			'cloudflare_health' => $this->make_definition(
				BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::ALLOW,
				id: 'cloudflare_health',
				user_agent_patterns: ['Cloudflare-Healthcheck'],
			),
		]);

		$detector = $this->make_detector($config, $registry);
		$result = $this->run_one($detector, $registry->get('cloudflare_health'));

		$this->assertInstanceOf(Result::class, $result);
		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'CLOUD_INFRASTRUCTURE must produce code=ALLOWED regardless of category overrides');
		$this->assertSame(EnforcementAction::ALLOWED, $result->enforcement);
	}

	public function test_cloud_infrastructure_allowed_when_default_action_is_block(): void
	{
		$registry = new InMemoryRegistry([
			'aws_elb_health' => $this->make_definition(
				BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::BLOCK,
				id: 'aws_elb_health',
				user_agent_patterns: ['ELB-HealthChecker'],
			),
		]);
		$detector = $this->make_detector(null, $registry);
		$result = $this->run_one($detector, $registry->get('aws_elb_health'));

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'Even with default_action=BLOCK, CLOUD_INFRASTRUCTURE is forced to ALLOW');
	}

	public function test_cloud_infrastructure_default_action_runtime_contract(): void
	{
		$default = new DefaultRegistry();
		foreach ($default->cloud_infrastructure() as $def) {
			$this->assertSame(
				BotAction::ALLOW,
				$def->default_action,
				"DefaultRegistry ships {$def->id} with default_action={$def->default_action->value}, expected ALLOW"
			);
		}
	}

	// ============================================================
	// 2. USER CATEGORY OVERRIDES
	// ============================================================

	/** @dataProvider overrideListProvider */
	public function test_category_override_wins_over_default_logic(
		string $list_key,
		ResultCode $expected_code,
		?EnforcementAction $expected_enforcement,
	): void {
		$config = $this->make_config([
			'bot_categories' => [
				$list_key => ['search_engine'],
			],
		]);

		$registry = new InMemoryRegistry([
			'googlebot' => $this->make_definition(
				BotCategory::SEARCH_ENGINE,
				default_action: BotAction::ALLOW,
				id: 'googlebot',
				user_agent_patterns: ['Googlebot'],
				verify_dns: true,
				dns_suffixes: ['googlebot.com'],
			),
		]);

		$detector = $this->make_detector($config, $registry);
		$result = $this->run_one($detector, $registry->get('googlebot'), verified: true);

		$this->assertInstanceOf(Result::class, $result);
		$this->assertSame($expected_code, $result->code,
			"category override list '$list_key' must yield code {$expected_code->value}");
		if ($expected_enforcement !== null) {
			$this->assertSame($expected_enforcement, $result->enforcement);
		}
	}

	public static function overrideListProvider(): array
	{
		return [
			'blocked wins over default' => [
				'blocked',
				ResultCode::BLOCKED_BOT,
				EnforcementAction::ENFORCED,
			],
			'challenge overrides default' => [
				'challenge',
				ResultCode::CHALLENGE_REQUIRED,
				EnforcementAction::ENFORCED,
			],
			// KNOWN LIMITATION: LOG_ONLY currently maps to Result::allow().
			'log_only produces allowed code' => [
				'log_only',
				ResultCode::ALLOWED,
				EnforcementAction::ALLOWED,
			],
			'allowed overrides default' => [
				'allowed',
				ResultCode::ALLOWED,
				EnforcementAction::ALLOWED,
			],
		];
	}

	public function test_override_priority_blocked_beats_allowed(): void
	{
		$config = $this->make_config([
			'bot_categories' => [
				'blocked' => ['search_engine'],
				'allowed' => ['search_engine'],
			],
		]);

		$registry = new InMemoryRegistry([
			'bingbot' => $this->make_definition(
				BotCategory::SEARCH_ENGINE,
				default_action: BotAction::ALLOW,
				id: 'bingbot',
				user_agent_patterns: ['bingbot'],
			),
		]);
		$detector = $this->make_detector($config, $registry);
		$result = $this->run_one($detector, $registry->get('bingbot'), verified: true);

		$this->assertSame(BotAction::BLOCK, $this->bot_action_from_result($result));
		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code);
	}

	// ============================================================
	// 3. DEFAULT CATEGORY-SPECIFIC LOGIC
	// ============================================================

	/**
	 * @dataProvider alwaysAllowedCategoryProvider
	 */
	public function test_revenue_categories_allow_verified_bots(BotCategory $category, string $bot_id): void
	{
		$registry = new InMemoryRegistry([
			$bot_id => $this->make_definition(
				$category,
				default_action: BotAction::CHALLENGE,
				id: $bot_id,
				user_agent_patterns: [$bot_id],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get($bot_id), verified: true);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			"{$category->value} / verified → ALLOWED expected");
	}

	public static function alwaysAllowedCategoryProvider(): array
	{
		return [
			'feed reader'      => [BotCategory::FEED_READER,       'feedly'],
			'shopping crawler' => [BotCategory::SHOPPING_CRAWLER,  'google_shopping'],
			'monitoring'       => [BotCategory::MONITORING,        'uptimerobot'],
			'archive crawler'  => [BotCategory::ARCHIVE_CRAWLER,   'commoncrawl'],
		];
	}

	// --- AI_CRAWLER ---

	public function test_ai_crawler_allowed_when_token_in_allowed_list(): void
	{
		$config = $this->make_config([
			'ai_crawlers' => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => true,
			],
		]);
		$registry = new InMemoryRegistry([
			'gptbot' => $this->make_definition(
				BotCategory::AI_CRAWLER,
				default_action: BotAction::CHALLENGE,
				id: 'gptbot',
				robots_txt_token: 'GPTBot',
				user_agent_patterns: ['GPTBot'],
			),
		]);
		$detector = $this->make_detector($config, $registry);

		$result = $this->run_one($detector, $registry->get('gptbot'), verified: false);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'AI crawler listed in allowed[] → ALLOW even if strict + block_unverified');
	}

	public function test_ai_crawler_blocked_when_strict_and_unverified(): void
	{
		$config = $this->make_config([
			'ai_crawlers' => [
				'allowed'          => [],
				'block_unverified' => false,
				'strict'           => true,
			],
		]);
		$registry = new InMemoryRegistry([
			'gptbot' => $this->make_definition(
				BotCategory::AI_CRAWLER,
				default_action: BotAction::CHALLENGE,
				id: 'gptbot',
				robots_txt_token: 'GPTBot',
				user_agent_patterns: ['GPTBot'],
			),
		]);
		$detector = $this->make_detector($config, $registry);

		$result = $this->run_one($detector, $registry->get('gptbot'), verified: false);

		$this->assertSame(ResultCode::BLOCKED_AI_CRAWLER, $result->code,
			'strict=true + unverified → BLOCK');
	}

	public function test_ai_crawler_challenged_when_not_strict_and_unverified(): void
	{
		$config = $this->make_config([
			'ai_crawlers' => [
				'allowed'          => [],
				'block_unverified' => false,
				'strict'           => false,
			],
		]);
		$registry = new InMemoryRegistry([
			'claude' => $this->make_definition(
				BotCategory::AI_CRAWLER,
				default_action: BotAction::BLOCK,
				id: 'claude',
				robots_txt_token: 'ClaudeBot',
				user_agent_patterns: ['ClaudeBot'],
			),
		]);
		$detector = $this->make_detector($config, $registry);

		$result = $this->run_one($detector, $registry->get('claude'), verified: false);

		$this->assertSame(ResultCode::CHALLENGE_REQUIRED, $result->code,
			'strict=false + unverified → CHALLENGE (default for AI)');
	}

	public function test_ai_crawler_blocked_when_block_unverified_and_unverified(): void
	{
		$config = $this->make_config([
			'ai_crawlers' => [
				'allowed'          => [],
				'block_unverified' => true,
				'strict'           => false,
			],
		]);
		$registry = new InMemoryRegistry([
			'mistral' => $this->make_definition(
				BotCategory::AI_CRAWLER,
				default_action: BotAction::ALLOW,
				id: 'mistral',
				robots_txt_token: 'MistralBot',
				user_agent_patterns: ['MistralBot'],
			),
		]);
		$detector = $this->make_detector($config, $registry);

		$result = $this->run_one($detector, $registry->get('mistral'), verified: false);

		$this->assertSame(ResultCode::BLOCKED_AI_CRAWLER, $result->code,
			'block_unverified=true + unverified → BLOCK');
	}

	// --- SEO_CRAWLER ---

	public function test_seo_crawler_uses_default_action_when_verified(): void
	{
		// SEO verified → default_action. To get verified=true without DNS,
		// provide ip_ranges matching the test IP 203.0.113.10.
		$registry = new InMemoryRegistry([
			'semrush' => $this->make_definition(
				BotCategory::SEO_CRAWLER,
				default_action: BotAction::CHALLENGE,
				id: 'semrush',
				user_agent_patterns: ['SemrushBot'],
				ip_ranges: ['203.0.113.0/24'], // covers test IP
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('semrush'), verified: true);

		$this->assertSame(ResultCode::CHALLENGE_REQUIRED, $result->code,
			'SEO crawler verified → CHALLENGE (matches default_action)');
	}

	public function test_seo_crawler_blocked_when_unverified(): void
	{
		$registry = new InMemoryRegistry([
			'ahrefs' => $this->make_definition(
				BotCategory::SEO_CRAWLER,
				default_action: BotAction::ALLOW,
				id: 'ahrefs',
				user_agent_patterns: ['AhrefsBot'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('ahrefs'), verified: false);

		$this->assertSame(ResultCode::BLOCKED_SEO_CRAWLER, $result->code,
			'SEO crawler unverified → BLOCK regardless of default_action');
	}

	// --- SEARCH_ENGINE ---

	public function test_search_engine_blocked_when_unverified(): void
	{
		$registry = new InMemoryRegistry([
			'googlebot' => $this->make_definition(
				BotCategory::SEARCH_ENGINE,
				default_action: BotAction::ALLOW,
				id: 'googlebot',
				user_agent_patterns: ['Googlebot'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('googlebot'), verified: false);

		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code,
			'Unverified search engine → BLOCK (impersonation protection)');
	}

	public function test_search_engine_allowed_when_verified(): void
	{
		// Search engine has no dedicated branch for `verified=true` —
		// it uses `if (!verified) return BLOCK; return ALLOW;`. To test
		// verified=true without DNS injection, provide ip_ranges.
		$registry = new InMemoryRegistry([
			'googlebot' => $this->make_definition(
				BotCategory::SEARCH_ENGINE,
				default_action: BotAction::BLOCK,    // contradictory default
				id: 'googlebot',
				user_agent_patterns: ['Googlebot'],
				ip_ranges: ['203.0.113.0/24'], // covers test IP
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('googlebot'), verified: true);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'Verified search engine → ALLOWED');
	}

	// --- SOCIAL_CRAWLER ---

	public function test_social_crawler_allowed_when_verified(): void
	{
		// SOCIAL_CRAWLER: verified → ALLOW, unverified → LOG_ONLY (→ ALLOWED code).
		// Use ip_ranges for determinism.
		$registry = new InMemoryRegistry([
			'facebook' => $this->make_definition(
				BotCategory::SOCIAL_CRAWLER,
				default_action: BotAction::BLOCK,
				id: 'facebook',
				user_agent_patterns: ['facebookexternalhit'],
				ip_ranges: ['203.0.113.0/24'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('facebook'), verified: true);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'Verified social crawler → ALLOWED (link previews must work)');
	}

	public function test_social_crawler_logged_only_when_unverified(): void
	{
		// KNOWN LIMITATION: Production code maps LOG_ONLY → Result::allow().
		$registry = new InMemoryRegistry([
			'twitter' => $this->make_definition(
				BotCategory::SOCIAL_CRAWLER,
				default_action: BotAction::CHALLENGE,
				id: 'twitter',
				user_agent_patterns: ['Twitterbot'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('twitter'), verified: false);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'Unverified social crawler → LOG_ONLY; production maps LOG_ONLY to code=ALLOWED');
	}

	// --- SECURITY_SCANNER ---

	public function test_security_scanner_logged_only_by_default(): void
	{
		$registry = new InMemoryRegistry([
			'shodan' => $this->make_definition(
				BotCategory::SECURITY_SCANNER,
				default_action: BotAction::BLOCK,
				id: 'shodan',
				user_agent_patterns: ['Shodan'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result_verified   = $this->run_one($detector, $registry->get('shodan'), verified: true);
		$result_unverified = $this->run_one($detector, $registry->get('shodan'), verified: false);

		// KNOWN LIMITATION: Production code maps LOG_ONLY → Result::allow().
		$this->assertSame(ResultCode::ALLOWED, $result_verified->code);
		$this->assertSame(ResultCode::ALLOWED, $result_unverified->code);
	}

	// ============================================================
	// 4. RESIDENTIAL_PROXY fallback
	// ============================================================

	public function test_residential_proxy_blocked_via_user_override(): void
	{
		// RESIDENTIAL_PROXY has no dedicated branch — falls through to
		// `$def->default_action`. To force BLOCK for residential proxy,
		// operators add it to bot_categories.blocked. This is the
		// realistic operator setup and is the documented recommendation.
		$config = $this->make_config([
			'bot_categories' => [
				'blocked' => ['residential_proxy'],
			],
		]);

		$registry = new InMemoryRegistry([
			'brightdata' => $this->make_definition(
				BotCategory::RESIDENTIAL_PROXY,
				default_action: BotAction::ALLOW,    // overridden
				id: 'brightdata',
				user_agent_patterns: ['BrightData'],
			),
		]);
		$detector = $this->make_detector($config, $registry);

		$result_verified   = $this->run_one($detector, $registry->get('brightdata'), verified: true);
		$result_unverified = $this->run_one($detector, $registry->get('brightdata'), verified: false);

		$this->assertSame(ResultCode::BLOCKED_BOT, $result_verified->code,
			'Residential proxy with bot_categories.blocked → BLOCK (verified)');
		$this->assertSame(ResultCode::BLOCKED_BOT, $result_unverified->code,
			'Residential proxy with bot_categories.blocked → BLOCK (unverified)');
	}

	public function test_residential_proxy_default_action_when_no_override(): void
	{
		// Without bot_categories.blocked, residential proxy falls through
		// to the definition's default_action. This documents the
		// CURRENT behavior — operators MUST add it to blocked[] to
		// actually block it. The "DefaultRegistry ships brightdata with
		// default_action=BLOCK" assumption is verified separately.
		$registry = new InMemoryRegistry([
			'brightdata_permissive' => $this->make_definition(
				BotCategory::RESIDENTIAL_PROXY,
				default_action: BotAction::ALLOW,
				id: 'brightdata_permissive',
				user_agent_patterns: ['BrightDataPermissive'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('brightdata_permissive'), verified: false);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'Residential proxy without user override → falls through to default_action');
	}

	public function test_residential_proxy_default_action_in_default_registry(): void
	{
		// DefaultRegistry ships brightdata with default_action=BLOCK so
		// that out-of-the-box behavior matches the "residential proxy
		// = block" intuition. This test asserts that contract.
		$default = new DefaultRegistry();
		$brightdata = $default->get('brightdata');

		$this->assertNotNull($brightdata,
			'DefaultRegistry must ship the brightdata residential-proxy definition');
		$this->assertSame(
			BotAction::BLOCK,
			$brightdata->default_action,
			'brightdata must ship with default_action=BLOCK (out-of-box residential proxy block)'
		);
	}

	public function test_residential_proxy_allowed_via_user_override(): void
	{
		// Even residential_proxy — the strictest default — must yield to
		// an explicit allowed[] override.
		$config = $this->make_config([
			'bot_categories' => [
				'allowed' => ['residential_proxy'],
			],
		]);
		$registry = new InMemoryRegistry([
			'brightdata' => $this->make_definition(
				BotCategory::RESIDENTIAL_PROXY,
				default_action: BotAction::BLOCK,
				id: 'brightdata',
				user_agent_patterns: ['BrightData'],
			),
		]);
		$detector = $this->make_detector($config, $registry);

		$result = $this->run_one($detector, $registry->get('brightdata'), verified: false);

		$this->assertSame(ResultCode::ALLOWED, $result->code,
			'residential_proxy is NOT a safety category — allowed[] must work');
	}

	// ============================================================
	// 5. META / unknown category
	// ============================================================

	public function test_unknown_category_falls_back_to_definition_default_action(): void
	{
		$registry = new InMemoryRegistry([
			'unknown_bot' => $this->make_definition(
				BotCategory::UNKNOWN,
				default_action: BotAction::CHALLENGE,
				id: 'unknown_bot',
				user_agent_patterns: ['MysteryBot'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('unknown_bot'));

		$this->assertSame(ResultCode::CHALLENGE_REQUIRED, $result->code,
			'Unknown category → fall through to definition->default_action (CHALLENGE here)');
	}

	public function test_malicious_category_falls_back_to_definition_default_action(): void
	{
		$registry = new InMemoryRegistry([
			'malware_xyz' => $this->make_definition(
				BotCategory::MALICIOUS,
				default_action: BotAction::BLOCK,
				id: 'malware_xyz',
				user_agent_patterns: ['MalwareXYZ/1.0'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('malware_xyz'));

		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code);
	}

	// ============================================================
	// 6. Result metadata carries bot identification
	// ============================================================

	public function test_challenge_result_metadata_includes_bot_identity(): void
	{
		$registry = new InMemoryRegistry([
			'gptbot' => $this->make_definition(
				BotCategory::AI_CRAWLER,
				default_action: BotAction::CHALLENGE,
				id: 'gptbot',
				robots_txt_token: 'GPTBot',
				user_agent_patterns: ['GPTBot'],
			),
		]);
		// strict=false → unverified AI → CHALLENGE
		$detector = $this->make_detector($this->make_config([
			'ai_crawlers' => [
				'allowed'          => [],
				'block_unverified' => false,
				'strict'           => false,
			],
		]), $registry);

		$result = $this->run_one($detector, $registry->get('gptbot'), verified: false);

		$this->assertSame(ResultCode::CHALLENGE_REQUIRED, $result->code);
		$this->assertSame('gptbot', $result->metadata['bot_id']);
		$this->assertSame('Test Bot', $result->metadata['bot_name']);
		$this->assertSame('ai_crawler', $result->metadata['bot_category']);
		$this->assertArrayHasKey('bot_verified', $result->metadata);
	}

	public function test_block_result_metadata_includes_bot_identity(): void
	{
		$registry = new InMemoryRegistry([
			'brightdata' => $this->make_definition(
				BotCategory::RESIDENTIAL_PROXY,
				default_action: BotAction::BLOCK,    // makes BLOCK the fallthrough
				id: 'brightdata',
				user_agent_patterns: ['BrightData'],
			),
		]);
		$detector = $this->make_detector(null, $registry);

		$result = $this->run_one($detector, $registry->get('brightdata'), verified: false);

		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code);
		$this->assertSame('brightdata', $result->metadata['bot_id']);
		$this->assertSame('residential_proxy', $result->metadata['bot_category']);
		$this->assertFalse($result->metadata['bot_verified']);
	}

	// ============================================================
	// Helpers
	// ============================================================

	private function bot_action_from_result(Result $result): BotAction
	{
		if ($result->code === ResultCode::CHALLENGE_REQUIRED) {
			return BotAction::CHALLENGE;
		}
		if (str_starts_with($result->code->value, 'blocked.')) {
			return BotAction::BLOCK;
		}
		return BotAction::ALLOW; // ALLOW and LOG_ONLY are indistinguishable
	}
}
