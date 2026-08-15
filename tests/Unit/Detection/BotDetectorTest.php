<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Detection\BotDetector;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

/**
 * BotDetector integration tests covering:
 *   - Known bots (search engines, AI crawlers, SEO crawlers, social, etc.)
 *   - Cloud infrastructure safety (NEVER blocked)
 *   - Regional bots
 *   - Dynamic IP range caching
 *   - Default-action categories (residential proxy, residential data, etc.)
 *   - strict_search_engines gate (the lenient-default fix for
 *     DuckDuckGo/Brave/Kagi/MojeekBot being silently blocked)
 *
 * These tests use REAL DNS resolvers (no stubs). That means:
 *   - Tests don't depend on DNS for cloud-infra IPs (those use static ranges).
 *   - For bots requiring DNS verification (Googlebot, Bingbot, etc.), tests
 *     use IPs from the bot's static ranges so the IP match short-circuits
 *     before DNS is consulted.
 *   - For unverified-bot tests, the IP is intentionally NOT in any static
 *     range, DNS fails in the test environment, and the bot is correctly
 *     classified as unverified.
 */
class BotDetectorTest extends TestCase
{
	private BotDetector $detector;
	private GenericAdapter $adapter;

	protected function setUp(): void
	{
		$this->adapter = new GenericAdapter();

		$config = Configuration::from_array([
			'preset'         => 'full',
			'ai_crawlers'    => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories' => ['blocked' => ['malicious']],
		], $this->adapter);

		$this->detector = new BotDetector($config, $this->adapter);
	}

	/**
	 * Build a RequestPackage with a sensible test UA plus typical browser
	 * headers, so detectors that inspect headers don't produce noise.
	 */
	private function createPackage(string $ua, string $ip = '203.0.113.1'): RequestPackage
	{
		return RequestPackage::create_for_test(
			user_agent: $ua,
			ip: $ip,
		);
	}

	// ============================================================
	// 1. Search engines
	// ============================================================

	public function test_known_search_engine_allowed(): void
	{
		// 66.249.64.1 is in googlebot's static range 66.249.64.0/19.
		// IP match short-circuits before DNS verification is consulted.
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
			'66.249.64.1'
		);

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Googlebot from a static Google IP must be allowed without DNS');
	}

	/**
	 * Strict search engines gate: with the flag OFF (default), an
	 * unverified SE that has no static IP ranges and no DNS verification
	 * falls through to $def->default_action. This is the documented
	 * behavior and the reason DuckDuckBot/Brave/Kagi/MojeekBot are no
	 * longer silently blocked under the lenient default.
	 */
	public function test_search_engine_unverified_with_strict_off_returns_default_action(): void
	{
		// DuckDuckBot has verify_dns=false and no static ranges; under
		// the old (buggy) behavior, claiming to be DuckDuckBot from an
		// unknown IP was a hard block. Under the fix, it's allowed.
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)',
			'192.0.2.1'
		);

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Under strict_search_engines=false (default), unverified UA-only '
			. 'search engines fall through to def->default_action, not BLOCK');
		$this->assertSame('search_engine', $result->metadata['bot_category'] ?? null,
			'Bot is still correctly categorized as SEARCH_ENGINE even when allowed');
	}

	/**
	 * Strict search engines gate: with the flag ON, an unverified SE is
	 * hard-blocked. This is the explicit opt-in for operators seeing
	 * fake-SE abuse who accept the FP risk.
	 */
	public function test_search_engine_unverified_with_strict_on_returns_block(): void
	{
		$adapter = new GenericAdapter();
		$config = Configuration::from_array([
			'preset'               => 'full',
			'strict_search_engines'=> true,
			'ai_crawlers'          => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories'       => ['blocked' => ['malicious']],
		], $adapter);

		$detector = new BotDetector($config, $adapter);

		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; DuckDuckBot/1.1)',
			'192.0.2.1'
		);

		$result = $detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_enforced_block(),
			'strict_search_engines=true must hard-block unverified SEs');
		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code);
	}

	/**
	 * Strict search engines gate: verification still short-circuits the
	 * gate. Under strict_search_engines=true, a verified Googlebot must
	 * still be allowed. Without this test, a refactor could accidentally
	 * move the gate before the verification check and break real
	 * Googlebot traffic.
	 */
	public function test_search_engine_verified_short_circuits_strict_gate(): void
	{
		$adapter = new GenericAdapter();
		$config = Configuration::from_array([
			'preset'               => 'full',
			'strict_search_engines'=> true,
			'ai_crawlers'          => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories'       => ['blocked' => ['malicious']],
		], $adapter);

		$detector = new BotDetector($config, $adapter);

		// 66.249.64.1 is in googlebot's static range → verified.
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
			'66.249.64.1'
		);

		$result = $detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Verified Googlebot must pass even when strict_search_engines=true');
	}

	// ============================================================
	// 2. AI crawlers
	// ============================================================

	public function test_ai_crawler_allowed_when_configured(): void
	{
		// GPTBot's static range 20.15.240.0/20 includes 20.15.240.1.
		// IP match short-circuits → ALLOW regardless of dns-verification state.
		$package = $this->createPackage('GPTBot/1.0', '20.15.240.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'GPTBot from a static OpenAI IP must be allowed');
	}

	public function test_ai_crawler_challenge_when_not_allowed_and_not_strict(): void
	{
		// ClaudeBot is NOT in allowed_ai_crawlers list → falls into the
		// default AI_CRAWLER branch. block_unverified=false, strict=false → CHALLENGE.
		$adapter = new GenericAdapter();
		$config = Configuration::from_array([
			'preset'         => 'full',
			'ai_crawlers'    => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => false,
				'strict'           => false,
			],
			'bot_categories' => ['blocked' => ['malicious']],
		], $adapter);

		$detector = new BotDetector($config, $adapter);

		// 192.0.2.1 is in no ClaudeBot range; DNS fails in test env → unverified.
		$package = $this->createPackage('ClaudeBot/1.0', '192.0.2.1');
		$result = $detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->requires_challenge());
		$this->assertSame(ResultCode::CHALLENGE_REQUIRED, $result->code);
	}

	public function test_ai_crawler_block_when_strict_and_unverified(): void
	{
		// ClaudeBot with strict=true, block_unverified=true → BLOCK.
		$adapter = new GenericAdapter();
		$config = Configuration::from_array([
			'preset'         => 'full',
			'ai_crawlers'    => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => true,
			],
			'bot_categories' => ['blocked' => ['malicious']],
		], $adapter);

		$detector = new BotDetector($config, $adapter);
		$package = $this->createPackage('ClaudeBot/1.0', '192.0.2.1');
		$result = $detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_blocked());
		$this->assertSame(ResultCode::BLOCKED_AI_CRAWLER, $result->code);
	}

	// ============================================================
	// 3. SEO crawlers
	// ============================================================

	public function test_seo_crawler_block_when_unverified(): void
	{
		$package = $this->createPackage('SemrushBot/1.0', '192.0.2.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_blocked());
		$this->assertSame(ResultCode::BLOCKED_SEO_CRAWLER, $result->code);
	}

	// ============================================================
	// 4. Social crawlers
	// ============================================================

	public function test_social_crawler_unverified_log_only(): void
	{
		// SOCIAL_CRAWLER + verified=false → LOG_ONLY → Result::allow().
		// The bot's UA matches the registry but verification fails.
		$package = $this->createPackage('facebookexternalhit/1.1', '192.0.2.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Unverified social crawler → LOG_ONLY → ALLOWED code with ENFORCED enforcement');
	}

	// ============================================================
	// 5. Dynamic IP range caching
	// ============================================================

	public function test_dynamic_ranges_cached(): void
	{
		// Pre-populate the cache with a dynamic range that includes our IP.
		// dynamic_ip_ranges is disabled by default, but here we explicitly enable it.
		$cacheAdapter = new GenericAdapter();
		$cacheAdapter->set('bb:ip_ranges:merged', [
			'data'    => ['googlebot' => ['64.233.160.0/19']],
			'fetched' => time(),
		], 3600);

		$config = Configuration::from_array([
			'preset'              => 'full',
			'dynamic_ip_ranges'   => ['enabled' => true],
			'ai_crawlers'         => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories'      => ['blocked' => ['malicious']],
		], $cacheAdapter);

		$detector = new BotDetector($config, $cacheAdapter);

		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; Googlebot/2.1)',
			'64.233.160.1'
		);

		$result = $detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Googlebot IP from dynamic-range cache must be allowed');
	}

	public function test_dynamic_ranges_disabled_uses_static(): void
	{
		// With dynamic_ip_ranges disabled, fall back to static IP ranges
		// in BotDefinition. 66.249.64.1 is in googlebot's static range.
		$config = Configuration::from_array([
			'preset'              => 'full',
			'dynamic_ip_ranges'   => ['enabled' => false],
			'ai_crawlers'         => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories'      => ['blocked' => ['malicious']],
		], new GenericAdapter());

		$detector = new BotDetector($config, new GenericAdapter());

		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; Googlebot/2.1)',
			'66.249.64.1'
		);

		$result = $detector->detect($package);
		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Without dynamic ranges, static googlebot range still applies');
	}

	// ============================================================
	// 6. Cloud infrastructure safety (THE most important test class)
	// ============================================================
	//
	// These tests verify that health probes from major CDNs / load
	// balancers are NEVER blocked, regardless of UA. Blocking these
	// takes the origin offline (CDN marks it unhealthy).

	public function test_cloudflare_health_ip_always_allowed(): void
	{
		// 173.245.48.1 is in cloudflare_health's static range 173.245.48.0/20.
		// Even with a UA that doesn't match any bot, the cloud-infra
		// whitelist fast-path returns ALLOW.
		$package = $this->createPackage('Some Random Probe Agent', '173.245.48.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Cloudflare probe IPs MUST be allowed — blocking them takes origin offline');
	}

	public function test_aws_elb_health_ip_always_allowed(): void
	{
		// aws_elb_health has empty static ranges, but its UA pattern
		// 'AWS-ELB-HealthChecker/1.0' matches the registry. The
		// CLOUD_INFRASTRUCTURE category has a hard-coded ALLOW safety
		// override in BotDetector::determine_action() — verified below.
		$package = $this->createPackage('AWS-ELB-HealthChecker/1.0', '54.239.128.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'AWS ELB health check MUST be allowed (via CLOUD_INFRASTRUCTURE safety override)');
	}

	public function test_gcp_load_balancer_health_always_allowed(): void
	{
		// 35.191.1.1 is in google_cloud_health's range 35.191.0.0/16.
		$package = $this->createPackage('GoogleHC', '35.191.1.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'GCP LB health probes MUST be allowed');
	}

	public function test_azure_health_probe_always_allowed(): void
	{
		// 168.63.129.16 is in azure_health's range 168.63.0.0/16.
		$package = $this->createPackage('Azure-LB-Health-Probe', '168.63.129.16');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Azure health probes MUST be allowed');
	}

	public function test_fastly_health_always_allowed(): void
	{
		// 151.101.1.1 is in fastly_health's range 151.101.0.0/16.
		$package = $this->createPackage('Fastly', '151.101.1.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Fastly health probes MUST be allowed');
	}

	// ============================================================
	// 7. Regional search engines (UA-only, no static IP, no DNS)
	// ============================================================
	//
	// These bots have verify_dns=false and no static IP ranges in
	// DefaultRegistry. Under the old (buggy) behavior they were hard-
	// blocked when claiming their UA from an unknown IP. The strict
	// search engines gate fix means they now fall through to
	// $def->default_action under the lenient default — they pass.

	public function test_coccoc_vietnam_bot_allowed_under_lenient_default(): void
	{
		// coccoc has verify_dns=false → UA-only matching.
		// Under the old buggy behavior this was BLOCKED.
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; coccocbot/2.0; +http://coccoc.com)',
			'192.0.2.1'
		);

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'coccoc has verify_dns=false and no static ranges; lenient '
			. 'strict_search_engines default allows UA-only SEs through');
		$this->assertSame('search_engine', $result->metadata['bot_category'] ?? null);
	}

	public function test_mailru_allowed_under_lenient_default(): void
	{
		// Mail.ru has verify_dns=true, but with no static ranges and DNS
		// failing in tests, it ends up unverified. Old behavior: BLOCK.
		// New behavior: allowed under lenient default.
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; Mail.RU_Bot/2.0)',
			'192.0.2.1'
		);

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Mail.ru unverified under lenient default must pass (verifies '
			. 'strict_search_engines gate handles DNS-fail-true case)');
	}

	public function test_coccoc_blocked_under_strict_mode(): void
	{
		// Same coccoc request as above, but with strict_search_engines=true.
		// Demonstrates that operators who want the old behavior can opt in.
		$adapter = new GenericAdapter();
		$config = Configuration::from_array([
			'preset'               => 'full',
			'strict_search_engines'=> true,
			'ai_crawlers'          => [
				'allowed'          => ['GPTBot'],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories'       => ['blocked' => ['malicious']],
		], $adapter);

		$detector = new BotDetector($config, $adapter);

		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; coccocbot/2.0; +http://coccoc.com)',
			'192.0.2.1'
		);

		$result = $detector->detect($package);

		$this->assertTrue($result->is_enforced_block(),
			'Under strict_search_engines=true, UA-only SEs are blocked');
		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code);
	}

	// ============================================================
	// 8. AI crawler additions
	// ============================================================

	public function test_amazonbot_blocked_when_unverified(): void
	{
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; Amazonbot/1.0; +https://developer.amazon.com/support/amazonbot)',
			'192.0.2.1'
		);

		$result = $this->detector->detect($package);

		$this->assertTrue($result->is_blocked());
		$this->assertSame(ResultCode::BLOCKED_AI_CRAWLER, $result->code);
	}

	public function test_diffbot_blocked_when_unverified(): void
	{
		$package = $this->createPackage(
			'Diffbot/2.0 (+https://www.diffbot.com)',
			'192.0.2.1'
		);

		$result = $this->detector->detect($package);

		$this->assertTrue($result->is_blocked());
	}

	public function test_brightdata_blocked_by_default(): void
	{
		$package = $this->createPackage(
			'Mozilla/5.0 (compatible; BrightData/1.0)',
			'192.0.2.1'
		);

		$result = $this->detector->detect($package);

		$this->assertTrue($result->is_blocked(),
			'BrightData residential proxy must default to BLOCK');
		$this->assertSame(ResultCode::BLOCKED_BOT, $result->code,
			'Residential proxy uses the generic BLOCKED_BOT code (see BotDetector::code_for_category)');
	}

	// ============================================================
	// 9. Shopping crawlers (revenue — always allowed)
	// ============================================================

	public function test_facebook_catalog_allowed(): void
	{
		// 157.240.1.1 is in facebook_catalog's range 157.240.0.0/16.
		$package = $this->createPackage('facebookcatalog/1.0', '157.240.1.1');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Facebook Catalog MUST be allowed (product feed revenue)');
	}

	// ============================================================
	// 10. Feed readers (RSS — always allowed)
	// ============================================================

	public function test_feedly_allowed(): void
	{
		// 54.144.1.1 is in feedly's range 54.144.0.0/16.
		$package = $this->createPackage(
			'Feedly/1.0 (+https://www.feedly.com/fetcher.html)',
			'54.144.1.1'
		);

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Feedly MUST be allowed (RSS reader brings real users)');
	}

	public function test_apple_news_allowed(): void
	{
		// 17.1.2.3 is in apple_news's range 17.0.0.0/8.
		$package = $this->createPackage('AppleNewsBot', '17.1.2.3');

		$result = $this->detector->detect($package);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed(),
			'Apple News MUST be allowed (publisher visibility)');
	}
}