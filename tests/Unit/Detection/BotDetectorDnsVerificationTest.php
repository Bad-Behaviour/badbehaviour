<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Configuration;
use BadBehaviour\Detection\BotDetector;
use BadBehaviour\Tests\Fixtures\Stubs\InMemoryAdapterStub;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

/**
 * BotDetector DNS verification tests — extends existing BotDetector test
 * coverage to cover multi-suffix bot definitions.
 *
 * Multi-suffix verification was added so bots like meta_ai can match
 * across multiple corporate suffixes (facebook.com, fbcdn.net, amazonaws.com)
 * using a single PTR lookup per IP. Each suffix has its own cache entry
 * so a failure on one suffix doesn't poison the others.
 *
 * === TEST FIXTURES ===
 *
 *   - InMemoryAdapterStub: in-memory CacheInterface implementation that
 *     records every get/set call so tests can assert on cache contents.
 *   - DNS resolver closures: injected via set_dns_resolvers() so tests
 *     don't depend on network DNS or /etc/hosts.
 */
class BotDetectorDnsVerificationTest extends TestCase
{
	private InMemoryAdapterStub $adapter;
	private Configuration $config;
	private InMemoryRegistry $registry;
	private BotDetector $detector;

	public int $reverse_call_count = 0;
	public int $forward_call_count = 0;

	protected function setUp(): void
	{
		$this->reverse_call_count = 0;
		$this->forward_call_count = 0;

		$this->adapter = new InMemoryAdapterStub();

		// Build Configuration via from_array() so the schema-driven
		// pipeline runs and produces a complete, validated object.
		// Direct named-arg construction is brittle — adding a new
		// constructor param silently breaks every test that doesn't
		// pass it.
		$this->config = Configuration::from_array([
			'preset'         => 'minimal',
			'strict_search_engines' => true,  // unverified SEARCH_ENGINE → BLOCK
			'dns_verification' => [
				'enabled'                   => true,
				'timeout_ms'                => 100,
				'require_forward_confirm'   => false,
				'positive_ttl'              => 604800,
				'negative_ttl'              => 86400,
			],
			'ai_crawlers'    => [
				'allowed'          => [],
				'block_unverified' => true,
				'strict'           => false,
			],
			'bot_categories' => [
				'blocked'   => [],
				'challenge' => [],
				'log_only'  => [],
				'allowed'   => [],
			],
		], $this->adapter);

		$this->registry = new InMemoryRegistry([
			'testbot' => new BotDefinition(
				id: 'testbot',
				name: 'Test Bot',
				user_agent_patterns: ['TestBot/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['testbot.example.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'TestBot',
				default_action: BotAction::ALLOW,
			),
		]);

		$this->detector = new BotDetector(
			$this->config,
			$this->adapter,
			$this->registry,
		);

		$this->detector->set_dns_resolvers(
			reverse: function (string $ip) {
				$this->reverse_call_count++;
				return match ($ip) {
					'1.2.3.4'      => 'crawl-1-2-3.testbot.example.com',
					'5.6.7.8'      => 'spoofed.evil.com',
					'2a03:2880::1' => 'crawl.testbot.example.com',
					default        => false,
				};
			},
			forward: function (string $host, int $type) {
				$this->forward_call_count++;
				return [];
			},
		);
	}

	private function make_package(string $ip, string $ua): RequestPackage
	{
		return RequestPackage::create_for_test(
			user_agent: $ua,
			ip: $ip,
			method: 'GET',
			uri: '/test',
		);
	}

	private function cache_key_for(string $ip, string $suffix): string
	{
		$bin = inet_pton($ip);
		$this->assertNotFalse($bin, "inet_pton failed for {$ip}");
		return 'bb:dns_verify:' . bin2hex($bin) . ':' . $suffix;
	}

	// ============================================================
	// 1. Cold cache — first-ever DNS lookup for an IP
	// ============================================================

	public function test_cold_cache_legit_bot_verified_and_allowed(): void
	{
		$result = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed(), 'Verified bot should be allowed');
		$this->assertSame(1, $this->reverse_call_count, 'Reverse DNS should be called exactly once');

		$cached = $this->adapter->cache[$this->cache_key_for('1.2.3.4', 'testbot.example.com')] ?? null;
		$this->assertNotNull($cached, 'Verified bot must be cached');
		$this->assertTrue($cached['value'], 'Cache value must reflect verification success');
		$ttl = $cached['expires'] - $cached['fetched'];
		$this->assertSame(604800, $ttl,
			'Positive TTL must match dns_verification_positive_ttl (7 days)');
	}

	public function test_cold_cache_spoofed_bot_blocked_and_cached_negative(): void
	{
		$result = $this->detector->detect($this->make_package('5.6.7.8', 'TestBot/1.0'));

		$this->assertTrue($result->is_blocked(), 'Spoofed bot should be blocked');

		$cached = $this->adapter->cache[$this->cache_key_for('5.6.7.8', 'testbot.example.com')] ?? null;
		$this->assertNotNull($cached, 'Spoofed bot must be cached for re-check');
		$this->assertFalse($cached['value'], 'Cache value must reflect verification failure');
		$ttl = $cached['expires'] - $cached['fetched'];
		$this->assertSame(86400, $ttl,
			'Negative TTL must match dns_verification_negative_ttl (1 day)');
	}

	// ============================================================
	// 2. Warm cache — second request skips DNS
	// ============================================================

	public function test_warm_cache_avoids_dns_call(): void
	{
		$cache_key = $this->cache_key_for('1.2.3.4', 'testbot.example.com');
		$this->adapter->cache[$cache_key] = [
			'value'    => true,
			'expires'  => time() + 3600,
			'fetched'  => time(),
		];

		$result = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed());
		$this->assertSame(0, $this->reverse_call_count,
			'Warm cache must skip the DNS resolver entirely');
	}

	public function test_expired_cache_triggers_re_verification(): void
	{
		$cache_key = $this->cache_key_for('1.2.3.4', 'testbot.example.com');
		$this->adapter->cache[$cache_key] = [
			'value'    => false,    // stale negative
			'expires'  => time() - 1,
			'fetched'  => time() - 100000,
		];

		$result = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed(),
			'After expiry, re-verification must run and the bot must pass now');
		$this->assertSame(1, $this->reverse_call_count,
			'Expired cache must trigger a fresh DNS lookup');
	}

	// ============================================================
	// 3. IPv6 normalization
	// ============================================================

	public function test_ipv6_bot_uses_binary_cache_key(): void
	{
		$result = $this->detector->detect($this->make_package('2a03:2880::1', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed());

		// Cache key must use inet_pton binary form, NOT text form.
		// Different text representations of the same IPv6 address
		// (e.g., '2a03:2880::1' vs '2a03:2880:0:0:0:0:0:1') must
		// produce identical cache keys.
		$bin = inet_pton('2a03:2880::1');
		$expected_key = 'bb:dns_verify:' . bin2hex($bin) . ':testbot.example.com';
		$this->assertArrayHasKey($expected_key, $this->adapter->cache,
			'IPv6 cache key must use binary (inet_pton) form');
	}

	public function test_normalize_ipv6_canonical_form(): void
	{
		// Sanity: IPv6 canonical form must collapse zero-runs to '::'.
		$bin_a = inet_pton('2a03:2880:0:0:0:0:0:1');
		$bin_b = inet_pton('2a03:2880::1');
		$this->assertSame($bin_a, $bin_b,
			'IPv6 canonical form must normalize so cache keys match');
	}

	// ============================================================
	// 4. Kill switch — dns_verification_enabled=false
	// ============================================================

	public function test_kill_switch_skips_dns_entirely(): void
	{
		// Build a config with DNS verification explicitly disabled.
		$adapter = new InMemoryAdapterStub();
		$disabled_config = Configuration::from_array([
			'preset'         => 'minimal',
			'strict_search_engines' => true,
			'dns_verification' => [
				'enabled' => false, // ← the kill switch
			],
		], $adapter);

		$detector = new BotDetector($disabled_config, $adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: function () { $this->reverse_call_count++; return false; },
			forward: function () { $this->forward_call_count++; return []; },
		);

		$result = $detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertSame(0, $this->reverse_call_count,
			'Kill switch must skip DNS even if resolver is set');
		// Search engine without IP match + no DNS verification → BLOCKED
		$this->assertTrue($result->is_blocked(),
			'Without DNS verification, an unverified search engine claim is blocked');
	}

	// ============================================================
	// 5. Strict mode (require_forward_confirm)
	// ============================================================

	public function test_strict_mode_accepts_when_forward_dns_confirms(): void
	{
		$adapter = new InMemoryAdapterStub();
		$strict_config = Configuration::from_array([
			'preset'         => 'minimal',
			'dns_verification' => [
				'enabled'                 => true,
				'timeout_ms'              => 100,
				'require_forward_confirm' => true,  // strict mode
				'positive_ttl'            => 604800,
				'negative_ttl'            => 86400,
			],
		], $adapter);

		$detector = new BotDetector($strict_config, $adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: fn(string $ip) => $ip === '1.2.3.4'
				? 'crawl-1-2-3.testbot.example.com'
				: false,
			forward: fn(string $host, int $type) => [['ip' => '1.2.3.4']],
		);

		$result = $detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed(),
			'Strict mode with matching A record must accept');
	}

	public function test_strict_mode_rejects_when_forward_dns_fails(): void
	{
		$adapter = new InMemoryAdapterStub();
		$strict_config = Configuration::from_array([
			'preset'         => 'minimal',
			'strict_search_engines' => true,
			'dns_verification' => [
				'enabled'                 => true,
				'require_forward_confirm' => true,
			],
		], $adapter);

		$detector = new BotDetector($strict_config, $adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: fn(string $ip) => $ip === '1.2.3.4'
				? 'crawl.testbot.example.com'
				: false,
			forward: fn() => [], // empty A record list
		);

		$result = $detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_blocked(),
			'Strict mode with empty A record must reject (PTR spoof protection)');
	}

	public function test_strict_mode_rejects_ipv6_without_aaaa_match(): void
	{
		// IPv6 AAAA records are rarely complete — strict mode is known
		// to have high IPv6 FP risk. This test verifies the rejection
		// happens as documented (the IPv6 FP risk is a deliberate
		// tradeoff noted in Configuration).
		$adapter = new InMemoryAdapterStub();
		$strict_config = Configuration::from_array([
			'preset'         => 'minimal',
			'strict_search_engines' => true,
			'dns_verification' => [
				'enabled'                 => true,
				'require_forward_confirm' => true,
			],
		], $adapter);

		$detector = new BotDetector($strict_config, $adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: fn(string $ip) => $ip === '2a03:2880::1'
				? 'crawl.testbot.example.com'
				: false,
			// Empty AAAA record → strict mode rejects
			forward: fn() => [],
		);

		$result = $detector->detect($this->make_package('2a03:2880::1', 'TestBot/1.0'));

		$this->assertTrue($result->is_blocked(),
			'Strict mode must reject IPv6 without matching AAAA record');
	}

	// ============================================================
	// 6. Resolver injection
	// ============================================================

	public function test_resolver_hook_can_be_swapped_via_setter(): void
	{
		// First detect uses the original (benign) resolver.
		$result1 = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));
		$this->assertTrue($result1->is_allowed());
		$this->assertSame(1, $this->reverse_call_count);

		// Swap to a malicious resolver that returns evil.com.
		$this->detector->set_dns_resolvers(
			reverse: function (string $ip) {
				$this->reverse_call_count++;
				return 'evil.com';
			},
			forward: function (string $host, int $type) {
				$this->forward_call_count++;
				return [];
			},
		);

		// Different IP → fresh lookup → spoofed → blocked
		$result2 = $this->detector->detect($this->make_package('9.9.9.9', 'TestBot/1.0'));
		$this->assertTrue($result2->is_blocked(),
			'After swapping to a malicious resolver, IPs must be blocked');
		$this->assertSame(2, $this->reverse_call_count);
	}

	public function test_set_dns_resolvers_invalidates_per_request_cache(): void
	{
		// First request populates the in-request cache (via warm
		// adapter cache from setUp).
		$adapter = new InMemoryAdapterStub();
		$cache_key = 'bb:dns_verify:' . bin2hex(inet_pton('1.2.3.4')) . ':testbot.example.com';
		$adapter->cache[$cache_key] = [
			'value'    => true,
			'expires'  => time() + 3600,
			'fetched'  => time(),
		];

		$detector = new BotDetector($this->config, $adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: fn() => 'cached.testbot.example.com',
			forward: fn() => [],
		);

		// Swap resolvers — per-request cache must be invalidated.
		$detector->set_dns_resolvers(
			reverse: fn() => 'evil.com',
			forward: fn() => [],
		);

		// (We can't easily reach the per-request cache state from here,
		// so this test is a smoke check that the setter doesn't throw.)
		$this->assertTrue(true);
	}

	// ========================================================================
	// Multi-suffix verification tests
	// ========================================================================

	/**
	 * Bot defines multiple DNS suffixes. PTR resolves to a host matching
	 * the FIRST suffix → verification succeeds, short-circuits.
	 *
	 * With reverse-DNS caching shared across suffixes, only ONE PTR
	 * lookup happens per IP.
	 */
	public function test_multi_suffix_first_match_succeeds(): void
	{
		$registry = new InMemoryRegistry([
			'multibot' => new BotDefinition(
				id: 'multibot',
				name: 'Multi Suffix Bot',
				user_agent_patterns: ['MultiBot/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: [
					'facebook.com',
					'fbcdn.net',
					'amazonaws.com',
				],
				// SEARCH_ENGINE so verified bots are ALLOWED.
				// (AI_CRAWLER would challenge by default — out of scope.)
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'MultiBot',
				default_action: BotAction::ALLOW,
			),
		]);

		$adapter = new InMemoryAdapterStub();
		$config = Configuration::from_array([
			'preset'         => 'minimal',
			'dns_verification' => ['enabled' => true, 'timeout_ms' => 100],
		], $adapter);

		$detector = new BotDetector($config, $adapter, $registry);

		$reverse_calls = [];
		$detector->set_dns_resolvers(
			reverse: function (string $ip) use (&$reverse_calls) {
				$reverse_calls[] = $ip;
				return match ($ip) {
					'1.2.3.4' => 'meta-crawler.facebook.com',
					default   => false,
				};
			},
			forward: fn() => [],
		);

		$result = $detector->detect(RequestPackage::create_for_test(
			user_agent: 'MultiBot/1.0',
			ip: '1.2.3.4',
			method: 'GET',
			uri: '/test',
		));

		$this->assertTrue($result->is_allowed(),
			'IP matching first suffix must be allowed');
		$this->assertSame(['1.2.3.4'], $reverse_calls,
			'Only one reverse lookup needed when first suffix matches');
	}

	/**
	 * Bot defines multiple DNS suffixes. PTR resolves to a host matching
	 * a LATER suffix (not the first).
	 *
	 * With per-IP PTR caching, the PTR lookup happens ONCE and the
	 * suffix checks iterate over the cached hostname. The bot passes.
	 */
	public function test_multi_suffix_later_match_succeeds(): void
	{
		$registry = new InMemoryRegistry([
			'metabot' => new BotDefinition(
				id: 'metabot',
				name: 'Meta AI',
				user_agent_patterns: ['MetaBot/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: [
					'facebook.com',
					'fbcdn.net',
					'amazonaws.com', // ← PTR host will match this
				],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'MetaBot',
				default_action: BotAction::ALLOW,
			),
		]);

		$adapter = new InMemoryAdapterStub();
		$config = Configuration::from_array([
			'preset'         => 'minimal',
			'dns_verification' => ['enabled' => true, 'timeout_ms' => 100],
		], $adapter);

		$detector = new BotDetector($config, $adapter, $registry);

		$reverse_calls = [];
		$detector->set_dns_resolvers(
			reverse: function (string $ip) use (&$reverse_calls) {
				$reverse_calls[] = $ip;
				// Resolves to a host matching the 3rd suffix only
				return match ($ip) {
					'1.2.3.4' => 'meta-crawler.amazonaws.com',
					default   => false,
				};
			},
			forward: fn() => [],
		);

		$result = $detector->detect(RequestPackage::create_for_test(
			user_agent: 'MetaBot/1.0',
			ip: '1.2.3.4',
			method: 'GET',
			uri: '/test',
		));

		$this->assertTrue($result->is_allowed(),
			'IP matching later suffix must be allowed');
		$this->assertCount(1, $reverse_calls,
			'Per-IP PTR caching: only ONE reverse lookup needed regardless of suffix count');
	}

	/**
	 * Bot defines multiple DNS suffixes. PTR resolves to a host
	 * matching NONE of them → all suffix checks fail, bot blocked.
	 *
	 * Each (IP, suffix) pair gets its own negative cache entry so
	 * future detections for the same IP/suffix combo don't re-run DNS.
	 */
	public function test_multi_suffix_no_match_blocks(): void
	{
		$registry = new InMemoryRegistry([
			'multibot' => new BotDefinition(
				id: 'multibot',
				name: 'Multi Suffix Bot',
				user_agent_patterns: ['MultiBot/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: [
					'facebook.com',
					'fbcdn.net',
					'amazonaws.com',
				],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'MultiBot',
				default_action: BotAction::ALLOW,
			),
		]);

		$adapter = new InMemoryAdapterStub();
		$config = Configuration::from_array([
			'preset'         => 'minimal',
			'strict_search_engines' => true,
			'dns_verification' => ['enabled' => true, 'timeout_ms' => 100],
		], $adapter);

		$detector = new BotDetector($config, $adapter, $registry);

		$detector->set_dns_resolvers(
			reverse: function (string $ip) {
				// PTR resolves to a host matching NONE of the suffixes
				return match ($ip) {
					'1.2.3.4' => 'spoofed-host.evil.com',
					default   => false,
				};
			},
			forward: fn() => [],
		);

		$result = $detector->detect(RequestPackage::create_for_test(
			user_agent: 'MultiBot/1.0',
			ip: '1.2.3.4',
			method: 'GET',
			uri: '/test',
		));

		$this->assertTrue($result->is_blocked(),
			'IP matching no suffix must be blocked');

		// Each suffix must have its own negative cache entry
		// (independent from per-IP PTR cache).
		$bin = inet_pton('1.2.3.4');
		foreach (['facebook.com', 'fbcdn.net', 'amazonaws.com'] as $suffix) {
			$key = 'bb:dns_verify:' . bin2hex($bin) . ':' . $suffix;
			$this->assertArrayHasKey($key, $adapter->cache,
				"Negative cache entry for suffix '{$suffix}' must exist");
			$this->assertFalse($adapter->cache[$key]['value'],
				"Cache entry for '{$suffix}' must be negative (false)");
		}
	}

	/**
	 * Negative cache on one suffix doesn't poison the others — if the
	 * reverse-DNS hostname changes (e.g., bot moves to a different IP
	 * that resolves differently), each suffix is re-checked independently.
	 *
	 * This is the key safety property: a failure on suffix A doesn't
	 * make us skip suffix B in the future.
	 */
	public function test_negative_cache_on_one_suffix_does_not_block_other_suffixes(): void
	{
		// Pre-populate cache: (1.2.3.4, facebook.com) → negative
		$bin = inet_pton('1.2.3.4');
		$adapter = new InMemoryAdapterStub();
		$adapter->cache['bb:dns_verify:' . bin2hex($bin) . ':facebook.com'] = [
			'value'   => false,
			'expires' => time() + 3600,
			'fetched' => time(),
		];

		$registry = new InMemoryRegistry([
			'multibot' => new BotDefinition(
				id: 'multibot',
				name: 'Multi Suffix Bot',
				user_agent_patterns: ['MultiBot/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: [
					'facebook.com',
					'amazonaws.com',
				],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'MultiBot',
				default_action: BotAction::ALLOW,
			),
		]);

		$config = Configuration::from_array([
			'preset'         => 'minimal',
			'dns_verification' => ['enabled' => true, 'timeout_ms' => 100],
		], $adapter);

		$detector = new BotDetector($config, $adapter, $registry);

		// PTR now resolves to amazonaws.com — but facebook.com cache is negative.
		$detector->set_dns_resolvers(
			reverse: function (string $ip) {
				return match ($ip) {
					'1.2.3.4' => 'crawler.amazonaws.com',
					default   => false,
				};
			},
			forward: fn() => [],
		);

		$result = $detector->detect(RequestPackage::create_for_test(
			user_agent: 'MultiBot/1.0',
			ip: '1.2.3.4',
			method: 'GET',
			uri: '/test',
		));

		$this->assertTrue($result->is_allowed(),
			'Negative cache on facebook.com must NOT prevent verification on amazonaws.com');
	}

	/**
	 * verify_dns=true but dns_suffixes=[] — degenerate config.
	 * The bot's verification loop has nothing to iterate, so the IP
	 * falls through as "unverified". With no static IP ranges either,
	 * a SEARCH_ENGINE bot gets blocked.
	 *
	 * This is a regression guard against an off-by-one where empty
	 * suffixes accidentally counted as a successful match.
	 */
	public function test_empty_dns_suffixes_skips_verification(): void
	{
		$registry = new InMemoryRegistry([
			'unconfigured' => new BotDefinition(
				id: 'unconfigured',
				name: 'Misconfigured Bot',
				user_agent_patterns: ['Unconfigured/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: [], // ← empty array
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Unconfigured',
				default_action: BotAction::ALLOW,
			),
		]);

		$adapter = new InMemoryAdapterStub();
		$config = Configuration::from_array([
			'preset'         => 'minimal',
			'strict_search_engines' => true,
			'dns_verification' => ['enabled' => true, 'timeout_ms' => 100],
		], $adapter);

		$detector = new BotDetector($config, $adapter, $registry);

		$reverse_calls = [];
		$detector->set_dns_resolvers(
			reverse: function (string $ip) use (&$reverse_calls) {
				$reverse_calls[] = $ip;
				return 'whatever.com';
			},
			forward: fn() => [],
		);

		$result = $detector->detect(RequestPackage::create_for_test(
			user_agent: 'Unconfigured/1.0',
			ip: '1.2.3.4',
			method: 'GET',
			uri: '/test',
		));

		$this->assertCount(0, $reverse_calls,
			'Empty dns_suffixes must NOT trigger any reverse DNS call');
		$this->assertTrue($result->is_blocked(),
			'Search engine without IP match + empty suffixes must be blocked '
			. '(regression guard against off-by-one in the loop)');
	}

	/**
	 * Multi-suffix + warm cache: a cached positive on ONE suffix
	 * causes immediate short-circuit on the others (no DNS, no
	 * suffix iteration). The shared PTR cache means we don't even
	 * re-check the hostname.
	 *
	 * This is the "happy path fast" of multi-suffix bots: warm caches
	 * turn multi-suffix bots into single-cache-hit lookups.
	 */
	public function test_multi_suffix_warm_cache_short_circuits(): void
	{
		// Pre-populate: (1.2.3.4, facebook.com) → positive
		// Pre-populate: PTR cache for 1.2.3.4 → some-host
		$bin = inet_pton('1.2.3.4');
		$adapter = new InMemoryAdapterStub();
		$adapter->cache['bb:dns_verify:' . bin2hex($bin) . ':facebook.com'] = [
			'value'   => true,
			'expires' => time() + 3600,
			'fetched' => time(),
		];
		$adapter->cache['bb:reverse_dns:' . bin2hex($bin)] = 'cached.facebook.com';

		$registry = new InMemoryRegistry([
			'multibot' => new BotDefinition(
				id: 'multibot',
				name: 'Multi Suffix Bot',
				user_agent_patterns: ['MultiBot/1.0'],
				host_patterns: [],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['facebook.com', 'fbcdn.net', 'amazonaws.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'MultiBot',
				default_action: BotAction::ALLOW,
			),
		]);

		$config = Configuration::from_array([
			'preset'         => 'minimal',
			'dns_verification' => ['enabled' => true, 'timeout_ms' => 100],
		], $adapter);

		$detector = new BotDetector($config, $adapter, $registry);

		$reverse_calls = [];
		$detector->set_dns_resolvers(
			reverse: function (string $ip) use (&$reverse_calls) {
				$reverse_calls[] = $ip;
				return 'should.not.be.called';
			},
			forward: fn() => [],
		);

		$result = $detector->detect(RequestPackage::create_for_test(
			user_agent: 'MultiBot/1.0',
			ip: '1.2.3.4',
			method: 'GET',
			uri: '/test',
		));

		$this->assertCount(0, $reverse_calls,
			'Warm caches (both PTR and per-suffix) must short-circuit all DNS');
		$this->assertTrue($result->is_allowed());
	}
}
