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

		$this->config = new Configuration(
			dns_verification_enabled: true,
			dns_verification_timeout_ms: 100,
			dns_verification_require_forward_confirm: false,
			dns_verification_positive_ttl: 604800,
			dns_verification_negative_ttl: 86400,
			blocked_bot_categories: [],
			allowed_ai_crawlers: [],
			block_unverified_ai: true,
			adapter: $this->adapter,
			);

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

	public function test_cold_cache_legit_bot_verified_and_allowed(): void
	{
		$result = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed(), 'Verified bot should be allowed');
		$this->assertSame(1, $this->reverse_call_count, 'Reverse DNS should be called exactly once');

		$cached = $this->adapter->cache[$this->cache_key_for('1.2.3.4', 'testbot.example.com')] ?? null;
		$this->assertNotNull($cached);
		$this->assertTrue($cached['value']);
		$ttl = $cached['expires'] - $cached['fetched'];
		$this->assertSame(604800, $ttl);
	}

	public function test_cold_cache_spoofed_bot_blocked_and_cached_negative(): void
	{
		$result = $this->detector->detect($this->make_package('5.6.7.8', 'TestBot/1.0'));

		$this->assertTrue($result->is_blocked(), 'Spoofed bot should be blocked');

		$cached = $this->adapter->cache[$this->cache_key_for('5.6.7.8', 'testbot.example.com')] ?? null;
		$this->assertNotNull($cached);
		$this->assertFalse($cached['value']);
		$ttl = $cached['expires'] - $cached['fetched'];
		$this->assertSame(86400, $ttl);
	}

	public function test_warm_cache_avoids_dns_call(): void
	{
		$cache_key = $this->cache_key_for('1.2.3.4', 'testbot.example.com');
		$this->adapter->cache[$cache_key] = [
			'value' => true,
			'expires' => time() + 3600,
			'fetched' => time(),
		];

		$result = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed());
		$this->assertSame(0, $this->reverse_call_count, 'Warm cache should skip DNS');
	}

	public function test_expired_cache_triggers_re_verification(): void
	{
		$cache_key = $this->cache_key_for('1.2.3.4', 'testbot.example.com');
		$this->adapter->cache[$cache_key] = [
			'value' => false,
			'expires' => time() - 1,
			'fetched' => time() - 100000,
		];

		$result = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed());
		$this->assertSame(1, $this->reverse_call_count, 'Expired cache should re-verify');
	}

	public function test_ipv6_bot_uses_binary_cache_key(): void
	{
		$result = $this->detector->detect($this->make_package('2a03:2880::1', 'TestBot/1.0'));

		$this->assertTrue($result->is_allowed());

		$bin = inet_pton('2a03:2880::1');
		$expected_key = 'bb:dns_verify:' . bin2hex($bin) . ':testbot.example.com';
		$this->assertArrayHasKey($expected_key, $this->adapter->cache);
	}

	public function test_kill_switch_skips_dns_entirely(): void
	{
		$disabled_config = new Configuration(
			dns_verification_enabled: false,
			dns_verification_timeout_ms: 300,
			dns_verification_require_forward_confirm: false,
			dns_verification_positive_ttl: 604800,
			dns_verification_negative_ttl: 86400,
			blocked_bot_categories: [],
			allowed_ai_crawlers: [],
			block_unverified_ai: true,
			adapter: $this->adapter,
			);

		$detector = new BotDetector($disabled_config, $this->adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: function () { $this->reverse_call_count++; return false; },
			forward: function () { $this->forward_call_count++; return []; },
			);

		$result = $detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));

		$this->assertSame(0, $this->reverse_call_count, 'Kill switch should skip DNS');
		$this->assertTrue($result->is_blocked());
	}

	public function test_strict_mode_requires_forward_confirm(): void
	{
		$strict_config = new Configuration(
			dns_verification_enabled: true,
			dns_verification_timeout_ms: 100,
			dns_verification_require_forward_confirm: true,
			dns_verification_positive_ttl: 604800,
			dns_verification_negative_ttl: 86400,
			blocked_bot_categories: [],
			allowed_ai_crawlers: [],
			block_unverified_ai: true,
			adapter: $this->adapter,
			);

		$detector = new BotDetector($strict_config, $this->adapter, $this->registry);
		$detector->set_dns_resolvers(
			reverse: fn(string $ip) => $ip === '1.2.3.4' ? 'crawl-1-2-3.testbot.example.com' : false,
			forward: fn(string $host, int $type) => [
				['ip' => '1.2.3.4'],
			],
			);

		$r1 = $detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));
		$this->assertTrue($r1->is_allowed());

		$r2 = $detector->detect($this->make_package('2a03:2880::1', 'TestBot/1.0'));
		$this->assertTrue($r2->is_blocked(), 'Strict mode should reject IPv6 without AAAA forward match');
	}

	public function test_resolver_hook_can_be_swapped_via_setter(): void
	{
		$result1 = $this->detector->detect($this->make_package('1.2.3.4', 'TestBot/1.0'));
		$this->assertTrue($result1->is_allowed());
		$this->assertSame(1, $this->reverse_call_count);

		$this->detector->set_dns_resolvers(
			reverse: function () { $this->reverse_call_count++; return 'evil.com'; },
			forward: function () { $this->forward_call_count++; return []; },
			);

		$result2 = $this->detector->detect($this->make_package('9.9.9.9', 'TestBot/1.0'));
		$this->assertTrue($result2->is_blocked());
		$this->assertSame(2, $this->reverse_call_count);
	}

	public function test_normalize_ipv6_canonical_form(): void
	{
		$bin_a = inet_pton('2a03:2880:0:0:0:0:0:1');
		$bin_b = inet_pton('2a03:2880::1');
		$this->assertSame($bin_a, $bin_b, 'IPv6 canonical form should normalize');
	}

	// ========================================================================
	// Multi-suffix verification tests
	// ========================================================================

	/**
	 * IP reverse-resolves to the FIRST suffix in the array.
	 * Should match on first lookup and short-circuit.
	 *
	 * FIX: Changed category from AI_CRAWLER to SEARCH_ENGINE so verified bots are ALLOWED.
	 * These tests verify DNS logic, not AI crawler policy.
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
				category: BotCategory::SEARCH_ENGINE,  // FIX: was AI_CRAWLER
				robots_txt_token: 'MultiBot',
				default_action: BotAction::ALLOW,
				),
		]);

		$adapter = new InMemoryAdapterStub();
		$config = new Configuration(
			dns_verification_enabled: true,
			dns_verification_timeout_ms: 100,
			dns_verification_require_forward_confirm: false,
			dns_verification_positive_ttl: 604800,
			dns_verification_negative_ttl: 86400,
			blocked_bot_categories: [],
			allowed_ai_crawlers: [],
			block_unverified_ai: true,
			adapter: $adapter,
			);

		$detector = new BotDetector($config, $adapter, $registry);

		// IP reverse-resolves to a host matching the FIRST suffix
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

		$this->assertTrue($result->is_allowed(), 'IP matching first suffix should be allowed');
		$this->assertSame(['1.2.3.4'], $reverse_calls, 'Only one reverse lookup needed for first-suffix match');
	}

	/**
     * IP reverse-resolves to a LATER suffix in the array (not the first).
     * Should iterate past the first failure and match on the second.
     *
     * FIX: Changed category from AI_CRAWLER to SEARCH_ENGINE so verified bots are ALLOWED.
     * Now expects 1 reverse DNS call (cached per IP, shared across suffixes).
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
                    'facebook.com',   // 1st — won't match
                    'fbcdn.net',      // 2nd — won't match
                    'amazonaws.com',  // 3rd — WILL match
                ],
                category: BotCategory::SEARCH_ENGINE,  // FIX: was AI_CRAWLER
                robots_txt_token: 'MetaBot',
                default_action: BotAction::ALLOW,
            ),
        ]);

        $adapter = new InMemoryAdapterStub();
        $config = new Configuration(
            dns_verification_enabled: true,
            dns_verification_timeout_ms: 100,
            dns_verification_require_forward_confirm: false,
            dns_verification_positive_ttl: 604800,
            dns_verification_negative_ttl: 86400,
            blocked_bot_categories: [],
            allowed_ai_crawlers: [],
            block_unverified_ai: true,
            adapter: $adapter,
        );

        $detector = new BotDetector($config, $adapter, $registry);

        $reverse_calls = [];
        $detector->set_dns_resolvers(
            reverse: function (string $ip) use (&$reverse_calls) {
                $reverse_calls[] = $ip;
                // Only reverse-resolves to a host matching the 3rd suffix
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

        $this->assertTrue($result->is_allowed(), 'IP matching later suffix should be allowed');

        // With reverse DNS caching, only 1 PTR lookup happens per IP
        // (shared across all suffix checks)
        $this->assertCount(1, $reverse_calls, 'Single reverse lookup per IP, shared across suffixes');
    }

	/**
	 * IP reverse-resolves to a host NOT matching any configured suffix.
	 * All suffix checks should fail (each gets its own negative cache entry).
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
		$config = new Configuration(
			dns_verification_enabled: true,
			dns_verification_timeout_ms: 100,
			dns_verification_require_forward_confirm: false,
			dns_verification_positive_ttl: 604800,
			dns_verification_negative_ttl: 86400,
			blocked_bot_categories: [],
			allowed_ai_crawlers: [],
			block_unverified_ai: true,
			adapter: $adapter,
			);

		$detector = new BotDetector($config, $adapter, $registry);

		// IP reverse-resolves to a host matching none of the suffixes
		$detector->set_dns_resolvers(
			reverse: function (string $ip) {
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

		$this->assertTrue($result->is_blocked(), 'IP not matching any suffix should be blocked');

		// All three suffixes should have negative cache entries
		$bin = inet_pton('1.2.3.4');
		foreach (['facebook.com', 'fbcdn.net', 'amazonaws.com'] as $suffix) {
			$key = 'bb:dns_verify:' . bin2hex($bin) . ':' . $suffix;
			$this->assertArrayHasKey($key, $adapter->cache, "Negative cache entry for {$suffix} should exist");
			$this->assertFalse($adapter->cache[$key]['value'], "Cache entry for {$suffix} should be negative");
		}
	}

	/**
	 * verify_dns=true but dns_suffixes=[] — no verification attempted.
	 * Bot falls through to IP-range check (none defined) and gets blocked.
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
				dns_suffixes: [],  // ← empty array, but verify_dns is true
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Unconfigured',
				default_action: BotAction::ALLOW,
				),
		]);

		$adapter = new InMemoryAdapterStub();
		$config = new Configuration(
			dns_verification_enabled: true,
			dns_verification_timeout_ms: 100,
			dns_verification_require_forward_confirm: false,
			dns_verification_positive_ttl: 604800,
			dns_verification_negative_ttl: 86400,
			blocked_bot_categories: [],
			allowed_ai_crawlers: [],
			block_unverified_ai: true,
			adapter: $adapter,
			);

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

		$this->assertSame(0, count($reverse_calls), 'No reverse DNS call should happen with empty dns_suffixes');
		$this->assertTrue($result->is_blocked(), 'Search engine with no IP match + empty suffixes = blocked');
	}
}
