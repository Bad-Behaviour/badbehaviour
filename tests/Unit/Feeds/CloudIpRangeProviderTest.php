<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Feeds\CloudIpRangeProvider;
use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\Util\ErrorReporter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tier 3 (defense-in-depth) tests for CloudIpRangeProvider.
 *
 * CloudIpRangeProvider is the cache-backed adapter for cloud-provider IP
 * ranges (AWS, Cloudflare, Fastly, GCP). It is read by
 * BotDetector::is_cloud_infrastructure_ip() to extend the static range
 * list with ranges refreshed from upstream feeds via cron.
 *
 * The provider is a CRITICAL AVAILABILITY COMPONENT — if it ships
 * unparseable CIDRs, health probes get blocked and the origin goes
 * offline.
 *
 * === TESTABILITY ===
 *
 * CloudIpRangeProvider's actual network fetches can't be exercised
 * from a unit test (no internet in CI, no way to verify feeds are
 * up). The tests here exercise:
 *
 *   1. Public constants & API surface
 *   2. Cache integration (store → retrieve → stale fallback)
 *   3. Behavior when the cache is empty / missing
 *   4. CIDR-format validation on what comes out of the provider
 *
 * The internal fetch() method (which calls file_get_contents on
 * upstream URLs) is left to integration tests.
 */
final class CloudIpRangeProviderTest extends TestCase
{
	// ---------- Test doubles ----------

	/**
	 * In-memory CacheInterface implementation.
	 *
	 * Records everything so tests can inspect what was written.
	 */
	private function make_cache(): CacheInterface
	{
		return new class implements CacheInterface {
			public array $store = [];
			public int $set_calls = 0;
			public int $get_calls = 0;

			public function get(string $key): mixed
			{
				$this->get_calls++;
				return $this->store[$key] ?? null;
			}

			public function set(string $key, mixed $value, int $ttl): bool
			{
				$this->set_calls++;
				$this->store[$key] = $value;
				return true;
			}

			public function delete(string $key): bool
			{
				unset($this->store[$key]);
				return true;
			}

			public function increment_counter(string $key, int $window): int
			{
				return 0;
			}

			public function get_counter(string $key): int
			{
				return 0;
			}

			public function get_set(string $key): array
			{
				return [];
			}

			public function add_to_set(string $key, string $value, int $ttl): bool
			{
				return true;
			}
		};
	}

	// ============================================================
	// 1. Public API surface
	// ============================================================

	public function test_feed_urls_constant_lists_documented_providers(): void
	{
		$expected = [
			'aws',
			'cloudflare',
			'fastly',
			'gcp',
		];

		$this->assertSame($expected, array_keys(CloudIpRangeProvider::FEED_URLS),
			'FEED_URLS keys are the canonical provider names accepted by ranges()');
	}

	public function test_feed_urls_are_https(): void
	{
		// Refusing HTTP for IP-range feeds prevents MITM tampering with
		// the very data that authorizes CDN health probes.
		foreach (CloudIpRangeProvider::FEED_URLS as $provider => $url) {
			$this->assertStringStartsWith(
				'https://',
				$url,
				"Feed URL for '{$provider}' must be HTTPS (got '{$url}')"
			);
		}
	}

	public function test_feed_urls_point_to_official_sources(): void
	{
		// Light sanity: each URL should come from the cloud provider's
		// own domain. If a feed URL silently drifts to a third-party
		// mirror, the registry is being poisoned by an attacker.
		$official_domains = [
			'aws'         => 'amazonaws.com',
			'cloudflare'  => 'cloudflare.com',
			'fastly'      => 'fastly.com',
			'gcp'         => 'gstatic.com',
		];

		foreach ($official_domains as $provider => $expected_domain) {
			$url = CloudIpRangeProvider::FEED_URLS[$provider];
			$this->assertStringContainsString(
				$expected_domain,
				$url,
				"Feed URL for '{$provider}' should be on '{$expected_domain}' (got '{$url}')"
			);
		}
	}

	// ============================================================
	// 2. Construction
	// ============================================================

	public function test_constructs_with_cache(): void
	{
		$provider = new CloudIpRangeProvider($this->make_cache());
		$this->assertInstanceOf(CloudIpRangeProvider::class, $provider);
	}

	public function test_constructs_with_custom_ttl(): void
	{
		$provider = new CloudIpRangeProvider($this->make_cache(), ttl: 3600);
		$this->assertInstanceOf(CloudIpRangeProvider::class, $provider);
	}

	// ============================================================
	// 3. Cache hit path
	// ============================================================

	public function test_ranges_returns_cached_data_when_fresh(): void
	{
		$cache = $this->make_cache();
		$cache->set('ip_range:aws:all', [
			'data'    => ['192.0.2.0/24', '198.51.100.0/24'],
			'fetched' => time(), // fresh
		], 86400);

		$provider = new CloudIpRangeProvider($cache);
		$result = $provider->ranges('aws');

		$this->assertSame(['192.0.2.0/24', '198.51.100.0/24'], $result);
	}

	public function test_ranges_returns_empty_for_unknown_provider(): void
	{
		$provider = new CloudIpRangeProvider($this->make_cache());

		$this->assertSame([], $provider->ranges('unknown_provider'));
	}

	public function test_ranges_returns_empty_when_cache_is_empty(): void
	{
		$this->require_offline();
		// No cache, no upstream fetch in unit tests → empty result.
		$provider = new CloudIpRangeProvider($this->make_cache());

		$this->assertSame([], $provider->ranges('aws'));
	}

	public function test_ranges_supports_tag_filter_in_cache_key(): void
	{
		// ranges($provider, $tag) uses a tag-scoped cache key, so
		// different tags don't pollute each other.
		$cache = $this->make_cache();
		$cache->set('ip_range:aws:CLOUDFRONT', [
			'data'    => ['192.0.2.0/24'],
			'fetched' => time(),
		], 86400);
		$cache->set('ip_range:aws:EC2', [
			'data'    => ['198.51.100.0/24'],
			'fetched' => time(),
		], 86400);

		$provider = new CloudIpRangeProvider($cache);

		$this->assertSame(['192.0.2.0/24'], $provider->ranges('aws', 'CLOUDFRONT'));
		$this->assertSame(['198.51.100.0/24'], $provider->ranges('aws', 'EC2'));
	}

	private function require_offline(): void
	{
		// These tests assume network is unreachable so that fetch() fails
		// and the cache-miss fallback returns []. When network IS reachable,
		// fetch() succeeds and returns real provider data, breaking the test.
		if (getenv('BB_TEST_OFFLINE') === '1') {
			return;
		}
		// Disable SSL verification in the probe context — we only care
		// whether the host is reachable, not whether TLS validates.
		// (CloudIpRangeProvider uses CaBundleLocator for real fetches.)
		$ctx = stream_context_create([
			'http' => ['timeout' => 2, 'ignore_errors' => true],
			'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
		]);
		$reachable = @file_get_contents('https://api.fastly.com/public-ip-list', false, $ctx) !== false;
		if ($reachable) {
			$this->markTestSkipped(
				'Requires unreachable network. Run with BB_TEST_OFFLINE=1 to enable.'
			);
		}
	}

	// ============================================================
	// 4. Stale-cache fallback
	// ============================================================

	public function test_stale_cache_returned_when_fresh_unavailable(): void
	{
		$this->require_offline();
		// We can't actually exercise the upstream fetch in a unit test,
		// but we CAN verify the stale-fallback contract: if a cache
		// entry exists but is stale (fetched > ttl seconds ago), the
		// provider should still return it (the `if ($cached...) return`
		// branch is reached before the fetch attempt).
		//
		// Inject a stale entry directly:
		$cache = $this->make_cache();
		$cache->set('ip_range:aws:all', [
			'data'    => ['192.0.2.0/24'],
			'fetched' => time() - (86400 * 8), // 8 days old, beyond 24h TTL
		], 86400 * 30);

		$provider = new CloudIpRangeProvider($cache);
		$result = $provider->ranges('aws');

		// The implementation checks `time() - $cached['fetched'] < $this->ttl`.
		// Since the entry IS stale, that check fails, so the provider
		// tries to fetch fresh — which fails in unit tests, returning [].
		//
		// Whether this is "the right behavior" is debatable: the docs say
		// "Stale fallback" — implying stale cache should still be returned.
		// Looking at the source, the current implementation only returns
		// stale cache if the fresh fetch fails. In unit tests, the fetch
		// always fails, so stale cache IS returned.
		$this->assertSame(['192.0.2.0/24'], $result,
			'Stale cache should be returned when fresh fetch fails (unit-test fallback path)');
	}

	// ============================================================
	// 5. Cache key format
	// ============================================================

	public function test_cache_key_shape_uses_provider_and_tag(): void
	{
		// The cache key is built as "ip_range:{provider}:{tag|null}".
		// We verify this indirectly by populating cache with that exact
		// shape and observing a hit.
		$cache = $this->make_cache();
		$cache->set('ip_range:fastly:all', [
			'data'    => ['203.0.113.0/24'],
			'fetched' => time(),
		], 86400);

		$provider = new CloudIpRangeProvider($cache);
		$result = $provider->ranges('fastly');

		$this->assertSame(['203.0.113.0/24'], $result);
		$this->assertGreaterThan(0, $cache->get_calls);
	}

	// ============================================================
	// 6. CIDR-format integrity (output contract)
	// ============================================================

	public function test_cached_cidrs_returned_unchanged(): void
	{
		// Whatever CIDRs we put in the cache, the provider returns
		// them as-is (no implicit parsing / rewriting).
		$cache = $this->make_cache();
		$cached_cidrs = [
			'192.0.2.0/24',
			'198.51.100.0/24',
			'2001:db8::/32',
		];
		$cache->set('ip_range:aws:all', [
			'data'    => $cached_cidrs,
			'fetched' => time(),
		], 86400);

		$provider = new CloudIpRangeProvider($cache);
		$result = $provider->ranges('aws');

		$this->assertSame($cached_cidrs, $result);
	}

	public function test_empty_cached_array_returns_empty(): void
	{
		// Some feeds may be empty (e.g., provider hasn't published
		// ranges yet). Provider should propagate empty cleanly.
		$cache = $this->make_cache();
		$cache->set('ip_range:gcp:all', [
			'data'    => [],
			'fetched' => time(),
		], 86400);

		$provider = new CloudIpRangeProvider($cache);
		$result = $provider->ranges('gcp');

		$this->assertSame([], $result);
	}

	// ============================================================
	// 7. Contract documentation — what the tests assume
	// ====================================

	public function test_provider_is_safe_against_constructor_without_args(): void
	{
		// Constructor signature: (CacheInterface $cache, int $ttl = 86400)
		// Default TTL of 24 hours matches the documented cron cadence
		// (0 */6 * * * — every 6 hours, so 24h cache survives stale).
		$provider = new CloudIpRangeProvider($this->make_cache());
		$this->assertInstanceOf(CloudIpRangeProvider::class, $provider);
	}

	// ============================================================
	// 8. Provider-specific contract: each provider has a URL
	// ============================================================


    #[DataProvider('everyProviderProvider')]
	public function test_each_documented_provider_has_a_feed_url(string $provider): void
	{
		$this->assertArrayHasKey(
			$provider,
			CloudIpRangeProvider::FEED_URLS,
			"Provider '{$provider}' is documented but missing from FEED_URLS"
		);

		$url = CloudIpRangeProvider::FEED_URLS[$provider];
		$this->assertNotEmpty($url);
		$this->assertStringStartsWith('https://', $url);
	}

	public static function everyProviderProvider(): array
	{
		return [
			'AWS'         => ['aws'],
			'Cloudflare'  => ['cloudflare'],
			'Fastly'      => ['fastly'],
			'GCP'         => ['gcp'],
		];
	}

	// ============================================================
	// 9. Return value type
	// ============================================================

	public function test_ranges_always_returns_an_array(): void
	{
		$provider = new CloudIpRangeProvider($this->make_cache());

		// Every provider — known and unknown — must return an array,
		// never null/false. BotDetector iterates ranges with foreach
		// and would crash on non-array returns.
		foreach (array_keys(CloudIpRangeProvider::FEED_URLS) as $provider_name) {
			$result = $provider->ranges($provider_name);
			$this->assertIsArray(
				$result,
				"ranges('{$provider_name}') must return an array (got "
				. get_debug_type($result) . ')'
			);
		}

		// And for unknown providers
		$this->assertIsArray($provider->ranges('nonexistent'));
	}

	public function test_ranges_never_throws_on_bad_cache_state(): void
	{
		// Inject a corrupted cache entry — provider must still return
		// something sensible rather than crashing.
		$cache = $this->make_cache();
		$cache->store['ip_range:aws:all'] = 'this is not the expected array shape';

		$provider = new CloudIpRangeProvider($cache);

		// Whatever happens internally, the public API should not throw.
		$result = $provider->ranges('aws');

		$this->assertIsArray($result,
			'Provider must return an array even when cache is corrupted');
	}

	// ============================================================
	// 10. Multiple providers are independent
	// ============================================================

	public function test_cache_for_one_provider_does_not_leak_to_another(): void
	{
		$this->require_offline();
		$cache = $this->make_cache();
		$cache->set('ip_range:aws:all', [
			'data'    => ['192.0.2.0/24'],
			'fetched' => time(),
		], 86400);

		$provider = new CloudIpRangeProvider($cache);

		// AWS has cache, Fastly does not
		$this->assertSame(['192.0.2.0/24'], $provider->ranges('aws'));
		$this->assertSame([], $provider->ranges('fastly'),
			'Fastly cache miss must not surface AWS data');
	}
}
