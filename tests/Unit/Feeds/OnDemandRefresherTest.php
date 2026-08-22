<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Feeds\CloudIpRangeProvider;
use BadBehaviour\Feeds\FeedProviderInterface;
use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\Feeds\OnDemandRefresher;
use BadBehaviour\Feeds\RefreshDecision;
use BadBehaviour\Feeds\RefreshResult;
use BadBehaviour\Util\ErrorReporter;
use PHPUnit\Framework\TestCase;

/**
 * Tests for OnDemandRefresher — the opportunistic "web cron" IP range
 * refresh mechanism.
 *
 * The class has four gates (probability, cooldown, staleness, mutex) and
 * two methods (maybe_refresh, do_refresh). We test each in isolation
 * plus the integration.
 *
 * Time and RNG are injected so every gate can be exercised deterministically.
 * No real cache backend is used — we provide an in-memory test double that
 * implements the full CacheInterface contract.
 */
final class OnDemandRefresherTest extends TestCase
{

	private InMemoryCache $cache;

	private FakeFeedProvider $registry;

	private FakeCloudProvider $cloud;

	private int $current_time = 1700000000;

	protected function setUp(): void
	{
		$this->cache = new InMemoryCache(fn (): int => $this->current_time);
		$this->registry = new FakeFeedProvider();
		$this->cloud = new FakeCloudProvider();
		$this->current_time = 1700000000;

		ErrorReporter::reset();
	}

	/**
	 * Convenience: build a refresher with the test fixtures.
	 *
	 * @param
	 *        	array<string, mixed> $options
	 * @param
	 *        	(callable(int, int): int)|null $rng
	 */
	private function makeRefresher(array $options = [], ?callable $rng = null): OnDemandRefresher
	{
		return new OnDemandRefresher(cache: $this->cache, registry: $this->registry, cloud: $this->cloud, options: $options, clock: fn (): int => $this->current_time, rng: $rng);
	}

	// ========================================================================
	// Gate 1: Probability
	// ========================================================================
	public function testGate1ProbabilitySkipsMostRequests(): void
	{
		// Force the RNG to always return values other than 1.
		// Probability gate should fail on every call.
		$rng = fn (int $min, int $max): int => $max; // never 1

		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000
		], $rng);

		// Run 100 times — none should schedule.
		for ($i = 0; $i < 100; $i ++) {
			$decision = $refresher->maybe_refresh();
			$this->assertFalse($decision->should_schedule, "Iteration {$i} should not schedule when RNG never rolls 1");
			$this->assertSame('probability', $decision->reason);
		}
	}

	public function testGate1ProbabilityPassesOnExactRoll(): void
	{
		// RNG returns exactly 1 every time — gate always passes.
		// Other gates need to be set up to pass too (no lock, no cache).
		$rng = fn (int $min, int $max): int => 1;

		// No cache entry → cold_start → schedule.
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);
		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);
		$this->assertSame('cold_start', $decision->reason);
	}

	public function testGate1ProbabilityDenominatorZeroIsRejectedAtConstruction(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->expectExceptionMessage('probability_denominator');
		$this->makeRefresher([
			'probability_denominator' => 0
		]);
	}

	// ========================================================================
	// Gate 2: Cooldown
	// ========================================================================
	public function testGate2CooldownSkipsWhenLockExists(): void
	{
		// Lock is already held by another worker (simulated).
		$this->cache->set(OnDemandRefresher::CACHE_KEY_LOCK, $this->current_time, 600);

		$rng = fn (int $min, int $max): int => 1; // Gate 1 passes
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertFalse($decision->should_schedule);
		$this->assertSame('cooldown', $decision->reason);
	}

	public function testGate2CooldownExpiresWithLockTtl(): void
	{
		// Lock set with very short TTL — expires before next call.
		$this->cache->set(OnDemandRefresher::CACHE_KEY_LOCK, $this->current_time, 1);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		// Advance time past the lock TTL.
		$this->current_time += 10;

		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);
	}

	// ========================================================================
	// Gate 3: Staleness
	// ========================================================================
	public function testGate3StalenessSkipsWhenFresh(): void
	{
		// Cache has been fetched 1 hour ago; min_age is 6 hours.
		// Gate 3 should reject as "fresh".
		$this->cache->set(OnDemandRefresher::CACHE_KEY_MERGED, [
			'data' => [
				'googlebot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => $this->current_time - 3600
		], 86400);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 21600
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertFalse($decision->should_schedule);
		$this->assertSame('fresh', $decision->reason);
	}

	public function testGate3StalenessSchedulesWhenStale(): void
	{
		// Cache is 7 hours old; min_age is 6 hours. Should refresh.
		$this->cache->set(OnDemandRefresher::CACHE_KEY_MERGED, [
			'data' => [
				'googlebot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => $this->current_time - (7 * 3600)
		], 86400);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 21600
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);
		$this->assertSame('stale', $decision->reason);
		$this->assertSame(7 * 3600, $decision->cache_age);
		$this->assertSame(21600, $decision->staleness_floor);
	}

	public function testGate3StalenessSchedulesOnColdStart(): void
	{
		// No cache at all → cold start → schedule.
		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 21600
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);
		$this->assertSame('cold_start', $decision->reason);
		$this->assertNull($decision->cache_age);
	}

	public function testGate3StalenessTreatsMalformedCacheAsAgeZero(): void
	{
		// Cache value is a string (not the expected array shape).
		// compute_cache_age treats this as malformed → age 0.
		// Age 0 < min_age 21600 → 'fresh' decision (no refresh).
		// This is documented behavior: operators with corrupted cache
		// need to manually delete the cache key to force a refresh.
		$this->cache->set(OnDemandRefresher::CACHE_KEY_MERGED, 'corrupted', 86400);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 21600
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertSame('fresh', $decision->reason);
		$this->assertFalse($decision->should_schedule);
	}

	public function testGate3StalenessRejectsFarFutureTimestamps(): void
	{
		// Cache value has 'fetched' timestamp 1 hour in the future
		// (clock skew, NTP correction, etc.). Treat as malformed → age 0.
		$this->cache->set(OnDemandRefresher::CACHE_KEY_MERGED, [
			'data' => [
				'googlebot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => $this->current_time + 3600
		], 86400);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 21600
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertSame('fresh', $decision->reason);
	}

	// ========================================================================
	// Gate 4: Mutex
	// ========================================================================
	public function testGate4MutexAcquiredOnSchedule(): void
	{
		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_LOCK));
		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);

		// Lock should now exist.
		$lock = $this->cache->get(OnDemandRefresher::CACHE_KEY_LOCK);
		$this->assertNotNull($lock, 'Lock must be acquired when scheduling');
		$this->assertSame($this->current_time, $lock);
	}

	public function testGate4MutexPreventsConcurrentSchedule(): void
	{
		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		// First call: acquires lock.
		$decision1 = $refresher->maybe_refresh();
		$this->assertTrue($decision1->should_schedule);

		// Second call: lock is held → cooldown.
		$decision2 = $refresher->maybe_refresh();
		$this->assertFalse($decision2->should_schedule);
		$this->assertSame('cooldown', $decision2->reason);
	}

	public function testGate4MutexClearedAfterRefresh(): void
	{
		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0,
			'lock_ttl' => 600
		], $rng);

		$refresher->maybe_refresh(); // acquire lock
		$refresher->do_refresh(); // run refresh (should clear lock)

		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_LOCK), 'do_refresh() must clear the lock when it finishes');

		// Subsequent maybe_refresh() should be able to schedule again.
		$this->cache->delete(OnDemandRefresher::CACHE_KEY_MERGED);
		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);
	}

	public function testGate4MutexReportsMutexLostOnSetFailure(): void
	{
		// Cache that throws on set() — simulates lock-acquire failure.
		// The catch is INSIDE try_acquire_lock(), so this surfaces as
		// 'mutex_lost' (a known failure mode) rather than 'error'.
		$cache = new ThrowingCache('set');
		$refresher = new OnDemandRefresher(cache: $cache, registry: $this->registry, cloud: $this->cloud, options: [
			'min_age_seconds' => 0
		], // force schedule
		clock: fn (): int => $this->current_time, rng: fn (int $min, int $max): int => 1);

		$decision = $refresher->maybe_refresh();
		$this->assertFalse($decision->should_schedule);
		$this->assertSame('mutex_lost', $decision->reason);
	}

	// ========================================================================
	// do_refresh() behavior
	// ========================================================================
	public function testDoRefreshMergesAllBotFeeds(): void
	{
		// Set up two feeds returning different bots.
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32',
				'5.6.7.8/32'
			]
		]));
		$this->registry->addFeed('openai', new FakeIpFeed([
			'gptbot' => [
				'9.10.11.12/32'
			]
		]));
		$this->cloud->setRanges('aws', [
			'13.14.15.16/32',
			'17.18.19.20/32'
		]);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		$this->assertTrue($result->success);
		$this->assertFalse($result->partial);
		$this->assertSame(3, $result->bot_count, 'Should merge 3 bot IDs (googlebot, gptbot, aws_elb_health)');
		$this->assertSame(5, $result->cidr_count, 'Should sum 2+1+2 = 5 CIDRs');
		$this->assertTrue($result->cache_written);

		// Verify the cache payload.
		$payload = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
		$this->assertIsArray($payload);
		$this->assertArrayHasKey('data', $payload);
		$this->assertArrayHasKey('fetched', $payload);
		$this->assertSame($this->current_time, $payload['fetched']);
		$this->assertSame([
			'1.2.3.4/32',
			'5.6.7.8/32'
		], $payload['data']['googlebot']);
		$this->assertSame([
			'9.10.11.12/32'
		], $payload['data']['gptbot']);
		$this->assertSame([
			'13.14.15.16/32',
			'17.18.19.20/32'
		], $payload['data']['aws_elb_health']);
	}

	public function testDoRefreshDeduplicatesOverlappingRanges(): void
	{
		// Two feeds both return a range for the same bot — should dedup.
		$this->registry->addFeed('feed-a', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32',
				'5.6.7.8/32'
			]
		]));
		$this->registry->addFeed('feed-b', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32',
				'9.10.11.12/32'
			]
		]));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$refresher->do_refresh();

		// 1.2.3.4/32 appears twice but should be deduped to once.
		$payload = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
		$this->assertSame([
			'1.2.3.4/32',
			'5.6.7.8/32',
			'9.10.11.12/32'
		], $payload['data']['googlebot']);
	}

	public function testDoRefreshContinuesOnPerFeedFailure(): void
	{
		$this->registry->addFeed('working', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));
		$this->registry->addFeed('broken', new FakeIpFeed(data: [], throws: new \RuntimeException('feed endpoint down')));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		$this->assertTrue($result->partial, 'One feed failed but one succeeded → partial');
		$this->assertFalse($result->success, 'Partial result is not full success');
		$this->assertTrue($result->cache_written, 'Partial data is still cached');

		// Working feed's data should be in the cache.
		$payload = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
		$this->assertSame([
			'1.2.3.4/32'
		], $payload['data']['googlebot']);
	}

	public function testDoRefreshSkipsCacheWriteOnTotalFailure(): void
	{
		$this->registry->addFeed('broken-1', new FakeIpFeed(throws: new \RuntimeException('fail 1')));
		$this->registry->addFeed('broken-2', new FakeIpFeed(throws: new \RuntimeException('fail 2')));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		$this->assertFalse($result->success);
		$this->assertFalse($result->partial);
		$this->assertFalse($result->cache_written, 'Total failure must not write empty cache');
		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED), 'Cache must remain unwritten on total failure');
	}

	public function testDoRefreshHonorsFeedTimeoutBudget(): void
	{
		// Each feed sleeps 1 second; budget is 1.5s. Should fetch the first
		// feed, then skip the rest with reason 'budget_exhausted'.
		$slowFeed = new FakeIpFeed(data: [
			'googlebot' => [
				'1.2.3.4/32'
			]
		], sleep_seconds: 1.0);
		$this->registry->addFeed('slow-1', $slowFeed);
		$this->registry->addFeed('slow-2', $slowFeed);
		$this->registry->addFeed('slow-3', $slowFeed);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0,
			'feed_timeout_seconds' => 1.5
		], $rng);

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		// At least one feed should be skipped with reason 'budget_exhausted'.
		$skipped = array_filter($result->feed_status, fn ($s) => ($s['status'] ?? null) === 'skipped');
		$this->assertGreaterThan(0, count($skipped), 'Slow feeds should be skipped when budget is exhausted');
	}

	public function testDoRefreshRespectsBotIdFilter(): void
	{
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			],
			'gptbot' => [
				'5.6.7.8/32'
			]
		]));
		$this->cloud->setRanges('aws', [
			'9.10.11.12/32'
		]);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0,
			'bot_ids' => [
				'googlebot'
			] // Only this bot
		], $rng);

		$refresher->maybe_refresh();
		$refresher->do_refresh();

		$payload = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
		$this->assertArrayHasKey('googlebot', $payload['data']);
		$this->assertArrayNotHasKey('gptbot', $payload['data'], 'gptbot must be filtered out by bot_ids option');
		$this->assertArrayNotHasKey('aws_elb_health', $payload['data'], 'aws_elb_health must be filtered out (not in bot_ids allow-list)');
	}

	public function testDoRefreshRespectsCloudProviderFilter(): void
	{
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));
		$this->cloud->setRanges('aws', [
			'9.10.11.12/32'
		]);
		$this->cloud->setRanges('cloudflare', [
			'13.14.15.16/32'
		]);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0,
			'cloud_providers' => [
				'cloudflare'
			] // Only this provider
		], $rng);

		$refresher->maybe_refresh();
		$refresher->do_refresh();

		$payload = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
		$this->assertArrayHasKey('googlebot', $payload['data']);
		$this->assertArrayHasKey('cloudflare_health', $payload['data']);
		$this->assertArrayNotHasKey('aws_elb_health', $payload['data'], 'aws must be filtered out by cloud_providers option');
	}

	public function testDoRefreshIsIdempotentForCacheWrite(): void
	{
		// Two consecutive do_refresh() calls should produce equivalent
		// cache payloads (modulo timestamp).
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$refresher->do_refresh();
		$payload1 = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);

		// Reset lock + cache so we can run again.
		$this->cache->delete(OnDemandRefresher::CACHE_KEY_LOCK);
		$this->cache->delete(OnDemandRefresher::CACHE_KEY_MERGED);

		$refresher->maybe_refresh();
		$refresher->do_refresh();
		$payload2 = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);

		$this->assertSame($payload1['data'], $payload2['data']);
	}

	public function testDoRefreshReportsFeedStatus(): void
	{
		$this->registry->addFeed('ok', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));
		$this->registry->addFeed('err', new FakeIpFeed(throws: new \RuntimeException('boom')));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		$this->assertArrayHasKey('ok', $result->feed_status);
		$this->assertSame('ok', $result->feed_status['ok']['status']);

		$this->assertArrayHasKey('err', $result->feed_status);
		$this->assertSame('error', $result->feed_status['err']['status']);
		$this->assertSame('boom', $result->feed_status['err']['error']);
	}

	public function testDoRefreshHandlesCloudProviderThrowing(): void
	{
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		// Make the cloud provider throw on every call.
		$this->cloud->alwaysThrow = new \RuntimeException('cloud api down');

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		// Bot feed succeeded → partial (cloud failed).
		$this->assertTrue($result->partial);
		$this->assertTrue($result->cache_written);

		// All four default cloud providers should be marked error.
		$cloud_statuses = array_filter($result->feed_status, fn ($_, $k) => str_starts_with($k, 'cloud:'), ARRAY_FILTER_USE_BOTH);
		$this->assertCount(4, $cloud_statuses, 'All 4 default cloud providers should be attempted');
		foreach ($cloud_statuses as $status) {
			$this->assertSame('error', $status['status']);
		}
	}

	// ========================================================================
	// Construction validation
	// ========================================================================
	public function testConstructorRejectsNegativeIntegers(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->makeRefresher([
			'min_age_seconds' => - 1
		]);
	}

	public function testConstructorRejectsStringInteger(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->makeRefresher([
			'lock_ttl' => '600'
		]); // string, not int
	}

	public function testConstructorRejectsNonArrayBotIds(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->makeRefresher([
			'bot_ids' => 'googlebot'
		]);
	}

	public function testConstructorRejectsNonArrayCloudProviders(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		$this->makeRefresher([
			'cloud_providers' => 'aws'
		]);
	}

	public function testDefaultsAreAppliedWhenOptionsEmpty(): void
	{
		$refresher = $this->makeRefresher();
		$opts = $refresher->get_options();
		$this->assertSame(1000, $opts['probability_denominator']);
		$this->assertSame(21600, $opts['min_age_seconds']);
		$this->assertSame(600, $opts['lock_ttl']);
		$this->assertSame(604800, $opts['cache_ttl']);
	}

	public function testConstructorMergesUserOptionsOverDefaults(): void
	{
		$refresher = $this->makeRefresher([
			'min_age_seconds' => 60
		]);
		$opts = $refresher->get_options();
		$this->assertSame(60, $opts['min_age_seconds']);
		$this->assertSame(1000, $opts['probability_denominator'], 'Untouched defaults preserved');
	}

	// ========================================================================
	// Edge cases & defensive behavior
	// ========================================================================
	public function testMaybeRefreshSurvivesCacheGetException(): void
	{
		$cache = new ThrowingCache('get');
		$refresher = new OnDemandRefresher(cache: $cache, registry: $this->registry, cloud: $this->cloud, options: [], clock: fn (): int => $this->current_time, rng: fn (int $min, int $max): int => 1);

		// Probability gate passes; cache->get() throws on lock check.
		// Should swallow the exception and return a skip('error') decision
		// rather than crash the request.
		$decision = $refresher->maybe_refresh();
		$this->assertFalse($decision->should_schedule);
		$this->assertSame('error', $decision->reason);
	}

	public function testDoRefreshClearsLockEvenOnException(): void
	{
		// One feed throws, but the do_refresh() finally-equivalent
		// code path must still clear the lock.
		$this->registry->addFeed('broken', new FakeIpFeed(throws: new \RuntimeException('boom')));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$refresher->maybe_refresh();
		$this->assertNotNull($this->cache->get(OnDemandRefresher::CACHE_KEY_LOCK));

		$refresher->do_refresh();
		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_LOCK), 'Lock must be cleared even when feeds throw');
	}

	public function testDoRefreshClearsLockEvenOnCacheWriteFailure(): void
	{
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));

		// Cache that throws only on set() of the MERGED key — not the lock.
		// Simulates cache full or write-rejected on the data path while
		// the lock path still works.
		$cache = new SelectiveThrowingCache(throw_on_key: OnDemandRefresher::CACHE_KEY_MERGED);
		$refresher = new OnDemandRefresher(cache: $cache, registry: $this->registry, cloud: $this->cloud, options: [
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], clock: fn (): int => $this->current_time, rng: fn (int $min, int $max): int => 1);

		$refresher->maybe_refresh();
		$result = $refresher->do_refresh();

		$this->assertFalse($result->cache_written, 'Cache write failed → not written');
		$this->assertNull($cache->get(OnDemandRefresher::CACHE_KEY_LOCK), 'Lock must be cleared even when cache write fails');
	}

	public function testWasRefreshInvokedFalseBeforeDoRefresh(): void
	{
		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$this->assertFalse($refresher->was_refresh_invoked());

		$refresher->maybe_refresh();
		$this->assertFalse($refresher->was_refresh_invoked(), 'was_refresh_invoked reflects do_refresh() invocation, not maybe_refresh()');

		$refresher->do_refresh();
		$this->assertTrue($refresher->was_refresh_invoked());
	}

	public function testGetLastResultReturnsNullInitially(): void
	{
		$refresher = $this->makeRefresher();
		$this->assertNull($refresher->get_last_result());

		$refresher->do_refresh();
		$this->assertNotNull($refresher->get_last_result());
		$this->assertInstanceOf(RefreshResult::class, $refresher->get_last_result());
	}

	// ========================================================================
	// RefreshResult value object
	// ========================================================================
	public function testRefreshResultCountsFeeds(): void
	{
		$result = new RefreshResult(success: true, partial: false, bot_count: 5, cidr_count: 100, elapsed_seconds: 1.5, cache_written: true, feed_status: [
			'feed-a' => [
				'status' => 'ok'
			],
			'feed-b' => [
				'status' => 'ok'
			],
			'feed-c' => [
				'status' => 'error',
				'error' => 'down'
			],
			'feed-d' => [
				'status' => 'skipped',
				'reason' => 'budget'
			]
		], started_at: 1000, finished_at: 1001);

		$this->assertSame(2, $result->successful_feed_count());
		$this->assertSame(1, $result->failed_feed_count());

		$arr = $result->to_array();
		$this->assertArrayHasKey('successful_feed_count', $arr);
		$this->assertArrayHasKey('failed_feed_count', $arr);
		$this->assertSame(2, $arr['successful_feed_count']);
		$this->assertSame(1, $arr['failed_feed_count']);
	}

	public function testRefreshResultToArrayShape(): void
	{
		$result = new RefreshResult(success: true, partial: false, bot_count: 1, cidr_count: 1, elapsed_seconds: 0.1, cache_written: true, feed_status: [
			'x' => [
				'status' => 'ok'
			]
		], started_at: 100, finished_at: 101);

		$arr = $result->to_array();
		$this->assertSame([
			'success',
			'partial',
			'bot_count',
			'cidr_count',
			'elapsed_seconds',
			'cache_written',
			'feed_status',
			'successful_feed_count',
			'failed_feed_count',
			'started_at',
			'finished_at'
		], array_keys($arr));
	}

	// ========================================================================
	// RefreshDecision value object
	// ========================================================================
	public function testRefreshDecisionSkipFactory(): void
	{
		$d = RefreshDecision::skip('probability');
		$this->assertFalse($d->should_schedule);
		$this->assertSame('probability', $d->reason);
		$this->assertNull($d->cache_age);
		$this->assertNull($d->staleness_floor);
	}

	public function testRefreshDecisionScheduleFactory(): void
	{
		$d = RefreshDecision::schedule('stale', 100000, 21600);
		$this->assertTrue($d->should_schedule);
		$this->assertSame('stale', $d->reason);
		$this->assertSame(100000, $d->cache_age);
		$this->assertSame(21600, $d->staleness_floor);
	}

	public function testRefreshDecisionStringable(): void
	{
		$skip = RefreshDecision::skip('probability');
		$this->assertStringContainsString('skip', (string) $skip);
		$this->assertStringContainsString('probability', (string) $skip);

		$schedule = RefreshDecision::schedule('stale', 21600, 21600);
		$this->assertStringContainsString('schedule', (string) $schedule);
		$this->assertStringContainsString('stale', (string) $schedule);
	}

	public function testRefreshDecisionScheduleWithNullCacheAge(): void
	{
		// cold_start case: cache was absent, no age to report.
		$d = RefreshDecision::schedule('cold_start', null, 21600);
		$this->assertTrue($d->should_schedule);
		$this->assertSame('cold_start', $d->reason);
		$this->assertNull($d->cache_age);
	}

	// ========================================================================
	// End-to-end scenarios
	// ========================================================================
	public function testEndToEndFirstRunFetchesAndPopulates(): void
	{
		// Simulates: fresh install, no cache anywhere.
		// First 999 requests → skip (probability).
		// 1000th request → schedule → do_refresh → cache populated.
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));

		// Initial state: no cache.
		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED));

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 0
		], $rng);

		$decision = $refresher->maybe_refresh();
		$this->assertTrue($decision->should_schedule);

		$result = $refresher->do_refresh();
		$this->assertTrue($result->success);

		// Now the cache has data, fetched_at = current_time.
		$payload = $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED);
		$this->assertNotNull($payload);
		$this->assertSame([
			'1.2.3.4/32'
		], $payload['data']['googlebot']);
		$this->assertSame($this->current_time, $payload['fetched']);
	}

	public function testEndToEndSteadyStateSkipsUntilStale(): void
	{
		// Simulates: cache was just refreshed. Six hours later, it becomes
		// eligible for refresh. After that, it gets refreshed.
		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));

		// Start with fresh cache.
		$this->cache->set(OnDemandRefresher::CACHE_KEY_MERGED, [
			'data' => [
				'googlebot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => $this->current_time
		], 86400);

		$rng = fn (int $min, int $max): int => 1;
		$refresher = $this->makeRefresher([
			'probability_denominator' => 1000,
			'min_age_seconds' => 21600
		], $rng);

		// Immediately: fresh → skip.
		$d = $refresher->maybe_refresh();
		$this->assertSame('fresh', $d->reason);

		// 5 hours later: still fresh → skip.
		$this->current_time += 5 * 3600;
		$d = $refresher->maybe_refresh();
		$this->assertSame('fresh', $d->reason);

		// 7 hours later: stale → schedule.
		$this->current_time += 2 * 3600;
		$d = $refresher->maybe_refresh();
		$this->assertTrue($d->should_schedule);
		$this->assertSame('stale', $d->reason);

		// Refresh runs, lock is acquired, then cleared.
		$refresher->do_refresh();
		$this->assertNull($this->cache->get(OnDemandRefresher::CACHE_KEY_LOCK));

		// Immediately after refresh: fresh again → skip.
		$d = $refresher->maybe_refresh();
		$this->assertSame('fresh', $d->reason);
	}

	public function testEndToEndProbabilityGateDistributesCorrectly(): void
	{
		// Pre-populate cache as "very stale" so the staleness gate passes
		// on the first firing of the probability gate.
		$this->cache->set(OnDemandRefresher::CACHE_KEY_MERGED, [
			'data' => [
				'googlebot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => $this->current_time - (7 * 3600) // 7 hours old
		], 86400);

		$this->registry->addFeed('google', new FakeIpFeed([
			'googlebot' => [
				'1.2.3.4/32'
			]
		]));

		// RNG fires on every 10th call.
		$call_count = 0;
		$rng = function (int $min, int $max) use (&$call_count): int {
			$call_count ++;
			return ($call_count % 10 === 5) ? 1 : $max;
		};

		$refresher = $this->makeRefresher([
			'probability_denominator' => 10,
			'min_age_seconds' => 21600
		], $rng);

		// Calls 1-4: probability gate fails (RNG returns max).
		for ($i = 1; $i <= 4; $i ++) {
			$d = $refresher->maybe_refresh();
			$this->assertFalse($d->should_schedule, "Call {$i} should skip");
			$this->assertSame('probability', $d->reason);
		}

		// Call 5: probability fires, no lock, cache is stale (7h > 6h) → schedule.
		$d = $refresher->maybe_refresh();
		$this->assertTrue($d->should_schedule, 'Call 5 should schedule');
		$this->assertSame('stale', $d->reason);

		// Run the refresh to clear the lock and refresh the cache.
		$refresher->do_refresh();

		// Calls 6-14: probability gate fails again.
		for ($i = 6; $i <= 14; $i ++) {
			$d = $refresher->maybe_refresh();
			$this->assertFalse($d->should_schedule, "Call {$i} should skip");
			$this->assertSame('probability', $d->reason);
		}

		// Call 15: probability fires, no lock, cache is fresh (just refreshed) → skip fresh.
		$d = $refresher->maybe_refresh();
		$this->assertFalse($d->should_schedule, 'Call 15 should skip (cache is fresh)');
		$this->assertSame('fresh', $d->reason);
	}
}

// ========================================================================
// Test fixtures: in-memory cache + fake feeds + throwing caches
// ========================================================================

/**
 * Full in-memory CacheInterface implementation for tests.
 *
 * Honors TTL semantics — expired entries are removed on access.
 * Mirrors the contract the production FileCache/Redis adapters
 * implement, so tests that pass here also work against real backends.
 */
class InMemoryCache implements CacheInterface
{

	/** @var array<string, array{value: mixed, expires: int}> */
	private array $store = [];

	/** @var callable(): int */
	private $clock;

	/**
	 *
	 * @param
	 *        	(callable(): int)|null $clock Override time() for tests.
	 *        	Defaults to PHP's time() in production.
	 */
	public function __construct(?callable $clock = null)
	{
		$this->clock = $clock ?? 'time';
	}

	public function get(string $key): mixed
	{
		if (! isset($this->store[$key])) {
			return null;
		}
		$entry = $this->store[$key];
		$now = ($this->clock)();
		if ($entry['expires'] < $now) {
			unset($this->store[$key]);
			return null;
		}
		return $entry['value'];
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		$this->store[$key] = [
			'value' => $value,
			'expires' => ($this->clock)() + $ttl
		];
		return true;
	}

	public function delete(string $key): bool
	{
		$existed = isset($this->store[$key]);
		unset($this->store[$key]);
		return $existed;
	}

	public function increment_counter(string $key, int $window): int
	{
		$current = $this->get_counter($key);
		$new = $current + 1;
		$this->store["counter:$key"] = [
			'value' => $new,
			'expires' => ($this->clock)() + $window
		];
		return $new;
	}

	public function get_counter(string $key): int
	{
		$val = $this->get("counter:$key");
		return is_int($val) ? $val : 0;
	}

	public function get_set(string $key): array
	{
		$val = $this->get("set:$key");
		return is_array($val) ? array_keys($val) : [];
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		$existing = $this->get("set:$key") ?? [];
		$existing[$value] = ($this->clock)() + $ttl;
		$this->store["set:$key"] = [
			'value' => $existing,
			'expires' => ($this->clock)() + $ttl
		];
		return true;
	}
}

/**
 * A FeedProviderInterface implementation that lets tests inject feeds directly.
 *
 * Production FeedRegistry has a hardcoded list of feeds with a heavy
 * constructor. For tests we need to control what feeds are iterated, so
 * we use this lightweight stand-in that implements FeedProviderInterface
 * without all the FeedRegistry construction overhead.
 */
final class FakeFeedProvider implements FeedProviderInterface
{

	/** @var array<string, IpFeedInterface> */
	private array $test_feeds = [];

	public function addFeed(string $name, IpFeedInterface $feed): void
	{
		$this->test_feeds[$name] = $feed;
	}

	public function get_feeds(): array
	{
		return $this->test_feeds;
	}
}

/**
 * A CloudIpRangeProvider subclass that returns ranges from a static map.
 *
 * Production CloudIpRangeProvider fetches live from external APIs and
 * caches the results. For tests we want a deterministic source so we
 * override ranges() to read from a local array.
 *
 * The parent constructor requires a CacheInterface; we pass a NullCache
 * since FakeCloudProvider's overridden ranges() never touches it.
 */
final class FakeCloudProvider extends CloudIpRangeProvider
{

	/** @var array<string, string[]> */
	private array $ranges = [];

	/**
	 * If non-null, the next call to ranges() will throw this exception
	 * (then clear).
	 * Lets tests simulate transient cloud API failures.
	 */
	public ?\Throwable $throwOnNext = null;

	/**
	 * If non-null, every call to ranges() throws this exception.
	 * Lets tests simulate sustained cloud API failures.
	 */
	public ?\Throwable $alwaysThrow = null;

	public function __construct()
	{
		parent::__construct(new NullCache());
	}

	/**
	 *
	 * @param
	 *        	array<string, string[]> $ranges provider => CIDRs
	 */
	public function setRanges(string $provider, array $ranges): void
	{
		$this->ranges[$provider] = $ranges;
	}

	public function ranges(string $provider, ?string $tag = null): array
	{
		if ($this->alwaysThrow !== null) {
			throw $this->alwaysThrow;
		}
		if ($this->throwOnNext !== null) {
			$e = $this->throwOnNext;
			$this->throwOnNext = null;
			throw $e;
		}
		return $this->ranges[$provider] ?? [];
	}
}

/**
 * A controllable IpFeedInterface for tests.
 *
 * Can return canned data, throw on demand, and simulate slow feeds.
 */
final class FakeIpFeed implements IpFeedInterface
{

	/**
	 *
	 * @param
	 *        	array<string, string[]> $data
	 */
	public function __construct(private array $data = [], private ?\Throwable $throws = null, private float $sleep_seconds = 0.0)
	{}

	public function fetch(): array
	{
		if ($this->sleep_seconds > 0) {
			usleep((int) ($this->sleep_seconds * 1_000_000));
		}
		if ($this->throws !== null) {
			throw $this->throws;
		}
		return $this->data;
	}

	public function get_source_name(): string
	{
		return 'fake-feed';
	}

	public function get_bot_ids(): array
	{
		return array_keys($this->data);
	}
}

/**
 * A CacheInterface that throws on a specific operation.
 *
 * Used to simulate cache backend failures and verify the refresher's
 * defensive behavior — failures must NEVER crash the request.
 */
final class ThrowingCache implements CacheInterface
{

	public function __construct(private readonly string $fail_on = 'get')
	{}

	public function get(string $key): mixed
	{
		if ($this->fail_on === 'get') {
			throw new \RuntimeException("cache get failed for {$key}");
		}
		return null;
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		if ($this->fail_on === 'set') {
			throw new \RuntimeException("cache set failed for {$key}");
		}
		return true;
	}

	public function delete(string $key): bool
	{
		if ($this->fail_on === 'delete') {
			throw new \RuntimeException("cache delete failed for {$key}");
		}
		return true;
	}

	public function increment_counter(string $key, int $window): int
	{
		if ($this->fail_on === 'increment_counter') {
			throw new \RuntimeException("cache increment failed for {$key}");
		}
		return 1;
	}

	public function get_counter(string $key): int
	{
		if ($this->fail_on === 'get_counter') {
			throw new \RuntimeException("cache get_counter failed for {$key}");
		}
		return 0;
	}

	public function get_set(string $key): array
	{
		if ($this->fail_on === 'get_set') {
			throw new \RuntimeException("cache get_set failed for {$key}");
		}
		return [];
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		if ($this->fail_on === 'add_to_set') {
			throw new \RuntimeException("cache add_to_set failed for {$key}");
		}
		return true;
	}
}

/**
 * A CacheInterface that throws on a specific cache key (not all keys).
 *
 * Used to simulate the "data path is broken but lock path works" or
 * vice versa. Inherits the in-memory semantics from InMemoryCache so
 * non-throwing operations behave like a real cache.
 */
final class SelectiveThrowingCache extends InMemoryCache
{

	public function __construct(private readonly string $throw_on_key)
	{
		parent::__construct();
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		if ($key === $this->throw_on_key) {
			throw new \RuntimeException("cache set failed for {$key}");
		}
		return parent::set($key, $value, $ttl);
	}
}

/**
 * Minimal CacheInterface that does nothing useful.
 *
 * Used as a placeholder when constructing FakeCloudProvider — the parent
 * CloudIpRangeProvider requires a cache in its constructor, but
 * FakeCloudProvider overrides ranges() entirely so the cache is never
 * actually used.
 */
final class NullCache implements CacheInterface
{

	public function get(string $key): mixed
	{
		return null;
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		return true;
	}

	public function delete(string $key): bool
	{
		return true;
	}

	public function increment_counter(string $key, int $window): int
	{
		return 1;
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
}
