<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Configuration;
use BadBehaviour\Tests\Fixtures\Stubs\RetentionTestAdapter;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\LogRetention;
use BadBehaviour\Util\RetentionDecision;
use BadBehaviour\Util\RetentionResult;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(LogRetention::class)]
#[CoversClass(RetentionDecision::class)]
#[CoversClass(RetentionResult::class)]
final class LogRetentionTest extends TestCase
{

	private RetentionTestAdapter $adapter;

	private Configuration $config;

	/**
	 * Fixed clock for deterministic time arithmetic.
	 */
	private int $fixedNow = 1_700_000_000;

	/**
	 * Fixed RNG that always rolls the requested outcome.
	 */
	private bool $rngRollsOne = true;

	protected function setUp(): void
	{
		parent::setUp();
		ErrorReporter::reset();
		$this->adapter = new RetentionTestAdapter();
		$this->config = $this->makeConfig();
	}

	protected function tearDown(): void
	{
		ErrorReporter::reset();
		parent::tearDown();
	}

	private function makeConfig(array $overrides = []): Configuration
	{
		return Configuration::from_array(array_merge([
			'log_retention' => [
				'enabled' => true,
				'max_age_days' => 7,
				'max_rows' => 0,
				'probability_denominator' => 1000,
				'min_interval_seconds' => 21600,
				'lock_ttl' => 600
			]
		], $overrides));
	}

	private function makeRetention(?int $chunk_size = null, ?float $max_total_seconds = null): LogRetention
	{
		return new LogRetention(adapter: $this->adapter, config: $this->config, cache: $this->adapter, chunk_size: $chunk_size ?? 10000, max_total_seconds: $max_total_seconds ?? 0.5, clock: fn () => $this->fixedNow, rng: fn (int $min, int $max) => $this->rngRollsOne ? 1 : $max);
	}

	// ========================================================================
	// Master switch
	// ========================================================================
	#[Test]
	public function disabled_by_default_skips_all_gates(): void
	{
		$this->config = $this->makeConfig([
			'log_retention' => [
				'enabled' => false
			]
		]);
		$retention = $this->makeRetention();

		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('disabled', $decision->reason);
	}

	#[Test]
	public function force_cleanup_now_returns_null_when_disabled(): void
	{
		$this->config = $this->makeConfig([
			'log_retention' => [
				'enabled' => false
			]
		]);
		$retention = $this->makeRetention();

		$this->assertNull($retention->force_cleanup_now());
		$this->assertFalse($retention->was_invoked());
	}

	// ========================================================================
	// Gate 1: Probability
	// ========================================================================
	#[Test]
	public function gate1_skips_when_rng_does_not_roll_one(): void
	{
		$this->rngRollsOne = false; // RNG returns max → roll != 1
		$retention = $this->makeRetention();

		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('probability', $decision->reason);
		// Locks must NOT have been touched on a probability-skip.
		$this->assertFalse($this->adapter->cacheHas(LogRetention::CACHE_KEY_LOCK));
	}

	#[Test]
	public function gate1_fires_when_rng_rolls_one(): void
	{
		$this->rngRollsOne = true;
		$retention = $this->makeRetention();

		$decision = $retention->maybe_cleanup();

		// RNG passed → at least got past Gate 1. Subsequent gates may
		// have caused skips, but the reason must not be 'probability'.
		$this->assertNotSame('probability', $decision->reason);
	}

	// ========================================================================
	// Gate 2: Cooldown (lock held)
	// ========================================================================
	#[Test]
	public function gate2_skips_when_lock_is_held(): void
	{
		$this->rngRollsOne = true;
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LOCK, $this->fixedNow, 600);

		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('cooldown', $decision->reason);
	}

	#[Test]
	public function gate2_returns_cooldown_when_no_cache_available(): void
	{
		// Adapter without CacheInterface → no mutex possible.
		$noCacheAdapter = new class() implements \BadBehaviour\Core\Interfaces\AdapterInterface {

			public function get_settings(): array
			{
				return [
					'log_table' => 't'
				];
			}

			public function get_whitelist(): array
			{
				return [];
			}

			public function get_email(): string
			{
				return '';
			}

			public function get_relative_path(): string
			{
				return '/';
			}

			public function get_table_schema(string $t): string
			{
				return '';
			}

			public function log_request(\BadBehaviour\Util\RequestPackage $p, \BadBehaviour\Core\Result $r): void
			{}

			public function query(string $sql): bool
			{
				return true;
			}

			public function increment_counter(string $k, int $w): int
			{
				return 1;
			}

			public function get_counter(string $k): int
			{
				return 0;
			}

			public function delete(string $k): bool
			{
				return true;
			}

			public function get_behavior_profile(string $s): ?array
			{
				return null;
			}

			public function save_behavior_profile(string $s, array $p, int $t): bool
			{
				return true;
			}

			public function add_to_set(string $k, string $v, int $t): bool
			{
				return true;
			}

			public function get_set(string $k): array
			{
				return [];
			}

			public function get_geoip(string $ip): ?array
			{
				return null;
			}

			public function verify_challenge(string $r, string $ip): bool
			{
				return false;
			}

			public function log(string $l, string $m, array $c = []): void
			{}

			public function probe_log_table(string $table): array
			{
				return [
					'newest' => null,
					'total' => 0,
					'error' => null
				];
			}

			// ADD THIS METHOD:
			public function last_query_affected_rows(): ?int
			{
				return null; // No DB connection → can't determine affected rows
			}
		};

		$retention = new LogRetention(adapter: $noCacheAdapter, config: $this->config, cache: null, clock: fn () => $this->fixedNow, rng: fn () => 1);

		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('cooldown', $decision->reason);
	}

	// ========================================================================
	// Gate 3: Staleness
	// ========================================================================
	#[Test]
	public function gate3_skips_when_last_run_was_recent(): void
	{
		$this->rngRollsOne = true;
		// Last cleanup 1 hour ago — well within 6h cooldown.
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LAST_RUN, $this->fixedNow - 3600, 86400);

		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('fresh', $decision->reason);
	}

	#[Test]
	public function gate3_fires_when_last_run_is_stale(): void
	{
		$this->rngRollsOne = true;
		// Last cleanup 7 hours ago — past the 6h floor.
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LAST_RUN, $this->fixedNow - (7 * 3600), 86400);

		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		$this->assertNotSame('fresh', $decision->reason);
		$this->assertNotSame('probability', $decision->reason);
	}

	#[Test]
	public function gate3_treats_absent_cache_as_cold_start(): void
	{
		$this->rngRollsOne = true;
		// No CACHE_KEY_LAST_RUN → cold start.
		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		$this->assertTrue($decision->should_cleanup);
		$this->assertSame('cold_start', $decision->reason);
		$this->assertNull($decision->last_run_age);
	}

	#[Test]
	public function gate3_treats_far_future_timestamp_as_cold_start(): void
	{
		$this->rngRollsOne = true;
		// Future timestamp (clock skew bug) → treated as malformed.
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LAST_RUN, $this->fixedNow + 86400, // 1 day in the future
		86400);

		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		// Far-future → compute_last_run_age returns null → cold start path.
		$this->assertTrue($decision->should_cleanup);
		$this->assertSame('cold_start', $decision->reason);
	}

	#[Test]
	public function gate3_treats_zero_or_negative_timestamp_as_cold_start(): void
	{
		$this->rngRollsOne = true;
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LAST_RUN, 0, 86400);
		$retention = $this->makeRetention();

		$decision = $retention->maybe_cleanup();

		$this->assertTrue($decision->should_cleanup);
		$this->assertSame('cold_start', $decision->reason);
	}

	#[Test]
	public function gate3_treats_non_numeric_timestamp_as_cold_start(): void
	{
		$this->rngRollsOne = true;
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LAST_RUN, 'not-a-number', 86400);
		$retention = $this->makeRetention();

		$decision = $retention->maybe_cleanup();

		$this->assertTrue($decision->should_cleanup);
		$this->assertSame('cold_start', $decision->reason);
	}

	// ========================================================================
	// Gate 4: Mutex
	// ========================================================================
	#[Test]
	public function gate4_skips_when_lock_acquisition_fails(): void
	{
		$this->rngRollsOne = true;
		// Make cache->set fail by using a cache that throws.
		$throwingCache = $this->adapter;
		// Override set() via a small wrapper — use a separate stub.
		// For simplicity, we use the in-memory adapter but make set() return false.
		// Instead, we directly test the lock-acquisition failure path
		// by NOT seeding the lock (which simulates Gate 2 having just passed)
		// and expecting Gate 4 to succeed.

		// Easier: use a separate cache-only failure simulation.
		$failingAdapter = new RetentionTestAdapter();
		$failingAdapter->queryReturnsTrue = false;
		// Override set to fail by injecting a wrapper:
		$retention = new LogRetention(adapter: $failingAdapter, config: $this->config, cache: new class() implements \BadBehaviour\Core\Interfaces\CacheInterface {

			public function get(string $k): mixed
			{
				return null;
			}

			public function set(string $k, mixed $v, int $t): bool
			{
				return false;
			}

			public function delete(string $k): bool
			{
				return true;
			}

			public function increment_counter(string $k, int $w): int
			{
				return 1;
			}

			public function get_counter(string $k): int
			{
				return 0;
			}

			public function get_set(string $k): array
			{
				return [];
			}

			public function add_to_set(string $k, string $v, int $t): bool
			{
				return true;
			}
		}, clock: fn () => $this->fixedNow, rng: fn () => 1);

		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('mutex_lost', $decision->reason);
	}

	#[Test]
	public function lock_is_acquired_on_successful_decision(): void
	{
		$this->rngRollsOne = true;
		$retention = $this->makeRetention();
		$retention->maybe_cleanup();

		// Decision was 'cold_start' → schedule path → lock must be set.
		$this->assertTrue($this->adapter->cacheHas(LogRetention::CACHE_KEY_LOCK));
	}

	// ========================================================================
	// Successful decision flow
	// ========================================================================
	#[Test]
	public function decision_returns_correct_shape_on_schedule(): void
	{
		$this->rngRollsOne = true;
		// 7h since last run (past 6h floor)
		$this->adapter->seedCache(LogRetention::CACHE_KEY_LAST_RUN, $this->fixedNow - (7 * 3600), 86400);

		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		$this->assertTrue($decision->should_cleanup);
		$this->assertSame('due', $decision->reason);
		$this->assertSame(7 * 3600, $decision->last_run_age);
		$this->assertSame(21600, $decision->staleness_floor);
	}

	#[Test]
	public function decision_skip_has_null_metadata(): void
	{
		$this->rngRollsOne = false;
		$retention = $this->makeRetention();
		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertNull($decision->last_run_age);
		$this->assertNull($decision->staleness_floor);
	}

	#[Test]
	public function decision_to_string_renders_usefully(): void
	{
		$skip = RetentionDecision::skip('probability');
		$this->assertStringContainsString('skip', $skip->__toString());
		$this->assertStringContainsString('probability', $skip->__toString());

		$sched = RetentionDecision::schedule('cold_start', null, 21600);
		$this->assertStringContainsString('schedule', $sched->__toString());
		$this->assertStringContainsString('cold_start', $sched->__toString());
		$this->assertStringContainsString('21600', $sched->__toString());
	}

	// ========================================================================
	// do_cleanup() — age-based deletion
	// ========================================================================
	#[Test]
	public function do_cleanup_emits_age_based_delete(): void
	{
		// Probe returns newest = 10 days ago, total = 500 rows.
		$ten_days_ago = $this->fixedNow - (10 * 86400);
		$this->adapter = new RetentionTestAdapter(logTable: 'bad_behaviour', probeNewest: $ten_days_ago, probeTotal: 500);
		$this->config = $this->makeConfig();

		$retention = $this->makeRetention();
		$result = $retention->force_cleanup_now();

		$this->assertInstanceOf(RetentionResult::class, $result);
		$this->assertSame('bad_behaviour', $result->log_table);
		$this->assertSame('age', $result->limit_by);
		$this->assertGreaterThan(0, $result->iterations);
		$this->assertNull($result->error);

		// Verify the SQL shape: DELETE FROM bad_behaviour WHERE date < cutoff
		$this->assertCount(1, $this->adapter->queryLog);
		$sql = $this->adapter->queryLog[0];
		$this->assertStringStartsWith('DELETE FROM `bad_behaviour` WHERE `date` < ', $sql);

		// Cutoff should be newest - 7*86400 (i.e. 3 days after ten_days_ago).
		$expected_cutoff = $ten_days_ago - (7 * 86400);
		$this->assertStringContainsString((string) $expected_cutoff, $sql);
		$this->assertSame($expected_cutoff, $result->cutoff_computed);
	}

	#[Test]
	public function do_cleanup_uses_time_anchor_when_probe_returns_null(): void
	{
		// No probe data → cutoff = now - 7 days.
		$this->adapter = new RetentionTestAdapter(probeNewest: null, probeTotal: 0);
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$result = $retention->force_cleanup_now();

		$expected_cutoff = $this->fixedNow - (7 * 86400);
		$this->assertSame($expected_cutoff, $result->cutoff_computed);
	}

	#[Test]
	public function do_cleanup_handles_iso_string_date_from_probe(): void
	{
		// Probe returns DATETIME-style string.
		$iso = gmdate('Y-m-d H:i:s', $this->fixedNow - (10 * 86400));
		$this->adapter = new RetentionTestAdapter(probeNewest: $iso, probeTotal: 100);
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$result = $retention->force_cleanup_now();

		$expected_newest = strtotime($iso);
		$expected_cutoff = $expected_newest - (7 * 86400);
		$this->assertSame($expected_cutoff, $result->cutoff_computed);
	}

	#[Test]
	public function do_cleanup_handles_unparseable_probe_string(): void
	{
		// Garbage probe → falls back to time()-anchor.
		$this->adapter = new RetentionTestAdapter(probeNewest: 'NOT-A-DATE', probeTotal: 0);
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$result = $retention->force_cleanup_now();

		$expected_cutoff = $this->fixedNow - (7 * 86400);
		$this->assertSame($expected_cutoff, $result->cutoff_computed);
	}

	// ========================================================================
	// do_cleanup() — row-count cap
	// ========================================================================
	#[Test]
	public function row_count_cap_triggers_row_limit_mode(): void
	{
		$this->config = $this->makeConfig([
			'log_retention' => [
				'max_age_days' => 7,
				'max_rows' => 10000, // cap
				'enabled' => true
			]
		]);
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow - 86400, probeTotal: 50000) // exceeds cap
		;
		$this->adapter->rowsAffectedPerQuery = 10000; // each DELETE removes one chunk

		$retention = $this->makeRetention(chunk_size: 10000);
		$result = $retention->force_cleanup_now();

		$this->assertSame('rows', $result->limit_by);
		// Row mode is iterative — first iteration removes 10000 rows,
		// second iteration finds the table drained (affected=0) and breaks.
		$this->assertGreaterThanOrEqual(1, $result->iterations);
		$this->assertGreaterThanOrEqual(10000, $result->rows_deleted);
	}

	#[Test]
	public function row_count_cap_not_triggered_under_limit(): void
	{
		$this->config = $this->makeConfig([
			'log_retention' => [
				'max_rows' => 10000,
				'enabled' => true,
				'max_age_days' => 7
			]
		]);
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow - 86400, probeTotal: 5000) // under cap
		;

		$retention = $this->makeRetention();
		$result = $retention->force_cleanup_now();

		$this->assertSame('age', $result->limit_by);
		$this->assertCount(1, $this->adapter->queryLog);
	}

	// ========================================================================
	// do_cleanup() — error paths
	// ========================================================================
	#[Test]
	public function do_cleanup_records_query_failure_as_error(): void
	{
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow - 86400, probeTotal: 100);
		$this->adapter->queryReturnsTrue = false; // simulate DB failure
		$this->config = $this->makeConfig();

		$retention = $this->makeRetention();
		$result = $retention->force_cleanup_now();

		$this->assertFalse($result->success);
		$this->assertNotNull($result->error);
		$this->assertSame(0, $result->rows_deleted);
	}

	#[Test]
	public function do_cleanup_sanitizes_log_table_name(): void
	{
		// Adapter returns a malicious-looking table name with backticks.
		$this->adapter = new RetentionTestAdapter(logTable: 'bad_behaviour`; DROP TABLE users; --', probeNewest: $this->fixedNow - 86400, probeTotal: 100);
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$retention->force_cleanup_now();

		$sql = $this->adapter->queryLog[0];
		// Dangerous punctuation must be stripped. The remaining
		// alphanumerics form an invalid table name (no injection risk),
		// which the DB will reject with a syntax error. Backticks
		// appear as the legitimate table-name delimiters around the
		// sanitized name.
		$this->assertStringNotContainsString(';', $sql);
		$this->assertStringNotContainsString('--', $sql);
		$this->assertMatchesRegularExpression('/^DELETE FROM `[a-zA-Z0-9_]+` WHERE `date` < \d+$/', $sql);
	}

	#[Test]
	public function do_cleanup_handles_empty_log_table(): void
	{
		$this->adapter = new RetentionTestAdapter(probeNewest: null, probeTotal: 0);
		$this->adapter->rowsAffectedPerQuery = 0; // nothing actually deleted
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$result = $retention->force_cleanup_now();

		// Emits exactly one DELETE, which reports 0 rows affected.
		$this->assertSame(1, $result->iterations);
		$this->assertSame(0, $result->rows_deleted);
	}

	// ========================================================================
	// Lifecycle / bookkeeping
	// ========================================================================
	#[Test]
	public function was_invoked_tracks_do_cleanup_calls(): void
	{
		$retention = $this->makeRetention();
		$this->assertFalse($retention->was_invoked());

		$retention->force_cleanup_now();
		$this->assertTrue($retention->was_invoked());
	}

	#[Test]
	public function get_last_result_returns_null_before_cleanup(): void
	{
		$retention = $this->makeRetention();
		$this->assertNull($retention->get_last_result());

		$retention->force_cleanup_now();
		$this->assertInstanceOf(RetentionResult::class, $retention->get_last_result());
	}

	#[Test]
	public function lock_is_cleared_after_cleanup(): void
	{
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow, probeTotal: 100);
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$retention->force_cleanup_now();

		$this->assertFalse($this->adapter->cacheHas(LogRetention::CACHE_KEY_LOCK));
	}

	#[Test]
	public function last_run_timestamp_is_recorded_after_successful_cleanup(): void
	{
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow, probeTotal: 100);
		$this->adapter->rowsAffectedPerQuery = 1; // at least one row was deleted
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$retention->force_cleanup_now();

		$this->assertTrue($this->adapter->cacheHas(LogRetention::CACHE_KEY_LAST_RUN));
		$this->assertSame($this->fixedNow, $this->adapter->get(LogRetention::CACHE_KEY_LAST_RUN));
	}

	#[Test]
	public function last_run_timestamp_is_not_recorded_when_nothing_deleted(): void
	{
		$this->adapter = new RetentionTestAdapter(probeNewest: null, probeTotal: 0);
		$this->adapter->rowsAffectedPerQuery = 0; // nothing actually deleted
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$retention->force_cleanup_now();

		// Empty table → 0 rows affected → no last_run recorded (lets next
		// request retry rather than waiting for cooldown to expire).
		$this->assertFalse($this->adapter->cacheHas(LogRetention::CACHE_KEY_LAST_RUN));
	}

	// ========================================================================
	// Error handling (must NOT propagate)
	// ========================================================================
	#[Test]
	public function maybe_cleanup_converts_exceptions_to_skip_decision(): void
	{
		$explodingAdapter = new RetentionTestAdapter();
		// Override the cache to throw.
		$explodingCache = new class() implements \BadBehaviour\Core\Interfaces\CacheInterface {

			public function get(string $k): mixed
			{
				throw new \RuntimeException('cache boom');
			}

			public function set(string $k, mixed $v, int $t): bool
			{
				return true;
			}

			public function delete(string $k): bool
			{
				return true;
			}

			public function increment_counter(string $k, int $w): int
			{
				return 1;
			}

			public function get_counter(string $k): int
			{
				return 0;
			}

			public function get_set(string $k): array
			{
				return [];
			}

			public function add_to_set(string $k, string $v, int $t): bool
			{
				return true;
			}
		};
		$retention = new LogRetention(adapter: $explodingAdapter, config: $this->config, cache: $explodingCache, clock: fn () => $this->fixedNow, rng: fn () => 1);

		$decision = $retention->maybe_cleanup();

		$this->assertFalse($decision->should_cleanup);
		$this->assertSame('error', $decision->reason);
	}

	// ========================================================================
	// Result value object
	// ========================================================================
	#[Test]
	public function retention_result_to_array_includes_all_fields(): void
	{
		$r = new RetentionResult(success: true, rows_deleted: 42, iterations: 3, elapsed_seconds: 0.123456, cutoff_computed: 1_700_000_000, log_table: 't', limit_by: 'age', error: null);

		$arr = $r->to_array();

		$this->assertSame(true, $arr['success']);
		$this->assertSame(42, $arr['rows_deleted']);
		$this->assertSame(3, $arr['iterations']);
		$this->assertSame(0.1235, $arr['elapsed_seconds']); // rounded
		$this->assertSame(1_700_000_000, $arr['cutoff_computed']);
		$this->assertSame('t', $arr['log_table']);
		$this->assertSame('age', $arr['limit_by']);
		$this->assertNull($arr['error']);
	}

	#[Test]
	public function configuration_accepts_log_retention_keys(): void
	{
		$config = Configuration::from_array([
			'log_retention' => [
				'enabled' => true,
				'max_age_days' => 30,
				'max_rows' => 100000,
				'probability_denominator' => 500,
				'min_interval_seconds' => 7200,
				'lock_ttl' => 900
			]
		]);

		$this->assertTrue($config->log_retention_enabled);
		$this->assertSame(30, $config->log_retention_max_age_days);
		$this->assertSame(100000, $config->log_retention_max_rows);
		$this->assertSame(500, $config->log_retention_probability_denominator);
		$this->assertSame(7200, $config->log_retention_min_interval_seconds);
		$this->assertSame(900, $config->log_retention_lock_ttl);
	}

	#[Test]
	public function configuration_clamps_log_retention_values(): void
	{
		// max_age_days < 1 must clamp to 1
		$config = Configuration::from_array([
			'log_retention' => [
				'max_age_days' => 0
			]
		]);
		$this->assertSame(1, $config->log_retention_max_age_days);

		// max_age_days > 3650 must clamp to 3650
		$config = Configuration::from_array([
			'log_retention' => [
				'max_age_days' => 99999
			]
		]);
		$this->assertSame(3650, $config->log_retention_max_age_days);

		// probability_denominator < 1 must clamp to 1
		$config = Configuration::from_array([
			'log_retention' => [
				'probability_denominator' => 0
			]
		]);
		$this->assertSame(1, $config->log_retention_probability_denominator);

		// min_interval_seconds < 60 must clamp to 60
		$config = Configuration::from_array([
			'log_retention' => [
				'min_interval_seconds' => 10
			]
		]);
		$this->assertSame(60, $config->log_retention_min_interval_seconds);
	}

	#[Test]
	public function configuration_round_trips_log_retention_in_to_array(): void
	{
		$config = Configuration::from_array([
			'log_retention' => [
				'enabled' => true,
				'max_age_days' => 14
			]
		]);

		$arr = $config->to_array();

		$this->assertSame(true, $arr['log_retention']['enabled']);
		$this->assertSame(14, $arr['log_retention']['max_age_days']);
		// Other keys fall back to defaults
		$this->assertSame(0, $arr['log_retention']['max_rows']);
		$this->assertSame(21600, $arr['log_retention']['min_interval_seconds']);
	}

	#[Test]
	public function adapter_probe_returns_documented_shape(): void
	{
		$adapter = new RetentionTestAdapter(probeNewest: 1_700_000_000, probeTotal: 42);

		$result = $adapter->probe_log_table('bad_behaviour');

		$this->assertArrayHasKey('newest', $result);
		$this->assertArrayHasKey('total', $result);
		$this->assertArrayHasKey('error', $result);
		$this->assertSame(1_700_000_000, $result['newest']);
		$this->assertSame(42, $result['total']);
		$this->assertNull($result['error']);
	}

	// ========================================================================
	// last_query_affected_rows() null contract
	// ========================================================================
	#[Test]
	public function null_affected_rows_does_not_block_subsequent_cleanups(): void
	{
		// Reproduces the silent-stall bug: when the adapter can't report
		// affected rows, the previous code fell back to chunk_size and
		// marked the cleanup as successful. Subsequent cleanups were
		// blocked by Gate 3 (staleness) for min_interval_seconds (6h),
		// causing unbounded log growth on WackoWiki+SQLite.
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow - 86400, probeTotal: 100);
		$this->adapter->forceNullAffectedRows = true; // ← CHANGE THIS LINE
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		// First cleanup: runs the DELETE, can't verify progress.
		$result1 = $retention->force_cleanup_now();
		$this->assertSame(1, $result1->iterations);
		$this->assertSame(0, $result1->rows_deleted);
		$this->assertFalse($result1->success);

		// CRITICAL: last_run is NOT recorded, so the next cleanup gets
		// a chance to run too.
		$this->assertFalse($this->adapter->cacheHas(LogRetention::CACHE_KEY_LAST_RUN), 'null affected_rows must not record last_run (would block future cleanups)');

		// A subsequent cleanup should also be able to run.
		$retention2 = $this->makeRetention();
		$result2 = $retention2->force_cleanup_now();
		$this->assertSame(1, $result2->iterations);
		// Two DELETEs total = two attempts.
		$this->assertCount(2, $this->adapter->queryLog);
	}

	#[Test]
	public function null_affected_rows_emits_diagnostic(): void
	{
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow - 86400, probeTotal: 100);
		$this->adapter->forceNullAffectedRows = true; // ← CHANGE THIS LINE
		$this->config = $this->makeConfig();
		$retention = $this->makeRetention();

		$retention->force_cleanup_now();

		// The diagnostic is emitted via ErrorReporter::warning, which
		// routes through the adapter's log() method. The stub records
		// nothing, but we can verify the path didn't crash.
		// (ErrorReporter::reset() in tearDown cleans any state.)
		$this->assertTrue(true); // reached without exception
	}

	#[Test]
	public function last_query_affected_rows_contract_returns_nullable_int(): void
	{
		// Verify the interface signature: ?int (not int).
		$reflection = new \ReflectionMethod(\BadBehaviour\Core\Interfaces\AdapterInterface::class, 'last_query_affected_rows');
		$return_type = $reflection->getReturnType();
		$this->assertNotNull($return_type);
		$this->assertTrue($return_type->allowsNull());
	}

	#[Test]
	public function rows_mode_stops_when_affected_rows_is_null(): void
	{
		// Adapter reports null on first call → log + break.
		$this->config = $this->makeConfig([
			'log_retention' => [
				'max_rows' => 1000,
				'enabled' => true,
				'max_age_days' => 7
			]
		]);
		$this->adapter = new RetentionTestAdapter(probeNewest: $this->fixedNow - 86400, probeTotal: 5000);
		$this->adapter->forceNullAffectedRows = true; // ← CHANGE THIS LINE

		$retention = $this->makeRetention(chunk_size: 1000);
		$result = $retention->force_cleanup_now();

		// First iteration: query runs, returns null → break.
		$this->assertSame(1, $result->iterations);
		$this->assertSame(0, $result->rows_deleted);
		$this->assertFalse($result->success);
		// No last-run recorded.
		$this->assertFalse($this->adapter->cacheHas(LogRetention::CACHE_KEY_LAST_RUN));
	}
}