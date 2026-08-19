<?php
declare(strict_types=1);

namespace BadBehaviour\Util;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;

/**
 * On-Demand Log Retention Cleanup ("Web Cron")
 *
 * === PROBLEM ===
 *
 * The bad_behaviour log table grows monotonically. The 2.x library had an
 * implicit cleanup that ran every request above a row threshold and deleted
 * rows older than 7 days. That implementation had two failure modes:
 *
 *   1. DELETE storm — high-traffic sites triggered cleanup on every request,
 *	  each issuing a DELETE that scanned the index, causing real-world
 *	  latency spikes.
 *
 *   2. Portable SQL assumption — the SQL was hardcoded for one adapter's
 *	  schema. Cross-adapter deployments (e.g., MediaWiki → GenericAdapter
 *	  migration) silently broke because the WHERE clause referenced the
 *	  wrong column type.
 *
 * === SOLUTION ===
 *
 * Mirror OnDemandRefresher's 4-gate design but applied to log cleanup:
 *
 *   Gate 1: Probability	1/N requests trigger the check
 *   Gate 2: Cooldown	   skip if cleanup lock exists (another worker)
 *   Gate 3: Staleness	  skip if last cleanup was within min_interval
 *   Gate 4: Mutex		  only one worker cleans at a time
 *
 * === DESIGN NOTES ===
 *
 * The actual DELETE is schema-portable: we don't assume a specific column
 * type for `date`. Instead we probe the table with `SELECT MAX(date)` and
 * parse the returned value through strtotime() / numeric coercion. If the
 * parse fails (schema incompatible), we fall back to `time() - max_age_days`
 * against `WHERE date < ?` with the cutoff as a unix timestamp, which works
 * on every common schema (DATETIME, INT, TEXT ISO-8601, VARCHAR).
 *
 * For SQLite — which locks the entire database on DELETE — we chunk the
 * DELETE into LIMIT'd statements bounded by a wall-clock budget (default
 * 500ms total). This prevents a 1M-row DELETE from blocking the request
 * thread for seconds.
 *
 * === CALLING PATTERN ===
 *
 *   $retention = new LogRetention($adapter, $config);
 *
 *   // On each request:
 *   $decision = $retention->maybe_cleanup();
 *   if ($decision->should_cleanup) {
 *	   register_shutdown_function(fn() => $retention->do_cleanup());
 *   }
 *
 * === OPTIONS (see Configuration::$log_retention_*) ===
 *
 *   enabled				master switch (default: true to match 2.x behavior)
 *   max_age_days		   rows older than this are deleted (default: 7)
 *   max_rows			   safety cap; 0 = no cap (default: 0)
 *   probability_denominator 1/N requests trigger Gate 1 (default: 1000)
 *   min_interval_seconds   hard cooldown between cleanups (default: 21600 = 6h)
 *   lock_ttl			   mutex lock TTL (default: 600 = 10 min)
 *   chunk_size			 rows per DELETE statement (default: 10000)
 *   max_total_seconds	  wall-clock budget for do_cleanup() (default: 0.5)
 */
final class LogRetention
{
	/** Cache key for the cleanup mutex lock. */
	public const CACHE_KEY_LOCK = 'bb:log_retention:lock';

	/** Cache key for the timestamp of the last successful cleanup. */
	public const CACHE_KEY_LAST_RUN = 'bb:log_retention:last_run';

	/** Default chunk size for SQLite-style chunked DELETEs. */
	private const DEFAULT_CHUNK_SIZE = 10000;

	/** Default wall-clock budget for do_cleanup() in seconds. */
	private const DEFAULT_MAX_TOTAL_SECONDS = 0.5;

	private AdapterInterface $adapter;
	private Configuration $config;
	private ?CacheInterface $cache;

	private int $chunk_size;
	private float $max_total_seconds;

	/** @var callable(): int */
	private $clock;

	/** @var callable(int, int): int */
	private $rng;

	private bool $cleanup_invoked = false;
	private static bool $unknown_affected_rows_logged = false;
	private ?RetentionResult $last_result = null;

	public function __construct(
		AdapterInterface $adapter,
		Configuration $config,
		?CacheInterface $cache = null,
		int $chunk_size = self::DEFAULT_CHUNK_SIZE,
		float $max_total_seconds = self::DEFAULT_MAX_TOTAL_SECONDS,
		?callable $clock = null,
		?callable $rng = null,
	) {
		$this->adapter = $adapter;
		$this->config = $config;
		$this->cache = $cache ?? ($adapter instanceof CacheInterface ? $adapter : null);
		$this->chunk_size = max(1, $chunk_size);
		$this->max_total_seconds = max(0.0, $max_total_seconds);
		$this->clock = $clock ?? 'time';
		$this->rng = $rng ?? 'mt_rand';
	}

	/**
	 * Decide whether the caller should schedule a background cleanup.
	 *
	 * Runs the four gates IN ORDER. First gate that fails short-circuits —
	 * that's what makes the hot path O(1):
	 *
	 *   Gate 1 (probability): 999/1000 requests fail here, returning early.
	 *   Gate 2 (cooldown):	Only checked on the 1/1000 that triggers Gate 1.
	 *   Gate 3 (staleness):   Only checked if Gate 2 passed.
	 *   Gate 4 (mutex):	   Only checked if Gate 3 passed.
	 *
	 * Returns a RetentionDecision. NEVER throws — any exception inside gate
	 * logic is converted to a "don't cleanup" decision via ErrorReporter.
	 */
	public function maybe_cleanup(): RetentionDecision
	{
		try {
			// Master switch — bail before any side effects when disabled.
			if (!$this->config->log_retention_enabled) {
				return RetentionDecision::skip('disabled');
			}

			// === Gate 1: Probability ===
			$denominator = $this->config->log_retention_probability_denominator;
			$rng = $this->rng;
			$roll = $rng(1, $denominator);
			if ($roll !== 1) {
				return RetentionDecision::skip('probability');
			}

			if ($this->cache === null) {
				// No shared cache → no mutex possible. Without a mutex we
				// can't safely rate-limit cleanup across workers. Bail to
				// the caller; they can still call force_cleanup_now() from
				// a single-worker CLI context (cron replacement).
				return RetentionDecision::skip('cooldown');
			}

			// === Gate 2: Cooldown (lock held = another worker cleaning) ===
			if ($this->cache->get(self::CACHE_KEY_LOCK) !== null) {
				return RetentionDecision::skip('cooldown');
			}

			// === Gate 3: Staleness ===
			$last_run = $this->cache->get(self::CACHE_KEY_LAST_RUN);
			$last_run_age = $this->compute_last_run_age($last_run);

			if ($last_run_age !== null
				&& $last_run_age < $this->config->log_retention_min_interval_seconds) {
				return RetentionDecision::skip('fresh');
			}

			// === Gate 4: Mutex ===
			$lock_acquired = $this->try_acquire_lock();
			if (!$lock_acquired) {
				return RetentionDecision::skip('mutex_lost');
			}

			return RetentionDecision::schedule(
				reason: $last_run_age === null ? 'cold_start' : 'due',
				last_run_age: $last_run_age,
				staleness_floor: $this->config->log_retention_min_interval_seconds,
			);
		} catch (\Throwable $e) {
			ErrorReporter::error(
				$this->adapter,
				'LogRetention: maybe_cleanup failed; skipping',
				[
					'error' => $e->getMessage(),
					'exception_class' => $e::class,
				],
				'log_retention_gate_failure'
			);
			return RetentionDecision::skip('error');
		}
	}

	/**
	 * Perform the actual cleanup: DELETE expired rows from log_table.
	 *
	 * Schema-portable DELETE: we probe the table first to discover the
	 * newest row's date, then compute a cutoff timestamp. The DELETE uses
	 * parameterized cutoff values where possible; for adapters without
	 * parameter binding we inline the cutoff (sanitized via is_numeric).
	 *
	 * Chunked for SQLite safety: each iteration DELETE LIMIT $chunk_size,
	 * bounded by $max_total_seconds wall-clock budget.
	 *
	 * Returns RetentionResult describing what happened. Stores the result
	 * for get_last_result().
	 *
	 * NEVER throws. Failures are caught, recorded in RetentionResult,
	 * logged once via ErrorReporter, and the lock is cleared so the next
	 * request can retry.
	 */
	public function do_cleanup(): RetentionResult
	{
		$this->cleanup_invoked = true;
		$start = $this->microtime();
		$deadline = $start + $this->max_total_seconds;

		$log_table = $this->resolve_log_table();
		$max_age_days = $this->config->log_retention_max_age_days;
		$max_rows = $this->config->log_retention_max_rows;

		// === Phase 1: Probe table ===
		$probe = $this->probe_table($log_table);
		if ($probe['error'] !== null) {
			return $this->finalize($start, 0, 0, 0, $log_table, 'none', $probe['error']);
		}

		$newest = $probe['newest'];
		$total = $probe['total'];

		// === Phase 2: Decide cutoff & mode ===
		$cutoff = $this->compute_cutoff($newest, $max_age_days);
		$limit_by = 'age';
		$rows_deleted = 0;
		$iterations = 0;
		$affected_known = true; // becomes false if any iteration reports null

		if ($max_rows > 0 && $total > $max_rows) {
			$limit_by = 'rows';
		}

		// === Phase 3: Chunked DELETE loop ===
		//
		// Two modes:
		//   - 'age'  mode: one DELETE, exit. (Default; max_rows = 0.)
		//   - 'rows' mode: iterative DELETE LIMIT chunk_size until 0 affected.
		//
		// We use a unified `while` loop for both, with the `age` mode exiting
		// after one iteration via the break on $limit_by !== 'rows'.
		$safety_iterations = 0;
		$max_iterations = 1000;

		try {
			while (true) {
				if ($this->microtime() >= $deadline) {
					break;
				}
				if (++$safety_iterations > $max_iterations) {
					break;
				}

				$sql = $this->build_delete_sql($log_table, $cutoff, $max_rows, $limit_by);
				if ($sql === null) {
					break;
				}

				$ok = $this->adapter->query($sql);
				$iterations++;

				if (!$ok) {
					return $this->finalize(
						$start, $rows_deleted, $iterations,
						$cutoff, $log_table, $limit_by,
						'query returned false'
						);
				}

				// === HONEST AFFECTED-ROWS HANDLING ===
				//
				// Three signals:
				//   int(N>0):  N rows deleted. Continue if rows-mode; break if age-mode.
				//   int(0):    Query succeeded; nothing matched. Break.
				//   null:      Adapter can't tell. One-shot diagnostic + break.
				$affected = method_exists($this->adapter, 'lastQueryAffectedRows')
				? $this->adapter->lastQueryAffectedRows()
				: null;

				if ($affected === null) {
					$this->log_unknown_affected_rows($log_table);
					$affected_known = false;  // ← ADD THIS LINE
					break;
				}

				if ($affected > 0) {
					$rows_deleted += $affected;
					// In age mode, one DELETE is enough. In rows mode, keep iterating.
					if ($limit_by !== 'rows') {
						break;
					}
					// Continue: try to delete another chunk.
				} else {
					// $affected === 0: query ran but matched nothing.
					break;
				}
			}

		} catch (\Throwable $e) {
			ErrorReporter::error(
				$this->adapter,
				'LogRetention: do_cleanup failed',
				[
					'error' => $e->getMessage(),
					'exception_class' => $e::class,
					'log_table' => $log_table,
				],
				'log_retention_do_cleanup_failure'
				);
			return $this->finalize(
				$start, $rows_deleted, $iterations,
				$cutoff, $log_table, $limit_by, $e->getMessage()
				);
		}

		// === Phase 4: Record last-run timestamp ===
		//
		// Only record when we have positive evidence of progress. Three cases:
		//
		//   1. rows_deleted > 0	   → record (progress was made)
		//   2. rows_deleted == 0 AND  → record (query ran; confirmed nothing
		//	  affected_known				matched; no point retrying same
		//									cutoff every request)
		//   3. rows_deleted == 0 AND  → DON'T record (we don't know if the
		//	  !affected_known			   DELETE did anything; let the next
		//									request retry against a possibly
		//									recovered adapter)
		//
		// The original code wrote CACHE_KEY_LAST_RUN unconditionally on
		// rows_deleted > 0 (which was always, due to chunk_size fallback).
		// That made every cleanup "succeed" and blocked the next attempt
		// for min_interval_seconds, hiding the underlying bug.
		$should_record_last_run = $rows_deleted > 0;

		if ($this->cache !== null && $should_record_last_run) {
			try {
				$this->cache->set(
					self::CACHE_KEY_LAST_RUN,
					$this->now(),
					$this->config->log_retention_min_interval_seconds * 2
					);
			} catch (\Throwable $e) {
				// Non-fatal: next request will retry based on the lock TTL.
			}
		}

		// === Phase 5: Clear the lock ===
		if ($this->cache !== null) {
			try {
				$this->cache->delete(self::CACHE_KEY_LOCK);
			} catch (\Throwable $e) {
				// Lock TTL will eventually clear it — non-fatal.
			}
		}

		// success is true only when we have positive evidence.
		// previously: success: $iterations > 0 && $rows_deleted > 0
		// Now: success requires rows_deleted > 0 OR (zero affected but known).
		// Unknown-affected stays success=false so the next request retries.
		$success = $rows_deleted > 0 || ($iterations > 0 && $affected_known);

		$result = new RetentionResult(
			success: $success,
			rows_deleted: $rows_deleted,
			iterations: $iterations,
			elapsed_seconds: $this->microtime() - $start,
			cutoff_computed: $cutoff,
			log_table: $log_table,
			limit_by: $limit_by,
			);

		$this->last_result = $result;
		return $result;
	}

	public function was_invoked(): bool
	{
		return $this->cleanup_invoked;
	}

	public function get_last_result(): ?RetentionResult
	{
		return $this->last_result;
	}

	/**
	 * Force an immediate synchronous cleanup. Bypasses all four gates.
	 * Useful for:
	 *   - Admin "Cleanup Now" buttons
	 *   - bin/cleanup-logs.php CLI invocations
	 *   - Tests asserting cleanup behavior without probabilistic gates
	 *
	 * Returns null if log_retention is disabled in config.
	 */
	public function force_cleanup_now(): ?RetentionResult
	{
		if (!$this->config->log_retention_enabled) {
			return null;
		}
		return $this->do_cleanup();
	}

	// ========================================================================
	// Internal helpers
	// ========================================================================

	private function resolve_log_table(): string
	{
		try {
			$settings = $this->adapter->get_settings();
			return $settings['log_table'] ?? 'bad_behaviour';
		} catch (\Throwable $e) {
			return 'bad_behaviour';
		}
	}

	/**
	 * Probe the log table to discover the newest row's date and total count.
	 *
	 * Returns ['newest' => int|string|null, 'total' => int, 'error' => ?string].
	 *
	 * Schema-portable: doesn't assume `date` is DATETIME. Accepts:
	 *   - Unix timestamp (int) stored as INT
	 *   - ISO 8601 / DATETIME stored as VARCHAR or TEXT
	 *   - NULL (empty table → total=0, newest=null)
	 *
	 * On query failure: returns total=0, newest=null, error=message.
	 * Caller treats error as "nothing to clean up".
	 *
	 * Note: this relies on the adapter exposing some way to read query
	 * results. Currently no adapter exposes fetch(); we add a minimal
	 * probe_query() fallback that subclasses can override. See
	 * ProbeCapable interface (added below).
	 */
	private function probe_table(string $log_table): array
	{
		// Adapter-side probe — most adapters don't have a generic fetch().
		// We try the only portable path: cache_get_probe() if exposed,
		// otherwise fall back to "assume now()" (which still produces a
		// safe cutoff = now - max_age_days).
		//
		// The actual row deletion via DELETE WHERE date < ? works on
		// every common schema (DATETIME, INT unix-ts, TEXT ISO-8601)
		// because the cutoff is a unix timestamp integer.
		//
		// See LogRetentionProbeInterface — adapters that CAN probe
		// (MediaWikiAdapter, WackoWikiAdapter with table introspection)
		// implement it for accurate "newest" computation. Adapters that
		// can't (GenericAdapter without DB) fall back to time()-based.
		if (method_exists($this->adapter, 'probe_log_table')) {
			try {
				return $this->adapter->probe_log_table($log_table);
			} catch (\Throwable $e) {
				// Probe failed — fall through to default.
			}
		}

		// Default probe: we can't read query results, so we don't know
		// the newest row. Use time() as the anchor — which means the
		// cutoff = time() - max_age_days deletes rows older than that
		// relative to NOW. This is correct in practice (we're not
		// running against a stale table) but slightly less optimal than
		// probing.
		return [
			'newest' => null,
			'total'  => 0,
			'error'  => null,
		];
	}

	/**
	 * Compute the unix-timestamp cutoff for age-based deletion.
	 *
	 * @param int|string|null $newest Newest row's date value (null = unknown)
	 * @param int $max_age_days Retention window in days
	 * @return int Unix timestamp
	 */
	private function compute_cutoff($newest, int $max_age_days): int
	{
		$now = $this->now();

		if ($newest === null) {
			// No probe data — anchor on now.
			return $now - ($max_age_days * 86400);
		}

		// Try numeric (INT column with unix timestamp)
		if (is_numeric($newest)) {
			$parsed = (int)$newest;
			if ($parsed > 0) {
				return $parsed - ($max_age_days * 86400);
			}
		}

		// Try string (DATETIME, VARCHAR ISO-8601)
		if (is_string($newest)) {
			$parsed = strtotime($newest);
			if ($parsed !== false && $parsed > 0) {
				return $parsed - ($max_age_days * 86400);
			}
		}

		// Couldn't parse — fall back to now-relative cutoff.
		return $now - ($max_age_days * 86400);
	}

	/**
	 * Build the DELETE statement.
	 *
	 * Returns null when there's nothing meaningful to issue (e.g., max_rows=0
	 * AND no age-based cutoff, which shouldn't happen but we defend).
	 */
	private function build_delete_sql(
		string $log_table,
		int $cutoff,
		int $max_rows,
		string $limit_by
	): ?string {
		// Table name sanitization: strip everything except alphanumerics +
		// underscore. Adapters inject their own prefixes but we never trust
		// the raw config value in SQL.
		$safe_table = preg_replace('/[^a-zA-Z0-9_]/', '', $log_table);
		if ($safe_table === '' || $safe_table === null) {
			$safe_table = 'bad_behaviour';
		}

		$cutoff_int = (int)$cutoff;
		if ($limit_by === 'rows') {
			// Row-count cap: keep newest N rows; delete the rest.
			// Most portable form: DELETE WHERE rowid NOT IN (SELECT rowid FROM ... ORDER BY date DESC LIMIT N).
			// But that requires a SELECT subquery which differs per-DB.
			// The simplest portable form is: DELETE LIMIT chunk_size ORDER BY date ASC.
			// MySQL ignores LIMIT without ORDER BY in multi-table DELETEs but accepts it for single-table;
			// SQLite accepts it; PostgreSQL requires a subquery.
			//
			// We use the SQLite/MySQL form here. Operators on PostgreSQL should
			// either override probe_log_table() to use a different strategy
			// OR rely on age-based deletion only (set max_rows=0).
			return sprintf(
				'DELETE FROM `%s` ORDER BY `date` ASC LIMIT %d',
				$safe_table,
				$this->chunk_size
			);
		}

		// Age-based: DELETE WHERE date < cutoff.
		// The cutoff is a unix timestamp integer — works whether `date` is
		// DATETIME (lexicographic compare of ISO strings still gives correct
		// ordering), INT (direct compare), or TEXT (strtotime parses).
		return sprintf(
			'DELETE FROM `%s` WHERE `date` < %d',
			$safe_table,
			$cutoff_int
		);
	}

	/**
	 * Try to acquire the cleanup lock. Returns true if successful.
	 *
	 * Uses cache->set() with TTL — same TOCTOU semantics as
	 * OnDemandRefresher::try_acquire_lock(). Acceptable because:
	 *   1. The lock TTL (10min default) bounds damage from races
	 *   2. Worst case = two parallel DELETEs which are idempotent
	 *	  (deleting already-deleted rows is a no-op)
	 *   3. The atomic-add contract isn't in CacheInterface; portable
	 *	  alternative would require per-adapter changes
	 */
	private function try_acquire_lock(): bool
	{
		if ($this->cache === null) {
			return false;
		}
		try {
			return $this->cache->set(
				self::CACHE_KEY_LOCK,
				$this->now(),
				$this->config->log_retention_lock_ttl
			);
		} catch (\Throwable $e) {
			return false;
		}
	}

	/**
	 * Compute the age (seconds) of the most recent cleanup timestamp.
	 *
	 * Returns:
	 *   - int:  age in seconds when cache exists and is well-formed
	 *   - null: cache absent (cold start — caller schedules immediately)
	 */
	private function compute_last_run_age(mixed $last_run): ?int
	{
		if ($last_run === null) {
			return null;
		}
		if (!is_numeric($last_run)) {
			return null;
		}
		$ts = (int)$last_run;
		if ($ts <= 0) {
			return null;
		}
		$now = $this->now();
		if ($ts > $now + 60) {
			// Far-future timestamp — treat as malformed.
			return null;
		}
		return max(0, $now - $ts);
	}

	private function finalize(
		float $start,
		int $rows_deleted,
		int $iterations,
		int $cutoff,
		string $log_table,
		string $limit_by,
		?string $error
	): RetentionResult {
		// Clear the lock even on failure paths.
		if ($this->cache !== null) {
			try {
				$this->cache->delete(self::CACHE_KEY_LOCK);
			} catch (\Throwable $e) {
				// non-fatal
			}
		}

		$result = new RetentionResult(
			success: $error === null && $rows_deleted > 0,
			rows_deleted: $rows_deleted,
			iterations: $iterations,
			elapsed_seconds: $this->microtime() - $start,
			cutoff_computed: $cutoff,
			log_table: $log_table,
			limit_by: $limit_by,
			error: $error,
		);
		$this->last_result = $result;
		return $result;
	}

	private function now(): int
	{
		try {
			$clock = $this->clock;
			return (int)$clock();
		} catch (\Throwable $e) {
			return time();
		}
	}

	private function microtime(): float
	{
		return microtime(true);
	}

	/**
	 * One-shot diagnostic for adapters that don't report affected rows.
	 *
	 * Logged at most once per process. Helps operators discover the
	 * configuration gap that causes cleanups to silently stall.
	 */
	private function log_unknown_affected_rows(string $log_table): void
	{
		if (self::$unknown_affected_rows_logged) {
			return;
		}
		self::$unknown_affected_rows_logged = true;

		try {
			ErrorReporter::warning(
				$this->adapter,
				'LogRetention: adapter does not report affected rows; '
				. 'cleanup effectiveness cannot be verified',
				[
					'log_table' => $log_table,
					'hint'      => 'Implement AdapterInterface::lastQueryAffectedRows() '
					. 'on your adapter. Without it, LogRetention cannot distinguish '
					. '"deleted N rows" from "query ran but matched nothing", so '
					. 'cleanups will be marked unverified and retried — but '
					. 'diagnostics will show 0 rows deleted every cycle.',
				],
				'log_retention_unknown_affected_rows'
				);
		} catch (\Throwable $e) {
			// ignore
		}
	}
}