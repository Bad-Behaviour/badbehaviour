<?php

declare(strict_types=1);

namespace BadBehaviour\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\ErrorReporter;

/**
 * On-Demand IP Range Refresh ("Web Cron")
 *
 * === PROBLEM ===
 *
 * IP ranges from cloud providers (Cloudflare, AWS, GCP, Fastly) and bot
 * operators (OpenAI, Anthropic, Apple, etc.) drift over time. The previous
 * design required `bin/update-ip-ranges.php` to run via cron — which fails
 * silently on shared hosting, PaaS deployments, and containerized apps
 * without scheduled-job support.
 *
 * === SOLUTION ===
 *
 * This class implements **opportunistic refresh**: on a fraction of
 * requests (default 1/1000), check whether the cached merged ranges are
 * stale; if so, fetch fresh from upstream feeds in the background
 * (after the response has been sent to the client) and atomically swap
 * the cache.
 *
 * === DESIGN: FOUR-GATE STALE REFRESH ===
 *
 *   Gate 1: Probability gate    — 1/N requests trigger the check at all
 *   Gate 2: Cooldown gate       — skip if we recently triggered
 *   Gate 3: Staleness gate      — skip if cached data is fresh enough
 *   Gate 4: Mutex gate          — only one worker fetches at a time
 *
 * Probability × cooldown × staleness × mutex together guarantee:
 *   - At most one refresh per `min_age_seconds` (typically 6 hours)
 *   - At most one concurrent refresh across all workers on a shared cache
 *   - At most ~6 checks/hour per worker at default settings
 *
 * === CALLING PATTERN ===
 *
 *   ```php
 *   $refresher = new OnDemandRefresher($cache, $registry, $cloud, $options);
 *
 *   // On each request:
 *   $decision = $refresher->maybe_refresh();
 *
 *   if ($decision->should_schedule) {
 *       // Caller decides when to flush / how to schedule.
 *       // Under PHP-FPM: fastcgi_finish_request() flushes the response,
 *       // then this closure runs after the client has disconnected.
 *       register_shutdown_function(function() use ($refresher) {
 *           $refresher->do_refresh();
 *       });
 *   }
 *   ```
 *
 * The class deliberately does NOT call register_shutdown_function itself
 * or assume FPM. The caller knows its deployment environment best.
 *
 * === FAILURE MODES ===
 *
 *   - Feed endpoints down → do_refresh() catches per-feed exceptions,
 *     logs once via ErrorReporter, returns false. Old cache remains.
 *
 *   - Cache backend full → log_write failure is non-fatal; lock cleared
 *     in finally-equivalent code so next request can try again.
 *
 *   - Worker crashes mid-refresh → cache lock has TTL (default 10 min);
 *     next worker that hits Gate 4 acquires it and retries.
 *
 *   - Multi-host deployment without shared cache → each host refreshes
 *     independently. With 1/1000 probability + 6h staleness floor,
 *     N hosts cost N×1 refresh per 6h ≈ trivial.
 *
 * === OPTIONS ===
 *
 *   - 'probability_denominator' (int, default 1000)
 *       1 in N requests triggers the staleness check. Higher = less
 *       frequent checks = less load on feed endpoints. At 100 req/min
 *       with denominator=1000: ~6 checks/hour per worker.
 *
 *   - 'min_age_seconds' (int, default 21600 = 6h)
 *       Hard floor on refresh frequency. Even if every request hits
 *       the probability gate, refresh won't fire more often than this.
 *
 *   - 'lock_ttl' (int, default 600 = 10 min)
 *       Cache lock TTL. Functions as both:
 *         (a) mutex across processes/hosts (only one worker fetches)
 *         (b) cooldown (don't re-check within this window)
 *
 *   - 'cache_ttl' (int, default 604800 = 7 days)
 *       TTL of the refreshed cache entry. Acts as "stale tolerance" —
 *       if feeds are unreachable for up to 7 days, the old ranges
 *       are still served (better than nothing).
 *
 *   - 'feed_timeout_seconds' (int, default 5)
 *       Hard wall-clock budget for the entire refresh. Protects against
 *       a misbehaving feed hanging the shutdown handler indefinitely.
 *
 *   - 'bot_ids' (string[], default null)
 *       Restrict refresh to specific bot IDs (e.g., ['googlebot', 'gptbot']).
 *       Null = all bots in the registry.
 *
 *   - 'cloud_providers' (string[], default null)
 *       Restrict refresh to specific cloud providers
 *       (e.g., ['cloudflare', 'aws']). Null = all four defaults.
 *
 * === THREAD SAFETY ===
 *
 * Not thread-safe in the strict sense — `do_refresh()` mutates the
 * `$refresh_invoked` flag on the instance. But because the cache lock
 * coordinates cross-process work and the class is instantiated per
 * request, the only concern is within a single request (where PHP's
 * single-threaded model applies).
 */
final class OnDemandRefresher
{
    /**
     * Cache key for the merged ranges payload.
     *
     * This is the SAME key the rest of BadBehaviour reads from
     * (BotDetector::get_dynamic_ranges() reads 'bb:ip_ranges:merged').
     * Keeping one key means refresh results are immediately visible
     * to the bot detector on the NEXT request after the swap.
     */
    public const CACHE_KEY_MERGED = 'bb:ip_ranges:merged';

    /**
     * Cache key for the refresh lock.
     *
     * Used for both mutex (one worker at a time) and cooldown
     * (don't re-trigger within lock_ttl).
     */
    public const CACHE_KEY_LOCK = 'bb:on_demand_refresh:lock';

    /**
     * Default options — overridable via constructor.
     *
     * @var array<string, mixed>
     */
    public const DEFAULTS = [
        'probability_denominator' => 1000,
        'min_age_seconds'         => 21600,    // 6 hours
        'lock_ttl'                => 600,      // 10 minutes
        'cache_ttl'               => 604800,   // 7 days
        'feed_timeout_seconds'    => 5,
        'bot_ids'                 => null,
        'cloud_providers'         => null,
    ];

    private CacheInterface $cache;
    private FeedProviderInterface $registry;
    private CloudIpRangeProvider $cloud;

    /** @var array<string, mixed> */
    private array $options;

    /**
     * Time provider: () => int (Unix timestamp).
     *
     * Injected for testability; defaults to PHP's time() in production.
     *
     * @var callable(): int
     */
    private $clock;

    /**
     * RNG provider: (int $min, int $max) => int.
     *
     * Injected for testability; defaults to mt_rand() in production.
     *
     * @var callable(int, int): int
     */
    private $rng;

    /**
     * Set to true after do_refresh() has been invoked at least once
     * on this instance. Used by tests to assert that scheduling fired.
     */
    private bool $refresh_invoked = false;

    /**
     * Result of the last do_refresh() call. Used by tests and by the
     * caller to inspect refresh metrics (CIDR count, elapsed time,
     * per-feed success/failure).
     */
    private ?RefreshResult $last_result = null;

    /**
     * @param CacheInterface $cache Shared cache for lock + data + cooldown.
     *        For multi-host deployments, MUST be a shared backend (Redis,
     *        Memcached, DB). File cache gives per-host mutex only.
     *
     * @param FeedProviderInterface $registry The feed registry to refresh from.
     *        Bot-specific feeds (Google, OpenAI, etc.).
     *
     * @param CloudIpRangeProvider $cloud Cloud-provider range feeds
     *        (AWS, Cloudflare, Fastly, GCP).
     *
     * @param array<string, mixed> $options See DEFAULTS for keys.
     *
     * @param (callable(): int)|null $clock Override time() for tests.
     * @param (callable(int, int): int)|null $rng Override mt_rand() for tests.
     */
    public function __construct(
        CacheInterface $cache,
        FeedProviderInterface $registry,
        CloudIpRangeProvider $cloud,
        array $options = [],
        ?callable $clock = null,
        ?callable $rng = null,
    ) {
        $this->cache    = $cache;
        $this->registry = $registry;
        $this->cloud    = $cloud;

        $this->options = array_merge(self::DEFAULTS, $options);

        // Validate option types — fail loudly on bad input rather than
        // silently doing the wrong thing later.
        //
        // Most numeric options are int-only: counts (probability_denominator)
        // and durations expressed as whole seconds (min_age_seconds, lock_ttl,
        // cache_ttl). Fractional values like "1.5 requests" or "0.5 seconds
        // of staleness floor" are nonsensical.
        foreach (['probability_denominator', 'min_age_seconds', 'lock_ttl',
        	'cache_ttl'] as $key) {
        	if (!is_int($this->options[$key]) || $this->options[$key] < 0) {
        		throw new \InvalidArgumentException(
        			"OnDemandRefresher: '{$key}' must be a non-negative int, got "
        			. get_debug_type($this->options[$key])
        		);
        	}
        }
        if ($this->options['probability_denominator'] === 0) {
        	throw new \InvalidArgumentException(
        		"OnDemandRefresher: 'probability_denominator' must be > 0"
        		);
        }

        // feed_timeout_seconds accepts int|float — operators may want
        // sub-second precision for fast paths (e.g., 0.5) or finer-grained
        // budgets (e.g., 1.5, 2.5). Internally compared as float against
        // microtime() output, so the float type is preserved end-to-end.
        $timeout = $this->options['feed_timeout_seconds'];
        if (!is_int($timeout) && !is_float($timeout)) {
        	throw new \InvalidArgumentException(
        		"OnDemandRefresher: 'feed_timeout_seconds' must be int or float, got "
        		. get_debug_type($timeout)
        		);
        }
        if ($timeout < 0) {
        	throw new \InvalidArgumentException(
        		"OnDemandRefresher: 'feed_timeout_seconds' must be non-negative, got {$timeout}"
        	);
        }

        foreach (['bot_ids', 'cloud_providers'] as $key) {
            $val = $this->options[$key];
            if ($val !== null && !is_array($val)) {
                throw new \InvalidArgumentException(
                    "OnDemandRefresher: '{$key}' must be null or array, got "
                    . get_debug_type($val)
                );
            }
        }

        $this->clock = $clock ?? 'time';
        $this->rng   = $rng   ?? 'mt_rand';
    }

    /**
     * Decide whether the caller should schedule a background refresh.
     *
     * Runs the four gates IN ORDER. The first gate that fails short-circuits
     * — that's what makes this O(1) on the hot path:
     *
     *   - 999/1000 requests fail at Gate 1 (probability) → return early
     *   - 0/1000 requests fail at Gate 2 (cooldown) → only check when triggered
     *   - 0/1000 requests fail at Gate 3 (staleness) → only check when stale
     *   - rare requests fail at Gate 4 (mutex held by other worker) → skip
     *
     * Returns a RefreshDecision describing what (if anything) to do.
     * The caller SHOULD schedule do_refresh() when decision->should_schedule
     * is true — but does NOT have to; for example, a worker running
     * shutdown_function with limited budget might skip the refresh.
     *
     * NEVER throws. All exceptions inside gate logic are caught and
     * converted to "don't refresh" decisions.
     */
    public function maybe_refresh(): RefreshDecision
    {
        try {
            // === Gate 1: Probability ===
            //
            // Cheap CPU-only check. Fails 999/1000 times, returning early
            // without touching the cache. This is what makes the hot path
            // fast — most requests don't even reach the cache.
            $denominator = $this->options['probability_denominator'];
            $rng = $this->rng;
            $roll = $rng(1, $denominator);
            if ($roll !== 1) {
                return RefreshDecision::skip('probability');
            }

            // === Gate 2: Cooldown ===
            //
            // Cache lock doubles as cooldown. If the lock exists, another
            // worker (or we ourselves, recently) triggered a refresh.
            // No point checking again until the lock expires.
            if ($this->cache->get(self::CACHE_KEY_LOCK) !== null) {
                return RefreshDecision::skip('cooldown');
            }

            // === Gate 3: Staleness ===
            //
            // Read the current merged cache. If fresh enough, skip.
            // If absent entirely (cold start / cache evicted), treat as
            // stale so we warm up ASAP — this is the recovery path for
            // a cache-backend eviction or fresh install.
            $cached = $this->cache->get(self::CACHE_KEY_MERGED);
            $age = $this->compute_cache_age($cached);

            if ($age !== null && $age < $this->options['min_age_seconds']) {
                return RefreshDecision::skip('fresh');
            }

            // === Gate 4: Mutex ===
            //
            // Set the lock BEFORE returning so concurrent requests see
            // Gate 2 fail. The actual fetch happens later (in
            // do_refresh()). The lock TTL is long enough to cover the
            // worst-case feed fetch (4 feeds × 5s timeout = 20s +
            // headroom → 10min is comfortable).
            $lock_acquired = $this->try_acquire_lock();
            if (!$lock_acquired) {
                return RefreshDecision::skip('mutex_lost');
            }

            return RefreshDecision::schedule(
                reason: $age === null ? 'cold_start' : 'stale',
                cache_age: $age,
                staleness_floor: $this->options['min_age_seconds'],
            );
        } catch (\Throwable $e) {
            // Any unexpected error → don't refresh. Better to skip than
            // to corrupt the cache or panic the request.
            ErrorReporter::error(
                null,
                'OnDemandRefresher: maybe_refresh failed; skipping',
                [
                    'error' => $e->getMessage(),
                    'exception_class' => $e::class,
                ],
                'on_demand_refresh_gate_failure'
            );
            return RefreshDecision::skip('error');
        }
    }

    /**
     * Perform the actual refresh: fetch all feeds, merge, write to cache.
     *
     * This is the slow part (network I/O). It SHOULD run after the HTTP
     * response has been sent — the caller is responsible for scheduling
     * it appropriately (register_shutdown_function, fastcgi_finish_request,
     * a queue worker, etc.).
     *
     * Returns a RefreshResult describing what happened. Caches the result
     * for tests via get_last_result().
     *
     * Defensive: NEVER throws. Failures inside feed fetches are caught
     * and recorded; the lock is cleared at the end so the next request
     * can try again.
     */
    public function do_refresh(): RefreshResult
    {
        $this->refresh_invoked = true;
        $start = $this->microtime();
        $deadline = $start + $this->options['feed_timeout_seconds'];

        $feed_status = [];
        $merged = [];
        $had_success = false;
        $had_failure = false;

        // === Phase 1: Bot-specific feeds (Google, OpenAI, Anthropic...) ===
        //
        // Run with a wall-clock budget so a single slow feed can't blow
        // out the whole shutdown handler.
        foreach ($this->registry->get_feeds() as $name => $feed) {
        	if ($this->microtime() >= $deadline) {
        		$feed_status[$name] = ['status' => 'skipped', 'reason' => 'budget_exhausted'];
        		continue;
        	}

        	try {
        		$data = $feed->fetch();
        		$feed_cidr_count = 0;
        		$feed_bot_count = 0;
        		foreach ($data as $bot_id => $cidrs) {
        			if (!$this->bot_id_allowed($bot_id)) {
        				continue;
        			}
        			$merged[$bot_id] = array_merge($merged[$bot_id] ?? [], $cidrs);
        			$feed_cidr_count += count($cidrs);
        			$feed_bot_count++;
        		}
        		$feed_status[$name] = [
        			'status'     => 'ok',
        			'bot_count'  => $feed_bot_count,
        			'cidr_count' => $feed_cidr_count,
        		];
        		$had_success = true;
        	} catch (\Throwable $e) {
        		$feed_status[$name] = [
        			'status' => 'error',
        			'error' => $e->getMessage(),
        			'exception_class' => $e::class,
        		];
        		$had_failure = true;
        		ErrorReporter::error(...);
        	}
        }

        // === Phase 2: Cloud provider ranges ===
        //
        // CloudIpRangeProvider::ranges() is cache-aware (it reads from
        // the same cache). We re-fetch each provider to refresh their
        // individual caches; the merged CIDRs go into the bot-specific
        // 'cloudflare_health', 'aws_elb_health', etc. entries.
        $providers = $this->options['cloud_providers']
            ?? ['aws', 'cloudflare', 'fastly', 'gcp'];

        foreach ($providers as $provider) {
            if ($this->microtime() >= $deadline) {
                $feed_status["cloud:{$provider}"] = ['status' => 'skipped', 'reason' => 'budget_exhausted'];
                continue;
            }

            try {
            	$cidrs = $this->cloud->ranges($provider);
            	$bot_id = $this->provider_to_bot_id($provider);
            	$bot_added = false;

            	if (!empty($cidrs) && $bot_id !== null && $this->bot_id_allowed($bot_id)) {
            		$merged[$bot_id] = array_merge(
            			$merged[$bot_id] ?? [],
            			$cidrs
            			);
            		$bot_added = true;
            	}

            	$feed_status["cloud:{$provider}"] = [
            		'status'     => 'ok',
            		'bot_count'  => $bot_added ? 1 : 0,
            		'cidr_count' => count($cidrs),
            	];
            	$had_success = true;
            } catch (\Throwable $e) {
                $feed_status["cloud:{$provider}"] = [
                    'status' => 'error',
                    'error' => $e->getMessage(),
                    'exception_class' => $e::class,
                ];
                $had_failure = true;
                ErrorReporter::error(
                    null,
                    'OnDemandRefresher: cloud provider fetch failed',
                    [
                        'provider' => $provider,
                        'error' => $e->getMessage(),
                        'exception_class' => $e::class,
                    ],
                    'on_demand_refresh_cloud_' . $provider
                );
            }
        }

        // === Phase 3: Deduplicate + write to cache ===
        //
        // We dedup per-bot-id (so the same CIDR doesn't appear twice
        // if multiple feeds cover the same bot) but NOT cross-bot-id
        // (different bots genuinely have different ranges even if
        // some overlap). The shape matches what BotDetector's
        // get_dynamic_ranges() expects.
        $total_cidrs = 0;
        foreach ($merged as $bot_id => $cidrs) {
        	$merged[$bot_id] = array_values(array_unique($cidrs));
        	$total_cidrs += count($merged[$bot_id]);
        }

        $elapsed = $this->microtime() - $start;

        // Did we actually accumulate any data? This is the right gate for
        // cache writes — not "did at least one feed return without throwing"
        // (which would let cloud providers reporting empty arrays count as
        // success and overwrite a populated cache with an empty one).
        //
        // Cases that suppress the cache write:
        //   - All feeds threw (total failure)
        //   - All feeds returned empty arrays (no data to write)
        //   - Mix of errors and empties (nothing useful)
        //
        // In all those cases, leave the existing cache alone — better stale
        // data than fresh empty data.
        $got_data = !empty($merged) && $total_cidrs > 0;

        $wrote_cache = false;
        if ($got_data) {
        	$payload = [
        		'data' => $merged,
        		'fetched' => $this->now(),
        	];
        	try {
        		$wrote_cache = $this->cache->set(
        			self::CACHE_KEY_MERGED,
        			$payload,
        			$this->options['cache_ttl']
        			);
        	} catch (\Throwable $e) {
        		ErrorReporter::error(
        			null,
        			'OnDemandRefresher: cache write failed',
        			[
        				'error' => $e->getMessage(),
        				'exception_class' => $e::class,
        			],
        			'on_demand_refresh_cache_write'
        			);
        	}
        }

        // === Phase 4: Clear the lock ===
        //
        // Done unconditionally. The lock TTL would clear it eventually,
        // but explicit cleanup means the cooldown window doesn't apply
        // if the refresh finished quickly and there's still time left
        // in the budget.
        try {
        	$this->cache->delete(self::CACHE_KEY_LOCK);
        } catch (\Throwable $e) {
        	// Lock TTL will eventually clear it — non-fatal.
        }

        // Result classification:
        //   success = no failures AND we have data
        //   partial = some failures AND we have data
        //   neither = total failure (all errors) OR no-op (no errors, no data)
        $result = new RefreshResult(
        	success: !$had_failure && $got_data,
        	partial: $had_failure && $got_data,
        	bot_count: count($merged),
        	cidr_count: $total_cidrs,
        	elapsed_seconds: $elapsed,
        	cache_written: $wrote_cache,
        	feed_status: $feed_status,
        	started_at: $this->now() - (int)$elapsed,
        	finished_at: $this->now(),
        );

        $this->last_result = $result;

        // Top-level summary log — one log line per refresh regardless
        // of feed count. Success path emits info; pure-failure path
        // already emitted warnings via per-feed catches.
        if ($had_success) {
            ErrorReporter::error(
                null,
                'OnDemandRefresher: refresh completed',
                [
                    'bot_count'       => count($merged),
                    'cidr_count'      => $total_cidrs,
                    'elapsed_seconds' => round($elapsed, 3),
                    'cache_written'   => $wrote_cache,
                    'partial'         => $had_failure,
                ],
                'on_demand_refresh_summary_' . ($had_failure ? 'partial' : 'ok')
            );
        }

        return $result;
    }

    /**
     * Was do_refresh() invoked on this instance?
     *
     * Distinct from "did maybe_refresh() decide to schedule" — that
     * information is in the RefreshDecision returned by maybe_refresh().
     *
     * This method tells the caller whether the slow refresh path actually
     * ran (useful for tests asserting that scheduling led to execution).
     */
    public function was_refresh_invoked(): bool
    {
        return $this->refresh_invoked;
    }

    /**
     * Return the result of the most recent do_refresh() call.
     *
     * Null if do_refresh() has never been called on this instance.
     */
    public function get_last_result(): ?RefreshResult
    {
        return $this->last_result;
    }

    /**
     * Return the configured options (after defaults merge).
     *
     * @return array<string, mixed>
     */
    public function get_options(): array
    {
        return $this->options;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /**
     * Try to acquire the refresh lock. Returns true if successful.
     *
     * The lock is set with `lock_ttl` so it auto-expires if the worker
     * crashes mid-refresh. There's a brief TOCTOU window between the
     * Gate 2 check and this write — if two workers pass Gate 2 at the
     * exact same instant, both could try to acquire. The cache->set()
     * return value is checked, and the loser returns false (mutex_lost).
     *
     * We use `set()` not `add()` because the underlying CacheInterface
     * contract doesn't expose atomic add — a regular set with a TTL is
     * the best we can do portably. The TOCTOU window is small enough
     * (one network round-trip for cache->get) that in practice this is
     * a non-issue; worst case, two workers refresh concurrently and
     * the last writer wins on the merged cache.
     */
    private function try_acquire_lock(): bool
    {
        try {
            return $this->cache->set(
                self::CACHE_KEY_LOCK,
                $this->now(),
                $this->options['lock_ttl']
            );
        } catch (\Throwable $e) {
            // Cache write failure → can't safely refresh (other workers
            // wouldn't know we're holding the lock). Bail out.
            return false;
        }
    }

    /**
     * Compute the age (in seconds) of the merged cache payload.
     *
     * Returns:
     *   - int:  age in seconds when cache exists and is well-formed
     *   - 0:    cache exists but 'fetched' is missing, malformed, or
     *           far-future (treat as maximally stale — caller treats
     *           0 < min_age as 'fresh', so malformed cache values
     *           will NOT trigger refresh; this is documented behavior)
     *   - null: cache absent entirely (treat as cold-start — caller
     *           refreshes immediately)
     */
    private function compute_cache_age(mixed $cached): ?int
    {
        if ($cached === null) {
            return null;
        }
        if (!is_array($cached) || !isset($cached['fetched'])) {
            return 0;
        }
        $fetched = (int)$cached['fetched'];
        $now = $this->now();
        if ($fetched <= 0 || $fetched > $now + 60) {
            // Negative or far-future timestamp — treat as malformed.
            return 0;
        }
        return max(0, $now - $fetched);
    }

    /**
     * Filter bot IDs by the configured allow-list (if set).
     *
     * When 'bot_ids' is null, all bots are allowed. When set, only
     * bots whose ID appears in the list are merged. This is the
     * knob operators use to limit refresh scope (e.g., a high-traffic
     * site that only cares about Google + GPTBot + Claude refreshes).
     */
    private function bot_id_allowed(string $bot_id): bool
    {
        $allowed = $this->options['bot_ids'];
        if ($allowed === null) {
            return true;
        }
        return in_array($bot_id, $allowed, true);
    }

    /**
     * Map a cloud provider name to the BotDefinition id used in
     * DefaultRegistry (cloud_infrastructure category).
     *
     * Returns null when the provider has no matching bot — which is
     * fine: the data still gets fetched into the individual cache
     * slots (CloudIpRangeProvider handles its own caching) but won't
     * be merged into the bb:ip_ranges:merged payload. Operators with
     * a custom registry that doesn't include these bot IDs will see
     * no effect; that's expected and harmless.
     */
    private function provider_to_bot_id(string $provider): ?string
    {
        return match ($provider) {
            'aws'         => 'aws_elb_health',
            'cloudflare'  => 'cloudflare_health',
            'fastly'      => 'fastly_health',
            'gcp'         => 'google_cloud_health',
            default       => null,
        };
    }

    /**
     * Current Unix timestamp via the injected clock.
     *
     * Falls back to time() if the injected callable throws — defensive
     * against clock-provider bugs.
     */
    private function now(): int
    {
        try {
            $clock = $this->clock;
            return (int)$clock();
        } catch (\Throwable $e) {
            return time();
        }
    }

    /**
     * Monotonic-ish microsecond timestamp for elapsed-time measurement.
     *
     * Uses microtime(true) for sub-second precision. Not strict-monotonic
     * (NTP can move the clock backwards), but for the 5-second budget
     * this is acceptable — the absolute time matters less than the
     * "have we exceeded the budget" check.
     */
    private function microtime(): float
    {
        return microtime(true);
    }
}