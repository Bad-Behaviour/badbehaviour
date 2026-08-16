<?php
/**
 * BadBehaviour 3.0 — Configuration Reference
 *
 * Copy this file to config/bb_config.php and customize.
 * Any setting you omit will use the default (safe, FP-prevention baseline).
 *
 * ============================================================================
 * HOW TO USE
 * ============================================================================
 *
 *   1. The ONLY settings most operators need are at the top of this file:
 *        preset, strictness, logging, behind_proxy
 *   2. Everything else is documented below for fine-tuning
 *   3. You can omit this file entirely; defaults will be used
 *
 * ============================================================================
 * PRESETS
 * ============================================================================
 *
 *   minimal          ~30 most common bots. Default. Fastest matching.
 *   full             All ~100 shipped bots. Slower but most thorough.
 *   verified-only    Only bots with DNS verification or IP ranges.
 *   no-ai            Everything except AI crawlers.
 *   no-seo           Everything except SEO crawlers.
 *   eu-only          European search engines + EU-relevant bots.
 *   human-only       No bots recognized (combine with custom registry).
 *   custom           Only your custom bots from bb_registry.php.
 *
 * ============================================================================
 * STRICTNESS LEVELS
 * ============================================================================
 *
 *   monitor-only     Log everything, block only obvious attacks.
 *                    Use when: evaluating the library, or blocking real
 *                    users is worse than letting bots through.
 *
 *   normal           (Default) Sync DNS verification ON. Unverified
 *                    bots logged but NOT blocked. Rate limiting ON
 *                    with conservative thresholds. Experimental
 *                    detectors OFF.
 *
 *   strict           All detectors ON. Unverified AI blocked. Forward
 *                    DNS confirmation enabled. Tighter rate limits.
 *                    Use only when: actively seeing spoofing/scraping.
 *
 * ============================================================================
 * FALSE POSITIVE PHILOSOPHY
 * ============================================================================
 *
 * Every detection feature carries a tradeoff between catching bots and
 * blocking real users. The comments below describe what each setting
 * prevents AND what false-positive risk it introduces, so you can make
 * informed decisions about whether to deviate from defaults.
 */

return [

	// =========================================================================
	// PRIMARY — the only section most operators ever edit
	// =========================================================================

	/**
	 * Which bot registry to load.
	 *
	 * Tradeoff: bigger registries catch more bots but slow down matching.
	 *   - 'minimal': ~30 most common bots (Google, Bing, GPT, Claude,
	 *     Cloudflare, AWS, social link previewers, monitoring). Matches
	 *     in <1ms.
	 *   - 'full': all ~100 shipped bots including regional search engines
	 *     and lesser-known AI crawlers. Matches in ~3ms.
	 *
	 * Default: 'minimal'
	 */
	'preset'        => 'minimal',

	/**
	 * Bot-blocking posture.
	 *
	 * Tradeoff: stricter postures catch more attacks but block more
	 * legitimate users on first visit.
	 *   - 'monitor-only': log everything, block nothing ambiguous
	 *   - 'normal': log unverified, block only verified spoofers
	 *   - 'strict': block unverified aggressively, enable PTR spoof
	 *     detection
	 *
	 * Default: 'normal'
	 */
	'strictness'    => 'normal',

	/**
	 * Write requests to the bad_behaviour database table.
	 *
	 * What this prevents: nothing — it's for forensics.
	 * What it costs: one INSERT per blocked/challenged request.
	 *
	 * Set to false to disable logging entirely. The library still blocks
	 * but you have no visibility into what was blocked.
	 *
	 * Default: true
	 */
	'logging'       => true,

	/**
	 * Block POST submissions with Referer from a different origin.
	 *
	 * What this prevents: cross-site form submission abuse (comment spam,
	 * trackback spam).
	 * FP risk: bookmarks/external links that POST to your site, API
	 * clients that don't send Referer.
	 *
	 * Default: false
	 */
	'offsite_forms' => false,

	// =========================================================================
	// REVERSE PROXY — set true if behind Cloudflare, AWS, GCP, Fastly, etc.
	// =========================================================================

	/**
	 * Reverse proxy configuration.
	 *
	 * What this prevents: rate-limit/ban your CDN IPs instead of real
	 * client IPs (when behind a proxy).
	 * What it does: reads the real client IP from the configured header,
	 * trusting only requests from addresses in the trusted list.
	 *
	 * FP risk: misconfigured trusted_proxies allows IP spoofing via the
	 * forwarded header. Only list IPs you actually control.
	 *
	 * Default: disabled
	 */
	'reverse_proxy' => [
		'enabled'   => false,
		'header'    => 'X-Forwarded-For',  // or 'CF-Connecting-IP' for Cloudflare
		'addresses' => [],                 // CIDR list of trusted proxy IPs
	],

	// =========================================================================
	// BOT DETECTION — most operators should leave these alone
	// =========================================================================

	/**
	 * AI crawler configuration.
	 *
	 * What this prevents: AI training scrapers (GPTBot, ClaudeBot, etc.)
	 * from consuming your content for model training.
	 *
	 * FP risk: regional/academic AI crawlers may have unresolvable DNS
	 * initially and be incorrectly flagged as unverified.
	 *
	 *   - 'allowed': tokens (robots.txt identifiers) for AI bots you
	 *     want to allow regardless of verification status
	 *   - 'block_unverified': true blocks AI bots that can't pass DNS
	 *     verification (HIGH FP risk for first-visit regional crawlers)
	 *   - 'strict': true challenges ALL unverified AI bots
	 *
	 * Default: GPTBot/ClaudeBot/Google-Extended allowed, others logged
	 * but not blocked.
	 */
	'ai_crawlers' => [
		'allowed'         => [
			// OpenAI family
			'GPTBot', 'OAI-SearchBot', 'ChatGPT-User',
			// Anthropic family
			'ClaudeBot', 'Claude-User', 'Claude-SearchBot',
			// Google AI (user-controlled via Search Console)
			'Google-Extended',
			// Apple AI (only if you've opted into Apple Intelligence training)
			'Applebot-Extended',
			// Meta AI
			'Meta-ExternalAgent',
			// Amazon
			'Amazonbot',
			// Other major operators with verified identity
			'PerplexityBot', 'Perplexity-User',
			'GrokBot', 'Grok-User',
			'CohereBot',
		],
		'block_unverified'=> false,
		'strict'          => false,
	],

	/**
	 * Strict search engine mode.
	 *
	 * What this prevents: bots claiming to be Google/Bing/etc. but not
	 * passing DNS verification.
	 * FP risk: HIGH. Search engines occasionally change IP ranges before
	 * the static list is updated. Enabling this can drop your site from
	 * search results until ranges are refreshed.
	 *
	 * Only enable if you're seeing fake search engine crawlers.
	 *
	 * Default: false
	 */
	'strict_search_engines' => false,

	/**
	 * Bot categories to override with a specific action.
	 *
	 * Pin a category to a specific action regardless of its default
	 * category-specific logic. Evaluated in priority order (most severe
	 * action wins on collision):
	 *
	 *   blocked[]   >  challenge[]  >  log_only[]  >  allowed[]
	 *
	 * What this prevents: lets you customize bot handling without
	 * forking the library or writing custom_rules for every bot.
	 *   - 'blocked': hard block by category (replaces category-specific logic)
	 *   - 'challenge': force CAPTCHA on category (e.g., social scrapers)
	 *   - 'log_only': log but never block (e.g., security scanners)
	 *   - 'allowed': explicitly allow a category that would otherwise
	 *     be verified-only (e.g., feed readers, archives)
	 *
	 * FP risk: depends on category. 'residential_proxy' in blocked[] is
	 * safest; 'social_crawler' in blocked[] will block legitimate link
	 * previews from Facebook/Twitter/LinkedIn and break social sharing.
	 *
	 * SAFETY OVERRIDE: CLOUD_INFRASTRUCTURE is ALWAYS allowed (hard-coded
	 * in BotDetector). Even if you add it to blocked[], it cannot be moved.
	 * Blocking CDN/LB health probes takes your origin offline.
	 *
	 * Default: all four lists empty — operators opt in to overrides.
	 */
	'bot_categories' => [
		// Hard-block by category (replaces category-specific default)
		'blocked'   => [],   // e.g., ['residential_proxy', 'malicious']

		// Force CAPTCHA on category
		'challenge' => [],   // e.g., ['social_crawler']

		// Log but never block
		'log_only'  => [],   // e.g., ['security_scanner']

		// Allow verified-by-default categories
		'allowed'   => [],   // e.g., ['feed_reader', 'archive_crawler']
	],

	// =========================================================================
	// RATE LIMITING
	// =========================================================================

	/**
	 * Rate limit configuration.
	 *
	 * What this prevents: volumetric scraping, credential stuffing,
	 * comment spam floods.
	 *
	 * FP risk: shared NAT IPs (corporate networks, mobile carriers, VPN
	 * exit nodes) can legitimately aggregate many users. Tighter
	 * thresholds = more false positives.
	 *
	 *   - 'global': requests per IP across all paths
	 *   - 'per_minute': burst protection
	 *   - 'post': limits form submissions specifically
	 *   - 'login': limits authentication attempts (credential stuffing)
	 *
	 * Default (in 'normal' strictness): 1000/hr global, 60/min burst
	 */
	'rate_limits' => [
		'enabled'     => true,
		'global'      => [
			'requests' => 1000,
			'window'   => 3600,           // per IP per hour
		],
		'per_minute'  => [
			'requests' => 60,
			'window'   => 60,             // per IP per minute
		],
		'post'        => [
			'requests' => 30,
			'window'   => 3600,           // POST per IP per hour
		],
		'login'       => [
			'requests' => 10,
			'window'   => 900,            // login attempts per IP per 15 min
		],
	],

	// =========================================================================
	// DNS VERIFICATION — verifies bots claiming to be Google/Bing/etc.
	// =========================================================================

	/**
	 * Synchronous DNS verification for bot UAs.
	 *
	 * What this prevents: malicious bots claiming to be Googlebot etc.
	 * by performing reverse DNS lookup and checking the hostname suffix.
	 *
	 * How it works:
	 *   1. Bot claims to be Googlebot (UA match)
	 *   2. IP not in static Google ranges
	 *   3. Library does gethostbyaddr($ip) → "crawl-X.googlebot.com"
	 *   4. Checks suffix matches "googlebot.com"
	 *   5. If yes → ALLOW. If no → CHALLENGE/BLOCK.
	 *
	 * Cost: 40-300ms latency on FIRST request per bot IP. Subsequent
	 * requests hit the cache.
	 *
	 * FP risk: very low. Only flags bots whose IP doesn't resolve to
	 * a matching hostname.
	 *
	 * Settings:
	 *   - 'enabled': master switch
	 *   - 'timeout_ms': soft timeout for the lookup (default 300ms)
	 *   - 'require_forward_confirm': also verify A/AAAA record matches
	 *     original IP (catches PTR spoofing; HIGH IPv6 FP risk)
	 *   - 'positive_ttl': how long to cache "this IP is verified"
	 *   - 'negative_ttl': how long to cache "this IP failed verification"
	 *     (shorter = re-check failed IPs faster after transient DNS issues)
	 *
	 * Default: enabled, 300ms timeout, no forward confirm, 7d/1h TTLs
	 */
	'dns_verification' => [
		'enabled'                  => true,
		'timeout_ms'               => 300,
		'require_forward_confirm'  => false,
		'positive_ttl'             => 604800,     // cache verified IPs for 7 days
		'negative_ttl'             => 3600,       // re-check failed IPs after 1 hour
	],

	// =========================================================================
	// ON-DEMAND IP RANGE REFRESH ("WEB CRON")
	// =========================================================================

	/**
	 * Automatic IP range refresh triggered by page traffic.
	 *
	 * Replaces `bin/update-ip-ranges.php` cron for deployments without
	 * scheduled-job support (shared hosting, PaaS, containerized apps
	 * without CronJob support). On a small fraction of requests, checks
	 * if the cached merged IP ranges are stale; if so, fetches fresh
	 * from upstream feeds in the background (after the response is
	 * sent to the client) and atomically swaps the cache.
	 *
	 * === WHEN TO USE ===
	 *
	 *   - Recommended for: shared hosting, PaaS, sites without cron access
	 *   - Not recommended for: high-traffic sites with cron available —
	 *     use `bin/update-ip-ranges.php` directly (more efficient, runs
	 *     on a known schedule, doesn't piggyback on user requests)
	 *
	 * === HOW IT WORKS ===
	 *
	 * Four gates gate each refresh — probability × cooldown × staleness ×
	 * mutex — so even on very busy sites the refresh runs at most once
	 * per `min_age_seconds` per worker, and at most once concurrently
	 * across all workers on a shared cache:
	 *
	 *   Gate 1: Probability   — 1 in N requests even checks
	 *   Gate 2: Cooldown      — skip while lock is held
	 *   Gate 3: Staleness     — skip when cache is fresh
	 *   Gate 4: Mutex         — only one worker fetches at a time
	 *
	 * The actual fetch runs after the HTTP response has been sent to the
	 * client, so user-facing latency is unaffected. Under PHP-FPM this
	 * uses `fastcgi_finish_request()`; under CLI / mod_php the refresh
	 * is skipped (no clean way to detach from response time).
	 *
	 * === CACHE BACKEND REQUIREMENT ===
	 *
	 * The mutex lock must be in a SHARED cache across processes/hosts:
	 *   - Redis, Memcached, DB-backed cache: works correctly
	 *   - File-based cache: gives per-host mutex only (still works, just
	 *     multiple hosts may refresh concurrently — bounded by
	 *     probability × staleness floor, so the cost is trivial)
	 *
	 * === COLD START ===
	 *
	 * On a fresh install with no cache, the FIRST triggering request will
	 * populate the cache during shutdown. Until that happens (a few seconds
	 * to a few minutes, depending on traffic), bots whose IPs aren't in
	 * the shipped static ranges won't be verified by DNS. The bundled
	 * static ranges already cover ~95% of production traffic, so this is
	 * generally fine.
	 *
	 * === FEED ENDPOINT PRESSURE ===
	 *
	 * At default settings (1/1000 probability, 6h staleness floor), each
	 * worker performs ~6 checks/hour and ~4 actual fetches/day. Well
	 * within feed providers' rate limits. If you raise the probability
	 * or shorten the staleness floor, monitor feed provider responses.
	 *
	 * === COST ===
	 *
	 *   - Per-request overhead: 1 mt_rand() call + 1 cache get on the
	 *     rare triggering request. Negligible.
	 *   - Per-refresh cost: 4-8 feed fetches × ~500ms each = 2-4 seconds
	 *     of shutdown-handler time, once every `min_age_seconds`.
	 *   - Cache storage: ~50KB for the merged ranges payload.
	 */
	'on_demand_ip_refresh' => [

		/**
		 * Master switch.
		 *
		 * Recommended for: shared hosting, PaaS, sites without cron access.
		 * Not recommended for: high-traffic sites with cron available
		 * (use `bin/update-ip-ranges.php` instead).
		 *
		 * Default: false
		 */
		'enabled' => false,

		/**
		 * Probability denominator.
		 *
		 * 1 in N requests triggers the staleness check. Higher values mean
		 * less frequent checks and less load on feed endpoints. At
		 * 100 req/min with denominator=1000: ~6 checks/hour per worker.
		 *
		 * At 1000 req/min with denominator=1000: ~60 checks/hour per worker.
		 * At 10000 req/min with denominator=1000: ~600 checks/hour per worker.
		 *
		 * The actual refresh frequency is bounded by `min_age_seconds`
		 * (Gate 3), so increasing the denominator doesn't increase feed
		 * endpoint pressure — it only reduces the CPU cost of Gate 1's
		 * mt_rand() call on the hot path.
		 *
		 * Default: 1000
		 */
		'probability_denominator' => 1000,

		/**
		 * Staleness floor (seconds).
		 *
		 * Minimum age of the cached data before a refresh is allowed,
		 * regardless of how often the probability gate fires. This is
		 * the hard floor on refresh frequency.
		 *
		 * Recommended values:
		 *   - 21600 (6h)  — typical; feeds change infrequently
		 *   - 43200 (12h) — conservative; less feed endpoint load
		 *   - 3600  (1h)  — aggressive; only if you observe feed-driven
		 *                   bot misidentifications
		 *
		 * Default: 21600
		 */
		'min_age_seconds' => 21600,

		/**
		 * Lock TTL (seconds).
		 *
		 * How long the refresh mutex is held. Functions as both:
		 *   (a) Cross-process/host mutex — only one worker fetches
		 *   (b) Cooldown — don't re-check within this window
		 *
		 * Should comfortably exceed the worst-case refresh duration
		 * (4 feeds × `feed_timeout_seconds`). With default timeouts:
		 * 4 × 5s = 20s, so 600s (10 min) gives 30× headroom.
		 *
		 * Default: 600
		 */
		'lock_ttl' => 600,

		/**
		 * Cache TTL (seconds).
		 *
		 * How long the refreshed cache entry lives in the cache backend.
		 * Acts as "stale tolerance" — if feed endpoints become unreachable
		 * for up to `cache_ttl` seconds, the old ranges are still served.
		 *
		 * 7 days is generous. Handles a feed going down for a long weekend
		 * without leaving the site un-protected.
		 *
		 * Default: 604800 (7 days)
		 */
		'cache_ttl' => 604800,

		/**
		 * Feed fetch timeout (seconds).
		 *
		 * Hard wall-clock budget for the entire refresh. Protects against
		 * a misbehaving feed hanging the shutdown handler indefinitely.
		 *
		 * Accepts fractional values (e.g., 0.5, 1.5) for sub-second
		 * budgets on fast networks.
		 *
		 * Default: 5
		 */
		'feed_timeout_seconds' => 5,

		/**
		 * Bot IDs to refresh (optional filter).
		 *
		 * Restrict the refresh scope to specific bots. Null = all bots
		 * in the registry. Useful for high-traffic sites that only care
		 * about a subset (e.g., ['googlebot', 'gptbot', 'claude']).
		 *
		 * Default: null (all bots)
		 */
		'bot_ids' => null,

		/**
		 * Cloud providers to refresh (optional filter).
		 *
		 * Restrict the refresh scope to specific cloud providers. Null =
		 * all four defaults ('aws', 'cloudflare', 'fastly', 'gcp').
		 *
		 * Useful if you don't use one of the providers and want to
		 * avoid the wasted fetch.
		 *
		 * Default: null (all four providers)
		 */
		'cloud_providers' => null,
	],

	// =========================================================================
	// LOG RETENTION
	// =========================================================================

	/**
	 * Automatic cleanup of old bad_behaviour log rows.
	 *
	 * Replaces BB 2.x's implicit per-request cleanup (which caused DELETE
	 * storms under load) with a 4-gated, on-demand approach. The cleanup
	 * runs in the background — user-facing latency is unaffected under
	 * PHP-FPM because the DELETE happens after the response has been sent.
	 *
	 * === WHEN TO USE ===
	 *
	 *   - Recommended for: any deployment that previously relied on the
	 *     BB 2.x "auto-delete after 7 days" behavior.
	 *   - For sites without cron access: leave on-request cleanup enabled
	 *     (the default). The 4-gate design guarantees at most one DELETE
	 *     per min_interval (default 6h) per worker.
	 *   - For sites with cron access: enable on-request cleanup AND run
	 *     bin/cleanup-logs.php daily — belt-and-suspenders for high-traffic
	 *     sites where the random 1/N gate might not fire often enough.
	 *
	 * === HOW IT WORKS ===
	 *
	 * Four gates gate each cleanup — probability × cooldown × staleness ×
	 * mutex — so even on very busy sites the cleanup runs at most once
	 * per min_interval_seconds per worker, and at most once concurrently
	 * across all workers on a shared cache:
	 *
	 *   Gate 1: Probability   — 1 in N requests even checks
	 *   Gate 2: Cooldown      — skip while cleanup lock is held
	 *   Gate 3: Staleness     — skip when last cleanup was recent
	 *   Gate 4: Mutex         — only one worker cleans at a time
	 *
	 * The actual DELETE runs after the HTTP response has been sent to
	 * the client. Under PHP-FPM the cleanup uses the shutdown function;
	 * under CLI / mod_php it's skipped (no clean way to detach from
	 * response time). Use bin/cleanup-logs.php for CLI invocation.
	 *
	 * === SCHEMA-PORTABLE DELETE ===
	 *
	 * The cleanup probes the table to discover the newest row's date,
	 * then computes cutoff = newest - max_age_days. This works on every
	 * common schema (DATETIME, INT unix-timestamp, TEXT ISO-8601) without
	 * adapter-specific SQL. SQLite uses chunked DELETEs (default 1000 rows
	 * per statement) bounded by a 500ms wall-clock budget to avoid
	 * database locks.
	 *
	 * === CACHE BACKEND REQUIREMENT ===
	 *
	 * The cleanup mutex requires a SHARED cache across processes/hosts:
	 *   - Redis, Memcached, DB-backed cache: works correctly
	 *   - File-based cache: gives per-host mutex only (still works, just
	 *     multiple hosts may clean concurrently — bounded by probability
	 *     × min_interval, so the cost is trivial)
	 *
	 * If no CacheInterface is available, cleanup is silently disabled.
	 * Use bin/cleanup-logs.php from a single-worker CLI cron instead.
	 *
	 * === COST ===
	 *
	 *   - Per-request overhead: 1 mt_rand() call + 1 cache get on the
	 *     rare triggering request. Negligible.
	 *   - Per-cleanup cost: 1-2 SQL queries (probe + DELETE) per worker
	 *     per min_interval, capped at 500ms wall-clock. Well within DB
	 *     load tolerance.
	 *   - Cache storage: ~100 bytes for the last-run timestamp.
	 */
	'log_retention' => [

		/**
		 * Master switch.
		 *
		 * Default: true (to match BB 2.x's "auto-delete after 7 days" behavior)
		 */
		'enabled' => true,

		/**
		 * Retention window in days.
		 *
		 * Rows older than this are deleted. The cutoff is computed relative
		 * to the newest row in the table (not now), so a table that hasn't
		 * received writes in 30 days still has its old rows deleted when
		 * the next write arrives.
		 *
		 * Recommended values:
		 *   - 7  — BB 2.x default; minimum useful for forensics
		 *   - 14 — two-week window for short-term abuse investigation
		 *   - 30 — monthly window for compliance audits
		 *   - 90 — quarterly window for long-term trend analysis
		 *
		 * Default: 7
		 */
		'max_age_days' => 7,

		/**
		 * Optional row-count safety cap.
		 *
		 * When the table exceeds this many rows, cleanup switches from
		 * age-based to row-count mode: oldest rows are deleted until the
		 * table has fewer than max_rows entries. Useful for sites where
		 * verbose logging produces millions of rows even within the
		 * retention window.
		 *
		 * 0 = no cap (age-based only). Default: 0.
		 */
		'max_rows' => 0,

		/**
		 * Probability denominator.
		 *
		 * 1 in N requests triggers the staleness check. Higher values mean
		 * less frequent checks and less load on the DB.
		 *
		 * The actual cleanup frequency is bounded by `min_interval_seconds`
		 * (Gate 3), so increasing the denominator doesn't increase cleanup
		 * frequency — it only reduces the CPU cost of Gate 1's mt_rand()
		 * call on the hot path.
		 *
		 * Default: 1000
		 */
		'probability_denominator' => 1000,

		/**
		 * Staleness floor (seconds).
		 *
		 * Minimum age of the last cleanup before another is allowed,
		 * regardless of how often the probability gate fires. This is
		 * the hard floor on cleanup frequency.
		 *
		 * Recommended values:
		 *   - 3600  (1h)   — aggressive; high-traffic sites with disk pressure
		 *   - 21600 (6h)   — typical; matches BB 2.x behavior loosely
		 *   - 86400 (24h)  — conservative; daily cleanup is plenty
		 *
		 * Default: 21600
		 */
		'min_interval_seconds' => 21600,

		/**
		 * Mutex lock TTL (seconds).
		 *
		 * How long the cleanup lock is held. Functions as both:
		 *   (a) Cross-process/host mutex — only one worker cleans
		 *   (b) Cooldown — don't re-check within this window
		 *
		 * Should comfortably exceed the worst-case cleanup duration
		 * (1 DELETE × 500ms wall-clock budget). Default 600s (10 min)
		 * gives 1200× headroom.
		 *
		 * Default: 600
		 */
		'lock_ttl' => 600,
	],

	// =========================================================================
	// DYNAMIC IP RANGES — fetches cloud provider IP feeds (Cloudflare, AWS, etc.)
	// =========================================================================

	/**
	 * Asynchronous IP range fetching from cloud providers.
	 *
	 * What this prevents: blocking cloud-hosted services that you actually
	 * want to allow (e.g., Cloudflare's edge nodes if you ARE Cloudflare).
	 *
	 * How it works: after each request, a background task fetches the
	 * latest IP ranges from Cloudflare/AWS/GCP/Fastly and caches them.
	 * Next request sees warm cache.
	 *
	 * Cost: zero request-path latency. Fetch happens after response sent.
	 *
	 * FP risk: very low. Just adds "known cloud IPs" to your allow list.
	 *
	 * Settings:
	 *   - 'enabled': master switch
	 *   - 'ttl': how long fetched ranges are cached before re-fetching
	 *   - 'feeds': which providers to fetch (trim to only what you use)
	 *
	 * Default: enabled, 24h TTL, all four providers
	 *
	 * IMPORTANT: default is FALSE. Enabling without setting up the cron
	 * causes empty-cache warnings on every fresh worker. The static IP
	 * ranges in the bot registry already cover Cloudflare/AWS/GCP/Fastly.
	 */
	'dynamic_ip_ranges' => [
		'enabled' => false,
		'ttl'     => 86400,   // re-fetch every 24 hours
		'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
	],

	// =========================================================================
	// BLACKLIST — blocks obvious attacks (raw XSS, SQL injection, etc.)
	// =========================================================================

	/**
	 * Strict mode for blacklist detector.
	 *
	 * What this prevents: contextual attack patterns (suspect behavior +
	 * suspect UA pattern = block).
	 *
	 * FP risk: moderate. Contextual scoring has false positives with
	 * non-browser clients (curl, mobile apps, link previewers).
	 *
	 * Default: false
	 */
	'strict' => false,

	// =========================================================================
	// CUSTOM RULES — your own block/allow/challenge rules
	// =========================================================================

	/**
	 * User-defined detection rules.
	 *
	 * What this prevents: whatever you explicitly target — specific IP
	 * ranges, specific UAs, specific countries, specific headers.
	 *
	 * FP risk: depends entirely on how you write the rules. IP rules
	 * are safest (specific scope). UA regex rules can over-match.
	 *
	 * Each rule has:
	 *   - 'type': ip | ua_regex | ua_contains | asn | country | header
	 *   - 'value': the pattern to match
	 *   - 'action': block | challenge | allow | log
	 *
	 * Examples:
	 *
	 *   // Block a specific IP range
	 *   [
	 *       'id'     => 'block-bad-network',
	 *       'type'   => 'ip',
	 *       'value'  => ['203.0.113.0/24'],
	 *       'action' => 'block',
	 *   ],
	 *
	 *   // Challenge requests from a country
	 *   [
	 *       'id'     => 'challenge-tor-countries',
	 *       'type'   => 'country',
	 *       'value'  => 'XX',
	 *       'action' => 'challenge',
	 *   ],
	 *
	 *   // Log but allow specific UA pattern
	 *   [
	 *       'id'     => 'log-internal-crawler',
	 *       'type'   => 'ua_contains',
	 *       'value'  => 'MyCompanyBot',
	 *       'action' => 'log',
	 *   ],
	 *
	 * Default: empty (no custom rules)
	 */
	'custom_rules' => [],

	// =========================================================================
	// EXPERIMENTAL DETECTORS — FP risk; OFF by default
	// =========================================================================

	/**
	 * Behavioral analysis: detects rapid requests, rotating UAs, etc.
	 *
	 * What this prevents: botnets that rotate User-Agents to evade
	 * per-UA detection, scrapers that make many requests in a session.
	 *
	 * FP risk: HIGH. Shared NAT IPs (corporate networks, mobile
	 * carriers, VPN exit nodes) legitimately aggregate many users with
	 * different UAs. A single IP making requests for 50 users looks
	 * identical to a botnet.
	 *
	 * Only enable if you observe actual UA rotation attacks against
	 * your site.
	 *
	 * Default: false
	 */
	'enable_behavioral_analysis'    => false,

	/**
	 * Client Hints validation: catches browsers with spoofed UA +
	 * Client Hints mismatch.
	 *
	 * What this prevents: bots that fake a Chrome UA but don't send
	 * Sec-CH-UA headers (or send inconsistent ones).
	 *
	 * FP risk: HIGH. Only Chromium browsers (Chrome, Edge, Brave, etc.)
	 * send Client Hints. Firefox, Safari, Opera in some modes, mobile
	 * browsers, and link previewers do NOT. Enabling this flags
	 * legitimate non-Chromium users.
	 *
	 * Default: false
	 */
	'enable_client_hints_validation' => false,

	/**
	 * Agentic detection: detects AI agent patterns (think-then-fetch,
	 * non-linear navigation, precision targeting).
	 *
	 * What this prevents: AI agents (ChatGPT browsing, Claude computer
	 * use, etc.) that load pages in unnatural patterns.
	 *
	 * FP risk: moderate. Experimental — known false positives with
	 * single-page apps (which fetch assets in bursts), link previewers,
	 * and screen readers.
	 *
	 * Default: false
	 */
	'enable_agentic_detection'      => false,

	/**
	 * Head request detection: blocks HEAD flooding / enumeration.
	 *
	 * What this prevents: bots that map your site by sending HEAD
	 * requests to thousands of URLs (faster than GET enumeration).
	 *
	 * FP risk: moderate. Legitimate monitoring (UptimeRobot, Pingdom,
	 * StatusCake, Lighthouse, link checkers) and REST API clients
	 * legitimately send HEAD.
	 *
	 *   - 'head_require_referer': set true to require Referer on HEAD
	 *     requests to non-API paths (HIGH FP risk for REST clients)
	 *
	 * Default: false
	 */
	'enable_head_request_detection' => false,
	'head_require_referer'          => false,
	'head_flood_threshold'          => 20,
	'head_probe_threshold'          => 50,
	'head_referer_exempt_paths'     => ['/api/', '/wp-json/'],

	/**
	 * Asset scraping detection: blocks direct asset scraping without
	 * page loads.
	 *
	 * What this prevents: bots that download all your images/PDFs/
	 * documents directly (AI training data collection, content theft).
	 *
	 * FP risk: moderate. Image proxies, link previewers (Slack, Twitter,
	 * Facebook), PDF viewers, and RSS readers fetch assets directly
	 * without loading the parent page.
	 *
	 * Settings:
	 *   - 'asset_extensions': which file types to watch
	 *   - 'asset_no_referer_threshold': requests without Referer before
	 *     blocking
	 *   - 'asset_only_session_threshold': assets without any HTML page
	 *     loads in the session
	 *
	 * Default: false
	 */
	'enable_asset_scraping_detection' => false,
	'asset_extensions'                => [
		'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
		'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
	],
	'asset_no_referer_threshold'     => 10,
	'asset_only_session_threshold'   => 20,
	'asset_pattern_threshold'        => 100,

	/**
	 * Fingerprinting: blocks known-bad TLS/HTTP2 fingerprints.
	 *
	 * What this prevents: requests with JA3/HTTP2 fingerprints known
	 * to belong to scraper frameworks (Python-requests, Go-http-client,
	 * headless Chrome variants used for abuse).
	 *
	 * FP risk: depends entirely on which fingerprints you list. Empty
	 * list = no blocking. Listing common HTTP libraries = blocks
	 * legitimate API clients.
	 *
	 * Default: false, empty fingerprint lists
	 */
	'enable_fingerprinting' => false,

	// =========================================================================
	// BLOCK PAGE — what the user sees when blocked
	// =========================================================================

	/**
	 * Show admin contact email on the block page.
	 *
	 * What this does: helps legitimate users who were accidentally
	 * blocked contact you.
	 * FP cost: exposes your email to actual attackers (minor).
	 *
	 * Default: false
	 */
	'show_contact_info'        => false,

	/**
	 * Show detailed block page (reason, support key, technical details).
	 *
	 * What this does: gives blocked users enough info to appeal.
	 * FP cost: gives attackers information about why they were blocked
	 * (helps them refine their approach).
	 *
	 * Default: false (minimal "Access Denied" page)
	 */
	'show_detailed_block_page' => false,

	// =========================================================================
	// GEOIP — country/ASN-based blocking (requires MaxMind or similar)
	// =========================================================================

	/**
	 * GeoIP-based blocking.
	 *
	 * What this prevents: traffic from countries/ASNs you don't serve.
	 *
	 * FP risk: HIGH if used aggressively. Blocking countries is a blunt
	 * instrument — VPN users appear to come from random countries,
	 * legitimate users travel, and attackers use residential proxies
	 * in "allowed" countries.
	 *
	 * Settings:
	 *   - 'database_path': path to MaxMind GeoLite2-Country.mmdb or
	 *     similar database
	 *   - 'blocked_countries': ISO 3166-1 alpha-2 codes (['CN', 'RU'])
	 *   - 'blocked_asns': ASN strings (['AS15169'] for Google)
	 *
	 * Default: disabled
	 */
	'geoip' => [
		'enabled'           => false,
		'database_path'     => '',         // path to MaxMind .mmdb file
		'blocked_countries' => [],         // ISO codes: ['CN', 'RU']
		'blocked_asns'      => [],         // ASN strings: ['AS15169']
	],

	// =========================================================================
	// DNSBL — IP reputation lookups (network dependent, can be slow)
	// =========================================================================

	/**
	 * DNS-based blocklist lookups (Spamhaus, etc.).
	 *
	 * What this prevents: requests from IPs known to send spam.
	 *
	 * FP risk: DNSBLs have known false positive rates (Spamhaus PBL
	 * flags residential IPs as "should not send email" — fine for mail,
	 * wrong for web). Listed IPs are often compromised devices, not
	 * the attackers themselves.
	 *
	 * Cost: adds DNS queries to every request.
	 *
	 * Default: disabled
	 */
	'dnsbl' => [
		'enabled' => false,
		'lists'   => ['zen.spamhaus.org', 'bl.spamcop.net'],
	],

	// =========================================================================
	// HTTP:BL — Project Honeypot (requires API key)
	// =========================================================================

	/**
	 * Project Honeypot http:BL integration.
	 *
	 * What this prevents: requests from IPs known to Project Honeypot
	 * as comment spammers, harvesters, or search engine junk.
	 *
	 * FP risk: low (Project Honeypot is well-curated) but real.
	 *
	 * Settings:
	 *   - 'key': your Project Honeypot access key (get one at
	 *     https://www.projecthoneypot.org/)
	 *   - 'threat': minimum threat score to block (0-255; default 25)
	 *   - 'maxage': max days since last activity (default 30)
	 *
	 * Default: disabled (no API key)
	 */
	'httpbl' => [
		'key'     => '',    // your Project Honeypot access key
		'threat'  => 25,    // minimum threat score to block (0-255)
		'maxage'  => 30,    // max days since last activity
	],

	// =========================================================================
	// CHALLENGE — captcha/JS-proof for suspicious requests
	// =========================================================================

	/**
	 * Challenge (CAPTCHA) provider configuration.
	 *
	 * What this prevents: bots that can't solve CAPTCHAs from accessing
	 * your site (uses your challenge provider's verification).
	 *
	 * FP risk: very low (provider does the verification). User
	 * experience cost: real users see a CAPTCHA on first request.
	 *
	 * Settings:
	 *   - 'provider': 'builtin' (JS timeproof), 'recaptcha', 'hcaptcha',
	 *     or 'turnstile' (Cloudflare)
	 *   - 'site_key'/'secret_key': from your provider's dashboard
	 *   - 'recaptcha_min_score': 0.0-1.0 (reCAPTCHA v3 only)
	 *
	 * Default: disabled
	 */
	'challenge' => [
		'enabled'             => false,
		'provider'            => 'builtin',   // builtin | recaptcha | hcaptcha | turnstile
		'site_key'            => '',
		'secret_key'          => '',
		'recaptcha_min_score' => 0.5,
	],

	// =========================================================================
	// PERFORMANCE — skip detection for static resources
	// =========================================================================

	/**
	 * Skip detection for static resources.
	 *
	 * What this does: skips ALL detection (DNS, behavioral, etc.) for
	 * requests to these paths/extensions.
	 *
	 * Why: 95%+ of web traffic is CSS/JS/images/fonts. Running the full
	 * detection pipeline on static assets wastes CPU and adds latency
	 * with zero security benefit (you serve these from a CDN anyway).
	 *
	 * FP risk: none — these are already publicly served files.
	 *
	 * Default: sensible list of common static extensions and paths
	 */
	'performance' => [
		'skip_extensions' => [
			'css','js','png','jpg','jpeg','gif','ico','svg',
			'woff','woff2','ttf','eot','webp','avif','map','txt',
		],
		'skip_paths' => [
			'/static/','/assets/','/media/','/images/','/css/',
			'/js/','/fonts/','/dist/','/build/','/vendor/',
		],
	],
];
