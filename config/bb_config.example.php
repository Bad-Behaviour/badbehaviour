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
		'allowed'         => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
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
	 * Bot categories to block unconditionally (default: none).
	 *
	 * What this prevents: entire classes of bots by category.
	 *   - 'malicious': known bad bots
	 *   - 'seo_crawler': SEMrush, Ahrefs, etc.
	 *   - 'residential_proxy': Bright Data, etc.
	 *   - 'security_scanner': Qualys, Shodan (logged, not blocked)
	 *
	 * FP risk: depends on category. 'residential_proxy' is safest to
	 * block; 'security_scanner' blocks legitimate security research.
	 *
	 * Default: empty (nothing blocked by category)
	 */
	'bot_categories' => [
		'blocked' => [],   // e.g., ['residential_proxy']
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
	 */
	'dynamic_ip_ranges' => [
		'enabled' => true,
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
