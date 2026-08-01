<?php
/**
 * Bad Behaviour 3.0 — Example Configuration
 *
 * Copy this file to config/bb_config.php and customize.
 * This file is loaded by BadBehaviour::withAdapter() and Configuration::from_file().
 *
 * --- QUICK START ---
 *
 * The shipped defaults match Bad Behaviour 2.x behavior exactly.
 *   1. cp config/bb_config.example.php config/bb_config.php
 *   2. (Optional) Edit config/bb_config.php to enable features
 *   3. Deploy — no other steps required for a drop-in upgrade
 *
 * --- CONFIGURATION PROFILES ---
 *
 * Three reference profiles cover ~95% of deployments:
 *
 *   DEFAULT  — 2.x-compatible, no FP risk, AJAX / uploads / HTTP tools all work
 *   MEDIUM   — Production-grade, adds Client Hints + agentic detection (roll out per week)
 *   STRICT   — High-security / API-only, may break AJAX / JSON / old browsers
 *
 * See docs/CONFIGURATION.md for full profile configs and per-setting rationale.
 *
 * --- ENVIRONMENT EXAMPLES ---
 *
 *   Shared hosting / no monitoring / AJAX is critical?  → DEFAULT
 *   Public CMS with modern browser traffic?             → MEDIUM
 *   Internal API / B2B / paid content?                 → STRICT
 *
 * @see docs/CONFIGURATION.md
 * @see docs/MIGRATION.md      (2.x → 3.0 upgrade guide)
 * @see docs/CHANGELOG.md
 */

return [

    // ============================================================
    // CORE
    // ============================================================

    /**
     * Master switch for request logging.
     * When false, blocked requests are not written to the database.
     * Disabling logging degrades some behavioral detection (rotating UA,
     * rapid request detection rely on history).
     *
     * @var bool Default: true
     */
    'logging' => true,

    /**
     * When true, EVERY request is logged (not just blocked).
     * Useful for debugging; expensive on high-traffic sites.
     *
     * @var bool Default: false
     */
    'verbose' => false,

    /**
     * Strict mode — additional header validation (Accept-Encoding required).
     * Breaks old browsers, privacy-focused browsers (some Brave configs),
     * and any non-browser client that doesn't send Accept-Encoding.
     *
     * Recommended: enable only on internal APIs or after FP audit.
     *
     * @var bool Default: false
     */
    'strict' => false,

    /**
     * When true, reject form POSTs whose Referer header doesn't match Host.
     * Breaks legitimate external form submissions (e.g., payment processors
     * posting back to your site).
     *
     * @var bool Default: false
     */
    'offsite_forms' => false,

    /**
     * When true, the admin email is shown on the block page.
     * Combine with show_detailed_block_page for full user support.
     *
     * @var bool Default: false
     */
    'show_contact_info' => false,

    /**
     * When true, the block page shows the request URI, reason, and support key.
     * When false, only "Reference #abc-1234" is shown (terse).
     *
     * @var bool Default: false
     */
    'show_detailed_block_page' => false,

    // ============================================================
    // REVERSE PROXY
    // ============================================================

    /**
     * REQUIRED if behind Cloudflare, AWS ALB, nginx reverse proxy, etc.
     * Without this, Bad Behaviour sees the proxy's IP instead of the real client.
     *
     * ⚠️  CRITICAL: Never enable 'enabled' => true without 'addresses' populated.
     *     Otherwise attackers can spoof their IP via the proxy header.
     */
    'reverse_proxy' => [
        /**
         * Master switch.
         *
         * @var bool Default: false
         */
        'enabled' => false,

        /**
         * HTTP header carrying the real client IP.
         * Cloudflare: CF-Connecting-IP
         * AWS ALB:    X-Forwarded-For
         * nginx:      X-Real-IP (if configured)
         *
         * @var string Default: 'X-Forwarded-For'
         */
        'header' => 'X-Forwarded-For',

        /**
         * CIDR ranges of trusted proxies.
         * Must include ALL proxies in front of your app.
         * For Cloudflare, see: https://www.cloudflare.com/ips/
         *
         * @var string[] Default: []
         */
        'addresses' => [
            // '173.245.48.0/20',
            // '103.21.244.0/22',
            // '103.22.200.0/22',
            // '103.31.4.0/22',
            // '141.101.64.0/18',
            // '108.162.192.0/18',
            // '190.93.240.0/20',
            // '188.114.96.0/20',
            // '197.234.240.0/22',
            // '198.41.128.0/17',
            // '162.158.0.0/15',
            // '104.16.0.0/13',
            // '104.24.0.0/14',
            // '172.64.0.0/13',
            // '131.0.72.0/22',
        ],
    ],

    // ============================================================
    // AI CRAWLERS
    // ============================================================

    /**
     * Tokens (matched against robots_txt_token in Registry) for AI crawlers
     * that should bypass all checks. Verified by DNS (reverse lookup) and/or IP.
     *
     * Default allowed: GPTBot, ClaudeBot, Google-Extended
     * To allow none: 'allowed' => []
     */
    'ai_crawlers' => [
        /**
         * Allowed AI crawler tokens (verified bots bypass everything).
         *
         * @var string[]
         */
        'allowed' => [
            'GPTBot',           // OpenAI
            'ClaudeBot',        // Anthropic
            'Google-Extended',  // Google Vertex/Bard/Gemini
            'PerplexityBot',    // Perplexity
            'GrokBot',          // xAI
            'MistralBot',       // Mistral AI
            'YouBot',           // You.com
            'Meta-ExternalAgent', // Meta AI
        ],

        /**
         * When true, unverified AI crawlers (UA matches but DNS/IP doesn't)
         * are blocked. Strongly recommended.
         *
         * @var bool Default: true
         */
        'block_unverified' => true,

        /**
         * When true, even verified AI crawlers NOT in 'allowed' are blocked.
         * When false (default), they're challenged instead.
         *
         * @var bool Default: false
         */
        'strict' => false,
    ],

    // ============================================================
    // BOT CATEGORIES
    // ============================================================

    /**
     * Categories of known bots to handle in specific ways.
     * Each entry configures the default behavior for that category.
     *
     * Categories:
     *   search_engine        — Googlebot, Bingbot, Yandex, Baidu, regional SE
     *   ai_crawler           — GPTBot, Claude, Gemini, etc.
     *   social_crawler       — Facebook, Twitter, Kakao, LINE, WeChat
     *   seo_crawler          — Ahrefs, Semrush, Siteimprove, etc.
     *   archive_crawler      — Internet Archive, BnF, UKWA, etc.
     *   monitoring           — UptimeRobot, Pingdom
     *   feed_reader          — Feedly, Apple News, Google News   (NEW)
     *   shopping_crawler     — Google Shopping, FB Catalog       (NEW)
     *   cloud_infrastructure — Cloudflare/AWS/GCP/Azure/Fastly   (NEW — never block)
     *   security_scanner     — Qualys, Shodan, Censys            (NEW — log only)
     *   malicious            — Known-bad actors
     *
     * 'blocked' — block entirely
     * 'challenge' — issue PoW/captcha
     * 'allow' — bypass (verified only)
     * 'log_only' — record, never block
     */
	'bot_categories' => [
		/**
		 * Categories to BLOCK entirely.
		 * Default: ['malicious'] — block nothing else out-of-the-box.
		 *
		 * Add 'seo_crawler' to block Ahrefs, Semrush, etc.
		 * Add 'social_crawler' to block FB/Twitter link previews (rare).
		 *
		 * @var string[]
		 */
		'blocked' => ['malicious'],

		/**
		 * Categories that LOG only without blocking.
		 * Security scanners fit here — auditing YOU is not an attack.
		 *
		 * @var string[] Default: ['security_scanner']
		 */
		'log_only' => ['security_scanner'],

		/**
		 * Categories that should be CHALLENGED (PoW/captcha).
		 * Default empty — by default new categories (feed/shopping/cloud)
		 * are ALLOWED. Add 'ai_crawler' here to force challenge on ALL AI.
		 *
		 * @var string[]
		 */
		'challenge' => [],

		/**
		 * Categories that should be ALLOWED (verified only).
		 * Default — feed/shopping/cloud/monitoring/archive.
		 *
		 * @var string[]
		 */
		'allowed' => [
			'feed_reader',
			'shopping_crawler',
			'cloud_infrastructure',
			'monitoring',
			'archive_crawler',
		],
	],

	// ============================================================
	// DYNAMIC IP RANGE FEEDS
	// ============================================================

	/**
	 * Pull fresh IP ranges from official cloud provider feeds to avoid
	 * hardcoded CIDR drift. Set true once you've confirmed the cron is
	 * running (see bin/update-ip-ranges.php).
	 *
	 * Critical for: cloud_infrastructure category (Cloudflare, AWS, GCP,
	 * Azure, Fastly). Without this, you'll get blocked-outage incidents
	 * when providers rotate ranges.
	 */
	'dynamic_ip_ranges' => [
		/**
		 * Master switch for pulling from AWS/Azure/GCP/Cloudflare/Fastly feeds.
		 * Requires cron: php bin/update-ip-ranges.php every 6-24 hours.
		 *
		 * @var bool Default: false
		 */
		'enabled' => false,

		/**
		 * Cache TTL for the merged IP range data.
		 * Lower = fresher (but more cron pressure). Higher = longer stale window.
		 *
		 * @var int Default: 86400 (24h)
		 */
		'ttl' => 86400,

		/**
		 * Specific feeds to enable. Disable a feed by removing it.
		 * All are recommended for global deployments.
		 *
		 * @var string[]
		 */
		'feeds' => [
			'aws',         // ip-ranges.amazonaws.com
			'cloudflare',  // api.cloudflare.com/client/v4/ips
			'fastly',      // api.fastly.com/public-ip-list
			'gcp',         // gstatic.com/ipranges/cloud.json
		],
	],

    // ============================================================
    // RATE LIMITS
    // ============================================================

    /**
     * Multi-tier rate limiting. Per-IP, in-memory or adapter-backed.
     * Tuned for typical public CMS — adjust for your traffic.
     */
    'rate_limits' => [
        /**
         * Master switch.
         *
         * @var bool Default: true
         */
        'enabled' => true,

        /**
         * Global per-IP cap (over the global.window).
         * Resets every `window` seconds per IP.
         */
        'global' => [
            'requests' => 1000,
            'window'   => 3600,  // 1 hour
        ],

        /**
         * Burst protection — per minute per IP.
         */
        'per_minute' => [
            'requests' => 60,
            'window'   => 60,
        ],

        /**
         * Form spam protection — POSTs per IP per window.
         */
        'post' => [
            'requests' => 30,
            'window'   => 3600,
        ],

        /**
         * Login brute force protection — triggered on URLs matching
         * /(login|signin|auth|password)/i.
         */
        'login' => [
            'requests' => 10,
            'window'   => 900,  // 15 min
        ],
    ],

    // ============================================================
    // BODY SCAN
    // ============================================================

    /**
     * Form field names to skip during SQL/XSS body inspection.
     * Heuristics also skip fields ending with _body, _content, _text,
     * _html, _markdown, _wiki or containing comment, description, code, source.
     */
    'body_scan_skip_fields' => [
        'body', 'comment', 'content', 'text', 'message', 'description',
        'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
        'article', 'page', 'entry', 'reply', 'review', 'feedback',
    ],

    // ============================================================
    // CHALLENGE SYSTEM
    // ============================================================

    /**
     * Issue a challenge (PoW or captcha) to suspicious requests instead of
     * blocking outright. Useful for grey-area traffic.
     */
    'challenge' => [
        /**
         * Master switch.
         *
         * @var bool Default: false
         */
        'enabled' => false,

        /**
         * Provider: 'builtin' (PoW, no deps), 'hcaptcha', 'recaptcha', 'turnstile'.
         */
        'provider' => 'builtin',

        /**
         * Site key (public). Required for hcaptcha/recaptcha/turnstile.
         */
        'site_key' => '',

        /**
         * Secret key (private). Required for hcaptcha/recaptcha/turnstile.
         * NEVER expose this — keep it server-side only.
         */
        'secret_key' => '',

        /**
         * reCAPTCHA v3 score threshold (0.0–1.0). Lower = stricter.
         */
        'recaptcha_min_score' => 0.5,
    ],

    // ============================================================
    // PERFORMANCE — Static Asset Skipping
    // ============================================================

    /**
     * Files matching these extensions or path prefixes bypass all detection.
     * Critical for performance — never inspect CSS/JS/images.
     */
    'performance' => [
        /**
         * @var string[]
         */
        'skip_extensions' => [
            'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg',
            'woff', 'woff2', 'ttf', 'eot', 'webp', 'avif', 'map', 'txt',
        ],

        /**
         * @var string[] Path prefixes
         */
        'skip_paths' => [
            '/static/', '/assets/', '/media/', '/images/', '/css/',
            '/js/', '/fonts/', '/dist/', '/build/', '/vendor/',
            '/node_modules/',
        ],
    ],

    // ============================================================
    // HTTP:BL (Project Honey Pot)
    // ============================================================

    /**
     * Query Project Honey Pot's IP reputation database.
     * Free API key required: https://www.projecthoneypot.org/
     */
    'httpbl' => [
        /**
         * API key from Project Honey Pot.
         */
        'key' => '',

        /**
         * Threat score threshold (0-255). IPs with score >= this are blocked.
         * Lower = stricter.
         */
        'threat' => 25,

        /**
         * Max days since last activity. IPs inactive longer are ignored.
         */
        'maxage' => 30,
    ],

    // ============================================================
    // DNSBL
    // ============================================================

    /**
     * Additional DNS-based blocklists beyond http:BL.
     * Each lookup adds ~100ms — use sparingly.
     */
    'dnsbl' => [
        /**
         * Master switch.
         *
         * @var bool Default: false
         */
        'enabled' => false,

        /**
         * DNSBL hostnames to query (in reverse-IP dotted notation).
         *
         * @var string[]
         */
        'lists' => [
            'zen.spamhaus.org',
            'bl.spamcop.net',
        ],
    ],

    // ============================================================
    // FINGERPRINTS — Opt-in, Config-Driven
    // ============================================================

    /**
     * Known-bad TLS / H2 / header-order fingerprints.
     * Only fingerprints EXPLICITLY listed here are blocked (zero FP by design).
     * Curate from your own attack logs.
     */
    'fingerprints' => [
        /**
         * JA3 TLS fingerprints to block.
         *
         * @var string[] Each is a 32-char MD5 hash
         */
        'bad_ja3' => [
            // Example: '771,4865-4867-4866-...,0-23-...,29-23-24,0',
        ],

        /**
         * HTTP/2 settings hashes to block.
         *
         * @var string[] Each is a 16-char SHA-256 prefix
         */
        'bad_h2' => [
            // Example: 'a1b2c3d4e5f67890',
        ],

        /**
         * Bot header-order hashes to block.
         *
         * @var string[]
         */
        'bot_header_orders' => [
            // Example: 'f9e8d7c6b5a43210',
        ],

        /**
         * (Reserved) Trusted JA3 fingerprints for bypass.
         *
         * @var string[]
         */
        'expected_ja3' => [],
    ],

    // ============================================================
    // GEOIP
    // ============================================================

    /**
     * Country / ASN blocking via MaxMind GeoIP2 database.
     * Requires GeoIP2 PHP API and a downloaded .mmdb file.
     */
    'geoip' => [
        /**
         * Master switch.
         *
         * @var bool Default: false
         */
        'enabled' => false,

        /**
         * Path to GeoLite2-Country.mmdb (or equivalent).
         */
        'database_path' => '/usr/share/GeoIP/GeoLite2-Country.mmdb',

        /**
         * ISO 3166-1 alpha-2 country codes to block.
         *
         * @var string[]
         */
        'blocked_countries' => [
            // 'XL', 'ZZ',
        ],

        /**
         * ASN numbers to block (e.g., 'AS15169' = Google).
         *
         * @var string[]
         */
        'blocked_asns' => [
            // 'AS12345',
        ],
    ],

    // ============================================================
    // CUSTOM RULES
    // ============================================================

    /**
     * User-defined rules evaluated BEFORE the detection pipeline.
     * First match wins. Order matters.
     *
     * Rule types: ip, ua_regex, ua_contains, asn, country, header
     * Actions:    allow, block, challenge, log  (log = record only, never blocks)
     */
    'custom_rules' => [
        // Example 1: Audit every verified Googlebot
        // [
        //     'type'    => 'ua_regex',
        //     'value'   => '/Googlebot/i',
        //     'action'  => 'log',
        //     'id'      => 'audit_googlebot',
        // ],

        // Example 2: Block a hostile network
        // [
        //     'type'    => 'ip',
        //     'value'   => '192.0.2.0/24',
        //     'action'  => 'block',
        //     'id'      => 'test_network',
        // ],

        // Example 3: Challenge requests from a specific country
        // [
        //     'type'    => 'country',
        //     'value'   => 'CN',
        //     'action'  => 'challenge',
        //     'id'      => 'china_challenge',
        // ],

        // Example 4: Log agentic UAs for policy decisions
        // [
        //     'type'    => 'header',
        //     'header'  => 'Sec-CH-UA',
        //     'value'   => 'Brave Leo',
        //     'action'  => 'log',
        //     'id'      => 'brave_leo_agentic',
        // ],
    ],

    // ============================================================
    // DETECTION FEATURES (All Opt-In)
    // ============================================================
    //
    // All features below are OFF by default for 2.x compatibility.
    // See docs/CONFIGURATION.md → Configuration Profiles for rollout order.

    /**
     * Enable JA3 / H2 / header-order fingerprint detection.
     * Only blocks fingerprints EXPLICITLY listed in 'fingerprints'.* above.
     * Zero FP risk if 'fingerprints.bad_ja3' etc. are empty.
     *
     * Risk: 🟡 MEDIUM (after you populate bad_*[])
     *
     * @var bool Default: false
     */
    'enable_fingerprinting' => false,

    /**
     * Inspect JSON request bodies for SQLi/XSS/command injection patterns.
     *
     * Risk: 🔴 HIGH — WILL break legitimate code snippets in JSON payloads
     * (wiki editors, code-sharing sites, etc.). Never enable on AJAX/JSON APIs.
     *
     * @var bool Default: false
     */
    'inspect_json_body' => false,

    /**
     * Inspect multipart/form-data bodies for SQLi/XSS patterns.
     *
     * Risk: 🔴 HIGH — Almost never safe; breaks file uploads with code in
     * metadata fields.
     *
     * @var bool Default: false
     */
    'inspect_multipart_body' => false,

    /**
     * Enable behavioral analysis: rate anomalies, rotating UA/IP, URL
     * enumeration, think-time checks, header validation.
     *
     * Risk: 🟢 LOW — safe default; legacy-compatible.
     *
     * @var bool Default: true
     */
    'enable_behavioral_analysis' => true,

    /**
     * Enforce the AI crawlers allowlist (verified AI only).
     *
     * Risk: 🟢 LOW — safe default.
     *
     * @var bool Default: true
     */
    'enable_ai_crawler_control' => true,

    /**
     * NEW in 3.0: Cross-validate User-Agent against Sec-CH-UA headers from
     * Chromium-based browsers (Chrome 89+, Edge, Brave, Vivaldi, Opera 75+).
     * Catches most spoofed UAs.
     *
     * ⚠️  Firefox / Safari don't send Sec-CH-UA — they are NOT validated
     *     (by design). Electron apps (Slack, VS Code, Discord) spoof Chrome
     *     but don't send Sec-CH-UA and WILL be blocked — whitelist if needed.
     *
     * Risk: 🟡 MEDIUM — enable after 1–2 weeks of monitoring.
     *
     * @var bool Default: false
     */
    'enable_client_hints_validation' => false,

    /**
     * NEW in 3.0: Detect AI-agent patterns (Brave Leo, ChatGPT operator,
     * Playwright scrapers mimicking humans):
     *   - think-then-fetch (long pause + asset burst)
     *   - non-linear navigation (5+ unrelated sections in 8 requests)
     *   - precision targeting (high API ratio, no CSS/fonts/tracking)
     *
     * ⚠️  Requires session cookies — anonymous traffic is skipped.
     *     False positives possible with single-page apps and power users.
     *
     * Risk: 🟡 MEDIUM — enable after auditing your power users.
     *
     * @var bool Default: false
     */
    'enable_agentic_detection' => false,

    /**
     * NEW in 3.0 (EXPERIMENTAL): Pull fresh IP ranges from official feeds
     * (Google, Bing, OpenAI, Anthropic, Apple, Perplexity, Cloudflare).
     *
     * REQUIRES cron to refresh the feed cache:
     *   0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php
     *
     * ⚠️  Experimental — known issues:
     *     1. Caching boundaries in multi-server deployments (file cache
     *        doesn't share; use Redis via MediaWiki adapter for production)
     *     2. Feed shape changes (vendors occasionally add fields)
     *     3. Cold-start latency (first request after TTL expiry)
     *     4. CA bundle portability in containers
     *
     * Risk: 🟡 MEDIUM-EXPERIMENTAL
     *
     * @var bool Default: false
     */
    'enable_dynamic_ip_ranges' => false,

    // ============================================================
    // HEAD REQUEST DETECTION (Enabled by Default — Low FP Risk)
    // ============================================================
    //
    // Unlike the other 3.0 detectors above, this is ON by default because
    // it targets clearly malicious behavior (site mapping / reconnaissance
    // via HEAD) that legitimate clients don't exhibit.

    /**
     * Detect HEAD request abuse: site mapping, link-checking at scale,
     * rapid reconnaissance. Three signals:
     *   - HEAD without Referer (except /api/, /wp-json/, /health, /status)
     *   - HEAD flood per session (>20 requests)
     *   - HEAD probing per IP (>50 requests in 5 minutes)
     *
     * Legitimate HEAD usage (link checkers, monitoring, REST APIs) is
     * allowed via the exempt paths configuration below.
     *
     * Risk: 🟢 LOW — link checkers send Referer naturally; REST clients
     * hitting /api/ are exempt by default.
     *
     * @var bool Default: true
     */
    'enable_head_request_detection' => true,

    /**
     * When true, HEAD requests to non-exempt paths without a Referer header
     * are blocked. Set false only if you have legitimate clients (rare HTTP
     * libraries) that issue HEAD to non-API paths without Referer.
     *
     * Risk: 🟢 LOW.
     *
     * @var bool Default: true
     */
    'head_require_referer' => true,

    /**
     * HEAD requests per session before flagging as flood.
     * Lower = stricter. Real browsers rarely exceed this in a single session.
     *
     * Risk: 🟢 LOW.
     *
     * @var int Default: 20
     */
    'head_flood_threshold' => 20,

    /**
     * HEAD probes per IP per 5-minute window before flagging as
     * reconnaissance. Lower = stricter.
     *
     * Risk: 🟢 LOW.
     *
     * @var int Default: 50
     */
    'head_probe_threshold' => 50,

    /**
     * Path prefixes exempt from the Referer requirement. REST clients and
     * monitoring tools issue HEAD to these endpoints without a Referer.
     * Defaults cover most CMS APIs (WordPress, WackoWiki) and common
     * health-check endpoints.
     *
     * Add your own API prefixes here as needed.
     *
     * Risk: 🟢 LOW.
     *
     * @var string[] Default: ['/api/', '/wp-json/', '/health', '/status']
     */
    'head_referer_exempt_paths' => [
        '/api/',
        '/wp-json/',
        '/health',
        '/status',
    ],

    // ============================================================
    // ASSET SCRAPING DETECTION (Enabled by Default — Low FP Risk)
    // ============================================================
    //
    // Detects AI training crawlers and image harvesters that download
    // assets in bulk without loading the HTML pages first. Legitimate
    // browsers: load HTML → load referenced assets. Scrapers: directly
    // request assets from a URL list.

    /**
     * Detect direct asset scraping. Three signals:
     *   - Asset requests without Referer (>10/hr per IP)
     *   - Asset-only session (>20 assets, zero HTML loads)
     *   - Sequential asset pattern (>100 assets in 5 min per IP)
     *
     * Real browsers always load HTML before assets, so legitimate users
     * never trigger signal 2.
     *
     * Risk: 🟢 LOW.
     *
     * @var bool Default: true
     */
    'enable_asset_scraping_detection' => true,

    /**
     * File extensions treated as "assets" for scraping detection.
     * Add extensions for content types you serve and want to protect
     * (e.g., 'csv', 'json', 'xml', 'zip'). Remove extensions used by
     * legitimate APIs that don't send Referer (rare).
     *
     * Risk: 🟡 MEDIUM — adding too many extensions increases false
     * positives on legitimate API responses.
     *
     * @var string[] Default: image, document, audio, video formats
     */
    'asset_extensions' => [
        // Images
        'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
        // Documents
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        // Audio / video
        'mp3', 'mp4', 'wav', 'ogg', 'webm',
    ],

    /**
     * Asset requests without Referer per IP per hour before flagging
     * as scraping. Lower = stricter.
     *
     * Risk: 🟢 LOW.
     *
     * @var int Default: 10
     */
    'asset_no_referer_threshold' => 10,

    /**
     * Asset requests within a single session (with zero HTML loads)
     * before flagging as asset-only scraping. Real browsers always
     * load HTML first, so this rarely fires for legitimate traffic.
     *
     * Risk: 🟢 LOW.
     *
     * @var int Default: 20
     */
    'asset_only_session_threshold' => 20,

    /**
     * Sequential asset URLs from a single IP per 5-minute window before
     * flagging as enumeration. Lower = stricter.
     *
     * Risk: 🟢 LOW.
     *
     * @var int Default: 100
     */
    'asset_pattern_threshold' => 100,
];
];