<?php
// config/bb_config.php
// Single source of truth — no parsing, no ambiguity, full types

return [
    // ===== CORE =====
    'logging'                    => true,
    'verbose'                    => false,
    'strict'                     => false,
    'offsite_forms'              => false,

	'show_contact_info'        => false,
	'show_detailed_block_page'	=> false,

    // ===== REVERSE PROXY =====
    'reverse_proxy'              => [
        'enabled'   => true,
        'header'    => 'CF-Connecting-IP',
        'addresses' => [
            '173.245.48.0/20',
            '103.21.244.0/22',
            // ... all Cloudflare ranges
        ],
    ],

    // ===== HTTP:BL =====
    'httpbl'                     => [
        'key'     => '',
        'threat'  => 25,
        'maxage'  => 30,
    ],

    // ===== DNSBL =====
    'dnsbl'                      => [
        'enabled' => false,
        'lists'   => ['zen.spamhaus.org', 'bl.spamcop.net'],
    ],

    // ===== AI CRAWLERS =====
    'ai_crawlers'                => [
        'allowed'          => [
            'GPTBot', 'ClaudeBot', 'Google-Extended',
            'PerplexityBot', 'GrokBot', 'MistralBot',
            'YouBot', 'Meta-ExternalAgent'
        ],
        'block_unverified' => true,
        'strict'           => false,
    ],

    // ===== BOT CATEGORIES =====
    'bot_categories'             => [
        'blocked' => ['malicious'],
    ],

    // ===== RATE LIMITS =====
    'rate_limits'                => [
        'enabled'      => true,
        'global'       => ['requests' => 1000, 'window' => 3600],
        'per_minute'   => ['requests' => 60,   'window' => 60],
        'post'         => ['requests' => 30,   'window' => 3600],
        'login'        => ['requests' => 10,   'window' => 900],
    ],

    // ===== CHALLENGE =====
    'challenge'                  => [
        'enabled'             => false,
        'provider'            => 'builtin', // builtin, hcaptcha, recaptcha, turnstile
        'site_key'            => '',
        'secret_key'          => '',
        'recaptcha_min_score' => 0.5,
    ],

    // ===== PERFORMANCE =====
    'performance'                => [
        'skip_extensions' => ['css','js','png','jpg','jpeg','gif','ico','svg','woff','woff2','ttf','eot','webp','avif','map','txt'],
        'skip_paths'      => ['/static/','/assets/','/media/','/images/','/css/','/js/','/fonts/','/dist/','/build/','/vendor/','/node_modules/'],
    ],

    // ===== GEOIP =====
    'geoip'                      => [
        'enabled'             => false,
        'database_path'       => '/usr/share/GeoIP/GeoLite2-Country.mmdb',
        'blocked_countries'   => [],
        'blocked_asns'        => [],
    ],

    // ===== FINGERPRINTS =====
    'fingerprints'               => [
        'bad_ja3'            => [],
        'bad_h2'             => [],
        'bot_header_orders'  => [],
        'expected_ja3'       => [],
    ],

    // ===== BODY SCAN =====
    'body_scan_skip_fields'      => [
        'body', 'comment', 'content', 'text', 'message', 'description',
        'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
        'article', 'page', 'entry', 'reply', 'review', 'feedback',
    ],

    // ===== CUSTOM RULES =====
    'custom_rules'               => [
        // ['type' => 'ip', 'value' => '192.0.2.0/24', 'action' => 'block', 'id' => 'test_network'],
        // ['type' => 'header', 'header' => 'Sec-CH-UA', 'value' => 'Brave Leo', 'action' => 'log', 'id' => 'brave_leo_agentic',],
    ],

    // ===== 3.0 FEATURES =====
    'enable_fingerprinting'      => false,
    'inspect_json_body'          => false,
    'inspect_multipart_body'     => false,
    'enable_behavioral_analysis' => true,
    'enable_ai_crawler_control'  => true,
	'enable_client_hints_validation' => true,
	'enable_agentic_detection' => true,
	'enable_dynamic_ip_ranges'      => false,  // EXPERIMENTAL - DISABLED BY DEFAULT

	// ===== HEAD REQUEST DETECTION =====
	// Detects abuse of HEAD requests for site mapping / reconnaissance
	'enable_head_request_detection' => true,
	'head_require_referer'          => true,
	'head_flood_threshold'          => 20,
	'head_probe_threshold'          => 50,
	'head_referer_exempt_paths'     => ['/api/', '/wp-json/', '/health', '/status'],

	// ===== ASSET SCRAPING DETECTION =====
	// Detects direct asset scraping (AI training crawlers, image harvesters)
	'enable_asset_scraping_detection' => true,
	'asset_extensions'                => [
		// Images
		'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
		// Documents
		'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
		// Audio/video
		'mp3', 'mp4', 'wav', 'ogg', 'webm',
	],
	'asset_no_referer_threshold'   => 10,
	'asset_only_session_threshold' => 20,
	'asset_pattern_threshold'      => 100,
];
