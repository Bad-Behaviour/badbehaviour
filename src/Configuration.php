<?php

namespace BadBehaviour;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\LoggerInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Interfaces\GeoIpInterface;

readonly class Configuration
{
    public function __construct(
        // Core
        public bool $logging = true,
        public bool $verbose = false,
        public bool $strict = false,
        public bool $offsite_forms = false,
    	public string $log_table = '',

        // Block page settings
    	public bool $show_contact_info = false,
    	public bool $show_detailed_block_page = false,

        // Reverse Proxy
        public bool $reverse_proxy = false,
        public string $reverse_proxy_header = 'X-Forwarded-For',
        public array $reverse_proxy_addresses = [],

        // http:BL
        public string $httpbl_key = '',
        public int $httpbl_threat = 25,
        public int $httpbl_maxage = 30,

        // DNSBL
        public bool $dnsbl_enabled = false,
        public array $dnsbl_lists = [],

        // AI Crawlers
        public array $allowed_ai_crawlers = [],
        public bool $block_unverified_ai = true,
        public bool $strict_ai = false,
        public bool $strict_search_engines = false,

        // Bot Categories
        public array $blocked_bot_categories = [],

        // Rate Limiting
        public bool $rate_limit_enabled = true,
        public array $rate_limits = [],

        // Custom Rules
        public array $custom_rules = [],

        // Fingerprints
        public array $bad_ja3_fingerprints = [],
        public array $bad_h2_fingerprints = [],
        public array $bot_header_orders = [],
        public array $expected_ja3 = [],

        // GeoIP
        public bool $geoip_enabled = false,
        public string $geoip_database_path = '',
        public array $blocked_countries = [],
        public array $blocked_asns = [],

        // Challenge
        public bool $challenge_enabled = false,
        public string $challenge_provider = 'builtin',
        public string $challenge_site_key = '',
        public string $challenge_secret_key = '',
        public float $recaptcha_min_score = 0.5,

        // Performance
        public array $skip_static_extensions = [],
        public array $skip_static_paths = [],

        // 3.0 Features
        public bool $enable_fingerprinting = false,
        public bool $inspect_json_body = false,
        public bool $inspect_multipart_body = false,
        public bool $enable_behavioral_analysis = true,
        public bool $enable_ai_crawler_control = true,
    	public bool $enable_dynamic_ip_ranges = true,
    	public bool $enable_client_hints_validation = true,
    	public bool $enable_agentic_detection = true,

    	public bool $enable_head_request_detection = true,
    	public bool $head_require_referer = true,
    	public int $head_flood_threshold = 20,
    	public int $head_probe_threshold = 50,
    	public array $head_referer_exempt_paths = [],

    	public bool $enable_asset_scraping_detection = true,
    	public array $asset_extensions = [],
    	public int $asset_no_referer_threshold = 10,
    	public int $asset_only_session_threshold = 20,
    	public int $asset_pattern_threshold = 100,

        // Dependencies (injected)
        public ?AdapterInterface $adapter = null,
        public ?LoggerInterface $logger = null,
        public ?CacheInterface $cache = null,
        public ?GeoIpInterface $geoip = null,
    ) {}

    /**
     * Create Configuration from PHP config file + optional overrides
     *
     * @param string|array $config PHP config file path OR array
     * @param AdapterInterface|null $adapter
     * @return self
     */
    public static function from_file(string $config_file, ?AdapterInterface $adapter = null): self
    {
        $config = file_exists($config_file)
            ? (require $config_file)
            : [];

        if (!is_array($config)) {
            throw new \InvalidArgumentException("Config file must return an array: $config_file");
        }

        return self::from_array($config, $adapter);
    }

    /**
     * Create Configuration from array (for testing/runtime overrides)
     */
    public static function from_array(array $config, ?AdapterInterface $adapter = null): self
    {
    	$defaults = self::get_defaults();
    	$merged = self::array_merge_recursive($defaults, $config);

    	// Extract nested sections
    	$reverse_proxy = $merged['reverse_proxy'] ?? [];
    	$httpbl = $merged['httpbl'] ?? [];
    	$dnsbl = $merged['dnsbl'] ?? [];
    	$ai_crawlers = $merged['ai_crawlers'] ?? [];
    	$rate_limits = $merged['rate_limits'] ?? [];
    	$challenge = $merged['challenge'] ?? [];
    	$performance = $merged['performance'] ?? [];
    	$geoip = $merged['geoip'] ?? [];
    	$fingerprints = $merged['fingerprints'] ?? [];
    	$bot_categories = $merged['bot_categories'] ?? [];

    	// FIX: Proper clamping for httpbl
    	$httpbl_threat = (int)($httpbl['threat'] ?? 25);
    	$httpbl_threat = max(0, min(255, $httpbl_threat));

    	$httpbl_maxage = (int)($httpbl['maxage'] ?? 30);
    	$httpbl_maxage = max(0, $httpbl_maxage);

    	// NEW: Clamp rate limit values
    	if (isset($rate_limits['global']['requests'])) {
    		$rate_limits['global']['requests'] = max(1, (int)$rate_limits['global']['requests']);
    	}
    	if (isset($rate_limits['global']['window'])) {
    		$rate_limits['global']['window'] = max(1, (int)$rate_limits['global']['window']);
    	}
    	if (isset($rate_limits['per_minute']['requests'])) {
    		$rate_limits['per_minute']['requests'] = max(1, (int)$rate_limits['per_minute']['requests']);
    	}
    	if (isset($rate_limits['per_minute']['window'])) {
    		$rate_limits['per_minute']['window'] = max(1, (int)$rate_limits['per_minute']['window']);
    	}

    	$show_contact_info = (bool)($merged['show_contact_info'] ?? false);
    	$show_detailed_block_page = (bool)($merged['show_detailed_block_page'] ?? false);

    	return new self(
    		logging: $merged['logging'] ?? true,
    		verbose: $merged['verbose'] ?? false,
    		strict: $merged['strict'] ?? false,
    		offsite_forms: $merged['offsite_forms'] ?? false,

    		show_contact_info: $show_contact_info,
    		show_detailed_block_page: $show_detailed_block_page,

    		reverse_proxy: (bool)($reverse_proxy['enabled'] ?? false),
    		reverse_proxy_header: $reverse_proxy['header'] ?? 'X-Forwarded-For',
    		reverse_proxy_addresses: self::ensure_array($reverse_proxy['addresses'] ?? []),

    		httpbl_key: $httpbl['key'] ?? '',
    		httpbl_threat: $httpbl_threat,
    		httpbl_maxage: $httpbl_maxage,

    		dnsbl_enabled: (bool)($dnsbl['enabled'] ?? false),
    		dnsbl_lists: self::ensure_array($dnsbl['lists'] ?? ['zen.spamhaus.org', 'bl.spamcop.net']),

    		allowed_ai_crawlers: self::ensure_array($ai_crawlers['allowed'] ?? ['GPTBot', 'ClaudeBot', 'Google-Extended']),
    		block_unverified_ai: (bool)($ai_crawlers['block_unverified'] ?? true),
    		strict_ai: (bool)($ai_crawlers['strict'] ?? false),
    		strict_search_engines: (bool)($merged['strict_search_engines'] ?? false),

    		blocked_bot_categories: self::ensure_array($bot_categories['blocked'] ?? ['malicious']),

    		rate_limit_enabled: (bool)($rate_limits['enabled'] ?? true),
    		rate_limits: self::normalize_rate_limits($rate_limits),

    		custom_rules: (array)($merged['custom_rules'] ?? []),

    		bad_ja3_fingerprints: (array)($fingerprints['bad_ja3'] ?? []),
    		bad_h2_fingerprints: (array)($fingerprints['bad_h2'] ?? []),
    		bot_header_orders: (array)($fingerprints['bot_header_orders'] ?? []),
    		expected_ja3: (array)($fingerprints['expected_ja3'] ?? []),

    		geoip_enabled: (bool)($geoip['enabled'] ?? false),
    		geoip_database_path: $geoip['database_path'] ?? '',
    		blocked_countries: self::ensure_array($geoip['blocked_countries'] ?? []),
    		blocked_asns: self::ensure_array($geoip['blocked_asns'] ?? []),

    		challenge_enabled: (bool)($challenge['enabled'] ?? false),
    		challenge_provider: $challenge['provider'] ?? 'builtin',
    		challenge_site_key: $challenge['site_key'] ?? '',
    		challenge_secret_key: $challenge['secret_key'] ?? '',
    		recaptcha_min_score: (float)($challenge['recaptcha_min_score'] ?? 0.5),

    		skip_static_extensions: (array)($performance['skip_extensions'] ?? self::default_skip_extensions()),
    		skip_static_paths: (array)($performance['skip_paths'] ?? self::default_skip_paths()),

    		enable_fingerprinting: (bool)($merged['enable_fingerprinting'] ?? false),
    		inspect_json_body: (bool)($merged['inspect_json_body'] ?? false),
    		inspect_multipart_body: (bool)($merged['inspect_multipart_body'] ?? false),
    		enable_behavioral_analysis: (bool)($merged['enable_behavioral_analysis'] ?? true),
    		enable_ai_crawler_control: (bool)($merged['enable_ai_crawler_control'] ?? true),
    		enable_client_hints_validation: (bool)($merged['enable_client_hints_validation'] ?? true),
    		enable_agentic_detection: (bool)($merged['enable_agentic_detection'] ?? true),
    		enable_dynamic_ip_ranges: (bool)($merged['enable_dynamic_ip_ranges'] ?? false),

    		enable_head_request_detection: (bool)($merged['enable_head_request_detection'] ?? true),
    		head_require_referer: (bool)($merged['head_require_referer'] ?? true),
    		head_flood_threshold: max(1, (int)($merged['head_flood_threshold'] ?? 20)),
    		head_probe_threshold: max(1, (int)($merged['head_probe_threshold'] ?? 50)),
    		head_referer_exempt_paths: self::ensure_array($merged['head_referer_exempt_paths'] ?? ['/api/', '/wp-json/']),

    		enable_asset_scraping_detection: (bool)($merged['enable_asset_scraping_detection'] ?? true),
    		asset_extensions: self::ensure_array($merged['asset_extensions'] ?? ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'pdf']),
    		asset_no_referer_threshold: max(1, (int)($merged['asset_no_referer_threshold'] ?? 10)),
    		asset_only_session_threshold: max(1, (int)($merged['asset_only_session_threshold'] ?? 20)),
    		asset_pattern_threshold: max(1, (int)($merged['asset_pattern_threshold'] ?? 100)),

    		adapter: $adapter,
    		);
    }

    private static function get_defaults(): array
    {
        return [
            'logging' => true,
            'verbose' => false,
            'strict' => false,
            'offsite_forms' => false,
        	'show_contact_info' => false,
        	'show_detailed_block_page' => false,
            'reverse_proxy' => ['enabled' => false, 'header' => 'X-Forwarded-For', 'addresses' => []],
            'httpbl' => ['key' => '', 'threat' => 25, 'maxage' => 30],
            'dnsbl' => ['enabled' => false, 'lists' => ['zen.spamhaus.org', 'bl.spamcop.net']],
            'ai_crawlers' => ['allowed' => ['GPTBot', 'ClaudeBot', 'Google-Extended'], 'block_unverified' => true, 'strict' => false],
            'bot_categories' => ['blocked' => ['malicious']],
            'rate_limits' => [
                'enabled' => true,
                'global' => ['requests' => 1000, 'window' => 3600],
                'per_minute' => ['requests' => 60, 'window' => 60],
                'post' => ['requests' => 30, 'window' => 3600],
                'login' => ['requests' => 10, 'window' => 900],
            ],
            'custom_rules' => [],
            'fingerprints' => ['bad_ja3' => [], 'bad_h2' => [], 'bot_header_orders' => [], 'expected_ja3' => []],
            'geoip' => ['enabled' => false, 'database_path' => '', 'blocked_countries' => [], 'blocked_asns' => []],
            'challenge' => ['enabled' => false, 'provider' => 'builtin', 'site_key' => '', 'secret_key' => '', 'recaptcha_min_score' => 0.5],
            'performance' => [
                'skip_extensions' => self::default_skip_extensions(),
                'skip_paths' => self::default_skip_paths(),
            ],
            'body_scan_skip_fields' => [
                'body', 'comment', 'content', 'text', 'message', 'description',
                'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
                'article', 'page', 'entry', 'reply', 'review', 'feedback',
            ],
            'enable_fingerprinting' => false,
            'inspect_json_body' => false,
            'inspect_multipart_body' => false,
            'enable_behavioral_analysis' => true,
            'enable_ai_crawler_control' => true,
        	'enable_dynamic_ip_ranges' => false,  // EXPERIMENTAL - OFF by default
        	'enable_client_hints_validation' => true,
        	'enable_agentic_detection' => true,
        	'enable_head_request_detection' => true,
        	'head_require_referer' => true,
        	'head_flood_threshold' => 20,
        	'head_probe_threshold' => 50,
        	'head_referer_exempt_paths' => ['/api/', '/wp-json/', '/health', '/status'],

        	'enable_asset_scraping_detection' => true,
        	'asset_extensions' => [
        		'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
        		'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        		'mp3', 'mp4', 'wav', 'ogg', 'webm',
        	],
        	'asset_no_referer_threshold' => 10,
        	'asset_only_session_threshold' => 20,
        	'asset_pattern_threshold' => 100,
        ];
    }

    public function to_array(): array
    {
    	return [
    		'logging' => $this->logging,
    		'verbose' => $this->verbose,
    		'strict' => $this->strict,
    		'offsite_forms' => $this->offsite_forms,
    		'show_contact_info' => $this->show_contact_info,
    		'show_detailed_block_page' => $this->show_detailed_block_page,

    		'reverse_proxy' => [
    			'enabled' => $this->reverse_proxy,
    			'header' => $this->reverse_proxy_header,
    			'addresses' => $this->reverse_proxy_addresses,
    		],
    		'httpbl' => [
    			'key' => $this->httpbl_key,
    			'threat' => $this->httpbl_threat,
    			'maxage' => $this->httpbl_maxage,
    		],
    		'dnsbl' => [
    			'enabled' => $this->dnsbl_enabled,
    			'lists' => $this->dnsbl_lists,
    		],
    		'ai_crawlers' => [
    			'allowed' => $this->allowed_ai_crawlers,
    			'block_unverified' => $this->block_unverified_ai,
    			'strict' => $this->strict_ai,
    		],
    		'bot_categories' => [
    			'blocked' => $this->blocked_bot_categories,
    		],
    		'rate_limits' => array_merge(['enabled' => $this->rate_limit_enabled], $this->rate_limits),
    		'custom_rules' => $this->custom_rules,
    		'fingerprints' => [
    			'bad_ja3' => $this->bad_ja3_fingerprints,
    			'bad_h2' => $this->bad_h2_fingerprints,
    			'bot_header_orders' => $this->bot_header_orders,
    			'expected_ja3' => $this->expected_ja3,
    		],
    		'geoip' => [
    			'enabled' => $this->geoip_enabled,
    			'database_path' => $this->geoip_database_path,
    			'blocked_countries' => $this->blocked_countries,
    			'blocked_asns' => $this->blocked_asns,
    		],
    		'challenge' => [
    			'enabled' => $this->challenge_enabled,
    			'provider' => $this->challenge_provider,
    			'site_key' => $this->challenge_site_key,
    			'secret_key' => $this->challenge_secret_key,
    			'recaptcha_min_score' => $this->recaptcha_min_score,
    		],
    		'performance' => [
    			'skip_extensions' => $this->skip_static_extensions,
    			'skip_paths' => $this->skip_static_paths,
    		],
    		'body_scan_skip_fields' => $this->body_scan_skip_fields ?? [],
    		'enable_fingerprinting' => $this->enable_fingerprinting,
    		'inspect_json_body' => $this->inspect_json_body,
    		'inspect_multipart_body' => $this->inspect_multipart_body,
    		'enable_behavioral_analysis' => $this->enable_behavioral_analysis,
    		'enable_ai_crawler_control' => $this->enable_ai_crawler_control,
    		'enable_dynamic_ip_ranges' => $this->enable_dynamic_ip_ranges,
    		'enable_client_hints_validation' => $this->enable_client_hints_validation,
    		'enable_agentic_detection' => $this->enable_agentic_detection,

    		'enable_head_request_detection' => $this->enable_head_request_detection,
    		'head_require_referer' => $this->head_require_referer,
    		'head_flood_threshold' => $this->head_flood_threshold,
    		'head_probe_threshold' => $this->head_probe_threshold,
    		'head_referer_exempt_paths' => $this->head_referer_exempt_paths,

    		'enable_asset_scraping_detection' => $this->enable_asset_scraping_detection,
    		'asset_extensions' => $this->asset_extensions,
    		'asset_no_referer_threshold' => $this->asset_no_referer_threshold,
    		'asset_only_session_threshold' => $this->asset_only_session_threshold,
    		'asset_pattern_threshold' => $this->asset_pattern_threshold,

    		'log_table' => $this->log_table ?? '',
    	];
    }


    private static function normalize_rate_limits(array $limits): array
    {
        $defaults = [
            'global'     => ['requests' => 1000, 'window' => 3600],
            'per_minute' => ['requests' => 60,   'window' => 60],
            'post'       => ['requests' => 30,   'window' => 3600],
            'login'      => ['requests' => 10,   'window' => 900],
        ];

        if (isset($limits['enabled']) && count($limits) === 1) {
            return ['enabled' => true] + $defaults;
        }

        foreach ($defaults as $name => $limit) {
            if (!isset($limits[$name])) {
                $limits[$name] = $limit;
            } elseif (is_array($limits[$name])) {
                $limits[$name] = array_merge($limit, $limits[$name]);
            }
        }

        return ['enabled' => $limits['enabled'] ?? true] + $limits;
    }

    private static function default_skip_extensions(): array
    {
        return ['css','js','png','jpg','jpeg','gif','ico','svg','woff','woff2','ttf','eot','webp','avif','map','txt'];
    }

    private static function default_skip_paths(): array
    {
        return ['/static/','/assets/','/media/','/images/','/css/','/js/','/fonts/','/dist/','/build/','/vendor/','/node_modules/'];
    }

    /**
     * Deep merge that preserves numeric keys (doesn't reindex)
     */
    private static function array_merge_recursive(array $a1, array $a2): array
    {
    	$merged = $a1;
    	foreach ($a2 as $key => $value) {
    		if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
    			// Detect if both are lists (numeric keys 0..n)
    			$is_list_1 = self::is_list($merged[$key]);
    			$is_list_2 = self::is_list($value);

    			if ($is_list_1 && $is_list_2) {
    				// Both are lists → REPLACE entirely (user config wins)
    				$merged[$key] = $value;
    			} elseif (!$is_list_1 && !$is_list_2) {
    				// Both are associative → MERGE recursively
    				$merged[$key] = self::array_merge_recursive($merged[$key], $value);
    			} else {
    				// Mixed types → REPLACE (user config wins)
    				$merged[$key] = $value;
    			}
    		} else {
    			$merged[$key] = $value;
    		}
    	}
    	return $merged;
    }

    /**
     * Check if array is a list (numeric keys 0, 1, 2... n-1)
     */
    private static function is_list(array $array): bool
    {
    	if ($array === []) return true;
    	$keys = array_keys($array);
    	return $keys === range(0, count($keys) - 1);
    }

    private static function ensure_array($value, array $default = []): array
    {
    	if (is_array($value)) {
    		return $value;
    	}
    	if (is_string($value) && $value !== '') {
    		return [$value];
    	}
    	return $default;
    }

    /**
     * Get defaults merged with adapter-specific overrides
     * Used when no config file exists
     */
    public static function get_defaults_merged(): array
    {
    	$defaults = self::get_defaults();
    	return $defaults; // Already complete
    }

    /**
     * Deep merge two arrays (preserves numeric keys)
     */
    public static function merge_arrays(array $a1, array $a2): array
    {
    	$merged = $a1;
    	foreach ($a2 as $key => $value) {
    		if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
    			$merged[$key] = self::merge_arrays($merged[$key], $value);
    		} else {
    			$merged[$key] = $value;
    		}
    	}
    	return $merged;
    }
}
