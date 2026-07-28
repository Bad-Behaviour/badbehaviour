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
        // Deep merge with defaults
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

        return new self(
            // Core
            logging: $merged['logging'] ?? true,
            verbose: $merged['verbose'] ?? false,
            strict: $merged['strict'] ?? false,
            offsite_forms: $merged['offsite_forms'] ?? false,

            // Reverse Proxy
            reverse_proxy: (bool)($reverse_proxy['enabled'] ?? false),
            reverse_proxy_header: $reverse_proxy['header'] ?? 'X-Forwarded-For',
            reverse_proxy_addresses: (array)($reverse_proxy['addresses'] ?? []),

            // http:BL
            httpbl_key: $httpbl['key'] ?? '',
            httpbl_threat: (int)($httpbl['threat'] ?? 25),
            httpbl_maxage: (int)($httpbl['maxage'] ?? 30),

            // DNSBL
            dnsbl_enabled: (bool)($dnsbl['enabled'] ?? false),
            dnsbl_lists: (array)($dnsbl['lists'] ?? ['zen.spamhaus.org', 'bl.spamcop.net']),

            // AI Crawlers
            allowed_ai_crawlers: (array)($ai_crawlers['allowed'] ?? ['GPTBot', 'ClaudeBot', 'Google-Extended']),
            block_unverified_ai: (bool)($ai_crawlers['block_unverified'] ?? true),
            strict_ai: (bool)($ai_crawlers['strict'] ?? false),
            strict_search_engines: (bool)($merged['strict_search_engines'] ?? false),

            // Bot Categories
            blocked_bot_categories: (array)($bot_categories['blocked'] ?? ['malicious']),

            // Rate Limiting
            rate_limit_enabled: (bool)($rate_limits['enabled'] ?? true),
            rate_limits: self::normalize_rate_limits($rate_limits),

            // Custom Rules
            custom_rules: (array)($merged['custom_rules'] ?? []),

            // Fingerprints
            bad_ja3_fingerprints: (array)($fingerprints['bad_ja3'] ?? []),
            bad_h2_fingerprints: (array)($fingerprints['bad_h2'] ?? []),
            bot_header_orders: (array)($fingerprints['bot_header_orders'] ?? []),
            expected_ja3: (array)($fingerprints['expected_ja3'] ?? []),

            // GeoIP
            geoip_enabled: (bool)($geoip['enabled'] ?? false),
            geoip_database_path: $geoip['database_path'] ?? '',
            blocked_countries: (array)($geoip['blocked_countries'] ?? []),
            blocked_asns: (array)($geoip['blocked_asns'] ?? []),

            // Challenge
            challenge_enabled: (bool)($challenge['enabled'] ?? false),
            challenge_provider: $challenge['provider'] ?? 'builtin',
            challenge_site_key: $challenge['site_key'] ?? '',
            challenge_secret_key: $challenge['secret_key'] ?? '',
            recaptcha_min_score: (float)($challenge['recaptcha_min_score'] ?? 0.5),

            // Performance
            skip_static_extensions: (array)($performance['skip_extensions'] ?? self::default_skip_extensions()),
            skip_static_paths: (array)($performance['skip_paths'] ?? self::default_skip_paths()),

            // 3.0 Features
            enable_fingerprinting: (bool)($merged['enable_fingerprinting'] ?? false),
            inspect_json_body: (bool)($merged['inspect_json_body'] ?? false),
            inspect_multipart_body: (bool)($merged['inspect_multipart_body'] ?? false),
            enable_behavioral_analysis: (bool)($merged['enable_behavioral_analysis'] ?? true),
            enable_ai_crawler_control: (bool)($merged['enable_ai_crawler_control'] ?? true),
        	enable_dynamic_ip_ranges: (bool)($merged['enable_dynamic_ip_ranges'] ?? true),
        	enable_client_hints_validation: (bool)($merged['enable_client_hints_validation'] ?? true),
        	enable_agentic_detection: (bool)($merged['enable_agentic_detection'] ?? true),

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
        	'enable_dynamic_ip_ranges' => true,
        	'enable_client_hints_validation' => true,
        	'enable_agentic_detection' => true,
        ];
    }

    public function to_array(): array
    {
    	return [
    		'logging' => $this->logging,
    		'verbose' => $this->verbose,
    		'strict' => $this->strict,
    		'offsite_forms' => $this->offsite_forms,
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
                $merged[$key] = self::array_merge_recursive($merged[$key], $value);
            } else {
                $merged[$key] = $value;
            }
        }
        return $merged;
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
