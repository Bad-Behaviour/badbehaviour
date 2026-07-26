<?php

namespace BadBehaviour;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\LoggerInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Interfaces\GeoIpInterface;
use BadBehaviour\Util\ConfigUtil;

readonly class Configuration
{
	public function __construct(
		// Core
		public bool $logging = true,
		public bool $verbose = false,
		public bool $strict = false,

		// Reverse Proxy
		public bool $reverse_proxy = false,
		public string $reverse_proxy_header = 'X-Forwarded-For',
		public array $reverse_proxy_addresses = [],

		// Forms
		public bool $offsite_forms = false,

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

		// Dependencies (injected)
		public ?AdapterInterface $adapter = null,
		public ?LoggerInterface $logger = null,
		public ?CacheInterface $cache = null,
		public ?GeoIpInterface $geoip = null,
	) {}

	public static function from_array(array $config, ?AdapterInterface $adapter = null): self
	{
		// 1. Expand dot notation & normalize arrays
		$config = ConfigUtil::expand_dot_notation($config);

		// 2. Merge with defaults
		$config = ConfigUtil::merge_with_defaults($config, self::get_defaults());

		// 3. Coerce types
		$coerce_int = fn($v, $min, $max) => max($min, min($max, (int)($v ?? 0)));
		$coerce_bool = fn($v) => filter_var($v, FILTER_VALIDATE_BOOLEAN);

		// 4. Extract nested sections
		$rate_limits = $config['rate_limits'] ?? [];
		$dnsbl = $config['dnsbl'] ?? [];
		$ai_crawlers = $config['ai_crawlers'] ?? [];
		$challenge = $config['challenge'] ?? [];
		$performance = $config['performance'] ?? [];
		$geoip = $config['geoip'] ?? [];
		$fingerprints = $config['fingerprints'] ?? [];
		$custom_rules = $config['custom_rules'] ?? [];
		$bot_categories = $config['bot_categories'] ?? [];
		$reverse_proxy = $config['reverse_proxy'] ?? [];

		return new self(
			// Core
			logging: $coerce_bool($config['logging'] ?? true),
			verbose: $coerce_bool($config['verbose'] ?? false),
			strict: $coerce_bool($config['strict'] ?? false),

			// Reverse Proxy
			reverse_proxy: $coerce_bool($reverse_proxy['enabled'] ?? false),
			reverse_proxy_header: $reverse_proxy['header'] ?? 'X-Forwarded-For',
			reverse_proxy_addresses: (array)($reverse_proxy['addresses'] ?? []),

			// Forms
			offsite_forms: $coerce_bool($config['offsite_forms'] ?? false),

			// http:BL
			httpbl_key: $config['httpbl_key'] ?? '',
			httpbl_threat: $coerce_int($config['httpbl_threat'] ?? 25, 0, 255),
			httpbl_maxage: $coerce_int($config['httpbl_maxage'] ?? 30, 0, 365),

			// DNSBL
			dnsbl_enabled: $coerce_bool($dnsbl['enabled'] ?? false),
			dnsbl_lists: (array)($dnsbl['lists'] ?? ['zen.spamhaus.org', 'bl.spamcop.net']),

			// AI Crawlers
			allowed_ai_crawlers: (array)($ai_crawlers['allowed'] ?? ['GPTBot', 'ClaudeBot', 'Google-Extended']),
			block_unverified_ai: $coerce_bool($ai_crawlers['block_unverified'] ?? true),
			strict_ai: $coerce_bool($ai_crawlers['strict'] ?? false),
			strict_search_engines: $coerce_bool($config['strict_search_engines'] ?? false),

			// Bot Categories
			blocked_bot_categories: (array)($bot_categories['blocked'] ?? ['malicious']),

			// Rate Limiting
			rate_limit_enabled: $coerce_bool($rate_limits['enabled'] ?? true),
			rate_limits: self::normalize_rate_limits($rate_limits),

			// Custom Rules
			custom_rules: (array)$custom_rules,

			// Fingerprints
			bad_ja3_fingerprints: (array)($fingerprints['bad_ja3'] ?? []),
			bad_h2_fingerprints: (array)($fingerprints['bad_h2'] ?? []),
			bot_header_orders: (array)($fingerprints['bot_header_orders'] ?? []),
			expected_ja3: (array)($fingerprints['expected_ja3'] ?? []),

			// GeoIP
			geoip_enabled: $coerce_bool($geoip['enabled'] ?? false),
			geoip_database_path: $geoip['database_path'] ?? '',
			blocked_countries: (array)($geoip['blocked_countries'] ?? []),
			blocked_asns: (array)($geoip['blocked_asns'] ?? []),

			// Challenge
			challenge_enabled: $coerce_bool($challenge['enabled'] ?? false),
			challenge_provider: $challenge['provider'] ?? 'builtin',
			challenge_site_key: $challenge['site_key'] ?? '',
			challenge_secret_key: $challenge['secret_key'] ?? '',
			recaptcha_min_score: (float)($challenge['recaptcha_min_score'] ?? 0.5),

			// Performance
			skip_static_extensions: (array)($performance['skip_extensions'] ?? self::default_skip_extensions()),
			skip_static_paths: (array)($performance['skip_paths'] ?? self::default_skip_paths()),

			// 3.0 Features
			enable_fingerprinting: $coerce_bool($config['enable_fingerprinting'] ?? false),
			inspect_json_body: $coerce_bool($config['inspect_json_body'] ?? false),
			inspect_multipart_body: $coerce_bool($config['inspect_multipart_body'] ?? false),
			enable_behavioral_analysis: $coerce_bool($config['enable_behavioral_analysis'] ?? true),
			enable_ai_crawler_control: $coerce_bool($config['enable_ai_crawler_control'] ?? true),

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
			'httpbl_key' => '',
			'httpbl_threat' => 25,
			'httpbl_maxage' => 30,
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
			'enable_fingerprinting' => false,
			'inspect_json_body' => false,
			'inspect_multipart_body' => false,
			'enable_behavioral_analysis' => true,
			'enable_ai_crawler_control' => true,
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
			return $defaults;
		}

		foreach ($limits as $name => $limit) {
			if (is_array($limit) && isset($limit['requests'], $limit['window'])) {
				$defaults[$name] = [
					'requests' => max(1, (int)$limit['requests']),
					'window'   => max(1, (int)$limit['window']),
				];
			}
		}
		return $defaults;
	}

	private static function default_skip_extensions(): array
	{
		return ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot', 'webp', 'avif', 'map', 'txt'];
	}

	private static function default_skip_paths(): array
	{
		return ['/static/', '/assets/', '/media/', '/images/', '/css/', '/js/', '/fonts/', '/dist/', '/build/', '/vendor/', '/node_modules/'];
	}
}
