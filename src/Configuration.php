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
		public array $dnsbl_lists = [
			'zen.spamhaus.org',
			'bl.spamcop.net',
		],

		// AI Crawlers
		public array $allowed_ai_crawlers = [],
		public bool $block_unverified_ai = true,
		public bool $strict_ai = false,
		public bool $strict_search_engines = false,

		// Bot Categories
		public array $blocked_bot_categories = ['malicious'],

		// Rate Limiting
		public bool $rate_limit_enabled = true,
		public array $rate_limits = [
			'global'     => ['requests' => 1000, 'window' => 3600],
			'per_minute' => ['requests' => 60,   'window' => 60],
			'post'       => ['requests' => 30,   'window' => 3600],
			'login'      => ['requests' => 10,   'window' => 900],
		],

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
		public array $skip_static_extensions = [
			'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg',
			'woff', 'woff2', 'ttf', 'eot', 'webp', 'avif', 'map', 'txt'
		],
		public array $skip_static_paths = [
			'/static/', '/assets/', '/media/', '/images/', '/css/', '/js/',
			'/fonts/', '/dist/', '/build/', '/vendor/', '/node_modules/'
		],

		// Dependencies (injected)
		public ?AdapterInterface $adapter = null,
		public ?LoggerInterface $logger = null,
		public ?CacheInterface $cache = null,
		public ?GeoIpInterface $geoip = null,
	) {}

	public static function from_array(array $config, ?AdapterInterface $adapter = null): self
	{
		// Coerce types
		$coerce_int = fn($v, $min, $max) => max($min, min($max, (int)($v ?? 0)));
		$coerce_bool = fn($v) => filter_var($v, FILTER_VALIDATE_BOOLEAN);

		return new self(
			logging: $coerce_bool($config['logging'] ?? true),
			verbose: $coerce_bool($config['verbose'] ?? false),
			strict: $coerce_bool($config['strict'] ?? false),
			reverse_proxy: $coerce_bool($config['reverse_proxy'] ?? false),
			reverse_proxy_header: $config['reverse_proxy_header'] ?? 'X-Forwarded-For',
			reverse_proxy_addresses: (array)($config['reverse_proxy_addresses'] ?? []),
			offsite_forms: $coerce_bool($config['offsite_forms'] ?? false),
			httpbl_key: $config['httpbl_key'] ?? '',
			httpbl_threat: $coerce_int($config['httpbl_threat'] ?? 25, 0, 255),
			httpbl_maxage: $coerce_int($config['httpbl_maxage'] ?? 30, 0, 365),
			dnsbl_lists: (array)($config['dnsbl_lists'] ?? ['zen.spamhaus.org', 'bl.spamcop.net']),
			allowed_ai_crawlers: (array)($config['allowed_ai_crawlers'] ?? []),
			block_unverified_ai: $coerce_bool($config['block_unverified_ai'] ?? true),
			strict_ai: $coerce_bool($config['strict_ai'] ?? false),
			strict_search_engines: $coerce_bool($config['strict_search_engines'] ?? false),
			blocked_bot_categories: (array)($config['blocked_bot_categories'] ?? ['malicious']),
			rate_limit_enabled: $coerce_bool($config['rate_limit_enabled'] ?? true),
			rate_limits: self::normalize_rate_limits($config['rate_limits'] ?? []),
			custom_rules: (array)($config['custom_rules'] ?? []),
			bad_ja3_fingerprints: (array)($config['bad_ja3_fingerprints'] ?? []),
			bad_h2_fingerprints: (array)($config['bad_h2_fingerprints'] ?? []),
			bot_header_orders: (array)($config['bot_header_orders'] ?? []),
			expected_ja3: (array)($config['expected_ja3'] ?? []),
			geoip_enabled: $coerce_bool($config['geoip_enabled'] ?? false),
			geoip_database_path: $config['geoip_database_path'] ?? '',
			blocked_countries: (array)($config['blocked_countries'] ?? []),
			blocked_asns: (array)($config['blocked_asns'] ?? []),
			challenge_enabled: $coerce_bool($config['challenge_enabled'] ?? false),
			challenge_provider: $config['challenge_provider'] ?? 'builtin',
			challenge_site_key: $config['challenge_site_key'] ?? '',
			challenge_secret_key: $config['challenge_secret_key'] ?? '',
			recaptcha_min_score: (float)($config['recaptcha_min_score'] ?? 0.5),
			skip_static_extensions: (array)($config['skip_static_extensions'] ?? self::default_skip_extensions()),
			skip_static_paths: (array)($config['skip_static_paths'] ?? self::default_skip_paths()),
			adapter: $adapter,
		);
	}

	private static function normalize_rate_limits(array $limits): array
	{
		$defaults = [
			'global'     => ['requests' => 1000, 'window' => 3600],
			'per_minute' => ['requests' => 60,   'window' => 60],
			'post'       => ['requests' => 30,   'window' => 3600],
			'login'      => ['requests' => 10,   'window' => 900],
		];

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
