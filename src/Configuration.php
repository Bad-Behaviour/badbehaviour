<?php
namespace BadBehaviour;

use BadBehaviour\Config\Diagnostics;
use BadBehaviour\Config\Schema;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Interfaces\GeoIpInterface;
use BadBehaviour\Core\Interfaces\LoggerInterface;
use BadBehaviour\Util\SafeConfigLoader;
use BadBehaviour\Util\SafeMode;

readonly class Configuration
{
    public function __construct(
        public bool $logging = true,
        public bool $verbose = false,
        public bool $strict = false,
        public bool $offsite_forms = false,
        public string $log_table = '',
        public string $strictness = 'normal',
        public string $preset = 'minimal',

        public bool $show_contact_info = false,
        public bool $show_detailed_block_page = false,

        public bool $reverse_proxy = false,
        public string $reverse_proxy_header = 'X-Forwarded-For',
        public array $reverse_proxy_addresses = [],

        public string $httpbl_key = '',
        public int $httpbl_threat = 25,
        public int $httpbl_maxage = 30,

        public bool $dnsbl_enabled = false,
        public array $dnsbl_lists = [],

        public array $allowed_ai_crawlers = [],
        public bool $block_unverified_ai = false,
        public bool $strict_ai = false,
        public bool $strict_search_engines = false,

        public array $blocked_bot_categories = [],
        public array $challenge_bot_categories = [],
        public array $log_only_bot_categories = [],
        public array $allowed_bot_categories = [],

        public bool $rate_limit_enabled = false,
        public array $rate_limits = [],

        public array $custom_rules = [],

        public array $bad_ja3_fingerprints = [],
        public array $bad_h2_fingerprints = [],
        public array $bot_header_orders = [],
        public array $expected_ja3 = [],

        public bool $geoip_enabled = false,
        public string $geoip_database_path = '',
        public array $blocked_countries = [],
        public array $blocked_asns = [],

        public bool $challenge_enabled = false,
        public string $challenge_provider = 'builtin',
        public string $challenge_site_key = '',
        public string $challenge_secret_key = '',
        public float $recaptcha_min_score = 0.5,

        public array $skip_static_extensions = [],
        public array $skip_static_paths = [],

        public array $body_scan_skip_fields = [],

        public bool $enable_fingerprinting = false,
        public bool $inspect_json_body = false,
        public bool $inspect_multipart_body = false,
        public bool $enable_behavioral_analysis = false,
        public bool $enable_ai_crawler_control = true,
        public bool $enable_client_hints_validation = false,
        public bool $enable_agentic_detection = false,

        public bool $dns_verification_enabled = true,
        public int $dns_verification_timeout_ms = 300,
        public bool $dns_verification_require_forward_confirm = false,
        public int $dns_verification_positive_ttl = 604800,
        public int $dns_verification_negative_ttl = 3600,

        public bool $dynamic_ip_ranges_enabled = false,
        public int $dynamic_ip_ranges_ttl = 86400,
        public array $dynamic_ip_ranges_feeds = ['aws', 'cloudflare', 'fastly', 'gcp'],

        public bool $enable_head_request_detection = false,
        public bool $head_require_referer = false,
        public int $head_flood_threshold = 20,
        public int $head_probe_threshold = 50,
        public array $head_referer_exempt_paths = [],

        public bool $enable_asset_scraping_detection = false,
        public array $asset_extensions = [],
        public int $asset_no_referer_threshold = 10,
        public int $asset_only_session_threshold = 20,
        public int $asset_pattern_threshold = 100,

        public ?AdapterInterface $adapter = null,
        public ?LoggerInterface $logger = null,
        public ?CacheInterface $cache = null,
        public ?GeoIpInterface $geoip = null,
    ) {}

    public const STRICTNESS_LEVELS = ['monitor-only', 'normal', 'strict'];

    public static function from_file(string $config_file, ?AdapterInterface $adapter = null): self
    {
        $config = SafeConfigLoader::load($config_file, $adapter, 'config_from_file');
        if ($config === null) {
            $config = SafeMode::settings('');
        }
        return self::from_array($config, $adapter);
    }

    public static function from_array(array $config, ?AdapterInterface $adapter = null): self
    {
        $flat_user    = Schema::flatten($config);
        $flat_default = Schema::flatten(self::get_defaults());

        $strictness = $flat_user['strictness'] ?? $flat_default['strictness'] ?? 'normal';
        if (!in_array($strictness, self::STRICTNESS_LEVELS, true)) {
            $strictness = $flat_default['strictness'] ?? 'normal';
        }
        $flat_overrides = Schema::flatten(self::strictness_overrides($strictness));

        $flat = array_merge($flat_default, $flat_overrides, $flat_user);

        $args = [];
        foreach (Schema::KEY_MAP as $dotted => $mapped) {
            $property = str_starts_with($mapped, '_collapsible:') ? null : $mapped;
            if ($property === null) continue;
            if (!array_key_exists($dotted, $flat)) continue;
            $args[$property] = self::coerce_for_property($flat[$dotted], $property, $dotted);
        }

        // === Clamping / range validation ===
        // These were in the legacy code path but not carried over to the
        // schema-driven rewrite. Without them, user input like
        // httpbl_threat=999 or dns_verification_timeout_ms=10 (which would
        // cause every DNS lookup to time out) reach the runtime as-is.

        	if (isset($args['httpbl_threat'])) {
        		$args['httpbl_threat'] = max(0, min(255, (int)$args['httpbl_threat']));
        	}
        	if (isset($args['httpbl_maxage'])) {
        		$args['httpbl_maxage'] = max(0, (int)$args['httpbl_maxage']);
        	}
        	if (isset($args['dns_verification_timeout_ms'])) {
        		$args['dns_verification_timeout_ms'] = max(50, min(2000, (int)$args['dns_verification_timeout_ms']));
        	}
        	if (isset($args['dns_verification_positive_ttl'])) {
        		$args['dns_verification_positive_ttl'] = max(3600, (int)$args['dns_verification_positive_ttl']);
        	}
        	if (isset($args['dns_verification_negative_ttl'])) {
        		$args['dns_verification_negative_ttl'] = max(60, (int)$args['dns_verification_negative_ttl']);
        	}
        	if (isset($args['dynamic_ip_ranges_ttl'])) {
        		$args['dynamic_ip_ranges_ttl'] = max(3600, (int)$args['dynamic_ip_ranges_ttl']);
        	}

        	// Threshold values must be >= 1 (zero would disable the detector entirely)
        	$threshold_props = [
        		'head_flood_threshold',
        		'head_probe_threshold',
        		'asset_no_referer_threshold',
        		'asset_only_session_threshold',
        		'asset_pattern_threshold',
        	];
        	foreach ($threshold_props as $prop) {
        		if (isset($args[$prop])) {
        			$args[$prop] = max(1, (int)$args[$prop]);
        		}
        	}

        	// Rate limits: nested buckets need clamping too
        	if (isset($args['rate_limits']) && is_array($args['rate_limits'])) {
        		foreach (['global', 'per_minute', 'post', 'login'] as $bucket) {
        			if (isset($args['rate_limits'][$bucket])) {
        				if (isset($args['rate_limits'][$bucket]['requests'])) {
        					$args['rate_limits'][$bucket]['requests'] = max(1, (int)$args['rate_limits'][$bucket]['requests']);
        				}
        				if (isset($args['rate_limits'][$bucket]['window'])) {
        					$args['rate_limits'][$bucket]['window'] = max(1, (int)$args['rate_limits'][$bucket]['window']);
        				}
        			}
        		}
        	}

        	// Force the validated strictness (user-provided invalid values
        	// were caught earlier, but $args['strictness'] got populated from
        	// $flat which includes user config — overwrite it here)
        	$args['strictness'] = $strictness;

        // === rate_limits: collapse nested buckets ===
        if (array_key_exists('rate_limits', $config) && is_array($config['rate_limits'])) {
            $args['rate_limits'] = self::normalize_rate_limits($config['rate_limits']);
        } else {
            $rl = [];
            foreach ($flat as $k => $v) {
                if (str_starts_with($k, 'rate_limits.')) {
                    $tail = substr($k, strlen('rate_limits.'));
                    if ($tail !== 'enabled') {
                        $rl[$tail] = $v;
                    }
                }
            }
            if (!empty($rl)) {
                $args['rate_limits'] = self::normalize_rate_limits($rl);
            }
        }

        // === bot_categories: collapse into 4 separate array properties ===
        foreach (['blocked', 'challenge', 'log_only', 'allowed'] as $cat) {
            $key = "bot_categories.$cat";
            if (array_key_exists($key, $flat)) {
                $args["{$cat}_bot_categories"] = self::ensure_array($flat[$key]);
            }
        }
        if (isset($config['bot_categories']) && is_array($config['bot_categories'])) {
            foreach (['blocked', 'challenge', 'log_only', 'allowed'] as $cat) {
                if (isset($config['bot_categories'][$cat])) {
                    $args["{$cat}_bot_categories"] = self::ensure_array($config['bot_categories'][$cat]);
                }
            }
        }

        // === geoip.blocked_countries / blocked_asns: collapse ===
        if (isset($config['geoip']) && is_array($config['geoip'])) {
            if (isset($config['geoip']['blocked_countries'])) {
                $args['blocked_countries'] = self::ensure_array($config['geoip']['blocked_countries']);
            }
            if (isset($config['geoip']['blocked_asns'])) {
                $args['blocked_asns'] = self::ensure_array($config['geoip']['blocked_asns']);
            }
        }
        if (array_key_exists('geoip.blocked_countries', $flat)) {
            $args['blocked_countries'] = self::ensure_array($flat['geoip.blocked_countries']);
        }
        if (array_key_exists('geoip.blocked_asns', $flat)) {
            $args['blocked_asns'] = self::ensure_array($flat['geoip.blocked_asns']);
        }

        // Record unknown keys
        foreach (Schema::unknown_keys($flat_user) as $dotted) {
            Diagnostics::record_unknown_key($dotted, $flat_user[$dotted] ?? null);
        }

        $args['adapter'] = $adapter;
        return new self(...$args);
    }

    /**
     * Coerce a value to match the expected type for a Configuration property.
     *
     * === PURPOSE ===
     *
     * `Configuration::from_array()` reads user-provided values (which may
     * come from bb_config.php, parse_ini_file, or programmatic array
     * construction) and assigns them to typed readonly properties. Without
     * coercion, type mismatches silently produce wrong behavior:
     *
     *   - 'verbose' => 'true'   (string) → bool conversion needed
     *   - '60' (string) for int field   → int conversion needed
     *   - '["foo", "bar"]' for array    → array expected
     *   - ['foo'] for int field         → scalar expected
     *
     * This function normalizes input to the property's expected type and
     * logs a diagnostic warning when the input required coercion.
     *
     * === ARRAY ALLOW-LIST ===
     *
     * Properties whose expected type is `array` MUST appear in $array_props.
     * Arrays for these pass through unchanged. Arrays for properties NOT in
     * this list are coerced (typically with a diagnostic warning) — which
     * is correct for scalar properties but WRONG for array properties.
     *
     * Without the allow-list, an over-defensive branch previously coerced
     * ALL arrays to `[]` when they landed on scalar-typed properties, which
     * ALSO caught legitimate array values destined for array-typed
     * properties that hadn't been added to the allow-list. The result
     * was silent wiping of properties like `skip_static_extensions`,
     * `allowed_ai_crawlers`, `dnsbl_lists`, etc. — a regression that
     * caused asset requests to bypass the static-skip fast path and
     * flood the log table when verbose=true.
     *
     * ADD NEW ARRAY PROPERTIES HERE WHEN ADDING THEM TO THE CONSTRUCTOR.
     *
     * @param mixed  $value     Raw user-provided value
     * @param string $property  Configuration property name (flat form)
     * @param string $dotted    User-facing dotted key (for diagnostics)
     * @return mixed            Value coerced to property's expected type
     */
    private static function coerce_for_property($value, string $property, string $dotted): mixed
    {
    	// === ARRAY ALLOW-LIST ===
    	//
    	// Every array-typed property on Configuration MUST be listed here.
    	// If you add a new array property to the constructor, add it here too.
    	// The schema integrity test (bin/test-config-schema.php) verifies
    	// this list is kept in sync with the constructor signature.
    	static $array_props = [
    		// Reverse proxy
    		'reverse_proxy_addresses',

    		// DNSBL
    		'dnsbl_lists',

    		// AI crawlers
    		'allowed_ai_crawlers',

    		// Bot categories
    		'blocked_bot_categories',
    		'challenge_bot_categories',
    		'log_only_bot_categories',
    		'allowed_bot_categories',

    		// Rate limits
    		'rate_limits',
    		'rate_limits.global',
    		'rate_limits.per_minute',
    		'rate_limits.post',
    		'rate_limits.login',

    		// Custom rules
    		'custom_rules',

    		// Fingerprints
    		'bad_ja3_fingerprints',
    		'bad_h2_fingerprints',
    		'bot_header_orders',
    		'expected_ja3',

    		// GeoIP
    		'blocked_countries',
    		'blocked_asns',

    		// Performance
    		'skip_static_extensions',
    		'skip_static_paths',

    		// Body scan
    		'body_scan_skip_fields',

    		// DNS verification / dynamic IP ranges
    		'dynamic_ip_ranges_feeds',

    		// Head detection
    		'head_referer_exempt_paths',

    		// Asset scraping
    		'asset_extensions',
    	];

    	// === SCALAR ALLOW-LIST ===
    	//
    	// Properties whose expected type is `bool`. Booleans are easy to
    	// get wrong from INI files (where everything is a string), so we
    	// do explicit conversion rather than relying on PHP's loose typing.
    	static $bool_props = [
    		'logging',
    		'verbose',
    		'strict',
    		'offsite_forms',
    		'show_contact_info',
    		'show_detailed_block_page',
    		'reverse_proxy',
    		'dnsbl_enabled',
    		'block_unverified_ai',
    		'strict_ai',
    		'strict_search_engines',
    		'rate_limit_enabled',
    		'geoip_enabled',
    		'challenge_enabled',
    		'enable_fingerprinting',
    		'inspect_json_body',
    		'inspect_multipart_body',
    		'enable_behavioral_analysis',
    		'enable_ai_crawler_control',
    		'enable_client_hints_validation',
    		'enable_agentic_detection',
    		'dns_verification_enabled',
    		'dns_verification_require_forward_confirm',
    		'dynamic_ip_ranges_enabled',
    		'enable_head_request_detection',
    		'head_require_referer',
    		'enable_asset_scraping_detection',
    	];

    	// Properties whose expected type is `int`.
    	static $int_props = [
    		'httpbl_threat',
    		'httpbl_maxage',
    		'dns_verification_timeout_ms',
    		'dns_verification_positive_ttl',
    		'dns_verification_negative_ttl',
    		'dynamic_ip_ranges_ttl',
    		'head_flood_threshold',
    		'head_probe_threshold',
    		'asset_no_referer_threshold',
    		'asset_only_session_threshold',
    		'asset_pattern_threshold',
    	];

    	// Properties whose expected type is `float`.
    	static $float_props = [
    		'recaptcha_min_score',
    	];

    	// Properties whose expected type is `string`.
    	static $string_props = [
    		'log_table',
    		'strictness',
    		'preset',
    		'reverse_proxy_header',
    		'httpbl_key',
    		'challenge_provider',
    		'challenge_site_key',
    		'challenge_secret_key',
    		'geoip_database_path',
    	];

    	// === ARRAY HANDLING ===
    	if (is_array($value)) {
    		// Known array property: pass through unchanged
    		if (in_array($property, $array_props, true)) {
    			return $value;
    		}

    		// Arrays NOT in the allow-list: this is a type mismatch.
    		//
    		// Before the fix, the previous implementation had an
    		// "over-defensive" branch that coerced ALL arrays to `[]`
    		// when landing on scalar-typed properties. That branch also
    		// caught array-typed properties that weren't on the allow-list,
    		// silently wiping them to empty. That's the bug we are fixing.
    		//
    		// Now: log a diagnostic warning (once per property per process)
    		// and return `[]`. Caller decides whether to fall back to
    		// defaults via the `?? self::default_skip_extensions()` pattern.
    		self::warn_coercion(
    			property: $property,
    			dotted: $dotted,
    			actual_type: 'array',
    			expected_type: in_array($property, $bool_props, true) ? 'bool' :
    			(in_array($property, $int_props, true) ? 'int' :
    				(in_array($property, $float_props, true) ? 'float' :
    					(in_array($property, $string_props, true) ? 'string' : 'unknown'))),
    			);

    		// Try to extract a sensible scalar from the array
    		if ($value === []) {
    			return match (true) {
    				in_array($property, $bool_props, true)   => false,
    				in_array($property, $int_props, true)    => 0,
    				in_array($property, $float_props, true)  => 0.0,
    				in_array($property, $string_props, true)  => '',
    				default                                  => null,
    			};
    		}
    		// Non-empty array: take first element
    		$first = reset($value);
    		return self::coerce_for_property($first, $property, $dotted);
    	}

    	// === BOOL HANDLING ===
    	if (in_array($property, $bool_props, true)) {
    		// Accept: bool, int (0/1), string ("true"/"false"/"1"/"0"/"yes"/"no"/"on"/"off"),
    		// null (→ false)
    		if ($value === null) {
    			return false;
    		}
    		if (is_bool($value)) {
    			return $value;
    		}
    		if (is_int($value) || is_float($value)) {
    			return (bool)$value;
    		}
    		if (is_string($value)) {
    			$normalized = strtolower(trim($value));
    			return match ($normalized) {
    				'true', '1', 'yes', 'on', 'enabled'  => true,
    				'false', '0', 'no', 'off', 'disabled', '' => false,
    				default => self::warn_coercion_and_return(
    					property: $property,
    					dotted: $dotted,
    					actual_type: 'string',
    					expected_type: 'bool',
    					actual_value: $value,
    					fallback: false,
    					),
    			};
    		}
    		// Unknown type: warn and return false
    		return self::warn_coercion_and_return(
    			property: $property,
    			dotted: $dotted,
    			actual_type: get_debug_type($value),
    			expected_type: 'bool',
    			actual_value: $value,
    			fallback: false,
    			);
    	}

    	// === INT HANDLING ===
    	if (in_array($property, $int_props, true)) {
    		if ($value === null || $value === '') {
    			return 0;
    		}
    		if (is_int($value)) {
    			return $value;
    		}
    		if (is_bool($value)) {
    			return $value ? 1 : 0;
    		}
    		if (is_float($value)) {
    			return (int)$value;
    		}
    		if (is_string($value)) {
    			// Numeric strings like "60" or "1000"
    			if (is_numeric($value)) {
    				return (int)$value;
    			}
    			return self::warn_coercion_and_return(
    				property: $property,
    				dotted: $dotted,
    				actual_type: 'string',
    				expected_type: 'int',
    				actual_value: $value,
    				fallback: 0,
    				);
    		}
    		return self::warn_coercion_and_return(
    			property: $property,
    			dotted: $dotted,
    			actual_type: get_debug_type($value),
    			expected_type: 'int',
    			actual_value: $value,
    			fallback: 0,
    			);
    	}

    	// === FLOAT HANDLING ===
    	if (in_array($property, $float_props, true)) {
    		if ($value === null || $value === '') {
    			return 0.0;
    		}
    		if (is_float($value)) {
    			return $value;
    		}
    		if (is_int($value) || is_bool($value)) {
    			return (float)$value;
    		}
    		if (is_string($value)) {
    			if (is_numeric($value)) {
    				return (float)$value;
    			}
    			return self::warn_coercion_and_return(
    				property: $property,
    				dotted: $dotted,
    				actual_type: 'string',
    				expected_type: 'float',
    				actual_value: $value,
    				fallback: 0.0,
    				);
    		}
    		return self::warn_coercion_and_return(
    			property: $property,
    			dotted: $dotted,
    			actual_type: get_debug_type($value),
    			expected_type: 'float',
    			actual_value: $value,
    			fallback: 0.0,
    			);
    	}

    	// === STRING HANDLING ===
    	if (in_array($property, $string_props, true)) {
    		if ($value === null) {
    			return '';
    		}
    		if (is_string($value)) {
    			return $value;
    		}
    		if (is_bool($value) || is_int($value) || is_float($value)) {
    			// Numeric/boolean → string (e.g., "1" → "1")
    			return (string)$value;
    		}
    		return self::warn_coercion_and_return(
    			property: $property,
    			dotted: $dotted,
    			actual_type: get_debug_type($value),
    			expected_type: 'string',
    			actual_value: $value,
    			fallback: '',
    			);
    	}

    	// === UNKNOWN PROPERTY (not in any allow-list) ===
    	//
    	// This should not happen — every Configuration property must be in
    	// one of the allow-lists above. If we reach here, either:
    	//   (a) a new property was added to the constructor without
    	//       updating the allow-lists in this function, OR
    	//   (b) the schema KEY_MAP references a property that doesn't
    	//       exist on Configuration.
    	//
    	// Log a diagnostic warning (once per property) and return the
    	// value as-is. This is safer than throwing, because throwing
    	// during config parsing would crash the host application on a
    	// missing allow-list entry.
    	self::warn_unknown_property($property, $dotted);

    	return $value;
    }

    /**
     * Log a coercion warning. Once per (property, dotted) tuple per process.
     */
    private static function warn_coercion(
    	string $property,
    	string $dotted,
    	string $actual_type,
    	string $expected_type,
    	): void {
    		static $warned = [];
    		$key = "coercion:{$property}";
    		if (isset($warned[$key])) return;
    		$warned[$key] = true;

    		try {
    			ErrorReporter::warning(
    				null,
    				'Configuration: type coercion applied',
    				[
    					'property'      => $property,
    					'dotted_key'    => $dotted,
    					'actual_type'   => $actual_type,
    					'expected_type' => $expected_type,
    					'hint'          => "If '{$property}' is supposed to be an array, "
    					. "add it to coerce_for_property() \$array_props allow-list. "
    						. "If it's supposed to be scalar, fix the user config to use "
    							. "the right type (e.g., 'true' instead of '[true]').",
    							],
    							"config_coercion_{$property}"
    							);
    		} catch (\Throwable $e) {
    			// ErrorReporter failure must not break config parsing
    		}
    }

    /**
     * Log a coercion warning AND return a fallback value.
     * Convenience wrapper for the common "warn + return default" pattern.
     */
    private static function warn_coercion_and_return(
    	string $property,
    	string $dotted,
    	string $actual_type,
    	string $expected_type,
    	mixed $actual_value,
    	mixed $fallback,
    	): mixed {
    		// Truncate long values for log readability
    		$display_value = is_scalar($actual_value) ? (string)$actual_value : get_debug_type($actual_value);
    		if (strlen($display_value) > 100) {
    			$display_value = substr($display_value, 0, 100) . '...';
    		}

    		static $warned = [];
    		$key = "coercion:{$property}";
    		if (!isset($warned[$key])) {
    			$warned[$key] = true;
    			try {
    				ErrorReporter::warning(
    					null,
    					'Configuration: type coercion applied',
    					[
    						'property'      => $property,
    						'dotted_key'    => $dotted,
    						'actual_type'   => $actual_type,
    						'expected_type' => $expected_type,
    						'actual_value'  => $display_value,
    						'fallback'      => $fallback,
    						'hint'          => "Coerced value to {$expected_type}, returning fallback",
    						],
    						"config_coercion_{$property}"
    						);
    			} catch (\Throwable $e) {
    				// ignore
    			}
    		}

    		return $fallback;
    }

    /**
     * Log a warning for properties not in any allow-list.
     */
    private static function warn_unknown_property(string $property, string $dotted): void
    {
    	static $warned = [];
    	$key = "unknown:{$property}";
    	if (isset($warned[$key])) return;
    	$warned[$key] = true;

    	try {
    		ErrorReporter::error(
    			null,
    			'Configuration: property not in any allow-list',
    			[
    				'property'   => $property,
    				'dotted_key' => $dotted,
    				'hint'       => "Add '{$property}' to coerce_for_property()'s "
    				. "\$bool_props/\$int_props/\$float_props/\$string_props allow-list. "
    					. "This is a developer error — every Configuration property must be listed.",
    					],
    					"config_unknown_property_{$property}"
    					);
    	} catch (\Throwable $e) {
    		// ignore
    	}
    }

    public static function strictness_overrides(?string $strictness = null): array
    {
        return match ($strictness ?? 'normal') {

            'monitor-only' => [
                'dns_verification' => [
                    'enabled' => false,
                    'require_forward_confirm' => false,
                    'negative_ttl' => 3600,
                ],
                'dynamic_ip_ranges' => ['enabled' => false, 'feeds' => []],
                'dnsbl' => ['enabled' => false, 'lists' => []],
                'ai_crawlers' => ['allowed' => [], 'block_unverified' => false, 'strict' => false],
                'rate_limits' => ['enabled' => false],
                'geoip' => ['enabled' => false],
                'challenge' => ['enabled' => false],

                'enable_fingerprinting'           => false,
                'enable_behavioral_analysis'      => false,
                'enable_client_hints_validation'  => false,
                'enable_agentic_detection'        => false,
                'enable_head_request_detection'   => false,
                'enable_asset_scraping_detection' => false,
                'strict_search_engines'           => false,
            ],

            'normal' => [
                'dns_verification' => [
                    'enabled' => true,
                    'require_forward_confirm' => false,
                    'negative_ttl' => 3600,
                ],
                'dynamic_ip_ranges' => ['enabled' => true],
                'dnsbl' => ['enabled' => false, 'lists' => ['zen.spamhaus.org', 'bl.spamcop.net']],
                'ai_crawlers' => [
                    'allowed' => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
                    'block_unverified' => false,
                    'strict' => false,
                ],
                'rate_limits' => [
                    'enabled' => true,
                    'global' => ['requests' => 1000, 'window' => 3600],
                    'per_minute' => ['requests' => 60, 'window' => 60],
                ],

                'enable_fingerprinting'           => false,
                'enable_behavioral_analysis'      => false,
                'enable_client_hints_validation'  => false,
                'enable_agentic_detection'        => false,
                'enable_head_request_detection'   => false,
                'enable_asset_scraping_detection' => false,
                'strict_search_engines'           => false,
            ],

            'strict' => [
                'dns_verification' => [
                    'enabled' => true,
                    'require_forward_confirm' => true,
                    'positive_ttl' => 2592000,
                    'negative_ttl' => 86400,
                ],
                'dynamic_ip_ranges' => ['enabled' => true],
                'dnsbl' => ['enabled' => true, 'lists' => ['zen.spamhaus.org', 'bl.spamcop.net']],
                'ai_crawlers' => [
                    'allowed' => [],
                    'block_unverified' => true,
                    'strict' => true,
                ],
                'rate_limits' => [
                    'enabled' => true,
                    'global' => ['requests' => 500, 'window' => 3600],
                    'per_minute' => ['requests' => 30, 'window' => 60],
                ],

                'enable_fingerprinting'           => true,
                'enable_behavioral_analysis'      => true,
                'enable_client_hints_validation'  => true,
                'enable_agentic_detection'        => true,
                'enable_head_request_detection'   => true,
                'enable_asset_scraping_detection' => true,
                'strict_search_engines'           => true,
            ],

            default => [],
        };
    }

    public static function get_defaults(): array
    {
        return [
            'preset'        => 'minimal',
            'strictness'    => 'normal',
            'logging'       => true,
            'verbose'       => false,
            'strict'        => false,
            'offsite_forms' => false,
            'show_contact_info'        => false,
            'show_detailed_block_page' => false,

            'reverse_proxy' => ['enabled' => false, 'header' => 'X-Forwarded-For', 'addresses' => []],
            'httpbl' => ['key' => '', 'threat' => 25, 'maxage' => 30],
            'dnsbl'  => ['enabled' => false, 'lists' => ['zen.spamhaus.org', 'bl.spamcop.net']],
            'ai_crawlers' => [
                'allowed' => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
                'block_unverified' => false,
                'strict' => false,
            ],
            'strict_search_engines' => false,

            'bot_categories' => ['blocked' => [], 'challenge' => [], 'log_only' => [], 'allowed' => []],

            'rate_limits' => [
                'enabled' => false,
                'global' => ['requests' => 1000, 'window' => 3600],
                'per_minute' => ['requests' => 60, 'window' => 60],
                'post' => ['requests' => 30, 'window' => 3600],
                'login' => ['requests' => 10, 'window' => 900],
            ],

            'custom_rules' => [],
            'fingerprints' => [
                'bad_ja3' => [], 'bad_h2' => [], 'bot_header_orders' => [], 'expected_ja3' => [],
            ],
            'geoip' => [
                'enabled' => false, 'database_path' => '',
                'blocked_countries' => [], 'blocked_asns' => [],
            ],
            'challenge' => [
                'enabled' => false, 'provider' => 'builtin',
                'site_key' => '', 'secret_key' => '', 'recaptcha_min_score' => 0.5,
            ],
            'performance' => [
                'skip_extensions' => self::default_skip_extensions(),
                'skip_paths' => self::default_skip_paths(),
            ],
            'body_scan_skip_fields' => [
                'body', 'comment', 'content', 'text', 'message', 'description',
                'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
                'article', 'page', 'entry', 'reply', 'review', 'feedback',
            ],

            'enable_fingerprinting'           => false,
            'inspect_json_body'               => false,
            'inspect_multipart_body'          => false,
            'enable_behavioral_analysis'      => false,
            'enable_ai_crawler_control'       => true,
            'enable_client_hints_validation'  => false,
            'enable_agentic_detection'        => false,

            'dns_verification' => [
                'enabled' => true, 'timeout_ms' => 300,
                'require_forward_confirm' => false,
                'positive_ttl' => 604800, 'negative_ttl' => 3600,
            ],
            'dynamic_ip_ranges' => [
                'enabled' => false, 'ttl' => 86400,
                'feeds' => ['aws', 'cloudflare', 'fastly', 'gcp'],
            ],

            'enable_head_request_detection'   => false,
            'head_require_referer'            => false,
            'head_flood_threshold'            => 20,
            'head_probe_threshold'            => 50,
            'head_referer_exempt_paths'       => ['/api/', '/wp-json/', '/health', '/status'],

            'enable_asset_scraping_detection' => false,
            'asset_extensions' => [
                'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
                'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                'mp3', 'mp4', 'wav', 'ogg', 'webm',
            ],
            'asset_no_referer_threshold'   => 10,
            'asset_only_session_threshold' => 20,
            'asset_pattern_threshold'      => 100,
        ];
    }

    public function get_strictness(): string { return $this->strictness; }
    public function get_preset(): string     { return $this->preset; }

    public function to_array(): array
    {
        return [
            'preset'      => $this->preset,
            'strictness'  => $this->strictness,
            'logging'     => $this->logging,
            'verbose'     => $this->verbose,
            'strict'      => $this->strict,
            'offsite_forms' => $this->offsite_forms,
            'show_contact_info' => $this->show_contact_info,
            'show_detailed_block_page' => $this->show_detailed_block_page,
            'log_table'   => $this->log_table,

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
            'strict_search_engines' => $this->strict_search_engines,

            'bot_categories' => [
                'blocked' => $this->blocked_bot_categories,
                'challenge' => $this->challenge_bot_categories,
                'log_only' => $this->log_only_bot_categories,
                'allowed' => $this->allowed_bot_categories,
            ],

            'rate_limits' => array_merge(
                ['enabled' => $this->rate_limit_enabled],
                $this->rate_limits
            ),

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
            'body_scan_skip_fields' => $this->body_scan_skip_fields,

            'enable_fingerprinting'           => $this->enable_fingerprinting,
            'inspect_json_body'               => $this->inspect_json_body,
            'inspect_multipart_body'          => $this->inspect_multipart_body,
            'enable_behavioral_analysis'      => $this->enable_behavioral_analysis,
            'enable_ai_crawler_control'       => $this->enable_ai_crawler_control,
            'enable_client_hints_validation'  => $this->enable_client_hints_validation,
            'enable_agentic_detection'        => $this->enable_agentic_detection,

            'dns_verification' => [
                'enabled' => $this->dns_verification_enabled,
                'timeout_ms' => $this->dns_verification_timeout_ms,
                'require_forward_confirm' => $this->dns_verification_require_forward_confirm,
                'positive_ttl' => $this->dns_verification_positive_ttl,
                'negative_ttl' => $this->dns_verification_negative_ttl,
            ],
            'dynamic_ip_ranges' => [
                'enabled' => $this->dynamic_ip_ranges_enabled,
                'ttl' => $this->dynamic_ip_ranges_ttl,
                'feeds' => $this->dynamic_ip_ranges_feeds,
            ],

            'enable_head_request_detection'   => $this->enable_head_request_detection,
            'head_require_referer'            => $this->head_require_referer,
            'head_flood_threshold'            => $this->head_flood_threshold,
            'head_probe_threshold'            => $this->head_probe_threshold,
            'head_referer_exempt_paths'       => $this->head_referer_exempt_paths,

            'enable_asset_scraping_detection' => $this->enable_asset_scraping_detection,
            'asset_extensions'                => $this->asset_extensions,
            'asset_no_referer_threshold'      => $this->asset_no_referer_threshold,
            'asset_only_session_threshold'    => $this->asset_only_session_threshold,
            'asset_pattern_threshold'         => $this->asset_pattern_threshold,
        ];
    }

    private static function ensure_array(mixed $value, array $default = []): array
    {
        if (is_array($value)) return $value;
        if (is_string($value) && $value !== '') {
            return preg_split('/\s*,\s*/', $value);
        }
        return $default;
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

                // === CLAMPING (moved here so it's guaranteed to run) ===
                if (isset($limits[$name]['requests'])) {
                	$limits[$name]['requests'] = max(1, (int)$limits[$name]['requests']);
                }
                if (isset($limits[$name]['window'])) {
                	$limits[$name]['window'] = max(1, (int)$limits[$name]['window']);
                }
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
}