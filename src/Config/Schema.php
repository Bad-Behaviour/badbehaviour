<?php
declare(strict_types=1);

namespace BadBehaviour\Config;

/**
 * Canonical schema mapping.
 */
final class Schema
{
	/**
	 * Canonical schema mapping between user-facing config keys (dotted path)
	 * and Configuration readonly properties.
	 *
	 * Single source of truth — every parse, serialize, validate, default,
	 * and override operation goes through this table. Adding a new config
	 * key means adding one row here and the matching constructor parameter
	 * in Configuration. That's it.
	 *
	 * === KEY FORMAT ===
	 *
	 *   'dotted.path' => 'property_name'
	 *
	 *   - dotted.path: the user-facing key (always NESTED form, e.g.
	 *                  'dynamic_ip_ranges.enabled')
	 *   - property_name: the Configuration property (always flat/typed)
	 *
	 * === WHY DOTTED KEYS ===
	 *
	 * The user-facing format has always been nested (matching the INI
	 * sections it was ported from). The internal properties are flat
	 * because PHP constructor parameters can't be nested. The dotted-key
	 * format bridges the two unambiguously — flat properties get exactly
	 * one dotted-key entry, nested config keys always round-trip through
	 * flatten() / nest() without ambiguity.
	 */

    /**
     * User-facing config key (dotted path) → Configuration property name.
     *
     * Sub-keys of arrays (rate_limits.*, bot_categories.*, etc.) are
     * marked with special property names starting with `_` to indicate
     * they're collapsed into a parent array property, not mapped to
     * individual constructor params.
     *
     * @var array<string, string>
     */
    public const KEY_MAP = [
        // === Meta ===
        'preset'                                 => 'preset',
        'strictness'                             => 'strictness',

        // === Core ===
        'logging'                                => 'logging',
        'verbose'                                => 'verbose',
        'strict'                                 => 'strict',
        'offsite_forms'                          => 'offsite_forms',
        'log_table'                              => 'log_table',
        'show_contact_info'                      => 'show_contact_info',
        'show_detailed_block_page'               => 'show_detailed_block_page',

        // === Reverse proxy ===
        'reverse_proxy.enabled'                  => 'reverse_proxy',
        'reverse_proxy.header'                   => 'reverse_proxy_header',
        'reverse_proxy.addresses'                => 'reverse_proxy_addresses',

        // === http:BL ===
        'httpbl.key'                             => 'httpbl_key',
        'httpbl.threat'                          => 'httpbl_threat',
        'httpbl.maxage'                          => 'httpbl_maxage',

        // === DNSBL ===
        'dnsbl.enabled'                          => 'dnsbl_enabled',
        'dnsbl.lists'                            => 'dnsbl_lists',

        // === AI crawlers ===
        'ai_crawlers.allowed'                    => 'allowed_ai_crawlers',
        'ai_crawlers.block_unverified'           => 'block_unverified_ai',
        'ai_crawlers.strict'                     => 'strict_ai',
        'strict_search_engines'                  => 'strict_search_engines',

        // === Bot categories (collapsed into one array property each) ===
        'bot_categories.blocked'                 => '_collapsible:blocked_bot_categories',
        'bot_categories.challenge'               => '_collapsible:challenge_bot_categories',
        'bot_categories.log_only'                => '_collapsible:log_only_bot_categories',
        'bot_categories.allowed'                 => '_collapsible:allowed_bot_categories',

        // === Rate limits ===
        // The enabled flag is a top-level property; sub-buckets collapse
        // into the rate_limits array via normalize_rate_limits().
        'rate_limits.enabled'                    => 'rate_limit_enabled',
        'rate_limits.global.requests'            => '_collapsible:rate_limits.global.requests',
        'rate_limits.global.window'              => '_collapsible:rate_limits.global.window',
        'rate_limits.per_minute.requests'        => '_collapsible:rate_limits.per_minute.requests',
        'rate_limits.per_minute.window'          => '_collapsible:rate_limits.per_minute.window',
        'rate_limits.post.requests'              => '_collapsible:rate_limits.post.requests',
        'rate_limits.post.window'                => '_collapsible:rate_limits.post.window',
        'rate_limits.login.requests'             => '_collapsible:rate_limits.login.requests',
        'rate_limits.login.window'               => '_collapsible:rate_limits.login.window',

        // === Custom rules ===
        'custom_rules'                           => 'custom_rules',

        // === Fingerprints ===
        'fingerprints.bad_ja3'                   => 'bad_ja3_fingerprints',
        'fingerprints.bad_h2'                    => 'bad_h2_fingerprints',
        'fingerprints.bot_header_orders'         => 'bot_header_orders',
        'fingerprints.expected_ja3'              => 'expected_ja3',

        // === GeoIP ===
        'geoip.enabled'                          => 'geoip_enabled',
        'geoip.database_path'                    => 'geoip_database_path',
        'geoip.blocked_countries'                => '_collapsible:geoip.blocked_countries',
        'geoip.blocked_asns'                     => '_collapsible:geoip.blocked_asns',

        // === Challenge ===
        'challenge.enabled'                      => 'challenge_enabled',
        'challenge.provider'                     => 'challenge_provider',
        'challenge.site_key'                     => 'challenge_site_key',
        'challenge.secret_key'                   => 'challenge_secret_key',
        'challenge.recaptcha_min_score'          => 'recaptcha_min_score',

        // === Performance ===
        'performance.skip_extensions'            => 'skip_static_extensions',
        'performance.skip_paths'                 => 'skip_static_paths',

        // === Body scan ===
        'body_scan_skip_fields'                  => 'body_scan_skip_fields',

        // === 3.0 feature flags ===
        'enable_fingerprinting'                  => 'enable_fingerprinting',
        'inspect_json_body'                      => 'inspect_json_body',
        'inspect_multipart_body'                 => 'inspect_multipart_body',
        'enable_behavioral_analysis'             => 'enable_behavioral_analysis',
        'enable_client_hints_validation'         => 'enable_client_hints_validation',
        'enable_agentic_detection'               => 'enable_agentic_detection',

        // === DNS verification ===
        'dns_verification.enabled'               => 'dns_verification_enabled',
        'dns_verification.timeout_ms'            => 'dns_verification_timeout_ms',
        'dns_verification.require_forward_confirm' => 'dns_verification_require_forward_confirm',
        'dns_verification.positive_ttl'          => 'dns_verification_positive_ttl',
        'dns_verification.negative_ttl'          => 'dns_verification_negative_ttl',

        // === Dynamic IP ranges ===
        'dynamic_ip_ranges.enabled'              => 'dynamic_ip_ranges_enabled',
        'dynamic_ip_ranges.ttl'                  => 'dynamic_ip_ranges_ttl',
        'dynamic_ip_ranges.feeds'                => 'dynamic_ip_ranges_feeds',

    	// === On-demand IP range refresh ===
    	'on_demand_ip_refresh.enabled'                => 'on_demand_ip_refresh_enabled',
    	'on_demand_ip_refresh.probability_denominator'=> 'on_demand_ip_refresh_probability_denominator',
    	'on_demand_ip_refresh.min_age_seconds'        => 'on_demand_ip_refresh_min_age_seconds',
    	'on_demand_ip_refresh.lock_ttl'               => 'on_demand_ip_refresh_lock_ttl',
    	'on_demand_ip_refresh.cache_ttl'              => 'on_demand_ip_refresh_cache_ttl',
    	'on_demand_ip_refresh.feed_timeout_seconds'   => 'on_demand_ip_refresh_feed_timeout_seconds',
    	'on_demand_ip_refresh.bot_ids'                => '_collapsible:on_demand_ip_refresh.bot_ids',
    	'on_demand_ip_refresh.cloud_providers'        => '_collapsible:on_demand_ip_refresh.cloud_providers',

        // === Head detection ===
        'enable_head_request_detection'          => 'enable_head_request_detection',
        'head_require_referer'                   => 'head_require_referer',
        'head_flood_threshold'                   => 'head_flood_threshold',
        'head_probe_threshold'                   => 'head_probe_threshold',
        'head_referer_exempt_paths'              => 'head_referer_exempt_paths',

        // === Asset scraping ===
        'enable_asset_scraping_detection'        => 'enable_asset_scraping_detection',
        'asset_extensions'                       => 'asset_extensions',
        'asset_no_referer_threshold'             => 'asset_no_referer_threshold',
        'asset_only_session_threshold'           => 'asset_only_session_threshold',
        'asset_pattern_threshold'                => 'asset_pattern_threshold',

        // === Log retention ===
    	'log_retention.enabled'                 => 'log_retention_enabled',
    	'log_retention.max_age_days'            => 'log_retention_max_age_days',
    	'log_retention.max_rows'                => 'log_retention_max_rows',
    	'log_retention.probability_denominator' => 'log_retention_probability_denominator',
    	'log_retention.min_interval_seconds'    => 'log_retention_min_interval_seconds',
    	'log_retention.lock_ttl'                => 'log_retention_lock_ttl',
    ];

    /**
     * Flatten nested array into dotted-key form.
     * Empty arrays stay at the parent level (don't get recursed).
     *
     * @param array<string, mixed> $nested
     * @return array<string, mixed>
     */
    public static function flatten(array $nested): array
    {
        $out = [];
        foreach ($nested as $key => $value) {
            if (is_array($value) && !self::is_list($value) && !empty($value)) {
                foreach (self::flatten($value) as $subkey => $subvalue) {
                    $out["{$key}.{$subkey}"] = $subvalue;
                }
            } else {
                $out[$key] = $value;
            }
        }
        return $out;
    }

    /**
     * Inverse: dotted-key → nested.
     *
     * @param array<string, mixed> $flat
     * @return array<string, mixed>
     */
    public static function nest(array $flat): array
    {
        $out = [];
        foreach ($flat as $key => $value) {
            if (!is_string($key) || !str_contains($key, '.')) {
                $out[$key] = $value;
                continue;
            }
            $segments = explode('.', $key);
            $cursor = &$out;
            $last = count($segments) - 1;
            foreach ($segments as $i => $seg) {
                if ($i === $last) {
                    $cursor[$seg] = $value;
                } else {
                    if (!isset($cursor[$seg]) || !is_array($cursor[$seg])) {
                        $cursor[$seg] = [];
                    }
                    $cursor = &$cursor[$seg];
                }
            }
            unset($cursor);
        }
        return $out;
    }

    /**
     * @return string[]
     */
    public static function known_keys(): array
    {
        return array_keys(self::KEY_MAP);
    }

    /**
     * @param array<string, mixed> $flat
     * @return string[]
     */
    public static function unknown_keys(array $flat): array
    {
        return array_diff(array_keys($flat), self::known_keys());
    }

    /**
     * Resolve a dotted key to its constructor property name.
     * Returns null for collapsible sub-keys (they collapse into parent arrays).
     */
    public static function property_for(string $dotted): ?string
    {
        $mapped = self::KEY_MAP[$dotted] ?? null;
        if ($mapped === null) return null;
        if (str_starts_with($mapped, '_collapsible:')) return null;
        return $mapped;
    }

    private static function is_list(array $array): bool
    {
        if ($array === []) return true;
        return array_is_list($array);
    }
}
