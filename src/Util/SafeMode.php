<?php

declare(strict_types=1);

namespace BadBehaviour\Util;

use BadBehaviour\Configuration;

/**
 * Centralized safe-mode configuration.
 *
 * "Safe-mode" is the fallback behavior when BadBehaviour is misconfigured
 * (missing/invalid bb_config.php, broken registry, etc). In safe-mode:
 *
 *   - Logging remains ON (so traffic is still observable)
 *   - All active defenses are OFF (no blocking, no challenging, no rate limits)
 *   - Network-touching features are OFF (no DNS lookups, no http:BL, no DNSBL)
 *   - Static-skip is preserved (assets never reach detection even in degraded mode)
 *
 * This ensures that BadBehaviour never causes the host application to break,
 * regardless of configuration state.
 *
 * === SINGLE SOURCE OF TRUTH ===
 *
 * SafeMode::settings() derives from Configuration::get_defaults() so the
 * two arrays can never drift apart. When a new config key is added to
 * Configuration::get_defaults(), safe-mode automatically inherits the
 * default value — the developer only needs to override keys that must
 * behave differently in safe-mode.
 *
 * === KEY SHAPE ===
 *
 * SAFE_MODE_OVERRIDES uses NESTED keys (matching Configuration::get_defaults()
 * and the user-facing bb_config.php format). Configuration::from_array()
 * reads nested keys, so flat keys in this map would be silently ignored.
 *
 * The keyset returned here MUST match the keys consumed by
 * `BadBehaviour\Configuration::from_array()`. When adding new fields
 * to Configuration, mirror them there.
 */
final class SafeMode
{
	/**
	 * Keys that must differ from the normal default in safe-mode.
	 *
	 * Uses NESTED keys to match Configuration::get_defaults() and
	 * Configuration::from_array() expectations. Flat keys here are
	 * silently ignored by from_array(), making the override a no-op.
	 *
	 * Why each is overridden:
	 *
	 *   - All `enable_*_detection` keys → OFF (no user intent known)
	 *   - `dns_verification.enabled` → OFF (network-dependent, dangerous)
	 *   - `dynamic_ip_ranges.enabled` → OFF (catastrophic if feeds unreachable)
	 *   - `head_require_referer` → OFF (could silently break REST API clients)
	 *   - `bot_categories` (all sub-keys) → empty (no user intent)
	 *   - `custom_rules` → empty (no user intent)
	 *   - `rate_limits.enabled` → false (no rate limiting in degraded mode)
	 *   - `reverse_proxy.enabled` → false (can't trust forwarded headers)
	 *   - `geoip.enabled` → false (no database, no point)
	 *   - `challenge.enabled` → false (no captcha in degraded mode)
	 *   - `dnsbl.enabled` → false (network-dependent)
	 *   - `httpbl.key` → '' (no API key, can't verify)
	 *   - `ai_crawlers.strict` → false, `block_unverified` → false
	 *
	 * Performance/static-skip defaults are INHERITED — safe-mode must still
	 * skip static assets to avoid log flooding with verbose=true.
	 *
	 * @var array<string, mixed>
	 */
	private const SAFE_MODE_OVERRIDES = [
		// === All active defenses OFF (flat boolean properties) ===

		// === Reverse proxy — disabled ===
		// Without operator config, we don't know which header to trust
		// or which addresses are legitimate proxies. Enabling this with
		// wrong settings could let attackers spoof their IP.
		'reverse_proxy' => [
			'enabled'   => false,
			'header'	=> 'X-Forwarded-For',
			'addresses' => [],
		],

		// === http:BL — disabled (no API key) ===
		'httpbl' => [
			'key'	=> '',
			'threat' => 25,
			'maxage' => 30,
		],

		// === DNSBL — disabled ===
		'dnsbl' => [
			'enabled' => false,
			'lists'   => [],
		],

		// === AI crawlers — no special access, no aggressive blocking ===
		'ai_crawlers' => [
			'allowed'		  => [],
			'block_unverified' => false,
			'strict'		   => false,
		],

		// === Bot categories — all empty ===
		// Defaults are also empty, but explicit here for clarity.
		'bot_categories' => [
			'blocked'   => [],
			'challenge' => [],
			'log_only'  => [],
			'allowed'   => [],
		],

		// === Rate limits — disabled, safe defaults preserved ===
		'rate_limits' => [
			'enabled'	 => false,
			'global'	  => ['requests' => 1000, 'window' => 3600],
			'per_minute'  => ['requests' => 60,   'window' => 60],
			'post'		=> ['requests' => 30,   'window' => 3600],
			'login'	   => ['requests' => 10,   'window' => 900],
		],

		// === Custom rules — empty (no user intent known) ===
		'custom_rules' => [],

		// === GeoIP — disabled ===
		'geoip' => [
			'enabled'		   => false,
			'database_path'	 => '',
			'blocked_countries' => [],
			'blocked_asns'	  => [],
		],

		// === Challenge — disabled ===
		'challenge' => [
			'enabled'			 => false,
			'provider'			=> 'builtin',
			'site_key'			=> '',
			'secret_key'		  => '',
			'recaptcha_min_score' => 0.5,
		],


		// === DNS verification — disabled (network-dependent) ===
		'dns_verification' => [
			'enabled'				 => false,
			'timeout_ms'			  => 300,
			'require_forward_confirm' => false,
			'positive_ttl'			=> 604800,
			'negative_ttl'			=> 3600,
		],

		// === Dynamic IP ranges — disabled ===
		'dynamic_ip_ranges' => [
			'enabled' => false,
			'ttl'	 => 86400,
			'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
		],

		// === Head detection — don't require Referer ===
		'head_require_referer'	  => false,

		// === Performance / static skip — INHERITED from defaults ===
		// Intentionally NOT overridden. Safe-mode MUST still skip static
		// assets. If this were overridden to empty, verbose logging
		// would flood the log with INSERTs for every CSS/JS/image
		// request, causing SQLite lock contention. See Test 15 in
		// bin/test-config-schema.php for the regression guard.

		// === Body scan skip fields — inherited from defaults ===
	];

	/**
	 * Return a safe-mode settings array.
	 *
	 * Derived from Configuration::get_defaults() with the SAFE_MODE_OVERRIDES
	 * applied on top. Then injects adapter-specific log_table and the
	 * internal _safe_mode marker.
	 *
	 * @param string $log_table Adapter-specific log table name (with prefix).
	 * @return array<string, mixed>
	 */
	public static function settings(string $log_table): array
	{
		$base = Configuration::get_defaults();
		$merged = array_merge($base, self::SAFE_MODE_OVERRIDES);

		// Adapter-specific injection (cannot come from defaults).
		$merged['log_table'] = $log_table;

		// Internal marker for diagnostics(). Not part of the public
		// Configuration surface — kept out of SAFE_MODE_OVERRIDES so it
		// doesn't appear in Schema validation.
		$merged['_safe_mode'] = true;

		return $merged;
	}

	/**
	 * Merge adapter-specific overrides on top of safe-mode base.
	 *
	 * @param array<string, mixed> $base Safe-mode settings (from settings())
	 * @param array<string, mixed> $overrides Adapter-specific overrides
	 * @return array<string, mixed>
	 */
	public static function merge(array $base, array $overrides): array
	{
		return array_merge($base, $overrides);
	}

	/**
	 * Return the list of keys that differ between normal defaults and safe-mode.
	 *
	 * @return array<string, mixed>
	 */
	public static function overrides(): array
	{
		return self::SAFE_MODE_OVERRIDES;
	}

	/**
	 * List of flat keys that MUST NOT appear in SAFE_MODE_OVERRIDES.
	 *
	 * Configuration::from_array() reads nested keys ('dns_verification.enabled'),
	 * not flat keys ('dns_verification_enabled'). If a flat key is used here,
	 * the override is silently ignored.
	 *
	 * Consumed by Test 21 in bin/test-config-schema.php as a guardrail.
	 *
	 * @return string[]
	 */
	public static function forbidden_flat_keys(): array
	{
		return [
			// DNS verification sub-keys
			'dns_verification_enabled',
			'dns_verification_timeout_ms',
			'dns_verification_require_forward_confirm',
			'dns_verification_positive_ttl',
			'dns_verification_negative_ttl',

			// Dynamic IP ranges sub-keys
			'dynamic_ip_ranges_enabled',
			'dynamic_ip_ranges_ttl',
			'dynamic_ip_ranges_feeds',

			// Reverse proxy sub-keys
			'reverse_proxy_enabled',
			'reverse_proxy_header',
			'reverse_proxy_addresses',

			// GeoIP sub-keys
			'geoip_enabled',
			'geoip_database_path',
			'geoip_blocked_countries',
			'geoip_blocked_asns',

			// Challenge sub-keys
			'challenge_enabled',
			'challenge_provider',
			'challenge_site_key',
			'challenge_secret_key',

			// http:BL sub-keys
			'httpbl_key',
			'httpbl_threat',
			'httpbl_maxage',

			// DNSBL sub-keys
			'dnsbl_enabled',
			'dnsbl_lists',

			// AI crawlers sub-keys
			'allowed_ai_crawlers',
			'block_unverified_ai',
			'strict_ai',

			// Bot categories sub-keys
			'blocked_bot_categories',
			'challenge_bot_categories',
			'log_only_bot_categories',
			'allowed_bot_categories',

			// Rate limits
			'rate_limit_enabled',
		];
	}

	private function __construct()
	{
		// Static class — no instances.
	}
}
