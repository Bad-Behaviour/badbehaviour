<?php

declare(strict_types=1);

namespace BadBehaviour\Util;

/**
 * Centralized safe-mode configuration.
 *
 * "Safe-mode" is the fallback behavior when BadBehaviour is misconfigured
 * (missing/invalid bb_config.php, broken registry, etc). In safe-mode:
 *
 *   - Logging remains ON (so traffic is still observable)
 *   - All active defenses are OFF (no blocking, no challenging, no rate limits)
 *   - Network-touching features are OFF (no DNS lookups, no http:BL, no DNSBL)
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
 * To add a new safe-mode override, edit the SAFE_MODE_OVERRIDES map below.
 * To add a new config key entirely, edit Configuration::get_defaults() —
 * it will propagate here automatically.
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
	 * Why each is overridden:
	 *
	 *   - All `enable_*_detection` / `rate_limit_enabled` / `dnsbl_enabled` /
	 *     `http:BL` keys → OFF because we have no valid config to interpret
	 *     user intent; running these could cause false positives.
	 *
	 *   - `dns_verification_enabled` → OFF because DNS lookups are slow and
	 *     network-dependent; running them when we don't know if the operator
	 *     wants this is dangerous.
	 *
	 *   - `dynamic_ip_ranges_enabled` → OFF because hitting AWS/GCP/Cloudflare
	 *     APIs on every request would be catastrophic if those endpoints are
	 *     unreachable (and they would be in many safe-mode scenarios).
	 *
	 *   - `head_require_referer` → OFF because requiring Referer on HEAD
	 *     requests in monitor-only mode would silently break REST API clients.
	 *
	 *   - `blocked_bot_categories`, `blocked_countries`, `blocked_asns`,
	 *     `custom_rules` → empty because we don't know the operator's intent;
	 *     any pre-populated values from normal defaults could surprise them.
	 *
	 *   - `_safe_mode` → true marker for diagnostics()
	 *
	 * Everything else is inherited from Configuration::get_defaults().
	 *
	 * @var array<string, mixed>
	 */
	private const SAFE_MODE_OVERRIDES = [
		// === Empty lists — no user intent known ===
		'blocked_bot_categories'    => [],
		'blocked_countries'         => [],
		'blocked_asns'              => [],
		'custom_rules'              => [],

		// === All active defenses OFF ===
		// These are the keys that could BLOCK or CHALLENGE a request.
		// In safe-mode we never interfere with the request flow.
		'enable_fingerprinting'         => false,
		'inspect_json_body'             => false,
		'inspect_multipart_body'        => false,
		'enable_behavioral_analysis'    => false,
		'enable_ai_crawler_control'     => false,
		'enable_client_hints_validation'=> false,
		'enable_agentic_detection'      => false,
		'enable_head_request_detection' => false,
		'enable_asset_scraping_detection' => false,

		// === Network-touching features OFF ===
		// Hitting external services in safe-mode is dangerous:
		// the host app may already be in a degraded state.
		'rate_limit_enabled'                  => false,
		'rate_limits'                         => [],
		'dnsbl_enabled'                       => false,
		'dnsbl_lists'                         => [],
		'httpbl_key'                          => '',
		'dns_verification_enabled'            => false,
		'dynamic_ip_ranges_enabled'           => false,
		'dynamic_ip_ranges_feeds'             => [],

		// === Head detector — don't require Referer in monitor mode ===
		// Could silently break legitimate REST API clients that send HEAD
		// without a Referer header.
		'head_require_referer'                => false,
		'head_referer_exempt_paths'           => [],

		// === Asset scraping detector — empty extensions list disables it ===
		'asset_extensions'                    => [],

		// === AI crawlers — no allowed list, no strict, no block-unverified ===
		// We don't know what the operator wants; default to "don't interfere".
		'allowed_ai_crawlers'                 => [],
		'block_unverified_ai'                 => false,
		'strict_ai'                           => false,
		'strict_search_engines'               => false,

		// === GeoIP — disabled (already default, but explicit for clarity) ===
		'geoip_enabled'                       => false,

		// === Challenge — disabled ===
		'challenge_enabled'                   => false,
		'challenge_provider'                  => 'builtin',
		'challenge_site_key'                  => '',
		'challenge_secret_key'                => '',

		// === Strict mode off — we don't know operator intent ===
		'strict'                              => false,

		// === Offsite forms — leave to operator's config when available ===
		'offsite_forms'                       => false,

		// === Verbose logging — only enable if operator asked ===
		'verbose'                             => false,

		// === Internal marker (consumed by diagnostics()) ===
		// Not part of the public Configuration surface — purely informational.
		'_safe_mode'                          => true,
	];

	/**
	 * Return a safe-mode settings array.
	 *
	 * Derived from Configuration::get_defaults() with the SAFE_MODE_OVERRIDES
	 * applied on top. Guarantees:
	 *   - All keys from Configuration::get_defaults() are present
	 *   - Safe-mode-specific overrides take precedence
	 *   - New keys added to Configuration::get_defaults() automatically appear here
	 *
	 * @param string $log_table Adapter-specific log table name (with prefix).
	 * @return array<string, mixed>
	 */
	public static function settings(string $log_table): array
	{
		// Single source of truth: start from Configuration's normal defaults.
		// Configuration::get_defaults() is a pure function returning a literal
		// array, so calling it here has no side effects.
		$base = \BadBehaviour\Configuration::get_defaults();

		// Apply safe-mode overrides on top.
		// array_merge (not array_merge_recursive) is intentional: when the
		// same key exists in both, the safe-mode value wins entirely — no
		// deep merging that could resurrect nested defaults.
		$merged = array_merge($base, self::SAFE_MODE_OVERRIDES);

		// Adapter-specific injection (cannot come from defaults — depends on
		// the host application's table prefix, which only the adapter knows).
		$merged['log_table'] = $log_table;

		return $merged;
	}

	/**
	 * Merge adapter-specific overrides on top of safe-mode base.
	 *
	 * Convenience helper for adapters that need to layer additional
	 * overrides (e.g., MediaWiki's $wgBadBehaviourSettings) on top
	 * of the safe-mode defaults.
	 *
	 * @param array $base Safe-mode settings (from settings())
	 * @param array $overrides Adapter-specific overrides
	 * @return array
	 */
	public static function merge(array $base, array $overrides): array
	{
		return array_merge($base, $overrides);
	}

	/**
	 * Return the list of keys that differ between normal defaults and safe-mode.
	 *
	 * Useful for diagnostics and tests — lets you assert "is this key
	 * actually different in safe-mode vs normal?" without hardcoding
	 * the comparison.
	 *
	 * @return array<string, mixed>
	 */
	public static function overrides(): array
	{
		return self::SAFE_MODE_OVERRIDES;
	}

	private function __construct()
	{
		// Static class — no instances.
	}
}