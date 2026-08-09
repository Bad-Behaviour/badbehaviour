<?php
// tests/Unit/Util/SafeModeTest.php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Configuration;
use BadBehaviour\Util\SafeMode;
use PHPUnit\Framework\TestCase;

class SafeModeTest extends TestCase
{
    /**
     * SafeMode::overrides() must return ONLY the keys that differ from
     * defaults — not the entire config. This is what makes the diff
     * testable: if you can't see the diff, you can't verify it.
     */
	public function test_overrides_relate_to_safety_features(): void
	{
		$overrides = SafeMode::overrides();

		// Every override should be a defense/feature key (not random user settings).
		// We allow redundancy with defaults because explicit-is-better-than-implicit
		// for safe-mode behavior — if defaults change in the future, we still
		// get safe behavior.
		$allowed = [
			// Nested section keys
			'reverse_proxy', 'httpbl', 'dnsbl', 'ai_crawlers',
			'bot_categories', 'rate_limits', 'geoip', 'challenge',
			'dns_verification', 'dynamic_ip_ranges', 'custom_rules',
			// Flat keys that are unique to safe-mode
			'head_require_referer',
		];

		$unexpected = [];
		foreach (array_keys($overrides) as $key) {
			if (!in_array($key, $allowed, true)) {
				$unexpected[] = $key;
			}
		}

		$this->assertEmpty(
			$unexpected,
			'SafeMode::overrides() contains unexpected keys (not safety-related): '
			. implode(', ', $unexpected)
			);
	}

    /**
     * SafeMode::overrides() must contain exactly the keys we expect
     * to differ from defaults. This catches accidental additions or
     * removals from SAFE_MODE_OVERRIDES.
     */
    public function test_overrides_contains_expected_keys(): void
    {
    	$overrides = SafeMode::overrides();

    	// Only keys that differ from defaults should be in overrides.
    	// (Explicit duplicates of defaults are not allowed.)
    	$expected = [
    		'dns_verification',      // nested form — disabled in safe-mode
    		'dynamic_ip_ranges',     // nested form — disabled
    		'reverse_proxy',         // nested form — disabled
    		'dnsbl',                 // nested form — disabled
    		'httpbl',                // nested form — key explicit empty
    		'geoip',                 // nested form — disabled
    		'challenge',             // nested form — disabled
    		'ai_crawlers',           // nested form — empty allowed list
    		'bot_categories',        // nested form — all four sub-keys empty
    		'rate_limits',           // nested form — enabled=false
    		'custom_rules',          // empty array (also default empty, but explicit)
    	];

    	foreach ($expected as $key) {
    		$this->assertArrayHasKey(
    			$key,
    			$overrides,
    			"overrides() must contain '$key'"
    			);
    	}
    }

    /**
     * SafeMode::overrides() may contain entries that match defaults —
     * this is INTENTIONAL for safety-critical features. Explicit
     * documentation prevents future default changes from silently
     * disabling safe-mode protections.
     *
     * What we forbid: adding random user settings to SafeMode that
     * have nothing to do with safety.
     */
    public function test_overrides_only_contains_safety_relevant_keys(): void
    {
    	$overrides = SafeMode::overrides();

    	// Allowlist: keys that belong in safe-mode (defense + safety features)
    	$allowed = [
    		// Defense features (explicit even when matching defaults)
    		'reverse_proxy',
    		'httpbl',
    		'dnsbl',
    		'dns_verification',
    		'dynamic_ip_ranges',

    		// Features where override DIFFERS from default
    		'ai_crawlers',
    		'rate_limits',
    		'geoip',
    		'challenge',
    		'bot_categories',
    		'custom_rules',

    		// Safety overrides
    		'head_require_referer',
    	];

    	$unexpected = [];
    	foreach (array_keys($overrides) as $key) {
    		if (!in_array($key, $allowed, true)) {
    			$unexpected[] = $key;
    		}
    	}

    	$this->assertEmpty(
    		$unexpected,
    		'SafeMode::overrides() contains non-safety keys. '
    		. 'Remove them: ' . implode(', ', $unexpected)
    		);
    }

    /**
     * settings() must include Configuration::get_defaults() PLUS
     * overrides() PLUS log_table injection. Used by Configuration::from_array()
     * as the safe-mode config fallback.
     */
    public function test_settings_includes_defaults_and_overrides(): void
    {
        $settings = SafeMode::settings('my_log_table');
        $defaults = Configuration::get_defaults();

        // Every default key must be present in settings()
        foreach (array_keys($defaults) as $key) {
            $this->assertArrayHasKey(
                $key,
                $settings,
                "settings() must include default key '$key'"
            );
        }

        // log_table injection works
        $this->assertSame(
            'my_log_table',
            $settings['log_table'],
            'settings() must inject the provided log_table'
        );
    }

    /**
     * settings() must include the _safe_mode marker for diagnostics().
     * This marker is what tells diagnostics() that the library is in
     * degraded mode (so it can show appropriate hints to operators).
     */
    public function test_settings_includes_safe_mode_marker(): void
    {
        $settings = SafeMode::settings('test_log');

        $this->assertArrayHasKey('_safe_mode', $settings);
        $this->assertTrue(
            $settings['_safe_mode'],
            'settings() must set _safe_mode = true'
        );
    }

    /**
     * Override values must win over defaults when merged.
     * (This is what array_merge does — but verify it explicitly.)
     */
    public function test_overrides_win_over_defaults(): void
    {
        $defaults = Configuration::get_defaults();
        $overrides = SafeMode::overrides();

        $merged = array_merge($defaults, $overrides);

        // dns_verification.enabled is true in defaults, false in overrides
        $this->assertTrue(
            $defaults['dns_verification']['enabled'],
            'precondition: dns_verification.enabled default is true'
        );
        $this->assertFalse(
            $overrides['dns_verification']['enabled'],
            'precondition: dns_verification.enabled override is false'
        );
        $this->assertFalse(
            $merged['dns_verification']['enabled'],
            'merged value must be override (false), not default (true)'
        );
    }

    /**
     * merge() must layer additional overrides on top of safe-mode base.
     * Used by adapters (MediaWiki, WackoWiki) that need to apply
     * their own settings on top of safe-mode.
     */
    public function test_merge_layers_additional_overrides(): void
    {
        $base = SafeMode::settings('base_log');
        $adapter_overrides = [
            'logging' => false,        // adapter wants logging off
            'preset'  => 'custom',     // adapter wants custom preset
            'log_table' => 'adapter_log', // adapter overrides log_table
        ];

        $merged = SafeMode::merge($base, $adapter_overrides);

        $this->assertFalse(
            $merged['logging'],
            'adapter override must disable logging'
        );
        $this->assertSame(
            'custom',
            $merged['preset'],
            'adapter override must change preset'
        );
        $this->assertSame(
            'adapter_log',
            $merged['log_table'],
            'adapter override must replace log_table'
        );

        // Safe-mode settings still apply for non-overridden keys
        $this->assertFalse(
            $merged['dns_verification']['enabled'],
            'safe-mode dns_verification.enabled must still be false'
        );
        $this->assertTrue(
            $merged['_safe_mode'],
            'safe-mode marker must persist through merge'
        );
    }

    /**
     * forbidden_flat_keys() must list every flat key that would be
     * silently ignored by Configuration::from_array(). This is the
     * guardrail consumed by Schema integrity tests.
     */
    public function test_forbidden_flat_keys_covers_dns_verification(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('dns_verification_enabled', $forbidden);
        $this->assertContains('dns_verification_timeout_ms', $forbidden);
        $this->assertContains('dns_verification_require_forward_confirm', $forbidden);
        $this->assertContains('dns_verification_positive_ttl', $forbidden);
        $this->assertContains('dns_verification_negative_ttl', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_dynamic_ip_ranges(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('dynamic_ip_ranges_enabled', $forbidden);
        $this->assertContains('dynamic_ip_ranges_ttl', $forbidden);
        $this->assertContains('dynamic_ip_ranges_feeds', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_reverse_proxy(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('reverse_proxy_enabled', $forbidden);
        $this->assertContains('reverse_proxy_header', $forbidden);
        $this->assertContains('reverse_proxy_addresses', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_geoip(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('geoip_enabled', $forbidden);
        $this->assertContains('geoip_database_path', $forbidden);
        $this->assertContains('geoip_blocked_countries', $forbidden);
        $this->assertContains('geoip_blocked_asns', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_challenge(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('challenge_enabled', $forbidden);
        $this->assertContains('challenge_provider', $forbidden);
        $this->assertContains('challenge_site_key', $forbidden);
        $this->assertContains('challenge_secret_key', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_httpbl(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('httpbl_key', $forbidden);
        $this->assertContains('httpbl_threat', $forbidden);
        $this->assertContains('httpbl_maxage', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_dnsbl(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('dnsbl_enabled', $forbidden);
        $this->assertContains('dnsbl_lists', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_ai_crawlers(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('allowed_ai_crawlers', $forbidden);
        $this->assertContains('block_unverified_ai', $forbidden);
        $this->assertContains('strict_ai', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_bot_categories(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('blocked_bot_categories', $forbidden);
        $this->assertContains('challenge_bot_categories', $forbidden);
        $this->assertContains('log_only_bot_categories', $forbidden);
        $this->assertContains('allowed_bot_categories', $forbidden);
    }

    public function test_forbidden_flat_keys_covers_rate_limit_enabled(): void
    {
        $forbidden = SafeMode::forbidden_flat_keys();

        $this->assertContains('rate_limit_enabled', $forbidden);
    }

    /**
     * NONE of the forbidden flat keys may appear in overrides().
     * If this test fails, someone added a flat key to SAFE_MODE_OVERRIDES
     * that will be silently ignored.
     */
    public function test_overrides_contains_no_forbidden_flat_keys(): void
    {
        $overrides = SafeMode::overrides();
        $forbidden = SafeMode::forbidden_flat_keys();

        foreach ($forbidden as $flat_key) {
            $this->assertArrayNotHasKey(
                $flat_key,
                $overrides,
                "overrides() must not contain forbidden flat key '$flat_key'. "
                . 'Use nested form (e.g., dns_verification.enabled) instead.'
            );
        }
    }

    /**
     * settings() must produce a Configuration that survives from_array()
     * with all defenses off. End-to-end test of the safe-mode path.
     */
    public function test_settings_produces_valid_configuration(): void
    {
        $settings = SafeMode::settings('integration_test_log');

        // Must be parseable by Configuration::from_array()
        $config = Configuration::from_array($settings);

        $this->assertFalse(
            $config->dns_verification_enabled,
            'safe-mode → dns_verification_enabled must be false'
        );
        $this->assertFalse(
            $config->dynamic_ip_ranges_enabled,
            'safe-mode → dynamic_ip_ranges_enabled must be false'
        );
        $this->assertFalse(
            $config->reverse_proxy,
            'safe-mode → reverse_proxy must be false'
        );
        $this->assertFalse(
            $config->dnsbl_enabled,
            'safe-mode → dnsbl_enabled must be false'
        );
        $this->assertTrue(
            $config->logging,
            'safe-mode → logging must remain true'
        );
        $this->assertSame(
            'integration_test_log',
            $config->log_table,
            'safe-mode → log_table must be the injected value'
        );
    }

    /**
     * SafeMode must NOT override performance.skip_extensions. Safe-mode
     * inherits the default static-skip list. If it didn't, every CSS/JS
     * request would be logged (the SQLite lock storm root cause).
     */
    public function test_safemode_preserves_static_skip_defaults(): void
    {
        $defaults = Configuration::get_defaults();
        $overrides = SafeMode::overrides();

        $this->assertArrayNotHasKey(
            'performance',
            $overrides,
            'SafeMode must not override performance — static-skip must inherit defaults'
        );
        $this->assertArrayHasKey(
            'performance',
            $defaults,
            'precondition: defaults must contain performance'
        );
        $this->assertContains(
            'js',
            $defaults['performance']['skip_extensions'],
            'precondition: defaults skip_extensions must contain js'
        );
    }

    /**
     * settings() must produce a Configuration where skip_static_extensions
     * still contains the full default set. End-to-end test for the
     * static-skip-in-safe-mode path.
     */
    public function test_safemode_settings_produces_full_static_skip(): void
    {
        $settings = SafeMode::settings('test_log');
        $config = Configuration::from_array($settings);

        $this->assertNotEmpty(
            $config->skip_static_extensions,
            'safe-mode Configuration must have non-empty skip_static_extensions'
        );
        $this->assertContains(
            'js',
            $config->skip_static_extensions,
            "safe-mode Configuration must have 'js' in skip_static_extensions"
        );
        $this->assertGreaterThanOrEqual(
            10,
            count($config->skip_static_extensions),
            'safe-mode Configuration must have full default static-skip set'
        );
    }

    /**
     * SafeMode must keep logging enabled. Logging is the whole point of
     * safe-mode — to observe traffic without acting on it.
     */
    public function test_safemode_keeps_logging_enabled(): void
    {
        $overrides = SafeMode::overrides();

        $this->assertArrayNotHasKey(
            'logging',
            $overrides,
            'SafeMode must not disable logging (the whole point is to observe)'
        );
    }

    /**
     * SafeMode must set verbose to false explicitly (or leave default).
     * If verbose leaked true into safe-mode, every allowed request
     * (including static assets) would flood the log table.
     */
    public function test_safemode_verbose_is_false(): void
    {
    	$config = Configuration::from_array(SafeMode::settings('test_log'));

    	$this->assertFalse(
    		$config->verbose,
    		'safe-mode must not enable verbose logging (would flood log table with asset requests)'
    		);
    }

    /**
     * settings() with empty log_table string must still produce a
     * valid Configuration (some adapters may not have a prefix).
     */
    public function test_settings_with_empty_log_table(): void
    {
        $settings = SafeMode::settings('');

        $this->assertSame('', $settings['log_table']);

        $config = Configuration::from_array($settings);

        $this->assertSame('', $config->log_table);
        $this->assertFalse($config->dns_verification_enabled);
    }

    /**
     * Safety-critical features MUST appear in SafeMode::overrides() even
     * when their values match defaults. This is a deliberate design choice:
     *
     *   1. Documentation: explicit listing makes safe-mode behavior obvious
     *      to anyone reading the code
     *   2. Future-proofing: if Configuration::get_defaults() changes a value
     *      to true (e.g., enabling a feature by default), safe-mode still
     *      disables it
     *   3. Regression prevention: if someone "cleans up" SafeMode by removing
     *      entries they think are redundant, this test catches it
     *
     * If you remove one of these entries, you're saying "this safety
     * feature doesn't need explicit protection" — which may be true, but
     * it requires explicit consideration, not silent removal.
     */
    public function test_safety_critical_features_are_explicit(): void
    {
    	$overrides = SafeMode::overrides();

    	$required = [
    		'reverse_proxy'       => ['enabled' => false],
    		'dns_verification'    => ['enabled' => false],
    		'dynamic_ip_ranges'   => ['enabled' => false],
    		'rate_limits'         => ['enabled' => false],
    		'challenge'           => ['enabled' => false],
    		'geoip'               => ['enabled' => false],
    		'dnsbl'               => ['enabled' => false],
    	];

    	foreach ($required as $key => $expected_subkeys) {
    		$this->assertArrayHasKey(
    			$key,
    			$overrides,
    			"SafeMode must explicitly list '$key' even if it matches defaults. "
    			. "Removing it removes safety documentation and future-proofing."
    			);

    		foreach ($expected_subkeys as $sub_key => $expected_value) {
    			$this->assertArrayHasKey(
    				$sub_key,
    				$overrides[$key],
    				"SafeMode['$key'] must contain '$sub_key'"
    				);
    			$this->assertSame(
    				$expected_value,
    				$overrides[$key][$sub_key],
    				"SafeMode['$key']['$sub_key'] must be " . var_export($expected_value, true)
    				);
    		}
    	}
    }
}