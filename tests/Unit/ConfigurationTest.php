<?php
// tests/Unit/ConfigurationTest.php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit;

use BadBehaviour\Configuration;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Config\Diagnostics;
use BadBehaviour\Config\Schema;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\SafeMode;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionIntersectionType;
use ReflectionNamedType;
use ReflectionUnionType;

class ConfigurationTest extends TestCase
{
    protected function setUp(): void
    {
        // Reset all diagnostics between tests so one test's warnings
        // don't leak into another.
        Diagnostics::reset();
        ErrorReporter::reset();
    }

    public function test_from_array_defaults(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([], $adapter);

        // === Core ===
        $this->assertTrue($config->logging);
        $this->assertFalse($config->verbose);
        $this->assertFalse($config->strict);
        $this->assertFalse($config->offsite_forms);
        $this->assertFalse($config->show_contact_info);
        $this->assertFalse($config->show_detailed_block_page);

        // === Meta ===
        $this->assertEquals('normal', $config->strictness);
        $this->assertEquals('minimal', $config->preset);

        // === Reverse proxy ===
        $this->assertFalse($config->reverse_proxy);
        $this->assertEquals('X-Forwarded-For', $config->reverse_proxy_header);
        $this->assertEquals([], $config->reverse_proxy_addresses);

        // === http:BL ===
        $this->assertEquals('', $config->httpbl_key);
        $this->assertEquals(25, $config->httpbl_threat);
        $this->assertEquals(30, $config->httpbl_maxage);

        // === DNSBL ===
        $this->assertFalse($config->dnsbl_enabled);
        $this->assertEquals(['zen.spamhaus.org', 'bl.spamcop.net'], $config->dnsbl_lists);

        // === AI crawlers ===
        $this->assertEquals(['GPTBot', 'ClaudeBot', 'Google-Extended'], $config->allowed_ai_crawlers);

        // FIX: default is false — aggressive blocking is OFF in 'normal' strictness
        // for FP prevention. Operators opt in via 'strict' or explicit override.
        $this->assertFalse($config->block_unverified_ai);

        $this->assertFalse($config->strict_ai);
        $this->assertFalse($config->strict_search_engines);

        // === Bot categories (Option A) ===
        // FIX: all four default to empty arrays. Operators opt in to overrides
        // by adding entries in their bb_config.php. The shipped config sets
        // blocked=['malicious'] explicitly; the DEFAULT is empty.
        $this->assertEquals([], $config->blocked_bot_categories);
        $this->assertEquals([], $config->challenge_bot_categories);
        $this->assertEquals([], $config->log_only_bot_categories);
        $this->assertEquals([], $config->allowed_bot_categories);

        // === Rate limiting ===
        // 'normal' strictness enables rate limiting by default
        $this->assertTrue($config->rate_limit_enabled);
        $this->assertArrayHasKey('global', $config->rate_limits);
        $this->assertArrayHasKey('per_minute', $config->rate_limits);
        $this->assertArrayHasKey('post', $config->rate_limits);
        $this->assertArrayHasKey('login', $config->rate_limits);

        // === Custom rules ===
        $this->assertEquals([], $config->custom_rules);

        // === Fingerprints ===
        $this->assertEquals([], $config->bad_ja3_fingerprints);
        $this->assertEquals([], $config->bad_h2_fingerprints);
        $this->assertEquals([], $config->bot_header_orders);
        $this->assertEquals([], $config->expected_ja3);

        // === GeoIP ===
        $this->assertFalse($config->geoip_enabled);
        $this->assertEquals('', $config->geoip_database_path);
        $this->assertEquals([], $config->blocked_countries);
        $this->assertEquals([], $config->blocked_asns);

        // === Challenge ===
        $this->assertFalse($config->challenge_enabled);
        $this->assertEquals('builtin', $config->challenge_provider);
        $this->assertEquals('', $config->challenge_site_key);
        $this->assertEquals('', $config->challenge_secret_key);
        $this->assertEquals(0.5, $config->recaptcha_min_score);

        // === Performance ===
        $this->assertNotEmpty($config->skip_static_extensions);
        $this->assertNotEmpty($config->skip_static_paths);

        // === 3.0 experimental features (FP prevention: all OFF in 'normal') ===
        $this->assertFalse($config->enable_fingerprinting);
        $this->assertFalse($config->inspect_json_body);
        $this->assertFalse($config->inspect_multipart_body);
        $this->assertFalse($config->enable_behavioral_analysis);
        $this->assertTrue($config->enable_ai_crawler_control);
        $this->assertFalse($config->enable_client_hints_validation);
        $this->assertFalse($config->enable_agentic_detection);

        // === DNS verification ===
        // 'normal' strictness enables DNS verification by default
        $this->assertTrue($config->dns_verification_enabled);
        $this->assertEquals(300, $config->dns_verification_timeout_ms);
        $this->assertFalse($config->dns_verification_require_forward_confirm);
        $this->assertEquals(604800, $config->dns_verification_positive_ttl);
        $this->assertEquals(3600, $config->dns_verification_negative_ttl);

        // === Dynamic IP ranges ===
        // 'normal' strictness enables dynamic IP ranges by default
        $this->assertTrue($config->dynamic_ip_ranges_enabled);
        $this->assertEquals(86400, $config->dynamic_ip_ranges_ttl);
        $this->assertEquals(['aws', 'cloudflare', 'fastly', 'gcp'], $config->dynamic_ip_ranges_feeds);

        // === Head / asset detectors (experimental — OFF in 'normal') ===
        $this->assertFalse($config->enable_head_request_detection);
        $this->assertFalse($config->head_require_referer);
        $this->assertEquals(20, $config->head_flood_threshold);
        $this->assertEquals(50, $config->head_probe_threshold);
        $this->assertNotEmpty($config->head_referer_exempt_paths);

        $this->assertFalse($config->enable_asset_scraping_detection);
        $this->assertNotEmpty($config->asset_extensions);
        $this->assertEquals(10, $config->asset_no_referer_threshold);
        $this->assertEquals(20, $config->asset_only_session_threshold);
        $this->assertEquals(100, $config->asset_pattern_threshold);

        // === Dependencies ===
        $this->assertSame($adapter, $config->adapter);
        $this->assertNull($config->logger);
        $this->assertNull($config->cache);
        $this->assertNull($config->geoip);

        // === Derived ===
        $this->assertEquals('normal', $config->get_strictness());
        $this->assertEquals('minimal', $config->get_preset());
    }

    /**
     * Option A regression test: all 4 bot_categories sub-keys round-trip
     * through Configuration without being silently dropped.
     *
     * This catches the original "silently dropped config keys" bug. If any
     * of these assertions fail, Option A has regressed and operators writing
     * custom challenge/log_only/allowed configs will get nothing again.
     */
    public function test_bot_categories_round_trip(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'bot_categories' => [
                'blocked'   => ['malicious', 'residential_proxy'],
                'challenge' => ['social_crawler', 'ai_crawler'],
                'log_only'  => ['security_scanner'],
                'allowed'   => ['feed_reader', 'archive_crawler'],
            ],
        ], $adapter);

        // Properties hold the input values
        $this->assertEquals(['malicious', 'residential_proxy'], $config->blocked_bot_categories);
        $this->assertEquals(['social_crawler', 'ai_crawler'], $config->challenge_bot_categories);
        $this->assertEquals(['security_scanner'], $config->log_only_bot_categories);
        $this->assertEquals(['feed_reader', 'archive_crawler'], $config->allowed_bot_categories);

        // to_array() preserves all four sub-keys (config save/load round-trip)
        $array = $config->to_array();
        $this->assertArrayHasKey('bot_categories', $array);
        $this->assertArrayHasKey('blocked', $array['bot_categories']);
        $this->assertArrayHasKey('challenge', $array['bot_categories']);
        $this->assertArrayHasKey('log_only', $array['bot_categories']);
        $this->assertArrayHasKey('allowed', $array['bot_categories']);
        $this->assertEquals(
            ['malicious', 'residential_proxy'],
            $array['bot_categories']['blocked']
        );
        $this->assertEquals(
            ['social_crawler', 'ai_crawler'],
            $array['bot_categories']['challenge']
        );
    }

    /**
     * Option A regression test: defaults don't ship with any sub-key pre-populated.
     *
     * If somebody accidentally puts `blocked => ['malicious']` in get_defaults()
     * (because it was in the shipped config), an operator who doesn't override
     * bot_categories will silently get `malicious` blocked. This catches that.
     */
    public function test_bot_categories_defaults_are_empty(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([], $adapter);

        $this->assertSame([], $config->blocked_bot_categories);
        $this->assertSame([], $config->challenge_bot_categories);
        $this->assertSame([], $config->log_only_bot_categories);
        $this->assertSame([], $config->allowed_bot_categories);
    }

    // =====================================================================
    // REGRESSION TESTS — skip_static_extensions wipe
    // =====================================================================
    //
    // The original WackoWiki production bug:
    //   1. User config: preset=minimal, strictness=monitor-only, verbose=true
    //   2. coerce_for_property() over-defensive branch wiped
    //      skip_static_extensions to [] during config parsing
    //   3. BadBehaviour::should_skip_static() iterated over [] and matched nothing
    //   4. Every CSS/JS/SVG request reached detection
    //   5. Every allowed asset was logged (because verbose=true)
    //   6. Concurrent asset loads caused SQLite "database is locked"
    //   7. WackoWiki rendered the SQL error as the response body
    //
    // These tests reproduce the exact conditions and assert the fix.

    /**
     * PRIMARY REGRESSION TEST: skip_static_extensions must contain its
     * defaults after from_array([]). The empty-config path must not
     * wipe the array to [].
     */
    public function test_skip_static_extensions_survives_coercion(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([], $adapter);

        $this->assertIsArray(
            $config->skip_static_extensions,
            'skip_static_extensions must be an array'
        );
        $this->assertNotEmpty(
            $config->skip_static_extensions,
            'skip_static_extensions must not be empty (defaults must flow through)'
        );
    }

    /**
     * PRIMARY REGRESSION TEST: the exact bug report config.
     *
     * Reproduces the WackoWiki production scenario verbatim:
     *   preset=minimal, strictness=monitor-only, verbose=true
     *
     * Asserts skip_static_extensions still contains 'js' (the asset
     * extension that triggered the bug). Without the fix, this list
     * would be empty and every .js request would be logged.
     */
    public function test_minimal_user_config_preserves_static_skip(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'preset'     => 'minimal',
            'strictness' => 'monitor-only',
            'logging'    => true,
            'verbose'    => true,
        ], $adapter);

        $this->assertNotEmpty(
            $config->skip_static_extensions,
            'minimal config → skip_static_extensions must be non-empty'
        );
        $this->assertContains(
            'js',
            $config->skip_static_extensions,
            "skip_static_extensions must contain 'js' — otherwise .js requests "
            . "flood the log with verbose=true (the original WackoWiki bug)"
        );
        $this->assertContains(
            'css',
            $config->skip_static_extensions,
            "skip_static_extensions must contain 'css'"
        );
        $this->assertContains(
            'png',
            $config->skip_static_extensions,
            "skip_static_extensions must contain 'png'"
        );
        $this->assertContains(
            'svg',
            $config->skip_static_extensions,
            "skip_static_extensions must contain 'svg'"
        );
        $this->assertContains(
            'woff',
            $config->skip_static_extensions,
            "skip_static_extensions must contain 'woff'"
        );
        $this->assertGreaterThanOrEqual(
            10,
            count($config->skip_static_extensions),
            'skip_static_extensions must have full default set'
        );

        // Same checks for skip_static_paths
        $this->assertNotEmpty(
            $config->skip_static_paths,
            'minimal config → skip_static_paths must be non-empty'
        );
        $this->assertContains(
            '/static/',
            $config->skip_static_paths,
            "skip_static_paths must contain '/static/'"
        );
    }

    /**
     * When the user explicitly writes an empty array, respect that intent.
     * (Distinguishes "defaults flowed through" from "user disabled".)
     */
    public function test_explicit_empty_skip_extensions_respects_user_intent(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'performance' => [
                'skip_extensions' => [],
                'skip_paths'      => [],
            ],
        ], $adapter);

        $this->assertSame(
            [],
            $config->skip_static_extensions,
            'explicit [] in user config must wipe defaults (user intent)'
        );
        $this->assertSame(
            [],
            $config->skip_static_paths,
            'explicit [] in user config must wipe defaults (user intent)'
        );
    }

    /**
     * Partial override: user sets only skip_extensions, skip_paths must
     * inherit defaults. Verifies the array merge handles nested arrays
     * correctly without wiping siblings.
     */
    public function test_partial_override_preserves_other_array_defaults(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'performance' => [
                'skip_extensions' => ['custom_ext'],
            ],
        ], $adapter);

        $this->assertSame(
            ['custom_ext'],
            $config->skip_static_extensions,
            'user override replaces skip_static_extensions entirely'
        );
        $this->assertNotEmpty(
            $config->skip_static_paths,
            'partial override preserves skip_static_paths defaults'
        );
    }

    /**
     * Reflection-based catch-all: every array-typed constructor parameter
     * on Configuration must survive coercion with non-empty content if
     * it has non-empty defaults, OR with empty array if defaults are empty.
     *
     * If anyone adds a new array property to Configuration without adding
     * it to coerce_for_property()'s $array_props allow-list, this test
     * catches the regression at the architectural level.
     */
    public function test_all_array_constructor_parameters_survive_coercion(): void
    {
    	$reflection = new ReflectionClass(Configuration::class);
    	$constructor = $reflection->getConstructor();
    	$array_params = [];

    	foreach ($constructor->getParameters() as $param) {
    		$type = $param->getType();
    		if ($type === null) {
    			continue;
    		}

    		// === Handle single named type (most common case) ===
    		if ($type instanceof ReflectionNamedType) {
    			if ($type->getName() === 'array') {
    				$array_params[] = $param->getName();
    			}
    			continue;
    		}

    		// === Handle union types (PHP 8.0+, e.g., int|float) ===
    		//
    		// ReflectionUnionType does NOT have getName() — it's a collection
    		// of ReflectionNamedType instances accessible via getTypes().
    		// Used by `on_demand_ip_refresh_feed_timeout_seconds` which
    		// accepts int|float for sub-second precision budgets.
    		if ($type instanceof ReflectionUnionType) {
    			foreach ($type->getTypes() as $namedType) {
    				if ($namedType instanceof ReflectionNamedType
    					&& $namedType->getName() === 'array') {
    						$array_params[] = $param->getName();
    						break;
    					}
    			}
    			continue;
    		}

    		// === Handle intersection types (PHP 8.1+) ===
    		//
    		// Cannot include `array` in practice (array isn't a class),
    		// so this branch never adds anything. Included for completeness.
    		if ($type instanceof ReflectionIntersectionType) {
    			continue;
    		}
    	}

    	$this->assertNotEmpty(
    		$array_params,
    		'Configuration must have at least one array parameter'
    		);

    	// Defaults that must produce non-empty arrays
    	$must_be_non_empty = [
    		'skip_static_extensions',
    		'skip_static_paths',
    		'allowed_ai_crawlers',
    		'dnsbl_lists',
    		'head_referer_exempt_paths',
    		'dynamic_ip_ranges_feeds',
    		'asset_extensions',
    		'body_scan_skip_fields',
    	];

    	// Defaults that must produce empty arrays (not null, not scalar)
    	$must_be_empty = [
    		'reverse_proxy_addresses',
    		'blocked_bot_categories',
    		'challenge_bot_categories',
    		'log_only_bot_categories',
    		'allowed_bot_categories',
    		'bad_ja3_fingerprints',
    		'bad_h2_fingerprints',
    		'bot_header_orders',
    		'expected_ja3',
    		'blocked_countries',
    		'blocked_asns',
    		'custom_rules',
    	];

    	// ============================================================
    	// FIX: Instantiate Configuration so we can read its properties
    	// ============================================================
    	$config = Configuration::from_array([]);

    	foreach ($array_params as $param) {
    		$value = $config->{$param} ?? null;

    		$this->assertIsArray(
    			$value,
    			"$param must be an array after from_array([]) "
    			. "(got " . get_debug_type($value) . ')'
    			);

    		if (in_array($param, $must_be_non_empty, true)) {
    			$this->assertNotEmpty(
    				$value,
    				"$param must be non-empty (defaults must survive coercion)"
    				);
    		} elseif (in_array($param, $must_be_empty, true)) {
    			$this->assertSame(
    				[],
    				$value,
    				"$param must be empty array (not null, not scalar)"
    				);
    		}
    		// rate_limits is complex — just verify it's an array
    	}
    }

    /**
     * Additional array properties that ship with non-empty defaults.
     * Catches any future regression where a new array property's
     * defaults get wiped during coercion.
     */
    public function test_specific_array_defaults_preserved(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([], $adapter);

        $cases = [
            ['skip_static_extensions', ['css', 'js']],
            ['skip_static_paths', ['/static/']],
            ['allowed_ai_crawlers', ['GPTBot']],
            ['dnsbl_lists', ['zen.spamhaus.org']],
            ['head_referer_exempt_paths', ['/api/']],
            ['dynamic_ip_ranges_feeds', ['aws']],
            ['asset_extensions', ['png']],
            ['body_scan_skip_fields', ['body']],
        ];

        foreach ($cases as [$prop, $must_contain]) {
            $actual = $config->{$prop};
            $this->assertIsArray($actual, "$prop must be array");
            $this->assertNotEmpty($actual, "$prop must be non-empty");
            foreach ($must_contain as $required) {
                $this->assertContains(
                    $required,
                    $actual,
                    "$prop must contain '$required'"
                );
            }
        }
    }

    // =====================================================================
    // REGRESSION TESTS — Type coercion
    // =====================================================================

    /**
     * Strings from parse_ini_file() / INI files must coerce to typed
     * properties. Without working coercion, INI-loaded configs arrive
     * as strings and break typed properties (e.g., 'true' as bool
     * stays string).
     */
    public function test_string_coerces_to_bool(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'verbose' => 'true',
            'logging' => '1',
        ], $adapter);

        $this->assertTrue(
            $config->verbose,
            "string 'true' must coerce to bool true"
        );
        $this->assertTrue(
            $config->logging,
            "string '1' must coerce to bool true"
        );
    }

    public function test_string_coerces_to_int(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'httpbl_threat' => '25',
            'dns_verification' => ['timeout_ms' => '300'],
            'head_flood_threshold' => '20',
        ], $adapter);

        $this->assertSame(
            25,
            $config->httpbl_threat,
            "string '25' must coerce to int 25"
        );
        $this->assertSame(
            300,
            $config->dns_verification_timeout_ms,
            "string '300' must coerce to int 300"
        );
        $this->assertSame(
            20,
            $config->head_flood_threshold,
            "string '20' must coerce to int 20"
        );
    }

    public function test_string_coerces_to_float(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'challenge' => ['recaptcha_min_score' => '0.7'],
        ], $adapter);

        $this->assertSame(
            0.7,
            $config->recaptcha_min_score,
            "string '0.7' must coerce to float 0.7"
        );
    }

    // =====================================================================
    // REGRESSION TESTS — Strictness overrides
    // =====================================================================

    public function test_monitor_only_disables_dns_verification(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array(['strictness' => 'monitor-only'], $adapter);

        $this->assertFalse(
            $config->dns_verification_enabled,
            "strictness='monitor-only' must disable DNS verification"
        );
    }

    public function test_normal_enables_dns_verification(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array(['strictness' => 'normal'], $adapter);

        $this->assertTrue(
            $config->dns_verification_enabled,
            "strictness='normal' must enable DNS verification"
        );
    }

    public function test_user_beats_strictness_override(): void
    {
        $adapter = new GenericAdapter();
        // monitor-only normally disables DNS verification,
        // but user explicitly enables it
        $config = Configuration::from_array([
            'strictness'       => 'monitor-only',
            'dns_verification' => ['enabled' => true],
        ], $adapter);

        $this->assertTrue(
            $config->dns_verification_enabled,
            "user override must beat strictness override"
        );
    }

    public function test_all_strictness_levels_preserve_static_skip(): void
    {
        $adapter = new GenericAdapter();

        foreach (['monitor-only', 'normal', 'strict'] as $level) {
            $config = Configuration::from_array(['strictness' => $level], $adapter);

            $this->assertNotEmpty(
                $config->skip_static_extensions,
                "strictness='$level' must preserve skip_static_extensions"
            );
            $this->assertContains(
                'js',
                $config->skip_static_extensions,
                "strictness='$level' must preserve 'js' in skip_static_extensions"
            );
            $this->assertNotEmpty(
                $config->skip_static_paths,
                "strictness='$level' must preserve skip_static_paths"
            );
        }
    }

    // =====================================================================
    // REGRESSION TESTS — Diagnostics typo detection
    // =====================================================================

    public function test_typos_in_user_config_are_flagged(): void
    {
        $adapter = new GenericAdapter();
        Configuration::from_array([
            'dynamc_ip_ranges' => ['enabled' => true],  // typo: dynamc
            'dns_verfiction'   => ['enabled' => false], // typo: verfiction
        ], $adapter);

        $unknown = Diagnostics::unknown_keys();

        $this->assertArrayHasKey(
            'dynamc_ip_ranges.enabled',
            $unknown,
            "typo 'dynamc_ip_ranges.enabled' must be flagged"
        );
        $this->assertArrayHasKey(
            'dns_verfiction.enabled',
            $unknown,
            "typo 'dns_verfiction.enabled' must be flagged"
        );
    }

    public function test_known_keys_not_flagged(): void
    {
        $adapter = new GenericAdapter();
        Configuration::from_array([
            'preset'           => 'minimal',
            'strictness'       => 'monitor-only',
            'logging'          => true,
            'verbose'          => true,
            'bot_categories'   => ['blocked' => ['malicious']],
            'dns_verification' => ['enabled' => true],
        ], $adapter);

        $unknown = Diagnostics::unknown_keys();

        $this->assertEmpty(
            $unknown,
            "valid config keys must not appear in Diagnostics::unknown_keys(). "
            . "Got: " . implode(', ', array_keys($unknown))
        );
    }

    // =====================================================================
    // REGRESSION TESTS — SafeMode
    // =====================================================================

    /**
     * SafeMode must produce a Configuration with ALL defenses disabled.
     * Previously failed because SafeMode used flat keys that
     * Configuration::from_array() silently ignored.
     */
    public function test_safemode_disables_all_defenses(): void
    {
        $config = Configuration::from_array(SafeMode::settings('test_log_table'));

        $defense_flags = [
            'dns_verification_enabled'           => false,
            'dynamic_ip_ranges_enabled'          => false,
            'dnsbl_enabled'                      => false,
            'rate_limit_enabled'                 => false,
            'enable_fingerprinting'              => false,
            'enable_behavioral_analysis'         => false,
            'enable_client_hints_validation'     => false,
            'enable_agentic_detection'           => false,
            'enable_head_request_detection'      => false,
            'enable_asset_scraping_detection'    => false,
            'geoip_enabled'                      => false,
            'challenge_enabled'                  => false,
            'block_unverified_ai'                => false,
            'strict_search_engines'              => false,
            'reverse_proxy'                      => false,
        ];

        foreach ($defense_flags as $prop => $expected) {
            $this->assertSame(
                $expected,
                $config->{$prop},
                "safe-mode must set $prop = " . var_export($expected, true)
            );
        }

        // Logging must remain ON (so traffic is observable)
        $this->assertTrue(
            $config->logging,
            'safe-mode must keep logging enabled (for observability)'
        );

        // Adapter-specific log_table injection
        $this->assertSame(
            'test_log_table',
            $config->log_table,
            'safe-mode must inject adapter-specific log_table'
        );
    }

    /**
     * SafeMode must preserve static-skip defaults. Without this, every
     * asset request would be processed in safe-mode (defeating the
     * purpose of "lightweight, degraded operation").
     */
    public function test_safemode_preserves_static_skip_defaults(): void
    {
        $settings = SafeMode::settings('test_log_table');

        $this->assertArrayHasKey('performance', $settings);
        $this->assertArrayHasKey('skip_extensions', $settings['performance']);
        $this->assertNotEmpty(
            $settings['performance']['skip_extensions'],
            'safe-mode must preserve performance.skip_extensions defaults'
        );
        $this->assertContains(
            'js',
            $settings['performance']['skip_extensions'],
            "safe-mode must preserve 'js' in performance.skip_extensions"
        );
        $this->assertNotEmpty(
            $settings['performance']['skip_paths'],
            'safe-mode must preserve performance.skip_paths defaults'
        );
    }

    /**
     * SafeMode's SAFE_MODE_OVERRIDES must use nested keys matching what
     * Configuration::from_array() reads. Flat keys are silently ignored,
     * causing the override to be a no-op.
     */
    public function test_safemode_overrides_use_nested_keys(): void
    {
        $overrides = SafeMode::overrides();
        $forbidden_flat = SafeMode::forbidden_flat_keys();

        $found_flat = [];
        // Flatten SafeMode overrides to check for forbidden flat keys
        $flattened = Schema::flatten($overrides);
        foreach ($forbidden_flat as $flat_key) {
            if (array_key_exists($flat_key, $flattened)) {
                $found_flat[] = $flat_key;
            }
        }

        $this->assertEmpty(
            $found_flat,
            'SafeMode::overrides() must not use flat keys that from_array() ignores. '
            . 'Found: ' . implode(', ', $found_flat)
        );
    }

    public function test_safemode_uses_nested_keys_for_network_features(): void
    {
        $overrides = SafeMode::overrides();

        $this->assertArrayHasKey(
            'dns_verification',
            $overrides,
            'SafeMode must use nested "dns_verification" key (not flat "dns_verification_enabled")'
        );
        $this->assertArrayHasKey(
            'enabled',
            $overrides['dns_verification'],
            'SafeMode nested "dns_verification" must contain "enabled" sub-key'
        );
        $this->assertFalse(
            $overrides['dns_verification']['enabled'],
            'SafeMode must disable dns_verification.enabled'
        );

        $this->assertArrayHasKey(
            'dynamic_ip_ranges',
            $overrides,
            'SafeMode must use nested "dynamic_ip_ranges" key'
        );
        $this->assertFalse(
            $overrides['dynamic_ip_ranges']['enabled'],
            'SafeMode must disable dynamic_ip_ranges.enabled'
        );

        $this->assertArrayHasKey(
            'reverse_proxy',
            $overrides,
            'SafeMode must use nested "reverse_proxy" key'
        );
        $this->assertFalse(
            $overrides['reverse_proxy']['enabled'],
            'SafeMode must disable reverse_proxy.enabled'
        );
    }

    // =====================================================================
    // REGRESSION TESTS — Schema integrity
    // =====================================================================

    public function test_schema_covers_all_defaults(): void
    {
        $known = Schema::known_keys();
        $default_flat = Schema::flatten(Configuration::get_defaults());

        // Keys that are dependencies (injected, not from config)
        $skip = ['adapter', 'logger', 'cache', 'geoip', 'log_table'];

        $missing = [];
        foreach ($known as $dotted) {
            if (in_array($dotted, $skip, true)) continue;
            if (!array_key_exists($dotted, $default_flat)) {
                $missing[] = $dotted;
            }
        }

        $this->assertEmpty(
            $missing,
            'Schema must cover all default config keys. Missing: '
            . implode(', ', $missing)
        );
    }

    public function test_strictness_overrides_use_known_schema_keys(): void
    {
        $known = Schema::known_keys();

        foreach (['monitor-only', 'normal', 'strict'] as $level) {
            $overrides = Schema::flatten(Configuration::strictness_overrides($level));
            $unknown = [];

            foreach (array_keys($overrides) as $dotted) {
                if (!in_array($dotted, $known, true)) {
                    $unknown[] = $dotted;
                }
            }

            $this->assertEmpty(
                $unknown,
                "strictness_overrides('$level') must use only known schema keys. "
                . 'Unknown: ' . implode(', ', $unknown)
            );
        }
    }

    public function test_safemode_overrides_use_known_schema_keys(): void
    {
        $known = Schema::known_keys();
        $safe_flat = Schema::flatten(SafeMode::overrides());

        $unknown = [];
        foreach (array_keys($safe_flat) as $dotted) {
            // _safe_mode is internal, not in schema
            if ($dotted === '_safe_mode') continue;
            if (!in_array($dotted, $known, true)) {
                $unknown[] = $dotted;
            }
        }

        $this->assertEmpty(
            $unknown,
            "SafeMode::overrides() must use only known schema keys. "
            . 'Unknown: ' . implode(', ', $unknown)
        );
    }

    // =====================================================================
    // REGRESSION TESTS — to_array() round-trip
    // =====================================================================

    public function test_to_array_round_trip_preserves_all_four_bot_categories(): void
    {
        $adapter = new GenericAdapter();
        $original = [
            'preset'         => 'minimal',
            'strictness'     => 'normal',
            'bot_categories' => [
                'blocked'   => ['malicious'],
                'challenge' => ['social_crawler'],
                'log_only'  => ['security_scanner'],
                'allowed'   => ['feed_reader'],
            ],
        ];

        $cfg = Configuration::from_array($original, $adapter);
        $round = $cfg->to_array();

        $this->assertArrayHasKey('bot_categories', $round);
        $this->assertEquals(
            ['malicious'],
            $round['bot_categories']['blocked'],
            'to_array() must round-trip bot_categories.blocked'
        );
        $this->assertEquals(
            ['social_crawler'],
            $round['bot_categories']['challenge'],
            'to_array() must round-trip bot_categories.challenge'
        );
        $this->assertEquals(
            ['security_scanner'],
            $round['bot_categories']['log_only'],
            'to_array() must round-trip bot_categories.log_only'
        );
        $this->assertEquals(
            ['feed_reader'],
            $round['bot_categories']['allowed'],
            'to_array() must round-trip bot_categories.allowed'
        );
    }

    // =====================================================================
    // REGRESSION TESTS — Edge cases
    // =====================================================================

    /**
     * Invalid strictness level must fall back to default, not throw.
     */
    public function test_invalid_strictness_falls_back_to_default(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array(['strictness' => 'invalid-level'], $adapter);

    	// Must NOT throw — falls back to 'normal' default
    	$this->assertSame(
    		'normal',
    		$config->strictness,
    		"invalid strictness must fall back to 'normal' default"
    		);
    }

    public function test_get_strictness_returns_configured_value(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array(['strictness' => 'monitor-only'], $adapter);

    	$this->assertSame('monitor-only', $config->get_strictness());
    }

    public function test_get_preset_returns_configured_value(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array(['preset' => 'full'], $adapter);

    	$this->assertSame('full', $config->get_preset());
    }

    public function test_get_strictness_returns_normal_by_default(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([], $adapter);

    	$this->assertSame('normal', $config->get_strictness());
    }

    /**
     * httpbl_threat must be clamped to 0-255 range.
     * Values outside this range are rejected by Project Honeypot.
     */
    public function test_httpbl_threat_clamped_to_255(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'httpbl' => ['threat' => 999],
    	], $adapter);

    	$this->assertSame(
    		255,
    		$config->httpbl_threat,
    		'httpbl_threat must be clamped to 255 max'
    		);
    }

    public function test_httpbl_threat_clamped_to_zero(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'httpbl' => ['threat' => -5],
    	], $adapter);

    	$this->assertSame(
    		0,
    		$config->httpbl_threat,
    		'httpbl_threat must be clamped to 0 min'
    		);
    }

    public function test_httpbl_maxage_floored_at_zero(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'httpbl' => ['maxage' => -1],
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		0,
    		$config->httpbl_maxage,
    		'httpbl_maxage must not be negative'
    		);
    }

    /**
     * DNS verification timeout must be clamped to 50-2000ms.
     * Too low: real DNS lookups can't complete.
     * Too high: request latency blows up.
     */
    public function test_dns_verification_timeout_clamped_min(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'dns_verification' => ['timeout_ms' => 10],  // too low
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		50,
    		$config->dns_verification_timeout_ms,
    		'dns_verification_timeout_ms must be clamped to 50ms min'
    		);
    }

    public function test_dns_verification_timeout_clamped_max(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'dns_verification' => ['timeout_ms' => 10000],  // too high
    	], $adapter);

    	$this->assertLessThanOrEqual(
    		2000,
    		$config->dns_verification_timeout_ms,
    		'dns_verification_timeout_ms must be clamped to 2000ms max'
    		);
    }

    /**
     * DNS verification TTLs must have minimum values.
     * positive_ttl < 3600: cache thrashing for known bots
     * negative_ttl < 60: hammering DNS for known-bad IPs
     */
    public function test_dns_verification_positive_ttl_floored(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'dns_verification' => ['positive_ttl' => 60],  // too low
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		3600,
    		$config->dns_verification_positive_ttl,
    		'dns_verification_positive_ttl must be >= 3600 (1 hour min)'
    		);
    }

    public function test_dns_verification_negative_ttl_floored(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'dns_verification' => ['negative_ttl' => 10],  // too low
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		60,
    		$config->dns_verification_negative_ttl,
    		'dns_verification_negative_ttl must be >= 60 (1 minute min)'
    		);
    }

    /**
     * Dynamic IP ranges TTL must be >= 3600 (1 hour).
     */
    public function test_dynamic_ip_ranges_ttl_floored(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'dynamic_ip_ranges' => ['ttl' => 60],  // too low
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		3600,
    		$config->dynamic_ip_ranges_ttl,
    		'dynamic_ip_ranges_ttl must be >= 3600'
    		);
    }

    /**
     * Rate limits: requests must be >= 1, window must be >= 1.
     * Zero/negative values would disable the limit entirely or cause
     * division by zero.
     */
    public function test_rate_limit_global_requests_floored(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'rate_limits' => [
    			'global' => ['requests' => 0, 'window' => 3600],
    		],
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		1,
    		$config->rate_limits['global']['requests'],
    		'rate_limits.global.requests must be >= 1'
    		);
    }

    public function test_rate_limit_window_floored(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'rate_limits' => [
    			'global' => ['requests' => 100, 'window' => 0],
    		],
    	], $adapter);

    	$this->assertGreaterThanOrEqual(
    		1,
    		$config->rate_limits['global']['window'],
    		'rate_limits.global.window must be >= 1'
    		);
    }

    /**
     * Threshold values must be >= 1.
     */
    public function test_thresholds_floored_at_one(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'head_flood_threshold'          => 0,
    		'head_probe_threshold'          => 0,
    		'asset_no_referer_threshold'    => 0,
    		'asset_only_session_threshold'  => 0,
    		'asset_pattern_threshold'       => 0,
    	], $adapter);

    	$this->assertGreaterThanOrEqual(1, $config->head_flood_threshold);
    	$this->assertGreaterThanOrEqual(1, $config->head_probe_threshold);
    	$this->assertGreaterThanOrEqual(1, $config->asset_no_referer_threshold);
    	$this->assertGreaterThanOrEqual(1, $config->asset_only_session_threshold);
    	$this->assertGreaterThanOrEqual(1, $config->asset_pattern_threshold);
    }

    /**
     * Strictness levels constant must contain exactly the three levels.
     */
    public function test_strictness_levels_constant(): void
    {
    	$this->assertSame(
    		['monitor-only', 'normal', 'strict'],
    		Configuration::STRICTNESS_LEVELS
    		);
    }

    /**
     * get_defaults() must return the same array on repeated calls
     * (caller should be able to safely inspect defaults without mutation).
     */
    public function test_get_defaults_is_pure(): void
    {
    	$a = Configuration::get_defaults();
    	$b = Configuration::get_defaults();

    	$this->assertEquals($a, $b);
    }

    /**
     * Mutating the result of get_defaults() must not affect subsequent calls.
     */
    public function test_get_defaults_returns_fresh_array(): void
    {
    	$a = Configuration::get_defaults();
    	$a['logging'] = false;
    	$a['preset'] = 'mutated';

    	$b = Configuration::get_defaults();

    	$this->assertTrue($b['logging'], 'logging must remain true after mutation');
    	$this->assertNotSame('mutated', $b['preset']);
    }
}
