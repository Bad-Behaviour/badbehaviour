<?php
// tests/Unit/ConfigurationTest.php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit;

use BadBehaviour\Configuration;
use BadBehaviour\Adapter\GenericAdapter;
use PHPUnit\Framework\TestCase;

class ConfigurationTest extends TestCase
{
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
}
