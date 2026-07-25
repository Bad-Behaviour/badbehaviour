<?php

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

        $this->assertTrue($config->logging);
        $this->assertFalse($config->verbose);
        $this->assertFalse($config->strict);
        $this->assertFalse($config->reverse_proxy);
        $this->assertEquals('X-Forwarded-For', $config->reverse_proxy_header);
        $this->assertEquals('', $config->httpbl_key);
        $this->assertEquals(25, $config->httpbl_threat);
        $this->assertEquals(30, $config->httpbl_maxage);
        $this->assertEquals(['zen.spamhaus.org', 'bl.spamcop.net'], $config->dnsbl_lists);
        $this->assertEquals([], $config->allowed_ai_crawlers);
        $this->assertTrue($config->block_unverified_ai);
        $this->assertFalse($config->strict_ai);
        $this->assertFalse($config->strict_search_engines);
        $this->assertEquals(['malicious'], $config->blocked_bot_categories);
        $this->assertTrue($config->rate_limit_enabled);
        $this->assertArrayHasKey('global', $config->rate_limits);
        $this->assertArrayHasKey('per_minute', $config->rate_limits);
        $this->assertArrayHasKey('post', $config->rate_limits);
        $this->assertArrayHasKey('login', $config->rate_limits);
        $this->assertFalse($config->geoip_enabled);
        $this->assertFalse($config->challenge_enabled);
        $this->assertEquals('builtin', $config->challenge_provider);
        $this->assertEquals(0.5, $config->recaptcha_min_score);
        $this->assertSame($adapter, $config->adapter);
    }

    public function test_from_array_overrides(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'logging' => false,
            'strict' => true,
            'reverse_proxy' => true,
            'reverse_proxy_header' => 'CF-Connecting-IP',
            'reverse_proxy_addresses' => ['10.0.0.0/8'],
            'httpbl_key' => 'test-key',
            'httpbl_threat' => 50,
            'httpbl_maxage' => 60,
            'allowed_ai_crawlers' => ['GPTBot', 'ClaudeBot'],
            'block_unverified_ai' => false,
            'strict_ai' => true,
            'blocked_bot_categories' => ['malicious', 'seo_crawler'],
            'rate_limit_enabled' => false,
            'geoip_enabled' => true,
            'geoip_database_path' => '/path/to/geoip.mmdb',
            'blocked_countries' => ['KP', 'IR'],
            'challenge_enabled' => true,
            'challenge_provider' => 'hcaptcha',
            'challenge_site_key' => 'site-key',
            'challenge_secret_key' => 'secret-key',
            'recaptcha_min_score' => 0.7,
        ], $adapter);

        $this->assertFalse($config->logging);
        $this->assertTrue($config->strict);
        $this->assertTrue($config->reverse_proxy);
        $this->assertEquals('CF-Connecting-IP', $config->reverse_proxy_header);
        $this->assertEquals(['10.0.0.0/8'], $config->reverse_proxy_addresses);
        $this->assertEquals('test-key', $config->httpbl_key);
        $this->assertEquals(50, $config->httpbl_threat);
        $this->assertEquals(60, $config->httpbl_maxage);
        $this->assertEquals(['GPTBot', 'ClaudeBot'], $config->allowed_ai_crawlers);
        $this->assertFalse($config->block_unverified_ai);
        $this->assertTrue($config->strict_ai);
        $this->assertEquals(['malicious', 'seo_crawler'], $config->blocked_bot_categories);
        $this->assertFalse($config->rate_limit_enabled);
        $this->assertTrue($config->geoip_enabled);
        $this->assertEquals('/path/to/geoip.mmdb', $config->geoip_database_path);
        $this->assertEquals(['KP', 'IR'], $config->blocked_countries);
        $this->assertTrue($config->challenge_enabled);
        $this->assertEquals('hcaptcha', $config->challenge_provider);
        $this->assertEquals('site-key', $config->challenge_site_key);
        $this->assertEquals('secret-key', $config->challenge_secret_key);
        $this->assertEquals(0.7, $config->recaptcha_min_score);
    }

    public function test_type_coercion(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'httpbl_threat' => '999', // Should clamp to 255
            'httpbl_maxage' => '-10', // Should clamp to 0
            'rate_limits' => [
                'global' => ['requests' => '0', 'window' => '-5'], // Should become 1, 1
            ],
        ], $adapter);

        $this->assertEquals(255, $config->httpbl_threat);
        $this->assertEquals(0, $config->httpbl_maxage);
        $this->assertEquals(1, $config->rate_limits['global']['requests']);
        $this->assertEquals(1, $config->rate_limits['global']['window']);
    }

    public function test_array_normalization(): void
    {
        $adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'reverse_proxy_addresses' => '10.0.0.0/8', // String instead of array
            'dnsbl_lists' => 'zen.spamhaus.org',
            'allowed_ai_crawlers' => 'GPTBot',
        ], $adapter);

        $this->assertEquals(['10.0.0.0/8'], $config->reverse_proxy_addresses);
        $this->assertEquals(['zen.spamhaus.org'], $config->dnsbl_lists);
        $this->assertEquals(['GPTBot'], $config->allowed_ai_crawlers);
    }
}
