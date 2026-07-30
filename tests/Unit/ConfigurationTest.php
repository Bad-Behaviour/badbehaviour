<?php
// tests/Unit/ConfigurationTest.php - COMPLETE FIXED

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
        $this->assertEquals(['GPTBot', 'ClaudeBot', 'Google-Extended'], $config->allowed_ai_crawlers);
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
}
