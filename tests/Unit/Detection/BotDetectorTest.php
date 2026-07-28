<?php
// tests/Unit/Detection/BotDetectorTest.php

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\BotDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class BotDetectorTest extends TestCase
{
    private BotDetector $detector;
    private GenericAdapter $adapter;

    protected function setUp(): void
    {
        $this->adapter = new GenericAdapter();
        $config = Configuration::from_array([
            'allowed_ai_crawlers' => ['GPTBot'],
            'block_unverified_ai' => true,
            'strict_ai' => false,
            'strict_search_engines' => false,
            'blocked_bot_categories' => ['malicious'],
        ], $this->adapter);

        $this->detector = new BotDetector($config, $this->adapter);
    }

    private function createPackage(string $ua, string $ip = '203.0.113.1'): RequestPackage
    {
        return RequestPackage::create_for_test($ua, $ip);
    }

    public function test_known_search_engine_allowed(): void
    {
        $package = $this->createPackage(
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            '66.249.64.1'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }

    public function test_unknown_bot_ua_only_not_allowed(): void
    {
        $package = $this->createPackage(
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            '192.0.2.1'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_blocked());
        $this->assertEquals('blocked.bot', $result->code->value);
    }

    public function test_ai_crawler_allowed_when_configured(): void
    {
        $package = $this->createPackage(
            'GPTBot/1.0',
            '20.15.240.1'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }

    public function test_ai_crawler_challenge_when_verified_not_allowed(): void
    {
        $package = $this->createPackage(
            'ClaudeBot/1.0',
            '192.0.2.1'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->requires_challenge());
        $this->assertEquals(ResultCode::CHALLENGE_REQUIRED, $result->code);
    }

    public function test_ai_crawler_block_when_strict(): void
    {
        $config = \BadBehaviour\Configuration::from_array([
            'allowed_ai_crawlers' => ['GPTBot'],
            'block_unverified_ai' => true,
            'strict_ai' => true,
            'strict_search_engines' => false,
            'blocked_bot_categories' => ['malicious'],
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new \BadBehaviour\Detection\BotDetector($config, new \BadBehaviour\Adapter\GenericAdapter());

        $package = $this->createPackage(
            'ClaudeBot/1.0',
            '192.0.2.1'
        );

        $result = $detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_AI_CRAWLER, $result->code);
    }

    public function test_seo_crawler_block_when_unverified(): void
    {
        $package = $this->createPackage(
            'SemrushBot/1.0',
            '192.0.2.1'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_SEO_CRAWLER, $result->code);
    }

    public function test_social_crawler_unverified_log_only(): void
    {
        $package = $this->createPackage(
            'facebookexternalhit/1.1',
            '192.0.2.1'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }

    public function test_dynamic_ranges_cached(): void
    {
        // Use FileCache adapter for testing cache
        $cacheAdapter = new \BadBehaviour\Adapter\GenericAdapter();

        // Manually set cache
        $cacheAdapter->set('bb:ip_ranges:merged', [
            'data' => ['googlebot' => ['64.233.160.0/19']],
            'fetched' => time(),
        ], 3600);

        $config = Configuration::from_array([
            'enable_dynamic_ip_ranges' => true,
            'allowed_ai_crawlers' => ['GPTBot'],
            'block_unverified_ai' => true,
            'strict_ai' => false,
            'strict_search_engines' => false,
            'blocked_bot_categories' => ['malicious'],
        ], $cacheAdapter);

        $detector = new BotDetector($config, $cacheAdapter);

        $package = $this->createPackage(
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            '64.233.160.1'
        );

        $result = $detector->detect($package);

        // Should use cached ranges and allow
        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }

    public function test_dynamic_ranges_disabled_uses_static(): void
    {
        $config = Configuration::from_array([
            'enable_dynamic_ip_ranges' => false,
            'allowed_ai_crawlers' => ['GPTBot'],
            'block_unverified_ai' => true,
            'strict_ai' => false,
            'strict_search_engines' => false,
            'blocked_bot_categories' => ['malicious'],
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new BotDetector($config, new \BadBehaviour\Adapter\GenericAdapter());

        // Googlebot with static range IP should work
        $package = $this->createPackage(
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            '66.249.64.1' // In static ranges
        );

        $result = $detector->detect($package);
        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }
}