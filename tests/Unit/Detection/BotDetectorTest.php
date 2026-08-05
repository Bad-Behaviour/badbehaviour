<?php
// tests/Unit/Detection/BotDetectorTest.php

declare(strict_types=1);

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
			'ai_crawlers' => [
				'allowed' => ['GPTBot'],
				'block_unverified' => true,
				'strict' => false,
			],
			'bot_categories' => ['blocked' => ['malicious']],
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
    	$config = \BadBehaviour\Configuration::from_array([
    		'ai_crawlers' => [
    			'allowed' => ['GPTBot'],
    			'block_unverified' => false,
    			'strict' => false,
    		],
    		'bot_categories' => ['blocked' => ['malicious']],
    	], new \BadBehaviour\Adapter\GenericAdapter());

    	$detector = new \BadBehaviour\Detection\BotDetector($config, new \BadBehaviour\Adapter\GenericAdapter());

    	$package = $this->createPackage('ClaudeBot/1.0', '192.0.2.1');
    	$result = $detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->requires_challenge());
    	$this->assertEquals(ResultCode::CHALLENGE_REQUIRED, $result->code);
    }

    public function test_ai_crawler_block_when_strict(): void
    {
    	$config = \BadBehaviour\Configuration::from_array([
    		'ai_crawlers' => [
    			'allowed' => ['GPTBot'],
    			'block_unverified' => true,
    			'strict' => true,
    		],
    		'bot_categories' => ['blocked' => ['malicious']],
    	], new \BadBehaviour\Adapter\GenericAdapter());

    	$detector = new \BadBehaviour\Detection\BotDetector($config, new \BadBehaviour\Adapter\GenericAdapter());

    	$package = $this->createPackage('ClaudeBot/1.0', '192.0.2.1');
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
        $cacheAdapter = new \BadBehaviour\Adapter\GenericAdapter();

        $cacheAdapter->set('bb:ip_ranges:merged', [
            'data' => ['googlebot' => ['64.233.160.0/19']],
            'fetched' => time(),
        ], 3600);

        $config = Configuration::from_array([
        	'dynamic_ip_ranges' => ['enabled' => true],
        	'ai_crawlers' => [
        		'allowed' => ['GPTBot'],
        		'block_unverified' => true,
        		'strict' => false,
        	],
        	'bot_categories' => ['blocked' => ['malicious']],
        ], $cacheAdapter);

        $detector = new BotDetector($config, $cacheAdapter);

        $package = $this->createPackage(
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            '64.233.160.1'
        );

        $result = $detector->detect($package);

        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }

    public function test_dynamic_ranges_disabled_uses_static(): void
    {
    	$config = Configuration::from_array([
    		'dynamic_ip_ranges' => ['enabled' => false],
    		'ai_crawlers' => [
    			'allowed' => ['GPTBot'],
    			'block_unverified' => true,
    			'strict' => false,
    		],
    		'bot_categories' => ['blocked' => ['malicious']],
    	], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new BotDetector($config, new \BadBehaviour\Adapter\GenericAdapter());

        $package = $this->createPackage(
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            '66.249.64.1'
        );

        $result = $detector->detect($package);
        $this->assertNotNull($result);
        $this->assertTrue($result->is_allowed());
    }

    // ========================================================================
    // Cloud infrastructure MUST be allowed
    // ========================================================================

    public function test_cloudflare_health_ip_always_allowed(): void
    {
    	$package = $this->createPackage('Some Random Probe Agent', '173.245.48.1');

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed(), 'Cloudflare probe IPs MUST be allowed');
    }

    public function test_aws_elb_health_ip_always_allowed(): void
    {
    	$package = $this->createPackage('AWS-ELB-HealthChecker/1.0', '54.239.128.1');

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed(), 'AWS ELB health check MUST be allowed');
    }

    public function test_gcp_load_balancer_health_always_allowed(): void
    {
    	$package = $this->createPackage('GoogleHC', '35.191.1.1');

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed());
    }

    public function test_azure_health_probe_always_allowed(): void
    {
    	$package = $this->createPackage('Azure-LB-Health-Probe', '168.63.129.16');

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed());
    }

    public function test_fastly_health_always_allowed(): void
    {
    	$package = $this->createPackage('Fastly', '151.101.1.1');

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed());
    }

    // ========================================================================
    // Regional search engines
    // ========================================================================

    public function test_coccoc_vietnam_bot_blocked_when_unverified(): void
    {
    	$package = $this->createPackage(
    		'Mozilla/5.0 (compatible; coccocbot/2.0; +http://coccoc.com)',
    		'192.0.2.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_blocked());
    	$this->assertEquals('blocked.bot', $result->code->value);
    }

    public function test_mailru_blocked_when_unverified(): void
    {
    	$package = $this->createPackage(
    		'Mozilla/5.0 (compatible; Mail.RU_Bot/2.0)',
    		'192.0.2.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertTrue($result->is_blocked());
    }

    // ========================================================================
    // AI crawler additions
    // ========================================================================

    public function test_amazonbot_blocked_when_unverified(): void
    {
    	$package = $this->createPackage(
    		'Mozilla/5.0 (compatible; Amazonbot/1.0; +https://developer.amazon.com/support/amazonbot)',
    		'192.0.2.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertTrue($result->is_blocked());
    	$this->assertEquals(ResultCode::BLOCKED_AI_CRAWLER, $result->code);
    }

    public function test_diffbot_blocked_when_unverified(): void
    {
    	$package = $this->createPackage(
    		'Diffbot/2.0 (+https://www.diffbot.com)',
    		'192.0.2.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertTrue($result->is_blocked());
    }

    public function test_brightdata_blocked_by_default(): void
    {
    	$package = $this->createPackage(
    		'Mozilla/5.0 (compatible; BrightData/1.0)',
    		'192.0.2.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertTrue($result->is_blocked(),
    		'BrightData residential proxy must default to BLOCK');
    	$this->assertEquals(ResultCode::BLOCKED_BOT, $result->code,
    		'Residential proxy is blocked via the generic BLOCKED_BOT code (see BotDetector::code_for_category)');
    }

    // ========================================================================
    // Shopping crawlers allowed (revenue)
    // ========================================================================

    public function test_facebook_catalog_allowed(): void
    {
    	$package = $this->createPackage(
    		'facebookcatalog/1.0',
    		'157.240.1.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed(),
    		'Facebook Catalog MUST be allowed (product feed revenue)');
    }

    // ========================================================================
    // Feed readers allowed
    // ========================================================================

    public function test_feedly_allowed(): void
    {
    	$package = $this->createPackage(
    		'Feedly/1.0 (+https://www.feedly.com/fetcher.html)',
    		'54.144.1.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed(),
    		'Feedly MUST be allowed (RSS reader brings real users)');
    }

    public function test_apple_news_allowed(): void
    {
    	$package = $this->createPackage(
    		'AppleNewsBot',
    		'17.1.2.3'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertNotNull($result);
    	$this->assertTrue($result->is_allowed(),
    		'Apple News MUST be allowed (publisher visibility)');
    }

    // ========================================================================
    // Petal promoted to search_engine
    // ========================================================================

    public function test_petal_search_blocked_when_unverified(): void
    {
    	$package = $this->createPackage(
    		'Mozilla/5.0 (compatible; PetalBot; +https://aspiegel.com/petalbot)',
    		'192.0.2.1'
    		);

    	$result = $this->detector->detect($package);

    	$this->assertTrue($result->is_blocked(),
    		'Unverified Petal (now search engine) must be blocked');
    }
}