<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Util\HeaderUtil;
use BadBehaviour\Util\IpUtil;
use PHPUnit\Framework\TestCase;

class RequestPackageTest extends TestCase
{
    protected function setUp(): void
    {
        $_SERVER = [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/test',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'REMOTE_ADDR' => '192.168.1.100',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'HTTP_ACCEPT' => 'text/html',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'REQUEST_TIME_FLOAT' => microtime(true),
        ];
    }

    public function test_from_globals(): void
    {
        $package = RequestPackage::from_globals([
            'reverse_proxy' => false,
        ]);

        $this->assertEquals('192.168.1.100', $package->ip);
        $this->assertEquals('GET', $package->request_method);
        $this->assertEquals('/test', $package->request_uri);
        $this->assertEquals('HTTP/1.1', $package->server_protocol);
        $this->assertEquals('Chrome', $package->ua_browser);
        $this->assertEquals(120, $package->ua_major);
        $this->assertEquals('Windows', $package->ua_os);
        $this->assertEquals('desktop', $package->ua_device);
        $this->assertFalse($package->ua_is_mobile);
        $this->assertFalse($package->ua_is_bot);
        $this->assertEquals('blink', $package->ua_engine);
    }

    public function test_claims_browser(): void
    {
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);

        $this->assertTrue($package->claims_browser('Chrome'));
        $this->assertFalse($package->claims_browser('Firefox'));
    }

    public function test_claims_modern_browser(): void
    {
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);
        $this->assertTrue($package->claims_modern_browser());
    }

    public function test_claims_modern_browser_old_version(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0) Chrome/80.0.0.0 Safari/537.36';
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);

        $this->assertFalse($package->claims_modern_browser());
    }

    public function test_get_engine(): void
    {
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);
        $this->assertEquals('blink', $package->get_engine());
    }

    public function test_with_enrichment(): void
    {
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);
        $enriched = $package->with_enrichment('AS15169', 'US', 'ja3hash', 'h2hash');

        $this->assertEquals('AS15169', $enriched->asn);
        $this->assertEquals('US', $enriched->country);
        $this->assertEquals('ja3hash', $enriched->ja3);
        $this->assertEquals('h2hash', $enriched->h2_settings);
        // Original values preserved
        $this->assertEquals('Chrome', $enriched->ua_browser);
    }

    public function test_mobile_device(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15';
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);

        $this->assertEquals('mobile', $package->ua_device);
        $this->assertTrue($package->ua_is_mobile);
        $this->assertEquals('iOS', $package->ua_os);
    }

    public function test_bot_device(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; Googlebot/2.1)';
        $package = RequestPackage::from_globals(['reverse_proxy' => false]);

        $this->assertEquals('bot', $package->ua_device);
        $this->assertTrue($package->ua_is_bot);
    }
}
