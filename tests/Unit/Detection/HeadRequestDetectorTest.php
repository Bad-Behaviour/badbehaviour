<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\HeadRequestDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class HeadRequestDetectorTest extends TestCase
{
    private HeadRequestDetector $detector;
    private AdapterInterface $adapter;

    protected function setUp(): void
    {
        $this->adapter = $this->createMock(AdapterInterface::class);
        $config = Configuration::from_array([
            'enable_head_request_detection' => true,
            'head_require_referer' => true,
            'head_flood_threshold' => 20,
            'head_probe_threshold' => 50,
            'head_referer_exempt_paths' => ['/api/', '/wp-json/'],
        ], $this->adapter);

        $this->detector = new HeadRequestDetector($config, $this->adapter);
    }

    public function test_get_request_returns_null(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120',
            '203.0.113.1',
            'GET',
            '/page'
        );

        $this->assertNull($this->detector->detect($package));
    }

    public function test_head_without_referer_blocked(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120',
            '203.0.113.1',
            'HEAD',
            '/sitemap.xml'
        );

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('HEAD', $result->message);
        $this->assertEquals('head_no_referer', $result->metadata['type']);
    }

    public function test_head_with_referer_allowed(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120',
            '203.0.113.1',
            'HEAD',
            '/sitemap.xml',
            ['Referer' => 'https://example.com/admin']
        );

        $this->assertNull($this->detector->detect($package));
    }

    public function test_head_to_api_exempt_from_referer(): void
    {
        $package = RequestPackage::create_for_test(
            'MyApp/2.0',
            '203.0.113.1',
            'HEAD',
            '/api/v1/status'
        );

        $this->assertNull($this->detector->detect($package));
    }

    public function test_head_to_wp_json_exempt_from_referer(): void
    {
        $package = RequestPackage::create_for_test(
            'MyApp/2.0',
            '203.0.113.1',
            'HEAD',
            '/wp-json/wp/v2/posts'
        );

        $this->assertNull($this->detector->detect($package));
    }

    public function test_head_flood_blocked_after_threshold(): void
    {
        $session_id = 'test-session';
        $counter = 0;

        $this->adapter->method('get_behavior_profile')
            ->willReturnCallback(function($sid) use (&$counter) {
                return ['head_count' => $counter];
            });

        $this->adapter->method('save_behavior_profile')
            ->willReturnCallback(function($sid, $profile, $ttl) use (&$counter) {
                $counter = $profile['head_count'];
                return true;
            });

        // 20 HEAD requests pass (counter goes 1, 2, ..., 20)
        // 21st request exceeds threshold of 20
        $result = null;
        for ($i = 0; $i < 21; $i++) {
            $package = RequestPackage::create_for_test(
                'Mozilla/5.0 Chrome/120',
                '203.0.113.1',
                'HEAD',
                '/page' . $i,
                ['Referer' => 'https://example.com/admin'],
                [],
                $session_id
            );
            $result = $this->detector->detect($package);
        }

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('head_flood', $result->metadata['type']);
    }

    public function test_head_probing_blocked_after_threshold(): void
    {
        $counts = [];
        $this->adapter->method('increment_counter')
            ->willReturnCallback(function($key, $window) use (&$counts) {
                $counts[$key] = ($counts[$key] ?? 0) + 1;
                return $counts[$key];
            });

        // All HEAD requests have Referer (pass signal 1)
        // But probe count exceeds 50
        $result = null;
        for ($i = 0; $i < 51; $i++) {
            $package = RequestPackage::create_for_test(
                'Mozilla/5.0 Chrome/120',
                '198.51.100.42',
                'HEAD',
                '/page' . $i,
                ['Referer' => 'https://example.com/admin']
            );
            $result = $this->detector->detect($package);
        }

        $this->assertNotNull($result);
        $this->assertEquals('head_probing', $result->metadata['type']);
    }

    public function test_disabled_returns_null(): void
    {
        $config = Configuration::from_array([
            'enable_head_request_detection' => false,
        ], $this->adapter);

        $detector = new HeadRequestDetector($config, $this->adapter);
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120',
            '203.0.113.1',
            'HEAD',
            '/page'
        );

        $this->assertNull($detector->detect($package));
    }
}