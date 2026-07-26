<?php

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\BehavioralDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class BehavioralDetectorTest extends TestCase
{
    private BehavioralDetector $detector;
    private Configuration $config;
    private AdapterInterface $adapter;

    protected function setUp(): void
    {
        $this->adapter = $this->createMock(AdapterInterface::class);
        $this->config = Configuration::from_array([
            'strict' => false,
            'offsite_forms' => false,
        ], $this->adapter);

        $this->detector = new BehavioralDetector($this->config, $this->adapter);
    }

    public function test_missing_accept_header_on_browser(): void
    {
        // Traditional browser page load (not AJAX, not JSON) - SHOULD BLOCK
        // EXPLICITLY omit Accept header by passing empty string
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'GET',
            '/page',
            ['Host' => 'example.com', 'Accept' => '']  // Explicitly empty Accept
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('Accept', $result->message);
    }

    public function test_missing_accept_header_on_ajax_allowed(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/api/preview',
            [
                'Host' => 'example.com',
                'X-Requested-With' => 'XMLHttpRequest',
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
            ['body' => 'test']
        );

        $result = $this->detector->detect($package);
        $this->assertNull($result);
    }

    public function test_missing_accept_header_on_json_api_allowed(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/api/comment',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
            ['body' => 'test']
        );

        $result = $this->detector->detect($package);
        $this->assertNull($result);
    }

    public function test_missing_accept_encoding_on_modern_browser(): void
    {
        $this->config = Configuration::from_array([
            'strict' => true,
            'offsite_forms' => false,
        ], $this->adapter);
        $this->detector = new BehavioralDetector($this->config, $this->adapter);

        // EXPLICITLY omit Accept-Encoding
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'GET',
            '/page',
            ['Host' => 'example.com', 'Accept' => 'text/html', 'Accept-Encoding' => '']
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('Accept-Encoding', $result->message);
    }

    public function test_missing_accept_encoding_not_strict_allowed(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'GET',
            '/page',
            ['Host' => 'example.com', 'Accept' => 'text/html', 'Accept-Encoding' => '']
        );

        $result = $this->detector->detect($package);
        $this->assertNull($result);
    }

    public function test_empty_referer_on_post(): void
    {
        $this->config = Configuration::from_array([
            'strict' => true,
            'offsite_forms' => false,
        ], $this->adapter);
        $this->detector = new BehavioralDetector($this->config, $this->adapter);

        // Traditional form POST - EXPLICITLY omit Referer
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/comment',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Accept' => 'text/html',
                'Referer' => '',  // Explicitly empty
            ],
            ['body' => 'test comment']
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('Referer', $result->message);
    }

    public function test_empty_referer_on_ajax_allowed(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/api/comment',
            [
                'Host' => 'example.com',
                'X-Requested-With' => 'XMLHttpRequest',
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
            ['body' => 'test']
        );

        $result = $this->detector->detect($package);
        $this->assertNull($result);
    }

    public function test_rapid_requests_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')
            ->willReturn([
                'count' => 150,
                'first_seen' => time() - 30,
                'user_agents' => ['ua1' => true],
                'ips' => ['192.0.2.1' => true],
                'static_count' => 20,
                'total_count' => 150,
                'urls' => [],
            ]);

        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120.0.0.0',
            '192.0.2.1',
            'GET',
            '/page',
            ['Host' => 'example.com'],
            [],
            'test-session'
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('Rapid requests', $result->message);
    }

    public function test_rotating_user_agents_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')
            ->willReturn([
                'count' => 10,
                'first_seen' => time() - 100,
                'user_agents' => array_fill_keys(range('a', 'f'), true),
                'ips' => ['192.0.2.1' => true],
                'static_count' => 5,
                'total_count' => 10,
                'urls' => [],
            ]);

        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120.0.0.0',
            '192.0.2.1',
            'GET',
            '/page',
            ['Host' => 'example.com'],
            [],
            'test-session'
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('Rotating User-Agents', $result->message);
    }

    public function test_no_static_resources_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')
            ->willReturn([
                'count' => 25,
                'first_seen' => time() - 100,
                'user_agents' => ['ua1' => true],
                'ips' => ['192.0.2.1' => true],
                'static_count' => 0,
                'total_count' => 25,
                'urls' => [],
            ]);

        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120.0.0.0',
            '192.0.2.1',
            'GET',
            '/page',
            ['Host' => 'example.com'],
            [],
            'test-session'
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('No static resources', $result->message);
    }

    public function test_form_timing_too_fast_blocked(): void
    {
        // Use willReturnCallback to handle consecutive calls
        $this->adapter->method('get_behavior_profile')
            ->willReturnCallback(function ($session_id) {
                return [
                    'form_load_time' => time() - 1,  // 1 second ago
                    'count' => 1,
                    'first_seen' => time(),
                    'user_agents' => [],
                    'ips' => [],
                    'static_count' => 0,
                    'total_count' => 1,
                    'urls' => [],
                ];
            });

        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/comment',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Accept' => 'text/html',
                'Referer' => 'https://example.com/page',
            ],
            ['body' => 'test comment'],
            'test-session'
        );

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('too fast after form load', $result->message);
    }

    public function test_form_timing_normal_allowed(): void
    {
        $this->adapter->method('get_behavior_profile')
            ->willReturnCallback(function ($session_id) {
                return [
                    'form_load_time' => time() - 10,  // 10 seconds ago
                    'count' => 1,
                    'first_seen' => time(),
                    'user_agents' => [],
                    'ips' => [],
                    'static_count' => 0,
                    'total_count' => 1,
                    'urls' => [],
                ];
            });

        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/comment',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Accept' => 'text/html',
                'Referer' => 'https://example.com/page',
            ],
            ['body' => 'test comment'],
            'test-session'
        );

        $result = $this->detector->detect($package);
        $this->assertNull($result);
    }

    public function test_form_timing_ajax_allowed(): void
    {
        $package = RequestPackage::create_for_test(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '192.0.2.1',
            'POST',
            '/api/preview',
            [
                'Host' => 'example.com',
                'X-Requested-With' => 'XMLHttpRequest',
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
            ['body' => 'test'],
            'test-session'
        );

        $result = $this->detector->detect($package);
        $this->assertNull($result);
    }
}
