<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\BehavioralDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class BehavioralDetectorTest extends TestCase
{
    private BehavioralDetector $detector;
    private AdapterInterface $adapter;

    protected function setUp(): void
    {
        $this->adapter = $this->createMock(AdapterInterface::class);
        $config = Configuration::from_array([], new \BadBehaviour\Adapter\GenericAdapter());
        $this->detector = new BehavioralDetector($config, $this->adapter);
    }

    private function create_package(string $ua, array $headers = []): RequestPackage
    {
        return RequestPackage::create_for_test($ua, '192.0.2.1', 'GET', '/test', $headers);
    }

    public function test_rapid_requests_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')->willReturn([
            'count' => 150,
            'first_seen' => time() - 30,
            'user_agents' => ['Chrome/120' => true],
            'ips' => ['192.0.2.1' => true],
            'static_count' => 50,
            'total_count' => 150,
            'urls' => [],
        ]);

        $package = $this->create_package('Chrome/120');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('rapid_requests', $result->metadata['type']);
    }

    public function test_rotating_ua_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')->willReturn([
            'count' => 20,
            'first_seen' => time() - 300,
            'user_agents' => [
                'Chrome/120' => true,
                'Firefox/121' => true,
                'Safari/17' => true,
                'Edge/120' => true,
                'Opera/106' => true,
                'Bot/1.0' => true,
            ],
            'ips' => ['192.0.2.1' => true],
            'static_count' => 10,
            'total_count' => 20,
            'urls' => [],
        ]);

        $package = $this->create_package('Chrome/120');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('rotating_ua', $result->metadata['type']);
    }

    public function test_rotating_ip_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')->willReturn([
            'count' => 10,
            'first_seen' => time() - 300,
            'user_agents' => ['Chrome/120' => true],
            'ips' => [
                '192.0.2.1' => true,
                '192.0.2.2' => true,
                '192.0.2.3' => true,
                '192.0.2.4' => true,
            ],
            'static_count' => 5,
            'total_count' => 10,
            'urls' => [],
        ]);

        $package = $this->create_package('Chrome/120');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('rotating_ip', $result->metadata['type']);
    }

    public function test_no_static_resources_blocked(): void
    {
        $this->adapter->method('get_behavior_profile')->willReturn([
            'count' => 30,
            'first_seen' => time() - 300,
            'user_agents' => ['Chrome/120' => true],
            'ips' => ['192.0.2.1' => true],
            'static_count' => 1,
            'total_count' => 30,
            'urls' => [],
        ]);

        $package = $this->create_package('Chrome/120');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('no_static', $result->metadata['type']);
    }

    public function test_missing_accept_header_on_browser(): void
    {
        $package = $this->create_package('Chrome/120', ['Accept' => '']);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('browser_no_accept', $result->metadata['type']);
    }

    public function test_missing_accept_encoding_on_modern_browser(): void
    {
        $package = $this->create_package('Chrome/120', ['Accept-Encoding' => '']);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('browser_no_encoding', $result->metadata['type']);
    }

    public function test_connection_conflict(): void
    {
        $package = $this->create_package('Chrome/120', ['Connection' => 'keep-alive, close']);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('conn_conflict', $result->metadata['type']);
    }

    public function test_te_without_connection_te(): void
    {
        $package = $this->create_package('Chrome/120', ['Te' => 'trailers', 'Connection' => 'keep-alive']);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('te_missing', $result->metadata['type']);
    }

    public function test_content_length_on_get(): void
    {
        $package = $this->create_package('Chrome/120')
            ->with_modified([
                'request_method' => 'GET',
                'headers_mixed' => array_merge(
                    RequestPackage::create_for_test('Chrome/120')->headers_mixed,
                    ['Content-Length' => '100']
                )
            ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('content_length_on_get', $result->metadata['type']);
    }

    public function test_missing_host_on_http11(): void
    {
        $package = $this->create_package('Chrome/120')
            ->with_modified([
                'server_protocol' => 'HTTP/1.1',
                'headers_mixed' => array_merge(
                    RequestPackage::create_for_test('Chrome/120')->headers_mixed,
                    ['Host' => '']
                )
            ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('missing_host', $result->metadata['type']);
    }

    public function test_empty_referer_on_post(): void
    {
        $package = $this->create_package('Chrome/120')
            ->with_modified([
                'request_method' => 'POST',
                'request_time' => 0.1, // Not too fast
                'headers_mixed' => array_merge(
                    RequestPackage::create_for_test('Chrome/120')->headers_mixed,
                    ['Referer' => '']
                )
            ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('empty_referer', $result->metadata['type']);
    }

    public function test_xff_too_many_hops(): void
    {
        $package = $this->create_package('Chrome/120', [
            'X-Forwarded-For' => implode(', ', array_map(fn($i) => "192.0.2.$i", range(1, 15)))
        ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertEquals('xff_too_many', $result->metadata['type']);
    }

    public function test_normal_browser_allowed(): void
    {
        $this->adapter->method('get_behavior_profile')->willReturn([
            'count' => 5,
            'first_seen' => time() - 300,
            'user_agents' => ['Chrome/120' => true],
            'ips' => ['192.0.2.1' => true],
            'static_count' => 3,
            'total_count' => 5,
            'urls' => [],
        ]);

        $package = $this->create_package('Chrome/120');
        $result = $this->detector->detect($package);

        $this->assertNull($result);
    }
}
