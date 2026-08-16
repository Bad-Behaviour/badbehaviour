<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\RateLimitDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class RateLimitDetectorTest extends TestCase
{
    private RateLimitDetector $detector;
    private AdapterInterface $adapter;

    protected function setUp(): void
    {
        $this->adapter = $this->createMock(AdapterInterface::class);
        $config = Configuration::from_array([
        	'rate_limits' => [
        		'enabled'    => true,
        		'global'     => ['requests' => 10, 'window' => 60],
        		'per_minute' => ['requests' => 5, 'window' => 60],
        		'post'       => ['requests' => 3, 'window' => 60],
        		'login'      => ['requests' => 2, 'window' => 60],
        	],
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $this->detector = new RateLimitDetector($config, $this->adapter);
    }

    private function create_package(string $method = 'GET', string $uri = '/'): RequestPackage
    {
        return new RequestPackage(
            ip: '192.0.2.1',
            headers: [],
            headers_mixed: ['User-Agent' => 'Chrome/120'],
            request_method: $method,
            request_uri: $uri,
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Chrome/120',
        );
    }

    public function test_disabled_returns_null(): void
    {
    	$config = Configuration::from_array([
    		'rate_limits' => ['enabled' => false],
    	], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new RateLimitDetector($config, $this->adapter);
        $package = $this->create_package();

        $this->assertNull($detector->detect($package));
    }

    public function test_global_limit_exceeded(): void
    {
        // Use a callback to track counts per key
        $counts = [];
        $this->adapter->method('increment_counter')
            ->willReturnCallback(function($key, $window) use (&$counts) {
                $counts[$key] = ($counts[$key] ?? 0) + 1;
                return $counts[$key];
            });

        $package = $this->create_package();

        // First 5 should pass (per_minute limit)
        for ($i = 0; $i < 5; $i++) {
            $result = $this->detector->detect($package);
            $this->assertNull($result, "Request $i should pass");
        }

        // 6th should hit per_minute limit
        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_RATE_LIMIT, $result->code);
        $this->assertEquals('per_minute', $result->metadata['limit_name']);
    }

    public function test_post_limit(): void
    {
        $counts = [];
        $this->adapter->method('increment_counter')
            ->willReturnCallback(function($key, $window) use (&$counts) {
                $counts[$key] = ($counts[$key] ?? 0) + 1;
                return $counts[$key];
            });

        $package = $this->create_package('POST', '/api');

        for ($i = 0; $i < 3; $i++) {
            $result = $this->detector->detect($package);
            $this->assertNull($result);
        }

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_RATE_LIMIT, $result->code);
        $this->assertEquals('post', $result->metadata['limit_name']);
    }

    public function test_login_limit(): void
    {
        $counts = [];
        $this->adapter->method('increment_counter')
            ->willReturnCallback(function($key, $window) use (&$counts) {
                $counts[$key] = ($counts[$key] ?? 0) + 1;
                return $counts[$key];
            });

        $package = $this->create_package('POST', '/login');

        for ($i = 0; $i < 2; $i++) {
            $result = $this->detector->detect($package);
            $this->assertNull($result);
        }

        $result = $this->detector->detect($package);
        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_RATE_LIMIT, $result->code);
        $this->assertEquals('login', $result->metadata['limit_name']);
    }

    public function test_different_ips_independent(): void
    {
        $counts = [];
        $this->adapter->method('increment_counter')
            ->willReturnCallback(function($key, $window) use (&$counts) {
                $counts[$key] = ($counts[$key] ?? 0) + 1;
                return $counts[$key];
            });

        $package1 = $this->create_package();
        $package1 = $package1->with_modified(['ip' => '192.0.2.1']);

        $package2 = $this->create_package();
        $package2 = $package2->with_modified(['ip' => '192.0.2.2']);

        $result1 = $this->detector->detect($package1);
        $result2 = $this->detector->detect($package2);

        // Both should pass as they have separate counters
        $this->assertNull($result1);
        $this->assertNull($result2);
    }
}
