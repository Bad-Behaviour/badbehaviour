<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\DnsblDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class DnsblDetectorTest extends TestCase
{
    private DnsblDetector $detector;

    protected function setUp(): void
    {
        $config = Configuration::from_array([
            'httpbl_key' => 'test-key',
            'httpbl_threat' => 25,
            'httpbl_maxage' => 30,
            'dnsbl_lists' => ['zen.spamhaus.org', 'bl.spamcop.net'],
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $this->detector = new DnsblDetector($config);
    }

    private function create_package(string $ip): RequestPackage
    {
        return new RequestPackage(
            ip: $ip,
            headers: [],
            headers_mixed: ['User-Agent' => 'Chrome/120'],
            request_method: 'GET',
            request_uri: '/',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Chrome/120',
        );
    }

    public function test_ipv6_returns_null(): void
    {
        $package = $this->create_package('2001:db8::1');

        $result = $this->detector->detect($package);

        $this->assertNull($result);
    }

    public function test_disabled_returns_null(): void
    {
        $config = Configuration::from_array([
            'httpbl_key' => '',
            'dnsbl_lists' => [],
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new DnsblDetector($config);
        $package = $this->create_package('192.0.2.1');

        $this->assertNull($detector->detect($package));
    }

    // Note: DNS-based tests would require mocking gethostbynamel
    // which is a global function. In practice, these would be integration tests
    // with a controlled DNS environment.
}
