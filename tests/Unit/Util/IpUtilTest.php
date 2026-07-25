<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Util\IpUtil;
use PHPUnit\Framework\TestCase;

class IpUtilTest extends TestCase
{
    public function test_normalize_ipv4(): void
    {
        $this->assertEquals('192.168.1.1', IpUtil::normalize('192.168.1.1'));
        $this->assertEquals('10.0.0.1', IpUtil::normalize('::ffff:10.0.0.1'));
    }

    public function test_normalize_ipv6(): void
    {
        $this->assertEquals('2001:db8::1', IpUtil::normalize('2001:db8::1'));
        $this->assertEquals('::1', IpUtil::normalize('::1'));
    }

    public function test_is_ipv6(): void
    {
        $this->assertTrue(IpUtil::is_ipv6('2001:db8::1'));
        $this->assertTrue(IpUtil::is_ipv6('::1'));
        $this->assertTrue(IpUtil::is_ipv6('::ffff:192.168.1.1'));
        $this->assertFalse(IpUtil::is_ipv6('192.168.1.1'));
    }

    public function test_is_private_ipv4(): void
    {
        $this->assertTrue(IpUtil::is_private('10.0.0.1'));
        $this->assertTrue(IpUtil::is_private('10.255.255.255'));
        $this->assertTrue(IpUtil::is_private('172.16.0.1'));
        $this->assertTrue(IpUtil::is_private('172.31.255.255'));
        $this->assertTrue(IpUtil::is_private('192.168.1.1'));
        $this->assertTrue(IpUtil::is_private('127.0.0.1'));
        $this->assertTrue(IpUtil::is_private('169.254.1.1'));
        $this->assertTrue(IpUtil::is_private('100.64.0.1'));
        $this->assertTrue(IpUtil::is_private('::ffff:10.0.0.1')); // IPv4-mapped

        $this->assertFalse(IpUtil::is_private('8.8.8.8'));
        $this->assertFalse(IpUtil::is_private('1.1.1.1'));
    }

    public function test_is_private_ipv6(): void
    {
        $this->assertTrue(IpUtil::is_private('::1'));
        $this->assertTrue(IpUtil::is_private('fc00::1'));
        $this->assertTrue(IpUtil::is_private('fd00::1'));
        $this->assertTrue(IpUtil::is_private('fe80::1'));
        $this->assertTrue(IpUtil::is_private('2001:db8::1'));
        $this->assertTrue(IpUtil::is_private('::ffff:192.168.1.1'));

        $this->assertFalse(IpUtil::is_private('2001:4860:4860::8888')); // Google DNS
    }

    public function test_match_cidr_ipv4(): void
    {
        $this->assertTrue(IpUtil::match_cidr('192.168.1.50', '192.168.1.0/24'));
        $this->assertTrue(IpUtil::match_cidr('10.5.5.5', '10.0.0.0/8'));
        $this->assertTrue(IpUtil::match_cidr('172.20.1.1', '172.16.0.0/12'));
        $this->assertFalse(IpUtil::match_cidr('192.168.2.1', '192.168.1.0/24'));
        $this->assertFalse(IpUtil::match_cidr('8.8.8.8', '192.168.1.0/24'));
    }

    public function test_match_cidr_ipv6(): void
    {
        $this->assertTrue(IpUtil::match_cidr('2001:db8::1', '2001:db8::/32'));
        $this->assertTrue(IpUtil::match_cidr('fc00::1', 'fc00::/7'));
        $this->assertFalse(IpUtil::match_cidr('2001:db9::1', '2001:db8::/32'));
    }

    public function test_match_cidr_single_ip(): void
    {
        $this->assertTrue(IpUtil::match_cidr('192.168.1.1', '192.168.1.1'));
        $this->assertTrue(IpUtil::match_cidr('2001:db8::1', '2001:db8::1'));
        $this->assertFalse(IpUtil::match_cidr('192.168.1.2', '192.168.1.1'));
    }

    public function test_match_any(): void
    {
        $cidrs = ['10.0.0.0/8', '192.168.0.0/16', '2001:db8::/32'];

        $this->assertTrue(IpUtil::match_any('10.5.5.5', $cidrs));
        $this->assertTrue(IpUtil::match_any('192.168.1.1', $cidrs));
        $this->assertTrue(IpUtil::match_any('2001:db8::1', $cidrs));
        $this->assertFalse(IpUtil::match_any('8.8.8.8', $cidrs));
    }
}
