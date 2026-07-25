<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Core;

use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

class ResultTest extends TestCase
{
    public function test_allow(): void
    {
        $result = Result::allow();

        $this->assertTrue($result->is_allowed());
        $this->assertFalse($result->is_blocked());
        $this->assertFalse($result->requires_challenge());
        $this->assertEquals(200, $result->http_status());
        $this->assertEquals(ResultCode::ALLOWED, $result->code);
    }

    public function test_block(): void
    {
        $package = new RequestPackage(
            ip: '192.168.1.1',
            headers: [],
            headers_mixed: [],
            request_method: 'GET',
            request_uri: '/test',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Test/1.0'
        );

        $result = Result::block(ResultCode::BLOCKED_BOT, 'Test block', $package, ['test' => 'data']);

        $this->assertFalse($result->is_allowed());
        $this->assertTrue($result->is_blocked());
        $this->assertFalse($result->requires_challenge());
        $this->assertEquals(403, $result->http_status());
        $this->assertEquals(ResultCode::BLOCKED_BOT, $result->code);
        $this->assertEquals('Test block', $result->message);
        $this->assertEquals($package, $result->package);
        $this->assertEquals(['test' => 'data'], $result->metadata);
        $this->assertNotNull($result->support_key);
    }

    public function test_challenge(): void
    {
        $package = new RequestPackage(
            ip: '192.168.1.1',
            headers: [],
            headers_mixed: [],
            request_method: 'GET',
            request_uri: '/test',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Test/1.0'
        );

        $result = Result::challenge(ResultCode::CHALLENGE_REQUIRED, 'Test challenge', $package);

        $this->assertFalse($result->is_allowed());
        $this->assertFalse($result->is_blocked());
        $this->assertTrue($result->requires_challenge());
        $this->assertEquals(403, $result->http_status());
        $this->assertEquals(ResultCode::CHALLENGE_REQUIRED, $result->code);
    }

    public function test_to_array(): void
    {
        $package = new RequestPackage(
            ip: '192.168.1.1',
            headers: [],
            headers_mixed: [],
            request_method: 'GET',
            request_uri: '/test',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Test/1.0'
        );

        $result = Result::block(ResultCode::BLOCKED_BOT, 'Test', $package);
        $array = $result->to_array();

        $this->assertArrayHasKey('code', $array);
        $this->assertArrayHasKey('message', $array);
        $this->assertArrayHasKey('support_key', $array);
        $this->assertArrayHasKey('http_status', $array);
        $this->assertArrayHasKey('metadata', $array);
        $this->assertEquals('blocked.bot', $array['code']);
        $this->assertEquals(403, $array['http_status']);
    }
}
