<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Core;

use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class ResultCodeTest extends TestCase
{

	public function test_http_status(): void
	{
		$this->assertEquals(200, ResultCode::ALLOWED->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_BOT->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_AI_CRAWLER->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_MALICIOUS_UA->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_ATTACK_PATTERN->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_DNSBL->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_HTTPBL->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_BEHAVIORAL->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_FINGERPRINT->http_status());
		$this->assertEquals(429, ResultCode::BLOCKED_RATE_LIMIT->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_CUSTOM_RULE->http_status());
		$this->assertEquals(403, ResultCode::BLOCKED_GEOIP->http_status());
		$this->assertEquals(403, ResultCode::CHALLENGE_REQUIRED->http_status());
		$this->assertEquals(403, ResultCode::CHALLENGE_FAILED->http_status());
		$this->assertEquals(500, ResultCode::ERROR_INTERNAL->http_status());
		$this->assertEquals(500, ResultCode::ERROR_CONFIGURATION->http_status());
	}

	public function test_is_blocked(): void
	{
		$this->assertFalse(ResultCode::ALLOWED->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_BOT->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_AI_CRAWLER->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_MALICIOUS_UA->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_ATTACK_PATTERN->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_DNSBL->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_HTTPBL->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_BEHAVIORAL->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_FINGERPRINT->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_RATE_LIMIT->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_CUSTOM_RULE->is_blocked());
		$this->assertTrue(ResultCode::BLOCKED_GEOIP->is_blocked());
		$this->assertFalse(ResultCode::CHALLENGE_REQUIRED->is_blocked());
		$this->assertTrue(ResultCode::CHALLENGE_FAILED->is_blocked());
		$this->assertFalse(ResultCode::ERROR_INTERNAL->is_blocked());
		$this->assertFalse(ResultCode::ERROR_CONFIGURATION->is_blocked());
	}

	public function test_requires_challenge(): void
	{
		$this->assertFalse(ResultCode::ALLOWED->requires_challenge());
		$this->assertFalse(ResultCode::BLOCKED_BOT->requires_challenge());
		$this->assertTrue(ResultCode::CHALLENGE_REQUIRED->requires_challenge());
		$this->assertFalse(ResultCode::CHALLENGE_FAILED->requires_challenge());
	}
}
