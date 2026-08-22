<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Challenge;

use BadBehaviour\Challenge\BuiltinChallenge;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

class BuiltinChallengeTest extends TestCase
{

	private BuiltinChallenge $challenge;

	private AdapterInterface $adapter;

	protected function setUp(): void
	{
		$this->adapter = $this->createMock(AdapterInterface::class);
		$config = Configuration::from_array([], new \BadBehaviour\Adapter\GenericAdapter());
		$this->challenge = new BuiltinChallenge($config, $this->adapter);

		// Ensure REMOTE_ADDR is set for tests
		$_SERVER['REMOTE_ADDR'] = '192.0.2.1';
	}

	public function test_verify_without_token(): void
	{
		$package = new RequestPackage(ip: '192.0.2.1', headers: [], headers_mixed: [], request_method: 'GET', request_uri: '/', server_protocol: 'HTTP/1.1', request_entity: [], user_agent: 'Test/1.0');

		$result = $this->challenge->verify($package);
		$this->assertFalse($result);
	}

	public function test_verify_with_valid_token(): void
	{
		$this->adapter->expects($this->once())
			->method('get_counter')
			->willReturn(1);
		$this->adapter->expects($this->once())
			->method('delete')
			->willReturn(true);

		$package = new RequestPackage(ip: '192.0.2.1', headers: [], headers_mixed: [], request_method: 'POST', request_uri: '/', server_protocol: 'HTTP/1.1', request_entity: [
			'bb_challenge_token' => 'valid-token'
		], user_agent: 'Test/1.0');

		$result = $this->challenge->verify($package);
		$this->assertTrue($result);
	}

	public function test_verify_with_invalid_token(): void
	{
		$this->adapter->method('get_counter')->willReturn(0);

		$package = new RequestPackage(ip: '192.0.2.1', headers: [], headers_mixed: [], request_method: 'POST', request_uri: '/', server_protocol: 'HTTP/1.1', request_entity: [
			'bb_challenge_token' => 'invalid-token'
		], user_agent: 'Test/1.0');

		$result = $this->challenge->verify($package);
		$this->assertFalse($result);
	}

	public function test_render_contains_form(): void
	{
		$html = $this->challenge->render('/test');

		$this->assertStringContainsString('<form', $html);
		$this->assertStringContainsString('bb_challenge_token', $html);
		$this->assertStringContainsString('action="/test"', $html);
		$this->assertStringContainsString('Security Check', $html);
	}

	public function test_render_mobile_difficulty(): void
	{
		$html = $this->challenge->render('/test');

		$this->assertStringContainsString('difficulty', $html);
		$this->assertStringContainsString('requestAnimationFrame', $html);
	}
}
