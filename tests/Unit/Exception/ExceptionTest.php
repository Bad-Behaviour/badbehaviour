<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Exception;

use BadBehaviour\Exception\BlockedException;
use BadBehaviour\Exception\ChallengeRequiredException;
use BadBehaviour\Exception\ConfigurationException;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

class ExceptionTest extends TestCase
{

	private function create_result(ResultCode $code): Result
	{
		$package = new RequestPackage(ip: '192.0.2.1', headers: [], headers_mixed: [], request_method: 'GET', request_uri: '/test', server_protocol: 'HTTP/1.1', request_entity: [], user_agent: 'Test/1.0');

		return Result::block($code, 'Test message', $package);
	}

	public function test_blocked_exception(): void
	{
		$result = $this->create_result(ResultCode::BLOCKED_BOT);
		$exception = BlockedException::from_result($result);

		$this->assertEquals(403, $exception->getCode());
		$this->assertEquals('Test message', $exception->getMessage());
		$this->assertEquals(ResultCode::BLOCKED_BOT, $exception->get_code());
		$this->assertEquals($result, $exception->get_result());
		$this->assertEquals($result->get_package(), $exception->get_package());
		$this->assertNotNull($exception->get_support_key());
	}

	public function test_challenge_required_exception(): void
	{
		$result = $this->create_result(ResultCode::CHALLENGE_REQUIRED);
		$exception = ChallengeRequiredException::from_result($result);

		$this->assertEquals(403, $exception->getCode());
		$this->assertEquals(ResultCode::CHALLENGE_REQUIRED, $exception->get_code());
		$this->assertTrue($exception->get_result()
			->requires_challenge());
	}

	public function test_configuration_exception_missing(): void
	{
		$exception = ConfigurationException::missing_required('httpbl_key');

		$this->assertEquals('httpbl_key', $exception->get_errors()['missing_key']);
		$this->assertStringContainsString('httpbl_key', $exception->getMessage());
	}

	public function test_configuration_exception_invalid_type(): void
	{
		$exception = ConfigurationException::invalid_type('httpbl_threat', 'int', 'string');

		$this->assertEquals('httpbl_threat', $exception->get_errors()['key']);
		$this->assertEquals('int', $exception->get_errors()['expected']);
		$this->assertEquals('string', $exception->get_errors()['actual']);
	}

	public function test_configuration_exception_from_validation(): void
	{
		$errors = [
			[
				'key' => 'httpbl_key',
				'message' => 'Required'
			],
			[
				'key' => 'httpbl_threat',
				'message' => 'Must be 0-255'
			]
		];

		$exception = ConfigurationException::from_validation($errors);

		$this->assertCount(2, $exception->get_errors());
		$this->assertStringContainsString('httpbl_key', $exception->getMessage());
		$this->assertStringContainsString('httpbl_threat', $exception->getMessage());
	}
}
