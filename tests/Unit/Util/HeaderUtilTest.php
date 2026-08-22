<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Util\HeaderUtil;
use PHPUnit\Framework\TestCase;

class HeaderUtilTest extends TestCase
{

	protected function setUp(): void
	{
		$_SERVER = [];
	}

	public function test_normalize_key(): void
	{
		$this->assertEquals('User-Agent', HeaderUtil::normalize_key('user-agent'));
		$this->assertEquals('Content-Type', HeaderUtil::normalize_key('content_type'));
		$this->assertEquals('X-Forwarded-For', HeaderUtil::normalize_key('x_forwarded_for'));
		$this->assertEquals('Accept-Language', HeaderUtil::normalize_key('accept-language'));
	}

	public function test_normalize_keys(): void
	{
		$input = [
			'user-agent' => 'test-agent',
			'content_type' => 'application/json',
			'x_custom_header' => 'value'
		];
		$expected = [
			'User-Agent' => 'test-agent',
			'Content-Type' => 'application/json',
			'X-Custom-Header' => 'value'
		];
		$this->assertEquals($expected, HeaderUtil::normalize_keys($input));
	}

	public function test_load_headers_from_server(): void
	{
		$_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';
		$_SERVER['HTTP_ACCEPT'] = 'application/json';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4';
		$_SERVER['CONTENT_TYPE'] = 'application/json';
		$_SERVER['CONTENT_LENGTH'] = '100';

		$headers = HeaderUtil::load_headers();

		$this->assertEquals('TestAgent/1.0', $headers['User-Agent']);
		$this->assertEquals('application/json', $headers['Accept']);
		$this->assertEquals('1.2.3.4', $headers['X-Forwarded-For']);
		$this->assertEquals('application/json', $headers['Content-Type']);
		$this->assertEquals('100', $headers['Content-Length']);
	}

	public function test_get_real_ip(): void
	{
		$headers = [
			'X-Forwarded-For' => '1.2.3.4, 10.0.0.1, 192.168.1.1'
		];
		$settings = [
			'reverse_proxy' => true,
			'reverse_proxy_header' => 'X-Forwarded-For',
			'reverse_proxy_addresses' => [
				'10.0.0.0/8',
				'192.168.0.0/16'
			]
		];

		$ip = HeaderUtil::get_real_ip($headers, $settings);
		$this->assertEquals('1.2.3.4', $ip);
	}

	public function test_get_real_ip_no_proxy(): void
	{
		$headers = [
			'X-Forwarded-For' => '1.2.3.4'
		];
		$settings = [
			'reverse_proxy' => false
		];

		$this->assertFalse(HeaderUtil::get_real_ip($headers, $settings));
	}

	public function test_get_real_ip_all_trusted(): void
	{
		$headers = [
			'X-Forwarded-For' => '10.0.0.1, 192.168.1.1'
		];
		$settings = [
			'reverse_proxy' => true,
			'reverse_proxy_header' => 'X-Forwarded-For',
			'reverse_proxy_addresses' => [
				'10.0.0.0/8',
				'192.168.0.0/16'
			]
		];

		$this->assertFalse(HeaderUtil::get_real_ip($headers, $settings));
	}

	public function test_get_ja3_fingerprint(): void
	{
		// JA3 fingerprint must be 32-char hex string (MD5 of JA3 string)
		$_SERVER['HTTP_CF_RAY_JA3'] = 'a1b2c3d4e5f678901234567890abcdef';

		$ja3 = HeaderUtil::get_ja3_fingerprint();
		$this->assertEquals('a1b2c3d4e5f678901234567890abcdef', $ja3);
	}

	public function test_get_h2_settings(): void
	{
		$_SERVER['HTTP_HTTP2_SETTINGS'] = 'AABAAB0A';

		$h2 = HeaderUtil::get_h2_settings();
		$this->assertEquals('AABAAB0A', $h2);
	}
}
