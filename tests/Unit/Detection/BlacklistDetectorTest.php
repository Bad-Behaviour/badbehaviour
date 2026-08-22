<?php
namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\BlacklistDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class BlacklistDetectorTest extends TestCase
{

	private BlacklistDetector $detector;

	private Configuration $config;

	protected function setUp(): void
	{
		$this->config = Configuration::from_array([
			'offsite_forms' => false
		]);
		$this->detector = new BlacklistDetector($this->config);
	}

	public function test_empty_user_agent_blocked(): void
	{
		$package = RequestPackage::create_for_test('', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
	}

	public function test_malicious_ua_prefix_blocked(): void
	{
		$package = RequestPackage::create_for_test('sqlmap/1.0', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
	}

	public function test_curl_ua_allowed(): void
	{
		// curl is now http_tool, not blocked by prefix checks
		$package = RequestPackage::create_for_test('curl/8.18.0', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNull($result);
	}

	public function test_wget_ua_allowed(): void
	{
		$package = RequestPackage::create_for_test('Wget/1.21.4', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNull($result);
	}

	public function test_python_requests_ua_allowed(): void
	{
		$package = RequestPackage::create_for_test('python-requests/2.31.0', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNull($result);
	}

	public function test_malicious_ua_substring_blocked(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 <script>alert(1)</script>', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
	}

	public function test_ua_regex_blocked(): void
	{
		$package = RequestPackage::create_for_test('BOT12345', '192.0.2.1');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
	}

	public function test_url_sqli_blocked(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'GET', '/?id=1+union+select+1');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_url_xss_blocked(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', '192.0.2.1', 'GET', '/?foo=<script>alert(1)</script>');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_url_path_traversal_blocked(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'GET', '/?file=../../etc/passwd');
		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_post_form_body_attack_detected(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'POST', '/comment', [
			'Host' => 'example.com',
			'Content-Type' => 'application/x-www-form-urlencoded',
			'Accept' => 'text/html',
			'Referer' => 'https://example.com/page'
		], [
			'subject' => 'test union select 1 from users'
		] // was 'body'
		);

		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_post_json_body_attack_allowed(): void
	{
		// JSON body with SQLi - NOT INSPECTED (legacy behavior)
		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'POST', '/api/comment', [
			'Host' => 'example.com',
			'Content-Type' => 'application/json',
			'Accept' => 'application/json'
		], [
			'body' => 'test union select 1 from users'
		]);

		$result = $this->detector->detect($package);
		$this->assertNull($result);
	}

	public function test_post_multipart_body_attack_allowed(): void
	{
		// Multipart body - NOT INSPECTED (legacy behavior)
		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'POST', '/upload', [
			'Host' => 'example.com',
			'Content-Type' => 'multipart/form-data; boundary=----WebKitFormBoundary',
			'Accept' => 'text/html'
		], [
			'file' => 'test'
		]);

		$result = $this->detector->detect($package);
		$this->assertNull($result);
	}

	public function test_trackback_suspicious_blocked(): void
	{
		// Trackback with browser UA - suspicious
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120.0.0.0', '192.0.2.1', 'POST', '/trackback', [
			'Host' => 'example.com',
			'Content-Type' => 'application/x-www-form-urlencoded'
		], [
			'title' => 'Test',
			'url' => 'https://example.com/post',
			'blog_name' => 'Test Blog'
		]);

		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_trackback_with_proxy_blocked(): void
	{
		$package = RequestPackage::create_for_test('WordPress/6.0', '192.0.2.1', 'POST', '/trackback', [
			'Host' => 'example.com',
			'Content-Type' => 'application/x-www-form-urlencoded',
			'Via' => '1.1 proxy.example.com'
		], [
			'title' => 'Test',
			'url' => 'https://example.com/post',
			'blog_name' => 'Test Blog'
		]);

		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_document_write_in_form_blocked(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'POST', '/comment', [
			'Host' => 'example.com',
			'Content-Type' => 'application/x-www-form-urlencoded'
		], [
			'title' => 'document.write("evil")'
		] // was 'comment'
		);

		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_offsite_form_blocked(): void
	{
		$this->config = Configuration::from_array([
			'offsite_forms' => false
		]);
		$this->detector = new BlacklistDetector($this->config);

		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'POST', '/comment', [
			'Host' => 'example.com',
			'Content-Type' => 'application/x-www-form-urlencoded',
			'Referer' => 'https://evil.com/form'
		], [
			'body' => 'test'
		]);

		$result = $this->detector->detect($package);
		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
	}

	public function test_offsite_form_allowed_when_enabled(): void
	{
		$this->config = Configuration::from_array([
			'offsite_forms' => true
		]);
		$this->detector = new BlacklistDetector($this->config);

		$package = RequestPackage::create_for_test('Mozilla/5.0', '192.0.2.1', 'POST', '/comment', [
			'Host' => 'example.com',
			'Content-Type' => 'application/x-www-form-urlencoded',
			'Referer' => 'https://evil.com/form'
		], [
			'body' => 'test'
		]);

		$result = $this->detector->detect($package);
		$this->assertNull($result);
	}
}
