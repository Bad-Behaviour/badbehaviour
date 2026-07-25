<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Integration;

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Configuration;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class BadBehaviourIntegrationTest extends TestCase
{
    private GenericAdapter $adapter;

    protected function setUp(): void
    {
        $this->adapter = new GenericAdapter();
    }

    private function create_test_package(
        string $user_agent,
        string $ip = '203.0.113.1',
        string $method = 'GET',
        string $uri = '/',
        array $headers = [],
        array $entity = []
    ): RequestPackage {
        return RequestPackage::create_for_test($user_agent, $ip, $method, $uri, [], []);
    }

    private function run_test(RequestPackage $package, array $config_overrides = []): Result
    {
        $config = \BadBehaviour\Configuration::from_array(array_merge([
            'logging' => false,
            'strict' => false,
            'reverse_proxy' => false,
            'rate_limit_enabled' => false,
            'challenge_enabled' => false,
            'dnsbl_lists' => [],
            'httpbl_key' => '',
        ], $config_overrides), $this->adapter);

        $bb = new \BadBehaviour\Core\BadBehaviour($config);

        return $bb->run_test_package($package);
    }

    public function test_normal_browser_allowed(): void
    {
        $package = $this->create_test_package(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            '203.0.113.1'
        );

        $result = $this->run_test($package);

        $this->assertTrue($result->is_allowed());
        $this->assertEquals(ResultCode::ALLOWED, $result->code);
    }

    public function test_googlebot_from_known_ip_allowed(): void
    {
        $package = $this->create_test_package(
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            '66.249.64.1'
        );

        $result = $this->run_test($package);

        $this->assertTrue($result->is_allowed());
    }

    public function test_gptbot_allowed_when_configured(): void
    {
        $package = $this->create_test_package(
            'GPTBot/1.0',
            '20.15.240.1'
        );

        $result = $this->run_test($package, [
            'allowed_ai_crawlers' => ['GPTBot'],
            'block_unverified_ai' => true,
        ]);

        $this->assertTrue($result->is_allowed());
    }

    public function test_claudebot_blocked_when_not_configured(): void
    {
        $package = $this->create_test_package(
            'ClaudeBot/1.0',
            '54.144.0.1'
        );

        $result = $this->run_test($package, [
            'allowed_ai_crawlers' => ['GPTBot'],
            'block_unverified_ai' => true,
            'strict_ai' => true,
        ]);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_AI_CRAWLER, $result->code);
    }

    public function test_sqlmap_blocked(): void
    {
        $package = $this->create_test_package('sqlmap/1.0');

        $result = $this->run_test($package);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_sql_injection_in_url_blocked(): void
    {
        $package = $this->create_test_package(
            'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36',
            '203.0.113.1',
            'GET',
            "/page?id=1' UNION SELECT * FROM users--"
        );

        $result = $this->run_test($package);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
    }

    public function test_headless_chrome_blocked(): void
    {
        $package = $this->create_test_package(
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 HeadlessChrome/120.0.0.0'
        );

        $result = $this->run_test($package);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_puppeteer_blocked(): void
    {
        $package = $this->create_test_package(
            'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36 Puppeteer/21.0.0'
        );

        $result = $this->run_test($package);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_empty_user_agent_blocked(): void
    {
        $package = $this->create_test_package('');

        $result = $this->run_test($package);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_MALICIOUS_UA, $result->code);
    }

    public function test_reverse_proxy_real_ip(): void
    {
        // Test the reverse proxy IP extraction logic directly
        $headers_mixed = [
            'User-Agent' => 'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36',
            'Accept' => 'text/html',
            'Accept-Language' => 'en-US,en;q=0.9',
            'Accept-Encoding' => 'gzip, deflate',
            'Connection' => 'keep-alive',
            'Host' => 'example.com',
            'X-Forwarded-For' => '203.0.113.50, 10.0.0.1',
        ];

        $settings = [
            'reverse_proxy' => true,
            'reverse_proxy_header' => 'X-Forwarded-For',
            'reverse_proxy_addresses' => ['10.0.0.0/8'],
        ];

        $real_ip = \BadBehaviour\Util\HeaderUtil::get_real_ip($headers_mixed, $settings);

        $this->assertEquals('203.0.113.50', $real_ip);
    }

    public function test_post_body_attack_detected(): void
    {
        $package = \BadBehaviour\Util\RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36',
            '203.0.113.1',
            'POST',
            '/api',
            [],
            ['query' => 'UNION SELECT * FROM users']
        );

        $result = $this->run_test($package);

        $this->assertTrue($result->is_blocked());
        $this->assertEquals(ResultCode::BLOCKED_ATTACK_PATTERN, $result->code);
    }
}
