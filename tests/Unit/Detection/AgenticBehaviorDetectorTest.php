<?php
// tests/Unit/Detection/AgenticBehaviorDetectorTest.php

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\AgenticBehaviorDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class AgenticBehaviorDetectorTest extends TestCase
{
    private AgenticBehaviorDetector $detector;
    private Configuration $config;
    private AdapterInterface $adapter;

    protected function setUp(): void
    {
        $this->adapter = $this->createMock(AdapterInterface::class);
        $this->config = Configuration::from_array([
            'enable_agentic_detection' => true,
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $this->detector = new AgenticBehaviorDetector($this->config, $this->adapter);
    }

    public function test_disabled_returns_null(): void
    {
        $config = Configuration::from_array([
            'enable_agentic_detection' => false,
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new AgenticBehaviorDetector($config, $this->adapter);
        $package = $this->createPackage();

        $this->assertNull($detector->detect($package));
    }

    public function test_no_session_id_returns_null(): void
    {
        $package = $this->createPackage(session_id: null);

        $this->assertNull($this->detector->detect($package));
    }

    public function test_insufficient_requests_returns_null(): void
    {
        $this->adapter->method('get_behavior_profile')
            ->willReturn(['request_log' => []]);

        $package = $this->createPackage();

        for ($i = 0; $i < 4; $i++) {
            $result = $this->detector->detect($package);
            $this->assertNull($result);
        }
    }

    public function test_think_then_fetch_detected(): void
    {
        $time = time();

        $requests = [
            ['time' => $time - 20, 'uri' => '/page1', 'method' => 'GET', 'assets' => false],
            ['time' => $time - 5, 'uri' => '/style.css', 'method' => 'GET', 'assets' => true],
            ['time' => $time - 4, 'uri' => '/script.js', 'method' => 'GET', 'assets' => true],
            ['time' => $time - 3, 'uri' => '/font.woff2', 'method' => 'GET', 'assets' => true],
            ['time' => $time - 2, 'uri' => '/image.png', 'method' => 'GET', 'assets' => true],
            ['time' => $time - 1, 'uri' => '/api/data.json', 'method' => 'GET', 'assets' => true],
        ];

        $this->adapter->method('get_behavior_profile')
            ->with('test-session')
            ->willReturn(['request_log' => $requests]);
        $this->adapter->method('save_behavior_profile')
            ->willReturn(true);

        $package = $this->createPackage();
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('think-then-fetch', $result->message);
    }

    public function test_non_linear_navigation_detected(): void
    {
        $requests = [];
        $paths = ['/blog/', '/shop/', '/admin/', '/api/', '/user/', '/settings/', '/help/', '/about/'];
        $time = time();

        foreach ($paths as $i => $path) {
            $requests[] = [
                'time' => $time - (10 - $i),
                'uri' => $path . 'page',
                'method' => 'GET',
                'assets' => false,
            ];
        }

        $this->adapter->method('get_behavior_profile')
            ->with('test-session')
            ->willReturn(['request_log' => $requests]);
        $this->adapter->method('save_behavior_profile')
            ->willReturn(true);

        $package = $this->createPackage();
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('non-linear', $result->message);
    }

    public function test_precision_targeting_detected(): void
    {
        $requests = [];
        $time = time();

        // 15 API calls
        for ($i = 0; $i < 15; $i++) {
            $requests[] = [
                'time' => $time - $i,
                'uri' => '/api/v1/data' . $i . '.json',
                'method' => 'GET',
                'assets' => false,
            ];
        }

        // 1 CSS, 0 fonts, 0 tracking
        $requests[] = ['time' => $time - 16, 'uri' => '/style.css', 'method' => 'GET', 'assets' => true];

        $this->adapter->method('get_behavior_profile')
            ->with('test-session')
            ->willReturn(['request_log' => $requests]);
        $this->adapter->method('save_behavior_profile')
            ->willReturn(true);

        $package = $this->createPackage();
        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
        $this->assertStringContainsString('precision', $result->message);
    }

    public function test_normal_browsing_allowed(): void
    {
        $requests = [];
        $time = time();

        $requests[] = ['time' => $time - 10, 'uri' => '/page', 'method' => 'GET', 'assets' => false];
        $requests[] = ['time' => $time - 9, 'uri' => '/style.css', 'method' => 'GET', 'assets' => true];
        $requests[] = ['time' => $time - 8, 'uri' => '/script.js', 'method' => 'GET', 'assets' => true];
        $requests[] = ['time' => $time - 7, 'uri' => '/font.woff2', 'method' => 'GET', 'assets' => true];
        $requests[] = ['time' => $time - 6, 'uri' => '/image.png', 'method' => 'GET', 'assets' => true];
        $requests[] = ['time' => $time - 5, 'uri' => '/api/data.json', 'method' => 'GET', 'assets' => false];
        $requests[] = ['time' => $time - 4, 'uri' => '/page2', 'method' => 'GET', 'assets' => false];
        $requests[] = ['time' => $time - 3, 'uri' => '/style2.css', 'method' => 'GET', 'assets' => true];

        $this->adapter->method('get_behavior_profile')
            ->with('test-session')
            ->willReturn(['request_log' => $requests]);
        $this->adapter->method('save_behavior_profile')
            ->willReturn(true);

        $package = $this->createPackage();
        $result = $this->detector->detect($package);

        $this->assertNull($result);
    }

    private function createPackage(?string $session_id = 'test-session'): RequestPackage
    {
        return RequestPackage::create_for_test(
            'Mozilla/5.0 Chrome/120',
            '192.0.2.1',
            'GET',
            '/',
            ['Host' => 'example.com'],
            [],
            $session_id
        );
    }
}
