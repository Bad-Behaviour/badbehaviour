<?php
// tests/Unit/Detection/ClientHintsDetectorTest.php

namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\ClientHintsDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class ClientHintsDetectorTest extends TestCase
{
    private ClientHintsDetector $detector;
    private Configuration $config;

    protected function setUp(): void
    {
        $this->config = Configuration::from_array([
            'enable_client_hints_validation' => true,
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $this->detector = new ClientHintsDetector($this->config);
    }

    public function test_disabled_returns_null(): void
    {
        $config = Configuration::from_array([
            'enable_client_hints_validation' => false,
        ], new \BadBehaviour\Adapter\GenericAdapter());

        $detector = new ClientHintsDetector($config);
        $package = $this->createPackage('Chrome/120');

        $this->assertNull($detector->detect($package));
    }

    public function test_non_chromium_ua_returns_null(): void
    {
        // Firefox doesn't send all client hints reliably
        $package = $this->createPackage('Firefox/120');
        $package = $package->with_modified(['headers_mixed' => [
            'User-Agent' => 'Mozilla/5.0 Firefox/120',
            'Accept' => 'text/html',
        ]]);

        $this->assertNull($this->detector->detect($package));
    }

    public function test_chrome_89_plus_missing_all_hints_blocked(): void
    {
        $package = $this->createPackage('Chrome/120');
        // No Sec-CH-UA headers at all

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_FINGERPRINT, $result->code);
        $this->assertStringContainsString('Missing Client Hints', $result->message);
    }

    public function test_chrome_89_plus_with_valid_hints_allowed(): void
    {
        $package = $this->createPackage('Chrome/120', headers: [
            'Sec-Ch-Ua' => '"Not A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-Ch-Ua-Full-Version-List' => '"Not A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.109", "Google Chrome";v="120.0.6099.109"',
            'Sec-Ch-Ua-Platform' => '"Linux"',
            'Sec-Ch-Ua-Mobile' => '?0',
        ]);

        $this->assertNull($this->detector->detect($package));
    }

    public function test_brand_mismatch_blocked(): void
    {
        $package = $this->createPackage('Chrome/120', headers: [
            'Sec-Ch-Ua' => '"Not A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"', // Wrong brand
        ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_FINGERPRINT, $result->code);
        $this->assertStringContainsString('brand mismatch', $result->message);
    }

    public function test_version_mismatch_blocked(): void
    {
        $package = $this->createPackage('Chrome/120', headers: [
            'Sec-Ch-Ua' => '"Not A Brand";v="8", "Chromium";v="120", "Google Chrome";v="100"', // Version mismatch > 2
        ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_FINGERPRINT, $result->code);
        $this->assertStringContainsString('Version mismatch', $result->metadata['detail'] ?? '');
    }

    public function test_platform_mismatch_blocked(): void
    {
        $package = $this->createPackage('Chrome/120', headers: [
            'Sec-Ch-Ua' => '"Google Chrome";v="120"',
            'Sec-Ch-Ua-Platform' => '"Windows"', // UA says Linux
        ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_FINGERPRINT, $result->code);
        $this->assertStringContainsString('platform mismatch', $result->metadata['detail'] ?? '');
    }

    public function test_mobile_mismatch_blocked(): void
    {
        $package = $this->createPackage('Chrome/120', headers: [
            'Sec-Ch-Ua' => '"Google Chrome";v="120"',
            'Sec-Ch-Ua-Mobile' => '?1', // UA says desktop
        ]);

        $result = $this->detector->detect($package);

        $this->assertNotNull($result);
        $this->assertEquals(ResultCode::BLOCKED_FINGERPRINT, $result->code);
        $this->assertStringContainsString('mobile mismatch', $result->metadata['detail'] ?? '');
    }

    public function test_old_chrome_version_skipped(): void
    {
        // Chrome 88 - before client hints
        $package = $this->createPackage('Chrome/88');

        $this->assertNull($this->detector->detect($package));
    }

    public function test_electron_skipped(): void
    {
        $package = $this->createPackage('Electron/20.0 Chrome/120');

        $this->assertNull($this->detector->detect($package));
    }

    private function createPackage(string $ua, array $headers = []): RequestPackage
    {
        $defaultHeaders = [
            'User-Agent' => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) {$ua} Safari/537.36",
            'Accept' => 'text/html',
        ];

        return RequestPackage::create_for_test(
            $defaultHeaders['User-Agent'],
            '192.0.2.1',
            'GET',
            '/',
            array_merge($defaultHeaders, $headers)
        );
    }
}
