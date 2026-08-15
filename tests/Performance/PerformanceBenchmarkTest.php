<?php
// tests/Performance/PerformanceBenchmarkTest.php

declare(strict_types=1);

namespace BadBehaviour\Tests\Performance;

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

/**
 * Performance benchmarks — skipped by default, run explicitly:
 *   vendor/bin/phpunit tests/Performance
 *
 * Or remove the markTestSkipped() call to run in CI.
 */
class PerformanceBenchmarkTest extends TestCase
{
    private BadBehaviour $bb;

    protected function setUp(): void
    {
    	$adapter = new GenericAdapter();
    	$config = Configuration::from_array([
    		'logging' => false,
    		'enable_fingerprinting' => false,
    		'enable_client_hints_validation' => false,
    		'enable_agentic_detection' => false,
    		'dynamic_ip_ranges' => ['enabled' => false],
    		'enable_behavioral_analysis' => true,
    		'rate_limit_enabled' => false,
    		'dnsbl_enabled' => false,
    		'reverse_proxy' => false,
    	], $adapter);

    	$this->bb = new BadBehaviour($config);

    	// Warmup — load classes, populate static caches (Registry::$cache, $ua_index)
    	$this->bb->run_test_package(
    		RequestPackage::create_for_test('Warmup/1.0', '203.0.113.99', 'GET', '/warmup')
    		);
    }

    public function test_static_resource_fast_path(): void
    {
        $iterations = 5000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->bb->run_test_package(
                RequestPackage::create_for_test(
                    'Mozilla/5.0 Chrome/120',
                    '203.0.113.1',
                    'GET',
                    '/wp-content/themes/style.css'
                )
            );
        }

        $elapsed_ms = (microtime(true) - $start) * 1000;
        $per_iter = $elapsed_ms / $iterations;

        fwrite(STDERR, "\n  Static CSS:    {$per_iter} ms/req ({$elapsed_ms} ms / {$iterations} iters)\n");

        $this->assertLessThan(
            0.5,
            $per_iter,
            "Static resource fast-path too slow: {$per_iter} ms (target: <0.5 ms)"
        );
    }

    public function test_empty_ua_fast_path(): void
    {
        $iterations = 1000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->bb->run_test_package(
                RequestPackage::create_for_test('', '198.51.100.43', 'GET', '/')
            );
        }

        $elapsed_ms = (microtime(true) - $start) * 1000;
        $per_iter = $elapsed_ms / $iterations;

        fwrite(STDERR, "\n  Empty UA:      {$per_iter} ms/req ({$elapsed_ms} ms / {$iterations} iters)\n");

        $this->assertLessThan(0.5, $per_iter);
    }

    public function test_legitimate_browser(): void
    {
        $iterations = 1000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->bb->run_test_package(
                RequestPackage::create_for_test(
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
                    '203.0.113.1',
                    'GET',
                    '/about'
                )
            );
        }

        $elapsed_ms = (microtime(true) - $start) * 1000;
        $per_iter = $elapsed_ms / $iterations;

        fwrite(STDERR, "\n  Browser HTML:  {$per_iter} ms/req ({$elapsed_ms} ms / {$iterations} iters)\n");

        $this->assertLessThan(10.0, $per_iter, "Browser request too slow: {$per_iter} ms");
    }

    public function test_known_search_engine(): void
    {
        $iterations = 1000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->bb->run_test_package(
                RequestPackage::create_for_test(
                    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                    '66.249.66.1',
                    'GET',
                    '/sitemap.xml'
                )
            );
        }

        $elapsed_ms = (microtime(true) - $start) * 1000;
        $per_iter = $elapsed_ms / $iterations;

        fwrite(STDERR, "\n  Googlebot:     {$per_iter} ms/req ({$elapsed_ms} ms / {$iterations} iters)\n");

        $this->assertLessThan(5.0, $per_iter);
    }
}