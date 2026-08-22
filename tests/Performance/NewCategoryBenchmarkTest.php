<?php
// tests/Performance/NewCategoryBenchmarkTest.php
// Validates that additions don't regress the hot path.
declare(strict_types = 1);
namespace BadBehaviour\Tests\Performance;

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;
use BadBehaviour\Detection\BotDetector;

/**
 * Run explicitly: vendor/bin/phpunit tests/Performance
 */
class NewCategoryBenchmarkTest extends TestCase
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
			'dynamic_ip_ranges' => [
				'enabled' => false
			], // Static only for benchmark
			'enable_behavioral_analysis' => true,
			'rate_limit_enabled' => false,
			'dnsbl_enabled' => false
		], $adapter);

		$this->bb = new BadBehaviour($config);

		// Warmup
		$this->bb->run_test_package(RequestPackage::create_for_test('Warmup/1.0', '203.0.113.99', 'GET', '/warmup'));
	}

	/**
	 * The cloud infrastructure fast path is the most performance-critical
	 * new feature.
	 * It runs on EVERY request before bot matching.
	 * Budget: < 0.05 ms per call.
	 */
	public function test_cloud_fast_path_isolated(): void
	{
		$adapter = new GenericAdapter();
		$config = Configuration::from_array([
			'dynamic_ip_ranges' => [
				'enabled' => false
			],
			'bot_categories' => [
				'blocked' => [
					'malicious'
				]
			]
		], $adapter);

		$detector = new BotDetector($config, $adapter);

		// Trigger static cache build inside is_cloud_infrastructure_ip()
		$warmup_pkg = RequestPackage::create_for_test('Warmup/1.0', '173.245.48.1', 'GET', '/');
		$detector->detect($warmup_pkg);

		$reflection = new \ReflectionMethod($detector, 'is_cloud_infrastructure_ip');

		$iterations = 100000;
		$start = microtime(true);
		for ($i = 0; $i < $iterations; $i ++) {
			$reflection->invoke($detector, '173.245.48.1');
		}
		$per_iter_us = ((microtime(true) - $start) * 1_000_000) / $iterations;

		fwrite(STDERR, sprintf("\n  Cloud check only: %.2f μs/req (budget: 50 μs, headroom: %.1fx)\n", $per_iter_us, 50.0 / $per_iter_us));

		$this->assertLessThan(50.0, $per_iter_us, "Cloud fast-path too slow: {$per_iter_us} μs (target: <50μs)");
	}

	/**
	 * Registry::all() now returns ~80 bots.
	 * Verify find_by_ua() index
	 * build is fast on cold path.
	 */
	public function test_registry_index_build_under_5_ms(): void
	{
		// Use reflection to reset static caches
		$reflection = new \ReflectionClass(\BadBehaviour\Bot\Registry::class);
		$cache = $reflection->getProperty('cache');
		$cache->setAccessible(true);
		$cache->setValue(null, null);
		$ua_index = $reflection->getProperty('ua_index');
		$ua_index->setAccessible(true);
		$ua_index->setValue(null, null);

		$start = microtime(true);
		$all = \BadBehaviour\Bot\Registry::all();
		$elapsed_ms = (microtime(true) - $start) * 1000;

		fwrite(STDERR, sprintf("\n  Registry::all(): %d bots, built in %.2f ms\n", count($all), $elapsed_ms));

		// First call (builds index) — should still be <5ms with ~80 bots
		$this->assertLessThan(5.0, $elapsed_ms, "Registry build too slow: {$elapsed_ms} ms (target: <5ms)");
	}
}