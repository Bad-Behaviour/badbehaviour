<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Detection;

use BadBehaviour\Detection\AssetScrapingDetector;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\ResultCode;
use PHPUnit\Framework\TestCase;

class AssetScrapingDetectorTest extends TestCase
{

	private AssetScrapingDetector $detector;

	private AdapterInterface $adapter;

	protected function setUp(): void
	{
		$this->adapter = $this->createMock(AdapterInterface::class);
		$config = Configuration::from_array([
			'enable_asset_scraping_detection' => true,
			'asset_extensions' => [
				'png',
				'jpg',
				'pdf',
				'docx'
			],
			'asset_no_referer_threshold' => 10,
			'asset_only_session_threshold' => 20,
			'asset_pattern_threshold' => 100
		], $this->adapter);

		$this->detector = new AssetScrapingDetector($config, $this->adapter);
	}

	// ====================================================================
	// BASIC: skip non-asset requests
	// ====================================================================
	public function test_html_page_returns_null(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/about');

		$this->assertNull($this->detector->detect($package));
	}

	public function test_html_extension_returns_null(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/page.html');

		$this->assertNull($this->detector->detect($package));
	}

	public function test_php_extension_returns_null(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/index.php');

		$this->assertNull($this->detector->detect($package));
	}

	public function test_api_endpoint_returns_null(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/api/v1/users');

		$this->assertNull($this->detector->detect($package));
	}

	// ====================================================================
	// SIGNAL 1: Asset without Referer (counter-based)
	// ====================================================================
	public function test_asset_with_referer_returns_null(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/image.png', [
			'Referer' => 'https://example.com/gallery'
		]);

		$this->assertNull($this->detector->detect($package));
	}

	public function test_asset_without_referer_allowed_below_threshold(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// First 5 requests pass (counter < 10)
		for ($i = 0; $i < 5; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.42', 'GET', '/image' . $i . '.png' // No Referer header
			);
			$this->assertNull($this->detector->detect($package));
		}
	}

	public function test_asset_without_referer_blocked_above_threshold(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// 11th request exceeds threshold of 10
		$result = null;
		for ($i = 0; $i < 11; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.42', 'GET', '/image' . $i . '.png' // No Referer header
			);
			$result = $this->detector->detect($package);
		}

		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
		$this->assertStringContainsString('Referer', $result->message);
		$this->assertEquals('asset_no_referer_flood', $result->metadata['type']);
		$this->assertEquals(11, $result->metadata['count']);
	}

	public function test_asset_empty_referer_string_treated_as_no_referer(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// 11 requests with explicitly empty Referer
		$result = null;
		for ($i = 0; $i < 11; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.43', 'GET', '/img' . $i . '.png', [
				'Referer' => ''
			] // explicitly empty
			);
			$result = $this->detector->detect($package);
		}

		$this->assertNotNull($result);
		$this->assertEquals('asset_no_referer_flood', $result->metadata['type']);
	}

	public function test_asset_whitespace_referer_treated_as_no_referer(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		$result = null;
		for ($i = 0; $i < 11; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.44', 'GET', '/img' . $i . '.jpg', [
				'Referer' => '   '
			] // whitespace only
			);
			$result = $this->detector->detect($package);
		}

		$this->assertNotNull($result);
		$this->assertEquals('asset_no_referer_flood', $result->metadata['type']);
	}

	// ====================================================================
	// SIGNAL 2: Asset-only session (no HTML loads)
	// ====================================================================
	public function test_asset_only_session_blocked(): void
	{
		$profile = [
			'html_requests' => 0,
			'asset_requests' => 0
		];

		$this->adapter->method('get_behavior_profile')->willReturnCallback(function () use (&$profile) {
			return $profile;
		});

		$this->adapter->method('save_behavior_profile')->willReturnCallback(function ($sid, $newProfile, $ttl) use (&$profile) {
			$profile = $newProfile;
			return true;
		});

		// 21 asset requests with valid Referer (passes signal 1),
		// but no HTML page loads
		$result = null;
		for ($i = 0; $i < 21; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/img' . $i . '.jpg', [
				'Referer' => 'https://example.com/gallery'
			], [], 'test-session');
			$result = $this->detector->detect($package);
		}

		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
		$this->assertEquals('asset_only_session', $result->metadata['type']);
		$this->assertGreaterThan(20, $result->metadata['asset_count']);
	}

	public function test_session_with_html_loads_allowed(): void
	{
		// Profile indicates HTML loads happened previously
		$profile = [
			'html_requests' => 5,
			'asset_requests' => 0
		];

		$this->adapter->method('get_behavior_profile')->willReturnCallback(function () use (&$profile) {
			return $profile;
		});

		$this->adapter->method('save_behavior_profile')->willReturnCallback(function ($sid, $newProfile, $ttl) use (&$profile) {
			$profile = $newProfile;
			return true;
		});

		// 30 asset requests — should pass because session has HTML history
		for ($i = 0; $i < 30; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/img' . $i . '.jpg', [], // empty headers (no Referer)
			[], 'test-session');
			$this->assertNull($this->detector->detect($package));
		}
	}

	public function test_no_session_id_skips_asset_only_check(): void
	{
		// Without session, signal 2 cannot be evaluated
		// Only signal 1 (no-referer) and signal 3 (pattern) apply
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// 30 asset requests without Referer, no session
		// Signal 1 will block at request 11
		$result = null;
		for ($i = 0; $i < 30; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.50', 'GET', '/img' . $i . '.png', [], [], null // NO session
			);
			$result = $this->detector->detect($package);
		}

		// Should be blocked by signal 1 (no-referer flood), not signal 2
		$this->assertNotNull($result);
		$this->assertEquals('asset_no_referer_flood', $result->metadata['type']);
	}

	public function test_html_load_increments_counter(): void
	{
		$profile = [
			'html_requests' => 0,
			'asset_requests' => 0
		];

		$this->adapter->method('get_behavior_profile')->willReturnCallback(function () use (&$profile) {
			return $profile;
		});

		$this->adapter->method('save_behavior_profile')->willReturnCallback(function ($sid, $newProfile, $ttl) use (&$profile) {
			$profile = $newProfile;
			return true;
		});

		// Mix of HTML + asset requests
		$package1 = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/index.html', [], [], 'test-session');
		$this->detector->detect($package1);

		// Verify profile was updated
		$this->assertEquals(1, $profile['html_requests']);
		$this->assertEquals(0, $profile['asset_requests']);

		// Now 25 asset requests — should still be allowed (html > 0)
		for ($i = 0; $i < 25; $i ++) {
			$package2 = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/img' . $i . '.png', [], [], 'test-session');
			$this->assertNull($this->detector->detect($package2));
		}

		$this->assertEquals(1, $profile['html_requests']);
		$this->assertGreaterThan(20, $profile['asset_requests']);
	}

	// ====================================================================
	// SIGNAL 3: Sequential asset pattern (IP-based counter)
	// ====================================================================
	public function test_asset_pattern_below_threshold_allowed(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// Asset requests WITH valid Referer (passes signal 1)
		// 50 requests total — all should pass (threshold is 100)
		for ($i = 0; $i < 50; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.60', 'GET', '/img' . $i . '.png', [
				'Referer' => 'https://example.com/gallery'
			]);
			$this->assertNull($this->detector->detect($package));
		}
	}

	public function test_asset_pattern_above_threshold_blocked(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// 101 requests with valid Referer — 101st triggers signal 3
		$result = null;
		for ($i = 0; $i < 101; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.61', 'GET', '/img' . $i . '.png', [
				'Referer' => 'https://example.com/gallery'
			]);
			$result = $this->detector->detect($package);
		}

		$this->assertNotNull($result);
		$this->assertEquals(ResultCode::BLOCKED_BEHAVIORAL, $result->code);
		$this->assertEquals('asset_pattern', $result->metadata['type']);
		$this->assertGreaterThan(100, $result->metadata['count']);
	}

	public function test_asset_pattern_per_ip_isolation(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// IP A: 60 requests (below threshold)
		for ($i = 0; $i < 60; $i ++) {
			$package_a = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.70', 'GET', '/img' . $i . '.png', [
				'Referer' => 'https://example.com/gallery'
			]);
			$this->assertNull($this->detector->detect($package_a));
		}

		// IP B: separate counter — also below threshold
		for ($i = 0; $i < 60; $i ++) {
			$package_b = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.71', 'GET', '/img' . $i . '.png', [
				'Referer' => 'https://example.com/gallery'
			]);
			$this->assertNull($this->detector->detect($package_b));
		}
	}

	// ====================================================================
	// EDGE CASES
	// ====================================================================
	public function test_pdf_detected_as_asset(): void
	{
		// PDF is in the configured extensions list
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/document.pdf');

		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		// Should be detected as asset request (no Referer → counter)
		// First request just increments, second still below threshold
		$result1 = $this->detector->detect($package);
		$result2 = $this->detector->detect($package);

		$this->assertNull($result1);
		$this->assertNull($result2);
		$this->assertArrayHasKey('bb:asset_no_referer:203.0.113.1', $counts);
	}

	public function test_docx_detected_as_asset(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/report.docx');

		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		$this->assertNull($this->detector->detect($package));
	}

	public function test_unknown_extension_returns_null(): void
	{
		// '.xyz' is not in the asset_extensions list
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/file.xyz');

		// Adapter should not be touched at all
		$this->adapter->expects($this->never())
			->method('increment_counter');
		$this->adapter->expects($this->never())
			->method('get_behavior_profile');

		$this->assertNull($this->detector->detect($package));
	}

	public function test_extension_match_is_case_insensitive(): void
	{
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/image.PNG' // uppercase
		);

		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		$this->assertNull($this->detector->detect($package));
		// Counter incremented → recognized as asset
		$this->assertArrayHasKey('bb:asset_no_referer:203.0.113.1', $counts);
	}

	public function test_asset_query_string_ignored(): void
	{
		// /img.png?v=1 should still be detected as PNG asset
		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/img.png?v=1&cache=12345');

		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		$this->assertNull($this->detector->detect($package));
	}

	// ====================================================================
	// MASTER SWITCH
	// ====================================================================
	public function test_disabled_returns_null(): void
	{
		$config = Configuration::from_array([
			'enable_asset_scraping_detection' => false,
			'asset_extensions' => [
				'png',
				'jpg'
			]
		], $this->adapter);

		$detector = new AssetScrapingDetector($config, $this->adapter);

		$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '203.0.113.1', 'GET', '/image.png');

		// Adapter should not be touched
		$this->adapter->expects($this->never())
			->method('increment_counter');

		$this->assertNull($detector->detect($package));
	}

	// ====================================================================
	// SIGNAL ORDER: no-referer fires FIRST (before asset-only check)
	// ====================================================================
	public function test_no_referer_blocks_before_asset_only_session(): void
	{
		// Profile is "clean" — asset-only check would pass if no-referer didn't block
		$profile = [
			'html_requests' => 0,
			'asset_requests' => 0
		];

		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		$this->adapter->method('get_behavior_profile')->willReturnCallback(function () use (&$profile) {
			return $profile;
		});

		$this->adapter->method('save_behavior_profile')->willReturnCallback(function ($sid, $newProfile, $ttl) use (&$profile) {
			$profile = $newProfile;
			return true;
		});

		// 11 requests — no Referer (signal 1 should fire at request 11)
		// Asset-only session threshold is 20 — wouldn't fire yet
		$result = null;
		for ($i = 0; $i < 11; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.80', 'GET', '/img' . $i . '.png', [], // No Referer
			[], 'test-session');
			$result = $this->detector->detect($package);
		}

		// First signal to fire wins
		$this->assertNotNull($result);
		$this->assertEquals('asset_no_referer_flood', $result->metadata['type']);
	}

	public function test_metadata_includes_useful_context(): void
	{
		$counts = [];
		$this->adapter->method('increment_counter')->willReturnCallback(function ($key, $window) use (&$counts) {
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			return $counts[$key];
		});

		$result = null;
		for ($i = 0; $i < 11; $i ++) {
			$package = RequestPackage::create_for_test('Mozilla/5.0 Chrome/120', '198.51.100.90', 'GET', '/img' . $i . '.png');
			$result = $this->detector->detect($package);
		}

		$this->assertNotNull($result);
		$this->assertArrayHasKey('type', $result->metadata);
		$this->assertArrayHasKey('count', $result->metadata);
		$this->assertEquals('asset_no_referer_flood', $result->metadata['type']);
		$this->assertIsInt($result->metadata['count']);
		$this->assertGreaterThan(0, $result->metadata['count']);
	}
}