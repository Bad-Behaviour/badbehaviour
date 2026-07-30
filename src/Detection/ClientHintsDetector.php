<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;

class ClientHintsDetector
{
	private Configuration $config;

	public function __construct(Configuration $config)
	{
		$this->config = $config;
	}

	public function detect(RequestPackage $package): ?Result
	{
		if (!$this->config->enable_client_hints_validation) {
			return null;
		}

		$headers = $package->headers_mixed;
		$ua = $package->user_agent;

		// Only validate for browsers that SHOULD send Client Hints
		if (!$this->should_send_client_hints($ua)) {
			return null;
		}

		$sec_ch_ua = $headers['Sec-Ch-Ua'] ?? '';
		$sec_ch_ua_full = $headers['Sec-Ch-Ua-Full-Version-List'] ?? '';
		$sec_ch_ua_platform = $headers['Sec-Ch-Ua-Platform'] ?? '';
		$sec_ch_ua_mobile = $headers['Sec-Ch-Ua-Mobile'] ?? '';

		// 1. Missing ALL Client Hints = suspicious for modern Chrome/Edge
		if (!$sec_ch_ua && !$sec_ch_ua_full && !$sec_ch_ua_platform) {
			return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Missing Client Hints headers', $package, [
				'type' => 'missing_client_hints',
				'ua_claims' => $package->ua_browser,
			]);
		}

		// 2. Parse claimed browser/version from UA
		$ua_browser = $package->ua_browser ?? '';
		$ua_version = $package->ua_version ?? '';
		$ua_platform = $package->ua_os ?? '';

		// 3. Cross-validate Sec-CH-UA brand/version
		if ($sec_ch_ua) {
			$mismatch = $this->validate_brand_consistency($sec_ch_ua, $ua_browser, $ua_version);
			if ($mismatch) {
				return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Client Hints brand mismatch', $package, [
					'type' => 'ch_ua_brand_mismatch',
					'detail' => $mismatch,
				]);
			}
		}

		// 4. Validate Full Version List
		if ($sec_ch_ua_full) {
			$mismatch = $this->validate_full_version($sec_ch_ua_full, $ua_browser, $ua_version);
			if ($mismatch) {
				return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Client Hints version mismatch', $package, [
					'type' => 'ch_ua_full_version_mismatch',
					'detail' => $mismatch,
				]);
			}
		}

		// 5. Platform consistency
		if ($sec_ch_ua_platform) {
			$claimed_platform = trim($sec_ch_ua_platform, '"');
			$ua_platform_normalized = $this->normalize_platform($ua_platform);
			if (strtolower($claimed_platform) !== strtolower($ua_platform_normalized)) {
				$detail = "Platform mismatch: claimed='$claimed_platform', ua='$ua_platform_normalized'";
				return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Client Hints platform mismatch', $package, [
					'type' => 'ch_ua_platform_mismatch',
					'detail' => $detail,
					'claimed' => $claimed_platform,
					'ua_claims' => $ua_platform_normalized,
				]);
			}
		}

		// 6. Mobile consistency
		if ($sec_ch_ua_mobile !== '') {
			$ch_mobile = strtolower(trim($sec_ch_ua_mobile, '"'));
			$ua_mobile = $package->ua_is_mobile ? '?1' : '?0';
			if ($ch_mobile !== $ua_mobile) {
				$detail = "Mobile mismatch: ch='$ch_mobile', ua='$ua_mobile'";
				return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Client Hints mobile mismatch', $package, [
					'type' => 'ch_ua_mobile_mismatch',
					'detail' => $detail,
					'ch_mobile' => $ch_mobile,
					'ua_mobile' => $ua_mobile,
				]);
			}
		}

		return null;
	}

	private function should_send_client_hints(string $ua): bool
	{
		// Chrome 89+, Edge 89+, Brave, Vivaldi, Opera 75+
		$ua_lower = strtolower($ua);

		// Must be a Chromium-based browser
		if (strpos($ua_lower, 'chrome/') === false && strpos($ua_lower, 'chromium/') === false) {
			return false; // Firefox, Safari don't send all hints reliably
		}

		// Exclude known non-Chromium UAs that mention Chrome (e.g., Electron apps)
		if (strpos($ua_lower, 'electron/') !== false) {
			return false;
		}

		// Version check: Chrome 89+ (March 2021)
		$major = $this->extract_chrome_major($ua);
		return $major >= 89;
	}

	private function extract_chrome_major(string $ua): int
	{
		if (preg_match('/chrome\/(\d+)/i', $ua, $m)) return (int)$m[1];
		if (preg_match('/chromium\/(\d+)/i', $ua, $m)) return (int)$m[1];
		if (preg_match('/crios\/(\d+)/i', $ua, $m)) return (int)$m[1];
		if (preg_match('/edg\/(\d+)/i', $ua, $m)) return (int)$m[1];
		if (preg_match('/brave\/(\d+)/i', $ua, $m)) return (int)$m[1];
		if (preg_match('/vivaldi\/(\d+)/i', $ua, $m)) return (int)$m[1];
		if (preg_match('/opr\/(\d+)/i', $ua, $m)) return (int)$m[1];
		return 0;
	}

	private function validate_brand_consistency(string $sec_ch_ua, string $ua_browser, string $ua_version): ?string
	{
		// Parse Sec-CH-UA: "Not A Brand";v="8", "Chromium";v="137", "Google Chrome";v="137"
		$brands = [];
		preg_match_all('/"([^"]+)";v="([^"]+)"/', $sec_ch_ua, $matches, PREG_SET_ORDER);
		foreach ($matches as $m) {
			$brands[strtolower($m[1])] = $m[2];
		}

		// Map UA browser to expected Sec-CH-UA brand
		$expected_brand = match(strtolower($ua_browser)) {
			'chrome' => 'google chrome',
			'edge' => 'microsoft edge',
			'brave' => 'brave',
			'vivaldi' => 'vivaldi',
			'opera' => 'opera',
			'chromium' => 'chromium',
			default => null,
		};

		if (!$expected_brand || !isset($brands[$expected_brand])) {
			return "Expected brand '$expected_brand' not found in Sec-CH-UA";
		}

		// Version consistency (allow minor drift)
		$ch_version = $brands[$expected_brand];
		$ua_major = (int)explode('.', $ua_version)[0];
		$ch_major = (int)explode('.', $ch_version)[0];

		if ($ch_major > 0 && abs($ua_major - $ch_major) > 2) {
			return "Version mismatch: UA=$ua_version vs CH=$ch_version";
		}

		// Chromium brand should always be present for Chromium-based
		if (!isset($brands['chromium'])) {
			return "Missing 'Chromium' brand in Sec-CH-UA";
		}

		return null;
	}

	private function validate_full_version(string $sec_ch_ua_full, string $ua_browser, string $ua_version): ?string
	{
		// "Not A Brand";v="8.0.0.0", "Chromium";v="137.0.7151.68", "Google Chrome";v="137.0.7151.68"
		$brands = [];
		preg_match_all('/"([^"]+)";v="([^"]+)"/', $sec_ch_ua_full, $matches, PREG_SET_ORDER);
		foreach ($matches as $m) {
			$brands[strtolower($m[1])] = $m[2];
		}

		$expected_brand = match(strtolower($ua_browser)) {
			'chrome' => 'google chrome',
			'edge' => 'microsoft edge',
			'brave' => 'brave',
			'vivaldi' => 'vivaldi',
			'opera' => 'opera',
			'chromium' => 'chromium',
			default => null,
		};

		if (!$expected_brand || !isset($brands[$expected_brand])) {
			return "Expected brand '$expected_brand' not found in Full Version List";
		}

		$ch_full = $brands[$expected_brand];
		$ch_major = (int)explode('.', $ch_full)[0];
		$ua_major = (int)explode('.', $ua_version)[0];

		if (abs($ua_major - $ch_major) > 2) {
			return "Full version mismatch: UA=$ua_version vs CH=$ch_full";
		}

		return null;
	}

	private function normalize_platform(string $ua_os): string
	{
		$os_lower = strtolower($ua_os);
		if (strpos($os_lower, 'windows') !== false) return 'Windows';
		if (strpos($os_lower, 'mac') !== false || strpos($os_lower, 'darwin') !== false) return 'macOS';
		if (strpos($os_lower, 'linux') !== false) return 'Linux';
		if (strpos($os_lower, 'android') !== false) return 'Android';
		if (strpos($os_lower, 'ios') !== false || strpos($os_lower, 'iphone') !== false || strpos($os_lower, 'ipad') !== false) return 'iOS';
		return 'Unknown';
	}
}
