<?php

declare(strict_types=1);

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;

/**
 * Detects direct asset scraping (AI training scrapers, image harvesters):
 * 1. Asset requests without Referer (not following page navigation)
 * 2. Asset-only sessions (no HTML page loads at all)
 * 3. Sequential asset URL patterns (rapid-fire enumeration)
 *
 * Legitimate browser behavior: load HTML page → load referenced assets.
 * Scrapers: directly request assets from a URL list.
 */
class AssetScrapingDetector
{
	private Configuration $config;
	private AdapterInterface $adapter;

	public function __construct(Configuration $config, AdapterInterface $adapter)
	{
		$this->config = $config;
		$this->adapter = $adapter;
	}

	public function detect(RequestPackage $package): ?Result
	{
		// Master switch — bail before any side effects when disabled
		if (!$this->config->enable_asset_scraping_detection) {
			return null;
		}

		$session_id = $package->session_id;

		// Track HTML page loads so the asset-only-session detector
		// can distinguish "real browser that loaded index.html first"
		// from "scraper hammering /img1.png, /img2.png, ... directly".
		// Must run even when the current request is NOT an asset,
		// otherwise html_requests stays at 0 forever.
		if ($session_id && !$this->is_asset_request($package->request_uri)) {
			if ($this->is_html_page($package->request_uri)) {
				$this->record_html_load($session_id);
			}
			return null;
		}

		if (!$this->is_asset_request($package->request_uri)) {
			return null;
		}

		// Signal 1: Asset request without Referer
		if ($this->is_asset_without_referer($package)) {
			$key = "bb:asset_no_referer:{$package->ip}";
			$count = $this->adapter->increment_counter($key, 3600);

			if ($count > $this->config->asset_no_referer_threshold) {
				return Result::block(
					ResultCode::BLOCKED_BEHAVIORAL,
					'Asset scraping: requests without Referer',
					$package,
					['type' => 'asset_no_referer_flood', 'count' => $count]
					);
			}
		}

		// Signal 2: Asset-only session (no HTML loads)
		if ($session_id) {
			$profile = $this->record_asset_request($session_id);

			// > threshold asset requests without ANY HTML page = scraping
			if ($profile['asset_requests'] > $this->config->asset_only_session_threshold
				&& $profile['html_requests'] === 0) {
					return Result::block(
						ResultCode::BLOCKED_BEHAVIORAL,
						'Asset scraping: no HTML page loads',
						$package,
						[
							'type' => 'asset_only_session',
							'asset_count' => $profile['asset_requests'],
						]
						);
				}
		}

		// Signal 3: Sequential asset pattern per IP (5-minute window)
		$pattern_key = "bb:asset_pattern:{$package->ip}";
		$pattern_count = $this->adapter->increment_counter($pattern_key, 300);

		if ($pattern_count > $this->config->asset_pattern_threshold) {
			return Result::block(
				ResultCode::BLOCKED_BEHAVIORAL,
				'Asset scraping: sequential pattern',
				$package,
				['type' => 'asset_pattern', 'count' => $pattern_count]
				);
		}

		return null;
	}

	private function is_asset_request(string $uri): bool
	{
		$path = parse_url($uri, PHP_URL_PATH) ?? '';
		$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
		return in_array($ext, $this->config->asset_extensions, true);
	}

	private function is_html_page(string $uri): bool
	{
		$path = parse_url($uri, PHP_URL_PATH) ?? '';
		$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
		// Empty extension or html/php/asp/etc. = page request
		return $ext === '' || in_array($ext, ['html', 'htm', 'php', 'asp', 'aspx', 'jsp'], true);
	}

	private function is_asset_without_referer(RequestPackage $package): bool
	{
		$referer = $package->headers_mixed['Referer'] ?? '';
		return trim($referer) === '';
	}

	/**
	 * Record that the user loaded an HTML page in this session.
	 * Used to distinguish real browsers from asset-only scrapers.
	 */
	private function record_html_load(string $session_id): void
	{
		$profile_key = "asset:{$session_id}";
		$profile = $this->adapter->get_behavior_profile($profile_key) ?? [
			'html_requests' => 0,
			'asset_requests' => 0,
		];

		$profile['html_requests']++;
		$this->adapter->save_behavior_profile($profile_key, $profile, 3600);
	}

	/**
	 * Record an asset request and return the updated profile
	 * (caller decides whether to block based on the counts).
	 */
	private function record_asset_request(string $session_id): array
	{
		$profile_key = "asset:{$session_id}";
		$profile = $this->adapter->get_behavior_profile($profile_key) ?? [
			'html_requests' => 0,
			'asset_requests' => 0,
		];

		$profile['asset_requests']++;
		$this->adapter->save_behavior_profile($profile_key, $profile, 3600);

		return $profile;
	}
}