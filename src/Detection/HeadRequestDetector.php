<?php

declare(strict_types=1);

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;

/**
 * Detects HEAD request abuse patterns:
 * 1. HEAD without Referer to non-API paths (site mapping)
 * 2. HEAD flood from a single session (enumeration)
 * 3. Excessive HEAD probing from a single IP (rapid-fire reconnaissance)
 *
 * Legitimate HEAD usage (link checkers, monitoring, REST APIs) is
 * allowed via configurable exemptions.
 */
class HeadRequestDetector
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
		if (!$this->config->enable_head_request_detection) {
			return null;
		}

		// Only act on HEAD requests
		if ($package->request_method !== 'HEAD') {
			return null;
		}

		// Signal 1: HEAD without Referer to non-exempt paths
		if ($this->should_require_referer($package->request_uri)
			&& $this->is_head_without_referer($package)) {
				return Result::block(
					ResultCode::BLOCKED_BEHAVIORAL,
					'HEAD request without Referer',
					$package,
					['type' => 'head_no_referer']
					);
			}

			// Signal 2: HEAD flood per session
			$session_id = $package->session_id;
			if ($session_id) {
				$profile_key = "head:{$session_id}";
				$profile = $this->adapter->get_behavior_profile($profile_key) ?? [];
				$head_count = ($profile['head_count'] ?? 0) + 1;
				$profile['head_count'] = $head_count;
				$this->adapter->save_behavior_profile($profile_key, $profile, 3600);

				$threshold = $this->config->head_flood_threshold;
				if ($head_count > $threshold) {
					return Result::block(
						ResultCode::BLOCKED_BEHAVIORAL,
						'HEAD request flood',
						$package,
						['type' => 'head_flood', 'count' => $head_count]
						);
				}
			}

			// Signal 3: Excessive HEAD probing per IP (5-minute window)
			$probe_key = "bb:head_probe:{$package->ip}";
			$probe_count = $this->adapter->increment_counter($probe_key, 300);

			if ($probe_count > $this->config->head_probe_threshold) {
				return Result::block(
					ResultCode::BLOCKED_BEHAVIORAL,
					'Excessive HEAD probing',
					$package,
					['type' => 'head_probing', 'count' => $probe_count]
					);
			}

			return null;
	}

	private function should_require_referer(string $uri): bool
	{
		if (!$this->config->head_require_referer) {
			return false;
		}

		$path = parse_url($uri, PHP_URL_PATH) ?? '';

		// Exempt API endpoints (REST clients don't send Referer)
		foreach ($this->config->head_referer_exempt_paths as $prefix) {
			if (str_starts_with($path, $prefix)) {
				return false;
			}
		}

		// Exempt specific monitoring endpoints
		$exempt_files = ['/health', '/status', '/ping', '/heartbeat'];
		if (in_array($path, $exempt_files, true)) {
			return false;
		}

		return true;
	}

	private function is_head_without_referer(RequestPackage $package): bool
	{
		$referer = $package->headers_mixed['Referer'] ?? '';
		return trim($referer) === '';
	}
}