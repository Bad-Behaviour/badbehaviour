<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;

class AgenticBehaviorDetector
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
		if (!$this->config->enable_agentic_detection) {
			return null;
		}

		$session_id = $package->session_id;
		if (!$session_id) return null;

		$behavior = $this->adapter->get_behavior_profile($session_id) ?? [];
		$requests = $behavior['request_log'] ?? [];

		// Add current request
		$requests[] = [
			'time' => time(),
			'uri' => $package->request_uri,
			'method' => $package->request_method,
			'assets' => $this->is_asset_request($package),
		];

		// Keep last 50 requests
		if (count($requests) > 50) {
			$requests = array_slice($requests, -50);
		}

		$behavior['request_log'] = $requests;
		$this->adapter->save_behavior_profile($session_id, $behavior, 3600);

		// Need at least 5 requests to analyze
		if (count($requests) < 5) return null;

		// Pattern 1: Long think time + rapid targeted fetches
		if ($this->detect_think_then_fetch($requests)) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Agentic pattern: think-then-fetch', $package, [
				'type' => 'agentic_think_fetch',
			]);
		}

		// Pattern 2: Non-linear navigation (jumping between unrelated pages)
		if ($this->detect_nonlinear_navigation($requests)) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Agentic pattern: non-linear navigation', $package, [
				'type' => 'agentic_nonlinear',
			]);
		}

		// Pattern 3: High precision targeting (only fetches exactly what's needed)
		if ($this->detect_precision_targeting($requests)) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Agentic pattern: precision targeting', $package, [
				'type' => 'agentic_precision',
			]);
		}

		return null;
	}

	private function detect_think_then_fetch(array $requests): bool
	{
		// Look for: long pause (>10s) followed by burst of asset requests (<1s apart)
		$pauses = [];
		for ($i = 1; $i < count($requests); $i++) {
			$gap = $requests[$i]['time'] - $requests[$i-1]['time'];
			if ($gap > 10) {
				$pauses[] = $i; // Index after pause
			}
		}

		foreach ($pauses as $pause_idx) {
			if ($pause_idx >= count($requests)) continue;

			$burst = 0;
			$burst_time = 0;
			for ($i = $pause_idx; $i < min($pause_idx + 10, count($requests)); $i++) {
				if ($this->is_asset_request_uri($requests[$i]['uri'])) {
					$burst++;
					$burst_time += $requests[$i]['time'] - ($i > $pause_idx ? $requests[$i-1]['time'] : $requests[$i]['time']);
				}
			}

			// 5+ assets in <5 seconds after long pause
			if ($burst >= 5 && $burst_time < 5) {
				return true;
			}
		}

		return false;
	}

	private function detect_nonlinear_navigation(array $requests): bool
	{
		// Agentic browsers often jump between unrelated sections
		// Measure path diversity in short time window
		$recent = array_slice($requests, -10);
		$paths = [];

		foreach ($recent as $req) {
			$path = parse_url($req['uri'], PHP_URL_PATH) ?? '';
			$top_level = $this->get_top_level_path($path);
			if ($top_level) $paths[] = $top_level;
		}

		$unique = count(array_unique($paths));
		$total = count($paths);

		// 8+ requests, 5+ different top-level sections = non-linear
		return $total >= 8 && $unique >= 5;
	}

	private function detect_precision_targeting(array $requests): bool
	{
		// Agentic: fetches only specific assets, skips decorative ones
		// Normal browser: loads CSS, JS, fonts, images, tracking pixels
		$recent = array_slice($requests, -20);

		$asset_types = ['css' => 0, 'js' => 0, 'font' => 0, 'image' => 0, 'tracking' => 0, 'api' => 0];

		foreach ($recent as $req) {
			$uri = $req['uri'];
			if (preg_match('/\.css(\?|$)/', $uri)) $asset_types['css']++;
			elseif (preg_match('/\.js(\?|$)/', $uri)) $asset_types['js']++;
			elseif (preg_match('/\.(woff2?|ttf|eot)(\?|$)/', $uri)) $asset_types['font']++;
			elseif (preg_match('/\.(png|jpg|jpeg|gif|webp|avif|svg)(\?|$)/', $uri)) $asset_types['image']++;
			elseif (preg_match('/(analytics|tracking|pixel|beacon)/', $uri)) $asset_types['tracking']++;
			elseif (preg_match('/\.(json|xml|graphql)(\?|$)/', $uri)) $asset_types['api']++;
		}

		// Agentic signature: High API/JSON, near-zero CSS/fonts/tracking
		$total = array_sum($asset_types);
		if ($total < 10) return false;

		$css_ratio = $asset_types['css'] / $total;
		$font_ratio = $asset_types['font'] / $total;
		$tracking_ratio = $asset_types['tracking'] / $total;
		$api_ratio = $asset_types['api'] / $total;

		return $css_ratio < 0.05 && $font_ratio < 0.02 && $tracking_ratio < 0.01 && $api_ratio > 0.3;
	}

	private function is_asset_request(RequestPackage $package): bool
	{
		return $this->is_asset_request_uri($package->request_uri);
	}

	private function is_asset_request_uri(string $uri): bool
	{
		return preg_match('/\.(css|js|woff2?|ttf|eot|png|jpg|jpeg|gif|webp|avif|svg|json|xml)(\?|$)/', $uri) === 1;
	}

	private function get_top_level_path(string $path): ?string
	{
		$parts = array_filter(explode('/', $path));
		return $parts ? '/' . $parts[0] : null;
	}
}