<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\HeaderUtil;

class BehavioralDetector
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
		$session_id = $package->session_id;
		$ua = $package->user_agent;
		$headers = $package->headers_mixed;
		$method = $package->request_method;
		$ua_browser = $package->ua_browser ?? '';

		// === 1. SESSION-BASED BEHAVIORAL ANALYSIS ===
		if ($session_id) {
			$behavior = $this->adapter->get_behavior_profile($session_id) ?? [
				'count' => 0,
				'first_seen' => time(),
				'user_agents' => [],
				'ips' => [],
				'static_count' => 0,
				'total_count' => 0,
				'urls' => [],
				'form_load_time' => 0,
			];

			$behavior['count']++;
			$behavior['total_count']++;
			$behavior['user_agents'][$ua] = true;
			$behavior['ips'][$package->ip] = true;
			$behavior['urls'][] = $package->request_uri;

			if (count($behavior['urls']) > 100) {
				$behavior['urls'] = array_slice($behavior['urls'], -100);
			}

			if ($this->is_static_resource($package->request_uri)) {
				$behavior['static_count']++;
			}

			$timespan = time() - $behavior['first_seen'];

			if ($behavior['count'] > 100 && $timespan < 60) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Rapid requests detected', $package, [
					'type' => 'rapid_requests',
					'count' => $behavior['count'],
					'timespan' => $timespan,
				]);
			}

			if (count($behavior['user_agents']) > 5) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Rotating User-Agents', $package, [
					'type' => 'rotating_ua',
					'count' => count($behavior['user_agents']),
				]);
			}

			if (count($behavior['ips']) > 3) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Rotating IPs', $package, [
					'type' => 'rotating_ip',
					'count' => count($behavior['ips']),
				]);
			}

			if ($behavior['total_count'] > 20 && $behavior['static_count'] / $behavior['total_count'] < 0.1) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'No static resources requested', $package, [
					'type' => 'no_static',
					'ratio' => $behavior['static_count'] / $behavior['total_count'],
				]);
			}

			if ($this->detect_enumeration($behavior['urls'])) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'URL enumeration detected', $package, [
					'type' => 'enumeration',
				]);
			}

			$this->adapter->save_behavior_profile($session_id, $behavior, 3600);
		}

		// === 2. FORM TIMING CHECK (Legacy: think time between form load and submit) ===
		// Only for traditional form POSTs (not AJAX, not JSON, not multipart)
		if ($method === 'POST' && $package->is_traditional_form_post() && $session_id) {
			$behavior = $this->adapter->get_behavior_profile($session_id) ?? [];
			$form_load_time = $behavior['form_load_time'] ?? 0;

			if ($form_load_time > 0) {
				$think_time = time() - $form_load_time;

				// Less than 2 seconds = too fast for human form submission
				if ($think_time < 2) {
					return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'POST too fast after form load', $package, [
						'type' => 'too_fast_post',
						'think_time' => $think_time,
					]);
				}
			}
		}

		// === 3. RECORD FORM LOAD TIME ON GET REQUESTS ===
		// Heuristic: pages that typically contain forms
		if ($method === 'GET' && $session_id) {
			$path = parse_url($package->request_uri, PHP_URL_PATH) ?? '';
			$has_form = str_contains($path, 'edit')
				|| str_contains($path, 'comment')
				|| str_contains($path, 'new')
				|| str_contains($path, 'post')
				|| str_contains($path, 'reply')
				|| str_contains($path, 'login')
				|| str_contains($path, 'register');

			if ($has_form) {
				$behavior = $this->adapter->get_behavior_profile($session_id) ?? [];
				$behavior['form_load_time'] = time();
				$this->adapter->save_behavior_profile($session_id, $behavior, 3600);
			}
		}

		// === 4. ACCEPT HEADER CHECKS (Legacy: only for verified traditional browsers) ===
		$accepts_html = isset($headers['Accept']) && str_contains($headers['Accept'], 'text/html');
		$is_ajax = $package->is_ajax();
		$is_json = $package->is_json_body();
		$is_multipart = $package->is_multipart_form();

		// Only enforce for traditional browser page loads
		$is_traditional_browser =
			$this->looks_like_browser($ua_browser)
			&& !$is_ajax
			&& !$is_json
			&& !$is_multipart
			&& $accepts_html;

		if ($is_traditional_browser && empty($headers['Accept'])) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Browser missing Accept header', $package, [
				'type' => 'browser_no_accept',
				'browser' => $ua_browser,
			]);
		}

		// Accept-Encoding only in strict mode + traditional browser
		if ($this->config->strict && $is_traditional_browser && empty($headers['Accept-Encoding'])) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Browser missing Accept-Encoding', $package, [
				'type' => 'browser_no_encoding',
				'browser' => $ua_browser,
			]);
		}

		// === 5. DNT CONTRADICTION ===
		if (($headers['Dnt'] ?? '') === '1' && $this->has_tracking_params($package->request_uri)) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'DNT header with tracking params', $package, [
				'type' => 'dnt_contradiction',
			]);
		}

		// === 6. CONNECTION HEADER CONFLICTS ===
		if (!empty($headers['Connection'])) {
			$conn = strtolower($headers['Connection']);
			if (str_contains($conn, 'keep-alive') && str_contains($conn, 'close')) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Conflicting Connection headers', $package, [
					'type' => 'conn_conflict',
				]);
			}
			if (preg_match('/\b(keep-alive|close)\b.*\b\1\b/i', $conn)) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Duplicate Connection values', $package, [
					'type' => 'conn_duplicate',
				]);
			}
		}

		// TE without Connection: TE
		if (!empty($headers['Te']) && !preg_match('/\bte\b/i', $headers['Connection'] ?? '')) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'TE header without Connection: TE', $package, [
				'type' => 'te_missing',
			]);
		}

		// Content-Length on safe methods
		if (in_array($method, ['GET', 'HEAD', 'OPTIONS', 'TRACE'], true) && !empty($headers['Content-Length'])) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Content-Length on safe method', $package, [
				'type' => 'content_length_on_get',
			]);
		}

		// Transfer-Encoding on safe methods
		if (in_array($method, ['GET', 'HEAD', 'OPTIONS', 'TRACE'], true) && !empty($headers['Transfer-Encoding'])) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Transfer-Encoding on safe method', $package, [
				'type' => 'transfer_encoding_on_get',
			]);
		}

		// X-Forwarded-For anomalies
		if (!empty($headers['X-Forwarded-For'])) {
			$xff = $headers['X-Forwarded-For'];
			$ips = array_map('trim', explode(',', $xff));
			if (count($ips) > 10) {
				return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Too many X-Forwarded-For hops', $package, [
					'type' => 'xff_too_many',
					'count' => count($ips),
				]);
			}
			foreach ($ips as $xff_ip) {
				if (\BadBehaviour\Util\IpUtil::is_private($xff_ip) && !$package->behind_proxy) {
					return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Private IP in X-Forwarded-For', $package, [
						'type' => 'xff_private',
					]);
				}
			}
		}

		// Host header missing on HTTP/1.1
		if ($package->server_protocol === 'HTTP/1.1' && empty($headers['Host'])) {
			return Result::block(ResultCode::BLOCKED_BEHAVIORAL, 'Missing Host header', $package, [
				'type' => 'missing_host',
			]);
		}

		return null;
	}

	private function is_static_resource(string $uri): bool
	{
		$path = parse_url($uri, PHP_URL_PATH) ?? '';
		$ext = pathinfo($path, PATHINFO_EXTENSION);
		return in_array(strtolower($ext), ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot', 'webp', 'avif', 'map'], true);
	}

	private function detect_enumeration(array $urls): bool
	{
		if (count($urls) < 10) return false;

		$ids = [];
		foreach ($urls as $url) {
			if (preg_match('/[=\/](\d{3,})($|[&\/#?])/', $url, $m)) {
				$ids[] = (int)$m[1];
			}
		}

		if (count($ids) < 5) return false;

		sort($ids);
		$sequential = 0;
		for ($i = 1; $i < count($ids); $i++) {
			if ($ids[$i] - $ids[$i-1] <= 2) $sequential++;
		}

		return $sequential > count($ids) * 0.7;
	}

	private function looks_like_browser(string $ua_browser): bool
	{
		return in_array($ua_browser, ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera', 'Internet Explorer'], true);
	}

	private function looks_like_modern_browser(string $ua_browser): bool
	{
		return in_array($ua_browser, ['Chrome', 'Edge', 'Brave', 'Vivaldi', 'Opera', 'Chromium', 'Firefox', 'Safari'], true);
	}

	private function has_tracking_params(string $uri): bool
	{
		foreach (['utm_', 'fbclid', 'gclid', 'mc_cid', 'mc_eid', '_ga', '_gl'] as $param) {
			if (str_contains($uri, $param)) return true;
		}
		return false;
	}
}
