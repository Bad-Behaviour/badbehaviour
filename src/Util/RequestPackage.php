<?php

namespace BadBehaviour\Util;

readonly class RequestPackage
{
	public function __construct(
		public string $ip,
		public array $headers,
		public array $headers_mixed,
		public string $request_method,
		public string $request_uri,
		public string $server_protocol,
		public array $request_entity,
		public string $user_agent,
		public bool $behind_proxy = false,
		public float $request_time = 0.0,
		public ?string $session_id = null,
		public ?string $asn = null,
		public ?string $country = null,
		public ?string $ja3 = null,
		public ?string $h2_settings = null,
		// UA parsing results
		public ?string $ua_browser = null,
		public ?string $ua_version = null,
		public ?int $ua_major = null,
		public ?string $ua_os = null,
		public ?string $ua_os_version = null,
		public ?string $ua_device = null,
		public ?bool $ua_is_mobile = null,
		public ?bool $ua_is_tablet = null,
		public ?bool $ua_is_bot = null,
		public ?bool $ua_is_http_tool = null,
		public ?string $ua_engine = null,
		) {}

		public static function from_globals(array $settings): self
		{
			$headers = HeaderUtil::load_headers();
			$headers_mixed = HeaderUtil::normalize_keys($headers);

			$ip = IpUtil::normalize($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
			$behind_proxy = false;

			if (($settings['reverse_proxy'] ?? false) && $real_ip = HeaderUtil::get_real_ip($headers_mixed, $settings)) {
				$headers['X-Bad-Behaviour-Remote-Address'] = $ip;
				$headers_mixed['X-Bad-Behaviour-Remote-Address'] = $ip;
				$ip = $real_ip;
				$behind_proxy = true;
			}

			$request_entity = [];
			$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

			if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
				foreach ($_POST as $k => $v) {
					$request_entity[$k] = is_array($v) ? 'Array' : $v;
				}
				if (empty($request_entity) && $input = @file_get_contents('php://input')) {
					$decoded = json_decode($input, true);
					if (is_array($decoded)) {
						$request_entity = $decoded;
					}
				}
			}

			$session_id = self::extract_session_id($headers_mixed);
			$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

			// Parse UA immediately - ALWAYS
			$ua_parsed = UaParser::parse($user_agent);

			return new self(
				ip: $ip,
				headers: $headers,
				headers_mixed: $headers_mixed,
				request_method: $method,
				request_uri: $_SERVER['REQUEST_URI'] ?? $_SERVER['SCRIPT_NAME'] ?? '/',
				server_protocol: $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1',
				request_entity: $request_entity,
				user_agent: $user_agent,
				behind_proxy: $behind_proxy,
				request_time: microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true)),
				session_id: $session_id,
				ua_browser: $ua_parsed['browser']['name'] ?? 'Unknown',
				ua_version: $ua_parsed['browser']['version'],
				ua_major: $ua_parsed['browser']['major'],
				ua_os: $ua_parsed['os']['name'] ?? 'Unknown',
				ua_os_version: $ua_parsed['os']['version'],
				ua_device: $ua_parsed['device']['type'] ?? 'desktop',
				ua_is_mobile: $ua_parsed['device']['is_mobile'] ?? false,
				ua_is_tablet: $ua_parsed['device']['is_tablet'] ?? false,
				ua_is_bot: $ua_parsed['device']['is_bot'] ?? false,
				ua_is_http_tool: $ua_parsed['device']['is_http_tool'] ?? false,
				ua_engine: $ua_parsed['engine']['name'] ?? 'unknown',
				);
		}

		/**
		 * Create a RequestPackage from server globals (for integration tests)
		 */
		public static function from_server_globals(array $settings, array $server): self
		{
			$headers = [];
			$headers_mixed = [];

			// Extract headers from server array
			foreach ($server as $key => $value) {
				if (str_starts_with($key, 'HTTP_')) {
					$header_name = HeaderUtil::normalize_key(substr($key, 5));
					$headers_mixed[$header_name] = $value;
					$headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
				} elseif (in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH', 'CONTENT_MD5'], true)) {
					$header_name = HeaderUtil::normalize_key($key);
					$headers_mixed[$header_name] = $value;
					$headers[strtolower(str_replace('_', '-', $key))] = $value;
				}
			}

			// Add default headers if missing (mimic real browser)
			$headers_mixed = array_merge([
				'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'Accept-Language' => 'en-US,en;q=0.5',
				'Accept-Encoding' => 'gzip, deflate',
				'Connection' => 'keep-alive',
			], $headers_mixed);

			$ip = IpUtil::normalize($server['REMOTE_ADDR'] ?? '127.0.0.1');
			$behind_proxy = false;

			if (($settings['reverse_proxy'] ?? false) && $real_ip = HeaderUtil::get_real_ip($headers_mixed, $settings)) {
				$headers_mixed['X-Bad-Behaviour-Remote-Address'] = $ip;
				$ip = $real_ip;
				$behind_proxy = true;
			}

			$request_entity = [];
			$method = $server['REQUEST_METHOD'] ?? 'GET';

			if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
				$request_entity = $server['REQUEST_ENTITY'] ?? [];
			}

			$session_id = self::extract_session_id($headers_mixed);
			$user_agent = $server['HTTP_USER_AGENT'] ?? '';

			// Parse UA immediately
			$ua_parsed = UaParser::parse($user_agent);

			return new self(
				ip: $ip,
				headers: [],
				headers_mixed: $headers_mixed,
				request_method: $method,
				request_uri: $server['REQUEST_URI'] ?? $server['SCRIPT_NAME'] ?? '/',
				server_protocol: $server['SERVER_PROTOCOL'] ?? 'HTTP/1.1',
				request_entity: $request_entity,
				user_agent: $server['HTTP_USER_AGENT'] ?? '',
				behind_proxy: $behind_proxy,
				request_time: 0.1,
				session_id: null,
				ua_browser: $ua_parsed['browser']['name'] ?? 'Unknown',
				ua_version: $ua_parsed['browser']['version'],
				ua_major: $ua_parsed['browser']['major'],
				ua_os: $ua_parsed['os']['name'] ?? 'Unknown',
				ua_os_version: $ua_parsed['os']['version'],
				ua_device: $ua_parsed['device']['type'] ?? 'desktop',
				ua_is_mobile: $ua_parsed['device']['is_mobile'] ?? false,
				ua_is_tablet: $ua_parsed['device']['is_tablet'] ?? false,
				ua_is_bot: $ua_parsed['device']['is_bot'] ?? false,
				ua_is_http_tool: $ua_parsed['device']['is_http_tool'] ?? false,
				ua_engine: $ua_parsed['engine']['name'] ?? 'unknown',
				);
		}

		/**
		 * Create a RequestPackage for testing with UA parsing
		 */
		public static function create_for_test(
			string $user_agent,
			string $ip = '192.0.2.1',
			string $method = 'GET',
			string $uri = '/',
			array $headers = [],
			array $entity = []
			): self {
				$ua_parsed = UaParser::parse($user_agent);
				$headers_mixed = HeaderUtil::normalize_keys($headers);

				// Add default headers if not present
				$headers_mixed = array_merge([
					'User-Agent' => $user_agent,
					'Accept' => 'text/html',
					'Accept-Language' => 'en-US',
					'Accept-Encoding' => 'gzip, deflate',
					'Connection' => 'keep-alive',
					'Host' => 'example.com',
				], $headers_mixed);

				return new self(
					ip: $ip,
					headers: $headers,
					headers_mixed: $headers_mixed,
					request_method: $method,
					request_uri: $uri,
					server_protocol: 'HTTP/1.1',
					request_entity: $entity,
					user_agent: $user_agent,
					behind_proxy: false,
					request_time: 0.1,
					session_id: 'test-session',
					ua_browser: $ua_parsed['browser']['name'] ?? 'Unknown',
					ua_version: $ua_parsed['browser']['version'],
					ua_major: $ua_parsed['browser']['major'],
					ua_os: $ua_parsed['os']['name'] ?? 'Unknown',
					ua_os_version: $ua_parsed['os']['version'],
					ua_device: $ua_parsed['device']['type'] ?? 'desktop',
					ua_is_mobile: $ua_parsed['device']['is_mobile'] ?? false,
					ua_is_tablet: $ua_parsed['device']['is_tablet'] ?? false,
					ua_is_bot: $ua_parsed['device']['is_bot'] ?? false,
					ua_is_http_tool: $ua_parsed['device']['is_http_tool'] ?? false,
					ua_engine: $ua_parsed['engine']['name'] ?? 'unknown',
					);
		}

		private static function extract_session_id(array $headers): ?string
		{
			$cookie = $headers['Cookie'] ?? '';
			$names = ['PHPSESSID', 'sessionid', 'sid', 'SESSION', 'JSESSIONID', 'ASP.NET_SessionId'];
			foreach ($names as $name) {
				if (preg_match('/' . preg_quote($name) . '=([^;]+)/', $cookie, $m)) {
					return $m[1];
				}
			}
			return null;
		}

		public function with_enrichment(?string $asn, ?string $country, ?string $ja3, ?string $h2_settings): self
		{
			return new self(
				ip: $this->ip,
				headers: $this->headers,
				headers_mixed: $this->headers_mixed,
				request_method: $this->request_method,
				request_uri: $this->request_uri,
				server_protocol: $this->server_protocol,
				request_entity: $this->request_entity,
				user_agent: $this->user_agent,
				behind_proxy: $this->behind_proxy,
				request_time: $this->request_time,
				session_id: $this->session_id,
				asn: $asn,
				country: $country,
				ja3: $ja3,
				h2_settings: $h2_settings,
				ua_browser: $this->ua_browser,
				ua_version: $this->ua_version,
				ua_major: $this->ua_major,
				ua_os: $this->ua_os,
				ua_os_version: $this->ua_os_version,
				ua_device: $this->ua_device,
				ua_is_mobile: $this->ua_is_mobile,
				ua_is_tablet: $this->ua_is_tablet,
				ua_is_bot: $this->ua_is_bot,
				ua_is_http_tool: $this->ua_is_http_tool,
				ua_engine: $this->ua_engine,
				);
		}

		public function with_modified(array $changes): self
		{
			return new self(
				ip: $changes['ip'] ?? $this->ip,
				headers: $changes['headers'] ?? $this->headers,
				headers_mixed: $changes['headers_mixed'] ?? $this->headers_mixed,
				request_method: $changes['request_method'] ?? $this->request_method,
				request_uri: $changes['request_uri'] ?? $this->request_uri,
				server_protocol: $changes['server_protocol'] ?? $this->server_protocol,
				request_entity: $changes['request_entity'] ?? $this->request_entity,
				user_agent: $changes['user_agent'] ?? $this->user_agent,
				behind_proxy: $changes['behind_proxy'] ?? $this->behind_proxy,
				request_time: $changes['request_time'] ?? $this->request_time,
				session_id: $changes['session_id'] ?? $this->session_id,
				asn: $changes['asn'] ?? $this->asn,
				country: $changes['country'] ?? $this->country,
				ja3: $changes['ja3'] ?? $this->ja3,
				h2_settings: $changes['h2_settings'] ?? $this->h2_settings,
				ua_browser: $this->ua_browser,
				ua_version: $this->ua_version,
				ua_major: $this->ua_major,
				ua_os: $this->ua_os,
				ua_os_version: $this->ua_os_version,
				ua_device: $this->ua_device,
				ua_is_mobile: $this->ua_is_mobile,
				ua_is_tablet: $this->ua_is_tablet,
				ua_is_bot: $this->ua_is_bot,
				ua_is_http_tool: $this->ua_is_http_tool,
				ua_engine: $this->ua_engine,
				);
		}

		public function claims_browser(string $browser): bool
		{
			return strcasecmp($this->ua_browser ?? '', $browser) === 0;
		}

		public function claims_modern_browser(): bool
		{
			$major = $this->ua_major ?? 0;
			return match($this->ua_browser) {
				'Chrome', 'Edge', 'Brave', 'Vivaldi', 'Opera', 'Chromium' => $major >= 100,
				'Firefox' => $major >= 100,
				'Safari' => $major >= 15,
				default => false,
			};
		}

		public function get_engine(): string
		{
			return $this->ua_engine ?? 'unknown';
		}

		// === NEW HELPER METHODS ===

		public function is_ajax(): bool
		{
			$headers = $this->headers_mixed;

			// Explicit AJAX headers
			if (($headers['X-Requested-With'] ?? '') === 'XMLHttpRequest') {
				return true;
			}

			// JSON API
			$accept = $headers['Accept'] ?? '';
			$content_type = $headers['Content-Type'] ?? '';

			if (str_contains($accept, 'application/json')
				|| str_contains($content_type, 'application/json')) {
					return true;
				}

				// Fetch/XHR modern
				if (($headers['Sec-Fetch-Mode'] ?? '') === 'cors'
					|| ($headers['Sec-Fetch-Dest'] ?? '') === 'empty') {
						return true;
					}

					return false;
		}

		public function is_json_body(): bool
		{
			return str_contains($this->headers_mixed['Content-Type'] ?? '', 'application/json');
		}

		public function is_multipart_form(): bool
		{
			return str_starts_with($this->headers_mixed['Content-Type'] ?? '', 'multipart/form-data');
		}

		public function is_http_tool(): bool
		{
			return $this->ua_device === 'http_tool' || $this->ua_is_http_tool === true;
		}

		public function is_traditional_form_post(): bool
		{
			return $this->request_method === 'POST'
				&& !$this->is_ajax()
				&& !$this->is_json_body()
				&& !$this->is_multipart_form()
				&& str_contains($this->headers_mixed['Content-Type'] ?? '', 'application/x-www-form-urlencoded');
		}
}
