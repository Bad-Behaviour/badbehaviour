<?php

namespace BadBehaviour\Util;

class HeaderUtil
{
	public static function load_headers(): array
	{
		if (function_exists('getallheaders')) {
			$headers = getallheaders();
			if (!empty($headers)) {
				return $headers;
			}
		}

		$headers = [];
		foreach ($_SERVER as $key => $value) {
			if (str_starts_with($key, 'HTTP_')) {
				$headers[self::normalize_key(substr($key, 5))] = $value;
			} elseif (in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH', 'CONTENT_MD5'], true)) {
				$headers[self::normalize_key($key)] = $value;
			}
		}

		if (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
			$headers['Authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
		}

		return $headers;
	}

	public static function normalize_key(string $key): string
	{
		return str_replace(' ', '-', ucwords(str_replace(['_', '-'], ' ', strtolower($key))));
	}

	public static function normalize_keys(array $headers): array
	{
		$normalized = [];
		foreach ($headers as $k => $v) {
			$normalized[self::normalize_key($k)] = $v;
		}
		return $normalized;
	}

	public static function get_real_ip(array $headers_mixed, array $settings): string|false
	{
		if (empty($settings['reverse_proxy'])) {
			return false;
		}

		$header = self::normalize_key($settings['reverse_proxy_header'] ?? 'X-Forwarded-For');

		if (!isset($headers_mixed[$header])) {
			return false;
		}

		$addrs = array_reverse(preg_split('/[\s,]+/', $headers_mixed[$header]));
		$trusted_proxies = $settings['reverse_proxy_addresses'] ?? [];

		foreach ($addrs as $addr) {
			$addr = trim($addr);
			if (empty($addr)) continue;

			$is_trusted = !empty($trusted_proxies) ? IpUtil::match_any($addr, $trusted_proxies) : false;
			$is_private = IpUtil::is_private($addr);

			if (!$is_trusted && !$is_private) {
				return $addr;
			}
		}

		return false;
	}

	public static function get_ja3_fingerprint(): ?string
	{
		$headers = [
			'CF-Ray-Ja3',           // Cloudflare (Enterprise)
			'X-Client-Ja3',         // Generic
			'X-Ja3-Fingerprint',    // Generic
			'SSL-Client-Ja3',       // HAProxy
		];

		foreach ($headers as $header) {
			$server_key = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
			$value = $_SERVER[$server_key] ?? null;
			if ($value && preg_match('/^[a-f0-9]{32}$/i', $value)) {
				return strtolower($value);
			}
		}

		return null;
	}

	public static function get_h2_settings(): ?string
	{
		return $_SERVER['HTTP_HTTP2_SETTINGS'] ??
			$_SERVER['HTTP_X_HTTP2_SETTINGS'] ??
			null;
	}
}
