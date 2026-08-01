<?php
// src/Util/HeaderUtil.php - HTTP/3 documentation additions

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

	/**
	 * Detect JA3 TLS fingerprint if forwarded by reverse proxy.
	 *
	 * Supported sources:
	 *   - Cloudflare Enterprise (CF-Ray-Ja3, X-Client-Ja3)
	 *   - HAProxy SSL-Client-Ja3
	 *   - nginx with ja3-nginx-module (X-Client-Ja3)
	 *
	 * === HTTP/3 (QUIC) LIMITATION ===
	 *
	 * HTTP/3 uses QUIC over UDP and encrypts more of the handshake than TLS over TCP.
	 * Standard JA3 (TLS ClientHello fingerprint) CANNOT be computed for HTTP/3
	 * connections from the application layer because:
	 *
	 *   1. The TLS ClientHello is encrypted inside the QUIC Initial packet
	 *   2. QUIC's transport parameters replace the TLS layer for many handshake fields
	 *   3. There's no application-layer visibility into QUIC frames
	 *
	 * For HTTP/3 detection, you MUST rely on:
	 *
	 *   (a) Reverse proxy forwarding — Cloudflare and some CDNs extract and
	 *       forward QUIC fingerprints via custom headers:
	 *         - Cloudflare: HTTP/3 fingerprint is NOT exposed (proprietary)
	 *         - Custom: X-Http3-Fp, X-QUIC-Fp, X-Alpn-H3
	 *
	 *   (b) Browser UA + Client Hints — HTTP/3-capable browsers (Chrome 87+,
	 *       Firefox 88+, Safari 14+) are identifiable via Sec-CH-UA headers,
	 *       which BadBehaviour's ClientHintsDetector handles.
	 *
	 *   (c) ALPN negotiation — When the reverse proxy terminates QUIC and
	 *       forwards HTTP/1.1, the X-Alpn-H3 header may be set:
	 *         - "h3"     = HTTP/3 over QUIC
	 *         - "h3-29"  = HTTP/3 draft 29 (legacy)
	 *
	 * Returns null when no fingerprint source is available.
	 */
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

	/**
	 * Return the HTTP/3 fingerprint headers if forwarded by the proxy.
	 * Returns null if not HTTP/3 (or not detectable).
	 *
	 * Possible header sources (config-dependent):
	 *   - X-Alpn-H3:        "h3" or "h3-29"
	 *   - X-QUIC-Fp:        QUIC transport parameter hash (CDN-specific)
	 *   - X-Http3-Fp:       Custom HTTP/3 fingerprint (proprietary)
	 *
	 * Note: As of 2026, no standardized HTTP/3 fingerprint exists comparable to JA3.
	 * The QUIC working group has discussed "QTP" (QUIC Transport Parameters)
	 * but it has not been standardized.
	 *
	 * @return array{alpn: ?string, fingerprint: ?string, is_http3: bool}
	 */
	public static function get_http3_info(): array
	{
		$alpn = $_SERVER['HTTP_X_ALPN_H3'] ?? null;
		$fingerprint = $_SERVER['HTTP_X_QUIC_FP'] ?? $_SERVER['HTTP_X_HTTP3_FP'] ?? null;

		$is_http3 = false;
		if ($alpn && (str_starts_with($alpn, 'h3') || str_starts_with($alpn, 'h3-'))) {
			$is_http3 = true;
		}

		return [
			'alpn'       => $alpn,
			'fingerprint' => $fingerprint,
			'is_http3'   => $is_http3,
		];
	}

	/**
	 * Return HTTP/2 settings if forwarded by reverse proxy.
	 * Returns null when not available.
	 *
	 * HTTP/2 SETTINGS frame is unencrypted and can be captured at the proxy,
	 * but the application layer never sees it directly — only via headers
	 * like HTTP2-Settings (nginx) or X-HTTP2-Settings (HAProxy).
	 */
	public static function get_h2_settings(): ?string
	{
		return $_SERVER['HTTP_HTTP2_SETTINGS'] ??
			$_SERVER['HTTP_X_HTTP2_SETTINGS'] ??
			null;
	}
}