<?php
// src/Feeds/Adapters/PlainTextFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;

class PlainTextFeed implements IpFeedInterface
{
	public function __construct(
		protected CacheInterface $cache,
		protected string $url,
		protected string $bot_id,
		protected int $ttl = 86400,
		protected int $timeout = 3
		) {}

		public function fetch(): array
		{
			$cache_key = 'ip_feed:' . $this->get_source_name();
			$cached = $this->cache->get($cache_key);

			if ($cached && isset($cached['data'], $cached['fetched'])) {
				if (time() - $cached['fetched'] < $this->ttl) {
					return $cached['data'];
				}
				$fallback = $cached['data'];
			} else {
				$fallback = null;
			}

			// Try cURL with CA bundle first
			$cidrs = $this->fetch_with_curl();

			// Fallback to stream context
			if ($cidrs === null) {
				$cidrs = $this->fetch_with_stream_context();
			}

			if ($cidrs === null || empty($cidrs)) {
				return $fallback ?? [];
			}

			$data = [$this->bot_id => $cidrs];
			$this->cache->set($cache_key, [
				'data' => $data,
				'fetched' => time(),
			], $this->ttl);

			return $data;
		}

		private function fetch_with_curl(): ?array
		{
			$ca_bundle = $this->find_ca_bundle();
			if (!$ca_bundle) {
				return null;
			}

			$ch = curl_init($this->url);
			curl_setopt_array($ch, [
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT => 10,
				CURLOPT_CAINFO => $ca_bundle,
				CURLOPT_CAPATH => dirname($ca_bundle),
				CURLOPT_SSL_VERIFYPEER => true,
				CURLOPT_USERAGENT => 'BadBehaviour/3.0 (+https://github.com/Bad-Behaviour/badbehaviour)',
			]);

			$response = curl_exec($ch);
			$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			$curl_error = curl_error($ch);
			curl_close($ch);

			if ($http_code !== 200 || !$response) {
				error_log("[BadBehaviour] PlainTextFeed {$this->get_source_name()} cURL failed: HTTP $http_code " . ($curl_error ?: ''));
				return null;
			}

			return $this->parse_response($response);
		}

		private function fetch_with_stream_context(): ?array
		{
			$ca_bundle = $this->find_ca_bundle();

			$context_options = [
				'http' => [
					'timeout' => 10,
					'user_agent' => 'BadBehaviour/3.0',
				],
			];

			if ($ca_bundle) {
				$context_options['ssl'] = [
					'cafile' => $ca_bundle,
					'verify_peer' => true,
					'verify_peer_name' => true,
				];
			} else {
				error_log("[BadBehaviour WARNING] No CA bundle for {$this->url}, fetching without SSL verification");
				$context_options['ssl'] = [
					'verify_peer' => false,
					'verify_peer_name' => false,
				];
			}

			$context = stream_context_create($context_options);
			$response = @file_get_contents($this->url, false, $context);

			if (!$response) {
				error_log("[BadBehaviour] PlainTextFeed {$this->get_source_name()} stream context failed");
				return null;
			}

			return $this->parse_response($response);
		}

		private function parse_response(string $response): array
		{
			$cidrs = array_filter(array_map('trim', explode("\n", $response)));
			return array_filter($cidrs, fn($c) => $c !== '' && !str_starts_with($c, '#'));
		}

		private function find_ca_bundle(): ?string
		{
			static $cached = null;

			if ($cached !== null) {
				return $cached;
			}

			$paths = [
				'/etc/ssl/certs/ca-certificates.crt',      // Debian/Ubuntu
				'/etc/pki/tls/certs/ca-bundle.crt',        // RHEL/CentOS/Fedora
				'/etc/ssl/ca-bundle.pem',                  // OpenSUSE
				'/usr/local/etc/openssl/cert.pem',         // macOS/Homebrew default
				'/usr/local/etc/openssl@1.1/cert.pem',     // Homebrew openssl@1.1
				'/usr/local/etc/openssl@3/cert.pem',       // Homebrew openssl@3
				'/opt/homebrew/etc/openssl@3/cert.pem',    // Apple Silicon Homebrew
				__DIR__ . '/../../../cacert.pem',          // Local fallback
			];

			foreach ($paths as $path) {
				if (file_exists($path) && is_readable($path)) {
					$cached = $path;
					return $cached;
				}
			}

			// Try PHP ini settings
			$ini_cafile = ini_get('openssl.cafile');
			if ($ini_cafile && file_exists($ini_cafile)) {
				$cached = $ini_cafile;
				return $cached;
			}

			$ini_capath = ini_get('openssl.capath');
			if ($ini_capath && is_dir($ini_capath)) {
				$cached = $ini_capath;
				return $cached;
			}

			return null;
		}

		public function get_source_name(): string { return "plaintext-{$this->bot_id}"; }
		public function get_bot_ids(): array { return [$this->bot_id]; }
}
