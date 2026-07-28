<?php
// src/Feeds/Adapters/AbstractJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;

abstract class AbstractJsonFeed implements IpFeedInterface
{
    protected string $url;
    protected int $timeout = 3;
    protected array $expected_keys = [];  // Required top-level keys

    public function __construct(
        protected CacheInterface $cache,
        protected int $ttl = 86400  // 24 hours
    ) {}

    public function fetch(): array
    {
        $cache_key = 'ip_feed:' . $this->get_source_name();

        // 1. Try cache first (even stale)
        $cached = $this->cache->get($cache_key);
        if ($cached && isset($cached['data'], $cached['fetched'])) {
            // If fresh, return immediately
            if (time() - $cached['fetched'] < $this->ttl) {
                return $cached['data'];
            }
            // Stale but usable — keep as fallback
            $fallback = $cached['data'];
        } else {
            $fallback = null;
        }

        // 2. Fetch fresh
        $fresh = $this->fetch_fresh();

        if ($fresh) {
            // Validate structure
            if ($this->validate($fresh)) {
                $this->cache->set($cache_key, [
                    'data' => $fresh,
                    'fetched' => time(),
                ], $this->ttl);
                return $fresh;
            }

            // Invalid structure — log and use fallback
            error_log("[BadBehaviour] Feed {$this->get_source_name()} returned invalid structure");
        }

        // 3. Graceful degradation: return stale cache
        if ($fallback) {
            error_log("[BadBehaviour] Using STALE cache for {$this->get_source_name()}");
            return $fallback;
        }

        // 4. No cache, no fresh — return empty (DNS verification will catch real bots)
        error_log("[BadBehaviour] Feed {$this->get_source_name()} unavailable, no cache");
        return [];
    }

    private function fetch_fresh(): ?array
    {
    	// Try cURL with CA bundle detection first
    	$result = $this->fetch_with_curl();
    	if ($result !== null) return $result;

    	// Fallback: file_get_contents with stream context
    	return $this->fetch_with_stream_context();
    }

    private function fetch_with_curl(): ?array
    {
    	$ch = curl_init($this->url);
    	$ca_bundle = $this->find_ca_bundle();

    	$options = [
    		CURLOPT_RETURNTRANSFER => true,
    		CURLOPT_TIMEOUT => $this->timeout,
    		CURLOPT_USERAGENT => 'BadBehaviour/3.0 (+https://github.com/Bad-Behaviour/badbehaviour)',
    	];

    	if ($ca_bundle) {
    		$options[CURLOPT_CAINFO] = $ca_bundle;
    		$options[CURLOPT_CAPATH] = dirname($ca_bundle);
    		$options[CURLOPT_SSL_VERIFYPEER] = true;
    	} else {
    		// No CA bundle found - skip this method, try stream context
    		return null;
    	}

    	curl_setopt_array($ch, $options);
    	$response = curl_exec($ch);
    	$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    	curl_close($ch);

    	if ($http_code !== 200 || !$response) {
    		return null;
    	}

    	$data = json_decode($response, true);
    	return (json_last_error() === JSON_ERROR_NONE && is_array($data)) ? $data : null;
    }

    private function fetch_with_stream_context(): ?array
    {
    	$ca_bundle = $this->find_ca_bundle();

    	$context_options = [
    		'http' => [
    			'timeout' => $this->timeout,
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
    		// Last resort: disable verification with warning
    		error_log("[BadBehaviour WARNING] No CA bundle found, fetching {$this->url} without SSL verification");
    		$context_options['ssl'] = [
    			'verify_peer' => false,
    			'verify_peer_name' => false,
    		];
    	}

    	$context = stream_context_create($context_options);
    	$response = @file_get_contents($this->url, false, $context);

    	if (!$response) return null;

    	$data = json_decode($response, true);
    	return (json_last_error() === JSON_ERROR_NONE && is_array($data)) ? $data : null;
    }

    private function find_ca_bundle(): ?string
    {
    	static $cached = null;

    	if ($cached !== null) return $cached;

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

    protected function validate(array $data): bool
    {
        foreach ($this->expected_keys as $key) {
            if (!isset($data[$key]) || !is_array($data[$key])) {
                return false;
            }
        }
        return true;
    }

    // Implement in children
    abstract public function get_source_name(): string;
    abstract public function get_bot_ids(): array;
}