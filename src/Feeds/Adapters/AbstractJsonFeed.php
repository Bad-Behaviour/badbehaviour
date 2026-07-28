<?php
// src/Feeds/Adapters/AbstractJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\CacheInterface;

abstract class AbstractJsonFeed implements IpFeedInterface
{
    protected string $url;
    protected int $timeout = 10;
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
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'BadBehaviour/3.0 (+https://github.com/Bad-Behaviour/badbehaviour)',
        ]);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200 || !$response) {
            return null;
        }

        $data = json_decode($response, true);
        return is_array($data) ? $data : null;
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