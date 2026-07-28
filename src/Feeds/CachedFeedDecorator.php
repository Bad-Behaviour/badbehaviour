<?php
// src/Feeds/CachedFeedDecorator.php

namespace BadBehaviour\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;

class CachedFeedDecorator implements IpFeedInterface
{
    public function __construct(
        private IpFeedInterface $feed,
        private CacheInterface $cache,
        private int $ttl = 86400,           // 24 hours fresh
        private int $stale_ttl = 604800     // 7 days stale fallback
    ) {}

    public function fetch(): array
    {
        $cache_key = 'feed:' . $this->feed->get_source_name();

        // 1. Try fresh cache
        $cached = $this->cache->get($cache_key);
        if ($cached && isset($cached['data'], $cached['fetched'])) {
            $age = time() - $cached['fetched'];

            if ($age < $this->ttl) {
                // Fresh - return immediately
                return $cached['data'];
            }

            // Stale but within grace period - keep as fallback
            $fallback = $cached['data'];
        } else {
            $fallback = null;
        }

        // 2. Fetch fresh from source
        try {
            $fresh = $this->feed->fetch();

            if ($fresh && $this->validate($fresh)) {
                $this->cache->set($cache_key, [
                    'data' => $fresh,
                    'fetched' => time(),
                ], $this->ttl);

                return $fresh;
            }

            // Invalid structure
            error_log("[BadBehaviour] Feed {$this->feed->get_source_name()} returned invalid structure");
        } catch (\Throwable $e) {
            error_log("[BadBehaviour] Feed {$this->feed->get_source_name()} fetch failed: " . $e->getMessage());
        }

        // 3. Graceful degradation: return stale cache
        if ($fallback) {
            error_log("[BadBehaviour] Using STALE cache for {$this->feed->get_source_name()} (age: " . (time() - $cached['fetched']) . "s)");
            return $fallback;
        }

        // 4. No cache, no fresh - empty array (DNS verification catches real bots)
        error_log("[BadBehaviour] Feed {$this->feed->get_source_name()} unavailable, no cache");
        return [];
    }

    private function validate(array $data): bool
    {
        // Must have at least one bot with CIDRs
        foreach ($data as $cidrs) {
            if (is_array($cidrs) && !empty($cidrs)) {
                return true;
            }
        }
        return false;
    }

    public function get_source_name(): string { return $this->feed->get_source_name(); }
    public function get_bot_ids(): array { return $this->feed->get_bot_ids(); }
}
