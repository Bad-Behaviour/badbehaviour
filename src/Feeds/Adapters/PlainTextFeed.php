<?php
// src/Feeds/Adapters/PlainTextFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\CacheInterface;

class PlainTextFeed implements IpFeedInterface
{
    public function __construct(
        protected CacheInterface $cache,
        protected string $url,
        protected string $bot_id,
        protected int $ttl = 86400
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

        $response = @file_get_contents($this->url);
        if ($response === false) {
            return $fallback ?? [];
        }

        $cidrs = array_filter(array_map('trim', explode("\n", $response)));
        $cidrs = array_filter($cidrs, fn($c) => $c !== '' && !str_starts_with($c, '#'));

        if (empty($cidrs)) {
            return $fallback ?? [];
        }

        $data = [$this->bot_id => $cidrs];
        $this->cache->set($cache_key, [
            'data' => $data,
            'fetched' => time(),
        ], $this->ttl);

        return $data;
    }

    public function get_source_name(): string { return "plaintext-{$this->bot_id}"; }
    public function get_bot_ids(): array { return [$this->bot_id]; }
}