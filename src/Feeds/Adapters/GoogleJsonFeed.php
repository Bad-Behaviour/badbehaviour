<?php
// src/Feeds/Adapters/GoogleJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

class GoogleJsonFeed extends AbstractJsonFeed
{
    public function __construct(CacheInterface $cache)
    {
        $this->url = 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json';
        $this->expected_keys = ['prefixes'];
        parent::__construct($cache);
    }

    public function fetch(): array
    {
        $raw = parent::fetch();
        if (!$raw) return [];

        // Google format: { "prefixes": [{ "ipv4Prefix": "...", "ipv6Prefix": "..." }] }
        $cidrs = [];
        foreach ($raw['prefixes'] as $entry) {
            if (!empty($entry['ipv4Prefix'])) $cidrs[] = $entry['ipv4Prefix'];
            if (!empty($entry['ipv6Prefix'])) $cidrs[] = $entry['ipv6Prefix'];
        }

        return ['googlebot' => array_unique($cidrs)];
    }

    public function get_source_name(): string { return 'google-common-crawlers'; }
    public function get_bot_ids(): array { return ['googlebot', 'google_ai']; }
}