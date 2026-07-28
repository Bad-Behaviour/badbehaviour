<?php
// src/Feeds/Adapters/BingJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

class BingJsonFeed extends AbstractJsonFeed
{
    public function __construct(CacheInterface $cache)
    {
        $this->url = 'https://www.bing.com/toolbox/bingbot.json';
        $this->expected_keys = ['prefixes'];
        parent::__construct($cache);
    }

    public function fetch(): array
    {
        $raw = parent::fetch();
        if (!$raw) return [];

        $cidrs = [];
        foreach ($raw['prefixes'] as $entry) {
            if (!empty($entry['ipv4Prefix'])) $cidrs[] = $entry['ipv4Prefix'];
            if (!empty($entry['ipv6Prefix'])) $cidrs[] = $entry['ipv6Prefix'];
        }

        return ['bingbot' => array_unique($cidrs)];
    }

    public function get_source_name(): string { return 'bingbot-json'; }
    public function get_bot_ids(): array { return ['bingbot']; }
}