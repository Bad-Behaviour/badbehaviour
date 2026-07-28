<?php
// src/Feeds/Adapters/AppleJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Core\Interfaces\CacheInterface;

class AppleJsonFeed extends AbstractJsonFeed
{
    public function __construct(CacheInterface $cache)
    {
        // Official Apple crawler IP ranges feed
        $this->url = 'https://search.developer.apple.com/applebot.json';
        $this->expected_keys = ['prefixes'];
        parent::__construct($cache);
    }

    public function fetch(): array
    {
        $raw = parent::fetch();
        if (!$raw) return [];

        // Apple format: { "prefixes": [{ "ipv4Prefix": "...", "ipv6Prefix": "..." }] }
        $cidrs = [];
        foreach ($raw['prefixes'] as $entry) {
            if (!empty($entry['ipv4Prefix'])) $cidrs[] = $entry['ipv4Prefix'];
            if (!empty($entry['ipv6Prefix'])) $cidrs[] = $entry['ipv6Prefix'];
        }

        // Applebot covers both search and AI crawler
        return [
            'applebot' => array_unique($cidrs),
            'apple_ai' => array_unique($cidrs), // Same ranges for Applebot-Extended
        ];
    }

    public function get_source_name(): string { return 'applebot-official'; }
    public function get_bot_ids(): array { return ['applebot', 'apple_ai']; }
}
