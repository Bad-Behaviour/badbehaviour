<?php
// src/Feeds/Adapters/AnthropicJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

class AnthropicJsonFeed extends AbstractJsonFeed
{
    public function __construct(CacheInterface $cache)
    {
        // Official Anthropic crawler IP ranges feed
        $this->url = 'https://claude.com/crawling/bots.json';
        $this->expected_keys = ['prefixes'];
        parent::__construct($cache);
    }

    public function fetch(): array
    {
        $raw = parent::fetch();
        if (!$raw) return [];

        // Anthropic format: { "prefixes": [{ "ipv4Prefix": "...", "ipv6Prefix": "..." }] }
        $cidrs = [];
        foreach ($raw['prefixes'] as $entry) {
            if (!empty($entry['ipv4Prefix'])) $cidrs[] = $entry['ipv4Prefix'];
            if (!empty($entry['ipv6Prefix'])) $cidrs[] = $entry['ipv6Prefix'];
        }

        return ['claude' => array_unique($cidrs)];
    }

    public function get_source_name(): string { return 'anthropic-claude'; }
    public function get_bot_ids(): array { return ['claude']; }
}
