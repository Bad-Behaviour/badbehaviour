<?php
// src/Feeds/Adapters/OpenAIJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Core\Interfaces\CacheInterface;

class OpenAIJsonFeed extends AbstractJsonFeed
{
    private string $bot_id;

    public function __construct(CacheInterface $cache, string $bot_id, string $url)
    {
        $this->bot_id = $bot_id;
        $this->url = $url;
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

        return [$this->bot_id => array_unique($cidrs)];
    }

    public function get_source_name(): string { return "openai-{$this->bot_id}"; }
    public function get_bot_ids(): array { return [$this->bot_id]; }
}