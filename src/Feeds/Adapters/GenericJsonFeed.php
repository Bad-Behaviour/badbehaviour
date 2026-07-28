<?php
// src/Feeds/Adapters/GenericJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Core\Interfaces\CacheInterface;

class GenericJsonFeed extends AbstractJsonFeed
{
    public function __construct(
        CacheInterface $cache,
        string $bot_id,
        string $url,
        array $expected_keys = ['prefixes']
    ) {
        $this->url = $url;
        $this->expected_keys = $expected_keys;
        $this->bot_id = $bot_id;
        parent::__construct($cache);
    }

    private string $bot_id;

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

    public function get_source_name(): string { return "generic-{$this->bot_id}"; }
    public function get_bot_ids(): array { return [$this->bot_id]; }
}