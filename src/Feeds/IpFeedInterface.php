<?php
// src/Feeds/IpFeedInterface.php

namespace BadBehaviour\Feeds;

interface IpFeedInterface
{
    /**
     * @return array<string, string[]> Bot ID => CIDR[]
     */
    public function fetch(): array;

    public function get_source_name(): string;
    public function get_bot_ids(): array;  // Which bots this feed covers
}