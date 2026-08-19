<?php
// src/Feeds/Adapters/GoogleJsonFeed.php

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Core\Interfaces\CacheInterface;

class GoogleJsonFeed extends AbstractJsonFeed
{
	/** @var array<string, array{url: string, bot_ids: string[], dns_suffixes: string[]}> */
	private array $feed_configs = [
		'common_crawlers' => [
			'url' => 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
			'bot_ids' => ['googlebot'],
			'dns_suffixes' => ['googlebot.com', 'google.com'],
		],
		'special_crawlers' => [
			'url' => 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
			'bot_ids' => ['googlebot'],
			'dns_suffixes' => ['googlebot.com', 'google.com'],
		],
		'user_triggered' => [
			'url' => 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
			'bot_ids' => ['google_user_triggered'],
			'dns_suffixes' => ['gae.googleusercontent.com', 'google-proxy'],
		],
		'user_triggered_google' => [
			'url' => 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
			'bot_ids' => ['google_user_triggered'],
			'dns_suffixes' => ['google.com', 'google-proxy'],
		],
		'user_triggered_agents' => [
			'url' => 'https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json',
			'bot_ids' => ['google_user_triggered_agents'],
			'dns_suffixes' => [],
		],
	];

	private array $enabled_feeds = [];

	public function __construct(CacheInterface $cache, array $enabled_feeds = [])
	{
		parent::__construct($cache);
		$this->enabled_feeds = $enabled_feeds ?: array_keys($this->feed_configs);
	}

	public function fetch(): array
	{
		$all = [];

		foreach ($this->enabled_feeds as $feed_key) {
			if (!isset($this->feed_configs[$feed_key])) continue;

			$config = $this->feed_configs[$feed_key];
			$raw = $this->fetch_url($config['url']);
			if (!$raw) continue;

			$cidrs = [];
			foreach ($raw['prefixes'] ?? [] as $entry) {
				if (!empty($entry['ipv4Prefix'])) $cidrs[] = $entry['ipv4Prefix'];
				if (!empty($entry['ipv6Prefix'])) $cidrs[] = $entry['ipv6Prefix'];
			}
			$cidrs = array_unique($cidrs);

			foreach ($config['bot_ids'] as $bot_id) {
				$all[$bot_id] = ($all[$bot_id] ?? []);
				$all[$bot_id] = array_merge($all[$bot_id], $cidrs);
				$all[$bot_id] = array_unique($all[$bot_id]);
			}
		}

		return $all;
	}

	public function get_source_name(): string { return 'google'; }
	public function get_bot_ids(): array { return ['googlebot', 'google_user_triggered', 'google_user_triggered_agents']; }
}
