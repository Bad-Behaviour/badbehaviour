<?php
// src/Feeds/FeedRegistry.php

namespace BadBehaviour\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Feeds\Adapters\GoogleJsonFeed;
use BadBehaviour\Feeds\Adapters\BingJsonFeed;
use BadBehaviour\Feeds\Adapters\OpenAIJsonFeed;
use BadBehaviour\Feeds\Adapters\AnthropicJsonFeed;
use BadBehaviour\Feeds\Adapters\AppleJsonFeed;
use BadBehaviour\Feeds\Adapters\PlainTextFeed;
use BadBehaviour\Feeds\Adapters\GenericJsonFeed;
use BadBehaviour\Feeds\CachedFeedDecorator;

class FeedRegistry implements FeedProviderInterface
{
    /** @var IpFeedInterface[] */
    private array $feeds = [];

    public function __construct(CacheInterface $cache)
    {
    	// === OFFICIAL FEEDS ===

    	// Google (common crawlers)
    	$this->feeds['google'] = new CachedFeedDecorator(new GoogleJsonFeed($cache), $cache);

    	// Google User-Triggered (Google-Extended, etc.)
    	$this->feeds['google'] = new CachedFeedDecorator(new GoogleJsonFeed($cache), $cache);
    	$this->feeds['google-user'] = new CachedFeedDecorator(
    		new GoogleJsonFeed($cache, 'https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json'),
    		$cache
    	);

    	// Bing
    	$this->feeds['bing'] = new CachedFeedDecorator(new BingJsonFeed($cache), $cache);

    	// OpenAI (separate feeds for different intents)
    	$this->feeds['gptbot'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\OpenAIJsonFeed($cache, 'gptbot', 'https://openai.com/gptbot.json'),
    		$cache
    		);
    	$this->feeds['chatgpt-user'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\OpenAIJsonFeed($cache, 'chatgpt-user', 'https://openai.com/chatgpt-user.json'),
    		$cache
    		);
    	$this->feeds['oai-searchbot'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\OpenAIJsonFeed($cache, 'oai-searchbot', 'https://openai.com/searchbot.json'),
    		$cache
    		);

    	// Anthropic - NEW dedicated adapter
    	$this->feeds['anthropic'] = new CachedFeedDecorator(new AnthropicJsonFeed($cache), $cache);

    	// Apple - NEW dedicated adapter
    	$this->feeds['apple'] = new CachedFeedDecorator(new AppleJsonFeed($cache), $cache);

    	// Perplexity
    	$this->feeds['perplexity'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\GenericJsonFeed($cache, 'perplexity', 'https://www.perplexity.ai/perplexitybot.json', ['prefixes']),
    		$cache
    		);

    	// DuckDuckGo
    	$this->feeds['duckduckgo'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\GenericJsonFeed($cache, 'duckduckgo', 'https://duckduckgo.com/duckassistbot.json', ['prefixes']),
    		$cache
    		);

    	// Amazon
    	$this->feeds['amazon'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\GenericJsonFeed($cache, 'amazonbot', 'https://developer.amazon.com/amazonbot/ip-addresses.json', ['prefixes']),
    		$cache
    		);

    	// Cloudflare (plain text)
    	$this->feeds['cloudflare-v4'] = new CachedFeedDecorator(
    		new PlainTextFeed($cache, 'https://www.cloudflare.com/ips-v4', 'cloudflare'),
    		$cache
    		);
    	$this->feeds['cloudflare-v6'] = new CachedFeedDecorator(
    		new PlainTextFeed($cache, 'https://www.cloudflare.com/ips-v6', 'cloudflare'),
    		$cache
    		);
    }

    /**
     * Fetch all feeds, merge by bot ID
     * @return array<string, string[]> Bot ID => merged CIDRs
     */
    public function fetch_all(): array
    {
    	$merged = [];
    	$start = microtime(true);
    	$max_total = 10.0;

    	foreach ($this->feeds as $name => $feed) {
    		if (microtime(true) - $start > $max_total) break;

    		try {
    			$data = $feed->fetch();
    			foreach ($data as $bot_id => $cidrs) {
    				$merged[$bot_id] = array_merge($merged[$bot_id] ?? [], $cidrs);
    			}
    		} catch (\Throwable $e) {
    			error_log("[BadBehaviour] Feed $name failed: " . $e->getMessage());
    		}
    	}

    	return array_map('array_unique', $merged);
    }

    /**
     * Return the configured feed list for iteration.
     *
     * Exposes the IpFeedInterface map so callers (notably OnDemandRefresher)
     * can iterate feeds and call fetch() on each. The returned array is
     * a copy of the internal map (PHP arrays are value types, so no
     * aliasing concern).
     *
     * @return array<string, IpFeedInterface>
     */
    public function get_feeds(): array
    {
    	return $this->feeds;
    }

    public function get_feed_status(): array
    {
        $status = [];
        foreach ($this->feeds as $name => $feed) {
            $status[$name] = [
                'source' => $feed->get_source_name(),
                'bots' => $feed->get_bot_ids(),
            ];
        }
        return $status;
    }
}