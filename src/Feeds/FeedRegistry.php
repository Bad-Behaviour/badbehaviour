<?php
// src/Feeds/FeedRegistry.php

namespace BadBehaviour\Feeds;

use BadBehaviour\CacheInterface;

class FeedRegistry
{
    /** @var IpFeedInterface[] */
    private array $feeds = [];

    public function __construct(CacheInterface $cache)
    {
    	// === OFFICIAL FEEDS ===

    	// Google (common crawlers)
    	$this->feeds['google'] = new CachedFeedDecorator(new GoogleJsonFeed($cache), $cache);

    	// Google User-Triggered (Google-Extended, etc.)
    	$this->feeds['google-user'] = new CachedFeedDecorator(
    		new \BadBehaviour\Feeds\Adapters\GoogleJsonFeed($cache),
    		$cache
    		);
    	$this->feeds['google-user']->feed->url = 'https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json';

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

        foreach ($this->feeds as $name => $feed) {
            try {
                $data = $feed->fetch();
                foreach ($data as $bot_id => $cidrs) {
                    if (!isset($merged[$bot_id])) {
                        $merged[$bot_id] = [];
                    }
                    $merged[$bot_id] = array_merge($merged[$bot_id], $cidrs);
                }
            } catch (\Throwable $e) {
                error_log("[BadBehaviour] Feed {$name} failed: " . $e->getMessage());
            }
        }

        // Deduplicate
        foreach ($merged as $bot_id => $cidrs) {
            $merged[$bot_id] = array_unique($cidrs);
        }

        return $merged;
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