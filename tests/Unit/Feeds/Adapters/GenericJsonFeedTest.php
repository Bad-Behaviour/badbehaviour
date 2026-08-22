<?php
// tests/Unit/Feeds/Adapters/GenericJsonFeedTest.php
namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\GenericJsonFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class GenericJsonFeedTest extends TestCase
{

	private GenericJsonFeed $feed;

	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->feed = new GenericJsonFeed($this->cache, 'perplexity', 'https://perplexity.ai/perplexitybot.json', [
			'prefixes'
		]);
	}

	public function test_get_source_name(): void
	{
		$this->assertEquals('generic-perplexity', $this->feed->get_source_name());
	}

	public function test_get_bot_ids(): void
	{
		$this->assertEquals([
			'perplexity'
		], $this->feed->get_bot_ids());
	}

	public function test_instantiation_with_different_bot(): void
	{
		$feed = new GenericJsonFeed($this->cache, 'duckduckgo', 'https://duckduckgo.com/duckassistbot.json', [
			'prefixes'
		]);

		$this->assertEquals('generic-duckduckgo', $feed->get_source_name());
		$this->assertEquals([
			'duckduckgo'
		], $feed->get_bot_ids());
	}

	public function test_instantiation_with_amazon(): void
	{
		$feed = new GenericJsonFeed($this->cache, 'amazonbot', 'https://developer.amazon.com/amazonbot/ip-addresses.json', [
			'prefixes'
		]);

		$this->assertEquals('generic-amazonbot', $feed->get_source_name());
		$this->assertEquals([
			'amazonbot'
		], $feed->get_bot_ids());
	}

	public function test_instantiation_with_custom_keys(): void
	{
		$feed = new GenericJsonFeed($this->cache, 'custombot', 'https://example.com/feed.json', [
			'cidrs',
			'ranges'
		]);

		$this->assertEquals('generic-custombot', $feed->get_source_name());
		$this->assertEquals([
			'custombot'
		], $feed->get_bot_ids());
	}

	public function test_instantiation(): void
	{
		$this->assertInstanceOf(GenericJsonFeed::class, $this->feed);
	}
}
