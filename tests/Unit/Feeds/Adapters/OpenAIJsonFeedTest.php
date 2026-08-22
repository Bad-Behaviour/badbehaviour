<?php
// tests/Unit/Feeds/Adapters/OpenAIJsonFeedTest.php
namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\OpenAIJsonFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class OpenAIJsonFeedTest extends TestCase
{

	private OpenAIJsonFeed $feed;

	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		// OpenAIJsonFeed requires bot_id and url in constructor
		$this->feed = new OpenAIJsonFeed($this->cache, 'gptbot', 'https://openai.com/gptbot.json');
	}

	public function test_get_source_name(): void
	{
		$this->assertEquals('openai-gptbot', $this->feed->get_source_name());
	}

	public function test_get_bot_ids(): void
	{
		$this->assertEquals([
			'gptbot'
		], $this->feed->get_bot_ids());
	}

	public function test_instantiation_with_different_bot_id(): void
	{
		$feed = new OpenAIJsonFeed($this->cache, 'chatgpt-user', 'https://openai.com/chatgpt-user.json');

		$this->assertEquals('openai-chatgpt-user', $feed->get_source_name());
		$this->assertEquals([
			'chatgpt-user'
		], $feed->get_bot_ids());
	}

	public function test_instantiation_with_searchbot(): void
	{
		$feed = new OpenAIJsonFeed($this->cache, 'oai-searchbot', 'https://openai.com/searchbot.json');

		$this->assertEquals('openai-oai-searchbot', $feed->get_source_name());
		$this->assertEquals([
			'oai-searchbot'
		], $feed->get_bot_ids());
	}

	public function test_instantiation(): void
	{
		$this->assertInstanceOf(OpenAIJsonFeed::class, $this->feed);
	}
}
