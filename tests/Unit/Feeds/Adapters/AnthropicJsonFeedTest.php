<?php
// tests/Unit/Feeds/Adapters/AnthropicJsonFeedTest.php

namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\AnthropicJsonFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class AnthropicJsonFeedTest extends TestCase
{
	private AnthropicJsonFeed $feed;
	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->feed = new AnthropicJsonFeed($this->cache);
	}

	public function test_get_source_name(): void
	{
		$this->assertEquals('anthropic-claude', $this->feed->get_source_name());
	}

	public function test_get_bot_ids(): void
	{
		$this->assertEquals(['claude'], $this->feed->get_bot_ids());
	}

	public function test_instantiation(): void
	{
		$this->assertInstanceOf(AnthropicJsonFeed::class, $this->feed);
	}
}
