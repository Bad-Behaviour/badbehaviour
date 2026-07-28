<?php
// tests/Unit/Feeds/Adapters/BingJsonFeedTest.php

namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\BingJsonFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class BingJsonFeedTest extends TestCase
{
	private BingJsonFeed $feed;
	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->feed = new BingJsonFeed($this->cache);
	}

	public function test_get_source_name(): void
	{
		$this->assertEquals('bingbot-json', $this->feed->get_source_name());
	}

	public function test_get_bot_ids(): void
	{
		$this->assertEquals(['bingbot'], $this->feed->get_bot_ids());
	}

	public function test_instantiation(): void
	{
		$this->assertInstanceOf(BingJsonFeed::class, $this->feed);
	}
}
