<?php
// tests/Unit/Feeds/Adapters/AppleJsonFeedTest.php

namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\AppleJsonFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class AppleJsonFeedTest extends TestCase
{
	private AppleJsonFeed $feed;
	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->feed = new AppleJsonFeed($this->cache);
	}

	public function test_get_source_name(): void
	{
		$this->assertEquals('applebot-official', $this->feed->get_source_name());
	}

	public function test_get_bot_ids(): void
	{
		// Apple feed covers both applebot and apple_ai
		$this->assertEquals(['applebot', 'apple_ai'], $this->feed->get_bot_ids());
	}

	public function test_instantiation(): void
	{
		$this->assertInstanceOf(AppleJsonFeed::class, $this->feed);
	}
}
