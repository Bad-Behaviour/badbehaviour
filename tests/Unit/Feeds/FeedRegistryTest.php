<?php
// tests/Unit/Feeds/FeedRegistryTest.php
namespace BadBehaviour\Tests\Unit\Feeds;

use BadBehaviour\Feeds\FeedRegistry;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class FeedRegistryTest extends TestCase
{

	private FeedRegistry $registry;

	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->registry = new FeedRegistry($this->cache);
	}

	public function test_get_feed_status(): void
	{
		$status = $this->registry->get_feed_status();

		$this->assertIsArray($status);
		$this->assertNotEmpty($status);

		// Check expected feeds
		$this->assertArrayHasKey('google', $status);
		$this->assertArrayHasKey('bing', $status);
		$this->assertArrayHasKey('anthropic', $status);
		$this->assertArrayHasKey('apple', $status);

		foreach ($status as $name => $info) {
			$this->assertArrayHasKey('source', $info);
			$this->assertArrayHasKey('bots', $info);
			$this->assertIsArray($info['bots']);
		}
	}

	public function test_fetch_all_returns_merged(): void
	{
		// This would need mocked feeds - skip for now
		$this->markTestSkipped('Requires mocked feed adapters');
	}
}
