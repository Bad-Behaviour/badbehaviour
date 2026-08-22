<?php
// tests/Unit/Feeds/Adapters/AbstractJsonFeedTest.php
namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\AbstractJsonFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class TestJsonFeed extends AbstractJsonFeed
{

	public function __construct(CacheInterface $cache)
	{
		parent::__construct($cache);
		$this->url = 'https://test.example.com/feed.json';
		$this->expected_keys = [
			'prefixes'
		];
	}

	public function get_source_name(): string
	{
		return 'test-feed';
	}

	public function get_bot_ids(): array
	{
		return [
			'testbot'
		];
	}
}

class AbstractJsonFeedTest extends TestCase
{

	private TestJsonFeed $feed;

	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->feed = new TestJsonFeed($this->cache);
	}

	public function test_validate_accepts_valid_structure(): void
	{
		$reflection = new \ReflectionClass($this->feed);
		$method = $reflection->getMethod('validate');
		$method->setAccessible(true);

		$valid = [
			'prefixes' => [
				[
					'ipv4Prefix' => '1.2.3.4/32'
				]
			]
		];
		$this->assertTrue($method->invoke($this->feed, $valid));

		$invalid = [
			'wrong_key' => []
		];
		$this->assertFalse($method->invoke($this->feed, $invalid));

		$missing = [
			'prefixes' => 'not_array'
		];
		$this->assertFalse($method->invoke($this->feed, $missing));
	}

	public function test_cache_fallback_on_invalid_structure(): void
	{
		$staleCache = [
			'data' => [
				'testbot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => time() - 3600 // 1 hour ago
		];

		$this->cache->method('get')->willReturn($staleCache);
		$this->cache->method('set')->willReturn(true);

		// Mock fetch_fresh to return invalid structure
		$reflection = new \ReflectionClass($this->feed);
		$fetchFresh = $reflection->getMethod('fetch_fresh');
		$fetchFresh->setAccessible(true);
		$fetchFresh->invoke($this->feed); // Returns invalid

		$result = $this->feed->fetch();

		// Should return stale cache
		$this->assertEquals([
			'testbot' => [
				'1.2.3.4/32'
			]
		], $result);
	}
}