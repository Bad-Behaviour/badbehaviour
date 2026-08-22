<?php
// tests/Unit/Feeds/CachedFeedDecoratorTest.php
namespace BadBehaviour\Tests\Unit\Feeds;

use BadBehaviour\Feeds\CachedFeedDecorator;
use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class MockFeed implements IpFeedInterface
{

	private array $data;

	private bool $shouldFail = false;

	public function __construct(array $data = [])
	{
		$this->data = $data;
	}

	public function setShouldFail(bool $fail): void
	{
		$this->shouldFail = $fail;
	}

	public function fetch(): array
	{
		if ($this->shouldFail) {
			throw new \Exception('Feed failed');
		}
		return $this->data;
	}

	public function get_source_name(): string
	{
		return 'mock-feed';
	}

	public function get_bot_ids(): array
	{
		return [
			'mockbot'
		];
	}
}

class CachedFeedDecoratorTest extends TestCase
{

	private CacheInterface $cache;

	private MockFeed $innerFeed;

	private CachedFeedDecorator $decorator;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->innerFeed = new MockFeed([
			'mockbot' => [
				'1.2.3.4/32'
			]
		]);
		$this->decorator = new CachedFeedDecorator($this->innerFeed, $this->cache, 3600);
	}

	public function test_returns_fresh_cache(): void
	{
		$cached = [
			'data' => [
				'mockbot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => time()
		];

		$this->cache->method('get')->willReturn($cached);

		$result = $this->decorator->fetch();

		$this->assertEquals([
			'mockbot' => [
				'1.2.3.4/32'
			]
		], $result);
	}

	public function test_returns_stale_cache_on_failure(): void
	{
		$staleCache = [
			'data' => [
				'mockbot' => [
					'1.2.3.4/32'
				]
			],
			'fetched' => time() - 7200 // 2 hours ago (stale but within grace)
		];

		$this->cache->method('get')->willReturn($staleCache);
		$this->innerFeed->setShouldFail(true);

		$result = $this->decorator->fetch();

		$this->assertEquals([
			'mockbot' => [
				'1.2.3.4/32'
			]
		], $result);
	}

	public function test_returns_empty_on_total_failure(): void
	{
		$this->cache->method('get')->willReturn(null);
		$this->innerFeed->setShouldFail(true);

		$result = $this->decorator->fetch();

		$this->assertEquals([], $result);
	}

	public function test_get_wrapped_feed(): void
	{
		$wrapped = $this->decorator->getWrappedFeed();
		$this->assertSame($this->innerFeed, $wrapped);
	}
}
