<?php
// tests/Unit/Feeds/Adapters/PlainTextFeedTest.php
namespace BadBehaviour\Tests\Unit\Feeds\Adapters;

use BadBehaviour\Feeds\Adapters\PlainTextFeed;
use BadBehaviour\Core\Interfaces\CacheInterface;
use PHPUnit\Framework\TestCase;

class PlainTextFeedTest extends TestCase
{

	private PlainTextFeed $feed;

	private CacheInterface $cache;

	protected function setUp(): void
	{
		$this->cache = $this->createMock(CacheInterface::class);
		$this->feed = new PlainTextFeed($this->cache, 'https://example.com/ips.txt', 'testbot');
	}

	public function test_parse_response(): void
	{
		$reflection = new \ReflectionClass($this->feed);
		$method = $reflection->getMethod('parse_response');
		$method->setAccessible(true);

		$response = "1.2.3.4/32\n5.6.7.8/24\n# comment\n\n9.10.11.12/16\n";
		$result = $method->invoke($this->feed, $response);

		$this->assertEquals([
			'1.2.3.4/32',
			'5.6.7.8/24',
			'9.10.11.12/16'
		], array_values($result));
	}

	public function test_get_source_name(): void
	{
		$this->assertEquals('plaintext-testbot', $this->feed->get_source_name());
	}

	public function test_get_bot_ids(): void
	{
		$this->assertEquals([
			'testbot'
		], $this->feed->get_bot_ids());
	}
}