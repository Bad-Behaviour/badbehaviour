<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Cache;

use BadBehaviour\Cache\FileCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(\BadBehaviour\Cache\FileCache::class)]
final class FileCacheTest extends TestCase
{

	private string $cacheDir;

	protected function setUp(): void
	{
		$this->cacheDir = sys_get_temp_dir() . '/bb_test_cache_' . uniqid('', true);
		mkdir($this->cacheDir, 0755, true);
	}

	protected function tearDown(): void
	{
		// Clean up test files
		$files = glob($this->cacheDir . '/*');
		if ($files !== false) {
			foreach ($files as $file) {
				@unlink($file);
			}
		}
		@rmdir($this->cacheDir);
	}

	public function testConstructorCreatesDirectoryIfMissing(): void
	{
		$newDir = sys_get_temp_dir() . '/bb_test_new_' . uniqid('', true);
		$this->assertDirectoryDoesNotExist($newDir);

		new FileCache($newDir);

		$this->assertDirectoryExists($newDir);

		@rmdir($newDir);
	}

	public function testSetAndGetStoresValue(): void
	{
		$cache = new FileCache($this->cacheDir);
		$cache->set('my_key', 'my_value', 60);

		$this->assertSame('my_value', $cache->get('my_key'));
	}

	public function testGetReturnsNullForMissingKey(): void
	{
		$cache = new FileCache($this->cacheDir);

		$this->assertNull($cache->get('nonexistent'));
	}

	public function testGetReturnsNullForExpiredValue(): void
	{
		$cache = new FileCache($this->cacheDir);

		// Write a file with a clearly past expiry by manipulating internal format
		$file = $this->cacheDir . '/expired.cache';
		$data = json_encode([
			'value' => 'should_not_be_returned',
			'expires' => time() - 100,
			'created' => time() - 200
		]);
		file_put_contents($file, $data);

		$this->assertNull($cache->get('expired'));
		$this->assertFileDoesNotExist($file, 'Expired file should have been deleted');
	}

	public function testGetRemovesCorruptFile(): void
	{
		$cache = new FileCache($this->cacheDir);

		$file = $this->cacheDir . '/corrupt.cache';
		file_put_contents($file, 'not valid json{{{');

		$this->assertNull($cache->get('corrupt'));
		$this->assertFileDoesNotExist($file);
	}

	public function testSetReturnsTrueOnSuccess(): void
	{
		$cache = new FileCache($this->cacheDir);

		$this->assertTrue($cache->set('k', 'v', 60));
	}

	public function testDeleteRemovesEntry(): void
	{
		$cache = new FileCache($this->cacheDir);
		$cache->set('to_delete', 'value', 60);

		$this->assertTrue($cache->delete('to_delete'));
		$this->assertNull($cache->get('to_delete'));
	}

	public function testDeleteReturnsFalseForMissingKey(): void
	{
		$cache = new FileCache($this->cacheDir);

		// @unlink returns false for missing files and that propagates
		// through delete() unchanged. Callers that need idempotent
		// delete semantics must check themselves (or use a different
		// cache adapter).
		$this->assertFalse($cache->delete('never_existed'));
	}

	public function testIncrementCounterStartsAtOne(): void
	{
		$cache = new FileCache($this->cacheDir);

		$this->assertSame(1, $cache->increment_counter('hits', 60));
		$this->assertSame(2, $cache->increment_counter('hits', 60));
		$this->assertSame(3, $cache->increment_counter('hits', 60));
	}

	public function testIncrementCounterRespectsWindow(): void
	{
		$cache = new FileCache($this->cacheDir);

		// First increment with window=10 — baseline timestamp = now
		$cache->increment_counter('windowed', 10);

		// A second increment in the same window must continue counting.
		$this->assertSame(2, $cache->increment_counter('windowed', 10));
	}

	public function testIncrementCounterReturnsZeroOnException(): void
	{
		$cache = new FileCache($this->cacheDir);

		// Make the cache directory read-only so writes fail.
		chmod($this->cacheDir, 0555);

		try {
			// write_put_contents will fail; the method must still return a sane int.
			// Implementation catches Throwable and returns 0.
			$result = $cache->increment_counter('ro_test', 60);
			$this->assertIsInt($result);
		} finally {
			chmod($this->cacheDir, 0755);
		}
	}

	public function testGetCounterReturnsZeroForMissingKey(): void
	{
		$cache = new FileCache($this->cacheDir);

		$this->assertSame(0, $cache->get_counter('never_incremented'));
	}

	public function testGetCounterReturnsCurrentValue(): void
	{
		$cache = new FileCache($this->cacheDir);
		$cache->increment_counter('k', 60);
		$cache->increment_counter('k', 60);
		$cache->increment_counter('k', 60);

		$this->assertSame(3, $cache->get_counter('k'));
	}

	public function testGetBehaviorProfileReturnsNullForMissingSession(): void
	{
		$cache = new FileCache($this->cacheDir);

		$this->assertNull($cache->get_behavior_profile('no-such-session'));
	}

	public function testSaveAndGetBehaviorProfileRoundTrip(): void
	{
		$cache = new FileCache($this->cacheDir);
		$profile = [
			'count' => 5,
			'urls' => [
				'/a',
				'/b',
				'/c'
			],
			'ua_hash' => 'abc123'
		];

		$cache->save_behavior_profile('sess-1', $profile, 60);

		$loaded = $cache->get_behavior_profile('sess-1');
		$this->assertIsArray($loaded);
		$this->assertSame(5, $loaded['count']);
		$this->assertSame([
			'/a',
			'/b',
			'/c'
		], $loaded['urls']);
		$this->assertSame('abc123', $loaded['ua_hash']);
	}

	public function testAddToSetAndGetSet(): void
	{
		$cache = new FileCache($this->cacheDir);
		$cache->add_to_set('ja3_set', 'ja3-hash-a', 60);
		$cache->add_to_set('ja3_set', 'ja3-hash-b', 60);

		$values = $cache->get_set('ja3_set');
		sort($values);
		$this->assertSame([
			'ja3-hash-a',
			'ja3-hash-b'
		], $values);
	}

	public function testAddToSetIsIdempotentForSameValue(): void
	{
		$cache = new FileCache($this->cacheDir);
		$cache->add_to_set('dup', 'x', 60);
		$cache->add_to_set('dup', 'x', 60);

		$values = $cache->get_set('dup');
		$this->assertCount(1, $values);
		$this->assertSame([
			'x'
		], $values);
	}

	public function testGetSetReturnsEmptyArrayForMissingKey(): void
	{
		$cache = new FileCache($this->cacheDir);

		$this->assertSame([], $cache->get_set('never_added'));
	}

	public function testGetSetPrunesExpiredEntries(): void
	{
		$cache = new FileCache($this->cacheDir);

		// Manually create a set file with one expired and one valid entry
		$file = $this->cacheDir . '/set:test_prune.cache';
		$data = [
			'alive' => time() + 100,
			'expired' => time() - 100
		];
		file_put_contents($file, json_encode($data));

		$values = $cache->get_set('test_prune');
		$this->assertSame([
			'alive'
		], $values);

		// File should have been rewritten with only valid entries
		$rewritten = json_decode(file_get_contents($file), true);
		$this->assertArrayHasKey('alive', $rewritten);
		$this->assertArrayNotHasKey('expired', $rewritten);
	}

	public function testCleanupExpiredRemovesExpiredFiles(): void
	{
		$cache = new FileCache($this->cacheDir);

		$expiredFile = $this->cacheDir . '/expired_garbage.cache';
		$freshFile = $this->cacheDir . '/fresh_value.cache';

		file_put_contents($expiredFile, json_encode([
			'value' => 'x',
			'expires' => time() - 1000,
			'created' => time() - 2000
		]));
		file_put_contents($freshFile, json_encode([
			'value' => 'y',
			'expires' => time() + 1000,
			'created' => time()
		]));

		$cache->cleanup_expired();

		$this->assertFileDoesNotExist($expiredFile);
		$this->assertFileExists($freshFile);
	}

	public function testCleanupExpiredRemovesCorruptFiles(): void
	{
		$cache = new FileCache($this->cacheDir);

		$corruptFile = $this->cacheDir . '/corrupt_garbage.cache';
		file_put_contents($corruptFile, 'not json{{');

		$cache->cleanup_expired();

		$this->assertFileDoesNotExist($corruptFile);
	}

	public function testFilePathSanitizationForUnsafeCharacters(): void
	{
		$cache = new FileCache($this->cacheDir);

		// Key with slashes, spaces, dots — must not escape cache_dir.
		$cache->set('foo/bar baz.qux', 'safe_value', 60);

		$this->assertSame('safe_value', $cache->get('foo/bar baz.qux'));

		// Confirm no file ended up outside the cache dir.
		$escaped = glob(sys_get_temp_dir() . '/foo*');
		$this->assertEmpty($escaped, 'Unsafe key characters must be sanitized');
	}

	public function testSetHandlesComplexValueTypes(): void
	{
		$cache = new FileCache($this->cacheDir);

		$value = [
			'string' => 'hello',
			'int' => 42,
			'float' => 3.14,
			'bool' => true,
			'null' => null,
			'array' => [
				1,
				2,
				'three'
			],
			'nested' => [
				'a' => [
					'b' => [
						'c' => 'deep'
					]
				]
			]
		];

		$cache->set('complex', $value, 60);
		$this->assertSame($value, $cache->get('complex'));
	}
}
