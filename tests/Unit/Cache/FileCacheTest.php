<?php
// tests/Unit/Cache/FileCacheTest.php

namespace BadBehaviour\Tests\Unit\Cache;

use BadBehaviour\Cache\FileCache;
use PHPUnit\Framework\TestCase;

class FileCacheTest extends TestCase
{
    private FileCache $cache;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/badbehaviour_test_' . uniqid();
        @mkdir($this->testDir, 0755, true);
        $this->cache = new FileCache($this->testDir);
    }

    protected function tearDown(): void
    {
        // Clean up test files
        $files = glob($this->testDir . '/*.cache');
        foreach ($files as $file) @unlink($file);
        @rmdir($this->testDir);
    }

    public function test_set_and_get(): void
    {
        $this->cache->set('test_key', 'test_value', 3600);
        $this->assertEquals('test_value', $this->cache->get('test_key'));
    }

    public function test_get_missing_returns_null(): void
    {
        $this->assertNull($this->cache->get('nonexistent'));
    }

    public function test_expiration(): void
    {
        $this->cache->set('expire_key', 'value', 1); // 1 second TTL
        $this->assertEquals('value', $this->cache->get('expire_key'));

        sleep(2);
        $this->assertNull($this->cache->get('expire_key'));
    }

    public function test_delete(): void
    {
        $this->cache->set('del_key', 'value', 3600);
        $this->assertTrue($this->cache->delete('del_key'));
        $this->assertNull($this->cache->get('del_key'));
    }

    public function test_increment_counter(): void
    {
        $count1 = $this->cache->increment_counter('counter_key', 60);
        $count2 = $this->cache->increment_counter('counter_key', 60);
        $count3 = $this->cache->increment_counter('counter_key', 60);

        $this->assertEquals(1, $count1);
        $this->assertEquals(2, $count2);
        $this->assertEquals(3, $count3);
    }

    public function test_counter_window_reset(): void
    {
        $this->cache->increment_counter('window_key', 1); // 1 second window
        sleep(2);
        $count = $this->cache->increment_counter('window_key', 1);

        // Should reset after window expires
        $this->assertEquals(1, $count);
    }

    public function test_get_counter(): void
    {
        $this->cache->increment_counter('get_counter', 60);
        $this->cache->increment_counter('get_counter', 60);

        $this->assertEquals(2, $this->cache->get_counter('get_counter'));
    }

    public function test_set_operations(): void
    {
        $this->cache->add_to_set('myset', 'value1', 60);
        $this->cache->add_to_set('myset', 'value2', 60);

        $set = $this->cache->get_set('myset');
        $this->assertContains('value1', $set);
        $this->assertContains('value2', $set);
        $this->assertCount(2, $set);
    }

    public function test_behavior_profile(): void
    {
        $profile = ['count' => 5, 'urls' => ['/a', '/b']];
        $this->cache->save_behavior_profile('session1', $profile, 60);

        $retrieved = $this->cache->get_behavior_profile('session1');
        $this->assertEquals($profile['count'], $retrieved['count']);
        $this->assertEquals($profile['urls'], $retrieved['urls']);
    }
}
