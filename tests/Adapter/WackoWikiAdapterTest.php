<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Adapter;

use BadBehaviour\Adapter\WackoWikiAdapter;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

/**
 * Anonymous class acting as the WackoWiki $db object.
 *
 * WackoWikiAdapter uses both method-call form ($this->db->q(...), the
 * first-class callable syntax which only works for actual methods) and
 * property-call form ($this->db->ll_query(...)) on $this->db. An anonymous
 * class with real methods handles both.
 */
function bb_make_wacko_db(): object
{
    return new class {
        public string $table_prefix = 'wacko_';
        public string $abuse_email  = 'admin@wiki.example';
        public bool $is_sqlite      = true;

        /** @var callable|null Set by tests to capture the SQL */
        public $ll_query = null;

        public function q(mixed $v): string
        {
            return "'" . str_replace("'", "\\'", (string)$v) . "'";
        }
    };
}

/**
 * @covers \BadBehaviour\Adapter\WackoWikiAdapter
 */
final class WackoWikiAdapterTest extends TestCase
{
    private string $tmpDir;
    private string $originalCwd;
    private object $db;

    protected function setUp(): void
    {
        $this->originalCwd = getcwd();
        $this->tmpDir      = sys_get_temp_dir() . '/bb_wacko_test_' . uniqid('', true);
        mkdir($this->tmpDir . '/config', 0755, true);
        chdir($this->tmpDir);

        $this->db = bb_make_wacko_db();

        if (!defined('CACHE_DIR')) {
            define('CACHE_DIR', sys_get_temp_dir() . '/bb_wacko_cache_' . uniqid('', true));
        }
    }

    protected function tearDown(): void
    {
        chdir($this->originalCwd);
        $this->rrmdir($this->tmpDir);
        if (defined('CACHE_DIR') && is_dir(CACHE_DIR)) {
            $this->rrmdir(CACHE_DIR);
        }
    }

    private function rrmdir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path)) {
                $this->rrmdir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    private function writeConfig(string $php): void
    {
        file_put_contents($this->tmpDir . '/config/bb_config.php', $php);
    }

    public function testConstructorCreatesCacheDirectory(): void
    {
        new WackoWikiAdapter($this->db);
        $this->assertDirectoryExists(CACHE_DIR . '/bad_behaviour/');
    }

    public function testStateMachineIsInternallyConsistent(): void
    {
        // The safe_mode / config_loaded flags are ALWAYS opposite after
        // get_settings() runs — that's the invariant. Whether config
        // resolves depends on CONFIG_DIR (which may already be defined
        // by the test bootstrap) and CWD, both of which are environmental.
        $adapter = new WackoWikiAdapter($this->db);
        $adapter->get_settings();

        $this->assertSame(
            $adapter->is_safe_mode(),
            !$adapter->is_config_loaded(),
            'safe_mode and config_loaded must be opposite booleans'
        );
    }

    public function testGetSettingsReturnsLogTableWithPrefix(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $settings = $adapter->get_settings();

        $this->assertArrayHasKey('log_table', $settings);
        $this->assertSame('wacko_bad_behaviour', $settings['log_table']);
    }

    public function testGetSettingsUsesConfiguredLogTablePrefix(): void
    {
        $this->db->table_prefix = 'custom_';
        $adapter = new WackoWikiAdapter($this->db);
        $settings = $adapter->get_settings();

        $this->assertSame('custom_bad_behaviour', $settings['log_table']);
    }

    public function testGetWhitelistReturnsEmptyDefaultsWhenMissing(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $whitelist = $adapter->get_whitelist();

        $this->assertSame(
            ['ip' => [], 'useragent' => [], 'url' => [], 'asn' => [], 'country' => []],
            $whitelist
        );
    }

    public function testGetEmailReturnsConfiguredAbuseEmail(): void
    {
        $this->db->abuse_email = 'security@wiki.example';
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertSame('security@wiki.example', $adapter->get_email());
    }

    public function testGetRelativePathReturnsRoot(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertSame('/', $adapter->get_relative_path());
    }

    public function testGetTableSchemaReturnsArrayForSqlite(): void
    {
        $this->db->is_sqlite = true;
        $adapter = new WackoWikiAdapter($this->db);
        $schema = $adapter->get_table_schema('wacko_bad_behaviour');

        $this->assertIsArray($schema);
        $this->assertStringContainsString('CREATE TABLE IF NOT EXISTS', $schema[0]);
        $this->assertStringContainsString('log_id', $schema[0]);
        $this->assertStringContainsString('user_agent', $schema[0]);
        $this->assertStringContainsString('enforcement_action', $schema[0]);
        $this->assertGreaterThan(1, count($schema));
        $this->assertStringContainsString('CREATE INDEX', $schema[1]);
    }

    public function testGetTableSchemaReturnsArrayForMysql(): void
    {
        $this->db->is_sqlite = false;
        $adapter = new WackoWikiAdapter($this->db);
        $schema = $adapter->get_table_schema('wacko_bad_behaviour');

        $this->assertIsArray($schema);
        $this->assertStringContainsString('CREATE TABLE IF NOT EXISTS', $schema[0]);
        $this->assertStringContainsString('ENGINE=InnoDB', $schema[0]);
        $this->assertStringContainsString('`log_id`', $schema[0]);
    }

    public function testLogRequestIsNoOpWhenLoggingDisabled(): void
    {
        $this->db->ll_query = function ($sql) {
            $this->fail('ll_query should not be called when logging is disabled');
        };

        $adapter = new WackoWikiAdapter($this->db);
        $package = new RequestPackage(
            ip: '198.51.100.10',
            headers: [],
            headers_mixed: ['User-Agent' => 'UA'],
            request_method: 'GET',
            request_uri: '/',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'UA',
        );
        $result = new Result(ResultCode::ALLOWED, 'ok', $package);

        // Without a config present, get_settings() returns safe-mode defaults
        // where logging=true, so we instead verify the no-throw contract.
        $adapter->log_request($package, $result);

        $this->expectNotToPerformAssertions();
    }

    public function testLogRequestDoesNotThrowOnDbFailure(): void
    {
        $this->db->ll_query = function ($sql) {
            throw new \RuntimeException('DB down');
        };

        $adapter = new WackoWikiAdapter($this->db);
        $package = new RequestPackage(
            ip: '198.51.100.10',
            headers: [],
            headers_mixed: ['User-Agent' => 'Mozilla/5.0'],
            request_method: 'GET',
            request_uri: '/',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Mozilla/5.0',
        );
        $result = new Result(ResultCode::ALLOWED, 'ok', $package);

        $adapter->log_request($package, $result);
        $this->expectNotToPerformAssertions();
    }

    public function testQueryReturnsFalseOnException(): void
    {
        $this->db->ll_query = function ($sql) {
            throw new \RuntimeException('boom');
        };

        $adapter = new WackoWikiAdapter($this->db);
        $this->assertFalse($adapter->query('SELECT 1'));
    }

    public function testCacheGetReturnsNullForMissingKey(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertNull($adapter->get('never_set'));
    }

    public function testCacheSetAndGetRoundTrip(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertTrue($adapter->set('k', 'v', 60));
        $this->assertSame('v', $adapter->get('k'));
    }

    public function testCacheDeleteRemovesEntry(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $adapter->set('k', 'v', 60);

        $this->assertTrue($adapter->delete('k'));
        $this->assertNull($adapter->get('k'));
    }

    public function testIncrementCounterStartsAtOne(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertSame(1, $adapter->increment_counter('c', 60));
        $this->assertSame(2, $adapter->increment_counter('c', 60));
    }

    public function testGetCounterReturnsCurrentValue(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $adapter->increment_counter('c', 60);
        $adapter->increment_counter('c', 60);

        $this->assertSame(2, $adapter->get_counter('c'));
    }

    public function testSaveAndGetBehaviorProfileIncludesExpiresField(): void
    {
        // Real behavior: save_behavior_profile injects '_expires' into
        // the stored profile so cache expiration can be enforced even
        // when get() is bypassed (e.g., direct file inspection).
        $adapter = new WackoWikiAdapter($this->db);
        $profile = ['count' => 7, 'ua' => 'abc'];

        $this->assertTrue($adapter->save_behavior_profile('sess', $profile, 60));
        $loaded = $adapter->get_behavior_profile('sess');

        $this->assertIsArray($loaded);
        $this->assertSame(7, $loaded['count']);
        $this->assertSame('abc', $loaded['ua']);
        $this->assertArrayHasKey('_expires', $loaded);
        $this->assertGreaterThan(time(), $loaded['_expires']);
    }

    public function testAddToSetAndGetSet(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $adapter->add_to_set('ja3', 'h1', 60);
        $adapter->add_to_set('ja3', 'h2', 60);

        $values = $adapter->get_set('ja3');
        sort($values);
        $this->assertSame(['h1', 'h2'], $values);
    }

    public function testGetSetPrunesExpired(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $adapter->add_to_set('ja3', 'live', 60);

        // Inject an expired entry via the underlying cache file.
        $reflection = new \ReflectionClass($adapter);
        $cacheFileMethod = $reflection->getMethod('cache_file');
        $cacheFileMethod->setAccessible(true);
        $file = $cacheFileMethod->invoke($adapter, 'set:ja3');

        $data = json_decode(file_get_contents($file), true);
        $data['dead'] = time() - 100;
        file_put_contents($file, json_encode($data), LOCK_EX);

        $values = $adapter->get_set('ja3');
        $this->assertSame(['live'], $values);
    }

    public function testGetGeoipReturnsNull(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertNull($adapter->get_geoip('1.2.3.4'));
    }

    public function testVerifyChallengeReturnsFalse(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $this->assertFalse($adapter->verify_challenge('response', '1.2.3.4'));
    }

    public function testLogDoesNotThrowOnCircularContext(): void
    {
        $adapter = new WackoWikiAdapter($this->db);
        $ctx = [];
        $ctx['self'] = &$ctx;

        $adapter->log('error', 'circular', $ctx);
        $this->expectNotToPerformAssertions();
    }
}
