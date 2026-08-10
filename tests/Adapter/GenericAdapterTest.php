<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Adapter;

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \BadBehaviour\Adapter\GenericAdapter
 */
final class GenericAdapterTest extends TestCase
{
    private string $tmpDir;
    private string $originalCwd;

    protected function setUp(): void
    {
        // The bootstrap may have set CONFIG_DIR (or not). To get reliable
        // isolation we chdir into a tmp dir containing our own config/
        // subdirectory, so production_config_path() falls through the
        // CWD-relative branch and reads OUR file (or fails safe-mode if
        // we don't create one).
        $this->originalCwd = getcwd();
        $this->tmpDir      = sys_get_temp_dir() . '/bb_gadapter_test_' . uniqid('', true);
        mkdir($this->tmpDir . '/config', 0755, true);
        chdir($this->tmpDir);
    }

    protected function tearDown(): void
    {
        chdir($this->originalCwd);

        // Recursive cleanup
        $this->rrmdir($this->tmpDir);
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

    private function makePackage(string $ip = '198.51.100.10', string $ua = 'Mozilla/5.0'): RequestPackage
    {
        return new RequestPackage(
            ip: $ip,
            headers: [],
            headers_mixed: ['User-Agent' => $ua, 'Accept' => 'text/html'],
            request_method: 'GET',
            request_uri: '/',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: $ua,
        );
    }

    public function testGetSettingsReportsStateMachineTransitions(): void
    {
    	// Start: no config present → safe_mode ON, config_loaded FALSE
    	$adapter = new GenericAdapter();

    	// First call to get_settings() runs config resolution. Whether
    	// it succeeds depends on CWD (where the test runner chdir'd),
    	// so we test the TRANSITIONS rather than initial state.
    	$adapter->get_settings();

    	// State after first resolution call must be internally consistent:
    	// either (safe_mode=true, config_loaded=false) OR (safe_mode=false, config_loaded=true).
    	$this->assertSame(
    		$adapter->is_safe_mode(),
    		!$adapter->is_config_loaded(),
    		'safe_mode and config_loaded must always be opposite booleans'
    		);
    }

    public function testGetSettingsEntersSafeModeWhenConfigMissing(): void
    {
        $adapter = new GenericAdapter();
        $settings = $adapter->get_settings();

        $this->assertTrue($adapter->is_safe_mode());
        $this->assertFalse($adapter->is_config_loaded());
        $this->assertArrayHasKey('log_table', $settings);
        $this->assertSame('bad_behaviour', $settings['log_table']);
    }

    public function testGetSettingsLoadsConfigFromCwdRelativePath(): void
    {
        $this->writeConfig("<?php\nreturn ['logging' => true, 'strictness' => 'strict', 'log_table' => 'my_logs'];\n");

        $adapter = new GenericAdapter();
        $settings = $adapter->get_settings();

        $this->assertFalse($adapter->is_safe_mode());
        $this->assertTrue($adapter->is_config_loaded());
        $this->assertSame('strict', $settings['strictness']);
        $this->assertSame('my_logs', $settings['log_table']);
    }

    public function testGetSettingsFallsBackToSafeModeOnParseError(): void
    {
        $this->writeConfig("<?php\nreturn [ 'missing' => , ];\n");

        $adapter = new GenericAdapter();
        $settings = $adapter->get_settings();

        $this->assertTrue($adapter->is_safe_mode());
        $this->assertFalse($adapter->is_config_loaded());
        $this->assertSame('bad_behaviour', $settings['log_table']);
    }

    public function testGetSettingsFallsBackToSafeModeWhenConfigReturnsNonArray(): void
    {
        $this->writeConfig("<?php\nreturn 'not an array';\n");

        $adapter = new GenericAdapter();
        $settings = $adapter->get_settings();

        $this->assertTrue($adapter->is_safe_mode());
        $this->assertFalse($adapter->is_config_loaded());
    }

    public function testGetSettingsInjectsLogTableDefaultWhenMissing(): void
    {
        $this->writeConfig("<?php\nreturn ['logging' => true];\n");

        $adapter = new GenericAdapter();
        $settings = $adapter->get_settings();

        $this->assertSame('bad_behaviour', $settings['log_table']);
    }

    public function testGetSettingsPreservesExplicitLogTable(): void
    {
        $this->writeConfig("<?php\nreturn ['logging' => true, 'log_table' => 'custom_logs'];\n");

        $adapter = new GenericAdapter();
        $settings = $adapter->get_settings();

        $this->assertSame('custom_logs', $settings['log_table']);
    }

    public function testGetWhitelistReturnsEmptyArrayWhenFileMissing(): void
    {
        $adapter = new GenericAdapter();
        $whitelist = $adapter->get_whitelist();

        $this->assertSame(
            ['ip' => [], 'useragent' => [], 'url' => [], 'asn' => [], 'country' => []],
            $whitelist
        );
    }

    public function testGetEmailReturnsDefault(): void
    {
        $adapter = new GenericAdapter();
        $this->assertSame('admin@example.com', $adapter->get_email());
    }

    public function testGetRelativePathReturnsRoot(): void
    {
        $adapter = new GenericAdapter();
        $this->assertSame('/', $adapter->get_relative_path());
    }

    public function testGetTableSchemaReturnsValidSqlWithExpectedColumns(): void
    {
        $adapter = new GenericAdapter();
        $schema = $adapter->get_table_schema('bad_behaviour');

        $this->assertIsString($schema);
        $this->assertStringContainsString('CREATE TABLE IF NOT EXISTS', $schema);
        $this->assertStringContainsString('`ip`', $schema);
        $this->assertStringContainsString('`ua`', $schema);
        $this->assertStringContainsString('`status_code`', $schema);
        $this->assertStringContainsString('`enforcement_action`', $schema);
        $this->assertStringContainsString('PRIMARY KEY', $schema);
    }

    public function testGetTableSchemaSanitizesTableName(): void
    {
        $adapter = new GenericAdapter();
        $schema = $adapter->get_table_schema('evil;DROP TABLE users;--');

        // The dangerous table name is sanitized before interpolation.
        $this->assertStringNotContainsString('DROP TABLE', $schema);
        // Backtick-wrapped name contains only alphanumeric/underscore chars.
        if (preg_match('/`([^`]+)`/', $schema, $m)) {
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9_]+$/', $m[1]);
        } else {
            $this->fail('Schema did not contain a backtick-quoted table name');
        }
    }

    public function testLogRequestIsNoOp(): void
    {
        $adapter = new GenericAdapter();
        $package = $this->makePackage();
        $result  = new Result(ResultCode::ALLOWED, 'ok', $package);

        $adapter->log_request($package, $result);

        $this->expectNotToPerformAssertions();
    }

    public function testQueryReturnsFalseByDefault(): void
    {
        $adapter = new GenericAdapter();
        $this->assertFalse($adapter->query('SELECT 1'));
    }

    public function testGetReturnsNull(): void
    {
        $adapter = new GenericAdapter();
        $this->assertNull($adapter->get('any_key'));
    }

    public function testSetReturnsTrue(): void
    {
        $adapter = new GenericAdapter();
        $this->assertTrue($adapter->set('any_key', 'any_value', 60));
    }

    public function testDeleteReturnsTrue(): void
    {
        $adapter = new GenericAdapter();
        $this->assertTrue($adapter->delete('any_key'));
    }

    public function testIncrementCounterIncrements(): void
    {
        $adapter = new GenericAdapter();
        $this->assertSame(1, $adapter->increment_counter('test', 60));
        $this->assertSame(2, $adapter->increment_counter('test', 60));
        $this->assertSame(3, $adapter->increment_counter('test', 60));
    }

    public function testIncrementCounterContinuesWithinWindow(): void
    {
        $adapter = new GenericAdapter();

        $this->assertSame(1, $adapter->increment_counter('w', 3600));
        $this->assertSame(2, $adapter->increment_counter('w', 3600));
    }

    public function testGetCounterReturnsCurrentValue(): void
    {
        $adapter = new GenericAdapter();
        $adapter->increment_counter('c', 60);
        $adapter->increment_counter('c', 60);

        $this->assertSame(2, $adapter->get_counter('c'));
    }

    public function testGetCounterReturnsZeroForMissingKey(): void
    {
        $adapter = new GenericAdapter();
        $this->assertSame(0, $adapter->get_counter('never'));
    }

    public function testSaveAndGetBehaviorProfile(): void
    {
        $adapter = new GenericAdapter();
        $profile = ['count' => 5, 'ua_hash' => 'xyz'];

        $this->assertTrue($adapter->save_behavior_profile('session-1', $profile, 60));
        $this->assertSame($profile, $adapter->get_behavior_profile('session-1'));
    }

    public function testGetBehaviorProfileReturnsNullForMissingSession(): void
    {
        $adapter = new GenericAdapter();
        $this->assertNull($adapter->get_behavior_profile('never'));
    }

    public function testAddToSetAndGetSet(): void
    {
        $adapter = new GenericAdapter();
        $adapter->add_to_set('ja3_set', 'hash-a', 60);
        $adapter->add_to_set('ja3_set', 'hash-b', 60);
        $adapter->add_to_set('ja3_set', 'hash-a', 60); // duplicate; expires updates

        $values = $adapter->get_set('ja3_set');
        sort($values);
        $this->assertSame(['hash-a', 'hash-b'], $values);
    }

    public function testGetSetReturnsEmptyArrayForMissingKey(): void
    {
        $adapter = new GenericAdapter();
        $this->assertSame([], $adapter->get_set('never_added'));
    }

    public function testGetSetPrunesExpired(): void
    {
        $adapter = new GenericAdapter();
        $adapter->add_to_set('prunable', 'live', 60);

        // Inject an expired entry via reflection.
        $reflection = new \ReflectionClass($adapter);
        $prop = $reflection->getProperty('sets');
        $prop->setAccessible(true);
        $sets = $prop->getValue($adapter);
        $sets['prunable']['dead'] = time() - 100;
        $prop->setValue($adapter, $sets);

        $values = $adapter->get_set('prunable');
        $this->assertSame(['live'], $values);
    }

    public function testGetGeoipReturnsNull(): void
    {
        $adapter = new GenericAdapter();
        $this->assertNull($adapter->get_geoip('1.2.3.4'));
    }

    public function testVerifyChallengeReturnsFalse(): void
    {
        $adapter = new GenericAdapter();
        $this->assertFalse($adapter->verify_challenge('any-response', '1.2.3.4'));
    }

    public function testLogDoesNotThrowEvenWithCircularContext(): void
    {
        $adapter = new GenericAdapter();
        $context = [];
        $context['self'] = &$context;

        $adapter->log('error', 'circular test', $context);
        $this->expectNotToPerformAssertions();
    }

    public function testLogSurvivesEmptyMessage(): void
    {
        $adapter = new GenericAdapter();
        $adapter->log('info', '', []);
        $this->expectNotToPerformAssertions();
    }

    public function testDeleteRemovesCounterAndBehaviorAndSet(): void
    {
        $adapter = new GenericAdapter();
        $adapter->increment_counter('c', 60);
        $adapter->save_behavior_profile('s', ['count' => 1], 60);
        $adapter->add_to_set('k', 'v', 60);

        $this->assertTrue($adapter->delete('c'));
        $this->assertTrue($adapter->delete('s'));
        $this->assertTrue($adapter->delete('k'));

        $this->assertSame(0, $adapter->get_counter('c'));
        $this->assertNull($adapter->get_behavior_profile('s'));
        $this->assertSame([], $adapter->get_set('k'));
    }
}
