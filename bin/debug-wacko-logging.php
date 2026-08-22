<?php
/**
 * bin/debug-wacko-logging.php
 *
 * Tests WackoWikiAdapter's actual log_request() implementation
 * to find why logging doesn't work in production.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\WackoWikiAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Result;
use BadBehaviour\Util\RequestPackage;

echo "=== Test 1: Create WackoWikiAdapter with mock DB ===\n";

// Mock the minimal $db object that WackoWikiAdapter needs
class MockDb
{
    public string $table_prefix = 'wacko_';
    public string $abuse_email = 'admin@example.com';
    public array $queries_executed = [];

    public function q(string $value): string
    {
        // Return a closure-like object that produces quoted SQL
        // In real WackoWiki, $this->db->q($value) returns a quoted string
        return "'" . addslashes($value) . "'";
    }

    public function ll_query(string $sql)
    {
        $this->queries_executed[] = $sql;
        echo "  [MOCK DB] Executed query: " . substr($sql, 0, 150) . "...\n";
        return true;
    }

    public function is_sqlite(): bool
    {
        return false;
    }
}

$mock_db = new MockDb();
$adapter = new WackoWikiAdapter($mock_db);

echo "  Adapter created: YES\n";
echo "  Table prefix: " . $mock_db->table_prefix . "\n\n";

// ============================================================
// Test 2: Check if WackoWikiAdapter has log_table configured
// ============================================================
echo "=== Test 2: What log_table does the adapter expect? ===\n";

$reflection = new ReflectionClass($adapter);
$method = $reflection->getMethod('log_request');
echo "  Method: " . $method->getDeclaringClass()->getName() . "::log_request()\n";
echo "  Lines: " . $method->getStartLine() . "-" . $method->getEndLine() . "\n\n";

// Read the source code of log_request
$filename = $method->getFileName();
$source = file($filename);
$method_source = '';
for ($i = $method->getStartLine() - 1; $i < $method->getEndLine(); $i++) {
    $method_source .= ($i + 1) . ": " . $source[$i];
}
echo "  Source:\n" . $method_source . "\n\n";

// ============================================================
// Test 3: Build config and inject it
// ============================================================
echo "=== Test 3: Build config and inject ===\n";

$user_config = [
    'preset'     => 'full',
    'strictness' => 'normal',
    'logging'    => true,
    'verbose'    => true,
    'dynamic_ip_ranges' => ['enabled' => true],
    'on_demand_ip_refresh' => ['enabled' => true],
];

$config = Configuration::from_array($user_config, $adapter);

echo "  Config logging: " . var_export($config->logging, true) . "\n";
echo "  Config verbose: " . var_export($config->verbose, true) . "\n";

// Check what get_settings() returns
$settings = $adapter->get_settings();
echo "  Adapter get_settings() logging: " . var_export($settings['logging'] ?? 'NOT SET', true) . "\n";
echo "  Adapter get_settings() verbose: " . var_export($settings['verbose'] ?? 'NOT SET', true) . "\n";
echo "  Adapter get_settings() log_table: " . var_export($settings['log_table'] ?? 'NOT SET', true) . "\n";
echo "\n";

// ============================================================
// Test 4: Try to actually log a request
// ============================================================
echo "=== Test 4: Call log_request() with an ALLOWED result ===\n";

$package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '203.0.113.1',
    uri: '/test-page',
);

$result = Result::allow($package);

echo "  Result code: " . $result->code->value . "\n";
echo "  Calling adapter->log_request()...\n";

try {
    $adapter->log_request($package, $result);
    echo "  log_request() returned without throwing\n";
} catch (\Throwable $e) {
    echo "  ✗ log_request() THREW: " . get_class($e) . "\n";
    echo "  Message: " . $e->getMessage() . "\n";
    echo "  File: " . $e->getFile() . ":" . $e->getLine() . "\n";
    echo "  Trace:\n" . $e->getTraceAsString() . "\n";
}

echo "\n  Queries executed by mock DB: " . count($mock_db->queries_executed) . "\n";
if (count($mock_db->queries_executed) > 0) {
    echo "  First query preview:\n";
    echo "    " . substr($mock_db->queries_executed[0], 0, 200) . "\n";
}
echo "\n";

// ============================================================
// Test 5: Check what happens BEFORE log_request() in the real flow
// ============================================================
echo "=== STEP 5: Check log_and_return() flow ===\n";

echo "  This is what BadBehaviour::log_and_return() checks:\n";
echo "  - \$this->config->logging = " . var_export($config->logging, true) . "\n";
echo "  - \$this->config->verbose = " . var_export($config->verbose, true) . "\n";

$should_log = $result->is_enforced_block()
    || $result->is_monitored()
    || ($result->code === \BadBehaviour\Core\ResultCode::ALLOWED && $config->verbose);

echo "  - should_log = " . var_export($should_log, true) . "\n";
echo "  (if false, log_request() is NEVER called)\n";
echo "\n";

// ============================================================
// Test 6: Simulate the FULL BadBehaviour pipeline
// ============================================================
echo "=== Test 6: Full BadBehaviour pipeline with spy ===\n";

class WackoSpyAdapter extends WackoWikiAdapter
{
    public int $log_request_calls = 0;
    public array $log_calls_details = [];

    public function log_request(\BadBehaviour\Util\RequestPackage $package, \BadBehaviour\Core\Result $result): void
    {
        $this->log_request_calls++;
        $this->log_calls_details[] = [
            'code'        => $result->code->value,
            'enforcement' => $result->enforcement->value,
            'ip'          => $package->ip,
        ];
        echo "    [SPY] log_request() called: code={$result->code->value}, ip={$package->ip}\n";

        // Call parent to actually test the logging
        parent::log_request($package, $result);
    }
}

$spy_db = new MockDb();
$spy_adapter = new WackoSpyAdapter($spy_db);
$spy_config = Configuration::from_array($user_config, $spy_adapter);
$bb = new \BadBehaviour\Core\BadBehaviour($spy_config);

echo "  Configuration injected into spy: ";
$spy_reflection = new ReflectionClass($spy_adapter);
$spy_prop = $spy_reflection->getProperty('configuration');
$spy_prop->setAccessible(true);
echo ($spy_prop->getValue($spy_adapter) !== null ? 'YES' : 'NO') . "\n";

$test_package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '203.0.113.100',
    uri: '/test-page',
);

echo "  Calling BadBehaviour::run_test_package()...\n";
$test_result = $bb->run_test_package($test_package);

echo "  Result code: " . $test_result->code->value . "\n";
echo "  Spy log_request() was called " . $spy_adapter->log_request_calls . " times\n";
echo "  Mock DB queries executed: " . count($spy_db->queries_executed) . "\n";

if ($spy_adapter->log_request_calls === 0) {
    echo "\n  ✗ BUG: log_request() never called\n";
    echo "  Check: \$config->verbose = " . var_export($spy_config->verbose, true) . "\n";
} elseif (count($spy_db->queries_executed) === 0) {
    echo "\n  ✗ BUG: log_request() called but no DB query executed\n";
    echo "  Check WackoWikiAdapter::log_request() implementation\n";
    echo "  Possible causes:\n";
    echo "    - settings['logging'] is empty/false\n";
    echo "    - INSERT query construction failed silently\n";
    echo "    - Exception caught and swallowed\n";
} else {
    echo "\n  ✓ log_request() called and DB query executed\n";
    echo "  Query: " . substr($spy_db->queries_executed[0], 0, 200) . "...\n";
}
