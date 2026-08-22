<?php
/**
 * bin/debug-logging.php
 *
 * Step-by-step diagnostic for "logging stops when partial arrays are set".
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Util\ErrorReporter;

ErrorReporter::reset();

// ============================================================
// Step 1: Load the user's config
// ============================================================
$user_config = [
    'preset'     => 'full',
    'strictness' => 'normal',
    'logging'    => true,
    'verbose'    => true,
    'dynamic_ip_ranges' => [
        'enabled' => true,
    ],
    'on_demand_ip_refresh' => [
        'enabled' => true,
    ],
];

echo "=== STEP 1: User config (as if loaded from bb_config.php) ===\n";
echo json_encode($user_config, JSON_PRETTY_PRINT) . "\n\n";

// ============================================================
// Step 2: Build Configuration and inject into adapter
// ============================================================
$adapter = new GenericAdapter();
$config = Configuration::from_array($user_config, $adapter);

// Simulate what BadBehaviour::__construct() does
if (method_exists($adapter, 'set_configuration')) {
    $adapter->set_configuration($config);
}

echo "=== STEP 2: Configuration object after from_array() ===\n";
echo "  logging:                          " . var_export($config->logging, true) . "\n";
echo "  verbose:                          " . var_export($config->verbose, true) . "\n";
echo "  dynamic_ip_ranges_enabled:        " . var_export($config->dynamic_ip_ranges_enabled, true) . "\n";
echo "  dynamic_ip_ranges_ttl:            " . var_export($config->dynamic_ip_ranges_ttl, true) . "\n";
echo "  dynamic_ip_ranges_feeds:          " . json_encode($config->dynamic_ip_ranges_feeds) . "\n";
echo "  on_demand_ip_refresh_enabled:     " . var_export($config->on_demand_ip_refresh_enabled, true) . "\n";
echo "  on_demand_ip_refresh_cache_ttl:   " . var_export($config->on_demand_ip_refresh_cache_ttl, true) . "\n";
echo "\n";

// ============================================================
// Step 3: Check what the adapter sees via get_settings()
// ============================================================
echo "=== STEP 3: Adapter get_settings() returns ===\n";
$adapter_settings = $adapter->get_settings();
echo "  logging:                          " . var_export($adapter_settings['logging'] ?? 'NOT SET', true) . "\n";
echo "  verbose:                          " . var_export($adapter_settings['verbose'] ?? 'NOT SET', true) . "\n";
echo "  dynamic_ip_ranges:                " . json_encode($adapter_settings['dynamic_ip_ranges'] ?? 'NOT SET') . "\n";
echo "  on_demand_ip_refresh:             " . json_encode($adapter_settings['on_demand_ip_refresh'] ?? 'NOT SET') . "\n";
echo "\n";

// ============================================================
// Step 4: Check if set_configuration was called
// ============================================================
echo "=== STEP 4: Did BadBehaviour inject Configuration into adapter? ===\n";
$reflection = new ReflectionClass($adapter);
if ($reflection->hasProperty('configuration')) {
    $prop = $reflection->getProperty('configuration');
    $prop->setAccessible(true);
    $injected_config = $prop->getValue($adapter);
    echo "  Configuration injected: " . ($injected_config !== null ? 'YES' : 'NO') . "\n";
    if ($injected_config !== null) {
        echo "  Injected config logging:  " . var_export($injected_config->logging, true) . "\n";
        echo "  Injected config verbose:  " . var_export($injected_config->verbose, true) . "\n";
    }
} else {
    echo "  Adapter doesn't have 'configuration' property (set_configuration not applied)\n";
}
echo "\n";

// ============================================================
// Step 5: Simulate log_and_return() decision
// ============================================================
echo "=== STEP 5: Simulating log_and_return() decision ===\n";

$package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '203.0.113.1',
);

$result = Result::allow($package);

echo "  Result code:           " . $result->code->value . "\n";
echo "  Result enforcement:    " . $result->enforcement->value . "\n";
echo "  Config logging:        " . var_export($config->logging, true) . "\n";
echo "  Config verbose:        " . var_export($config->verbose, true) . "\n";

$should_log = $result->is_enforced_block()
    || $result->is_monitored()
    || ($result->code === ResultCode::ALLOWED && $config->verbose);

echo "  should_log evaluates to: " . var_export($should_log, true) . "\n";
echo "  (expected: true — verbose=true means ALLOWED requests are logged)\n";
echo "\n";

// ============================================================
// Step 8: Full pipeline test with verbose=true
// ============================================================
echo "=== STEP 8: Full pipeline test with verbose=true ===\n";

class LoggingSpyAdapter extends GenericAdapter
{
    public int $log_request_calls = 0;
    public array $logged_requests = [];

    public function log_request(\BadBehaviour\Util\RequestPackage $package, \BadBehaviour\Core\Result $result): void
    {
        $this->log_request_calls++;
        $this->logged_requests[] = [
            'code'        => $result->code->value,
            'enforcement' => $result->enforcement->value,
            'ip'          => $package->ip,
        ];
        echo "    [SPY] log_request() called: code={$result->code->value}, ip={$package->ip}\n";
    }
}

$spy_adapter = new LoggingSpyAdapter();
$spy_config = Configuration::from_array($user_config, $spy_adapter);
$bb = new BadBehaviour($spy_config);

$test_package = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '203.0.113.100',
    uri: '/test-page',
);

echo "  Calling BadBehaviour::run_test_package()...\n";
$test_result = $bb->run_test_package($test_package);

echo "  Result code: " . $test_result->code->value . "\n";
echo "  Spy log_request() was called " . $spy_adapter->log_request_calls . " times\n";
echo "  (expected: 1 — ALLOWED + verbose=true should trigger logging)\n";

if ($spy_adapter->log_request_calls === 0) {
    echo "\n  ✗ BUG CONFIRMED: log_request() was never called despite verbose=true\n";
} else {
    echo "\n  ✓ log_request() was called correctly\n";
}
echo "\n";
