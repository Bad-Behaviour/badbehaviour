<?php
/**
 * Bad Behaviour Performance Benchmark
 * Run from CLI: php tests/benchmark.php
 *
 * Measures execution time across request types to validate optimizations.
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/bootstrap.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;

if (php_sapi_name() !== 'cli') {
    die("Run from CLI only.\n");
}

echo "Bad Behaviour 3.0 Performance Benchmark\n";
echo str_repeat('=', 60) . "\n\n";

// Setup
$adapter = new GenericAdapter();
$config = Configuration::from_array([
    'logging' => false,                    // No DB writes during benchmark
    'enable_fingerprinting' => false,
    'enable_client_hints_validation' => false,
    'enable_agentic_detection' => false,
    'enable_dynamic_ip_ranges' => false,
    'enable_behavioral_analysis' => true,
    'enable_ai_crawler_control' => true,
    'rate_limit_enabled' => false,        // Don't pollute counters
    'dnsbl_enabled' => false,
    'httpbl_key' => '',
    'reverse_proxy' => false,
], $adapter);

$bb = new BadBehaviour($config);

// Warmup (load classes, initialize caches)
$bb->run_test_package(RequestPackage::create_for_test('Warmup/1.0', '203.0.113.99', 'GET', '/warmup'));

// Benchmark helper
function bench(string $label, callable $fn, int $iterations = 1000): array
{
    $start = microtime(true);
    for ($i = 0; $i < $iterations; $i++) {
        $fn();
    }
    $elapsed = microtime(true) - $start;
    $per_iter = ($elapsed * 1000) / $iterations;  // ms per request

    printf("%-40s %8.4f ms/req  (%6.2f ms total, %d iters)\n",
        $label,
        $per_iter,
        $elapsed * 1000,
        $iterations
    );
    return ['per_iter_ms' => $per_iter, 'total_ms' => $elapsed * 1000];
}

$results = [];

// ========================================================================
// Test 1: Static resource (CSS/JS/image) — should hit fast path #1
// ========================================================================
$results['static_css'] = bench('Static CSS (fast path)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'Mozilla/5.0 (Windows NT 10.0) Chrome/120',
        '203.0.113.1',
        'GET',
        '/wp-content/themes/style.css'
    ));
}, 5000);

// ========================================================================
// Test 2: Legitimate browser (HTML page) — full pipeline
// ========================================================================
$results['browser_html'] = bench('Browser HTML page', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        '203.0.113.1',
        'GET',
        '/about'
    ));
}, 1000);

// ========================================================================
// Test 3: AJAX POST (JSON body) — common for SPAs
// ========================================================================
$results['ajax_post'] = bench('AJAX POST (JSON)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'Mozilla/5.0 Chrome/120',
        '203.0.113.1',
        'POST',
        '/api/save',
        [
            'Host' => 'example.com',
            'X-Requested-With' => 'XMLHttpRequest',
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ],
        ['title' => 'Test post', 'body' => 'Content here']
    ));
}, 1000);

// ========================================================================
// Test 4: Known search engine (Googlebot with IP match)
// ========================================================================
$results['googlebot_valid'] = bench('Googlebot (valid IP)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        '66.249.66.1',  // In Google's range
        'GET',
        '/sitemap.xml'
    ));
}, 1000);

// ========================================================================
// Test 5: Unverified bot (UA matches but IP doesn't)
// ========================================================================
$results['fake_googlebot'] = bench('Fake Googlebot (UA only)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'Mozilla/5.0 (compatible; Googlebot/2.1)',
        '198.51.100.42',  // NOT in Google's range
        'GET',
        '/admin'
    ));
}, 500);

// ========================================================================
// Test 6: Empty UA (should hit fast path #2)
// ========================================================================
$results['empty_ua'] = bench('Empty UA (fast path)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        '',
        '198.51.100.43',
        'GET',
        '/'
    ));
}, 1000);

// ========================================================================
// Test 7: Malicious UA (sqlmap)
// ========================================================================
$results['sqlmap'] = bench('SQLMap UA (blocked)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'sqlmap/1.5.2',
        '198.51.100.44',
        'GET',
        '/'
    ));
}, 500);

// ========================================================================
// Test 8: cURL (HTTP tool)
// ========================================================================
$results['curl'] = bench('cURL (http_tool)', function() use ($bb) {
    $bb->run_test_package(RequestPackage::create_for_test(
        'curl/8.4.0',
        '198.51.100.45',
        'GET',
        '/health'
    ));
}, 1000);

// ========================================================================
// Summary
// ========================================================================
echo "\n" . str_repeat('=', 60) . "\n";
echo "SUMMARY (per-request latency)\n";
echo str_repeat('=', 60) . "\n";
foreach ($results as $name => $data) {
    printf("%-30s %8.4f ms\n", $name . ':', $data['per_iter_ms']);
}

echo "\nExpected after Phase 1 optimizations:\n";
echo "  static_css:  < 0.1 ms   (was ~5-10 ms — 50-100x faster)\n";
echo "  empty_ua:    < 0.1 ms   (was ~5-10 ms — immediate block)\n";
echo "  browser_html: ~3 ms     (was ~8 ms — minor improvement)\n";
echo "  googlebot_valid: ~2 ms  (was ~12 ms — DNS cache hit)\n";
echo "  fake_googlebot: ~5 ms   (was ~450 ms — async DNS helps next time)\n";
echo "\n";