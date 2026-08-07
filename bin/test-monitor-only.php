// bin/test-monitor-only.php
require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Util\RequestPackage;

$adapter = new GenericAdapter();
$config = Configuration::from_array([
    'preset'     => 'minimal',
    'strictness' => 'monitor-only',
    'logging'    => true,
], $adapter);

$bb = new BadBehaviour($config);

// === Test 1: A known bot UA — should be MONITORED, not ENFORCED ===
$pkg = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    ip: '116.179.32.0',  // in Baidu's IP range
);
$result = $bb->run_test_package($pkg);

echo "Test 1 (Baiduspider):\n";
echo "  code:        {$result->code->value}\n";
echo "  enforcement: {$result->enforcement->value}\n";
echo "  is_enforced_block: " . ($result->is_enforced_block() ? 'YES (BUG!)' : 'NO (correct)') . "\n";
echo "  is_monitored:      " . ($result->is_monitored() ? 'YES (correct)' : 'NO (BUG!)') . "\n";

// === Test 2: Empty UA — SHOULD still be ENFORCED ===
$pkg2 = RequestPackage::create_for_test(
    user_agent: '',
    ip: '203.0.113.1',
);
$result2 = $bb->run_test_package($pkg2);

echo "\nTest 2 (empty UA):\n";
echo "  code:        {$result2->code->value}\n";
echo "  enforcement: {$result2->enforcement->value}\n";
echo "  is_enforced_block: " . ($result2->is_enforced_block() ? 'YES (correct — obvious attack)' : 'NO (BUG — should enforce)') . "\n";

// === Test 3: Raw XSS in URI — SHOULD still be ENFORCED ===
$pkg3 = RequestPackage::create_for_test(
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
    ip: '203.0.113.2',
    uri: '/search?q=<script>alert(1</script>',
);
$result3 = $bb->run_test_package($pkg3);

echo "\nTest 3 (raw XSS):\n";
echo "  code:        {$result3->code->value}\n";
echo "  enforcement: {$result3->enforcement->value}\n";
echo "  is_enforced_block: " . ($result3->is_enforced_block() ? 'YES (correct — obvious attack)' : 'NO (BUG — should enforce)') . "\n";