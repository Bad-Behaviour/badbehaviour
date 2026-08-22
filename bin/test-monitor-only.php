<?php
/**
 * bin/test-monitor-only.php
 *
 * Tests the monitor-only mode demotion logic.
 *
 * SCENARIOS:
 *   Test 1: Malicious UA (sqlmap)  → MONITORED   (block demoted, request reaches app)
 *   Test 2: Empty UA			   → ENFORCED	(always enforced, even in monitor-only)
 *   Test 3: Raw XSS in URI		 → ENFORCED	(always enforced, even in monitor-only)
 *   Test 4: handle_result() on MONITORED  → returns normally (defensive guard)
 *   Test 5: API contract matrix across result types
 *   Test 6: Regression — old !is_allowed() bug demonstration
 *
 * The previous version of this script tested Baiduspider from a verified
 * Baidu IP and labeled the ALLOWED result as a "BUG!". That was wrong:
 * verified search engines should be ALLOWED in monitor-only mode (and
 * in any mode). The monitor-only demotion only applies to would-be
 * blocks/challenges — not to allows.
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

$adapter = new GenericAdapter();
$config = Configuration::from_array([
	'preset'	 => 'minimal',
	'strictness' => 'monitor-only',
	'logging'	=> true,
], $adapter);

$bb = new BadBehaviour($config);

function header_line(string $s): void
{
	echo "\n=== $s ===\n";
}

function assert_true(bool $cond, string $msg): void
{
	if ($cond) {
		echo "  ✓ $msg\n";
		return;
	}
	echo "  ✗ FAIL: $msg\n";
	exit(1);
}

// =====================================================================
// Test 1: Malicious UA → MONITORED (the actual demotion scenario)
// =====================================================================
//
// sqlmap/1.5.2 matches BlacklistDetector's MALICIOUS_PREFIXES list.
// Without monitor-only mode, this would be Result::block(BLOCKED_MALICIOUS_UA).
// In monitor-only mode, the block is demoted to MONITORED_MALICIOUS_UA.
header_line('Test 1: Malicious UA prefix (sqlmap) → MONITORED');

$pkg_malicious = RequestPackage::create_for_test(
	user_agent: 'sqlmap/1.5.2#stable (https://sqlmap.org)',
	ip: '203.0.113.50',
);
$result_malicious = $bb->run_test_package($pkg_malicious);

echo "  code:		{$result_malicious->code->value}\n";
echo "  enforcement: {$result_malicious->enforcement->value}\n";
assert_true(
	str_starts_with($result_malicious->code->value, 'monitored.'),
	'code starts with monitored.*'
);
assert_true(
	$result_malicious->enforcement === \BadBehaviour\Core\EnforcementAction::MONITORED,
	'enforcement is MONITORED'
);
assert_true($result_malicious->is_monitored(),				  'is_monitored() = TRUE');
assert_true(!$result_malicious->is_enforced_block(),			'is_enforced_block() = FALSE');
assert_true(!$result_malicious->is_actionable(),				'is_actionable() = FALSE');
assert_true($result_malicious->reaches_application(),		   'reaches_application() = TRUE');
assert_true(!$result_malicious->is_purely_allowed(),			'is_purely_allowed() = FALSE');

// =====================================================================
// Test 2: Empty UA → ENFORCED (exception to monitor-only demotion)
// =====================================================================
header_line('Test 2: empty UA → ENFORCED (obvious attack exception)');

$pkg_empty = RequestPackage::create_for_test(
	user_agent: '',
	ip: '203.0.113.51',
);
$result_empty = $bb->run_test_package($pkg_empty);

echo "  code:		{$result_empty->code->value}\n";
echo "  enforcement: {$result_empty->enforcement->value}\n";
assert_true(
	$result_empty->code === ResultCode::BLOCKED_MALICIOUS_UA,
	'code is BLOCKED_MALICIOUS_UA'
);
assert_true(
	$result_empty->message === 'Empty or invalid User-Agent',
	'message identifies empty UA'
);
assert_true(
	$result_empty->enforcement === \BadBehaviour\Core\EnforcementAction::ENFORCED,
	'enforcement is ENFORCED'
);
assert_true($result_empty->is_enforced_block(),  'is_enforced_block() = TRUE');
assert_true($result_empty->is_actionable(),	  'is_actionable() = TRUE');
assert_true(!$result_empty->reaches_application(), 'reaches_application() = FALSE');

// =====================================================================
// Test 3: Raw XSS in URI → ENFORCED (exception to monitor-only demotion)
// =====================================================================
header_line('Test 3: raw <script> in URI → ENFORCED (obvious attack exception)');

$pkg_xss = RequestPackage::create_for_test(
	user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0',
	ip: '203.0.113.52',
	uri: '/search?q=<script>alert(1</script>',
);
$result_xss = $bb->run_test_package($pkg_xss);

echo "  code:		{$result_xss->code->value}\n";
echo "  enforcement: {$result_xss->enforcement->value}\n";
assert_true(
	str_starts_with($result_xss->code->value, 'blocked.'),
	'code starts with blocked.*'
);
assert_true(
	($result_xss->metadata['tier'] ?? null) === 'raw_uri',
	'metadata[tier] = raw_uri (the demotion exception marker)'
);
assert_true(
	$result_xss->enforcement === \BadBehaviour\Core\EnforcementAction::ENFORCED,
	'enforcement is ENFORCED'
);
assert_true($result_xss->is_enforced_block(), 'is_enforced_block() = TRUE');

// =====================================================================
// Test 4: handle_result() on MONITORED — defensive guard
// =====================================================================
//
// Calling handle_result() with a non-actionable result is misuse. The
// defensive guard logs a warning and returns NORMALLY instead of
// throwing LogicException (which crashed WackoWiki in production).
header_line('Test 4: handle_result() on MONITORED — must not crash');

ErrorReporter::reset();

ob_start();
try {
	$bb->handle_result($result_malicious);   // MONITORED from Test 1
	$captured = ob_get_clean();
	assert_true(true, 'returned normally (no exception thrown)');
} catch (\Throwable $e) {
	ob_end_clean();
	echo "  ✗ FAIL: handle_result() THREW " . get_class($e)
	   . ": {$e->getMessage()}\n";
	exit(1);
}

// =====================================================================
// Test 5: API contract matrix
// =====================================================================
header_line('Test 5: API contract across result types');

echo sprintf(
	"  %-12s %-15s %-15s %-15s %-20s\n",
	'STATE', 'is_purely_alw', 'is_allowed', 'is_actionable', 'reaches_application'
);

$cases = [
	'ALLOWED'   => fn() => Result::allow($pkg_malicious),
	'MONITORED' => fn() => $result_malicious,
	'ENFORCED'  => fn() => $result_empty,
];

foreach ($cases as $label => $factory) {
	$r = $factory();
	echo sprintf(
		"  %-12s %-15s %-15s %-15s %-20s\n",
		$label,
		$r->is_purely_allowed()	? 'T' : 'F',
		$r->is_allowed()		   ? 'T' : 'F',
		$r->is_actionable()		? 'T' : 'F',
		$r->reaches_application()  ? 'T' : 'F',
	);
}

// Verify the matrix matches what hosts should rely on:
//   ALLOWED:   reaches_application = T, is_actionable = F
//   MONITORED: reaches_application = T, is_actionable = F  (request reaches app)
//   ENFORCED:  reaches_application = F, is_actionable = T  (BadBehaviour serves response)
$allowed   = $cases['ALLOWED']();
$monitored = $cases['MONITORED']();
$enforced  = $cases['ENFORCED']();

assert_true($allowed->reaches_application()   && !$allowed->is_actionable(),   'ALLOWED: reaches, not actionable');
assert_true($monitored->reaches_application() && !$monitored->is_actionable(), 'MONITORED: reaches, not actionable');
assert_true(!$enforced->reaches_application() && $enforced->is_actionable(),  'ENFORCED: does not reach, is actionable');

// And the critical "old method was confusing" assertion:
assert_true(!$monitored->is_allowed(), 'is_allowed() returns FALSE for MONITORED (the old bug source)');

// =====================================================================
// Test 6: Regression — old !is_allowed() check on MONITORED
// =====================================================================
//
// The WackoWiki production crash was caused by:
//	 if (!$result->is_allowed()) { $bb->handle_result($result); }
//
// For MONITORED results, is_allowed() returns FALSE (strict semantic),
// so the buggy check evaluates to TRUE, and handle_result() is called
// on a non-actionable result. The defensive guard now handles this
// gracefully instead of crashing.
header_line('Test 6: regression — old !is_allowed() check');

ErrorReporter::reset();

// Show the divergence between old buggy check and new correct check
$old_check = !$result_malicious->is_allowed();	// TRUE for MONITORED (the bug)
$new_check = $result_malicious->is_actionable();  // FALSE (correct)

echo "  Old buggy check: !\$result->is_allowed()	   = " . var_export($old_check, true) . "\n";
echo "	→ would call handle_result() on a MONITORED result\n";
echo "	→ in old code: LogicException → 500 error\n";
echo "  New correct check: \$result->is_actionable()   = " . var_export($new_check, true) . "\n";
echo "	→ does NOT call handle_result() on MONITORED\n";
echo "	→ request reaches the application\n";
assert_true($old_check === true,  'old check evaluates TRUE for MONITORED (the bug)');
assert_true($new_check === false, 'new check evaluates FALSE for MONITORED (the fix)');

// Simulate the buggy integration calling handle_result() anyway
ob_start();
try {
	$bb->handle_result($result_malicious);
	$captured = ob_get_clean();
	echo "  handle_result() on MONITORED: returned normally (FIXED — no crash)\n";
	assert_true(true, 'defensive guard catches the misuse without crashing');
} catch (\Throwable $e) {
	ob_end_clean();
	echo "  ✗ FAIL: handle_result() threw " . get_class($e) . "\n";
	exit(1);
}

echo "\n✓ All tests passed.\n";
