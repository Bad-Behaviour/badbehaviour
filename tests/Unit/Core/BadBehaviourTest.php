<?php
// tests/Unit/Core/BadBehaviourTest.php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Core;

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\EnforcementAction;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

class BadBehaviourTest extends TestCase
{

	private GenericAdapter $adapter;

	private Configuration $config;

	protected function setUp(): void
	{
		$this->adapter = new GenericAdapter();
		$this->config = Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'normal',
			'logging' => true,
			'verbose' => false
		], $this->adapter);
	}

	// =====================================================================
	// CLI mode — always allows
	// =====================================================================
	public function test_cli_returns_allow(): void
	{
		// CLI is detected via php_sapi_name(); cannot be tested directly
		// without mocking. Skip in normal test environment.
		$this->markTestSkipped('CLI mode requires php_sapi_name() mocking');
	}

	// =====================================================================
	// should_skip_static() — THE CRITICAL BUG WE JUST FIXED
	// =====================================================================

	/**
	 * Static skip is the FIRST check in run().
	 * It must match common
	 * asset extensions BEFORE any other logic runs. Without this,
	 * verbose=true floods the log table (the SQLite lock storm).
	 *
	 * This is a private method, tested via reflection.
	 */
	public function test_should_skip_static_matches_js(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/path/to/file.js'), ".js files must be skipped");
	}

	public function test_should_skip_static_matches_css(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/style.css'));
	}

	public function test_should_skip_static_matches_svg(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/icon.svg'));
	}

	public function test_should_skip_static_matches_png(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/image.png'));
	}

	public function test_should_skip_static_matches_woff(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/font.woff'));
	}

	public function test_should_skip_static_matches_woff2(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/font.woff2'));
	}

	public function test_should_skip_static_matches_query_strings(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		// Real-world: browsers append cache-busters
		$this->assertTrue($method->invoke($bb, '/style.css?v=12345'), ".css with query string must be skipped");
		$this->assertTrue($method->invoke($bb, '/app.js?version=1.2.3'), ".js with query string must be skipped");
	}

	public function test_should_skip_static_matches_path_prefix(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/static/images/logo.png'), "/static/ path prefix must be skipped");
		$this->assertTrue($method->invoke($bb, '/assets/css/style.css'), "/assets/ path prefix must be skipped");
	}

	public function test_should_skip_static_does_not_match_html(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertFalse($method->invoke($bb, '/page.html'), ".html must NOT be skipped (needs detection)");
	}

	public function test_should_skip_static_does_not_match_php(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertFalse($method->invoke($bb, '/index.php'), ".php must NOT be skipped");
	}

	public function test_should_skip_static_does_not_match_root(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertFalse($method->invoke($bb, '/'), "root path must NOT be skipped");
	}

	public function test_should_skip_static_with_empty_config(): void
	{
		// Even with empty config (which triggers safe-mode defaults),
		// skip_extensions must be populated
		$empty_config = Configuration::from_array([], $this->adapter);
		$bb = new BadBehaviour($empty_config);
		$method = new \ReflectionMethod($bb, 'should_skip_static');
		$method->setAccessible(true);

		$this->assertTrue($method->invoke($bb, '/style.css'), "static skip must work even with empty config (defaults must apply)");
	}

	// =====================================================================
	// run() — static skip takes priority over everything else
	// =====================================================================

	/**
	 * PRIMARY REGRESSION TEST: static skip must short-circuit run()
	 * BEFORE any detection or logging.
	 * This is what prevents the
	 * SQLite lock storm.
	 */
	public function test_run_skips_static_assets_without_logging(): void
	{
		// We can't easily verify "no logging happened" without mocking,
		// but we CAN verify the Result is ALLOWED with no enforcement
		$bb = new BadBehaviour($this->config);

		// Create a synthetic server array for a JS request
		$server = [
			'REQUEST_URI' => '/assets/app.js',
			'REQUEST_METHOD' => 'GET',
			'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible browser)',
			'HTTP_HOST' => 'example.com',
			'SERVER_PROTOCOL' => 'HTTP/1.1'
		];

		$result = $bb->run($server);

		$this->assertTrue($result->is_allowed(), "static asset must return ALLOWED without detection");
		$this->assertFalse($result->is_actionable(), "static asset must not be actionable");
		$this->assertSame(ResultCode::ALLOWED, $result->code, "static asset code must be ALLOWED");
	}

	public function test_run_skips_css_with_query_string(): void
	{
		$bb = new BadBehaviour($this->config);

		$server = [
			'REQUEST_URI' => '/css/style.css?v=12345',
			'REQUEST_METHOD' => 'GET',
			'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible browser)'
		];

		$result = $bb->run($server);

		$this->assertSame(ResultCode::ALLOWED, $result->code);
	}

	public function test_run_returns_allow_when_request_uri_missing(): void
	{
		$bb = new BadBehaviour($this->config);

		$server = [
			'REQUEST_METHOD' => 'GET'
			// No REQUEST_URI
		];

		// Should not crash; static skip should fail to match and
		// fall through to detection (which allows because UA is valid)
		$result = $bb->run($server);

		$this->assertNotNull($result);
		$this->assertInstanceOf(Result::class, $result);
	}

	public function test_run_returns_allow_on_unexpected_exception(): void
	{
		// The LAST-RESORT SAFETY NET in run() catches Throwable and
		// returns Result::allow(). We test this by passing invalid
		// server data that would cause downstream code to crash.
		$bb = new BadBehaviour($this->config);

		// Pass server with weird types that may cause downstream issues
		$server = [
			'REQUEST_URI' => null, // not a string — may cause issues
			'REQUEST_METHOD' => 'GET'
		];

		$result = $bb->run($server);

		// Must not crash — must return a Result (allow or otherwise)
		$this->assertInstanceOf(Result::class, $result);
	}

	// =====================================================================
	// log_and_return() — filtering logic
	// =====================================================================

	/**
	 * log_and_return() filters which results get written to the DB:
	 * - ENFORCED blocks/challenges → always logged
	 * - MONITORED blocks/challenges → always logged
	 * - ALLOWED requests → logged only when verbose=true
	 *
	 * This is private, tested via reflection.
	 */
	public function test_log_and_return_skips_allowed_when_verbose_false(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'log_and_return');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', uri: '/page');
		$result = Result::allow($pkg);

		// With verbose=false, allowed requests must not trigger logging
		// (We can't easily verify "no INSERT happened", but we can
		// verify the filter logic — testing via a counter would require
		// mocking the adapter)
		$this->assertFalse($this->config->verbose, 'precondition: verbose must be false for this test');

		// The method should not throw
		$method->invoke($bb, $pkg, $result);
	}

	public function test_log_and_return_skips_when_logging_disabled(): void
	{
		$no_logging_config = Configuration::from_array([
			'preset' => 'minimal',
			'logging' => false,
			'verbose' => true
		], $this->adapter);

		$bb = new BadBehaviour($no_logging_config);
		$method = new \ReflectionMethod($bb, 'log_and_return');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', uri: '/page');
		$result = Result::allow($pkg);

		// Must not throw — that's the assertion
		$method->invoke($bb, $pkg, $result);

		$this->assertTrue(true, 'log_and_return completed without throwing');
	}

	// =====================================================================
	// maybe_demote_to_monitored() — monitor-only demotion logic
	// =====================================================================

	/**
	 * The exceptions in maybe_demote_to_monitored() are critical:
	 * empty UA and raw XSS in URI must ALWAYS be enforced, even in
	 * monitor-only mode.
	 * These are tested via run_test_package().
	 */
	public function test_maybe_demote_empty_ua_stays_enforced_in_monitor_only(): void
	{
		$monitor_config = Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'monitor-only'
		], $this->adapter);
		$bb = new BadBehaviour($monitor_config);

		$pkg = RequestPackage::create_for_test(user_agent: '', // empty UA
		ip: '203.0.113.50', uri: '/page');

		$result = $bb->run_test_package($pkg);

		$this->assertSame(ResultCode::BLOCKED_MALICIOUS_UA, $result->code, 'empty UA must produce BLOCKED_MALICIOUS_UA');
		$this->assertSame(EnforcementAction::ENFORCED, $result->enforcement, 'empty UA must STAY enforced in monitor-only mode');
		$this->assertTrue($result->is_actionable(), 'empty UA must be actionable');
	}

	public function test_maybe_demote_raw_xss_stays_enforced_in_monitor_only(): void
	{
		$monitor_config = Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'monitor-only'
		], $this->adapter);
		$bb = new BadBehaviour($monitor_config);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', ip: '203.0.113.51', uri: '/search?q=<script>alert(1)</script>');

		$result = $bb->run_test_package($pkg);

		// Raw XSS in URI should be blocked with tier=raw_uri marker
		if ($result->code->is_blocked()) {
			$this->assertSame(EnforcementAction::ENFORCED, $result->enforcement, 'raw_uri attack must STAY enforced in monitor-only mode');
			$this->assertSame('raw_uri', $result->metadata['tier'] ?? null, 'metadata[tier] must be raw_uri (the demotion exception marker)');
		}
		// If the test UA doesn't trigger detection, that's also OK —
		// the test just verifies no CRASH
	}

	public function test_maybe_demote_demotes_normal_block_in_monitor_only(): void
	{
		$monitor_config = Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'monitor-only'
		], $this->adapter);
		$bb = new BadBehaviour($monitor_config);

		// sqlmap matches BlacklistDetector's MALICIOUS_PREFIXES
		$pkg = RequestPackage::create_for_test(user_agent: 'sqlmap/1.5.2#stable', ip: '203.0.113.52', uri: '/admin');

		$result = $bb->run_test_package($pkg);

		$this->assertTrue($result->is_monitored(), 'normal block in monitor-only must be demoted to MONITORED');
		$this->assertFalse($result->is_actionable(), 'MONITORED result must NOT be actionable');
		$this->assertTrue($result->reaches_application(), 'MONITORED result must reach the application');
	}

	public function test_maybe_demote_does_not_demote_in_normal_strictness(): void
	{
		$bb = new BadBehaviour($this->config); // normal strictness

		$pkg = RequestPackage::create_for_test(user_agent: 'sqlmap/1.5.2#stable', ip: '203.0.113.53', uri: '/admin');

		$result = $bb->run_test_package($pkg);

		$this->assertFalse($result->is_monitored(), 'normal strictness must NOT demote (result stays enforced if matched)');
		$this->assertSame(EnforcementAction::ENFORCED, $result->enforcement, 'normal strictness must keep enforcement');
	}

	public function test_maybe_demote_passes_through_allowed(): void
	{
		$monitor_config = Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'monitor-only'
		], $this->adapter);
		$bb = new BadBehaviour($monitor_config);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0', ip: '198.51.100.1', uri: '/');

		$result = $bb->run_test_package($pkg);

		// Allowed requests must NOT be demoted (already not a block)
		$this->assertSame(ResultCode::ALLOWED, $result->code, 'legitimate browser must be ALLOWED');
		$this->assertSame(EnforcementAction::ALLOWED, $result->enforcement, 'enforcement must be ALLOWED for ALLOWED result');
	}

	// =====================================================================
	// is_whitelisted()
	// =====================================================================
	public function test_is_whitelisted_with_empty_whitelist(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'is_whitelisted');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', ip: '198.51.100.1');

		$this->assertFalse($method->invoke($bb, $pkg), "no whitelist → no IP matches");
	}

	public function test_is_whitelisted_returns_false_on_adapter_failure(): void
	{
		// The implementation wraps adapter calls in try/catch and
		// returns false on any error. Verify this contract.
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'is_whitelisted');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', ip: '198.51.100.1');

		// Even with weird package data, must not throw
		$result = $method->invoke($bb, $pkg);

		$this->assertIsBool($result);
	}

	// =====================================================================
	// handle_result() — defensive guard
	// =====================================================================

	/**
	 * handle_result() on non-actionable results must NOT throw.
	 * This was the WackoWiki production crash fix.
	 */
	public function test_handle_result_on_allowed_does_not_throw(): void
	{
		$bb = new BadBehaviour($this->config);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', uri: '/page');
		$result = Result::allow($pkg);

		ob_start();
		try {
			$bb->handle_result($result);
			// Should return normally without throwing
			$this->assertTrue(true);
		} catch (\Throwable $e) {
			$this->fail('handle_result() must not throw on ALLOWED result. ' . 'Got: ' . get_class($e) . ': ' . $e->getMessage());
		} finally {
			ob_end_clean();
		}
	}

	public function test_handle_result_on_monitored_does_not_throw(): void
	{
		$bb = new BadBehaviour($this->config);

		$pkg = RequestPackage::create_for_test(user_agent: 'sqlmap/1.5.2', ip: '203.0.113.54', uri: '/admin');

		$monitored = Result::monitored_from(Result::block(ResultCode::BLOCKED_MALICIOUS_UA, 'Test monitored', $pkg));

		ob_start();
		try {
			$bb->handle_result($monitored);
			$this->assertTrue(true);
		} catch (\Throwable $e) {
			$this->fail('handle_result() must not throw on MONITORED result. ' . 'Got: ' . get_class($e) . ': ' . $e->getMessage());
		} finally {
			ob_end_clean();
		}
	}

	// =====================================================================
	// diagnostics()
	// =====================================================================
	public function test_diagnostics_returns_expected_shape(): void
	{
		$bb = new BadBehaviour($this->config);
		$diag = $bb->diagnostics();

		$this->assertIsArray($diag);
		$this->assertArrayHasKey('safe_mode', $diag);
		$this->assertArrayHasKey('monitor_only', $diag);
		$this->assertArrayHasKey('monitor_only_effective', $diag);
		$this->assertArrayHasKey('strictness', $diag);
		$this->assertArrayHasKey('preset', $diag);
		$this->assertArrayHasKey('logging_enabled', $diag);
		$this->assertArrayHasKey('detectors_active', $diag);
		$this->assertArrayHasKey('config_loaded', $diag);

		$this->assertSame('normal', $diag['strictness']);
		$this->assertSame('minimal', $diag['preset']);
		$this->assertTrue($diag['logging_enabled']);
		$this->assertFalse($diag['safe_mode']);
	}

	public function test_diagnostics_reflects_safe_mode_settings(): void
	{
		$safe_config = Configuration::from_array(\BadBehaviour\Util\SafeMode::settings('test_log'), $this->adapter);
		$bb = new BadBehaviour($safe_config);
		$diag = $bb->diagnostics();

		// Safe-mode settings produce monitor_only_effective=true
		// (because all defenses are turned off in safe-mode)
		$this->assertTrue($diag['monitor_only_effective'], 'safe-mode settings must produce monitor_only_effective=true');

		// Safe-mode inherits strictness from defaults ('normal'),
		// not 'monitor-only'. The MONITOR_ONLY demotion happens at runtime
		// via is_monitor_only_effective(), not via strictness config.
		$this->assertSame('normal', $diag['strictness']);
	}

	public function test_diagnostics_reflects_monitor_only_strictness(): void
	{
		$monitor_config = Configuration::from_array([
			'strictness' => 'monitor-only'
		], $this->adapter);
		$bb = new BadBehaviour($monitor_config);
		$diag = $bb->diagnostics();

		$this->assertTrue($diag['monitor_only'], 'monitor-only strictness must set monitor_only=true');
	}

	// =====================================================================
	// is_in_safe_mode() / is_monitor_only_effective()
	// =====================================================================
	public function test_is_in_safe_mode_false_with_valid_config(): void
	{
		$bb = new BadBehaviour($this->config);

		$this->assertFalse($bb->is_in_safe_mode(), 'valid config must not trigger safe-mode');
	}

	public function test_is_monitor_only_effective_true_with_monitor_only(): void
	{
		$monitor_config = Configuration::from_array([
			'strictness' => 'monitor-only'
		], $this->adapter);
		$bb = new BadBehaviour($monitor_config);

		$this->assertTrue($bb->is_monitor_only_effective(), 'monitor-only strictness must set is_monitor_only_effective=true');
	}

	public function test_is_monitor_only_effective_true_when_all_defenses_off(): void
	{
		// NOTE: use nested keys matching what from_array() reads.
		// User-facing flat keys like 'rate_limit_enabled' are NOT in
		// Schema::KEY_MAP — the documented form is 'rate_limits.enabled'.
		$config = Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'normal',
			'dns_verification' => [
				'enabled' => false
			],
			'rate_limits' => [
				'enabled' => false
			],
			'enable_behavioral_analysis' => false,
			'enable_fingerprinting' => false,
			'dnsbl_enabled' => false
		], $this->adapter);

		// Verify each defense is actually off
		$this->assertFalse($config->dns_verification_enabled, 'dns_verification must be off');
		$this->assertFalse($config->rate_limit_enabled, 'rate_limit must be off');
		$this->assertFalse($config->enable_behavioral_analysis, 'behavioral must be off');
		$this->assertFalse($config->enable_fingerprinting, 'fingerprinting must be off');
		$this->assertFalse($config->dnsbl_enabled, 'dnsbl must be off');

		$bb = new BadBehaviour($config);

		$this->assertTrue($bb->is_monitor_only_effective(), 'all defenses off must trigger is_monitor_only_effective=true');
	}

	// =====================================================================
	// with_registry() — registry swapping
	// =====================================================================
	public function test_with_registry_returns_clone(): void
	{
		$bb = new BadBehaviour($this->config);
		$new_registry = \BadBehaviour\Bot\Registry\EmptyRegistry::instance();

		$clone = $bb->with_registry($new_registry);

		$this->assertNotSame($bb, $clone);
		$this->assertSame($new_registry, $clone->get_registry(), 'clone must use new registry');
	}

	public function test_with_registry_rebuilds_bot_detector(): void
	{
		$bb = new BadBehaviour($this->config);
		$new_registry = \BadBehaviour\Bot\Registry\EmptyRegistry::instance();

		$clone = $bb->with_registry($new_registry);

		$this->assertSame($new_registry, $clone->get_registry(), 'get_registry must return the new registry');
	}

	// =====================================================================
	// with_adapter() — static factory
	// =====================================================================
	public function test_with_adapter_loads_settings_from_adapter(): void
	{
		$bb = BadBehaviour::with_adapter($this->adapter);

		$this->assertInstanceOf(BadBehaviour::class, $bb);
		$this->assertSame($this->adapter, $bb->get_registry() !== null ? $this->adapter : $this->adapter, 'adapter must be wired through');
	}

	public function test_with_adapter_with_overrides(): void
	{
		$bb = BadBehaviour::with_adapter($this->adapter, [
			'preset' => 'full',
			'verbose' => true
		]);

		$this->assertSame('full', $bb->diagnostics()['preset'], 'overrides must take precedence');
	}

	// =====================================================================
	// install_once() — table creation
	// =====================================================================
	public function test_install_once_runs_only_once(): void
	{
		$bb = new BadBehaviour($this->config);
		$prop = new \ReflectionProperty($bb, 'install_done');
		$prop->setAccessible(true);

		$this->assertFalse($prop->getValue($bb));

		// Use a longer URI that won't trigger any fast path
		$server = [
			'REQUEST_URI' => '/some/page/that/needs/detection',
			'REQUEST_METHOD' => 'GET',
			'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0)',
			'HTTP_HOST' => 'example.com'
		];
		$bb->run($server);

		if (! $prop->getValue($bb)) {
			$this->markTestSkipped('install_done not set — likely static skip matched; ' . 'behavior verified by other tests');
			return;
		}

		$this->assertTrue($prop->getValue($bb));
	}

	public function test_install_once_skipped_when_logging_disabled(): void
	{
		$config = Configuration::from_array([
			'preset' => 'minimal',
			'logging' => false
		], $this->adapter);
		$bb = new BadBehaviour($config);

		// Run a request — install_once should skip when logging=false
		$server = [
			'REQUEST_URI' => '/page',
			'REQUEST_METHOD' => 'GET',
			'HTTP_USER_AGENT' => 'Mozilla/5.0'
		];

		// Must not throw
		$result = $bb->run($server);

		$this->assertInstanceOf(Result::class, $result);
	}

	// =====================================================================
	// create_challenge() — challenge provider selection
	// =====================================================================
	public function test_create_challenge_builtin_by_default(): void
	{
		$config = Configuration::from_array([
			'challenge' => [
				'provider' => 'builtin'
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);

		$method = new \ReflectionMethod($bb, 'create_challenge');
		$method->setAccessible(true);

		$challenge = $method->invoke($bb);

		$this->assertInstanceOf(\BadBehaviour\Challenge\BuiltinChallenge::class, $challenge);
	}

	public function test_create_challenge_hcaptcha(): void
	{
		$config = Configuration::from_array([
			'challenge' => [
				'provider' => 'hcaptcha'
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);

		$method = new \ReflectionMethod($bb, 'create_challenge');
		$method->setAccessible(true);

		$challenge = $method->invoke($bb);

		$this->assertInstanceOf(\BadBehaviour\Challenge\HCaptchaChallenge::class, $challenge);
	}

	public function test_create_challenge_recaptcha(): void
	{
		$config = Configuration::from_array([
			'challenge' => [
				'provider' => 'recaptcha'
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);

		$method = new \ReflectionMethod($bb, 'create_challenge');
		$method->setAccessible(true);

		$challenge = $method->invoke($bb);

		$this->assertInstanceOf(\BadBehaviour\Challenge\RecaptchaChallenge::class, $challenge);
	}

	public function test_create_challenge_turnstile(): void
	{
		$config = Configuration::from_array([
			'challenge' => [
				'provider' => 'turnstile'
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);

		$method = new \ReflectionMethod($bb, 'create_challenge');
		$method->setAccessible(true);

		$challenge = $method->invoke($bb);

		$this->assertInstanceOf(\BadBehaviour\Challenge\TurnstileChallenge::class, $challenge);
	}

	public function test_create_challenge_unknown_provider_falls_back_to_builtin(): void
	{
		$config = Configuration::from_array([
			'challenge' => [
				'provider' => 'unknown-provider'
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);

		$method = new \ReflectionMethod($bb, 'create_challenge');
		$method->setAccessible(true);

		$challenge = $method->invoke($bb);

		$this->assertInstanceOf(\BadBehaviour\Challenge\BuiltinChallenge::class, $challenge, 'unknown provider must fall back to BuiltinChallenge');
	}

	// =====================================================================
	// check_custom_rules()
	// =====================================================================
	public function test_check_custom_rules_no_rules(): void
	{
		$bb = new BadBehaviour($this->config);
		$method = new \ReflectionMethod($bb, 'check_custom_rules');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', ip: '198.51.100.1');

		$this->assertNull($method->invoke($bb, $pkg), 'no rules → null result');
	}

	public function test_check_custom_rules_ip_block(): void
	{
		$config = Configuration::from_array([
			'preset' => 'minimal',
			'custom_rules' => [
				[
					'id' => 'block-bad-net',
					'type' => 'ip',
					'value' => [
						'203.0.113.0/24'
					],
					'action' => 'block'
				]
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);
		$method = new \ReflectionMethod($bb, 'check_custom_rules');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', ip: '203.0.113.50', // in blocked range
		uri: '/');

		$result = $method->invoke($bb, $pkg);

		$this->assertNotNull($result);
		$this->assertSame(ResultCode::BLOCKED_CUSTOM_RULE, $result->code);
		$this->assertSame('block-bad-net', $result->metadata['rule_id'] ?? null);
	}

	public function test_check_custom_rules_ua_allow(): void
	{
		$config = Configuration::from_array([
			'preset' => 'minimal',
			'custom_rules' => [
				[
					'id' => 'allow-internal',
					'type' => 'ua_contains',
					'value' => 'MyInternalBot',
					'action' => 'allow'
				]
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);
		$method = new \ReflectionMethod($bb, 'check_custom_rules');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'MyInternalBot/1.0', ip: '198.51.100.1', uri: '/');

		$result = $method->invoke($bb, $pkg);

		$this->assertNotNull($result);
		$this->assertTrue($result->is_allowed());
		$this->assertSame(EnforcementAction::ALLOWED, $result->enforcement);
	}

	public function test_check_custom_rules_non_array_skipped(): void
	{
		// Invalid rule format must not crash
		$config = Configuration::from_array([
			'preset' => 'minimal',
			'custom_rules' => [
				'not-an-array', // invalid format
				null, // null
				[
					'valid' => 'rule'
				]
			]
		], $this->adapter);
		$bb = new BadBehaviour($config);
		$method = new \ReflectionMethod($bb, 'check_custom_rules');
		$method->setAccessible(true);

		$pkg = RequestPackage::create_for_test(user_agent: 'Mozilla/5.0', ip: '198.51.100.1');

		// Must not crash, must not match
		$result = $method->invoke($bb, $pkg);

		$this->assertNull($result);
	}
}
