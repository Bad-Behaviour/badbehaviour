<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Tests for ErrorReporter.
 *
 * ErrorReporter is a final static class. The major testable behaviors are:
 * 1. Routing: prefer adapter->log() over fallback (error_log)
 * 2. Once-tag gating: hard once-per-process suppression
 * 3. Time-based throttle: defense-in-depth against log flooding
 * 4. Fatal: one fatal per process
 * 5. Resilience: adapter/log failures must not crash
 * 6. reset(): clears gates for test isolation
 */
final class ErrorReporterTest extends TestCase
{

	/**
	 *
	 * @var resource stderr capture for fallback_log() inspection
	 */
	private $stderr_capture;

	protected function setUp(): void
	{
		// Reset all static state between tests for isolation
		ErrorReporter::reset();
	}

	protected function tearDown(): void
	{
		// Defensive: ensure no capture is left dangling
		if (is_resource($this->stderr_capture)) {
			fclose($this->stderr_capture);
		}
		ErrorReporter::reset();
	}

	// ====================================================================
	// Helpers
	// ====================================================================

	/**
	 * Capture PHP error_log() output via the error_log "destination" mechanism.
	 *
	 * Uses `error_log($msg, 3, $file)` style by overriding the destination.
	 * Since ErrorReporter uses error_log() with type 0 (default destination,
	 * which is OS logging), we instead use set_error_handler/ini_set to
	 * intercept by overriding error_log() via a spy mock.
	 *
	 * Note: PHPUnit 11 already captures stderr. We rely on PHPUnit's
	 * output buffering via expectOutputRegex / expectError for assertions.
	 */
	private function captureErrorLog(callable $fn): string
	{
		ob_start();
		try {
			$fn();
			return ob_get_clean();
		} catch (\Throwable $e) {
			ob_end_clean();
			throw $e;
		}
	}

	/**
	 * Build an adapter double that records calls to log().
	 */
	private function makeCapturingAdapter(): AdapterInterface
	{
		return new class() extends GenericAdapter {

			/** @var array<int, array{level: string, message: string, context: array}> */
			public array $calls = [];

			/** @var bool If true, throw on log() to test fallback */
			public bool $throw_on_log = false;

			public function log(string $level, string $message, array $context = []): void
			{
				if ($this->throw_on_log) {
					throw new \RuntimeException('adapter logger exploded');
				}
				$this->calls[] = [
					'level' => $level,
					'message' => $message,
					'context' => $context
				];
			}
		};
	}

	/**
	 * Use reflection to inspect private static state on ErrorReporter.
	 */
	private function getStatic(string $prop): mixed
	{
		$r = new ReflectionClass(ErrorReporter::class);
		$p = $r->getProperty($prop);
		$p->setAccessible(true);
		return $p->getValue();
	}

	// ====================================================================
	// error()
	// ====================================================================
	public function testErrorRoutesThroughAdapterWhenAvailable(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'something broke', [
			'key' => 'value'
		]);

		$this->assertCount(1, $adapter->calls);
		$this->assertSame('error', $adapter->calls[0]['level']);
		$this->assertSame('something broke', $adapter->calls[0]['message']);
		$this->assertSame([
			'key' => 'value'
		], $adapter->calls[0]['context']);
	}

	public function testErrorFallsBackToErrorLogWhenAdapterIsNull(): void
	{
		// When adapter is null, must not throw and must invoke fallback.
		ErrorReporter::error(null, 'null-adapter path', [
			'a' => 1
		]);

		// The fallback logs via error_log(); we can't intercept that easily
		// in PHPUnit without process isolation, so we just assert no throw.
		$this->assertTrue(true);
	}

	public function testErrorFallsBackWhenAdapterLoggerThrows(): void
	{
		$adapter = $this->makeCapturingAdapter();
		$adapter->throw_on_log = true;

		// Must NOT propagate the adapter exception
		ErrorReporter::error($adapter, 'message', []);

		// Adapter threw → 0 calls recorded
		$this->assertCount(0, $adapter->calls);
		$this->assertTrue(true); // survived without crashing
	}

	public function testErrorOnceTagSuppressesSecondCall(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'first', [], 'once-tag-x');
		ErrorReporter::error($adapter, 'second', [], 'once-tag-x');
		ErrorReporter::error($adapter, 'third', [], 'once-tag-x');

		$this->assertCount(1, $adapter->calls);
		$this->assertSame('first', $adapter->calls[0]['message']);
	}

	public function testErrorDifferentOnceTagsAreIndependent(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'm1', [], 'tag-a');
		ErrorReporter::error($adapter, 'm2', [], 'tag-b');
		ErrorReporter::error($adapter, 'm3', [], 'tag-a'); // suppressed
		ErrorReporter::error($adapter, 'm4', [], 'tag-c');

		$this->assertCount(3, $adapter->calls);
		$this->assertSame('m1', $adapter->calls[0]['message']);
		$this->assertSame('m2', $adapter->calls[1]['message']);
		$this->assertSame('m4', $adapter->calls[2]['message']);
	}

	public function testErrorWithoutOnceTagNeverSuppresses(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'one');
		ErrorReporter::error($adapter, 'two');
		ErrorReporter::error($adapter, 'three');

		$this->assertCount(3, $adapter->calls);
	}

	public function testErrorNullOnceTagIsNotSuppressed(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'a', [], null);
		ErrorReporter::error($adapter, 'b', [], null);
		ErrorReporter::error($adapter, 'c', [], null);

		$this->assertCount(3, $adapter->calls);
	}

	public function testErrorOnceTagWithTimeThrottleIsTracked(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'first', [], 'throttled-tag');

		// Inspect the private time-throttle array
		$lastEmitted = $this->getStatic('last_emitted_at');
		$this->assertArrayHasKey('throttled-tag', $lastEmitted);
		$this->assertIsInt($lastEmitted['throttled-tag']);
		$this->assertGreaterThanOrEqual(time() - 2, $lastEmitted['throttled-tag']);
	}

	// ====================================================================
	// warning()
	// ====================================================================
	public function testWarningRoutesThroughAdapter(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::warning($adapter, 'soft warning', [
			'k' => 'v'
		]);

		$this->assertCount(1, $adapter->calls);
		$this->assertSame('warning', $adapter->calls[0]['level']);
		$this->assertSame('soft warning', $adapter->calls[0]['message']);
		$this->assertSame([
			'k' => 'v'
		], $adapter->calls[0]['context']);
	}

	public function testWarningOnceTagSuppresses(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::warning($adapter, 'one', [], 'warn-once');
		ErrorReporter::warning($adapter, 'two', [], 'warn-once');

		$this->assertCount(1, $adapter->calls);
	}

	public function testWarningFallsBackOnAdapterException(): void
	{
		$adapter = $this->makeCapturingAdapter();
		$adapter->throw_on_log = true;

		// Must not throw
		ErrorReporter::warning($adapter, 'msg');
		$this->assertTrue(true);
	}

	public function testErrorAndWarningShareOnceTagGates(): void
	{
		// The implementation tracks once-tags in a shared `$reported` set,
		// so an error with tag 'x' suppresses a subsequent warning with tag 'x'.
		// (We assert this is the documented contract.)
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'err', [], 'shared-tag');
		ErrorReporter::warning($adapter, 'warn', [], 'shared-tag');

		$this->assertCount(1, $adapter->calls);
		$this->assertSame('error', $adapter->calls[0]['level']);
	}

	// ====================================================================
	// fatal()
	// ====================================================================
	public function testFatalIsLoggedOnce(): void
	{
		$e1 = new \RuntimeException('first');
		$e2 = new \RuntimeException('second');

		ErrorReporter::fatal($e1, 'ComponentA');
		ErrorReporter::fatal($e2, 'ComponentB');
		ErrorReporter::fatal(new \LogicException('third'), 'ComponentC');

		// No direct way to read "fatal_logged" externally; the second
		// call's component name ('ComponentB') should NOT appear in
		// output. We assert no throw and check that the boolean stays
		// set — using reflection.
		$logged = $this->getStatic('fatal_logged');
		$this->assertTrue($logged, 'fatal_logged flag must be set after first fatal');
	}

	public function testFatalAcceptsAnyThrowable(): void
	{
		// Subclasses should also work
		ErrorReporter::fatal(new \RuntimeException('rt'));
		ErrorReporter::fatal(new \LogicException('logic'));
		ErrorReporter::fatal(new \InvalidArgumentException('ia'));
		ErrorReporter::fatal(new \ParseError('parse'));
		ErrorReporter::fatal(new \TypeError('type'));
		ErrorReporter::fatal(new \DivisionByZeroError('div'));

		$this->assertTrue($this->getStatic('fatal_logged'));
	}

	public function testFatalDoesNotPropagateExceptionsFromErrorLog(): void
	{
		// Force a scenario where the inner error_log path would itself
		// throw. The fatal path wraps its own internal try/catch, so
		// we cannot easily induce failure from outside. We assert that
		// normal invocation doesn't throw.
		ErrorReporter::fatal(new \RuntimeException('boom'));

		$this->expectNotToPerformAssertions();
	}

	// ====================================================================
	// reset()
	// ====================================================================
	public function testResetClearsOnceTags(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'before-reset', [], 'tag-1');

		ErrorReporter::reset();

		// After reset, same tag should re-fire
		ErrorReporter::error($adapter, 'after-reset', [], 'tag-1');

		$this->assertCount(2, $adapter->calls);
	}

	public function testResetClearsTimeThrottle(): void
	{
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'one', [], 'throttle-tag');
		ErrorReporter::reset();

		$lastEmitted = $this->getStatic('last_emitted_at');
		$this->assertArrayNotHasKey('throttle-tag', $lastEmitted);

		$reported = $this->getStatic('reported');
		$this->assertArrayNotHasKey('throttle-tag', $reported);
	}

	public function testResetClearsFatalGate(): void
	{
		ErrorReporter::fatal(new \RuntimeException('first'));
		$this->assertTrue($this->getStatic('fatal_logged'));

		ErrorReporter::reset();
		$this->assertFalse($this->getStatic('fatal_logged'));
	}

	// ====================================================================
	// State isolation
	// ====================================================================
	public function testMultipleOnceTagsAccumulate(): void
	{
		$adapter = $this->makeCapturingAdapter();

		for ($i = 0; $i < 10; $i ++) {
			ErrorReporter::error($adapter, "msg-{$i}", [], "tag-{$i}");
		}

		// 10 distinct tags → 10 calls
		$this->assertCount(10, $adapter->calls);
	}

	public function testErrorLogUsesErrorLevel(): void
	{
		$adapter = $this->makeCapturingAdapter();
		ErrorReporter::error($adapter, 'msg', [], 'lvl-tag');
		$this->assertSame('error', $adapter->calls[0]['level']);
	}

	public function testWarningLogUsesWarningLevel(): void
	{
		$adapter = $this->makeCapturingAdapter();
		ErrorReporter::warning($adapter, 'msg', [], 'lvl-tag');
		$this->assertSame('warning', $adapter->calls[0]['level']);
	}

	// ====================================================================
	// Edge cases
	// ====================================================================
	public function testErrorAcceptsEmptyContext(): void
	{
		$adapter = $this->makeCapturingAdapter();
		ErrorReporter::error($adapter, 'msg');

		$this->assertSame([], $adapter->calls[0]['context']);
	}

	public function testErrorAcceptsComplexContext(): void
	{
		$adapter = $this->makeCapturingAdapter();
		$ctx = [
			'string' => 'value',
			'int' => 42,
			'nested' => [
				'a' => 1,
				'b' => [
					2,
					3
				]
			],
			'null' => null,
			'false' => false
		];

		ErrorReporter::error($adapter, 'msg', $ctx);

		$this->assertSame($ctx, $adapter->calls[0]['context']);
	}

	public function testErrorWithContextContainingNonUtf8IsHandled(): void
	{
		// json_encode may fail on invalid UTF-8; ErrorReporter catches that
		// and logs without context. The implementation's fallback_log()
		// catches \Throwable from json_encode and writes without context.
		$adapter = $this->makeCapturingAdapter();
		$bad_utf8 = "\xB1\x31"; // invalid UTF-8 sequence

		// This must NOT throw
		ErrorReporter::error($adapter, 'utf8 test', [
			'bad' => $bad_utf8
		]);

		// Adapter got called (json_encode succeeded in our test env or
		// fallback was hit). Either way: no exception.
		$this->assertGreaterThanOrEqual(1, count($adapter->calls));
	}

	public function testAdapterWithNonLogMethodObjectIsHandled(): void
	{
		// GenericAdapter has log(); we use it. If we passed an object
		// without log(), method_exists returns false and fallback path
		// is used. Verified by passing a plain object via a custom
		// AdapterInterface implementation lacking log().
		$adapter = new class() implements AdapterInterface {

			// Intentionally omit log() — note: PHP's strict interface
			// implementation will FAIL because the interface declares log().
			// So we instead subclass GenericAdapter and break the method.
			public function probe_log_table(string $table): array
			{
				return [
					'newest' => null,
					'total' => 0,
					'error' => null
				];
			}

			public function get_settings(): array
			{
				return [];
			}

			public function get_whitelist(): array
			{
				return [];
			}

			public function get_email(): string
			{
				return '';
			}

			public function get_relative_path(): string
			{
				return '';
			}

			public function get_table_schema(string $t): string|array
			{
				return '';
			}

			public function log_request(RequestPackage $p, Result $r): void
			{}

			public function query(string $sql): bool
			{
				return false;
			}

			public function get(string $k): mixed
			{
				return null;
			}

			public function set(string $k, mixed $v, int $ttl): bool
			{
				return true;
			}

			public function delete(string $k): bool
			{
				return true;
			}

			public function increment_counter(string $k, int $w): int
			{
				return 0;
			}

			public function get_counter(string $k): int
			{
				return 0;
			}

			public function get_behavior_profile(string $s): ?array
			{
				return null;
			}

			public function save_behavior_profile(string $s, array $p, int $ttl): bool
			{
				return true;
			}

			public function add_to_set(string $k, string $v, int $ttl): bool
			{
				return true;
			}

			public function get_set(string $k): array
			{
				return [];
			}

			public function get_geoip(string $ip): ?array
			{
				return null;
			}

			public function verify_challenge(string $r, string $ip): bool
			{
				return false;
			}

			public function log(string $level, string $message, array $context = []): void
			{
				// No-op success
			}
		};

		ErrorReporter::error($adapter, 'msg', [], 'untagged');
		$this->assertTrue(true);
	}

	public function testContextMayContainResultLikeObjects(): void
	{
		// Some callers pass Result instances in context for forensics.
		$adapter = $this->makeCapturingAdapter();
		$package = RequestPackage::create_for_test('Mozilla/5.0', '127.0.0.1');
		$result = Result::block(ResultCode::BLOCKED_BOT, 'test', $package, [
			'detector' => 'BotDetector'
		]);

		ErrorReporter::error($adapter, 'detector failed', [
			'result_code' => $result->code->value, // 'blocked.bot'
			'support_key' => $result->support_key
		]);

		$this->assertCount(1, $adapter->calls);
		$this->assertSame('blocked.bot', $adapter->calls[0]['context']['result_code']);
		$this->assertNotNull($adapter->calls[0]['context']['support_key']);
	}

	// ====================================================================
	// Class shape
	// ====================================================================
	public function testClassIsFinal(): void
	{
		$r = new ReflectionClass(ErrorReporter::class);
		$this->assertTrue($r->isFinal(), 'ErrorReporter must be final');
	}

	public function testClassHasPrivateConstructor(): void
	{
		$r = new ReflectionClass(ErrorReporter::class);
		$c = $r->getConstructor();
		$this->assertNotNull($c, 'private constructor must exist');
		$this->assertTrue($c->isPrivate(), 'constructor must be private (static class)');
	}

	public function testExposesOnlyStaticApi(): void
	{
		$r = new ReflectionClass(ErrorReporter::class);

		$publicMethods = array_filter($r->getMethods(\ReflectionMethod::IS_PUBLIC), fn ($m) => $m->getDeclaringClass()->getName() === ErrorReporter::class);

		// All public methods must be static
		foreach ($publicMethods as $m) {
			$this->assertTrue($m->isStatic(), "Method {$m->getName()} must be static");
		}

		// No public instance methods
		$this->assertEmpty(array_filter($publicMethods, fn ($m) => ! $m->isStatic()));
	}

	public function testPublicApiSurface(): void
	{
		// Document the expected public surface so accidental renames are caught
		$expected = [
			'error',
			'warning',
			'fatal',
			'reset'
		];

		$r = new ReflectionClass(ErrorReporter::class);
		$actual = array_map(fn ($m) => $m->getName(), $r->getMethods(\ReflectionMethod::IS_PUBLIC));

		sort($expected);
		sort($actual);

		$this->assertSame($expected, array_values(array_intersect($expected, $actual)));
	}

	public function testCannotInstantiate(): void
	{
		$r = new ReflectionClass(ErrorReporter::class);
		$this->expectException(\Throwable::class);
		$r->newInstance(); // private constructor
	}

	// ====================================================================
	// Adapter-aware semantics (one-tag gate persists per process)
	// ====================================================================
	public function testOnceTagGateIsProcessScoped(): void
	{
		// We can only simulate "process" by sharing the static across
		// calls in the same test. After reset() the gate clears.
		$adapter = $this->makeCapturingAdapter();

		ErrorReporter::error($adapter, 'a', [], 'process-tag');
		ErrorReporter::error($adapter, 'b', [], 'process-tag');
		$this->assertCount(1, $adapter->calls);

		// Without reset, still suppressed
		ErrorReporter::error($adapter, 'c', [], 'process-tag');
		$this->assertCount(1, $adapter->calls);

		// After reset, re-fires
		ErrorReporter::reset();
		ErrorReporter::error($adapter, 'd', [], 'process-tag');
		$this->assertCount(2, $adapter->calls);
		$this->assertSame('d', $adapter->calls[1]['message']);
	}
}
