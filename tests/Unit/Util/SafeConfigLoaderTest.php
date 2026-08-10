<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\SafeConfigLoader;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Tests for SafeConfigLoader.
 *
 * Public surface:
 *   - load(string $path, ?AdapterInterface $adapter = null, ?string $once_tag = null): ?array
 *   - find_existing(array $candidates): ?string
 *
 * Failure paths covered:
 *   1. File does not exist          → returns null, ErrorReporter::error logged
 *   2. ParseError (syntax error)     → returns null, ErrorReporter::error logged
 *   3. Throwable during require      → returns null, ErrorReporter::error logged
 *   4. Non-array return              → returns null, ErrorReporter::error logged
 *   5. Adapter throws on log()       → falls back to error_log, no propagation
 *   6. Once-tag deduplication        → second call with same tag is suppressed
 *   7. Successful load               → returns the array as-is
 *   8. find_existing()               → first existing path, ignores nulls
 */
final class SafeConfigLoaderTest extends TestCase
{
    /** @var string[] Files created for tests; cleaned up in tearDown */
    private array $temp_files = [];

    /** @var string[] Directories created for tests; cleaned up in tearDown */
    private array $temp_dirs = [];

    protected function setUp(): void
    {
        // The static reporter gates state must be clean per test
        ErrorReporter::reset();
    }

    protected function tearDown(): void
    {
        foreach ($this->temp_files as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
        foreach ($this->temp_dirs as $d) {
            if (is_dir($d)) {
                @rmdir($d);
            }
        }
        $this->temp_files = [];
        $this->temp_dirs = [];
        ErrorReporter::reset();
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    /**
     * Create a temp file containing the given PHP source.
     * Returns absolute path; auto-cleaned in tearDown.
     */
    private function writeTempPhp(string $contents, ?string $filename = null): string
    {
        $dir = sys_get_temp_dir() . '/bb_safe_config_loader_' . bin2hex(random_bytes(4));
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            $this->fail("Could not create temp dir: {$dir}");
        }
        $this->temp_dirs[] = $dir;

        $name = $filename ?? ('cfg_' . bin2hex(random_bytes(4)) . '.php');
        $path = $dir . '/' . $name;
        if (file_put_contents($path, $contents) === false) {
            $this->fail("Could not write temp file: {$path}");
        }
        $this->temp_files[] = $path;

        return $path;
    }

    /**
     * Capturing adapter (extends GenericAdapter so it implements
     * CacheInterface/AdapterInterface fully).
     */
    private function makeCapturingAdapter(): AdapterInterface
    {
        return new class extends GenericAdapter {
            /** @var array<int, array{level: string, message: string, context: array}> */
            public array $calls = [];
            public bool $throw_on_log = false;

            public function log(string $level, string $message, array $context = []): void
            {
                if ($this->throw_on_log) {
                    throw new \RuntimeException('adapter logger exploded');
                }
                $this->calls[] = [
                    'level' => $level,
                    'message' => $message,
                    'context' => $context,
                ];
            }
        };
    }

    // ====================================================================
    // load(): success path
    // ====================================================================

    public function testLoadReturnsArrayOnSuccess(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn ['logging' => true, 'verbose' => false];");

        $result = SafeConfigLoader::load($path);

        $this->assertSame(
            ['logging' => true, 'verbose' => false],
            $result,
            'load() must return the array verbatim'
        );
    }

    public function testLoadReturnsEmptyArray(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn [];");

        $result = SafeConfigLoader::load($path);

        $this->assertSame([], $result);
    }

    public function testLoadReturnsNestedArray(): void
    {
        $expected = [
            'logging' => true,
            'reverse_proxy' => ['enabled' => true, 'addresses' => ['10.0.0.0/8']],
            'rate_limits' => ['enabled' => false, 'global' => ['requests' => 1000]],
        ];
        $path = $this->writeTempPhp("<?php\nreturn " . var_export($expected, true) . ";");

        $result = SafeConfigLoader::load($path);

        $this->assertSame($expected, $result);
    }

    public function testLoadAcceptsAdapterAndOnceTag(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn ['k' => 'v'];");
        $adapter = $this->makeCapturingAdapter();

        $result = SafeConfigLoader::load($path, $adapter, 'my-once-tag');

        $this->assertSame(['k' => 'v'], $result);
        // Success path doesn't log anything
        $this->assertCount(0, $adapter->calls);
    }

    public function testLoadAcceptsNullAdapterAndNullOnceTag(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn [1, 2, 3];");

        $result = SafeConfigLoader::load($path, null, null);

        $this->assertSame([1, 2, 3], $result);
    }

    public function testLoadAcceptsNonArrayKeys(): void
    {
        // BB configs commonly have integer, string, and float values
        $expected = [
            'integer' => 42,
            'string'  => 'hello',
            'float'   => 3.14,
            'bool'    => true,
            'null'    => null,
        ];
        $path = $this->writeTempPhp("<?php\nreturn " . var_export($expected, true) . ";");

        $this->assertSame($expected, SafeConfigLoader::load($path));
    }

    // ====================================================================
    // load(): missing file
    // ====================================================================

    public function testLoadReturnsNullForMissingFile(): void
    {
        $path = '/this/path/does/not/exist/' . bin2hex(random_bytes(8)) . '.php';

        $this->assertFalse(file_exists($path));

        $result = SafeConfigLoader::load($path);

        $this->assertNull($result, 'Missing file must return null');
    }

    public function testLoadLogsErrorForMissingFile(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = '/this/path/does/not/exist/' . bin2hex(random_bytes(8)) . '.php';

        SafeConfigLoader::load($path, $adapter, 'missing-file-tag');

        $this->assertCount(1, $adapter->calls);
        $this->assertSame('error', $adapter->calls[0]['level']);
        $this->assertStringContainsString('config', strtolower($adapter->calls[0]['message']));
        $this->assertSame($path, $adapter->calls[0]['context']['path']);
    }

    public function testLoadMissingFileWithoutAdapterDoesNotThrow(): void
    {
        $path = '/no/such/path/' . bin2hex(random_bytes(8)) . '.php';

        // Falls through to error_log fallback; must not throw
        $result = SafeConfigLoader::load($path, null);
        $this->assertNull($result);
    }

    // ====================================================================
    // load(): parse error
    // ====================================================================

    public function testLoadReturnsNullOnParseError(): void
    {
        // Genuine syntax error: unclosed array bracket
        $path = $this->writeTempPhp("<?php\nreturn ['missing' => 1,");

        $result = SafeConfigLoader::load($path);

        $this->assertNull($result, 'ParseError must result in null');
    }

    public function testLoadLogsErrorOnParseError(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = $this->writeTempPhp("<?php\nreturn ['k' => 'v'");

        SafeConfigLoader::load($path, $adapter, 'parse-error-tag');

        $this->assertCount(1, $adapter->calls);
        $this->assertSame('error', $adapter->calls[0]['level']);
        $this->assertStringContainsString('syntax', strtolower($adapter->calls[0]['message']));
        $this->assertSame($path, $adapter->calls[0]['context']['path']);
        $this->assertArrayHasKey('error', $adapter->calls[0]['context']);
        $this->assertArrayHasKey('line', $adapter->calls[0]['context']);
        $this->assertArrayHasKey('hint', $adapter->calls[0]['context']);
    }

    public function testLoadLogsParseErrorLineNumber(): void
    {
        $adapter = $this->makeCapturingAdapter();
        // Multiline file with syntax error on line 3
        $contents = "<?php\n// line 2\nreturn 'no semicolon'\n";
        $path = $this->writeTempPhp($contents);

        SafeConfigLoader::load($path, $adapter, 'parse-line-tag');

        $this->assertArrayHasKey('line', $adapter->calls[0]['context']);
        $this->assertIsInt($adapter->calls[0]['context']['line']);
        $this->assertGreaterThan(0, $adapter->calls[0]['context']['line']);
    }

    public function testLoadParseErrorIsRecoverable(): void
    {
        // After a parse error, a second valid load must still succeed
        $bad = $this->writeTempPhp("<?php\nreturn ['broken' =>", 'bad.php');
        $good = $this->writeTempPhp("<?php\nreturn ['good' => true];", 'good.php');

        $this->assertNull(SafeConfigLoader::load($bad));
        $this->assertSame(['good' => true], SafeConfigLoader::load($good));
    }

    // ====================================================================
    // load(): exception during require
    // ====================================================================

    public function testLoadReturnsNullOnRuntimeExceptionInConfig(): void
    {
        // File that throws a RuntimeException during require
        $contents = <<<'PHP'
<?php
throw new \RuntimeException('misconfigured');
PHP;
        $path = $this->writeTempPhp($contents);

        $result = SafeConfigLoader::load($path);

        $this->assertNull($result);
    }

    public function testLoadReturnsNullOnAnyThrowableInConfig(): void
    {
        // Throwing a non-RuntimeException (e.g., TypeError, LogicException)
        $contents = <<<'PHP'
<?php
if (true) throw new \LogicException('logic-boom');
PHP;
        $path = $this->writeTempPhp($contents);

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadLogsErrorOnRuntimeException(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $contents = "<?php\nthrow new \\RuntimeException('boom');";
        $path = $this->writeTempPhp($contents);

        SafeConfigLoader::load($path, $adapter, 'runtime-tag');

        $this->assertCount(1, $adapter->calls);
        $this->assertSame('error', $adapter->calls[0]['level']);
        $this->assertStringContainsString('failed', strtolower($adapter->calls[0]['message']));
        $this->assertSame($path, $adapter->calls[0]['context']['path']);
        $this->assertArrayHasKey('error', $adapter->calls[0]['context']);
        $this->assertSame(\RuntimeException::class, $adapter->calls[0]['context']['exception_class']);
    }

    public function testLoadLogsErrorOnUnexpectedThrowable(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $contents = "<?php\nthrow new \\TypeError('type-boom');";
        $path = $this->writeTempPhp($contents);

        SafeConfigLoader::load($path, $adapter, 'unexpected-tag');

        $this->assertCount(1, $adapter->calls);
        $this->assertSame(\TypeError::class, $adapter->calls[0]['context']['exception_class']);
    }

    public function testLoadRecoverAfterException(): void
    {
        // After a runtime exception in config, a clean config still loads
        $bad = $this->writeTempPhp("<?php\nthrow new \\Exception('x');", 'bad.php');
        $good = $this->writeTempPhp("<?php\nreturn ['recovered' => true];", 'good.php');

        $this->assertNull(SafeConfigLoader::load($bad));
        $this->assertSame(['recovered' => true], SafeConfigLoader::load($good));
    }

    // ====================================================================
    // load(): non-array return
    // ====================================================================

    public function testLoadReturnsNullForScalarReturn(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn 'a string';");

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadReturnsNullForIntegerReturn(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn 42;");

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadReturnsNullForBooleanReturn(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn true;");

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadReturnsNullForNullReturn(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn null;");

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadReturnsNullForObjectReturn(): void
    {
        $contents = "<?php\nreturn new \\stdClass();";
        $path = $this->writeTempPhp($contents);

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadLogsErrorForNonArrayReturn(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = $this->writeTempPhp("<?php\nreturn 'oops';");

        SafeConfigLoader::load($path, $adapter, 'non-array-tag');

        $this->assertCount(1, $adapter->calls);
        $this->assertSame('error', $adapter->calls[0]['level']);
        $this->assertStringContainsString('array', strtolower($adapter->calls[0]['message']));
        $this->assertSame($path, $adapter->calls[0]['context']['path']);
        $this->assertSame('string', $adapter->calls[0]['context']['actual_type']);
        $this->assertArrayHasKey('hint', $adapter->calls[0]['context']);
    }

    public function testLoadNonArrayLogIncludesActualType(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = $this->writeTempPhp("<?php\nreturn 99;");

        SafeConfigLoader::load($path, $adapter, 'type-tag');

        $this->assertSame('integer', $adapter->calls[0]['context']['actual_type']);
    }

    // ====================================================================
    // load(): adapter resilience
    // ====================================================================

    public function testLoadDoesNotCrashWhenAdapterLoggerThrows(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $adapter->throw_on_log = true;

        // Must fall back to error_log; must NOT propagate the exception
        $result = SafeConfigLoader::load(
            '/no/such/path/' . bin2hex(random_bytes(8)) . '.php',
            $adapter,
            'crash-tag'
        );

        $this->assertNull($result);
        $this->assertCount(0, $adapter->calls); // adapter logger rejected everything
    }

    public function testLoadWithoutAdapterDoesNotCrashOnAnyFailure(): void
    {
        // Missing file, no adapter — must not throw, must return null
        $result = SafeConfigLoader::load(
            '/no/such/path/' . bin2hex(random_bytes(8)) . '.php',
            null
        );
        $this->assertNull($result);
    }

    public function testLoadParseErrorWithNullAdapterDoesNotCrash(): void
    {
        $path = $this->writeTempPhp("<?php\nreturn [,,");

        $this->assertNull(SafeConfigLoader::load($path, null));
    }

    // ====================================================================
    // load(): once-tag dedup
    // ====================================================================

    public function testLoadOnceTagSuppressesRepeatedErrors(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = $this->writeTempPhp("<?php\nreturn ['ok' => 1];", 'good.php');
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        // First: missing-file call logs
        SafeConfigLoader::load($missing, $adapter, 'shared-tag');
        // Second: same tag, different file — still suppressed
        SafeConfigLoader::load($missing, $adapter, 'shared-tag');

        $this->assertCount(1, $adapter->calls);
    }

    public function testLoadDifferentOnceTagsAreIndependent(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        SafeConfigLoader::load($missing, $adapter, 'tag-a');
        SafeConfigLoader::load($missing, $adapter, 'tag-b');
        SafeConfigLoader::load($missing, $adapter, 'tag-a'); // suppressed
        SafeConfigLoader::load($missing, $adapter, 'tag-c');

        $this->assertCount(3, $adapter->calls);
    }

    public function testLoadNullOnceTagIsNotDeduped(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        SafeConfigLoader::load($missing, $adapter, null);
        SafeConfigLoader::load($missing, $adapter, null);
        SafeConfigLoader::load($missing, $adapter, null);

        $this->assertCount(3, $adapter->calls);
    }

    public function testLoadOnceTagAcrossFailureModes(): void
    {
        // Once-tag suppresses across all failure types when same tag reused
        $adapter = $this->makeCapturingAdapter();
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';
        $parse_bad = $this->writeTempPhp("<?php\nreturn [,");

        SafeConfigLoader::load($missing,    $adapter, 'unified-tag');
        SafeConfigLoader::load($parse_bad,  $adapter, 'unified-tag');
        SafeConfigLoader::load($missing,    $adapter, 'unified-tag');

        $this->assertCount(1, $adapter->calls);
    }

    public function testLoadOnceTagDoesNotSuppressSuccess(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path1 = $this->writeTempPhp("<?php\nreturn ['a' => 1];", 'a.php');
        $path2 = $this->writeTempPhp("<?php\nreturn ['b' => 2];", 'b.php');

        // Even with the same once-tag, success-path loads do not log anyway,
        // so multiple successes with one tag yield 0 log calls.
        SafeConfigLoader::load($path1, $adapter, 'success-tag');
        SafeConfigLoader::load($path2, $adapter, 'success-tag');

        $this->assertCount(0, $adapter->calls);
    }

    // ====================================================================
    // load(): context shape (sanity)
    // ====================================================================

    public function testLoadMissingFileContextIncludesPath(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = '/nope/' . bin2hex(random_bytes(8));

        SafeConfigLoader::load($path, $adapter, 'ctx-tag');

        $this->assertSame($path, $adapter->calls[0]['context']['path']);
    }

    public function testLoadParseErrorContextIncludesLineAndHint(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = $this->writeTempPhp("<?php\nreturn [,");

        SafeConfigLoader::load($path, $adapter, 'hint-tag');

        $ctx = $adapter->calls[0]['context'];
        $this->assertArrayHasKey('line', $ctx);
        $this->assertIsInt($ctx['line']);
        $this->assertArrayHasKey('hint', $ctx);
        $this->assertIsString($ctx['hint']);
        $this->assertNotEmpty($ctx['hint']);
    }

    public function testLoadNonArrayContextIncludesHint(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $path = $this->writeTempPhp("<?php\nreturn 'x';");

        SafeConfigLoader::load($path, $adapter, 'non-array-hint-tag');

        $ctx = $adapter->calls[0]['context'];
        $this->assertArrayHasKey('hint', $ctx);
        $this->assertStringContainsString('return', $ctx['hint']);
    }

    // ====================================================================
    // load(): adapter that doesn't implement log()
    // ====================================================================

    public function testLoadWithNonLoggingAdapterFallsBack(): void
    {
    	// Adapter that swallows log calls — verifies SafeConfigLoader doesn't
    	// crash on adapters that don't propagate to a real logger.
    	$adapter = new class extends GenericAdapter {
    		public function log(string $level, string $message, array $context = []): void
    		{
    			// no-op
    		}
    	};

    	$missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';
    	$this->assertNull(SafeConfigLoader::load($missing, $adapter, 'no-log-tag'));
    }


    // ====================================================================
    // find_existing()
    // ====================================================================

    public function testFindExistingReturnsFirstExistingPath(): void
    {
        $a = $this->writeTempPhp("<?php\nreturn [];", 'a.php');
        $b = $this->writeTempPhp("<?php\nreturn [];", 'b.php');
        $c = $this->writeTempPhp("<?php\nreturn [];", 'c.php');

        $this->assertSame($a, SafeConfigLoader::find_existing([$a, $b, $c]));
    }

    public function testFindExistingSkipsMissingFiles(): void
    {
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';
        $existing = $this->writeTempPhp("<?php\nreturn [];", 'real.php');
        $also_missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        $this->assertSame(
            $existing,
            SafeConfigLoader::find_existing([$missing, $also_missing, $existing])
        );
    }

    public function testFindExistingSkipsNullEntries(): void
    {
        $existing = $this->writeTempPhp("<?php\nreturn [];", 'real.php');

        $this->assertSame(
            $existing,
            SafeConfigLoader::find_existing([null, $existing, null])
        );
    }

    public function testFindExistingSkipsEmptyStrings(): void
    {
        $existing = $this->writeTempPhp("<?php\nreturn [];", 'real.php');

        $this->assertSame(
            $existing,
            SafeConfigLoader::find_existing(['', $existing, ''])
        );
    }

    public function testFindExistingReturnsNullWhenNothingExists(): void
    {
        $this->assertNull(
            SafeConfigLoader::find_existing([
                '/no/such/a.php',
                '/no/such/b.php',
                '/no/such/c.php',
            ])
        );
    }

    public function testFindExistingReturnsNullForEmptyArray(): void
    {
        $this->assertNull(SafeConfigLoader::find_existing([]));
    }

    public function testFindExistingReturnsNullForAllNulls(): void
    {
        $this->assertNull(SafeConfigLoader::find_existing([null, null, null]));
    }

    public function testFindExistingIgnoresNonStringEntriesDefensively(): void
    {
        // Per the impl: `is_string($path)` check before file_exists()
        $existing = $this->writeTempPhp("<?php\nreturn [];", 'real.php');

        // int, bool, array, object are silently skipped
        $this->assertSame(
            $existing,
            SafeConfigLoader::find_existing([
                42,
                true,
                ['nested' => 'array'],
                new \stdClass(),
                null,
                $existing,
            ])
        );
    }

    public function testFindExistingOrderMatters(): void
    {
        $a = $this->writeTempPhp("<?php\nreturn [];", 'a.php');
        $b = $this->writeTempPhp("<?php\nreturn [];", 'b.php');

        // First in the input array wins
        $this->assertSame($a, SafeConfigLoader::find_existing([$a, $b]));
        $this->assertSame($b, SafeConfigLoader::find_existing([$b, $a]));
    }

    public function testFindExistingReturnsStringType(): void
    {
        $existing = $this->writeTempPhp("<?php\nreturn [];", 'real.php');

        $result = SafeConfigLoader::find_existing([$existing]);
        $this->assertIsString($result);
        $this->assertSame($existing, $result);
    }

    public function testFindExistingEmptyResultHasTypeNull(): void
    {
        $result = SafeConfigLoader::find_existing(['/no/such.php']);
        $this->assertNull($result);
    }

    // ====================================================================
    // Class shape / invariants
    // ====================================================================

    public function testClassIsFinal(): void
    {
        $r = new ReflectionClass(SafeConfigLoader::class);
        $this->assertTrue($r->isFinal());
    }

    public function testClassHasPrivateConstructor(): void
    {
        $r = new ReflectionClass(SafeConfigLoader::class);
        $c = $r->getConstructor();
        $this->assertNotNull($c);
        $this->assertTrue($c->isPrivate());
    }

    public function testPublicApiSurface(): void
    {
        $r = new ReflectionClass(SafeConfigLoader::class);
        $publicMethods = array_map(
            fn(\ReflectionMethod $m) => $m->getName(),
            $r->getMethods(\ReflectionMethod::IS_PUBLIC)
        );

        $expected = ['load', 'find_existing'];
        sort($expected);
        sort($publicMethods);

        $this->assertSame($expected, $publicMethods);
    }

    public function testAllPublicMethodsAreStatic(): void
    {
        $r = new ReflectionClass(SafeConfigLoader::class);
        foreach ($r->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
            $this->assertTrue($m->isStatic(), "{$m->getName()} must be static");
        }
    }

    public function testCannotInstantiate(): void
    {
        $this->expectException(\Throwable::class);
        (new ReflectionClass(SafeConfigLoader::class))->newInstance();
    }

    // ====================================================================
    // Integration with ErrorReporter
    // ====================================================================

    public function testLoadUsesErrorReporterNotDirectErrorLog(): void
    {
        // Adapter should receive the log call, not PHP's error_log.
        // Verified by adapter capturing the call.
        $adapter = $this->makeCapturingAdapter();
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        SafeConfigLoader::load($missing, $adapter, 'integration-tag');

        $this->assertCount(1, $adapter->calls);
    }

    public function testLoadManyErrorsWithOnceTagLogsOne(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        for ($i = 0; $i < 100; $i++) {
            SafeConfigLoader::load($missing, $adapter, 'flood-tag');
        }

        $this->assertCount(1, $adapter->calls);
    }

    public function testLoadManyErrorsWithoutOnceTagLogsAll(): void
    {
        $adapter = $this->makeCapturingAdapter();
        $missing = '/no/such/' . bin2hex(random_bytes(8)) . '.php';

        for ($i = 0; $i < 5; $i++) {
            SafeConfigLoader::load($missing, $adapter, null);
        }

        $this->assertCount(5, $adapter->calls);
    }

    // ====================================================================
    // load(): @-suppression of ParseError (the load() uses @require)
    // ====================================================================

    public function testLoadParseErrorDoesNotEmitPhpWarning(): void
    {
        // Even with a syntax-error file, load() must not produce
        // a PHP-level warning or notice. Use PHPUnit's strict mode.
        $path = $this->writeTempPhp("<?php\nreturn [,,");

        $result = SafeConfigLoader::load($path);

        // No PHP warning emitted; if it were, PHPUnit would fail
        // under beStrictAboutOutputDuringTests="true".
        $this->assertNull($result);
    }

    // ====================================================================
    // Pathological inputs
    // ====================================================================

    public function testLoadAcceptsEmptyStringPath(): void
    {
        // file_exists('') === false → returns null, no throw
        $this->assertNull(SafeConfigLoader::load(''));
    }

    public function testLoadAcceptsDirectoryAsPath(): void
    {
        $dir = sys_get_temp_dir() . '/bb_dir_' . bin2hex(random_bytes(4));
        @mkdir($dir, 0700, true);
        $this->temp_dirs[] = $dir;

        // Treating a directory as a file → file_exists is true but
        // require() will fail. Should return null, not crash.
        $result = SafeConfigLoader::load($dir);

        $this->assertNull($result);
    }

    public function testLoadAcceptsZeroLengthFile(): void
    {
        $path = $this->writeTempPhp('', 'empty.php');

        // Empty file: require succeeds, returns int(1), is_array fails → null
        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadAcceptsFileWithNoReturnStatement(): void
    {
        // Valid PHP, no return → require returns int(1)
        $path = $this->writeTempPhp("<?php\n\$x = 1;", 'no-return.php');

        $this->assertNull(SafeConfigLoader::load($path));
    }

    public function testLoadAcceptsFileReturningArrayExpression(): void
    {
        // return without semicolon, e.g. computed array
        $path = $this->writeTempPhp(
            "<?php\n\$v = 1;\nreturn ['computed' => \$v];",
            'computed.php'
        );

        $this->assertSame(['computed' => 1], SafeConfigLoader::load($path));
    }
}
