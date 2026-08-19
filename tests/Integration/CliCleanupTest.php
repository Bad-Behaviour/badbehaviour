<?php
declare(strict_types=1);

namespace BadBehaviour\Tests\Integration;

use BadBehaviour\Configuration;
use BadBehaviour\Tests\Fixtures\Stubs\SqliteTestAdapter;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\LogRetention;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(LogRetention::class)]
final class CliCleanupTest extends TestCase
{
	private string $tempDbFile;
	private SqliteTestAdapter $adapter;

	protected function setUp(): void
	{
		parent::setUp();
		ErrorReporter::reset();
		// Use a temp file (not :memory:) so the subprocess can open it.
		$this->tempDbFile = tempnam(sys_get_temp_dir(), 'bb_cleanup_test_') . '.sqlite';
		$this->adapter = new SqliteTestAdapter('sqlite:' . $this->tempDbFile);
	}

	protected function tearDown(): void
	{
		ErrorReporter::reset();
		if (file_exists($this->tempDbFile)) {
			@unlink($this->tempDbFile);
		}
		parent::tearDown();
	}

	private function makeConfig(int $maxAgeDays = 7): Configuration
	{
		return Configuration::from_array([
			'log_retention' => [
				'enabled'                 => true,
				'max_age_days'            => $maxAgeDays,
				'max_rows'                => 0,
				'probability_denominator' => 1000,
				'min_interval_seconds'    => 60,    // short for tests
				'lock_ttl'                => 60,
			],
		]);
	}

	private function unixDaysAgo(int $days): int
	{
		return time() - ($days * 86400);
	}

	// ========================================================================
	// In-process tests (fast, deterministic)
	// ========================================================================

	#[Test]
	public function in_process_deletes_rows_older_than_max_age(): void
	{
		// Insert 5 old + 3 recent rows (using unix timestamps)
		for ($i = 0; $i < 5; $i++) {
			$this->adapter->insertRow((string)$this->unixDaysAgo(30));
		}
		for ($i = 0; $i < 3; $i++) {
			$this->adapter->insertRow((string)$this->unixDaysAgo(1));
		}

		$this->assertSame(8, $this->adapter->countRows());

		$retention = new LogRetention(
			adapter: $this->adapter,
			config: $this->makeConfig(maxAgeDays: 7),
			cache: $this->adapter,
			);

		$result = $retention->force_cleanup_now();

		$this->assertNotNull($result);
		$this->assertTrue($result->success);
		$this->assertSame(5, $result->rows_deleted);
		$this->assertSame(1, $result->iterations);
		$this->assertSame('age', $result->limit_by);

		// Only the 3 recent rows should remain.
		$this->assertSame(3, $this->adapter->countRows());
		$dates = $this->adapter->listDates();
		foreach ($dates as $date) {
			$this->assertGreaterThanOrEqual(
				$this->unixDaysAgo(7),
				(int)$date,
				"Surviving row $date should not be older than 7 days"
				);
		}
	}

	#[Test]
	public function in_process_skips_empty_table(): void
	{
		$retention = new LogRetention(
			adapter: $this->adapter,
			config: $this->makeConfig(),
			cache: $this->adapter,
			);

		$result = $retention->force_cleanup_now();

		$this->assertNotNull($result);
		$this->assertSame(0, $result->rows_deleted);
		// force_cleanup_now() always runs at least one DELETE, even on empty table.
		// The query executes but affects 0 rows.
		$this->assertSame(1, $result->iterations);
		$this->assertSame(0, $this->adapter->countRows());
	}

	#[Test]
	public function in_process_uses_newest_row_as_cutoff_anchor(): void
	{
		// Newest row is 20 days old. With max_age_days=7, cutoff = newest - 7d.
		// Rows older than 20-7 = 13 days should be deleted.
		// (i.e., the 20-day-old row survives; the 30-day-old row does not)
		$this->adapter->insertRow((string)$this->unixDaysAgo(30));
		$this->adapter->insertRow((string)$this->unixDaysAgo(20));

		$retention = new LogRetention(
			adapter: $this->adapter,
			config: $this->makeConfig(maxAgeDays: 7),
			cache: $this->adapter,
			);

		$result = $retention->force_cleanup_now();

		$this->assertSame(1, $result->rows_deleted);
		$this->assertSame(1, $this->adapter->countRows());  // ← FIX: 1 row survives, not 2
	}

	// ========================================================================
	// CLI subprocess tests (end-to-end)
	// ========================================================================

	#[Test]
	public function cli_subprocess_deletes_old_rows_and_exits_zero(): void
	{
		// Insert old + recent rows (unix timestamps)
		for ($i = 0; $i < 4; $i++) {
			$this->adapter->insertRow((string)$this->unixDaysAgo(30));
		}
		$this->adapter->insertRow((string)$this->unixDaysAgo(1));

		$this->assertSame(5, $this->adapter->countRows());

		// Run the CLI as a subprocess
		$output = $this->runCli();

		$this->assertSame(0, $output['exit'], "CLI failed:\n" . $output['stdout'] . "\n" . $output['stderr']);

		// Verify stdout contains expected sections
		$this->assertStringContainsString('BadBehaviour log retention cleanup', $output['stdout']);
		$this->assertStringContainsString('max_age_days:', $output['stdout']);
		$this->assertStringContainsString('rows_deleted:', $output['stdout']);

		// Verify the deletion actually happened
		// Open a fresh adapter (subprocess wrote the DB)
		$verify = new SqliteTestAdapter('sqlite:' . $this->tempDbFile);
		$this->assertSame(1, $verify->countRows(), 'CLI did not delete old rows');
	}

	#[Test]
	public function cli_subprocess_exits_zero_when_nothing_to_clean(): void
	{
		// Empty table
		$output = $this->runCli();

		$this->assertSame(0, $output['exit'], "CLI failed on empty table:\n" . $output['stdout']);
		$this->assertStringContainsString('Nothing to clean', $output['stdout']);
	}

	/**
	 * Invoke bin/cleanup-logs.php as a subprocess with the temp DB wired in.
	 *
	 * @return array{exit: int, stdout: string, stderr: string}
	 */
	private function runCli(): array
	{
		$cli = realpath(__DIR__ . '/../../bin/cleanup-logs.php');
		if ($cli === false) {
			$this->markTestSkipped('bin/cleanup-logs.php not found');
		}

		$cmd = sprintf(
			'%s %s 2>&1',
			escapeshellarg(PHP_BINARY),
			escapeshellarg($cli),
			);

		$descriptors = [
			0 => ['pipe', 'r'],
			1 => ['pipe', 'w'],
			2 => ['pipe', 'w'],
		];

		$env = [
			'BB_DB_DSN'    => 'sqlite:' . $this->tempDbFile,
			'BB_DB_TABLE'  => 'bad_behaviour',
			'PATH'         => getenv('PATH'),
		];

		$proc = proc_open($cmd, $descriptors, $pipes, dirname($cli), $env);
		if (!is_resource($proc)) {
			$this->markTestSkipped('Could not start subprocess');
		}

		fclose($pipes[0]);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);

		$exit = proc_close($proc);

		return [
			'exit'   => $exit,
			'stdout' => $stdout,
			'stderr' => $stderr,
		];
	}
}