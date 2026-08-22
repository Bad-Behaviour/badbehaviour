<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Fixtures\Stubs;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Util\RequestPackage;

/**
 * SQLite-backed adapter for integration tests.
 *
 * Provides a real PDO connection (file-based or :memory:) so LogRetention's
 * DELETE statements actually execute. Implements both AdapterInterface and
 * CacheInterface so LogRetention's full pipeline (probe, mutate, lock,
 * last_run) can be exercised end-to-end.
 *
 * The schema is the production `bad_behaviour` table with a `date TEXT`
 * column (ISO-8601 format) — the most common WackoWiki/MySQL shape. Tests
 * that need to verify schema-portability can construct their own adapters
 * with different column types.
 */
class SqliteTestAdapter implements AdapterInterface, CacheInterface
{

	private \PDO $db;

	/** @var array<string, array{0: mixed, 1: int}> */
	private array $cacheStore = [];

	public function __construct(string $dsn = 'sqlite::memory:', string $tableName = 'bad_behaviour')
	{
		$this->db = new \PDO($dsn);
		$this->db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
		$this->db->exec("
            CREATE TABLE IF NOT EXISTS `$tableName` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL
            )
        ");
		$this->tableName = $tableName;
	}

	private string $tableName;

	public function getDb(): \PDO
	{
		return $this->db;
	}

	// AdapterInterface
	public function get_settings(): array
	{
		return [
			'log_table' => $this->tableName
		];
	}

	public function get_whitelist(): array
	{
		return [
			'ip' => [],
			'useragent' => [],
			'url' => [],
			'asn' => [],
			'country' => []
		];
	}

	public function get_email(): string
	{
		return 'test@example.com';
	}

	public function get_relative_path(): string
	{
		return '/';
	}

	public function get_table_schema(string $table_name): string|array
	{
		return "CREATE TABLE IF NOT EXISTS `$table_name` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL
        )";
	}

	public function log_request(RequestPackage $package, Result $result): void
	{}

	public function query(string $sql): bool
	{
		$this->db->exec($sql);
		return true;
	}

	public function probe_log_table(string $table): array
	{
		try {
			$newest = $this->db->query("SELECT MAX(date) FROM `$table`")->fetchColumn();
			$total = (int) $this->db->query("SELECT COUNT(*) FROM `$table`")->fetchColumn();
			return [
				'newest' => $newest,
				'total' => $total,
				'error' => null
			];
		} catch (\Throwable $e) {
			return [
				'newest' => null,
				'total' => 0,
				'error' => $e->getMessage()
			];
		}
	}

	// CacheInterface — minimal in-memory implementation
	public function get(string $key): mixed
	{
		if (! isset($this->cacheStore[$key])) {
			return null;
		}
		[
			$value,
			$expires
		] = $this->cacheStore[$key];
		if ($expires > 0 && $expires < time()) {
			unset($this->cacheStore[$key]);
			return null;
		}
		return $value;
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		$this->cacheStore[$key] = [
			$value,
			$ttl > 0 ? time() + $ttl : 0
		];
		return true;
	}

	public function delete(string $key): bool
	{
		unset($this->cacheStore[$key]);
		return true;
	}

	public function increment_counter(string $key, int $window): int
	{
		return 1;
	}

	public function get_counter(string $key): int
	{
		return 0;
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		return null;
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		return true;
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		return true;
	}

	public function get_set(string $key): array
	{
		return [];
	}

	public function get_geoip(string $ip): ?array
	{
		return null;
	}

	public function verify_challenge(string $response, string $remote_ip): bool
	{
		return false;
	}

	public function log(string $level, string $message, array $context = []): void
	{}

	// Test helpers

	/**
	 * Insert a row with an ISO-8601 date string.
	 *
	 * @param string $isoDate
	 *        	e.g., '2026-08-15 12:00:00'
	 */
	public function insertRow(string $isoDate): int
	{
		$stmt = $this->db->prepare("INSERT INTO `{$this->tableName}` (date) VALUES (:date)");
		$stmt->execute([
			':date' => $isoDate
		]);
		return (int) $this->db->lastInsertId();
	}

	/**
	 * Count rows currently in the table.
	 */
	public function countRows(): int
	{
		return (int) $this->db->query("SELECT COUNT(*) FROM `{$this->tableName}`")->fetchColumn();
	}

	/**
	 * Return all dates currently in the table, ordered by date ascending.
	 *
	 * @return string[]
	 */
	public function listDates(): array
	{
		$rows = $this->db->query("SELECT date FROM `{$this->tableName}` ORDER BY date ASC")->fetchAll(\PDO::FETCH_COLUMN);
		return array_map('strval', $rows);
	}

	// Add this method to the SqliteTestAdapter class (after probe_log_table or anywhere in the class):

	/**
	 * Return the number of rows affected by the most recent query().
	 *
	 * Uses PDO's rowCount() which works for DELETE/INSERT/UPDATE statements.
	 * Returns null on any error (consistent with the interface contract).
	 */
	public function last_query_affected_rows(): ?int
	{
		try {
			// PDO::rowCount() returns the number of rows affected by the
			// last DELETE/INSERT/UPDATE statement.
			return (int) $this->db->query('SELECT changes()')->fetchColumn();
		} catch (\Throwable $e) {
			return null;
		}
	}
}