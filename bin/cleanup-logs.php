#!/usr/bin/env php
<?php
/**
 * Bad Behaviour 3.0 — Log retention cleanup.
 *
 * Deletes rows older than the configured retention window from the
 * bad_behaviour log table. Run via cron, or invoke manually:
 *
 *   php /path/to/badbehaviour/bin/cleanup-logs.php
 *
 * Recommended schedule (when not relying on on-request cleanup):
 *
 *   0 3 * * * php /path/to/badbehaviour/bin/cleanup-logs.php >> /var/log/bb-cleanup.log 2>&1
 *
 * Exit codes:
 *   0 — Success (rows deleted, or nothing to delete)
 *   1 — Configuration error (missing config, adapter not writable)
 *   2 — Query failure (DB error, probe failed)
 *
 * @see config/bb_config.example.php → log_retention
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;

$start = microtime(true);

try {
	// Optional SQLite override for testing. When BB_DB_DSN is set (e.g.,
	// by integration tests pointing at a temp file), construct a minimal
	// SQLite-backed adapter inline. Production deployments leave the env
	// var unset and get GenericAdapter (no DB — script exits informatively).
	$db_dsn = getenv('BB_DB_DSN') ?: null;
	if ($db_dsn !== null) {
		$pdo = new \PDO($db_dsn);
		$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
		$table = getenv('BB_DB_TABLE') ?: 'bad_behaviour';
		$pdo->exec("CREATE TABLE IF NOT EXISTS `$table` (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL)");

		$adapter = new class($pdo, $table) implements \BadBehaviour\Core\Interfaces\AdapterInterface, \BadBehaviour\Core\Interfaces\CacheInterface {
			private array $cacheStore = [];
			public function __construct(private \PDO $db, private string $table) {}
			public function get_settings(): array { return ['log_table' => $this->table]; }
			public function get_whitelist(): array { return []; }
			public function get_email(): string { return 'cli@example.com'; }
			public function get_relative_path(): string { return '/'; }
			public function get_table_schema(string $t): string|array { return ''; }
			public function log_request(\BadBehaviour\Util\RequestPackage $p, \BadBehaviour\Core\Result $r): void {}
			public function query(string $sql): bool { $this->db->exec($sql); return true; }
			public function last_query_affected_rows(): ?int
			{
				try {
					return (int)$this->db->query('SELECT changes()')->fetchColumn();
				} catch (\Throwable $e) {
					return null;
				}
			}
			public function probe_log_table(string $table): array {
				try {
					return ['newest' => $this->db->query("SELECT MAX(date) FROM `$table`")->fetchColumn(), 'total' => (int)$this->db->query("SELECT COUNT(*) FROM `$table`")->fetchColumn(), 'error' => null];
				} catch (\Throwable $e) { return ['newest' => null, 'total' => 0, 'error' => $e->getMessage()]; }
			}
			public function get(string $key): mixed {
				if (!isset($this->cacheStore[$key])) return null;
				[$v, $exp] = $this->cacheStore[$key];
				if ($exp > 0 && $exp < time()) { unset($this->cacheStore[$key]); return null; }
				return $v;
			}
			public function set(string $key, mixed $value, int $ttl): bool { $this->cacheStore[$key] = [$value, $ttl > 0 ? time() + $ttl : 0]; return true; }
			public function delete(string $key): bool { unset($this->cacheStore[$key]); return true; }
			public function increment_counter(string $k, int $w): int { return 1; }
			public function get_counter(string $k): int { return 0; }
			public function get_behavior_profile(string $s): ?array { return null; }
			public function save_behavior_profile(string $s, array $p, int $t): bool { return true; }
			public function add_to_set(string $k, string $v, int $t): bool { return true; }
			public function get_set(string $k): array { return []; }
			public function get_geoip(string $ip): ?array { return null; }
			public function verify_challenge(string $r, string $ip): bool { return false; }
			public function log(string $l, string $m, array $c = []): void {}
		};
	} else {
		$adapter = new GenericAdapter();
	}

    // Load config from standard locations.
    $config = null;
    $config_paths = [
        __DIR__ . '/../config/bb_config.php',
        getenv('BB_CONFIG_PATH') ?: null,
    ];

    foreach (array_filter($config_paths) as $path) {
        if (file_exists($path)) {
            $raw = require $path;
            $config = is_array($raw) ? Configuration::from_array($raw, $adapter) : null;
            break;
        }
    }

    if ($config === null) {
        $config = new Configuration(adapter: $adapter);
    }

    // === Guard: ensure adapter can actually execute SQL ===
    try {
    	$adapter->query('SELECT 1');
    } catch (\RuntimeException $e) {
    	if (str_contains($e->getMessage(), 'GenericAdapter cannot execute SQL')) {
    		echo "No database adapter configured for CLI cleanup.\n\n";
    		echo "Options:\n";
    		echo "  1. Set BB_DB_DSN environment variable to a SQLite DSN:\n";
    		echo "     BB_DB_DSN=sqlite:/path/to/bad_behaviour.sqlite php bin/cleanup-logs.php\n";
    		echo "  2. Use a WackoWikiAdapter or MediaWikiAdapter with proper DB wiring.\n";
    		echo "  3. Configure a cache backend and adapter in config/bb_config.php.\n\n";
    		echo "See config/bb_config.example.php for log_retention settings.\n";
    		exit(1);
    	}
    	throw $e;
    }

    echo "[" . date('c') . "] BadBehaviour log retention cleanup\n\n";

    if (!$config->log_retention_enabled) {
        echo "log_retention.enabled is false. Exiting without changes.\n";
        echo "Set 'log_retention.enabled' => true in config/bb_config.php to enable.\n";
        exit(0);
    }

    echo "Settings:\n";
    echo sprintf("  max_age_days:            %d\n", $config->log_retention_max_age_days);
    echo sprintf("  max_rows:                %s\n",
        $config->log_retention_max_rows > 0 ? (string)$config->log_retention_max_rows : '(unlimited)');
    echo sprintf("  log_table:               %s\n", $adapter->get_settings()['log_table'] ?? '(unknown)');

    // Construct LogRetention directly (mirrors how bin/update-ip-ranges.php
    // bypasses the BadBehaviour class to avoid on-request gate overhead).
    $cache = $adapter instanceof \BadBehaviour\Core\Interfaces\CacheInterface ? $adapter : null;

    if ($cache === null) {
        echo "\nFATAL: Adapter does not implement CacheInterface — cannot coordinate mutex.\n";
        echo "Use a WackoWikiAdapter, MediaWikiAdapter, or configure an explicit cache.\n";
        exit(1);
    }

    $retention = new \BadBehaviour\Util\LogRetention(
        adapter: $adapter,
        config: $config,
        cache: $cache,
    );

    // Bypass all four gates — operator-invoked cleanup runs unconditionally.
    $result = $retention->force_cleanup_now();

    if ($result === null) {
        echo "\nFATAL: Cleanup returned null (unexpected for enabled retention).\n";
        exit(2);
    }

    $elapsed = round(microtime(true) - $start, 3);

    if ($result->error !== null) {
    	echo "\nFATAL: " . $result->error . "\n";
    	error_log("[BadBehaviour] CLI cleanup failed: " . $result->error);
    	exit(2);
    }

    echo "\nResult:\n";
    echo sprintf("  table:           %s\n", $result->log_table);
    echo sprintf("  limit_by:        %s\n", $result->limit_by);
    echo sprintf("  cutoff_computed: %s (%s)\n",
    	$result->cutoff_computed,
    	gmdate('Y-m-d H:i:s', $result->cutoff_computed));
    echo sprintf("  rows_deleted:    %d\n", $result->rows_deleted);
    echo sprintf("  iterations:      %d\n", $result->iterations);
    echo sprintf("  elapsed:         %.3fs\n", $elapsed);

    if ($result->rows_deleted === 0) {
    	echo "\nNothing to clean (table empty or no rows match cutoff).\n";
    	exit(0);
    }

    echo sprintf("\n✓ Cleaned %d rows from %s in %.3fs\n",
    	$result->rows_deleted, $result->log_table, $elapsed);
    exit(0);

} catch (\Throwable $e) {
    echo "FATAL: " . $e->getMessage() . "\n";
    error_log("[BadBehaviour] CLI cleanup failed: " . $e->getMessage());
    exit(2);
}