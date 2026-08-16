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
    $adapter = new GenericAdapter();

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