<?php
/**
 * bin/config-check.php
 *
 * Shows exactly which config file the adapter is loading
 * and why it's different from what Configuration::from_array() receives.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;

$adapter = new GenericAdapter();

// Check what file the adapter is loading
echo "=== Adapter config file resolution ===\n\n";

// For GenericAdapter, check production_config_path()
$reflection = new ReflectionClass($adapter);
if ($reflection->hasMethod('production_config_path')) {
	$method = $reflection->getMethod('production_config_path');
	$method->setAccessible(true);
	$file = $method->invoke($adapter);

	echo "CONFIG_DIR defined: " . (defined('CONFIG_DIR') ? 'YES (' . CONFIG_DIR . ')' : 'NO') . "\n";
	echo "CWD: " . getcwd() . "\n";
	echo "File adapter would load: " . ($file ?? 'NULL') . "\n";

	if ($file && file_exists($file)) {
		echo "File exists: YES\n";
		echo "File size: " . filesize($file) . " bytes\n";
		echo "Last modified: " . date('Y-m-d H:i:s', filemtime($file)) . "\n";
		echo "\n=== File contents ===\n";
		echo file_get_contents($file);
		echo "\n=== End file contents ===\n";
	} else {
		echo "File exists: NO\n";
		echo "\n=== Searching for bb_config.php ===\n";
		$candidates = [
			'config/bb_config.php',
			__DIR__ . '/../config/bb_config.php',
			__DIR__ . '/../vendor/badbehaviour/badbehaviour/config/bb_config.php',
		];
		foreach ($candidates as $candidate) {
			if (file_exists($candidate)) {
				echo "FOUND: $candidate\n";
			}
		}
	}
} else {
	echo "GenericAdapter doesn't have production_config_path()\n";
	echo "It uses get_settings() directly\n";
}

echo "\n=== What get_settings() actually returns ===\n";
$settings = $adapter->get_settings();
echo json_encode($settings, JSON_PRETTY_PRINT) . "\n";
