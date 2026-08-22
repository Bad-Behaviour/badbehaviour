<?php
declare(strict_types = 1);

require_once __DIR__ . '/../vendor/autoload.php';

// Define constants for testing
if (! defined('BB_CORE')) {
	define('BB_CORE', __DIR__ . '/../src');
}
if (! defined('BB_CWD')) {
	define('BB_CWD', __DIR__ . '/..');
}
if (! defined('BB_VERSION')) {
	define('BB_VERSION', '3.0.0-test');
}

// Ensure PHP settings for testing
ini_set('display_errors', '1');
error_reporting(E_ALL);

// Create whitelist file for tests if it doesn't exist
$whitelist_file = __DIR__ . '/../config/bb_whitelist.conf';
if (! file_exists($whitelist_file)) {
	@mkdir(dirname($whitelist_file), 0755, true);
	file_put_contents($whitelist_file, "; Auto-generated for tests\n");
}
