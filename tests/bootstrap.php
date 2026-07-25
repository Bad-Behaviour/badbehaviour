<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

// Define constants for testing
if (!defined('BB2_CORE')) {
    define('BB2_CORE', __DIR__ . '/../src');
}
if (!defined('BB2_CWD')) {
    define('BB2_CWD', __DIR__ . '/..');
}
if (!defined('BB2_VERSION')) {
    define('BB2_VERSION', '3.0.0-test');
}

// Ensure PHP settings for testing
ini_set('display_errors', '1');
error_reporting(E_ALL);
