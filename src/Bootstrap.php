<?php

/**
 * Bad Behaviour 3.0 - Bootstrap
 * Single entry point for all integrations
 */

declare(strict_types=1);

namespace BadBehaviour;

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Configuration;
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Core\Result;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Run Bad Behaviour with given configuration
 *
 * @param array<string, mixed> $config_overrides
 * @return Result
 */
function run(array $config_overrides = []): Result
{
	// Load settings.ini if exists
	$settings_file = __DIR__ . '/../settings.ini';
	$file_config = file_exists($settings_file)
		? parse_ini_file($settings_file, true)
		: [];

	// Merge: file config < overrides
	$merged = array_merge_recursive($file_config, $config_overrides);

	// Create adapter (can be swapped for MediaWiki/WackoWiki)
	$adapter = new GenericAdapter();

	// Build configuration object
	$config = Configuration::from_array($merged, $adapter);

	// Run
	$bb = new BadBehaviour($config);
	$result = $bb->run();

	// Handle blocked/challenge
	if (!$result->is_allowed()) {
		$bb->handle_result($result);
	}

	return $result;
}

/**
 * Quick check for middleware usage - returns true if blocked
 */
function check(array $config_overrides = []): bool
{
	$result = run($config_overrides);
	return !$result->is_allowed();
}
