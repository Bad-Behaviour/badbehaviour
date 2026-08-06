<?php

declare(strict_types=1);

namespace BadBehaviour\Util;

use BadBehaviour\Core\Interfaces\AdapterInterface;

/**
 * Safe config loader shared by all adapters.
 *
 * Loading bb_config.php can fail in many ways:
 *   - File doesn't exist
 *   - Syntax error (ParseError)
 *   - File throws an exception during require
 *   - File returns something other than an array
 *
 * Each of these used to be handled inline in every adapter, leading to
 * duplicated try/catch blocks. This utility centralizes that logic.
 *
 * Adapters call `SafeConfigLoader::load($path, $adapter)` and receive
 * either the loaded config array OR null (in which case the adapter
 * falls back to safe-mode defaults).
 */
final class SafeConfigLoader
{
	/**
	 * Attempt to load and validate a config file.
	 *
	 * Returns the loaded config array on success, or null on any failure
	 * (file missing, parse error, non-array return, exception during
	 * require). Errors are logged via the adapter logger or error_log.
	 *
	 * @param string $path Absolute path to the config file
	 * @param AdapterInterface|null $adapter Optional adapter for logging context
	 * @param string|null $once_tag One-shot tag for error dedup
	 * @return array<string, mixed>|null
	 */
	public static function load(
		string $path,
		?AdapterInterface $adapter = null,
		?string $once_tag = null
	): ?array {
		// Suppress parse errors; we catch the exception explicitly
		try {
			$config = @require $path;
		} catch (\ParseError $e) {
			ErrorReporter::error($adapter, 'BadBehaviour config has syntax error', [
				'path' => $path,
				'error' => $e->getMessage(),
				'line' => $e->getLine(),
				'hint' => 'Check the config file for syntax errors (missing semicolons, unmatched brackets, etc.)',
			], $once_tag);
			return null;
		} catch (\Throwable $e) {
			ErrorReporter::error($adapter, 'BadBehaviour config failed to load', [
				'path' => $path,
				'error' => $e->getMessage(),
				'exception_class' => get_class($e),
			], $once_tag);
			return null;
		}

		if (!is_array($config)) {
			ErrorReporter::error($adapter, 'BadBehaviour config must return an array', [
				'path' => $path,
				'actual_type' => gettype($config),
				'hint' => 'config file must end with: return [ /* ... */ ];',
			], $once_tag);
			return null;
		}

		return $config;
	}

	/**
	 * Check if a config file exists at any of the candidate paths.
	 *
	 * @param array<string|null> $candidates
	 * @return string|null First existing path, or null
	 */
	public static function find_existing(array $candidates): ?string
	{
		foreach (array_filter($candidates) as $path) {
			if (is_string($path) && file_exists($path)) {
				return $path;
			}
		}
		return null;
	}

	private function __construct()
	{
		// Static class — no instances.
	}
}
