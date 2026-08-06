<?php

declare(strict_types=1);

namespace BadBehaviour\Util;

use BadBehaviour\Core\Interfaces\AdapterInterface;

/**
 * Centralized error reporting for BadBehaviour.
 *
 * Every component of the library needs to report problems (config errors,
 * detector failures, DB issues, etc.) but we have three concerns:
 *
 *   1. Don't throw — logging must never crash the request
 *   2. Prefer the adapter's logger (so logs go to the host app's
 *      log destination — MediaWiki's logger, WackoWiki's log, etc.)
 *   3. Avoid log flooding — recurring errors on every request would
 *      fill the disk; use one-shot gating for repeated events
 *
 * Use these helpers instead of inline try/catch around error_log() everywhere.
 */
final class ErrorReporter
{
	/**
	 * Track which one-shot errors have already been reported this process.
	 * Keyed by a caller-supplied tag.
	 *
	 * @var array<string, true>
	 */
	private static array $reported = [];

	/**
	 * Track whether ANY fatal has been reported (for fatal_logged semantics).
	 */
	private static bool $fatal_logged = false;

	/**
	 * Report a non-fatal error.
	 *
	 * Prefers the adapter's `log()` method (so logs flow to the host app's
	 * logging system); falls back to PHP's `error_log()` if no adapter is
	 * available or it throws.
	 *
	 * @param AdapterInterface|null $adapter
	 * @param string $message
	 * @param array<string, mixed> $context
	 * @param string|null $once_tag If set, this error is reported AT MOST ONCE per
	 *                              process for this tag. Use for recurring problems
	 *                              (e.g., "DB connection failed" on every request).
	 */
	public static function error(
		?AdapterInterface $adapter,
		string $message,
		array $context = [],
		?string $once_tag = null
	): void {
		if ($once_tag !== null) {
			if (isset(self::$reported[$once_tag])) {
				return;
			}
			self::$reported[$once_tag] = true;
		}

		if ($adapter !== null && method_exists($adapter, 'log')) {
			try {
				$adapter->log('error', $message, $context);
				return;
			} catch (\Throwable $e) {
				// Adapter logger failed — fall through to error_log
			}
		}

		self::fallback_log('error', $message, $context);
	}

	/**
	 * Report a warning.
	 *
	 * @param AdapterInterface|null $adapter
	 * @param string $message
	 * @param array<string, mixed> $context
	 * @param string|null $once_tag
	 */
	public static function warning(
		?AdapterInterface $adapter,
		string $message,
		array $context = [],
		?string $once_tag = null
	): void {
		if ($once_tag !== null) {
			if (isset(self::$reported[$once_tag])) {
				return;
			}
			self::$reported[$once_tag] = true;
		}

		if ($adapter !== null && method_exists($adapter, 'log')) {
			try {
				$adapter->log('warning', $message, $context);
				return;
			} catch (\Throwable $e) {
				// fall through
			}
		}

		self::fallback_log('warning', $message, $context);
	}

	/**
	 * Report a fatal error.
	 *
	 * ONE fatal error is logged per PHP process — subsequent fatals are
	 * suppressed to avoid disk flooding (e.g., a buggy detector throwing
	 * on every request would otherwise fill the log with thousands of
	 * identical entries before anyone can react).
	 *
	 * @param \Throwable $e
	 * @param string $component Component name for log context (e.g., "BotDetector")
	 */
	public static function fatal(\Throwable $e, string $component = 'BadBehaviour'): void
	{
		if (self::$fatal_logged) {
			return;
		}
		self::$fatal_logged = true;

		try {
			error_log(sprintf(
				'[BadBehaviour FATAL] %s in %s: %s in %s:%d — request allowed as fallback. '
				. 'Hint: BadBehaviour caught this internally so your app stays online. '
				. 'Investigate the cause or disable the failing detector.',
				$component,
				get_class($e),
				$e->getMessage(),
				$e->getFile(),
				$e->getLine()
			));
		} catch (\Throwable $e2) {
			// Truly nothing we can do — the logging subsystem itself is broken
		}
	}

	/**
	 * Reset one-shot gates (mainly for tests).
	 */
	public static function reset(): void
	{
		self::$reported = [];
		self::$fatal_logged = false;
	}

	/**
	 * Last-resort logging via PHP's error_log().
	 */
	private static function fallback_log(string $level, string $message, array $context): void
	{
		try {
			$json = json_encode($context);
			error_log("[BadBehaviour] [$level] $message $json");
		} catch (\Throwable $e) {
			// Context serialization failed — log without it
			try {
				error_log("[BadBehaviour] [$level] $message");
			} catch (\Throwable $e2) {
				// Silent
			}
		}
	}

	private function __construct()
	{
		// Static class — no instances.
	}
}
