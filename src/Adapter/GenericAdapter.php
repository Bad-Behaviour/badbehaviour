<?php

namespace BadBehaviour\Adapter;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Configuration;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\SafeConfigLoader;
use BadBehaviour\Util\SafeMode;

class GenericAdapter implements AdapterInterface, CacheInterface
{
	private array $defaults = [
		'log_table' => 'bad_behaviour',
		'display_stats' => false,
	];

	// In-memory storage (not persistent - use Redis/Memcached in production)
	private array $counters = [];
	private array $behavior = [];
	private array $sets = [];

	private bool $safe_mode = false;
	private bool $config_loaded = false;

	/**
	 * The Configuration object — single source of truth.
	 *
	 * Set via set_configuration() after Configuration::from_array()
	 * builds it. Once set, get_settings() returns its array form
	 * instead of re-loading from disk.
	 *
	 * Why: prevents the adapter and Configuration from diverging.
	 * The adapter was previously loading from config/bb_config.php
	 * while Configuration::from_array() was given a different array
	 * (or vice versa), causing log_request() to see stale/wrong
	 * values like verbose=false when verbose=true was intended.
	 */
	private ?\BadBehaviour\Configuration $configuration = null;

	/**
	 * Is the adapter running in safe-mode (config missing or invalid)?
	 *
	 * Safe-mode = monitor-only: still logs traffic, but disables all
	 * active defenses (blocking, challenging, rate-limiting, etc.).
	 */
	public function is_safe_mode(): bool
	{
		return $this->safe_mode;
	}

	/**
	 * Did the config load successfully (vs falling back to defaults)?
	 */
	public function is_config_loaded(): bool
	{
		return $this->config_loaded;
	}

	public function get_settings(): array
	{
		// Single source of truth: the Configuration object if injected.
		//
		// BadBehaviour calls set_configuration() after building the
		// Configuration object. Once injected, get_settings() returns
		// its array form — guaranteeing the adapter sees exactly what
		// Configuration::from_array() built.
		//
		// Falls back to file loading only when no Configuration object
		// has been injected (legacy direct-adapter usage without
		// BadBehaviour bootstrap).
		if ($this->configuration !== null) {
			$config = $this->configuration->to_array();

			// Inject adapter-specific default if not set
			$config['log_table'] = $config['log_table'] ?? 'bad_behaviour';

			return $config;
		}

		// Legacy fallback: load from file (CONFIG_DIR or CWD-relative)
		$file = $this->production_config_path();

		if (file_exists($file)) {
			$config = SafeConfigLoader::load($file, $this, 'bb_config_load');
			if ($config !== null) {
				$this->safe_mode = false;
				$this->config_loaded = true;

				// Inject adapter-specific default if not set
				$config['log_table'] = $config['log_table'] ?? 'bad_behaviour';

				return $config;
			}
			// Load failed (parse error / bad return type / exception) — fall through
		}

		// No usable config found — enter safe-mode
		$this->safe_mode = true;
		$this->config_loaded = false;

		ErrorReporter::warning($this,
			'BadBehaviour config not found — running in safe-mode (monitor only)',
			[
				'hint' => 'Either define CONFIG_DIR (recommended for production) '
				. 'or run from a directory containing config/bb_config.php',
			],
			'bb_config_missing'
			);

		return SafeMode::settings('bad_behaviour');
	}

	/**
	 * Resolve the production config file location.
	 *
	 * GenericAdapter has no canonical application directory, so the
	 * resolution order is:
	 *
	 *   1. CONFIG_DIR/bb_config.php — preferred for production.
	 *      Operators using a custom bootstrap should define CONFIG_DIR
	 *      pointing at their application's config directory.
	 *
	 *   2. config/bb_config.php — CWD-relative. Fine for CLI tools and
	 *      test harnesses; ambiguous in web context. Logged as a warning
	 *      so operators know to set CONFIG_DIR.
	 *
	 * The package directory (vendor/badbehaviour/.../config/bb_config.php)
	 * is intentionally excluded — that file exists only as a unit-test
	 * fixture and is not safe for production use.
	 *
	 * @return string Path to config/bb_config.php, never empty.
	 */
	private function production_config_path(): string
	{
		if (defined('CONFIG_DIR') && is_dir(CONFIG_DIR)) {
			$candidate = CONFIG_DIR . '/bb_config.php';
			if (file_exists($candidate)) {
				return $candidate;
			}
		}

		$cwd_candidate = 'config/bb_config.php';
		if (file_exists($cwd_candidate)) {
			// Warn once per process: this resolution path is fine for CLI
			// and tests but is ambiguous in web context. If you're seeing
			// this warning in production logs, your CONFIG_DIR isn't
			// being defined before BadBehaviour boots.
			ErrorReporter::warning($this,
				'GenericAdapter resolving config/bb_config.php via CWD; '
				. 'production deployments should define CONFIG_DIR',
				[
					'resolved_path' => realpath($cwd_candidate) ?: $cwd_candidate,
					'cwd' => getcwd(),
					'hint' => 'Define CONFIG_DIR in your bootstrap (e.g., '
					. '`define(\'CONFIG_DIR\', __DIR__ . \'/config\');`) '
					. 'before instantiating GenericAdapter.',
				],
				'bb_config_cwd_relative'  // once-tag
				);
			return $cwd_candidate;
		}

		// Caller (get_settings) will fall through to safe-mode.
		return $cwd_candidate;
	}

	public function get_whitelist(): array
	{
		$file = __DIR__ . '/../../../config/bb_whitelist.conf';

		// Use @ to suppress warning if file doesn't exist
		$parsed = @parse_ini_file($file, true, INI_SCANNER_TYPED);

		// parse_ini_file returns false on failure (missing file, parse error)
		if ($parsed === false) {
			return [
				'ip' => [],
				'useragent' => [],
				'url' => [],
				'asn' => [],
				'country' => [],
			];
		}

		return $parsed;
	}

	public function get_email(): string
	{
		return 'admin@example.com';
	}

	/**
	 * Inject the Configuration object as the single source of truth.
	 *
	 * Called by BadBehaviour's bootstrap after Configuration::from_array().
	 * Once set, get_settings() returns the Configuration's array form
	 * instead of re-loading from disk.
	 *
	 * Defensive: never throws. If the configuration is invalid, logs
	 * a warning and continues to use file-based loading as fallback.
	 */
	public function set_configuration(\BadBehaviour\Configuration $config): void
	{
		$this->configuration = $config;
		// Mark config as loaded — we have authoritative settings now
		$this->config_loaded = true;
		$this->safe_mode = false;
	}

	public function get_relative_path(): string
	{
		return '/';
	}

	public function get_table_schema(string $table_name): string
	{
		$name = preg_replace('/[^a-zA-Z0-9_]/', '', $table_name);
		return <<<SQL
CREATE TABLE IF NOT EXISTS `$name` (
	`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`ip` VARCHAR(45) NOT NULL,
	`date` DATETIME NOT NULL,
	`method` VARCHAR(8) NOT NULL,
	`uri` VARCHAR(2048) NOT NULL,
	`ua` TEXT,
	`status_code` VARCHAR(50) NOT NULL,
	`status_message` TEXT,
	`support_key` VARCHAR(64),
	`bot_category` VARCHAR(32),
	`bot_verified` BOOLEAN DEFAULT FALSE,
	`ja3` CHAR(32),
	`h2_hash` CHAR(16),
	`header_order_hash` CHAR(16),
	`asn` VARCHAR(32),
	`country` CHAR(2),
	`request_time_ms` INT UNSIGNED,
	`enforcement_action` VARCHAR(16) NOT NULL DEFAULT 'enforced',
	`original_code` VARCHAR(50) NULL,
	PRIMARY KEY (`id`),
	KEY `idx_ip` (`ip`),
	KEY `idx_status` (`status_code`),
	KEY `idx_date` (`date`),
	KEY `idx_bot` (`bot_category`, `bot_verified`),
	KEY `idx_enforcement` (`enforcement_action`, `date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL;
	}

	public function log_request(RequestPackage $package, Result $result): void
	{
		// No-op for generic adapter - implement in specific adapters
		// (kept defensive: never throw, even if subclassing misbehaves)
		// NOTE: For actual logging, use WackoWikiAdapter or MediaWikiAdapter.
		// GenericAdapter doesn't persist logs.
	}

	public function query(string $sql): bool
	{
		// Generic adapter has no DB connection by default
		return false;
	}

	// CacheInterface implementation
	public function get(string $key): mixed
	{
		return null;
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		return true;
	}

	public function delete(string $key): bool
	{
		unset($this->counters[$key], $this->behavior[$key], $this->sets[$key]);
		return true;
	}

	public function increment_counter(string $key, int $window): int
	{
		try {
			$now = time();
			$window_start = $now - $window;

			if (!isset($this->counters[$key]) || $this->counters[$key]['window'] < $window_start) {
				$this->counters[$key] = ['count' => 0, 'window' => $window_start];
			}

			return ++$this->counters[$key]['count'];
		} catch (\Throwable $e) {
			return 0;
		}
	}

	public function get_counter(string $key): int
	{
		try {
			return $this->counters[$key]['count'] ?? 0;
		} catch (\Throwable $e) {
			return 0;
		}
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		try {
			return $this->behavior[$session_id] ?? null;
		} catch (\Throwable $e) {
			return null;
		}
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		try {
			$this->behavior[$session_id] = $profile;
			return true;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		try {
			if (!isset($this->sets[$key])) {
				$this->sets[$key] = [];
			}
			$this->sets[$key][$value] = time() + $ttl;
			return true;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function get_set(string $key): array
	{
		try {
			$now = time();
			$set = $this->sets[$key] ?? [];
			$set = array_filter($set, fn($exp) => $exp > $now);
			$this->sets[$key] = $set;
			return array_keys($set);
		} catch (\Throwable $e) {
			return [];
		}
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
	{
		// Adapter logger contract — called by core / detectors / utilities.
		// Never let logging throw.
		try {
			error_log("[BadBehaviour] [$level] $message " . json_encode($context));
		} catch (\Throwable $e) {
			// Last-resort: silent fail
		}
	}
}
