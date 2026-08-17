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

if (!defined('CACHE_DIR')) {
	define('CACHE_DIR', sys_get_temp_dir() . '/badbehaviour_cache');
}

class WackoWikiAdapter implements AdapterInterface, CacheInterface
{
	private $db;
	private string $cache_dir;
	private bool $safe_mode = false;
	private bool $config_loaded = false;

	/**
	 * The Configuration object — single source of truth.
	 *
	 * Set via set_configuration() after Configuration::from_array()
	 * builds it. Once set, get_settings() returns its array form
	 * instead of re-loading from disk.
	 */
	private ?\BadBehaviour\Configuration $configuration = null;

	public function __construct($db)
	{
		$this->db = $db;
		$this->cache_dir = CACHE_DIR . '/bad_behaviour/';
		@mkdir($this->cache_dir, 0755, true);
	}

	/**
	 * Is the adapter running in safe-mode (config missing or invalid)?
	 *
	 * Safe-mode = monitor-only: still logs traffic, but disables all
	 * active defenses (blocking, challenging, rate-limiting, etc.).
	 * This prevents a misconfigured library from breaking the host app.
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

	// =========================================================================
	// SETTINGS — Single source: config/bb_config.php
	// =========================================================================

	public function get_settings(): array
	{
		// Single source of truth: the Configuration object if injected.
		//
		// BadBehaviour calls set_configuration() after building the
		// Configuration object. Once injected, get_settings() returns
		// its array form — guaranteeing the adapter sees exactly what
		// Configuration::from_array() built.
		//
		// This prevents the divergence bug where the adapter loaded from
		// disk (with different values) while Configuration was built from
		// a different array, causing log_request() to use wrong values.
		//
		// Falls back to file loading only when no Configuration object
		// has been injected (legacy behavior for backward compatibility).
		if ($this->configuration !== null) {
			$config = $this->configuration->to_array();

			// INJECT adapter-specific setting that must NOT come from config
			$prefix = $this->db->table_prefix ?? '';
			$config['log_table'] = $prefix . 'bad_behaviour';

			return $config;
		}

		// Legacy fallback: load from file (CONFIG_DIR/bb_config.php)
		$file = $this->production_config_path();

		if ($file !== null) {
			$config = SafeConfigLoader::load($file, $this, 'bb_config_load');
			if ($config !== null) {
				$this->safe_mode = false;
				$this->config_loaded = true;

				// INJECT adapter-specific setting that must NOT come from config
				$prefix = $this->db->table_prefix ?? '';
				$config['log_table'] = $prefix . 'bad_behaviour';

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
				'expected_path' => defined('CONFIG_DIR')
				? CONFIG_DIR . '/bb_config.php'
				: 'CONFIG_DIR not defined',
				'hint' => 'Create config/bb_config.php from config/bb_config.sample.php to enable full protection',
			],
			'bb_config_missing'
			);

		return $this->safe_mode_settings();
	}

	/**
	 * Resolve the production config file location for WackoWiki.
	 *
	 * === RESOLUTION ORDER ===
	 *
	 *   1. BB_CONFIG_FILE constant (explicit override)
	 *      Set this in your WackoWiki bootstrap if the auto-resolve
	 *      heuristics don't match your install layout:
	 *
	 *          define('BB_CONFIG_FILE', __DIR__ . '/config/bb_config.php');
	 *
	 *      This is the recommended path for production — it bypasses
	 *      the fragile CONFIG_DIR-relative logic that breaks when
	 *      CONFIG_DIR is set to a relative segment like 'config'
	 *      (which is WackoWiki's default).
	 *
	 *   2. CONFIG_DIR + '/bb_config.php'
	 *      WackoWiki's CONFIG_DIR constant. Must point at a directory
	 *      that actually contains bb_config.php. If the constant is
	 *      defined but points to the wrong place (e.g., relative
	 *      'config' that doesn't resolve from the FPM CWD), this
	 *      branch logs a one-shot warning and falls through.
	 *
	 *   3. CWD-relative 'config/bb_config.php'
	 *      Legacy fallback. Works for CLI tools and test harnesses;
	 *      ambiguous in web context where PHP-FPM's CWD is the
	 *      document root, not the application root. If this hits,
	 *      log a one-shot warning suggesting the BB_CONFIG_FILE
	 *      override.
	 *
	 * The package directory is intentionally excluded as a final
	 * fallback — that file exists only as a unit-test fixture and
	 * is NOT safe for production use.
	 *
	 * === WHY THE BB_CONFIG_FILE OVERRIDE ===
	 *
	 * WackoWiki's config/constants.php defines:
	 *
	 *     const CONFIG_DIR = 'config';
	 *
	 * which is a *relative* segment. PHP-FPM workers' CWD is usually
	 * the document root, not the application root, so
	 * CONFIG_DIR . '/bb_config.php' resolves to <docroot>/config/bb_config.php
	 * — typically wrong. WackoWikiAdapter historically trusted this
	 * resolution without validation, which silently dropped the
	 * library into safe-mode in production.
	 *
	 * BB_CONFIG_FILE lets operators point at the exact file with no
	 * ambiguity. Set it once in the bootstrap and forget about it.
	 *
	 * @return string|null Absolute path to bb_config.php, or null
	 *                     if not resolvable (caller should enter safe-mode).
	 */
	private function production_config_path(): ?string
	{
		// === 1. Explicit override (recommended for production) ===
		if (defined('BB_CONFIG_FILE')) {
			$candidate = BB_CONFIG_FILE;

			if (!is_string($candidate) || $candidate === '') {
				ErrorReporter::warning($this,
					'WackoWikiAdapter: BB_CONFIG_FILE defined but empty or non-string; '
					. 'cannot locate bb_config.php',
					[
						'hint' => 'Set BB_CONFIG_FILE to the absolute path of '
						. 'bb_config.php in your bootstrap, e.g.: '
						. '`define(\'BB_CONFIG_FILE\', __DIR__ . \'/config/bb_config.php\');`',
					],
					'bb_wacko_bb_config_file_empty'
					);
			} elseif (!file_exists($candidate)) {
				ErrorReporter::warning($this,
					'WackoWikiAdapter: BB_CONFIG_FILE defined but file does not exist',
					[
						'defined_path' => $candidate,
						'hint'         => 'Either create bb_config.php at this location '
						. 'or correct the BB_CONFIG_FILE definition in your bootstrap.',
					],
					'bb_wacko_bb_config_file_missing'
					);
			} else {
				return $candidate;
			}

			// Fall through to other resolution paths — the override was
			// present but invalid, so don't bail without trying.
		}

		// === 2. CONFIG_DIR + '/bb_config.php' ===
		//
		// WackoWiki sets CONFIG_DIR in config/constants.php. The historical
		// value is the relative segment 'config', which doesn't resolve
		// correctly under PHP-FPM (CWD ≠ application root). Validate the
		// result before trusting it; if it points at a non-existent file,
		// warn loudly and fall through to the next branch.
		if (defined('CONFIG_DIR')) {
			$config_dir = CONFIG_DIR;

			// Guard against empty or non-string values — defensive against
			// future WackoWiki changes that might accidentally unset the
			// constant or assign it a non-string.
			if (!is_string($config_dir) || $config_dir === '') {
				ErrorReporter::warning($this,
					'WackoWikiAdapter: CONFIG_DIR defined but empty or non-string',
					[
						'actual_type' => get_debug_type($config_dir),
						'hint'        => 'WackoWiki\'s CONFIG_DIR constant must be a '
						. 'non-empty string. Either fix the constant definition or '
						. 'define BB_CONFIG_FILE in your bootstrap.',
					],
					'bb_wacko_config_dir_empty'
					);
			} else {
				$candidate = $config_dir . '/bb_config.php';

				if (file_exists($candidate)) {
					return $candidate;
				}

				// CONFIG_DIR is defined but points at the wrong place.
				// This is the most common production failure mode —
				// WackoWiki sets CONFIG_DIR = 'config' (relative), PHP-FPM's
				// CWD is the docroot, and 'config/bb_config.php' doesn't
				// exist there. Warn loudly so operators can fix it.
				ErrorReporter::warning($this,
					'WackoWikiAdapter: CONFIG_DIR defined but bb_config.php not found at '
					. $candidate,
					[
						'config_dir'    => $config_dir,
						'expected_path' => $candidate,
						'cwd'           => getcwd() ?: '(unknown)',
						'hint'          => 'WackoWiki\'s CONFIG_DIR constant is set to a '
						. 'relative path that does not resolve from PHP-FPM\'s CWD. '
						. 'Define BB_CONFIG_FILE in your bootstrap with the absolute '
						. 'path, e.g.: '
						. '`define(\'BB_CONFIG_FILE\', __DIR__ . \'/config/bb_config.php\');`',
					],
					'bb_wacko_config_dir_unresolved'
					);
				// Fall through — let subsequent branches try.
			}
		}

		// === 3. CWD-relative 'config/bb_config.php' ===
		//
		// Legacy fallback. Works for CLI tools and test harnesses run
		// from the application root; ambiguous under PHP-FPM. Log a
		// one-shot warning when this branch is the one that succeeds,
		// so operators know to set the explicit override for cleaner
		// resolution.
		$cwd_candidate = 'config/bb_config.php';
		if (file_exists($cwd_candidate)) {
			ErrorReporter::warning($this,
				'WackoWikiAdapter: resolving bb_config.php via CWD-relative path; '
				. 'production deployments should define BB_CONFIG_FILE',
				[
					'resolved_path' => realpath($cwd_candidate) ?: $cwd_candidate,
					'cwd'           => getcwd() ?: '(unknown)',
					'hint'          => 'Add `define(\'BB_CONFIG_FILE\', __DIR__ . '
					. '\'/config/bb_config.php\');` to your bootstrap before '
					. 'BadBehaviour boots. This bypasses the fragile CWD-relative '
					. 'fallback.',
				],
				'bb_wacko_config_cwd_relative'
				);
			return $cwd_candidate;
		}

		// === Resolution failed ===
		//
		// None of the three branches succeeded. Caller (get_settings)
		// will fall through to safe-mode. ErrorReporter::warning() calls
		// above already recorded WHY each branch failed, so the operator
		// has the diagnostic context they need.
		return null;
	}

	/**
	 * Safe-mode settings for WackoWiki.
	 *
	 * Returns the shared safe-mode baseline with the WackoWiki-specific
	 * log_table (prefixed by the wiki's table prefix).
	 */
	private function safe_mode_settings(): array
	{
		$prefix = $this->db->table_prefix ?? '';
		return SafeMode::settings($prefix . 'bad_behaviour');
	}

	// =========================================================================
	// WHITELIST
	// =========================================================================

	public function get_whitelist(): array
	{
		$file = defined('CONFIG_DIR') ? CONFIG_DIR . '/bb_whitelist.conf' : 'config/bb_whitelist.conf';

		if (!file_exists($file)) {
			return [
				'ip' => [],
				'useragent' => [],
				'url' => [],
				'asn' => [],
				'country' => [],
			];
		}

		// Whitelist stays INI (flat, simple, human-editable)
		$parsed = @parse_ini_file($file, true, INI_SCANNER_TYPED);
		if ($parsed === false) {
			ErrorReporter::warning($this, 'BadBehaviour whitelist parse error', [
				'path' => $file,
				'hint' => 'Check bb_whitelist.conf for syntax errors',
			], 'bb_whitelist_parse');
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

	/**
	 * Inject the Configuration object as the single source of truth.
	 *
	 * Called by BadBehaviour's bootstrap after Configuration::from_array().
	 * Once set, get_settings() returns the Configuration's array form
	 * instead of re-loading from disk.
	 */
	public function set_configuration(\BadBehaviour\Configuration $config): void
	{
		$this->configuration = $config;
		$this->config_loaded = true;
		$this->safe_mode = false;
	}

	// =========================================================================
	// EMAIL / PATHS
	// =========================================================================

	public function get_email(): string
	{
		try {
			return $this->db->abuse_email ?? 'admin@example.com';
		} catch (\Throwable $e) {
			return 'admin@example.com';
		}
	}

	public function get_relative_path(): string
	{
		return '/';
	}

	// =========================================================================
	// DATABASE / LOGGING
	// =========================================================================

	public function get_table_schema(string $table_name): array
	{
		$name = $table_name;
		$sqlite = $this->db->is_sqlite;

		if ($sqlite) {
			return [
				// BB 3.0 schema — see docs/CONFIGURATION.md for the full rationale.
				// Notable changes vs the 3.0 pre-release:
				//   * host:            VARCHAR(2083) → VARCHAR(253)   [RFC 1035 max hostname]
				//   * *_hash columns:   CHAR(40) SHA-1 → CHAR(16) half-SHA-256 [admin grouping only]
				//   * status_code:     VARCHAR(50) → VARCHAR(32)       [longest enum value = 26 chars]
				//   * status_message:  TEXT → VARCHAR(255)             [dynamic context, capped]
				//   * h2_hash:         DROPPED                        [was empty in 99% of rows]
				//   * header_order_hash: DROPPED                       [was empty in 99% of rows]
				//   * ip:              VARCHAR(45) KEPT                [human-readable, admin-facing]
				"CREATE TABLE IF NOT EXISTS \"{$name}\" (
					\"log_id\" INTEGER PRIMARY KEY AUTOINCREMENT,
					\"ip\" VARCHAR(45) NOT NULL DEFAULT '',
					\"host\" VARCHAR(253) NOT NULL DEFAULT '',
					\"date\" DATETIME NULL,
					\"request_method\" VARCHAR(8) NOT NULL DEFAULT '',
					\"request_uri\" VARCHAR(2048) NOT NULL DEFAULT '',
					\"request_uri_hash\" CHAR(16) NOT NULL DEFAULT '',
					\"server_protocol\" VARCHAR(12) NOT NULL DEFAULT '',
					\"http_headers\" TEXT NOT NULL,
					\"user_agent\" TEXT NULL,
					\"user_agent_hash\" CHAR(16) NOT NULL DEFAULT '',
					\"request_entity\" TEXT DEFAULT NULL,
					\"status_code\" VARCHAR(32) NOT NULL DEFAULT '',
					\"status_message\" VARCHAR(255),
					\"support_key\" VARCHAR(64),
					\"bot_category\" VARCHAR(32),
					\"bot_verified\" BOOLEAN DEFAULT 0,
					\"ja3\" CHAR(32),
					\"asn\" VARCHAR(32),
					\"country\" CHAR(2),
					\"request_time_ms\" INTEGER UNSIGNED,
					\"enforcement_action\" VARCHAR(16) NOT NULL DEFAULT 'enforced',
					\"original_code\" VARCHAR(50) DEFAULT NULL,
					\"resolved_at\" DATETIME NULL DEFAULT NULL,
					\"check\" TINYINT(1) NOT NULL DEFAULT 0
				);",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_ip\" ON \"{$name}\" (\"ip\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_status\" ON \"{$name}\" (\"status_code\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_date\" ON \"{$name}\" (\"date\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_bot\" ON \"{$name}\" (\"bot_category\", \"bot_verified\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_ua_hash\" ON \"{$name}\" (\"user_agent_hash\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_uri_hash\" ON \"{$name}\" (\"request_uri_hash\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_method\" ON \"{$name}\" (\"request_method\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_enforcement\" ON \"{$name}\" (\"enforcement_action\", \"date\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_check\" ON \"{$name}\" (\"check\");",
				];
		}
		else {
			return [
				// BB 3.0 schema — see docs/CONFIGURATION.md for the full rationale.
				// Notable changes vs the 3.0 pre-release:
				//   * host:             VARCHAR(2083) → VARCHAR(253)  [RFC 1035 max hostname]
				//   * *_hash columns:   CHAR(40) SHA-1 → CHAR(16) half-SHA-256 [admin grouping only]
				//   * status_code:      VARCHAR(50) → VARCHAR(32)      [longest enum value = 26 chars]
				//   * status_message:   TEXT → VARCHAR(255)            [dynamic context, capped]
				//   * h2_hash:          DROPPED                       [was empty in 99% of rows]
				//   * header_order_hash: DROPPED                       [was empty in 99% of rows]
				//   * ip:               VARCHAR(45) KEPT               [human-readable, admin-facing]
				//   * http_headers:     TEXT → MEDIUMTEXT              [up to 16MB; was capped at 64KB]
				//   * request_entity:   TEXT → MEDIUMTEXT              [same]
				"CREATE TABLE IF NOT EXISTS `$name` (
					`log_id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
					`ip` VARCHAR(45) NOT NULL DEFAULT '',
					`host` VARCHAR(253) NOT NULL DEFAULT '',
					`date` DATETIME NOT NULL,
					`request_method` VARCHAR(8) NOT NULL DEFAULT '',
					`request_uri` VARCHAR(2048) NOT NULL DEFAULT '',
					`request_uri_hash` CHAR(16) NOT NULL DEFAULT '',
					`server_protocol` VARCHAR(12) NOT NULL DEFAULT '',
					`http_headers` MEDIUMTEXT NOT NULL,
					`user_agent` TEXT,
					`user_agent_hash` CHAR(16) NOT NULL DEFAULT '',
					`request_entity` MEDIUMTEXT DEFAULT NULL,
					`status_code` VARCHAR(32) NOT NULL DEFAULT '',
					`status_message` VARCHAR(255),
					`support_key` VARCHAR(64),
					`bot_category` VARCHAR(32),
					`bot_verified` BOOLEAN DEFAULT 0,
					`ja3` CHAR(32),
					`asn` VARCHAR(32),
					`country` CHAR(2),
					`request_time_ms` INT UNSIGNED,
					`enforcement_action` VARCHAR(16) NOT NULL DEFAULT 'enforced',
					`original_code` VARCHAR(50) NULL,
					`resolved_at` DATETIME NULL DEFAULT NULL,
					`check` TINYINT(1) NOT NULL DEFAULT 0,
				PRIMARY KEY (`log_id`),
				KEY `idx_ip` (`ip`),
				KEY `idx_status` (`status_code`),
				KEY `idx_date` (`date`),
				KEY `idx_bot` (`bot_category`, `bot_verified`),
				KEY `idx_user_agent_hash` (`user_agent_hash`),
				KEY `idx_request_uri_hash` (`request_uri_hash`),
				KEY `idx_request_method` (`request_method`),
				KEY `idx_enforcement` (`enforcement_action`, `date`),
				KEY `idx_check` (`check`)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
			];
		}
	}

	public function probe_log_table(string $table_name): array
	{
		$safe = preg_replace('/[^a-zA-Z0-9_]/', '', $table_name);
		if ($safe === '' || $safe === null) {
			return ['newest' => null, 'total' => 0, 'error' => 'invalid_table_name'];
		}

		try {
			$result = $this->db->ll_query("SELECT MAX(`date`) AS newest, COUNT(*) AS total FROM `{$safe}`");
			if (!$result) {
				return ['newest' => null, 'total' => 0, 'error' => null];
			}
			$row = $this->db->fetch_assoc($result) ?: ['newest' => null, 'total' => 0];
			return [
				'newest' => $row['newest'] ?? null,
				'total'  => (int)($row['total'] ?? 0),
				'error'  => null,
			];
		} catch (\Throwable $e) {
			return [
				'newest' => null,
				'total'  => 0,
				'error'  => $e->getMessage(),
			];
		}
	}

	/**
	 * Set the `check` flag on a single log row.
	 *
	 * Used by the admin UI to mark records the operator wants to keep an eye on
	 * (typical use case: false positives to investigate later, entries to share
	 * with a colleague, suspicious patterns to whitelist before autodelete kicks
	 * in). Checked rows are exempt from automatic log retention cleanup — the
	 * retention service MUST include `AND check = 0` in its DELETE WHERE clause
	 * (see get_log_retention() JSDoc for the full contract).
	 *
	 * Idempotent: setting an already-checked row to true is a no-op (returns
	 * true). Setting to false clears the flag regardless of prior state.
	 *
	 * Validation:
	 *   - log_id must be > 0 (defensive against bad dispatch)
	 *   - table name comes from get_settings()['log_table'], sanitized via
	 *     preg_replace to disallow anything but [a-zA-Z0-9_]
	 *
	 * @param int  $log_id  Primary key from the log table.
	 * @param bool $checked New value for the `check` column.
	 * @return bool         true on success, false on DB failure (already logged).
	 */
	public function set_log_check(int $log_id, bool $checked): bool
	{
		// === Validate inputs ===
		if ($log_id <= 0)
		{
			return false;
		}

		// Resolve + sanitize table name from current settings. Falls back to the
		// adapter's default if settings haven't loaded (e.g. early bootstrap).
		$settings = $this->get_settings();
		$table = $settings['log_table'] ?? (($this->db->table_prefix ?? '') . 'bad_behaviour');

		$safe = preg_replace('/[^a-zA-Z0-9_]/', '', $table);
		if ($safe === '' || $safe === null)
		{
			return false;
		}

		$val = $checked ? 1 : 0;
		// Note: `check` is a reserved word in MySQL 8+ in some contexts, but is
		// perfectly valid as a column identifier when backtick-quoted. Both
		// drivers handle this without issue.
		$sql = "UPDATE `{$safe}` SET `check` = {$val} WHERE `log_id` = " . (int)$log_id;

		try
		{
			$result = $this->db->ll_query($sql);
			return $result !== false;
		}
		catch (\Throwable $e)
		{
			ErrorReporter::error($this, 'set_log_check failed', [
				'log_id'  => $log_id,
				'checked' => $checked,
				'table'   => $safe,
				'error'   => $e->getMessage(),
			], 'set_log_check_failure');
			return false;
		}
	}

	public function log_request(RequestPackage $package, Result $result): void
	{
		// CRITICAL: never let logging failures crash the request.
		// Wrap the entire body in try/catch so the response always succeeds.
		try {
			$settings = $this->get_settings();
			if (empty($settings['logging'])) {
				return;
			}

			$table = $settings['log_table'] ?? (($this->db->table_prefix ?? '') . 'bad_behaviour');

			$q = $this->db->q(...);

			$ip       = $q($package->ip);
			$host     = $q(@gethostbyaddr($package->ip) ?: $package->ip);
			$date     = $q(gmdate('Y-m-d H:i:s'));
			$method   = $q($package->request_method);
			$uri      = $q($package->request_uri);
			// BB 3.0: hash shortened to 16 hex chars (half of SHA-256). Used only for
			// grouping/filtering in the admin UI — not a cryptographic identifier.
			// Collisions at 100k rows: ~0.0003% per row pair; acceptable for that use.
			$uri_hash = $q(substr(hash('sha256', $package->request_uri), 0, 16));
			$protocol = $q($package->server_protocol);
			$ua       = $q($package->user_agent);
			$ua_hash  = $q(substr(hash('sha256', $package->user_agent), 0, 16));

			// Build raw headers string WITHOUT individual quoting
			$headers = "$method $uri $protocol\n";
			foreach ($package->headers_mixed as $h => $v) {
				$headers .= "$h: $v\n";
			}
			$headers = $q($headers);

			$request_entity = '';
			if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
				foreach ($package->request_entity as $k => $v) {
					$request_entity .= "$k: $v\n";
				}
			}
			$request_entity = $q($request_entity);

			$status_key = $result->code->value;
			$status_message = $q($result->message);
			$support_key = $q($result->support_key ?? '');
			$bot_category = $q($result->metadata['bot_category'] ?? '');
			$bot_verified = ($result->metadata['bot_verified'] ?? false) ? 1 : 0;
			$ja3 = $q($package->ja3 ?? '');
			// h2_hash and header_order_hash dropped — see schema comment.
			$asn = $q($package->asn ?? '');
			$country = $q($package->country ?? '');
			$time_ms = (int)($package->request_time * 1000);
			$enforcement = $q($result->enforcement->value);
			$original_code = $q($result->metadata['original_code'] ?? '');

			$sql = "INSERT INTO `$table`
				(`ip`,`host`,`date`,`request_method`,`request_uri`,`request_uri_hash`,`server_protocol`,
				 `http_headers`,`user_agent`,`user_agent_hash`,`request_entity`,`status_code`,`status_message`,
				 `support_key`,`bot_category`,`bot_verified`,`ja3`,`asn`,`country`,`request_time_ms`,
				 `enforcement_action`,`original_code`)
				VALUES ($ip,$host,$date,$method,$uri,$uri_hash,$protocol,$headers,$ua,$ua_hash,$request_entity,
				        '$status_key',$status_message,$support_key,$bot_category,$bot_verified,$ja3,$asn,$country,$time_ms,
				        $enforcement,$original_code)";

			$this->db->ll_query($sql);
		} catch (\Throwable $e) {
			// Never propagate — logging must not crash the user's response.
			ErrorReporter::error($this, 'log_request failed', [
				'error' => $e->getMessage(),
				'exception_class' => get_class($e),
				'hint' => 'Check DB connectivity and log table schema',
			], 'log_request_failure');
		}
	}

	public function query(string $sql)
	{
		try {
			return $this->db->ll_query($sql);
		} catch (\Throwable $e) {
			ErrorReporter::error($this, 'BadBehaviour query failed', [
				'sql_preview' => substr($sql, 0, 200),
				'error' => $e->getMessage(),
			], 'query_failure');
			return false;
		}
	}

	// =========================================================================
	// CACHE (CacheInterface) — File-based
	// =========================================================================

	private function cache_file(string $key): string
	{
		return $this->cache_dir . md5($key) . '.json';
	}

	public function get(string $key): mixed
	{
		try {
			$file = $this->cache_file($key);
			if (!file_exists($file)) return null;
			$data = json_decode(@file_get_contents($file), true);
			return $data['value'] ?? null;
		} catch (\Throwable $e) {
			return null;
		}
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		try {
			$file = $this->cache_file($key);
			$data = ['value' => $value, 'expires' => time() + $ttl];
			return @file_put_contents($file, json_encode($data), LOCK_EX) !== false;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function delete(string $key): bool
	{
		try {
			$file = $this->cache_file($key);
			return @unlink($file);
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function increment_counter(string $key, int $window): int
	{
		try {
			$file = $this->cache_file("counter:$key");
			$now = time();
			$window_start = $now - $window;

			$data = ['count' => 0, 'window' => $window_start];
			if (file_exists($file)) {
				$json = @file_get_contents($file);
				$decoded = $json ? json_decode($json, true) : null;
				if ($decoded && ($decoded['window'] ?? 0) >= $window_start) {
					$data = $decoded;
				}
			}

			$data['count']++;
			@file_put_contents($file, json_encode($data), LOCK_EX);
			return $data['count'];
		} catch (\Throwable $e) {
			return 0;
		}
	}

	public function get_counter(string $key): int
	{
		try {
			$file = $this->cache_file("counter:$key");
			if (!file_exists($file)) return 0;
			$data = json_decode(@file_get_contents($file), true);
			return $data['count'] ?? 0;
		} catch (\Throwable $e) {
			return 0;
		}
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		try {
			$file = $this->cache_file("behavior:$session_id");
			if (!file_exists($file)) return null;
			return json_decode(@file_get_contents($file), true);
		} catch (\Throwable $e) {
			return null;
		}
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		try {
			$file = $this->cache_file("behavior:$session_id");
			$profile['_expires'] = time() + $ttl;
			return @file_put_contents($file, json_encode($profile), LOCK_EX) !== false;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		try {
			$file = $this->cache_file("set:$key");
			$set = [];
			if (file_exists($file)) {
				$set = json_decode(@file_get_contents($file), true) ?? [];
			}
			$set[$value] = time() + $ttl;
			return @file_put_contents($file, json_encode($set), LOCK_EX) !== false;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function get_set(string $key): array
	{
		try {
			$file = $this->cache_file("set:$key");
			if (!file_exists($file)) return [];
			$set = json_decode(@file_get_contents($file), true) ?? [];
			$now = time();
			$set = array_filter($set, fn($exp) => $exp > $now);
			@file_put_contents($file, json_encode($set), LOCK_EX);
			return array_keys($set);
		} catch (\Throwable $e) {
			return [];
		}
	}

	// =========================================================================
	// GEOIP / CHALLENGE / LOGGING
	// =========================================================================

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
			// Last-resort: silent fail (we tried twice)
		}
	}
}
