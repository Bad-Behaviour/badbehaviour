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
		// In WackoWiki context: CONFIG_DIR/bb_config.php
		// In badbehaviour repo (tests): __DIR__/../../../config/bb_config.php
		// Fallback: config/bb_config.php (relative to CWD)
		$possible_paths = [
			defined('CONFIG_DIR') ? CONFIG_DIR . '/bb_config.php' : null,
			'config/bb_config.php',                           // Relative to CWD
			__DIR__ . '/../../../config/bb_config.php',       // From badbehaviour repo
		];

		$file = SafeConfigLoader::find_existing($possible_paths);

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
				'checked_paths' => array_values(array_filter($possible_paths)),
				'hint' => 'Create config/bb_config.php from config/bb_config.sample.php to enable full protection',
			],
			'bb_config_missing'
		);

		return $this->safe_mode_settings();
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
				//   * bot_category:    VARCHAR(32) → VARCHAR(20)       [longest enum value = 20 chars]
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
					\"bot_category\" VARCHAR(20),
					\"bot_verified\" BOOLEAN DEFAULT 0,
					\"ja3\" CHAR(32),
					\"asn\" VARCHAR(32),
					\"country\" CHAR(2),
					\"request_time_ms\" INTEGER UNSIGNED,
					\"resolved_at\" DATETIME NULL DEFAULT NULL
				);",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_ip\" ON \"{$name}\" (\"ip\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_status\" ON \"{$name}\" (\"status_code\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_date\" ON \"{$name}\" (\"date\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_bot\" ON \"{$name}\" (\"bot_category\", \"bot_verified\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_ua_hash\" ON \"{$name}\" (\"user_agent_hash\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_uri_hash\" ON \"{$name}\" (\"request_uri_hash\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_method\" ON \"{$name}\" (\"request_method\");",
				];
		}
		else {
			return [
				// BB 3.0 schema — see docs/CONFIGURATION.md for the full rationale.
				// Notable changes vs the 3.0 pre-release:
				//   * host:             VARCHAR(2083) → VARCHAR(253)  [RFC 1035 max hostname]
				//   * *_hash columns:   CHAR(40) SHA-1 → CHAR(16) half-SHA-256 [admin grouping only]
				//   * status_code:      VARCHAR(50) → VARCHAR(32)      [longest enum value = 26 chars]
				//   * bot_category:     VARCHAR(32) → VARCHAR(20)      [longest enum value = 20 chars]
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
					`bot_category` VARCHAR(20),
					`bot_verified` BOOLEAN DEFAULT 0,
					`ja3` CHAR(32),
					`asn` VARCHAR(32),
					`country` CHAR(2),
					`request_time_ms` INT UNSIGNED,
					`resolved_at` DATETIME NULL DEFAULT NULL,
				PRIMARY KEY (`log_id`),
				KEY `idx_ip` (`ip`),
				KEY `idx_status` (`status_code`),
				KEY `idx_date` (`date`),
				KEY `idx_bot` (`bot_category`, `bot_verified`),
				KEY `idx_user_agent_hash` (`user_agent_hash`),
				KEY `idx_request_uri_hash` (`request_uri_hash`),
				KEY `idx_request_method` (`request_method`)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
			];
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

			$sql = "INSERT INTO `$table`
				(`ip`,`host`,`date`,`request_method`,`request_uri`,`request_uri_hash`,`server_protocol`,
				 `http_headers`,`user_agent`,`user_agent_hash`,`request_entity`,`status_code`,`status_message`,
				 `support_key`,`bot_category`,`bot_verified`,`ja3`,`asn`,`country`,`request_time_ms`)
				VALUES ($ip,$host,$date,$method,$uri,$uri_hash,$protocol,$headers,$ua,$ua_hash,$request_entity,
				        '$status_key',$status_message,$support_key,$bot_category,$bot_verified,$ja3,$asn,$country,$time_ms)";

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
