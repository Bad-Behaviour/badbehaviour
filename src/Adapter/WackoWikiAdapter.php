<?php

namespace BadBehaviour\Adapter;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Configuration;

if (!defined('CACHE_DIR')) {
	define('CACHE_DIR', sys_get_temp_dir() . '/badbehaviour_cache');
}

class WackoWikiAdapter implements AdapterInterface, CacheInterface
{
	private $db;
	private string $cache_dir;

	public function __construct($db)
	{
		$this->db = $db;
		$this->cache_dir = CACHE_DIR . '/bad_behaviour/';
		@mkdir($this->cache_dir, 0755, true);
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

		$file = null;
		foreach ($possible_paths as $path) {
			if ($path && file_exists($path)) {
				$file = $path;
				break;
			}
		}

		if (!$file) {
			throw new \RuntimeException('BadBehaviour config file not found. Checked: ' . implode(', ', array_filter($possible_paths)));
		}

		$settings = Configuration::from_file($file, $this)->to_array();

		// INJECT: log_table (not in config file - adapter-specific)
		// WackoWiki uses table prefix from $this->db->table_prefix
		$prefix = $this->db->table_prefix ?? '';
		$settings['log_table'] = $prefix . 'bad_behaviour';

		return $settings;
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
		return parse_ini_file($file, true, INI_SCANNER_TYPED) ?: [];
	}

	// =========================================================================
	// EMAIL / PATHS
	// =========================================================================

	public function get_email(): string
	{
		return $this->db->abuse_email;
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
		if (!$this->get_settings()['logging']) {
			return;
		}

		$table = $this->get_settings()['log_table'];

		$q = $this->db->q(...);

		$ip       = $q($package->ip);
		$host     = $q(@gethostbyaddr($package->ip) ?: $package->ip);
		$date     = $q(gmdate('Y-m-d H:i:s'));
		$method   = $q($package->request_method);
		$uri      = $q($package->request_uri);
		$uri      = $q($package->request_uri);
		// BB 3.0: hash shortened to 16 hex chars (half of SHA-256). Used only for
		// grouping/filtering in the admin UI — not a cryptographic identifier.
		// Collisions at 100k rows: ~0.0003% per row pair; acceptable for that use.
		$uri_hash = $q(substr(hash('sha256', $package->request_uri), 0, 16));
		$protocol = $q($package->server_protocol);
		$ua       = $q($package->user_agent);
		$ua_hash  = $q(substr(hash('sha256', $package->user_agent), 0, 16));
		$protocol = $q($package->server_protocol);

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
	}

	public function query(string $sql)
	{
		return $this->db->ll_query($sql);
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
		$file = $this->cache_file($key);
		if (!file_exists($file)) return null;
		$data = json_decode(@file_get_contents($file), true);
		return $data ?? null;
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		$file = $this->cache_file($key);
		$data = ['value' => $value, 'expires' => time() + $ttl];
		return @file_put_contents($file, json_encode($data), LOCK_EX) !== false;
	}

	public function delete(string $key): bool
	{
		$file = $this->cache_file($key);
		return @unlink($file);
	}

	public function increment_counter(string $key, int $window): int
	{
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
	}

	public function get_counter(string $key): int
	{
		$file = $this->cache_file("counter:$key");
		if (!file_exists($file)) return 0;
		$data = json_decode(@file_get_contents($file), true);
		return $data['count'] ?? 0;
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		$file = $this->cache_file("behavior:$session_id");
		if (!file_exists($file)) return null;
		return json_decode(@file_get_contents($file), true);
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		$file = $this->cache_file("behavior:$session_id");
		$profile['_expires'] = time() + $ttl;
		return @file_put_contents($file, json_encode($profile), LOCK_EX) !== false;
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		$file = $this->cache_file("set:$key");
		$set = [];
		if (file_exists($file)) {
			$set = json_decode(@file_get_contents($file), true) ?? [];
		}
		$set[$value] = time() + $ttl;
		return @file_put_contents($file, json_encode($set), LOCK_EX) !== false;
	}

	public function get_set(string $key): array
	{
		$file = $this->cache_file("set:$key");
		if (!file_exists($file)) return [];
		$set = json_decode(@file_get_contents($file), true) ?? [];
		$now = time();
		$set = array_filter($set, fn($exp) => $exp > $now);
		@file_put_contents($file, json_encode($set), LOCK_EX);
		return array_keys($set);
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
		error_log("[BadBehaviour] [$level] $message " . json_encode($context));
	}
}
