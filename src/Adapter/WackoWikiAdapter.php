<?php

namespace BadBehaviour\Adapter;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;

if (!defined('CACHE_DIR')) {
	define('CACHE_DIR', sys_get_temp_dir() . '/badbehaviour_cache');
}

class WackoWikiAdapter implements AdapterInterface, CacheInterface
{
	private $db;
	private array $defaults;
	private string $cache_dir;

	public function __construct($db)
	{
		$this->db = $db;
		$this->cache_dir = CACHE_DIR . '/bad_behaviour/';
		@mkdir($this->cache_dir, 0755, true);

		$this->defaults = [
			'log_table' => $db->table_prefix . 'bad_behaviour',
			'display_stats' => false,
			'logging' => true,
			'httpbl_key' => '',
			'httpbl_threat' => 25,
			'httpbl_maxage' => 30,
			'offsite_forms' => false,
			'reverse_proxy' => false,
			'reverse_proxy_header' => 'X-Forwarded-For',
			'reverse_proxy_addresses' => [],
		];
	}

	public function get_settings(): array
	{
		$settings = @parse_ini_file('config/bb_settings.conf', true) ?: [];
		return array_merge($this->defaults, $settings);
	}

	public function get_whitelist(): array
	{
		return @parse_ini_file('config/bb_whitelist.conf', true) ?: [];
	}

	public function get_email(): string
	{
		return $this->db->abuse_email;
	}

	public function get_relative_path(): string
	{
		return '/';
	}

	public function get_table_schema(string $table_name): array
	{
		$name = $this->db->table_prefix . $table_name;
		$sqlite = $this->db->is_sqlite;

		if ($sqlite)
		{
			return [
				"CREATE TABLE IF NOT EXISTS \"{$name}\" (
					\"id\" INTEGER PRIMARY KEY AUTOINCREMENT,
					\"ip\" VARCHAR(45) NOT NULL DEFAULT '',
					\"date\" DATETIME NOT NULL,
					\"method\" VARCHAR(8) NOT NULL DEFAULT '',
					\"uri\" VARCHAR(2048) NOT NULL DEFAULT '',
					\"ua\" TEXT,
					\"status_code\" VARCHAR(50) NOT NULL DEFAULT '',
					\"status_message\" TEXT,
					\"support_key\" VARCHAR(64),
					\"bot_category\" VARCHAR(32),
					\"bot_verified\" BOOLEAN DEFAULT 0,
					\"ja3\" CHAR(32),
					\"h2_hash\" CHAR(16),
					\"header_order_hash\" CHAR(16),
					\"asn\" VARCHAR(32),
					\"country\" CHAR(2),
					\"request_time_ms\" INTEGER UNSIGNED
				);",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_ip\" ON \"{$name}\" (\"ip\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_status\" ON \"{$name}\" (\"status_code\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_date\" ON \"{$name}\" (\"date\");",
				"CREATE INDEX IF NOT EXISTS \"idx_{$name}_bot\" ON \"{$name}\" (\"bot_category\", \"bot_verified\");",
			];
		}

		return [
			"CREATE TABLE IF NOT EXISTS `$name` (
				`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
				`ip` VARCHAR(45) NOT NULL DEFAULT '',
				`date` DATETIME NOT NULL,
				`method` VARCHAR(8) NOT NULL DEFAULT '',
				`uri` VARCHAR(2048) NOT NULL DEFAULT '',
				`ua` TEXT,
				`status_code` VARCHAR(50) NOT NULL DEFAULT '',
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
				PRIMARY KEY (`id`),
				KEY `idx_ip` (`ip`),
				KEY `idx_status` (`status_code`),
				KEY `idx_date` (`date`),
				KEY `idx_bot` (`bot_category`, `bot_verified`)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
		];
	}

	public function log_request(RequestPackage $package, Result $result): void
	{
		if (!$this->get_settings()['logging']) {
			return;
		}

		$table = $this->get_settings()['log_table'];
		$ip = $this->db->quote($package->ip);
		$date = $this->db->quote(gmdate('Y-m-d H:i:s'));
		$method = $this->db->quote($package->request_method);
		$uri = $this->db->quote($package->request_uri);
		$ua = $this->db->quote($package->user_agent);
		$code = $this->db->quote($result->code->value);
		$message = $this->db->quote($result->message);
		$support = $this->db->quote($result->support_key);
		$bot_cat = $this->db->quote($result->metadata['bot_category'] ?? '');
		$bot_ver = $result->metadata['bot_verified'] ?? false ? 1 : 0;
		$ja3 = $this->db->quote($package->ja3 ?? '');
		$h2 = $this->db->quote($package->h2_settings ? substr(hash('sha256', $package->h2_settings), 0, 16) : '');
		$hdr = $this->db->quote(substr(hash('sha256', implode(',', array_keys($package->headers_mixed))), 0, 16));
		$asn = $this->db->quote($package->asn ?? '');
		$country = $this->db->quote($package->country ?? '');
		$time_ms = (int)($package->request_time * 1000);

		$sql = "INSERT INTO `$table` (`ip`,`date`,`method`,`uri`,`ua`,`status_code`,`status_message`,`support_key`,`bot_category`,`bot_verified`,`ja3`,`h2_hash`,`header_order_hash`,`asn`,`country`,`request_time_ms`)
			VALUES ($ip,$date,$method,$uri,$ua,$code,$message,$support,$bot_cat,$bot_ver,$ja3,$h2,$hdr,$asn,$country,$time_ms)";

		$this->db->ll_query($sql);
	}

	public function query(string $sql)
	{
		return $this->db->ll_query($sql);
	}

	private function cache_file(string $key): string
	{
		return $this->cache_dir . md5($key) . '.json';
	}

	// CacheInterface - file-based
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
