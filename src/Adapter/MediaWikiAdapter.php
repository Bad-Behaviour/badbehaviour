<?php

namespace BadBehaviour\Adapter;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\ConfigUtil;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;

class MediaWikiAdapter implements AdapterInterface, CacheInterface
{
	private $db;
	private string $emergency_email;
	private string $script_path;
	private array $defaults;

	public function __construct($db, string $db_prefix, string $emergency_email, string $script_path)
	{
		$this->db = $db;
		$this->emergency_email = $emergency_email;
		$this->script_path = dirname($script_path) . "/";
		$this->defaults = [
			'log_table' => $db_prefix . 'bad_behaviour',
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
		global $wgBadBehaviourSettings;
		$settings = $wgBadBehaviourSettings ?? [];
		return array_merge($this->defaults, $settings);
	}

	public function get_whitelist(): array
	{
		return @parse_ini_file(__DIR__ . '/../../whitelist.ini', true) ?: [];
	}

	public function get_email(): string
	{
		return $this->emergency_email;
	}

	public function get_relative_path(): string
	{
		return $this->script_path;
	}

	public function get_table_schema(string $table_name): string
	{
		$name = $this->db->tableName($table_name);
		return <<<SQL
CREATE TABLE IF NOT EXISTS `$name` (
	`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
	`ip` VARBINARY(16) NOT NULL,
	`date` DATETIME NOT NULL,
	`method` VARCHAR(8) NOT NULL,
	`uri` VARBINARY(2048) NOT NULL,
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
	PRIMARY KEY (`id`),
	KEY `idx_ip` (`ip`),
	KEY `idx_status` (`status_code`),
	KEY `idx_date` (`date`),
	KEY `idx_bot` (`bot_category`, `bot_verified`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL;
	}

	public function log_request(RequestPackage $package, Result $result): void
	{
		if (!$this->get_settings()['logging']) {
			return;
		}

		$table = $this->get_settings()['log_table'];
		$ip_bin = inet_pton($package->ip);

		$this->db->insert($table, [
			'ip'                => $ip_bin,
			'date'              => gmdate('Y-m-d H:i:s'),
			'method'            => $package->request_method,
			'uri'               => $package->request_uri,
			'ua'                => $package->user_agent,
			'status_code'       => $result->code->value,
			'status_message'    => $result->message,
			'support_key'       => $result->support_key,
			'bot_category'      => $result->metadata['bot_category'] ?? null,
			'bot_verified'      => $result->metadata['bot_verified'] ?? false,
			'ja3'               => $package->ja3,
			'h2_hash'           => $package->h2_settings ? substr(hash('sha256', $package->h2_settings), 0, 16) : null,
			'header_order_hash' => substr(hash('sha256', implode(',', array_keys($package->headers_mixed))), 0, 16),
			'asn'               => $package->asn,
			'country'           => $package->country,
			'request_time_ms'   => (int)($package->request_time * 1000),
		], __METHOD__);
	}

	public function query(string $sql): bool
	{
		try {
			$this->db->query($sql);
			return true;
		} catch (\DBQueryError $e) {
			$this->log('error', 'Query failed', ['error' => $e->getMessage()]);
			return false;
		}
	}

	// CacheInterface - uses MediaWiki WAN cache
	public function get(string $key): mixed
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		return $cache->get($key);
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$cache->set($key, $value, $ttl);
		return true;
	}

	public function delete(string $key): bool
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$cache->delete($key);
		return true;
	}

	public function increment_counter(string $key, int $window): int
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$now = time();
		$window_start = $now - $window;

		$value = $cache->get($key);
		if ($value === false || ($value['window'] ?? 0) < $window_start) {
			$value = ['count' => 0, 'window' => $window_start];
		}

		$value['count']++;
		$cache->set($key, $value, $window);
		return $value['count'];
	}

	public function get_counter(string $key): int
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$value = $cache->get($key);
		return $value['count'] ?? 0;
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		return $cache->get("bb_behavior:$session_id");
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$cache->set("bb_behavior:$session_id", $profile, $ttl);
		return true;
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$set = $cache->get($key) ?? [];
		$set[$value] = time() + $ttl;
		$cache->set($key, $set, $ttl);
		return true;
	}

	public function get_set(string $key): array
	{
		$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
		$set = $cache->get($key) ?? [];
		$now = time();
		$set = array_filter($set, fn($exp) => $exp > $now);
		$cache->set($key, $set, 86400);
		return array_keys($set);
	}

	public function get_geoip(string $ip): ?array
	{
		// Hook for MaxMind integration
		return null;
	}

	public function verify_challenge(string $response, string $remote_ip): bool
	{
		return false;
	}

	public function log(string $level, string $message, array $context = []): void
	{
		\MediaWiki\Logger\LoggerFactory::getInstance('badbehaviour')->$level($message, $context);
	}
}
