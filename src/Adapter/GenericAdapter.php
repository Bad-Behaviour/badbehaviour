<?php

namespace BadBehaviour\Adapter;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\ConfigUtil;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;

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

	public function get_settings(): array
	{
		$file = __DIR__ . '/../../settings.ini';
		$settings = ConfigUtil::parse_ini($file);
		return ConfigUtil::merge_with_defaults($settings, $this->defaults);
	}

	public function get_whitelist(): array
	{
		$file = __DIR__ . '/../../whitelist.ini';
		return ConfigUtil::parse_ini($file, expand_dots: false);
	}

	public function get_email(): string
	{
		return 'admin@example.com';
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
		// No-op for generic adapter - implement in specific adapters
	}

	public function query(string $sql): bool
	{
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
		$now = time();
		$window_start = $now - $window;

		if (!isset($this->counters[$key]) || $this->counters[$key]['window'] < $window_start) {
			$this->counters[$key] = ['count' => 0, 'window' => $window_start];
		}

		return ++$this->counters[$key]['count'];
	}

	public function get_counter(string $key): int
	{
		return $this->counters[$key]['count'] ?? 0;
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		return $this->behavior[$session_id] ?? null;
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		$this->behavior[$session_id] = $profile;
		return true;
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		if (!isset($this->sets[$key])) {
			$this->sets[$key] = [];
		}
		$this->sets[$key][$value] = time() + $ttl;
		return true;
	}

	public function get_set(string $key): array
	{
		$now = time();
		$set = $this->sets[$key] ?? [];
		$set = array_filter($set, fn($exp) => $exp > $now);
		$this->sets[$key] = $set;
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
