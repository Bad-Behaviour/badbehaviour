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

class MediaWikiAdapter implements AdapterInterface, CacheInterface
{
	private $db;
	private string $emergency_email;
	private string $script_path;
	private array $db_defaults;

	private bool $safe_mode = false;
	private bool $config_loaded = false;

	public function __construct($db, string $db_prefix, string $emergency_email, string $script_path)
	{
		$this->db = $db;
		$this->emergency_email = $emergency_email;
		$this->script_path = dirname($script_path) . "/";

		$this->db_defaults = [
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
		global $wgBadBehaviourSettings;

		// Single source of truth: the MediaWiki config directory.
		// The package directory is intentionally not searched — see
		// production_config_path() for the rationale.
		$file = $this->production_config_path();
		if ($file !== null) {
			try {
				$base_settings = Configuration::from_file($file, $this)->to_array();
				$this->safe_mode = false;
				$this->config_loaded = true;
			} catch (\ParseError $e) {
				$this->safe_mode = true;
				$this->config_loaded = false;
				ErrorReporter::error($this, 'BadBehaviour config has syntax error', [
					'path' => $file,
					'error' => $e->getMessage(),
					'line' => $e->getLine(),
					'hint' => 'Check bb_config.php for syntax errors',
				], 'bb_config_load');
				$base_settings = SafeMode::settings($this->db_defaults['log_table']);
			} catch (\Throwable $e) {
				$this->safe_mode = true;
				$this->config_loaded = false;
				ErrorReporter::error($this, 'BadBehaviour config failed to load', [
					'path' => $file,
					'error' => $e->getMessage(),
					'exception_class' => get_class($e),
				], 'bb_config_load');
				$base_settings = SafeMode::settings($this->db_defaults['log_table']);
			}
		} else {
			// No config file — start from safe-mode defaults
			$this->safe_mode = true;
			$this->config_loaded = false;
			$base_settings = SafeMode::settings($this->db_defaults['log_table']);
		}

		// Override with MediaWiki settings (LocalSettings.php)
		if (isset($wgBadBehaviourSettings) && is_array($wgBadBehaviourSettings)) {
			try {
				$base_settings = Configuration::merge_arrays($base_settings, $wgBadBehaviourSettings);
			} catch (\Throwable $e) {
				ErrorReporter::error($this, 'BadBehaviour MediaWiki settings merge failed', [
					'error' => $e->getMessage(),
				], 'bb_mw_settings_merge');
			}
		}

		// Ensure log_table uses correct prefix (adapter-specific, must not come from config)
		$base_settings['log_table'] = $this->db_defaults['log_table'];

		return $base_settings;
	}

	/**
	 * Resolve the production config file location for MediaWiki.
	 *
	 * MediaWiki's convention is MW_CONFIG_FILE pointing to LocalSettings.php.
	 * BadBehaviour config lives next to it (same directory). That is the
	 * ONLY acceptable production location — the package's bundled test
	 * fixture is intentionally excluded because it can shadow the
	 * operator's actual config.
	 *
	 * @return string|null Absolute path, or null if not resolvable.
	 */
	private function production_config_path(): ?string
	{
		if (!defined('MW_CONFIG_FILE')) {
			ErrorReporter::warning($this,
				'MediaWikiAdapter: MW_CONFIG_FILE not defined; cannot '
				. 'locate config/bb_config.php in MediaWiki config directory',
				[
					'hint' => 'BadBehaviour expects config/bb_config.php next to '
					. 'LocalSettings.php. If MW_CONFIG_FILE isn\'t defined '
					. 'when BadBehaviour boots, you may need to load BadBehaviour '
					. 'later in MediaWiki\'s initialization sequence.',
				],
				'bb_mw_config_dir_unresolved'  // once-tag
				);
			return null;
		}

		if (!file_exists(MW_CONFIG_FILE)) {
			// MW_CONFIG_FILE is defined but the file doesn't exist —
			// something is misconfigured upstream. Don't fall back to
			// the package fixture (that's the bug we're fixing).
			return null;
		}

		$candidate = dirname(MW_CONFIG_FILE) . '/config/bb_config.php';
		if (file_exists($candidate)) {
			return $candidate;
		}

		return null;
	}

	public function get_whitelist(): array
	{
		$file = __DIR__ . '/../../../config/bb_whitelist.conf';
		$parsed = @parse_ini_file($file, true, INI_SCANNER_TYPED);
		if ($parsed === false) {
			ErrorReporter::warning($this, 'BadBehaviour whitelist parse error or missing', [
				'path' => $file,
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

	public function probe_log_table(string $table_name): array
	{
		try {
			$row = $this->db->selectRow(
				$table_name,
				['MAX(date) AS newest', 'COUNT(*) AS total'],
				[],
				__METHOD__
				);
			if ($row === false) {
				return ['newest' => null, 'total' => 0, 'error' => null];
			}
			return [
				'newest' => $row->newest ?? null,
				'total'  => (int)($row->total ?? 0),
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

	public function log_request(RequestPackage $package, Result $result): void
	{
		// CRITICAL: never let logging failures crash the request.
		try {
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
				'enforcement_action'=> $result->enforcement->value,
				'original_code'     => $result->metadata['original_code'] ?? null,
			], __METHOD__);
		} catch (\Throwable $e) {
			// Never propagate — logging must not crash the user's response.
			ErrorReporter::error($this, 'log_request failed', [
				'error' => $e->getMessage(),
				'exception_class' => get_class($e),
				'hint' => 'Check DB connectivity and log table schema',
			], 'log_request_failure');
		}
	}

	public function query(string $sql): bool
	{
		try {
			$this->db->query($sql);
			return true;
		} catch (\DBQueryError $e) {
			ErrorReporter::error($this, 'Query failed', [
				'error' => $e->getMessage(),
			], 'query_failure');
			return false;
		} catch (\Throwable $e) {
			ErrorReporter::error($this, 'Query failed (unexpected)', [
				'error' => $e->getMessage(),
				'exception_class' => get_class($e),
			], 'query_failure');
			return false;
		}
	}

	// CacheInterface - uses MediaWiki WAN cache
	public function get(string $key): mixed
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			return $cache->get($key);
		} catch (\Throwable $e) {
			return null;
		}
	}

	public function set(string $key, mixed $value, int $ttl): bool
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			$cache->set($key, $value, $ttl);
			return true;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function delete(string $key): bool
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			$cache->delete($key);
			return true;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function increment_counter(string $key, int $window): int
	{
		try {
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
		} catch (\Throwable $e) {
			return 0;
		}
	}

	public function get_counter(string $key): int
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			$value = $cache->get($key);
			return $value['count'] ?? 0;
		} catch (\Throwable $e) {
			return 0;
		}
	}

	public function get_behavior_profile(string $session_id): ?array
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			return $cache->get("bb_behavior:$session_id");
		} catch (\Throwable $e) {
			return null;
		}
	}

	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			$cache->set("bb_behavior:$session_id", $profile, $ttl);
			return true;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function add_to_set(string $key, string $value, int $ttl): bool
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			$set = $cache->get($key) ?? [];
			$set[$value] = time() + $ttl;
			$cache->set($key, $set, $ttl);
			return true;
		} catch (\Throwable $e) {
			return false;
		}
	}

	public function get_set(string $key): array
	{
		try {
			$cache = \MediaWiki\MediaWikiServices::getInstance()->getMainWANObjectCache();
			$set = $cache->get($key) ?? [];
			$now = time();
			$set = array_filter($set, fn($exp) => $exp > $now);
			$cache->set($key, $set, 86400);
			return array_keys($set);
		} catch (\Throwable $e) {
			return [];
		}
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
		try {
			\MediaWiki\Logger\LoggerFactory::getInstance('badbehaviour')->$level($message, $context);
		} catch (\Throwable $e) {
			// Last-resort: fall back to error_log
			try {
				error_log("[BadBehaviour] [$level] $message " . json_encode($context));
			} catch (\Throwable $e2) {
				// Silent
			}
		}
	}

	/**
	 * Return the number of rows affected by the most recent query().
	 *
	 * MediaWiki's Database class exposes affectedRows() directly. Returns
	 * null when the connection is unavailable or the value can't be determined.
	 */
	public function last_query_affected_rows(): ?int
	{
		try {
			if (isset($this->db) && method_exists($this->db, 'affectedRows')) {
				$n = $this->db->affectedRows();
				if ($n === false || $n === null) {
					return null;
				}
				return (int)$n;
			}
		} catch (\Throwable $e) {
			// fall through
		}
		return null;
	}
}
