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
	// SETTINGS — Single source: config/bad_behaviour.php
	// =========================================================================

	public function get_settings(): array
	{
		$file = defined('CONFIG_DIR') ? CONFIG_DIR . '/bad_behaviour.php' : 'config/bad_behaviour.php';

		if (!file_exists($file)) {
			// Fallback for non-WackoWiki contexts
			$file = __DIR__ . '/../../../config/bad_behaviour.php';
		}

		return Configuration::from_file($file, $this)->to_array();
	}

	// Admin panel uses the SAME format — no conversion needed
	public function get_admin_settings(): array
	{
		$nested = $this->get_settings();

		// Map to admin panel's expected HYBRID format
		return [
			// ===== CORE (flat) =====
			'strict'           => $nested['strict'] ?? false,
			'verbose'          => $nested['verbose'] ?? false,
			'logging'          => $nested['logging'] ?? true,
			'offsite_forms'    => $nested['offsite_forms'] ?? false,

			// ===== REVERSE PROXY (flat) =====
			'reverse_proxy'            => $nested['reverse_proxy']['enabled'] ?? false,
			'reverse_proxy_header'     => $nested['reverse_proxy']['header'] ?? 'X-Forwarded-For',
			'reverse_proxy_addresses'  => $nested['reverse_proxy']['addresses'] ?? [],

			// ===== HTTP:BL (flat) =====
			'httpbl_key'       => $nested['httpbl']['key'] ?? '',
			'httpbl_threat'    => (int)($nested['httpbl']['threat'] ?? 25),
			'httpbl_maxage'    => (int)($nested['httpbl']['maxage'] ?? 30),

			// ===== DNSBL (flat) =====
			'dnsbl_enabled'    => $nested['dnsbl']['enabled'] ?? false,
			'dnsbl_lists'      => $nested['dnsbl']['lists'] ?? ['zen.spamhaus.org', 'bl.spamcop.net'],

			// ===== AI CRAWLERS (flat) =====
			'block_unverified_ai' => $nested['ai_crawlers']['block_unverified'] ?? true,
			'strict_ai'           => $nested['ai_crawlers']['strict'] ?? false,
			'allowed_ai_crawlers' => $nested['ai_crawlers']['allowed'] ?? ['GPTBot', 'ClaudeBot', 'Google-Extended', 'PerplexityBot', 'GrokBot', 'MistralBot', 'YouBot', 'Meta-ExternalAgent'],

			// ===== BEHAVIORAL (flat) =====
			'enable_behavioral_analysis' => $nested['enable_behavioral_analysis'] ?? true,
			'enable_fingerprinting'      => $nested['enable_fingerprinting'] ?? false,
			'inspect_json_body'          => $nested['inspect_json_body'] ?? false,
			'inspect_multipart_body'     => $nested['inspect_multipart_body'] ?? false,

			// ===== RATE LIMITS (HYBRID - flat enabled + nested details) =====
			'rate_limit_enabled' => $nested['rate_limits']['enabled'] ?? true,
			'rate_limits'        => [
				'global'       => $nested['rate_limits']['global']       ?? ['requests' => 1000, 'window' => 3600],
				'per_minute'   => $nested['rate_limits']['per_minute']   ?? ['requests' => 60,   'window' => 60],
				'post'         => $nested['rate_limits']['post']         ?? ['requests' => 30,   'window' => 3600],
				'login'        => $nested['rate_limits']['login']        ?? ['requests' => 10,   'window' => 900],
			],

			// ===== CHALLENGE (HYBRID - flat enabled + nested details) =====
			'challenge_enabled'     => $nested['challenge']['enabled'] ?? false,
			'challenge_provider'    => $nested['challenge']['provider'] ?? 'builtin',
			'challenge_site_key'    => $nested['challenge']['site_key'] ?? '',
			'challenge_secret_key'  => $nested['challenge']['secret_key'] ?? '',
			'recaptcha_min_score'   => (float)($nested['challenge']['recaptcha_min_score'] ?? 0.5),

			// ===== PERFORMANCE (flat) =====
			'skip_static_extensions' => $nested['performance']['skip_extensions'] ?? ['css','js','png','jpg','jpeg','gif','ico','svg','woff','woff2','ttf','eot','webp','avif','map','txt'],
			'skip_static_paths'      => $nested['performance']['skip_paths']      ?? ['/static/','/assets/','/media/','/images/','/css/','/js/','/fonts/','/dist/','/build/','/vendor/','/node_modules/'],

			// ===== GEOIP (HYBRID - flat enabled + nested details) =====
			'geoip_enabled'        => $nested['geoip']['enabled'] ?? false,
			'geoip_database_path'  => $nested['geoip']['database_path'] ?? '',
			'blocked_countries'    => $nested['geoip']['blocked_countries'] ?? [],
			'blocked_asns'         => $nested['geoip']['blocked_asns'] ?? [],

			// ===== FINGERPRINTS (flat) =====
			'bad_ja3_fingerprints'       => $nested['fingerprints']['bad_ja3'] ?? [],
			'bad_h2_fingerprints'        => $nested['fingerprints']['bad_h2'] ?? [],
			'bot_header_orders'          => $nested['fingerprints']['bot_header_orders'] ?? [],
			'expected_ja3'               => $nested['fingerprints']['expected_ja3'] ?? [],

			// ===== BODY SCAN (flat) =====
			'body_scan_skip_fields' => $nested['body_scan_skip_fields'] ?? [
				'body', 'comment', 'content', 'text', 'message', 'description',
				'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
				'article', 'page', 'entry', 'reply', 'review', 'feedback',
			],

			// ===== CUSTOM RULES (flat) =====
			'custom_rules' => $nested['custom_rules'] ?? [],

			// ===== BOT CATEGORIES (flat) =====
			'blocked_bot_categories' => $nested['bot_categories']['blocked'] ?? ['malicious'],

			// ===== 3.0 FEATURES (flat) =====
			'enable_fingerprinting'      => $nested['enable_fingerprinting'] ?? false,
			'inspect_json_body'          => $nested['inspect_json_body'] ?? false,
			'inspect_multipart_body'     => $nested['inspect_multipart_body'] ?? false,
			'enable_behavioral_analysis' => $nested['enable_behavioral_analysis'] ?? true,
			'enable_ai_crawler_control'  => $nested['enable_ai_crawler_control'] ?? true,
			'enable_client_hints_validation' => $nested['enable_client_hints_validation'] ?? true,
			'enable_agentic_detection'   => $nested['enable_agentic_detection'] ?? true,
			'enable_dynamic_ip_ranges'   => $nested['enable_dynamic_ip_ranges'] ?? true,
		];
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
				"CREATE TABLE IF NOT EXISTS \"{$name}\" (
					\"log_id\" INTEGER PRIMARY KEY AUTOINCREMENT,
					\"ip\" VARCHAR(45) NOT NULL DEFAULT '',
					\"host\" VARCHAR(2083) NOT NULL DEFAULT '',
					\"date\" DATETIME NULL,
					\"request_method\" VARCHAR(8) NOT NULL DEFAULT '',
					\"request_uri\" VARCHAR(2083) NOT NULL DEFAULT '',
					\"request_uri_hash\" CHARACTER(40) NOT NULL DEFAULT '',
					\"server_protocol\" VARCHAR(12) NOT NULL DEFAULT '',
					\"http_headers\" TEXT NOT NULL,
					\"user_agent\" TEXT NULL,
					\"user_agent_hash\" CHARACTER(40) NOT NULL DEFAULT '',
					\"request_entity\" TEXT NULL,
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
				"CREATE INDEX IF NOT EXISTS \"bb_idx_user_agent_hash\" ON \"{$name}\" (\"user_agent_hash\");",
				"CREATE INDEX IF NOT EXISTS \"bb_idx_staus_key\" ON \"{$name}\" (\"status_code\");",
				"CREATE INDEX IF NOT EXISTS \"bb_idx_request_uri_hash\" ON \"{$name}\" (\"request_uri_hash\");",
				"CREATE INDEX IF NOT EXISTS \"bb_idx_request_method\" ON \"{$name}\" (\"request_method\");",
			];
		} else {
			return [
				"CREATE TABLE IF NOT EXISTS `$name` (
					`log_id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
					`ip` VARCHAR(45) NOT NULL DEFAULT '',
					`host` VARCHAR(2083) NOT NULL DEFAULT '',
					`date` DATETIME NOT NULL,
					`request_method` VARCHAR(8) NOT NULL DEFAULT '',
					`request_uri` VARCHAR(2048) NOT NULL DEFAULT '',
					`request_uri_hash` CHAR(40) NOT NULL DEFAULT '',
					`server_protocol` VARCHAR(12) NOT NULL DEFAULT '',
					`http_headers` TEXT NOT NULL,
					`user_agent` TEXT,
					`user_agent_hash` CHAR(40) NOT NULL DEFAULT '',
					`request_entity` TEXT DEFAULT NULL,
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
		$uri_hash = $q(substr(hash('sha1', $package->request_uri), 0, 40));
		$protocol = $q($package->server_protocol);
		$ua       = $q($package->user_agent);
		$ua_hash  = $q(substr(hash('sha1', $package->user_agent), 0, 40));

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
		$h2 = $q($package->h2_settings ? substr(hash('sha256', $package->h2_settings), 0, 16) : '');
		$hdr = $q(substr(hash('sha256', implode(',', array_keys($package->headers_mixed))), 0, 16));
		$asn = $q($package->asn ?? '');
		$country = $q($package->country ?? '');
		$time_ms = (int)($package->request_time * 1000);

		$sql = "INSERT INTO `$table`
        (`ip`,`host`,`date`,`request_method`,`request_uri`,`request_uri_hash`,`server_protocol`,
         `http_headers`,`user_agent`,`user_agent_hash`,`request_entity`,`status_code`,`status_message`,
         `support_key`,`bot_category`,`bot_verified`,`ja3`,`h2_hash`,`header_order_hash`,`asn`,`country`,`request_time_ms`)
        VALUES ($ip,$host,$date,$method,$uri,$uri_hash,$protocol,$headers,$ua,$ua_hash,$request_entity,
                '$status_key',$status_message,$support_key,$bot_category,$bot_verified,$ja3,$h2,$hdr,$asn,$country,$time_ms)";

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
