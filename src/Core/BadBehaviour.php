<?php

declare(strict_types=1);

namespace BadBehaviour\Core;

use BadBehaviour\Bot\Registry\Presets;
use BadBehaviour\Bot\RegistryFactory;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Interfaces\GeoIpInterface;
use BadBehaviour\Core\Interfaces\LoggerInterface;
use BadBehaviour\Detection\AgenticBehaviorDetector;
use BadBehaviour\Detection\AssetScrapingDetector;
use BadBehaviour\Detection\BehavioralDetector;
use BadBehaviour\Detection\BlacklistDetector;
use BadBehaviour\Detection\BotDetector;
use BadBehaviour\Detection\ClientHintsDetector;
use BadBehaviour\Detection\DnsblDetector;
use BadBehaviour\Detection\FingerprintDetector;
use BadBehaviour\Detection\HeadRequestDetector;
use BadBehaviour\Detection\RateLimitDetector;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\HeaderUtil;
use BadBehaviour\Util\IpUtil;
use BadBehaviour\Util\RequestPackage;

class BadBehaviour
{
	/** @var bool Whether install() has already run this process */
	private bool $install_done = false;

	private Configuration $config;
	private AdapterInterface $adapter;
	private ?LoggerInterface $logger;
	private ?CacheInterface $cache;
	private ?GeoIpInterface $geoip;
	private RegistryInterface $registry;

	private BotDetector $bot_detector;
	private BlacklistDetector $blacklist_detector;
	private BehavioralDetector $behavioral_detector;
	private FingerprintDetector $fingerprint_detector;
	private RateLimitDetector $rate_limit_detector;
	private DnsblDetector $dnsbl_detector;
	private ClientHintsDetector $client_hints_detector;
	private AgenticBehaviorDetector $agentic_detector;
	private HeadRequestDetector $head_detector;
	private AssetScrapingDetector $asset_detector;

	/**
	 * @param Configuration $config
	 * @param RegistryInterface|null $registry Optional bot registry override.
	 *        If null, loads from config/bb_registry.php (or falls back to
	 *        the configured preset's registry).
	 */
	public function __construct(Configuration $config, ?RegistryInterface $registry = null)
	{
		$this->config = $config;
		$this->adapter = $config->adapter ?? throw new \InvalidArgumentException('Adapter is required');
		$this->logger = $config->logger;
		$this->cache = $config->cache;
		$this->geoip = $config->geoip;

		// === Registry: explicit injection > config file > preset default ===
		// Registry loading can fail (missing file, parse error). Always fall
		// back to the configured preset — never throw on missing registry.
		try {
			if ($registry !== null) {
				$this->registry = $registry;
			} else {
				try {
					$this->registry = RegistryFactory::from_file();
				} catch (\Throwable $e) {
					// bb_registry.php missing or invalid — use the configured preset
					$this->registry = Presets::load($config->get_preset());
				}
			}
		} catch (\Throwable $e) {
			// Preset loading failed too — last-resort fallback
			ErrorReporter::error($this->adapter,
				'BadBehaviour registry load failed; using minimal default', [
					'error' => $e->getMessage(),
					'exception_class' => get_class($e),
					'preset' => $config->get_preset(),
				], 'registry_load_failure'
			);
			$this->registry = Presets::load('minimal');
		}

		// Pass registry to BotDetector (others don't need it directly)
		$this->bot_detector = new BotDetector($this->config, $this->adapter, $this->registry);
		$this->blacklist_detector = new BlacklistDetector($this->config);
		$this->behavioral_detector = new BehavioralDetector($this->config, $this->adapter);
		$this->fingerprint_detector = new FingerprintDetector($this->config, $this->adapter);
		$this->rate_limit_detector = new RateLimitDetector($this->config, $this->adapter);
		$this->dnsbl_detector = new DnsblDetector($this->config);
		$this->client_hints_detector = new ClientHintsDetector($this->config);
		$this->agentic_detector = new AgenticBehaviorDetector($this->config, $this->adapter);
		$this->head_detector = new HeadRequestDetector($this->config, $this->adapter);
		$this->asset_detector = new AssetScrapingDetector($this->config, $this->adapter);
	}

	/**
	 * Return a clone of this BadBehaviour instance with a different registry.
	 *
	 * Useful for per-request swapping in multi-tenant setups.
	 * Detectors that depend on the registry are rebuilt; others are reused.
	 */
	public function with_registry(RegistryInterface $registry): self
	{
		$clone = clone $this;
		$clone->registry = $registry;
		$clone->bot_detector = new BotDetector($this->config, $this->adapter, $registry);
		return $clone;
	}

	/**
	 * Get the currently active registry.
	 */
	public function get_registry(): RegistryInterface
	{
		return $this->registry;
	}

	/**
	 * Is the library running in safe-mode (config missing/invalid)?
	 *
	 * Safe-mode is set automatically when the adapter's config file is
	 * missing or malformed. The library runs in monitor-only mode:
	 * logs traffic but does not block. Use is_monitor_only() to also
	 * detect intentionally monitor-only configurations.
	 */
	public function is_in_safe_mode(): bool
	{
		if (method_exists($this->adapter, 'is_safe_mode')) {
			try {
				return $this->adapter->is_safe_mode();
			} catch (\Throwable $e) {
				return false;
			}
		}
		return false;
	}

	/**
	 * Is the library in monitor-only mode?
	 *
	 * True when:
	 *   - Configured strictness is 'monitor-only', OR
	 *   - All active defenses are disabled (defensive FP-prevention)
	 */
	public function is_monitor_only(): bool
	{
		if ($this->config->get_strictness() === 'monitor-only') {
			return true;
		}
		// Detect "all defenses off" as effectively monitor-only
		return !$this->config->dns_verification_enabled
			&& !$this->config->rate_limit_enabled
			&& !$this->config->enable_behavioral_analysis
			&& !$this->config->enable_fingerprinting
			&& !$this->config->dnsbl_enabled;
	}

	/**
	 * Return diagnostic information for admin dashboards / health checks.
	 *
	 * @return array{
	 *     safe_mode: bool,
	 *     monitor_only: bool,
	 *     strictness: string,
	 *     preset: string,
	 *     logging_enabled: bool,
	 *     detectors_active: array<string, bool>,
	 *     config_loaded: bool,
	 *     hint: ?string
	 * }
	 */
	public function diagnostics(): array
	{
		$safe_mode = $this->is_in_safe_mode();
		$monitor_only = $this->is_monitor_only();
		$strictness = $this->config->get_strictness();

		$detectors = [
			'blacklist'    => true, // always-on
			'bot'          => true, // always-on
			'dns_verify'   => $this->config->dns_verification_enabled,
			'dyn_ranges'   => $this->config->dynamic_ip_ranges_enabled,
			'rate_limit'   => $this->config->rate_limit_enabled,
			'dnsbl'        => $this->config->dnsbl_enabled,
			'behavioral'   => $this->config->enable_behavioral_analysis,
			'fingerprint'  => $this->config->enable_fingerprinting,
			'client_hints' => $this->config->enable_client_hints_validation,
			'agentic'      => $this->config->enable_agentic_detection,
			'head'         => $this->config->enable_head_request_detection,
			'asset'        => $this->config->enable_asset_scraping_detection,
		];

		$config_loaded = false;
		if (method_exists($this->adapter, 'is_config_loaded')) {
			try {
				$config_loaded = $this->adapter->is_config_loaded();
			} catch (\Throwable $e) {
				$config_loaded = false;
			}
		}

		$hint = null;
		if ($safe_mode) {
			$hint = 'BadBehaviour config is missing or invalid. '
				  . 'Create config/bb_config.php from config/bb_config.example.php. '
				  . 'Traffic is being logged but no requests are being blocked.';
		} elseif ($strictness === 'monitor-only') {
			$hint = 'BadBehaviour is in monitor-only mode by configuration. '
				  . 'Traffic is logged but not blocked. Change strictness to \'normal\' '
				  . 'or \'strict\' when you\'re ready to enforce.';
		} elseif ($monitor_only) {
			// All defenses off but not by user choice
			$hint = 'All active defenses are disabled. Set strictness to \'normal\' '
				  . 'or \'strict\' in your config to enable bot protection.';
		}

		return [
			'safe_mode'        => $safe_mode,
			'monitor_only'     => $monitor_only,
			'strictness'       => $strictness,
			'preset'           => $this->config->get_preset(),
			'config_loaded'    => $config_loaded,
			'logging_enabled'  => $this->config->logging,
			'detectors_active' => $detectors,
			'hint'             => $hint,
		];
	}

	public function run(array $server = null): Result
	{
		if (php_sapi_name() === 'cli') {
			return Result::allow();
		}

		// FAST PATH 1: Static resource skip — cheapest possible check.
		// Runs BEFORE install() and BEFORE building the RequestPackage,
		// because 95%+ of traffic is CSS/JS/images/fonts and we don't
		// want to spend even one cycle of CPU on them.
		$uri = $server['REQUEST_URI'] ?? $_SERVER['REQUEST_URI'] ?? '/';
		if ($this->should_skip_static($uri)) {
			return Result::allow();
		}

		// LAST-RESORT SAFETY NET:
		// The entire request pipeline is wrapped so that ANY unexpected
		// exception degrades gracefully to "allow" instead of 500.
		// BadBehaviour must NEVER be the reason the host application goes down.
		try {
			return $this->run_internal($server);
		} catch (\Throwable $e) {
			ErrorReporter::fatal($e, 'BadBehaviour::run');
			return Result::allow();
		}
	}

	/**
	 * Inner request pipeline — all the real work.
	 *
	 * Extracted from run() so the top-level try/catch in run() can
	 * convert any uncaught exception into a logged "allow" fallback.
	 */
	private function run_internal(?array $server): Result
	{
		// Lazy install: only runs once per PHP process, and only for
		// requests that actually need detection.
		$this->install_once();

		// Build proxy settings once (used by both package builders)
		$proxy_settings = [
			'reverse_proxy'             => $this->config->reverse_proxy,
			'reverse_proxy_header'      => $this->config->reverse_proxy_header,
			'reverse_proxy_addresses'   => $this->config->reverse_proxy_addresses,
		];

		// Build the package (now we need full request context)
		$package = $server !== null
			? RequestPackage::from_server_globals($proxy_settings, $server)
			: RequestPackage::from_globals($proxy_settings);

		// FAST PATH 2: Empty UA → immediate block (no DNS, no detection)
		if (empty($package->user_agent) || strlen(trim($package->user_agent)) < 5) {
			return Result::block(
				ResultCode::BLOCKED_MALICIOUS_UA,
				'Empty or invalid User-Agent',
				$package
			);
		}

		// FAST PATH 3: Whitelisted IP → immediate allow (skip all detectors)
		if ($this->is_whitelisted($package)) {
			return Result::allow($package);
		}

		// Enrich with GeoIP (only if available — avoid cost when not configured)
		if ($this->geoip) {
			try {
				if ($geoip = $this->geoip->lookup($package->ip)) {
					$package = $package->with_enrichment(
						$geoip['asn'] ?? null,
						$geoip['country'] ?? null,
						null,
						null
					);
				}
			} catch (\Throwable $e) {
				// GeoIP failures must not break detection
			}
		}

		// Enrich with fingerprints (cheap — just string hashing)
		try {
			$ja3 = HeaderUtil::get_ja3_fingerprint();
			$h2  = HeaderUtil::get_h2_settings();
			$package = $package->with_enrichment(null, null, $ja3, $h2);
		} catch (\Throwable $e) {
			// Fingerprint computation is best-effort
		}

		// Run detection pipeline (each detector is wrapped in try/catch internally)
		$result = $this->detect($package);

		// Logging: blocked/challenged always, allowed only when verbose
		if ($this->config->logging) {
			$should_log = !$result->is_allowed() || $this->config->verbose;
			if ($should_log) {
				// CRITICAL: logging failures must never crash the request
				try {
					$this->adapter->log_request($package, $result);
				} catch (\Throwable $e) {
					ErrorReporter::error($this->adapter,
						'log_request failed (further errors suppressed)', [
							'error' => $e->getMessage(),
							'exception_class' => get_class($e),
						], 'log_request_failure'
					);
				}
			}
		}

		return $result;
	}

	public function run_test_package(RequestPackage $package): Result
	{
		try {
			if ($this->should_skip_static($package->request_uri)) {
				return Result::allow($package);
			}

			try {
				$ja3 = HeaderUtil::get_ja3_fingerprint();
				$h2 = HeaderUtil::get_h2_settings();
				$package = $package->with_enrichment(null, null, $ja3, $h2);
			} catch (\Throwable $e) {
				// best-effort enrichment
			}

			$result = $this->detect($package);

			// Same logging logic as run()
			if ($this->config->logging) {
				$should_log = !$result->is_allowed() || $this->config->verbose;
				if ($should_log) {
					try {
						$this->adapter->log_request($package, $result);
					} catch (\Throwable $e) {
						// Silent: logging failure during test must not affect result
					}
				}
			}

			return $result;
		} catch (\Throwable $e) {
			ErrorReporter::fatal($e, 'BadBehaviour::run_test_package');
			return Result::allow($package);
		}
	}

	public function handle_result(Result $result): never
	{
		if ($result->is_allowed()) {
			throw new \LogicException('handle_result() called with allowed result');
		}

		if ($result->requires_challenge()) {
			$this->serve_challenge($result);
		}

		$this->serve_block_page($result);
	}

	private function detect(RequestPackage $package): Result
	{
		// 1. Whitelist (always-on, immediate allow)
		if ($this->is_whitelisted($package)) return Result::allow($package);

		// 2. Custom Rules (always-on, can block/challenge/allow/log)
		try {
			if ($result = $this->check_custom_rules($package)) return $result;
		} catch (\Throwable $e) {
			ErrorReporter::error($this->adapter, 'custom_rules check failed', [
				'error' => $e->getMessage(),
			], 'custom_rules_check_failure');
		}

		// 3. Known Bots (always-on — BotDetector only blocks verified-spoof attempts)
		try {
			if ($result = $this->bot_detector->detect($package)) return $result;
		} catch (\Throwable $e) {
			ErrorReporter::error($this->adapter, 'BotDetector failed', [
				'error' => $e->getMessage(),
			], 'bot_detector_failure');
		}

		// === Experimental / FP-risk detectors (gated by config) ===

		// 3b. Head Request Detection (catches HEAD flooding)
		if ($this->config->enable_head_request_detection) {
			try {
				if ($result = $this->head_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'HeadRequestDetector failed', [
					'error' => $e->getMessage(),
				], 'head_detector_failure');
			}
		}

		// 4. Client Hints Validation (catches spoofed UAs)
		if ($this->config->enable_client_hints_validation) {
			try {
				if ($result = $this->client_hints_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'ClientHintsDetector failed', [
					'error' => $e->getMessage(),
				], 'client_hints_detector_failure');
			}
		}

		// 5. Blacklist (attacks, malicious UA) (always-on — basic attack patterns)
		try {
			if ($result = $this->blacklist_detector->detect($package)) return $result;
		} catch (\Throwable $e) {
			ErrorReporter::error($this->adapter, 'BlacklistDetector failed', [
				'error' => $e->getMessage(),
			], 'blacklist_detector_failure');
		}

		// 5b. Asset Scraping Detection (catches AI training scrapers)
		if ($this->config->enable_asset_scraping_detection) {
			try {
				if ($result = $this->asset_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'AssetScrapingDetector failed', [
					'error' => $e->getMessage(),
				], 'asset_detector_failure');
			}
		}

		// 6. Behavioral (rate, rotating UA, think time) (FP risk — OFF in normal strictness)
		if ($this->config->enable_behavioral_analysis) {
			try {
				if ($result = $this->behavioral_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'BehavioralDetector failed', [
					'error' => $e->getMessage(),
				], 'behavioral_detector_failure');
			}
		}

		// 7. Agentic Detection (AI agent patterns)
		if ($this->config->enable_agentic_detection) {
			try {
				if ($result = $this->agentic_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'AgenticBehaviorDetector failed', [
					'error' => $e->getMessage(),
				], 'agentic_detector_failure');
			}
		}

		// 8. Rate limiting (ON in normal/strict strictness)
		if ($this->config->rate_limit_enabled) {
			try {
				if ($result = $this->rate_limit_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'RateLimitDetector failed', [
					'error' => $e->getMessage(),
				], 'rate_limit_detector_failure');
			}
		}

		// 9. DNSBL (network dependent — OFF by default)
		if ($this->config->dnsbl_enabled) {
			try {
				if ($result = $this->dnsbl_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'DnsblDetector failed', [
					'error' => $e->getMessage(),
				], 'dnsbl_detector_failure');
			}
		}

		// 10. Fingerprinting
		if ($this->config->enable_fingerprinting) {
			try {
				if ($result = $this->fingerprint_detector->detect($package)) return $result;
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter, 'FingerprintDetector failed', [
					'error' => $e->getMessage(),
				], 'fingerprint_detector_failure');
			}
		}

		return Result::allow($package);
	}

	// === Static Resource Skip Logic ===
	private function should_skip_static(string $uri): bool
	{
		try {
			$path = parse_url($uri, PHP_URL_PATH) ?? $uri;

			// Check skip_extensions
			foreach ($this->config->skip_static_extensions as $ext) {
				if (str_ends_with(strtolower($path), '.' . $ext)) {
					return true;
				}
			}

			// Check skip_paths
			foreach ($this->config->skip_static_paths as $prefix) {
				if (str_starts_with($path, $prefix)) {
					return true;
				}
			}
		} catch (\Throwable $e) {
			// If static-skip evaluation fails, don't skip — proceed with detection
		}

		return false;
	}

	private function is_whitelisted(RequestPackage $package): bool
	{
		try {
			$whitelist = $this->adapter->get_whitelist();
			if (!is_array($whitelist)) {
				return false;
			}

			if (!empty($whitelist['ip']) && IpUtil::match_any($package->ip, $whitelist['ip'])) {
				return true;
			}

			if (!empty($whitelist['useragent']) && in_array($package->user_agent, $whitelist['useragent'], true)) {
				return true;
			}

			if (!empty($whitelist['url'])) {
				$clean = strtok($package->request_uri, '?');
				foreach ($whitelist['url'] as $prefix) {
					if (str_starts_with($clean, $prefix)) {
						return true;
					}
				}
			}

			if (!empty($whitelist['asn']) && $package->asn && in_array($package->asn, $whitelist['asn'], true)) {
				return true;
			}

			if (!empty($whitelist['country']) && $package->country && in_array($package->country, $whitelist['country'], true)) {
				return true;
			}
		} catch (\Throwable $e) {
			// Whitelist lookup failure must not produce a security bypass,
			// but also must not crash. Treat as "not whitelisted".
		}

		return false;
	}

	private function check_custom_rules(RequestPackage $package): ?Result
	{
		foreach ($this->config->custom_rules as $rule) {
			if (!is_array($rule)) continue;

			$match = match($rule['type'] ?? '') {
				'ip'         => IpUtil::match_any($package->ip, (array)($rule['value'] ?? [])),
				'ua_regex'   => @preg_match($rule['value'] ?? '', $package->user_agent) === 1,
				'ua_contains'=> stripos($package->user_agent, $rule['value'] ?? '') !== false,
				'asn'        => $package->asn && $package->asn === ($rule['value'] ?? ''),
				'country'    => $package->country && $package->country === ($rule['value'] ?? ''),
				'header'     => isset($package->headers_mixed[$rule['header'] ?? '']) &&
					(($rule['value'] ?? '') === '' || stripos($package->headers_mixed[$rule['header']], $rule['value']) !== false),
				default      => false,
			};

			if ($match) {
				return match($rule['action'] ?? 'block') {
					'allow'     => Result::allow($package),
					'challenge' => Result::challenge(ResultCode::CHALLENGE_REQUIRED, 'Custom rule challenge', $package),
					'log'       => null,
					default     => Result::block(ResultCode::BLOCKED_CUSTOM_RULE, 'Blocked by custom rule', $package, ['rule_id' => $rule['id'] ?? 'unknown']),
				};
			}
		}
		return null;
	}

	private function install_once(): void
	{
		if ($this->install_done) {
			return;
		}
		// Set FIRST so we never retry on this process, even if install fails
		$this->install_done = true;

		if (defined('BB2_NO_CREATE') || !$this->config->logging) {
			return;
		}

		// CRITICAL: install errors must NEVER propagate.
		// The host application must continue serving even if the log table
		// cannot be created (DB down, missing privileges, schema mismatch, etc.)
		try {
			$table = $this->config->adapter->get_settings()['log_table'] ?? 'bad_behaviour';
			$schema = $this->adapter->get_table_schema($table);

			// Handle both array (SQLite) and string (MySQL)
			$statements = is_array($schema) ? $schema : [$schema];

			foreach ($statements as $sql) {
				if (!$this->adapter->query($sql)) {
					ErrorReporter::error($this->adapter,
						'table creation query returned false', [
							'sql_preview' => substr((string)$sql, 0, 200),
						], 'install_query_failed'
					);
				}
			}
		} catch (\Throwable $e) {
			// Swallow + log. Logging itself must not throw.
			ErrorReporter::error($this->adapter, 'install_once failed', [
				'error' => $e->getMessage(),
				'exception_class' => get_class($e),
				'hint' => 'Run bin/install-bb.php to set up the log table manually, '
					. 'or check database connectivity and permissions',
			], 'install_once_failure');
		}
	}

	private function serve_challenge(Result $result): never
	{
		try {
			$challenge = $this->create_challenge();
			$html = $challenge->render($result->package?->request_uri ?? '/');

			http_response_code(403);
			header('Content-Type: text/html; charset=utf-8');
			echo $html;
		} catch (\Throwable $e) {
			// If challenge rendering fails, fall back to block page
			ErrorReporter::error($this->adapter, 'challenge render failed', [
				'error' => $e->getMessage(),
			], 'challenge_render_failure');
			$this->serve_block_page($result);
		}
		exit;
	}

	private function serve_block_page(Result $result): never
	{
		try {
			http_response_code($result->http_status());
			header('Content-Type: text/html; charset=utf-8');

			$support = htmlspecialchars($result->support_key ?? 'unknown');
			$message = htmlspecialchars($result->message);
			$uri = htmlspecialchars($result->package?->request_uri ?? '/');

			// Use !empty() consistently for both flags
			$show_email = !empty($this->config->show_contact_info);
			$detailed = !empty($this->config->show_detailed_block_page);

			$email = $show_email ? htmlspecialchars((string) $this->adapter->get_email()) : null;

			if ($detailed) {
				$contact_para = ($show_email && $email)
				? "<p>If you are unable to fix the problem yourself, please contact <a href=\"mailto:$email\">$email</a> and provide the technical support key shown above.</p>"
				: '';

				$content = <<<HTML
			<h1>Access Denied</h1>
			<p>We're sorry, but we could not fulfill your request for <code>$uri</code> on this server.</p>
			<p><strong>Reason:</strong> $message</p>
			<p>Your technical support key is: <strong>$support</strong></p>
			$contact_para
HTML;
			} else {
				$content = <<<HTML
			<h1>Access Denied</h1>
			<p>You don't have permission to access this resource.</p>
			<div class="ref">Reference #$support</div>
HTML;
			}

			echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Access Denied</title>
		<style>
			body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
			.card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
			h1 { color: #dc3545; margin-bottom: 1rem; }
			.ref { font-family: monospace; background: #f8f9fa; padding: 0.5rem; border-radius: 4px; display: inline-block; margin-top: 1rem; }
			code { background: #f8f9fa; padding: 0.2rem 0.4rem; border-radius: 3px; }
		</style>
</head>
<body>
		<div class="card">
			$content
		</div>
</body>
</html>
HTML;
		} catch (\Throwable $e) {
			// Last-resort: at least output a minimal plain-text block page
			// rather than letting BadBehaviour crash the response.
			try {
				http_response_code($result->http_status());
				header('Content-Type: text/plain; charset=utf-8');
				echo "Access Denied\nReference: " . htmlspecialchars($result->support_key ?? 'unknown') . "\n";
			} catch (\Throwable $e2) {
				// Truly nothing we can do; exit gracefully
			}
		}
		exit;
	}

	private function create_challenge(): \BadBehaviour\Challenge\ChallengeInterface
	{
		return match($this->config->challenge_provider) {
			'hcaptcha'    => new \BadBehaviour\Challenge\HCaptchaChallenge($this->config),
			'recaptcha'   => new \BadBehaviour\Challenge\RecaptchaChallenge($this->config),
			'turnstile'   => new \BadBehaviour\Challenge\TurnstileChallenge($this->config),
			default       => new \BadBehaviour\Challenge\BuiltinChallenge($this->config, $this->adapter),
		};
	}

	// Convenience factory
	public static function with_adapter(
		\BadBehaviour\Core\Interfaces\AdapterInterface $adapter,
		array $config_overrides = []
	): self {
		// Load settings from adapter (which reads bb_config.php for WackoWiki)
		try {
			$adapter_settings = $adapter->get_settings();
			if (!is_array($adapter_settings)) {
				$adapter_settings = [];
			}
		} catch (\Throwable $e) {
			$adapter_settings = [];
		}

		// Merge: adapter settings < explicit overrides
		$merged = array_merge($adapter_settings, $config_overrides);

		$config = Configuration::from_array($merged, $adapter);
		return new self($config);
	}
}
