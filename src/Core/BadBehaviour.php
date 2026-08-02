<?php

declare(strict_types=1);

namespace BadBehaviour\Core;

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
	private RegistryInterface $registry;  // ← NEW

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
	 *        If null, loads from config/bb_registry.php (or falls back to DefaultRegistry).
	 */
	public function __construct(Configuration $config, ?RegistryInterface $registry = null)
	{
		$this->config = $config;
		$this->adapter = $config->adapter ?? throw new \InvalidArgumentException('Adapter is required');
		$this->logger = $config->logger;
		$this->cache = $config->cache;
		$this->geoip = $config->geoip;

		// === Registry: explicit injection > config file > default ===
		$this->registry = $registry ?? RegistryFactory::from_file();

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
		if ($this->geoip && $geoip = $this->geoip->lookup($package->ip)) {
			$package = $package->with_enrichment(
				$geoip['asn'] ?? null,
				$geoip['country'] ?? null,
				null,
				null
			);
		}

		// Enrich with fingerprints (cheap — just string hashing)
		$ja3 = HeaderUtil::get_ja3_fingerprint();
		$h2  = HeaderUtil::get_h2_settings();
		$package = $package->with_enrichment(null, null, $ja3, $h2);

		// Run detection pipeline
		$result = $this->detect($package);

		// Logging: blocked/challenged always, allowed only when verbose
		if ($this->config->logging) {
			$should_log = !$result->is_allowed() || $this->config->verbose;
			if ($should_log) {
				$this->adapter->log_request($package, $result);
			}
		}

		return $result;
	}

	public function run_test_package(RequestPackage $package): Result
	{
		if ($this->should_skip_static($package->request_uri)) {
			return Result::allow($package);
		}

		$ja3 = HeaderUtil::get_ja3_fingerprint();
		$h2 = HeaderUtil::get_h2_settings();
		$package = $package->with_enrichment(null, null, $ja3, $h2);

		$result = $this->detect($package);

		// Same logging logic as run()
		if ($this->config->logging) {
			$should_log = !$result->is_allowed() || $this->config->verbose;
			if ($should_log) {
				$this->adapter->log_request($package, $result);
			}
		}

		return $result;
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
		// 1. Whitelist
		if ($this->is_whitelisted($package)) return Result::allow($package);

		// 2. Custom Rules
		if ($result = $this->check_custom_rules($package)) return $result;

		// 3. Known Bots (verified ALLOW)
		if ($result = $this->bot_detector->detect($package)) return $result;

		// 3b. Head Request Detection (catches HEAD flooding)
		if ($this->config->enable_head_request_detection) {
			if ($result = $this->head_detector->detect($package)) return $result;
		}

		// 4. Client Hints Validation (catches spoofed UAs)
		if ($this->config->enable_client_hints_validation) {
			if ($result = $this->client_hints_detector->detect($package)) return $result;
		}

		// 5. Blacklist (attacks, malicious UA)
		if ($result = $this->blacklist_detector->detect($package)) return $result;

		// 5b. Asset Scraping Detection (catches AI training scrapers)
		if ($this->config->enable_asset_scraping_detection) {
			if ($result = $this->asset_detector->detect($package)) return $result;
		}

		// 6. Behavioral (rate, rotating UA, think time)
		if ($this->config->enable_behavioral_analysis) {
			if ($result = $this->behavioral_detector->detect($package)) return $result;
		}

		// 7. Agentic Detection (AI agent patterns)
		if ($this->config->enable_agentic_detection) {
			if ($result = $this->agentic_detector->detect($package)) return $result;
		}

		// 8. Rate limiting
		if ($this->config->rate_limit_enabled) {
			if ($result = $this->rate_limit_detector->detect($package)) return $result;
		}

		// 9. DNSBL
		if ($this->config->dnsbl_enabled) {
			if ($result = $this->dnsbl_detector->detect($package)) return $result;
		}

		// 10. Fingerprinting
		if ($this->config->enable_fingerprinting) {
			if ($result = $this->fingerprint_detector->detect($package)) return $result;
		}

		return Result::allow($package);
	}

	// === Static Resource Skip Logic ===
	private function should_skip_static(string $uri): bool
	{
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

		return false;
	}

	private function is_whitelisted(RequestPackage $package): bool
	{
		$whitelist = $this->adapter->get_whitelist();

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

		return false;
	}

	private function check_custom_rules(RequestPackage $package): ?Result
	{
		foreach ($this->config->custom_rules as $rule) {
			$match = match($rule['type'] ?? '') {
				'ip'         => IpUtil::match_any($package->ip, (array)($rule['value'] ?? [])),
				'ua_regex'   => preg_match($rule['value'], $package->user_agent) === 1,
				'ua_contains'=> stripos($package->user_agent, $rule['value']) !== false,
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
		$this->install_done = true;

		if (defined('BB2_NO_CREATE') || !$this->config->logging) {
			return;
		}

		$table = $this->config->adapter->get_settings()['log_table'] ?? 'bad_behaviour';
		$schema = $this->adapter->get_table_schema($table);

		// Handle both array (SQLite) and string (MySQL)
		$statements = is_array($schema) ? $schema : [$schema];

		foreach ($statements as $sql) {
			$this->adapter->query($sql);
		}
	}

	private function serve_challenge(Result $result): never
	{
		$challenge = $this->create_challenge();
		$html = $challenge->render($result->package?->request_uri ?? '/');

		http_response_code(403);
		header('Content-Type: text/html; charset=utf-8');
		echo $html;
		exit;
	}

	private function serve_block_page(Result $result): never
	{
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
		$adapter_settings = $adapter->get_settings();

		// Merge: adapter settings < explicit overrides
		$merged = array_merge($adapter_settings, $config_overrides);

		$config = Configuration::from_array($merged, $adapter);
		return new self($config);
	}
}
