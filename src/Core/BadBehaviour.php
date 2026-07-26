<?php

namespace BadBehaviour\Core;

use BadBehaviour\Bot\Registry;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotAction;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Interfaces\GeoIpInterface;
use BadBehaviour\Core\Interfaces\LoggerInterface;
use BadBehaviour\Detection\BotDetector;
use BadBehaviour\Detection\BlacklistDetector;
use BadBehaviour\Detection\BehavioralDetector;
use BadBehaviour\Detection\FingerprintDetector;
use BadBehaviour\Detection\RateLimitDetector;
use BadBehaviour\Detection\DnsblDetector;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Util\HeaderUtil;
use BadBehaviour\Util\IpUtil;

class BadBehaviour
{
	private Configuration $config;
	private AdapterInterface $adapter;
	private ?LoggerInterface $logger;
	private ?CacheInterface $cache;
	private ?GeoIpInterface $geoip;

	private BotDetector $bot_detector;
	private BlacklistDetector $blacklist_detector;
	private BehavioralDetector $behavioral_detector;
	private FingerprintDetector $fingerprint_detector;
	private RateLimitDetector $rate_limit_detector;
	private DnsblDetector $dnsbl_detector;

	public function __construct(Configuration $config)
	{
		$this->config = $config;
		$this->adapter = $config->adapter ?? throw new \InvalidArgumentException('Adapter is required');
		$this->logger = $config->logger;
		$this->cache = $config->cache;
		$this->geoip = $config->geoip;

		$this->bot_detector = new BotDetector($this->config, $this->adapter);
		$this->blacklist_detector = new BlacklistDetector($this->config);
		$this->behavioral_detector = new BehavioralDetector($this->config, $this->adapter);
		$this->fingerprint_detector = new FingerprintDetector($this->config, $this->adapter);
		$this->rate_limit_detector = new RateLimitDetector($this->config, $this->adapter);
		$this->dnsbl_detector = new DnsblDetector($this->config);
	}

	public function run(array $server = null): Result
	{
		if (php_sapi_name() === 'cli') {
			return Result::allow();
		}

		$this->install();

		// Build request package
		if ($server !== null) {
			$package = RequestPackage::from_server_globals([
				'reverse_proxy' => $this->config->reverse_proxy,
				'reverse_proxy_header' => $this->config->reverse_proxy_header,
				'reverse_proxy_addresses' => $this->config->reverse_proxy_addresses,
			], $server);
		} else {
			$package = RequestPackage::from_globals([
				'reverse_proxy' => $this->config->reverse_proxy,
				'reverse_proxy_header' => $this->config->reverse_proxy_header,
				'reverse_proxy_addresses' => $this->config->reverse_proxy_addresses,
			]);
		}

		// Skip static resources
		if ($this->should_skip_static($package->request_uri)) {
			return Result::allow($package);
		}

		// Enrich with GeoIP
		if ($this->geoip && $geoip = $this->geoip->lookup($package->ip)) {
			$package = $package->with_enrichment(
				$geoip['asn'] ?? null,
				$geoip['country'] ?? null,
				null, null
			);
		}

		// Enrich with fingerprints
		$ja3 = HeaderUtil::get_ja3_fingerprint();
		$h2 = HeaderUtil::get_h2_settings();
		$package = $package->with_enrichment(null, null, $ja3, $h2);

		// Run detection pipeline
		$result = $this->detect($package);

		// Always log blocked/challenged requests
		// Only log allowed requests when verbose = true
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
		
		// Same logging logic
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
		if ($this->is_whitelisted($package)) {
			return Result::allow($package);
		}

		// 2. Custom Rules
		if ($result = $this->check_custom_rules($package)) {
			return $result;
		}

		// 3. Known Bots (verified search engines/AI BYPASS ALL)
		if ($result = $this->bot_detector->detect($package)) {
			return $result;
		}

		// 4. Blacklist (malicious UA, URL attacks, form body)
		if ($result = $this->blacklist_detector->detect($package)) {
			return $result;
		}

		// 5. Behavioral (rate anomalies, rotating UA, think time, headers)
		if ($this->config->enable_behavioral_analysis) {
			if ($result = $this->behavioral_detector->detect($package)) {
				return $result;
			}
		}

		// 6. Rate limiting
		if ($this->config->rate_limit_enabled) {
			if ($result = $this->rate_limit_detector->detect($package)) {
				return $result;
			}
		}

		// 7. DNSBL / http:BL (opt-in, runs last)
		if ($this->config->dnsbl_enabled) {
			if ($result = $this->dnsbl_detector->detect($package)) {
				return $result;
			}
		}

		// 8. Fingerprinting (opt-in)
		if ($this->config->enable_fingerprinting) {
			if ($result = $this->fingerprint_detector->detect($package)) {
				return $result;
			}
		}

		return Result::allow($package);
	}

	// === NEW: Static Resource Skip Logic ===
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

	private function install(): void
	{
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

		$email = htmlspecialchars($this->adapter->get_email());
		$uri = htmlspecialchars($result->package?->request_uri ?? '/');
		$support = htmlspecialchars($result->support_key ?? 'unknown');
		$message = htmlspecialchars($result->message);

		echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><title>HTTP Error {$result->http_status()}</title></head>
<body>
<h1>Error {$result->http_status()}</h1>
<p>We're sorry, but we could not fulfill your request for <code>$uri</code> on this server.</p>
<p>$message</p>
<p>Your technical support key is: <strong>$support</strong></p>
<p>If you are unable to fix the problem yourself, please contact <a href="mailto:$email">$email</a> and provide the technical support key shown above.</p>
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
	public static function withAdapter(
		\BadBehaviour\Core\Interfaces\AdapterInterface $adapter,
		array $configOverrides = []
	): self
	{
		$config = Configuration::from_array($configOverrides, $adapter);
		return new self($config);
	}
}