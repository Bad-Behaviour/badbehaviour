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
	 * Optional on-demand IP range refresher. Null when disabled by
	 * config or when construction failed. See run_internal() for
	 * how/when it's invoked.
	 */
	private ?\BadBehaviour\Feeds\OnDemandRefresher $refresh_checker = null;

	/**
	 * @param Configuration $config
	 * @param RegistryInterface|null $registry Optional bot registry override.
	 *        If null, loads from config/bb_registry.php (or falls back to
	 *        the configured preset's registry).
	 * @param CacheInterface|null $cache Optional cache backend override.
	 *        If null, uses $config->cache; if that's also null, falls back
	 *        to $adapter if it implements CacheInterface.
	 *        Exposed primarily for testing — production code should set
	 *        the cache via Configuration::from_array()'s adapter param
	 *        (adapters that need cache typically implement CacheInterface
	 *        themselves, so the fallback chain usually works without
	 *        explicit injection).
	 */
	public function __construct(
		Configuration $config,
		?RegistryInterface $registry = null,
		?CacheInterface $cache = null
	) {
		$this->config = $config;
		$this->adapter = $config->adapter ?? throw new \InvalidArgumentException('Adapter is required');
		$this->logger = $config->logger;
		// Cache resolution priority:
		//   1. explicit constructor argument (testing/manual override)
		//   2. $config->cache (production setting via Configuration)
		//   3. $adapter if it implements CacheInterface (adapter-as-cache)
		$this->cache = $cache ?? $config->cache ?? (
			$this->adapter instanceof CacheInterface ? $this->adapter : null
		);
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

		// === NEW: BlacklistDetector receives a closure bound to this
		// instance's monitor-only state, so it can gate the ua_is_bot
		// short-circuit when the library is effectively in monitor-only mode.
		$this->blacklist_detector = new BlacklistDetector($this->config);

		$this->behavioral_detector = new BehavioralDetector($this->config, $this->adapter);
		$this->fingerprint_detector = new FingerprintDetector($this->config, $this->adapter);
		$this->rate_limit_detector = new RateLimitDetector($this->config, $this->adapter);
		$this->dnsbl_detector = new DnsblDetector($this->config);
		$this->client_hints_detector = new ClientHintsDetector($this->config);
		$this->agentic_detector = new AgenticBehaviorDetector($this->config, $this->adapter);
		$this->head_detector = new HeadRequestDetector($this->config, $this->adapter);
		$this->asset_detector = new AssetScrapingDetector($this->config, $this->adapter);

		// === On-demand IP range refresher ===
		//
		// Constructed lazily and gated by config — default off (opt-in).
		// When enabled, replaces the need for `bin/update-ip-ranges.php`
		// cron on deployments without scheduled-job support.
		//
		// Failure to instantiate (missing cache backend, broken cloud
		// provider setup) is non-fatal: the refresher stays null and
		// run_internal() treats on-demand refresh as a no-op. Detection
		// continues to work using the shipped static IP ranges.
		if ($this->config->on_demand_ip_refresh_enabled) {
			try {
				// Pick the best available cache backend. Prefer explicit
				// config injection; fall back to the adapter if it implements
				// CacheInterface.
				if ($this->cache !== null) {
					$cache = $this->cache;
				} elseif ($this->adapter instanceof CacheInterface) {
					$cache = $this->adapter;
				} else {
					throw new \RuntimeException(
						'No CacheInterface available — pass $config->cache or use an adapter that implements CacheInterface'
						);
				}

				$this->refresh_checker = new \BadBehaviour\Feeds\OnDemandRefresher(
					cache: $cache,
					registry: new \BadBehaviour\Feeds\FeedRegistry($cache),
					cloud: new \BadBehaviour\Feeds\CloudIpRangeProvider($cache),
					options: [
						'probability_denominator' => $this->config->on_demand_ip_refresh_probability_denominator,
						'min_age_seconds'         => $this->config->on_demand_ip_refresh_min_age_seconds,
						'lock_ttl'                => $this->config->on_demand_ip_refresh_lock_ttl,
						'cache_ttl'               => $this->config->on_demand_ip_refresh_cache_ttl,
						'feed_timeout_seconds'    => $this->config->on_demand_ip_refresh_feed_timeout_seconds,
						'bot_ids'                 => $this->config->on_demand_ip_refresh_bot_ids ?: null,
						'cloud_providers'         => $this->config->on_demand_ip_refresh_cloud_providers ?: null,
					],
					);
			} catch (\Throwable $e) {
				ErrorReporter::error($this->adapter,
					'BadBehaviour: on-demand refresher init failed; disabled',
					[
						'error' => $e->getMessage(),
						'exception_class' => $e::class,
						'hint' => 'Check cache backend connectivity and config.',
					],
					'on_demand_refresher_init_failed'
					);
				$this->refresh_checker = null;
			}
		}
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

	// ====================================================================
	// ON-DEMAND IP REFRESH API
	// ====================================================================
	//
	// Exposed for:
	//   - Integration tests that assert refresh behavior end-to-end
	//   - Hosts that want manual control over refresh timing
	//   - Admin tooling (e.g., "refresh now" button in admin UI)
	//
	// All methods are safe to call regardless of whether the feature is
	// enabled in config — they return null/false when disabled.

	/**
	 * Evaluate whether the on-demand refresher would schedule a background
	 * refresh on the next detection call.
	 *
	 * Runs the four-gate check (probability × cooldown × staleness × mutex)
	 * WITHOUT acquiring the lock or triggering any side effects. Safe to
	 * call from anywhere.
	 *
	 * Returns null when on-demand refresh is disabled in config
	 * (no refresher constructed = no decision possible).
	 *
	 * @return \BadBehaviour\Feeds\RefreshDecision|null
	 */
	public function peek_refresh_decision(): ?\BadBehaviour\Feeds\RefreshDecision
	{
		try {
			$refresher = $this->build_refresher();
			if ($refresher === null) {
				return null;
			}
			return $refresher->maybe_refresh();
		} catch (\Throwable $e) {
			ErrorReporter::error($this->adapter,
				'peek_refresh_decision failed', [
					'error' => $e->getMessage(),
				], 'peek_refresh_decision_failure');
			return null;
		}
	}

	/**
	 * Check if the on-demand refresher has been constructed and is usable.
	 *
	 * True when:
	 *   - on_demand_ip_refresh_enabled = true in config
	 *   - Cache backend is available (either $config->cache or adapter
	 *     implements CacheInterface)
	 *
	 * @return bool
	 */
	public function is_on_demand_refresh_enabled(): bool
	{
		return $this->config->on_demand_ip_refresh_enabled
		&& $this->resolve_cache() !== null;
	}

	/**
	 * Force an immediate synchronous refresh.
	 *
	 * Bypasses all gates (probability, cooldown, staleness, mutex) and
	 * runs the refresh NOW, returning the result. Useful for:
	 *   - Admin "refresh now" buttons
	 *   - Cron replacement scripts (manual trigger from admin UI)
	 *   - Tests that need to assert refresh behavior
	 *
	 * Returns null when refresh is not configured. Returns the
	 * RefreshResult on success/partial/failure.
	 *
	 * NOTE: This does NOT take the mutex. If another worker is refreshing
	 * concurrently, you'll both write to the cache (last writer wins).
	 * Acceptable for manual/admin triggers; not for hot-path use.
	 *
	 * @return \BadBehaviour\Feeds\RefreshResult|null
	 */
	public function force_refresh_now(): ?\BadBehaviour\Feeds\RefreshResult
	{
		try {
			$refresher = $this->build_refresher();
			if ($refresher === null) {
				return null;
			}
			return $refresher->do_refresh();
		} catch (\Throwable $e) {
			ErrorReporter::error($this->adapter,
				'force_refresh_now failed', [
					'error' => $e->getMessage(),
					'exception_class' => get_class($e),
				], 'force_refresh_now_failure');
			return null;
		}
	}

	/**
	 * Register a shutdown function that runs the refresh IF the gates
	 * pass. Mirrors the production wiring — call this from your bootstrap
	 * or middleware to opt into automatic refresh.
	 *
	 * Returns true if a shutdown function was registered, false if:
	 *   - on-demand refresh is disabled
	 *   - no cache backend available
	 *   - refresher construction failed
	 *
	 * Tests use this to verify the wiring without actually waiting for
	 * shutdown.
	 */
	public function register_shutdown_refresh(): bool
	{
		$refresher = $this->build_refresher();
		if ($refresher === null) {
			return false;
		}

		register_shutdown_function(static function () use ($refresher): void {
			// Re-evaluate gates at shutdown time (cache state may have
			// changed since register_shutdown_refresh() was called).
			$decision = $refresher->maybe_refresh();
			if ($decision->should_schedule) {
				$refresher->do_refresh();
			}
		});

			return true;
	}

	/**
	 * Get the result of the most recent force_refresh_now() or shutdown
	 * refresh. Null if no refresh has completed on this instance.
	 *
	 * Used by tests and admin dashboards to inspect refresh metrics.
	 */
	public function get_last_refresh_result(): ?\BadBehaviour\Feeds\RefreshResult
	{
		$refresher = $this->build_refresher();
		if ($refresher === null) {
			return null;
		}
		return $refresher->get_last_result();
	}

	// === Internal helpers (package-private) ===

	/**
	 * Build an OnDemandRefresher from current config + adapter.
	 *
	 * Returns null when:
	 *   - on_demand_ip_refresh_enabled = false
	 *   - no cache backend is available
	 *
	 * Cached per-instance so multiple calls don't rebuild.
	 */
	private ?\BadBehaviour\Feeds\OnDemandRefresher $refresher_instance = null;

	private function build_refresher(): ?\BadBehaviour\Feeds\OnDemandRefresher
	{
		if (!$this->config->on_demand_ip_refresh_enabled) {
			return null;
		}
		if ($this->refresher_instance !== null) {
			return $this->refresher_instance;
		}

		try {
			$cache = $this->resolve_cache();
			if ($cache === null) {
				return null;
			}

			$registry = new \BadBehaviour\Feeds\FeedRegistry($cache);
			$cloud = new \BadBehaviour\Feeds\CloudIpRangeProvider($cache);

			$this->refresher_instance = new \BadBehaviour\Feeds\OnDemandRefresher(
				cache: $cache,
				registry: $registry,
				cloud: $cloud,
				options: [
					'probability_denominator' => $this->config->on_demand_ip_refresh_probability_denominator,
					'min_age_seconds'         => $this->config->on_demand_ip_refresh_min_age_seconds,
					'lock_ttl'                => $this->config->on_demand_ip_refresh_lock_ttl,
					'cache_ttl'               => $this->config->on_demand_ip_refresh_cache_ttl,
					'feed_timeout_seconds'    => $this->config->on_demand_ip_refresh_feed_timeout_seconds,
					'bot_ids'                 => $this->config->on_demand_ip_refresh_bot_ids ?: null,
					'cloud_providers'         => $this->config->on_demand_ip_refresh_cloud_providers ?: null,
				],
				);
			return $this->refresher_instance;
		} catch (\Throwable $e) {
			ErrorReporter::error($this->adapter,
				'OnDemandRefresher construction failed', [
					'error' => $e->getMessage(),
				], 'on_demand_refresher_build_failure');
			return null;
		}
	}

	/**
	 * Resolve the cache backend from config or adapter.
	 *
	 * Priority: $config->cache (explicit injection) > adapter implementing
	 * CacheInterface (fallback for adapters like GenericAdapter, WackoWiki).
	 */
	private function resolve_cache(): ?\BadBehaviour\Core\Interfaces\CacheInterface
	{
		if ($this->config->cache instanceof \BadBehaviour\Core\Interfaces\CacheInterface) {
			return $this->config->cache;
		}
		if ($this->adapter instanceof \BadBehaviour\Core\Interfaces\CacheInterface) {
			return $this->adapter;
		}
		return null;
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
	 * logs traffic but does not block. Use is_monitor_only_effective() to
	 * also detect intentionally monitor-only configurations.
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
	 * Is the library in monitor-only mode BY CONFIGURATION?
	 *
	 * True when:
	 *   - Configured strictness is 'monitor-only', OR
	 *   - All active defenses are disabled (defensive FP-prevention)
	 *
	 * Does NOT include safe-mode (use is_monitor_only_effective() for that).
	 * Kept as-is for backward compatibility.
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
	 * Is the library EFFECTIVELY in monitor-only mode (for demotion decisions)?
	 *
	 * True when ANY of:
	 *   - Safe-mode is active (config missing/invalid)
	 *   - Configured strictness is 'monitor-only'
	 *   - All active defenses are disabled
	 *
	 * Used by:
	 *   - maybe_demote_to_monitored() in run_internal()
	 *   - BlacklistDetector (via closure) to skip the ua_is_bot short-circuit
	 *   - diagnostics() to surface the effective policy to operators
	 */
	public function is_monitor_only_effective(): bool
	{
		if ($this->is_in_safe_mode()) {
			return true;
		}
		return $this->is_monitor_only();
	}

	/**
	 * Return diagnostic information for admin dashboards / health checks.
	 *
	 * @return array{
	 *     safe_mode: bool,
	 *     monitor_only: bool,
	 *     monitor_only_effective: bool,
	 *     strictness: string,
	 *     preset: string,
	 *     logging_enabled: bool,
	 *     detectors_active: array<string, bool>,
	 *     on_demand_refresh: array<string, mixed>,
	 *     config_loaded: bool,
	 *     hint: ?string
	 * }
	 */
	public function diagnostics(): array
	{
		$safe_mode = $this->is_in_safe_mode();
		$monitor_only = $this->is_monitor_only();
		$monitor_only_effective = $this->is_monitor_only_effective();
		$strictness = $this->config->get_strictness();

		$detectors = [
			'blacklist'    => true, // always-on (except in safe-mode)
			'bot'          => true, // always-on (except in safe-mode)
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

		$on_demand_refresh = [
			'enabled'                 => $this->config->on_demand_ip_refresh_enabled,
			'usable'                  => $this->is_on_demand_refresh_enabled(),
			'probability_denominator' => $this->config->on_demand_ip_refresh_probability_denominator,
			'min_age_seconds'         => $this->config->on_demand_ip_refresh_min_age_seconds,
			'cache_ttl'               => $this->config->on_demand_ip_refresh_cache_ttl,
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
				  . 'or \'strict\' when you\'re ready to enforce. '
				  . 'Only obvious attacks (empty UA, raw XSS in URI) are still enforced.';
		} elseif ($monitor_only_effective && !$safe_mode) {
			// All defenses off but not by user choice
			$hint = 'All active defenses are disabled. Set strictness to \'normal\' '
				  . 'or \'strict\' in your config to enable bot protection.';
		}

		return [
			'safe_mode'              => $safe_mode,
			'monitor_only'           => $monitor_only,
			'monitor_only_effective' => $monitor_only_effective,
			'strictness'             => $strictness,
			'preset'                 => $this->config->get_preset(),
			'config_loaded'          => $config_loaded,
			'logging_enabled'        => $this->config->logging,
			'detectors_active'       => $detectors,
			'on_demand_refresh'      => $on_demand_refresh,
			'hint'                   => $hint,
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

		// Build the package FIRST — we need IP/UA/URI before any detection
		// and before the timeout handler (so it has something to log).
		$package = $server !== null
			? RequestPackage::from_server_globals($proxy_settings, $server)
			: RequestPackage::from_globals($proxy_settings);

		// FAST PATH 1: Empty UA → immediate block. NEVER demoted in
		// monitor-only mode — no UA = never a legitimate request.
		if (empty($package->user_agent) || strlen(trim($package->user_agent)) < 5) {
			$result = Result::block(
				ResultCode::BLOCKED_MALICIOUS_UA,
				'Empty or invalid User-Agent',
				$package
			);
			$this->log_and_return($package, $result);
			return $result;
		}

		// FAST PATH 2: Whitelisted IP → immediate allow (skip all detectors)
		if ($this->is_whitelisted($package)) {
			$result = Result::allow($package);
			$this->log_and_return($package, $result);
			return $result;
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

		// ============================================================
		// ON-DEMAND IP RANGE REFRESH GATE
		//
		// Cheap check (1/N requests trigger even the cache lookup) that
		// schedules a background fetch of fresh IP ranges. Runs AFTER
		// enrichment so we have what we need for logs, but BEFORE
		// detection so the next request benefits from any refresh that
		// completes during this request's shutdown handler.
		//
		// Latency impact on this request: ~1 mt_rand() call + 1-2 cache
		// reads. The actual feed fetches happen after the response is
		// sent (register_shutdown_function), so user-facing latency is
		// unaffected under PHP-FPM.
		//
		// Skipped entirely when the refresher isn't configured
		// (refresh_checker is null) — zero overhead for the common case.
		// ============================================================
		$this->maybe_schedule_refresh();

		// ============================================================
		// HARD TIME BUDGET — Detection must NEVER stall the request.
		// Wraps ONLY $this->detect() — enrichment and fast paths are
		// outside the budget so they can't be cut off mid-flight.
		// ============================================================
		$bb_run_start = microtime(true);
		$bb_budget_seconds = 1.5;

		// Set up hard timeout via pcntl_alarm (Unix only)
		$bb_pcntl_available = function_exists('pcntl_signal') && function_exists('pcntl_alarm');
		if ($bb_pcntl_available) {
			pcntl_signal(SIGALRM, function() {
				throw new \RuntimeException('bb_detection_timeout');
			});
		}

		// Wrap the detection pipeline
		try {
			if ($bb_pcntl_available) {
				pcntl_alarm((int)ceil($bb_budget_seconds));
			}

			$result = $this->detect($package);

			if ($bb_pcntl_available) {
				pcntl_alarm(0); // Cancel alarm
			}

		} catch (\RuntimeException $e) {
			if (strpos($e->getMessage(), 'bb_detection_timeout') !== false) {
				if ($bb_pcntl_available) {
					pcntl_alarm(0);
				}

				// $package is now in scope and safe to use
				ErrorReporter::error($this->adapter,
					'BadBehaviour detection timed out — request allowed as fallback',
					[
						'elapsed_ms' => round((microtime(true) - $bb_run_start) * 1000, 2),
						'budget_ms' => $bb_budget_seconds * 1000,
						'uri' => $package->request_uri ?? 'unknown',
						'ip' => $package->ip ?? 'unknown',
						'hint' => 'Detection exceeded time limit. Check slow detectors or disabled features.',
					],
					'bb_detection_timeout'
					);

				$result = Result::allow($package);
			} else {
				throw $e;
			}
		}

		// === monitor-only demotion ===
		// After detection, if monitor-only mode is active and the result is
		// a block/challenge, decide whether to enforce or demote to "monitored".
		$result = $this->maybe_demote_to_monitored($result);

		$this->log_and_return($package, $result);

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
			$result = $this->maybe_demote_to_monitored($result);

			// Same logging logic as run()
			if ($this->config->logging) {
				$should_log = $result->is_enforced_block()
					|| $result->is_monitored()
					|| ($result->code === ResultCode::ALLOWED && $this->config->verbose);
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

	/**
	 * Handle a Result by serving the appropriate response (block page
	 * or challenge).
	 *
	 * === CALLING CONTRACT ===
	 *
	 *   ALLOWED      → don't call; let the request reach your app
	 *   MONITORED    → don't call; let the request reach your app
	 *   ENFORCED     → call this method; serves 403 (block page or challenge)
	 *
	 * Use Result::is_actionable() (or the equivalent is_enforced_block())
	 * as the gate:
	 *
	 *   $result = $bb->run();
	 *   if ($result->is_actionable()) {
	 *       $bb->handle_result($result);
	 *   }
	 *   // otherwise continue serving the request normally
	 *
	 * === DEFENSIVE BEHAVIOR ===
	 *
	 * If called with a non-actionable result (ALLOWED or MONITORED),
	 * this method logs a one-shot warning and returns NORMALLY rather
	 * than throwing. The previous implementation threw LogicException,
	 * which crashed production if any host integration forgot the gate.
	 *
	 * Why the change:
	 *
	 *   1. Crashing production for a misuse is too harsh — the request
	 *      was ALLOWED or MONITORED anyway, so the right outcome is
	 *      "let it through to the app".
	 *
	 *   2. The warning is logged (via ErrorReporter with a once-tag)
	 *      so operators can find and fix the misbehaving integration
	 *      without the site going down in the meantime.
	 *
	 *   3. Returning normally (instead of exiting) is safe because:
	 *      - For ALLOWED/MONITORED, the host's code will continue and
	 *        serve the request (which is what should happen).
	 *      - For ENFORCED, the existing challenge/block paths still
	 *        call exit() internally.
	 *
	 * @param Result $result
	 * @return void Returns normally on misuse; never returns (exits via
	 *              challenge or block page) for actionable results.
	 */
	public function handle_result(Result $result): void
	{
		// === Defensive guard: non-actionable result = misuse ===
		//
		// The host should have checked is_actionable() before calling.
		// If they didn't, log a warning and return normally so the
		// application can serve the request (which is the correct
		// outcome for ALLOWED and MONITORED results).
		if (!$result->is_actionable()) {
			ErrorReporter::warning(
				$this->adapter,
				'handle_result() called on non-actionable result; passing through to application',
				[
					'code'        => $result->code->value,
					'enforcement' => $result->enforcement->value,
					'hint'        => 'Check Result::is_actionable() (or is_enforced_block()) '
					. 'before calling handle_result(). ALLOWED and MONITORED '
					. 'results must reach the application, not handle_result().',
				],
				'handle_result_misuse'  // once-tag: logged at most once per process
				);
			return;
		}

		if ($result->requires_challenge()) {
			$this->serve_challenge($result);
			return;
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

		// 3. Known Bots (always-on — BotDetector is the SOLE arbiter for bot classification)
		//
		// If this returns a result (allow/challenge/block), we're done.
		// If this returns null, the bot is either unknown or verification
		// failed. In either case, BlacklistDetector MUST NOT make a bot
		// classification decision — it only detects attack patterns.
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
		//
		// BlacklistDetector detects: raw XSS, SQL injection, path traversal,
		// credential leaks, technical anomalies. It does NOT classify bots.
		// All bot classification is handled by BotDetector above. The old
		// ua_is_bot short-circuit was removed because it produced false
		// positives on legitimate search engines (YandexBot, bingbot,
		// Baiduspider all match /bot|spider/i in the UA).
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

	/**
	 * If monitor-only mode is active, convert would-be blocks into "monitored"
	 * results — the detection still runs (and is logged with full context),
	 * but no block page is served and the request flows through to the app.
	 *
	 * === "OBVIOUS ATTACK" EXCEPTIONS (still enforced even in monitor-only) ===
	 *
	 *   1. Empty/invalid User-Agent
	 *      No UA = never a legitimate browser, mobile app, or HTTP client.
	 *      Identified by stable message 'Empty or invalid User-Agent'.
	 *
	 *   2. Raw, unencoded attack payload in URI (Tier 0.5 of BlacklistDetector)
	 *      Unencoded <script>, javascript:, data:text/html in the URI means
	 *      a non-browser client (scanner, modified proxy, custom script,
	 *      manual cURL). Browsers always percent-encode per RFC 3986.
	 *      Identified by metadata['tier'] === 'raw_uri'.
	 *
	 * These are technical anomalies with zero FP risk — no legitimate
	 * client triggers them. Letting them through in monitor-only would
	 * defeat the purpose of running the library, so we enforce them
	 * regardless of strictness.
	 *
	 * === EVERYTHING ELSE ===
	 *
	 * Demoted to MONITORED. The detection still runs (and is logged with
	 * full context — bot name, category, IP, etc.), but no 403 page is
	 * served. The request flows through to the host application normally.
	 */
	private function maybe_demote_to_monitored(Result $result): Result
	{
		if ($result->code === ResultCode::ALLOWED) {
			return $result;
		}

		if (!$this->is_monitor_only_effective()) {
			return $result;
		}

		// === Exception 1: Empty/invalid UA ===
		// The fast-path empty-UA check in run_internal() already creates a
		// BLOCKED_MALICIOUS_UA with message 'Empty or invalid User-Agent'.
		// Keep it enforced even in monitor-only.
		if ($result->code === ResultCode::BLOCKED_MALICIOUS_UA
			&& $result->message === 'Empty or invalid User-Agent') {
			return $result;
		}

		// === Exception 2: Raw unencoded attack payload in URI ===
		// Identified by metadata['tier'] === 'raw_uri' (set by BlacklistDetector
		// Tier 0.5). Browsers never produce raw <script>, javascript:, etc.
		// in the URI — they always percent-encode.
		if (isset($result->metadata['tier']) && $result->metadata['tier'] === 'raw_uri') {
			return $result;
		}

		// === Everything else: demote to monitored ===
		return Result::monitored_from($result);
	}

	/**
	 * Log the result to the bad_behaviour table (if logging is enabled
	 * and the result passes the logging filter).
	 *
	 * Extracted from run_internal() and run_test_package() so both paths
	 * share identical logging semantics.
	 *
	 * Logging filter:
	 *   - ENFORCED blocks/challenges → always logged
	 *   - MONITORED blocks/challenges → always logged (this is the point
	 *     of monitor-only mode: record what *would* have happened)
	 *   - ALLOWED requests → logged only when verbose=true
	 *
	 * Failures inside log_request() are swallowed by the adapter itself
	 * (never throw); we still wrap here as a belt-and-suspenders defense.
	 */
	private function log_and_return(RequestPackage $package, Result $result): void
	{
		if (!$this->config->logging) {
			return;
		}

		$should_log = $result->is_enforced_block()
			|| $result->is_monitored()
			|| ($result->code === ResultCode::ALLOWED && $this->config->verbose);

		if (!$should_log) {
			return;
		}

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

	/**
	 * Run the on-demand IP range refresh gate and, if it schedules,
	 * register a shutdown function to perform the actual refresh.
	 *
	 * === WHERE IT FITS IN THE PIPELINE ===
	 *
	 * Called after fast-path checks (empty UA, whitelist, enrichment)
	 * and before detection. Placement rationale:
	 *
	 *   - After fast paths: empty UA / whitelist requests skip the
	 *     gate entirely (zero overhead).
	 *   - Before detection: gives the next request the freshest data
	 *     possible — if this request's refresh completes before the
	 *     next request starts (common on low/medium traffic), the
	 *     next request sees warm ranges immediately.
	 *
	 * === LATENCY ===
	 *
	 * On the hot path (Gate 1 fails): 1 mt_rand() call, ~1µs.
	 * On the slow path (Gate 1 passes): 2 cache reads + 1 cache write
	 * for the lock, ~1ms even on slow backends. Still well below the
	 * "skip static" speed.
	 *
	 * The actual feed fetches (potentially seconds) happen in the
	 * shutdown function, AFTER the response has been sent under
	 * PHP-FPM. Under mod_php / CGI, shutdown runs before the response
	 * is fully flushed, so the user waits for the refresh — documented
	 * limitation.
	 *
	 * === FAILURE MODES ===
	 *
	 * - maybe_refresh() itself NEVER throws (defensive contract).
	 *   Gate failures just return skip decisions.
	 * - do_refresh() inside the shutdown function also NEVER throws.
	 *   Per-feed failures degrade to partial refresh.
	 * - Shutdown function not registered when refresh_checker is null
	 *   (refresher disabled or failed to construct).
	 *
	 * @return void
	 */
	private function maybe_schedule_refresh(): void
	{
		if ($this->refresh_checker === null) {
			return;
		}

		try {
			$decision = $this->refresh_checker->maybe_refresh();
		} catch (\Throwable $e) {
			// Defensive: maybe_refresh() shouldn't throw, but if a
			// future bug introduces one, we MUST NOT crash the request.
			ErrorReporter::error($this->adapter,
				'on-demand refresh gate threw; skipping',
				[
					'error' => $e->getMessage(),
					'exception_class' => $e::class,
				],
				'on_demand_refresh_gate_threw'
				);
			return;
		}

		if (!$decision->should_schedule) {
			return;
		}

		// Schedule the slow work for after the response is sent.
		//
		// Under PHP-FPM: shutdown_function runs after fastcgi_finish_request
		// (if the host calls it) or after the response buffer is flushed
		// naturally. Either way, the user doesn't wait for the refresh.
		//
		// Under mod_php/CGI: shutdown_function runs before the response
		// is fully flushed. User waits up to feed_timeout_seconds × N feeds
		// (default 5s × 8 feeds ≈ 40s worst case). Acceptable since this
		// fires at most once per min_age_seconds per worker.
		//
		// We capture the refresher by reference (it's a property on $this,
		// which outlives this request scope for the duration of the
		// shutdown sequence).
		$refresher = $this->refresh_checker;
		register_shutdown_function(static function () use ($refresher): void {
			try {
				$refresher->do_refresh();
			} catch (\Throwable $e) {
				// Defensive: do_refresh() shouldn't throw, but if it
				// ever does (a future bug, a network stack that throws
				// during shutdown), swallow + log.
				error_log(
					'[BadBehaviour] on-demand refresh shutdown handler threw: '
					. $e->getMessage()
					);
			}
		});
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

		if (defined('BB_NO_CREATE') || !$this->config->logging) {
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
				'exception_class' => $e::class,
				'hint' => 'Run bin/install-bb.php to set up the log table and '
				. '(if on-demand refresh is enabled) seed the IP-range cache, '
				. 'or check database connectivity and permissions',
			], 'install_once_failure');
		}

		// === Opportunistic cache seeding ===
		//
		// If on-demand refresh is enabled AND the cache is empty/cold,
		// fetch fresh ranges synchronously here — but ONLY if we have
		// spare time budget (cap at 3 seconds; install_once is on the
		// hot path of the first request of a process).
		//
		// Host apps that want guaranteed seeding (rather than opportunistic)
		// should run bin/install-bb.php during their install flow instead.
		//
		// Why opportunistic: zero ops burden for hosts that already have
		// bin/install-bb.php running; zero extra work for hosts that don't
		// care about cold-start optimization.
		if ($this->refresh_checker === null) {
			return; // On-demand refresh not enabled — nothing to seed.
		}

		// Skip if cache already has data (any non-empty payload counts).
		$existing = $this->cache !== null
		? $this->cache->get(OnDemandRefresher::CACHE_KEY_MERGED)
		: ($this->adapter instanceof CacheInterface
			? $this->adapter->get(OnDemandRefresher::CACHE_KEY_MERGED)
			: null);
		if (is_array($existing) && !empty($existing['data'])) {
			return;
		}

		// Skip during CLI — no per-request latency concern, but also no
		// point running from a CLI process's first request.
		if (php_sapi_name() === 'cli') {
			return;
		}

		// Cap seeding at 3 seconds. install_once runs on the first request
		// of a process; we can't afford to block the user for the full
		// feed_timeout_seconds × N feeds.
		$install_budget = 3.0;
		$start = microtime(true);

		try {
			// Build a one-shot refresher with the install-time budget.
			// We deliberately don't reuse $this->refresh_checker here
			// because its options are already locked-in for runtime use.
			$cache = $this->cache ?? ($this->adapter instanceof CacheInterface
				? $this->adapter
				: null);
			if ($cache === null) {
				return; // No cache backend; nothing to do.
			}

			$seeder = new OnDemandRefresher(
				cache: $cache,
				registry: new \BadBehaviour\Feeds\FeedRegistry($cache),
				cloud: new \BadBehaviour\Feeds\CloudIpRangeProvider($cache),
				options: [
					'probability_denominator' => 1, // Skip the gate; we know we want this.
					'min_age_seconds'         => $this->config->on_demand_ip_refresh_min_age_seconds,
					'lock_ttl'                => $this->config->on_demand_ip_refresh_lock_ttl,
					'cache_ttl'               => $this->config->on_demand_ip_refresh_cache_ttl,
					'feed_timeout_seconds'    => $install_budget,
					'bot_ids'                 => $this->config->on_demand_ip_refresh_bot_ids ?: null,
					'cloud_providers'         => $this->config->on_demand_ip_refresh_cloud_providers ?: null,
				],
				);

			// Acquire the lock (fresh install — no contention expected).
			$decision = $seeder->maybe_refresh();
			if (!$decision->should_schedule) {
				// Another worker seeded concurrently. That's fine — we
				// don't need to do anything.
				return;
			}

			// Run the fetch synchronously, capped by the budget.
			$result = $seeder->do_refresh();

			if ($result->cache_written) {
				error_log(sprintf(
					'[BadBehaviour] install_once: seeded %d CIDRs from %d feeds in %.2fs',
					$result->cidr_count,
					$result->successful_feed_count(),
					microtime(true) - $start
					));
			} else {
				error_log(
					'[BadBehaviour] install_once: seed fetch returned no data; '
					. 'cache left empty. Operator should run bin/install-bb.php manually.'
					);
			}
		} catch (\Throwable $e) {
			// Never let install_once throw. Worst case the user gets a
			// cold-start window and the on-demand refresher catches up
			// on a later request.
			ErrorReporter::error($this->adapter,
				'install_once: opportunistic seed failed',
				[
					'error' => $e->getMessage(),
					'exception_class' => $e::class,
					'hint' => 'Run bin/install-bb.php manually to seed the cache.',
				],
				'install_once_seed_failed'
				);
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
