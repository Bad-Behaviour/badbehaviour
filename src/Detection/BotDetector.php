<?php

declare(strict_types=1);

namespace BadBehaviour\Detection;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Feeds\CloudIpRangeProvider;
use BadBehaviour\Util\ErrorReporter;
use BadBehaviour\Util\IpUtil;
use BadBehaviour\Util\RequestPackage;

class BotDetector
{
	private Configuration $config;
	private AdapterInterface $adapter;
	private RegistryInterface $registry;

	private array $dns_cache = [];
	private array $dns_reverse_cache = [];

	/**
	 * DNS resolver hooks for testability. Defaults to PHP built-ins.
	 * Production code should leave these alone.
	 *
	 * Signature: (string $ip) => string|false
	 */
	private $reverse_resolver;

	/**
	 * Signature: (string $host, int $type) => array|false
	 */
	private $forward_resolver;

	private ?array $dynamic_ranges = null;
	private bool $dynamic_ranges_fetched = false;
	private ?CloudIpRangeProvider $cloud_provider = null;

	/**
	 * Per-instance result memoization (NOT static — avoids cross-config pollution).
	 * Cache key includes config fingerprint so different BadBehaviour instances
	 * with different configs get independent caches.
	 *
	 * NOTE: $dns_cache above is a separate, smaller cache for DNS verification
	 * only. It is NOT a candidate for merging with $result_cache — the two
	 * serve different purposes:
	 *
	 *   - $dns_cache: keyed by "ip@suffix", stores bool, request-scoped.
	 *     Avoids redundant DNS lookups within a single request.
	 *
	 *   - $result_cache: keyed by fingerprint+hash(ip|ua), stores Result,
	 *     instance-scoped with 300s TTL. Memoizes full bot detection.
	 *
	 * The two caches operate at different levels of the detection pipeline
	 * and have non-overlapping key spaces. Merging them would couple
	 * concerns without measurable benefit. Out of scope for any current
	 * refactor.
	 */
	private array $result_cache = [];
	private int $result_cache_max = 5000;
	private string $config_fingerprint;
	private const RESULT_CACHE_TTL = 300;

	/**
	 * Providers proven unreachable this PHP process.
	 *
	 * Keyed by provider name. Once we determine a provider has no
	 * cached ranges (or its cache read fails), we record it here so
	 * subsequent BotDetector::is_cloud_infrastructure_ip() calls skip
	 * the cache lookup entirely. This is what prevents the asset
	 * "log lines per page request" pathology when a high-traffic
	 * page generates many sub-requests.
	 *
	 * Static at class level (not function-level) so it survives across
	 * BotDetector instances in the same process.
	 *
	 * @var array<string, true>
	 */
	private static array $known_unreachable_providers = [];

	public function __construct(
		Configuration $config,
		AdapterInterface $adapter,
		?RegistryInterface $registry = null,
		?callable $reverse_resolver = null,
		?callable $forward_resolver = null,
	) {
		$this->config = $config;
		$this->adapter = $adapter;
		$this->registry = $registry ?? \BadBehaviour\Bot\RegistryFactory::default();

		// DNS resolver hooks — defaults to PHP built-ins. Production code
		// should not override these; tests inject stubs for determinism.
		$this->reverse_resolver = $reverse_resolver ?? 'gethostbyaddr';
		$this->forward_resolver = $forward_resolver ?? 'dns_get_record';

		$this->config_fingerprint = $this->compute_config_fingerprint($config);

		// Initialize cloud range provider if available
		if (method_exists($adapter, 'get') && $config->dynamic_ip_ranges_enabled) {
			try {
				$this->cloud_provider = new CloudIpRangeProvider($adapter);
			} catch (\Throwable $e) {
				// Cloud range provider init failed — disable gracefully
				$this->cloud_provider = null;
			}
		}
	}

	private function compute_config_fingerprint(Configuration $config): string
	{
		return substr(hash('sha256', json_encode([
			'blocked_cat'       => $config->blocked_bot_categories,
			'allowed_ai'        => $config->allowed_ai_crawlers,
			'block_unverified'  => $config->block_unverified_ai,
			'strict_ai'         => $config->strict_ai,
			'strict_se'         => $config->strict_search_engines,
			'dns_verify_enabled'=> $config->dns_verification_enabled,
			'dns_require_fwd'   => $config->dns_verification_require_forward_confirm,
			'registry_hash'     => spl_object_hash($this->registry),
		])), 0, 16);
	}

	public function detect(RequestPackage $package): ?Result
	{
		// CRITICAL: never let bot detection crash the response.
		// Any exception inside detect_uncached must degrade to "no match"
		// so downstream detectors still get a chance.
		try {
			$ip = $package->ip;
			$ua = $package->user_agent;

			if ($ua === '') {
				return null;
			}

			$cache_key = $this->compute_cache_key($ip, $ua);
			$cached = $this->get_cached_result($cache_key);

			if ($cached !== false) {
				$cached_result = $cached['result'];
				if ($cached_result === null) {
					return null;
				}
				return $this->rebuild_result($cached_result, $package);
			}

			$result = $this->detect_uncached($package);
			$this->set_cached_result($cache_key, $result);

			return $result;
		} catch (\Throwable $e) {
			// CRITICAL: never let bot detection crash the response.
			// Any unexpected error falls through as "no match" so other
			// detectors (blacklist, behavioral, rate limit) still run.
			ErrorReporter::fatal($e, 'BotDetector');
			return null;
		}
	}

	private function detect_uncached(RequestPackage $package): ?Result
	{
		$ip = $package->ip;
		$ua = $package->user_agent;

		// === FAST PATH: CLOUD INFRASTRUCTURE WHITELIST ===
		// CRITICAL: Do this BEFORE bot UA matching — these are network probes,
		// not real bots, and blocking them = downtime.
		if ($this->is_cloud_infrastructure_ip($ip)) {
			return Result::allow($package, [
				'bot_category' => BotCategory::CLOUD_INFRASTRUCTURE->value,
				'bot_name'     => 'Cloud Infrastructure',
				'bot_verified' => true,
			]);
		}

		try {
			$dynamic_ranges = $this->get_dynamic_ranges();
		} catch (\Throwable $e) {
			$dynamic_ranges = [];
		}

		// Primary: substring match against the registry's indexed UA fragments
		try {
			$candidate_ids = $this->registry->find_by_ua($ua);

			// Secondary: token match (with noise filter)
			if (empty($candidate_ids)) {
				$candidate_ids = $this->registry->find_by_tokens($ua);
			}
		} catch (\Throwable $e) {
			return null;
		}

		if (empty($candidate_ids)) {
			return null;
		}

		foreach ($candidate_ids as $bot_id) {
			try {
				$def = $this->registry->get($bot_id);
				if ($def === null) {
					continue;
				}

				// Merge static + dynamic ranges
				$all_ranges = array_merge(
					$def->ip_ranges,
					$dynamic_ranges[$bot_id] ?? []
				);

				$ip_match = !empty($all_ranges) && IpUtil::match_any($ip, $all_ranges);

				// === CHANGED: Iterate over dns_suffixes array ===
				// Previously: single $def->dns_suffix check
				// Now: try each suffix until one matches (or all fail)
				// Short-circuits on first match; each suffix has its own cache entry
				$dns_verified = false;
				if ($def->verify_dns) {
					foreach ($def->dns_suffixes as $suffix) {
						if ($this->verify_dns($ip, $suffix)) {
							$dns_verified = true;
							break;
						}
					}
				}

				$verified = $ip_match || $dns_verified;
				$action = $this->determine_action($def, $verified);

				$bot_metadata = [
					'bot_id'       => $bot_id,
					'bot_name'     => $def->name,
					'bot_category' => $def->category->value,
					'bot_verified' => $verified,
				];

				return match ($action) {
					BotAction::ALLOW		=> Result::allow($package, $bot_metadata),
					BotAction::LOG_ONLY		=> Result::allow($package, $bot_metadata),
					BotAction::CHALLENGE	=> Result::challenge(
						ResultCode::CHALLENGE_REQUIRED,
						"Bot challenge required: {$def->name}",
						$package,
						$bot_metadata,
					),
					BotAction::BLOCK		=> Result::block(
						$this->code_for_category($def->category),
						"Bot blocked: {$def->name}",
						$package,
						$bot_metadata,
					),
				};
			} catch (\Throwable $e) {
				// Per-bot error: skip this bot, try the next
				ErrorReporter::error($this->adapter, 'BotDetector per-bot evaluation failed', [
					'bot_id' => $bot_id,
					'error' => $e->getMessage(),
				], 'bot_detector_per_bot_' . $bot_id);
				continue;
			}
		}

		return null;
	}

	/**
	 * Check if IP belongs to any known cloud infrastructure provider.
	 *
	 * CRITICAL fast path: do NOT block these or your origin gets marked
	 * unhealthy and your CDN takes you offline.
	 *
	 * Uses the INJECTED registry's cloud_infrastructure() method so swapping
	 * registries (e.g., preset='human-only') affects this check too.
	 *
	 * === TRIPLE-LAYER PROTECTION AGAINST LOG FLOODING ===
	 *
	 * When cloud feeds are unreachable, this method MUST surface a
	 * warning to the operator (Goal 2: "Signal to the user when
	 * something is broken"). But it MUST NOT flood the log when many
	 * requests trigger the same code path (Goal 3: never break the app).
	 *
	 * Three independent gates ensure at most one warning per 5 minutes
	 * per PHP-FPM worker:
	 *
	 *   1. Function-local `static $warned` — once per worker process
	 *      for this method, regardless of how many BotDetector instances
	 *      exist or how many times the method is called.
	 *
	 *   2. `self::$known_unreachable_providers` — class-level static
	 *      memoization. After the first call identifies a provider as
	 *      unreachable, subsequent calls skip the cache lookup entirely
	 *      for that provider. Reduces per-request work AND makes the
	 *      function-level $warned the only gate that matters.
	 *
	 *   3. `ErrorReporter::warning($once_tag = 'cloud_init_slow')` —
	 *      defense-in-depth. The once-tag + time-throttle in
	 *      ErrorReporter catches any path that bypasses gates 1 and 2.
	 */
	private function is_cloud_infrastructure_ip(string $ip): bool
	{
		try {
			$start = microtime(true);
			$deadline = $start + 0.1; // 100ms absolute max for init

			static $cloud_ranges = null;
			static $init_done = false;

			if ($cloud_ranges === null && !$init_done) {
				$init_done = true;
				$cloud_ranges = [];
				$unreachable_providers = [];
				$empty_cache_providers = [];

				// 1. Static ranges from the in-memory registry (fast).
				foreach ($this->registry->cloud_infrastructure() as $bot) {
					$cloud_ranges = array_merge($cloud_ranges, $bot->ip_ranges);
					if (microtime(true) > $deadline) {
						// Even static ranges shouldn't blow the budget on
						// first init. Subsequent calls hit the static cache.
						$cloud_ranges = [];
						break;
					}
				}

				// 2. Dynamic ranges from the cache (only if enabled).
				//    Reads from cache — never live-fetches here. Live
				//    fetching belongs in bin/update-ip-ranges.php (cron).
				if ($this->cloud_provider
					&& $this->config->dynamic_ip_ranges_enabled
					&& microtime(true) < $deadline) {

						foreach ($this->config->dynamic_ip_ranges_feeds as $provider) {
							if (microtime(true) >= $deadline) {
								break;
							}

							// Skip providers already proven unreachable this
							// process. Saves a cache lookup per request
							// after the first one identifies the problem.
							if (isset(self::$known_unreachable_providers[$provider])) {
								$unreachable_providers[] = $provider;
								continue;
							}

							$cache_key = "ip_range:{$provider}:all";
							$cached = null;
							try {
								$cached = $this->adapter->get($cache_key);
							} catch (\Throwable $e) {
								// Cache read failure — treat as unreachable,
								// remember it for subsequent calls.
								$unreachable_providers[] = $provider;
								self::$known_unreachable_providers[$provider] = true;
								continue;
							}

							if ($cached === null) {
								// No cache entry at all. Either:
								//   (a) cron job has never run (no data yet), or
								//   (b) cache backend was reset.
								// Both are operator-fixable; remember and skip.
								$unreachable_providers[] = $provider;
								self::$known_unreachable_providers[$provider] = true;
								continue;
							}

							$data = is_array($cached) ? ($cached['data'] ?? []) : [];
							if (empty($data)) {
								$empty_cache_providers[] = $provider;
								continue;
							}

							$cloud_ranges = array_merge($cloud_ranges, $data);
						}
					}

					// 3. Surface slow init to the operator.
					//    Triple-layer protection against log flooding:
					//      - Function-local static $warned (once per process)
					//      - ErrorReporter::warning() with once_tag
					//      - ErrorReporter time-based throttle (5 min)
					//    Any one of these is sufficient; all three together
					//    guarantee at most one warning per 5 minutes per worker.
					$elapsed_ms = (microtime(true) - $start) * 1000;
					static $warned = false;
					if (!$warned && ($elapsed_ms > 50 || !empty($unreachable_providers))) {
						$warned = true;

						$hint = $this->build_cloud_init_hint(
							$unreachable_providers,
							$empty_cache_providers
							);

						ErrorReporter::warning($this->adapter,
							'Cloud infrastructure whitelist initialization has '
							. 'problems — health-check IPs may be blocked',
							[
								'elapsed_ms'             => round($elapsed_ms, 2),
								'range_count'            => count($cloud_ranges),
								'dynamic_enabled'        => $this->config->dynamic_ip_ranges_enabled,
								'unreachable_providers'  => $unreachable_providers,
								'empty_cache_providers'  => $empty_cache_providers,
								'feed_urls'              => array_intersect_key(
									CloudIpRangeProvider::FEED_URLS,
									array_flip($this->config->dynamic_ip_ranges_feeds)
									),
								'hint' => $hint,
							],
							'cloud_init_slow'  // once-tag (ErrorReporter layer)
							);
					}
			}

			if (empty($cloud_ranges)) {
				return false;
			}

			return IpUtil::match_any($ip, $cloud_ranges);
		} catch (\Throwable $e) {
			// Never let cloud check crash detection
			return false;
		}
	}

	/**
	 * Build an actionable hint for the operator based on which providers
	 * had problems during initialization.
	 *
	 * Three failure modes are distinguished so the operator doesn't have
	 * to guess:
	 *
	 *   - unreachable:  no cache entry exists. Either cron never ran, or
	 *                  the cache was cleared, or the cache backend is
	 *                  unreachable. Operator action required.
	 *   - empty cache:  cache entry exists but contains no ranges.
	 *                  Usually means cron ran but the upstream feed
	 *                  returned no data (or the feed URL changed).
	 *   - slow init:    initialization took >50ms but no providers are
	 *                  unreachable. Likely a slow cache backend.
	 *
	 * @param string[] $unreachable Providers with no cache entry
	 * @param string[] $empty       Providers with empty cache entry
	 * @return string Operator-facing hint
	 */
	private function build_cloud_init_hint(array $unreachable, array $empty): string
	{
		if (!empty($unreachable)) {
			$urls = array_intersect_key(
				CloudIpRangeProvider::FEED_URLS,
				array_flip($unreachable)
				);
			$url_list = implode("\n  - ", array_map(
				fn($p, $u) => "$p: $u",
				array_keys($urls),
				array_values($urls)
				));

			return "Cloud provider(s) have no cached ranges: "
				. implode(', ', $unreachable)
				. ". Either:\n"
					. "  (1) Run bin/update-ip-ranges.php via cron (recommended):\n"
						. "        0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php\n"
							. "  (2) Or disable dynamic_ip_ranges in config/bb_config.php:\n"
								. "        'dynamic_ip_ranges' => ['enabled' => false]\n"
									. "  (3) Or fix network reachability to:\n"
										. "        $url_list";
		}

		if (!empty($empty)) {
			return "Cloud provider(s) have empty cached ranges: "
				. implode(', ', $empty)
				. ". Cron likely ran but feeds returned no data. "
					. "Check bin/update-ip-ranges.php logs and verify feed URLs.";
		}

		return "Initialization took longer than 50ms but no providers "
			. "are unreachable. Likely a slow cache backend — check "
				. "adapter->get() performance.";
	}

	/**
	 * Verify the bot's IP via reverse DNS (and optionally forward confirmation).
	 *
	 * === BEHAVIOR ===
	 *
	 *   1. Kill switch: if dns_verification_enabled is false, return false
	 *      immediately. Caller treats as unverified.
	 *   2. Per-request instance cache: zero-cost hit on repeated lookups
	 *      within the same request.
	 *   3. Cross-request adapter cache: warm lookups skip DNS entirely.
	 *   4. Cold cache: synchronously runs DNS with a bounded timeout.
	 *      The latency cost (40-300ms) is paid ONCE per IP (for PTR) +
	 *      per (IP, suffix) for forward confirmation.
	 *
	 * === WHY SYNCHRONOUS ===
	 *
	 * The previous implementation deferred DNS to register_shutdown_function()
	 * to avoid blocking the request. This created a false-positive window:
	 * the FIRST request from any bot whose IP wasn't in static ranges was
	 * blocked because verification hadn't completed yet. The bot would
	 * retry, the cache would warm, and subsequent requests would succeed —
	 * but only IF the bot retried. Regional / academic / AI crawlers often
	 * do not retry, resulting in permanent blocks for legitimate bots.
	 *
	 * The synchronous path eliminates this window at the cost of a one-time
	 * DNS latency hit per IP. For a real bot visiting your site,
	 * that's 1 slow request followed by N fast ones.
	 *
	 * === CACHE KEY SHAPE ===
	 *
	 * - Reverse DNS: `bb:reverse_dns:{bin2hex(inet_pton($ip))}` (per IP)
	 * - Forward confirm: `bb:dns_verify:{bin2hex(inet_pton($ip))}:{suffix}` (per IP+suffix)
	 *
	 * Binary IP form ensures IPv6 normalization. Stable across adapter
	 * backends (no escaping issues with colons in IPv6 text form).
	 *
	 * === MULTI-SUFFIX OPTIMIZATION ===
	 *
	 * Multiple bots sharing suffixes (e.g., meta_ai and facebook_catalog both
	 * use 'facebook.com') share the same reverse DNS cache entry for the IP.
	 * The PTR lookup happens ONCE per IP, then each suffix is checked
	 * against the cached hostname. Forward confirmation (if enabled) is
	 * still per-suffix since it involves different queries.
	 */
	private function verify_dns(string $ip, string $suffix): bool
	{
		try {
			// === Kill switch ===
			if (!$this->config->dns_verification_enabled) {
				return false;
			}

			$key = "{$ip}@{$suffix}";

			// === Per-request instance cache (for this IP+suffix combo) ===
			if (isset($this->dns_cache[$key])) {
				return $this->dns_cache[$key];
			}

			// === Cross-process adapter cache (binary IP for IPv6 normalization) ===
			$bin_ip = @inet_pton($ip);
			if ($bin_ip === false) {
				$this->dns_cache[$key] = false;
				return false;
			}
			$cache_key = 'bb:dns_verify:' . bin2hex($bin_ip) . ':' . $suffix;
			try {
				$cached = $this->adapter->get($cache_key);
			} catch (\Throwable $e) {
				$cached = null;
			}
			if ($cached !== null) {
				$result = (bool)$cached;
				$this->dns_cache[$key] = $result;
				return $result;
			}

			// === Get reverse DNS (cached per IP, shared across suffixes) ===
			$host = $this->get_reverse_dns_cached($ip, $bin_ip);
			if ($host === false) {
				$result = false;
			} else {
				// === Verify suffix match and optional forward confirmation ===
				$result = $this->verify_hostname_suffixes($host, $suffix, $ip);
			}

			$ttl = $result
				? $this->config->dns_verification_positive_ttl
				: $this->config->dns_verification_negative_ttl;

			try {
				$this->adapter->set($cache_key, $result, $ttl);
			} catch (\Throwable $e) {
				// Cache write failed — non-fatal
			}
			$this->dns_cache[$key] = $result;

			return $result;
		} catch (\Throwable $e) {
			// DNS verification failed: treat as unverified.
			// Caller will fall through to next defense (challenge/block).
			ErrorReporter::error($this->adapter, 'verify_dns failed', [
				'ip' => $ip,
				'suffix' => $suffix,
				'error' => $e->getMessage(),
			], 'dns_verify_' . md5($ip . $suffix));
			return false;
		}
	}

	/**
	 * Get reverse DNS for an IP, with caching (per IP, shared across suffixes).
	 */
	private function get_reverse_dns_cached(string $ip, string $bin_ip): string|false
	{
		try {
			$reverse_cache_key = 'reverse@' . bin2hex($bin_ip);

			// Instance cache check
			if (isset($this->dns_cache[$reverse_cache_key])) {
				return $this->dns_cache[$reverse_cache_key];
			}

			// Adapter cache check
			$adapter_key = 'bb:reverse_dns:' . bin2hex($bin_ip);
			try {
				$cached = $this->adapter->get($adapter_key);
			} catch (\Throwable $e) {
				$cached = null;
			}
			if ($cached !== null) {
				$this->dns_cache[$reverse_cache_key] = $cached;
				return $cached;
			}

			// Cold: do the PTR lookup
			$reverse_resolver = $this->reverse_resolver;
			$host = @$reverse_resolver($ip);

			// Normalize: false/IP/empty → false (cacheable)
			if ($host === false || $host === $ip || $host === '') {
				$host = false;
			}

			// Cache the raw hostname (or false) for 7 days
			$ttl = $this->config->dns_verification_positive_ttl;
			try {
				$this->adapter->set($adapter_key, $host, $ttl);
			} catch (\Throwable $e) {
				// non-fatal
			}
			$this->dns_cache[$reverse_cache_key] = $host;

			return $host;
		} catch (\Throwable $e) {
			return false;
		}
	}

	/**
	 * Verify a resolved hostname against a specific DNS suffix.
	 * Performs forward confirmation if required by config.
	 */
	private function verify_hostname_suffixes(string $host, string $suffix, string $ip): bool
	{
		$start = microtime(true);
		$deadline_ms = $this->config->dns_verification_timeout_ms;

		// === Phase 1: Suffix check ===
		$host_lower = strtolower($host);
		$suffix_lower = strtolower($suffix);

		// Match either ".suffix" (FQDN) or "suffix" (host may lack trailing dot)
		if (!str_ends_with($host_lower, '.' . $suffix_lower)
			&& !str_ends_with($host_lower, $suffix_lower)) {
			return false;
		}

		// === Phase 2: Forward confirmation (optional) ===
		if (!$this->config->dns_verification_require_forward_confirm) {
			return true;
		}

		// Budget check before forward lookup
		if ((microtime(true) - $start) * 1000 > $deadline_ms) {
			return false;
		}

		$forward_resolver = $this->forward_resolver;
		$is_ipv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

		// Try A records (IPv4 forward confirm)
		$a_records = @$forward_resolver($host, DNS_A);
		if (is_array($a_records)) {
			foreach ($a_records as $r) {
				if (($r['ip'] ?? null) === $ip) {
					return true;
				}
			}
		}

		// Budget check after A lookup
		if ((microtime(true) - $start) * 1000 > $deadline_ms) {
			return false;
		}

		// Try AAAA records (IPv6 forward confirm)
		if ($is_ipv6) {
			$aaaa_records = @$forward_resolver($host, DNS_AAAA);
			if (is_array($aaaa_records)) {
				foreach ($aaaa_records as $r) {
					if (($r['ipv6'] ?? null) === $ip) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Run reverse-DNS verification with a soft timeout. Returns false
	 * (verified-as-failed) on any failure or timeout.
	 *
	 * === STRICT-MODE OPT-IN ===
	 *
	 * When dns_verification_require_forward_confirm is true, the bot must
	 * pass BOTH:
	 *   - reverse: PTR record resolves to a host whose suffix matches
	 *   - forward: that host's A/AAAA records contain the original IP
	 *
	 * When false (default), reverse+suffix match is sufficient. This
	 * matches the effective behavior of the previous deferred implementation
	 * (which only verified suffix in the deferred callback before exiting).
	 *
	 * The strict mode catches PTR-spoofing (attacker sets their own PTR to
	 * "crawl-1-2-3.googlebot.com") but may FPs legitimate IPv6-only bots
	 * because forward-confirm paths are inconsistent across IPv6 setups.
	 * Keep strict mode off unless you observe PTR-spoofing abuse.
	 *
	 * === TIMEOUT BEHAVIOR ===
	 *
	 * The soft timeout is checked between phases (after reverse lookup,
	 * after each forward-confirm attempt). If exceeded, returns false —
	 * treated as "could not verify" by the caller (which falls through
	 * to the next defense, typically CHALLENGE rather than BLOCK).
	 *
	 * === WHY THIS DUPLICATES verify_hostname_suffixes() ===
	 *
	 * This method exists as a standalone callable for test injection and
	 * for direct use from external callers (e.g., admin tools) that need
	 * a bounded DNS verify without going through the full detection
	 * pipeline. The internal verify_hostname_suffixes() is the per-suffix
	 * phase used by verify_dns().
	 */
	private function do_dns_verify_bounded(string $ip, string $suffix): bool
	{
		$start = microtime(true);
		$deadline_ms = $this->config->dns_verification_timeout_ms;

		// === Phase 1: Reverse DNS ===
		$reverse_resolver = $this->reverse_resolver;
		$host = @$reverse_resolver($ip);
		if ($host === false || $host === $ip || $host === '') {
			return false;
		}

		// Budget check after reverse lookup
		if ((microtime(true) - $start) * 1000 > $deadline_ms) {
			return false;
		}

		// === Phase 2: Suffix check ===
		$host_lower = strtolower($host);
		$suffix_lower = strtolower($suffix);

		// Match either ".suffix" (FQDN) or "suffix" (host may lack trailing dot)
		if (!str_ends_with($host_lower, '.' . $suffix_lower)
			&& !str_ends_with($host_lower, $suffix_lower)) {
			return false;
		}

		// === Phase 3: Forward confirmation (optional) ===
		if (!$this->config->dns_verification_require_forward_confirm) {
			return true;
		}

		$forward_resolver = $this->forward_resolver;
		$is_ipv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

		// Try A records (IPv4 forward confirm)
		$a_records = @$forward_resolver($host, DNS_A);
		if (is_array($a_records)) {
			foreach ($a_records as $r) {
				if (($r['ip'] ?? null) === $ip) {
					return true;
				}
			}
		}

		// Budget check after A lookup
		if ((microtime(true) - $start) * 1000 > $deadline_ms) {
			return false;
		}

		// Try AAAA records (IPv6 forward confirm)
		if ($is_ipv6) {
			$aaaa_records = @$forward_resolver($host, DNS_AAAA);
			if (is_array($aaaa_records)) {
				foreach ($aaaa_records as $r) {
					if (($r['ipv6'] ?? null) === $ip) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Inject custom DNS resolvers (test-only).
	 *
	 * Signatures:
	 *   $reverse: (string $ip) => string|false
	 *   $forward: (string $host, int $type) => array|false
	 *
	 * Production code should not call this. Used by tests to inject
	 * deterministic DNS responses without relying on network or /etc/hosts.
	 */
	public function set_dns_resolvers(callable $reverse, callable $forward): void
	{
		$this->reverse_resolver = $reverse;
		$this->forward_resolver = $forward;
		// Invalidate per-request cache so the new resolvers take effect
		$this->dns_cache = [];
	}

	private function compute_cache_key(string $ip, string $ua): string
	{
		return $this->config_fingerprint . ':' . substr(hash('sha256', $ip . '|' . $ua), 0, 24);
	}

	private function get_cached_result(string $key): array|false
	{
		if (!isset($this->result_cache[$key])) {
			return false;
		}
		$entry = $this->result_cache[$key];
		if (time() - $entry['ts'] > self::RESULT_CACHE_TTL) {
			unset($this->result_cache[$key]);
			return false;
		}
		return $entry;
	}

	private function set_cached_result(string $key, ?Result $result): void
	{
		if (count($this->result_cache) >= $this->result_cache_max) {
			// LRU-style eviction: drop the oldest 10% of entries
			$evict_count = (int)($this->result_cache_max * 0.1);
			$evicted = array_slice($this->result_cache, 0, $evict_count, true);
			$this->result_cache = array_diff_key($this->result_cache, $evicted);
		}
		$this->result_cache[$key] = ['result' => $result, 'ts' => time()];
	}

	private function rebuild_result(Result $cached, RequestPackage $package): Result
	{
		// Cached Results carry the wrong package reference; rebuild so the
		// returned Result points at THIS request's package (support key etc.).
		if ($cached->is_allowed()) {
			return Result::allow($package, $cached->metadata);  // ← preserve metadata
		}
		return new Result(
			code: $cached->code,
			message: $cached->message,
			package: $package,
			metadata: $cached->metadata,
			support_key: Result::generate_support_key_public($package),
		);
	}

	private function get_dynamic_ranges(): array
	{
		if ($this->dynamic_ranges !== null) {
			return $this->dynamic_ranges;
		}
		if (!$this->config->dynamic_ip_ranges_enabled) {
			$this->dynamic_ranges = [];
			return [];
		}
		try {
			$cache_key = 'bb:ip_ranges:merged';
			$cached = $this->adapter->get($cache_key);
			if ($cached && isset($cached['data'], $cached['fetched'])) {
				$this->dynamic_ranges = $cached['data'];
				return $this->dynamic_ranges;
			}
		} catch (\Throwable $e) {
			// Cache read failed — treat as cold
		}
		if (!$this->dynamic_ranges_fetched) {
			$this->dynamic_ranges_fetched = true;
			error_log("[BadBehaviour] Dynamic IP ranges: no cache, run bin/update-ip-ranges.php");
		}
		$this->dynamic_ranges = [];
		return [];
	}

	private function determine_action(BotDefinition $def, bool $verified): BotAction
	{
		$cat = $def->category->value;

		// === 1. SAFETY OVERRIDE: CLOUD_INFRASTRUCTURE always allowed ===
		// Cannot be moved to blocked[] or challenge[] — blocking these
		// takes your origin offline (CDN/LB marks origin unhealthy → downtime).
		// Hard-coded safety; runs BEFORE user category overrides so even an
		// accidental `'blocked' => ['cloud_infrastructure']` in bb_config.php
		// cannot break the host application.
		if ($cat === BotCategory::CLOUD_INFRASTRUCTURE->value) {
			return BotAction::ALLOW;
		}

		// === 2. USER CATEGORY OVERRIDES ===
		// Operators can pin a category to a specific action regardless of
		// its default category-specific logic. Evaluated in priority order
		// (most severe action wins on collision):
		//
		//   blocked[]   >  challenge[]  >  log_only[]  >  allowed[]
		//
		// All four lists default to empty — see Configuration::get_defaults()
		// and STRICTNESS.md → Bot Category Overrides.
		if (in_array($cat, $this->config->blocked_bot_categories, true)) {
			return BotAction::BLOCK;
		}
		if (in_array($cat, $this->config->challenge_bot_categories, true)) {
			return BotAction::CHALLENGE;
		}
		if (in_array($cat, $this->config->log_only_bot_categories, true)) {
			return BotAction::LOG_ONLY;
		}
		if (in_array($cat, $this->config->allowed_bot_categories, true)) {
			return BotAction::ALLOW;
		}

		// === 3. DEFAULT CATEGORY-SPECIFIC LOGIC (unchanged from 3.0) ===
		// Runs only when no user override matched. Preserves existing
		// behavior for operators who don't customize bot_categories.

		// === FEED READERS / SHOPPING / MONITORING / ARCHIVE: allow verified ===
		if (in_array($cat, [
			BotCategory::FEED_READER->value,
			BotCategory::SHOPPING_CRAWLER->value,
			BotCategory::MONITORING->value,
			BotCategory::ARCHIVE_CRAWLER->value,
		], true)) {
			return BotAction::ALLOW;
		}

		// === AI CRAWLERS ===
		if ($def->category === BotCategory::AI_CRAWLER) {
			$token = $def->robots_txt_token ?? $def->name;
			if (in_array($token, $this->config->allowed_ai_crawlers, true)) {
				return BotAction::ALLOW;
			}
			if ($this->config->block_unverified_ai && !$verified) {
				return BotAction::BLOCK;
			}
			return $this->config->strict_ai ? BotAction::BLOCK : BotAction::CHALLENGE;
		}

		// === SEO CRAWLERS ===
		if ($def->category === BotCategory::SEO_CRAWLER) {
			return $verified ? $def->default_action : BotAction::BLOCK;
		}

		// === SEARCH ENGINES ===
		if ($def->category === BotCategory::SEARCH_ENGINE) {
			if (!$verified) {
				return BotAction::BLOCK;
			}
			return BotAction::ALLOW;
		}

		// === SOCIAL CRAWLERS ===
		if ($def->category === BotCategory::SOCIAL_CRAWLER) {
			return $verified ? BotAction::ALLOW : BotAction::LOG_ONLY;
		}

		// === SECURITY SCANNERS: log only by default ===
		if ($def->category === BotCategory::SECURITY_SCANNER) {
			return BotAction::LOG_ONLY;
		}

		return $def->default_action;
	}

	private function code_for_category(BotCategory $cat): ResultCode
	{
		return match($cat) {
			BotCategory::AI_CRAWLER         => ResultCode::BLOCKED_AI_CRAWLER,
			BotCategory::SEO_CRAWLER        => ResultCode::BLOCKED_SEO_CRAWLER,
			BotCategory::RESIDENTIAL_PROXY  => ResultCode::BLOCKED_BOT,
			default                         => ResultCode::BLOCKED_BOT,
		};
	}
}
