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
use BadBehaviour\Util\IpUtil;
use BadBehaviour\Util\RequestPackage;

class BotDetector
{
	private Configuration $config;
	private AdapterInterface $adapter;
	private RegistryInterface $registry;

	private array $dns_cache = [];

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
	 * only. See follow-up note in verify_dns().
	 */
	private array $result_cache = [];
	private int $result_cache_max = 5000;
	private string $config_fingerprint;
	private const RESULT_CACHE_TTL = 300;

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
			$this->cloud_provider = new CloudIpRangeProvider($adapter);
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
	}

	private function detect_uncached(RequestPackage $package): ?Result
	{
		$ip = $package->ip;
		$ua = $package->user_agent;

		// === FAST PATH: CLOUD INFRASTRUCTURE WHITELIST ===
		// CRITICAL: Do this BEFORE bot UA matching — these are network probes,
		// not real bots, and blocking them = downtime.
		if ($this->is_cloud_infrastructure_ip($ip)) {
			return Result::allow($package);
		}

		$dynamic_ranges = $this->get_dynamic_ranges();

		// Primary: substring match against the registry's indexed UA fragments
		$candidate_ids = $this->registry->find_by_ua($ua);

		// Secondary: token match (with noise filter)
		if (empty($candidate_ids)) {
			$candidate_ids = $this->registry->find_by_tokens($ua);
		}

		if (empty($candidate_ids)) {
			return null;
		}

		foreach ($candidate_ids as $bot_id) {
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

			$dns_verified = false;
			if ($def->verify_dns && $def->dns_suffix) {
				$dns_verified = $this->verify_dns($ip, $def->dns_suffix);
			}

			$verified = $ip_match || $dns_verified;
			$action = $this->determine_action($def, $verified);

			return match ($action) {
				BotAction::ALLOW => Result::allow($package),
				BotAction::LOG_ONLY => Result::allow($package),
				BotAction::CHALLENGE => Result::challenge(
					ResultCode::CHALLENGE_REQUIRED,
					"Bot challenge required: {$def->name}",
					$package,
					[
						'bot_id'       => $bot_id,
						'bot_name'     => $def->name,
						'bot_category' => $def->category->value,
						'bot_verified' => $verified,
					]
				),
				BotAction::BLOCK => Result::block(
					$this->code_for_category($def->category),
					"Bot blocked: {$def->name}",
					$package,
					[
						'bot_id'       => $bot_id,
						'bot_name'     => $def->name,
						'bot_category' => $def->category->value,
						'bot_verified' => $verified,
					]
				),
			};
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
	 */
	private function is_cloud_infrastructure_ip(string $ip): bool
	{
		static $cloud_ranges = null;
		if ($cloud_ranges === null) {
			$cloud_ranges = [];
			foreach ($this->registry->cloud_infrastructure() as $bot) {
				$cloud_ranges = array_merge($cloud_ranges, $bot->ip_ranges);
			}
			// Optional: append dynamic ranges if enabled
			if ($this->cloud_provider && $this->config->dynamic_ip_ranges_enabled) {
				foreach ($this->config->dynamic_ip_ranges_feeds as $provider) {
					$cloud_ranges = array_merge($cloud_ranges, $this->cloud_provider->ranges($provider));
				}
			}
		}

		if (empty($cloud_ranges)) {
			return false;
		}

		return IpUtil::match_any($ip, $cloud_ranges);
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
	 *      The latency cost (40-300ms) is paid ONCE per (IP, suffix) tuple,
	 *      then cached.
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
	 * DNS latency hit per (IP, suffix). For a real bot visiting your site,
	 * that's 1 slow request followed by N fast ones.
	 *
	 * === CACHE KEY SHAPE ===
	 *
	 * `bb:dns_verify:{bin2hex(inet_pton($ip))}:{suffix}`
	 *
	 * Binary IP form ensures IPv6 normalization (e.g., "2a03:2880::1" and
	 * "2a03:2880:0:0:0:0:0:1" produce the same key). Stable across adapter
	 * backends (no escaping issues with colons in IPv6 text form).
	 *
	 * === FOLLOW-UP NOTE ===
	 *
	 *   - $dns_cache: keyed by "ip@suffix", stores bool, request-scoped.
	 *     Avoids redundant DNS lookups within a single request.
	 *
	 *   - $result_cache: keyed by fingerprint+hash(ip|ua), stores Result,
	 *     instance-scoped with 300s TTL. Memoizes full bot detection.
	 *
	 * The two caches operate at different levels of the detection pipeline
	 * and have non-overlapping key spaces.
	 */
	private function verify_dns(string $ip, string $suffix): bool
	{
		// === Kill switch ===
		if (!$this->config->dns_verification_enabled) {
			return false;
		}

		$key = "{$ip}@{$suffix}";

		// === Per-request instance cache ===
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
		$cached = $this->adapter->get($cache_key);
		if ($cached !== null) {
			$result = (bool)$cached;
			$this->dns_cache[$key] = $result;
			return $result;
		}

		// === Cold cache — synchronous verification with bounded timeout ===
		$result = $this->do_dns_verify_bounded($ip, $suffix);

		$ttl = $result
			? $this->config->dns_verification_positive_ttl
			: $this->config->dns_verification_negative_ttl;

		$this->adapter->set($cache_key, $result, $ttl);
		$this->dns_cache[$key] = $result;

		return $result;
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
			return Result::allow($package);
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
		$cache_key = 'bb:ip_ranges:merged';
		$cached = $this->adapter->get($cache_key);
		if ($cached && isset($cached['data'], $cached['fetched'])) {
			$this->dynamic_ranges = $cached['data'];
			return $this->dynamic_ranges;
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

		// === HARD BLOCK: category explicitly blocked ===
		if (in_array($cat, $this->config->blocked_bot_categories, true)) {
			return BotAction::BLOCK;
		}

		// === CLOUD INFRASTRUCTURE: never block ===
		if ($cat === BotCategory::CLOUD_INFRASTRUCTURE->value) {
			return BotAction::ALLOW;
		}

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
