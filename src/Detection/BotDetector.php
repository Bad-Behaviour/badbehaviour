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
	private ?array $dynamic_ranges = null;
	private bool $dynamic_ranges_fetched = false;
	private ?CloudIpRangeProvider $cloud_provider = null;

	/**
	 * Per-instance result memoization (NOT static — avoids cross-config pollution).
	 * Cache key includes config fingerprint so different BadBehaviour instances
	 * with different configs get independent caches.
	 */
	private array $result_cache = [];
	private int $result_cache_max = 5000;
	private string $config_fingerprint;
	private const RESULT_CACHE_TTL = 300;

	public function __construct(
		Configuration $config,
		AdapterInterface $adapter,
		?RegistryInterface $registry = null  // ← NEW: optional injection
	) {
		$this->config = $config;
		$this->adapter = $adapter;
		// If no registry injected, fall back to the default shipped registry.
		// No global state mutation here — keep BotDetector pure.
		$this->registry = $registry ?? \BadBehaviour\Bot\RegistryFactory::default();

		$this->config_fingerprint = $this->compute_config_fingerprint($config);

		// Initialize cloud range provider if available
		if (method_exists($adapter, 'get') && $config->enable_dynamic_ip_ranges) {
			$this->cloud_provider = new CloudIpRangeProvider($adapter);
		}
	}

	private function compute_config_fingerprint(Configuration $config): string
	{
		return substr(hash('sha256', json_encode([
			'blocked_cat'      => $config->blocked_bot_categories,
			'allowed_ai'       => $config->allowed_ai_crawlers,
			'block_unverified' => $config->block_unverified_ai,
			'strict_ai'        => $config->strict_ai,
			'strict_se'        => $config->strict_search_engines,
			// Registry identity participates in the cache key so swapping
			// the registry cleanly invalidates cached results.
			'registry_hash'    => spl_object_hash($this->registry),
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
			if ($this->cloud_provider) {
				foreach (['aws', 'cloudflare', 'fastly', 'gcp'] as $provider) {
					$cloud_ranges = array_merge($cloud_ranges, $this->cloud_provider->ranges($provider));
				}
			}
		}

		if (empty($cloud_ranges)) {
			return false;
		}

		return IpUtil::match_any($ip, $cloud_ranges);
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
		if (!$this->config->enable_dynamic_ip_ranges) {
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

	private function verify_dns(string $ip, string $suffix): bool
	{
		$key = "{$ip}@{$suffix}";
		if (isset($this->dns_cache[$key])) {
			return $this->dns_cache[$key];
		}
		$cached = $this->adapter->get("bb:dns_verify:{$key}");
		if ($cached !== null) {
			$this->dns_cache[$key] = (bool)$cached;
			return (bool)$cached;
		}
		// Schedule background DNS lookup for the next request.
		// Returns false now — we don't block on DNS round-trip latency.
		$this->schedule_background_dns_lookup($ip, $suffix, $key);
		return false;
	}

	/**
	 * Defer the DNS verification to shutdown. On the next request, the cached
	 * result will be consulted via $this->adapter->get().
	 *
	 * Background lookups cost ~50-200ms each — we never want them on the
	 * hot path. Only run once per (IP, suffix) tuple per process lifetime
	 * (advisory — actual cache lives in the adapter).
	 */
	private function schedule_background_dns_lookup(string $ip, string $suffix, string $key): void
	{
		register_shutdown_function(function() use ($ip, $suffix, $key) {
			$host = @gethostbyaddr($ip);
			if (!$host) {
				$this->adapter->set("bb:dns_verify:{$key}", false, 3600);
				return;
			}
			$rev_host = strrev($host);
			$rev_suffix = strrev($suffix);
			if (strpos($rev_host, $rev_suffix) !== 0) {
				$this->adapter->set("bb:dns_verify:{$key}", false, 3600);
				return;
			}
			$addrs = @gethostbynamel($host);
			$verified = $addrs !== false && in_array($ip, $addrs, true);
			$this->adapter->set("bb:dns_verify:{$key}", $verified, 86400 * 7);
		});
	}
}
