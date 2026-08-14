<?php

declare(strict_types=1);

namespace BadBehaviour\Feeds\Adapters;

use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Feeds\IpFeedInterface;
use BadBehaviour\Util\CaBundleLocator;

/**
 * Abstract base for JSON-format IP range feeds.
 *
 * Concrete subclasses (GoogleJsonFeed, BingJsonFeed, OpenAIJsonFeed,
 * AnthropicJsonFeed, AppleJsonFeed, GenericJsonFeed) just need to
 * implement get_source_name() and get_bot_ids(), and optionally
 * override fetch() if the JSON shape doesn't match the
 * {"prefixes": [{ipv4Prefix|ipv6Prefix}]} standard.
 *
 * === FETCH STRATEGY ===
 *
 * Two-tier fetch with graceful degradation:
 *
 *   Tier 1: cURL with explicit CA bundle
 *     - Pinned CA bundle via CaBundleLocator::find()
 *     - cURL sets verify_peer=true based on the CA bundle path
 *     - Returns null on any HTTP error (404, 500, timeout, etc.)
 *
 *   Tier 2: file_get_contents with stream context
 *     - Same CA bundle, but applied via stream context options
 *     - Falls back to "verify_peer=false" only as a last resort
 *       (and logs a warning when it does)
 *
 * If both tiers fail, returns the stale cache (if any) or [].
 *
 * === CACHING ===
 *
 * Each concrete subclass is wrapped in CachedFeedDecorator, which
 * caches per-source results. This base class does its own per-call
 * caching too via the `cache_key` derived from get_source_name().
 * The double-caching is intentional: outer for cross-process reuse,
 * inner for in-process duplicate-call suppression.
 */
abstract class AbstractJsonFeed implements IpFeedInterface
{
	/** @var string Feed URL — set by concrete subclass constructor */
	protected string $url;

	/** @var int HTTP timeout in seconds */
	protected int $timeout = 3;

	/** @var string[] Top-level JSON keys required for the payload to be considered valid */
	protected array $expected_keys = [];

	/** @var CacheInterface */
	protected $cache;

	/** @var int Cache TTL in seconds */
	protected int $ttl;

	/**
	 * @param CacheInterface $cache Shared cache backend.
	 * @param int $ttl              Fresh-TTL in seconds (default 24h).
	 */
	public function __construct(CacheInterface $cache, int $ttl = 86400)
	{
		$this->cache = $cache;
		$this->ttl = $ttl;
	}

	/**
	 * Fetch IP ranges with cache fallback.
	 *
	 * Tries fresh cache → fresh fetch → stale cache → empty array.
	 * Never throws — feed failures are logged and degraded gracefully.
	 *
	 * @return array<string, string[]> Bot ID => CIDR list (per bot covered by this feed)
	 */
	public function fetch(): array
	{
		$cache_key = 'ip_feed:' . $this->get_source_name();

		// 1. Try cache first (even stale)
		$cached = $this->cache->get($cache_key);
		if ($cached && isset($cached['data'], $cached['fetched'])) {
			// If fresh, return immediately
			if (time() - $cached['fetched'] < $this->ttl) {
				return $cached['data'];
			}
			// Stale but usable — keep as fallback
			$fallback = $cached['data'];
		} else {
			$fallback = null;
		}

		// 2. Fetch fresh
		$fresh = $this->fetch_fresh();

		if ($fresh) {
			// Validate structure
			if ($this->validate($fresh)) {
				$this->cache->set($cache_key, [
					'data' => $fresh,
					'fetched' => time(),
				], $this->ttl);
				return $fresh;
			}

			// Invalid structure — log and use fallback
			error_log("[BadBehaviour] Feed {$this->get_source_name()} returned invalid structure");
		}

		// 3. Graceful degradation: return stale cache
		if ($fallback) {
			error_log("[BadBehaviour] Using STALE cache for {$this->get_source_name()}");
			return $fallback;
		}

		// 4. No cache, no fresh — return empty (DNS verification will catch real bots)
		error_log("[BadBehaviour] Feed {$this->get_source_name()} unavailable, no cache");
		return [];
	}

	/**
	 * Try both fetch tiers in order. Returns null on total failure.
	 */
	private function fetch_fresh(): ?array
	{
		$result = $this->fetch_with_curl();
		if ($result !== null) return $result;

		return $this->fetch_with_stream_context();
	}

	/**
	 * cURL-based fetch with explicit CA bundle pinning.
	 *
	 * Returns null on:
	 *   - missing CA bundle (caller falls back to stream context)
	 *   - non-200 HTTP response
	 *   - network error
	 *   - JSON decode failure
	 *
	 * Returns the decoded JSON array on success.
	 */
	private function fetch_with_curl(): ?array
	{
		$ch = curl_init($this->url);
		$ca_bundle = CaBundleLocator::find();

		$options = [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT => $this->timeout,
			CURLOPT_USERAGENT => 'BadBehaviour/3.0 (+https://github.com/Bad-Behaviour/badbehaviour)',
		];

		if ($ca_bundle !== null) {
			$options[CURLOPT_CAINFO] = $ca_bundle;
			// CAPATH is the directory holding the cert files (Debian-style
			// /etc/ssl/certs/ with hashed symlinks). When the locator
			// returned a directory, point CAPATH at it directly; when it
			// returned a single PEM bundle file, point CAPATH at the parent
			// directory (some cURL builds fall back to it).
			if (is_dir($ca_bundle)) {
				$options[CURLOPT_CAPATH] = $ca_bundle;
			} else {
				$options[CURLOPT_CAPATH] = dirname($ca_bundle);
			}
			$options[CURLOPT_SSL_VERIFYPEER] = true;
		} else {
			// No CA bundle found — skip cURL, try stream context with
			// relaxed verification. This path is rare; the locator
			// covers all common OS install layouts.
			return null;
		}

		curl_setopt_array($ch, $options);
		$response = curl_exec($ch);
		$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$curl_error = curl_error($ch);
		curl_close($ch);

		if ($http_code !== 200 || !$response) {
			error_log("[BadBehaviour] Feed {$this->get_source_name()} cURL failed: "
			. "HTTP {$http_code} " . ($curl_error ?: ''));
			return null;
		}

		$data = json_decode($response, true);
		if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
			error_log("[BadBehaviour] Feed {$this->get_source_name()} returned invalid JSON");
			return null;
		}

		return $data;
	}

	/**
	 * file_get_contents-based fallback.
	 *
	 * Tries with a properly pinned CA bundle first (via stream context);
	 * falls back to verify_peer=false with a loud warning if no CA bundle
	 * is available anywhere. Returns null on network failure.
	 */
	private function fetch_with_stream_context(): ?array
	{
		$ca_bundle = CaBundleLocator::find();

		$context_options = [
			'http' => [
				'timeout' => $this->timeout,
				'user_agent' => 'BadBehaviour/3.0',
			],
		];

		if ($ca_bundle !== null && !is_dir($ca_bundle)) {
			// cafile: single PEM bundle.
			$context_options['ssl'] = [
				'cafile' => $ca_bundle,
				'verify_peer' => true,
				'verify_peer_name' => true,
			];
		} elseif ($ca_bundle !== null && is_dir($ca_bundle)) {
			// capath: directory of hashed cert symlinks (Debian-style).
			$context_options['ssl'] = [
				'capath' => $ca_bundle,
				'verify_peer' => true,
				'verify_peer_name' => true,
			];
		} else {
			// No CA bundle found. Last-resort: disable verification.
			// Logged loudly so operators know they're shipping unverified
			// TLS in production — not a security catastrophe for IP range
			// feeds (the data is public anyway) but worth fixing.
			error_log("[BadBehaviour WARNING] No CA bundle found, "
				. "fetching {$this->url} without SSL verification");
			$context_options['ssl'] = [
				'verify_peer' => false,
				'verify_peer_name' => false,
			];
		}

		$context = stream_context_create($context_options);
		$response = @file_get_contents($this->url, false, $context);

		if (!$response) {
			$last_error = error_get_last();
			error_log("[BadBehaviour] Feed {$this->get_source_name()} stream context failed"
			. (isset($last_error['message']) ? " — {$last_error['message']}" : ''));
			return null;
		}

		$data = json_decode($response, true);
		if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
			error_log("[BadBehaviour] Feed {$this->get_source_name()} returned invalid JSON");
			return null;
		}

		return $data;
	}

	/**
	 * Validate that the decoded JSON contains the expected structure.
	 *
	 * Concrete subclasses declare $expected_keys (e.g., ['prefixes']) and
	 * this check ensures each one is present and is an array. Subclasses
	 * that have non-standard JSON shapes should override this method
	 * (currently none do — all conform to {prefixes: [...]}).
	 */
	protected function validate(array $data): bool
	{
		foreach ($this->expected_keys as $key) {
			if (!isset($data[$key]) || !is_array($data[$key])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Subclass identifier for cache keys and logging.
	 */
	abstract public function get_source_name(): string;

	/**
	 * Bot IDs this feed covers (used for cache partitioning and metrics).
	 *
	 * @return string[]
	 */
	abstract public function get_bot_ids(): array;
}