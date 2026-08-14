<?php

declare(strict_types=1);

namespace BadBehaviour\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Util\CaBundleLocator;

/**
 * Resolves cloud provider IP ranges (AWS, Cloudflare, Fastly, GCP) from
 * their official JSON endpoints.
 *
 * The point of this class is to avoid hardcoded CIDR drift in
 * BotDefinition — ranges change weekly for AWS, monthly for Cloudflare,
 * and we shouldn't ship a library update every time.
 *
 * === CACHE LAYOUT ===
 *
 * Each provider has its own cache key: `ip_range:{$provider}:{$tag}`.
 * Default tag is 'all' (every range for the provider). AWS also supports
 * per-service tags like 'CLOUDFRONT' or 'ROUTE53_HEALTHCHECKS'.
 *
 * The merged cross-provider payload that BotDetector reads lives at
 * `bb:ip_ranges:merged` (see OnDemandRefresher::CACHE_KEY_MERGED) —
 * this class does NOT write to that key.
 *
 * === FETCH STRATEGY ===
 *
 * Reads cache first. If fresh (< TTL), returns cached payload. If stale
 * or absent, calls fetch() which uses file_get_contents with explicit
 * CA bundle. On total network failure, falls back to stale cache.
 *
 * === USAGE ===
 *
 * ```php
 * $provider = new CloudIpRangeProvider($cache);
 * $aws_cidrs = $provider->ranges('aws');                          // all ranges
 * $cloudfront = $provider->ranges('aws', 'CLOUDFRONT');           // service tag
 * ```
 */
class CloudIpRangeProvider
{
	/** @var CacheInterface */
	private $cache;

	/** @var int Cache TTL in seconds (default 24h) */
	private int $ttl = 86400;

	/**
	 * Service endpoints for official JSON feeds.
	 *
	 * Public so other components can reference URLs by name in logs
	 * and diagnostics (see BotDetector::build_cloud_init_hint()).
	 *
	 * @var array<string, string>
	 */
	public const FEED_URLS = [
		'aws'         => 'https://ip-ranges.amazonaws.com/ip-ranges.json',
		'cloudflare'  => 'https://api.cloudflare.com/client/v4/ips',
		'fastly'      => 'https://api.fastly.com/public-ip-list',
		'gcp'         => 'https://www.gstatic.com/ipranges/cloud.json',
	];

	public function __construct(CacheInterface $cache, int $ttl = 86400)
	{
		$this->cache = $cache;
		$this->ttl = $ttl;
	}

	/**
	 * Resolve a service tag to its CIDR list.
	 *
	 * Reads from cache first; if stale or absent, fetches from the
	 * upstream JSON feed and updates the cache. Returns the cached
	 * payload even on total upstream failure (stale tolerance).
	 *
	 * @param string      $provider 'aws' | 'cloudflare' | 'fastly' | 'gcp'
	 * @param string|null $tag      For AWS: service tag like 'CLOUDFRONT',
	 *                              'AMAZON', 'EC2', 'ROUTE53_HEALTHCHECKS'.
	 *                              Null = all ranges for the provider.
	 * @return string[] CIDR list (IPv4 + IPv6 mixed)
	 */
	public function ranges(string $provider, ?string $tag = null): array
	{
		$cache_key = "ip_range:{$provider}:" . ($tag ?? 'all');
		$cached = $this->cache->get($cache_key);
		if ($cached && isset($cached['data'], $cached['fetched'])) {
			if (time() - $cached['fetched'] < $this->ttl) {
				return $cached['data'];
			}
		}

		$fetched = $this->fetch($provider, $tag);
		if ($fetched !== null) {
			$this->cache->set($cache_key, ['data' => $fetched, 'fetched' => time()], $this->ttl);
			return $fetched;
		}

		// Stale fallback — better than nothing when feeds are down
		if ($cached && isset($cached['data'])) {
			return $cached['data'];
		}

		return [];
	}

	/**
	 * Fetch and parse a provider's IP range feed.
	 *
	 * Returns null on:
	 *   - unknown provider
	 *   - network failure
	 *   - invalid JSON
	 *
	 * Returns the parsed CIDR list (per provider-specific shape) on success.
	 */
	private function fetch(string $provider, ?string $tag): ?array
	{
		$url = self::FEED_URLS[$provider] ?? null;
		if (!$url) return null;

		$ca_bundle = CaBundleLocator::find();

		$context_options = [
			'http' => [
				'timeout' => 5,
				'user_agent' => 'BadBehaviour/3.1 (+ip-range-feed)',
			],
		];

		if ($ca_bundle !== null && !is_dir($ca_bundle)) {
			// cafile: single PEM bundle file. Use directly.
			$context_options['ssl'] = [
				'cafile' => $ca_bundle,
				'verify_peer' => true,
				'verify_peer_name' => true,
			];
		} elseif ($ca_bundle !== null && is_dir($ca_bundle)) {
			// capath: directory of hashed cert files (Debian-style).
			// file_get_contents supports capath via the capath option.
			$context_options['ssl'] = [
				'capath' => $ca_bundle,
				'verify_peer' => true,
				'verify_peer_name' => true,
			];
		} else {
			// No CA bundle found anywhere. Log loudly and disable
			// verification as a last resort. In practice the locator
			// covers all common OS install layouts, so reaching this
			// branch means something is unusual about the deployment.
			error_log("[BadBehaviour WARNING] CloudIpRangeProvider: no CA bundle "
				. "found, fetching {$url} without TLS verification");
			$context_options['ssl'] = [
				'verify_peer' => false,
				'verify_peer_name' => false,
			];
		}

		$ctx = stream_context_create($context_options);
		$json = @file_get_contents($url, false, $ctx);

		if (!$json) {
			$last_error = error_get_last();
			error_log("[BadBehaviour] CloudIpRangeProvider: failed to fetch {$url}"
			. (isset($last_error['message']) ? " — {$last_error['message']}" : ''));
			return null;
		}

		$data = json_decode($json, true);
		if (!is_array($data)) {
			error_log("[BadBehaviour] CloudIpRangeProvider: {$url} did not return valid JSON");
			return null;
		}

		return match ($provider) {
			'aws'         => $this->parse_aws($data, $tag),
			'cloudflare'  => $this->parse_cloudflare($data),
			'fastly'      => $this->parse_fastly($data),
			'gcp'         => $this->parse_gcp($data),
			default       => [],
		};
	}

	/**
	 * AWS ip-ranges.json shape:
	 * {
	 *   "prefixes": [
	 *     {"ip_prefix": "x.x.x.x/n", "service": "CLOUDFRONT", "region": "..."},
	 *     ...
	 *   ],
	 *   "ipv6_prefixes": [
	 *     {"ipv6_prefix": "...", "service": "...", "region": "..."},
	 *     ...
	 *   ]
	 * }
	 *
	 * @param array<string, mixed> $data Decoded JSON
	 * @param string|null          $tag Service tag filter (null = all)
	 * @return string[]
	 */
	private function parse_aws(array $data, ?string $tag): array
	{
		$out = [];

		foreach ($data['prefixes'] ?? [] as $p) {
			if ($tag === null
				|| ($p['service'] ?? '') === $tag
				|| ($p['region'] ?? '') === $tag) {
					if (!empty($p['ip_prefix'])) {
						$out[] = $p['ip_prefix'];
					}
				}
		}

		foreach ($data['ipv6_prefixes'] ?? [] as $p) {
			if ($tag === null
				|| ($p['service'] ?? '') === $tag
				|| ($p['region'] ?? '') === $tag) {
					if (!empty($p['ipv6_prefix'])) {
						$out[] = $p['ipv6_prefix'];
					}
				}
		}

		return array_values(array_unique($out));
	}

	/**
	 * Cloudflare /client/v4/ips shape:
	 * {
	 *   "result": {
	 *     "ipv4_cidrs": ["x.x.x.x/n", ...],
	 *     "ipv6_cidrs": ["::/n", ...]
	 *   },
	 *   "success": true,
	 *   ...
	 * }
	 *
	 * @param array<string, mixed> $data Decoded JSON
	 * @return string[]
	 */
	private function parse_cloudflare(array $data): array
	{
		$out = [];

		foreach ($data['result']['ipv4_cidrs'] ?? [] as $cidr) {
			$out[] = $cidr;
		}

		foreach ($data['result']['ipv6_cidrs'] ?? [] as $cidr) {
			$out[] = $cidr;
		}

		return array_values(array_unique($out));
	}

	/**
	 * Fastly /public-ip-list shape:
	 * {
	 *   "addresses": ["x.x.x.x/n", "::/n", ...],
	 *   "ipv6_addresses": ["::/n", ...]    // present in newer responses
	 * }
	 *
	 * @param array<string, mixed> $data Decoded JSON
	 * @return string[]
	 */
	private function parse_fastly(array $data): array
	{
		$out = [];

		foreach ($data['addresses'] ?? [] as $cidr) {
			$out[] = $cidr;
		}

		return array_values(array_unique($out));
	}

	/**
	 * Google Cloud /ipranges/cloud.json shape:
	 * {
	 *   "prefixes": [
	 *     {"ipv4Prefix": "x.x.x.x/n", "service": "...", "scope": "..."},
	 *     {"ipv6Prefix": "::/n", "service": "...", "scope": "..."}
	 *   ],
	 *   "creationTime": "...",
	 *   ...
	 * }
	 *
	 * @param array<string, mixed> $data Decoded JSON
	 * @return string[]
	 */
	private function parse_gcp(array $data): array
	{
		$out = [];

		foreach ($data['prefixes'] ?? [] as $p) {
			if (!empty($p['ipv4Prefix'])) {
				$out[] = $p['ipv4Prefix'];
			}
			if (!empty($p['ipv6Prefix'])) {
				$out[] = $p['ipv6Prefix'];
			}
		}

		return array_values(array_unique($out));
	}
}