<?php
// src/Feeds/CloudIpRangeProvider.php
// Implements IpRangeProvider for AWS/Azure/GCP/Cloudflare/Fastly service tags.
// Avoids hardcoded CIDR drift in BotDefinition.

namespace BadBehaviour\Feeds;

use BadBehaviour\Core\Interfaces\CacheInterface;

class CloudIpRangeProvider
{
	private CacheInterface $cache;
	private int $ttl = 86400; // 24h

	// Service endpoints for official JSON feeds.
	// Public so other components can reference URLs by name (logging, hints).
	public const FEED_URLS = [
		'aws'         => 'https://ip-ranges.amazonaws.com/ip-ranges.json',
		'cloudflare'  => 'https://api.cloudflare.com/client/v4/ips',  // alt: plain-text ips-v4/v6
		'fastly'      => 'https://api.fastly.com/public-ip-list',
		'gcp'         => 'https://www.gstatic.com/ipranges/cloud.json',
	];

	public function __construct(CacheInterface $cache, int $ttl = 86400)
	{
		$this->cache = $cache;
		$this->ttl = $ttl;
	}

	/**
	 * Resolve a service tag to CIDR list.
	 *
	 * @param string $provider  'aws'|'cloudflare'|'fastly'|'gcp'
	 * @param string|null $tag  'CLOUDFRONT', 'AMAZON', 'EC2', 'ROUTE53_HEALTHCHECKS', etc.
	 *                          Null = all ranges for the provider.
	 * @return string[]
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

		// Stale fallback
		if ($cached && isset($cached['data'])) {
			return $cached['data'];
		}

		return [];
	}

	private function fetch(string $provider, ?string $tag): ?array
	{
		$url = self::FEED_URLS[$provider] ?? null;
		if (!$url) return null;

		$ctx = stream_context_create([
			'http' => ['timeout' => 5, 'user_agent' => 'BadBehaviour/3.1 (+ip-range-feed)'],
		]);
		$json = @file_get_contents($url, false, $ctx);
		if (!$json) return null;

		$data = json_decode($json, true);
		if (!is_array($data)) return null;

		return match($provider) {
			'aws'         => $this->parse_aws($data, $tag),
			'cloudflare'  => $this->parse_cloudflare($data),
			'fastly'      => $this->parse_fastly($data),
			'gcp'         => $this->parse_gcp($data),
			default       => [],
		};
	}

	/**
	 * AWS ip-ranges.json:
	 * { "prefixes": [{"ip_prefix": "x.x.x.x/n", "service": "CLOUDFRONT"}, ...],
	 *   "ipv6_prefixes": [{"ipv6_prefix": "...", "service": "..."}] }
	 */
	private function parse_aws(array $data, ?string $tag): array
	{
		$out = [];
		foreach ($data['prefixes'] ?? [] as $p) {
			if ($tag === null || ($p['service'] ?? '') === $tag || ($p['region'] ?? '') === $tag) {
				if (!empty($p['ip_prefix'])) $out[] = $p['ip_prefix'];
			}
		}
		foreach ($data['ipv6_prefixes'] ?? [] as $p) {
			if ($tag === null || ($p['service'] ?? '') === $tag || ($p['region'] ?? '') === $tag) {
				if (!empty($p['ipv6_prefix'])) $out[] = $p['ipv6_prefix'];
			}
		}
		return array_values(array_unique($out));
	}

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

	private function parse_fastly(array $data): array
	{
		$out = [];
		foreach ($data['addresses'] ?? [] as $cidr) {
			$out[] = $cidr;
		}
		return array_values(array_unique($out));
	}

	private function parse_gcp(array $data): array
	{
		$out = [];
		foreach ($data['prefixes'] ?? [] as $p) {
			if (!empty($p['ipv4Prefix'])) $out[] = $p['ipv4Prefix'];
			if (!empty($p['ipv6Prefix'])) $out[] = $p['ipv6Prefix'];
		}
		return array_values(array_unique($out));
	}
}