<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Bot\RegistryTokens;

/**
 * Combines multiple registries into one, with later sources taking priority.
 *
 * Use cases:
 *   - Add custom bots to a default registry without subclassing
 *   - Multi-tenant: per-tenant additions over a shared default
 *   - Override shipped definitions (e.g., "I disagree with the default for `petal`")
 *
 * === MERGE RULES ===
 *
 *   - Bot IDs are unique within the merged result
 *   - Later registries in the array OVERWRITE earlier ones for the same ID
 *   - Categories are partitioned across all sources
 *
 * === EXAMPLE ===
 *
 * ```php
 * $registry = new MergedRegistry([
 *     new DefaultRegistry(),          // ~100 shipped bots
 *     new CustomRegistry([            // + my additions
 *         'internal_search' => new BotDefinition(/* ... *\/),
 *     ]),
 * ]);
 * ```
 */
class MergedRegistry implements RegistryInterface
{
	/** @var RegistryInterface[] */
	private array $registries;

	private ?array $all_cache = null;
	private ?array $ua_index = null;
	private ?array $ua_token_index = null;

	/**
	 * @param RegistryInterface[] $registries Order matters: later wins.
	 * @throws \InvalidArgumentException If any entry isn't a RegistryInterface
	 */
	public function __construct(array $registries)
	{
		foreach ($registries as $i => $r) {
			if (!$r instanceof RegistryInterface) {
				throw new \InvalidArgumentException(
					"MergedRegistry: entry {$i} is not a RegistryInterface"
				);
			}
		}
		$this->registries = array_values($registries);
	}

	// ========================================================================
	// RegistryInterface implementation
	// ========================================================================

	public function all(): array
	{
		if ($this->all_cache !== null) {
			return $this->all_cache;
		}

		$merged = [];
		// Iterate in REVERSE so later registries overwrite earlier (last-wins)
		for ($i = count($this->registries) - 1; $i >= 0; $i--) {
			foreach ($this->registries[$i]->all() as $id => $def) {
				$merged[$id] = $def;
			}
		}

		return $this->all_cache = $merged;
	}

	public function count(): int
	{
		return count($this->all());
	}

	public function has(string $bot_id): bool
	{
		return $this->get($bot_id) !== null;
	}

	public function get(string $bot_id): ?BotDefinition
	{
		// Search in REVERSE order so later registries take priority
		for ($i = count($this->registries) - 1; $i >= 0; $i--) {
			$def = $this->registries[$i]->get($bot_id);
			if ($def !== null) {
				return $def;
			}
		}
		return null;
	}

	public function find_by_ua(string $ua): array
	{
		$ua_lower = strtolower($ua);
		if ($ua_lower === '') {
			return [];
		}

		$this->ensure_ua_index();

		$matched = [];
		foreach ($this->ua_index as $fragment => $bot_ids) {
			if (strlen($fragment) < 4) {
				continue;
			}
			if (str_contains($ua_lower, $fragment)) {
				foreach ($bot_ids as $id) {
					$matched[$id] = true;
				}
			}
		}
		return array_keys($matched);
	}

	public function find_by_tokens(string $ua): array
	{
		if ($ua === '') {
			return [];
		}

		$this->ensure_token_index();

		$ua_lower = strtolower($ua);
		$tokens = preg_split('/[^a-z0-9]+/', $ua_lower);
		$min_len = RegistryTokens::MIN_TOKEN_LENGTH;
		$tokens = array_filter(
			$tokens,
			fn($t) => strlen($t) >= $min_len && !in_array($t, RegistryTokens::NOISE, true)
		);

		if (empty($tokens)) {
			return [];
		}

		$matched = [];
		foreach ($tokens as $token) {
			if (isset($this->ua_token_index[$token])) {
				foreach ($this->ua_token_index[$token] as $id) {
					$matched[$id] = true;
				}
			}
		}
		return array_keys($matched);
	}

	/**
	 * Return the underlying registries (read-only access for inspection/testing).
	 *
	 * @return RegistryInterface[]
	 */
	public function get_registries(): array
	{
		return $this->registries;
	}

	// ========================================================================
	// Per-category accessors
	// ========================================================================

	public function search_engines(): array
	{
		return $this->collect_category('search_engines');
	}

	public function ai_crawlers(): array
	{
		return $this->collect_category('ai_crawlers');
	}

	public function social_crawlers(): array
	{
		return $this->collect_category('social_crawlers');
	}

	public function seo_crawlers(): array
	{
		return $this->collect_category('seo_crawlers');
	}

	public function archive_crawlers(): array
	{
		return $this->collect_category('archive_crawlers');
	}

	public function monitoring(): array
	{
		return $this->collect_category('monitoring');
	}

	public function feed_readers(): array
	{
		return $this->collect_category('feed_readers');
	}

	public function shopping_crawlers(): array
	{
		return $this->collect_category('shopping_crawlers');
	}

	public function cloud_infrastructure(): array
	{
		return $this->collect_category('cloud_infrastructure');
	}

	public function security_scanners(): array
	{
		return $this->collect_category('security_scanners');
	}

	public function residential_crawlers(): array
	{
		return $this->collect_category('residential_crawlers');
	}

	/**
	 * Collect bots of a given category across all source registries.
	 * Later registries overwrite earlier ones for the same ID (last-wins).
	 */
	private function collect_category(string $method): array
	{
		$merged = [];
		// Reverse for last-wins semantics
		for ($i = count($this->registries) - 1; $i >= 0; $i--) {
			if (method_exists($this->registries[$i], $method)) {
				foreach ($this->registries[$i]->$method() as $id => $def) {
					$merged[$id] = $def;
				}
			}
		}
		return $merged;
	}

	// ========================================================================
	// Index builders (lazy)
	// ========================================================================

	private function ensure_ua_index(): void
	{
		if ($this->ua_index !== null) {
			return;
		}
		$this->ua_index = [];
		foreach ($this->all() as $bot_id => $def) {
			foreach ($def->user_agent_patterns as $pattern) {
				$key = strtolower($pattern);
				if ($key === '' || strlen($key) < 4) {
					continue;
				}
				$this->ua_index[$key][] = $bot_id;
			}
		}
	}

	private function ensure_token_index(): void
	{
		if ($this->ua_token_index !== null) {
			return;
		}
		$this->ua_token_index = [];
		$min_len = RegistryTokens::MIN_TOKEN_LENGTH;
		foreach ($this->all() as $bot_id => $def) {
			foreach ($def->user_agent_patterns as $pattern) {
				$lower = strtolower($pattern);
				$tokens = preg_split('/[^a-z0-9]+/', $lower);
				foreach ($tokens as $token) {
					if (strlen($token) >= $min_len && !in_array($token, RegistryTokens::NOISE, true)) {
						$this->ua_token_index[$token][] = $bot_id;
					}
				}
			}
		}
	}
}
