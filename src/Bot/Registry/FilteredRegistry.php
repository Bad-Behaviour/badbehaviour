<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Bot\RegistryTokens;

/**
 * Wraps another registry, filtering bots by keep-list, exclude-list, or categories.
 *
 * Lazy and cache-friendly:
 *   - Filters are applied once on first `all()` call and cached
 *   - Per-category accessors delegate to the inner registry's category methods,
 *     then filter results (no second cache layer needed — inner registry's
 *     results are already efficient)
 *
 * Use cases:
 *   - Apply `exclude_bots` from config to a default registry
 *   - Build `minimal`/`verified-only`/`no-ai` style subsets
 *   - Drop a category (e.g., "no SEO crawlers in my registry")
 *
 * === EXAMPLE ===
 *
 * ```php
 * $filtered = new FilteredRegistry(
 *     inner: new DefaultRegistry(),
 *     exclude_bots: ['petal', 'brightdata'],
 *     exclude_categories: ['seo_crawler'],
 * );
 * ```
 *
 * === FILTER PRECEDENCE (applied to each bot) ===
 *
 *   1. Keep-list (whitelist) — bot must be in this list to pass
 *   2. Exclude-list — bot must NOT be in this list
 *   3. Category include — bot's category must be in this list (if set)
 *   4. Category exclude — bot's category must NOT be in this list
 *
 * Steps 1 and 2 are bot-ID based; steps 3 and 4 are category-based.
 * A bot must pass ALL active filters.
 */
class FilteredRegistry implements RegistryInterface
{
	private RegistryInterface $inner;

	/** @var string[] Bot IDs to keep (whitelist). Empty = no whitelist. */
	private array $keep_bots;

	/** @var string[] Bot IDs to exclude (blacklist). */
	private array $exclude_bots;

	/** @var string[]|null Categories to include (null = no filter). */
	private ?array $include_categories;

	/** @var string[] Categories to exclude. */
	private array $exclude_categories;

	/** Cached filtered `all()` result. */
	private ?array $all_cache = null;

	/** Lazily built UA index. */
	private ?array $ua_index = null;

	/** Lazily built token index. */
	private ?array $ua_token_index = null;

	/**
	 * @param RegistryInterface $inner
	 * @param string[] $keep_bots Whitelist of bot IDs (empty = no whitelist)
	 * @param string[] $exclude_bots Blacklist of bot IDs
	 * @param string[]|null $include_categories If set, ONLY these categories pass
	 * @param string[] $exclude_categories Categories to drop
	 */
	public function __construct(
		RegistryInterface $inner,
		array $keep_bots = [],
		array $exclude_bots = [],
		?array $include_categories = null,
		array $exclude_categories = []
	) {
		$this->inner = $inner;
		$this->keep_bots = $keep_bots;
		$this->exclude_bots = $exclude_bots;
		$this->include_categories = $include_categories;
		$this->exclude_categories = $exclude_categories;
	}

	// ========================================================================
	// Static factory helpers (more readable at the call site)
	// ========================================================================

	/**
	 * Convenience: keep only specific bot IDs.
	 */
	public static function by_bot_ids(
		RegistryInterface $inner,
		array $keep = [],
		array $exclude = []
	): self {
		return new self($inner, keep_bots: $keep, exclude_bots: $exclude);
	}

	/**
	 * Convenience: filter by category.
	 */
	public static function by_category(
		RegistryInterface $inner,
		?array $include = null,
		array $exclude = []
	): self {
		return new self(
			$inner,
			include_categories: $include,
			exclude_categories: $exclude
		);
	}

	// ========================================================================
	// RegistryInterface implementation
	// ========================================================================

	public function all(): array
	{
		if ($this->all_cache !== null) {
			return $this->all_cache;
		}

		$this->all_cache = array_filter(
			$this->inner->all(),
			fn(BotDefinition $bot) => $this->passes($bot)
		);

		return $this->all_cache;
	}

	public function count(): int
	{
		return count($this->all());
	}

	public function has(string $bot_id): bool
	{
		$bot = $this->inner->get($bot_id);
		return $bot !== null && $this->passes($bot);
	}

	public function get(string $bot_id): ?BotDefinition
	{
		$bot = $this->inner->get($bot_id);
		if ($bot === null || !$this->passes($bot)) {
			return null;
		}
		return $bot;
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
	 * Inspect the underlying registry (for diagnostics).
	 */
	public function get_inner(): RegistryInterface
	{
		return $this->inner;
	}

	// ========================================================================
	// Per-category accessors — delegate to inner, then filter
	// ========================================================================

	public function search_engines(): array
	{
		return $this->filter_category($this->inner->search_engines());
	}

	public function ai_crawlers(): array
	{
		return $this->filter_category($this->inner->ai_crawlers());
	}

	public function social_crawlers(): array
	{
		return $this->filter_category($this->inner->social_crawlers());
	}

	public function seo_crawlers(): array
	{
		return $this->filter_category($this->inner->seo_crawlers());
	}

	public function archive_crawlers(): array
	{
		return $this->filter_category($this->inner->archive_crawlers());
	}

	public function monitoring(): array
	{
		return $this->filter_category($this->inner->monitoring());
	}

	public function feed_readers(): array
	{
		return $this->filter_category($this->inner->feed_readers());
	}

	public function shopping_crawlers(): array
	{
		return $this->filter_category($this->inner->shopping_crawlers());
	}

	public function cloud_infrastructure(): array
	{
		return $this->filter_category($this->inner->cloud_infrastructure());
	}

	public function security_scanners(): array
	{
		return $this->filter_category($this->inner->security_scanners());
	}

	public function residential_crawlers(): array
	{
		return $this->filter_category($this->inner->residential_crawlers());
	}

	// ========================================================================
	// Internal: filter logic
	// ========================================================================

	/**
	 * Apply all configured filters to a single bot.
	 *
	 * Returns true if the bot should be visible in this filtered registry.
	 */
	private function passes(BotDefinition $bot): bool
	{
		// 1. Keep-list (whitelist) — if set, bot MUST be in this list
		if (!empty($this->keep_bots) && !in_array($bot->id, $this->keep_bots, true)) {
			return false;
		}

		// 2. Explicit exclude-list
		if (in_array($bot->id, $this->exclude_bots, true)) {
			return false;
		}

		// 3. Category include-filter (when set, ONLY these categories pass)
		if ($this->include_categories !== null) {
			if (!in_array($bot->category->value, $this->include_categories, true)) {
				return false;
			}
		}

		// 4. Category exclude-filter
		if (in_array($bot->category->value, $this->exclude_categories, true)) {
			return false;
		}

		return true;
	}

	private function filter_category(array $bots): array
	{
		return array_filter($bots, fn(BotDefinition $bot) => $this->passes($bot));
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
