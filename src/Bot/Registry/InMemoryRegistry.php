<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Bot\RegistryTokens;

/**
 * A registry that wraps a user-provided array of BotDefinitions.
 *
 * Most useful for:
 *   - Tests (mock registries with known bots)
 *   - Programmatic construction (build a registry from code, not config)
 *   - Composing registries (use MergedRegistry with this as one source)
 *
 * Duplicate IDs are silently overwritten (last one wins) — callers should
 * validate uniqueness themselves if it matters.
 *
 * === EXAMPLE ===
 *
 * ```php
 * $registry = new InMemoryRegistry([
 *     'my_bot' => new BotDefinition(
 *         id: 'my_bot',
 *         name: 'My Bot',
 *         user_agent_patterns: ['MyBot'],
 *         category: BotCategory::SEARCH_ENGINE,
 *     ),
 * ]);
 * ```
 */
class InMemoryRegistry implements RegistryInterface
{
	/** Bot definitions by category, lazily partitioned. */
	private array $by_category = [];

	/** Lazily built UA index: lowercase fragment => [bot_id, ...] */
	private ?array $ua_index = null;

	/** Lazily built token index: token => [bot_id, ...] */
	private ?array $ua_token_index = null;

	/**
	 * @param array<string, BotDefinition> $bots Bot ID => definition
	 * @throws \InvalidArgumentException If any entry isn't a BotDefinition or has empty UA patterns
	 */
	public function __construct(array $bots = [])
	{
		foreach ($bots as $id => $def) {
			if (!$def instanceof BotDefinition) {
				throw new \InvalidArgumentException(
					"InMemoryRegistry: entry '{$id}' is not a BotDefinition"
				);
			}
			if (empty($def->user_agent_patterns)) {
				throw new \InvalidArgumentException(
					"InMemoryRegistry: bot '{$id}' has empty user_agent_patterns"
				);
			}
		}

		foreach ($bots as $id => $def) {
			$cat = $def->category->value;
			$this->by_category[$cat][$id] = $def;
		}
	}

	// ========================================================================
	// RegistryInterface implementation
	// ========================================================================

	public function all(): array
	{
		$merged = [];
		foreach ($this->by_category as $bots) {
			foreach ($bots as $id => $def) {
				$merged[$id] = $def;
			}
		}
		return $merged;
	}

	public function count(): int
	{
		$n = 0;
		foreach ($this->by_category as $bots) {
			$n += count($bots);
		}
		return $n;
	}

	public function has(string $bot_id): bool
	{
		foreach ($this->by_category as $bots) {
			if (isset($bots[$bot_id])) {
				return true;
			}
		}
		return false;
	}

	public function get(string $bot_id): ?BotDefinition
	{
		foreach ($this->by_category as $bots) {
			if (isset($bots[$bot_id])) {
				return $bots[$bot_id];
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
			// Fragments shorter than 4 chars are noise — same threshold
			// the legacy Registry used to avoid false positives.
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

	// ========================================================================
	// Per-category accessors
	// ========================================================================

	public function search_engines(): array
	{
		return $this->by_category[BotCategory::SEARCH_ENGINE->value] ?? [];
	}

	public function ai_crawlers(): array
	{
		return $this->by_category[BotCategory::AI_CRAWLER->value] ?? [];
	}

	public function social_crawlers(): array
	{
		return $this->by_category[BotCategory::SOCIAL_CRAWLER->value] ?? [];
	}

	public function seo_crawlers(): array
	{
		return $this->by_category[BotCategory::SEO_CRAWLER->value] ?? [];
	}

	public function archive_crawlers(): array
	{
		return $this->by_category[BotCategory::ARCHIVE_CRAWLER->value] ?? [];
	}

	public function monitoring(): array
	{
		return $this->by_category[BotCategory::MONITORING->value] ?? [];
	}

	public function feed_readers(): array
	{
		return $this->by_category[BotCategory::FEED_READER->value] ?? [];
	}

	public function shopping_crawlers(): array
	{
		return $this->by_category[BotCategory::SHOPPING_CRAWLER->value] ?? [];
	}

	public function cloud_infrastructure(): array
	{
		return $this->by_category[BotCategory::CLOUD_INFRASTRUCTURE->value] ?? [];
	}

	public function security_scanners(): array
	{
		return $this->by_category[BotCategory::SECURITY_SCANNER->value] ?? [];
	}

	public function residential_crawlers(): array
	{
		return $this->by_category[BotCategory::RESIDENTIAL_PROXY->value] ?? [];
	}

	// ========================================================================
	// Mutation (not part of RegistryInterface — convenience for callers)
	// ========================================================================

	/**
	 * Add or replace a bot in this registry.
	 *
	 * Useful for runtime registration (e.g., plugin-loaded custom bots).
	 * Invalidates the UA/token indices lazily on next query.
	 */
	public function add(BotDefinition $bot): void
	{
		$cat = $bot->category->value;
		$this->by_category[$cat][$bot->id] = $bot;
		$this->ua_index = null;
		$this->ua_token_index = null;
	}

	/**
	 * Remove a bot from this registry.
	 *
	 * Returns true if the bot was present and removed, false otherwise.
	 */
	public function remove(string $bot_id): bool
	{
		foreach ($this->by_category as $cat => $bots) {
			if (isset($bots[$bot_id])) {
				unset($this->by_category[$cat][$bot_id]);
				if (empty($this->by_category[$cat])) {
					unset($this->by_category[$cat]);
				}
				$this->ua_index = null;
				$this->ua_token_index = null;
				return true;
			}
		}
		return false;
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
