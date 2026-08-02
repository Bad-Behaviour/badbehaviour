<?php

declare(strict_types=1);

namespace BadBehaviour\Bot;

/**
 * Read-only access to the bot registry.
 *
 * Implementations may be the shipped DefaultRegistry, a filtered subset,
 * a merged combination, or fully custom user-defined bots.
 *
 * Used by BadBehaviour internally (via BotDetector) and exposed publicly
 * for inspection, custom integrations, and testing.
 *
 * === NAMING CONVENTION ===
 *
 * All method names use snake_case to match the existing project style
 * (see Registry::find_by_ua, Registry::search_engines, etc.).
 *
 * === STABILITY ===
 *
 * This interface is the public API for third-party integrations.
 * New methods MAY be added in minor versions but existing signatures
 * are stable.
 */
interface RegistryInterface
{
	/**
	 * All registered bots as id => BotDefinition.
	 *
	 * Returned array shape: ['bot_id' => BotDefinition, ...]
	 * Order is implementation-defined (typically insertion or alphabetical).
	 */
	public function all(): array;

	/** Count of bots in the registry (for diagnostics). */
	public function count(): int;

	/** True if a bot with the given ID exists. */
	public function has(string $bot_id): bool;

	/** Get a single bot by ID, or null if not present. */
	public function get(string $bot_id): ?BotDefinition;

	/**
	 * Find bot IDs whose UA fragments match the given User-Agent.
	 *
	 * Substring match: each bot's user_agent_patterns entry is checked
	 * (case-insensitive). Patterns shorter than 4 chars are ignored.
	 *
	 * Returns ['bot_id1', 'bot_id2', ...] (may be empty).
	 */
	public function find_by_ua(string $ua): array;

	/**
	 * Token-based fallback matching.
	 *
	 * Splits the UA into tokens (split on non-alphanumeric), filters out
	 * noise tokens (browser/engine names, see RegistryTokens::NOISE) and
	 * short tokens (< RegistryTokens::MIN_TOKEN_LENGTH chars), then matches
	 * each remaining token against bot pattern substrings.
	 *
	 * Returns ['bot_id1', ...] (may be empty).
	 */
	public function find_by_tokens(string $ua): array;

	// ========================================================================
	// Per-category accessors (return id => BotDefinition)
	// ========================================================================

	/** @return array<string, BotDefinition> */
	public function search_engines(): array;

	/** @return array<string, BotDefinition> */
	public function ai_crawlers(): array;

	/** @return array<string, BotDefinition> */
	public function social_crawlers(): array;

	/** @return array<string, BotDefinition> */
	public function seo_crawlers(): array;

	/** @return array<string, BotDefinition> */
	public function archive_crawlers(): array;

	/** @return array<string, BotDefinition> */
	public function monitoring(): array;

	/** @return array<string, BotDefinition> */
	public function feed_readers(): array;

	/** @return array<string, BotDefinition> */
	public function shopping_crawlers(): array;

	/** @return array<string, BotDefinition> */
	public function cloud_infrastructure(): array;

	/** @return array<string, BotDefinition> */
	public function security_scanners(): array;

	/** @return array<string, BotDefinition> */
	public function residential_crawlers(): array;
}
