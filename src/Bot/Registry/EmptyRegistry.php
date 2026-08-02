<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\RegistryInterface;

/**
 * A registry that matches nothing.
 *
 * Use cases:
 *   - "Humans only" deployments (paired with additions via MergedRegistry)
 *   - Bypassing bot detection in specific code paths (testing, emergency)
 *   - Placeholder when no bots should be recognized
 *
 * === PERFORMANCE ===
 *
 * Singleton via the static `instance()` helper to avoid allocation on hot paths.
 * Every method returns an empty result without consulting any backing data.
 *
 * === EXAMPLE ===
 *
 * ```php
 * $registry = new MergedRegistry([
 *     EmptyRegistry::instance(),                            // humans
 *     new InMemoryRegistry($my_internal_bots),             // + my bots
 * ]);
 * ```
 */
class EmptyRegistry implements RegistryInterface
{
	/** Shared singleton instance. */
	private static ?self $instance = null;

	/** Get the shared empty instance. */
	public static function instance(): self
	{
		if (self::$instance === null) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function all(): array
	{
		return [];
	}

	public function count(): int
	{
		return 0;
	}

	public function has(string $bot_id): bool
	{
		return false;
	}

	public function get(string $bot_id): ?\BadBehaviour\Bot\BotDefinition
	{
		return null;
	}

	public function find_by_ua(string $ua): array
	{
		return [];
	}

	public function find_by_tokens(string $ua): array
	{
		return [];
	}

	public function search_engines(): array
	{
		return [];
	}

	public function ai_crawlers(): array
	{
		return [];
	}

	public function social_crawlers(): array
	{
		return [];
	}

	public function seo_crawlers(): array
	{
		return [];
	}

	public function archive_crawlers(): array
	{
		return [];
	}

	public function monitoring(): array
	{
		return [];
	}

	public function feed_readers(): array
	{
		return [];
	}

	public function shopping_crawlers(): array
	{
		return [];
	}

	public function cloud_infrastructure(): array
	{
		return [];
	}

	public function security_scanners(): array
	{
		return [];
	}

	public function residential_crawlers(): array
	{
		return [];
	}
}
