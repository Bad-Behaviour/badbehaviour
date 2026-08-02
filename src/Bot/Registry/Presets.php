<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\RegistryInterface;

/**
 * Builds curated bot-registry presets.
 *
 * A preset is a named subset of the default registry, optimized for
 * specific use cases. Use via RegistryFactory::from_array([...]) with a
 * `preset` key, or call Presets::load() directly for programmatic use.
 *
 * === AVAILABLE PRESETS ===
 *
 *   - 'full'           — All ~100 shipped bots (alias for DefaultRegistry)
 *   - 'minimal'        — ~30 most common bots
 *   - 'verified-only'  — Only bots with DNS verification or IP ranges
 *   - 'no-ai'          — Everything except AI crawlers
 *   - 'no-seo'         — Everything except SEO crawlers
 *   - 'eu-only'        — European search engines + EU-relevant bots
 *   - 'human-only'     — Empty registry (combine with additions via MergedRegistry)
 *   - 'custom'         — User-defined bots only (handled by RegistryFactory)
 */
class Presets
{
	/** Names of all available presets (for validation). */
	public const AVAILABLE = [
		'full',
		'minimal',
		'verified-only',
		'no-ai',
		'no-seo',
		'eu-only',
		'human-only',
		'custom',
	];

	/**
	 * Build a registry for a preset name.
	 *
	 * @param string $name Preset identifier (see AVAILABLE)
	 * @param RegistryInterface|null $base Optional base registry. If null, uses DefaultRegistry.
	 * @return RegistryInterface
	 * @throws \InvalidArgumentException On unknown preset name
	 */
	public static function load(string $name, ?RegistryInterface $base = null): RegistryInterface
	{
		$base = $base ?? new DefaultRegistry();

		return match ($name) {
			'full'             => $base,
			'minimal'          => self::minimal($base),
			'verified-only'    => self::verified_only($base),
			'no-ai'            => self::exclude_category($base, BotCategory::AI_CRAWLER),
			'no-seo'           => self::exclude_category($base, BotCategory::SEO_CRAWLER),
			'eu-only'          => self::eu_only($base),
			'human-only'       => EmptyRegistry::instance(),
			'custom'           => EmptyRegistry::instance(),  // Real custom bots added via MergedRegistry
			default            => throw new \InvalidArgumentException(
				"Unknown registry preset: '{$name}'. " .
				"Available: " . implode(', ', self::AVAILABLE)
			),
		};
	}

	/**
	 * 'minimal' — just the bots you actually encounter regularly.
	 *
	 * Reduces index size for faster matching (~3x faster on average).
	 * Cloud infrastructure is explicitly included — DO NOT remove.
	 */
	private static function minimal(RegistryInterface $full): RegistryInterface
	{
		$keep = [
			// Search engines — global + a few regional
			'googlebot', 'bingbot', 'duckduckgo', 'yandex', 'baidu',
			'applebot', 'petal',

			// AI crawlers — the major ones
			'gptbot', 'claude', 'perplexity', 'google_ai', 'meta_ai',
			'apple_ai', 'grok', 'mistral', 'cohere',

			// Social — messengers and link previews
			'facebook', 'twitter', 'linkedin', 'discord', 'slack',
			'telegram', 'whatsapp', 'pinterest', 'reddit',

			// Monitoring
			'uptimerobot', 'pingdom', 'statuscake', 'lighthouse',

			// Cloud infrastructure — CRITICAL (do not omit)
			'cloudflare_health', 'aws_elb_health', 'google_cloud_health',
			'azure_health', 'fastly_health',

			// Archives
			'internet_archive', 'commoncrawl',

			// Feed readers
			'feedly', 'apple_news', 'google_news',

			// Shopping
			'google_shopping', 'facebook_catalog',
		];

		return FilteredRegistry::by_bot_ids($full, keep: $keep);
	}

	/**
	 * 'verified-only' — only bots with DNS verification or IP ranges.
	 *
	 * Stricter, but may miss some regional bots that only match by UA token.
	 */
	private static function verified_only(RegistryInterface $full): RegistryInterface
	{
		$verified = [];
		foreach ($full->all() as $id => $def) {
			// A bot is "verified-capable" if it has either DNS verification
			// or static IP ranges. Bots relying solely on UA-token matching
			// (e.g., FOSSies) are excluded by this preset.
			if ($def->verify_dns || !empty($def->ip_ranges)) {
				$verified[$id] = $def;
			}
		}
		return new InMemoryRegistry($verified);
	}

	/**
	 * 'eu-only' — European search engines + EU-relevant bots.
	 *
	 * Useful for sites subject to GDPR / EU regulatory requirements.
	 * Cloud infrastructure is explicitly included — DO NOT remove.
	 */
	private static function eu_only(RegistryInterface $full): RegistryInterface
	{
		$keep = [
			// European search engines
			'duckduckgo', 'qwant', 'mojeek', 'seznam', 'centrum',
			'marginalia', 'wiby', 'stract', 'fossies',
			'coccoc',  // Vietnam (GDPR-style data handling)

			// EU archives
			'internet_archive', 'web_archive_uk',
			'biblio_nationale_fr', 'dnb_de', 'kb_nl', 'commoncrawl',

			// Cloud infra — always include (critical for availability)
			'cloudflare_health', 'aws_elb_health', 'google_cloud_health',
			'azure_health', 'fastly_health',

			// AI crawlers with EU presence
			'gptbot', 'claude', 'mistral',  // Mistral is French

			// Monitoring — always relevant
			'uptimerobot', 'pingdom', 'statuscake', 'gtmetrix',
		];

		return FilteredRegistry::by_bot_ids($full, keep: $keep);
	}

	/**
	 * Exclude a single category (used by `no-ai` and `no-seo`).
	 */
	private static function exclude_category(
		RegistryInterface $full,
		BotCategory $category
	): RegistryInterface {
		return FilteredRegistry::by_category($full, exclude: [$category->value]);
	}

	/**
	 * Check whether a preset name is valid.
	 */
	public static function is_valid(string $name): bool
	{
		return in_array($name, self::AVAILABLE, true);
	}
}
