<?php

declare(strict_types=1);

namespace BadBehaviour\Bot;

/**
 * Shared constants for bot registry implementations.
 *
 * These tokens are excluded from token-based UA matching because they
 * appear in nearly every browser UA and would create excessive false
 * positives when used to match bots.
 *
 * Single source of truth — referenced by all Registry implementations
 * (DefaultRegistry, InMemoryRegistry, MergedRegistry, FilteredRegistry,
 * CustomRegistry). If you need to add another generic browser/engine
 * token, add it here once.
 */
final class RegistryTokens
{
	/**
	 * Tokens too generic to identify a specific bot.
	 * Excluded from token matching to prevent false positives
	 * when common UA components overlap with bot names.
	 *
	 * @var string[]
	 */
	public const NOISE = [
		'mozilla', 'compatible', 'agent', 'http', 'client', 'browser',
		'like', 'khtml', 'gecko', 'applewebkit', 'safari', 'version',
		'mobile', 'tablet', 'desktop', 'linux', 'windows', 'macintosh',
		'macos', 'darwin', 'android', 'chrome', 'firefox',
		'edge', 'opera', 'brave', 'vivaldi', 'samsung', 'ucbrowser',
		'internet', 'explorer', 'trident', 'presto', 'blink', 'webkit',
		'search', 'preview', 'fetcher', 'render', 'producer',
		'playstation', 'google', 'facebook', 'twitter', 'linkedin',
		'discord', 'slack', 'telegram', 'whatsapp', 'pinterest',
		'reddit', 'youtube',
	];

	/**
	 * Minimum token length to be considered for matching.
	 * Shorter tokens are excluded to avoid noise (e.g., "a", "b", "v").
	 */
	public const MIN_TOKEN_LENGTH = 5;

	private function __construct()
	{
		// Static class — no instances.
	}
}
