<?php

namespace BadBehaviour\Bot;

enum BotCategory: string
{
	case SEARCH_ENGINE         = 'search_engine';
	case AI_CRAWLER            = 'ai_crawler';
	case SOCIAL_CRAWLER        = 'social_crawler';
	case SEO_CRAWLER           = 'seo_crawler';
	case ARCHIVE_CRAWLER       = 'archive_crawler';
	case MONITORING            = 'monitoring';
	case MALICIOUS             = 'malicious';
	case UNKNOWN               = 'unknown';
	case FEED_READER           = 'feed_reader';
	case SHOPPING_CRAWLER      = 'shopping_crawler';
	case CLOUD_INFRASTRUCTURE  = 'cloud_infrastructure';
	case SECURITY_SCANNER      = 'security_scanner';

	/**
	 * Human-readable label for dashboards / logging.
	 */
	public function label(): string
	{
		return match($this) {
			self::SEARCH_ENGINE         => 'Search Engine',
			self::AI_CRAWLER            => 'AI Crawler',
			self::SOCIAL_CRAWLER        => 'Social Crawler',
			self::SEO_CRAWLER           => 'SEO Crawler',
			self::ARCHIVE_CRAWLER       => 'Archive Crawler',
			self::MONITORING            => 'Monitoring',
			self::MALICIOUS             => 'Malicious',
			self::UNKNOWN               => 'Unknown',
			self::FEED_READER           => 'Feed Reader',
			self::SHOPPING_CRAWLER      => 'Shopping Crawler',
			self::CLOUD_INFRASTRUCTURE  => 'Cloud Infrastructure',
			self::SECURITY_SCANNER      => 'Security Scanner',
		};
	}

	/**
	 * Default action hint for this category.
	 * Used by BotDetector when the BotDefinition doesn't specify a default.
	 */
	public function default_action_hint(): string
	{
		return match($this) {
			// Revenue / uptime critical — always allow
			self::SHOPPING_CRAWLER,
			self::CLOUD_INFRASTRUCTURE,
			self::FEED_READER,
			self::MONITORING,
			self::ARCHIVE_CRAWLER => 'allow',

			// Grey-area: log for analysis, default to challenge
			self::AI_CRAWLER,
			self::SEO_CRAWLER,
			self::SOCIAL_CRAWLER  => 'challenge',

			// Strict
			self::SECURITY_SCANNER => 'log_only',
			self::MALICIOUS        => 'block',
			default                => 'allow',
		};
	}
}