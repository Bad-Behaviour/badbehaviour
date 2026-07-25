<?php

namespace BadBehaviour\Bot;

enum BotCategory: string
{
	case SEARCH_ENGINE   = 'search_engine';
	case AI_CRAWLER      = 'ai_crawler';
	case SOCIAL_CRAWLER  = 'social_crawler';
	case SEO_CRAWLER     = 'seo_crawler';
	case ARCHIVE_CRAWLER = 'archive_crawler';
	case MONITORING      = 'monitoring';
	case MALICIOUS       = 'malicious';
	case UNKNOWN         = 'unknown';
}
