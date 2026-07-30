<?php

namespace BadBehaviour\Bot;

use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotAction;

class Registry
{
	/**
	 * @return array<string, BotDefinition>
	 */
	public static function all(): array
	{
		return array_merge(
			self::search_engines(),
			self::ai_crawlers(),
			self::social_crawlers(),
			self::seo_crawlers(),
			self::archive_crawlers(),
			self::monitoring(),
		);
	}

	public static function search_engines(): array
	{
		return [
			'googlebot' => new BotDefinition(
				id: 'googlebot',
				name: 'Googlebot',
				user_agent_patterns: ['Googlebot', 'Google-PageRenderer', 'Google-Read-Aloud', 'GoogleProducer', 'DuplexWeb-Google'],
				host_patterns: ['googlebot.com', 'google.com'],
				ip_ranges: [
					'64.233.160.0/19', '66.249.64.0/19', '66.102.0.0/20', '72.14.192.0/18',
					'74.125.0.0/16', '209.85.128.0/17', '216.239.32.0/19', '203.208.32.0/19',
					'172.217.0.0/16', '172.253.0.0/16', '108.177.0.0/17', '142.250.0.0/15',
					'2404:6800:4000::/36', '2607:f8b0:4000::/36', '2800:3f0:4000::/36',
					'2a00:1450:4000::/36', '2c0f:fb50:4000::/36'
				],
				verify_dns: true,
				dns_suffix: 'googlebot.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Googlebot',
			),
			'bingbot' => new BotDefinition(
				id: 'bingbot',
				name: 'Bingbot',
				user_agent_patterns: ['bingbot', 'MSNBot', 'MS Search', 'BingPreview'],
				host_patterns: ['search.msn.com', 'msn.com', 'bing.com'],
				ip_ranges: [
					'13.107.21.0/24', '13.107.24.0/21', '40.76.0.0/14', '40.121.0.0/16',
					'157.54.0.0/15', '157.56.0.0/14', '157.60.0.0/16', '207.46.0.0/16',
					'65.52.0.0/14', '207.68.128.0/18', '207.68.192.0/20', '64.4.0.0/18',
					'2620:1ec:4::/48', '2620:1ec:8::/48', '2620:1ec:a::/48', '2620:1ec:c::/48',
				],
				verify_dns: true,
				dns_suffix: 'search.msn.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Bingbot',
			),
			'yandex' => new BotDefinition(
				id: 'yandex',
				name: 'YandexBot',
				user_agent_patterns: ['YandexBot', 'YandexImages', 'YandexVideo', 'YandexMedia', 'YandexBlogs', 'YandexMetrika'],
				host_patterns: ['yandex.ru', 'yandex.net', 'yandex.com'],
				ip_ranges: [
					'5.255.255.0/24', '5.255.253.0/24', '37.9.112.0/20', '37.140.128.0/18',
					'77.88.0.0/17', '84.201.128.0/18', '87.250.255.0/24', '93.158.128.0/18',
					'95.108.128.0/17', '100.43.64.0/18', '130.193.48.0/20', '141.8.128.0/17',
					'178.154.128.0/17', '213.180.192.0/19', '2a02:6b8::/32',
				],
				verify_dns: true,
				dns_suffix: 'yandex.ru',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'YandexBot',
			),
			'baidu' => new BotDefinition(
				id: 'baidu',
				name: 'Baiduspider',
				user_agent_patterns: ['Baiduspider', 'BaiduSpider'],
				host_patterns: ['baidu.com', 'baidu.jp'],
				ip_ranges: [
					'119.63.192.0/21', '123.125.71.0/24', '180.76.0.0/16', '220.181.0.0/16',
					'116.179.32.0/20', '116.179.0.0/17', '111.206.0.0/16', '123.125.68.0/22',
				],
				verify_dns: true,
				dns_suffix: 'baidu.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Baiduspider',
			),
			'duckduckgo' => new BotDefinition(
				id: 'duckduckgo',
				name: 'DuckDuckBot',
				user_agent_patterns: ['DuckDuckBot', 'DuckDuckGo-Favicons-Bot'],
				host_patterns: ['duckduckgo.com'],
				ip_ranges: ['52.209.0.0/16', '52.208.0.0/16', '34.192.0.0/12', '52.0.0.0/11'],
				verify_dns: false,
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'DuckDuckBot',
			),
			'brave' => new BotDefinition(
				id: 'brave',
				name: 'Brave Search',
				user_agent_patterns: ['BraveSpider', 'BraveBot'],
				host_patterns: ['search.brave.com'],
				ip_ranges: ['185.199.108.0/22'],
				verify_dns: false,
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'BraveSpider',
			),
			'kagi' => new BotDefinition(
				id: 'kagi',
				name: 'KagiBot',
				user_agent_patterns: ['KagiBot'],
				host_patterns: ['kagi.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'KagiBot',
			),
			'applebot' => new BotDefinition(
				id: 'applebot',
				name: 'Applebot (Search)',
				user_agent_patterns: ['Applebot'],
				host_patterns: ['applebot.apple.com', 'apple.com'],
				ip_ranges: [
					'17.0.0.0/8',           // Apple's /8 allocation
					'2a03:b000::/28',       // Apple IPv6
				],
				verify_dns: true,
				dns_suffix: 'applebot.apple.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Applebot',
			),
			'qwant' => new BotDefinition(
				id: 'qwant',
				name: 'QwantBot',
				user_agent_patterns: ['Qwantbot', 'QwantBot', 'Qwantbot/1.0', 'Mozilla/5.0 (compatible; Qwantbot'],
				host_patterns: ['qwant.com'],
				ip_ranges: [
					'91.242.162.0/24',      // Primary Qwant range (Strasbourg, France)
					'194.187.168.0/22',     // Broader Qwant allocation
				],
				verify_dns: true,
				dns_suffix: 'qwant.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'QwantBot',
			),

			// === ASIAN SEARCH ENGINES ===

			'naver' => new BotDefinition(
				id: 'naver',
				name: 'Naver Bot (Korea #1)',
				user_agent_patterns: ['Yeti', 'NaverBot', 'NaverBot/1.0'],
				host_patterns: ['naver.com', 'navercorp.com'],
				ip_ranges: [
					'125.209.192.0/18', '125.209.0.0/17', '203.133.160.0/19',
					'210.89.160.0/20', '211.232.0.0/16', '119.192.0.0/13',
				],
				verify_dns: true,
				dns_suffix: 'naver.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Yeti',
			),
			'daum' => new BotDefinition(
				id: 'daum',
				name: 'Daum Bot (Korea #2)',
				user_agent_patterns: ['DaumBot', 'Daumoa'],
				host_patterns: ['daum.net', 'kakao.com'],
				ip_ranges: [
					'211.232.0.0/16', '121.128.0.0/14', '112.216.0.0/13',
				],
				verify_dns: true,
				dns_suffix: 'daum.net',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'DaumBot',
			),
			'sogou' => new BotDefinition(
				id: 'sogou',
				name: 'Sogou Spider (China #2)',
				user_agent_patterns: ['Sogou Spider', 'Sogou web spider', 'SogouNewsSpider', 'SogouPicSpider'],
				host_patterns: ['sogou.com'],
				ip_ranges: [
					// Verified Sogou ranges (removed Baidu contamination)
					'106.120.0.0/14',      // Legitimate Sogou block (106.120-123.x.x)
					'123.126.0.0/15',      // Most frequently observed (123.126-127.x.x)
					'220.181.0.0/16',      // Major range — DNS verification required (Baidu overlap)
					'218.30.96.0/19',      // Frequently observed
					'61.135.0.0/16',       // Major Chinanet block
					'106.37.0.0/16',       // Common crawling range
					'106.38.0.0/15',       // Adjacent block
					'123.112.0.0/12',      // Large block including 123.126.x.x
					'220.180.0.0/16',      // Heavy scraping
					'49.7.0.0/16',         // Recent logs
					'223.109.252.0/22',    // Verified active Feb 2026
				],
				verify_dns: true,
				dns_suffix: 'sogou.com',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Sogou Spider',
			),
			'qihoo360' => new BotDefinition(
				id: 'qihoo360',
				name: '360 Spider / Haosou (China)',
				user_agent_patterns: ['360Spider', 'HaosouSpider', '360Spider-Image', '360Spider-Video', '360Spider-News'],
				host_patterns: ['360.cn', 'so.com', 'haosou.com', 'qihoo.net'],
				ip_ranges: [
					'180.153.0.0/16', '180.163.0.0/16', '42.236.0.0/16',
					'106.120.0.0/14', '183.60.0.0/16',
				],
				verify_dns: false,
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: '360Spider',
			),
			'bytedance' => new BotDefinition(
				id: 'bytedance',
				name: 'ByteDance Bot (TikTok parent)',
				user_agent_patterns: ['Bytespider', 'ByteSpider', 'ToutiaoSpider'],
				host_patterns: ['bytedance.com', 'byteoversea.com', 'toutiao.com'],
				ip_ranges: [
					'110.249.0.0/16', '111.225.0.0/16', '222.186.0.0/16',
					'101.227.0.0/16', '183.62.0.0/15',
				],
				verify_dns: false,
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Bytespider',
			),
			'shenma' => new BotDefinition(
				id: 'shenma',
				name: 'Shenma / Yisou Spider (China Mobile)',
				user_agent_patterns: ['YisouSpider', 'ShenmaSpider', 'SM-G9500', 'UCBrowser.*Shenma'],
				host_patterns: ['shenma.com', 'sm.cn', 'uc.cn'],
				ip_ranges: [
					'106.120.0.0/14', '183.60.0.0/16', '117.136.0.0/16',
				],
				verify_dns: false,
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'YisouSpider',
			),
			'seznam' => new BotDefinition(
				id: 'seznam',
				name: 'Seznam Bot (Czech Republic #1)',
				user_agent_patterns: ['SeznamBot', 'SeznamBot/3.0', 'SeznamBot/4.0'],
				host_patterns: ['seznam.cz'],
				ip_ranges: [
					'77.75.76.0/22', '77.75.72.0/21', '2a02:598:3::/48',
				],
				verify_dns: true,
				dns_suffix: 'seznam.cz',
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'SeznamBot',
			),
		];
	}

	public static function ai_crawlers(): array
	{
		return [
			'gptbot' => new BotDefinition(
				id: 'gptbot',
				name: 'OpenAI GPTBot',
				user_agent_patterns: ['GPTBot', 'OAI-SearchBot', 'ChatGPT-User'],
				host_patterns: ['openai.com'],
				ip_ranges: [
					'20.15.240.0/20', '40.83.0.0/16', '40.112.0.0/16', '40.113.0.0/16',
					'40.114.0.0/16', '40.115.0.0/16', '40.116.0.0/16', '40.117.0.0/16',
					'40.118.0.0/16', '40.119.0.0/16', '104.214.0.0/16', '104.215.0.0/16'
				],
				verify_dns: true,
				dns_suffix: 'openai.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'GPTBot',
				default_action: BotAction::CHALLENGE,
			),
			'claude' => new BotDefinition(
				id: 'claude',
				name: 'Anthropic ClaudeBot',
				user_agent_patterns: ['ClaudeBot', 'Claude-Web', 'anthropic-ai', 'Claude-Crawler'],
				host_patterns: ['anthropic.com'],
				ip_ranges: [
					'54.144.0.0/16', '54.145.0.0/16', '54.146.0.0/16', '54.147.0.0/16',
					'54.148.0.0/16', '54.149.0.0/16', '54.150.0.0/16', '54.151.0.0/16'
				],
				verify_dns: true,
				dns_suffix: 'anthropic.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'ClaudeBot',
				default_action: BotAction::CHALLENGE,
			),
			'perplexity' => new BotDefinition(
				id: 'perplexity',
				name: 'PerplexityBot',
				user_agent_patterns: ['PerplexityBot', 'Perplexity-User', 'PerplexityBot/1.0'],
				host_patterns: ['perplexity.ai'],
				ip_ranges: ['54.176.0.0/16', '54.177.0.0/16', '54.178.0.0/16'],
				verify_dns: false,
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'PerplexityBot',
				default_action: BotAction::CHALLENGE,
			),
			'google_ai' => new BotDefinition(
				id: 'google_ai',
				name: 'Google AI (Vertex/Bard/Gemini)',
				user_agent_patterns: ['Google-Extended', 'VertexAI', 'Bard', 'Gemini', 'GoogleOther'],
				host_patterns: ['google.com', 'googlebot.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffix: 'googlebot.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'Google-Extended',
				default_action: BotAction::CHALLENGE,
			),
			'meta_ai' => new BotDefinition(
				id: 'meta_ai',
				name: 'Meta AI',
				user_agent_patterns: ['Meta-ExternalAgent', 'Meta-ExternalFetcher', 'MetaAI', 'FacebookBot', 'meta-externalagent', 'meta-webindexer'],
				host_patterns: ['facebook.com', 'fbcdn.net'],
				ip_ranges: [
					// IPv4 (existing known ranges)
					'31.13.64.0/18', '45.64.40.0/22', '66.220.144.0/20', '69.63.176.0/20',
					'69.171.224.0/19', '74.119.76.0/22', '103.4.96.0/22', '129.134.0.0/16',
					'157.240.0.0/16', '173.252.64.0/18', '179.60.192.0/22', '185.60.216.0/22',
					// IPv6 (NEW - Meta's allocations)
					'2a03:2880::/32',      // Primary Facebook IPv6 block
					'2a03:2880:f800::/48', // Observed crawler subrange
					'2a03:2880:f900::/48',
					'2a03:2880:fa00::/48',
					'2a03:2880:fb00::/48',
					'2a03:2880:fc00::/48',
					'2a03:2880:fd00::/48',
					'2a03:2880:fe00::/48',
					'2a03:2880:ff00::/48',
				],
				verify_dns: true,
				dns_suffix: 'facebook.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'Meta-ExternalAgent',
				default_action: BotAction::CHALLENGE,
			),
			'apple_ai' => new BotDefinition(
				id: 'apple_ai',
				name: 'Applebot-Extended',
				user_agent_patterns: ['Applebot-Extended'],
				host_patterns: ['apple.com', 'applebot.apple.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffix: 'applebot.apple.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'Applebot-Extended',
				default_action: BotAction::CHALLENGE,
			),
			'grok' => new BotDefinition(
				id: 'grok',
				name: 'xAI Grok',
				user_agent_patterns: ['GrokBot', 'Grok-User', 'xAI', 'Grok'],
				host_patterns: ['x.ai', 'grok.x.ai'],
				ip_ranges: [
					'38.132.0.0/16',
					'192.229.0.0/16',
				],
				verify_dns: true,
				dns_suffix: 'x.ai',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'GrokBot',
				default_action: BotAction::CHALLENGE,
			),
			'mistral' => new BotDefinition(
				id: 'mistral',
				name: 'Mistral AI',
				user_agent_patterns: ['MistralBot', 'Mistral-User', 'MistralAI', 'MistralBot/1.0'],
				host_patterns: ['mistral.ai'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffix: 'mistral.ai',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'MistralBot',
				default_action: BotAction::CHALLENGE,
			),
			'cohere' => new BotDefinition(
				id: 'cohere',
				name: 'Cohere Bot',
				user_agent_patterns: ['CohereBot', 'Cohere-User', 'Cohere'],
				host_patterns: ['cohere.com', 'cohere.ai'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffix: 'cohere.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'CohereBot',
				default_action: BotAction::CHALLENGE,
			),
			'ai21' => new BotDefinition(
				id: 'ai21',
				name: 'AI21 Labs',
				user_agent_patterns: ['AI21Bot', 'AI21-User', 'AI21'],
				host_patterns: ['ai21.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffix: 'ai21.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'AI21Bot',
				default_action: BotAction::CHALLENGE,
			),
			'youbot' => new BotDefinition(
				id: 'youbot',
				name: 'You.com Bot',
				user_agent_patterns: ['YouBot', 'You.com', 'YouBot/1.0'],
				host_patterns: ['you.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffix: 'you.com',
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'YouBot',
				default_action: BotAction::CHALLENGE,
			),
			'phind' => new BotDefinition(
				id: 'phind',
				name: 'Phind Bot',
				user_agent_patterns: ['PhindBot', 'Phind-User', 'Phind'],
				host_patterns: ['phind.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'PhindBot',
				default_action: BotAction::CHALLENGE,
			),
		];
	}

	public static function social_crawlers(): array
	{
		return [
			'facebook' => new BotDefinition(
				id: 'facebook',
				name: 'Facebook Crawler',
				user_agent_patterns: ['facebookexternalhit', 'FacebookBot', 'facebookcatalog', 'Facebot'],
				host_patterns: ['facebook.com', 'fbcdn.net'],
				ip_ranges: [
					'31.13.64.0/18', '45.64.40.0/22', '66.220.144.0/20', '69.63.176.0/20',
					'69.171.224.0/19', '74.119.76.0/22', '103.4.96.0/22', '129.134.0.0/16',
					'157.240.0.0/16', '173.252.64.0/18', '179.60.192.0/22', '185.60.216.0/22',
				],
				verify_dns: true,
				dns_suffix: 'facebook.com',
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'twitter' => new BotDefinition(
				id: 'twitter',
				name: 'Twitter/X Bot',
				user_agent_patterns: ['Twitterbot', 'TwitterBot/1.0'],
				host_patterns: ['twitter.com', 't.co', 'x.com'],
				ip_ranges: ['104.244.42.0/24', '104.244.43.0/24', '199.16.156.0/22', '199.59.148.0/22'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'linkedin' => new BotDefinition(
				id: 'linkedin',
				name: 'LinkedIn Bot',
				user_agent_patterns: ['LinkedInBot'],
				host_patterns: ['linkedin.com'],
				ip_ranges: ['108.174.0.0/15'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'discord' => new BotDefinition(
				id: 'discord',
				name: 'Discord Bot',
				user_agent_patterns: ['Discordbot'],
				host_patterns: ['discord.com', 'discordapp.com'],
				ip_ranges: ['162.159.128.0/17'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'slack' => new BotDefinition(
				id: 'slack',
				name: 'Slack Bot',
				user_agent_patterns: ['Slackbot', 'Slackbot-LinkExpanding'],
				host_patterns: ['slack.com'],
				ip_ranges: ['52.11.0.0/16', '52.12.0.0/16', '52.24.0.0/15'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'telegram' => new BotDefinition(
				id: 'telegram',
				name: 'Telegram Bot',
				user_agent_patterns: ['TelegramBot'],
				host_patterns: ['telegram.org'],
				ip_ranges: ['149.154.160.0/20', '91.108.4.0/22'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'whatsapp' => new BotDefinition(
				id: 'whatsapp',
				name: 'WhatsApp Bot',
				user_agent_patterns: ['WhatsApp'],
				host_patterns: ['whatsapp.net'],
				ip_ranges: ['31.13.64.0/18', '157.240.0.0/16'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'pinterest' => new BotDefinition(
				id: 'pinterest',
				name: 'Pinterest Bot',
				user_agent_patterns: ['Pinterestbot'],
				host_patterns: ['pinterest.com'],
				ip_ranges: ['54.236.0.0/16'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'reddit' => new BotDefinition(
				id: 'reddit',
				name: 'Reddit Bot',
				user_agent_patterns: ['RedditBot'],
				host_patterns: ['reddit.com'],
				ip_ranges: ['151.101.0.0/16'],
				verify_dns: false,
				category: BotCategory::SOCIAL_CRAWLER,
			),
		];
	}

	public static function seo_crawlers(): array
	{
		return [
			'semrush' => new BotDefinition(
				id: 'semrush',
				name: 'SemrushBot',
				user_agent_patterns: ['SemrushBot', 'SemrushBot/7~bl'],
				host_patterns: ['semrush.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'SemrushBot',
				default_action: BotAction::CHALLENGE,
			),
			'ahrefs' => new BotDefinition(
				id: 'ahrefs',
				name: 'AhrefsBot',
				user_agent_patterns: ['AhrefsBot', 'AhrefsBot/7.0'],
				host_patterns: ['ahrefs.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'AhrefsBot',
				default_action: BotAction::CHALLENGE,
			),
			'mj12' => new BotDefinition(
				id: 'mj12',
				name: 'MJ12bot',
				user_agent_patterns: ['MJ12bot', 'MJ12bot/v1.4.8'],
				host_patterns: ['mj12bot.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'MJ12bot',
				default_action: BotAction::CHALLENGE,
			),
			'dotbot' => new BotDefinition(
				id: 'dotbot',
				name: 'DotBot (Moz)',
				user_agent_patterns: ['DotBot', 'DotBot/1.1'],
				host_patterns: ['dotbot.net', 'moz.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'DotBot',
				default_action: BotAction::CHALLENGE,
			),
			'petalbot' => new BotDefinition(
				id: 'petalbot',
				name: 'PetalBot (Huawei)',
				user_agent_patterns: ['PetalBot', 'PetalBot/1.0'],
				host_patterns: ['petalbot.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'PetalBot',
				default_action: BotAction::CHALLENGE,
			),
		];
	}

	public static function archive_crawlers(): array
	{
		return [
			'commoncrawl' => new BotDefinition(
				id: 'commoncrawl',
				name: 'Common Crawl',
				user_agent_patterns: ['CCBot'],
				host_patterns: ['commoncrawl.org'],
				ip_ranges: ['38.107.191.0/24'],
				verify_dns: false,
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'CCBot',
			),
			'internet_archive' => new BotDefinition(
				id: 'internet_archive',
				name: 'Internet Archive',
				user_agent_patterns: ['ia_archiver', 'archive.org_bot', 'Archive-It'],
				host_patterns: ['archive.org'],
				ip_ranges: ['207.241.224.0/19'],
				verify_dns: false,
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'ia_archiver',
			),
		];
	}

	public static function monitoring(): array
	{
		return [
			'uptimerobot' => new BotDefinition(
				id: 'uptimerobot',
				name: 'UptimeRobot',
				user_agent_patterns: ['UptimeRobot'],
				host_patterns: ['uptimerobot.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
			),
			'pingdom' => new BotDefinition(
				id: 'pingdom',
				name: 'Pingdom',
				user_agent_patterns: ['Pingdom.com_bot'],
				host_patterns: ['pingdom.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
			),
			'statuscake' => new BotDefinition(
				id: 'statuscake',
				name: 'StatusCake',
				user_agent_patterns: ['StatusCake'],
				host_patterns: ['statuscake.com'],
				ip_ranges: [],
				verify_dns: false,
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
			),
		];
	}
}
