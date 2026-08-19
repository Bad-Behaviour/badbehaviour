<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Bot\RegistryTokens;

/**
 * The default, shipped registry of ~100 verified bots.
 *
 * Backed by hardcoded data covering:
 *   - Global + regional search engines (Google, Bing, Yandex, Baidu, Naver, etc.)
 *   - AI crawlers (GPTBot, Claude, Gemini, Grok, Mistral, etc.)
 *   - Social/messenger link previewers (Facebook, Twitter, Kakao, LINE, WeChat)
 *   - SEO crawlers (Semrush, Ahrefs, Moz, etc.)
 *   - Web archives (Internet Archive, BnF, UKWA, KB-NL)
 *   - Monitoring (UptimeRobot, Pingdom, StatusCake, Lighthouse)
 *   - Feed readers (Feedly, Apple News, Google News)
 *   - Shopping crawlers (Google Shopping, Facebook Catalog)
 *   - Cloud infrastructure health probes (Cloudflare, AWS, GCP, Azure, Fastly)
 *   - Security scanners (Qualys, Detectify, Shodan, Censys)
 *   - Residential proxy networks (Bright Data)
 *
 * For most use cases, use RegistryFactory::default() instead of instantiating
 * this class directly.
 *
 * @see RegistryFactory::default()
 */
class DefaultRegistry implements RegistryInterface
{
	/** Lazily built UA index: lowercase fragment => [bot_id, ...] */
	private ?array $ua_index = null;

	/** Lazily built token index: token => [bot_id, ...] */
	private ?array $ua_token_index = null;

	// ========================================================================
	// RegistryInterface implementation
	// ========================================================================

	public function all(): array
	{
		return array_merge(
			$this->search_engines(),
			$this->ai_crawlers(),
			$this->social_crawlers(),
			$this->seo_crawlers(),
			$this->archive_crawlers(),
			$this->feed_readers(),
			$this->shopping_crawlers(),
			$this->cloud_infrastructure(),
			$this->monitoring(),
			$this->security_scanners(),
			$this->residential_crawlers(),
			$this->utility_bots(),
		);
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
		foreach ($this->all() as $id => $def) {
			if ($id === $bot_id) {
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

	// ========================================================================
	// Per-category definitions
	//
	// Each method returns array<string, BotDefinition>. Categories partition
	// the registry — a bot appears in exactly one category.
	// ========================================================================

	public function search_engines(): array
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
					'2a00:1450:4000::/36', '2c0f:fb50:4000::/36',
				],
				verify_dns: true,
				dns_suffixes: ['googlebot.com', 'google.com'],
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
				dns_suffixes: ['search.msn.com', 'bing.com'],
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
				dns_suffixes: ['yandex.ru', 'yandex.net', 'yandex.com'],
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
				dns_suffixes: ['baidu.com', 'baidu.jp'],
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
				dns_suffixes: [],
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
				dns_suffixes: [],
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
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'KagiBot',
			),
			'applebot' => new BotDefinition(
				id: 'applebot',
				name: 'Applebot (Search)',
				user_agent_patterns: ['Applebot'],
				host_patterns: ['applebot.apple.com', 'apple.com'],
				ip_ranges: ['17.0.0.0/8', '2a03:b000::/28'],
				verify_dns: true,
				dns_suffixes: ['applebot.apple.com', 'apple.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Applebot',
			),
			'qwant' => new BotDefinition(
				id: 'qwant',
				name: 'QwantBot',
				user_agent_patterns: ['Qwantbot', 'QwantBot', 'Qwantbot/1.0'],
				host_patterns: ['qwant.com'],
				ip_ranges: ['91.242.162.0/24', '194.187.168.0/22'],
				verify_dns: true,
				dns_suffixes: ['qwant.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'QwantBot',
			),
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
				dns_suffixes: ['naver.com', 'navercorp.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Yeti',
			),
			'daum' => new BotDefinition(
				id: 'daum',
				name: 'Daum Bot (Korea #2)',
				user_agent_patterns: ['DaumBot', 'Daumoa'],
				host_patterns: ['daum.net', 'kakao.com'],
				ip_ranges: ['211.232.0.0/16', '121.128.0.0/14', '112.216.0.0/13'],
				verify_dns: true,
				dns_suffixes: ['daum.net', 'kakao.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'DaumBot',
			),
			'sogou' => new BotDefinition(
				id: 'sogou',
				name: 'Sogou Spider (China #2)',
				user_agent_patterns: ['Sogou Spider', 'Sogou web spider', 'SogouNewsSpider', 'SogouPicSpider'],
				host_patterns: ['sogou.com'],
				ip_ranges: [
					'106.120.0.0/14', '123.126.0.0/15', '220.181.0.0/16', '218.30.96.0/19',
					'61.135.0.0/16', '106.37.0.0/16', '106.38.0.0/15', '123.112.0.0/12',
					'220.180.0.0/16', '49.7.0.0/16', '223.109.252.0/22',
				],
				verify_dns: true,
				dns_suffixes: ['sogou.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Sogou Spider',
			),
			'qihoo360' => new BotDefinition(
				id: 'qihoo360',
				name: '360 Spider / Haosou (China)',
				user_agent_patterns: ['360Spider', 'HaosouSpider', '360Spider-Image', '360Spider-Video', '360Spider-News'],
				host_patterns: ['360.cn', 'so.com', 'haosou.com', 'qihoo.net'],
				ip_ranges: ['180.153.0.0/16', '180.163.0.0/16', '42.236.0.0/16', '106.120.0.0/14', '183.60.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: '360Spider',
			),
			'bytedance' => new BotDefinition(
				id: 'bytedance',
				name: 'ByteDance Bot (TikTok parent)',
				user_agent_patterns: ['Bytespider', 'ByteSpider', 'ToutiaoSpider'],
				host_patterns: ['bytedance.com', 'byteoversea.com', 'toutiao.com'],
				ip_ranges: ['110.249.0.0/16', '111.225.0.0/16', '222.186.0.0/16', '101.227.0.0/16', '183.62.0.0/15'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Bytespider',
			),
			'shenma' => new BotDefinition(
				id: 'shenma',
				name: 'Shenma / Yisou Spider (China Mobile)',
				user_agent_patterns: ['YisouSpider', 'ShenmaSpider', 'SM-G9500', 'UCBrowser.*Shenma'],
				host_patterns: ['shenma.com', 'sm.cn', 'uc.cn'],
				ip_ranges: ['106.120.0.0/14', '183.60.0.0/16', '117.136.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'YisouSpider',
			),
			'seznam' => new BotDefinition(
				id: 'seznam',
				name: 'Seznam Bot (Czech Republic #1)',
				user_agent_patterns: ['SeznamBot', 'SeznamBot/3.0', 'SeznamBot/4.0'],
				host_patterns: ['seznam.cz'],
				ip_ranges: ['77.75.76.0/22', '77.75.72.0/21', '2a02:598:3::/48'],
				verify_dns: true,
				dns_suffixes: ['seznam.cz'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'SeznamBot',
			),
			'mojeek' => new BotDefinition(
				id: 'mojeek',
				name: 'MojeekBot',
				user_agent_patterns: ['MojeekBot'],
				host_patterns: ['mojeek.com'],
				ip_ranges: ['5.102.173.0/24', '5.102.174.0/24', '5.102.175.0/24', '85.91.168.0/21'],
				verify_dns: true,
				dns_suffixes: ['mojeek.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'MojeekBot',
			),
			'wiby' => new BotDefinition(
				id: 'wiby',
				name: 'Wibybot',
				user_agent_patterns: ['Wibybot'],
				host_patterns: ['wiby.me'],
				ip_ranges: ['2602:ff16:3::/48'],
				verify_dns: true,
				dns_suffixes: ['wiby.me'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Wibybot',
			),
			'coccoc' => new BotDefinition(
				id: 'coccoc',
				name: 'Cốc Cốc Bot (Vietnam #1)',
				user_agent_patterns: ['coccocbot', 'CocCocBot', 'coccocbot-web', 'coccocbot-image'],
				host_patterns: ['coccoc.com'],
				ip_ranges: [
					'113.160.0.0/13', '113.172.0.0/14', '117.0.0.0/12',
					'123.16.0.0/12', '171.224.0.0/11',
				],
				verify_dns: true,
				dns_suffixes: ['coccoc.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'CocCocBot',
				description: "Vietnam's #1 search engine, used by ~30M+ users monthly.",
			),
			'mailru' => new BotDefinition(
				id: 'mailru',
				name: 'Mail.ru Bot / Rambler (Russia)',
				user_agent_patterns: ['Mail.RU_Bot', 'Rambler', 'MailRuBot', 'rambler.ru'],
				host_patterns: ['mail.ru', 'rambler.ru', 'go.mail.ru'],
				ip_ranges: [
					'5.61.16.0/20', '5.61.232.0/21', '94.100.176.0/20',
					'128.140.168.0/21', '178.237.16.0/20', '185.30.176.0/22',
					'188.93.56.0/21', '195.211.20.0/22', '195.218.168.0/24',
					'217.69.128.0/20', '2a00:ab00::/32',
				],
				verify_dns: true,
				dns_suffixes: ['mail.ru', 'rambler.ru', 'go.mail.ru'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'Mail.RU_Bot',
				description: 'Mail.ru / Rambler (Russia). Post-Yandex, Rambler often uses Yandex engine.',
			),
			'petal' => new BotDefinition(
				id: 'petal',
				name: 'PetalBot / AspiegelBot (Huawei Search)',
				user_agent_patterns: ['PetalBot', 'AspiegelBot', 'PetalBot-Huawei', 'HuaweiSymantec'],
				host_patterns: ['petalbot.com', 'aspiegel.com', 'huawei.com'],
				ip_ranges: [
					'119.36.0.0/16', '121.36.0.0/14', '121.40.0.0/14',
					'121.44.0.0/13', '122.9.0.0/16', '119.36.80.0/20',
				],
				verify_dns: true,
				dns_suffixes: ['petalbot.com', 'aspiegel.com', 'huawei.com'],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'PetalBot',
				description: "Huawei's Petal Search engine (global). Promoted from SEO_CRAWLER.",
			),
			'zum' => new BotDefinition(
				id: 'zum',
				name: 'Zum Bot (Korea)',
				user_agent_patterns: ['ZumBot', 'ZUMBot', 'ZumSearch'],
				host_patterns: ['zum.com', 'zumnet.com'],
				ip_ranges: ['121.128.0.0/14', '211.174.0.0/15', '210.89.160.0/20'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'ZumBot',
				description: 'Korean portal/portal-search (Zum).',
			),
			'stract' => new BotDefinition(
				id: 'stract',
				name: 'Stract (Open Source Search)',
				user_agent_patterns: ['StractBot', 'Stract', 'stract.com'],
				host_patterns: ['stract.com', 'stract.net'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'StractBot',
				description: 'Open-source indie search engine. Token match only.',
			),
			'marginalia' => new BotDefinition(
				id: 'marginalia',
				name: 'Marginalia Search (Indie)',
				user_agent_patterns: ['search.marginalia.nu', 'MarginaliaBot'],
				host_patterns: ['marginalia.nu', 'search.marginalia.nu'],
				ip_ranges: [
					'81.170.128.52/32',
					'193.183.0.162/31',
					'193.183.0.164/30',
					'193.183.0.168/30',
					'193.183.0.172/31',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'search.marginalia.nu',
				description: 'Indie/non-commercial search engine focused on non-commercial content.',
			),
			'centrum' => new BotDefinition(
				id: 'centrum',
				name: 'Centrum / Sklik Bot (Czech)',
				user_agent_patterns: ['CentrumBot', 'SklikBot'],
				host_patterns: ['centrum.cz', 'sklik.cz'],
				ip_ranges: ['77.75.76.0/22'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEARCH_ENGINE,
				robots_txt_token: 'CentrumBot',
				description: 'Czech search/Sklik ad platform (often co-located with Seznam infra).',
			),
		];
	}

	public function ai_crawlers(): array
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
					'40.118.0.0/16', '40.119.0.0/16', '104.214.0.0/16', '104.215.0.0/16',
				],
				verify_dns: true,
				dns_suffixes: ['openai.com'],
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
					'54.148.0.0/16', '54.149.0.0/16', '54.150.0.0/16', '54.151.0.0/16',
				],
				verify_dns: true,
				dns_suffixes: ['anthropic.com'],
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
				dns_suffixes: [],
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
				dns_suffixes: ['googlebot.com', 'google.com', 'googleusercontent.com'],
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
					'31.13.64.0/18', '45.64.40.0/22', '66.220.144.0/20', '69.63.176.0/20',
					'69.171.224.0/19', '74.119.76.0/22', '103.4.96.0/22', '129.134.0.0/16',
					'157.240.0.0/16', '173.252.64.0/18', '179.60.192.0/22', '185.60.216.0/22',
				],
				verify_dns: true,
				dns_suffixes: [
					'facebook.com',
					'fb.com',
					'fbcdn.net',
					'amazonaws.com',
				],
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
				dns_suffixes: ['applebot.apple.com', 'apple.com'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'Applebot-Extended',
				default_action: BotAction::CHALLENGE,
			),
			'grok' => new BotDefinition(
				id: 'grok',
				name: 'xAI Grok',
				user_agent_patterns: ['GrokBot', 'Grok-User'],
				host_patterns: ['x.ai', 'grok.x.ai'],
				ip_ranges: ['38.132.0.0/16', '192.229.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['x.ai', 'grok.x.ai'],
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
				dns_suffixes: ['mistral.ai'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'MistralBot',
				default_action: BotAction::CHALLENGE,
			),
			'cohere' => new BotDefinition(
				id: 'cohere',
				name: 'Cohere Bot',
				user_agent_patterns: ['CohereBot', 'Cohere-User', 'CohereAI'],
				host_patterns: ['cohere.com', 'cohere.ai'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['cohere.com', 'cohere.ai'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'CohereBot',
				default_action: BotAction::CHALLENGE,
			),
			'ai21' => new BotDefinition(
				id: 'ai21',
				name: 'AI21 Labs',
				user_agent_patterns: ['AI21Bot', 'AI21-User'],
				host_patterns: ['ai21.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['ai21.com'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'AI21Bot',
				default_action: BotAction::CHALLENGE,
			),
			'youbot' => new BotDefinition(
				id: 'youbot',
				name: 'You.com Bot',
				user_agent_patterns: ['YouBot', 'YouBot/1.0'],
				host_patterns: ['you.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['you.com'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'YouBot',
				default_action: BotAction::CHALLENGE,
			),
			'phind' => new BotDefinition(
				id: 'phind',
				name: 'Phind Bot',
				user_agent_patterns: ['PhindBot', 'Phind-User'],
				host_patterns: ['phind.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'PhindBot',
				default_action: BotAction::CHALLENGE,
			),
			'amazon_ai' => new BotDefinition(
				id: 'amazon_ai',
				name: 'Amazonbot (AWS AI Crawler)',
				user_agent_patterns: ['Amazonbot', 'AWSBot'],
				host_patterns: ['amazon.com', 'aws.amazon.com', 'amazonbot.amazon'],
				ip_ranges: [
					'52.84.0.0/15', '52.94.224.0/19', '54.239.0.0/16', '54.240.128.0/18',
				],
				verify_dns: true,
				dns_suffixes: [
					'amazonbot.amazon',
					'amazon.com',
					'aws.amazon.com',
				],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'Amazonbot',
				default_action: BotAction::CHALLENGE,
				description: "Amazon's product/AI crawler. Default challenge.",
			),
			'semantic_scholar' => new BotDefinition(
				id: 'semantic_scholar',
				name: 'Semantic Scholar Bot (AI2 / Allen Institute)',
				user_agent_patterns: ['SemanticScholarBot', 'S2Bot', 'AI2Bot'],
				host_patterns: ['semanticscholar.org', 'allenai.org'],
				ip_ranges: ['54.245.0.0/16', '34.216.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['semanticscholar.org', 'allenai.org'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'SemanticScholarBot',
				default_action: BotAction::CHALLENGE,
				description: 'Aggressive academic/AI crawler (Allen Institute).',
			),
			'diffbot' => new BotDefinition(
				id: 'diffbot',
				name: 'Diffbot (Knowledge Graph AI)',
				user_agent_patterns: ['Diffbot', 'diffbot.com'],
				host_patterns: ['diffbot.com'],
				ip_ranges: ['107.170.0.0/16', '192.241.0.0/16', '198.199.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['diffbot.com'],
				category: BotCategory::AI_CRAWLER,
				robots_txt_token: 'Diffbot',
				default_action: BotAction::CHALLENGE,
				description: 'Knowledge-graph / structured-data extractor.',
			),
		];
	}

	public function social_crawlers(): array
	{
		return [
			'facebook' => new BotDefinition(
				id: 'facebook',
				name: 'Facebook Crawler',
				user_agent_patterns: ['facebookexternalhit', 'facebookcatalog', 'Facebot'],
				host_patterns: ['facebook.com', 'fbcdn.net'],
				ip_ranges: [
					'31.13.64.0/18', '45.64.40.0/22', '66.220.144.0/20', '69.63.176.0/20',
					'69.171.224.0/19', '74.119.76.0/22', '103.4.96.0/22', '129.134.0.0/16',
					'157.240.0.0/16', '173.252.64.0/18', '179.60.192.0/22', '185.60.216.0/22',
				],
				verify_dns: true,
				dns_suffixes: ['facebook.com', 'fbcdn.net'],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'twitter' => new BotDefinition(
				id: 'twitter',
				name: 'Twitter/X Bot',
				user_agent_patterns: ['Twitterbot', 'TwitterBot/1.0'],
				host_patterns: ['twitter.com', 't.co', 'x.com'],
				ip_ranges: ['104.244.42.0/24', '104.244.43.0/24', '199.16.156.0/22', '199.59.148.0/22'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'linkedin' => new BotDefinition(
				id: 'linkedin',
				name: 'LinkedIn Bot',
				user_agent_patterns: ['LinkedInBot'],
				host_patterns: ['linkedin.com'],
				ip_ranges: ['108.174.0.0/15'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'discord' => new BotDefinition(
				id: 'discord',
				name: 'Discord Bot',
				user_agent_patterns: ['Discordbot'],
				host_patterns: ['discord.com', 'discordapp.com'],
				ip_ranges: ['162.159.128.0/17'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'slack' => new BotDefinition(
				id: 'slack',
				name: 'Slack Bot (Link Unfurling)',
				user_agent_patterns: ['Slackbot', 'Slackbot-LinkExpanding'],
				host_patterns: ['slack.com', 'slack-imgs.com'],
				ip_ranges: [
					'52.11.0.0/16', '52.12.0.0/16', '52.24.0.0/15', '52.32.0.0/14',
					'52.40.0.0/14', '52.44.0.0/15', '52.46.0.0/18', '52.46.64.0/19',
					'52.46.96.0/20', '52.46.112.0/21', '52.46.120.0/22', '52.46.124.0/23',
					'52.46.126.0/24',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'telegram' => new BotDefinition(
				id: 'telegram',
				name: 'Telegram Bot',
				user_agent_patterns: ['TelegramBot'],
				host_patterns: ['telegram.org'],
				ip_ranges: ['149.154.160.0/20', '91.108.4.0/22'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'whatsapp' => new BotDefinition(
				id: 'whatsapp',
				name: 'WhatsApp Bot',
				user_agent_patterns: ['WhatsApp/2.'],
				host_patterns: ['whatsapp.net'],
				ip_ranges: ['31.13.64.0/18', '157.240.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'pinterest' => new BotDefinition(
				id: 'pinterest',
				name: 'Pinterest Bot',
				user_agent_patterns: ['Pinterestbot'],
				host_patterns: ['pinterest.com'],
				ip_ranges: ['54.236.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'reddit' => new BotDefinition(
				id: 'reddit',
				name: 'Reddit Bot',
				user_agent_patterns: ['RedditBot'],
				host_patterns: ['reddit.com'],
				ip_ranges: ['151.101.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
			),
			'kakao' => new BotDefinition(
				id: 'kakao',
				name: 'KakaoTalk Bot (Korea #1 Messenger)',
				user_agent_patterns: ['KakaoTalk', 'KakaoBot', 'KakaoLink', 'KakaoStory'],
				host_patterns: ['kakao.com', 'kakaocdn.net'],
				ip_ranges: ['121.128.0.0/14', '211.232.0.0/16', '210.89.160.0/20'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
				default_action: BotAction::ALLOW,
				description: "Korea's dominant messenger — link previews.",
			),
			'line' => new BotDefinition(
				id: 'line',
				name: 'LINE Bot (Japan/Taiwan/Thailand)',
				user_agent_patterns: ['LINE', 'LineBot', 'LINE/1.0'],
				host_patterns: ['line.me', 'line-scdn.net', 'line-apps.com', 'linecorp.com'],
				ip_ranges: ['182.48.0.0/14', '203.104.0.0/14'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
				default_action: BotAction::ALLOW,
				description: 'Dominant messenger in JP/TW/TH — link previews.',
			),
			'wechat' => new BotDefinition(
				id: 'wechat',
				name: 'WeChat Bot (China Super App)',
				user_agent_patterns: ['MicroMessenger', 'WeChat', 'wechat', 'wxwork'],
				host_patterns: ['wechat.com', 'weixin.qq.com', 'qq.com'],
				ip_ranges: [
					'101.226.0.0/15', '101.227.0.0/16', '119.147.0.0/16',
					'140.206.0.0/16', '157.255.0.0/16', '180.163.0.0/16',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
				default_action: BotAction::ALLOW,
				description: "China's super-app — link previews on shared content.",
			),
			'notion' => new BotDefinition(
				id: 'notion',
				name: 'Notion Bot (Link Previews)',
				user_agent_patterns: ['NotionBot', 'Notion-Web-Previewer'],
				host_patterns: ['notion.so', 'notion.site', 'notion.com'],
				ip_ranges: ['54.144.0.0/16', '54.145.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SOCIAL_CRAWLER,
				default_action: BotAction::ALLOW,
				description: "Notion's embedded-page link previewer.",
			),
		];
	}

	public function seo_crawlers(): array
	{
		return [
			'semrush' => new BotDefinition(
				id: 'semrush',
				name: 'SemrushBot',
				user_agent_patterns: ['SemrushBot', 'SemrushBot/7~bl', 'SemrushBot-BA', 'SemrushBot-SI', 'SemrushBot-CT', 'SemrushBot-OCOB'],
				host_patterns: ['semrush.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
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
				dns_suffixes: [],
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
				dns_suffixes: [],
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
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'DotBot',
				default_action: BotAction::CHALLENGE,
			),
			'similarweb' => new BotDefinition(
				id: 'similarweb',
				name: 'SimilarWeb Bot',
				user_agent_patterns: ['SimilarWeb', 'SimilarWebBot', 'swbot'],
				host_patterns: ['similarweb.com'],
				ip_ranges: ['54.152.0.0/16', '54.153.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'SimilarWeb',
				default_action: BotAction::CHALLENGE,
				description: 'Market-intelligence / competitive-traffic analytics.',
			),
			'seobility' => new BotDefinition(
				id: 'seobility',
				name: 'SeobilityBot',
				user_agent_patterns: ['SeobilityBot', 'Seobility'],
				host_patterns: ['seobility.net'],
				ip_ranges: ['88.99.0.0/16', '136.243.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['seobility.net'],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'SeobilityBot',
				default_action: BotAction::CHALLENGE,
				description: 'SEO auditing crawler (German company, Hetzner-hosted).',
			),
			'botify' => new BotDefinition(
				id: 'botify',
				name: 'Botify Bot',
				user_agent_patterns: ['Botify', 'BotifyBot'],
				host_patterns: ['botify.com'],
				ip_ranges: ['52.0.0.0/11'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'Botify',
				default_action: BotAction::CHALLENGE,
				description: 'Enterprise SEO crawler (AWS-hosted).',
			),
			'siteimprove' => new BotDefinition(
				id: 'siteimprove',
				name: 'Siteimprove Bot',
				user_agent_patterns: ['Siteimprove', 'SiteimproveBot'],
				host_patterns: ['siteimprove.com'],
				ip_ranges: ['54.171.0.0/16', '54.172.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'Siteimprove',
				default_action: BotAction::ALLOW,
				description: 'Accessibility / SEO auditing — generally benign.',
			),
			'lumar' => new BotDefinition(
				id: 'lumar',
				name: 'Lumar (formerly DeepCrawl)',
				user_agent_patterns: ['Lumar', 'DeepCrawl', 'LumarBot'],
				host_patterns: ['lumar.io', 'deepcrawl.com'],
				ip_ranges: ['52.0.0.0/11'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'LumarBot',
				default_action: BotAction::CHALLENGE,
				description: 'Enterprise technical-SEO crawler.',
			),
			'oncrawl' => new BotDefinition(
				id: 'oncrawl',
				name: 'OnCrawl Bot',
				user_agent_patterns: ['OnCrawl', 'OnCrawlBot'],
				host_patterns: ['oncrawl.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'OnCrawlBot',
				default_action: BotAction::CHALLENGE,
			),
			'screaming_frog' => new BotDefinition(
				id: 'screaming_frog',
				name: 'Screaming Frog SEO Spider (Cloud)',
				user_agent_patterns: ['Screaming Frog', 'ScreamingFrog'],
				host_patterns: ['screamingfrog.co.uk'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'Screaming Frog',
				default_action: BotAction::CHALLENGE,
			),
			'contentking' => new BotDefinition(
				id: 'contentking',
				name: 'ContentKing (Conductor)',
				user_agent_patterns: ['ContentKing', 'ContentKingBot'],
				host_patterns: ['contentkingapp.com', 'conductor.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SEO_CRAWLER,
				robots_txt_token: 'ContentKing',
				default_action: BotAction::CHALLENGE,
				description: 'Real-time SEO monitoring.',
			),
		];
	}

	public function archive_crawlers(): array
	{
		return [
			'commoncrawl' => new BotDefinition(
				id: 'commoncrawl',
				name: 'Common Crawl',
				user_agent_patterns: ['CCBot'],
				host_patterns: ['commoncrawl.org', 'crawl.commoncrawl.org'],
				// IPv4 Ranges
				'3.41.188.32/29',
				'18.97.9.168/29',
				'18.97.14.80/29',
				'18.97.14.88/30',
				'98.85.178.216/32',
				// IPv6 Range
				'2600:1f28:365:8000::/56',
				verify_dns: true,
				dns_suffixes: ['crawl.commoncrawl.org'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'CCBot',
				description: 'CCBot — Common Crawl web archive.',
			),
			'internet_archive' => new BotDefinition(
				id: 'internet_archive',
				name: 'Internet Archive (Wayback)',
				user_agent_patterns: ['ia_archiver', 'archive.org_bot', 'Archive-It'],
				host_patterns: ['archive.org'],
				ip_ranges: ['207.241.224.0/19'],
				verify_dns: true,
				dns_suffixes: ['archive.org'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'ia_archiver',
			),
			'web_archive_uk' => new BotDefinition(
				id: 'web_archive_uk',
				name: 'UK Web Archive (British Library)',
				user_agent_patterns: ['UKWA', 'BritishLibrary', 'BL-Bot'],
				host_patterns: ['webarchive.org.uk', 'bl.uk'],
				ip_ranges: ['193.60.0.0/16', '193.61.0.0/16', '193.62.0.0/16', '193.63.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['webarchive.org.uk', 'bl.uk'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'UKWA',
				default_action: BotAction::ALLOW,
				description: 'UK legal-deposit web archive.',
			),
			'biblio_nationale_fr' => new BotDefinition(
				id: 'biblio_nationale_fr',
				name: 'Bibliothèque nationale de France (BnF)',
				user_agent_patterns: ['BnF-Bot', 'BnfBot', 'GallicaBot'],
				host_patterns: ['bnf.fr', 'gallica.bnf.fr'],
				ip_ranges: ['193.48.0.0/16', '193.49.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['bnf.fr', 'gallica.bnf.fr'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'BnF-Bot',
				default_action: BotAction::ALLOW,
				description: 'French national library / Gallica archive.',
			),
			'dnb_de' => new BotDefinition(
				id: 'dnb_de',
				name: 'Deutsche Nationalbibliothek (DNB)',
				user_agent_patterns: ['DNB-Bot', 'DNB_Crawler'],
				host_patterns: ['dnb.de'],
				ip_ranges: ['193.174.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['dnb.de'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'DNB-Bot',
				default_action: BotAction::ALLOW,
				description: 'German national library.',
			),
			'fossies' => new BotDefinition(
				id: 'fossies',
				name: 'FOSSies (Fraunhofer SCAI)',
				user_agent_patterns: ['FOSSies-Fresher'],
				host_patterns: ['fossies.org'],
				ip_ranges: ['148.251.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['fossies.org'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'FOSSies-Fresher',
				description: 'FOSS software archive. Indexes open-source releases for research/engineering/science.',
			),
			'kb_nl' => new BotDefinition(
				id: 'kb_nl',
				name: 'Koninklijke Bibliotheek (Netherlands)',
				user_agent_patterns: ['KB-Bot', 'KBNL-Crawler', 'DelpherBot'],
				host_patterns: ['kb.nl', 'delpher.nl'],
				ip_ranges: ['194.171.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['kb.nl', 'delpher.nl'],
				category: BotCategory::ARCHIVE_CRAWLER,
				robots_txt_token: 'KB-Bot',
				default_action: BotAction::ALLOW,
				description: 'Dutch national library / Delpher archive.',
			),
		];
	}

	public function feed_readers(): array
	{
		return [
			'feedly' => new BotDefinition(
				id: 'feedly',
				name: 'Feedly Bot',
				user_agent_patterns: ['Feedly', 'FeedlyBot', 'Feedly/1.0'],
				host_patterns: ['feedly.com'],
				ip_ranges: ['54.144.0.0/16', '54.145.0.0/16', '54.146.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::FEED_READER,
				robots_txt_token: 'Feedly',
				default_action: BotAction::ALLOW,
				description: 'Major RSS reader (~30M users).',
			),
			'inoreader' => new BotDefinition(
				id: 'inoreader',
				name: 'Inoreader Bot',
				user_agent_patterns: ['Inoreader', 'InoreaderBot', 'Inoreader/1.0'],
				host_patterns: ['inoreader.com'],
				ip_ranges: ['88.99.0.0/16', '136.243.0.0/16'],
				verify_dns: true,
				dns_suffixes: ['inoreader.com'],
				category: BotCategory::FEED_READER,
				robots_txt_token: 'Inoreader',
				default_action: BotAction::ALLOW,
			),
			'flipboard' => new BotDefinition(
				id: 'flipboard',
				name: 'Flipboard Proxy',
				user_agent_patterns: ['FlipboardProxy', 'FlipboardRSS', 'Flipboard'],
				host_patterns: ['flipboard.com'],
				ip_ranges: ['54.183.0.0/16', '54.184.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::FEED_READER,
				robots_txt_token: 'FlipboardProxy',
				default_action: BotAction::ALLOW,
			),
			'newsblur' => new BotDefinition(
				id: 'newsblur',
				name: 'NewsBlur Bot',
				user_agent_patterns: ['NewsBlur', 'NewsBlur Feed Fetcher', 'NewsBlur Page Fetcher'],
				host_patterns: ['newsblur.com'],
				ip_ranges: ['192.241.0.0/16', '198.199.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::FEED_READER,
				robots_txt_token: 'NewsBlur',
				default_action: BotAction::ALLOW,
			),
			'google_news' => new BotDefinition(
				id: 'google_news',
				name: 'Google News Bot',
				user_agent_patterns: ['Googlebot-News'],
				host_patterns: ['googlebot.com', 'google.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['googlebot.com', 'google.com'],
				category: BotCategory::FEED_READER,
				robots_txt_token: 'Googlebot-News',
				default_action: BotAction::ALLOW,
				description: 'Google News crawls; news sites depend on this for visibility.',
			),
			'apple_news' => new BotDefinition(
				id: 'apple_news',
				name: 'Apple News Bot',
				user_agent_patterns: ['AppleNewsBot', 'AppleNews'],
				host_patterns: ['apple.com', 'applebot.apple.com'],
				ip_ranges: ['17.0.0.0/8'],
				verify_dns: true,
				dns_suffixes: ['applebot.apple.com', 'apple.com'],
				category: BotCategory::FEED_READER,
				robots_txt_token: 'AppleNewsBot',
				default_action: BotAction::ALLOW,
			),
		];
	}

	public function shopping_crawlers(): array
	{
		return [
			'google_shopping' => new BotDefinition(
				id: 'google_shopping',
				name: 'Google Shopping / Merchant Center',
				user_agent_patterns: ['Googlebot-Shopping', 'GoogleShopping', 'Google-Read-Aloud'],
				host_patterns: ['googlebot.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['googlebot.com', 'google.com'],
				category: BotCategory::SHOPPING_CRAWLER,
				robots_txt_token: 'Googlebot-Shopping',
				default_action: BotAction::ALLOW,
				description: 'Google Shopping/Product crawler. Critical for merchants.',
			),
			'bing_shopping' => new BotDefinition(
				id: 'bing_shopping',
				name: 'Bing Shopping / Merchant',
				user_agent_patterns: ['bingbot-shopping', 'MSNBot-Media', 'BingPreview', 'AdIdxBot'],
				host_patterns: ['bing.com', 'msn.com'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['search.msn.com', 'bing.com'],
				category: BotCategory::SHOPPING_CRAWLER,
				robots_txt_token: 'Bingbot-Shopping',
				default_action: BotAction::ALLOW,
			),
			'pinterest_shopping' => new BotDefinition(
				id: 'pinterest_shopping',
				name: 'Pinterest Shopping / Catalog',
				user_agent_patterns: ['Pinterestbot', 'Pinterest/0.1', 'Pinterest-Saved'],
				host_patterns: ['pinterest.com'],
				ip_ranges: ['54.236.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SHOPPING_CRAWLER,
				robots_txt_token: 'Pinterestbot',
				default_action: BotAction::ALLOW,
			),
			'facebook_catalog' => new BotDefinition(
				id: 'facebook_catalog',
				name: 'Facebook/Instagram Catalog Crawler',
				user_agent_patterns: ['facebookcatalog', 'FacebookCatalog', 'facebookexternalhit'],
				host_patterns: ['facebook.com', 'fbcdn.net'],
				ip_ranges: [],
				verify_dns: true,
				dns_suffixes: ['facebook.com', 'fbcdn.net'],
				category: BotCategory::SHOPPING_CRAWLER,
				robots_txt_token: 'FacebookCatalog',
				default_action: BotAction::ALLOW,
			),
			'shopify' => new BotDefinition(
				id: 'shopify',
				name: 'Shopify Bot (Storefront/SEO)',
				user_agent_patterns: ['Shopify', 'ShopifyBot', 'Storefront'],
				host_patterns: ['shopify.com', 'myshopify.com'],
				ip_ranges: ['23.227.32.0/20', '23.227.36.0/23', '185.199.108.0/22'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SHOPPING_CRAWLER,
				robots_txt_token: 'Shopify',
				default_action: BotAction::ALLOW,
			),
		];
	}

	public function cloud_infrastructure(): array
	{
		// CRITICAL FOR AVAILABILITY.
		// If you block these, your Load Balancer marks your origin "Unhealthy"
		// and takes you offline. Default ALLOW — no exceptions.
		return [
			'cloudflare_health' => new BotDefinition(
				id: 'cloudflare_health',
				name: 'Cloudflare Health Checks',
				user_agent_patterns: ['Cloudflare-Healthcheck', 'Cloudflare-HTTP-Probe', 'Cloudflare-Traffic-Manager'],
				host_patterns: ['cloudflare.com'],
				ip_ranges: [
					'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
					'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
					'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
					'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
					'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
					'2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::ALLOW,
				description: 'CRITICAL: Cloudflare LB health probes. Blocking takes you offline.',
			),
			'aws_elb_health' => new BotDefinition(
				id: 'aws_elb_health',
				name: 'AWS ELB/ALB Health Checks',
				user_agent_patterns: ['ELB-HealthChecker', 'AWS-ELB-HealthCheck', 'AWS-Security-Scanner', 'ELBHC'],
				host_patterns: ['amazonaws.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::ALLOW,
				description: 'CRITICAL: AWS ELB/ALB health probes.',
			),
			'google_cloud_health' => new BotDefinition(
				id: 'google_cloud_health',
				name: 'Google Cloud Load Balancer Health Checks',
				user_agent_patterns: ['GoogleHC', 'GCP-Health-Check', 'Google-Cloud-Load-Balancer', 'GCLB'],
				host_patterns: ['google.com', 'googleusercontent.com'],
				ip_ranges: ['35.191.0.0/16', '130.211.0.0/22'],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::ALLOW,
				description: 'CRITICAL: GCP LB health probes.',
			),
			'azure_health' => new BotDefinition(
				id: 'azure_health',
				name: 'Azure Load Balancer / Front Door Health Probes',
				user_agent_patterns: ['Azure-LB-Health-Probe', 'AzureFrontDoor', 'Azure-Health-Probe', 'EdgeHealthProbe'],
				host_patterns: ['azure.com', 'azurefd.net', 'azureedge.net'],
				ip_ranges: [
					'168.61.49.0/24', '168.62.0.0/16', '168.63.0.0/16',
					'20.0.0.0/8', '13.107.0.0/16',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::ALLOW,
				description: 'CRITICAL: Azure LB / Front Door health probes.',
			),
			'fastly_health' => new BotDefinition(
				id: 'fastly_health',
				name: 'Fastly Health Checks',
				user_agent_patterns: ['Fastly', 'Fastly-HTTP-Probe'],
				host_patterns: ['fastly.net', 'fastly.com'],
				ip_ranges: [
					'23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23',
					'103.245.224.0/23', '104.156.80.0/20', '146.75.0.0/17', '151.101.0.0/16',
					'157.52.64.0/18', '167.82.0.0/17', '167.82.128.0/18', '172.111.64.0/18',
					'185.31.16.0/22', '190.168.72.0/22', '190.168.76.0/22', '199.232.0.0/16',
					'199.27.72.0/21', '204.74.96.0/20', '204.74.112.0/20',
					'204.74.128.0/18', '204.74.192.0/18', '204.74.208.0/20',
					'204.74.224.0/20', '204.74.240.0/20', '205.185.208.0/20',
					'208.123.80.0/20', '209.122.0.0/17', '209.122.128.0/18',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::CLOUD_INFRASTRUCTURE,
				default_action: BotAction::ALLOW,
				description: 'CRITICAL: Fastly CDN health probes.',
			),
		];
	}

	public function monitoring(): array
	{
		return [
			'uptimerobot' => new BotDefinition(
				id: 'uptimerobot',
				name: 'UptimeRobot',
				user_agent_patterns: ['UptimeRobot'],
				host_patterns: ['uptimerobot.com'],
				ip_ranges: [
					'216.144.250.150/24', '69.162.124.226/24', '63.143.42.66/24',
					'174.138.0.0/16', '46.166.151.0/24',
				],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
			),
			'pingdom' => new BotDefinition(
				id: 'pingdom',
				name: 'Pingdom',
				user_agent_patterns: ['Pingdom.com_bot'],
				host_patterns: ['pingdom.com'],
				ip_ranges: ['94.247.0.0/16'],
				verify_dns: false,
				dns_suffixes: [],
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
				dns_suffixes: [],
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
			),
			'gtmetrix' => new BotDefinition(
				id: 'gtmetrix',
				name: 'GTmetrix',
				user_agent_patterns: ['GTmetrix'],
				host_patterns: ['gtmetrix.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
				description: 'Performance testing tool.',
			),
			'lighthouse' => new BotDefinition(
				id: 'lighthouse',
				name: 'Google Lighthouse',
				user_agent_patterns: ['Chrome-Lighthouse'],
				host_patterns: ['google.com', 'googleusercontent.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::MONITORING,
				default_action: BotAction::ALLOW,
				description: 'Performance / a11y auditing.',
			),
		];
	}

	public function security_scanners(): array
	{
		return [
			'qualys' => new BotDefinition(
				id: 'qualys',
				name: 'Qualys Scanner',
				user_agent_patterns: ['Qualys'],
				host_patterns: ['qualys.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SECURITY_SCANNER,
				default_action: BotAction::LOG_ONLY,
				description: 'Enterprise vulnerability scanner.',
			),
			'detectify' => new BotDefinition(
				id: 'detectify',
				name: 'Detectify Scanner',
				user_agent_patterns: ['Detectify'],
				host_patterns: ['detectify.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SECURITY_SCANNER,
				default_action: BotAction::LOG_ONLY,
			),
			'rapid7' => new BotDefinition(
				id: 'rapid7',
				name: 'Rapid7 (InsightVM/Metasploit)',
				user_agent_patterns: ['Rapid7', 'InsightVM'],
				host_patterns: ['rapid7.com'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SECURITY_SCANNER,
				default_action: BotAction::LOG_ONLY,
			),
			'shodan' => new BotDefinition(
				id: 'shodan',
				name: 'Shodan (Internet Scanner)',
				user_agent_patterns: ['Shodan', 'Shodan.io'],
				host_patterns: ['shodan.io'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SECURITY_SCANNER,
				default_action: BotAction::LOG_ONLY,
				description: 'Internet-wide scanner. Not malicious — observation only.',
			),
			'censys' => new BotDefinition(
				id: 'censys',
				name: 'Censys Scanner',
				user_agent_patterns: ['CensysInspect'],
				host_patterns: ['censys.io'],
				ip_ranges: [],
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::SECURITY_SCANNER,
				default_action: BotAction::LOG_ONLY,
			),
		];
	}

	public function residential_crawlers(): array
	{
		// Residential proxy networks used for scraping.
		// Default action: BLOCK — these are commercial data-collection
		// services with no legitimate crawl purpose. They evade IP-based
		// detection by routing through real residential connections.
		return [
			'brightdata' => new BotDefinition(
				id: 'brightdata',
				name: 'Bright Data (Residential Proxy Network)',
				user_agent_patterns: ['BrightData', 'DataCollector', 'Luminati', 'BrightDataBot'],
				host_patterns: ['brightdata.com', 'luminati.io'],
				ip_ranges: [],  // Residential — IP detection is useless
				verify_dns: false,
				dns_suffixes: [],
				category: BotCategory::RESIDENTIAL_PROXY,
				robots_txt_token: 'BrightData',
				default_action: BotAction::BLOCK,
				description: 'Residential proxy network used for AI/scraping. Default BLOCK.',
			),
			// Future: 'oxylabs', 'smartproxy', 'iproyal', 'geosurf', 'netnut'
		];
	}

	public function utility_bots(): array
	{
		// Utility bots that don't fit cleanly into another category.
		// Currently only IABot (Wikimedia's dead-link checker, archive-adjacent).
		return [
			'iabot' => new BotDefinition(
				id: 'iabot',
				name: 'Internet Archive Bot (IABot)',
				user_agent_patterns: ['IABot'],
				host_patterns: ['wmcloud.org', 'archive.org', 'wikimedia.org'],
				ip_ranges: [
					'208.80.152.0/22',
					'185.15.56.0/22',
				],
				verify_dns: true,
				dns_suffixes: ['wikimedia.org', 'wmcloud.org', 'archive.org'],
				category: BotCategory::ARCHIVE_CRAWLER,  // Functionally archival
				robots_txt_token: 'IABot',
				default_action: BotAction::ALLOW,
			),
		];
	}
}