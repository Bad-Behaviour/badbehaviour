<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Bot\Registry;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Feeds\FeedRegistry;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\IpUtil;

class BotDetector
{
	private Configuration $config;
	private AdapterInterface $adapter;
	private array $dns_cache = [];
	private ?array $dynamic_ranges = null;
	private bool $dynamic_ranges_fetched = false;

	public function __construct(Configuration $config, AdapterInterface $adapter)
	{
		$this->config = $config;
		$this->adapter = $adapter;
	}

	private function get_dynamic_ranges(): array
	{
		if ($this->dynamic_ranges !== null) {
			return $this->dynamic_ranges;
		}

		// EXPERIMENTAL: Disabled by default
		if (!$this->config->enable_dynamic_ip_ranges) {
			$this->dynamic_ranges = [];
			return [];
		}

		// Check persistent cache first (non-blocking)
		$cache_key = 'bb:ip_ranges:merged';
		$cached = $this->adapter->get($cache_key);

		if ($cached && isset($cached['data'], $cached['fetched'])) {
			$this->dynamic_ranges = $cached['data'];
			return $this->dynamic_ranges;
		}

		// NO CACHE: Don't fetch on request path - return empty, log once
		if (!$this->dynamic_ranges_fetched) {
			$this->dynamic_ranges_fetched = true;
			error_log("[BadBehaviour] Dynamic IP ranges: no cache, feature enabled but fetch deferred. Run 'php bin/update-ip-ranges.php' via cron.");
		}

		$this->dynamic_ranges = [];
		return [];
	}

	public function detect(RequestPackage $package): ?Result
	{
		$ip = $package->ip;
		$ua = $package->user_agent;
		$ua_lower = strtolower($ua);

		// Get dynamic ranges (cached)
		$dynamic_ranges = $this->get_dynamic_ranges();

		foreach (Registry::all() as $bot_id => $def) {
			// UA match
			$ua_match = false;
			foreach ($def->user_agent_patterns as $pattern) {
				if (stripos($ua_lower, strtolower($pattern)) !== false) {
					$ua_match = true;
					break;
				}
			}
			if (!$ua_match) continue;

			// IP match: STATIC + DYNAMIC
			$all_ranges = array_merge($def->ip_ranges, $dynamic_ranges[$bot_id] ?? []);
			$ip_match = !empty($all_ranges) && IpUtil::match_any($ip, $all_ranges);

			// DNS verification
			$dns_verified = false;
			if ($def->verify_dns && $def->dns_suffix) {
				$dns_verified = $this->verify_dns($ip, $def->dns_suffix);
			}

			$verified = $ip_match || $dns_verified;

			// REMOVED: The $matches filter that skipped unverified SEO/AI crawlers
			// All matched bots now go through determine_action()

			// Additional check: UA parser says bot but not verified - suspicious
			if ($ua_parsed_bot && !$verified && $def->category === BotCategory::SEARCH_ENGINE) {
				return Result::block(ResultCode::BLOCKED_BOT, "Suspicious: UA says bot but not verified: {$def->name}", $package, [
					'bot_id' => $bot_id,
					'bot_name' => $def->name,
					'bot_category' => $def->category->value,
					'bot_verified' => $verified,
					'ua_parsed_bot' => true,
				]);
			}

			// Determine action
			$action = $this->determine_action($def, $verified);

			return match($action) {
				BotAction::ALLOW => Result::allow($package),
				BotAction::LOG_ONLY => Result::allow($package),
				BotAction::CHALLENGE => Result::challenge(ResultCode::CHALLENGE_REQUIRED, "Bot challenge required: {$def->name}", $package, [
					'bot_id' => $bot_id,
					'bot_name' => $def->name,
					'bot_category' => $def->category->value,
					'bot_verified' => $verified,
				]),
				BotAction::BLOCK => Result::block($this->code_for_category($def->category), "Bot blocked: {$def->name}", $package, [
					'bot_id' => $bot_id,
					'bot_name' => $def->name,
					'bot_category' => $def->category->value,
					'bot_verified' => $verified,
				]),
			};
		}

		return null;
	}

	private function determine_action(BotDefinition $def, bool $verified): BotAction
	{
		$cat = $def->category->value;

		if (in_array($cat, $this->config->blocked_bot_categories, true)) {
			return BotAction::BLOCK;
		}

		if ($def->category === BotCategory::AI_CRAWLER) {
			$token = $def->robots_txt_token ?? $def->name;
			if (in_array($token, $this->config->allowed_ai_crawlers, true)) {
				return BotAction::ALLOW;
			}
			if ($this->config->block_unverified_ai && !$verified) {
				return BotAction::BLOCK;
			}
			return $this->config->strict_ai ? BotAction::BLOCK : BotAction::CHALLENGE;
		}

		if ($def->category === BotCategory::SEO_CRAWLER) {
			return $verified ? $def->default_action : BotAction::BLOCK;
		}

		if ($def->category === BotCategory::SEARCH_ENGINE) {
			if (!$verified) {
				return BotAction::BLOCK;
			}
			return BotAction::ALLOW;
		}

		if ($def->category === BotCategory::SOCIAL_CRAWLER) {
			return $verified ? BotAction::ALLOW : BotAction::LOG_ONLY;
		}

		if ($def->category === BotCategory::ARCHIVE_CRAWLER || $def->category === BotCategory::MONITORING) {
			return BotAction::ALLOW;
		}

		return $def->default_action;
	}

	private function code_for_category(BotCategory $cat): ResultCode
	{
		return match($cat) {
			BotCategory::AI_CRAWLER => ResultCode::BLOCKED_AI_CRAWLER,
			BotCategory::SEO_CRAWLER => ResultCode::BLOCKED_SEO_CRAWLER,
			BotCategory::SEARCH_ENGINE => ResultCode::BLOCKED_BOT,
			BotCategory::SOCIAL_CRAWLER => ResultCode::BLOCKED_BOT,
			BotCategory::ARCHIVE_CRAWLER => ResultCode::BLOCKED_BOT,
			BotCategory::MONITORING => ResultCode::BLOCKED_BOT,
			BotCategory::MALICIOUS => ResultCode::BLOCKED_BOT,
			default => ResultCode::BLOCKED_BOT,
		};
	}

	private function verify_dns(string $ip, string $suffix): bool
	{
		$key = "$ip@$suffix";
		if (isset($this->dns_cache[$key])) {
			return $this->dns_cache[$key];
		}

		$host = @gethostbyaddr($ip);
		if (!$host) {
			$this->dns_cache[$key] = false;
			return false;
		}

		$rev_host = strrev($host);
		$rev_suffix = strrev($suffix);
		if (strpos($rev_host, $rev_suffix) !== 0) {
			$this->dns_cache[$key] = false;
			return false;
		}

		$addrs = @gethostbynamel($host);
		$verified = in_array($ip, $addrs ?? [], true);

		$this->dns_cache[$key] = $verified;
		return $verified;
	}
}
