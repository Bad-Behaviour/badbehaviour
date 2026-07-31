<?php
// src/Detection/BotDetector.php - FINAL with per-instance memoization

namespace BadBehaviour\Detection;

use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\Registry;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
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

    /**
     * Per-instance result memoization (NOT static — avoids cross-config pollution).
     * Cache key includes config fingerprint so different BadBehaviour instances
     * with different configs get independent caches.
     */
    private array $result_cache = [];
    private int $result_cache_max = 5000;
    private string $config_fingerprint;
    private const RESULT_CACHE_TTL = 300;

    public function __construct(Configuration $config, AdapterInterface $adapter)
    {
        $this->config = $config;
        $this->adapter = $adapter;
        $this->config_fingerprint = $this->compute_config_fingerprint($config);
    }

    private function compute_config_fingerprint(Configuration $config): string
    {
        return substr(hash('sha256', json_encode([
            'blocked_cat'        => $config->blocked_bot_categories,
            'allowed_ai'         => $config->allowed_ai_crawlers,
            'block_unverified'   => $config->block_unverified_ai,
            'strict_ai'          => $config->strict_ai,
            'strict_se'          => $config->strict_search_engines,
        ])), 0, 16);
    }

    public function detect(RequestPackage $package): ?Result
    {
        $ip = $package->ip;
        $ua = $package->user_agent;

        if ($ua === '') {
            return null;
        }

        $cache_key = $this->compute_cache_key($ip, $ua);
        $cached = $this->get_cached_result($cache_key);

        if ($cached !== false) {
            $cached_result = $cached['result'];
            if ($cached_result === null) {
                return null;
            }
            return $this->rebuild_result($cached_result, $package);
        }

        $result = $this->detect_uncached($package);
        $this->set_cached_result($cache_key, $result);

        return $result;
    }

    private function detect_uncached(RequestPackage $package): ?Result
    {
        $ip = $package->ip;
        $ua = $package->user_agent;

        $dynamic_ranges = $this->get_dynamic_ranges();

        // Primary: substring match against indexed UA fragments
        $candidate_ids = Registry::find_by_ua($ua);

        // Secondary: token match (with noise filter)
        if (empty($candidate_ids)) {
            $candidate_ids = Registry::find_by_tokens($ua);
        }

        if (empty($candidate_ids)) {
            return null;
        }

        foreach ($candidate_ids as $bot_id) {
            $def = Registry::all()[$bot_id] ?? null;
            if ($def === null) {
                continue;
            }

            $all_ranges = array_merge($def->ip_ranges, $dynamic_ranges[$bot_id] ?? []);
            $ip_match = !empty($all_ranges) && IpUtil::match_any($ip, $all_ranges);

            $dns_verified = false;
            if ($def->verify_dns && $def->dns_suffix) {
                $dns_verified = $this->verify_dns($ip, $def->dns_suffix);
            }

            $verified = $ip_match || $dns_verified;
            $action = $this->determine_action($def, $verified);

            return match($action) {
                BotAction::ALLOW => Result::allow($package),
                BotAction::LOG_ONLY => Result::allow($package),
                BotAction::CHALLENGE => Result::challenge(
                    ResultCode::CHALLENGE_REQUIRED,
                    "Bot challenge required: {$def->name}",
                    $package,
                    [
                        'bot_id' => $bot_id,
                        'bot_name' => $def->name,
                        'bot_category' => $def->category->value,
                        'bot_verified' => $verified,
                    ]
                ),
                BotAction::BLOCK => Result::block(
                    $this->code_for_category($def->category),
                    "Bot blocked: {$def->name}",
                    $package,
                    [
                        'bot_id' => $bot_id,
                        'bot_name' => $def->name,
                        'bot_category' => $def->category->value,
                        'bot_verified' => $verified,
                    ]
                ),
            };
        }

        return null;
    }

    private function compute_cache_key(string $ip, string $ua): string
    {
        return $this->config_fingerprint . ':' . substr(hash('sha256', $ip . '|' . $ua), 0, 24);
    }

    private function get_cached_result(string $key): array|false
    {
        if (!isset($this->result_cache[$key])) {
            return false;
        }
        $entry = $this->result_cache[$key];
        if (time() - $entry['ts'] > self::RESULT_CACHE_TTL) {
            unset($this->result_cache[$key]);
            return false;
        }
        return $entry;
    }

    private function set_cached_result(string $key, ?Result $result): void
    {
        if (count($this->result_cache) >= $this->result_cache_max) {
            $evict_count = (int)($this->result_cache_max * 0.1);
            $evicted = array_slice($this->result_cache, 0, $evict_count, true);
            $this->result_cache = array_diff_key($this->result_cache, $evicted);
        }
        $this->result_cache[$key] = ['result' => $result, 'ts' => time()];
    }

    private function rebuild_result(Result $cached, RequestPackage $package): Result
    {
        if ($cached->is_allowed()) {
            return Result::allow($package);
        }
        return new Result(
            code: $cached->code,
            message: $cached->message,
            package: $package,
            metadata: $cached->metadata,
            support_key: Result::generate_support_key_public($package),
        );
    }

    private function get_dynamic_ranges(): array
    {
        if ($this->dynamic_ranges !== null) {
            return $this->dynamic_ranges;
        }
        if (!$this->config->enable_dynamic_ip_ranges) {
            $this->dynamic_ranges = [];
            return [];
        }
        $cache_key = 'bb:ip_ranges:merged';
        $cached = $this->adapter->get($cache_key);
        if ($cached && isset($cached['data'], $cached['fetched'])) {
            $this->dynamic_ranges = $cached['data'];
            return $this->dynamic_ranges;
        }
        if (!$this->dynamic_ranges_fetched) {
            $this->dynamic_ranges_fetched = true;
            error_log("[BadBehaviour] Dynamic IP ranges: no cache, run bin/update-ip-ranges.php");
        }
        $this->dynamic_ranges = [];
        return [];
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
            default => ResultCode::BLOCKED_BOT,
        };
    }

    private function verify_dns(string $ip, string $suffix): bool
    {
        $key = "{$ip}@{$suffix}";
        if (isset($this->dns_cache[$key])) {
            return $this->dns_cache[$key];
        }
        $cached = $this->adapter->get("bb:dns_verify:{$key}");
        if ($cached !== null) {
            $this->dns_cache[$key] = (bool)$cached;
            return (bool)$cached;
        }
        $this->schedule_background_dns_lookup($ip, $suffix, $key);
        return false;
    }

    private function schedule_background_dns_lookup(string $ip, string $suffix, string $key): void
    {
        register_shutdown_function(function() use ($ip, $suffix, $key) {
            $host = @gethostbyaddr($ip);
            if (!$host) {
                $this->adapter->set("bb:dns_verify:{$key}", false, 3600);
                return;
            }
            $rev_host = strrev($host);
            $rev_suffix = strrev($suffix);
            if (strpos($rev_host, $rev_suffix) !== 0) {
                $this->adapter->set("bb:dns_verify:{$key}", false, 3600);
                return;
            }
            $addrs = @gethostbynamel($host);
            $verified = $addrs !== false && in_array($ip, $addrs, true);
            $this->adapter->set("bb:dns_verify:{$key}", $verified, 86400 * 7);
        });
    }
}