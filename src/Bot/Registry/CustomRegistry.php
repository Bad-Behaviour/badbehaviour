<?php

declare(strict_types=1);

namespace BadBehaviour\Bot\Registry;

use BadBehaviour\Bot\BotAction;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Bot\RegistryTokens;

/**
 * A registry built from a config-style array of bot definitions.
 *
 * Used to materialize user-supplied bots (from `bb_registry.php`'s `additions`
 * or `bots` keys) into BotDefinition instances.
 *
 * === SCHEMA ===
 *
 * ```php
 * $bots = [
 *     'my_internal_search' => [
 *         'name'                => 'My Bot',                    // required
 *         'user_agent_patterns' => ['MyBot', 'MyBot/1.0'],      // required, ≥1 entry
 *         'category'            => 'search_engine',             // required, BotCategory value
 *         'host_patterns'       => ['bot.example.com'],        // optional
 *         'ip_ranges'           => ['10.0.0.0/8'],              // optional, CIDRs
 *         'verify_dns'          => true,                        // optional
 *         'dns_suffixes'        => [                            // optional
 *             'bot.example.com',
 *             'cdn.example.net',
 *         ],
 *         'robots_txt_token'    => 'MyBot',                     // optional
 *         'default_action'      => 'allow',                     // optional: allow|challenge|block|log_only
 *         'description'         => 'What this bot does',        // optional
 *     ],
 * ];
 * ```
 *
 * === VALIDATION BEHAVIOR ===
 *
 * Invalid entries are logged via `error_log()` and skipped (the registry keeps
 * valid ones). This is intentional — bad config shouldn't break the entire
 * library. Use `get_errors()` / `has_errors()` to inspect what was rejected.
 *
 * Validation is NOT performed on bots added via `add()` — that's a programmatic
 * path, the caller is responsible for constructing valid BotDefinitions.
 */
class CustomRegistry implements RegistryInterface
{
	/** @var array<string, BotDefinition> */
	private array $bots = [];

	/** @var array<int, array{bot_id: string, error: string}> */
	private array $errors = [];

	/** Lazily built UA index. */
	private ?array $ua_index = null;

	/** Lazily built token index. */
	private ?array $ua_token_index = null;

	/**
	 * @param array<string, array> $bots Bot ID => array definition
	 */
	public function __construct(array $bots = [])
	{
		foreach ($bots as $bot_id => $definition) {
			$bot = $this->validate_and_build($bot_id, $definition);
			if ($bot !== null) {
				$this->bots[$bot_id] = $bot;
			}
		}
	}

	/**
	 * Build from a config array (alias for the constructor — slightly more readable).
	 *
	 * @param array<string, array> $bots
	 */
	public static function from_array(array $bots): self
	{
		return new self($bots);
	}

	/**
	 * Add a single bot programmatically (skips validation).
	 *
	 * Use this when you've already constructed a valid BotDefinition and just
	 * need to insert it. For config-driven bots, use the constructor.
	 */
	public function add(BotDefinition $bot): void
	{
		$this->bots[$bot->id] = $bot;
		$this->invalidate_index();
	}

	/**
	 * Get any validation errors that occurred during construction.
	 *
	 * Each entry is ['bot_id' => string, 'error' => string].
	 * Empty array means all bots validated cleanly.
	 *
	 * @return array<int, array{bot_id: string, error: string}>
	 */
	public function get_errors(): array
	{
		return $this->errors;
	}

	/**
	 * True if any bots were rejected during construction.
	 */
	public function has_errors(): bool
	{
		return !empty($this->errors);
	}

	// ========================================================================
	// RegistryInterface implementation
	// ========================================================================

	public function all(): array
	{
		return $this->bots;
	}

	public function count(): int
	{
		return count($this->bots);
	}

	public function has(string $bot_id): bool
	{
		return isset($this->bots[$bot_id]);
	}

	public function get(string $bot_id): ?BotDefinition
	{
		return $this->bots[$bot_id] ?? null;
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

	// ========================================================================
	// Per-category accessors
	// ========================================================================

	public function search_engines(): array
	{
		return $this->by_category(BotCategory::SEARCH_ENGINE);
	}

	public function ai_crawlers(): array
	{
		return $this->by_category(BotCategory::AI_CRAWLER);
	}

	public function social_crawlers(): array
	{
		return $this->by_category(BotCategory::SOCIAL_CRAWLER);
	}

	public function seo_crawlers(): array
	{
		return $this->by_category(BotCategory::SEO_CRAWLER);
	}

	public function archive_crawlers(): array
	{
		return $this->by_category(BotCategory::ARCHIVE_CRAWLER);
	}

	public function monitoring(): array
	{
		return $this->by_category(BotCategory::MONITORING);
	}

	public function feed_readers(): array
	{
		return $this->by_category(BotCategory::FEED_READER);
	}

	public function shopping_crawlers(): array
	{
		return $this->by_category(BotCategory::SHOPPING_CRAWLER);
	}

	public function cloud_infrastructure(): array
	{
		return $this->by_category(BotCategory::CLOUD_INFRASTRUCTURE);
	}

	public function security_scanners(): array
	{
		return $this->by_category(BotCategory::SECURITY_SCANNER);
	}

	public function residential_crawlers(): array
	{
		return $this->by_category(BotCategory::RESIDENTIAL_PROXY);
	}

	private function by_category(BotCategory $category): array
	{
		return array_filter(
			$this->bots,
			fn(BotDefinition $b) => $b->category === $category
		);
	}

	// ========================================================================
	// Validation
	// ========================================================================

	/**
	 * Validate a bot definition and return a BotDefinition, or null on failure.
	 *
	 * Records any error via record_error() so get_errors() can surface it.
	 */
	private function validate_and_build(string $bot_id, array $def): ?BotDefinition
	{
		// === Required: name ===
		$name = $def['name'] ?? null;
		if (!is_string($name) || $name === '') {
			$this->record_error($bot_id, "missing or empty 'name'");
			return null;
		}

		// === Required: user_agent_patterns ===
		$ua_patterns = $def['user_agent_patterns'] ?? null;
		if (!is_array($ua_patterns) || empty($ua_patterns)) {
			$this->record_error($bot_id, "missing or empty 'user_agent_patterns'");
			return null;
		}

		// Validate each pattern individually
		foreach ($ua_patterns as $i => $pattern) {
			if (!is_string($pattern) || $pattern === '') {
				$this->record_error($bot_id, "user_agent_patterns[{$i}] is not a non-empty string");
				return null;
			}
			// Patterns <3 chars are rejected outright (they can never match
			// reliably — too many false positives).
			if (strlen($pattern) < 3) {
				$this->record_error(
					$bot_id,
					"user_agent_patterns[{$i}] is too short (min 3 chars): '{$pattern}'"
				);
				return null;
			}
		}

		// === Required: category ===
		$category_value = $def['category'] ?? null;
		if (!is_string($category_value)) {
			$this->record_error($bot_id, "missing 'category' (must be string)");
			return null;
		}
		$category = BotCategory::tryFrom($category_value);
		if ($category === null) {
			$valid = implode(', ', array_column(BotCategory::cases(), 'value'));
			$this->record_error(
				$bot_id,
				"invalid 'category' '{$category_value}' (valid: {$valid})"
			);
			return null;
		}

		// === Optional: host_patterns ===
		$host_patterns = $def['host_patterns'] ?? [];
		if (!is_array($host_patterns)) {
			$this->record_error($bot_id, "'host_patterns' must be an array");
			return null;
		}

		// === Optional: ip_ranges ===
		$ip_ranges = $def['ip_ranges'] ?? [];
		if (!is_array($ip_ranges)) {
			$this->record_error($bot_id, "'ip_ranges' must be an array");
			return null;
		}
		// Validate CIDR format (loose check; full validation requires IpUtil)
		foreach ($ip_ranges as $i => $cidr) {
			if (!is_string($cidr)) {
				$this->record_error($bot_id, "ip_ranges[{$i}] is not a string");
				return null;
			}
			if (!preg_match('#^[\d\.:a-fA-F]+/\d+$#', $cidr)) {
				$this->record_error($bot_id, "ip_ranges[{$i}] is not a valid CIDR: '{$cidr}'");
				return null;
			}
		}

		// === Optional: verify_dns (boolean) ===
		$verify_dns = (bool)($def['verify_dns'] ?? false);

		// === Optional: dns_suffixes (array of strings) ===
		$dns_suffixes = $def['dns_suffixes'] ?? [];
		if (!is_array($dns_suffixes)) {
			$this->record_error($bot_id, "'dns_suffixes' must be an array");
			return null;
		}
		foreach ($dns_suffixes as $i => $suffix) {
			if (!is_string($suffix)) {
				$this->record_error($bot_id, "dns_suffixes[{$i}] is not a string");
				return null;
			}
			if ($suffix === '') {
				$this->record_error($bot_id, "dns_suffixes[{$i}] is empty");
				return null;
			}
		}

		// === Optional: robots_txt_token (string|null) ===
		$robots_txt_token = $def['robots_txt_token'] ?? null;
		if ($robots_txt_token !== null && !is_string($robots_txt_token)) {
			$this->record_error($bot_id, "'robots_txt_token' must be a string");
			return null;
		}

		// === Optional: default_action (BotAction enum value) ===
		$action_value = $def['default_action'] ?? 'allow';
		if (!is_string($action_value)) {
			$this->record_error($bot_id, "'default_action' must be a string");
			return null;
		}
		$action = BotAction::tryFrom($action_value);
		if ($action === null) {
			$valid = implode(', ', array_column(BotAction::cases(), 'value'));
			$this->record_error(
				$bot_id,
				"invalid 'default_action' '{$action_value}' (valid: {$valid})"
			);
			return null;
		}

		// === Optional: description ===
		$description = (string)($def['description'] ?? '');

		return new BotDefinition(
			id: $bot_id,
			name: $name,
			user_agent_patterns: array_values($ua_patterns),
			host_patterns: array_values($host_patterns),
			ip_ranges: array_values($ip_ranges),
			verify_dns: $verify_dns,
			dns_suffixes: array_values($dns_suffixes),
			category: $category,
			robots_txt_token: $robots_txt_token,
			default_action: $action,
			description: $description,
		);
	}

	private function record_error(string $bot_id, string $error): void
	{
		$this->errors[] = ['bot_id' => $bot_id, 'error' => $error];
		error_log("[BadBehaviour] CustomRegistry: bot '{$bot_id}' rejected: {$error}");
	}

	private function invalidate_index(): void
	{
		$this->ua_index = null;
		$this->ua_token_index = null;
	}

	// ========================================================================
	// Index builders (lazy)
	// ========================================================================

	private function ensure_ua_index(): void
	{
		if ($this->ua_index !== null) {
			return;
		}
		$this->ua_index = [];
		foreach ($this->bots as $bot_id => $def) {
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
		foreach ($this->bots as $bot_id => $def) {
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
}