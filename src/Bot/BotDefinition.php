<?php

namespace BadBehaviour\Bot;

use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotAction;

readonly class BotDefinition
{
	public function __construct(
		public string $id,
		public string $name,
		public array $user_agent_patterns,
		public array $host_patterns,
		public array $ip_ranges,
		public bool $verify_dns = false,
		public array $dns_suffixes = [],
		public BotCategory $category = BotCategory::UNKNOWN,
		public ?string $robots_txt_token = null,
		public string $description = '',
		public BotAction $default_action = BotAction::ALLOW,
		) {}

		/**
		 * Return all DNS suffixes this bot may reverse-resolve to.
		 *
		 * Always returns an array (never null/empty when not used). Returns
		 * an empty array when the bot has no DNS verification configured —
		 * callers should check `$def->verify_dns` first.
		 *
		 * @return string[] List of suffixes to match against
		 */
		public function get_dns_suffixes(): array
		{
			return $this->dns_suffixes;
		}
}