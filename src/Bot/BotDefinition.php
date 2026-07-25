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
		public ?string $dns_suffix = null,
		public BotCategory $category = BotCategory::UNKNOWN,
		public ?string $robots_txt_token = null,
		public string $description = '',
		public BotAction $default_action = BotAction::ALLOW,
	) {}
}
