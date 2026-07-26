<?php

namespace BadBehaviour\Core;

enum ResultCode: string
{
	case ALLOWED                    = 'allowed';
	case BLOCKED_BOT                = 'blocked.bot';
	case BLOCKED_AI_CRAWLER         = 'blocked.ai_crawler';
	case BLOCKED_SEO_CRAWLER        = 'blocked.seo_crawler';
	case BLOCKED_MALICIOUS_UA       = 'blocked.malicious_ua';
	case BLOCKED_ATTACK_PATTERN     = 'blocked.attack_pattern';
	case BLOCKED_DNSBL              = 'blocked.dnsbl';
	case BLOCKED_HTTPBL             = 'blocked.httpbl';
	case BLOCKED_BEHAVIORAL         = 'blocked.behavioral';
	case BLOCKED_FINGERPRINT        = 'blocked.fingerprint';
	case BLOCKED_RATE_LIMIT         = 'blocked.rate_limit';
	case BLOCKED_CUSTOM_RULE        = 'blocked.custom_rule';
	case BLOCKED_GEOIP              = 'blocked.geoip';
	case CHALLENGE_REQUIRED         = 'challenge.required';
	case CHALLENGE_FAILED           = 'challenge.failed';
	case ERROR_INTERNAL             = 'error.internal';
	case ERROR_CONFIGURATION        = 'error.configuration';

	public function http_status(): int
	{
		return match($this) {
			self::ALLOWED => 200,
			self::CHALLENGE_REQUIRED, self::CHALLENGE_FAILED => 403,
			self::BLOCKED_RATE_LIMIT => 429,
			self::ERROR_INTERNAL, self::ERROR_CONFIGURATION => 500,
			default => 403,
		};
	}

	// In src/Core/ResultCode.php
	public function getMessage(): ?string
	{
		return match($this) {
			self::BLOCKED_BOT => 'Known bot blocked',
			self::BLOCKED_AI_CRAWLER => 'AI crawler blocked',
			self::BLOCKED_SEO_CRAWLER => 'SEO crawler blocked',
			self::BLOCKED_MALICIOUS_UA => 'Malicious User-Agent',
			self::BLOCKED_ATTACK_PATTERN => 'Attack payload detected',
			self::BLOCKED_DNSBL => 'DNSBL match',
			self::BLOCKED_HTTPBL => 'http:BL match',
			self::BLOCKED_BEHAVIORAL => 'Behavioral anomaly',
			self::BLOCKED_FINGERPRINT => 'Bad fingerprint',
			self::BLOCKED_RATE_LIMIT => 'Rate limit exceeded',
			self::BLOCKED_CUSTOM_RULE => 'Custom rule match',
			self::BLOCKED_GEOIP => 'GeoIP block',
			self::CHALLENGE_REQUIRED => 'Challenge required',
			self::CHALLENGE_FAILED => 'Challenge failed',
			self::ERROR_INTERNAL => 'Internal error',
			self::ERROR_CONFIGURATION => 'Configuration error',
			default => null,
		};
	}

	public function is_blocked(): bool
	{
		return str_starts_with($this->value, 'blocked.') || $this === self::CHALLENGE_FAILED;
	}

	public function requires_challenge(): bool
	{
		return $this === self::CHALLENGE_REQUIRED;
	}
}
