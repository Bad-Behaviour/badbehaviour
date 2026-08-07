<?php

namespace BadBehaviour\Core;

enum ResultCode: string
{
	case ALLOWED                    = 'allowed';

	// === ENFORCED blocks (a 403 page was actually served) ===
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

	// === MONITORED blocks (logged but NOT enforced; monitor-only mode only) ===
	// These exist so the log can distinguish "would have blocked" from
	// "actually blocked." They are produced by Result::monitored_from().
	//
	// DO NOT use these directly in a `return Result::block(MONITORED_X)` —
	// they are set automatically when a `blocked.*` result is demoted
	// by BadBehaviour::maybe_demote_to_monitored().
	case MONITORED_BOT              = 'monitored.bot';
	case MONITORED_AI_CRAWLER       = 'monitored.ai_crawler';
	case MONITORED_SEO_CRAWLER      = 'monitored.seo_crawler';
	case MONITORED_MALICIOUS_UA     = 'monitored.malicious_ua';
	case MONITORED_ATTACK_PATTERN   = 'monitored.attack_pattern';
	case MONITORED_DNSBL            = 'monitored.dnsbl';
	case MONITORED_HTTPBL           = 'monitored.httpbl';
	case MONITORED_BEHAVIORAL       = 'monitored.behavioral';
	case MONITORED_FINGERPRINT      = 'monitored.fingerprint';
	case MONITORED_RATE_LIMIT       = 'monitored.rate_limit';
	case MONITORED_CUSTOM_RULE      = 'monitored.custom_rule';
	case MONITORED_GEOIP            = 'monitored.geoip';
	case MONITORED_CHALLENGE        = 'monitored.challenge';

	public function http_status(): int
	{
		return match($this) {
			self::ALLOWED => 200,
			self::CHALLENGE_REQUIRED,
			self::CHALLENGE_FAILED,
			self::MONITORED_CHALLENGE => 403,
			self::BLOCKED_RATE_LIMIT,
			self::MONITORED_RATE_LIMIT => 429,
			self::ERROR_INTERNAL,
			self::ERROR_CONFIGURATION => 500,
			// Monitored codes never reach the wire — fall back to 403
			// for completeness in case they ever leak into handle_result().
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

			// === Monitored variants (same human-readable message as enforced) ===
			self::MONITORED_BOT => 'Known bot blocked (monitor-only)',
			self::MONITORED_AI_CRAWLER => 'AI crawler blocked (monitor-only)',
			self::MONITORED_SEO_CRAWLER => 'SEO crawler blocked (monitor-only)',
			self::MONITORED_MALICIOUS_UA => 'Malicious User-Agent (monitor-only)',
			self::MONITORED_ATTACK_PATTERN => 'Attack payload detected (monitor-only)',
			self::MONITORED_DNSBL => 'DNSBL match (monitor-only)',
			self::MONITORED_HTTPBL => 'http:BL match (monitor-only)',
			self::MONITORED_BEHAVIORAL => 'Behavioral anomaly (monitor-only)',
			self::MONITORED_FINGERPRINT => 'Bad fingerprint (monitor-only)',
			self::MONITORED_RATE_LIMIT => 'Rate limit exceeded (monitor-only)',
			self::MONITORED_CUSTOM_RULE => 'Custom rule match (monitor-only)',
			self::MONITORED_GEOIP => 'GeoIP block (monitor-only)',
			self::MONITORED_CHALLENGE => 'Challenge required (monitor-only)',

			default => null,
		};
	}

	/**
	 * True if this code represents a real block (enforced or monitored).
	 *
	 * For ENFORCEMENT purposes, prefer `Result::is_enforced_block()` which
	 * also checks `enforcement` against `EnforcementAction::ENFORCED`.
	 *
	 * This method only tells you what KIND of result the code represents;
	 * it does not tell you whether anything was actually enforced.
	 */
	public function is_blocked(): bool
	{
		return str_starts_with($this->value, 'blocked.') || $this === self::CHALLENGE_FAILED;
	}

	/**
	 * True if this is a challenge code (enforced or monitored).
	 */
	public function requires_challenge(): bool
	{
		return $this === self::CHALLENGE_REQUIRED;
	}

	/**
	 * True if this code is a "monitored" variant (would-have-blocked
	 * recorded in monitor-only mode; no 403 was actually served).
	 */
	public function is_monitored(): bool
	{
		return str_starts_with($this->value, 'monitored.');
	}

	/**
	 * Convert a `blocked.X` code (or `challenge.required`) into its
	 * `monitored.X` counterpart.
	 *
	 * Returns null for codes that have no monitored counterpart —
	 * typically ALLOWED, ERROR_*, CHALLENGE_FAILED (which is a post-hoc
	 * failure state, not a detection), or already-monitored codes.
	 *
	 * Used by Result::monitored_from() to demote a result when the
	 * library is in monitor-only mode.
	 */
	public function to_monitored(): ?self
	{
		return match ($this) {
			self::BLOCKED_BOT              => self::MONITORED_BOT,
			self::BLOCKED_AI_CRAWLER       => self::MONITORED_AI_CRAWLER,
			self::BLOCKED_SEO_CRAWLER      => self::MONITORED_SEO_CRAWLER,
			self::BLOCKED_MALICIOUS_UA     => self::MONITORED_MALICIOUS_UA,
			self::BLOCKED_ATTACK_PATTERN   => self::MONITORED_ATTACK_PATTERN,
			self::BLOCKED_DNSBL            => self::MONITORED_DNSBL,
			self::BLOCKED_HTTPBL           => self::MONITORED_HTTPBL,
			self::BLOCKED_BEHAVIORAL       => self::MONITORED_BEHAVIORAL,
			self::BLOCKED_FINGERPRINT      => self::MONITORED_FINGERPRINT,
			self::BLOCKED_RATE_LIMIT       => self::MONITORED_RATE_LIMIT,
			self::BLOCKED_CUSTOM_RULE      => self::MONITORED_CUSTOM_RULE,
			self::BLOCKED_GEOIP            => self::MONITORED_GEOIP,
			self::CHALLENGE_REQUIRED       => self::MONITORED_CHALLENGE,
			default                        => null,
		};
	}
}
