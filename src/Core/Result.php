<?php
// src/Core/Result.php - Adds enforcement action + monitored_from() + new query methods

namespace BadBehaviour\Core;

use BadBehaviour\Util\RequestPackage;

readonly class Result
{
	public function __construct(
		public ResultCode $code,
		public string $message = '',
		public ?RequestPackage $package = null,
		public array $metadata = [],
		public ?string $support_key = null,
		/**
		 * What was actually done with this request.
		 *
		 * Defaults to ENFORCED for backward compatibility — existing call
		 * sites that construct Result directly (tests, custom detectors)
		 * continue to work without modification.
		 *
		 * BadBehaviour::maybe_demote_to_monitored() is the canonical
		 * place that sets this to MONITORED in monitor-only mode.
		 */
		public EnforcementAction $enforcement = EnforcementAction::ENFORCED,
		) {}

		public static function allow(?RequestPackage $package = null): self
		{
			return new self(
				ResultCode::ALLOWED,
				'Request allowed',
				$package,
				enforcement: EnforcementAction::ALLOWED,
				);
		}

		public static function block(ResultCode $code, string $message, RequestPackage $package, array $metadata = []): self
		{
			return new self(
				$code,
				$message,
				$package,
				$metadata,
				self::generate_support_key($package),
				enforcement: EnforcementAction::ENFORCED,
				);
		}

		public static function challenge(ResultCode $code, string $message, RequestPackage $package, array $metadata = []): self
		{
			return new self(
				$code,
				$message,
				$package,
				$metadata,
				self::generate_support_key($package),
				enforcement: EnforcementAction::ENFORCED,
				);
		}

		/**
		 * Build a "monitored" result from a would-be-block result.
		 *
		 * Used by BadBehaviour::maybe_demote_to_monitored() in monitor-only mode
		 * to record what the detector wanted to do without actually enforcing it.
		 *
		 * The new result carries:
		 *   - code:          monitored.* counterpart of the original blocked.*
		 *                    (e.g., blocked.bot → monitored.bot)
		 *   - enforcement:   MONITORED
		 *   - metadata:      original_code + monitor_only=true, plus any
		 *                    metadata the original result carried
		 *
		 * If the original code has no monitored counterpart (e.g., it was
		 * already a monitored.* code, or ERROR_*), the original code is kept
		 * but enforcement is still set to MONITORED. This preserves information
		 * rather than throwing away context.
		 */
		public static function monitored_from(Result $original): self
		{
			$new_code = $original->code->to_monitored() ?? $original->code;

			$metadata = $original->metadata;
			$metadata['original_code'] = $original->code->value;
			$metadata['monitor_only'] = true;

			return new self(
				code: $new_code,
				message: $original->message,
				package: $original->package,
				metadata: $metadata,
				support_key: $original->support_key,
				enforcement: EnforcementAction::MONITORED,
				);
		}

		/**
		 * Was this result an allowed request that flowed through normally?
		 *
		 * NOTE: This returns FALSE for MONITORED results — those are
		 * "would-have-blocked" entries that *did* flow through to the app.
		 * Use is_allowed_or_monitored() if you want to know whether the
		 * request was actually served.
		 */
		public function is_allowed(): bool
		{
			return $this->code === ResultCode::ALLOWED;
		}

		/**
		 * Did the request pass through to the application?
		 *
		 * True for ALLOWED (no detection matched) and MONITORED (detection
		 * matched but suppressed in monitor-only mode).
		 *
		 * Use this when the host application needs to decide "should I keep
		 * serving this request, or has BadBehaviour already handled the
		 * response?" — and you want to be defensive against accidentally
		 * double-serving in monitor-only mode.
		 */
		public function is_allowed_or_monitored(): bool
		{
			return $this->code === ResultCode::ALLOWED
			|| $this->enforcement === EnforcementAction::MONITORED;
		}

		/**
		 * Did this result represent an actually-enforced block or challenge?
		 *
		 * Combines code semantics with enforcement state:
		 *   - blocked.X / challenge.X with enforcement=enforced   → true
		 *   - blocked.X / challenge.X with enforcement=monitored  → false
		 *   - allowed                                                → false
		 *
		 * This is the right check for `handle_result()` (refuse to serve
		 * a block page for a monitored result) and for logging decisions
		 * (only enforced blocks need full forensic detail).
		 */
		public function is_enforced_block(): bool
		{
			return $this->enforcement === EnforcementAction::ENFORCED
			&& ($this->code->is_blocked() || $this->code->requires_challenge());
		}

		/**
		 * Was this a detection that was suppressed (monitor-only mode)?
		 */
		public function is_monitored(): bool
		{
			return $this->enforcement === EnforcementAction::MONITORED;
		}

		/**
		 * Was this result blocked (enforced or merely detected)?
		 *
		 * Prefer is_enforced_block() when you care about enforcement.
		 * This method is kept for backward compatibility with existing
		 * call sites that mean "did the detector flag this".
		 */
		public function is_blocked(): bool
		{
			return $this->code->is_blocked() || $this->code->is_monitored();
		}

		public function requires_challenge(): bool
		{
			return $this->code->requires_challenge();
		}

		public function http_status(): int
		{
			return $this->code->http_status();
		}

		public function to_array(): array
		{
			return [
				'code'         => $this->code->value,
				'message'      => $this->message,
				'support_key'  => $this->support_key,
				'http_status'  => $this->http_status(),
				'metadata'     => $this->metadata,
				'enforcement'  => $this->enforcement->value,
				'is_monitored' => $this->is_monitored(),
				'original_code' => $this->metadata['original_code'] ?? null,
			];
		}

		public function get_package(): ?RequestPackage
		{
			return $this->package;
		}

		/**
		 * Public method to regenerate support key for a different package.
		 * Used by detectors that memoize results across requests.
		 */
		public static function generate_support_key_public(RequestPackage $package): string
		{
			return self::generate_support_key($package);
		}

		private static function generate_support_key(RequestPackage $package): string
		{
			$ip_parts = explode('.', $package->ip);
			$ip_hex = '';
			foreach ($ip_parts as $octet) {
				$ip_hex .= str_pad(dechex((int)$octet), 2, '0', STR_PAD_LEFT);
			}
			$key_part = substr(hash('sha256', $package->user_agent . $package->request_uri), 0, 8);
			return implode('-', str_split($ip_hex . $key_part, 4));
		}
}
