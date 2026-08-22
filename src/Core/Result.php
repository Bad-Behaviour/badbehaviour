<?php
// src/Core/Result.php — Complete, production-ready

declare(strict_types=1);

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

	// =====================================================================
	// Factory methods
	// =====================================================================

	public static function allow(?RequestPackage $package = null, array $metadata = []): self
	{
		return new self(
			ResultCode::ALLOWED,
			'Request allowed',
			$package,
			$metadata,
			enforcement: EnforcementAction::ALLOWED,
			);
	}

	public static function block(
		ResultCode $code,
		string $message,
		RequestPackage $package,
		array $metadata = []
	): self {
		return new self(
			$code,
			$message,
			$package,
			$metadata,
			self::generate_support_key($package),
			enforcement: EnforcementAction::ENFORCED,
		);
	}

	public static function challenge(
		ResultCode $code,
		string $message,
		RequestPackage $package,
		array $metadata = []
	): self {
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
	 *   - code:		  monitored.* counterpart of the original blocked.*
	 *					(e.g., blocked.bot → monitored.bot)
	 *   - enforcement:   MONITORED
	 *   - metadata:	  original_code + monitor_only=true, plus any
	 *					metadata the original result carried
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

	// =====================================================================
	// Routing decisions — the methods hosts SHOULD call
	// =====================================================================

	/**
	 * Should the host application route this request through BadBehaviour's
	 * response (block page / challenge), or let it reach the application?
	 *
	 * Returns TRUE when:
	 *   - code is blocked.*  AND  enforcement is enforced   → serve block page
	 *   - code is challenge.required AND enforcement is enforced → serve challenge
	 *
	 * Returns FALSE when:
	 *   - code is allowed (no detection matched)		 → let app handle it
	 *   - enforcement is monitored (detection matched but suppressed) → let app handle it
	 *
	 * === THIS IS THE METHOD HOSTS SHOULD CALL ===
	 *
	 * Pattern:
	 * ```php
	 * $result = $bb->run();
	 * if ($result->is_actionable()) {
	 *	 $bb->handle_result($result);   // serves 403
	 * }
	 * // otherwise, $result is ALLOWED or MONITORED → serve normally
	 * ```
	 *
	 * Same semantic as is_enforced_block(); the clearer name is preferred.
	 */
	public function is_actionable(): bool
	{
		return $this->is_enforced_block();
	}

	/**
	 * Did the request pass through to the application?
	 *
	 * Returns TRUE when:
	 *   - code is ALLOWED (no detection matched)
	 *   - enforcement is MONITORED (detection matched but suppressed)
	 *
	 * Returns FALSE when BadBehaviour should serve a response itself.
	 */
	public function reaches_application(): bool
	{
		return $this->code === ResultCode::ALLOWED
			|| $this->enforcement === EnforcementAction::MONITORED;
	}

	/**
	 * Was this an allowed request with NO detection match at all?
	 *
	 * STRICT semantic — returns TRUE ONLY when code === ALLOWED.
	 * MONITORED results return FALSE here even though they did reach
	 * the application.
	 *
	 * Used internally for log filtering and cache decisions where the
	 * distinction between "no detection" and "suppressed detection"
	 * matters. Hosts generally want is_actionable() or
	 * reaches_application() instead.
	 */
	public function is_purely_allowed(): bool
	{
		return $this->code === ResultCode::ALLOWED;
	}

	// =====================================================================
	// Existing methods — preserved for backward compatibility
	// =====================================================================

	/**
	 * Was this result an allowed request that flowed through normally?
	 *
	 * STRICT semantic — returns FALSE for MONITORED results.
	 *
	 * @deprecated Since 3.0. Prefer:
	 *   - is_actionable()		→ "should BadBehaviour handle this?"
	 *   - reaches_application()  → "did the request reach the application?"
	 *   - is_purely_allowed()	→ "was no detection matched at all?"
	 *
	 * The strict semantic is preserved here for backward compatibility
	 * and is used internally where the distinction matters (cache logic,
	 * log filtering). Hosts should migrate to is_actionable().
	 */
	public function is_allowed(): bool
	{
		return $this->code === ResultCode::ALLOWED;
	}

	/**
	 * Did this result represent an actually-enforced block or challenge?
	 *
	 * The right check for routing: TRUE means BadBehaviour should serve
	 * a response, FALSE means the request reaches the application.
	 *
	 * Same semantic as is_actionable() — that name was added as a clearer
	 * alias; this method is retained for code already calling it.
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
	 * @deprecated Prefer is_actionable() for routing decisions.
	 */
	public function is_blocked(): bool
	{
		return $this->code->is_blocked() || $this->code->is_monitored();
	}

	/**
	 * Did this result require a challenge?
	 */
	public function requires_challenge(): bool
	{
		return $this->code->requires_challenge();
	}

	/**
	 * HTTP status code this result should produce when enforced.
	 */
	public function http_status(): int
	{
		return $this->code->http_status();
	}

	/**
	 * Serialize the result to an associative array.
	 */
	public function to_array(): array
	{
		return [
			'code'		  => $this->code->value,
			'message'	   => $this->message,
			'support_key'   => $this->support_key,
			'http_status'   => $this->http_status(),
			'metadata'	  => $this->metadata,
			'enforcement'   => $this->enforcement->value,
			'is_monitored'  => $this->is_monitored(),
			'is_actionable' => $this->is_actionable(),
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

	/**
	 * Generate a stable per-(IP, UA, URI) support key for log correlation.
	 *
	 * Format: "XXXX-XXXX-XXXX-XXXX" (4 groups of 4 hex chars).
	 *   - First 8 hex chars: IP address (each octet encoded as 2 hex chars)
	 *   - Next 8 hex chars:  hash of (UA + URI)
	 *
	 * Stable across requests with the same identity, so operators can
	 * grep their log for a support key reported by a blocked user.
	 */
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
