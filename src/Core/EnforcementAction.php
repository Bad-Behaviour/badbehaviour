<?php
declare(strict_types=1);

namespace BadBehaviour\Core;

/**
 * What was actually done with a request, separate from what was *detected*.
 *
 * A detection can produce a Result with code=BLOCKED_MALICIOUS_UA, but the
 * library may choose not to enforce that block (e.g., in monitor-only mode).
 * `enforcement` records what actually happened to the response.
 *
 * Used by:
 *   - log_request(): writes `enforcement_action` column to the bad_behaviour table
 *   - handle_result(): refuses to serve block pages for non-enforced results
 *   - diagnostics(): surfaces the current effective enforcement policy
 */
enum EnforcementAction: string
{
	/** The detection ran and the response was actually changed (403 served, etc.). */
	case ENFORCED  = 'enforced';

	/** A block/challenge was detected but suppressed (monitor-only mode). Request was served normally. */
	case MONITORED = 'monitored';

	/** No block was detected; request was allowed to proceed. */
	case ALLOWED   = 'allowed';
}