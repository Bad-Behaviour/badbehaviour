<?php
declare(strict_types=1);

namespace BadBehaviour\Util;

/**
 * Immutable decision returned by LogRetention::maybe_cleanup().
 *
 * Mirrors RefreshDecision's shape so operators get a consistent mental model
 * across the two on-demand mechanisms (IP range refresh + log retention).
 *
 * Fields:
 *   - should_cleanup:  true if the caller should run do_cleanup() now
 *   - reason:           why cleanup was/wasn't scheduled (for logs)
 *   - last_run_age:     age (seconds) of the most recent successful cleanup
 *                      when scheduling (null when not scheduling or never run)
 *   - staleness_floor:  configured min_interval_seconds at decision time
 *
 * Reasons:
 *   - 'disabled'        Master switch off (log_retention.enabled = false)
 *   - 'probability'     Gate 1 failed — RNG didn't roll a 1
 *   - 'cooldown'        Gate 2 failed — cleanup lock is held by another worker
 *   - 'fresh'           Gate 3 failed — last cleanup was within min_interval
 *   - 'mutex_lost'      Gate 4 failed — couldn't acquire lock ourselves
 *   - 'due'             All gates passed; cleanup is overdue
 *   - 'cold_start'      All gates passed; cleanup has never run on this install
 *   - 'error'           Unexpected exception inside gate logic
 */
final readonly class RetentionDecision
{
    private function __construct(
        public bool $should_cleanup,
        public string $reason,
        public ?int $last_run_age,
        public ?int $staleness_floor,
    ) {}

    public static function skip(string $reason): self
    {
        return new self(
            should_cleanup: false,
            reason: $reason,
            last_run_age: null,
            staleness_floor: null,
        );
    }

    public static function schedule(string $reason, ?int $last_run_age, int $staleness_floor): self
    {
        return new self(
            should_cleanup: true,
            reason: $reason,
            last_run_age: $last_run_age,
            staleness_floor: $staleness_floor,
        );
    }

    public function __toString(): string
    {
        if ($this->should_cleanup) {
            return sprintf(
                'RetentionDecision(schedule, reason=%s, last_run_age=%ds, floor=%ds)',
                $this->reason,
                $this->last_run_age ?? -1,
                $this->staleness_floor ?? -1,
            );
        }
        return sprintf('RetentionDecision(skip, reason=%s)', $this->reason);
    }
}