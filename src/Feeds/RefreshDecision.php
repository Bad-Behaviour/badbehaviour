<?php

declare(strict_types=1);

namespace BadBehaviour\Feeds;

/**
 * Immutable decision returned by OnDemandRefresher::maybe_refresh().
 *
 * Tells the caller:
 *   - should_schedule:  true if a refresh should be performed in the background
 *   - reason:           why a refresh was/wasn't scheduled (for logs)
 *   - cache_age:        age of the current cached data when scheduling (null
 *                       when not scheduling or cache is absent)
 *   - staleness_floor:  configured min_age_seconds at the time of decision
 *
 * Reasons:
 *   - 'probability'      Gate 1 failed — RNG didn't roll a 1
 *   - 'cooldown'         Gate 2 failed — lock exists
 *   - 'fresh'            Gate 3 failed — cache is fresh enough
 *   - 'mutex_lost'       Gate 4 failed — couldn't acquire lock
 *   - 'stale'            All gates passed; cache is older than min_age_seconds
 *   - 'cold_start'       All gates passed; no cache existed
 *   - 'error'            Unexpected exception inside gate logic
 */
final readonly class RefreshDecision
{
    private function __construct(
        public bool $should_schedule,
        public string $reason,
        public ?int $cache_age,
        public ?int $staleness_floor,
    ) {}

    public static function skip(string $reason): self
    {
        return new self(
            should_schedule: false,
            reason: $reason,
            cache_age: null,
            staleness_floor: null,
        );
    }

    public static function schedule(string $reason, ?int $cache_age, int $staleness_floor): self
    {
        return new self(
            should_schedule: true,
            reason: $reason,
            cache_age: $cache_age,
            staleness_floor: $staleness_floor,
        );
    }

    public function __toString(): string
    {
        if ($this->should_schedule) {
            return sprintf(
                'RefreshDecision(schedule, reason=%s, cache_age=%ds, floor=%ds)',
                $this->reason,
                $this->cache_age ?? -1,
                $this->staleness_floor ?? -1,
            );
        }
        return sprintf('RefreshDecision(skip, reason=%s)', $this->reason);
    }
}
