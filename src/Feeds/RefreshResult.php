<?php

declare(strict_types=1);

namespace BadBehaviour\Feeds;

/**
 * Immutable result of an OnDemandRefresher::do_refresh() call.
 *
 * Fields:
 *   - success:           true iff every feed fetched without error AND at
 *                        least one feed succeeded
 *   - partial:           true iff some feeds succeeded AND some failed
 *                        (cache write still happens — partial data is
 *                        better than no data)
 *   - bot_count:         number of bot IDs in the merged payload
 *   - cidr_count:        total CIDRs across all bots
 *   - elapsed_seconds:   wall-clock time spent in do_refresh()
 *   - cache_written:     true iff the merged cache was updated
 *                        (false on total failure OR on cache write error)
 *   - feed_status:       per-feed status map; keys are feed names (for
 *                        bot feeds) or "cloud:{provider}" (for cloud feeds),
 *                        values are ['status' => 'ok'|'error'|'skipped', ...]
 *   - started_at:        Unix timestamp when do_refresh() was invoked
 *   - finished_at:       Unix timestamp when do_refresh() returned
 */
final readonly class RefreshResult
{
    /**
     * @param array<string, array<string, mixed>> $feed_status
     */
    public function __construct(
        public bool $success,
        public bool $partial,
        public int $bot_count,
        public int $cidr_count,
        public float $elapsed_seconds,
        public bool $cache_written,
        public array $feed_status,
        public int $started_at,
        public int $finished_at,
    ) {}

    /**
     * Count of feeds that returned an error.
     */
    public function failed_feed_count(): int
    {
        $count = 0;
        foreach ($this->feed_status as $status) {
            if (($status['status'] ?? null) === 'error') {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Count of feeds that completed successfully.
     */
    public function successful_feed_count(): int
    {
        $count = 0;
        foreach ($this->feed_status as $status) {
            if (($status['status'] ?? null) === 'ok') {
                $count++;
            }
        }
        return $count;
    }

    /**
     * @return array<string, mixed>
     */
    public function to_array(): array
    {
        return [
            'success'               => $this->success,
            'partial'               => $this->partial,
            'bot_count'             => $this->bot_count,
            'cidr_count'            => $this->cidr_count,
            'elapsed_seconds'       => $this->elapsed_seconds,
            'cache_written'         => $this->cache_written,
            'feed_status'           => $this->feed_status,
            'successful_feed_count' => $this->successful_feed_count(),
            'failed_feed_count'     => $this->failed_feed_count(),
            'started_at'            => $this->started_at,
            'finished_at'           => $this->finished_at,
        ];
    }
}
