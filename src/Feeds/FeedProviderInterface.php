<?php

declare(strict_types=1);

namespace BadBehaviour\Feeds;

/**
 * Provider of bot IP-range feeds for OnDemandRefresher.
 *
 * OnDemandRefresher iterates over get_feeds() and calls fetch() on
 * each. FeedRegistry implements this interface implicitly (it has the
 * right method shape); tests use a fake to avoid FeedRegistry's heavy
 * constructor.
 *
 * This interface is intentionally minimal — just the iteration surface
 * the refresher needs. The full FeedRegistry API (fetch_all,
 * get_feed_status, etc.) is richer than this interface requires;
 * consumers that only need iteration can type-hint against this
 * interface for cleaner dependencies.
 */
interface FeedProviderInterface
{
    /**
     * Return the configured feed list for iteration.
     *
     * @return array<string, IpFeedInterface> feed name → feed instance
     */
    public function get_feeds(): array;
}
