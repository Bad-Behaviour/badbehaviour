#!/usr/bin/env php
<?php
// bin/update-ip-ranges.php

require_once __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Feeds\FeedRegistry;
use BadBehaviour\Adapter\GenericAdapter;

try {
    $adapter = new GenericAdapter();
    $registry = new FeedRegistry($adapter);

    echo "Fetching from " . count($registry->get_feed_status()) . " feeds...\n";

    $start = microtime(true);
    $ranges = $registry->fetch_all();
    $elapsed = round(microtime(true) - $start, 2);

    if (empty($ranges)) {
        echo "WARNING: No ranges fetched\n";
        exit(1);
    }

    // Save merged cache
    $adapter->set('bb:ip_ranges:merged', [
        'data' => $ranges,
        'fetched' => time(),
    ], 86400); // 24h

    $total = 0;
    foreach ($ranges as $bot => $cidrs) {
        echo "  {$bot}: " . count($cidrs) . " CIDRs\n";
        $total += count($cidrs);
    }

    echo "Success: {$total} total CIDRs cached in {$elapsed}s\n";
    exit(0);

} catch (\Throwable $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    error_log("[BadBehaviour] CLI IP fetch failed: " . $e->getMessage());
    exit(1);
}
