<?php
/**
 * Bad Behaviour 3.0 - Generic PHP Bootstrap Example
 *
 * This is NOT a shim — it's a copy-paste snippet for hosts that don't
 * have a dedicated integration. Adapt the bootstrap timing and
 * adapter choice to your framework.
 *
 * === BOOTSTRAP TIMING ===
 *
 * Run BadBehaviour BEFORE your framework's main request handler so
 * blocked requests never reach your application logic:
 *
 *   index.php:
 *     require 'vendor/autoload.php';
 *     // ... bad-behaviour detection here ...
 *     $app = new MyApp();
 *     $app->handle();
 *
 * === ADAPTER CHOICE ===
 *
 * - GenericAdapter: no DB, no cache; uses file-based fallback cache
 * - Custom adapter: implement AdapterInterface + CacheInterface for
 *   your specific backend (Redis, Memcached, custom DB, etc.)
 */

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\GenericAdapter;

require __DIR__ . '/vendor/autoload.php';

// === Adapter ===
//
// GenericAdapter implements both AdapterInterface and CacheInterface,
// so it works standalone without any host-specific configuration.
// Replace with a custom adapter for production deployments.

$adapter = new GenericAdapter();

// === Detection ===

$bb = BadBehaviour::with_adapter($adapter);
$result = $bb->run();

if ($result->is_actionable()) {
    $bb->handle_result($result);
    // handle_result() calls exit(); execution does not return.
}

// === Application continues normally for ALLOWED / MONITORED requests ===
// (MONITORED = "would have blocked in monitor-only mode" — still served)

$app = new MyApp();
$app->handle();