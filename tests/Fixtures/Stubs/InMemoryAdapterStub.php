<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Fixtures\Stubs;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Util\RequestPackage;

/**
 * In-memory adapter stub for unit tests.
 *
 * Implements CacheInterface fully (so DNS verification cache behavior is
 * testable). Other AdapterInterface methods are no-ops — tests of
 * BotDetector don't exercise logging, email lookup, etc.
 */
class InMemoryAdapterStub implements AdapterInterface, CacheInterface
{
    /** @var array<string, array{value: mixed, expires: int, fetched: int}> */
    public array $cache = [];

    /** @var array<string, int> */
    public array $counters = [];

    public int $call_count = 0;

    public function get(string $key): mixed
    {
        $this->call_count++;
        $entry = $this->cache[$key] ?? null;
        if (!$entry) return null;
        if (($entry['expires'] ?? 0) < time()) {
            unset($this->cache[$key]);
            return null;
        }
        return $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttl): bool
    {
        $this->cache[$key] = [
            'value' => $value,
            'expires' => time() + $ttl,
            'fetched' => time(),
        ];
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->cache[$key], $this->counters[$key]);
        return true;
    }

    public function increment_counter(string $key, int $window): int
    {
        $now = time();
        $window_start = $now - $window;

        $data = $this->counters[$key] ?? null;
        if ($data === null || $data < $window_start) {
            $this->counters[$key] = $now;
            return 1;
        }

        return ++$this->counters[$key];
    }

    public function get_counter(string $key): int
    {
        return $this->counters[$key] ?? 0;
    }

    public function get_behavior_profile(string $session_id): ?array
    {
        return $this->get("behavior:{$session_id}");
    }

    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
    {
        return $this->set("behavior:{$session_id}", $profile, $ttl);
    }

    public function add_to_set(string $key, string $value, int $ttl): bool
    {
        return $this->set("set:{$key}", $value, $ttl);
    }

    public function get_set(string $key): array
    {
        return [];
    }

    public function get_settings(): array
    {
        return ['log_table' => 'bad_behaviour_test'];
    }

    public function get_whitelist(): array
    {
        return ['ip' => [], 'useragent' => [], 'url' => [], 'asn' => [], 'country' => []];
    }

    public function get_email(): string
    {
        return 'test@example.com';
    }

    public function get_relative_path(): string
    {
        return '/';
    }

    public function log_request(RequestPackage $package, Result $result): void
    {
        // no-op
    }

    /**
     * No-op probe — InMemoryAdapterStub has no real DB to query.
     * Returns the documented no-op shape so LogRetention falls through
     * to its time()-anchor cutoff without logging a spurious error.
     */
    public function probe_log_table(string $table_name): array
    {
    	return ['newest' => null, 'total' => 0, 'error' => null];
    }

    public function get_table_schema(string $table_name): string|array
    {
        return '';
    }

    public function query(string $sql): bool
    {
        return true;
    }

    public function get_geoip(string $ip): ?array
    {
        return null;
    }

    public function verify_challenge(string $response, string $remote_ip): bool
    {
        return false;
    }

    public function log(string $level, string $message, array $context = []): void
    {
        // no-op
    }
}