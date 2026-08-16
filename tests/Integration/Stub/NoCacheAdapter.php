<?php
/**
 * Test stub: AdapterInterface that does NOT implement CacheInterface.
 *
 * Used to verify that on-demand refresh correctly reports "disabled"
 * when no cache backend is reachable. The default GenericAdapter
 * implements both interfaces, which makes it impossible to test the
 * "no cache available" branch with production adapters.
 */

declare(strict_types=1);

namespace BadBehaviour\Tests\Integration\Stub;

use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Util\RequestPackage;

class NoCacheAdapter implements AdapterInterface
{
	public function probe_log_table(string $table): array
	{
		return ['newest' => null, 'total' => 0, 'error' => null];
	}

    public function get_settings(): array
    {
        return [
            'log_table' => 'stub_table',
        ];
    }

    public function get_whitelist(): array
    {
        return ['ip' => [], 'useragent' => [], 'url' => [], 'asn' => [], 'country' => []];
    }

    public function get_email(): string
    {
        return 'stub@example.com';
    }

    public function get_relative_path(): string
    {
        return '/';
    }

    public function get_table_schema(string $table_name): string
    {
        return "CREATE TABLE stub (id INT)";
    }

    public function log_request(RequestPackage $package, Result $result): void
    {
        // no-op
    }

    public function query(string $sql): bool
    {
        return true;
    }

    public function increment_counter(string $key, int $window_seconds): int
    {
        return 1;
    }

    public function get_counter(string $key): int
    {
        return 0;
    }

    public function delete(string $key): bool
    {
        return true;
    }

    public function get_behavior_profile(string $session_id): ?array
    {
        return null;
    }

    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
    {
        return true;
    }

    public function add_to_set(string $key, string $value, int $ttl): bool
    {
        return true;
    }

    public function get_set(string $key): array
    {
        return [];
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