<?php
declare(strict_types=1);

namespace BadBehaviour\Tests\Fixtures\Stubs;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Core\Interfaces\CacheInterface;
use BadBehaviour\Core\Result;
use BadBehaviour\Util\RequestPackage;

/**
 * Minimal adapter stub for LogRetention tests.
 *
 * Implements AdapterInterface + CacheInterface with in-memory state:
 *   - query() appends to $queryLog and returns configurable success
 *   - probe_log_table() returns the configured newest/total/error
 *   - cache get/set/delete works against an in-memory array
 *   - get_settings() returns the configured log_table
 *
 * Tests can assert on $adapter->queryLog to verify DELETE statements
 * were issued with the expected shape.
 */
class RetentionTestAdapter implements AdapterInterface, CacheInterface
{
	public int $rowsAffectedPerQuery = 0;

    /** @var string[] SQL statements passed to query() */
    public array $queryLog = [];

    /** Configurable: should query() return true (success) or false (failure)? */
    public bool $queryReturnsTrue = true;

    /** @var array<string, mixed> In-memory cache store */
    private array $cacheStore = [];

    public function __construct(
    	private string $logTable = 'bad_behaviour',
    	private int|string|null $probeNewest = null,
    	private int $probeTotal = 0,
    	private ?string $probeError = null,
    ) {}

    // AdapterInterface — minimal stubs

    public function get_settings(): array
    {
        return ['log_table' => $this->logTable];
    }

    public function get_whitelist(): array
    {
        return ['ip' => [], 'useragent' => [], 'url' => [], 'asn' => [], 'country' => []];
    }

    public function get_email(): string { return 'test@example.com'; }
    public function get_relative_path(): string { return '/'; }
    public function get_table_schema(string $table_name): string { return ''; }
    public function log_request(RequestPackage $package, Result $result): void {}

    public function query(string $sql): bool
    {
    	$this->queryLog[] = $sql;
    	return $this->queryReturnsTrue;
    }

    /**
     * Test hook: how many rows did the most recent query() affect?
     * LogRetention uses this to track actual deletion progress instead
     * of guessing chunk_size on every iteration.
     */
    public function lastQueryAffectedRows(): int
    {
    	return $this->rowsAffectedPerQuery;
    }

    public function increment_counter(string $key, int $window): int { return 1; }
    public function get_counter(string $key): int { return 0; }
    public function get_behavior_profile(string $session_id): ?array { return null; }
    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool { return true; }
    public function add_to_set(string $key, string $value, int $ttl): bool { return true; }
    public function get_set(string $key): array { return []; }
    public function get_geoip(string $ip): ?array { return null; }
    public function verify_challenge(string $response, string $remote_ip): bool { return false; }

    public function log(string $level, string $message, array $context = []): void {}

    // Optional probe method — adapters opt in
    public function probe_log_table(string $table): array
    {
        return [
            'newest' => $this->probeNewest,
            'total'  => $this->probeTotal,
            'error'  => $this->probeError,
        ];
    }

    // CacheInterface — in-memory store

    public function get(string $key): mixed
    {
        if (!isset($this->cacheStore[$key])) {
            return null;
        }
        [$value, $expires] = $this->cacheStore[$key];
        if ($expires > 0 && $expires < time()) {
            unset($this->cacheStore[$key]);
            return null;
        }
        return $value;
    }

    public function set(string $key, mixed $value, int $ttl): bool
    {
        $this->cacheStore[$key] = [$value, $ttl > 0 ? time() + $ttl : 0];
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->cacheStore[$key]);
        return true;
    }

    // Test helpers

    public function seedCache(string $key, mixed $value, int $ttl = 0): void
    {
        $this->cacheStore[$key] = [$value, $ttl > 0 ? time() + $ttl : 0];
    }

    public function cacheHas(string $key): bool
    {
        return isset($this->cacheStore[$key]);
    }
}