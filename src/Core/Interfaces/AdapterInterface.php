<?php

namespace BadBehaviour\Core\Interfaces;

use BadBehaviour\Core\Result;
use BadBehaviour\Util\RequestPackage;

interface AdapterInterface
{
	// Configuration
	public function get_settings(): array;
	public function get_whitelist(): array;
	public function get_email(): string;
	public function get_relative_path(): string;

	// Database / Storage
	public function log_request(RequestPackage $package, Result $result): void;
	public function get_table_schema(string $table_name): string|array;

	// Cache / Rate Limiting
	public function increment_counter(string $key, int $window_seconds): int;
	public function get_counter(string $key): int;
	public function delete(string $key): bool;

	// Behavioral Storage
	public function get_behavior_profile(string $session_id): ?array;
	public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool;

	// Set Operations (JA3, etc.)
	public function add_to_set(string $key, string $value, int $ttl): bool;
	public function get_set(string $key): array;

	// GeoIP
	public function get_geoip(string $ip): ?array;

	// Challenge
	public function verify_challenge(string $response, string $remote_ip): bool;

	// Logging
	public function log(string $level, string $message, array $context = []): void;
}
