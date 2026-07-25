<?php

namespace BadBehaviour\Core\Interfaces;

interface CacheInterface
{
	public function get(string $key): mixed;
	public function set(string $key, mixed $value, int $ttl): bool;
	public function delete(string $key): bool;
	public function increment_counter(string $key, int $window): int;
	public function get_counter(string $key): int;
	public function get_set(string $key): array;
	public function add_to_set(string $key, string $value, int $ttl): bool;
}

