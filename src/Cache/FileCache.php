<?php
// src/Cache/FileCache.php

namespace BadBehaviour\Cache;

use BadBehaviour\Core\Interfaces\CacheInterface;

class FileCache implements CacheInterface
{
    private string $cache_dir;
    private int $cleanup_probability = 10; // 10% chance on write

    public function __construct(?string $cache_dir = null)
    {
        $this->cache_dir = $cache_dir ?? sys_get_temp_dir() . '/badbehaviour_cache';

        if (!is_dir($this->cache_dir)) {
            @mkdir($this->cache_dir, 0755, true);
        }

        // Register shutdown cleanup
        register_shutdown_function([$this, 'cleanup_expired']);
    }

    private function file(string $key): string
    {
        // Sanitize key for filesystem
        $safe = preg_replace('/[^a-zA-Z0-9_:.-]/', '_', $key);
        return $this->cache_dir . '/' . $safe . '.cache';
    }

    public function get(string $key): mixed
    {
        $file = $this->file($key);

        if (!file_exists($file)) {
            return null;
        }

        $data = @file_get_contents($file);
        if ($data === false) {
            return null;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded) || !isset($decoded['value'], $decoded['expires'])) {
            @unlink($file);
            return null;
        }

        // Check expiration
        if ($decoded['expires'] < time()) {
            @unlink($file);
            return null;
        }

        return $decoded['value'];
    }

    public function set(string $key, mixed $value, int $ttl): bool
    {
        $file = $this->file($key);
        $data = [
            'value' => $value,
            'expires' => time() + $ttl,
            'created' => time(),
        ];

        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return false;
        }

        $result = @file_put_contents($file, $json, LOCK_EX);

        // Probabilistic cleanup
        if (mt_rand(1, 100) <= $this->cleanup_probability) {
            $this->cleanup_expired();
        }

        return $result !== false;
    }

    public function delete(string $key): bool
    {
        $file = $this->file($key);
        return @unlink($file);
    }

    public function increment_counter(string $key, int $window): int
    {
        $file = $this->file("counter:$key");
        $now = time();
        $window_start = $now - $window;

        $data = ['count' => 0, 'window' => $window_start];

        if (file_exists($file)) {
            $json = @file_get_contents($file);
            $decoded = $json ? json_decode($json, true) : null;

            if ($decoded && isset($decoded['count'], $decoded['window'])) {
                if ($decoded['window'] >= $window_start) {
                    $data = $decoded;
                }
            }
        }

        $data['count']++;
        @file_put_contents($file, json_encode($data), LOCK_EX);

        return $data['count'];
    }

    public function get_counter(string $key): int
    {
        $file = $this->file("counter:$key");

        if (!file_exists($file)) {
            return 0;
        }

        $json = @file_get_contents($file);
        $decoded = $json ? json_decode($json, true) : null;

        return $decoded['count'] ?? 0;
    }

    public function get_behavior_profile(string $session_id): ?array
    {
        return $this->get("behavior:$session_id");
    }

    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool
    {
        $profile['_expires'] = time() + $ttl;
        return $this->set("behavior:$session_id", $profile, $ttl);
    }

    public function add_to_set(string $key, string $value, int $ttl): bool
    {
        $file = $this->file("set:$key");
        $set = [];

        if (file_exists($file)) {
            $json = @file_get_contents($file);
            $decoded = $json ? json_decode($json, true) : null;

            if (is_array($decoded)) {
                $now = time();
                // Filter expired entries
                foreach ($decoded as $v => $exp) {
                    if ($exp > $now) {
                        $set[$v] = $exp;
                    }
                }
            }
        }

        $set[$value] = time() + $ttl;
        return @file_put_contents($file, json_encode($set), LOCK_EX) !== false;
    }

    public function get_set(string $key): array
    {
        $file = $this->file("set:$key");

        if (!file_exists($file)) {
            return [];
        }

        $json = @file_get_contents($file);
        $decoded = $json ? json_decode($json, true) : null;

        if (!is_array($decoded)) {
            return [];
        }

        $now = time();
        $valid = [];

        foreach ($decoded as $value => $expires) {
            if ($expires > $now) {
                $valid[$value] = $expires;
            }
        }

        // Clean up expired entries
        if (count($valid) !== count($decoded)) {
            @file_put_contents($file, json_encode($valid), LOCK_EX);
        }

        return array_keys($valid);
    }

    public function cleanup_expired(): void
    {
        $now = time();
        $files = glob($this->cache_dir . '/*.cache');

        if ($files === false) return;

        foreach ($files as $file) {
            $json = @file_get_contents($file);
            $decoded = $json ? json_decode($json, true) : null;

            if (!$decoded || !isset($decoded['expires']) || $decoded['expires'] < $now) {
                @unlink($file);
            }
        }
    }
}
