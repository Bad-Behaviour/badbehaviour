<?php

namespace BadBehaviour\Util;

class ConfigUtil
{
    /**
     * Parse INI file with support for:
     * - Multi-line arrays: key[] = "value"
     * - Comma-separated: key = "val1, val2"
     * - Nested dot notation: section.sub.key = value
     */
    public static function parse_ini(string $file, bool $expand_dots = true): array
    {
        if (!file_exists($file)) {
            return [];
        }

        $raw = @parse_ini_file($file, true, INI_SCANNER_TYPED);
        if ($raw === false) {
            return [];
        }

        $result = [];

        foreach ($raw as $section => $values) {
            foreach ($values as $key => $value) {
                $full_key = $section . '.' . $key;

                // Handle array syntax: key[] = "val"
                if (str_ends_with($key, '[]')) {
                    $base_key = substr($full_key, 0, -2);
                    $result[$base_key][] = $value;
                    continue;
                }

                // Handle comma-separated strings
                if (is_string($value) && str_contains($value, ',') && !str_starts_with($value, '[')) {
                    $value = array_map('trim', explode(',', $value));
                }

                $result[$full_key] = $value;
            }
        }

        // Expand dot notation to nested arrays
        if ($expand_dots) {
            $result = self::expand_dot_notation($result);
        }

        return $result;
    }

    /**
     * Convert flat dot-notation keys to nested arrays
     * 'rate_limits.global.requests' => 1000
     * becomes ['rate_limits' => ['global' => ['requests' => 1000]]]
     */
    public static function expand_dot_notation(array $config): array
    {
        $nested = [];

        foreach ($config as $key => $value) {
            // Already nested (from PHP config or previous processing)
            if (is_array($value) && !self::is_sequential_array($value)) {
                $nested[$key] = $value;
                continue;
            }

            if (str_contains($key, '.')) {
                $parts = explode('.', $key);
                $target = &$nested;

                foreach ($parts as $i => $part) {
                    if (!isset($target[$part]) || !is_array($target[$part])) {
                        $target[$part] = [];
                    }

                    if ($i === count($parts) - 1) {
                        // Last part: assign value
                        $target[$part] = $value;
                    } else {
                        // Traverse deeper
                        $target = &$target[$part];
                    }
                }
            } else {
                $nested[$key] = $value;
            }
        }

        return $nested;
    }

    private static function is_sequential_array(array $arr): bool
    {
        return array_keys($arr) === range(0, count($arr) - 1);
    }

    /**
     * Merge config with defaults, preserving nested structure
     */
    public static function merge_with_defaults(array $config, array $defaults): array
    {
        return self::array_merge_recursive_distinct($defaults, $config);
    }

    /**
     * Recursive merge that doesn't re-index numeric arrays
     */
    private static function array_merge_recursive_distinct(array $a1, array $a2): array
    {
        $merged = $a1;

        foreach ($a2 as $key => $value) {
            if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
                $merged[$key] = self::array_merge_recursive_distinct($merged[$key], $value);
            } else {
                $merged[$key] = $value;
            }
        }

        return $merged;
    }
}
