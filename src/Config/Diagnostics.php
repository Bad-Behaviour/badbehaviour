<?php
declare(strict_types=1);

namespace BadBehaviour\Config;

/**
 * Collects diagnostics from the config pipeline.
 *
 * Held separately from Configuration because Configuration is a
 * readonly value object — it can't carry mutable state. Static
 * properties on readonly classes also can't have default values
 * (PHP 8.2+ restriction), so even collecting unknown keys inline
 * would require a constructor trick.
 *
 * Reset between tests via reset(). Production code rarely needs to
 * touch this; the primary consumer is bin/diagnose.php and the
 * schema-integrity test.
 */
final class Diagnostics
{
    /** @var array<string, string[]> dotted-key → list of values seen */
    private static array $unknown_keys_seen = [];

    /** @var array<string, mixed> arbitrary warnings collected during parsing */
    private static array $warnings = [];

    public static function record_unknown_key(string $dotted_key, mixed $value): void
    {
        self::$unknown_keys_seen[$dotted_key][] = $value;
    }

    public static function record_warning(string $code, string $message, array $context = []): void
    {
        self::$warnings[$code] = ['message' => $message, 'context' => $context];
    }

    /** @return array<string, string[]> */
    public static function unknown_keys(): array
    {
        return self::$unknown_keys_seen;
    }

    /** @return array<string, array{message: string, context: array}> */
    public static function warnings(): array
    {
        return self::$warnings;
    }

    public static function reset(): void
    {
        self::$unknown_keys_seen = [];
        self::$warnings = [];
    }

    private function __construct() {}
}
