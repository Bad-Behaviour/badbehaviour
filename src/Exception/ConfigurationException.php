<?php

namespace BadBehaviour\Exception;

class ConfigurationException extends \InvalidArgumentException
{
	private array $errors = [];

	public function __construct(string $message = '', array $errors = [], int $code = 0, ?\Throwable $previous = null)
	{
		$this->errors = $errors;
		parent::__construct($message, $code, $previous);
	}

	public function get_errors(): array
	{
		return $this->errors;
	}

	public function has_errors(): bool
	{
		return !empty($this->errors);
	}

	public static function missing_required(string $key): self
	{
		return new self(
			"Required configuration key missing: {$key}",
			['missing_key' => $key]
		);
	}

	public static function invalid_type(string $key, string $expected, string $actual): self
	{
		return new self(
			"Configuration key '{$key}' expects {$expected}, got {$actual}",
			['key' => $key, 'expected' => $expected, 'actual' => $actual]
		);
	}

	public static function invalid_value(string $key, string $reason): self
	{
		return new self(
			"Configuration key '{$key}' has invalid value: {$reason}",
			['key' => $key, 'reason' => $reason]
		);
	}

	public static function from_validation(array $errors): self
	{
		$messages = array_map(
			fn($e) => "{$e['key']}: {$e['message']}",
			$errors
		);

		return new self(
			'Configuration validation failed: ' . implode('; ', $messages),
			$errors
		);
	}
}
