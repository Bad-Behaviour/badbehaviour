<?php

namespace BadBehaviour\Core;

use BadBehaviour\Util\RequestPackage;

readonly class Result
{
	public function __construct(
		public ResultCode $code,
		public string $message = '',
		public ?RequestPackage $package = null,
		public array $metadata = [],
		public ?string $support_key = null,
	) {}

	public static function allow(?RequestPackage $package = null): self
	{
		return new self(ResultCode::ALLOWED, 'Request allowed', $package);
	}

	public static function block(ResultCode $code, string $message, RequestPackage $package, array $metadata = []): self
	{
		return new self($code, $message, $package, $metadata, self::generate_support_key($package));
	}

	public static function challenge(ResultCode $code, string $message, RequestPackage $package, array $metadata = []): self
	{
		return new self($code, $message, $package, $metadata, self::generate_support_key($package));
	}

	public function is_allowed(): bool
	{
		return $this->code === ResultCode::ALLOWED;
	}

	public function is_blocked(): bool
	{
		return $this->code->is_blocked();
	}

	public function requires_challenge(): bool
	{
		return $this->code->requires_challenge();
	}

	public function http_status(): int
	{
		return $this->code->http_status();
	}

	public function to_array(): array
	{
		return [
			'code'         => $this->code->value,
			'message'      => $this->message,
			'support_key'  => $this->support_key,
			'http_status'  => $this->http_status(),
			'metadata'     => $this->metadata,
		];
	}

	public function get_package(): ?RequestPackage
	{
		return $this->package;
	}

	private static function generate_support_key(RequestPackage $package): string
	{
		$ip_parts = explode('.', $package->ip);
		$ip_hex = '';
		foreach ($ip_parts as $octet) {
			$ip_hex .= str_pad(dechex((int)$octet), 2, '0', STR_PAD_LEFT);
		}
		$key_part = substr(hash('sha256', $package->user_agent . $package->request_uri), 0, 8);
		return implode('-', str_split($ip_hex . $key_part, 4));
	}
}
