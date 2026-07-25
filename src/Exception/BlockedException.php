<?php

namespace BadBehaviour\Exception;

use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;

class BlockedException extends \RuntimeException
{
	private Result $result;

	public function __construct(Result $result)
	{
		$this->result = $result;
		parent::__construct($result->message, $result->http_status());
	}

	public function get_result(): Result
	{
		return $this->result;
	}

	public function get_code(): ResultCode
	{
		return $this->result->code;
	}

	public function get_package(): RequestPackage
	{
		return $this->result->package;
	}

	public function get_support_key(): ?string
	{
		return $this->result->support_key;
	}

	public static function from_result(Result $result): self
	{
		return new self($result);
	}
}
