<?php

namespace BadBehaviour\Exception;

use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;

class ChallengeRequiredException extends \RuntimeException
{
	private Result $result;

	public function __construct(Result $result)
	{
		$this->result = $result;
		parent::__construct($result->message, 403);
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

	public function get_challenge_html(string $action_url): string
	{
		$challenge = $this->create_challenge();
		return $challenge->render($action_url);
	}

	private function create_challenge(): \BadBehaviour\Challenge\ChallengeInterface
	{
		$config = \BadBehaviour\Configuration::from_array([]);
		$adapter = new \BadBehaviour\Adapter\GenericAdapter();

		return match($this->result->metadata['challenge_provider'] ?? 'builtin') {
			'hcaptcha'    => new \BadBehaviour\Challenge\HCaptchaChallenge($config),
			'recaptcha'   => new \BadBehaviour\Challenge\RecaptchaChallenge($config),
			'turnstile'   => new \BadBehaviour\Challenge\TurnstileChallenge($config),
			default       => new \BadBehaviour\Challenge\BuiltinChallenge($config, $adapter),
		};
	}

	public static function from_result(Result $result): self
	{
		return new self($result);
	}
}
