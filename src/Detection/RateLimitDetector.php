<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;

class RateLimitDetector
{
	private Configuration $config;
	private AdapterInterface $adapter;

	public function __construct(Configuration $config, AdapterInterface $adapter)
	{
		$this->config = $config;
		$this->adapter = $adapter;
	}

	public function detect(RequestPackage $package): ?Result
	{
		if (!$this->config->rate_limit_enabled) {
			return null;
		}

		$ip = $package->ip;
		$method = $package->request_method;
		$uri = $package->request_uri;

		$limits = $this->config->rate_limits;

		// Always check global and per_minute
		$applicable = ['global', 'per_minute'];

		// Check post limit on POST requests
		if ($method === 'POST') {
			$applicable[] = 'post';
		}

		// Check login limit ONLY on login URLs
		if (preg_match('/(login|signin|auth|password)/i', $uri)) {
			$applicable[] = 'login';
		}

		foreach ($applicable as $name) {
			if (!isset($limits[$name])) continue;

			$limit = $limits[$name];
			$key = "ratelimit:$name:$ip";
			$count = $this->adapter->increment_counter($key, $limit['window']);

			if ($count > $limit['requests']) {
				return Result::block(ResultCode::BLOCKED_RATE_LIMIT, "Rate limit exceeded: $name", $package, [
					'limit_name' => $name,
					'limit' => $limit['requests'],
					'window' => $limit['window'],
					'current' => $count,
				]);
			}
		}

		return null;
	}
}
