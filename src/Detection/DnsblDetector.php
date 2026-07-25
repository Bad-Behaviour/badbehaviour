<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\IpUtil;  // ADD THIS IMPORT

class DnsblDetector
{
	private Configuration $config;

	public function __construct(Configuration $config)
	{
		$this->config = $config;
	}

	public function detect(RequestPackage $package): ?Result
	{
		if (IpUtil::is_ipv6($package->ip)) {
			return null; // DNSBL typically IPv4 only
		}

		$ip = $package->ip;
		$reversed = implode('.', array_reverse(explode('.', $ip)));

		// http:BL
		if (!empty($this->config->httpbl_key)) {
			$key = $this->config->httpbl_key;
			$lookup = "{$key}.{$reversed}.dnsbl.httpbl.org.";

			$result = @gethostbynamel($lookup);
			if (!empty($result)) {
				$parts = explode('.', $result[0]);
				if (count($parts) === 4 && $parts[0] === '127') {
					$activity = (int)$parts[1];
					$threat = (int)$parts[2];
					$type = (int)$parts[3];

					$max_age = $this->config->httpbl_maxage;
					$threat_threshold = $this->config->httpbl_threat;

					if ($type === 0) {
						return null; // Search engine - whitelisted
					}

					if ($activity <= $max_age && $threat >= $threat_threshold) {
						return Result::block(ResultCode::BLOCKED_HTTPBL, 'http:BL match', $package, [
							'activity' => $activity,
							'threat' => $threat,
							'type' => $type,
						]);
					}
				}
			}
		}

		// Additional DNSBL lists
		$lists = $this->config->dnsbl_lists ?? ['zen.spamhaus.org', 'bl.spamcop.net'];

		foreach ($lists as $list) {
			$lookup = $reversed . '.' . $list;
			$result = @gethostbynamel($lookup);

			if (!empty($result)) {
				foreach ($result as $r) {
					if (str_starts_with($r, '127.0.0.')) {
						$code = (int)explode('.', $r)[3];
						$skip = [1, 2, 3, 4, 5, 6, 7]; // Common false positives
						if (!in_array($code, $skip, true)) {
							return Result::block(ResultCode::BLOCKED_DNSBL, "DNSBL match: $list", $package, [
								'list' => $list,
								'code' => $code,
							]);
						}
					}
				}
			}
		}

		return null;
	}
}
