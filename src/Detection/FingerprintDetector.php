<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\HeaderUtil;

class FingerprintDetector
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
		$ua = $package->user_agent;

		// JA3 TLS Fingerprint - ONLY block known bad fingerprints
		if ($package->ja3) {
			$ja3 = $package->ja3;

			// Known bad JA3s from config
			$bad_ja3s = $this->config->bad_ja3_fingerprints ?? [];
			if (in_array($ja3, $bad_ja3s, true)) {
				return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Known bad JA3 fingerprint', $package, [
					'type' => 'ja3_bad',
					'ja3' => $ja3,
				]);
			}

			// Track JA3 for this IP (for analysis)
			$this->adapter->add_to_set("ja3:{$package->ip}", $ja3, 86400);
		}

		// HTTP/2 Settings Fingerprint - ONLY block known bad
		if ($package->h2_settings) {
			$h2_hash = substr(hash('sha256', $package->h2_settings), 0, 16);
			$bad_h2 = $this->config->bad_h2_fingerprints ?? [];
			if (in_array($h2_hash, $bad_h2, true)) {
				return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Known bad HTTP/2 fingerprint', $package, [
					'type' => 'h2_bad',
					'h2_hash' => $h2_hash,
				]);
			}
		}

		// Header Order Fingerprint - ONLY block known bad bot orders
		$header_order = array_keys($package->headers_mixed);
		$order_hash = substr(hash('sha256', implode(',', $header_order)), 0, 16);

		$bot_orders = $this->config->bot_header_orders ?? [];
		if (in_array($order_hash, $bot_orders, true)) {
			return Result::block(ResultCode::BLOCKED_FINGERPRINT, 'Known bot header order', $package, [
				'type' => 'header_order_bot',
				'order_hash' => $order_hash,
			]);
		}

		return null;
	}
}