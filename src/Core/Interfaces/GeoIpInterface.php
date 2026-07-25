<?php

namespace BadBehaviour\Core\Interfaces;

interface GeoIpInterface
{
	/**
	 * @return array{country?: string, asn?: string, city?: string, isp?: string}|null
	 */
	public function lookup(string $ip): ?array;
}
