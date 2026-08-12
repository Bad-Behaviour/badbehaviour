<?php

namespace BadBehaviour\Util;

class IpUtil
{
	public static function normalize(string $ip): string
	{
		return preg_replace('/^::ffff:/', '', $ip);
	}

	public static function is_ipv6(string $ip): bool
	{
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			return true;
		}
		return str_starts_with($ip, '::ffff:');
	}

	public static function is_private(string $ip): bool
	{
		$ip = self::normalize($ip);
		$is_v6 = self::is_ipv6($ip);

		if ($is_v6) {
			$ranges = ['fc00::/7', 'fe80::/10', '::1/128', '2001:db8::/32', '::ffff:0:0/96', '::/128'];
		} else {
			$ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10'];
		}

		foreach ($ranges as $range) {
			if (self::match_cidr($ip, $range)) {
				return true;
			}
		}
		return false;
	}

	public static function match_cidr(string $ip, string $cidr): bool
	{
		$ip = self::normalize($ip);
		if (strpos($cidr, '/') === false) {
			$cidr .= self::is_ipv6($ip) ? '/128' : '/32';
		}

		[$net, $mask] = explode('/', $cidr);
		$net = self::normalize($net);
		$mask = (int)$mask;

		if (self::is_ipv6($net) !== self::is_ipv6($ip)) {
			return false;
		}

		if (self::is_ipv6($ip)) {
			// IPv6 logic (already correct)
			$ip_bin = @inet_pton($ip);
			$net_bin = @inet_pton($net);
			if ($ip_bin === false || $net_bin === false) return false;

			for ($i = 0; $i < $mask; $i++) {
				$byte_idx = $i >> 3;
				$bit_idx = 7 - ($i & 7);
				if ((ord($ip_bin[$byte_idx]) >> $bit_idx & 1) !== (ord($net_bin[$byte_idx]) >> $bit_idx & 1)) {
					return false;
				}
			}
			return true;
		}

		// IPv4 — FIX: handle 64-bit signed integer issue
		$mask = $mask ?: 32;
		$ip_long = ip2long($ip);
		$net_long = ip2long($net);

		if ($ip_long === false || $net_long === false) {
			return false;
		}

		// Convert to unsigned 32-bit to avoid negative number issues
		$ip_long = $ip_long & 0xFFFFFFFF;
		$net_long = $net_long & 0xFFFFFFFF;
		$mask_long = $mask === 0 ? 0 : ((0xFFFFFFFF << (32 - $mask)) & 0xFFFFFFFF);

		return ($ip_long & $mask_long) === ($net_long & $mask_long);
	}

	public static function match_any(string $ip, array $cidrs): bool
	{
		foreach ($cidrs as $cidr) {
			if (self::match_cidr($ip, $cidr)) {
				return true;
			}
		}
		return false;
	}
}
