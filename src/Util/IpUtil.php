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
			$ip_bin = @inet_pton($ip);
			$net_bin = @inet_pton($net);

			if ($ip_bin === false || $net_bin === false) {
				return false;
			}

			// Compare bit by bit up to mask length
			for ($i = 0; $i < $mask; $i++) {
				$byte_idx = $i >> 3;
				$bit_idx = 7 - ($i & 7);

				$ip_bit = (ord($ip_bin[$byte_idx]) >> $bit_idx) & 1;
				$net_bit = (ord($net_bin[$byte_idx]) >> $bit_idx) & 1;

				if ($ip_bit !== $net_bit) {
					return false;
				}
			}
			return true;
		}

		$mask = $mask ?: 32;
		$ip_long = ip2long($ip);
		$net_long = ip2long($net);
		$mask_long = -1 << (32 - $mask);
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
