<?php

namespace BadBehaviour\Util;

class UaParser
{
	private static array $browser_patterns = [
		'edge'        => ['/Edg\/(\d+(?:\.\d+)*)/i', '/EdgA\/(\d+(?:\.\d+)*)/i', '/EdgiOS\/(\d+(?:\.\d+)*)/i'],
		'opera'      => ['/OPR\/(\d+(?:\.\d+)*)/i', '/Opera\/(\d+(?:\.\d+)*)/i', '/OPT\/(\d+(?:\.\d+)*)/i'],
		'brave'       => ['/Brave\/(\d+(?:\.\d+)*)/i'],
		'vivaldi'     => ['/Vivaldi\/(\d+(?:\.\d+)*)/i'],
		'samsung'     => ['/SamsungBrowser\/(\d+(?:\.\d+)*)/i'],
		'ucbrowser'   => ['/UCBrowser\/(\d+(?:\.\d+)*)/i'],
		'chrome'      => ['/Chrome\/(\d+(?:\.\d+)*)/i', '/CriOS\/(\d+(?:\.\d+)*)/i'],
		'firefox'     => ['/Firefox\/(\d+(?:\.\d+)*)/i', '/FxiOS\/(\d+(?:\.\d+)*)/i'],
		'safari'      => ['/Version\/(\d+(?:\.\d+)*)/i'],
		'chromium'    => ['/Chromium\/(\d+(?:\.\d+)*)/i'],
		'ie'          => ['/MSIE (\d+(?:\.\d+)*)/i', '/Trident\/.*rv:(\d+(?:\.\d+)*)/i'],
	];

	private static array $os_patterns = [
		'windows'     => ['/Windows NT ([\d.]+)/i'],
		'macos'       => ['/Mac OS X ([\d_]+)/i', '/macOS ([\d.]+)/i'],
		'linux'       => ['/Linux/i'],
		'android'     => ['/Android ([\d.]+)/i'],
		'ios'         => ['/iPhone OS ([\d_]+)/i', '/iPad.*OS ([\d_]+)/i', '/iOS ([\d.]+)/i'],
		'freebsd'     => ['/FreeBSD/i'],
		'openbsd'     => ['/OpenBSD/i'],
		'netbsd'      => ['/NetBSD/i'],
		'sunos'       => ['/SunOS/i'],
	];

	private static array $device_patterns = [
		'bot'         => [
			'/bot/i', '/crawler/i', '/spider/i', '/scraper/i',
			'/headless/i', '/puppeteer/i', '/playwright/i',
			'/selenium/i', '/phantomjs/i'
		],
		'http_tool'   => [
			'/^curl\//i', '/^wget\//i', '/^python-requests\//i',
			'/^go-http-client\//i', '/^java\//i', '/^okhttp\//i',
			'/^apache-httpclient\//i', '/^axios\//i', '/^node-fetch\//i'
		],
		'mobile'      => ['/Mobile/i', '/Android.*Mobile/i', '/iPhone/i', '/iPod/i'],
		'tablet'      => ['/iPad/i', '/Android.*(?!Mobile)/i', '/Tablet/i'],
		'desktop'     => ['/Windows NT/i', '/Macintosh/i', '/X11/i', '/Linux/i'],
	];

	private static array $engine_patterns = [
		'blink'       => ['/Chrome/i', '/Chromium/i', '/OPR/i', '/Edg/i', '/Brave/i', '/Vivaldi/i', '/SamsungBrowser/i', '/UCBrowser/i', '/CriOS/i'],
		'webkit'      => ['/AppleWebKit/i', '/Version\/[\d.]+.*Safari/i'],
		'gecko'       => ['/Firefox/i', '/Gecko/i', '/FxiOS/i'],
		'trident'     => ['/Trident/i', '/MSIE/i'],
		'presto'      => ['/Presto/i'],
	];

	public static function parse(string $ua): array
	{
		$result = [
			'browser'  => ['name' => 'Unknown', 'version' => null, 'major' => null],
			'os'       => ['name' => 'Unknown', 'version' => null],
			'device'   => ['type' => 'desktop', 'is_mobile' => false, 'is_tablet' => false, 'is_bot' => false, 'is_http_tool' => false],
			'engine'   => ['name' => 'Unknown'],
			'raw'      => $ua,
		];

		// Browser - check in order (Edge before Chrome, etc.)
		foreach (self::$browser_patterns as $name => $patterns) {
			foreach ($patterns as $pattern) {
				if (preg_match($pattern, $ua, $matches)) {
					$version = $matches[1] ?? null;
					$result['browser'] = [
						'name'    => self::normalize_browser_name($name),
						'version' => $version,
						'major'   => $version ? (int)explode('.', $version)[0] : null,
					];
					break 2;
				}
			}
		}

		// OS
		foreach (self::$os_patterns as $name => $patterns) {
			foreach ($patterns as $pattern) {
				if (preg_match($pattern, $ua, $matches)) {
					$version = $matches[1] ?? null;
					if ($version !== null) {
						$version = str_replace('_', '.', $version);
					}
					$result['os'] = [
						'name'    => self::normalize_os_name($name),
						'version' => $version,
					];
					break 2;
				}
			}
		}

		// Device - check bot FIRST, then http_tool
		$is_mobile = false;
		$is_tablet = false;
		$is_bot = false;
		$is_http_tool = false;

		foreach (self::$device_patterns as $type => $patterns) {
			foreach ($patterns as $pattern) {
				if (preg_match($pattern, $ua)) {
					switch ($type) {
						case 'mobile':
							$is_mobile = true;
							break;
						case 'tablet':
							$is_tablet = true;
							break;
						case 'bot':
							$is_bot = true;
							break;
						case 'http_tool':
							$is_http_tool = true;
							break;
					}
				}
			}
		}

		if ($is_bot) {
			$result['device']['type'] = 'bot';
		} elseif ($is_http_tool) {
			$result['device']['type'] = 'http_tool';
		} elseif ($is_tablet) {
			$result['device']['type'] = 'tablet';
		} elseif ($is_mobile) {
			$result['device']['type'] = 'mobile';
		}

		$result['device']['is_mobile'] = $is_mobile;
		$result['device']['is_tablet'] = $is_tablet;
		$result['device']['is_bot'] = $is_bot;
		$result['device']['is_http_tool'] = $is_http_tool;

		// Engine - Blink first for Chrome/Edge
		foreach (self::$engine_patterns as $name => $patterns) {
			foreach ($patterns as $pattern) {
				if (preg_match($pattern, $ua)) {
					$result['engine']['name'] = $name;
					break 2;
				}
			}
		}

		return $result;
	}

	public static function is_bot(string $ua): bool
	{
		$parsed = self::parse($ua);
		return $parsed['device']['is_bot'];
	}

	public static function is_http_tool(string $ua): bool
	{
		$parsed = self::parse($ua);
		return $parsed['device']['is_http_tool'];
	}

	public static function is_mobile(string $ua): bool
	{
		$parsed = self::parse($ua);
		return $parsed['device']['is_mobile'];
	}

	public static function is_tablet(string $ua): bool
	{
		$parsed = self::parse($ua);
		return $parsed['device']['is_tablet'];
	}

	public static function get_browser_name(string $ua): string
	{
		return self::parse($ua)['browser']['name'];
	}

	public static function get_browser_version(string $ua): ?string
	{
		return self::parse($ua)['browser']['version'];
	}

	public static function get_browser_major(string $ua): ?int
	{
		return self::parse($ua)['browser']['major'];
	}

	public static function get_os_name(string $ua): string
	{
		return self::parse($ua)['os']['name'];
	}

	public static function get_os_version(string $ua): ?string
	{
		return self::parse($ua)['os']['version'];
	}

	public static function get_device_type(string $ua): string
	{
		return self::parse($ua)['device']['type'];
	}

	public static function get_engine(string $ua): string
	{
		return self::parse($ua)['engine']['name'];
	}

	private static function normalize_browser_name(string $name): string
	{
		return match($name) {
			'chrome'      => 'Chrome',
			'firefox'     => 'Firefox',
			'safari'      => 'Safari',
			'edge'        => 'Edge',
			'opera'       => 'Opera',
			'ie'          => 'Internet Explorer',
			'samsung'     => 'Samsung Internet',
			'ucbrowser'   => 'UC Browser',
			'vivaldi'     => 'Vivaldi',
			'brave'       => 'Brave',
			'chromium'    => 'Chromium',
			default       => ucfirst($name),
		};
	}

	private static function normalize_os_name(string $name): string
	{
		return match($name) {
			'windows' => 'Windows',
			'macos'   => 'macOS',
			'linux'   => 'Linux',
			'android' => 'Android',
			'ios'     => 'iOS',
			'freebsd' => 'FreeBSD',
			'openbsd' => 'OpenBSD',
			'netbsd'  => 'NetBSD',
			'sunos'   => 'Solaris',
			default   => ucfirst($name),
		};
	}

	public static function matches_bot_registry(string $ua, array $patterns): bool
	{
		$ua_lower = strtolower($ua);
		foreach ($patterns as $pattern) {
			if (stripos($ua_lower, strtolower($pattern)) !== false) {
				return true;
			}
		}
		return false;
	}

	public static function extract_version(string $ua, string $browser): ?string
	{
		$patterns = [
			'chrome'   => '/Chrome\/(\d+(?:\.\d+)*)/i',
			'firefox'  => '/Firefox\/(\d+(?:\.\d+)*)/i',
			'safari'   => '/Version\/(\d+(?:\.\d+)*)/i',
			'edge'     => '/Edg\/(\d+(?:\.\d+)*)/i',
			'opera'    => '/OPR\/(\d+(?:\.\d+)*)/i',
			'ie'       => ['/MSIE (\d+(?:\.\d+)*)/i', '/rv:(\d+(?:\.\d+)*)/i'],
		];

		$browser_patterns = $patterns[$browser] ?? [];
		if (!is_array($browser_patterns)) {
			$browser_patterns = [$browser_patterns];
		}

		foreach ($browser_patterns as $pattern) {
			if (preg_match($pattern, $ua, $matches)) {
				return $matches[1];
			}
		}

		return null;
	}
}
