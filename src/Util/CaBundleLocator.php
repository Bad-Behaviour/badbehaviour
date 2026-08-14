<?php

declare(strict_types=1);

namespace BadBehaviour\Util;

/**
 * Locate a CA bundle for TLS verification.
 *
 * Both cURL-based and `file_get_contents`-based fetchers in BadBehaviour
 * need to pin a CA bundle explicitly when the PHP runtime's default
 * `openssl.cafile` points at a non-existent path (common on Homebrew,
 * macOS, and custom-compiled PHP installs).
 *
 * === WHY THIS EXISTS ===
 *
 * PHP's default CA file resolution is unreliable across platforms:
 *   - Debian/Ubuntu:  /etc/ssl/certs/ca-certificates.crt
 *   - RHEL/CentOS:     /etc/pki/tls/certs/ca-bundle.crt
 *   - OpenSUSE:        /etc/ssl/ca-bundle.pem
 *   - Homebrew x86_64: /usr/local/etc/openssl@1.1/cert.pem
 *   - Homebrew ARM64:  /opt/homebrew/etc/openssl@3/cert.pem
 *   - Alpine:          /etc/ssl/cert.pem
 *
 * Plus the ini setting `openssl.cafile` and `openssl.capath`. If none
 * exist, TLS verification silently fails — `file_get_contents` returns
 * false and the caller has no way to distinguish "feed is down" from
 * "feed URL unreachable due to TLS".
 *
 * Without an explicit CA bundle, cURL on some builds defaults to
 * `verify_peer = true` with no bundle and rejects all HTTPS; on other
 * builds it silently disables verification. `file_get_contents` with
 * `verify_peer = true` and no `cafile` simply fails.
 *
 * === BEHAVIOR ===
 *
 * Probes the candidate paths in order. Returns the FIRST existing,
 * readable path. Caches the result process-locally so repeated lookups
 * (every fetch) don't hit the filesystem.
 *
 * === USAGE ===
 *
 * ```php
 * $ca = CaBundleLocator::find();
 * if ($ca !== null) {
 *     curl_setopt($ch, CURLOPT_CAINFO, $ca);
 * }
 * ```
 *
 * Or with stream_context_create:
 *
 * ```php
 * $ctx = stream_context_create([
 *     'ssl' => ['cafile' => CaBundleLocator::find(), 'verify_peer' => true],
 * ]);
 * ```
 */
final class CaBundleLocator
{
	/**
	 * Probed candidate paths in priority order.
	 *
	 * Listed before the ini-setting fallback because the ini setting
	 * is more often wrong than right (operators rarely set it; it's
	 * inherited from the OS package's default php.ini which may not
	 * match the actual install layout).
	 */
	private const CANDIDATE_PATHS = [
		'/etc/ssl/certs/ca-certificates.crt',      // Debian, Ubuntu, Alpine
		'/etc/pki/tls/certs/ca-bundle.crt',        // RHEL, CentOS, Fedora
		'/etc/ssl/ca-bundle.pem',                  // OpenSUSE
		'/etc/ssl/cert.pem',                       // Alpine (alternative)
		'/usr/local/etc/openssl/cert.pem',         // Homebrew default
		'/usr/local/etc/openssl@1.1/cert.pem',     // Homebrew openssl@1.1
		'/usr/local/etc/openssl@3/cert.pem',       // Homebrew openssl@3
		'/opt/homebrew/etc/openssl@3/cert.pem',    // Apple Silicon Homebrew
		__DIR__ . '/../../cacert.pem',             // BadBehaviour-shipped fallback
	];

	/**
	 * Process-local cache of the resolved path.
	 *
	 * Sentinel values:
	 *   - string path:    a CA bundle was found at this path
	 *   - null:           probed and no CA bundle exists (cached miss)
	 *
	 * The miss is cached too so we don't re-probe on every fetch. To
	 * force a re-probe (e.g., after installing a CA bundle mid-process),
	 * call reset_cache().
	 */
	private static ?string $cache = null;
	private static bool $probed = false;

	/**
	 * Locate a CA bundle on the local filesystem.
	 *
	 * Returns the absolute path to a readable CA bundle file or
	 * directory, or null if no candidate exists. The result is cached
	 * process-locally; subsequent calls are O(1).
	 *
	 * The returned path may be either:
	 *   - a file path (single PEM bundle) — use as `cafile`
	 *   - a directory path (hashed cert symlinks, Debian-style) —
	 *     use as `capath`
	 *
	 * Callers should distinguish via `is_dir()`.
	 */
	public static function find(): ?string
	{
		if (self::$probed) {
			return self::$cache;
		}

		foreach (self::CANDIDATE_PATHS as $path) {
			if (is_string($path) && $path !== '' && file_exists($path) && is_readable($path)) {
				self::$cache = $path;
				self::$probed = true;
				return $path;
			}
		}

		// Fallback to PHP's ini setting. This catches custom-compiled
		// PHP installs that bundle their own CA bundle somewhere unusual.
		$ini_cafile = ini_get('openssl.cafile');
		if (is_string($ini_cafile) && $ini_cafile !== '' && file_exists($ini_cafile) && is_readable($ini_cafile)) {
			self::$cache = $ini_cafile;
			self::$probed = true;
			return $ini_cafile;
		}

		// capath is a directory of individual cert files (Debian-style
		// /etc/ssl/certs/ with hashed symlinks). It's a valid CA bundle
		// for cURL's CAPATH but NOT for file_get_contents' cafile.
		// Return it only when cafile isn't available — callers that
		// support CAPATH (cURL) will use it; stream-context callers
		// will fall through to "no bundle" path.
		$ini_capath = ini_get('openssl.capath');
		if (is_string($ini_capath) && $ini_capath !== '' && is_dir($ini_capath)) {
			self::$cache = $ini_capath;
			self::$probed = true;
			return $ini_capath;
		}

		self::$probed = true;
		self::$cache = null;
		return null;
	}

	/**
	 * Clear the process-local cache. Useful in tests and for operators
	 * who install a CA bundle at runtime and want subsequent fetches
	 * to find it without restarting PHP-FPM.
	 */
	public static function reset_cache(): void
	{
		self::$cache = null;
		self::$probed = false;
	}

	/**
	 * True when at least one candidate CA bundle path exists on disk.
	 *
	 * Convenience wrapper around find() for callers that just want to
	 * know "is there a CA bundle I should use?" without caring which one.
	 */
	public static function is_available(): bool
	{
		return self::find() !== null;
	}

	private function __construct()
	{
		// Static utility — no instances.
	}
}