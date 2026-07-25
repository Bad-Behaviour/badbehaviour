<?php

namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;

class BlacklistDetector
{
	private Configuration $config;

	private const MALICIOUS_PREFIXES = [
		'sqlmap', 'nmap', 'nikto', 'nessus', 'openvas', 'acunetix', 'w3af', 'skipfish',
		'havij', 'pangolin', 'safe3', 'bsqlbf', 'sqlninja', 'thesqlinjector',
		'dirbuster', 'gobuster', 'ffuf', 'feroxbuster', 'dirsearch', 'wfuzz',
		'masscan', 'zmap', 'zgrab', 'httpx', 'nuclei', 'jaeles', 'dalfox',
		'xsser', 'xsstrike', 'brutespray', 'hydra', 'medusa', 'ncrack',
		'metasploit', 'msfconsole', 'meterpreter', 'cobaltstrike', 'bruteratel',
		'sliver', 'mythic', 'havoc', 'silenttrinity', 'poshc2',
		'sentry mba', 'snip', 'openbullet', 'silverbullet', 'stellar', 'woxy',
		'account hitman', 'checker', 'config', 'combo', 'credential',
		'scrapy', 'pyspider', 'portia', 'webmagic', 'crawlee', 'playwright',
		'puppeteer', 'selenium', 'phantomjs', 'casperjs', 'nightmare',
		'headless', 'chrome-headless', 'firefox-headless',
		'emailcollector', 'emailsiphon', 'emailwolf', 'extractorpro', 'harvest',
		'mass mail', 'mailbot', 'spambot', 'surfbot', 'webbandit',
		'xrumer', 'zenno', 'zenoposter', 'ubot', 'autoposter', 'spam poster',
		'comment bot', 'forum bot', 'profile bot', 'register bot',
		'appscan', 'webinspect', 'burp', 'burpsuite', 'qualys', 'rapid7',
		'retina', 'corer', 'secunia', 'f-secure',
		'cobalt strike', 'sliver implant', 'mythic agent', 'havoc demon',
		'bruteratel badge', 'poshc2 implant', 'silenttrinity stager',
		'shodan', 'censys', 'binaryedge', 'fofa', 'zoomeye', 'hunter',
		'onyphe', 'spyse', 'criminalip',
		'curl/', 'wget/', 'python-requests', 'python-urllib', 'go-http-client',
		'java/', 'okhttp', 'apache-httpclient', 'axios/', 'fetch/',
		'node-fetch', 'request-promise', 'superagent', 'got/', 'ky/',
	];

	private const MALICIOUS_SUBSTRINGS = [
		'<script', 'alert(', 'onerror=', 'onload=', 'eval(', 'document.',
		'union select', 'select * from', 'insert into', 'drop table',
		'exec(', 'system(', 'shell_exec', 'passthru', 'base64_decode',
		'${jndi:', '${lower:', '${upper:', '${::-', '${env:',
		'() { :; };',
		'jndi:ldap', 'jndi:rmi', 'jndi:dns', 'jndi:iiop',
		'class.module.classloader',
		'sleep(', 'benchmark(', 'waitfor delay', 'pg_sleep',
		'extractvalue(', 'updatexml(', 'floor(', 'rand(',
		'acunetix', 'netsparker', 'appscan', 'webinspect',
		'hp404', 'webvulnscan', 'vulnscanner',
		'mirai', 'bashlite', 'gafgyt', 'qbot', 'emotet', 'trickbot',
		'dridex', 'zeus', 'gozi', 'ramnit', 'ursnif', 'dana bot',
	];

	private const URL_PATTERNS = [
		'/union\s+all\s+select/i',
		'/union\s+select/i',
		'/select\s+.*\s+from\s+/i',
		'/insert\s+into/i',
		'/update\s+.*\s+set/i',
		'/delete\s+from/i',
		'/drop\s+table/i',
		'/create\s+table/i',
		'/alter\s+table/i',
		'/exec\s*\(/i',
		'/execute\s*\(/i',
		'/sp_executesql/i',
		'/xp_cmdshell/i',
		'/benchmark\s*\(/i',
		'/sleep\s*\(/i',
		'/waitfor\s+delay/i',
		'/pg_sleep\s*\(/i',
		'/extractvalue\s*\(/i',
		'/updatexml\s*\(/i',
		'/floor\s*\(/i',
		'/<script/i',
		'/javascript:/i',
		'/on\w+\s*=/i',
		'/alert\s*\(/i',
		'/prompt\s*\(/i',
		'/confirm\s*\(/i',
		'/eval\s*\(/i',
		'/expression\s*\(/i',
		'/vbscript:/i',
		'/data:text\/html/i',
		'/\.\.\//',
		'/\.\.\\\\/',
		'/%2e%2e%2f/i',
		'/%2e%2e%5c/i',
		'/..%2f/i',
		'/..%5c/i',
		'/%252e%252e%252f/i',
		'/;\s*(cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/i',
		'/\|\s*(cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/i',
		'/`(cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)`/i',
		'/\$\((cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\)/i',
		'/\$\{jndi:/i',
		'/\$\{lower:/i',
		'/\$\{upper:/i',
		'/\$\{::-/i',
		'/\$\{env:/i',
		'/\$\{sys:/i',
		'/\$\{date:/i',
		'/\$\{main:/i',
		'/class\.module\.classloader/i',
		'/(include|require|include_once|require_once)\s*\(/i',
		'/(file|php|zip|phar|expect|input|data|glob|ftp):\/\//i',
		'/<\!entity/i',
		'/<\!doctype/i',
		'/system\s*"/i',
		'/public\s*"/i',
		'/169\.254\.169\.254/i',
		'/metadata\.google\.internal/i',
		'/metadata\.azure\.com/i',
		'/169\.254\.169\.254\/latest\/meta-data/i',
		'/http:\/\/127\.0\.0\.1/i',
		'/http:\/\/localhost/i',
		'/http:\/\/\[::1\]/i',
		'/http:\/\/0\.0\.0\.0/i',
		'/wp-admin\/admin-ajax\.php.*action=/i',
		'/xmlrpc\.php/i',
		'/wp-login\.php/i',
		'/administrator\/index\.php/i',
		'/manager\/html/i',
		'/console/i',
		'/actuator\/health/i',
		'/actuator\/env/i',
		'/actuator\/info/i',
		'/actuator\/metrics/i',
		'/actuator\/trace/i',
		'/actuator\/heapdump/i',
		'/actuator\/threaddump/i',
		'/swagger/i',
		'/api-docs/i',
		'/openapi/i',
		'/graphql/i',
		'/\.git\//i',
		'/\.svn\//i',
		'/\.env/i',
		'/\.htaccess/i',
		'/web\.config/i',
		'/composer\.json/i',
		'/package\.json/i',
		'/yarn\.lock/i',
		'/pnpm-lock\.yaml/i',
		'/dockerfile/i',
		'/docker-compose/i',
		'/kubeconfig/i',
		'/\.kube\/config/i',
		'/id_rsa/i',
		'/id_dsa/i',
		'/id_ecdsa/i',
		'/id_ed25519/i',
		'/authorized_keys/i',
		'/known_hosts/i',
		'/config\.json/i',
		'/settings\.json/i',
		'/secrets/i',
		'/credentials/i',
		'/password/i',
		'/api[_-]?key/i',
		'/access[_-]?token/i',
		'/secret[_-]?key/i',
		'/private[_-]?key/i',
	];

	private const UA_REGEX = [
		'/^[a-z0-9]{20,}$/i',
		'/mozilla\/(\d{2,})\.0/i',
		'/msie\s+(\d{2,})\.0/i',
		'/^bot\d+$/i',
		'/^crawler\d+$/i',
		'/^spider\d+$/i',
		'/scan(ner|bot)?\d*$/i',
		'/^0x[0-9a-f]+$/i',
		'/(union|select|insert|update|delete|drop|create|alter)\s+/i',
	];

	public function __construct(Configuration $config)
	{
		$this->config = $config;
	}

	public function detect(RequestPackage $package): ?Result
	{
		$ua = $package->user_agent;
		$uri = $package->request_uri;
		$method = $package->request_method;
		$ua_lower = strtolower($ua);

		// Empty UA
		if (empty($ua) || $ua === '-' || strlen(trim($ua)) < 5) {
			return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, 'Empty or invalid User-Agent', $package);
		}

		// UA parser detected bot - check this FIRST
		if ($package->ua_is_bot) {
			return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, 'Bot detected by UA parser', $package, [
				'device_type' => $package->ua_device,
				'browser' => $package->ua_browser,
			]);
		}

		// Prefix matches
		foreach (self::MALICIOUS_PREFIXES as $prefix) {
			if (str_starts_with($ua_lower, $prefix) ||
				preg_match('/\b' . preg_quote($prefix, '/') . '\b/i', $ua)) {
				return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, "Malicious UA prefix: $prefix", $package);
			}
		}

		// Substring matches
		foreach (self::MALICIOUS_SUBSTRINGS as $substr) {
			if (stripos($ua, $substr) !== false) {
				return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, "Malicious UA substring: $substr", $package);
			}
		}

		// Regex matches
		foreach (self::UA_REGEX as $pattern) {
			if (preg_match($pattern, $ua)) {
				return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, "Malicious UA pattern", $package);
			}
		}

		// URL patterns
		foreach (self::URL_PATTERNS as $pattern) {
			if (preg_match($pattern, $uri)) {
				return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, "Attack pattern in URL", $package);
			}
		}

		// Request body for POST/PUT/PATCH
		if (in_array($method, ['POST', 'PUT', 'PATCH'], true) && !empty($package->request_entity)) {
			$body = is_string($package->request_entity)
				? $package->request_entity
				: http_build_query($package->request_entity);

			// Decode URL-encoded body (http_build_query uses + for spaces)
			$body = urldecode($body);

			foreach (self::URL_PATTERNS as $pattern) {
				if (preg_match($pattern, $body)) {
					return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, "Attack pattern in request body", $package);
				}
			}
		}

		return null;
	}
}
