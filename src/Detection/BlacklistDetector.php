<?php
// src/Detection/BlacklistDetector.php - FINAL

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

    /**
     * URL attack patterns.
     *
     * SQLi requires CONTEXT (numeric/quote/paren before union) to avoid
     * matching legitimate content like "union select 1" in page text.
     * XSS matches actual script tags — <script> in URLs is almost always
     * an attack (legitimate content gets URL-encoded by browsers).
     */
    private const URL_PATTERNS = [
        // === SQL Injection (CONTEXT-REQUIRED) ===
        '/\b\d+\s+union\s+(?:all\s+)?select\b/i',
        '/\'\s*union\s+(?:all\s+)?select\b/i',
        '/"\s*union\s+(?:all\s+)?select\b/i',
        '/\)\s*union\s+(?:all\s+)?select\b/i',
        '/\bunion\s+(?:all\s+)?select\s+\d+\s+from\b/i',
        '/\)\s+or\s+1\s*=\s*1\b/i',
        '/\)\s+or\s+\d+\s*=\s*\d+/i',
        '/\'\s+or\s+\'1\'\s*=\s*\'1/i',
        '/"\s+or\s+"1"\s*=\s*"1/i',
        '/\bor\s+1\s*=\s*1\s*--/i',
        '/\bor\s+1\s*=\s*1\s*#/i',
        '/\band\s+1\s*=\s*1\s*--/i',
        '/\bdrop\s+table\s+\w+/i',
        '/\bdrop\s+database\s+/i',
        '/\binsert\s+into\s+\w+\s+select/i',
        '/\bexec\s*\(\s*[\'"]/i',
        '/\bsp_executesql\s+/i',
        '/\bxp_cmdshell\s+/i',
        '/information_schema\./i',
        '/\bsleep\s*\(\s*\d+\s*\)/i',
        '/\bbenchmark\s*\(\s*\d+\s*,/i',
        '/\bwaitfor\s+delay\s+[\'"]/i',
        '/\bpg_sleep\s*\(\s*\d+\s*\)/i',
        '/\bextractvalue\s*\(\s*1\s*,/i',
        '/\bupdatexml\s*\(\s*1\s*,/i',
        '/\bfloor\s*\(\s*rand\s*\(\s*0\s*\)\s*\*\s*2\s*\)\)/i',

        // === XSS (actual script injection — <script> in URLs is attack) ===
        '/<script\b[^>]*>/i',
        '/<\/script>/i',
        '/<iframe\b[^>]*>/i',
        '/javascript\s*:\s*[a-z]/i',
        '/\bon\w+\s*=\s*[\'"]?\s*[a-z]/i',
        '/<svg\b[^>]*on\w+/i',
        '/<img\b[^>]*on\w+/i',
        '/<body\b[^>]*on\w+/i',
        '/<input\b[^>]*on\w+/i',
        '/<select\b[^>]*on\w+/i',
        '/<button\b[^>]*on\w+/i',
        '/<form\b[^>]*on\w+/i',
        '/\beval\s*\(\s*[a-z\$]/i',
        '/\bexpression\s*\(\s*[a-z]/i',
        '/vbscript\s*:/i',
        '/data\s*:\s*text\/html/i',
        '/data\s*:\s*application\/javascript/i',

        // === Path Traversal ===
        '#\.\./#',
        '#\.\.\\\\#',
        '/%2e%2e%2f/i',
        '/%2e%2e%5c/i',
        '/\.%2e/i',
        '/%252e%252e%252f/i',
        '/%c0%ae%c0%ae/i',

        // === Command Injection ===
        '/;\s*(cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/i',
        '/\|\s*(cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/i',
        '/`(cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)`/i',
        '/\$\((cat|ls|id|whoami|pwd|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/i',

        // === Log4Shell / JNDI ===
        '/\$\{jndi\s*:\s*ldap/i',
        '/\$\{jndi\s*:\s*rmi/i',
        '/\$\{jndi\s*:\s*dns/i',
        '/\$\{lower\s*:/i',
        '/\$\{upper\s*:/i',
        '/\$\{::-/i',
        '/\$\{env\s*:/i',
        '/\$\{sys\s*:/i',
        '/\$\{date\s*:/i',
        '/\$\{main\s*:/i',
        '/\$\{ctx\s*:/i',
        '/class\.module\.classloader/i',

        // === Shellshock ===
        '/\(\)\s*\{[^}]*;\s*\}\s*;/',

        // === PHP injection ===
        '/\b(include|require|include_once|require_once)\s*\(\s*[\'"]?\s*(https?|ftp|php|data|zip|phar|expect|input|glob):/i',
        '/\bfile\s*:\s*\/\/\s*[\w]/i',
        '/\bphp\s*:\s*\/\//i',
        '/\bzip\s*:\s*\/\//i',
        '/\bphar\s*:\s*\/\//i',

        // === XXE ===
        '/<\!entity\s+/i',
        '/<\!doctype\s+[\w-]+\s+system\s+/i',

        // === SSRF / Cloud Metadata ===
        '/169\.254\.169\.254/i',
        '/metadata\.google\.internal/i',
        '/metadata\.azure\.com/i',
        '/100\.100\.100\.200/i',
        '/fd00:ec2::254/i',
        '/http:\/\/127\.0\.0\.1/i',
        '/http:\/\/localhost/i',
        '/http:\/\/\[::1\]/i',
        '/http:\/\/0\.0\.0\.0/i',

        // === CMS probing ===
        '/\/wp-admin\/admin-ajax\.php.*\baction\s*=\s*[a-z_]+\s*&/i',
        '/\/xmlrpc\.php/i',
        '/\/wp-login\.php/i',
        '/\/administrator\/index\.php/i',
        '/\/manager\/html/i',

        // === Actuator / API docs ===
        '/\/actuator\/(health|env|info|metrics|trace|heapdump|threaddump|configprops|beans|mappings)\b/i',
        '/\/swagger[\/\-]?/i',
        '/\/api-docs/i',
        '/\/openapi\.json/i',
        '/\/graphql\b/i',

        // === Source control / secrets exposure ===
        '/\/\.git\/(config|HEAD|index|packed-refs|objects)/i',
        '/\/\.svn\/(entries|wc-db|format)/i',
        '/\/\.env(\.|$)/i',
        '/\/\.htaccess/i',
        '/\/web\.config/i',
        '/\/composer\.json/i',
        '/\/package\.json/i',
        '/\/yarn\.lock/i',
        '/\/pnpm-lock\.yaml/i',
        '/\/dockerfile/i',
        '/\/docker-compose\.yml/i',
        '/\/kubeconfig/i',
        '/\/\.kube\/config/i',
        '/\/id_rsa/i',
        '/\/id_dsa/i',
        '/\/id_ecdsa/i',
        '/\/id_ed25519/i',
        '/\/authorized_keys/i',
        '/\/known_hosts/i',

        // === Scanner signatures ===
        '/w00tw00t/i',
        '/nikto/i',
        '/sqlmap/i',
        '/nmap/i',
        '/masscan/i',
        '/acunetix/i',
        '/netsparker/i',
    ];

    /**
     * Contextual patterns — only flag when value looks like an actual
     * credential leak (long random token in URL param).
     * Param NAMES like "password" alone never trigger — only when
     * combined with a high-entropy VALUE.
     */
    private const CONTEXTUAL_URL_PATTERNS = [
        '/[\?&\/](password|passwd|pwd)\s*=\s*[a-zA-Z0-9_\-\.\/\+]{20,}/i',
        '/[\?&\/](api[_\-]?key|access[_\-]?token|secret[_\-]?key|private[_\-]?key)\s*=\s*[a-zA-Z0-9_\-\.\/\+]{32,}/i',
        '/[\?&\/](credentials|secrets)\s*=\s*[a-zA-Z0-9_\-\.\/\+]{32,}/i',
    ];

    private const UA_REGEX = [
        '/^[a-z0-9]{20,}$/i',
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
        $headers = $package->headers_mixed;

        if (empty($ua) || $ua === '-' || strlen(trim($ua)) < 5) {
            return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, 'Empty or invalid User-Agent', $package);
        }

        if ($package->ua_is_bot) {
            return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, 'Bot detected by UA parser', $package, [
                'device_type' => $package->ua_device,
                'browser' => $package->ua_browser,
            ]);
        }

        $is_http_tool = $package->is_http_tool();

        if (!$is_http_tool) {
            foreach (self::MALICIOUS_PREFIXES as $prefix) {
                if (str_starts_with($ua_lower, $prefix) ||
                    preg_match('/\b' . preg_quote($prefix, '/') . '\b/i', $ua)) {
                    return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, "Malicious UA prefix: $prefix", $package);
                }
            }

            foreach (self::MALICIOUS_SUBSTRINGS as $substr) {
                if (stripos($ua, $substr) !== false) {
                    return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, "Malicious UA substring: $substr", $package);
                }
            }
        }

        foreach (self::UA_REGEX as $pattern) {
            if (@preg_match($pattern, $ua)) {
                return Result::block(ResultCode::BLOCKED_MALICIOUS_UA, "Malicious UA pattern", $package);
            }
        }

        $normalized_uri = urldecode($uri);

        foreach (self::URL_PATTERNS as $pattern) {
            if (@preg_match($pattern, $normalized_uri)) {
                return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, "Attack pattern in URL", $package);
            }
        }

        foreach (self::CONTEXTUAL_URL_PATTERNS as $pattern) {
            if (@preg_match($pattern, $normalized_uri)) {
                return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, "Suspicious credential in URL", $package);
            }
        }

        if (in_array($method, ['POST', 'PUT', 'PATCH'], true) && !empty($package->request_entity)) {
            $content_type = $headers['Content-Type'] ?? '';
            $content_type_lower = strtolower($content_type);

            $is_json = str_contains($content_type_lower, 'application/json');
            $is_multipart = str_starts_with($content_type_lower, 'multipart/form-data');
            $is_form = str_contains($content_type_lower, 'application/x-www-form-urlencoded');

            if ($is_form) {
                $entity = $package->request_entity;

                if (isset($entity['title']) && isset($entity['url']) && isset($entity['blog_name'])) {
                    if ($this->is_suspicious_trackback($headers, $entity)) {
                        return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, 'Suspicious trackback', $package);
                    }
                }

                if (!$this->config->offsite_forms && isset($headers['Referer'])) {
                    if ($this->is_offsite_form($headers, $package)) {
                        return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, 'Offsite form submission', $package);
                    }
                }

                foreach ($entity as $key => $value) {
                    if ($this->is_safe_content_field($key)) {
                        continue;
                    }

                    $key_str = (string)$key;
                    $value_str = is_string($value) ? $value : (is_array($value) ? json_encode($value) : '');

                    if (stripos($key_str, 'document.write') !== false
                        || stripos($value_str, 'document.write') !== false) {
                        return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, 'Malicious document.write', $package);
                    }

                    $normalized_value = urldecode($value_str);

                    foreach (self::URL_PATTERNS as $pattern) {
                        if (@preg_match($pattern, $normalized_value)) {
                            return Result::block(ResultCode::BLOCKED_ATTACK_PATTERN, "Attack pattern in request body", $package);
                        }
                    }
                }
            }
        }

        return null;
    }

    private function is_safe_content_field(string $field_name): bool
    {
        $field_lower = strtolower($field_name);

        $skip_fields = $this->config->body_scan_skip_fields ?? [];
        if (in_array($field_lower, $skip_fields, true)) {
            return true;
        }

        $safe_suffixes = [
            '_body', '_content', '_text', '_message', '_html', '_markdown', '_wiki',
            '_description', '_details', '_summary', '_notes', '_instructions',
            '_readme', '_changelog', '_documentation', '_docs', '_example',
            '_template', '_script', '_query', '_sql', '_code', '_source',
            '_snippet', '_payload', '_data', '_input', '_output',
        ];
        foreach ($safe_suffixes as $suffix) {
            if (str_ends_with($field_lower, $suffix)) {
                return true;
            }
        }

        $safe_infixes = [
            'comment', 'description', 'content', 'body', 'message', 'text',
            'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
            'article', 'page', 'entry', 'reply', 'review', 'feedback',
            'bio', 'about', 'summary', 'details', 'notes', 'instructions',
            'readme', 'changelog', 'documentation', 'docs', 'example',
            'template', 'script', 'query', 'sql', 'payload', 'markup',
        ];
        foreach ($safe_infixes as $infix) {
            if (str_contains($field_lower, $infix)) {
                return true;
            }
        }

        $parameter_indicators = [
            'search', 'query', 'filter', 'sort', 'order', 'limit', 'offset',
            'page', 'per_page', 'username', 'password', 'email', 'login',
            'register', 'signup', 'signin', 'auth', 'token', 'key',
            'redirect', 'return', 'next', 'prev', 'action', 'cmd', 'command',
            'exec', 'execute', 'run', 'eval', 'callback', 'url', 'uri', 'path',
            'file', 'filename', 'upload', 'import', 'export', 'delete', 'remove',
            'create', 'update', 'edit', 'modify', 'change', 'set', 'config',
        ];
        foreach ($parameter_indicators as $indicator) {
            if (str_contains($field_lower, $indicator)) {
                return false;
            }
        }

        return false;
    }

    private function is_suspicious_trackback(array $headers, array $entity): bool
    {
        $ua = $headers['User-Agent'] ?? '';

        if ($this->looks_like_browser($this->parse_browser($ua))) {
            return true;
        }

        if (isset($headers['Via']) || isset($headers['Max-Forwards'])
            || isset($headers['X-Forwarded-For']) || isset($headers['Client-Ip'])) {
            return true;
        }

        if (stripos($ua, 'WordPress/') !== false) {
            $ct = $headers['Content-Type'] ?? '';
            if (!str_contains($ct, 'charset=')) {
                return true;
            }
        }

        return false;
    }

    private function is_offsite_form(array $headers, RequestPackage $package): bool
    {
        $referer = $headers['Referer'] ?? '';
        $host = $headers['Host'] ?? '';

        if (empty($referer) || empty($host)) return false;

        $url = parse_url($referer);
        if (!$url || empty($url['host'])) return false;

        $ref_host = preg_replace('|^www\.|', '', $url['host']);
        $my_host = preg_replace('|^www\.|', '', $host);
        $my_host = preg_replace('|:\d+$|', '', $my_host);

        return strcasecmp($ref_host, $my_host) !== 0;
    }

    private function looks_like_browser(string $ua_browser): bool
    {
        return in_array($ua_browser, ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera', 'Internet Explorer'], true);
    }

    private function parse_browser(string $ua): string
    {
        if (stripos($ua, 'Edg/') !== false) return 'Edge';
        if (stripos($ua, 'OPR/') !== false || stripos($ua, 'Opera/') !== false) return 'Opera';
        if (stripos($ua, 'Brave/') !== false) return 'Brave';
        if (stripos($ua, 'Vivaldi/') !== false) return 'Vivaldi';
        if (stripos($ua, 'Chrome/') !== false || stripos($ua, 'CriOS/') !== false) return 'Chrome';
        if (stripos($ua, 'Firefox/') !== false || stripos($ua, 'FxiOS/') !== false) return 'Firefox';
        if (stripos($ua, 'Safari/') !== false && stripos($ua, 'Chrome') === false) return 'Safari';
        if (stripos($ua, 'MSIE') !== false || stripos($ua, 'Trident/') !== false) return 'Internet Explorer';
        return 'Unknown';
    }
}