# Bad Behaviour

Bad Behaviour prevents spammers from ever delivering their junk, and in many cases, from ever reading your site in the first place.

## Description

Welcome to a whole new way of keeping your blog, forum, guestbook, wiki, or content management system free of link spam, malicious bots, AI scrapers, and automated attacks. Bad Behaviour is a PHP-based solution for blocking unwanted web traffic and the robots which deliver it.

Thousands of sites large and small trust Bad Behaviour to help reduce incoming link spam, malicious bot traffic, AI scrapers, and automated attacks.

Bad Behaviour complements other security solutions by acting as a gatekeeper, preventing bad actors from ever delivering their payloads, and in many cases, from ever reading your site in the first place. This keeps your site's load down, makes your site logs cleaner, and can help prevent denial of service conditions caused by malicious bots.

Bad Behaviour transcends other solutions by working in a completely different, unique way. Instead of merely looking at the content of potential attacks, Bad Behaviour analyzes the delivery method, TLS fingerprint, HTTP/2 settings, header ordering, behavioral patterns, and the software the attacker is using. In this way, Bad Behaviour can stop attacks even when nobody has ever seen the particular exploit before.

Bad Behaviour is designed to work alongside existing security services to increase their effectiveness and efficiency. Whenever possible, you should run it in combination with a WAF, rate limiter, or traditional spam prevention service.

Bad Behaviour works on, or can be adapted to, virtually any PHP-based Web software package. Bad Behaviour is available for many platforms.

Installing and configuring Bad Behaviour on most platforms is simple and takes only a few minutes. In most cases, no configuration at all is needed. Simply turn it on and stop worrying about spam, scrapers, and automated attacks!

The core of Bad Behaviour is free software released under the GNU Lesser General Public License, version 3, or at your option, any later version.

---

## What's New in 3.0 (Complete Modern Rewrite)

Version 3.0 represents a complete rewrite of Bad Behaviour, modernizing the 10+ year old codebase from procedural PHP to a clean, typed PHP 8.2+ architecture with modern bot detection capabilities.

* **Complete Rewrite**: Modern PHP 8.2+ architecture with strict typing, enums, readonly classes, and PSR-4 autoloading
* **AI Crawler Control**: Granular control over GPTBot, ClaudeBot, Google-Extended, PerplexityBot, Meta AI, Applebot-Extended, and more
* **AI/ML-Ready Fingerprinting**: JA3 TLS fingerprinting, HTTP/2 settings analysis, header order analysis (config-driven, zero false positives)
* **Advanced POST Body Inspection**: SQLi, XSS, command injection, Log4Shell, Spring4Shell, SSRF, path traversal, file inclusion
* **Behavioral Analysis**: Rate anomalies, rotating User-Agents/IPs, URL enumeration, missing headers, timing analysis
* **Multi-Tier Rate Limiting**: Global, per-minute, POST, and login endpoints with adapter-backed storage
* **IPv6 Support**: Full CIDR matching with binary comparison fallback (no GMP required)
* **Challenge System**: Builtin proof-of-work, hCaptcha, reCAPTCHA v3, Cloudflare Turnstile
- **Structured JSON Logging**: SIEM-ready logging with semantic result codes
- **Structured Configuration**: INI with sections ([core], [reverse_proxy], [ai_crawlers], [rate_limits], etc.)
- **Complete Bot Registry**: 50+ bots across Search, AI, Social, SEO, Archive, Monitoring categories
- **Zero False Positive Fingerprinting**: Only blocks KNOWN bad fingerprints from config
- **Structured Logging**: JSON format for SIEM integration

**BREAKING CHANGES from 2.x:**
- Minimum PHP version now 8.2
- All procedural `.inc.php` files replaced with OOP classes in `src/`
- Hex result codes (e.g. `'17f4e8c8'`) replaced with semantic `ResultCode` enum
- Configuration format changed from flat INI to structured INI with sections
- Adapter interface expanded with new required methods
- Database schema updated with new columns (`bot_category`, `ja3`, `header_order_hash`, `asn`, `country`)
- Custom adapters must implement new `CacheInterface` methods

---

## Architecture

```
src/
├── BadBehaviour.php              # Main orchestrator
├── Configuration.php             # Typed config with validation
├── Bootstrap.php                 # Single entry point for any PHP app
├── Core/
│   ├── BadBehaviour.php          # Main orchestrator
│   ├── Result.php / ResultCode.php  # Semantic result objects
│   └── Interfaces/
│       ├── AdapterInterface.php  # Host adapter contract
│       ├── LoggerInterface.php   # PSR-3 compatible logging
│       ├── CacheInterface.php    # Rate limit/behavior storage
│       └── GeoIpInterface.php    # MaxMind/ipinfo.io integration
├── Detection/
│   ├── BotDetector.php           # 50+ known bots
│   ├── BlacklistDetector.php     # Malicious UA, attacks
│   ├── BehavioralDetector.php    # Behavioral anomalies
│   ├── FingerprintDetector.php   # JA3, H2, header order (config-only)
│   ├── RateLimitDetector.php     # Multi-tier rate limiting
│   └── DnsblDetector.php         # http:BL, Spamhaus, SpamCop
├── Bot/
│   ├── BotDefinition.php
│   ├── BotCategory.php
│   ├── BotAction.php
│   └── Registry.php              # 50+ known bots
├── Challenge/
│   ├── ChallengeInterface.php
│   ├── BuiltinChallenge.php      # Proof-of-work
│   ├── HCaptchaChallenge.php
│   ├── RecaptchaChallenge.php
│   └── TurnstileChallenge.php
├── Adapter/
│   ├── GenericAdapter.php        # Standalone PHP apps
│   ├── MediaWikiAdapter.php      # MediaWiki integration
│   └── WackoWikiAdapter.php      # WackoWiki integration
├── Util/
│   ├── IpUtil.php                # IPv4/IPv6 CIDR matching
│   ├── HeaderUtil.php            # Header normalization
│   ├── UaParser.php              # Browser/OS/device/bot parsing
│   └── RequestPackage.php        # Immutable request DTO
└── Exception/
    ├── BlockedException.php
    ├── ChallengeRequiredException.php
    └── ConfigurationException.php
```

---

## Installation & Usage

### Option 1: Modern Composer Usage (Recommended)

1. Install via Composer:
   ```bash
   composer require badbehaviour/badbehaviour
   ```

2. Instantiate the library:

**For Generic Applications (Laravel, Symfony, Slim, etc.):**
```php
require 'vendor/autoload.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Adapter\GenericAdapter;
use BadBehaviour\Configuration;

// Optional custom settings
$custom = [
    'strict' => true,
    'allowed_ai_crawlers' => ['GPTBot', 'ClaudeBot'],
    'block_unverified_ai' => true,
    'strict_ai' => true,
];

$adapter = new GenericAdapter();
$bb = new BadBehaviour($adapter, $custom);

$result = $bb->run();
if (!$result->is_allowed()) {
    $bb->handle_result($result);
    // OR: if ($bb->run()) { exit; } // Legacy style
}
```

**For MediaWiki (e.g. `LocalSettings.php`):**
```php
require "$IP/vendor/autoload.php";

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Adapter\MediaWikiAdapter;

$db = wfGetDB(DB_MASTER);
$adapter = new MediaWikiAdapter($db, $wgDBprefix, $wgEmergencyContact, $wgScript);
$bb = new BadBehaviour($adapter);
$bb->run();
```

**For WackoWiki:**
```php
require 'vendor/autoload.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Adapter\WackoWikiAdapter;

$adapter = new WackoWikiAdapter($db);
$bb = new BadBehaviour($adapter);

if (!$bb->run()->is_allowed()) {
    exit;
}
```

### Option 2: Single Entry Point (Any PHP App)

For maximum simplicity, use the single entry point:

```php
require 'vendor/autoload.php';

// Optional overrides
$_ENV['BB_STRICT'] = 'true';
$_ENV['BB_ALLOWED_AI_CRAWLERS'] = 'GPTBot,ClaudeBot';

\BadBehaviour\Bootstrap::run();

// Or for middleware-style:
if (!\BadBehaviour\Bootstrap::check(['strict' => true])) {
    exit; // Blocked
}
```

### Option 3: Legacy Drop-In Usage

If you maintain an existing site and simply wish to upgrade from 2.x without refactoring your integration, the legacy entry points continue to function exactly as before. They now act as forwarding shims over the new OOP architecture internally.

1. Upload the `badbehaviour` directory to your project.
2. Include the legacy bootstrap file as you always have:
   * MediaWiki: `include( './extensions/Bad-Behaviour/bad-behaviour-mediawiki.php' );`
   * Generic: `require_once 'bad-behaviour-generic.php';`
   * WackoWiki: `require_once 'bad-behaviour-wackowiki.php';`

---

## Configuration

Bad Behaviour 3.0 uses a structured INI configuration. Copy `settings.ini.example` to `settings.ini` and customize.

### Core Settings (`settings.ini`)

```ini
[core]
logging = true
verbose = false
strict = false

[reverse_proxy]
enabled = true
header = "CF-Connecting-IP"
addresses[] = "10.0.0.0/8"
addresses[] = "172.16.0.0/12"
; Cloudflare IPs (update regularly via API)
; addresses[] = "173.245.48.0/20"
; addresses[] = "103.21.244.0/22"

[ai_crawlers]
; Add tokens to allow specific AI crawlers (respects robots.txt)
allowed[] = "GPTBot"
allowed[] = "ClaudeBot"
allowed[] = "Google-Extended"
allowed[] = "PerplexityBot"
block_unverified_ai = true
strict_ai = false

[bot_categories]
blocked[] = "malicious"
; blocked[] = "seo_crawler"

[rate_limits]
enabled = true
global_requests = 1000
global_window = 3600
per_minute_requests = 60
per_minute_window = 60
post_requests = 30
post_window = 3600
login_requests = 10
login_window = 900

[challenge]
enabled = false
provider = "builtin"  ; builtin, hcaptcha, recaptcha, turnstile
site_key = ""
secret_key = ""
recaptcha_min_score = 0.5

[performance]
skip_extensions[] = "css"
skip_extensions[] = "js"
skip_paths[] = "/static/"
```

### Whitelist (`whitelist.ini`)

```ini
[ip]
internal = "10.0.0.0/8"
office = "203.0.113.0/24"
cloudflare = "173.245.48.0/20"

[useragent]
monitoring = "InternalMonitor/1.0"
api_client = "MyApp/2.0 (Internal)"

[url]
health = "/health"
webhook = "/webhook/"
api = "/api/v1/status"

[asn]
google = "AS15169"
cloudflare = "AS13335"

[country]
us = "US"
ca = "CA"
de = "DE"
```

---

## Detection Pipeline (Execution Order)

1. **Whitelist** - IP, UA, URL, ASN, Country
2. **Custom Rules** - IP, UA regex, ASN, Country, Header
3. **BotDetector** - 50+ known bots (Search, AI, Social, SEO, Archive, Monitoring)
4. **BlacklistDetector** - Malicious UA, attack payloads, headless browsers
5. **FingerprintDetector** - ONLY known bad fingerprints (config-driven)
6. **DnsblDetector** - http:BL, Spamhaus, SpamCop
7. **BehavioralDetector** - Rate anomalies, rotating UA/IP, enumeration
8. **RateLimitDetector** - Multi-tier (global, per-minute, POST, login)

---

## AI Crawler Management

Bad Behaviour 3.0 provides granular control over AI crawlers:

```ini
[ai_crawlers]
allowed[] = "GPTBot"           ; OpenAI
allowed[] = "ClaudeBot"        ; Anthropic
allowed[] = "Google-Extended"  ; Google Vertex/Bard
allowed[] = "PerplexityBot"    ; Perplexity
allowed[] = "CohereBot"        ; Cohere
allowed[] = "Meta-ExternalAgent" ; Meta
allowed[] = "Applebot-Extended"  ; Apple
allowed[] = "YouBot"           ; You.com
allowed[] = "KagiBot"          ; Kagi Search
block_unverified_ai = true     ; Block spoofed AI crawlers
strict_ai = false              ; true = block even verified unallowed AI
```

| Crawler | Token | Robots.txt Token | Verification |
|---------|-------|------------------|--------------|
| GPTBot | GPTBot | GPTBot | DNS (openai.com) |
| ClaudeBot | ClaudeBot | ClaudeBot | DNS (anthropic.com) |
| Google-Extended | Google-Extended | Google-Extended | DNS (googlebot.com) |
| PerplexityBot | PerplexityBot | PerplexityBot | IP ranges only |
| Meta AI | Meta AI | Meta-ExternalAgent | DNS (facebook.com) |
| Applebot-Extended | Applebot-Extended | Applebot-Extended | DNS (applebot.apple.com) |
| Common Crawl | CCBot | CCBot | IP ranges only |
| Internet Archive | ia_archiver | ia_archiver | IP ranges only |

---

## Challenge System

When `challenge_enabled = true`, suspicious requests receive a challenge:

```ini
[challenge]
enabled = true
provider = "hcaptcha"  ; builtin, hcaptcha, recaptcha, turnstile
site_key = "your-site-key"
secret_key = "your-secret-key"
recaptcha_min_score = 0.5
```

**Providers:**
- `builtin` - Zero-dependency proof-of-work (no external dependencies)
- `hcaptcha` - hCaptcha checkbox/invisible
- `recaptcha` - reCAPTCHA v3 (score-based)
- `turnstile` - Cloudflare Turnstile

---

## Rate Limiting

Multi-tier rate limiting with adapter-backed storage:

```ini
[rate_limits]
enabled = true
global_requests = 1000      ; per hour
global_window = 3600
per_minute_requests = 60
per_minute_window = 60
post_requests = 30          ; per hour
post_window = 3600
login_requests = 10         ; per 15 min
login_window = 900
```

---

## Custom Adapters

Implement `HostAdapterInterface` for custom platforms:

```php
use BadBehaviour\Core\Interfaces\AdapterInterface;

class MyCustomAdapter implements AdapterInterface
{
    // Required methods:
    public function get_settings(): array;
    public function get_whitelist(): array;
    public function get_email(): string;
    public function get_relative_path(): string;
    public function get_table_schema(string $table_name): string;
    
    // Database
    public function query(string $sql): bool;
    public function log_request(RequestPackage $package, Result $result): void;
    
    // Cache/Rate Limiting
    public function increment_counter(string $key, int $window): int;
    public function get_counter(string $key): int;
    public function get_behavior_profile(string $session_id): ?array;
    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool;
    public function add_to_set(string $key, string $value, int $ttl): bool;
    public function get_set(string $key): array;
    
    // GeoIP
    public function get_geoip(string $ip): ?array;
    
    // Challenge
    public function verify_challenge(string $response, string $remote_ip): bool;
    
    // Logging
    public function log(string $level, string $message, array $context = []): void;
}
```

---

## Result Codes (Semantic, Not Hex)

| Code | HTTP | Description |
|------|------|-------------|
| `allowed` | 200 | Request permitted |
| `blocked.bot` | 403 | Known bot blocked |
| `blocked.ai_crawler` | 403 | AI crawler blocked |
| `blocked.seo_crawler` | 403 | SEO crawler blocked |
| `blocked.malicious_ua` | 403 | Malicious User-Agent |
| `blocked.attack_pattern` | 403 | Attack payload detected |
| `blocked.dnsbl` | 403 | DNSBL match |
| `blocked.httpbl` | 403 | http:BL match |
| `blocked.behavioral` | 403 | Behavioral anomaly |
| `blocked.fingerprint` | 403 | Bad fingerprint |
| `blocked.rate_limit` | 429 | Rate limit exceeded |
| `blocked.custom_rule` | 403 | Custom rule match |
| `blocked.geoip` | 403 | GeoIP block |
| `challenge.required` | 403 | Challenge required |
| `challenge.failed` | 403 | Challenge failed |

---

## Migration from 2.x

See [MIGRATION.md](MIGRATION.md) for detailed upgrade instructions.

Key changes:
1. **Config**: Flat INI → Structured INI with sections
2. **Result Codes**: Hex strings → `ResultCode` enum
3. **Adapters**: New interface methods required
4. **Database**: New columns required (`bot_category`, `ja3`, `header_order_hash`, `asn`, `country`)
5. **Entry Points**: Use `Bootstrap::run()` or `new BadBehaviour($adapter, $config)`

---

## Requirements

- PHP 8.2+
- Extensions: `json`, `mbstring`, `curl`, `gmp` (for IPv6 CIDR)
- Composer 2+

---

## Testing

```bash
# Run all tests
vendor/bin/phpunit

# Unit tests only
vendor/bin/phpunit --testsuite Unit

# Integration tests
vendor/bin/phpunit --testsuite Integration

# With coverage
vendor/bin/phpunit --coverage-html build/coverage/html
```

---

## License

GNU Lesser General Public License v3.0 or later.

---

## Support & Documentation

- [Wiki](https://github.com/Bad-Behaviour/badbehaviour/wiki) - Full documentation
- [Migration Guide](MIGRATION.md) - 2.x to 3.0 upgrade
- [Issues](https://github.com/Bad-Behaviour/badbehaviour/issues) - Bug reports
- [Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions) - Questions

---

*Bad Behaviour 3.0 - Modern bot detection for the modern web.*