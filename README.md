# Bad Behaviour

Bad Behaviour prevents spammers from ever delivering their junk, and in many cases, from ever reading your site in the first place.

## Description

Welcome to a whole new way of keeping your blog, forum, guestbook, wiki, or content management system free of link spam, malicious bots, AI scrapers, and automated attacks. Bad Behaviour is a PHP-based solution for blocking unwanted web traffic and the robots which deliver it.

Thousands of sites large and small trust Bad Behaviour to help reduce incoming link spam, malicious bot traffic, AI scrapers, and automated attacks.

Bad Behaviour complements other security solutions by acting as a gatekeeper, preventing bad actors from ever delivering their payloads, and in many cases, from ever reading your site in the first place. This keeps your site's load down, makes your site logs cleaner, and can help prevent denial of service conditions caused by malicious bots.

Bad Behaviour transcends other solutions by working in a completely different, unique way. Instead of merely looking at the content of potential attacks, Bad Behaviour analyzes the delivery method, TLS fingerprint, HTTP/2 settings, header ordering, behavioral patterns, and the software the attacker is using. In this way, Bad Behaviour can stop attacks even when nobody has ever seen the particular exploit before.

Bad Behaviour is designed to work alongside existing security services to increase their effectiveness and efficiency. Whenever possible, you should run it in combination with a WAF, rate limiter, or traditional spam prevention service.

Bad Behaviour works on, or can be adapted to, virtually any PHP-based Web software package. Bad Behaviour is available for many platforms.

Installing and configuring Bad Behaviour on most platforms is simple and takes only a few minutes. In most cases, **no configuration at all is needed** — the safe defaults work out of the box. Simply turn it on and stop worrying about spam, scrapers, and automated attacks!

The core of Bad Behaviour is free software released under the GNU Lesser General Public License, version 3, or at your option, any later version.

---

## What's New in 3.0 (Complete Modern Rewrite)

Version 3.0 represents a complete rewrite of Bad Behaviour, modernizing the 10+ year old codebase from procedural PHP to a clean, typed PHP 8.2+ architecture with modern bot detection capabilities.

* **Complete Rewrite**: Modern PHP 8.2+ architecture with strict typing, enums, readonly classes, and PSR-4 autoloading
* **AI Crawler Control**: Granular control over GPTBot, ClaudeBot, Google-Extended, PerplexityBot, Meta AI, Applebot-Extended, and more (**opt-in**)
* **AI/ML-Ready Fingerprinting**: JA3 TLS fingerprinting, HTTP/2 settings analysis, header order analysis — **config-driven, opt-in, zero false positives by default**
* **Advanced POST Body Inspection**: SQLi, XSS, command injection, Log4Shell, Spring4Shell, SSRF, path traversal, file inclusion — **only for form data, opt-in for JSON/multipart**
* **Behavioral Analysis**: Rate anomalies, rotating User-Agents/IPs, URL enumeration, missing headers, timing analysis — **safe defaults, legacy-compatible**
* **Multi-Tier Rate Limiting**: Global, per-minute, POST, and login endpoints with adapter-backed storage
* **IPv6 Support**: Full CIDR matching with binary comparison fallback (no GMP required)
* **Challenge System**: Builtin proof-of-work, hCaptcha, reCAPTCHA v3, Cloudflare Turnstile
* **Structured JSON Logging**: SIEM-ready logging with semantic result codes
* **Structured Configuration**: INI with sections ([core], [reverse_proxy], [ai_crawlers], [rate_limits], etc.)
* **Complete Bot Registry**: 50+ bots across Search, AI, Social, SEO, Archive, Monitoring categories
* **Legacy-Compatible Defaults**: **Zero false positives on AJAX, JSON APIs, file uploads, curl/wget** — works like 2.x out of the box

**BREAKING CHANGES from 2.x:**
- Minimum PHP version now 8.2
- All procedural `.inc.php` files replaced with OOP classes in `src/`
- Hex result codes (e.g. `'17f4e8c8'`) replaced with semantic `ResultCode` enum
- Configuration format changed from flat INI to structured INI with sections
- Adapter interface expanded with new required methods
- Database schema updated with new columns (`bot_category`, `ja3`, `header_order_hash`, `asn`, `country`)
- Custom adapters must implement new `CacheInterface` methods

> **Important**: Unlike typical 3.0 rewrites, **Bad Behaviour 3.0 defaults to legacy 2.x behavior**. All new detection features (fingerprinting, JSON body inspection, multipart inspection, strict header checks) are **disabled by default**. Enable them explicitly via configuration when needed.

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
│   ├── BotDetector.php           # 50+ known bots (verified SE/AI bypass all)
│   ├── BlacklistDetector.php     # Malicious UA, URL attacks, form body (form-only)
│   ├── BehavioralDetector.php    # Rate anomalies, rotating UA/IP, think time, headers
│   ├── FingerprintDetector.php   # JA3, H2, header order (opt-in, config-only)
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
│   ├── UaParser.php              # Browser/OS/device/bot/http_tool parsing
│   └── RequestPackage.php        # Immutable request DTO with AJAX/form helpers
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
use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;

// Optional custom settings
$custom = [
    'strict' => true,
    'allowed_ai_crawlers' => ['GPTBot', 'ClaudeBot'],
    'block_unverified_ai' => true,
    'strict_ai' => true,
];

$adapter = new GenericAdapter();
$config = Configuration::from_array($custom, $adapter);
$bb = new BadBehaviour($config);

$result = $bb->run();
if (!$result->is_allowed())
{
    $bb->handle_result($result);
}
```

**For MediaWiki (e.g. `LocalSettings.php`):**
```php
require "$IP/vendor/autoload.php";

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\MediaWikiAdapter;

$db = wfGetDB(DB_MASTER);
$adapter = new MediaWikiAdapter($db, $wgDBprefix, $wgEmergencyContact, $wgScript);
$bb = new BadBehaviour(Configuration::from_array([], $adapter));
$bb->run();
```

**For WackoWiki:**
```php
require 'vendor/autoload.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\WackoWikiAdapter;

$adapter = new WackoWikiAdapter($db);
$bb = BadBehaviour::withAdapter($adapter);

$result = $bb->run();
if (!$result->is_allowed())
{
	$bb->handle_result($result);
}
```

### Option 2: Single Entry Point (Any PHP App)

For maximum simplicity, use the single entry point:

```php
require 'vendor/autoload.php';

// Optional overrides via environment
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

### Quick Start: Safe Defaults (Legacy-Compatible)

```ini
; config/bb_settings.conf (or settings.ini)
[core]
logging = true
verbose = false
strict = false
offsite_forms = false

; New 3.0 features (opt-in — all FALSE by default for compatibility)
enable_fingerprinting = false
inspect_json_body = false
inspect_multipart_body = false
enable_behavioral_analysis = true
enable_ai_crawler_control = true

[ai_crawlers]
allowed[] = "GPTBot"
allowed[] = "ClaudeBot"
allowed[] = "Google-Extended"
allowed[] = "GrokBot"
allowed[] = "MistralBot"
block_unverified_ai = true
strict_ai = false

[rate_limits]
enabled = true
global.requests = 1000
global.window = 3600
per_minute.requests = 60
per_minute.window = 60
post.requests = 30
post.window = 3600
login.requests = 10
login.window = 900
```
> **Note**: The parser automatically converts all formats (dot notation, arrays, comma-separated) to the nested array structure expected by the code. Use whichever style you prefer — they're interchangeable.

### Core Settings (`[core]`)

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `logging` | bool | `true` | **NONE** | Always — required for audit trail |
| `verbose` | bool | `false` | **LOW** — log volume | Debugging only; logs *every* request |
| `strict` | bool | `false` | 🔴 **HIGH** — breaks valid traffic | Only if you control all clients (API-only, internal) |
| `offsite_forms` | bool | `false` | 🟡 **MEDIUM** — blocks external POSTs | If you have **zero** legitimate external form posts |
| `enable_fingerprinting` | bool | `false` | 🟡 **MEDIUM** — FP on old browsers/proxies | After 2+ weeks monitoring logs |
| `inspect_json_body` | bool | `false` | 🔴 **HIGH** — blocks wiki markup, code | **Never** for AJAX/JSON apps |
| `inspect_multipart_body` | bool | `false` | 🔴 **HIGH** — blocks file uploads | **Never** for upload endpoints |
| `enable_behavioral_analysis` | bool | `true` | 🟢 **LOW** — rate/rotating UA | Keep enabled (safe) |
| `enable_ai_crawler_control` | bool | `true` | 🟢 **LOW** — verified AI allowed | Keep enabled |

### Reverse Proxy (`[reverse_proxy]`)

| Setting | Type | Default | Risk | When to Configure |
|---------|------|---------|------|-------------------|
| `enabled` | bool | `false` | 🟡 **MEDIUM** — wrong IP if misconfigured | **Required** if behind Cloudflare, nginx, ALB, etc. |
| `header` | string | `X-Forwarded-For` | — | Match your proxy's header |
| `addresses[]` | CIDR[] | `[]` | 🔴 **HIGH** — spoofing if wrong | **Must** list all proxy IP ranges |

> ⚠️ **Never enable `enabled=true` without `addresses[]`** — allows IP spoofing.

**Common Cloudflare IPs** (add to `addresses[]`):
```
173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22
141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20
197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13
104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
```

### AI Crawlers (`[ai_crawlers]`)

| Setting | Type | Default | Risk | When to Change |
|---------|------|---------|------|----------------|
| `allowed[]` | string[] | `GPTBot, ClaudeBot, Google-Extended` | 🟢 **LOW** | Add/remove based on your robots.txt policy |
| `block_unverified_ai` | bool | `true` | 🟢 **LOW** | Keep `true` — blocks spoofed AI bots |
| `strict_ai` | bool | `false` | 🟡 **MEDIUM** — blocks even verified unallowed AI | Only if you want **zero** AI crawlers |

**Verified AI Crawlers** (IP + DNS verified):
| Token | Robots.txt | Owner | Verification |
|-------|------------|-------|--------------|
| `GPTBot` | `GPTBot` | OpenAI | DNS `openai.com` |
| `ClaudeBot` | `ClaudeBot` | Anthropic | DNS `anthropic.com` |
| `Google-Extended` | `Google-Extended` | Google | DNS `googlebot.com` |
| `PerplexityBot` | `PerplexityBot` | Perplexity | IP ranges only |
| `Meta-ExternalAgent` | `Meta-ExternalAgent` | Meta | DNS `facebook.com` |
| `Applebot-Extended` | `Applebot-Extended` | Apple | DNS `applebot.apple.com` |
| `CCBot` | `CCBot` | Common Crawl | IP ranges only |
| `ia_archiver` | `ia_archiver` | Internet Archive | IP ranges only |

### Bot Categories (`[bot_categories]`)

| Setting | Type | Default | Risk | Notes |
|---------|------|---------|------|-------|
| `blocked[]` | string[] | `["malicious"]` | 🟡 **MEDIUM** | Categories: `search_engine`, `ai_crawler`, `social_crawler`, `seo_crawler`, `archive_crawler`, `monitoring`, `malicious`, `unknown` |

> Only `malicious` blocked by default. Adding `seo_crawler` blocks Ahrefs, Semrush, MJ12bot, etc.

### Rate Limiting (`[rate_limits]`)

| Setting | Type | Default | Risk | Tuning |
|---------|------|---------|------|--------|
| `enabled` | bool | `true` | 🟢 **LOW** | Keep enabled |
| `global_requests` | int | `1000` | 🟢 **LOW** | Per IP per `global_window` |
| `global_window` | int | `3600` | — | Seconds (1 hour) |
| `per_minute_requests` | int | `60` | 🟢 **LOW** | Burst protection |
| `per_minute_window` | int | `60` | — | Seconds |
| `post_requests` | int | `30` | 🟢 **LOW** | Form spam protection |
| `post_window` | int | `3600` | — | Seconds (1 hour) |
| `login_requests` | int | `10` | 🟢 **LOW** | Brute force protection |
| `login_window` | int | `900` | — | Seconds (15 min) |

**Login endpoint detection**: Automatically triggers on URLs matching `/(login|signin|auth|password)/i`.

### Challenge System (`[challenge]`)

| Setting | Type | Default | Risk | Providers |
|---------|------|---------|------|-----------|
| `enabled` | bool | `false` | 🟡 **MEDIUM** — UX friction | `builtin`, `hcaptcha`, `recaptcha`, `turnstile` |
| `provider` | string | `builtin` | — | `builtin` = PoW (no external deps) |
| `site_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `secret_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `recaptcha_min_score` | float | `0.5` | — | reCAPTCHA v3 only (0.0–1.0) |

> **Builtin PoW** works everywhere, no keys needed. Use for internal/admin areas.

### Performance (`[performance]`)

| Setting | Type | Default | Notes |
|---------|------|---------|-------|
| `skip_extensions[]` | string[] | `css, js, png, jpg, jpeg, gif, ico, svg, woff, woff2, ttf, eot, webp, avif, map, txt` | Never inspect these |
| `skip_paths[]` | string[] | `/static/, /assets/, /media/, /images/, /css/, /js/, /fonts/, /dist/, /build/, /vendor/, /node_modules/` | Prefix match |

### http:BL (`[httpbl]`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `httpbl_key` | string | `""` | API key from Project Honey Pot |
| `httpbl_threat` | int | `25` | Threat score threshold (0-255) |
| `httpbl_maxage` | int | `30` | Max days since last activity |

### DNSBL (`[dnsbl]`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `dnsbl_lists[]` | string[] | `zen.spamhaus.org, bl.spamcop.net` | Additional DNSBL lists |

### Fingerprints (`[fingerprints]`) — Opt-in Only

```ini
[fingerprints]
bad_ja3[] = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
bad_h2[] = "a1b2c3d4e5f67890"
bot_header_orders[] = "a1b2c3d4e5f67890"
```

### GeoIP (`[geoip]`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `geoip_enabled` | bool | `false` | Enable GeoIP lookups |
| `geoip_database_path` | string | `""` | Path to MaxMind DB |
| `blocked_countries[]` | string[] | `[]` | ISO country codes to block |
| `blocked_asns[]` | string[] | `[]` | ASN numbers to block |

### Custom Rules (`[custom_rules]`)

```ini
[custom_rules]
rule1_type = "ip"
rule1_value = "192.0.2.0/24"
rule1_action = "block"
rule1_id = "test_network"

rule2_type = "ua_regex"
rule2_value = "badbot\d+"
rule2_action = "block"
rule2_id = "badbot_pattern"

rule3_type = "country"
rule3_value = "CN"
rule3_action = "challenge"
rule3_id = "china_challenge"

rule4_type = "asn"
rule4_value = "AS12345"
rule4_action = "block"
rule4_id = "bad_asn"
```

**Rule Types:** `ip`, `ua_regex`, `ua_contains`, `asn`, `country`, `header`
**Actions:** `allow`, `block`, `challenge`, `log`

### Logging (`[logging]`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `log_destination` | string | `"database"` | `database`, `syslog`, `file`, `json` |
| `log_file_path` | string | `""` | Path for file logging |
| `log_json_format` | bool | `false` | Use JSON format for logs |

---

## Whitelist (`whitelist.ini`)

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
de = "DE"
```

---

## Detection Pipeline (Execution Order)

1. **Whitelist** - IP, UA, URL, ASN, Country
2. **Custom Rules** - IP, UA regex, ASN, Country, Header
3. **BotDetector** - 50+ known bots (verified Search/AI **bypass all checks**)
4. **BlacklistDetector** - Malicious UA, URL attack patterns, **form body only**
5. **DnsblDetector** - http:BL, Spamhaus, SpamCop
6. **BehavioralDetector** - Rate anomalies, rotating UA/IP, **think time**, headers
7. **RateLimitDetector** - Multi-tier (global, per-minute, POST, login)
8. **FingerprintDetector** - JA3, H2, header order (**opt-in only**)

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
global.requests = 1000      ; per hour
global.window = 3600
per_minute.requests = 60
per_minute.window = 60
post.requests = 30          ; per hour
post.window = 3600
login.requests = 10         ; per 15 min
login.window = 900
```

---

## Custom Adapters

Implement `AdapterInterface` for custom platforms:

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
5. **Entry Points**: Use `Bootstrap::run()` or `BadBehaviour::withAdapter($adapter)`

> **Good news**: If you use the legacy entry points (`bad-behaviour-wackowiki.php`, etc.), they work unchanged. The new defaults **match 2.x behavior exactly** — no config changes needed.

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
- [Migration Guide](docs/MIGRATION.md) - 2.x to 3.0 upgrade
- [Configuration Reference](docs/CONFIGURATION.md) - Complete settings guide with risk matrix
- [Issues](https://github.com/Bad-Behaviour/badbehaviour/issues) - Bug reports
- [Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions) - Questions

---

*Bad Behaviour 3.0 - Modern bot detection for the modern web. With legacy-compatible defaults.*
