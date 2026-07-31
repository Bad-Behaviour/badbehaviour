# Bad Behaviour

**A PHP gatekeeper that blocks link spam, malicious bots, AI scrapers, and automated attacks before they reach your application.**

Trusted by thousands of sites—from personal blogs to enterprise platforms—to drastically reduce malicious traffic and server load.

### Why Bad Behaviour?
| Feature | Benefit |
| :--- | :--- |
| **Pre-emptive Blocking** | Stops bad actors *before* they deliver payloads or read your content. |
| **Performance** | Lowers server load; keeps access logs clean. |
| **DoS Mitigation** | Helps prevent denial-of-service conditions caused by bot swarms. |
| **Zero-Config Defaults** | Works out-of-the-box on most PHP platforms in minutes. |

### How It's Different
Unlike WAFs or content filters that inspect *payloads*, Bad Behaviour analyzes the **delivery mechanism**:
*   **TLS & HTTP/2 Fingerprinting** (JA3, Settings, Header Order)
*   **Client Hints Cross-Validation** (`Sec-CH-UA` vs `User-Agent`)
*   **Behavioral & Agentic Analysis** (Rate anomalies, AI-agent patterns)
*   **Request-Method Analysis** (HEAD flooding for site mapping)
*   **Asset-Scraping Detection** (AI training crawlers that skip HTML loads)
*   **Attacker Software Identification** (50+ verified bots, dynamic IP feeds)

This allows it to block **zero-day exploits and novel scrapers** that signature-based tools miss.

### Ecosystem & Compatibility
*   **Framework Agnostic:** Works with virtually any PHP-based software (WordPress, Drupal, MediaWiki, custom CMS, forums).
*   **Defense in Depth:** Designed to run **alongside** a WAF, rate limiter, or spam service—increasing their efficiency by filtering noise upstream.
*   **Platform Integrations:** Ready-to-use adapters for [Generic PHP](#option-1-modern-composer-usage-recommended), [MediaWiki](#for-mediawiki-eg-localsettingsphp), [WackoWiki](#for-wackowiki), and legacy drop-in files.

### Quick Start
```bash
# 1. Install
composer require badbehaviour/badbehaviour

# 2. Run (Generic PHP example)
php -r "require 'vendor/autoload.php'; \BadBehaviour\Bootstrap::run();"
```
> **No configuration required** for safe, legacy-compatible defaults. **[Installation Guide →](#installation--usage)** | **[Configuration Reference →](#configuration)**

---

### License
**LGPL-3.0-or-later** – Free to use, modify, and distribute. *[Full License →](#license)*

---

## What's New in 3.0 (Complete Modern Rewrite)

Version 3.0 is a complete rewrite of Bad Behaviour, modernizing the 10+ year old codebase from procedural PHP to a clean, typed PHP 8.2+ architecture with modern bot detection capabilities and a modern detection surface.

### Core changes

* **Complete Rewrite** — modern PHP 8.2+ architecture with strict typing, enums, readonly classes, and PSR-4 autoloading
* **PHP-array configuration** (`bb_config.php`) — typed values, no INI parsing ambiguity, full IDE support
* **Structured JSON logging** — SIEM-ready logging with semantic result codes
* **IPv6 Support** — full CIDR matching with binary comparison (no GMP required)
* **Challenge System** — builtin proof-of-work, hCaptcha, reCAPTCHA v3, Cloudflare Turnstile
* **Complete Bot Registry** — 50+ bots across Search, AI, Social, SEO, Archive, Monitoring categories
* **Legacy-Compatible Defaults** — **zero false positives on AJAX, JSON APIs, file uploads, curl/wget** — works like 2.x out of the box

### Detection gaps closed

| Gap | Solution |
|-----|----------|
| Spoofed UA + missing Client Hints | `ClientHintsDetector` — cross-validates `User-Agent` against `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile`, full version list |
| Stale IP ranges | `IpFeedInterface` + `FeedRegistry` — pulls fresh ranges from Google, Bing, OpenAI, Anthropic, Apple, Perplexity, Cloudflare (cron-driven, **experimental**) |
| AI agents mimicking humans | `AgenticBehaviorDetector` — detects think-then-fetch bursts, non-linear navigation, precision targeting (no CSS/fonts/tracking) |
| HEAD flooding + direct asset scraping | `HeadRequestDetector` + `AssetScrapingDetector` — flags site-mapping via HEAD and AI training scrapers hitting `/img1.png, /img2.png, …` without loading the HTML page that references them |

### AI Crawler Control

Granular control over GPTBot, ClaudeBot, Google-Extended, PerplexityBot, Meta AI, Applebot-Extended, and more (**opt-in**).

### AI/ML-Ready Fingerprinting

JA3 TLS fingerprinting, HTTP/2 settings analysis, header order analysis — **config-driven, opt-in, zero false positives by default**.

### Advanced POST Body Inspection

SQLi, XSS, command injection, Log4Shell, Spring4Shell, SSRF, path traversal, file inclusion — **only for form data, opt-in for JSON/multipart**.

### Behavioral Analysis

Rate anomalies, rotating User-Agents/IPs, URL enumeration, missing headers, timing analysis — **safe defaults, legacy-compatible**.

### Multi-Tier Rate Limiting

Global, per-minute, POST, and login endpoints with adapter-backed storage.

### BREAKING CHANGES from 2.x

- Minimum PHP version now 8.2
- All procedural `.inc.php` files replaced with OOP classes in `src/`
- Hex result codes (e.g. `'17f4e8c8'`) replaced with semantic `ResultCode` enum
- Configuration format changed from INI to a **PHP array** in `bb_config.php`
- Adapter interface expanded with new required methods
- Database schema updated with new columns (`bot_category`, `ja3`, `header_order_hash`, `asn`, `country`)
- Custom adapters must implement new `CacheInterface` methods

> **Important**: Unlike typical 3.0 rewrites, **Bad Behaviour 3.0 defaults to legacy 2.x behavior**. Most new detection features (fingerprinting, JSON body inspection, multipart inspection, strict header checks, Client Hints validation, agentic detection) are **disabled by default**. The two exceptions — **HEAD request detection** and **asset scraping detection** — are enabled by default because they target clearly malicious patterns (site-mapping and AI training scrapers) with negligible false-positive risk. Enable the others explicitly via configuration when needed.

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
│   ├── DnsblDetector.php         # http:BL, Spamhaus, SpamCop
│   ├── ClientHintsDetector.php   # NEW — Sec-CH-UA brand/version/platform/mobile validation
│   ├── AgenticBehaviorDetector.php # NEW — AI-agent pattern detection
│   ├── HeadRequestDetector.php   # NEW — HEAD flooding + Referer check
│   └── AssetScrapingDetector.php # NEW — asset-only sessions + sequential patterns
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
├── Feeds/                        # NEW — dynamic IP range feeds (experimental)
│   ├── IpFeedInterface.php
│   ├── FeedRegistry.php
│   ├── CachedFeedDecorator.php
│   └── Adapters/
│       ├── AbstractJsonFeed.php
│       ├── GoogleJsonFeed.php
│       ├── BingJsonFeed.php
│       ├── OpenAIJsonFeed.php
│       ├── AnthropicJsonFeed.php
│       ├── AppleJsonFeed.php
│       ├── GenericJsonFeed.php
│       └── PlainTextFeed.php
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

Bad Behaviour 3.0 uses a typed **PHP-array configuration file** (`config/bb_config.php`). The file returns an associative array with full IDE type support and zero parsing ambiguity.

### Quick Start: Safe Defaults (Legacy-Compatible)

Copy `config/bb_config.example.php` → `config/bb_config.php`. The shipped defaults are 2.x-compatible — no edits needed for a drop-in upgrade.

```php
<?php
// config/bb_config.php
return [
    // ===== CORE =====
    'logging'                    => true,
    'verbose'                    => false,
    'strict'                     => false,
    'offsite_forms'              => false,

    'show_contact_info'          => false,  // Block page: show admin email
    'show_detailed_block_page'   => false,  // Block page: show reason + support key

    // ===== REVERSE PROXY =====
    'reverse_proxy' => [
        'enabled'   => false,
        'header'    => 'X-Forwarded-For',
        'addresses' => [],
    ],

    // ===== AI CRAWLERS =====
    'ai_crawlers' => [
        'allowed'          => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
        'block_unverified' => true,
        'strict'           => false,
    ],

    // ===== 3.0 DETECTION FEATURES (opt-in) =====
    'enable_fingerprinting'           => false,  // JA3, H2, header order
    'inspect_json_body'               => false,  // SQL/XSS in JSON bodies
    'inspect_multipart_body'          => false,  // SQL/XSS in multipart uploads
    'enable_behavioral_analysis'      => true,
    'enable_ai_crawler_control'       => true,
    'enable_client_hints_validation'  => false,  // NEW — Sec-CH-UA cross-check
    'enable_agentic_detection'        => false,  // NEW — AI-agent pattern detection
    'enable_dynamic_ip_ranges'        => false,  // NEW (EXPERIMENTAL) — feeds on cron

    // ===== HEAD REQUEST DETECTION (enabled by default — low FP risk) =====
    'enable_head_request_detection'   => true,
    'head_require_referer'            => true,
    'head_flood_threshold'            => 20,
    'head_probe_threshold'            => 50,
    'head_referer_exempt_paths'       => ['/api/', '/wp-json/', '/health', '/status'],

    // ===== ASSET SCRAPING DETECTION (enabled by default — low FP risk) =====
    'enable_asset_scraping_detection' => true,
    'asset_extensions'                => [
        'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'mp3', 'mp4', 'wav', 'ogg', 'webm',
    ],
    'asset_no_referer_threshold'      => 10,
    'asset_only_session_threshold'    => 20,
    'asset_pattern_threshold'         => 100,
];
```

See [`CONFIGURATION.md`](docs/CONFIGURATION.md) for the complete reference.

### Configuration Profiles

Three reference profiles cover ~95% of use cases. Pick one as your starting point, then customize.

| | **Default** | **Medium** | **Strict** |
|---|---|---|---|
| Compatibility | All browsers & tools | Modern browsers + most tools | Chromium 89+ / Firefox 100+ / Safari 15+ |
| False positive risk | 🟢 Minimal | 🟡 Low (monitor 1–2 weeks per feature) | 🔴 High (full FP audit first) |
| Setup effort | None — drop-in | ~30 min monitoring, then flip switches | Multi-week rollout |
| Best for | 2.x migration, shared hosting, public CMS | Production sites with monitored traffic | Internal APIs, paid content, abuse targets |

#### Quick decision

```
Migrating from 2.x or shared hosting?
  → DEFAULT

Production site with modern browsers + monitoring?
  → MEDIUM (after 1-2 weeks soak per new feature)

Internal API / B2B / paid content / high-abuse target?
  → STRICT (with full FP audit first)

Public CMS with mixed audience (old browsers, AJAX, uploads)?
  → DEFAULT (strict would break too much)
```

#### What breaks at each level

| Client | Default | Medium | Strict |
|--------|:-------:|:------:|:------:|
| Chrome 89+ | ✅ | ✅ | ✅ |
| Chrome < 89 | ✅ | ⚠️ | 🔴 |
| Firefox (any) | ✅ | ✅ | ⚠️ if `strict` |
| Safari 15+ | ✅ | ✅ | ✅ |
| Safari < 15 | ✅ | ✅ | 🔴 |
| Edge 89+ | ✅ | ✅ | ✅ |
| IE 11 | ✅ | ✅ | 🔴 |
| Electron apps | ✅ | ⚠️ needs whitelist | 🔴 |
| curl / wget / Python | ✅ | ✅ | ✅ |
| AJAX / fetch / XHR | ✅ | ✅ | ⚠️ if `inspect_json_body` |
| File uploads | ✅ | ✅ | 🔴 if `inspect_multipart_body` |
| Webhooks (off-site POST) | ✅ | ✅ | ⚠️ if `offsite_forms` |
| AI agents (Brave Leo, etc.) | ❌ allowed | ✅ detected | ✅ detected |
| AI training scrapers (asset-only sessions) | ❌ allowed | ✅ detected | ✅ detected |
| Legacy curl/wget link checkers | ✅ | ✅ | ⚠️ if `strict` |

✅ works • ⚠️ may need config • 🔴 will break • ❌ not detected

See [`CONFIGURATION.md`](docs/CONFIGURATION.md#configuration-profiles) for full profile configs and per-setting rationale.

#### Hard points to remember

- **Firefox does NOT send Sec-CH-UA headers** — Client Hints validation ignores Firefox/Safari by design. Only Chromium-based browsers are validated.
- **Electron apps** (Slack, VS Code, Discord) send Chrome UA but no Client Hints — they'll be blocked at Medium+. Add to whitelist if needed.
- **Agentic detection requires session cookies** — anonymous traffic is skipped entirely.
- **`strict = true`** requires `Accept-Encoding` header — breaks some privacy-focused browsers.
- **`inspect_json_body` / `inspect_multipart_body`** — almost never safe to enable on public sites; breaks legitimate code snippets and uploads.

---

### Core Settings

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
| `enable_client_hints_validation` | bool | `false` | 🟡 **MEDIUM** — FP on older browsers | After monitoring; requires Chromium 89+ |
| `enable_agentic_detection` | bool | `false` | 🟡 **MEDIUM** — FP on power users | After monitoring; needs session cookies |
| `enable_dynamic_ip_ranges` | bool | `false` | 🟡 **EXPERIMENTAL** | Requires cron; see [Feeds](#dynamic-ip-range-feeds) |

#### Head Request Detection (`head_*`)

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `enable_head_request_detection` | bool | `true` | 🟢 **LOW** | Keep enabled — blocks a real attack vector |
| `head_require_referer` | bool | `true` | 🟢 **LOW** | Keep enabled — link checkers send Referer naturally |
| `head_flood_threshold` | int | `20` | 🟢 **LOW** | HEAD requests per session before block |
| `head_probe_threshold` | int | `50` | 🟢 **LOW** | HEAD probes per IP per 5 min |
| `head_referer_exempt_paths[]` | string[] | `['/api/', '/wp-json/', '/health', '/status']` | 🟢 **LOW** | Paths where HEAD without Referer is legitimate (REST clients, monitoring) |

#### Asset Scraping Detection (`asset_*`)

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `enable_asset_scraping_detection` | bool | `true` | 🟢 **LOW** | Keep enabled — targets AI training scrapers |
| `asset_extensions[]` | string[] | images, documents, audio, video | 🟡 **MEDIUM** | Add/remove based on what content you serve |
| `asset_no_referer_threshold` | int | `10` | 🟢 **LOW** | Asset requests without Referer per IP per hour |
| `asset_only_session_threshold` | int | `20` | 🟢 **LOW** | Asset requests with no HTML loads per session |
| `asset_pattern_threshold` | int | `100` | 🟢 **LOW** | Sequential asset URLs per IP per 5 min |

### Reverse Proxy

| Setting | Type | Default | Risk | When to Configure |
|---------|------|---------|------|-------------------|
| `reverse_proxy.enabled` | bool | `false` | 🟡 **MEDIUM** — wrong IP if misconfigured | **Required** if behind Cloudflare, nginx, ALB, etc. |
| `reverse_proxy.header` | string | `X-Forwarded-For` | — | Match your proxy's header |
| `reverse_proxy.addresses[]` | CIDR[] | `[]` | 🔴 **HIGH** — spoofing if wrong | **Must** list all proxy IP ranges |

> ⚠️ **Never enable `enabled=true` without `addresses[]`** — allows IP spoofing.

**Common Cloudflare IPs** (add to `addresses[]`):
```
173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22
141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20
197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13
104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
```

### AI Crawlers (`ai_crawlers`)

| Setting | Type | Default | Risk | When to Change |
|---------|------|---------|------|----------------|
| `allowed[]` | string[] | `GPTBot, ClaudeBot, Google-Extended` | 🟢 **LOW** | Add/remove based on your robots.txt policy |
| `block_unverified` | bool | `true` | 🟢 **LOW** | Keep `true` — blocks spoofed AI bots |
| `strict` | bool | `false` | 🟡 **MEDIUM** — blocks even verified unallowed AI | Only if you want **zero** AI crawlers |

**Verified AI Crawlers** (IP + DNS verified):
| Token | Robots.txt | Owner | Verification |
|-------|------------|-------|--------------|
| `GPTBot` | `GPTBot` | OpenAI | DNS `openai.com` |
| `ClaudeBot` | `ClaudeBot` | Anthropic | DNS `anthropic.com` |
| `Google-Extended` | `Google-Extended` | Google | DNS `googlebot.com` |
| `PerplexityBot` | `PerplexityBot` | Perplexity | IP ranges only |
| `Meta-ExternalAgent` | `Meta-ExternalAgent` | Meta | DNS `facebook.com` |
| `Applebot-Extended` | `Applebot-Extended` | Apple | DNS `applebot.apple.com` |
| `GrokBot` | `GrokBot` | xAI | DNS `x.ai` |
| `MistralBot` | `MistralBot` | Mistral AI | DNS `mistral.ai` |
| `CCBot` | `CCBot` | Common Crawl | IP ranges only |
| `ia_archiver` | `ia_archiver` | Internet Archive | IP ranges only |

### Bot Categories (`bot_categories`)

| Setting | Type | Default | Risk | Notes |
|---------|------|---------|------|-------|
| `blocked[]` | string[] | `["malicious"]` | 🟡 **MEDIUM** | Categories: `search_engine`, `ai_crawler`, `social_crawler`, `seo_crawler`, `archive_crawler`, `monitoring`, `malicious`, `unknown` |

> Only `malicious` blocked by default. Adding `seo_crawler` blocks Ahrefs, Semrush, MJ12bot, etc.

### Rate Limiting (`rate_limits`)

| Setting | Type | Default | Risk | Tuning |
|---------|------|---------|------|--------|
| `enabled` | bool | `true` | 🟢 **LOW** | Keep enabled |
| `global.requests` | int | `1000` | 🟢 **LOW** | Per IP per `global.window` |
| `global.window` | int | `3600` | — | Seconds (1 hour) |
| `per_minute.requests` | int | `60` | 🟢 **LOW** | Burst protection |
| `per_minute.window` | int | `60` | — | Seconds |
| `post.requests` | int | `30` | 🟢 **LOW** | Form spam protection |
| `post.window` | int | `3600` | — | Seconds (1 hour) |
| `login.requests` | int | `10` | 🟢 **LOW** | Brute force protection |
| `login.window` | int | `900` | — | Seconds (15 min) |

**Login endpoint detection**: Automatically triggers on URLs matching `/(login|signin|auth|password)/i`.

### Challenge System (`challenge`)

| Setting | Type | Default | Risk | Providers |
|---------|------|---------|------|-----------|
| `enabled` | bool | `false` | 🟡 **MEDIUM** — UX friction | `builtin`, `hcaptcha`, `recaptcha`, `turnstile` |
| `provider` | string | `builtin` | — | `builtin` = PoW (no external deps) |
| `site_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `secret_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `recaptcha_min_score` | float | `0.5` | — | reCAPTCHA v3 only (0.0–1.0) |

> **Builtin PoW** works everywhere, no keys needed. Use for internal/admin areas.

### Performance (`performance`)

| Setting | Type | Default | Notes |
|---------|------|---------|-------|
| `skip_extensions[]` | string[] | `css, js, png, jpg, jpeg, gif, ico, svg, woff, woff2, ttf, eot, webp, avif, map, txt` | Never inspect these |
| `skip_paths[]` | string[] | `/static/, /assets/, /media/, /images/, /css/, /js/, /fonts/, /dist/, /build/, /vendor/, /node_modules/` | Prefix match |

### Custom Rules (`custom_rules`)

```php
'custom_rules' => [
    // Block a hostile network
    ['type' => 'ip', 'value' => '192.0.2.0/24', 'action' => 'block', 'id' => 'test_network'],

    // Block a UA pattern
    ['type' => 'ua_regex', 'value' => 'badbot\d+', 'action' => 'block', 'id' => 'badbot_pattern'],

    // Challenge a country
    ['type' => 'country', 'value' => 'CN', 'action' => 'challenge', 'id' => 'china_challenge'],

    // Block an ASN
    ['type' => 'asn', 'value' => 'AS12345', 'action' => 'block', 'id' => 'bad_asn'],

    // Inspect a request header
    ['type' => 'header', 'header' => 'User-Agent', 'value' => 'suspicious-tool', 'action' => 'block', 'id' => 'bad_ua_header'],
],
```

**Rule Types:** `ip`, `ua_regex`, `ua_contains`, `asn`, `country`, `header`
**Actions:** `allow`, `block`, `challenge`, **`log`** (record only — continue pipeline)

#### Logging permitted bots (audit trail)

Use `action: 'log'` to record specific bots/search engines that you *allow* — useful for analytics, robots.txt auditing, or detecting brand-new bots:

```php
'custom_rules' => [
    // 1. Log every verified Googlebot hit
    [
        'type'    => 'ua_regex',
        'value'   => '/Googlebot/i',
        'action'  => 'log',
        'id'      => 'audit_googlebot',
    ],

    // 2. Log GPTBot (which you allow) — distinct from `ai_crawlers.allowed`
    [
        'type'    => 'ua_contains',
        'value'   => 'GPTBot',
        'action'  => 'log',
        'id'      => 'audit_gptbot',
    ],

    // 3. Log the new "Brave Leo" agentic UA so you can decide policy later
    [
        'type'    => 'header',
        'header'  => 'Sec-CH-UA',
        'value'   => 'Brave Leo',
        'action'  => 'log',
        'id'      => 'brave_leo_agentic',
    ],

    // 4. Log monitoring tools you whitelist (UptimeRobot, etc.)
    [
        'type'    => 'ua_regex',
        'value'   => '/UptimeRobot|Pingdom|StatusCake/i',
        'action'  => 'log',
        'id'      => 'audit_monitoring',
    ],
],
```

`log` rules **never block** — they return `null` from the rules evaluator, so the request continues through the full detection pipeline. The rule ID is recorded in the result metadata for downstream log filtering.

### Whitelist (`config/bb_whitelist.conf`)

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

1. **Whitelist** — IP, UA, URL, ASN, Country
2. **Custom Rules** — IP, UA regex, ASN, Country, Header (incl. `action: 'log'`)
3. **BotDetector** — 50+ known bots (verified Search/AI **bypass all checks**)
3b. **HeadRequestDetector** — HEAD flooding + Referer check (enabled by default)
4. **ClientHintsDetector** — Sec-CH-UA cross-check (opt-in)
5. **BlacklistDetector** — Malicious UA, URL attack patterns, **form body only**
5b. **AssetScrapingDetector** — Asset-only sessions, no-Referer floods, sequential URL patterns (enabled by default)
6. **BehavioralDetector** — Rate anomalies, rotating UA/IP, **think time**, headers
7. **AgenticBehaviorDetector** — AI-agent pattern detection (opt-in)
8. **RateLimitDetector** — Multi-tier (global, per-minute, POST, login)
9. **DnsblDetector** — http:BL, Spamhaus, SpamCop
10. **FingerprintDetector** — JA3, H2, header order (**opt-in only**)

---

## Dynamic IP Range Feeds (Experimental)

Hard-coded IP ranges go stale the moment a vendor adds a new region. `FeedRegistry` solves this by pulling fresh ranges from official sources.

### Supported sources

| Feed | Source | Bots covered |
|------|--------|--------------|
| Google common crawlers | `developers.google.com/.../common-crawlers.json` | `googlebot`, `google_ai` |
| Google user-triggered agents | `developers.google.com/.../user-triggered-agents.json` | `google_ai` |
| Bing | `www.bing.com/toolbox/bingbot.json` | `bingbot` |
| OpenAI GPTBot | `openai.com/gptbot.json` | `gptbot` |
| OpenAI ChatGPT-User | `openai.com/chatgpt-user.json` | `chatgpt-user` |
| OpenAI OAI-SearchBot | `openai.com/searchbot.json` | `oai-searchbot` |
| Anthropic Claude | `claude.com/crawling/bots.json` | `claude` |
| Apple Applebot | `search.developer.apple.com/applebot.json` | `applebot`, `apple_ai` |
| Perplexity | `www.perplexity.ai/perplexitybot.json` | `perplexity` |
| DuckDuckGo | `duckduckgo.com/duckassistbot.json` | `duckduckgo` |
| Amazon | `developer.amazon.com/amazonbot/ip-addresses.json` | `amazonbot` |
| Cloudflare v4/v6 | `cloudflare.com/ips-v4`, `.../ips-v6` | `cloudflare` |

### Enabling

In `bb_config.php`:
```php
'enable_dynamic_ip_ranges' => true,
```

### Refreshing (cron)

Feeds are **not fetched on the request path** — they're too slow. Run the included CLI script via cron:

```bash
# Refresh every 6 hours
0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php
```

The script writes to `bb:ip_ranges:merged` in your adapter's cache (file by default, Redis in MediaWiki adapter). Each feed has its own 24h TTL with a 7-day stale fallback.

### ⚠️ Why "experimental"?

1. **Caching boundaries** — file cache doesn't share across multi-server deployments; use the MediaWiki adapter's WAN cache for production
2. **Feed shape changes** — vendors occasionally add new fields; the parser must be tolerant
3. **Cold-start latency** — first request after TTL expiry triggers fetches unless cron runs in time
4. **CA bundle portability** — auto-detection works on Debian/RHEL/Homebrew but not on stripped-down containers

Once these are resolved the flag will be dropped in a 3.x point release.

---

## AI Crawler Management

Bad Behaviour 3.0 provides granular control over AI crawlers:

```php
'ai_crawlers' => [
    'allowed' => [
        'GPTBot',           // OpenAI
        'ClaudeBot',        // Anthropic
        'Google-Extended',  // Google Vertex/Bard/Gemini
        'PerplexityBot',    // Perplexity
        'CohereBot',        // Cohere
        'Meta-ExternalAgent', // Meta
        'Applebot-Extended',  // Apple
        'YouBot',           // You.com
        'KagiBot',          // Kagi Search
    ],
    'block_unverified' => true,  // Block spoofed AI crawlers
    'strict'           => false, // true = block even verified unallowed AI
],
```

| Crawler | Token | Robots.txt Token | Verification |
|---------|-------|------------------|--------------|
| GPTBot | GPTBot | GPTBot | DNS (openai.com) |
| ClaudeBot | ClaudeBot | ClaudeBot | DNS (anthropic.com) |
| Google-Extended | Google-Extended | Google-Extended | DNS (googlebot.com) |
| PerplexityBot | PerplexityBot | PerplexityBot | IP ranges only |
| Meta AI | Meta-ExternalAgent | Meta-ExternalAgent | DNS (facebook.com) |
| Applebot-Extended | Applebot-Extended | Applebot-Extended | DNS (applebot.apple.com) |
| Common Crawl | CCBot | CCBot | IP ranges only |
| Internet Archive | ia_archiver | ia_archiver | IP ranges only |

---

## Challenge System

When `challenge.enabled = true`, suspicious requests receive a challenge:

```php
'challenge' => [
    'enabled'  => true,
    'provider' => 'hcaptcha',  // builtin, hcaptcha, recaptcha, turnstile
    'site_key'   => 'your-site-key',
    'secret_key' => 'your-secret-key',
    'recaptcha_min_score' => 0.5,
],
```

**Providers:**
- `builtin` — zero-dependency proof-of-work (no external dependencies)
- `hcaptcha` — hCaptcha checkbox/invisible
- `recaptcha` — reCAPTCHA v3 (score-based)
- `turnstile` — Cloudflare Turnstile

---

## Client Hints Validation (3.0+)

Modern Chromium browsers (Chrome 89+, Edge 89+, Brave, Vivaldi, Opera 75+) send `Sec-CH-UA` headers that reveal the *real* browser brand and version. Spoofed UAs almost always omit or mis-match these.

Enable:
```php
'enable_client_hints_validation' => true,
```

**What it checks:**
- Missing *all* `Sec-CH-*` headers from a Chromium UA → **block** (impossible for a real browser)
- Brand mismatch (`Sec-CH-UA` says Edge, UA says Chrome) → **block**
- Version drift > 2 major releases → **block**
- Platform mismatch (UA says Linux, `Sec-CH-UA-Platform` says Windows) → **block**
- Mobile bit contradiction (`Sec-CH-UA-Mobile: ?1` but UA is desktop) → **block**

**Risk:** 🟡 MEDIUM — old Chromium-based browsers (< 89), Electron apps, and some headless tools don't send hints. Always monitor for 1–2 weeks before enabling in production.

---

## Agentic Behavior Detection (3.0+)

AI agents (Brave Leo, ChatGPT operator, custom scrapers built on Playwright/Selenium) increasingly *look* like browsers but fail to imitate *human browsing patterns*.

Enable:
```php
'enable_agentic_detection' => true,
```

**Three pattern detectors:**

1. **Think-then-fetch** — long pause (>10s) followed by burst of asset requests (<1s apart, ≥5 assets in <5s) → **block**
2. **Non-linear navigation** — 8+ requests across 5+ unrelated top-level sections → **block**
3. **Precision targeting** — high API/JSON ratio (>30%) with near-zero CSS/font/tracking requests (<5% / <2% / <1%) → **block**

**Risk:** 🟡 MEDIUM — power users with aggressive tab-opening habits or single-page-app users may trigger false positives. Requires a session cookie (`PHPSESSID`, `JSESSIONID`, etc.) — fully anonymous traffic is skipped.

---

## HEAD Request Detection (3.0+)

HEAD requests are cheap (no body transfer) and ideal for site mapping. Bots send thousands of HEAD requests to enumerate URLs without downloading content. Legitimate HEAD usage (link checkers, monitoring, REST APIs) is usually low-volume and from known sources.

Enable (enabled by default — `enable_head_request_detection = true`):

```php
'enable_head_request_detection' => true,
'head_require_referer'          => true,
'head_flood_threshold'          => 20,   // per session
'head_probe_threshold'          => 50,   // per IP per 5 min
'head_referer_exempt_paths'     => ['/api/', '/wp-json/', '/health', '/status'],
```

**Three signal detectors:**

1. **HEAD without Referer** — site mapping typically omits Referer; real browsers send it. Exempt paths (REST APIs, health checks) don't trigger this check.
2. **HEAD flood per session** — >20 HEAD requests in a single session = enumeration.
3. **HEAD probing per IP** — >50 HEAD requests from one IP in 5 minutes = rapid-fire reconnaissance.

**Risk:** 🟢 LOW — link checkers and monitoring tools naturally send Referer. REST clients hitting `/api/` are exempt by default. Disable `head_require_referer` only if you have legitimate clients (rare HTTP libraries) that send HEAD to non-API paths without Referer.

---

## Asset Scraping Detection (3.0+)

AI training scrapers and image harvesters download assets in bulk, often without loading the HTML pages first. Legitimate browser behavior: load HTML page → load referenced assets. Scrapers: directly request assets from a URL list.

Enable (enabled by default — `enable_asset_scraping_detection = true`):

```php
'enable_asset_scraping_detection' => true,
'asset_extensions'                => [
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'mp3', 'mp4', 'wav', 'ogg', 'webm',
],
'asset_no_referer_threshold'      => 10,   // per IP per hour
'asset_only_session_threshold'    => 20,   // per session (no HTML loads)
'asset_pattern_threshold'         => 100,  // sequential per IP per 5 min
```

**Three signal detectors:**

1. **Asset without Referer** — bots fetching `/img1.png, /img2.png, …` directly (not following page navigation) don't send Referer. Legitimate browsers do.
2. **Asset-only session** — >20 asset requests in a session where `html_requests === 0` = pure asset harvesting. Real browsers always load the HTML first.
3. **Sequential asset pattern** — >100 assets from a single IP in 5 minutes = scraping. Real browser asset requests are spread over time and mixed with HTML navigation.

**Risk:** 🟢 LOW — real browsers load HTML before assets, so legitimate users never trigger signal 2. For signal 1, monitor for `type: 'asset_no_referer_flood'` in logs to tune the threshold. Add `csv`, `json`, `xml`, or `zip` to `asset_extensions` if you serve those file types and want them protected.

---

## Rate Limiting

Multi-tier rate limiting with adapter-backed storage:

```php
'rate_limits' => [
    'enabled'      => true,
    'global'       => ['requests' => 1000, 'window' => 3600],  // per hour
    'per_minute'   => ['requests' => 60,   'window' => 60],
    'post'         => ['requests' => 30,   'window' => 3600],
    'login'        => ['requests' => 10,   'window' => 900],   // 15 min
],
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

See [`UPGRADE.md`](docs/UPGRADE.md) for detailed upgrade instructions. Key changes:

1. **Config**: INI → **PHP array** (`bb_config.php`)
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

- [Migration Guide](docs/UPGRADE.md) — 2.x to 3.0 upgrade
- [Configuration Reference](docs/CONFIGURATION.md) — Complete settings guide with risk matrix
- [Issues](https://github.com/Bad-Behaviour/badbehaviour/issues) — Bug reports
- [Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions) — Questions

---

*Bad Behaviour 3.0 — Modern bot detection for the modern web. With legacy-compatible defaults.*