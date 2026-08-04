# Bad Behaviour

**A PHP gatekeeper that blocks link spam, malicious bots, AI scrapers, and automated attacks before they reach your application.**

Trusted by thousands of sites—from personal blogs to enterprise platforms—to drastically reduce malicious traffic and server load.

### Why Bad Behaviour?
| Feature | Benefit |
| :--- | :--- |
| **Pre-emptive Blocking** | Stops bad actors *before* they deliver payloads or read your content. |
| **Performance** | Lowers server load; keeps access logs clean. |
| **DoS Mitigation** | Helps prevent denial-of-service conditions caused by bot swarms. |
| **Cloud Safety** | Hard-allows Cloudflare/AWS/GCP/Azure/Fastly LB health probes — blocking these = origin marked unhealthy = site-wide outage. |
| **Zero-Config Defaults** | Works out-of-the-box on most PHP platforms in minutes. |
| **Custom Bot Registries** | Pluggable, composable bot set: add internal bots, swap registries per tenant, or filter the ~100 shipped bots without forking the library. |

### How It's Different
Unlike WAFs or content filters that inspect *payloads*, Bad Behaviour analyzes the **delivery mechanism**:
*   **TLS & HTTP/2 Fingerprinting** (JA3, Settings, Header Order)
*   **Client Hints Cross-Validation** (`Sec-CH-UA` vs `User-Agent`)
*   **Behavioral & Agentic Analysis** (Rate anomalies, AI-agent patterns)
*   **Request-Method Analysis** (HEAD flooding for site mapping)
*   **Asset-Scraping Detection** (AI training crawlers that skip HTML loads)
*   **Attacker Software Identification** — **100+ verified bots** across 11 categories, dynamic IP feeds, **customizable registries**
*   **Cloud-LB Safety Net** — pre-UA-match fast path for AWS/Cloudflare/GCP/Azure/Fastly health probes

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

Version 3.0 is a complete rewrite of Bad Behaviour, modernizing the 10+ year old codebase from procedural PHP to a clean, typed PHP 8.2+ architecture. It bundles the full bot-registry expansion, four new bot categories, the cloud-infrastructure safety net, and a fully pluggable registry system.

### Core changes

* **Complete Rewrite** — modern PHP 8.2+ architecture with strict typing, enums, readonly classes, and PSR-4 autoloading
* **PHP-array configuration** (`bb_config.php`) — typed values, no INI parsing ambiguity, full IDE support
* **Structured JSON logging** — SIEM-ready logging with semantic result codes
* **IPv6 Support** — full CIDR matching with binary comparison (no GMP required)
* **Challenge System** — builtin proof-of-work, hCaptcha, reCAPTCHA v3, Cloudflare Turnstile
* **Custom Bot Registries** — `RegistryInterface` + eight implementations + factory + presets + per-tenant swap
* **Complete Bot Registry** — **100+ bots** across **11 categories** (Search, AI, Social, SEO, Archive, Monitoring, Feed, Shopping, Cloud, Security, Malicious)
* **Legacy-Compatible Defaults** — **zero false positives on AJAX, JSON APIs, file uploads, curl/wget** — works like 2.x out of the box

### Custom registries (new pluggable system)

Before: a single static `Registry` class holding ~100 bots; customization meant forking the library.

After: a proper `RegistryInterface` hierarchy you can compose without touching the library:

| Class | Purpose |
|---|---|
| `DefaultRegistry` | The ~100 shipped bots (read-only singleton) |
| `InMemoryRegistry` | Wrap a user-provided array of `BotDefinition`s |
| `EmptyRegistry` | No-op singleton — "humans only" baseline |
| `FilteredRegistry` | Keep/exclude lists + category filters |
| `MergedRegistry` | Compose multiple registries, last-wins per ID |
| `CustomRegistry` | Built from a config array, with validation |
| `RegistryFactory` | Builder entry point — `from_array()`, `from_file()`, `default()` |
| `Presets` | `full` / `minimal` / `verified-only` / `no-ai` / `no-seo` / `eu-only` / `human-only` / `custom` |

Pick a preset via the new `config/bb_registry.php` (ships with `full` + `cloud_infrastructure` safety net), or inject your own `RegistryInterface` programmatically:

```php
$registry = RegistryFactory::from_array([
    'preset'             => 'minimal',
    'exclude_categories' => ['seo_crawler'],
    'additions'          => ['my_bot' => [/* BotDefinition schema */]],
]);
$bb = new BadBehaviour($config, $registry);

// Per-tenant swap (multi-tenant deployments):
$bb->with_registry($tenant_registry);
```

See [**Custom Bot Registries**](#custom-bot-registries) below for the full schema, presets, and examples.

### Bot registry (~100 bots)

| Category | New additions |
|---|---|
| **search_engines** | `coccoc` (Vietnam #1), `mailru`/`Rambler` (Russia), `petal` (Huawei — promoted from SEO), `zum` (Korea), `stract`, `marginalia` (indie), `centrum`/`sklik` (Czech) |
| **ai_crawlers** | `amazon_ai` (Amazonbot), `semantic_scholar` (Allen Institute), `diffbot` (knowledge graph), `brightdata` (**default `BLOCK`** — residential proxy network) |
| **social_crawlers** | `kakao` (KR), `line` (JP/TW/TH), `wechat` (CN), `notion` (link previews) |
| **seo_crawlers** | `similarweb`, `seobility`, `botify`, `siteimprove`, `lumar`, `oncrawl`, `screaming_frog`, `contentking` |
| **archive_crawlers** | `UKWA` (British Library), `BnF` (Gallica, France), `DNB` (Germany), `KB-NL` (Delpher, Netherlands) — all `allow` (legal-deposit archives) |
| **feed_readers** | `feedly`, `inoreader`, `flipboard`, `newsblur`, `google_news`, `apple_news` — all `ALLOW` |
| **shopping_crawlers** | `google_shopping`, `bing_shopping`, `pinterest_shopping`, `facebook_catalog`, `shopify` — all `ALLOW` |
| **cloud_infrastructure** | `cloudflare_health`, `aws_elb_health`, `google_cloud_health`, `azure_health`, `fastly_health` — all **HARD `ALLOW`** |
| **security_scanners** | `qualys`, `detectify`, `rapid7`, `shodan`, `censys` — all `LOG_ONLY` |

### UA matching improvements

*   **`RegistryTokens::NOISE`** list to filter generic tokens (`"mozilla"`, `"compatible"`, `"browser"`, `"chrome"`, `"google"`, `"facebook"`, …) that cause false positives in token-based matching.
*   `find_by_tokens()` ignores tokens <5 chars and noise tokens.
*   `find_by_ua()` ignores fragments <4 chars.
*   `RegistryTokens` is the **single source of truth** — referenced by `DefaultRegistry`, `InMemoryRegistry`, `MergedRegistry`, `FilteredRegistry`, and `CustomRegistry` so noise rules stay consistent across all registry types.

### BotDetector changes

*   **`RegistryInterface` injection** — `new BotDetector($config, $adapter, $registry)`. Defaults to `RegistryFactory::default()` for drop-in compatibility.
*   **Fast path**: `is_cloud_infrastructure_ip()` runs **BEFORE** UA matching. Any IP in known cloud LB ranges short-circuits to `ALLOW` regardless of UA. **Reads the injected registry's `cloud_infrastructure()` method** so swapping the registry affects this check too (e.g., `human-only` preset removes the safety net — see warning below).
*   `determine_action()` gains hard-blocks for explicitly-blocked categories, hard-allows for `cloud_infrastructure`, and per-category defaults for feed/shopping/monitoring/archive (verified-only).
*   Result cache keyed by config fingerprint **and `spl_object_hash($registry)`** so swapping the registry cleanly invalidates cached results.
*   DNS verification scheduled via `register_shutdown_function` so it doesn't add to request latency.

> ⚠️ **Cloud-LB safety depends on your registry**. The `full` preset (shipped default) includes `cloudflare_health`, `aws_elb_health`, `google_cloud_health`, `azure_health`, `fastly_health`. If you build a `custom` registry or pick a preset that drops these without re-adding them, **the cloud-LB fast path becomes empty and your CDN probes will be evaluated against UA/behavior rules**. The shipped `config/bb_registry.php` force-includes `cloud_infrastructure` via `include_categories` as a safety net — keep that if you use any non-`full` preset.

### Detection gaps closed

| Gap | Solution |
|-----|----------|
| Spoofed UA + missing Client Hints | `ClientHintsDetector` — cross-validates `User-Agent` against `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile`, full version list |
| Stale IP ranges | `IpFeedInterface` + `FeedRegistry` — pulls fresh ranges from Google, Bing, OpenAI, Anthropic, Apple, Perplexity, DuckDuckGo, Amazon, Cloudflare (cron-driven, **experimental**) |
| AI agents mimicking humans | `AgenticBehaviorDetector` — detects think-then-fetch bursts, non-linear navigation, precision targeting (no CSS/fonts/tracking) |
| HEAD flooding + direct asset scraping | `HeadRequestDetector` + `AssetScrapingDetector` — flags site-mapping via HEAD and AI training scrapers hitting `/img1.png, /img2.png, …` without loading the HTML page that references them |
| **CDN/LB probes blocked by mistake** | `BotDetector::is_cloud_infrastructure_ip()` — IP-range fast path BEFORE UA match; **never** blocks Cloudflare/AWS/GCP/Azure/Fastly probes (when registry contains the cloud bots) |

### New infrastructure

*   **`Bot\RegistryInterface`** — public contract for third-party integrations. Returns arrays of `BotDefinition` keyed by ID; snake_case methods to match the existing project style.
*   **`Bot\Registry\DefaultRegistry`** — extracted ~100 shipped bots into a typed, self-contained class with per-category accessor methods (`search_engines()`, `ai_crawlers()`, `cloud_infrastructure()`, etc.).
*   **`Bot\RegistryFactory`** — three entry points: `from_file()` (loads `config/bb_registry.php`), `from_array()` (build from config), `default()` (singleton `DefaultRegistry`).
*   **`Bot\Registry\Presets`** — eight named presets (`full`, `minimal`, `verified-only`, `no-ai`, `no-seo`, `eu-only`, `human-only`, `custom`).
*   **`Bot\RegistryTokens`** — single source of truth for `NOISE` tokens and `MIN_TOKEN_LENGTH` constants.
*   **`Feeds\CloudIpRangeProvider`** — pulls fresh CIDRs from AWS/Cloudflare/Fastly/GCP official JSON feeds to prevent hardcoded CIDR drift. Caches via `CacheInterface` with 24h TTL; falls back to stale cache on fetch failure.
*   **`bin/update-ip-ranges.php`** extended to refresh both bot-specific feeds and cloud-provider feeds, tagged by bot ID heuristically.
*   **`BotCategory::label()`** and **`BotCategory::default_action_hint()`** helpers for dashboards and logging.

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
- **Bot registry is now injectable** — code that called `Registry::all()` directly must use `RegistryFactory::default()->all()` (or accept a `RegistryInterface`)
- Adapter interface expanded with new required methods
- Database schema updated with new columns (`bot_category`, `ja3`, `header_order_hash`, `asn`, `country`)
- Custom adapters must implement new `CacheInterface` methods

> **Important**: Unlike typical 3.0 rewrites, **Bad Behaviour 3.0 defaults to legacy 2.x behavior**. Most new detection features (fingerprinting, JSON body inspection, multipart inspection, strict header checks, Client Hints validation, agentic detection) are **disabled by default**. The exceptions — **HEAD request detection**, **asset scraping detection**, and **cloud-infrastructure safety** — are enabled by default because they target clearly malicious patterns or catastrophic failure modes with negligible false-positive risk. Enable the others explicitly via configuration when needed.

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
│   ├── BotDetector.php           # 100+ known bots; cloud-LB fast path BEFORE UA match;
│   │                             # accepts RegistryInterface injection
│   ├── BlacklistDetector.php     # Malicious UA, URL attacks, form body (form-only)
│   ├── BehavioralDetector.php    # Rate anomalies, rotating UA/IP, think time, headers
│   ├── FingerprintDetector.php   # JA3, H2, header order (opt-in, config-only)
│   ├── RateLimitDetector.php     # Multi-tier rate limiting
│   ├── DnsblDetector.php         # http:BL, Spamhaus, SpamCop
│   ├── ClientHintsDetector.php   # Sec-CH-UA brand/version/platform/mobile validation
│   ├── AgenticBehaviorDetector.php # AI-agent pattern detection
│   ├── HeadRequestDetector.php   # HEAD flooding + Referer check
│   └── AssetScrapingDetector.php # asset-only sessions + sequential patterns
├── Bot/
│   ├── BotDefinition.php         # Immutable bot record
│   ├── BotCategory.php           # 11 cases: SEARCH_ENGINE, AI_CRAWLER, SOCIAL_CRAWLER,
│   │                             # SEO_CRAWLER, ARCHIVE_CRAWLER, MONITORING, MALICIOUS,
│   │                             # UNKNOWN, FEED_READER, SHOPPING_CRAWLER,
│   │                             # CLOUD_INFRASTRUCTURE, SECURITY_SCANNER
│   ├── BotAction.php             # ALLOW, CHALLENGE, BLOCK, LOG_ONLY
│   ├── RegistryInterface.php     # Public contract — all registry types implement this
│   ├── RegistryFactory.php       # from_file() / from_array() / default()
│   ├── RegistryTokens.php        # Shared NOISE / MIN_TOKEN_LENGTH constants
│   └── Registry/
│       ├── DefaultRegistry.php   # ~100 shipped bots (the real `Registry`)
│       ├── InMemoryRegistry.php  # Wrap a user-provided array
│       ├── EmptyRegistry.php     # No-op singleton
│       ├── FilteredRegistry.php  # Keep/exclude + category filters
│       ├── MergedRegistry.php    # Compose registries, last-wins per ID
│       ├── CustomRegistry.php    # Built from a config array (validated)
│       └── Presets.php           # full / minimal / verified-only / no-ai / no-seo /
│                                 # eu-only / human-only / custom
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
├── Feeds/                        # Dynamic IP range feeds
│   ├── IpFeedInterface.php
│   ├── FeedRegistry.php          # Bot-specific feeds (Google, Bing, OpenAI, etc.)
│   ├── CloudIpRangeProvider.php  # Cloud infra CIDRs (AWS/Cloudflare/Fastly/GCP)
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

$adapter = new GenericAdapter();
$config = Configuration::from_array([], $adapter);   // safe defaults
$bb = new BadBehaviour($config);                    // uses RegistryFactory::default()

$result = $bb->run();
if (!$result->is_allowed()) {
    $bb->handle_result($result);
}
```

**Inject a custom registry:**
```php
use BadBehaviour\Bot\RegistryFactory;

$registry = RegistryFactory::from_file();   // loads config/bb_registry.php if present
$bb = new BadBehaviour($config, $registry);
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
if (!$result->is_allowed()) {
    $bb->handle_result($result);
}
```

### Option 2: Single Entry Point (Any PHP App)

```php
require 'vendor/autoload.php';

\BadBehaviour\Bootstrap::run();

// Middleware-style:
if (!\BadBehaviour\Bootstrap\check(['strict' => true])) {
    exit; // Blocked
}
```

### Option 3: Legacy Drop-In Usage

Existing 2.x integrations continue to work unchanged — the legacy entry points now act as forwarding shims over the new OOP architecture.

1. Upload the `badbehaviour` directory to your project.
2. Include the legacy bootstrap file as you always have:
   * MediaWiki: `include( './extensions/Bad-Behaviour/bad-behaviour-mediawiki.php' );`
   * Generic: `require_once 'bad-behaviour-generic.php';`
   * WackoWiki: `require_once 'bad-behaviour-wackowiki.php';`

---

## Custom Bot Registries

The shipped `DefaultRegistry` covers ~100 verified bots across 11 categories. It's **read-only** and the **default** when no config file is present.

For customization, drop a `config/bb_registry.php` (shipped with safe defaults — see below) or build a registry programmatically.

### Config file: `config/bb_registry.php`

The shipped default looks like this:

```php
<?php
// config/bb_registry.php  — shipped default, safe for production
return [
    'preset' => 'full',
    'include_categories' => [
        'cloud_infrastructure',   // SAFETY NET — keep this if you ever switch presets
    ],
];
```

Override by copying `config/bb_registry.example.php` to `config/bb_registry.php` and editing it. Full schema:

```php
return [
    // Starting set (see Presets below)
    'preset' => 'minimal',

    // Remove entire categories (applied after preset)
    'exclude_categories' => ['seo_crawler'],

    // Force-include categories (overrides exclude). SAFETY: always keep
    // cloud_infrastructure here if you're behind a CDN.
    'include_categories' => ['cloud_infrastructure'],

    // Remove specific bots by ID
    'exclude_bots' => ['petal', 'brightdata'],

    // Add your own bots (merged on top of the filtered preset)
    'additions' => [
        'internal_uptime' => [
            'name' => 'Internal Uptime Monitor',
            'user_agent_patterns' => ['InternalMonitor/1.0'],
            'category' => 'monitoring',
            'ip_ranges' => ['10.0.0.0/8'],
            'verify_dns' => true,
            'dns_suffix' => 'monitor.internal',
            'default_action' => 'allow',
        ],
    ],

    // ONLY used when preset='custom': defines the complete bot set.
    // Cloud_infrastructure bots MUST be included manually.
    'bots' => [
        // ...
    ],
];
```

**Filter execution order:** `preset → exclude_categories → include_categories → exclude_bots → additions`.

### Presets

| Preset | What it ships | Use when |
|---|---|---|
| `full` | All ~100 shipped bots (default) | Small/medium sites, want coverage |
| `minimal` | ~30 most common bots (~3× faster matching) | High-traffic sites, speed matters |
| `verified-only` | Only bots with DNS verification or IP ranges | Stricter, but may miss regional bots |
| `no-ai` | Everything except `AI_CRAWLER` | Publishers blocking AI training crawlers |
| `no-seo` | Everything except `SEO_CRAWLER` | Block SEO crawlers only |
| `eu-only` | EU search engines + EU-relevant bots | GDPR-conscious deployments |
| `human-only` | Empty (humans-only baseline) | Combine with `additions` for known bots only |
| `custom` | Only the `bots` you define | Total control — must include cloud_infrastructure manually |

### BotDefinition schema (for `additions` and `bots`)

```php
'my_bot' => [
    'name'                => 'My Bot',                    // required
    'user_agent_patterns' => ['MyBot', 'MyBot/1.0'],      // required, ≥1 entry, ≥3 chars each
    'category'            => 'search_engine',             // required, see BotCategory enum
    'host_patterns'       => ['bot.example.com'],         // optional
    'ip_ranges'           => ['10.0.0.0/8'],              // optional, CIDRs
    'verify_dns'          => true,                        // optional
    'dns_suffix'          => 'example.com',               // optional, required if verify_dns=true
    'robots_txt_token'    => 'MyBot',                     // optional
    'default_action'      => 'allow',                     // optional: allow|challenge|block|log_only
    'description'         => 'What this bot does',        // optional
],
```

Valid `category` values: `search_engine`, `ai_crawler`, `social_crawler`, `seo_crawler`, `archive_crawler`, `monitoring`, `feed_reader`, `shopping_crawler`, `cloud_infrastructure`, `security_scanner`, `malicious`, `residential_proxy`, `unknown`.

Valid `default_action` values: `allow`, `challenge`, `block`, `log_only`.

### Programmatic registries

```php
use BadBehaviour\Bot\RegistryFactory;
use BadBehaviour\Bot\Registry\MergedRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Bot\Registry\FilteredRegistry;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\BotCategory;

// From config file
$registry = RegistryFactory::from_file();

// From config array
$registry = RegistryFactory::from_array([
    'preset' => 'minimal',
    'additions' => ['my_bot' => [/* schema */]],
]);

// Manual composition (chain registries with last-wins semantics)
$registry = new MergedRegistry([
    RegistryFactory::default(),                                       // base
    new FilteredRegistry($otherRegistry, exclude_categories: ['seo_crawler']),
    new InMemoryRegistry(['override' => new BotDefinition(...)]),     // overrides
]);

// Per-tenant swap on an existing instance
$bb = $bb->with_registry($tenant_registry);
```

### Validating custom registries

```php
$registry = new CustomRegistry($bots_array);
if ($registry->has_errors()) {
    foreach ($registry->get_errors() as $err) {
        // ['bot_id' => 'my_bot', 'error' => 'missing user_agent_patterns']
        error_log("Bot registry: {$err['bot_id']} — {$err['error']}");
    }
}
```

Invalid entries are **logged and skipped** — the registry keeps valid bots. This is intentional: bad config shouldn't break the entire library.

### Inspecting the active registry

```php
// What does my current registry contain?
$registry = $bb->get_registry();

echo "Total bots: " . $registry->count() . "\n";
foreach ($registry->cloud_infrastructure() as $id => $bot) {
    echo "  {$id}: {$bot->name} — {$bot->ip_ranges[0]}\n";
}

// Which preset-like groups exist?
$registry->search_engines();      // ['googlebot' => BotDefinition, ...]
$registry->ai_crawlers();
$registry->social_crawlers();
$registry->seo_crawlers();
$registry->archive_crawlers();
$registry->monitoring();
$registry->feed_readers();
$registry->shopping_crawlers();
$registry->cloud_infrastructure();
$registry->security_scanners();
$registry->residential_crawlers();
```

### Cloud-LB safety with custom registries

The `BotDetector::is_cloud_infrastructure_ip()` fast path reads `$registry->cloud_infrastructure()`. If your custom registry drops `cloud_infrastructure` bots, that fast path becomes empty and your CDN's health probes get evaluated against the rest of the pipeline — which they will likely fail.

Three safe patterns:

1. **`preset = 'full'`** (shipped default) — keeps everything.
2. **`preset = 'minimal'`** with `include_categories = ['cloud_infrastructure']` — fastest, still safe.
3. **`preset = 'custom'`** — you **must** include all five cloud bots manually (`cloudflare_health`, `aws_elb_health`, `google_cloud_health`, `azure_health`, `fastly_health`) in your `bots` definition.

---

## Configuration

Bad Behaviour 3.0 uses a typed **PHP-array configuration file** (`config/bb_config.php`).

### Quick Start: Safe Defaults (Legacy-Compatible)

Copy `config/bb_config.example.php` → `config/bb_config.php`. Shipped defaults are 2.x-compatible — no edits needed for a drop-in upgrade.

```php
<?php
// config/bb_config.php
return [
    // ===== CORE =====
    'logging'                    => true,
    'verbose'                    => false,
    'strict'                     => false,
    'offsite_forms'              => false,

    'show_contact_info'          => false,
    'show_detailed_block_page'   => false,

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

    // ===== BOT CATEGORIES =====
    'bot_categories' => [
        'blocked'   => ['malicious'],
        'log_only'  => ['security_scanner'],
        'challenge' => [],
        'allowed'   => [
            'feed_reader',
            'shopping_crawler',
            'cloud_infrastructure',
            'monitoring',
            'archive_crawler',
        ],
    ],

    // ===== DYNAMIC IP RANGES =====
    'dynamic_ip_ranges' => [
        'enabled' => false,        // flip after cron is in place
        'ttl'     => 86400,
        'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
    ],

    // ===== DETECTION FEATURES (opt-in) =====
    'enable_fingerprinting'           => false,
    'inspect_json_body'               => false,
    'inspect_multipart_body'          => false,
    'enable_behavioral_analysis'      => true,
    'enable_ai_crawler_control'       => true,
    'enable_client_hints_validation'  => false,
    'enable_agentic_detection'        => false,
    'enable_dynamic_ip_ranges'        => false,

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

---

### Configuration Profiles

Three reference profiles cover ~95% of use cases. Pick one as your starting point, then customize.

| | **Default** | **Medium** | **Strict** |
|---|---|---|---|
| Compatibility | All browsers & tools | Modern browsers + most tools | Chromium 89+ / Firefox 100+ / Safari 15+ |
| False positive risk | 🟢 Minimal | 🟡 Low (monitor 1–2 weeks per feature) | 🔴 High (full FP audit first) |
| Setup effort | None — drop-in | ~30 min monitoring, then flip switches | Multi-week rollout |
| Best for | 2.x migration, shared hosting, public CMS | Production sites with monitored traffic | Internal APIs, paid content, abuse targets |
| Cloud-LB safety | ✅ always allowed | ✅ | ✅ |
| AI training scrapers | ✅ detected | ✅ | ✅ |

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

Site is behind Cloudflare / AWS ALB / GCP LB / Fastly / Azure?
  → ALL profiles — cloud LB probes are always allowed
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
| Cloudflare/AWS/GCP LB probes | ✅ | ✅ | ✅ |
| RSS readers (Feedly, Apple News) | ✅ | ✅ | ✅ |
| Product crawlers (Google Shopping, FB Catalog) | ✅ | ✅ | ✅ |
| Security scanners (Shodan, Qualys) | ✅ logged | ✅ logged | ✅ logged |
| AI agents (Brave Leo, etc.) | ❌ allowed | ✅ detected | ✅ detected |
| AI training scrapers (asset-only sessions) | ❌ allowed | ✅ detected | ✅ detected |
| Legacy curl/wget link checkers | ✅ | ✅ | ⚠️ if `strict` |

✅ works • ⚠️ may need config • 🔴 will break • ❌ not detected

See [`CONFIGURATION.md`](docs/CONFIGURATION.md#configuration-profiles) for full profile configs.

#### Hard points to remember

- **Firefox does NOT send Sec-CH-UA headers** — Client Hints validation ignores Firefox/Safari by design.
- **Electron apps** (Slack, VS Code, Discord) send Chrome UA but no Client Hints — blocked at Medium+.
- **Agentic detection requires session cookies** — anonymous traffic is skipped.
- **`strict = true`** requires `Accept-Encoding` header — breaks some privacy-focused browsers.
- **`inspect_json_body` / `inspect_multipart_body`** — almost never safe to enable on public sites.
- **Cloud LB probes are ALWAYS allowed** — the cloud fast path runs before every other check, in every profile.
- **`cloud_infrastructure` is hard-coded `ALLOW`** in `BotDetector::determine_action()` — `bot_categories.blocked[]` cannot override it.

---

### Core Settings

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `logging` | bool | `true` | **NONE** | Always — required for audit trail |
| `verbose` | bool | `false` | 🟢 **LOW** | Debugging only; logs *every* request |
| `strict` | bool | `false` | 🔴 **HIGH** | Only if you control all clients (API-only, internal) |
| `offsite_forms` | bool | `false` | 🟡 **MEDIUM** | If you have **zero** legitimate external form posts |
| `enable_fingerprinting` | bool | `false` | 🟡 **MEDIUM** | After 2+ weeks monitoring logs |
| `inspect_json_body` | bool | `false` | 🔴 **HIGH** | **Never** for AJAX/JSON apps |
| `inspect_multipart_body` | bool | `false` | 🔴 **HIGH** | **Never** for upload endpoints |
| `enable_behavioral_analysis` | bool | `true` | 🟢 **LOW** | Keep enabled |
| `enable_ai_crawler_control` | bool | `true` | 🟢 **LOW** | Keep enabled |
| `enable_client_hints_validation` | bool | `false` | 🟡 **MEDIUM** | After monitoring; requires Chromium 89+ |
| `enable_agentic_detection` | bool | `false` | 🟡 **MEDIUM** | After monitoring; needs session cookies |
| `enable_dynamic_ip_ranges` | bool | `false` | 🟡 **EXPERIMENTAL** | Requires cron; see [Feeds](#dynamic-ip-range-feeds-experimental) |

#### Head Request Detection (`head_*`)

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `enable_head_request_detection` | bool | `true` | 🟢 **LOW** | Keep enabled — blocks a real attack vector |
| `head_require_referer` | bool | `true` | 🟢 **LOW** | Keep enabled |
| `head_flood_threshold` | int | `20` | 🟢 **LOW** | HEAD requests per session before block |
| `head_probe_threshold` | int | `50` | 🟢 **LOW** | HEAD probes per IP per 5 min |
| `head_referer_exempt_paths[]` | string[] | `['/api/', '/wp-json/', '/health', '/status']` | 🟢 **LOW** | Paths where HEAD without Referer is legitimate |

#### Asset Scraping Detection (`asset_*`)

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `enable_asset_scraping_detection` | bool | `true` | 🟢 **LOW** | Keep enabled — targets AI training scrapers |
| `asset_extensions[]` | string[] | images, documents, audio, video | 🟡 **MEDIUM** | Add/remove based on what content you serve |
| `asset_no_referer_threshold` | int | `10` | 🟢 **LOW** | Asset requests without Referer per IP per hour |
| `asset_only_session_threshold` | int | `20` | 🟢 **LOW** | Asset requests with no HTML loads per session |
| `asset_pattern_threshold` | int | `100` | 🟢 **LOW** | Sequential asset URLs per IP per 5 min |

#### Dynamic IP Ranges (`dynamic_ip_ranges`)

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `dynamic_ip_ranges.enabled` | bool | `false` | 🟡 **EXPERIMENTAL** | After `bin/update-ip-ranges.php` is on cron (every 6–24h) |
| `dynamic_ip_ranges.ttl` | int | `86400` | 🟢 **LOW** | Cache TTL for the merged feed (lower = fresher, more cron pressure) |
| `dynamic_ip_ranges.feeds[]` | string[] | `['aws', 'cloudflare', 'fastly', 'gcp']` | 🟢 **LOW** | Subset of cloud-provider feeds to pull |

See [Dynamic IP Range Feeds](#dynamic-ip-range-feeds-experimental) for setup.

### Reverse Proxy

| Setting | Type | Default | Risk | When to Configure |
|---------|------|---------|------|-------------------|
| `reverse_proxy.enabled` | bool | `false` | 🟡 **MEDIUM** | **Required** if behind Cloudflare, nginx, ALB, etc. |
| `reverse_proxy.header` | string | `X-Forwarded-For` | — | Match your proxy's header |
| `reverse_proxy.addresses[]` | CIDR[] | `[]` | 🔴 **HIGH** | **Must** list all proxy IP ranges |

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
| `strict` | bool | `false` | 🟡 **MEDIUM** | Only if you want **zero** AI crawlers |

**Verified AI Crawlers** (IP + DNS verified):

| Token | Robots.txt | Owner | Verification |
|-------|------------|-------|--------------|
| `GPTBot` | `GPTBot` | OpenAI | DNS `openai.com` |
| `ClaudeBot` | `ClaudeBot` | Anthropic | DNS `anthropic.com` |
| `Google-Extended` | `Google-Extended` | Google | DNS `googlebot.com` |
| `PerplexityBot` | `PerplexityBot` | Perplexity | IP ranges |
| `Meta-ExternalAgent` | `Meta-ExternalAgent` | Meta | DNS `facebook.com` |
| `Applebot-Extended` | `Applebot-Extended` | Apple | DNS `applebot.apple.com` |
| `GrokBot` | `GrokBot` | xAI | DNS `x.ai` |
| `MistralBot` | `MistralBot` | Mistral AI | DNS `mistral.ai` |
| `CohereBot` | `CohereBot` | Cohere | DNS `cohere.com` |
| `YouBot` | `YouBot` | You.com | DNS `you.com` |
| `CCBot` | `CCBot` | Common Crawl | IP ranges |
| `ia_archiver` | `ia_archiver` | Internet Archive | DNS `archive.org` |
| `Amazonbot` | `Amazonbot` | Amazon | DNS + IP |
| `Diffbot` | `Diffbot` | Diffbot | DNS + IP |
| `BrightData` | `BrightData` | Bright Data | UA-only — **default `BLOCK`** (residential proxy) |

### Bot Categories (`bot_categories`)

11 categories with four configurable behaviors:

```php
'bot_categories' => [
    'blocked'   => ['malicious'],
    'log_only'  => ['security_scanner'],
    'challenge' => [],
    'allowed'   => [
        'feed_reader',
        'shopping_crawler',
        'cloud_infrastructure',
        'monitoring',
        'archive_crawler',
    ],
],
```

| Bucket | Default contents | Risk | Effect |
|--------|------------------|------|--------|
| `blocked[]` | `['malicious']` | 🟡 **MEDIUM** | Hard-block by category |
| `log_only[]` | `['security_scanner']` | 🟢 **LOW** | Record only, never block |
| `challenge[]` | `[]` | 🟡 **MEDIUM** | Force PoW/captcha |
| `allowed[]` | feed/shopping/cloud/monitoring/archive | 🟢 **LOW** | Verified-only allow |

#### Category reference (11 categories)

| Category | Default action | Tunable via | Notes |
|---|---|---|---|
| `search_engine` | verified → allow, unverified → block | n/a (handled in BotDetector) | Google, Bing, Yandex, Baidu, DuckDuckGo, +8 regional |
| `ai_crawler` | depends on `ai_crawlers.*` | `ai_crawlers.allowed[]`, `ai_crawlers.strict`, `ai_crawlers.block_unverified` | GPTBot, Claude, Gemini, +12 others |
| `social_crawler` | verified → allow, unverified → log_only | n/a | Facebook, Twitter, Kakao, LINE, WeChat |
| `seo_crawler` | verified → default, unverified → block | n/a | Ahrefs, Semrush, Siteimprove, +10 others |
| `archive_crawler` | verified → allow | `allowed[]` (default) | Internet Archive, UKWA, BnF, DNB, KB-NL |
| `monitoring` | verified → allow | `allowed[]` (default) | UptimeRobot, Pingdom, StatusCake |
| `feed_reader` | allow (verified-only) | `allowed[]` (default) | Feedly, Apple News, Google News |
| `shopping_crawler` | allow (verified-only) | `allowed[]` (default) | Google Shopping, FB Catalog, Shopify |
| `cloud_infrastructure` | **HARD allow — never blocked** | n/a (always allowed) | Cloudflare, AWS, GCP, Azure, Fastly |
| `security_scanner` | log_only | `log_only[]` (default) | Shodan, Qualys, Censys, Detectify, Rapid7 |
| `malicious` | hard block | `blocked[]` (default) | Known-bad actors |

> ⚠️ **`cloud_infrastructure` is hard-coded as `ALLOW` in `BotDetector::determine_action()` and cannot be moved to `blocked[]` or `challenge[]`.** This is intentional — blocking these probes takes your origin offline. The setting exists only for completeness; the safety override always wins. If you build a custom registry that drops cloud bots, see [Custom Bot Registries → Cloud-LB safety](#cloud-lb-safety-with-custom-registries).

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

Login endpoint detection: triggers on URLs matching `/(login|signin|auth|password)/i`.

### Challenge System (`challenge`)

| Setting | Type | Default | Risk | Providers |
|---------|------|---------|------|-----------|
| `enabled` | bool | `false` | 🟡 **MEDIUM** | `builtin`, `hcaptcha`, `recaptcha`, `turnstile` |
| `provider` | string | `builtin` | — | `builtin` = PoW (no external deps) |
| `site_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `secret_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `recaptcha_min_score` | float | `0.5` | — | reCAPTCHA v3 only (0.0–1.0) |

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
    ['type' => 'header', 'header' => 'User-Agent', 'value' => 'suspicious-tool',
     'action' => 'block', 'id' => 'bad_ua_header'],
],
```

**Rule Types:** `ip`, `ua_regex`, `ua_contains`, `asn`, `country`, `header`
**Actions:** `allow`, `block`, `challenge`, **`log`** (record only — continue pipeline)

#### Logging permitted bots (audit trail)

Use `action: 'log'` to record specific bots you allow — useful for analytics, robots.txt auditing, or detecting brand-new bots:

```php
'custom_rules' => [
    // 1. Log every verified Googlebot hit
    [
        'type'    => 'ua_regex',
        'value'   => '/Googlebot/i',
        'action'  => 'log',
        'id'      => 'audit_googlebot',
    ],

    // 2. Log a feed reader you allow
    [
        'type'    => 'ua_contains',
        'value'   => 'Feedly',
        'action'  => 'log',
        'id'      => 'audit_feedly',
    ],

    // 3. Log a security scanner auditing you
    [
        'type'    => 'ua_contains',
        'value'   => 'Shodan',
        'action'  => 'log',
        'id'      => 'audit_shodan',
    ],

    // 4. Log the new "Brave Leo" agentic UA so you can decide policy later
    [
        'type'    => 'header',
        'header'  => 'Sec-CH-UA',
        'value'   => 'Brave Leo',
        'action'  => 'log',
        'id'      => 'brave_leo_agentic',
    ],
],
```

`log` rules **never block** — they return `null` from the rules evaluator. The rule ID is recorded in result metadata for downstream filtering.

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
3. **BotDetector** —
   - **Cloud LB fast path** — IP-range check against `$registry->cloud_infrastructure()` (Cloudflare/AWS/Fastly/GCP); **short-circuits to ALLOW** before any UA matching
   - **UA match** — ~100 known bots (verified Search/AI **bypass all checks**)
3b. **HeadRequestDetector** — HEAD flooding + Referer check (enabled by default)
4. **ClientHintsDetector** — Sec-CH-UA cross-check (opt-in)
5. **BlacklistDetector** — Malicious UA, URL attack patterns, **form body only**
5b. **AssetScrapingDetector** — Asset-only sessions, no-Referer floods, sequential URL patterns (enabled by default)
6. **BehavioralDetector** — Rate anomalies, rotating UA/IP, **think time**, headers
7. **AgenticBehaviorDetector** — AI-agent pattern detection (opt-in)
8. **RateLimitDetector** — Multi-tier (global, per-minute, POST, login)
9. **DnsblDetector** — http:BL, Spamhaus, SpamCop
10. **FingerprintDetector** — JA3, H2, header order (**opt-in only**)

> **Why does step 3 have two phases?** The cloud-LB fast path runs **before** UA matching so that a probe from a Cloudflare IP with an unrecognized UA still gets through. UA matching happens *after* we've confirmed the IP is not from a known cloud provider (per the active registry).

---

## Dynamic IP Range Feeds (Experimental)

Hard-coded IP ranges go stale the moment a vendor adds a new region. Bad Behaviour ships two independent feed pipelines:

### A. Bot-specific feeds (`FeedRegistry`)

Pulls fresh ranges for **specific bot definitions** (Googlebot, Bingbot, GPTBot, etc.):

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
| Cloudflare v4/v6 (legacy) | `cloudflare.com/ips-v4`, `.../ips-v6` | `cloudflare` |

### B. Cloud-provider feeds (`CloudIpRangeProvider`)

Pulls fresh ranges for **cloud infrastructure** (used by the BotDetector fast path):

| Provider | Source | Tag examples |
|----------|--------|--------------|
| `aws` | `ip-ranges.amazonaws.com/ip-ranges.json` | `CLOUDFRONT`, `AMAZON`, `EC2`, `ROUTE53_HEALTHCHECKS`, `GLOBALACCELERATOR` |
| `cloudflare` | `api.cloudflare.com/client/v4/ips` | (whole range) |
| `fastly` | `api.fastly.com/public-ip-list` | (whole range) |
| `gcp` | `gstatic.com/ipranges/cloud.json` | (whole range) |

> Note: Azure is in the registry but its JSON endpoint shape differs from the others — currently it's documented as a TODO. The `azure_health` bot definition relies on the static ranges shipped with the registry.

### Enabling

In `bb_config.php`:
```php
'enable_dynamic_ip_ranges' => true,    // gate
'dynamic_ip_ranges' => [
    'enabled' => true,
    'ttl'     => 86400,                 // 24h
    'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
],
```

### Refreshing (cron)

Feeds are **not fetched on the request path** — they're too slow. Run the CLI script via cron:

```bash
# Refresh every 6 hours
0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php
```

The script writes the merged data to `bb:ip_ranges:merged` in your adapter's cache (file by default, Redis in the MediaWiki adapter). Each feed has its own 24h TTL with a 7-day stale fallback.

To run a subset:
```bash
php bin/update-ip-ranges.php --feeds=google,anthropic
php bin/update-ip-ranges.php --dry-run
php bin/update-ip-ranges.php --ttl=43200
```

### ⚠️ Why "experimental"?

1. **Caching boundaries** — file cache doesn't share across multi-server deployments; use the MediaWiki adapter's WAN cache for production.
2. **Feed shape changes** — vendors occasionally add new fields; parsers must be tolerant.
3. **Cold-start latency** — first request after TTL expiry triggers fetches unless cron runs in time.
4. **CA bundle portability** — auto-detection works on Debian/RHEL/Homebrew but not on stripped-down containers.

Once these are resolved the flag will be dropped in a 3.x point release.

---

## AI Crawler Management

```php
'ai_crawlers' => [
    'allowed' => [
        'GPTBot',              // OpenAI
        'ClaudeBot',           // Anthropic
        'Google-Extended',     // Google Vertex/Bard/Gemini
        'PerplexityBot',       // Perplexity
        'CohereBot',           // Cohere
        'Meta-ExternalAgent',  // Meta
        'Applebot-Extended',   // Apple
        'YouBot',              // You.com
        'GrokBot',             // xAI
        'MistralBot',          // Mistral AI
        'KagiBot',             // Kagi Search
    ],
    'block_unverified' => true,  // Block spoofed AI crawlers
    'strict'           => false, // true = block even verified unallowed AI
],
```

See the [Verified AI Crawlers](#ai-crawlers-ai_crawlers) table above for the full list.

---

## Cloud Infrastructure Safety — **READ THIS IF YOU'RE BEHIND A CDN**

If your site sits behind **Cloudflare, AWS ELB/ALB, GCP Load Balancer, Azure Front Door, or Fastly**, the load balancer periodically sends health-check probes to your origin. These probes come from the CDN's IP ranges, often with generic UAs like `ELB-HealthChecker/1.0`, `GoogleHC`, or `curl/7.x`.

**If Bad Behaviour blocks these probes**, your CDN marks your origin as "unhealthy" and **takes your site offline** — a much bigger outage than the bot traffic would have caused.

### Why it's hard to get right

- UA-only matching fails: probes have generic UAs that look suspicious.
- IP-range matching fails: CDNs add ranges frequently and silently (Cloudflare publishes 15+ IPv4 ranges today, all of which have changed in the last 3 years).
- DNS verification fails: probes don't have stable hostnames.

### The 3.0 solution

Two layers of defense:

1. **Static IP ranges** ship in the `DefaultRegistry` for every major CDN (`cloudflare_health`, `aws_elb_health`, `google_cloud_health`, `azure_health`, `fastly_health`). These work out-of-the-box with `enable_dynamic_ip_ranges = false`.
2. **`CloudIpRangeProvider`** pulls **fresh** CIDR lists from official AWS/Cloudflare/Fastly/GCP feeds when `dynamic_ip_ranges.enabled = true`. Cached 24h with a 7-day stale fallback.

`BotDetector::is_cloud_infrastructure_ip()` is the **first check** in the bot pipeline. It runs **before UA matching**. Any IP matching a known cloud range short-circuits to `ALLOW` regardless of UA. This is hard-coded — you cannot accidentally turn it off, **as long as your active registry contains cloud bots**. The shipped `config/bb_registry.php` and the `full` preset both do; if you customize, see [Custom Bot Registries → Cloud-LB safety](#cloud-lb-safety-with-custom-registries).

### Verification

```php
use BadBehaviour\Bot\RegistryFactory;
use BadBehaviour\Util\IpUtil;

$registry = RegistryFactory::default();   // or your custom registry

// All five cloud bots are present and hard-allowed
foreach ($registry->cloud_infrastructure() as $id => $def) {
    // $def->default_action === BotAction::ALLOW (enforced by BotDetector)
    // $def->robots_txt_token === null  (no robots.txt governance)
    // $def->ip_ranges is non-empty OR dynamic loading is enabled
}

// Test a known CF IP
IpUtil::match_cidr('173.245.48.1', '173.245.48.0/20');  // true
```

If your CDN isn't on the list, [open an issue](https://github.com/Bad-Behaviour/badbehaviour/issues) — adding a new cloud provider is a 30-line patch.

---

## Feed Readers, Shopping Crawlers, Security Scanners

Three new categories ship with conservative defaults. You usually want them as-is, but here's the rationale:

### Feed Readers — default `allow`

RSS / news aggregator bots (Feedly, Apple News, Google News, Inoreader, Flipboard, NewsBlur) often get caught by aggressive spam filters because they look like generic fetchers. They bring real users — a Feedly subscriber clicks through to the original article.

### Shopping Crawlers — default `allow`

E-commerce product fetchers (Google Shopping, Bing Shopping, Pinterest Shopping, Facebook Catalog, Shopify) are **revenue-critical** for merchants. Blocking them makes your products invisible on Google Shopping and Meta surfaces.

### Security Scanners — default `log_only` (never block)

Known security vendors (Qualys, Detectify, Rapid7, Shodan, Censys) routinely scan the entire internet as part of legitimate research or paid audits. Blocking them doesn't make you more secure — it just blinds you to what they're seeing. They're recorded in your log with category `security_scanner` for audit, but never blocked.

If you want to challenge them (e.g., they hammer you), add `'security_scanner'` to `bot_categories.challenge[]`:

```php
'bot_categories' => [
    'challenge' => ['security_scanner'],
],
```

---

## Challenge System

When `challenge.enabled = true`, suspicious requests receive a challenge:

```php
'challenge' => [
    'enabled'  => true,
    'provider' => 'hcaptcha',
    'site_key'   => 'your-site-key',
    'secret_key' => 'your-secret-key',
    'recaptcha_min_score' => 0.5,
],
```

**Providers:**
- `builtin` — zero-dependency proof-of-work (no external services)
- `hcaptcha` — hCaptcha checkbox/invisible
- `recaptcha` — reCAPTCHA v3 (score-based)
- `turnstile` — Cloudflare Turnstile

---

## Client Hints Validation

Modern Chromium browsers (Chrome 89+, Edge 89+, Brave, Vivaldi, Opera 75+) send `Sec-CH-UA` headers that reveal the *real* browser brand and version. Spoofed UAs almost always omit or mis-match these.

```php
'enable_client_hints_validation' => true,
```

**What it checks:**
- Missing *all* `Sec-CH-*` headers from a Chromium UA → **block**
- Brand mismatch (`Sec-CH-UA` says Edge, UA says Chrome) → **block**
- Version drift > 2 major releases → **block**
- Platform mismatch (UA says Linux, `Sec-CH-UA-Platform` says Windows) → **block**
- Mobile bit contradiction → **block**

**Risk:** 🟡 MEDIUM — old Chromium-based browsers (< 89), Electron apps, and some headless tools don't send hints. Monitor for 1–2 weeks before enabling.

---

## Agentic Behavior Detection

AI agents (Brave Leo, ChatGPT operator, custom scrapers built on Playwright/Selenium) increasingly *look* like browsers but fail to imitate *human browsing patterns*.

```php
'enable_agentic_detection' => true,
```

**Three pattern detectors:**

1. **Think-then-fetch** — long pause (>10s) followed by burst of asset requests (≥5 in <5s) → **block**
2. **Non-linear navigation** — 8+ requests across 5+ unrelated top-level sections → **block**
3. **Precision targeting** — API/JSON ratio >30% with near-zero CSS/font/tracking (<5% / <2% / <1%) → **block**

**Risk:** 🟡 MEDIUM — power users with aggressive tab-opening habits or single-page-app users may trigger false positives. Requires a session cookie — fully anonymous traffic is skipped.

---

## HEAD Request Detection

HEAD requests are cheap (no body transfer) and ideal for site mapping. Bots send thousands of HEAD requests to enumerate URLs without downloading content.

```php
'enable_head_request_detection' => true,        // enabled by default
'head_require_referer'          => true,
'head_flood_threshold'          => 20,           // per session
'head_probe_threshold'          => 50,           // per IP per 5 min
'head_referer_exempt_paths'     => ['/api/', '/wp-json/', '/health', '/status'],
```

**Three signals:**

1. **HEAD without Referer** — site mapping typically omits Referer; real browsers send it.
2. **HEAD flood per session** — >20 HEAD requests in a single session = enumeration.
3. **HEAD probing per IP** — >50 HEAD requests from one IP in 5 minutes = reconnaissance.

**Risk:** 🟢 LOW.

---

## Asset Scraping Detection

AI training scrapers and image harvesters download assets in bulk, often without loading the HTML pages first.

```php
'enable_asset_scraping_detection' => true,       // enabled by default
'asset_extensions'                => [
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'mp3', 'mp4', 'wav', 'ogg', 'webm',
],
'asset_no_referer_threshold'      => 10,
'asset_only_session_threshold'    => 20,
'asset_pattern_threshold'         => 100,
```

**Three signals:**

1. **Asset without Referer** — bots fetching `/img1.png, /img2.png, …` directly don't send Referer.
2. **Asset-only session** — >20 asset requests in a session where `html_requests === 0` = pure asset harvesting. Real browsers always load HTML first.
3. **Sequential asset pattern** — >100 assets from one IP in 5 minutes = scraping.

**Risk:** 🟢 LOW.

---

## Rate Limiting

Multi-tier rate limiting with adapter-backed storage:

```php
'rate_limits' => [
    'enabled'      => true,
    'global'       => ['requests' => 1000, 'window' => 3600],
    'per_minute'   => ['requests' => 60,   'window' => 60],
    'post'         => ['requests' => 30,   'window' => 3600],
    'login'        => ['requests' => 10,   'window' => 900],
],
```

---

## Custom Adapters

Implement `AdapterInterface` for custom platforms:

```php
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;

class MyCustomAdapter implements AdapterInterface
{
    public function get_settings(): array;
    public function get_whitelist(): array;
    public function get_email(): string;
    public function get_relative_path(): string;
    public function get_table_schema(string $table_name): string;

    public function query(string $sql): bool;
    public function log_request(RequestPackage $package, Result $result): void;

    public function increment_counter(string $key, int $window): int;
    public function get_counter(string $key): int;
    public function get_behavior_profile(string $session_id): ?array;
    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool;
    public function add_to_set(string $key, string $value, int $ttl): bool;
    public function get_set(string $key): array;

    public function get_geoip(string $ip): ?array;
    public function verify_challenge(string $response, string $remote_ip): bool;
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

The `metadata` field on every `Result` includes `bot_category` (string) and `bot_verified` (bool) — use these to log which category triggered a block.

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
- Extensions: `json`, `mbstring`, `curl`
- Composer 2+

---

## Testing

```bash
vendor/bin/phpunit                          # all tests
vendor/bin/phpunit --testsuite Unit         # unit only
vendor/bin/phpunit --testsuite Integration  # integration only
vendor/bin/phpunit tests/Performance        # benchmarks
vendor/bin/phpunit --coverage-html build/coverage/html
```

---

## License

GNU Lesser General Public License v3.0 or later.

---

## Support & Documentation

- [Migration Guide 2.x → 3.0](docs/UPGRADE.md)
- [Configuration Reference](docs/CONFIGURATION.md) — Complete settings guide with risk matrix
- [Issues](https://github.com/Bad-Behaviour/badbehaviour/issues) — Bug reports
- [Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions) — Questions

---

*Bad Behaviour 3.0 — Modern bot detection for the modern web. With legacy-compatible defaults and cloud-LB safety built in.*