# Migration & Upgrade Guide: Bad Behaviour 2.x → 3.0

This document covers both **migrating** an existing installation from 2.x and **upgrading** to specific 3.x point releases.

---

## Requirements

### 1. Minimum Requirements

- **PHP 8.2+** (was 7.0+)
- Extensions: `json`, `mbstring`, `curl`, `gmp` (for IPv6 CIDR)
- Composer 2+

### 2. From the Old Procedural Codebase

Bad Behaviour 3.0 is a complete rewrite:

- All procedural `.inc.php` files replaced with OOP classes in `src/`
- Hex result codes (e.g. `'17f4e8c8'`, `'f1182195'`) replaced with `ResultCode` enum
- Global state replaced with constructor-injected dependencies
- INI configuration replaced with **PHP array** (`bb_config.php`)

---

## Breaking Changes

### 1. Configuration Format (INI → PHP array)

**Old:**
```ini
; settings.ini (2.x)
httpbl_key = "abc123"
strict = 1
rate_limits_global_requests = 1000
```

**New:**
```php
<?php
// config/bb_config.php (3.0)
return [
    'httpbl' => [
        'key'    => 'abc123',
        'threat' => 25,
        'maxage' => 30,
    ],
    'strict' => true,
    'rate_limits' => [
        'global' => ['requests' => 1000, 'window' => 3600],
    ],
];
```

A side-by-side reference for the most common keys:

| 2.x flat INI | 3.0 `bb_config.php` |
|--------------|---------------------|
| `httpbl_key = "abc123"` | `'httpbl' => ['key' => 'abc123']` |
| `httpbl_threat = 50` | `'httpbl' => ['threat' => 50]` |
| `httpbl_maxage = 60` | `'httpbl' => ['maxage' => 60]` |
| `reverse_proxy = 1` | `'reverse_proxy' => ['enabled' => true]` |
| `reverse_proxy_header = "CF-Connecting-IP"` | `'reverse_proxy' => ['header' => 'CF-Connecting-IP']` |
| `reverse_proxy_addresses[] = "10.0.0.0/8"` | `'reverse_proxy' => ['addresses' => ['10.0.0.0/8']]` |
| `dnsbl_enabled = 1` | `'dnsbl' => ['enabled' => true]` |
| `dnsbl_lists[] = "zen.spamhaus.org"` | `'dnsbl' => ['lists' => ['zen.spamhaus.org']]` |
| `ai_crawlers_allowed[] = "GPTBot"` | `'ai_crawlers' => ['allowed' => ['GPTBot']]` |
| `block_unverified_ai = 1` | `'ai_crawlers' => ['block_unverified' => true]` |
| `strict_ai = 1` | `'ai_crawlers' => ['strict' => true]` |
| `rate_limits_global_requests = 1000` | `'rate_limits' => ['global' => ['requests' => 1000, 'window' => 3600]]` |
| `challenge_enabled = 1` | `'challenge' => ['enabled' => true]` |
| `challenge_provider = "hcaptcha"` | `'challenge' => ['provider' => 'hcaptcha']` |
| `display_stats = true` | (removed — admin panel only) |

### 2. Entry Points

**Old:** Multiple entry files (`bad-behaviour-generic.php`, etc.) with global state.
**New:** Single `Bootstrap.php` with functional API, or OOP `BadBehaviour::withAdapter($adapter)`.

```php
// Old (still works — legacy shim)
require_once 'bad-behaviour-generic.php';

// New (recommended)
require 'vendor/autoload.php';
\BadBehaviour\Bootstrap::run();

// Or OOP:
$bb = BadBehaviour::withAdapter($adapter);
$bb->run();
```

### 3. Result Codes

**Old:** Hex strings (`'17f4e8c8'`, `'f1182195'`)
**New:** `ResultCode` enum with semantic names

```php
// Old
if ($key === '17f4e8c8') { /* UA blacklist */ }

// New
if ($result->code === ResultCode::BLOCKED_MALICIOUS_UA) { /* ... */ }
```

**Mapping (most common):**

| 2.x hex | 3.0 `ResultCode` |
|---------|------------------|
| `00000000` | `ResultCode::ALLOWED` |
| `17f4e8c8` | `ResultCode::BLOCKED_BOT` |
| `96c0bd29` | `ResultCode::BLOCKED_AI_CRAWLER` |
| `b9d1ea74` | `ResultCode::BLOCKED_SEO_CRAWLER` |
| `83465e5d` | `ResultCode::BLOCKED_MALICIOUS_UA` |
| `85a2138e` | `ResultCode::BLOCKED_ATTACK_PATTERN` |
| `6c7e5d4b` | `ResultCode::BLOCKED_BEHAVIORAL` |
| `9033f5b7` | `ResultCode::BLOCKED_RATE_LIMIT` |
| `9d392eed` | `ResultCode::CHALLENGE_REQUIRED` |
| `2b402ad5` | `ResultCode::BLOCKED_DNSBL` |
| `c1a2c89b` | `ResultCode::BLOCKED_HTTPBL` |
| `a92a8eaa` | `ResultCode::BLOCKED_FINGERPRINT` |
| `f1182195` | `ResultCode::BLOCKED_CUSTOM_RULE` |
| `b6e5e5b9` | `ResultCode::BLOCKED_GEOIP` |
| *(new in 3.0)* | `ResultCode::BLOCKED_RESIDENTIAL_PROXY` |

The final row is a new code introduced in 3.0 with no 2.x equivalent. Use it to filter logs and dashboards for residential-proxy blocks (e.g., `SELECT COUNT(*) FROM bad_behaviour WHERE status_code = 'blocked.residential_proxy'`).

For the full mapping, see `Core/ResultCode.php` — values match the enum's `->value` string.

### 4. Adapter Interface

**Old:** 14 methods, procedural-style.
**New:** 18 methods, interface-based with Cache/GeoIP/Logger separation.

```php
// Implement these new methods:
- increment_counter()
- get_counter()
- delete()
- get_behavior_profile()
- save_behavior_profile()
- add_to_set() / get_set()
- get_geoip()
- verify_challenge()
- log()
```

See `src/Adapter/GenericAdapter.php` for a reference implementation.

### 5. Database Schema

**Old:** `log_id`, `status_key` (hex).
**New:** Normalized columns with semantic names.

**MySQL migration:**

```sql
ALTER TABLE `prefix_bad_behaviour`
    ADD COLUMN `status_code` VARCHAR(50) NOT NULL DEFAULT '' AFTER `request_entity`,
    ADD COLUMN `status_message` TEXT AFTER `status_code`,
    ADD COLUMN `support_key` VARCHAR(64) AFTER `status_message`,
    ADD COLUMN `bot_category` VARCHAR(32) AFTER `support_key`,
    ADD COLUMN `bot_verified` BOOLEAN DEFAULT FALSE AFTER `bot_category`,
    ADD COLUMN `ja3` CHAR(32) AFTER `bot_verified`,
    ADD COLUMN `h2_hash` CHAR(16) AFTER `ja3`,
    ADD COLUMN `header_order_hash` CHAR(16) AFTER `h2_hash`,
    ADD COLUMN `asn` VARCHAR(32) AFTER `header_order_hash`,
    ADD COLUMN `country` CHAR(2) AFTER `asn`,
    ADD COLUMN `request_time_ms` INT UNSIGNED AFTER `country`;

ALTER TABLE `prefix_bad_behaviour`
    ADD INDEX `idx_status` (`status_code`),
    ADD INDEX `idx_user_agent_hash` (`user_agent_hash`),
    ADD INDEX `idx_request_uri_hash` (`request_uri_hash`);
```

**SQLite migration:**

```sql
ALTER TABLE "prefix_bad_behaviour"
    ADD COLUMN "status_code" VARCHAR(50) NOT NULL DEFAULT '',
    ADD COLUMN "status_message" TEXT,
    ADD COLUMN "support_key" VARCHAR(64),
    ADD COLUMN "bot_category" VARCHAR(32),
    ADD COLUMN "bot_verified" BOOLEAN DEFAULT 0,
    ADD COLUMN "ja3" CHAR(32),
    ADD COLUMN "h2_hash" CHAR(16),
    ADD COLUMN "header_order_hash" CHAR(16),
    ADD COLUMN "asn" VARCHAR(32),
    ADD COLUMN "country" CHAR(2),
    ADD COLUMN "request_time_ms" INTEGER UNSIGNED;

CREATE INDEX IF NOT EXISTS "idx_status" ON "prefix_bad_behaviour" ("status_code");
CREATE INDEX IF NOT EXISTS "idx_user_agent_hash" ON "prefix_bad_behaviour" ("user_agent_hash");
CREATE INDEX IF NOT EXISTS "idx_request_uri_hash" ON "prefix_bad_behaviour" ("request_uri_hash");
```

---

## New Features in 3.0

### Expanded Bot Registry & Categories (NEW)

3.0 ships with **~100 bots across 12 categories**. Every bot is now a typed `BotDefinition` object, every registry implements the `RegistryInterface` contract, and the shipped data lives in `DefaultRegistry`.

| Category | Default | Examples |
|---|---|---|
| `search_engine` | `allow` (verified) | Googlebot, Bingbot, Yandex, Baidu, DuckDuckBot, Brave, Kagi, Naver, Sogou, Qihoo360, ByteDance, Petal, Cốc Cốc, Mail.ru, Stract, Marginalia, Centrum |
| `ai_crawler` | `challenge` | GPTBot, ClaudeBot, Gemini, Meta-ExternalAgent, PerplexityBot, Grok, Mistral, Cohere, Amazonbot, Diffbot |
| `social_crawler` | `allow` (verified) / `log_only` (unverified) | Facebook, Twitter, LinkedIn, Slack, Telegram, WhatsApp, KakaoTalk, LINE, WeChat, Notion |
| `seo_crawler` | `challenge` | Semrush, Ahrefs, MJ12, DotBot, SimilarWeb, Seobility, Botify, Lumar, Screaming Frog |
| `archive_crawler` | `allow` (verified) | Internet Archive, Common Crawl, UKWA, BnF, DNB, KB-NL, **FOSSies** |
| `monitoring` | `allow` | UptimeRobot, Pingdom, StatusCake, GTmetrix, Lighthouse |
| `feed_reader` | `allow` | Feedly, Inoreader, Flipboard, NewsBlur, Google News, Apple News |
| `shopping_crawler` | `allow` | Google Shopping, Bing Shopping, Facebook Catalog, Pinterest Shopping, Shopify |
| `cloud_infrastructure` | **`hard allow`** | Cloudflare, AWS ELB/ALB, GCP LB, Azure LB/Front Door, Fastly |
| `security_scanner` | `log_only` | Qualys, Detectify, Rapid7, Shodan, Censys |
| `residential_proxy` | `block` | Bright Data (Luminati) |
| `malicious` | `block` | Known-bad actors |
| `unknown` | (catch-all) | — |

**Categorical defaults are tunable** via `bot_categories.{blocked, log_only, challenge, allowed}`:

```php
'bot_categories' => [
    'blocked'   => ['malicious', 'residential_proxy'],
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

### Custom Registries (NEW) — Pluggable, Composable

The old static `Registry` class is replaced by a proper interface hierarchy so operators can ship tailored bot lists, swap registries per-tenant, or build a completely custom bot set without forking the library.

**Architecture:**

| Component | Purpose |
|-----------|---------|
| `RegistryInterface` | Read-only contract — every registry implementation satisfies it |
| `DefaultRegistry` | All ~100 shipped bots, hardcoded as `BotDefinition` instances |
| `InMemoryRegistry` | Wrap a user-provided array of `BotDefinition`s (tests, programmatic construction) |
| `EmptyRegistry` | No-op singleton — humans-only baseline |
| `FilteredRegistry` | Keep/exclude bot IDs + category filters over any inner registry |
| `MergedRegistry` | Compose multiple registries (last-wins semantics) |
| `CustomRegistry` | Config-array driven, with per-bot validation and `get_errors()` reporting |
| `Presets` | Named subsets: `full`, `minimal`, `verified-only`, `no-ai`, `no-seo`, `eu-only`, `human-only`, `custom` |
| `RegistryFactory` | Builder entry points: `from_file()`, `from_array()`, `default()` |
| `RegistryTokens` | Single source of truth for `NOISE` tokens and `MIN_TOKEN_LENGTH` (DRY) |

**New configuration file:** `config/bb_registry.php`

Operators drop a `bb_registry.php` with one of eight preset names, optional category filters, and an `additions` array for internal bots. If the file is absent, `RegistryFactory::default()` (the full ~100-bot registry) is used — backward-compatible default.

```php
<?php
// config/bb_registry.php

return [
    // Pick one of: full | minimal | verified-only | no-ai | no-seo | eu-only | human-only | custom
    'preset'             => 'minimal',

    // Optional category-level filters
    'exclude_categories' => ['seo_crawler'],
    'include_categories' => ['cloud_infrastructure'],   // overrides exclude

    // Optional bot-level filters
    'exclude_bots'       => ['petal'],

    // Optional: define internal/custom bots (merged on top, last-wins)
    'additions'          => [
        'internal_uptime_monitor' => [
            'name'                => 'Internal Uptime Monitor',
            'user_agent_patterns' => ['InternalMonitor/1.0'],
            'host_patterns'       => ['monitor.internal'],
            'ip_ranges'           => ['10.0.0.0/8'],
            'verify_dns'          => true,
            'dns_suffixes'        => ['monitor.internal'],
            'category'            => 'monitoring',
            'default_action'      => 'allow',
            'description'         => 'Our internal uptime checker',
        ],
    ],
];
```

**Filter execution order** (applied left-to-right, each step takes the previous output as input):
1. Load preset (or empty for `human-only`/`custom`)
2. Apply `exclude_categories` (drop whole categories)
3. Apply `include_categories` (re-add, overrides exclude — useful as a safety net)
4. Apply `exclude_bots` (remove specific bots by ID)
5. Merge `additions` (custom bots on top, last-wins)

**Per-tenant swaps** — `BadBehaviour` accepts a registry at construction and can be cloned with a different one:

```php
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Bot\Registry\MergedRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;

$bb = BadBehaviour::withAdapter($adapter);

$tenant_registry = $bb->with_registry(
    new MergedRegistry([
        $bb->get_registry(),
        new InMemoryRegistry($tenant_specific_bots),
    ])
);

$result = $tenant_registry->run();
```

**Validation behavior:** `CustomRegistry` validates each config entry against the `BotDefinition` schema. Invalid entries are logged via `error_log()` and skipped — they don't break the whole registry. Required keys are `name`, `user_agent_patterns` (≥1 entry), and `category` (one of the 12 enum cases). Call `$registry->has_errors()` / `get_errors()` programmatically if you build registries in code.

**Cloud infrastructure safety:** The shipped `config/bb_registry.php` includes `'include_categories' => ['cloud_infrastructure']` as a safety net. This guarantees CDN health probes (Cloudflare, AWS ELB, GCP LB, Azure, Fastly) remain allowed even if a future preset accidentally drops them — blocking them takes your origin offline.

See [CONFIGURATION.md → Bot Registry](CONFIGURATION.md#bot-registry--custom-composable-pluggable) for full programmatic examples.

### Cloud Infrastructure Fast Path (NEW — Critical)

A new early-exit check runs **before** UA matching: if the IP falls in a known cloud LB range (Cloudflare, AWS, GCP, Azure, Fastly), the request is **immediately allowed**.

```php
// In BotDetector::detect_uncached() — runs FIRST
if ($this->is_cloud_infrastructure_ip($ip)) {
    return Result::allow($package);
}
```

**Why this matters**: blocking CDN health probes marks your origin unhealthy in the load balancer and takes your site offline. This was the #1 outage vector in older bot blockers. The fast path covers ~30 known CIDR blocks statically; enable `enable_dynamic_ip_ranges` for live coverage from Cloudflare/AWS/GCP/Fastly feeds.

⚠️ **Never** add cloud LB ranges to `custom_rules` with `action: 'block'`. Even if the fast path short-circuits before custom rules, defensive coding means: don't put yourself in a position to accidentally block the CDN.

### AI Crawler Control

```php
'ai_crawlers' => [
    'allowed'          => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
    'block_unverified' => true,
    'strict'           => false,
],
```

Verified tokens: `GPTBot`, `ClaudeBot`, `Google-Extended`, `PerplexityBot`, `Meta-ExternalAgent`, `Applebot-Extended`, `CCBot`, `ia_archiver`, `GrokBot`, `MistralBot`, `YouBot`.

> **Migration note**: `brightdata` (Bright Data / Luminati residential proxy network) is **no longer in the `ai_crawler` category**. It now lives in the new `residential_proxy` category with default action `BLOCK`. If you relied on `bot_categories.blocked: ['ai_crawler']` to catch Bright Data, you must add `'residential_proxy'` to that list. The bot is still blocked out of the box.

### Client Hints Validation (NEW)

```php
'enable_client_hints_validation' => true,
```

Cross-validates `User-Agent` against `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile`, full version list. Catches most spoofed UAs from Chromium 89+ browsers. Off by default — enable after monitoring for 1–2 weeks.

### Agentic Behavior Detection (NEW)

```php
'enable_agentic_detection' => true,
```

Detects AI-agent patterns (Brave Leo, ChatGPT operator, Playwright scrapers):
- **Think-then-fetch** — long pause + asset burst
- **Non-linear navigation** — 5+ unrelated sections in 8 requests
- **Precision targeting** — high API ratio, no CSS/fonts/tracking

Off by default — risk of false positives on power users.

### Head Request Detection (NEW)

```php
'enable_head_request_detection' => true,   // default: true
'head_require_referer'          => true,
'head_flood_threshold'          => 20,
'head_probe_threshold'          => 50,
'head_referer_exempt_paths'     => ['/api/', '/wp-json/', '/health', '/status'],
```

Detects HEAD request abuse for site mapping and reconnaissance. Three signals:
- HEAD without Referer (except `/api/`, `/wp-json/`, `/health`, `/status`)
- HEAD flood per session (>20 requests)
- HEAD probing per IP (>50 requests in 5 minutes)

Low FP risk — enabled by default.

### Asset Scraping Detection (NEW)

```php
'enable_asset_scraping_detection' => true,  // default: true
'asset_extensions'                => ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'pdf', 'doc', 'docx'],
'asset_no_referer_threshold'      => 10,
'asset_only_session_threshold'    => 20,
'asset_pattern_threshold'         => 100,
```

Detects AI training crawlers and image harvesters that download assets in bulk without loading HTML pages first. Three signals:
- Asset requests without Referer (>10/hr per IP)
- Asset-only session (>20 assets, zero HTML loads)
- Sequential asset pattern (>100 assets in 5 min per IP)

Low FP risk — enabled by default.

### Dynamic IP Range Feeds (NEW, experimental)

```php
'enable_dynamic_ip_ranges' => true,
'dynamic_ip_ranges' => [
    'enabled' => true,
    'ttl'     => 86400,
    'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
],
```

Pulls fresh ranges from Google, Bing, OpenAI, Anthropic, Apple, Perplexity, DuckDuckGo, Amazon, Cloudflare. Requires cron:

```bash
0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php
```

**Status: experimental** — caching boundaries and timing issues to be resolved before graduating from experimental. Stale-cache fallback is automatic; if a feed fetch fails, the application uses the last-known good data. See [PERFORMANCE.md → Keep cloud ranges up to date](PERFORMANCE.md#keep-cloud-ranges-up-to-date).

### Rate Limiting

```php
'rate_limits' => [
    'enabled'    => true,
    'global'     => ['requests' => 1000, 'window' => 3600],
    'per_minute' => ['requests' => 60,   'window' => 60],
    'post'       => ['requests' => 30,   'window' => 3600],
    'login'      => ['requests' => 10,   'window' => 900],
],
```

Auto-detects login endpoints via `/(login|signin|auth|password)/i`. Storage via adapter (`increment_counter`, `get_counter`).

### Challenge System

```php
'challenge' => [
    'enabled'             => true,
    'provider'            => 'hcaptcha',  // builtin, hcaptcha, recaptcha, turnstile
    'site_key'            => 'your-site-key',
    'secret_key'          => 'your-secret-key',
    'recaptcha_min_score' => 0.5,
],
```

`builtin` = Zero-dependency Proof-of-Work (no external deps).

### Fingerprinting (Opt-in, Config-Only)

```php
'fingerprints' => [
    'bad_ja3' => ['771,4865-4867-4866-...,0-23-65281-...,29-23-24,0'],
    'bad_h2'  => ['a1b2c3d4e5f67890'],
    'bot_header_orders' => ['a1b2c3d4e5f67890'],
],
```

Only blocks **known bad** fingerprints from config — zero false positives by design.

### GeoIP Blocking

```php
'geoip' => [
    'enabled'           => true,
    'database_path'     => '/usr/share/GeoIP/GeoLite2-Country.mmdb',
    'blocked_countries' => ['XL', 'ZZ'],
    'blocked_asns'      => [],
],
```

### Static Asset Skipping (Performance)

```php
'performance' => [
    'skip_extensions' => ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot', 'webp', 'avif', 'map', 'txt'],
    'skip_paths'      => ['/static/', '/assets/', '/media/', '/images/', '/css/', '/js/', '/fonts/', '/dist/', '/build/', '/vendor/', '/node_modules/'],
],
```

Checked **first** — bypasses all detection.

### Custom Rules — `action: 'log'` (NEW)

Audit permitted bots/search-engines without affecting their behavior:

```php
'custom_rules' => [
    [
        'type'    => 'ua_regex',
        'value'   => '/Googlebot|Bingbot|DuckDuckBot/i',
        'action'  => 'log',
        'id'      => 'audit_search_engines',
    ],
    [
        'type'    => 'ua_contains',
        'value'   => 'GPTBot',
        'action'  => 'log',
        'id'      => 'audit_gptbot',
    ],
],
```

`log` rules return `null` from the evaluator so the request continues through the full detection pipeline. The rule ID is recorded in `Result::metadata['rule_id']` for downstream log filtering. See [CONFIGURATION.md → Custom Rules](CONFIGURATION.md#custom-rules-custom_rules) for more examples.

### Block Page Customization (NEW)

```php
'show_contact_info'        => true,  // Show admin email on block page
'show_detailed_block_page' => true,  // Show reason + support key (vs. terse "Reference #xxx")
```

---

## Legacy Compatibility (Default Behavior)

| Feature | 2.x | 3.0 Default |
|---------|-----|-------------|
| Missing `Accept` header | Block browser-like UAs | **Only traditional page loads** |
| POST body inspection | Trackbacks + `document.write` | **Only `application/x-www-form-urlencoded`** |
| `curl`/`wget`/HTTP libs | Allowed | **Allowed** (`http_tool` category) |
| JSON body inspection | Never | **Disabled** (`inspect_json_body = false`) |
| Multipart inspection | Never | **Disabled** (`inspect_multipart_body = false`) |
| Strict header checks | Opt-in | **Disabled** (`strict = false`) |
| Client Hints validation | N/A | **Disabled** (`enable_client_hints_validation = false`) |
| Agentic detection | N/A | **Disabled** (`enable_agentic_detection = false`) |
| Dynamic IP ranges | N/A | **Disabled** (`enable_dynamic_ip_ranges = false`) |
| Head request detection | N/A | **Enabled** (`enable_head_request_detection = true`) |
| Asset scraping detection | N/A | **Enabled** (`enable_asset_scraping_detection = true`) |
| Cloud LB fast path | N/A | **Enabled** (always-on safety check) |
| Verified search engines | Bypass all | **Bypass all** |

**Result**: Drop-in upgrade for most sites — no config changes needed beyond creating `bb_config.php` from the example.

---

## Migration Steps

### 1. Backup & Update Code

```bash
cp -r vendor/badbehaviour vendor/badbehaviour.bak
cp config/bb_settings.conf config/bb_settings.conf.bak   # if migrating from 2.x INI
composer update bad-behaviour/bad-behaviour
```

### 2. Create `bb_config.php`

```bash
cp config/bb_config.example.php config/bb_config.php
# Edit config/bb_config.php and translate from your old settings.ini
```

**Start with the [Default configuration profile](CONFIGURATION.md#configuration-profiles)** — it matches 2.x behavior exactly. After 1–2 weeks of monitoring, graduate to [Medium](CONFIGURATION.md#profile-medium-production-grade-monitored) by enabling the new detectors one at a time.

A side-by-side converter for common keys is in [CONFIGURATION.md](CONFIGURATION.md#migration-from-ini-format-2x--30). The full three-profile matrix with compatibility trade-offs is in [Configuration Profiles](CONFIGURATION.md#configuration-profiles).

### 3. Run Database Migration

```bash
# MySQL
mysql -u user -p dbname < vendor/bad-behaviour/bad-behaviour/migrations/mysql_upgrade_3.0.sql

# SQLite
sqlite3 data/wacko.db < vendor/bad-behaviour/bad-behaviour/migrations/sqlite_upgrade_3.0.sql
```

### 4. Update Legacy Entry Points (if used)

```php
// Old (still works as a shim)
require_once 'bad-behaviour-wackowiki.php';

// New (recommended)
require 'vendor/autoload.php';
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\WackoWikiAdapter;

$adapter = new WackoWikiAdapter($db);
$bb = BadBehaviour::withAdapter($adapter);
$bb->run();
```

### 5. Whitelist Format (Unchanged)

```ini
; config/bb_whitelist.conf — same as 2.x
[ip]
internal = "10.0.0.0/8"

[useragent]
monitoring = "InternalMonitor/1.0"

[url]
health = "/health"

; NEW sections (require GeoIP)
[asn]
google = "AS15169"

[country]
us = "US"
de = "DE"
```

### 6. Test Before Deploy

```bash
# Unit tests
vendor/bin/phpunit --testsuite Unit

# Integration tests
vendor/bin/phpunit --testsuite Integration

# Manual test
curl -X POST https://yoursite/src/AddComment \
  -H "Content-Type: application/json" \
  -d '{"ajax_preview":"1","body":"test"}'
# Should return 200 OK (not 403)
```

---

## Admin Panel (WackoWiki)

### Updated Module

- `src/admin/module/tool_badbehaviour.php` updated for 3.0
- Uses `ResultCode` enum + legacy hex code map (for backward-compatible display)
- All 3.0 settings exposed in UI with risk labels
- Column `status_key` → `status_code` (semantic values)

### Language Strings

Add to `lang/en.php`:

```php
'BbEnableBehavioral'           => 'Enable behavioral analysis',
'BbEnableFingerprinting'       => 'Enable TLS/HTTP2 fingerprinting',
'BbInspectJson'                => 'Inspect JSON request bodies',
'BbInspectMultipart'           => 'Inspect multipart bodies',
'BbBlockUnverifiedAi'          => 'Block unverified AI crawlers',
'BbStrictAi'                   => 'Strict AI mode',
'BbAllowedAiCrawlers'          => 'Allowed AI crawler tokens',
'BbEnableClientHints'          => 'Enable Client Hints validation',
'BbEnableAgentic'              => 'Enable agentic behavior detection',
'BbEnableDynamicIpRanges'      => 'Enable dynamic IP ranges (experimental)',
'BbEnableHeadRequestDetection' => 'Enable HEAD request abuse detection',
'BbEnableAssetScrapingDetection' => 'Enable asset scraping detection',
'BbShowContactInfo'            => 'Show contact info on block page',
'BbShowDetailedBlockPage'      => 'Show detailed block page',
'BbDnsblEnabled'               => 'Enable DNSBL checks',
'BbRateLimitEnabled'           => 'Enable rate limiting',
'BbChallengeEnabled'           => 'Enable challenges',
'BbGeoipEnabled'               => 'Enable GeoIP lookups',
'BbBotCategoriesBlocked'       => 'Bot categories to block',
'BbBotCategoriesLogOnly'       => 'Bot categories to log only',
'BbBotCategoriesChallenge'     => 'Bot categories to challenge',
'BbBotCategoriesAllowed'       => 'Bot categories to allow',
```

---

## Performance Notes

See [PERFORMANCE.md](PERFORMANCE.md) for full benchmarks. Highlights:

1. **DNS Verification**: Cached 7 days per `(IP, dns_suffixes)` pair (was 1 hour in 2.x)
2. **Cloud LB fast path**: 8 μs per request — covers ~30 static CIDR blocks
3. **Result cache**: 5-minute TTL per `(IP, UA, config_fingerprint)` — expected 40–70% hit rate on busy sites
4. **Rate Limiting**: Requires persistent adapter storage (Redis/DB) for production
5. **GeoIP**: Load MaxMind DB once at startup
6. **Static Files**: Configure `performance.skip_extensions`/`skip_paths` to avoid processing CSS/JS/images (~145 μs saved per skipped request)
7. **Logging**: Only blocked requests logged by default (`verbose = false`)
8. **Dynamic Feeds** (experimental): runs out-of-band via cron — never on the request path
9. **Client Hints validation**: cheap (string parsing) — safe to enable at any scale

Headline numbers from `tests/benchmark.php`:

| Request type | Latency |
|--------------|--------:|
| Static resource | 12 μs |
| Cloud LB health probe | 8 μs |
| Empty UA (block) | 62 μs |
| Browser HTML page | 158 μs |
| Verified search engine | 84 μs |

---

## Monitoring

### JSON Logging (SIEM)

In `bb_config.php`:
```php
'logging'  => true,
'verbose'  => false,   // set true to log every request, not just blocks
```

Log format (when your adapter persists results):
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "warning",
  "action": "block",
  "code": "blocked.attack_pattern",
  "ip": "203.0.113.42",
  "ua": "sqlmap/1.0",
  "uri": "/article?id=1",
  "method": "GET",
  "country": "US",
  "asn": "AS12345",
  "support_key": "c000-0201-acf1",
  "rule_id": null,
  "bot_category": null,
  "bot_verified": false
}
```

`rule_id` is populated for `custom_rules` matches (including `action: 'log'`).
`bot_category` is one of: `search_engine`, `ai_crawler`, `social_crawler`, `seo_crawler`, `archive_crawler`, `monitoring`, `feed_reader`, `shopping_crawler`, `cloud_infrastructure`, `security_scanner`, `residential_proxy`, `malicious`, `unknown`.
`code` includes `blocked.residential_proxy` for residential-proxy blocks.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `status_key` column not found | Run DB migration (see step 3 above) |
| AJAX requests blocked | Ensure `inspect_json_body = false` (default) |
| File uploads blocked | Ensure `inspect_multipart_body = false` (default) |
| `curl`/`wget` blocked | Update UA parser (fixed in 3.0.1+) |
| `bb_config.php` not loading | Check `CONFIG_DIR` constant; verify file returns an array |
| `enable_dynamic_ip_ranges` stale data | Run `bin/update-ip-ranges.php` via cron |
| Client Hints false positives | Disable for Electron apps; check `enable_client_hints_validation = false` |
| Agentic detection false positives | Require session cookies; monitor for power-user patterns |
| Origin marked unhealthy by CDN | Check that cloud LB ranges are NOT in `custom_rules` block list — see [PERFORMANCE.md → Trust the cloud fast path](PERFORMANCE.md#trust-the-cloud-fast-path) |
| HEAD requests from monitoring blocked | Add monitoring path prefixes to `head_referer_exempt_paths` |

---

## Rollback Plan

```bash
# 1. Restore code
rm -rf vendor/bad-behaviour
mv vendor/bad-behaviour.bak vendor/bad-behaviour

# 2. Restore config
mv config/bb_settings.conf.bak config/bb_settings.conf

# 3. Restore DB (if migrated)
# Restore from backup or drop new columns:
ALTER TABLE `prefix_bad_behaviour`
    DROP COLUMN status_code, status_message, support_key,
    bot_category, bot_verified, ja3, h2_hash, header_order_hash,
    asn, country, request_time_ms;
```

---

## Upgrading to 3.x Point Releases

Bad Behaviour follows [Semantic Versioning](https://semver.org/):

- **Patch (3.0.x)**: bug fixes, no config changes required
- **Minor (3.x.0)**: new optional detectors / feed sources / bot categories, opt-in only, no breaking changes
- **Major (x.0.0)**: breaking config or interface changes (e.g. 3.0 INI → PHP array)

**Always review** `CHANGELOG.md` before upgrading minor versions — new opt-in features may be worth enabling. Major versions require reading the migration guide section for the relevant version bump.

---

## Support

- [Configuration Reference](CONFIGURATION.md)
- [Performance Guide](PERFORMANCE.md)
- [Issues](https://github.com/Bad-Behaviour/badbehaviour/issues)
- [Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions)
- [Wiki](https://github.com/Bad-Behaviour/badbehaviour/wiki)
