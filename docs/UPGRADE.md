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

For full mapping, see `Core/ResultCode.php` — values match the enum's `->value` string.

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

### AI Crawler Control

```php
'ai_crawlers' => [
    'allowed'          => ['GPTBot', 'ClaudeBot', 'Google-Extended'],
    'block_unverified' => true,
    'strict'           => false,
],
```

Verified tokens: `GPTBot`, `ClaudeBot`, `Google-Extended`, `PerplexityBot`, `Meta-ExternalAgent`, `Applebot-Extended`, `CCBot`, `ia_archiver`, `GrokBot`, `MistralBot`, `YouBot`.

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

### Dynamic IP Range Feeds (NEW, experimental)

```php
'enable_dynamic_ip_ranges' => true,
```

Pulls fresh ranges from Google, Bing, OpenAI, Anthropic, Apple, Perplexity, DuckDuckGo, Amazon, Cloudflare. Requires cron:

```bash
0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php
```

**Status: experimental** — caching boundaries and timing issues to be resolved before graduating from experimental. See [README → Dynamic IP Range Feeds](README.md#dynamic-ip-range-feeds-experimental).

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
    'blocked_countries' => ['KP', 'IR'],
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

A side-by-side converter for common keys is in [CONFIGURATION.md](CONFIGURATION.md#migration-from-ini-format-2x--30).

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
'BbShowContactInfo'            => 'Show contact info on block page',
'BbShowDetailedBlockPage'      => 'Show detailed block page',
'BbDnsblEnabled'               => 'Enable DNSBL checks',
'BbRateLimitEnabled'           => 'Enable rate limiting',
'BbChallengeEnabled'           => 'Enable challenges',
'BbGeoipEnabled'               => 'Enable GeoIP lookups',
```

---

## Performance Notes

1. **DNS Verification**: Cached 1 hour per IP
2. **Rate Limiting**: Requires persistent adapter storage (Redis/DB) for production
3. **GeoIP**: Load MaxMind DB once at startup
4. **Static Files**: Configure `performance.skip_extensions`/`skip_paths` to avoid processing CSS/JS/images
5. **Logging**: Only blocked requests logged by default (`verbose = false`)
6. **Dynamic Feeds** (experimental): runs out-of-band via cron — never on the request path
7. **Client Hints validation**: cheap (string parsing) — safe to enable at any scale

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
  "rule_id": null
}
```

`rule_id` is populated for `custom_rules` matches (including `action: 'log'`).

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
- **Minor (3.x.0)**: new optional detectors / feed sources, opt-in only, no breaking changes
- **Major (x.0.0)**: breaking config or interface changes (e.g. 3.0 INI → PHP array)

**Always review** `CHANGELOG.md` before upgrading minor versions — new opt-in features may be worth enabling. Major versions require reading the migration guide section for the relevant version bump.

---

## Support

- [Configuration Reference](CONFIGURATION.md)
- [Issues](https://github.com/Bad-Behaviour/badbehaviour/issues)
- [Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions)
- [Wiki](https://github.com/Bad-Behaviour/badbehaviour/wiki)