# Bad Behaviour 3.0 — Configuration Reference

---

## 🔧 CACHE_DIR — Critical for Production

Bad Behaviour stores **rate-limit counters, behavioral profiles, JA3 sets, and challenge tokens** in a file cache.
By default it uses the system temp directory:

```php
// WackoWikiAdapter.php (lines 12–14)
if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', sys_get_temp_dir() . '/badbehaviour_cache');
}
```

| Environment | Default Path |
|-------------|--------------|
| Linux/Unix  | `/tmp/badbehaviour_cache/bad_behaviour/` |
| macOS       | `/private/tmp/badbehaviour_cache/bad_behaviour/` |
| Windows     | `C:\Windows\Temp\badbehaviour_cache\bad_behaviour\` |

### ⚠️ Why Override It?

1. **`/tmp` is cleared on reboot** — counters reset (acceptable for short windows)
2. **Shared hosting** — other users *could* read/write `/tmp/badbehaviour_cache/`
3. **Container/ephemeral deployments** — `/tmp` lost on pod restart
4. **Multi-server** — each node has its own cache (use Redis via MediaWikiAdapter instead)

### ✅ Recommended: Define in `constants.php`

```php
// config/constants.php — add near the other CACHE_* constants

const CACHE_CONFIG_DIR            = '_cache/config';
const CACHE_FEED_DIR              = '_cache/feed';
const CACHE_PAGE_DIR              = '_cache/page';
const CACHE_SQL_DIR               = '_cache/query';
const CACHE_TEMPLATE_DIR          = '_cache/template';
const CACHE_SESSION_DIR           = '/tmp';

// >>> ADD HERE <<<
if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', '/var/cache/wackowiki/badbehaviour');
}
```

> **Must be defined before** `require 'class/init.php';` or `use BadBehaviour\Adapter\WackoWikiAdapter;`

### Alternative: Override in `index.php` (Local Dev)

```php
<?php
// index.php — BEFORE include 'class/init.php';

if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', __DIR__ . '/_cache/badbehaviour');  // project-local
}

const IN_WACKO = 'wacko';
include 'class/init.php';
```

### Directory Permissions

```bash
# Production
mkdir -p /var/cache/wackowiki/badbehaviour
chown www-data:www-data /var/cache/wackowiki/badbehaviour
chmod 750 /var/cache/wackowiki/badbehaviour

# Local dev (if using project-local)
mkdir -p _cache/badbehaviour
chmod 777 _cache/badbehaviour
```

### Verify It Works

```bash
# After a few requests
ls -la /var/cache/wackowiki/badbehaviour/
# counter_ratelimit:global:192.0.2.1.json
# behavior_abc123.json
# challenge:192.0.2.1:xyz.json
```

---

## Configuration File Format (3.0)

Starting with 3.0, configuration is a **typed PHP array** returned by `config/bb_config.php`. This replaces the INI file format used in 2.x.

```php
<?php
// config/bb_config.php

return [
    'logging' => true,
    'verbose' => false,
    // ...
];
```

**Why PHP array instead of INI?**

- ✅ Full IDE type checking & autocomplete
- ✅ No parsing ambiguity (string vs int vs bool)
- ✅ Can compute values at load time
- ✅ Easy to override per-environment via `array_merge`
- ✅ Comments use `//` like normal PHP

---

## Quick Start: Safe Defaults

```php
<?php
// config/bb_config.php

return [
    // ===== CORE =====
    'logging'                    => true,
    'verbose'                    => false,
    'strict'                     => false,
    'offsite_forms'              => false,

    'show_contact_info'          => false,  // Admin email on block page
    'show_detailed_block_page'   => false,  // Detailed block page w/ support key

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
        'blocked' => ['malicious'],
    ],

    // ===== RATE LIMITS =====
    'rate_limits' => [
        'enabled'    => true,
        'global'     => ['requests' => 1000, 'window' => 3600],
        'per_minute' => ['requests' => 60,   'window' => 60],
        'post'       => ['requests' => 30,   'window' => 3600],
        'login'      => ['requests' => 10,   'window' => 900],
    ],

    // ===== 3.0 DETECTION FEATURES (opt-in) =====
    'enable_fingerprinting'          => false,
    'inspect_json_body'              => false,
    'inspect_multipart_body'         => false,
    'enable_behavioral_analysis'     => true,
    'enable_ai_crawler_control'      => true,
    'enable_client_hints_validation' => false, // NEW
    'enable_agentic_detection'       => false, // NEW
    'enable_dynamic_ip_ranges'       => false, // NEW (EXPERIMENTAL)
];
```

> All new 3.0 features are **off by default** for backward compatibility with 2.x.

---

## Complete Settings Reference

### Core

| Setting | Type | Default | Risk | Description |
|---------|------|---------|------|-------------|
| `logging` | bool | `true` | **NONE** | Required for audit trail |
| `verbose` | bool | `false` | **LOW** | When true, logs *every* request (not just blocks) |
| `strict` | bool | `false` | 🔴 **HIGH** | Strict mode — extra checks for Accept-Encoding, etc. Breaks old browsers / non-browser clients |
| `offsite_forms` | bool | `false` | 🟡 **MEDIUM** | Reject form POSTs where Referer doesn't match Host |
| `show_contact_info` | bool | `false` | 🟢 **LOW** | Show admin email on block page |
| `show_detailed_block_page` | bool | `false` | 🟢 **LOW** | Show reason + support key on block page (vs. terse "Reference #xxx") |

**Block page rendering** (`BadBehaviour::serve_block_page()`):

```php
// Simple (default when both flags are false)
<h1>Access Denied</h1>
<p>You don't have permission to access this resource.</p>
<div class="ref">Reference #abc-1234-def0</div>

// Detailed (when show_detailed_block_page = true)
<h1>Access Denied</h1>
<p>We're sorry, but we could not fulfill your request for <code>/path</code>.</p>
<p><strong>Reason:</strong> Bot blocked: AhrefsBot</p>
<p>Your technical support key is: <strong>abc-1234-def0</strong></p>
// + contact paragraph (when show_contact_info = true)
```

---

### Reverse Proxy

| Setting | Type | Default | Risk | When to Configure |
|---------|------|---------|------|-------------------|
| `enabled` | bool | `false` | 🟡 **MEDIUM** — wrong IP if misconfigured | **Required** if behind Cloudflare, nginx, ALB, etc. |
| `header` | string | `X-Forwarded-For` | — | Match your proxy's header |
| `addresses[]` | CIDR[] | `[]` | 🔴 **HIGH** — spoofing if wrong | **Must** list all proxy IP ranges (Cloudflare, AWS ALB, etc.) |

> ⚠️ **Never enable `enabled=true` without `addresses[]`** — allows IP spoofing.

**Cloudflare IPs** (add to `addresses[]`):
```php
'addresses' => [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
],
```

---

### AI Crawlers (`ai_crawlers`)

| Setting | Type | Default | Risk | When to Change |
|---------|------|---------|------|----------------|
| `allowed[]` | string[] | `GPTBot, ClaudeBot, Google-Extended` | 🟢 **LOW** | Add/remove based on your robots.txt policy |
| `block_unverified` | bool | `true` | 🟢 **LOW** | Keep `true` — blocks spoofed AI bots |
| `strict` | bool | `false` | 🟡 **MEDIUM** | `true` = block even verified unallowed AI |

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

---

### Bot Categories (`bot_categories`)

| Setting | Type | Default | Risk | Notes |
|---------|------|---------|------|-------|
| `blocked[]` | string[] | `["malicious"]` | 🟡 **MEDIUM** | Categories: `search_engine`, `ai_crawler`, `social_crawler`, `seo_crawler`, `archive_crawler`, `monitoring`, `malicious`, `unknown` |

> Only `malicious` blocked by default. Adding `seo_crawler` blocks Ahrefs, Semrush, MJ12bot, etc.

---

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

---

### Body Scan (`body_scan_skip_fields`)

Prevents false positives on legitimate code snippets in comments/articles.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `body_scan_skip_fields[]` | string[] | See below | Field names to **skip** SQL/XSS scanning (form bodies only) |

**Default allowlist**:
```php
'body_scan_skip_fields' => [
    'body', 'comment', 'content', 'text', 'message', 'description',
    'code', 'source', 'snippet', 'markdown', 'html', 'wiki', 'post',
    'article', 'page', 'entry', 'reply', 'review', 'feedback',
],
```

**Heuristics also skip** fields ending with `_body`, `_content`, `_text`, `_html`, `_markdown`, `_wiki` or containing `comment`, `description`, `code`, `source`, etc.

**Parameter fields are NEVER skipped**: `search`, `query`, `filter`, `username`, `password`, `email`, `redirect`, `action`, `url`, `file`, `id`, `token`, etc.

---

### Custom Rules (`custom_rules`)

Each rule is an associative array. Order matters — rules are evaluated top to bottom, first match wins.

**Schema**:
```php
[
    'type'    => 'ip' | 'ua_regex' | 'ua_contains' | 'asn' | 'country' | 'header',
    'value'   => string | string[],   // for ip/asn/country/ua_regex/ua_contains
    'header'  => string,             // only for type: 'header'
    'action'  => 'allow' | 'block' | 'challenge' | 'log',
    'id'      => string,              // appears in result metadata
]
```

**`action: 'log'` — record without blocking**

Use `log` when you want to *observe* a permitted bot/search-engine without changing its behavior. The rule returns `null` so the request continues through the full detection pipeline. The rule `id` is recorded in `Result::metadata['rule_id']`.

```php
'custom_rules' => [
    // 1. Audit every verified Googlebot
    [
        'type'    => 'ua_regex',
        'value'   => '/Googlebot/i',
        'action'  => 'log',
        'id'      => 'audit_googlebot',
    ],

    // 2. Audit GPTBot (already allowed via ai_crawlers.allowed)
    [
        'type'    => 'ua_contains',
        'value'   => 'GPTBot',
        'action'  => 'log',
        'id'      => 'audit_gptbot',
    ],

    // 3. Audit the new "Brave Leo" agentic UA — decide policy later
    [
        'type'    => 'header',
        'header'  => 'Sec-CH-UA',
        'value'   => 'Brave Leo',
        'action'  => 'log',
        'id'      => 'brave_leo_agentic',
    ],

    // 4. Audit monitoring services you whitelist
    [
        'type'    => 'ua_regex',
        'value'   => '/UptimeRobot|Pingdom|StatusCake/i',
        'action'  => 'log',
        'id'      => 'audit_monitoring',
    ],

    // (non-log rules below still take effect normally)
    ['type' => 'ip', 'value' => '192.0.2.0/24', 'action' => 'block', 'id' => 'test_network'],
    ['type' => 'ua_regex', 'value' => 'badbot\d+', 'action' => 'block', 'id' => 'badbot_pattern'],
],
```

**Combining with `ai_crawlers.allowed`**: `custom_rules` runs **before** `BotDetector`. A `log` rule never blocks, so it doesn't interfere with `ai_crawlers.allowed`. A `block` rule short-circuits — useful for blocking specific bots even if they're in the AI allowlist.

---

### Challenge System (`challenge`)

| Setting | Type | Default | Risk | Providers |
|---------|------|---------|------|-----------|
| `enabled` | bool | `false` | 🟡 **MEDIUM** — UX friction | `builtin`, `hcaptcha`, `recaptcha`, `turnstile` |
| `provider` | string | `builtin` | — | `builtin` = PoW (no external deps) |
| `site_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `secret_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `recaptcha_min_score` | float | `0.5` | — | reCAPTCHA v3 only (0.0–1.0) |

> **Builtin PoW** works everywhere, no keys needed. Use for internal/admin areas.

---

### Performance (`performance`)

| Setting | Type | Default | Notes |
|---------|------|---------|-------|
| `skip_extensions[]` | string[] | `css, js, png, jpg, jpeg, gif, ico, svg, woff, woff2, ttf, eot, webp, avif, map, txt` | Never inspect these |
| `skip_paths[]` | string[] | `/static/, /assets/, /media/, /images/, /css/, /js/, /fonts/, /dist/, /build/, /vendor/, /node_modules/` | Prefix match |

---

### http:BL (`httpbl`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `key` | string | `""` | API key from Project Honey Pot |
| `threat` | int | `25` | Threat score threshold (0-255) |
| `maxage` | int | `30` | Max days since last activity |

---

### DNSBL (`dnsbl`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for DNSBL lookups |
| `lists[]` | string[] | `zen.spamhaus.org, bl.spamcop.net` | Additional DNSBL lists |

---

### Fingerprints (`fingerprints`) — Opt-in Only

```php
'fingerprints' => [
    'bad_ja3'           => [],  // Known-bad JA3 TLS fingerprints
    'bad_h2'            => [],  // Known-bad H2 settings hashes
    'bot_header_orders' => [],  // Known-bot header order hashes
    'expected_ja3'      => [],  // (reserved) trusted JA3 list
],
```

Only blocks **known bad** fingerprints from config — zero false positives by design.

---

### GeoIP (`geoip`)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `false` | Enable GeoIP lookups |
| `database_path` | string | `""` | Path to MaxMind DB |
| `blocked_countries[]` | string[] | `[]` | ISO country codes to block |
| `blocked_asns[]` | string[] | `[]` | ASN numbers to block |

---

### 3.0 Detection Features (Opt-in)

These are the new detectors introduced in 3.0. **All default to `false`** for legacy compatibility.

| Setting | Type | Default | Risk | Description |
|---------|------|---------|------|-------------|
| `enable_fingerprinting` | bool | `false` | 🟡 **MEDIUM** | Enables JA3/H2/header-order checks |
| `inspect_json_body` | bool | `false` | 🔴 **HIGH** | Apply attack patterns to JSON bodies |
| `inspect_multipart_body` | bool | `false` | 🔴 **HIGH** | Apply attack patterns to multipart uploads |
| `enable_behavioral_analysis` | bool | `true` | 🟢 **LOW** | Rate/UA/think-time heuristics |
| `enable_ai_crawler_control` | bool | `true` | 🟢 **LOW** | Verified AI allowlist enforcement |
| `enable_client_hints_validation` | bool | `false` | 🟡 **MEDIUM** | Sec-CH-UA cross-check (requires Chromium 89+) |
| `enable_agentic_detection` | bool | `false` | 🟡 **MEDIUM** | AI-agent pattern detection (think-then-fetch, precision) |
| `enable_dynamic_ip_ranges` | bool | `false` | 🟡 **EXPERIMENTAL** | Use FeedRegistry (requires cron, see [Feeds](README.md#dynamic-ip-range-feeds)) |

#### `enable_client_hints_validation`

Catches spoofed UAs from Chromium 89+ browsers. Validates:
- Missing `Sec-CH-UA`/`Sec-CH-UA-Platform`/`Sec-CH-UA-Mobile`
- Brand mismatch (`Sec-CH-UA` says Edge, UA says Chrome)
- Version drift > 2 majors
- Platform / mobile contradictions

False positive risk: Electron apps, very old Chromium, some headless tools.

#### `enable_agentic_detection`

Three pattern detectors (see [`AgenticBehaviorDetector`](README.md#agentic-behavior-detection-30)):
1. **Think-then-fetch** — long pause + asset burst
2. **Non-linear navigation** — 5+ unrelated sections in 8 requests
3. **Precision targeting** — high API ratio, no CSS/fonts/tracking

False positive risk: power users, single-page-app users. Requires session cookies.

#### `enable_dynamic_ip_ranges` (Experimental)

Pulls fresh IP ranges from Google, Bing, OpenAI, Anthropic, Apple, Perplexity, Cloudflare feeds. Requires `bin/update-ip-ranges.php` on cron. Known issues: caching boundaries in multi-server deployments, cold-start latency, CA bundle portability. See [Feeds](README.md#dynamic-ip-range-feeds-experimental) for full details.

---

## Whitelist (`config/bb_whitelist.conf`)

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

## Risk Matrix Summary

| Setting | Risk | Safe Default | Enable After |
|---------|------|--------------|--------------|
| `strict` | 🔴 HIGH | `false` | Never (or internal only) |
| `offsite_forms` | 🟡 MEDIUM | `false` | No external forms |
| `enable_fingerprinting` | 🟡 MEDIUM | `false` | 2+ weeks logs clean |
| `inspect_json_body` | 🔴 HIGH | `false` | Never (AJAX apps) |
| `inspect_multipart_body` | 🔴 HIGH | `false` | Never (uploads) |
| `enable_client_hints_validation` | 🟡 MEDIUM | `false` | 1–2 weeks monitoring |
| `enable_agentic_detection` | 🟡 MEDIUM | `false` | Power-user FPs ruled out |
| `enable_dynamic_ip_ranges` | 🟡 EXPERIMENTAL | `false` | Cron deployed + single server or Redis |
| `block_unverified_ai` | 🟢 LOW | `true` | Keep enabled |
| `strict_ai` | 🟡 MEDIUM | `false` | Zero AI policy |
| `enable_behavioral_analysis` | 🟢 LOW | `true` | Keep enabled |
| `enable_ai_crawler_control` | 🟢 LOW | `true` | Keep enabled |
| `reverse_proxy.enabled` | 🟡 MEDIUM | `false` | Behind proxy + `addresses[]` |

---

## Migration from INI Format (2.x → 3.0)

The 2.x INI format is replaced by `bb_config.php`. See [`MIGRATION.md`](MIGRATION.md) for the full conversion guide.

**Quick conversion example:**

```ini
; Old 2.x settings.ini
httpbl_key = "abc123"
strict = 1
rate_limits_global_requests = 1000
rate_limits_global_window = 3600
```

```php
// New 3.0 bb_config.php
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

---

## Example: Production Wiki (WackoWiki)

```php
<?php
// config/bb_config.php

return [
    // ===== CORE =====
    'logging'                    => true,
    'verbose'                    => false,
    'strict'                     => false,
    'offsite_forms'              => false,
    'show_contact_info'          => true,
    'show_detailed_block_page'   => true,

    // ===== REVERSE PROXY =====
    'reverse_proxy' => [
        'enabled'   => true,
        'header'    => 'CF-Connecting-IP',
        'addresses' => [
            '173.245.48.0/20', '103.21.244.0/22', // ... all Cloudflare ranges
        ],
    ],

    // ===== AI CRAWLERS =====
    'ai_crawlers' => [
        'allowed' => [
            'GPTBot', 'ClaudeBot', 'Google-Extended',
            'PerplexityBot', 'GrokBot', 'MistralBot',
            'YouBot', 'Meta-ExternalAgent',
        ],
        'block_unverified' => true,
        'strict'           => false,
    ],

    // ===== RATE LIMITS =====
    'rate_limits' => [
        'enabled'    => true,
        'global'     => ['requests' => 1000, 'window' => 3600],
        'per_minute' => ['requests' => 60,   'window' => 60],
        'post'       => ['requests' => 30,   'window' => 3600],
        'login'      => ['requests' => 10,   'window' => 900],
    ],

    // ===== 3.0 FEATURES (gradual rollout) =====
    'enable_fingerprinting'          => false,  // Week 3+
    'inspect_json_body'              => false,  // Never for AJAX apps
    'inspect_multipart_body'         => false,  // Never for uploads
    'enable_behavioral_analysis'     => true,
    'enable_ai_crawler_control'      => true,
    'enable_client_hints_validation' => true,   // Week 1 — low FP risk
    'enable_agentic_detection'       => false,  // Week 4+ — monitor FPs
    'enable_dynamic_ip_ranges'       => true,   // After cron deployed

    // ===== CUSTOM RULES — audit permitted bots =====
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
];
```

---

## Testing Configuration Changes

```bash
# 1. Validate PHP syntax
php -l config/bb_config.php

# 2. Dump the parsed config
php -r "var_export(require 'config/bb_config.php');"

# 3. Test specific endpoint (comment with code)
curl -X POST https://yourwiki/test/BBEvaluation/_addcomment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'body=Here is code: document.write("test"); union select 1'

# 4. Check logs / cache
ls -la /var/cache/wackowiki/badbehaviour/
tail -f /var/log/wackowiki/bad_behaviour.log  # or your DB table

# 5. Verify rate limits (should 429 after 60)
for i in {1..65}; do curl -s -o /dev/null -w "%{http_code}\n" /; done | sort | uniq -c
```

---

## Files to Distribute

| File | Purpose |
|------|---------|
| `config/bb_config.php` | Typed PHP-array configuration (single source of truth) |
| `config/bb_config.example.php` | Fully commented example |
| `config/bb_whitelist.conf` | Whitelist (INI — human-editable, simple) |
| `bin/update-ip-ranges.php` | Cron script for `enable_dynamic_ip_ranges` |

---

This reference gives admins **exactly what they need**: risk level, when to enable, and what breaks if misconfigured.