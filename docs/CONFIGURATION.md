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
const CACHE_SESSION_DIR           = '/tmp';              // '/tmp', '_cache/session'

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
// ...
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

## Quick Start: Safe Defaults

```ini
; config/bb_settings.conf (or settings.ini)
[core]
logging = true
verbose = false
strict = false
offsite_forms = false

; New 3.0 features (opt-in)
enable_fingerprinting = false
inspect_json_body = false
inspect_multipart_body = false
enable_behavioral_analysis = true
enable_ai_crawler_control = true

[ai_crawlers]
allowed[] = "GPTBot"
allowed[] = "ClaudeBot"
allowed[] = "Google-Extended"
allowed[] = "PerplexityBot"
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

---

## Complete Settings Reference

### `[core]` — Core Behaviour

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `logging` | bool | `true` | **NONE** | Always — required for audit trail |
| `verbose` | bool | `false` | **LOW** — log volume | Debugging only; logs *every* request |
| `strict` | bool | `false` | **HIGH** — breaks valid traffic | Only if you control all clients (API-only, internal) |
| `offsite_forms` | bool | `false` | **MEDIUM** — blocks external POSTs | If you have **zero** legitimate external form posts |
| `enable_fingerprinting` | bool | `false` | **MEDIUM** — FP on old browsers/proxies | After 2+ weeks monitoring logs |
| `inspect_json_body` | bool | `false` | **HIGH** — blocks wiki markup, code | **Never** for AJAX/JSON apps |
| `inspect_multipart_body` | bool | `false` | **HIGH** — blocks file uploads | **Never** for upload endpoints |
| `enable_behavioral_analysis` | bool | `true` | **LOW** — rate/rotating UA | Keep enabled (safe) |
| `enable_ai_crawler_control` | bool | `true` | **LOW** — verified AI allowed | Keep enabled |

---

### `[reverse_proxy]` — Proxy / Load Balancer

| Setting | Type | Default | Risk | When to Configure |
|---------|------|---------|------|-------------------|
| `enabled` | bool | `false` | **MEDIUM** — wrong IP if misconfigured | **Required** if behind Cloudflare, nginx, ALB, etc. |
| `header` | string | `X-Forwarded-For` | — | Match your proxy's header |
| `addresses[]` | CIDR[] | `[]` | **HIGH** — spoofing if wrong | **Must** list all proxy IP ranges (Cloudflare, AWS ALB, etc.) |

> ⚠️ **Never enable `enabled=true` without `addresses[]`** — allows IP spoofing.

**Cloudflare IPs** (add to `addresses[]`):
```ini
addresses[] = "173.245.48.0/20"
addresses[] = "103.21.244.0/22"
addresses[] = "103.22.200.0/22"
addresses[] = "103.31.4.0/22"
addresses[] = "141.101.64.0/18"
addresses[] = "108.162.192.0/18"
addresses[] = "190.93.240.0/20"
addresses[] = "188.114.96.0/20"
addresses[] = "197.234.240.0/22"
addresses[] = "198.41.128.0/17"
addresses[] = "162.158.0.0/15"
addresses[] = "104.16.0.0/13"
addresses[] = "104.24.0.0/14"
addresses[] = "172.64.0.0/13"
addresses[] = "131.0.72.0/22"
```

---

### `[ai_crawlers]` — AI Crawler Management

| Setting | Type | Default | Risk | When to Change |
|---------|------|---------|------|----------------|
| `allowed[]` | string[] | `GPTBot, ClaudeBot, Google-Extended, PerplexityBot, GrokBot, MistralBot` | **LOW** | Add/remove based on your `robots.txt` policy |
| `block_unverified_ai` | bool | `true` | **LOW** | Keep `true` — blocks spoofed AI bots |
| `strict_ai` | bool | `false` | **MEDIUM** — blocks even verified unallowed AI | Only if you want **zero** AI crawlers |

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

### `[bot_categories]` — Category Blocking

| Setting | Type | Default | Risk | Notes |
|---------|------|---------|------|-------|
| `blocked[]` | string[] | `["malicious"]` | **MEDIUM** | Categories: `search_engine`, `ai_crawler`, `social_crawler`, `seo_crawler`, `archive_crawler`, `monitoring`, `malicious`, `unknown` |

> Only `malicious` blocked by default. Adding `seo_crawler` blocks Ahrefs, Semrush, MJ12bot, etc.

---

### `[rate_limits]` — Rate Limiting

| Setting | Type | Default | Risk | Tuning |
|---------|------|---------|------|--------|
| `enabled` | bool | `true` | **LOW** | Keep enabled |
| `global.requests` | int | `1000` | **LOW** | Per IP per `global_window` |
| `global.window` | int | `3600` | — | Seconds (1 hour) |
| `per_minute.requests` | int | `60` | **LOW** | Burst protection |
| `per_minute.window` | int | `60` | — | Seconds |
| `post.requests` | int | `30` | **LOW** | Form spam protection |
| `post.window` | int | `3600` | — | Seconds (1 hour) |
| `login.requests` | int | `10` | **LOW** | Brute force protection |
| `login.window` | int | `900` | — | Seconds (15 min) |

**Login endpoint detection**: Automatically triggers on URLs matching `/(login|signin|auth|password)/i`.

---

### `[body_scan]` — Form Body Scanning (NEW in 3.0)

Prevents false positives on legitimate code snippets in comments/articles.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `body_scan_skip_fields[]` | string[] | See below | Field names to **skip** SQL/XSS scanning |

**Default allowlist** (configured in `BlacklistDetector.php` + config):
```ini
body_scan_skip_fields[] = "body"
body_scan_skip_fields[] = "comment"
body_scan_skip_fields[] = "content"
body_scan_skip_fields[] = "text"
body_scan_skip_fields[] = "message"
body_scan_skip_fields[] = "description"
body_scan_skip_fields[] = "code"
body_scan_skip_fields[] = "source"
body_scan_skip_fields[] = "snippet"
body_scan_skip_fields[] = "markdown"
body_scan_skip_fields[] = "html"
body_scan_skip_fields[] = "wiki"
body_scan_skip_fields[] = "post"
body_scan_skip_fields[] = "article"
body_scan_skip_fields[] = "page"
body_scan_skip_fields[] = "entry"
body_scan_skip_fields[] = "reply"
body_scan_skip_fields[] = "review"
body_scan_skip_fields[] = "feedback"
body_scan_skip_fields[] = "bio"
body_scan_skip_fields[] = "about"
body_scan_skip_fields[] = "summary"
body_scan_skip_fields[] = "details"
body_scan_skip_fields[] = "notes"
body_scan_skip_fields[] = "instructions"
body_scan_skip_fields[] = "readme"
body_scan_skip_fields[] = "changelog"
body_scan_skip_fields[] = "documentation"
body_scan_skip_fields[] = "docs"
body_scan_skip_fields[] = "example"
body_scan_skip_fields[] = "template"
body_scan_skip_fields[] = "script"
body_scan_skip_fields[] = "query"
body_scan_skip_fields[] = "sql"
body_scan_skip_fields[] = "php"
body_scan_skip_fields[] = "js"
body_scan_skip_fields[] = "css"
```

**Heuristics also skip** fields ending with `_body`, `_content`, `_text`, `_html`, `_markdown`, `_wiki` or containing `comment`, `description`, `code`, `source`, etc.

**Parameter fields are NEVER skipped**: `search`, `query`, `filter`, `username`, `password`, `email`, `redirect`, `action`, `url`, `file`, `id`, `token`, etc.

---

### `[challenge]` — Challenge System

| Setting | Type | Default | Risk | Providers |
|---------|------|---------|------|-----------|
| `enabled` | bool | `false` | **MEDIUM** — UX friction | `builtin`, `hcaptcha`, `recaptcha`, `turnstile` |
| `provider` | string | `builtin` | — | `builtin` = PoW (no external deps) |
| `site_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `secret_key` | string | `""` | — | Required for hCaptcha/reCAPTCHA/Turnstile |
| `recaptcha_min_score` | float | `0.5` | — | reCAPTCHA v3 only (0.0–1.0) |

> **Builtin PoW** works everywhere, no keys needed. Use for internal/admin areas.

---

### `[performance]` — Static Asset Skipping

| Setting | Type | Default | Notes |
|---------|------|---------|-------|
| `skip_extensions[]` | string[] | `css, js, png, jpg, jpeg, gif, ico, svg, woff, woff2, ttf, eot, webp, avif, map, txt` | Never inspect these |
| `skip_paths[]` | string[] | `/static/, /assets/, /media/, /images/, /css/, /js/, /fonts/, /dist/, /build/, /vendor/, /node_modules/` | Prefix match |

---

### `[httpbl]` — Project Honey Pot

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `httpbl_key` | string | `""` | API key from Project Honey Pot |
| `httpbl_threat` | int | `25` | Threat score threshold (0-255) |
| `httpbl_maxage` | int | `30` | Max days since last activity |

---

### `[dnsbl]` — Additional DNSBL Lists

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `dnsbl_lists[]` | string[] | `zen.spamhaus.org, bl.spamcop.net` | Additional DNSBL lists |

---

### `[fingerprints]` — Known Bad Fingerprints (opt-in)

```ini
[fingerprints]
bad_ja3[] = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
bad_h2[] = "a1b2c3d4e5f67890"
bot_header_orders[] = "a1b2c3d4e5f67890"
```

---

### `[geoip]` — GeoIP / ASN Blocking

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `geoip_enabled` | bool | `false` | Enable GeoIP lookups |
| `geoip_database_path` | string | `""` | Path to MaxMind DB |
| `blocked_countries[]` | string[] | `[]` | ISO country codes to block |
| `blocked_asns[]` | string[] | `[]` | ASN numbers to block |

---

### `[custom_rules]` — Custom Rules

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
| `block_unverified_ai` | 🟢 LOW | `true` | Keep enabled |
| `strict_ai` | 🟡 MEDIUM | `false` | Zero AI policy |
| `enable_behavioral_analysis` | 🟢 LOW | `true` | Keep enabled |
| `enable_ai_crawler_control` | 🟢 LOW | `true` | Keep enabled |
| `reverse_proxy.enabled` | 🟡 MEDIUM | `false` | Behind proxy + addresses[] |

---

## Migration from 2.x

| 2.x Setting | 3.0 Equivalent |
|-------------|----------------|
| `strict` | `strict` |
| `verbose` | `verbose` |
| `logging` | `logging` |
| `offsite_forms` | `offsite_forms` |
| `httpbl_key` | `[httpbl] httpbl_key` |
| `httpbl_threat` | `[httpbl] httpbl_threat` |
| `httpbl_maxage` | `[httpbl] httpbl_maxage` |
| `reverse_proxy` | `[reverse_proxy] enabled` |
| `reverse_proxy_header` | `[reverse_proxy] header` |
| `reverse_proxy_addresses` | `[reverse_proxy] addresses[]` |
| `display_stats` | Admin panel (TBD) |

---

## Example: Production Wiki (WackoWiki)

```ini
; config/bb_settings.conf

[core]
logging = true
verbose = false
strict = false
offsite_forms = false
enable_fingerprinting = false
inspect_json_body = false
inspect_multipart_body = false
enable_behavioral_analysis = true
enable_ai_crawler_control = true

[reverse_proxy]
enabled = true
header = "CF-Connecting-IP"
addresses[] = "173.245.48.0/20"
addresses[] = "103.21.244.0/22"
; ... all Cloudflare ranges

[ai_crawlers]
allowed[] = "GPTBot"
allowed[] = "ClaudeBot"
allowed[] = "Google-Extended"
allowed[] = "PerplexityBot"
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

[body_scan]
; Already defaults to skip body, comment, content, code, markdown, etc.
; Add custom fields if needed:
; body_scan_skip_fields[] = "custom_field_name"

[performance]
skip_extensions[] = "css"
skip_extensions[] = "js"
; ... (defaults fine)
```

---

## Testing Configuration Changes

```bash
# 1. Validate INI syntax
php -r "var_dump(parse_ini_file('config/bb_settings.conf', true));"

# 2. Test specific endpoint (comment with code)
curl -X POST https://yourwiki/test/BBEvaluation/_addcomment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'body=Here is code: document.write("test"); union select 1'

# 3. Check logs / cache
ls -la /var/cache/wackowiki/badbehaviour/
tail -f /var/log/wackowiki/bad_behaviour.log  # or your DB table

# 4. Verify rate limits (should 429 after 60)
for i in {1..65}; do curl -s -o /dev/null -w "%{http_code}\n" /; done | sort | uniq -c
```

---

## Files to Distribute

| File | Purpose |
|------|---------|
| `settings.ini.example` | Full commented example |
| `bb_whitelist.conf.example` | Whitelist template |
| `CONFIGURATION.md` | This document |
| `MIGRATION.md` | 2.x → 3.0 guide |

---

This reference gives admins **exactly what they need**: risk level, when to enable, and what breaks if misconfigured.