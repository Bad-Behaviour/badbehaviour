# Bad Behaviour 3.0 — Configuration Reference

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
block_unverified_ai = true
strict_ai = false

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
```

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

---

### `[ai_crawlers]` — AI Crawler Management

| Setting | Type | Default | Risk | When to Change |
|---------|------|---------|------|----------------|
| `allowed[]` | string[] | `GPTBot, ClaudeBot, Google-Extended` | **LOW** | Add/remove based on your robots.txt policy |
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
| `global_requests` | int | `1000` | **LOW** | Per IP per `global_window` |
| `global_window` | int | `3600` | — | Seconds (1 hour) |
| `per_minute_requests` | int | `60` | **LOW** | Burst protection |
| `per_minute_window` | int | `60` | — | Seconds |
| `post_requests` | int | `30` | **LOW** | Form spam protection |
| `post_window` | int | `3600` | — | Seconds (1 hour) |
| `login_requests` | int | `10` | **LOW** | Brute force protection |
| `login_window` | int | `900` | — | Seconds (15 min) |

**Login endpoint detection**: Automatically triggers on URLs matching `/(login|signin|auth|password)/i`.

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
| `httpbl_key` | `httpbl_key` (in `[core]`) |
| `httpbl_threat` | `httpbl_threat` |
| `httpbl_maxage` | `httpbl_maxage` |
| `reverse_proxy` | `[reverse_proxy] enabled` |
| `reverse_proxy_header` | `[reverse_proxy] header` |
| `reverse_proxy_addresses` | `[reverse_proxy] addresses[]` |
| `display_stats` | Admin panel (TBD) |

---

## Example: Production Wiki (Your Case)

```ini
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

# 2. Test specific endpoint
curl -X POST https://yourwiki/src/AddComment \
  -H "Content-Type: application/json" \
  -d '{"ajax_preview":"1","body":"test"}'

# 3. Check logs
tail -f data/bad_behaviour.log  # or your DB table

# 4. Verify rate limits
for i in {1..65}; do curl -s -o /dev/null -w "%{http_code}\n" /; done | sort | uniq -c
# Should see 429 after 60/min
```

---

## Files to Distribute

| File | Purpose |
|------|---------|
| `settings.ini.example` | Full commented example |
| `whitelist.ini.example` | Whitelist template |
| `CONFIGURATION.md` | This document |
| `MIGRATION.md` | 2.x → 3.0 guide |

This reference gives admins **exactly what they need**: risk level, when to enable, and what breaks if misconfigured.