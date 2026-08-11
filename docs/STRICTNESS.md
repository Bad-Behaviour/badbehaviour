# Strictness Levels

How Bad Behaviour chooses what to block, what to log, and what to allow. The `strictness` config key selects one of three modes that determine the library's overall posture: `monitor-only`, `normal`, or `strict`.

---

## Table of Contents

1. [Overview](#1-overview)
2. [The three levels at a glance](#2-the-three-levels-at-a-glance)
3. [Monitor-only mode (the safe default)](#3-monitor-only-mode-the-safe-default)
4. [Normal mode (production baseline)](#4-normal-mode-production-baseline)
5. [Strict mode (maximum defense)](#5-strict-mode-maximum-defense)
6. [Per-feature matrix](#6-per-feature-matrix)
7. [The demotion logic (how monitor-only works)](#7-the-demotion-logic-how-monitor-only-works)
8. [Reading the log in monitor-only mode](#8-reading-the-log-in-monitor-only-mode)
9. [Choosing a level for your deployment](#9-choosing-a-level-for-your-deployment)
10. [Migration paths between levels](#10-migration-paths-between-levels)
11. [Footnotes](#11-footnotes)

---

## 1. Overview

`strictness` is the single most important config key. It selects a baseline posture; everything else in `bb_config.php` either uses that baseline or overrides it on a per-feature basis.

```php
return [
    'strictness' => 'monitor-only',  // or 'normal' or 'strict'
];
```

Three levels, increasing in aggressiveness:

| Level | Posture | Best for |
|---|---|---|
| **`monitor-only`** | Log everything, block nothing ambiguous | First 1-2 weeks of deployment, sites where blocking real users is worse than letting bots through |
| **`normal`** *(default)* | Block obvious attacks + unverified spoofers, log experimental detections | Production baseline for most sites |
| **`strict`** | Block everything suspicious, enable PTR spoof detection, tighter rate limits | When actively under attack (spam flood, credential stuffing, scraping) |

Each level sets a coordinated set of feature flags. You can override any individual feature in your `bb_config.php` — the merge order is:

```
defaults (Configuration::get_defaults)
    ↓
strictness overrides (Configuration::strictness_overrides)
    ↓
your config  ← ALWAYS WINS
```

So `strictness: 'normal'` + `'block_unverified_ai' => true` enables aggressive AI blocking at the normal level (strict would have it on by default; you can opt into it earlier). Conversely, `strictness: 'strict'` + `'rate_limit_enabled' => false` disables rate limits even at strict (you'd only do this during a DNS outage or rate-limit-induced incident).

---

## 2. The three levels at a glance

### Monitor-only

- **Blocks**: empty User-Agent, raw unencoded `<script>` / `javascript:` in URI. Nothing else.
- **Logs as `enforced`**: only those two exceptions above (~5-20/day for a typical site)
- **Logs as `monitored`**: everything else that would have blocked at `normal`/`strict` (~50-5000/day)
- **Logs as `allowed`**: nothing (unless `verbose: true`)
- **False-positive risk**: effectively zero. The only enforced blocks are technical anomalies that no legitimate browser/app produces.
- **Performance impact**: minimal. Most experimental detectors are OFF.

### Normal

- **Blocks**: everything monitor-only blocks + rate limits + verified-spoofer blocks (DNS verification catches them)
- **Logs as `enforced`**: blocked requests (hundreds/day for typical sites)
- **Logs as `monitored`**: experimental detectors that would have triggered at `strict` but are OFF at `normal`
- **Logs as `allowed`**: nothing (unless `verbose: true`)
- **False-positive risk**: low. Search engines and AI crawlers may take 1-2 visits to verify (DNS verification has first-request latency ~40-300ms).
- **Performance impact**: moderate. DNS verification adds synchronous PTR lookups on cache misses.

### Strict

- **Blocks**: everything normal blocks + behavioral anomalies (UA rotation, botnet patterns) + fingerprinting hits + forward-confirmed DNS (catches PTR spoofers) + tighter rate limits (500/hr, 30/min)
- **Logs as `enforced`**: most detected threats (hundreds-thousands/day depending on traffic)
- **Logs as `monitored`**: only the rare cases where even strict demotes (none currently — strict never demotes)
- **False-positive risk**: moderate. Behavioral and fingerprinting detectors have known FP patterns (shared NAT IPs, corporate proxies, headless browsers used legitimately for testing).
- **Performance impact**: high. All detectors running, forward-confirm DNS adds ~100ms latency on first request per IP, tighter rate limits mean more 429s.

---

## 3. Monitor-only mode (the safe default)

Monitor-only is the **first-class safety mode** of Bad Behaviour. It's not a debug option or a "log only" afterthought — it's designed for permanent deployment on sites where blocking real users is unacceptable (e-commerce checkout, public services, anything where a false-positive costs money or trust).

### What monitor-only does

1. **All detectors run** and produce their normal `Result` (blocked, challenged, allowed).
2. After detection, `maybe_demote_to_monitored()` runs and converts would-be blocks into `monitored` results.
3. The result is logged with `enforcement_action = 'monitored'`, `status_code = 'monitored.X'`, and `original_code = 'blocked.X'` (the code that WOULD have applied).
4. The host application continues normally — no 403, no CAPTCHA, no block page.
5. **Two exceptions** are still enforced: empty UA and raw unencoded XSS (see [§7 The demotion logic](#7-the-demotion-logic-how-monitor-only-works)).

### Why it's safe

| Concern | How monitor-only addresses it |
|---|---|
| "Will I break real users?" | No. Only technical anomalies are blocked; everything else passes through. |
| "Will I lose search engine indexing?" | No. Google/Bing/etc. are logged but not blocked. |
| "Will I break mobile apps?" | No. Mobile API clients are logged but not blocked. |
| "Will I break my CDN health probes?" | No. Cloud-infrastructure category is hard-coded to ALLOW (cannot be overridden). |
| "Will I block legitimate AI crawlers (ChatGPT browsing, etc.)?" | No. They are logged but not blocked. |
| "How do I know what would have blocked?" | `WHERE enforcement_action = 'monitored'` — queryable in SQL. |

### When to use monitor-only

- **First 1-2 weeks after installing Bad Behaviour** — observe, don't enforce. Build confidence in your traffic patterns.
- **Production sites with high FP cost** — e-commerce checkout, medical/legal portals, anything where a blocked user is a lost customer.
- **Sites you don't own the policy for** — managed hosting where the customer decides whether to enforce.
- **Permanent mode if you can't risk enforcement** — some operators run monitor-only indefinitely because the log analytics provide more value than the actual blocking.

### What monitor-only does NOT do

- It does not protect against active exploitation beyond empty-UA and raw-XSS.
- It does not stop volumetric abuse (no rate limits).
- It does not block credential stuffing (no DNSBL / http:BL by default — though you can enable them).
- It does not catch PTR spoofers (DNS verification is OFF).

If you observe abuse in monitor-only logs, the path forward is to either:

1. **Target the abuse specifically** via `custom_rules` (block the specific IP/UA/country/header without affecting anyone else).
2. **Promote to `normal`** to enable DNS verification + rate limits.
3. **Stay at monitor-only + `bot_categories`** to override specific categories.

### Recommended monitoring-only → normal migration

1. Run monitor-only + `verbose: true` for 7-14 days
2. Query the `monitored` results — what would have blocked?
3. Identify false-positive candidates (Googlebot, legitimate mobile app UAs, etc.)
4. Add `bot_categories.allowed[]` overrides to whitelist them at any future strictness level
5. Switch to `strictness: 'normal'`
6. Monitor `enforced` rows for 3-7 days
7. If FP rate is acceptable, optionally add experimental detectors (`enable_behavioral_analysis`, etc.)

---

## 4. Normal mode (production baseline)

`normal` is the default strictness level and the recommended production posture for most sites.

### What normal enables

Everything that's safe to enforce without tuning:

| Feature | Why it's safe |
|---|---|
| `dns_verification_enabled` | Catches fake Google/Bing/etc. bots whose IP doesn't resolve to the expected hostname. Caches positive results for 7 days. |
| `dynamic_ip_ranges_enabled` | Keeps CDN/cloud IP ranges fresh. Prevents you from blocking CDN edge nodes that proxy legitimate traffic. |
| `rate_limit_enabled` | Conservative thresholds (1000/hr, 60/min per IP). Shared NAT IPs aren't typically exceeded. |
| `ai_crawlers.block_unverified = false` | Unverified AI bots are CHALLENGED (CAPTCHA), not blocked. They can self-verify or solve the CAPTCHA. |
| `strict_search_engines = false` | Verified search engines are allowed even with imperfect IP coverage. |

### What normal does NOT enable (FP risk)

| Feature | Why it's off |
|---|---|
| `enable_fingerprinting` | JA3 blacklisting has high FP risk; would lock out specific TLS library versions |
| `enable_behavioral_analysis` | Botnet patterns can be confused with shared NAT traffic |
| `enable_client_hints_validation` | Only works for Chrome/Edge/Chromium browsers; flags all Firefox/Safari users |
| `enable_agentic_detection` | Experimental; false positives with single-page apps and screen readers |
| `enable_head_request_detection` | Legitimate monitoring (UptimeRobot, Pingdom, link checkers) sends HEAD |
| `enable_asset_scraping_detection` | Image proxies, link previewers, RSS readers fetch assets directly |
| `dns_verification_require_forward_confirm` | HIGH IPv6 FP risk; many IPv6 setups have inconsistent forward/reverse DNS |
| `dnsbl_enabled` | DNSBLs flag residential IPs (correct for email, wrong for web) |
| `block_unverified_ai` | Regional / academic AI crawlers often have unresolvable DNS initially |
| `strict_search_engines` | Search engines occasionally change IP ranges before the static list is updated |

### What normal logs

- **`enforced`** — actual blocks (rate limit hits, unverified spoofer blocks)
- **`monitored`** — experimental detector hits that are OFF at normal (none at normal currently — see `bot_categories` for an alternative)
- **`allowed`** — nothing unless `verbose: true`

To see what the experimental detectors would have caught at strict, see [`§10 Migration paths`](#10-migration-paths-between-levels).

### When to use normal

- **Production deployment** after you've finished the monitor-only observation phase
- **Public sites** with moderate abuse traffic (comment spam, scraping, credential stuffing attempts)
- **Sites that want DNS verification** (catches fake search engine bots) but not behavioral/fingerprinting

### What changes from monitor-only → normal

| Behavior | monitor-only | normal |
|---|---|---|
| Empty UA | 403 (enforced) | 403 (enforced) — unchanged |
| Raw XSS in URI | 403 (enforced) | 403 (enforced) — unchanged |
| DNS-verified bot with no DNS match (spoof) | logged only | **403 (enforced)** ← new |
| Rate limit exceeded | logged only | **403 (enforced)** ← new |
| Unverified AI crawler | logged only | CAPTCHA (enforced challenge) ← new |
| Behavior anomaly (rotating UA) | logged only | logged only |
| JA3 hit | logged only | logged only |

The two rightmost columns (behavior, JA3) are still only logged at normal — they'd only enforce at `strict`.

---

## 5. Strict mode (maximum defense)

`strict` enables everything. Use only when actively under attack.

### What strict enables on top of normal

| Feature | Purpose | FP risk |
|---|---|---|
| `dns_verification_require_forward_confirm` | Catches PTR spoofers (attacker sets PTR to `*.googlebot.com` but A record doesn't match) | HIGH on IPv6 — many legit bots have inconsistent forward/reverse DNS |
| `enable_fingerprinting` | Blocks known-bad JA3 / HTTP2 / header-order fingerprints | HIGH — blacklisting a JA3 locks out an entire TLS version |
| `enable_behavioral_analysis` | Detects rotating UAs, IP rotation, rapid requests, missing browser headers | HIGH — shared NAT IPs (corporate, mobile carriers, VPNs) trigger this |
| `enable_client_hints_validation` | Cross-validates Chrome's `Sec-CH-UA` headers against claimed browser | MODERATE — only Chromium browsers; false-positive on Firefox/Safari/etc. |
| `enable_agentic_detection` | Detects AI agent patterns (think-then-fetch, non-linear navigation) | MODERATE — single-page apps fetch assets in bursts; screen readers behave non-linearly |
| `enable_head_request_detection` | Blocks HEAD flooding / enumeration | MODERATE — monitoring tools (UptimeRobot, Pingdom, StatusCake, Lighthouse) legitimately use HEAD |
| `enable_asset_scraping_detection` | Blocks direct asset scraping without page loads | MODERATE — link previewers (Slack, Twitter), image proxies, PDF viewers |
| Tighter rate limits | 500/hr, 30/min per IP | HIGH — same NAT concerns as normal |
| `dnsbl_enabled` | Spamhaus, Spamcop lookups | MODERATE — DNSBLs flag residential IPs |
| `block_unverified_ai` | Block AI crawlers that can't pass DNS verification | HIGH on first visit for regional/academic AI bots |
| `strict_search_engines` | Search engines without DNS verification get blocked | HIGH — search engines occasionally change IP ranges; drop from search results until refresh |

### When to use strict

- **Active attack in progress** — spam flood, credential stuffing, content scraping at scale
- **Short-term deployment** (1-4 weeks) — enable strict, evaluate FP rate, disable if unacceptable
- **Always-on** for high-value targets (financial, government, healthcare) where the abuse volume justifies the FP cost

### What strict does NOT do

Even at strict, certain things remain logged-only (not enforced) because no detector has both low FP and high detection confidence:

- A single suspicious UA (vs a confirmed bot pattern)
- A single missing header (vs confirmed header-order anomaly)
- A single rate limit hit on the global bucket (vs confirmed burst)
- Slow-burn scraping (within rate limits)

To catch these, add `custom_rules` with specific IP/UA/header patterns.

### What changes from normal → strict

| Behavior | normal | strict |
|---|---|---|
| Unverified search engine bot | logged only | **403 (enforced)** |
| AI crawler without DNS verification | CAPTCHA | **403 (enforced)** |
| Forward-DNS mismatch (PTR spoofer) | allowed | **403 (enforced)** |
| Rotating UA in same session | logged only | **403 (enforced)** |
| Missing required browser header (Accept, etc.) | logged only | **403 (enforced)** |
| JA3 in `bad_ja3` list | logged only | **403 (enforced)** |
| Rate limit hit | 1000/hr, 60/min thresholds | 500/hr, 30/min thresholds |
| HEAD without Referer (non-API path) | logged only | **403 (enforced)** |
| Asset request without Referer | logged only | **403 (enforced)** (after threshold) |

---

## 6. Per-feature matrix

| Feature | monitor-only | normal | strict |
|---|---|---|---|
| **`logging`** | true (recommended) | true | true |
| **`verbose`** | true (recommended) | false (recommended) | false |
| `dns_verification_enabled` | OFF | **ON** | ON |
| `dns_verification_require_forward_confirm` | OFF | OFF | **ON** |
| `dns_verification_positive_ttl` | 7 days | 7 days | **30 days** |
| `dns_verification_negative_ttl` | 1 hour | 1 hour | **1 day** |
| `dynamic_ip_ranges_enabled` | OFF | **ON** | ON |
| `rate_limit_enabled` | OFF | **ON** | ON |
| `rate_limits.global` | (none) | 1000/hr | **500/hr** |
| `rate_limits.per_minute` | (none) | 60/min | **30/min** |
| `enable_fingerprinting` | OFF | OFF | **ON** |
| `enable_behavioral_analysis` | OFF | OFF | **ON** |
| `enable_client_hints_validation` | OFF | OFF | **ON** |
| `enable_agentic_detection` | OFF | OFF | **ON** |
| `enable_head_request_detection` | OFF | OFF | **ON** |
| `head_require_referer` | OFF | OFF | **ON** |
| `enable_asset_scraping_detection` | OFF | OFF | **ON** |
| `dnsbl_enabled` | OFF | OFF | **ON** |
| `block_unverified_ai` | OFF | OFF | **ON** |
| `strict_search_engines` | OFF | OFF | **ON** |

**Bold** = the value changes from the previous level.

User config always overrides these defaults. To opt into a strict feature at normal strictness:

```php
return [
    'strictness' => 'normal',
    'enable_behavioral_analysis' => true,   // opt in
];
```

To opt out of a strict feature at strict strictness:

```php
return [
    'strictness' => 'strict',
    'enable_fingerprinting' => false,      // opt out (FP risk too high)
];
```

---

## 7. The demotion logic (how monitor-only works)

The demotion step runs after detection and before logging. It converts would-be blocks into monitored results:

```php
// src/Core/BadBehaviour.php
private function maybe_demote_to_monitored(Result $result): Result
{
    if ($result->code === ResultCode::ALLOWED) {
        return $result;
    }

    if (!$this->is_monitor_only_effective()) {
        return $result;
    }

    // === Exception 1: Empty/invalid UA — ALWAYS enforced ===
    if ($result->code === ResultCode::BLOCKED_MALICIOUS_UA
        && $result->message === 'Empty or invalid User-Agent') {
        return $result;
    }

    // === Exception 2: Raw unencoded attack payload in URI — ALWAYS enforced ===
    if (isset($result->metadata['tier']) && $result->metadata['tier'] === 'raw_uri') {
        return $result;
    }

    // === Everything else: demote to monitored ===
    return Result::monitored_from($result);
}
```

### Why these two exceptions

The "obvious attack" exceptions are technical anomalies that no legitimate browser, mobile app, or HTTP client produces:

1. **Empty User-Agent** (< 5 chars): HTTP/1.1 requires UA per RFC 7231. Real browsers, mobile apps, HTTP libraries all send some UA. A missing/empty UA is either:
   - An attacker (script kiddies, scanners, custom exploits)
   - A misconfigured client (broken library, custom proxy stripping headers)

   Either way, refusing the request costs nothing — the request would fail at the application layer anyway.

2. **Raw unencoded `<script>` / `javascript:` in URI**: Browsers always percent-encode URI components per RFC 3986. A raw `<script>` in the URI is either:
   - An attacker (XSS attempt, scanner testing)
   - A non-browser client (manual cURL, modified proxy, custom script)

   Legitimate browser requests never produce this.

These two exceptions are **never** demoted — even monitor-only blocks them. Everything else (bots, rate limits, behavioral, fingerprinting) is demoted to monitored.

### Where the demotion step runs

In the request pipeline:

```
1. Build RequestPackage (parse headers, UA, IP)
2. FAST PATH: Empty UA → enforced block (returns here)
3. FAST PATH: Whitelisted IP → enforced allow (returns here)
4. Enrichment (GeoIP, fingerprints)
5. Detection pipeline (BotDetector, BlacklistDetector, etc.)
6. >>> maybe_demote_to_monitored() runs HERE <<<
7. log_and_return()
8. Return Result to caller
```

Step 2 (empty UA) happens BEFORE the demotion step — it's a fast-path early return that bypasses the entire detection pipeline. That's why empty-UA blocks don't go through demotion logic; they're enforced directly.

### Demoted results carry full context

When a result is demoted, the new `monitored` result preserves:

- All metadata from the original `blocked` result (bot_id, bot_name, matched patterns, etc.)
- `metadata['original_code']` — the blocked.X code that WOULD have applied
- `metadata['monitor_only'] = true` — flag for downstream consumers

Example:

```php
// Original (would-have-blocked) result:
Result(
    code: BLOCKED_BOT,
    message: "Bot blocked: Baiduspider",
    metadata: ['bot_id' => 'baidu', 'bot_name' => 'Baiduspider', ...]
)

// After demotion:
Result(
    code: MONITORED_BOT,
    message: "Bot blocked: Baiduspider",
    metadata: [
        'bot_id' => 'baidu',
        'bot_name' => 'Baiduspider',
        'original_code' => 'blocked.bot',
        'monitor_only' => true,
        ...
    ],
    enforcement: MONITORED
)
```

Both the `status_code` and `original_code` columns end up in the log row, so you can see both what the library decided to do (`monitored.bot`) and what it would have done (`blocked.bot`).

---

## 8. Reading the log in monitor-only mode

Every log row in the `bad_behaviour` table carries two key columns:

| Column | Meaning |
|---|---|
| `enforcement_action` | What was actually done to the request: `enforced` / `monitored` / `allowed` |
| `status_code` | What the detector wanted to do: `allowed` / `blocked.X` / `monitored.X` / `challenge.X` |

The combination tells the whole story:

| `enforcement_action` | `status_code` prefix | Meaning |
|---|---|---|
| `allowed` | `allowed` | Detector saw nothing wrong. Request served normally. |
| `monitored` | `monitored.*` | Detector wanted to block; we logged it but **didn't** enforce. Request served normally. |
| `enforced` | `blocked.*` | Detector wanted to block; we **did** enforce it (403 served). Request blocked. |
| `enforced` | `challenge.*` | Detector wanted to challenge; we **did** serve the challenge. Request challenged. |
| `enforced` | `monitored.*` | Should not happen — `monitored.*` codes never reach `enforced` enforcement. |

### What you'll see in monitor-only

After running for a week with default config:

```sql
SELECT enforcement_action, status_code, COUNT(*) AS n
FROM bad_behaviour
WHERE date >= NOW() - INTERVAL 7 DAY
GROUP BY enforcement_action, status_code
ORDER BY n DESC;
```

Typical output:

```
enforced   blocked.malicious_ua    42      ← empty UA, every day
enforced   blocked.attack_pattern  18      ← raw XSS in URI, every day
monitored  monitored.bot           1847    ← Google/Bing/etc. + would-be-blocked bots
monitored  monitored.malicious_ua  312     ← bot-like UAs (UA regex matched)
monitored  monitored.attack_pattern 47     ← encoded attack patterns
```

The `enforced` count stays low (just empty UA + raw XSS). The `monitored` count tells you "this is what would have blocked at normal strictness."

### Verification: is monitor-only actually working?

Run this query after a week of monitor-only operation:

```sql
SELECT
    enforcement_action,
    COUNT(*) AS n,
    ROUND(AVG(TIMESTAMPDIFF(HOUR, date, NOW())), 0) AS avg_age_hours
FROM bad_behaviour
WHERE date >= NOW() - INTERVAL 7 DAY
GROUP BY enforcement_action;
```

**Expected**:

```
enforced   |  ~5-20      ← only empty UA + raw XSS exceptions
monitored  |  hundreds-thousands  ← would-have-blocked at normal/strict
allowed    |  0           ← verbose=false skips these
```

**Red flags**:

- `enforced` count is much higher than ~20/day → something's bypassing the demotion step. Check `bot_categories` overrides and `custom_rules`.
- `monitored` count is zero → no detections happening. Check `bot` detector is active (`diagnostics()['detectors_active']['bot'] === true`).
- `allowed` count is high → you have `verbose: true` and you're logging everything. That's expected, just generates more data.

### Top offenders (IPs)

```sql
SELECT ip, COUNT(*) AS hits, MIN(date) AS first_seen, MAX(date) AS last_seen
FROM bad_behaviour
WHERE enforcement_action = 'monitored'
  AND date >= NOW() - INTERVAL 7 DAY
GROUP BY ip
ORDER BY hits DESC
LIMIT 20;
```

For each top offender, you can drill down:

```sql
SELECT date, status_code, original_code, status_message, user_agent
FROM bad_behaviour
WHERE ip = '203.0.113.42'
  AND date >= NOW() - INTERVAL 7 DAY
ORDER BY date DESC;
```

### False positive candidates

The scariest monitor-only output is "would have blocked a legitimate request." Detect these:

```sql
-- Search engines flagged as monitored (should not happen if bot_categories.allowed includes search_engine)
SELECT ip, user_agent, status_code, COUNT(*) AS n
FROM bad_behaviour
WHERE enforcement_action = 'monitored'
  AND user_agent REGEXP 'Googlebot|Bingbot|YandexBot|DuckDuckBot|Baiduspider'
GROUP BY ip, user_agent, status_code
ORDER BY n DESC;

-- Browser UAs flagged as monitored (suggests a false positive in your config)
SELECT ip, user_agent, status_code, COUNT(*) AS n
FROM bad_behaviour
WHERE enforcement_action = 'monitored'
  AND user_agent REGEXP 'Mozilla|Chrome|Safari|Firefox|Edge'
GROUP BY ip, user_agent, status_code
ORDER BY n DESC;

-- Mobile app UAs flagged as monitored
SELECT ip, user_agent, status_code, COUNT(*) AS n
FROM bad_behaviour
WHERE enforcement_action = 'monitored'
  AND user_agent REGEXP 'iOS|Android|okhttp|api.client|MyApp'
GROUP BY ip, user_agent, status_code
ORDER BY n DESC;
```

If you find legitimate-looking UAs in the `monitored` set, that's an FP and you should:

1. **For bots you want to whitelist** — add the bot's category to `bot_categories.allowed[]`
2. **For specific IPs** — add to `custom_rules` with `action: 'allow'`
3. **For specific UA patterns** — add a `ua_contains` or `ua_regex` rule to `custom_rules`

### What would have been blocked at normal strictness?

If you're running monitor-only and considering switching to `normal`:

```sql
-- All monitor-only rows from the last 7 days
SELECT status_code, COUNT(*) AS n
FROM bad_behaviour
WHERE enforcement_action = 'monitored'
  AND date >= NOW() - INTERVAL 7 DAY
GROUP BY status_code
ORDER BY n DESC;

-- Likely output:
-- monitored.bot              1847   ← would block at normal
-- monitored.malicious_ua     312    ← would block at normal
-- monitored.attack_pattern    47     ← would block at normal
```

Sum the counts: that's approximately how many requests per week would have been blocked at `normal`. If that number is acceptable for your use case, switch to `normal`.

### What would have been blocked at strict strictness?

If you're running monitor-only or normal and considering strict:

Monitor-only doesn't enable the strict-only detectors (`behavioral`, `fingerprinting`, etc.), so you'd need to enable them one at a time at your current strictness level to preview:

```php
return [
    'strictness' => 'monitor-only',
    'enable_behavioral_analysis' => true,
    'enable_fingerprinting' => true,
    'enable_client_hints_validation' => true,
    // ... etc.
];
```

After a week, check `enforcement_action = 'monitored'` for the experimental detector hits. Sum them — that's what strict would enforce.

---

## 9. Choosing a level for your deployment

### Decision tree

```
Are you deploying BadBehaviour for the first time?
├── YES → monitor-only + verbose: true  (1-2 weeks of observation)
│
└── NO — what tolerance do you have for false positives?
    │
    ├── ZERO tolerance (e-commerce, public services, medical)
    │   → monitor-only  +  custom_rules for specific abuse
    │
    ├── LOW tolerance (most content sites)
    │   → normal  +  bot_categories.allowed for known-good
    │   → switch to strict only during attacks
    │
    └── MODERATE tolerance (forums, UGC sites, sites already dealing with spam)
        → strict  +  review FP rate after 1-2 weeks
```

### Per-site-type recommendations

| Site type | Recommended strictness | Why |
|---|---|---|
| **E-commerce** | monitor-only + targeted custom_rules | Blocking real customers at checkout costs money |
| **News / publisher** | normal + `ai_crawlers.block_unverified: true` | Want to block AI training scrapers, keep search engines indexed |
| **Blog / personal site** | normal | Moderate FP tolerance, want spam blocked |
| **Forum / UGC** | strict | High abuse volume, blocking bots is more valuable than FP risk |
| **API / B2B** | strict + custom_rules | API consumers shouldn't be browser-like; tighten aggressively |
| **Government / healthcare** | strict + audit logging | Regulatory requirement to block malicious traffic |
| **Wiki (MediaWiki, WackoWiki)** | normal + `bot_categories.allowed: ['search_engine']` | Search engines are critical for visibility |
| **First deployment anywhere** | monitor-only + verbose: true | Always observe first |

### Lifetime of a deployment

Most operators follow this progression:

```
Week 1-2:    monitor-only + verbose: true
             ↓ (observe logs, identify FP candidates)
Week 3-4:    monitor-only + bot_categories.allowed: [legitimate bots]
             ↓ (FP candidates whitelisted)
Month 2:     normal + verbose: false
             ↓ (FP rate measured and acceptable)
Month 3+:    normal (steady state)
             ↑ (occasional: bump to strict during active attack, back to normal after)
```

Some operators stay at monitor-only indefinitely if their abuse profile is targeted enough that `custom_rules` covers it without needing library-wide detection.

---

## 10. Migration paths between levels

### Up: monitor-only → normal

**Pre-migration checklist**:

1. ✓ Run monitor-only + `verbose: true` for at least 7 days
2. ✓ Review `enforcement_action = 'monitored'` results for FP candidates
3. ✓ Whitelist legitimate bots via `bot_categories.allowed`
4. ✓ Whitelist legitimate IPs via `custom_rules` if needed
5. ✓ Confirm DNS resolution works for the request hosts (`nslookup crawl-X.googlebot.com`)

**The change**:

```php
// Before
'strictness' => 'monitor-only',
'verbose'    => true,

// After
'strictness' => 'normal',
'verbose'    => false,    // optional: keep verbose briefly to compare logs
```

**What changes**: Rate limits and DNS verification now enforce. Verified spoofers get 403. Expected new `enforced` count: hundreds per day for typical sites.

**Post-migration monitoring** (3-7 days):

```sql
-- FP candidates at normal: legitimate-looking UAs now blocked
SELECT ip, user_agent, status_code, COUNT(*) AS n
FROM bad_behaviour
WHERE enforcement_action = 'enforced'
  AND date >= NOW() - INTERVAL 7 DAY
  AND user_agent REGEXP 'Mozilla|Chrome|Safari|Firefox|Edge|Googlebot|Bingbot'
GROUP BY ip, user_agent, status_code
ORDER BY n DESC;
```

If you see legitimate-looking UAs in the `enforced` set, roll back to monitor-only and investigate.

### Up: normal → strict

**Pre-migration checklist**:

1. ✓ Run normal for at least 30 days
2. ✓ Confirm FP rate at normal is acceptable (<0.1% of legitimate traffic blocked)
3. ✓ Identify and whitelist any borderline cases via `custom_rules`
4. ✓ Have a rollback plan (just change `strictness` back)

**The change**:

```php
'strictness' => 'strict',
```

**What changes**: Behavioral, fingerprinting, client hints, head detection, asset scraping, DNSBL, forward-confirm DNS, tighter rate limits — all now enforce.

**Expected FP rate increase**: 0.01% – 0.1% of legitimate traffic. The biggest sources:
- Corporate networks (shared NAT IP, many UAs in same session)
- Mobile users on cell carriers (shared NAT)
- VPN exit nodes
- Headless browsers used for testing (Puppeteer, Playwright)
- Single-page apps that fetch assets in bursts (flagged by agentic detection)
- Image proxies / link previewers (flagged by asset scraping)

If FP rate is unacceptable, disable specific detectors:

```php
'strictness' => 'strict',
'enable_fingerprinting' => false,        // FP risk too high
'enable_client_hints_validation' => false, // Firefox/Safari users flagged
'enable_head_request_detection' => false,  // UptimeRobot breaks
```

### Down: any level → monitor-only

Safe and easy — just change the value:

```php
'strictness' => 'monitor-only',
```

This is what you do when:
- An incident requires you to stop blocking (DNS outage, rate limit misconfig, etc.)
- A new release needs rollout observation
- The site is under unexpected FP pressure (e.g., legitimate users got caught by a new detector)

Going down is non-destructive — your existing `custom_rules` and `bot_categories` overrides continue to work, but they're now logged instead of enforced.

### Emergency: disable everything

For a complete kill switch (don't block anything, log nothing):

```php
'strictness' => 'monitor-only',
'logging'    => false,
```

This puts the library in a no-op state. Useful during incident response when you want to remove BadBehaviour's involvement entirely.

---

## 11. Footnotes

### Note on `BlacklistDetector` and `ua_is_bot`

The `BlacklistDetector` has a `ua_is_bot` short-circuit that originally fired for any User-Agent matching `/bot|crawler|spider/i`. This was a real bug — legitimate search engines (Applebot, Baidu, Sogou) match those patterns but should be handled by `BotDetector` with per-category actions, not blocked by `BlacklistDetector`.

In monitor-only mode, the `ua_is_bot` check is **gated behind `is_monitor_only_effective()`**. The check is skipped in monitor-only because `BotDetector` runs first and handles bot classification correctly (verified search engines → ALLOW, unverified → challenge at normal strictness).

The check still runs at normal and strict strictness, but only for UAs that `BotDetector` didn't match — i.e., bots not in the shipped registry.

### Note on DNS verification latency

DNS verification is **synchronous** in the request path. First request from any bot whose IP isn't in static ranges pays 40-300ms for a PTR lookup. Subsequent requests hit the cache.

If you observe latency spikes:
- First-deploy scenario: cache is cold. Latency will improve after the first ~100 bot requests.
- After long uptime: latency should be near-zero. If not, check your DNS resolver.
- During DNS outage: latency spikes become timeouts. Use `'strictness' => 'monitor-only'` to disable verification until DNS recovers.

### Note on `bot_categories` interaction with strictness

The `bot_categories` overrides are evaluated **independently of strictness**. If you set:

```php
'strictness' => 'monitor-only',
'bot_categories' => [
    'blocked' => ['residential_proxy'],
],
```

then at any strictness level, `residential_proxy` bots will be blocked (and that block will be demoted to monitored at monitor-only strictness). The override applies before the demotion step.

The cloud-infrastructure safety override runs even earlier — `CLOUD_INFRASTRUCTURE` is hard-coded to ALLOW before any category override check. You cannot accidentally block your CDN's health probes.

### Note on `verbose: true` storage cost

`verbose: true` logs every request, not just blocked/monitored ones. For a site with 10,000 requests/day, that's roughly:

- 10,000 rows × ~500 bytes/row = 5 MB/day
- ~35 MB/week, ~150 MB/month

With `verbose: false` (default), only blocked/monitored requests are logged — typically hundreds of rows per day, ~5-10 MB/month.

Use `verbose: true` for the first 1-2 weeks. Switch to `false` once you've validated your traffic patterns.

### Note on "obvious attack" detection reliability

The empty-UA and raw-XSS detection patterns are the most reliable detections in the library. The false-positive rate is structurally zero because:

- **Empty UA**: Real browsers, mobile apps, and HTTP libraries all send some User-Agent per HTTP/1.1 (RFC 7231). The only producers of empty UAs are attackers and broken clients. A broken client can't make a useful request anyway.

- **Raw XSS in URI**: Browsers percent-encode URI components per RFC 3986. Real browser requests never contain raw `<script>`, `javascript:`, `vbscript:`, etc. in the URI. Only manual cURL, modified proxies, and custom scripts produce these.

Both detections are kept current (not affected by UA-parser drift) and don't depend on third-party lists.

---

## See also

- [`CONFIGURATION.md`](./CONFIGURATION.md) — full config reference
- [`README.md`](./README.md) — quick start and architecture overview
- [`bin/diagnose.php`](./bin/diagnose.php) — runtime diagnostics
- [`docs/Bot-Registry.md`](./docs/Bot-Registry.md) — bot category reference
