# DNS Subsystem Guide

## Overview

BadBehaviour 3.0 uses DNS at three different points in its detection pipeline. They solve different problems, have different performance profiles, and fail in different ways — but from the operator's perspective, they are **one underlying DNS infrastructure**, not three features to choose between.

```
┌──────────────────────────────────────────────────────────────────────┐
│                  Operator's view                                     │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   preset:        minimal                                             │
│   strictness:    normal                                              │
│                                                                      │
│   → DNS infrastructure picks itself: which subsystems run,           │
│     which are disabled, what cache TTLs to use.                      │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                  Implementation (hidden from operator)               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   1. Synchronous DNS verification    ← catches bot spoofers          │
│   2. Async dynamic IP range feeds    ← keeps cloud-IP list current   │
│   3. On-demand cache refresh         ← cron substitute               │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

This guide explains how the three subsystems work, how `strictness` selects among them, and what knobs exist for operators who need to override the defaults.

---

## What You Actually Control

Most operators change **one or two settings**:

```php
return [
    'preset'     => 'minimal',     // which bots to recognize
    'strictness' => 'normal',      // which DNS subsystems to enable
];
```

That's it. The DNS infrastructure (sync verification, async feeds, cache TTLs) is automatically configured based on `strictness`. The settings documented in this guide (`dns_verification.timeout_ms`, `dynamic_ip_ranges.feeds`, etc.) are **escape hatches** for the 1% of operators who need fine-grained control.

### The `strictness` Knob

The full mapping between strictness and DNS infrastructure:

| Strictness level | Sync DNS verify | Async IP ranges | Forward DNS confirm | Negative cache TTL |
|---|---|---|---|---|
| `monitor-only` | ❌ OFF | ❌ OFF | ❌ | n/a |
| `normal` (default) | ✅ ON | ✅ ON | ❌ | 1 hour |
| `strict` | ✅ ON | ✅ ON | ✅ ON (catches PTR spoofing) | 1 day |

Plus implied effects:
- `monitor-only`: no DNS lookups at all. Requests are logged but not verified against bot UAs.
- `normal`: sync DNS verification runs for bots claiming to be Google/Bing/etc. Async feed keeps Cloudflare/AWS/GCP IP ranges current. Failed DNS lookups cached for 1 hour — re-checked fast to recover from transient DNS issues.
- `strict`: same as normal, plus forward DNS confirmation (the bot's PTR record's A/AAAA must resolve back to the original IP — catches attackers who set fake PTRs). Failed lookups cached longer (1 day).

### When to Use Each Strictness

| Situation | Recommended |
|---|---|
| Evaluating the library, want to see what it logs without risking blocks | `monitor-only` |
| Most production deployments | `normal` |
| Actively seeing bot spoofing attacks (fake Googlebot, fake GPTBot) | `strict` |
| Behind a CDN that already terminates and validates DNS | `monitor-only` (you don't need double DNS) |
| Real-time API where every millisecond of TTFB matters | `monitor-only` |
| High-value target seeing scraping/spoofing attacks | `strict` |

You can set `strictness` and then **override individual DNS settings** if needed. Example: `strictness => 'normal'` with `dns_verification.require_forward_confirm => true` to enable PTR spoof detection without otherwise escalating.

---

## Subsystem 1: Synchronous DNS Verification

### What it does

When a request claims to be `Googlebot` (UA match) and the IP isn't already in static Google ranges, the library performs a reverse DNS lookup to verify the claim. If the hostname suffix matches (e.g., `crawl-X.googlebot.com`), the bot is real. Otherwise, it's a spoofer.

### How it works

```
Request arrives claiming to be Googlebot
    │
    ▼
IP in static Google CIDR ranges? ──Yes──▶ ALLOW (no DNS)
    │ No
    ▼
Cache hit on 'bb:dns_verify:<bin_ip>:googlebot.com'? ──Yes──▶ cached result
    │ No
    ▼
gethostbyaddr($ip)            ◄── 40-300ms synchronous, bounded by timeout_ms
    │
    ▼
Hostname ends in '.googlebot.com'?
    │ No
    ▼
unverified → CHALLENGE/BLOCK based on bot category default action
    │
    │ Yes
    ▼
require_forward_confirm? ──No──▶ verified → ALLOW
    │ Yes (only in 'strict')
    ▼
dns_get_record(host, DNS_A + DNS_AAAA) ◄── additional 40-300ms
    │
    ▼
One of the A/AAAA records === $ip? ──Yes──▶ verified → ALLOW
    │ No
    ▼
unverified → CHALLENGE/BLOCK (PTR spoof detected)
```

### Cache key shapes

```
bb:reverse_dns:<bin2hex(inet_pton($ip))>           → "crawl-1-2-3.googlebot.com"
bb:dns_verify:<bin2hex(inet_pton($ip))>:<suffix>   → true | false
```

Binary IP form normalizes IPv6 (no colons to escape) and is stable across adapter backends.

### Settings (escape hatches — defaults controlled by `strictness`)

| Setting | Default | When to override |
|---|---|---|
| `dns_verification.enabled` | `true` (in `normal`/`strict`) | Disable for latency-critical APIs |
| `dns_verification.timeout_ms` | `300` | Lower if your DNS is fast; raise if you have slow DNS and many bots |
| `dns_verification.require_forward_confirm` | `false` (in `normal`), `true` (in `strict`) | Enable in `normal` only when actively seeing PTR spoofing |
| `dns_verification.positive_ttl` | `604800` (7d) | Shorter if you see bot IPs change hands quickly |
| `dns_verification.negative_ttl` | `3600` (1h in `normal`), `86400` (1d in `strict`) | Shorter for faster recovery from DNS outages |

### Cost

| Operation | Latency |
|---|---|
| First request per bot IP per week | +40-300ms (one synchronous PTR lookup) |
| Subsequent requests | 0ms (cache hit) |
| Forward confirmation (strict only) | Additional +40-300ms |
| Cross-request cache | Yes (adapter cache, configurable TTLs) |
| Per-request cache | Yes (instance cache, request-scoped) |

### Pros and cons

**Pros**
- Eliminates the first-request false-positive window (catches regional/academic bots immediately on first visit)
- Catches PTR spoofing when forward-confirm is on
- Multi-suffix sharing: one PTR lookup serves all bots sharing a suffix (e.g., `meta_ai` and `facebook_catalog` both use `facebook.com`)
- Negative caching prevents repeated DNS for known-bad IPs

**Cons**
- 40-300ms latency on first request per bot IP per week
- Hard dependency on system DNS resolver being reachable
- Forward-confirm mode can false-positive on IPv6-only legitimate bots

### Use this when

- ✅ You need to defend against bots claiming to be major search engines or AI crawlers
- ✅ DNS resolver is fast and reliable (<100ms p99)
- ✅ You're OK with one slow first request per bot per week

### Don't use this when

- ❌ Every millisecond of TTFB matters (real-time APIs — set `dns_verification.enabled => false`)
- ❌ Your DNS resolver is unreliable or rate-limited (frequent negative cache hits, users locked out for `negative_ttl` duration)
- ❌ You're behind a CDN that already terminated and validated DNS (your CDN already did this work)

---

## Subsystem 2: Async Dynamic IP Range Feeds

### What it does

Fetches authoritative IP range lists from cloud providers (Cloudflare, AWS, GCP, Fastly) and merges them with the static bot registry. Lets BadBehaviour recognize "this IP belongs to Cloudflare's edge" even when Cloudflare changes their ranges.

### How it works

```
First request after process start (or after cache expiry)
    │
    ▼
adapter.get('bb:ip_ranges:merged')
    │
    ├──cache hit──▶ use cached ranges, no fetch
    │
    └──cache miss
         │
         ▼
    register_shutdown_function() registers async fetcher
         │
         ▼
    [Request returns to user — does NOT wait]
         │
         ▼
    After response sent, fetches fire in background:
      - Cloudflare JSON API
      - AWS ip-ranges.json
      - GCP cloud.json
      - Fastly public-ip-list
         │
         ▼
    Results merged by bot_id, cached for TTL (default 24h)
         │
         ▼
    Next request sees warm cache
```

### Settings

| Setting | Default | When to override |
|---|---|---|
| `dynamic_ip_ranges.enabled` | `true` (in `normal`/`strict`) | Disable if feeds are unreachable from your server |
| `dynamic_ip_ranges.ttl` | `86400` (1d) | Shorter if providers change ranges frequently; longer if cache is precious |
| `dynamic_ip_ranges.feeds` | `['aws','cloudflare','fastly','gcp']` | Trim to only providers you actually use |

### Pros and cons

**Pros**
- Zero request-path latency — fetch happens after response
- Stale-cache fallback: if fetch fails, last-known-good is used
- Each provider cached independently
- Auto-scales with traffic (busier sites refresh more often)
- Survives transient network failures

**Cons**
- Provider JSON formats can change without notice (experimental flag, off by default in older configs)
- Empty cache on first deploy = no cloud IP recognition for 24h
- Async fetch via `register_shutdown_function` can be killed on shared hosting at process exit
- Requires writable cache backend (file/Redis/Memcached)

### Use this when

- ✅ You're behind Cloudflare/AWS/GCP/Fastly and need to recognize their health probes
- ✅ You have writable cache storage
- ✅ You can tolerate up to 24h staleness on cloud IP ranges

### Don't use this when

- ❌ You're on shared hosting where `register_shutdown_function()` is unreliable (consider Subsystem 3 instead)
- ❌ Your cache backend is read-only
- ❌ You don't actually need cloud-provider IP recognition (most bots are already in static ranges)

---

## Subsystem 3: On-Demand IP Range Refresh ("Web Cron")

### Status

✅ **Implemented.** This subsystem replaces the need for `bin/update-ip-ranges.php` cron when scheduled-job support is unavailable. It is **off by default** to avoid surprising existing users.

### Purpose

A **cron substitute** for sites that can't run scheduled jobs (shared hosting, PaaS, containers without CronJob support). Uses a **probabilistic lazy refresh** pattern: on each request, with low probability, check if the dynamic IP range cache is stale; if stale, fetch **after the response has been sent to the client** (so user-facing latency is unaffected).

### How it works

The refresh is gated by **four sequential checks**. The first one to fail short-circuits the rest:

```
Request N arrives (after detection completes)
    │
    ▼
BadBehaviour::register_shutdown_refresh() was called by host?
    │ No
    ▼
(skip — refresh not wired into this request)
    │
    │ Yes
    ▼
OnDemandRefresher::maybe_refresh() runs at shutdown (after response sent):
    │
    ▼
Gate 1: Probability ──── Roll mt_rand(1, denominator); only roll=1 proceeds
    │ (999/1000 requests fail here — single mt_rand() call, ~ns)
    │
    │ Roll = 1
    ▼
Gate 2: Cooldown ────── Check 'bb:on_demand_refresh:lock' key in cache
    │ Lock exists
    ▼
(skip — another worker refreshed recently; TTL is `lock_ttl`)
    │
    │ Lock absent
    ▼
Gate 3: Staleness ───── Read 'bb:ip_ranges:merged' key, compute age
    │ Cache is fresh (< min_age_seconds old)
    ▼
(skip — no refresh needed)
    │
    │ Cache absent OR older than min_age_seconds
    ▼
Gate 4: Mutex ───────── Set 'bb:on_demand_refresh:lock' with TTL = lock_ttl
    │ Lock acquire failed
    ▼
(skip — TOCTOU race with another worker; they'll do the refresh)
    │
    │ Lock acquired
    ▼
OnDemandRefresher::do_refresh() runs:
    │
    ├──Fetch each configured bot feed (Google, Bing, OpenAI, Anthropic, etc.)
    │
    ├──Fetch each configured cloud provider feed (AWS, Cloudflare, Fastly, GCP)
    │
    ├──Merge by bot_id, dedup CIDRs
    │
    ├──Write 'bb:ip_ranges:merged' with TTL = cache_ttl
    │
    └──Clear 'bb:on_demand_refresh:lock'
```

**Wall-clock budget:** the entire refresh is bounded by `feed_timeout_seconds` (default 5s). Skipped feeds are recorded as `'skipped' => 'budget_exhausted'` in the per-feed status.

### Settings

| Setting | Type | Default | Purpose |
|---|---|---|---|
| `on_demand_ip_refresh.enabled` | bool | `false` | Master switch — opt-in |
| `on_demand_ip_refresh.probability_denominator` | int | `1000` | 1-in-N chance per request to consider refreshing |
| `on_demand_ip_refresh.min_age_seconds` | int | `21600` (6h) | Hard floor on refresh frequency |
| `on_demand_ip_refresh.lock_ttl` | int | `600` (10min) | Mutex TTL — doubles as cooldown |
| `on_demand_ip_refresh.cache_ttl` | int | `604800` (7d) | How long refreshed cache entry lives |
| `on_demand_ip_refresh.feed_timeout_seconds` | int\|float | `5` | Wall-clock budget for the entire refresh |
| `on_demand_ip_refresh.bot_ids` | string[]\|null | `null` | Restrict refresh to specific bot IDs (null = all) |
| `on_demand_ip_refresh.cloud_providers` | string[]\|null | `null` | Restrict refresh to specific cloud providers (null = all 4 defaults) |

### Seeding the cache at install time

Subsystem 3 triggers **on page traffic** — but on a fresh install with no traffic yet, the cache stays empty until the first user visits. To populate the cache immediately:

```bash
php bin/install-bb.php              # seed cache (skip if fresh)
php bin/install-bb.php --force      # always re-seed
php bin/install-bb.php --dry-run    # show what would happen
php bin/install-bb.php --verbose    # per-feed progress output
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Success (cache seeded, or already fresh and not `--force`) |
| `1` | Configuration error (no cache backend, etc.) |
| `2` | Partial failure (some feeds errored; cache written with what we got) |
| `3` | Total failure (no feeds succeeded; cache NOT written) |

After seeding, the cache key is `bb:ip_ranges:merged` and contains:
```php
[
    'data'    => ['googlebot' => ['1.2.3.0/24', ...], ...],
    'fetched' => 1735689600,  // Unix timestamp
]
```

### Programmatic API

For tests, admin tools, and hosts that want manual control, `BadBehaviour` exposes:

```php
use BadBehaviour\Core\BadBehaviour;

$bb = new BadBehaviour($config);

// Read-only gate check — what would the next refresh call do?
$decision = $bb->peek_refresh_decision();
// $decision->should_schedule (bool)
// $decision->reason ('probability' | 'cooldown' | 'fresh' | 'mutex_lost' | 'stale' | 'cold_start')
// $decision->cache_age (int|null) — age of cached data when scheduling
// $decision->staleness_floor (int|null)

$bb->is_on_demand_refresh_enabled();  // bool: feature enabled AND cache available?

$result = $bb->force_refresh_now();  // sync, bypasses all gates
// $result->success, $result->partial, $result->bot_count, $result->cidr_count,
// $result->elapsed_seconds, $result->cache_written, $result->feed_status

if ($bb->register_shutdown_refresh()) {
    // Shutdown function is now queued (returns false if disabled or no cache)
}

$bb->get_last_refresh_result();  // ?RefreshResult, null until first refresh completes
```

### Diagnostics integration

```php
$diag = $bb->diagnostics();
// $diag['on_demand_refresh']['enabled']   (bool)
// $diag['on_demand_refresh']['usable']    (bool — feature + cache available)
// $diag['on_demand_refresh']['probability_denominator'] (int)
// $diag['on_demand_refresh']['min_age_seconds'] (int)
// $diag['on_demand_refresh']['cache_ttl'] (int)
```

### Pros and cons

**Pros**
- Zero ops requirement — install and forget, no cron needed
- Self-healing — if cache is stale for any reason, traffic naturally triggers refresh
- Auto-scales with traffic — higher-traffic sites refresh more often
- Naturally bounded — probability × min_age × mutex prevents feed hammering
- Alternative to Subsystem 2's `register_shutdown_function` which fails on some shared hosts
- `bin/install-bb.php` solves the cold-start problem by pre-seeding the cache

**Cons**
- Cold start: fresh install with no traffic has empty cache until first triggering request (~1000 requests at default probability)
- Auto-scales with traffic — quiet sites have slow refresh cycles
- Multi-host coordination only works with shared cache backend (Redis/Memcached/DB)
- Probabilistic — no guarantee when refresh happens, only that it eventually will
- Requires the host application to call `register_shutdown_refresh()` in its bootstrap

### Use this when

- ✅ You don't have cron access (shared hosting, PaaS, containers without CronJob)
- ✅ Subsystem 2's `register_shutdown_function` is unreliable in your environment
- ✅ Your traffic volume is sufficient to trigger refreshes within a few hours
- ✅ You can add one line to your bootstrap (`$bb->register_shutdown_refresh()`)

### Don't use this when

- ❌ You already have cron — use `bin/update-ip-ranges.php` instead (more predictable)
- ❌ Traffic is very low (<10 req/min) — refresh windows become very wide
- ❌ You need deterministic refresh times for compliance/audit reasons
- ❌ You can't modify the application bootstrap to register the shutdown function

---

## Comparison Matrix

### By use case

| Use case | Sync DNS | Async ranges | Web cron | Rationale |
|---|---|---|---|---|
| Personal blog, shared hosting | via `monitor-only` strictness → OFF | OFF | when implemented: ON | DNS verification OFF; static ranges cover ~all bots |
| Small business, has cron, Cloudflare | via `normal` strictness → ON | ON | OFF | Cron does what web cron would do |
| E-commerce behind Cloudflare, has cron | `normal` (or `strict` if scraping) | ON | OFF | Sync catches spoofers; cron handles range refresh |
| High-traffic news site | `strict` | ON | OFF | Async refresh happens frequently from traffic volume |
| Latency-critical API behind AWS ELB | `monitor-only` (override `dns_verification.enabled => false`) | ON | depends | Sync DNS would kill TTFB; async still needed for ELB IP recognition |
| SaaS behind ELB, k8s CronJob available | `normal` | ON | OFF | Cron does refresh; sync optional based on bot defense needs |
| Multi-host cluster, Redis cache, no external scheduler | `normal` | ON | when implemented: ON | Shared Redis mutex coordinates across hosts |
| Air-gapped / locked-down network | `monitor-only` (override) | OFF | OFF | All subsystems require external network calls |

### By setting (which subsystem owns each)

| Setting | Subsystem 1 (Sync) | Subsystem 2 (Async) | Subsystem 3 (Web Cron) |
|---|---|---|---|
| `dns_verification.enabled` | ✓ controls | — | — |
| `dns_verification.timeout_ms` | ✓ controls | — | — |
| `dns_verification.require_forward_confirm` | ✓ controls | — | — |
| `dns_verification.positive_ttl` | ✓ controls | — | — |
| `dns_verification.negative_ttl` | ✓ controls | — | — |
| `dynamic_ip_ranges.enabled` | — | ✓ controls | — |
| `dynamic_ip_ranges.ttl` | — | ✓ controls | — |
| `dynamic_ip_ranges.feeds` | — | ✓ controls | — |
| `on_demand_ip_refresh.enabled` | — | — | ✓ controls |
| `on_demand_ip_refresh.probability_denominator` | — | — | ✓ controls |
| `on_demand_ip_refresh.min_age_seconds` | — | — | ✓ controls |
| `on_demand_ip_refresh.lock_ttl` | — | — | ✓ controls |
| `on_demand_ip_refresh.cache_ttl` | — | — | ✓ controls |
| `on_demand_ip_refresh.feed_timeout_seconds` | — | — | ✓ controls |
| `on_demand_ip_refresh.bot_ids` | — | — | ✓ controls |
| `on_demand_ip_refresh.cloud_providers` | — | — | ✓ controls |

### By trade-off

| Trade-off | Subsystem 1 (Sync) | Subsystem 2 (Async) | Subsystem 3 (Web Cron) |
|---|---|---|---|
| Request-path latency added | +40-300ms first time per IP | 0ms | 0ms (probability gate) |
| Operational setup required | None | None | None (if enabled) |
| Cold-start behavior | Slow first request per bot | Empty cache 24h after install | Empty cache until traffic accumulates |
| Shared-hosting safe | ✓ | ⚠️ shutdown_function can fail | ✓ |
| Determinism | Deterministic per-IP, per-request | Non-deterministic (after first cache) | Non-deterministic (probabilistic) |
| Predictable refresh timing | N/A | TTL-based (24h default) | Min-age based (6h default), triggered by traffic |
| Multi-host coordination | N/A (per-IP caching) | Each host refreshes independently | Requires shared cache for mutex |
| Observability | Cache inspectable | Cache inspectable | Log output + cache inspectable |
| External dependency | System DNS resolver | Cloud provider JSON feeds | Cloud provider JSON feeds |

### By failure scenario

| Scenario | Subsystem 1 | Subsystem 2 | Subsystem 3 |
|---|---|---|---|
| DNS server unreachable | Cache miss → timeout → unverified → CHALLENGE | No effect | No effect |
| Cloud provider JSON endpoint down | No effect | Stale cache used | Stale cache used |
| Cache backend corrupted | Cache miss → fresh DNS | Cache miss → async fetch | Cache miss → next trigger fetches |
| Process killed mid-fetch | No effect (sync completes before response) | Fetch lost, retry next process | Fetch lost, retry on next trigger |
| Negative cache poisoning | Respects `negative_ttl` (1h default in `normal`), re-verifies after | No effect | No effect |
| Cache backend full | Log + skip (no cache) | Log + skip (no async fetch on next) | Log + skip (no refresh on next) |
| Worker crashes mid-refresh | N/A | Partial cache lost, next process retries | Partial cache lost, next trigger retries |

---

## Cache Behavior

### Key shapes

```
bb:reverse_dns:<bin2hex(inet_pton($ip))>           → "crawl-1-2-3.googlebot.com"
bb:dns_verify:<bin2hex(inet_pton($ip))>:<suffix>   → true | false
bb:ip_ranges:merged                                → array<bot_id, CIDR[]>
bb:on_demand_refresh:lock                          → Unix timestamp (refresh lock)
```

| Key | Purpose | Written by | Read by |
|---|---|---|---|
| `bb:reverse_dns:*` | Reverse DNS cache (per IP, shared across suffixes) | `BotDetector::verify_dns()` | `BotDetector::verify_dns()` |
| `bb:dns_verify:*` | Per-(IP, suffix) verification result | `BotDetector::verify_dns()` | `BotDetector::verify_dns()` |
| `bb:ip_ranges:merged` | Merged dynamic IP ranges by bot_id | `OnDemandRefresher::do_refresh()` and `bin/update-ip-ranges.php` | `BotDetector::get_dynamic_ranges()` and `bin/install-bb.php` |
| `bb:on_demand_refresh:lock` | Refresh mutex + cooldown | `OnDemandRefresher::try_acquire_lock()` | `OnDemandRefresher::maybe_refresh()` (Gate 2 + Gate 4) |

Binary IP form (in `bb:reverse_dns:*` and `bb:dns_verify:*`) normalizes IPv6 (no colons to escape) and is stable across adapter backends.

### TTL strategy by strictness

| Strictness | Positive TTL | Negative TTL | Rationale |
|---|---|---|---|
| `monitor-only` | n/a | n/a | DNS verification disabled |
| `normal` | 7 days | 1 hour | Verified IPs are stable; failed IPs get re-checked fast to recover from transient DNS issues |
| `strict` | 30 days | 1 day | Tighter caching — verified IPs almost never change; failed IPs are more likely to be permanently bad (PTR spoofers don't usually fix their PTRs) |

### Multi-suffix sharing

When multiple bots share a DNS suffix (e.g., `meta_ai` and `facebook_catalog` both use `facebook.com`), they share the same reverse DNS cache entry for the IP. The PTR lookup happens **once per IP**, then each suffix is checked against the cached hostname. Forward confirmation (when enabled) is per-suffix since it involves different queries.

---

## False Positive Considerations

The DNS subsystems have these false positive risks:

### Sync verification FP risk

| Risk | Mitigation |
|---|---|
| IPv6-only bots fail forward-confirm (strict mode) | Default `require_forward_confirm` is `false` in `normal` strictness |
| Regional search engines with unresolvable DNS at first visit | Cached after first attempt; failed lookups re-checked after `negative_ttl` |
| Bot operates from a host with a generic PTR (e.g., `host.example.com`) | Cannot be verified as a major bot → CHALLENGE, not BLOCK (in `normal`) |
| Transient DNS outage → all bots look unverified for `negative_ttl` duration | `negative_ttl` is 1h in `normal` (not 24h) — fast recovery |

### Async ranges FP risk

| Risk | Mitigation |
|---|---|
| Cloud provider range changes between fetches | TTL=24h is short enough for most changes; static ranges are fallback |
| Stale cache used if feed endpoint down | Stale cache is better than no cache (cloud IPs still recognized until next fetch) |
| Empty cache on first deploy | `bin/install-bb.php` seeds cache; static ranges cover the most common cloud IPs in the meantime |

### Web cron FP risk (planned)

| Risk | Mitigation |
|---|---|
| Multi-host thundering herd | Mutex via shared cache backend (Redis/Memcached) |
| Cold start window before first refresh | `bin/install-bb.php` pre-seeds cache at deploy time; cache stays warm as long as traffic flows |
| Feed endpoint down | CachedFeedDecorator's stale-cache fallback (existing infrastructure) |

---

## Decision Flowchart

```
START: Do you need to verify bots claiming to be Google/Bing/etc.?
    │
    ├──No──▶ Set strictness to 'monitor-only' or override
    │         dns_verification.enabled => false.
    │         You're done.
    │
    └──Yes
         │
         ▼
    Is DNS lookup latency acceptable (<300ms p99)?
         │
         ├──No──▶ Set strictness to 'monitor-only' or override
         │         dns_verification.enabled => false.
         │         Rely on static CIDR ranges + behavioral detection.
         │         (Most major bots are already covered by static ranges.)
         │
         └──Yes
              │
              ▼
    Are you behind a CDN that already terminates DNS?
              │
              ├──Yes──▶ Use strictness 'normal' (no forward-confirm).
              │         CDN already validated; double-check is redundant.
              │
              └──No
                       │
                       ▼
    Have you observed PTR-spoofing attacks?
                       │
                       ├──No──▶ Use strictness 'normal' (default).
                       │         require_forward_confirm stays false.
                       │
                       └──Yes──▶ Use strictness 'strict'.
                                  require_forward_confirm becomes true.


───────────────────────────────────────────────────────────────


START: Do you need dynamic IP ranges from cloud providers?
    │
    ├──No──▶ Override dynamic_ip_ranges.enabled => false.
    │         Static ranges cover ~all common cases.
    │
    └──Yes
         │
         ▼
    Can you set up a cron job?
         │
         ├──Yes──▶ Use strictness 'normal' or 'strict'.
         │         async ranges ON. Run bin/update-ip-ranges.php
         │         every 6-24h. Keep async enabled for safety net.
         │
         └──No──▶ Use strictness 'normal' or 'strict'.
                  async ranges ON (default).
                  Enable on_demand_ip_refresh.
                  Add one line to bootstrap:
                    $bb->register_shutdown_refresh();
                  Optionally run bin/install-bb.php at deploy time
                  to pre-warm the cache.
```

---

## Recommended Configurations

### Minimal (default — recommended for most sites)

```php
'preset'     => 'minimal',
'strictness' => 'normal',
```

**Effect:** Sync DNS verification ON, async ranges ON, no forward-confirm, conservative cache TTLs. Covers ~95% of bot defenses with FP-safe defaults.

### Production with cron

```php
'preset'     => 'minimal',
'strictness' => 'normal',
'dns_verification' => [
    'timeout_ms' => 200,            // tighter if your DNS is fast
],
'dynamic_ip_ranges' => [
    'feeds' => ['cloudflare', 'aws'],   // only what you actually use
],
```

**Cron:** `0 */6 * * * php /path/to/bin/update-ip-ranges.php`

### Production under attack (PTR spoofing observed)

```php
'preset'     => 'full',          // expand bot coverage
'strictness' => 'strict',
```

**Effect:** All DNS verification ON including forward-confirm. Catches PTR spoofers. Tighter cache TTLs. Use this when actively seeing bot spoofing attacks.

### Latency-critical API

```php
'preset'     => 'minimal',
'strictness' => 'normal',
'dns_verification' => [
    'enabled' => false,           // user override after strictness
],
'dynamic_ip_ranges' => [
    'enabled' => true,
    'feeds' => ['aws'],           // only ELB ranges matter
],
```

**Effect:** No sync DNS (TTFB-safe). Async ranges still recognize AWS ELB IPs. Forward-confirm disabled. Use for APIs behind load balancers where every millisecond counts.

### Behind CDN with no cron (shared hosting)

```php
'preset'     => 'minimal',
'strictness' => 'normal',
'on_demand_ip_refresh' => [
    'enabled' => true,
],
```

**Effect:** Sync DNS verification ON (catches spoofers). Async ranges ON (via on-demand refresh in FPM shutdown, not `register_shutdown_function`). Cache stays warm as long as traffic flows. Run `bin/install-bb.php` at deploy time to pre-warm the cache and avoid the cold-start window.

**Bootstrap integration:** add this to your entry point (before serving any request):
```php
$bb->register_shutdown_refresh();
```

### Evaluating the library

```php
'preset'     => 'minimal',
'strictness' => 'monitor-only',
```

**Effect:** Log everything, block nothing. Watch the `bad_behaviour` table for 7 days to see what would be blocked. Then decide whether to escalate to `normal` or `strict`.

---

## Quick Reference

### One-knob answers

| Want this? | Set strictness to |
|---|---|
| Log only, block nothing ambiguous | `monitor-only` |
| Standard bot defense (recommended) | `normal` |
| Maximum defense under attack | `strict` |
| Disable sync DNS but keep async ranges | `normal` + override `dns_verification.enabled => false` |
| Disable all DNS infrastructure | `monitor-only` |

### Escape-hatch settings (rarely touched)

| Need | Setting |
|---|---|
| Tighter DNS lookup budget | `dns_verification.timeout_ms` |
| Catches PTR spoofers | `dns_verification.require_forward_confirm` (or use `strict`) |
| Faster recovery from DNS outages | `dns_verification.negative_ttl` (lower) |
| Trim cloud providers to only what you use | `dynamic_ip_ranges.feeds` |
| Update cloud IPs from cron | `bin/update-ip-ranges.php` every 6-24h |
| Update cloud IPs without cron | `on_demand_ip_refresh.enabled => true` + `$bb->register_shutdown_refresh()` in bootstrap |

### Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Implemented and active by default at this strictness |
| ❌ | Disabled at this strictness |
| ⚙️ | Implemented, opt-in (off by default — flip a config to enable) |
| 🔜 | Planned but not yet implemented |

---
