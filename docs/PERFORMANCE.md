# Performance — Bad Behaviour 3.0

> Measured on PHP 8.3.32, OPcache enabled, single process, Generic adapter, in-memory cache. Run with `php tests/benchmark.php > your_baseline.txt` and `diff` against the shipped baselines to validate your environment.

## Headline Numbers

| Request type | Latency | Cost at 100 req/s |
|--------------|--------:|------------------:|
| **Static resource** (CSS/JS/image) | **12 μs** | 0.12% of 1 core |
| **Browser HTML page** | **152 μs** | 1.5% of 1 core |
| **AJAX POST (JSON body)** | **144 μs** | 1.4% of 1 core |
| **Verified search engine** | **81 μs** | 0.8% of 1 core |
| **Empty User-Agent** (block) | **62 μs** | 0.6% of 1 core |
| **HTTP tool (curl/wget)** | **90 μs** | 0.9% of 1 core |
| **Unverified bot (cold DNS)** | **102 μs** | 1.0% of 1 core |
| **Unverified bot (warm DNS)** | **98 μs** | 1.0% of 1 core |

**Bottom line**: A busy site running 100 req/s spends ~1.5% of one CPU core on detection. Detection overhead is negligible for any realistic workload.

## Why It's Fast

### 1. Static-resource fast path (`should_skip_static`)

The first thing `run()` checks is whether the URI is a static asset. 95% of traffic on a typical CMS is CSS/JS/images/fonts — and **none of it goes through detection**. The check is a single `parse_url()` + `pathinfo()` + `str_ends_with()`, costing ~12 μs.

### 2. Empty User-Agent fast fail

Requests with no UA (or a UA shorter than 5 chars) are blocked immediately without constructing a full `RequestPackage`, calling `gethostbyaddr()`, or iterating the bot registry. **62 μs total.**

### 3. Whitelist check

Whitelisted IPs, UAs, URL prefixes, ASNs, and countries skip the entire detection pipeline. The check is a single `IpUtil::match_any()` call against an array (typically 0–10 entries).

### 4. Async DNS verification (`BotDetector::verify_dns`)

Reverse DNS lookups (`gethostbyaddr()`) cost 50–500 ms. Bad Behaviour caches them for 7 days per `(IP, suffix)` pair, and uses `register_shutdown_function()` to populate the cache without blocking the response:

- **First request from a fresh IP** → fails open (assumes not verified), schedules a background DNS lookup
- **Subsequent requests** → cache hit, instant verification

The PHP process returns the response to the client *before* the DNS lookup completes. Real-world impact: **450 ms → <100 μs** for cold lookups, **0 ms** for warm lookups.

### 5. Bot registry UA index (`Registry::find_by_ua`)

The bot registry contains 50+ bots across 6 categories. Without an index, `BotDetector` iterates all of them per request (~50 `stripos()` calls). With the index, exact UA tokens are O(1) — and substring fallback is only used for the small fraction of non-exact UAs.

### 6. Lazy install

Schema checks (`CREATE TABLE IF NOT EXISTS …`) run once per PHP process, on the first non-skip request. Subsequent requests skip the DB round-trip entirely.

## Profiling the Pipeline

| Phase | Cost | Triggered by |
|-------|------|--------------|
| Static-skip check | 12 μs | Always |
| Package construction | ~50 μs | UA parsing, header normalization |
| Empty-UA block | +10 μs | UA empty / <5 chars |
| Whitelist check | +5 μs | IPs/UAs/URLs/ASNs/countries |
| Bot detection (UA-index hit) | +30 μs | Known bot UA |
| Bot detection (substring scan) | +60 μs | Unknown UA pattern |
| DNS verification (warm) | +5 μs | Cache hit |
| DNS verification (cold) | 50–500 ms | First request from a fresh IP |
| Behavioral analysis | +40 μs | Session cookie present |
| Rate limiting | +10 μs | Per-IP counter increment |
| Logging | +200 μs | `log_request()` DB write |

## Tuning for Your Workload

### Maximize static-resource throughput

The `skip_extensions` and `skip_paths` settings in `bb_config.php` determine what bypasses detection entirely. If your site serves traffic from `/themes/`, `/static/`, or `/dist/` that isn't already covered by the defaults, **add those prefixes**. Every request that hits the skip list saves 140 μs.

```php
'performance' => [
    'skip_paths' => [
        '/static/', '/assets/', '/media/', '/images/', '/css/',
        '/js/', '/fonts/', '/dist/', '/build/', '/vendor/',
        '/node_modules/',
        // Add your CDN paths here:
        // '/wp-content/uploads/',
        // '/sites/default/files/',
    ],
],
```

### Minimize DNS lookups

DNS verification is the most expensive thing Bad Behaviour does. If your site gets a lot of traffic from the same IPs repeatedly, the cache will be warm and lookups are free. If you get a long tail of unique IPs (e.g., a public-facing search engine), you'll see cold-cache latency on first contact only.

For internal/admin areas where you know all clients, **whitelist the IP range** in `bb_whitelist.conf` — DNS verification is skipped entirely for whitelisted requests.

### Disable features you don't need

Each opt-in detector adds ~10–20 μs:

```php
'enable_fingerprinting'          => false,  // -15 μs
'enable_client_hints_validation' => false,  // -20 μs
'enable_agentic_detection'       => false,  // -30 μs (session tracking only)
'inspect_json_body'              => false,  // -25 μs (POST body scan)
'inspect_multipart_body'         => false,  // -30 μs (file upload scan)
```

These are off by default. Turn them on only after monitoring your traffic for 1–2 weeks.

### Run cron for dynamic IP ranges

If you enable `enable_dynamic_ip_ranges`, **make sure the cron job runs** (`bin/update-ip-ranges.php`). Without fresh feed data, the bot detector falls back to stale in-process cache — which is fine for correctness but means every cold request re-runs the cache check.

## Benchmark Methodology

```bash
# 1. Run the benchmark
php tests/benchmark.php > my_baseline.txt

# 2. Compare against shipped baselines
diff benchmark_baseline.txt my_baseline.txt

# 3. Run via PHPUnit for CI
vendor/bin/phpunit tests/Performance/PerformanceBenchmarkTest.php
```

The PHPUnit suite runs the same scenarios but emits results to STDERR (so they don't trigger `failOnRisky`).

## Test Environment

The shipped baselines were measured on:

- **PHP**: 8.3.32 with OPcache enabled
- **Adapter**: `GenericAdapter` (in-memory, no DB round-trips)
- **Cache**: In-memory counters / behavior profiles
- **Bot registry**: 50+ bots across search, AI, social, SEO, archive, monitoring
- **Static skips**: Default `skip_extensions` + `skip_paths`

For production numbers (with Redis, DB writes, and reverse-proxy enrichment), expect **+100–300 μs** per request vs. these baselines. The static-resource path is unaffected (it never touches the adapter).

## What We Did NOT Optimize

The following are **known** but intentionally **not** optimized yet — they're candidates for Phase 2/3 work:

- CIDR matching against 50+ ranges (currently O(n) per IP check, could be O(log n) with a trie)
- Header fingerprinting for non-CDN traffic (cheap in isolation but called per-request)
- Behavioral profile I/O on every session-touching request (file-cache writes dominate)
- DNS retry on transient failures (no backoff, just first-shot)
- DNS verification for bots with empty `dns_suffix` (currently skipped — good)

If your site serves >10,000 req/s and detection is visible in CPU profiles, file an issue with `pprof` output and we'll prioritize.