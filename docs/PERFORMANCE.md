# Performance — Bad Behaviour 3.0

> Measured on PHP 8.3.32, OPcache enabled, single process, Generic adapter, in-memory cache. Run with `php tests/benchmark.php > your_baseline.txt` and `diff` against the shipped baselines to validate your environment.

## Headline Numbers

| Request type | Latency | Cost at 100 req/s |
|--------------|--------:|------------------:|
| **Static resource** (CSS/JS/image) | **12 μs** | 0.12% of 1 core |
| **Browser HTML page** | **158 μs** | 1.6% of 1 core |
| **AJAX POST (JSON body)** | **148 μs** | 1.5% of 1 core |
| **Verified search engine** | **84 μs** | 0.8% of 1 core |
| **Empty User-Agent** (block) | **62 μs** | 0.6% of 1 core |
| **HTTP tool (curl/wget)** | **92 μs** | 0.9% of 1 core |
| **Cloud LB health probe** | **8 μs** | 0.08% of 1 core |
| **Unverified bot (cold DNS)** | **105 μs** | 1.1% of 1 core |
| **Unverified bot (warm DNS)** | **101 μs** | 1.0% of 1 core |

**Bottom line**: A busy site running 100 req/s spends ~1.6% of one CPU core on detection. Detection overhead is negligible for any realistic workload.

The cloud LB probe path is the most important — those probes fire multiple times per second from CDNs and must never be slowed down. The 8 μs number reflects the early-exit on `is_cloud_infrastructure_ip()` before UA matching.

## Why It's Fast

### 1. Static-resource fast path (`should_skip_static`)

The first thing `run()` checks is whether the URI is a static asset. 95% of traffic on a typical CMS is CSS/JS/images/fonts — and **none of it goes through detection**. The check is a single `parse_url()` + `pathinfo()` + `str_ends_with()`, costing ~12 μs.

### 2. Empty User-Agent fast fail

Requests with no UA (or a UA shorter than 5 chars) are blocked immediately without constructing a full `RequestPackage`, calling `gethostbyaddr()`, or iterating the bot registry. **62 μs total.**

### 3. Cloud infrastructure fast path

If the IP falls in a known cloud LB range (Cloudflare, AWS, GCP, Azure, Fastly), the request is **immediately allowed**. This is critical — blocking these probes marks the origin unhealthy in the CDN and takes the site offline. Static ranges for ~30 known CIDR blocks are merged into a single array on first use, costing **~8 μs** per request (zero allocation, single `IpUtil::match_any()` call). Dynamic ranges (from `CloudIpRangeProvider` feeds) are appended when `enable_dynamic_ip_ranges` is true, adding ~2 μs.

### 4. Whitelist check

Whitelisted IPs, UAs, URL prefixes, ASNs, and countries skip the entire detection pipeline. The check is a single `IpUtil::match_any()` call against an array (typically 0–10 entries).

### 5. Async DNS verification (`BotDetector::verify_dns`)

Reverse DNS lookups (`gethostbyaddr()`) cost 50–500 ms. Bad Behaviour caches them for 7 days per `(IP, suffix)` pair, and uses `register_shutdown_function()` to populate the cache without blocking the response:

- **First request from a fresh IP** → fails open (assumes not verified), schedules a background DNS lookup
- **Subsequent requests** → cache hit, instant verification

The PHP process returns the response to the client *before* the DNS lookup completes. Real-world impact: **450 ms → <100 μs** for cold lookups, **0 ms** for warm lookups.

### 6. Bot registry UA index (`RegistryInterface::find_by_ua`)

The bot registry contains **~100 bots across 12 categories** (or ~30 if you use the `minimal` preset). Without an index, `BotDetector` iterates all of them per request (~100 `stripos()` calls). With the lazy UA index, exact-token UA fragments are O(1) — and substring fallback is only used for the small fraction of non-exact UAs.

The `RegistryTokens::NOISE` filter (single source of truth, referenced by all registry implementations) skips generic tokens like `"mozilla"`, `"chrome"`, `"google"` from token matching. This prevents false positives on substring fallback when common UA components happen to overlap with bot names.

**Per-preset matching cost** (cold build of the UA index, 5,000-entry result cache):

| Preset | Bots | Cold index build | Average match |
|--------|-----:|-----------------:|--------------:|
| `full` | ~100 | ~4.8 ms | ~40 μs |
| `minimal` | ~30 | ~1.4 ms | ~12 μs |
| `verified-only` | ~50 | ~2.3 ms | ~22 μs |
| `no-ai` | ~80 | ~3.7 ms | ~32 μs |
| `eu-only` | ~25 | ~1.1 ms | ~10 μs |

Cold index builds happen **once per PHP process** (lazy), not per request — so the relevant number for steady-state is the "Average match" column. Choosing `minimal` cuts matching cost by ~3× vs. `full`, which is significant on sites with >1,000 req/s of bot UA traffic.

### 7. Lazy install

Schema checks (`CREATE TABLE IF NOT EXISTS …`) run once per PHP process, on the first non-skip request. Subsequent requests skip the DB round-trip entirely.

### 8. Result cache with config fingerprint (`BotDetector`)

Added a per-instance result cache (5000 entries, 5-minute TTL) keyed by `(IP, UA, config_fingerprint)`. For repeat traffic patterns (common on busy sites — same bots hitting the same endpoints), this skips UA matching, IP matching, and DNS verification entirely. The `config_fingerprint` ensures config changes invalidate the cache without an explicit flush. **Expected hit rate on busy sites: 40–70%** → saves ~50 μs per hit.

## Profiling the Pipeline

| Phase | Cost | Triggered by |
|-------|------|--------------|
| Static-skip check | 12 μs | Always |
| Cloud infrastructure check | 8 μs | Always |
| Package construction | ~50 μs | UA parsing, header normalization |
| Empty-UA block | +10 μs | UA empty / <5 chars |
| Whitelist check | +5 μs | IPs/UAs/URLs/ASNs/countries |
| Bot detection (UA-index hit, `minimal` preset) | +12 μs | Known bot UA, ~30 bots |
| Bot detection (UA-index hit, `full` preset) | +30 μs | Known bot UA, ~100 bots |
| Bot detection (substring scan, `full`) | +65 μs | Unknown UA pattern |
| Bot detection (token match, `full`) | +40 μs | Fallback when substring misses |
| Bot detection (custom `InMemoryRegistry`) | +20 μs | User-provided bot array |
| DNS verification (warm) | +5 μs | Cache hit |
| DNS verification (cold) | 50–500 ms | First request from a fresh IP |
| Result cache hit | +2 μs | Repeat (IP, UA) within 5 min |
| Behavioral analysis | +40 μs | Session cookie present |
| Rate limiting | +10 μs | Per-IP counter increment |
| Logging | +200 μs | `log_request()` DB write |

## Tuning for Your Workload

### Maximize static-resource throughput

The `skip_extensions` and `skip_paths` settings in `bb_config.php` determine what bypasses detection entirely. If your site serves traffic from `/themes/`, `/static/`, or `/dist/` that isn't already covered by the defaults, **add those prefixes**. Every request that hits the skip list saves ~145 μs.

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

### Keep cloud ranges up to date

The cloud infrastructure fast path is only as good as the CIDR list. With static ranges alone, you cover ~95% of CDN probes. For the long tail (e.g., when AWS adds a new region), enable `enable_dynamic_ip_ranges`:

```php
'dynamic_ip_ranges' => [
    'enabled' => true,
    'ttl'     => 86400,  // 24h
    'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
],
```

And run the cron to keep the cache fresh:

```cron
0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php >> /var/log/bb-feeds.log 2>&1
```

**Stale cache fallback is automatic** — if a feed fetch fails, the application uses the last-known good data. Worst case is a slightly larger cold-cache window after a CDN range rotation; you will not lose availability.

### Minimize DNS lookups

DNS verification is the most expensive thing Bad Behaviour does. If your site gets a lot of traffic from the same IPs repeatedly, the cache will be warm and lookups are free. If you get a long tail of unique IPs (e.g., a public-facing search engine), you'll see cold-cache latency on first contact only.

For internal/admin areas where you know all clients, **whitelist the IP range** in `bb_whitelist.conf` — DNS verification is skipped entirely for whitelisted requests.

For sites that serve bots with verified DNS but a long tail of unique IPs (e.g., Googlebot hitting millions of pages), pre-warm the DNS cache via:

```bash
# Add to your cron, run hourly
php /path/to/badbehaviour/bin/warm-dns-cache.php
```

(This is a planned addition for 3.2 — currently the only warmer is the in-request `register_shutdown_function`.)

### Disable features you don't need

Each opt-in detector adds ~10–30 μs:

```php
// Registry preset choice — one-time build, affects every matching operation
//'registry' => RegistryFactory::from_array(['preset' => 'minimal']),  // ~3× faster matching vs 'full'

'enable_fingerprinting'          => false,  // -15 μs
'enable_client_hints_validation' => false,  // -20 μs
'enable_agentic_detection'       => false,  // -30 μs (session tracking only)
'enable_head_request_detection'  => false,  // -8 μs
'enable_asset_scraping_detection'=> false,  // -10 μs
'inspect_json_body'              => false,  // -25 μs (POST body scan)
'inspect_multipart_body'         => false,  // -30 μs (file upload scan)
```

These are off by default except `head_request_detection` and `asset_scraping_detection` (both enabled by default in 3.0 because their FP rate is near zero). Turn them on only after monitoring your traffic for 1–2 weeks.

### Trust the cloud fast path

**Never** add cloud LB ranges to your custom_rules block list. The cloud infrastructure fast path runs *before* custom rules — but if you somehow add a CIDR like `173.245.48.0/20` (Cloudflare) to `custom_rules` with action `block`, you will mark your origin unhealthy in Cloudflare's load balancer and take your site offline.

If you need to inspect traffic from a specific cloud provider for analytics, use the **log-only** action:

```php
'custom_rules' => [
    // Log Cloudflare traffic without blocking it
    [
        'type'   => 'ip',
        'value'  => ['173.245.48.0/20', '103.21.244.0/22'],
        'action' => 'log',
        'id'     => 'audit_cloudflare',
    ],
],
```

## Benchmark Methodology

```bash
# 1. Run the benchmark
php tests/benchmark.php > my_baseline.txt

# 2. Compare against shipped baselines
diff benchmark_baseline.txt my_baseline.txt

# 3. Run via PHPUnit for CI
vendor/bin/phpunit tests/Performance/PerformanceBenchmarkTest.php
vendor/bin/phpunit tests/Performance/NewCategoryBenchmarkTest.php
```

The PHPUnit suite runs the same scenarios but emits results to STDERR (so they don't trigger `failOnRisky`).

`NewCategoryBenchmarkTest` validates that the additions (cloud fast path, expanded registry) don't regress the hot path:

- `test_cloud_fast_path_isolated` — measures `is_cloud_infrastructure_ip()` alone; budget <50 μs.
- `test_registry_index_build_under_5_ms` — cold build of the 100-bot registry; budget <5 ms.

## Test Environment

The shipped baselines were measured on:

- **PHP**: 8.3.32 with OPcache enabled
- **Adapter**: `GenericAdapter` (in-memory, no DB round-trips)
- **Cache**: In-memory counters / behavior profiles
- **Bot registry**: ~100 bots across search, AI, social, SEO, archive, feed reader, shopping, cloud infrastructure, monitoring, security scanner, residential proxy
- **Cloud ranges**: Static (Cloudflare, AWS, GCP, Azure, Fastly)
- **Static skips**: Default `skip_extensions` + `skip_paths`
- **Dynamic IP ranges**: Disabled (baseline)

For production numbers (with Redis, DB writes, and reverse-proxy enrichment), expect **+100–300 μs** per request vs. these baselines. The static-resource path is unaffected (it never touches the adapter).

## What We Did NOT Optimize

The following are **known** but intentionally **not** optimized yet — they're candidates for Phase 2/3 work:

- CIDR matching against 30+ cloud ranges (currently O(n) per IP check, could be O(log n) with a trie; saves ~3 μs but adds code complexity)
- Substring scanning against the registry UA index when tokens don't match (still O(n) over ~100 entries for `full` preset, ~30 for `minimal`; trie-based matching is on the roadmap)
- Header fingerprinting for non-CDN traffic (cheap in isolation but called per-request)
- Behavioral profile I/O on every session-touching request (file-cache writes dominate)
- DNS retry on transient failures (no backoff, just first-shot)
- Cloud range updates via AWS SNS webhook (currently cron-based; sub-hour drift possible between runs)

If your site serves >10,000 req/s and detection is visible in CPU profiles, file an issue with `pprof` output and we'll prioritize.

---
