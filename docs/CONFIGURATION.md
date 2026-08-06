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

    // ===== BOT CATEGORIES (11 categories) =====
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

    // ===== DYNAMIC IP RANGES (cloud providers) =====
    'dynamic_ip_ranges' => [
        'enabled' => false,
        'ttl'     => 86400,
        'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
    ],

    // ===== RATE LIMITS =====
    'rate_limits' => [
        'enabled'    => true,
        'global'     => ['requests' => 1000, 'window' => 3600],
        'per_minute' => ['requests' => 60,   'window' => 60],
        'post'       => ['requests' => 30,   'window' => 3600],
        'login'      => ['requests' => 10,   'window' => 900],
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

    // ===== HEAD REQUEST DETECTION (on by default — low FP risk) =====
    'enable_head_request_detection'   => true,
    'head_require_referer'            => true,
    'head_flood_threshold'            => 20,
    'head_probe_threshold'            => 50,
    'head_referer_exempt_paths'       => ['/api/', '/wp-json/', '/health', '/status'],

    // ===== ASSET SCRAPING DETECTION (on by default — low FP risk) =====
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

> **New 3.0 features** are off by default for backward compatibility with 2.x — except `enable_head_request_detection`, `enable_asset_scraping_detection`, and the hard-coded **cloud-infrastructure safety net** (which can't be disabled and never blocks CDN/LB probes).

---

## Bot Registry — Custom, Composable, Pluggable

The bot registry is now a **pluggable, composable system** built on a `RegistryInterface` contract. The default ships ~100 verified bots across 12 categories, but operators can swap, filter, or build entirely custom bot sets without forking the library.

### Architecture

| Component | Purpose |
|-----------|---------|
| `RegistryInterface` | Read-only contract for any registry implementation |
| `DefaultRegistry` | All ~100 shipped bots extracted as `BotDefinition` instances |
| `InMemoryRegistry` | Wrap a user-provided array of `BotDefinition`s |
| `EmptyRegistry` | No-op singleton (humans-only baseline) |
| `FilteredRegistry` | Keep/exclude filters + category filters over any inner registry |
| `MergedRegistry` | Compose multiple registries (last-wins semantics) |
| `CustomRegistry` | Config-array driven, with per-bot validation |
| `Presets` | Named subsets: `full`, `minimal`, `verified-only`, `no-ai`, `no-seo`, `eu-only`, `human-only`, `custom` |
| `RegistryFactory` | Builder entry points — `from_file()`, `from_array()`, `default()` |
| `RegistryTokens` | Single source of truth for `NOISE` tokens and `MIN_TOKEN_LENGTH` |

### Configuration File: `config/bb_registry.php`

A new config file controls which bots the library recognizes. Operators drop a `bb_registry.php` with one of eight preset names, optional category filters, and an `additions` array for internal bots.

```php
<?php
// config/bb_registry.php — ship with one of these:

return [
    'preset'             => 'full',                          // see Presets::AVAILABLE
    'exclude_categories' => ['seo_crawler'],                  // optional
    'include_categories' => ['cloud_infrastructure'],         // optional (overrides exclude)
    'exclude_bots'       => ['petal'],                       // optional
    'additions'          => [/* your internal bots */],       // optional
];
```

**Filter execution order:**
1. Load preset
2. Apply `exclude_categories`
3. Apply `include_categories` (overrides exclude)
4. Apply `exclude_bots`
5. Merge `additions` (custom bots on top)

**Available presets:**

| Preset | Use case |
|--------|----------|
| `full` | All ~100 shipped bots (default if `bb_registry.php` is absent) |
| `minimal` | ~30 most common bots (3× faster matching) |
| `verified-only` | Only bots with DNS verification or IP ranges |
| `no-ai` | Everything except AI crawlers |
| `no-seo` | Everything except SEO crawlers |
| `eu-only` | European search engines + EU-relevant bots |
| `human-only` | Empty registry (combine with `additions`) |
| `custom` | Use ONLY bots defined in the `bots` key |

### Per-Category Behavior (12 categories)

| Category | Default action | Tunable via | Example bots |
|---|---|---|---|
| `search_engine` | verified → allow, unverified → block | n/a | Googlebot, Bingbot, Yandex, Baidu, DuckDuckBot, Brave, Kagi, Naver, Daum, Sogou, Qihoo360, ByteDance, Seznam, Mojeek, Wiby, Cốc Cốc, Mail.ru, Petal, Zum, Stract, Marginalia, Centrum |
| `ai_crawler` | depends on `ai_crawlers.*` | `ai_crawlers.allowed[]`, `strict`, `block_unverified` | GPTBot, ClaudeBot, Google-Extended, PerplexityBot, Meta-ExternalAgent, Applebot-Extended, GrokBot, MistralBot, CohereBot, YouBot, Amazonbot, Semantic Scholar, Diffbot, **BrightData (default BLOCK)** |
| `social_crawler` | verified → allow, unverified → log_only | n/a | Facebook, Twitter, LinkedIn, Discord, Slack, Telegram, WhatsApp, Pinterest, Reddit, Kakao, LINE, WeChat, Notion |
| `seo_crawler` | verified → default, unverified → block | n/a | Ahrefs, Semrush, MJ12, DotBot, Similarweb, Seobility, Botify, Siteimprove, Lumar, Oncrawl, Screaming Frog, ContentKing |
| `archive_crawler` | verified → allow | `allowed[]` (default) | Internet Archive, Common Crawl, UKWA, BnF, DNB, KB-NL, FOSSies |
| `monitoring` | verified → allow | `allowed[]` (default) | UptimeRobot, Pingdom, StatusCake, GTmetrix, Lighthouse |
| `feed_reader` | allow (verified-only) | `allowed[]` (default) | Feedly, Inoreader, Flipboard, NewsBlur, Google News, Apple News |
| `shopping_crawler` | allow (verified-only) | `allowed[]` (default) | Google Shopping, Bing Shopping, Facebook Catalog, Pinterest Shopping, Shopify |
| `cloud_infrastructure` | **HARD allow — never blocked** | n/a (always allowed) | Cloudflare, AWS ELB, GCP LB, Azure, Fastly health probes |
| `security_scanner` | log_only | `log_only[]` (default) | Qualys, Detectify, Rapid7, Shodan, Censys |
| `residential_proxy` | hard block | `blocked[]` (default) | Bright Data / Luminati |
| `malicious` | hard block | `blocked[]` (default) | Known-bad actors |

> ⚠️ **`cloud_infrastructure` cannot be moved to `blocked[]` or `challenge[]`.** The hard-allow is enforced inside `BotDetector::determine_action()` — the safety override always wins, because blocking these probes takes your origin offline.

### Adding Custom Bots

To add your own bots (internal monitoring, niche crawlers), use the `additions` key:

```php
return [
    'preset'    => 'full',
    'additions' => [
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

Required keys: `name`, `user_agent_patterns` (≥1 entry), `category` (one of the 12 cases).
Optional keys: `host_patterns`, `ip_ranges`, `verify_dns`, `dns_suffixes`, `robots_txt_token`, `default_action` (`allow`/`challenge`/`block`/`log_only`), `description`.

Invalid entries are logged via `error_log()` and skipped — they don't break the whole registry. Check `$registry->has_errors()` programmatically if you build registries in code.

### Programmatic Composition

```php
use BadBehaviour\Bot\RegistryFactory;
use BadBehaviour\Bot\Registry\MergedRegistry;
use BadBehaviour\Bot\Registry\EmptyRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Bot\BotDefinition;
use BadBehaviour\Bot\BotCategory;

// Option 1: From a config array
$registry = RegistryFactory::from_array([
    'preset' => 'no-ai',
    'additions' => [/* ... */],
]);

// Option 2: Per-tenant swap
$tenant_registry = $default_bb->with_registry(
    new MergedRegistry([
        $default_bb->get_registry(),
        new InMemoryRegistry($tenant_specific_bots),
    ])
);

// Option 3: Custom registry with empty baseline
$registry = new MergedRegistry([
    EmptyRegistry::instance(),
    new InMemoryRegistry($my_bots),
]);
```

See `config/bb_registry.example.php` for a fully-commented example.

---

## Configuration Profiles

Three reference profiles cover ~95% of deployments. Pick one as your starting point, then customize per [`Complete Settings Reference`](#complete-settings-reference).

### Decision flowchart

```
START
  │
  ├─ Migrating from 2.x or shared hosting?
  │   └─→ DEFAULT profile
  │
  ├─ Production site with modern browser traffic?
  │   ├─ Have monitoring infrastructure?
  │   │   └─→ MEDIUM profile (after 1-2 weeks soak per feature)
  │   └─ No monitoring capacity?
  │       └─→ DEFAULT + show_detailed_block_page = true
  │
  ├─ Internal API / B2B / paid content / high abuse target?
  │   └─→ STRICT profile (with full FP audit first)
  │
  ├─ Public CMS with mixed audience (old browsers, AJAX, uploads)?
  │   └─→ DEFAULT (strict would break too much)
  │
  └─ Behind Cloudflare / AWS ALB / GCP LB / Fastly / Azure?
      └─→ ANY profile — cloud LB probes are always allowed
```

---

### Profile: **Default** (drop-in 2.x replacement)

**Use when:**
- Migrating from 2.x and want zero behavior change
- You have no monitoring infrastructure yet
- Site has long-tail browser users (old Firefox, IE, niche tools)
- AJAX / JSON APIs / file uploads are core functionality

**What it does:**
- Blocks only clear attacks (SQLi, XSS in URLs, malicious UAs)
- Allows all known bots, all HTTP tools, all modern browsers
- DNS-verified search engines and AI crawlers bypass everything
- Head request detection and asset scraping detection are on (low FP risk)
- Cloud LB probes are always allowed

**Configuration:**

```php
<?php
return [
    // ===== CORE — all safe defaults =====
    'logging'                    => true,
    'verbose'                    => false,
    'strict'                     => false,
    'offsite_forms'              => false,

    // Block page
    'show_contact_info'          => false,
    'show_detailed_block_page'   => false,

    // Reverse proxy (only if behind Cloudflare/CDN — see Medium profile)
    'reverse_proxy' => [
        'enabled'   => false,
        'header'    => 'X-Forwarded-For',
        'addresses' => [],
    ],

    // AI crawlers — permissive allowlist
    'ai_crawlers' => [
        'allowed'          => ['GPTBot', 'ClaudeBot', 'Google-Extended',
                              'PerplexityBot', 'GrokBot', 'MistralBot',
                              'YouBot', 'Meta-ExternalAgent'],
        'block_unverified' => true,
        'strict'           => false,
    ],

    // Bot categories — defaults are conservative
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

    // Rate limits — standard
    'rate_limits' => [
        'enabled'    => true,
        'global'     => ['requests' => 1000, 'window' => 3600],
        'per_minute' => ['requests' => 60,   'window' => 60],
        'post'       => ['requests' => 30,   'window' => 3600],
        'login'      => ['requests' => 10,   'window' => 900],
    ],

    // ===== DETECTION FEATURES — opt-in =====
    'enable_fingerprinting'           => false,
    'inspect_json_body'               => false,
    'inspect_multipart_body'          => false,
    'enable_behavioral_analysis'      => true,   // safe (rotating UA, rate)
    'enable_ai_crawler_control'       => true,
    'enable_client_hints_validation'  => false,  // would break old Firefox/IE
    'enable_agentic_detection'        => false,  // would break power users
    'enable_dynamic_ip_ranges'        => false,  // experimental

    // Head + asset scraping — ON by default, low FP risk
    'enable_head_request_detection'   => true,
    'enable_asset_scraping_detection' => true,
];
```

**Hard points:**
- ✅ All AJAX / JSON / fetch / XHR requests work
- ✅ All file uploads work
- ✅ curl / wget / Python-requests work
- ✅ Firefox 1–88 works (no Sec-CH-UA required)
- ✅ IE 11 works (no modern headers required)
- ✅ RSS readers (Feedly, Apple News) work
- ✅ Product crawlers (Google Shopping, FB Catalog) work
- ✅ Cloudflare / AWS / GCP LB probes always allowed
- ✅ Security scanners (Shodan, Qualys) are logged, never blocked
- ❌ Does NOT catch spoofed UAs from real Chromium browsers
- ❌ Does NOT catch AI agents mimicking humans

---

### Profile: **Medium** (production-grade, monitored)

**Use when:**
- You've run Default for 1–2 weeks and reviewed logs
- Your traffic is mostly modern browsers (Chrome 89+, Firefox 100+, Safari 15+)
- You want to catch spoofed UAs and emerging AI agent traffic
- You can monitor for false positives (recommend a 1-week soak period per feature)

**What it adds over Default:**
- Client Hints validation — catches most UA spoofing from Chromium browsers
- Agentic detection — catches AI scrapers mimicking human behavior
- Dynamic IP ranges — fresh ranges from Google/Bing/OpenAI/AWS/Cloudflare/etc.
- Detailed block page — easier user support

**Configuration:** Start from Default, then flip these:

```php
<?php
return [
    // ... (all Default settings above) ...

    // Block page — informative for support
    'show_contact_info'        => true,
    'show_detailed_block_page' => true,

    // ===== TURN THESE ON ONE AT A TIME =====
    // Week 1: Client Hints (lowest FP risk of the new detectors)
    'enable_client_hints_validation' => true,

    // Week 2: Dynamic IP ranges (requires cron first!)
    'enable_dynamic_ip_ranges'       => true,
    'dynamic_ip_ranges' => [
        'enabled' => true,
        'ttl'     => 86400,
        'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
    ],

    // Week 3: Agentic detection (after you understand your power users)
    'enable_agentic_detection'       => true,

    // Fingerprinting — only after 2+ weeks of clean logs
    'enable_fingerprinting'          => false,  // still off — needs curated bad_ja3[]
];
```

**Hard points — what to watch for:**

- ⚠️ **Firefox does NOT send Sec-CH-UA** — only Chromium-based browsers do. Client Hints validation ignores Firefox/Safari by design.
- ⚠️ **Electron apps** (Slack, VS Code, Discord) spoof Chrome UA but don't send Client Hints — they'll get blocked. Add to whitelist if needed:

  ```ini
  ; config/bb_whitelist.conf
  [useragent]
  electron_apps = "^Mozilla/.*Electron/.*Chrome/[\\d.]+$"
  ```

- ⚠️ **Old Chromium (< 89)** — ~3% of traffic in 2024. Won't send Client Hints. Either accept the FP rate or whitelist old Chrome.
- ⚠️ **Agentic detection requires session cookies** — anonymous traffic is skipped. If you don't use sessions, this detector does nothing.
- ⚠️ **Agentic FP triggers** — single-page apps with rapid navigation, power users with many tabs, automated testing. Monitor for `type: 'agentic_nonlinear'` in logs.
- ⚠️ **Dynamic IP ranges** — requires `bin/update-ip-ranges.php` on cron. Without it, falls back to static ranges (same as Default). See [`enable_dynamic_ip_ranges`](#enable_dynamic_ip_ranges).

**Recommended rollout order for Medium:**

1. Day 1: flip `show_detailed_block_page = true` (no FP risk, just observability)
2. Week 1: enable `enable_client_hints_validation` (lowest FP risk — Firefox/Safari/old Chrome are not validated)
3. Week 2: deploy `bin/update-ip-ranges.php` cron, then enable `enable_dynamic_ip_ranges` and the `dynamic_ip_ranges` block
4. Week 3: enable `enable_agentic_detection` after you've audited your power users
5. Week 4+: consider `enable_fingerprinting` only if you've curated `fingerprints.bad_ja3[]`

---

### Profile: **Strict** (high-security / API-only)

**Use when:**
- You control all clients (internal API, B2B, paid content)
- Zero tolerance for spoofed traffic
- Your users all use modern browsers
- You have ops capacity to handle support tickets

**What it adds over Medium:**
- Strict mode — extra header validation (Accept-Encoding required)
- Fingerprinting — blocks known-bad JA3/H2 from config
- Body inspection — checks JSON bodies for attack patterns
- Stricter rate limits
- Tight AI allowlist (or zero AI)
- May block specific bot categories (`seo_crawler`, `social_crawler`)

**Configuration:** Start from Medium, then add:

```php
<?php
return [
    // ... (all Medium settings above) ...

    // ===== STRICT MODE =====
    'strict' => true,  // requires Accept-Encoding header — breaks old browsers

    // Inspect JSON request bodies
    // ⚠️ WILL break legitimate code snippets in JSON payloads
    'inspect_json_body' => true,

    // Tighter rate limits
    'rate_limits' => [
        'enabled'    => true,
        'global'     => ['requests' => 500,  'window' => 3600],
        'per_minute' => ['requests' => 30,   'window' => 60],
        'post'       => ['requests' => 10,   'window' => 3600],
        'login'      => ['requests' => 5,    'window' => 900],
    ],

    // Fingerprinting — curate known-bad fingerprints
    'enable_fingerprinting' => true,
    'fingerprints' => [
        'bad_ja3' => [
            // known-bad TLS fingerprints
            '771,4865-4867-4866-...,0-23-...,29-23-24,0',
        ],
        'bad_h2' => [
            // known-bad H2 settings hashes
        ],
        'bot_header_orders' => [
            // known-bot header order hashes
        ],
    ],

    // Tighter AI policy (uncomment to block all AI)
    'ai_crawlers' => [
        'allowed'          => [],  // no AI allowed
        'block_unverified' => true,
        'strict'           => true,  // block even verified
    ],

    // Block SEO + social crawlers too (strict-mode anti-link-spam)
    'bot_categories' => [
        'blocked'   => ['malicious', 'seo_crawler', 'social_crawler'],
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
];
```

**Hard points:**

- 🔴 **`strict = true`** — blocks any browser that doesn't send `Accept-Encoding`. Most modern browsers do, but some privacy-focused ones don't.
- 🔴 **`inspect_json_body = true`** — JSON payloads containing `union select`, `<script>`, etc. are blocked. **Will break** wiki editors, code-sharing sites, any feature that sends code in JSON.
- 🔴 **`inspect_multipart_body = true`** — same risk for file uploads. Almost never safe.
- 🔴 **Tight rate limits** — generous crawlers and power users will hit limits. Monitor 429 responses.
- 🔴 **JA3 fingerprinting** — only effective if you've curated `bad_ja3[]` from observed attacks. Empty config = no effect.
- 🔴 **Zero AI policy** — legitimate academic research, archival, and content syndication use cases will be blocked. Document this publicly.
- 🔴 **Blocking `seo_crawler`** — link analysis tools (Ahrefs, Semrush) won't see your site. If you do SEO yourself, you'll be flying blind.

---

### Compatibility matrix

What breaks at each level:

| Client type | Default | Medium | Strict |
|-------------|:-------:|:------:|:------:|
| Chrome 89+ (desktop) | ✅ | ✅ | ✅ |
| Chrome < 89 | ✅ | ⚠️ blocked by Client Hints | 🔴 blocked |
| Firefox (any version) | ✅ | ✅ | ⚠️ blocked if `strict` |
| Safari 15+ | ✅ | ✅ | ✅ |
| Safari < 15 | ✅ | ✅ | 🔴 blocked |
| Edge 89+ | ✅ | ✅ | ✅ |
| Internet Explorer 11 | ✅ | ✅ | 🔴 blocked |
| Electron apps (Slack, VS Code, Discord) | ✅ | ⚠️ need whitelist | 🔴 blocked |
| curl / wget / Python-requests | ✅ | ✅ | ✅ |
| AJAX / fetch / XHR | ✅ | ✅ | ⚠️ if `inspect_json_body` |
| File uploads | ✅ | ✅ | 🔴 if `inspect_multipart_body` |
| Webhooks (off-site POST) | ✅ | ✅ | ⚠️ if `offsite_forms` |
| Cloudflare / AWS / GCP / Azure / Fastly probes | ✅ | ✅ | ✅ |
| RSS readers (Feedly, Apple News) | ✅ | ✅ | ✅ |
| Product crawlers (Google Shopping, FB Catalog) | ✅ | ✅ | ✅ |
| Security scanners (Shodan, Qualys) | ✅ logged | ✅ logged | ✅ logged |
| AI agents (Brave Leo, etc.) | ❌ allowed | ✅ detected | ✅ detected |

✅ works • ⚠️ may need config adjustment • 🔴 will break • ❌ not detected

---

## Cloud Infrastructure Safety — **READ THIS IF YOU'RE BEHIND A CDN**

If your site sits behind **Cloudflare, AWS ELB/ALB, GCP Load Balancer, Azure Front Door, or Fastly**, the load balancer periodically sends health-check probes to your origin. These probes come from the CDN's IP ranges, often with generic UAs like `ELB-HealthChecker/1.0`, `GoogleHC`, or `curl/7.x`.

**If Bad Behaviour blocks these probes**, your CDN marks your origin as "unhealthy" and **takes your site offline** — a much bigger outage than the bot traffic would have caused.

### Why it's hard to get right

- UA-only matching fails: probes have generic UAs that look suspicious.
- IP-range matching fails: CDNs add ranges frequently and silently (Cloudflare publishes 15+ IPv4 ranges today, all of which have changed in the last 3 years).
- DNS verification fails: probes don't have stable hostnames.

### The solution

Two layers of defense:

1. **Static IP ranges** ship in the `Registry` for every major CDN (`cloudflare_health`, `aws_elb_health`, `google_cloud_health`, `azure_health`, `fastly_health`). These work out-of-the-box with `enable_dynamic_ip_ranges = false`.

2. **`CloudIpRangeProvider`** pulls **fresh** CIDR lists from official AWS/Cloudflare/Fastly/GCP feeds when `dynamic_ip_ranges.enabled = true`. Cached 24h with a 7-day stale fallback.

`BotDetector::is_cloud_infrastructure_ip()` is the **first check** in the bot pipeline. It runs **before UA matching**. Any IP matching a known cloud range short-circuits to `ALLOW` regardless of UA. This is hard-coded — you cannot accidentally turn it off.

### Verification

```php
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\RegistryInterface;
use BadBehaviour\Util\IpUtil;

// Default registry (or inject your own — see "Bot Registry" section above)
$registry = new DefaultRegistry();

// All five cloud bots are present and hard-allowed
foreach ($registry->cloud_infrastructure() as $id => $def) {
    // $def->default_action === BotAction::ALLOW (enforced)
    // $def->robots_txt_token === null  (no robots.txt governance)
    // $def->ip_ranges is non-empty OR dynamic loading is enabled
}

// Test a known CF IP
IpUtil::match_cidr('173.245.48.1', '173.245.48.0/20');  // true
```

**Verifying via the active registry** (in a running app):

```php
// In production code, the registry is whatever was injected or loaded
// from config/bb_registry.php. Access it via BadBehaviour::get_registry():
$bb = BadBehaviour::withAdapter($adapter);
$registry = $bb->get_registry();

foreach ($registry->cloud_infrastructure() as $id => $def) {
    assert($def->default_action === BotAction::ALLOW);
    assert($def->robots_txt_token === null);
    assert(!empty($def->ip_ranges));
}
```

**Filtering check** (after applying `exclude_categories`/`include_categories`):

```php
$registry = RegistryFactory::from_array([
    'preset'             => 'full',
    'include_categories' => ['cloud_infrastructure'],  // safety net
    'exclude_categories' => ['seo_crawler'],           // unrelated
]);

// cloud_infrastructure MUST still be present even if you tried to exclude it
// via the wrong key order. The include_categories step overrides exclude.
$cf = $registry->get('cloudflare_health');
assert($cf !== null);
```

If your CDN isn't on the list, [open an issue](https://github.com/Bad-Behaviour/badbehaviour/issues) — adding a new cloud provider is a 30-line patch to `DefaultRegistry::cloud_infrastructure()`.

---

## Complete Settings Reference

### Core

| Setting | Type | Default | Risk | Description |
|---------|------|---------|------|-------------|
| `logging` | bool | `true` | **NONE** | Required for audit trail |
| `verbose` | bool | `false` | 🟢 **LOW** | When true, logs *every* request (not just blocks) |
| `strict` | bool | `false` | 🔴 **HIGH** | Strict mode — extra checks for Accept-Encoding, etc. Breaks old browsers / non-browser clients |
| `offsite_forms` | bool | `false` | 🟡 **MEDIUM** | Reject form POSTs where Referer doesn't match Host |
| `show_contact_info` | bool | `false` | 🟢 **LOW** | Show admin email on block page |
| `show_detailed_block_page` | bool | `false` | 🟢 **LOW** | Show reason + support key on block page (vs. terse "Reference #xxx") |

**Block page rendering** (`BadBehaviour::serve_block_page()`):

```php
// Simple (default when both flags are false)
<h1>Access Denied</h1>
<p>You don't have permission to access this resource</p>
<div class="ref">Reference #abc-1234-def0</div>

// Detailed (when show_detailed_block_page = true)
<h1>Access Denied</h1>
<p>We're sorry, but we could not fulfill your request for <code>/path</code</p>
<p><strong>Reason</strong> Bot blocked: AhrefsBot</p>
<p>Your technical support key is: <strong>abc-1234-def0</strong</p>
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

| Token | Robots.txt | Owner | Verification | Default action |
|-------|------------|-------|--------------|----------------|
| `GPTBot` | `GPTBot` | OpenAI | DNS `openai.com` | challenge |
| `ClaudeBot` | `ClaudeBot` | Anthropic | DNS `anthropic.com` | challenge |
| `Google-Extended` | `Google-Extended` | Google | DNS `googlebot.com` | challenge |
| `PerplexityBot` | `PerplexityBot` | Perplexity | IP ranges | challenge |
| `Meta-ExternalAgent` | `Meta-ExternalAgent` | Meta | DNS `facebook.com` | challenge |
| `Applebot-Extended` | `Applebot-Extended` | Apple | DNS `applebot.apple.com` | challenge |
| `GrokBot` | `GrokBot` | xAI | DNS `x.ai` | challenge |
| `MistralBot` | `MistralBot` | Mistral AI | DNS `mistral.ai` | challenge |
| `CohereBot` | `CohereBot` | Cohere | DNS `cohere.com` | challenge |
| `YouBot` | `YouBot` | You.com | DNS `you.com` | challenge |
| `CCBot` | `CCBot` | Common Crawl | IP ranges | challenge |
| `ia_archiver` | `ia_archiver` | Internet Archive | DNS `archive.org` | challenge |
| `Amazonbot` | `Amazonbot` | Amazon | DNS + IP | challenge |
| `Diffbot` | `Diffbot` | Diffbot | DNS + IP | challenge |
| `BrightData` | `BrightData` | Bright Data | UA-only | **block** (residential proxy) |

---

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

| Setting | Type | Default | Risk | Effect |
|---------|------|---------|------|--------|
| `blocked[]` | string[] | `['malicious']` | 🟡 **MEDIUM** | Hard-block by category |
| `log_only[]` | string[] | `['security_scanner']` | 🟢 **LOW** | Record only, never block |
| `challenge[]` | string[] | `[]` | 🟡 **MEDIUM** | Force PoW/captcha |
| `allowed[]` | string[] | feed/shopping/cloud/monitoring/archive | 🟢 **LOW** | Verified-only allow |

**Valid category names** (11 cases):

```
search_engine, ai_crawler, social_crawler, seo_crawler,
archive_crawler, monitoring, feed_reader, shopping_crawler,
cloud_infrastructure, security_scanner, malicious, unknown
```

> ⚠️ **`cloud_infrastructure` cannot be moved to `blocked[]` or `challenge[]`.** The hard-allow is enforced in `BotDetector::determine_action()` and overrides any configuration. This is intentional — blocking these probes takes your origin offline.

#### Common category recipes

**Block all SEO crawlers (Ahrefs, Semrush, MJ12, etc.):**
```php
'bot_categories' => [
    'blocked' => ['malicious', 'seo_crawler'],
],
```

**Challenge AI scrapers but allow verified:**
```php
'ai_crawlers' => [
    'allowed' => ['GPTBot', 'ClaudeBot'],
    'block_unverified' => true,
    'strict' => false,
],
'bot_categories' => [
    'challenge' => ['ai_crawler'],
],
```

**Log but allow social crawlers (for analytics):**
```php
// already the default — social_crawler category is verified-allow
// for analytics, add a custom_rule with action: 'log'
```

---

### Dynamic IP Ranges (`dynamic_ip_ranges`)

Pulls fresh IP ranges from cloud provider feeds to prevent hardcoded CIDR drift.

| Setting | Type | Default | Risk | Description |
|---------|------|---------|------|-------------|
| `enabled` | bool | `false` | 🟡 **EXPERIMENTAL** | Master switch. Requires `bin/update-ip-ranges.php` on cron |
| `ttl` | int | `86400` | 🟢 **LOW** | Cache TTL for merged feed (seconds). Lower = fresher, more cron pressure |
| `feeds[]` | string[] | `['aws', 'cloudflare', 'fastly', 'gcp']` | 🟢 **LOW** | Subset of cloud-provider feeds to pull |

**Two independent feed pipelines:**

1. **Bot-specific feeds** (`FeedRegistry`) — refreshes Googlebot, Bingbot, GPTBot, Claude, Applebot, Perplexity, DuckDuckGo, Amazonbot, Cloudflare v4/v6 ranges.

2. **Cloud-provider feeds** (`CloudIpRangeProvider`) — used by the `BotDetector` fast path. Pulls from `ip-ranges.amazonaws.com`, `api.cloudflare.com/client/v4/ips`, `api.fastly.com/public-ip-list`, `gstatic.com/ipranges/cloud.json`.

**Note:** Azure is in the registry but its JSON endpoint shape differs — currently a TODO. `azure_health` relies on the static ranges shipped with the registry.

**Cron setup:**
```bash
# Refresh every 6 hours
0 */6 * * * php /path/to/badbehaviour/bin/update-ip-ranges.php >> /var/log/badbehaviour-feeds.log 2>&1
```

**Known issues** (why "experimental"):
1. **Caching boundaries** — file cache doesn't share across multi-server deployments; use the MediaWiki adapter's WAN cache for production
2. **Feed shape changes** — vendors occasionally add new fields; parsers must be tolerant
3. **Cold-start latency** — first request after TTL expiry triggers fetches unless cron runs in time
4. **CA bundle portability** — auto-detection works on Debian/RHEL/Homebrew but not on stripped-down containers

**CLI flags:**
```bash
php bin/update-ip-ranges.php                       # Full refresh
php bin/update-ip-ranges.php --dry-run             # Fetch but don't cache
php bin/update-ip-ranges.php --feeds=google,anthropic  # Subset only
php bin/update-ip-ranges.php --ttl=43200           # Override cache TTL
```

**Exit codes:**
- `0` — success (all feeds fetched or stale cache used)
- `1` — partial failure (some feeds failed)
- `2` — total failure (no feeds fetched, no cache)

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

**Login endpoint detection**: automatically triggers on URLs matching `/(login|signin|auth|password)/i`.

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

    // 3. Audit Feedly (feed reader you allow)
    [
        'type'    => 'ua_contains',
        'value'   => 'Feedly',
        'action'  => 'log',
        'id'      => 'audit_feedly',
    ],

    // 4. Audit a security scanner auditing you
    [
        'type'    => 'ua_contains',
        'value'   => 'Shodan',
        'action'  => 'log',
        'id'      => 'audit_shodan',
    ],

    // 5. Audit the new "Brave Leo" agentic UA — decide policy later
    [
        'type'    => 'header',
        'header'  => 'Sec-CH-UA',
        'value'   => 'Brave Leo',
        'action'  => 'log',
        'id'      => 'brave_leo_agentic',
    ],

    // 6. Audit monitoring services you whitelist
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

### Head Request Detection (`head_*`)

Detects abuse of HEAD requests: site mapping, link-checking at scale, and rapid reconnaissance. HEAD is cheap (no body transfer) and ideal for fingerprinting a site without reading content.

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `enable_head_request_detection` | bool | `true` | 🟢 **LOW** | Keep enabled — blocks a real attack vector |
| `head_require_referer` | bool | `true` | 🟢 **LOW** | Keep enabled — link checkers send Referer naturally |
| `head_flood_threshold` | int | `20` | 🟢 **LOW** | Requests per session before block; tune for your traffic |
| `head_probe_threshold` | int | `50` | 🟢 **LOW** | HEAD probes per IP per 5 min; lower = stricter |
| `head_referer_exempt_paths` | string[] | `['/api/', '/wp-json/', '/health', '/status']` | 🟢 **LOW** | Paths where HEAD without Referer is legitimate |

**Exempt paths** should include any endpoint where REST clients or monitoring tools legitimately issue HEAD without a Referer. Defaults cover most CMS APIs and common health-check endpoints.

**Three signals:**

1. **HEAD without Referer** — site mapping typically omits Referer; real browsers send it.
2. **HEAD flood per session** — >20 HEAD requests in a single session = enumeration.
3. **HEAD probing per IP** — >50 HEAD requests from one IP in 5 minutes = reconnaissance.

---

### Asset Scraping Detection (`asset_*`)

Detects direct asset scraping (AI training crawlers, image harvesters, bulk downloaders). Legitimate browsers load HTML first, then assets referenced from it. Scrapers directly request assets from a URL list with no HTML navigation.

| Setting | Type | Default | Risk | When to Enable |
|---------|------|---------|------|----------------|
| `enable_asset_scraping_detection` | bool | `true` | 🟢 **LOW** | Keep enabled — targets a real scraping pattern |
| `asset_extensions` | string[] | image, doc, audio, video formats | 🟡 **MEDIUM** | Add/remove based on what content you serve |
| `asset_no_referer_threshold` | int | `10` | 🟢 **LOW** | Asset requests without Referer per IP per hour |
| `asset_only_session_threshold` | int | `20` | 🟢 **LOW** | Asset requests with no HTML loads per session |
| `asset_pattern_threshold` | int | `100` | 🟢 **LOW** | Sequential asset URLs per IP per 5 min |

**When to extend `asset_extensions`**: add extensions for content types you serve that you want to protect (e.g., `'csv'`, `'json'`, `'xml'`, `'zip'`).
**When to remove**: remove extensions used by legitimate APIs that don't send Referer (rare — most APIs return JSON, not files).

**Three signals:**

1. **Asset without Referer** — bots fetching `/img1.png, /img2.png, …` directly don't send Referer. Legitimate browsers do.
2. **Asset-only session** — >20 asset requests in a session where `html_requests === 0` = pure asset harvesting. Real browsers always load HTML first.
3. **Sequential asset pattern** — >100 assets from one IP in 5 minutes = scraping.

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

### Detection Features (Opt-in)

These are the new detectors. **All default to `false`** for legacy compatibility — except `enable_head_request_detection` and `enable_asset_scraping_detection`, which default to `true` (low FP risk).

| Setting | Type | Default | Risk | Description |
|---------|------|---------|------|-------------|
| `enable_fingerprinting` | bool | `false` | 🟡 **MEDIUM** | Enables JA3/H2/header-order checks |
| `inspect_json_body` | bool | `false` | 🔴 **HIGH** | Apply attack patterns to JSON bodies |
| `inspect_multipart_body` | bool | `false` | 🔴 **HIGH** | Apply attack patterns to multipart uploads |
| `enable_behavioral_analysis` | bool | `true` | 🟢 **LOW** | Rate/UA/think-time heuristics |
| `enable_ai_crawler_control` | bool | `true` | 🟢 **LOW** | Verified AI allowlist enforcement |
| `enable_client_hints_validation` | bool | `false` | 🟡 **MEDIUM** | Sec-CH-UA cross-check (requires Chromium 89+) |
| `enable_agentic_detection` | bool | `false` | 🟡 **MEDIUM** | AI-agent pattern detection (think-then-fetch, precision) |
| `enable_dynamic_ip_ranges` | bool | `false` | 🟡 **EXPERIMENTAL** | Use FeedRegistry (requires cron, see [`dynamic_ip_ranges`](#dynamic-ip-ranges-dynamic_ip_ranges)) |
| `enable_head_request_detection` | bool | `true` | 🟢 **LOW** | HEAD flooding + Referer check |
| `enable_asset_scraping_detection` | bool | `true` | 🟢 **LOW** | Asset-only session detection |

#### `enable_client_hints_validation`

Catches spoofed UAs from Chromium 89+ browsers. Validates:
- Missing `Sec-CH-UA`/`Sec-CH-UA-Platform`/`Sec-CH-UA-Mobile`
- Brand mismatch (`Sec-CH-UA` says Edge, UA says Chrome)
- Version drift > 2 majors
- Platform / mobile contradictions

False positive risk: Electron apps, very old Chromium, some headless tools.

#### `enable_agentic_detection`

Three pattern detectors:
1. **Think-then-fetch** — long pause + asset burst
2. **Non-linear navigation** — 5+ unrelated sections in 8 requests
3. **Precision targeting** — high API ratio, no CSS/fonts/tracking

False positive risk: power users, single-page-app users. Requires session cookies.

#### `enable_dynamic_ip_ranges` (Experimental)

Pulls fresh IP ranges from Google, Bing, OpenAI, Anthropic, Apple, Perplexity, DuckDuckGo, Amazon, AWS, Cloudflare, Fastly, GCP feeds. Requires `bin/update-ip-ranges.php` on cron. See [`dynamic_ip_ranges`](#dynamic-ip-ranges-dynamic_ip_ranges) for the configuration block and [`enable_dynamic_ip_ranges`](#enable_dynamic_ip_ranges-experimental) for details.

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

> Whitelist runs **before** BotDetector. Whitelisted IPs/UAs skip all detection — including the cloud-LB safety net (not a problem in practice: whitelisting your own IPs is the whole point).

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
| `enable_head_request_detection` | 🟢 LOW | `true` | Keep enabled |
| `enable_asset_scraping_detection` | 🟢 LOW | `true` | Keep enabled |
| `block_unverified_ai` | 🟢 LOW | `true` | Keep enabled |
| `strict_ai` | 🟡 MEDIUM | `false` | Zero AI policy |
| `enable_behavioral_analysis` | 🟢 LOW | `true` | Keep enabled |
| `enable_ai_crawler_control` | 🟢 LOW | `true` | Keep enabled |
| `reverse_proxy.enabled` | 🟡 MEDIUM | `false` | Behind proxy + `addresses[]` |
| `bot_categories.blocked` | 🟡 MEDIUM | `['malicious']` | Custom policy |
| `bot_categories.allowed` | 🟢 LOW | feed/shopping/cloud/monitoring/archive | Custom policy |
| Cloud LB safety net | 🟢 LOW | **always on** | Cannot disable |

---

## Migration from INI Format (2.x → 3.0)

The 2.x INI format is replaced by `bb_config.php`. See [`UPGRADE.md`](UPGRADE.md) for the full conversion guide.

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

    // ===== BOT CATEGORIES =====
    'bot_categories' => [
        'blocked'   => ['malicious'],
        'log_only'  => ['security_scanner'],
        'challenge' => [],
        'allowed'   => [
            'feed_reader', 'shopping_crawler', 'cloud_infrastructure',
            'monitoring', 'archive_crawler',
        ],
    ],

    // ===== DYNAMIC IP RANGES =====
    'dynamic_ip_ranges' => [
        'enabled' => true,
        'ttl'     => 86400,
        'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
    ],

    // ===== RATE LIMITS =====
    'rate_limits' => [
        'enabled'    => true,
        'global'     => ['requests' => 1000, 'window' => 3600],
        'per_minute' => ['requests' => 60,   'window' => 60],
        'post'       => ['requests' => 30,   'window' => 3600],
        'login'      => ['requests' => 10,   'window' => 900],
    ],

    // ===== DETECTION FEATURES (gradual rollout) =====
    'enable_fingerprinting'           => false,  // Week 3+
    'inspect_json_body'               => false,  // Never for AJAX apps
    'inspect_multipart_body'          => false,  // Never for uploads
    'enable_behavioral_analysis'      => true,
    'enable_ai_crawler_control'       => true,
    'enable_client_hints_validation'  => true,   // Week 1 — low FP risk
    'enable_agentic_detection'        => false,  // Week 4+ — monitor FPs
    'enable_dynamic_ip_ranges'        => true,   // After cron deployed

    // ===== HEAD + ASSET SCRAPING (on by default) =====
    'enable_head_request_detection'   => true,
    'enable_asset_scraping_detection' => true,

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
        [
            'type'    => 'ua_contains',
            'value'   => 'Feedly',
            'action'  => 'log',
            'id'      => 'audit_feedly',
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

# 6. Verify cloud LB probes pass through
curl -H "User-Agent: ELB-HealthChecker/1.0" https://yourwiki/health
# Expect 200 — never 403

# 7. Test the dynamic IP cron
php /path/to/badbehaviour/bin/update-ip-ranges.php --dry-run
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