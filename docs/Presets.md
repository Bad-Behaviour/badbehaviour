# BadBehaviour 3.0 — Bot Registry Presets

## What is a Preset?

A **preset** determines **which bots** BadBehaviour recognizes. The library ships with a registry of ~100 known bots (search engines, AI crawlers, social link previewers, monitoring services, etc.), but most operators only encounter a fraction of them in practice.

The `preset` config key selects which subset of that registry is active. Combined with `strictness`, it answers the two fundamental questions:

| Knob | Question |
|---|---|
| `preset` | **Which** bots should BadBehaviour know about? |
| `strictness` | **How aggressively** should it enforce against them? |

---

## The Eight Presets

### `full` — All ~100 shipped bots

Recognizes every bot in the shipped registry: search engines (global + regional), AI crawlers (GPT, Claude, Gemini, etc.), social link previewers, SEO crawlers, web archives, monitoring, feed readers, shopping crawlers, cloud infrastructure, security scanners, residential proxy networks.

**Use when:**
- You're not sure which bots you need to recognize
- You operate in multiple regions (EU + US + Asia traffic)
- You're seeing unidentified bot traffic and want maximum coverage

**Cost:** Larger index, slower matching (~3ms per request vs ~1ms for `minimal`). For most sites this is negligible.

### `minimal` (default) — ~30 most common bots

Recognizes the bots you're most likely to encounter: major search engines (Google, Bing, DuckDuckGo), major AI crawlers (GPT, Claude, Perplexity, etc.), major social link previewers (Facebook, Twitter, Slack), monitoring (UptimeRobot, Pingdom), and **all cloud infrastructure** (Cloudflare, AWS, GCP, Fastly).

The cloud infrastructure subset is **never omitted** — blocking those takes your CDN offline. It's included in every preset except `human-only` and `custom`.

**Use when:**
- Default for most sites
- You want fast matching without coverage gaps for common bots
- You're not seeing unidentified traffic that needs recognition

**Cost:** ~1ms matching time. Covers ~95% of real-world bot encounters.

### `verified-only` — Bots with DNS verification or IP ranges

A subset of `full` that only includes bots whose identity can be cryptographically or cryptographically-ish verified: bots with static IP ranges (Cloudflare, Google, Bing, etc.) or DNS verification enabled (Googlebot, Bingbot, etc.).

Excludes bots that match only by UA token, which are more prone to false positives (someone setting their UA to `Mozilla/5.0 ... YandexBot/1.0` to bypass UA-based blocks).

**Use when:**
- You have very low tolerance for false positives
- You only care about bots you can definitively verify

**Cost:** Misses regional bots, newer AI crawlers, social previewers. Coverage may be insufficient for non-English-language sites.

### `no-ai` — Everything except AI crawlers

Same as `full` but with all AI crawlers (GPTBot, ClaudeBot, Google-Extended, Bytespider, etc.) removed.

**Use when:**
- You don't want to block AI training scrapers (you allow AI training on your content)
- You want all the other bot defenses without the AI-specific ones

**Cost:** None — same performance as `full`.

### `no-seo` — Everything except SEO crawlers

Same as `full` but with SEO crawlers (Semrush, Ahrefs, MJ12, etc.) removed.

**Use when:**
- You want SEO crawlers to access your site (some sites rely on SEO tool indexing)
- You want all other bot defenses

**Cost:** None.

### `eu-only` — European search engines + EU-relevant bots

A regional subset focused on European search engines (DuckDuckGo, Qwant, Mojeek, Seznam, Brave) and EU-relevant archives (Internet Archive, BnF, DNB, KB-NL). Includes cloud infrastructure and monitoring.

**Use when:**
- You operate a GDPR-strict site
- Your audience is primarily European
- You want to avoid any US-based AI crawler (note: EU-only excludes Mistral AI as well as the US AI crawlers; see the registry source for the exact list)

**Cost:** Misses US/Asian search engines and AI crawlers.

### `human-only` — No bots recognized

Empty registry. No bots are matched by UA.

**Use when:**
- You want BadBehaviour to be a pure attack-pattern detector (XSS, SQL injection, rate limiting) with no bot-specific logic
- You're testing what the non-bot detection layers see
- You're combining with a completely custom registry (see "Combining with custom bots" below)

**Cost:** Cloud infrastructure IPs are no longer auto-allowed. You MUST add them yourself or risk blocking your CDN's health probes.

### `custom` — Only your custom bots

Empty base registry, populated only with the bots you define in `config/bb_registry.php`.

**Use when:**
- You have a curated list of bots relevant to your specific site
- You want full control over what gets recognized

**Cost:** None of the shipped bots are included. You must explicitly add any you need.

---

## Decision Tree

```
START: Do you need bot-specific recognition at all?
    │
    ├──No──▶ Use preset='human-only'.
    │         You still get attack-pattern detection
    │         (XSS, SQLi, rate limiting) and cloud IP
    │         allowlisting IF you add it manually.
    │
    └──Yes
         │
         ▼
    Are you running a typical website/blog?
         │
         ├──Yes──▶ Use preset='minimal' (default).
         │         Covers ~95% of real-world bots.
         │
         └──No, I have specific needs
              │
              ├──Regional focus (EU, Asia)
              │   └──▶ preset='eu-only' (or similar)
              │
              ├──Don't want AI training scrapers blocked
              │   └──▶ preset='no-ai'
              │
              ├──Want SEO tools to crawl freely
              │   └──▶ preset='no-seo'
              │
              ├──Very low FP tolerance
              │   └──▶ preset='verified-only'
              │
              ├──Need full coverage for unknown traffic
              │   └──▶ preset='full'
              │
              └──Custom list of bots specific to my site
                  └──▶ preset='custom' + define bots in
                      config/bb_registry.php
```

---

## Combining with Strictness

`preset` and `strictness` are independent:

```
preset='full'         +  strictness='monitor-only'  =  recognize many bots, block none
preset='minimal'      +  strictness='normal'        =  standard defense (recommended)
preset='no-ai'        +  strictness='strict'        =  no AI blocks, max defense otherwise
preset='custom'       +  strictness='normal'        =  your bots + standard defense
preset='eu-only'      +  strictness='strict'        =  EU focus + max defense
```

You can combine them freely. They're not mutually exclusive.

---

## Custom Bot Definitions

To define your own bots, create `config/bb_registry.php` alongside `config/bb_config.php`. Format:

```php
<?php
return [
    'preset' => 'custom',    // start from empty registry

    // === Custom bot definitions ===
    'additions' => [
        'my_internal_search' => [
            'name'                => 'My Internal Search Bot',
            'user_agent_patterns' => ['MyBot', 'MyBot/1.0'],
            'category'            => 'search_engine',
            'host_patterns'       => ['bot.example.com'],
            'ip_ranges'           => ['10.0.0.0/8'],
            'verify_dns'          => true,
            'dns_suffixes'        => ['example.com'],
            'default_action'      => 'allow',
            'description'         => 'Our internal search indexer',
        ],
    ],
];
```

The full schema for bot definitions is in `CONFIGURATION.md` under "Custom Bot Schema".

### Combining with a preset

You can use any preset as the base AND add custom bots:

```php
return [
    'preset' => 'minimal',    // start from the 30 most common bots

    // Add your own on top
    'additions' => [
        'my_bot' => [/* ... */],
    ],
];
```

Your custom bots are merged on top of the preset, with your definitions winning on conflict.

### Excluding specific bots

You can also exclude specific bots from a preset:

```php
return [
    'preset'       => 'full',
    'exclude_bots' => ['petal', 'brightdata'],    // don't recognize these
];
```

Or exclude entire categories:

```php
return [
    'preset'              => 'full',
    'exclude_categories'  => ['seo_crawler'],     // don't recognize any SEO crawlers
];
```

Or whitelist only specific bots from a preset:

```php
return [
    'preset'           => 'verified-only',
    'keep_bots'        => ['googlebot', 'bingbot', 'gptbot'],  // only these three
];
```

The full filter precedence (apply order) is:

1. Load preset (or empty for `human-only` / `custom`)
2. Apply `exclude_categories` (remove whole categories)
3. Apply `include_categories` (re-add, overrides exclude)
4. Apply `exclude_bots` (remove specific bots)
5. Apply `keep_bots` (whitelist — only these bots pass)
6. Merge `additions` (custom bots on top)

---

## What About Strictness's Effect on Presets?

`strictness` doesn't change which bots are recognized — that's `preset`'s job. But it does change how unrecognized bots are handled:

| Strictness | Behavior toward unrecognized requests |
|---|---|
| `monitor-only` | Logged. Not blocked. |
| `normal` | Logged. Not blocked unless obvious attack. |
| `strict` | Logged. Unverified AI bots specifically blocked. Unverified search engines flagged. |

So if you use `preset='human-only'` (no bots recognized) at `strictness='strict'`, you'll still see heavy blocking — because no bots match, so nothing gets the "verified" pass that allows search engines and AI crawlers through.

---

## Performance Characteristics

### Index size

| Preset | Approximate bots | Index lookup time |
|---|---|---|
| `human-only` | 0 | ~0ms |
| `custom` (empty) | 0 | ~0ms |
| `minimal` | ~30 | ~1ms |
| `verified-only` | ~50 | ~2ms |
| `no-ai` / `no-seo` | ~80 | ~2.5ms |
| `eu-only` | ~25 | ~1ms |
| `full` | ~100 | ~3ms |

Numbers are approximate and depend on hardware. In absolute terms, even `full` is fast enough for any production website — the difference between 1ms and 3ms per request is rarely the bottleneck.

### Memory

The bot registry is loaded once per process. Index sizes:

| Preset | Approximate memory |
|---|---|
| `minimal` | ~500KB |
| `full` | ~2MB |

For typical PHP process memory budgets (32MB-128MB), this is negligible.

---

## Common Misconceptions

### "More presets = more security"

Not directly. `preset` determines what gets **recognized**, but `strictness` determines what gets **blocked**. A `preset='full'` + `strictness='monitor-only'` configuration recognizes every bot in the registry but blocks none of them. You need both knobs in combination.

### "minimal means I'm not protected from bots"

Wrong. `minimal` covers all the bots you're likely to see. Bots not in the `minimal` preset are mostly regional variants, niche AI crawlers, and obscure monitoring tools. The vast majority of bot traffic on any given site comes from the ~30 bots in `minimal`.

### "I should pick full just to be safe"

Unnecessary for most sites. `minimal` is faster and covers the common cases. Only pick `full` if you have a specific reason (operating in multiple regions, seeing unidentified traffic).

### "human-only disables BadBehaviour"

No. `human-only` only means no bots are UA-matched. All other detection (blacklist, rate limiting, fingerprinting, custom rules, cloud IP allowlisting via static ranges) still works.

### "I need to define every bot in bb_registry.php"

Only if you use `preset='custom'`. For all other presets, the registry is populated automatically from the shipped definitions. You only need `bb_registry.php` if you have bots not in the shipped registry.

### "Cloud infrastructure is always in minimal"

Yes — and it must always be somewhere. Cloud infrastructure IPs (Cloudflare load balancers, AWS ELB health probes, etc.) need to be allowed or your CDN takes you offline. If you use `preset='human-only'` or `preset='custom'`, you must add these explicitly or your site goes down.

---

## See Also

- [STRICTNESS.md](STRICTNESS.md) — How strictness controls enforcement
- [CONFIGURATION.md](CONFIGURATION.md) — Full configuration reference
- [DNS.md](DNS.md) — DNS subsystem details
- [EVALUATION.md](EVALUATION.md) — How to evaluate BadBehaviour before committing
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — Common FP issues and solutions