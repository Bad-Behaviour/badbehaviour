# BadBehaviour 3.0 — Evaluating Before Committing

## The Problem This Solves

You install BadBehaviour, pick a strictness level, and within hours you get a support ticket: "Your site blocked me." You dig in, find the ticket is from a real customer, disable BadBehaviour, and conclude "bot blockers are broken."

This document describes a **safe evaluation workflow** that catches false positives BEFORE you commit to enforcement.

---

## The Core Principle

> **Never enforce what you haven't observed.**

BadBehaviour defaults to a posture where everything is logged but only obvious attacks are blocked. You run it that way for a period, examine what was logged, and only then decide whether to escalate enforcement. The library gives you visibility first, enforcement second.

This means a misconfigured or over-aggressive BadBehaviour cannot cause customer-facing damage during evaluation.

---

## The 7-Day Evaluation Workflow

### Day 0: Install

Install BadBehaviour with **explicit evaluation settings**:

```php
// config/bb_config.php
return [
    'preset'     => 'minimal',
    'strictness' => 'monitor-only',
    'logging'    => true,
];
```

What this does:
- **Logging is on** — every request that BadBehaviour looks at is recorded
- **Monitor-only strictness** — only obvious attacks (raw XSS, empty UA, obvious SQLi) are blocked
- **Minimal preset** — recognizes ~30 common bots but doesn't act on them

At this stage, BadBehaviour is **observing** your traffic. Real users are unaffected. Real attackers are partially deflected (the obvious-attack filter still works). You are gathering data.

### Day 1-2: Verify the System Works

Within 48 hours, you should see entries in your log table. Check:

```sql
SELECT COUNT(*) FROM bad_behaviour;
SELECT date, ip, user_agent, status_code, status_message
FROM bad_behaviour
ORDER BY date DESC
LIMIT 20;
```

You should see traffic that includes:
- Real browsers with valid UAs (status_code: `allowed`)
- Bots matching your registry (status_code: `allowed` with bot_category populated)
- Empty or short UAs (status_code: `blocked.malicious_ua`)
- Obvious attack patterns (status_code: `blocked.attack_pattern`)

If you see NOTHING in the log:
- The `bad_behaviour` table wasn't created — check `bin/install-bb.php`
- You're on the static-resource skip path — check `performance.skip_paths`
- The log is being filtered — check `logging.verbose` (set `true` to log everything)

### Day 3-5: Examine What Would Be Blocked

The key insight: at `strictness='monitor-only'`, almost nothing is blocked. But you can simulate what `normal` or `strict` would do by querying the log table for entries that WOULD have been blocked at higher strictness levels.

#### Simulate `strictness='normal'`

At normal strictness, additional things would be blocked:
- DNS-unverified bots claiming to be Google/Bing/etc.
- Requests exceeding 1000/hour from a single IP
- Requests exceeding 60/minute from a single IP

Check for legitimate traffic that would be affected:

```sql
-- IPs that would hit the global rate limit (1000/hour)
SELECT ip, COUNT(*) AS hits, MIN(date) AS first_seen, MAX(date) AS last_seen
FROM bad_behaviour
WHERE date > DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY ip
HAVING COUNT(*) > 1000;

-- IPs that would hit the per-minute rate limit (60/min)
SELECT ip, COUNT(*) AS hits
FROM bad_behaviour
WHERE date > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
GROUP BY ip
HAVING COUNT(*) > 60;

-- Bots that didn't pass DNS verification (would be logged but not blocked at normal)
SELECT date, ip, user_agent, bot_category, bot_verified, status_message
FROM bad_behaviour
WHERE bot_category IS NOT NULL
  AND bot_verified = 0
ORDER BY date DESC
LIMIT 50;
```

Look for:
- **Corporate NAT IPs**: A single IP with hundreds of users behind it (they'll all look like the same IP to rate limiters)
- **Mobile carrier IPs**: Same — many users behind one IP
- **Legitimate bots that fail DNS**: Some real bots (regional search engines, in-house tools) may not pass DNS verification

#### Simulate `strictness='strict'`

At strict, additional things would happen:
- Forward DNS confirmation (catches PTR spoofers, may FP on IPv6-only bots)
- DNSBL lookups (Spamhaus, etc.)
- Behavioral analysis (rotating UAs, rapid requests — can FP on shared NAT)
- Client Hints validation (only Chromium browsers send hints)
- Unverified AI bots BLOCKED

Check for legitimate traffic that would be affected:

```sql
-- IPv6 clients (forward-confirm may FP these)
SELECT date, ip, user_agent
FROM bad_behaviour
WHERE ip LIKE '%:%'  -- IPv6 contains colons
  AND status_code = 'allowed'
ORDER BY date DESC
LIMIT 50;

-- Firefox/Safari users (Client Hints validation would flag them)
SELECT date, ip, user_agent
FROM bad_behaviour
WHERE user_agent LIKE '%Firefox%'
   OR user_agent LIKE '%Safari%'
   OR user_agent LIKE '%Applebot%'
GROUP BY ip
ORDER BY date DESC;

-- Shared NAT IPs (high user count, rotating UAs)
SELECT ip, COUNT(DISTINCT user_agent) AS distinct_uas, COUNT(*) AS total_requests
FROM bad_behaviour
WHERE date > DATE_SUB(NOW(), INTERVAL 1 DAY)
GROUP BY ip
HAVING distinct_uas > 5
ORDER BY distinct_uas DESC;
```

Look for:
- **IPv6 traffic**: If you have significant IPv6 traffic, forward-confirm is risky
- **Non-Chromium browsers**: Firefox, Safari users would be flagged
- **Corporate / mobile / VPN IPs**: Many distinct UAs from one IP

### Day 6-7: Make a Decision

Based on what you found, choose your production posture:

#### If everything looked clean

You saw no legitimate traffic in the "would be blocked at higher strictness" queries. Escalate:

```php
return [
    'preset'     => 'minimal',
    'strictness' => 'normal',     // safe to enforce
];
```

#### If you saw legitimate traffic that would be blocked

Keep `monitor-only` or use `normal` with specific overrides:

```php
return [
    'preset'     => 'minimal',
    'strictness' => 'normal',
    'dns_verification' => [
        'enabled' => false,    // if your CDN already does this
    ],
    // Or specifically exclude problematic patterns:
    'custom_rules' => [
        [
            'id'     => 'allow-corporate-nat',
            'type'   => 'ip',
            'value'  => ['203.0.113.0/24'],  // your corporate NAT
            'action' => 'allow',
        ],
    ],
];
```

#### If you saw actual attacks

If your log table shows entries like:

```sql
SELECT date, ip, user_agent, status_code, status_message
FROM bad_behaviour
WHERE status_code LIKE 'blocked.%'
ORDER BY date DESC
LIMIT 20;
```

And the entries are genuine attacks (not false positives), escalate:

```php
return [
    'preset'     => 'full',        // broader bot coverage
    'strictness' => 'strict',      // maximum defense
];
```

But continue to monitor for false positives.

---

## Common False Positives to Watch For

These are the most common legitimate-traffic patterns that bot blockers get wrong:

### 1. Mobile carrier NAT IPs

A single mobile carrier IP can represent thousands of users, each with their own User-Agent and behavior pattern.

**What it looks like in logs:**
```sql
SELECT ip, COUNT(DISTINCT user_agent) AS uas
FROM bad_behaviour
WHERE date > DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY ip
HAVING uas > 10
ORDER BY uas DESC;
```

**Mitigation:** Whitelist the carrier's IP range, or disable behavioral analysis.

### 2. Corporate networks behind proxy

Employees behind a corporate proxy all share one egress IP. They browse different sites, use different applications, behave differently — looks like a botnet.

**What it looks like in logs:** Same query as above.

**Mitigation:** Whitelist corporate egress IPs, or disable behavioral analysis.

### 3. IPv6-only legitimate bots

Some bots (especially regional search engines) operate exclusively over IPv6. Forward DNS confirmation may flag them because IPv6 reverse DNS is inconsistently configured.

**What it looks like in logs:**
```sql
SELECT date, ip, user_agent
FROM bad_behaviour
WHERE ip LIKE '%:%'  -- IPv6
  AND bot_category IS NOT NULL
ORDER BY date DESC;
```

**Mitigation:** Keep `dns_verification.require_forward_confirm => false`, or accept the FP risk.

### 4. Firefox / Safari / mobile browsers

Only Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi) send Client Hints headers. Client Hints validation at `strictness='strict'` flags everyone else.

**What it looks like in logs:**
```sql
SELECT user_agent, COUNT(*) AS hits
FROM bad_behaviour
WHERE date > DATE_SUB(NOW(), INTERVAL 1 DAY)
  AND status_code = 'allowed'
GROUP BY user_agent
ORDER BY hits DESC
LIMIT 20;
```

**Mitigation:** Disable Client Hints validation explicitly, or stay at `strictness='normal'`.

### 5. Link previewers and embedders

Slack, Twitter, Facebook, Discord, Telegram, WhatsApp, etc. all fetch URLs to generate link previews. They appear as bots with rotating UAs (each service has multiple UA variants).

**What it looks like:** UA matches social_crawler category, IP is the social service's IP range.

**Mitigation:** These are typically already whitelisted by the social_crawler category default action. Verify with your registry settings.

### 6. Monitoring services you actually use

UptimeRobot, Pingdom, StatusCake, Lighthouse, your CI pipeline, etc. — they all send HEAD or GET requests at regular intervals.

**What it looks like:** Regular intervals from same IP, HEAD method, monitoring UA.

**Mitigation:** Cloud infrastructure IPs are auto-allowed. Personal monitoring services should be added to your whitelist.

---

## Logging Levels

BadBehaviour logs at two granularities:

### Standard logging (default)

```php
'logging' => true,
'verbose' => false,
```

Logs only:
- Blocked requests (always)
- Challenged requests (always)
- Allowed requests with bot_category populated (i.e., recognized bots)

Human users browsing normally are NOT logged. This keeps the table small.

### Verbose logging

```php
'logging' => true,
'verbose' => true,
```

Logs every request BadBehaviour looks at. The table fills up fast. Use this for:
- Short debugging sessions (set `verbose=true` for 1 hour, then back to false)
- Post-incident analysis (set after detecting an attack, leave for a day)

### No logging

```php
'logging' => false,
```

Logs nothing. The library still blocks, but you have no visibility. Don't use this in production.

---

## Interpreting the Log Table

Key columns and what they mean:

| Column | Meaning |
|---|---|
| `date` | Request timestamp |
| `ip` | Client IP (post-proxy if reverse_proxy enabled) |
| `user_agent` | Full UA string |
| `status_code` | What BadBehaviour did: `allowed`, `blocked.bot`, `blocked.attack_pattern`, `challenge.required`, etc. |
| `status_message` | Human-readable reason for the status |
| `support_key` | Unique identifier for this block — give to users who contact you about being blocked |
| `bot_category` | If recognized as a bot: search_engine, ai_crawler, social_crawler, etc. |
| `bot_verified` | If bot: was it DNS-verified? 1=yes, 0=no, NULL=not a recognized bot |
| `ja3` | TLS fingerprint (if available) |
| `asn` | Autonomous System Number (if GeoIP enabled) |
| `country` | Country code (if GeoIP enabled) |
| `request_time_ms` | How long BadBehaviour took to evaluate this request |

### Useful queries

**Top blocked IPs:**
```sql
SELECT ip, COUNT(*) AS blocks, MAX(date) AS last_blocked
FROM bad_behaviour
WHERE status_code LIKE 'blocked.%'
  AND date > DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY ip
ORDER BY blocks DESC
LIMIT 20;
```

**Most common UA patterns among blocked:**
```sql
SELECT user_agent, COUNT(*) AS blocks
FROM bad_behaviour
WHERE status_code LIKE 'blocked.%'
  AND date > DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY user_agent
ORDER BY blocks DESC
LIMIT 20;
```

**False positive check (blocked UAs that look like real browsers):**
```sql
SELECT date, ip, user_agent, status_code, status_message, support_key
FROM bad_behaviour
WHERE status_code LIKE 'blocked.%'
  AND date > DATE_SUB(NOW(), INTERVAL 7 DAY)
  AND (user_agent LIKE '%Mozilla%' OR user_agent LIKE '%Chrome%' OR user_agent LIKE '%Safari%')
ORDER BY date DESC;
```

If you see real-browser UAs in this result, you have a false positive problem. Investigate by:
1. Looking at the IP — is it a known NAT range?
2. Looking at the status_message — which detector flagged it?
3. Looking at the request_uri — was there something attack-like in the URL?

---

## Setting Up the Log Table

If the table doesn't exist, BadBehaviour will try to create it on first use (via `install_once()`). If that fails (permissions, etc.), it falls back to logging-only mode.

You can also create the table manually:

```bash
php bin/install-bb.php
```

Or run the SQL schema directly. See `INSTALL.md` for the schema.

---

## Going to Production

After evaluation, your production config should look like one of these:

### Conservative (recommended first production deploy)

```php
return [
    'preset'     => 'minimal',
    'strictness' => 'normal',
    'logging'    => true,
];
```

Watch the log table for the first week of production traffic. Look for:
- Support tickets about being blocked (most legitimate users will contact you)
- False positives in the log table (real-browser UAs with `blocked.*` status)
- Genuine attacks being deflected (entries with `blocked.attack_pattern`)

### After a clean week

If you saw no false positives, consider escalating:

```php
return [
    'preset'     => 'minimal',
    'strictness' => 'strict',      // only if you have evidence of need
];
```

### If you have a specific attack vector to defend

If your log analysis shows you're being targeted by AI training scrapers:

```php
return [
    'preset'     => 'no-ai',       // exclude AI bots entirely
    'strictness' => 'strict',
];
```

Or by SEO crawlers:

```php
return [
    'preset'     => 'no-seo',
    'strictness' => 'strict',
];
```

---

## Evaluation Checklist

Before deploying to production with enforcement enabled, confirm:

- [ ] Log table is populating correctly
- [ ] No real-browser UAs appear with `blocked.*` status (during monitor-only period)
- [ ] No IPs from your known user base (corporate, mobile carriers, etc.) appear with `blocked.*` status
- [ ] Cloud infrastructure IPs (Cloudflare, AWS ELB, etc.) are appearing with `allowed` status
- [ ] Genuine attacks are being logged (you can see attack patterns in the table)
- [ ] You've decided which strictness level to start with
- [ ] You have a plan for monitoring false positives after going to enforcement

---

## See Also

- [STRICTNESS.md](STRICTNESS.md) — What each strictness level enables
- [PRESETS.md](PRESETS.md) — Choosing the right bot registry
- [CONFIGURATION.md](CONFIGURATION.md) — Full configuration reference
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — Solving specific problems
- [DNS.md](DNS.md) — DNS subsystem details