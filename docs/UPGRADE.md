```markdown
# Bad Behaviour 3.0 - Upgrade Guide

## Breaking Changes

### 1. Minimum Requirements
- **PHP 8.2+** (was 7.0+)
- Extensions: `json`, `mbstring`, `curl`, `gmp` (for IPv6 CIDR)

### 2. Configuration Format
- **Old**: Flat INI (`strict = true`, `rate_limits_global_requests = 1000`)
- **New**: Structured INI with **dot notation** for nesting
  ```ini
  ; Old (still works but deprecated)
  strict = true
  rate_limits_global_requests = 1000
  
  ; New (preferred)
  strict = true
  rate_limits.global.requests = 1000
  rate_limits.global.window = 3600
  ```
- Parser also accepts: `key[] = value` (arrays), `key = "a, b, c"` (comma-separated)
- All 3.0 features **opt-in** (disabled by default for legacy compatibility)

### 3. Adapter Interface Changes
**New required methods:**
```php
interface AdapterInterface
{
    // Existing (unchanged)
    public function get_settings(): array;
    public function get_whitelist(): array;
    public function get_email(): string;
    public function get_relative_path(): string;
    public function get_table_schema(string $table_name): string|array;
    public function log_request(RequestPackage $package, Result $result): void;
    public function query(string $sql): bool;
    
    // Cache/Rate Limiting (NEW)
    public function increment_counter(string $key, int $window): int;
    public function get_counter(string $key): int;
    public function delete(string $key): bool;
    public function get_behavior_profile(string $session_id): ?array;
    public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool;
    public function add_to_set(string $key, string $value, int $ttl): bool;
    public function get_set(string $key): array;
    
    // GeoIP (NEW)
    public function get_geoip(string $ip): ?array;
    
    // Challenge (NEW)
    public function verify_challenge(string $response, string $remote_ip): bool;
    
    // Logging (NEW)
    public function log(string $level, string $message, array $context = []): void;
}
```

### 4. Result Codes
- **Old**: Hex strings (`'17f4e8c8'`, `'96c0bd29'`)
- **New**: Semantic `ResultCode` enum
  ```php
  ResultCode::ALLOWED                    // 200
  ResultCode::BLOCKED_BOT                // 403
  ResultCode::BLOCKED_AI_CRAWLER         // 403
  ResultCode::BLOCKED_ATTACK_PATTERN     // 403
  ResultCode::BLOCKED_RATE_LIMIT         // 429
  ResultCode::CHALLENGE_REQUIRED         // 403
  // ... see ResultCode enum for full list
  ```
- `ResultCode::from('legacy_hex')` works for backward compatibility

### 5. Database Schema
**New columns** (run migration):
```sql
-- MySQL
ALTER TABLE `prefix_bad_behaviour` 
  ADD COLUMN `status_code` VARCHAR(50) NOT NULL DEFAULT '' AFTER `request_entity`,
  ADD COLUMN `status_message` TEXT AFTER `status_code`,
  ADD COLUMN `support_key` VARCHAR(64) AFTER `status_message`,
  ADD COLUMN `bot_category` VARCHAR(32) AFTER `support_key`,
  ADD COLUMN `bot_verified` BOOLEAN DEFAULT FALSE AFTER `bot_category`,
  ADD COLUMN `ja3` CHAR(32) AFTER `bot_verified`,
  ADD COLUMN `h2_hash` CHAR(16) AFTER `ja3`,
  ADD COLUMN `header_order_hash` CHAR(16) AFTER `h2_hash`,
  ADD COLUMN `asn` VARCHAR(32) AFTER `header_order_hash`,
  ADD COLUMN `country` CHAR(2) AFTER `asn`,
  ADD COLUMN `request_time_ms` INT UNSIGNED AFTER `country`;

-- Add missing indexes for admin panel
ALTER TABLE `prefix_bad_behaviour` 
  ADD INDEX `idx_user_agent_hash` (`user_agent_hash`),
  ADD INDEX `idx_request_uri_hash` (`request_uri_hash`),
  ADD INDEX `idx_status` (`status_code`);

-- SQLite
ALTER TABLE "prefix_bad_behaviour" 
  ADD COLUMN "status_code" VARCHAR(50) NOT NULL DEFAULT '',
  ADD COLUMN "status_message" TEXT,
  ADD COLUMN "support_key" VARCHAR(64),
  ADD COLUMN "bot_category" VARCHAR(32),
  ADD COLUMN "bot_verified" BOOLEAN DEFAULT 0,
  ADD COLUMN "ja3" CHAR(32),
  ADD COLUMN "h2_hash" CHAR(16),
  ADD COLUMN "header_order_hash" CHAR(16),
  ADD COLUMN "asn" VARCHAR(32),
  ADD COLUMN "country" CHAR(2),
  ADD COLUMN "request_time_ms" INTEGER UNSIGNED;

CREATE INDEX IF NOT EXISTS "idx_status" ON "prefix_bad_behaviour" ("status_code");
CREATE INDEX IF NOT EXISTS "idx_user_agent_hash" ON "prefix_bad_behaviour" ("user_agent_hash");
CREATE INDEX IF NOT EXISTS "idx_request_uri_hash" ON "prefix_bad_behaviour" ("request_uri_hash");
```

### 6. Custom Adapters
Update your adapter to implement new interface methods. Minimal stubs:

```php
// Cache/Rate Limiting
public function increment_counter(string $key, int $window): int { return 1; }
public function get_counter(string $key): int { return 0; }
public function delete(string $key): bool { return true; }
public function get_behavior_profile(string $session_id): ?array { return null; }
public function save_behavior_profile(string $session_id, array $profile, int $ttl): bool { return true; }
public function add_to_set(string $key, string $value, int $ttl): bool { return true; }
public function get_set(string $key): array { return []; }

// GeoIP
public function get_geoip(string $ip): ?array { return null; }

// Challenge
public function verify_challenge(string $response, string $remote_ip): bool { return false; }

// Logging
public function log(string $level, string $message, array $context = []): void { 
    error_log("[$level] $message " . json_encode($context)); 
}

// Table schema - return array for SQLite compatibility
public function get_table_schema(string $table_name): array { ... }
```

---

## Migration Steps

### 1. Backup & Update Code
```bash
# Backup
cp -r vendor/badbehaviour vendor/badbehaviour.bak
cp settings.ini settings.ini.bak

# Update via Composer
composer update badbehaviour/badbehaviour
```

### 2. Update Configuration File
```bash
# Rename old file
mv settings.ini settings.ini.v2

# Create new settings.ini with dot notation
cat > settings.ini <<'EOF'
[core]
logging = true
verbose = false
strict = false
offsite_forms = false

; 3.0 features (opt-in)
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
global.requests = 1000
global.window = 3600
per_minute.requests = 60
per_minute.window = 60
post.requests = 30
post.window = 3600
login.requests = 10
login.window = 900
EOF
```

### 3. Run Database Migration
```bash
# MySQL
mysql -u user -p dbname < vendor/badbehaviour/badbehaviour/migrations/mysql_upgrade_3.0.sql

# SQLite
sqlite3 data/wacko.db < vendor/badbehaviour/badbehaviour/migrations/sqlite_upgrade_3.0.sql
```

### 4. Update Legacy Entry Points (if used)
```php
// Old (still works - legacy shims)
require_once 'bad-behaviour-wackowiki.php';

// New (recommended)
require 'vendor/autoload.php';
use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Adapter\WackoWikiAdapter;
use BadBehaviour\Configuration;

$adapter = new WackoWikiAdapter($db);
$config = Configuration::from_array([], $adapter);
$bb = new BadBehaviour($config);
$bb->run();
```

### 5. Whitelist Format (unchanged, but supports new sections)
```ini
[ip]
internal = "10.0.0.0/8"
office = "203.0.113.0/24"

[useragent]
monitoring = "InternalMonitor/1.0"

[url]
health = "/health"
webhook = "/webhook/"

; NEW: ASN and Country (require GeoIP)
[asn]
google = "AS15169"

[country]
us = "US"
de = "DE"
```

### 6. Test Before Deploy
```bash
# Unit tests
vendor/bin/phpunit --testsuite Unit

# Integration tests
vendor/bin/phpunit --testsuite Integration

# Manual test
curl -X POST https://yoursite/src/AddComment \
  -H "Content-Type: application/json" \
  -d '{"ajax_preview":"1","body":"test"}'
# Should return 200 OK (not 403)
```

---

## New Features (All Opt-In)

### AI Crawler Control
```ini
[ai_crawlers]
allowed[] = "GPTBot"
allowed[] = "ClaudeBot"
allowed[] = "Google-Extended"
block_unverified_ai = true   ; Block spoofed AI bots
strict_ai = false            ; Block even verified unallowed AI
```

**Verified tokens:** `GPTBot`, `ClaudeBot`, `Google-Extended`, `PerplexityBot`, `Meta-ExternalAgent`, `Applebot-Extended`, `CCBot`, `ia_archiver`

### Rate Limiting
```ini
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
- Auto-detects login endpoints via `/(login|signin|auth|password)/i`
- Storage via adapter (`increment_counter`, `get_counter`)

### Challenge System
```ini
[challenge]
enabled = true
provider = "hcaptcha"        ; builtin, hcaptcha, recaptcha, turnstile
site_key = "your-site-key"
secret_key = "your-secret-key"
recaptcha_min_score = 0.5    ; reCAPTCHA v3 only
```
- `builtin` = Zero-dependency Proof-of-Work (no external deps)

### Fingerprinting (Opt-In, Config-Only)
```ini
[fingerprints]
bad_ja3[] = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
bad_h2[] = "a1b2c3d4e5f67890"
bot_header_orders[] = "a1b2c3d4e5f67890"
```
- Only blocks **known bad** fingerprints from config
- Zero false positives by design

### GeoIP Blocking
```ini
[geoip]
enabled = true
database_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
blocked_countries[] = "KP"
blocked_countries[] = "IR"
blocked_asns[] = "AS12345"
```

### Static Asset Skipping (Performance)
```ini
[performance]
skip_extensions[] = "css"
skip_extensions[] = "js"
skip_paths[] = "/static/"
skip_paths[] = "/assets/"
```
- Checked **first** — bypasses all detection

---

## Legacy Compatibility (Default Behavior)

| Feature | 2.x | 3.0 Default |
|---------|-----|-------------|
| Missing `Accept` header | Block browser-like UAs | **Only traditional page loads** |
| POST body inspection | Trackbacks + `document.write` | **Only `application/x-www-form-urlencoded`** |
| `curl`/`wget`/HTTP libs | Allowed | **Allowed** (`http_tool` category) |
| JSON body inspection | Never | **Disabled** (`inspect_json_body = false`) |
| Multipart inspection | Never | **Disabled** (`inspect_multipart_body = false`) |
| Strict header checks | Opt-in | **Disabled** (`strict = false`) |
| Verified search engines | Bypass all | **Bypass all** |

**Result**: Drop-in upgrade for most sites — no config changes needed.

---

## Admin Panel (WackoWiki)

### Updated Module
- `src/admin/module/tool_badbehaviour.php` updated for 3.0
- Uses `ResultCode` enum + legacy hex code map
- All 3.0 settings exposed in UI with risk labels
- Column `status_key` → `status_code` (semantic values)

### Language Strings
Add to `lang/en.php`:
```php
'BbEnableBehavioral'     => 'Enable behavioral analysis',
'BbEnableFingerprinting' => 'Enable TLS/HTTP2 fingerprinting',
'BbInspectJson'          => 'Inspect JSON request bodies',
'BbInspectMultipart'     => 'Inspect multipart bodies',
'BbBlockUnverifiedAi'    => 'Block unverified AI crawlers',
'BbStrictAi'             => 'Strict AI mode',
'BbAllowedAiCrawlers'    => 'Allowed AI crawler tokens',
'BbDnsblEnabled'         => 'Enable DNSBL checks',
'BbRateLimitEnabled'     => 'Enable rate limiting',
'BbChallengeEnabled'     => 'Enable challenges',
'BbGeoipEnabled'         => 'Enable GeoIP lookups',
```

---

## Performance Notes

1. **DNS Verification**: Cached 1 hour per IP
2. **Rate Limiting**: Requires persistent adapter storage (Redis/DB) for production
3. **GeoIP**: Load MaxMind DB once at startup
4. **Static Files**: Configure `skip_static_extensions`/`skip_paths` to avoid processing CSS/JS/images
5. **Logging**: Only blocked requests logged by default (`verbose = false`)

---

## Monitoring

### JSON Logging (SIEM)
```ini
[logging]
log_destination = "json"
log_file_path = "/var/log/bad-behaviour.json"
log_json_format = true
```

**Log format:**
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "warning",
  "action": "block",
  "code": "blocked.attack_pattern",
  "ip": "203.0.113.42",
  "ua": "sqlmap/1.0",
  "uri": "/article?id=1",
  "method": "GET",
  "country": "US",
  "asn": "AS12345",
  "support_key": "c000-0201-acf1"
}
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `status_key` column not found | Run DB migration (see step 3) |
| AJAX requests blocked | Ensure `inspect_json_body = false` (default) |
| File uploads blocked | Ensure `inspect_multipart_body = false` (default) |
| `curl`/`wget` blocked | Update UA parser (fixed in 3.0.1+) |
| Config keys undefined | Run `Configuration::from_array()` with `ConfigUtil::merge_with_defaults()` |

---

## Rollback Plan

```bash
# 1. Restore code
rm -rf vendor/badbehaviour
mv vendor/badbehaviour.bak vendor/badbehaviour

# 2. Restore config
mv settings.ini.bak settings.ini

# 3. Restore DB (if migrated)
# Restore from backup or drop new columns
```

---

## Support

- [Migration Issues](https://github.com/Bad-Behaviour/badbehaviour/issues)
- [Configuration Reference](CONFIGURATION.md)
- [Legacy Entry Points](README.md#option-3-legacy-drop-in-usage)
```