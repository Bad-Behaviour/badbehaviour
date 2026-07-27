# Migration Guide: Bad Behaviour 2.x → 3.0

## Breaking Changes

### 1. Configuration Format
**Old:** Flat `settings.ini` with string values
**New:** Structured INI with sections and typed values

```ini
; Old
httpbl_key = "abc123"
strict = 1

; New
[httpbl]
key = "abc123"

[core]
strict = true
```

### 2. Entry Points
**Old:** Multiple entry files (`bad-behaviour-generic.php`, etc.) with global state
**New:** Single `Bootstrap.php` with functional API

```php
// Old
require_once 'bad-behaviour-generic.php';
// ... globals set ...

// New
require_once 'vendor/autoload.php';
\BadBehaviour\Bootstrap\run();
```

### 3. Result Codes
**Old:** Hex strings (`'17f4e8c8'`, `'f1182195'`)
**New:** `ResultCode` enum with semantic names

```php
// Old
if ($key === '17f4e8c8') { /* UA blacklist */ }

// New
if ($result->code === ResultCode::BLOCKED_MALICIOUS_UA) { /* ... */ }
```

### 4. Adapter Interface
**Old:** 14 methods, procedural-style
**New:** 18 methods, interface-based with Cache/GeoIP/Logger separation

```php
// Implement these new methods:
- increment_counter()
- get_behavior_profile()
- save_behavior_profile()
- add_to_set() / get_set()
- get_geoip()
- verify_challenge()
- log()
```

### 5. Database Schema
**Old:** `log_id`, `status_key` (hex)
**New:** Normalized columns with semantic names

```sql
-- New columns
`status_code VARCHAR(50)        -- e.g. 'blocked.ai_crawler'
bot_category VARCHAR(32)  -- 'ai_crawler', 'search_engine', etc.
bot_verified BOOLEAN      -- DNS/IP verified
ja3 CHAR(32)              -- TLS fingerprint
h2_hash CHAR(16)          -- HTTP/2 settings hash
header_order_hash CHAR(16)
asn VARCHAR(32)
country CHAR(2)
request_time_ms INT
```

## New Features

### AI Crawler Control
```ini
[ai_crawlers]
allowed[] = "GPTBot"
allowed[] = "ClaudeBot"
allowed[] = "Google-Extended"
block_unverified = true
```

### Rate Limiting
```ini
[rate_limits]
enabled = true
global_requests = 1000
global_window = 3600
per_minute_requests = 60
per_minute_window = 60
```

### Challenge System
```ini
[challenge]
enabled = true
provider = "hcaptcha"  ; builtin, hcaptcha, recaptcha, turnstile
site_key = "your-site-key"
secret_key = "your-secret-key"
```

### GeoIP Blocking
```ini
[geoip]
enabled = true
database_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
blocked_countries[] = "KP"
blocked_countries[] = "IR"
```

## Migration Steps

1. **Backup** your current `settings.ini` and database
2. **Generate new config**: Copy `settings.ini.example` → `settings.ini`
3. **Update adapter**: Implement new interface methods (see `GenericAdapter` for reference)
4. **Migrate database**: Run the new schema (see `get_table_schema()`)
5. **Test**: Run in `BB2_TEST=1` mode first
6. **Deploy**: Monitor logs for false positives

## Compatibility Layer

For gradual migration, a compatibility shim is available:

```php
require_once 'vendor/autoload.php';
use BadBehaviour\Bootstrap;
use BadBehaviour\Compat\LegacyAdapter;

$legacy = new LegacyAdapter($old_settings);
$result = Bootstrap\run($legacy->get_config());
```