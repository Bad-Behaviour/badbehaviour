# Bad Behaviour 3.0 - Upgrade Guide

## Breaking Changes

### 1. Configuration Format
- Old: `settings.ini` with flat keys
- New: Structured INI with arrays (see `Config::getExampleSettings()`)

### 2. Adapter Interface
- Added new methods: `increment_counter()`, `get_behavior_profile()`, `add_to_set()`, `get_geoip()`, `verify_challenge()`, `log_event()`
- Existing adapters (MediaWiki, WackoWiki) updated with stub implementations

### 3. Bot Detection Logic
- Completely rewritten using `BotRegistry` and `BotDetector`
- Old `searchengine.inc.php`, `blacklist.inc.php`, `browser.inc.php` deprecated
- New system uses IP ranges, DNS verification, and behavioral analysis

### 4. AI Crawler Support
- New `allowed_ai_crawlers` setting controls which AI bots are permitted
- Tokens: `GPTBot`, `ClaudeBot`, `Google-Extended`, `PerplexityBot`, `CohereBot`, `Meta-ExternalAgent`, `Applebot-Extended`, `YouBot`, `KagiBot`

### 5. Challenge System
- New `BotAction::CHALLENGE` for suspicious but unverified bots
- Supports: Built-in PoW, hCaptcha, reCAPTCHA v3, Cloudflare Turnstile

## Migration Steps

### 1. Update Configuration
```bash
# Backup old settings
cp settings.ini settings.ini.bak

# Generate new settings template
php -r "require 'vendor/autoload.php'; echo \BadBehaviour\Core\Config::getExampleSettings();" > settings.ini.new

# Edit settings.ini.new with your values
mv settings.ini.new settings.ini
```

### 2. Update Database Schema
```sql
-- New columns for enhanced logging
ALTER TABLE bad_behaviour 
  ADD COLUMN bot_category VARCHAR(32) DEFAULT NULL,
  ADD COLUMN bot_verified BOOLEAN DEFAULT FALSE,
  ADD COLUMN ja3_fingerprint CHAR(32) DEFAULT NULL,
  ADD COLUMN header_order_hash CHAR(16) DEFAULT NULL,
  ADD COLUMN asn VARCHAR(32) DEFAULT NULL,
  ADD COLUMN country CHAR(2) DEFAULT NULL;

-- New tables for rate limiting and challenges
CREATE TABLE bb_rate_limits (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    key_hash CHAR(64) NOT NULL,
    window_start INT NOT NULL,
    count INT DEFAULT 1,
    KEY idx_key_window (key_hash, window_start)
);

CREATE TABLE bb_challenges (
    token CHAR(32) PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    issued INT NOT NULL,
    expires INT NOT NULL,
    solved BOOLEAN DEFAULT FALSE,
    KEY idx_ip (ip)
);

CREATE TABLE bb_behavior (
    session_id CHAR(32) PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    user_agent TEXT,
    data JSON NOT NULL,
    updated INT NOT NULL,
    KEY idx_ip (ip)
);
```

### 3. Update Custom Adapters
If you have a custom adapter, implement the new interface methods:

```php
// Minimal stub implementations
public function increment_counter(string $key, int $window): int { return 1; }
public function get_counter(string $key): int { return 0; }
public function get_behavior_profile(string $sessionId): ?array { return null; }
public function save_behavior_profile(string $sessionId, array $profile, int $ttl): bool { return true; }
public function add_to_set(string $key, string $value, int $ttl): bool { return true; }
public function get_set(string $key): array { return []; }
public function get_geoip(string $ip): ?array { return null; }
public function verify_challenge(string $response, string $remoteIp): bool { return false; }
public function log_event(string $level, string $message, array $context = []): void { error_log($message); }
```

### 4. Whitelist Format
New whitelist.ini supports additional sections:

```ini
; IP ranges (CIDR)
[ip]
192.0.2.0/24 = "Test network"
2001:db8::/32 = "Documentation network"

; Exact User-Agent matches
[useragent]
"My Custom Bot/1.0" = "Internal monitoring"

; URL prefixes
[url]
/api/health = "Health checks"
/webhook/ = "Webhook endpoints"

; ASN numbers (requires GeoIP)
[asn]
AS15169 = "Google"
AS13335 = "Cloudflare"

; Country codes (requires GeoIP)
[country]
US = "United States"
CA = "Canada"
```

### 5. Test Before Deploy
```bash
# Run in test mode
BB2_TEST=1 php -r "
require 'bad-behaviour-generic.php';
\$bb = new \BadBehaviour\Core\BadBehaviour(new \BadBehaviour\Core\Adapter\GenericAdapter());
var_dump(\$bb->run());
"
```

## New Features

### AI Crawler Control
```ini
; Allow specific AI crawlers (they must verify via DNS/IP)
allowed_ai_crawlers[] = "GPTBot"
allowed_ai_crawlers[] = "ClaudeBot"
allowed_ai_crawlers[] = "Google-Extended"

; Block unverified AI crawlers (spoofed UAs)
block_unverified_ai = true

; Strict mode: block even verified AI crawlers not in allow list
strict_ai = false
```

### Rate Limiting
```ini
rate_limit_enabled = true
rate_limits[global][requests] = 1000
rate_limits[global][window] = 3600
rate_limits[per_minute][requests] = 60
rate_limits[per_minute][window] = 60
```

### Challenge System
```ini
challenge_enabled = true
challenge_provider = "hcaptcha"  ; or "recaptcha", "turnstile", "builtin"
challenge_site_key = "your-site-key"
challenge_secret_key = "your-secret-key"
```

### GeoIP Blocking
```ini
geoip_enabled = true
geoip_database_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
blocked_countries[] = "KP"
blocked_countries[] = "IR"
```

## Performance Considerations

1. **DNS Verification**: Cached for 1 hour by default. Adjust `dns_cache_ttl`.
2. **Rate Limiting**: Requires persistent storage (Redis/Memcached) for production.
3. **GeoIP**: Load MaxMind DB at startup, not per-request.
4. **Static Files**: Configure `skip_static_extensions` and `skip_static_paths` to avoid processing CSS/JS/images.

## Monitoring

Enable JSON logging for SIEM integration:
```ini
log_destination = "json"
log_file_path = "/var/log/bad-behaviour.json"
log_json_format = true
```

Log format:
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "warning",
  "action": "block",
  "reason": "bot_block_gptbot",
  "ip": "203.0.113.42",
  "ua": "GPTBot/1.0",
  "uri": "/article/123",
  "method": "GET",
  "country": "US",
  "asn": "AS12345",
  "ja3": "771,4865-4867...",
  "header_order": "a1b2c3d4..."
}
```
