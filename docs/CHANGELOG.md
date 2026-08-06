# Changelog

All notable changes to Bad Behaviour will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **DNS verification is now synchronous.** Bots whose `BotDefinition` has
  `verify_dns: true` are verified via DNS on the FIRST request from any IP,
  not deferred to `register_shutdown_function()`. The previous behavior
  caused a false-positive window where bots were blocked on their first
  request because DNS verification had not yet completed. Real search
  engines retry and would succeed on subsequent requests, but regional,
  academic, and AI crawlers often do not retry — resulting in permanent
  blocks for legitimate bots.

  Latency cost: 40–300ms on first request per `(IP, suffix)` tuple,
  zero overhead on cached requests. Bounded by a configurable timeout
  (`dns_verification.timeout_ms`, default 300ms).

- **DNS verification cache key uses binary IP form.** New format:
  `bb:dns_verify:{bin2hex(inet_pton($ip))}:{suffix}`. This normalizes
  IPv6 canonical forms (e.g., `2a03:2880::1` and `2a03:2880:0:0:0:0:0:1`
  share a cache entry) and avoids escaping issues in cache backends.

- **`enable_dynamic_ip_ranges` (flat boolean) is replaced by the
  `dynamic_ip_ranges` array.** New shape:
  ```php
  'dynamic_ip_ranges' => [
      'enabled' => false,
      'ttl'     => 86400,
      'feeds'   => ['aws', 'cloudflare', 'fastly', 'gcp'],
  ],
  ```
  The old flat key is **not** honored — strict restructure, no back-compat.

### Added

- New top-level config block `dns_verification`:
  - `enabled` (default: `true`) — kill switch for DNS verification
  - `timeout_ms` (default: `300`) — soft timeout per verification
  - `require_forward_confirm` (default: `false`) — opt-in strict mode
    that requires forward-confirm in addition to reverse+suffix match
  - `positive_ttl` (default: `604800` = 7 days) — cache TTL for verified bots
  - `negative_ttl` (default: `86400` = 1 day) — cache TTL for failed verifications
  - Shorter TTL for negative results bounds cache size for spoofed scanners
    and avoids permanent blocks if a bot fixes its DNS

- New `BotDetector::set_dns_resolvers()` method for testability. Production
  code should not call this; it exists so unit tests can inject deterministic
  DNS resolvers without relying on network or `/etc/hosts`.

- New `Configuration` properties: `dns_verification_enabled`,
  `dns_verification_timeout_ms`, `dns_verification_require_forward_confirm`,
  `dns_verification_positive_ttl`, `dns_verification_negative_ttl`,
  `dynamic_ip_ranges_enabled`, `dynamic_ip_ranges_ttl`,
  `dynamic_ip_ranges_feeds`.

### Removed

- `BotDetector::schedule_background_dns_lookup()` — replaced by synchronous
  verification. Pre-release codebase, no legacy support needed.

- `Configuration::$enable_dynamic_ip_ranges` — replaced by the
  `dynamic_ip_ranges` array.

### Fixed

- False positives on first encounter with DNS-verifiable bots (Bingbot,
  Sogou Spider, Naver Yeti, Amazonbot, YouBot, and others) where the IP
  was not in the static range list. Synchronous DNS verification now
  succeeds on the first request rather than blocking it.

- IPv6 normalization in DNS cache keys (was: text comparison of IPv6
  strings; now: binary form via `inet_pton`).

### Notes for Operators

- If you previously had `enable_dynamic_ip_ranges => false` in your config,
  migrate to `dynamic_ip_ranges.enabled => false`. Other keys (TTL, feeds)
  now have explicit defaults if omitted.

- Default `dns_verification.enabled = true` means the first request from
  any DNS-verifiable bot costs 40–300ms. If you have a high-traffic site
  where this is unacceptable, set `enabled => false` — bots will fall
  through to the next defense (typically CHALLENGE rather than BLOCK).

- If you observe PTR-spoofing abuse (attackers setting their PTR record
  to a known bot hostname), set `dns_verification.require_forward_confirm
  => true`. Note this may false-positive on IPv6-only bots
  (Meta-ExternalAgent, Meta-ExternalFetcher) — add them to
  `ai_crawlers.allowed` if so.

### Known Limitations (out of scope for this change)

- Some bots in the registry have `dns_suffix` values that don't match
  all of their actual reverse-DNS outputs (e.g., `meta_ai` with
  `dns_suffix: 'facebook.com'` but EC2 IPs reverse to
  `compute-1.amazonaws.com`). Follow-up commit will extend `BotDefinition`
  with a `dns_suffixes: array` field and update affected entries.