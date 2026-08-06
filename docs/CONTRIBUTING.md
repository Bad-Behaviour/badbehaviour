# Contributing to Bad Behaviour

Thank you for your interest in contributing! Bad Behaviour 3.0 is a modern PHP 8.2+ library and welcomes contributions in many forms: code, documentation, bug reports, feature requests, translations, and testing.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold it. Report unacceptable behavior to the maintainers (see GitHub repo for contact).

---

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/Bad-Behaviour/badbehaviour/issues) with:

1. **Bad Behaviour version** (e.g., `3.0.0`)
2. **PHP version** (`php -v`)
3. **Adapter in use** (Generic, MediaWiki, WackoWiki, custom)
4. **Steps to reproduce**
5. **Expected vs actual behavior**
6. **Verbose log** (set `verbose => true` in `bb_config.php`, reproduce, attach log entries)

For **security vulnerabilities**, **do not** open a public issue — see [SECURITY.md](SECURITY.md).

### Suggesting Features

Open a [GitHub Discussion](https://github.com/Bad-Behaviour/badbehaviour/discussions) under "Ideas" before opening a PR. This avoids duplicate work and surfaces design considerations early.

### Submitting Pull Requests

1. **Fork** the repo and create a feature branch (`git checkout -b feat/agentic-fingerprinting`)
2. **Write tests** — unit tests under `tests/Unit/`, integration tests under `tests/Integration/`
3. **Match code style** — see below
4. **Run the test suite** locally
5. **Update documentation** — README.md, CONFIGURATION.md, MIGRATION.md as needed
6. **One feature per PR** — keep changes focused
7. **Describe your changes** in the PR description using the template

---

## Development Setup

### Requirements

- PHP 8.2+
- Composer 2+
- Extensions: `json`, `mbstring`, `curl`, `gmp` (IPv6 CIDR)
- PHPUnit 11+

### Clone & Install

```bash
git clone https://github.com/yourname/badbehaviour.git
cd badbehaviour
composer install
```

### Run Tests

```bash
# All tests
vendor/bin/phpunit

# Unit tests only (fast feedback loop)
vendor/bin/phpunit --testsuite Unit

# Integration tests
vendor/bin/phpunit --testsuite Integration

# With coverage
vendor/bin/phpunit --coverage-html build/coverage/html
```

### Static Analysis

```bash
vendor/bin/phpstan analyse src tests --level=5
```

### Code Style

The project uses PSR-12 with tabs (see `.editorconfig`):

```bash
# Check
vendor/bin/phpcs src tests

# Auto-fix
vendor/bin/phpcbf src tests
```

Key conventions:

- **Tabs for indentation** (`.editorconfig`)
- **LF line endings** (`.gitattributes`)
- **Strict types** in every file: `declare(strict_types=1);`
- **Type hints** on all parameters and return values
- **Readonly properties** where possible
- **Enums** for fixed sets of values (see `ResultCode`, `BotCategory`, `BotAction`)
- **Namespaces** follow PSR-4 (`BadBehaviour\` → `src/`)

---

## Project Structure

```
src/
├── Core/              # Orchestrator + interfaces
├── Detection/         # BotDetector, BlacklistDetector, BehavioralDetector,
│                       #   FingerprintDetector, RateLimitDetector, DnsblDetector,
│                       #   ClientHintsDetector, AgenticBehaviorDetector
├── Bot/               # Bot registry + definitions
├── Challenge/         # PoW, hCaptcha, reCAPTCHA, Turnstile
├── Adapter/           # Generic, MediaWiki, WackoWiki
├── Feeds/             # Dynamic IP range feeds (experimental)
├── Util/              # IpUtil, HeaderUtil, UaParser, RequestPackage
├── Exception/         # BlockedException, ChallengeRequiredException,
│                       #   ConfigurationException
├── Configuration.php  # Typed config object
├── BadBehaviour.php   # Main entry point
└── Bootstrap.php      # Single entry point for any PHP app

tests/
├── Unit/              # Isolated unit tests
└── Integration/       # Adapter + pipeline tests

config/
├── bb_config.php      # PHP-array configuration
├── bb_config.example.php  # Documented example
└── bb_whitelist.conf  # INI whitelist

bin/
└── update-ip-ranges.php  # Cron script for dynamic IP feeds
```

---

## Architecture Guidelines

### Adding a new Detector

Detectors live in `src/Detection/` and implement a consistent pattern:

```php
namespace BadBehaviour\Detection;

use BadBehaviour\Configuration;
use BadBehaviour\Util\RequestPackage;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Core\Interfaces\AdapterInterface;

class MyDetector
{
    private Configuration $config;
    private ?AdapterInterface $adapter = null;

    public function __construct(Configuration $config, ?AdapterInterface $adapter = null)
    {
        $this->config = $config;
        $this->adapter = $adapter;
    }

    public function detect(RequestPackage $package): ?Result
    {
        // Opt-in check — detectors MUST respect the config flag
        if (!$this->config->my_detector_enabled) {
            return null;
        }

        // Return null if request is allowed
        // Return Result::block(...) or Result::challenge(...) if blocked
        return null;
    }
}
```

Then:

1. Add `my_detector_enabled` (or similar) to `Configuration::__construct` + `get_defaults()`
2. Wire the detector into `BadBehaviour::detect()` pipeline
3. Add unit tests under `tests/Unit/Detection/MyDetectorTest.php`
4. Update `docs/CONFIGURATION.md` with the new setting
5. Add to the [Configuration Profiles](docs/CONFIGURATION.md#configuration-profiles-recommended-starting-point) if applicable

### Adding a new Bot

Bots live in `src/Bot/Registry/DefaultRegistry.php` as `BotDefinition` objects:

```php
'yourbot' => new BotDefinition(
    id: 'yourbot',
    name: 'YourBot',
    user_agent_patterns: ['YourBot', 'YourBot/2.0'],
    host_patterns: ['yourbot.example.com'],
    ip_ranges: ['203.0.113.0/24'],
    verify_dns: true,
    dns_suffixes: ['yourbot.example.com'],
    category: BotCategory::SEARCH_ENGINE,
    robots_txt_token: 'YourBot',
    default_action: BotAction::ALLOW,
),
```

Categories: `SEARCH_ENGINE`, `AI_CRAWLER`, `SOCIAL_CRAWLER`, `SEO_CRAWLER`, `ARCHIVE_CRAWLER`, `MONITORING`, `MALICIOUS`.

Default actions: `ALLOW`, `CHALLENGE`, `BLOCK`, `LOG_ONLY`.

### Adding a new IP Feed

Feeds live in `src/Feeds/Adapters/` and implement `IpFeedInterface`. Either extend `AbstractJsonFeed` or `PlainTextFeed`, or implement the interface directly.

Then register the feed in `src/Feeds/FeedRegistry.php::__construct()`.

**Important**: New feeds are **experimental** — they must be tested in isolation, handle stale cache gracefully, and survive vendor feed shape changes.

### Adding a new Challenge Provider

Challenges live in `src/Challenge/` and implement `ChallengeInterface`. See `BuiltinChallenge`, `RecaptchaChallenge`, `HCaptchaChallenge`, `TurnstileChallenge` for reference.

---

## Documentation Standards

- **All public API must be documented** — at minimum, docblock with `@param`, `@return`, and a one-line summary
- **All new settings must be added** to `CONFIGURATION.md` (per-setting reference) and considered for the Configuration Profiles (Default/Medium/Strict)
- **Breaking changes** must be documented in `CHANGELOG.md` under the next major version
- **Wiki pages** (`/wiki`) on GitHub should mirror major repo docs

---

## Release Process

Releases are managed by maintainers. The process:

1. Update `CHANGELOG.md` — move `[Unreleased]` items to a new versioned section
2. Bump version in `composer.json` and any other version constants
3. Tag the release (`git tag -s v3.x.y`)
4. Push the tag — CI publishes to Packagist

### Versioning

- **Patch** (3.0.x): bug fixes, no config changes
- **Minor** (3.x.0): new optional features, opt-in only, no breaking changes
- **Major** (x.0.0): breaking config or interface changes

---

## Testing Strategy

### Unit Tests

Each class should have a unit test:

- `tests/Unit/Detection/FooDetectorTest.php` for `src/Detection/FooDetector.php`
- Mock dependencies (`AdapterInterface`, `CacheInterface`)
- Cover happy path + at least 2 failure modes per detector

### Integration Tests

`tests/Integration/` covers:

- Full `BadBehaviour::run_test_package()` flow
- Adapter integration (where feasible)
- Real-world request shapes (AJAX, JSON, multipart, traditional form)

### Test Coverage Targets

- **Core**: ≥ 90%
- **Detectors**: ≥ 85% per class
- **Adapters**: ≥ 70% (some paths require host environment)

---

## Security

For security issues, see [SECURITY.md](SECURITY.md). **Do not** open public GitHub issues for security vulnerabilities.

---

## License

By contributing, you agree that your contributions will be licensed under the [GNU Lesser General Public License v3.0 or later](https://www.gnu.org/licenses/lgpl-3.0.html) — the same license as the project.

---

## Questions?

- [GitHub Discussions](https://github.com/Bad-Behaviour/badbehaviour/discussions) — design questions, ideas
- [GitHub Issues](https://github.com/Bad-Behaviour/badbehaviour/issues) — bug reports
- [Wiki](https://github.com/Bad-Behaviour/badbehaviour/wiki) — user-facing documentation

Thank you for contributing! 🎉