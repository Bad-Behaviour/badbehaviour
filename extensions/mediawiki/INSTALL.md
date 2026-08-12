# MediaWiki Installation

## Prerequisites

- MediaWiki 1.35 or later
- PHP 8.1 or later
- BadBehaviour 3.0 installed via Composer

## Install

```bash
cd /path/to/mediawiki

# Install the library (autoloads src/ only, NOT the shim)
composer require bad-behaviour/badbehaviour

# Copy the integration shim into your extension directory
mkdir -p extensions/BadBehaviour
cp vendor/bad-behaviour/badbehaviour/extensions/mediawiki/bad-behaviour-mediawiki.php \
   extensions/BadBehaviour/

# Copy or create the config file
cp vendor/bad-behaviour/badbehaviour/config/bb_config.example.php \
   extensions/BadBehaviour/bb_config.php
chmod 600 extensions/BadBehaviour/bb_config.php
```

Add to `LocalSettings.php`:

```php
wfLoadExtension('BadBehaviour');
require_once "$IP/extensions/BadBehaviour/bad-behaviour-mediawiki.php";

// Optional: enable the debug footer comment
$wgBadBehaviourTimer = true;
```

## Configuration

Edit `extensions/BadBehaviour/bb_config.php`. See
`config/bb_config.example.php` in the package for the full schema.

## Troubleshooting

### "BadBehaviour" doesn't appear on Special:Version

The shim wasn't loaded. Check that:
1. The file was copied to `extensions/BadBehaviour/`
2. The `require_once` line is in `LocalSettings.php`
3. There's no syntax error (check `php -l`)

### All requests are being blocked

You're probably in safe-mode (config missing or invalid). Check:
1. `bb_config.php` is in the path the adapter expects
   (usually `extensions/BadBehaviour/`)
2. The file returns an array (ends with `return [...];`)
3. Run `php bin/diagnose.php` for the full diagnostic report

### The shim loaded in a non-MediaWiki context

The shim guards with `if (!defined('MEDIAWIKI')) return;` so it's a
no-op outside MediaWiki. If you see it executing elsewhere, something
is bypassing the guard.