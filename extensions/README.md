# Integration Shims

This directory contains **integration shims** — small glue files that
adapt BadBehaviour to specific host applications. They are application
code, not library code, so they live outside `src/` and are **not
autoloaded by Composer**.

## Why?

BadBehaviour is a library; it provides detection primitives. Each host
application (MediaWiki, WackoWiki, WordPress, custom PHP, ...) needs a
different integration point:

- **MediaWiki**: requires `$wgExtensionFunctions` / `$wgHooks` registration
- **WackoWiki**: inline directly in `index.php`
- **Generic PHP**: depends on the host framework

Composer autoload would either skip these (worse — the operator has
to figure out why their MediaWiki install isn't protected) or worse,
attempt to load them in non-MediaWiki contexts and fail mysteriously.

By keeping shims outside the autoload graph, each host controls when
and how the shim runs.

## Install

Each shim has its own `INSTALL.md` with host-specific instructions.
In general:

```bash
# MediaWiki
cp extensions/mediawiki/bad-behaviour-mediawiki.php \
   /path/to/mediawiki/extensions/BadBehaviour/

# WackoWiki
# (no file copy — inline the snippet from INSTALL.md into index.php)

# Generic
# (no file copy — copy the snippet from example.php into your bootstrap)
```

## Adding a new integration

When you add support for a new host application:

1. Create `extensions/<host>/` with the shim file + `INSTALL.md`
2. Guard the shim with `if (!defined('<HOST_MARKER>')) return;`
3. Make it idempotent: `if (defined('BB_3_LOADED')) return;`
4. Update `composer.json`'s `archive.exclude` to include the new dir if
   you want to ship a tarball without examples

Don't:

- ❌ Put the shim in `src/` (pollutes the library namespace)
- ❌ Reference the shim in `composer.json`'s `autoload.files` (auto-runs
     on every composer install, even in unrelated projects)
- ❌ Reference the shim from library code (creates circular dependency
     between host adapters and host integrations)

## Cleanup history

Earlier versions of BadBehaviour shipped shims in the repo root:
`bad-behaviour-generic.php`, `bad-behaviour-wackowiki.php`,
`bad-behaviour-mediawiki.php`. These have been moved here as part of
the 3.0 cleanup. See CHANGELOG.md for details.