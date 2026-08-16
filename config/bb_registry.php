<?php
/**
 * Bad Behaviour — Default bot registry configuration (shipped).
 *
 * === PURPOSE ===
 *
 * This file is the safe fallback used ONLY when the operator has NOT
 * created their own config/bb_registry.php in their application root.
 *
 * Operators SHOULD create their own bb_registry.php with their preferred
 * preset and filters. See config/bb_registry.example.php for examples.
 *
 * === WHY THIS IS SAFE ===
 *
 * The previous version of this file used:
 *   'include_categories' => ['cloud_infrastructure']
 * thinking it was a "safety net" to ensure CDN/LB health probes are always
 * allowed. That was WRONG — FilteredRegistry interprets include_categories
 * as a strict whitelist, which silently dropped every other bot from
 * BotDetector. Production deployments saw almost nothing blocked because
 * BotDetector's registry contained only 5 cloud health probes.
 *
 * The shipped default now just loads the full preset with no filtering.
 * Cloud-infrastructure bots are included by default in ALL presets
 * (see Presets::load() in src/Bot/Registry/Presets.php), so no safety-net
 * mechanism is needed at this level.
 *
 * If you create your own bb_registry.php and exclude categories aggressively,
 * use `include_categories` (which now does additive merge, not whitelisting)
 * to add back the categories you need:
 *
 *   return [
 *       'preset' => 'minimal',
 *       'exclude_categories' => ['seo_crawler', 'social_crawler'],
 *       'include_categories' => ['cloud_infrastructure'],  // additive
 *   ];
 *
 * === STRICT WHITELIST MODE ===
 *
 * For genuine whitelist use cases (closed intranets, minimal curated
 * subsets), use `only_categories` instead:
 *
 *   return [
 *       'preset' => 'full',
 *       'only_categories' => ['monitoring', 'cloud_infrastructure'],
 *   ];
 *
 * This RESTRICTS the registry to only those categories (destructive).
 */

return [
	'preset' => 'full',
];
