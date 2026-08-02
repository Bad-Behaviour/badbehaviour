<?php
/**
 * Bad Behaviour — Default bot registry configuration.
 *
 * Shipped with the library so config/bb_registry.php always exists.
 * Operators can override by copying bb_registry.example.php to bb_registry.php
 * and editing it. This file MUST return the array — do not wrap in logic.
 *
 * === DEFAULT POLICY ===
 *
 * Full preset (~100 bots) with cloud_infrastructure force-included as a
 * safety net. If you ever exclude a category in your override, the cloud
 * probes will still be present, preventing the catastrophic "all CDN
 * probes blocked → origin marked unhealthy → offline" failure mode.
 */

return [
	'preset' => 'full',

	// SAFETY NET: always include cloud probes regardless of other filters.
	// Critical for availability — see Configurations.md → Cloud Infrastructure.
	'include_categories' => [
		'cloud_infrastructure',
	],
];

