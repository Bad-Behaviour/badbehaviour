<?php

declare(strict_types=1);

namespace BadBehaviour\Bot;

use BadBehaviour\Bot\Registry\CustomRegistry;
use BadBehaviour\Bot\Registry\DefaultRegistry;
use BadBehaviour\Bot\Registry\EmptyRegistry;
use BadBehaviour\Bot\Registry\FilteredRegistry;
use BadBehaviour\Bot\Registry\InMemoryRegistry;
use BadBehaviour\Bot\Registry\MergedRegistry;
use BadBehaviour\Bot\Registry\Presets;

/**
 * Builds RegistryInterface instances from config arrays, config files,
 * or programmatic definitions.
 *
 * === THREE ENTRY POINTS ===
 *
 *   - from_file()  — Load from bb_registry.php
 *   - from_array() — Build from a config array
 *   - default()    — Get the unmodified DefaultRegistry
 *
 * === CONFIG ARRAY SHAPE ===
 *
 * ```php
 * [
 *     'preset'             => 'minimal',                 // see Presets::AVAILABLE
 *     'exclude_categories' => ['seo_crawler'],           // optional
 *     'include_categories' => ['cloud_infrastructure'],  // optional
 *     'exclude_bots'       => ['petal'],                 // optional
 *     'additions'          => [                          // optional
 *         'my_bot' => [/* BotDefinition schema *\/],
 *     ],
 *     'bots'               => [/* ... *\/],               // only when preset='custom'
 * ]
 * ```
 *
 * === FILTER EXECUTION ORDER ===
 *
 *   1. Load preset (or empty for 'human-only' / 'custom')
 *   2. Apply exclude_categories (remove whole categories)
 *   3. Apply include_categories (re-add, overrides exclude)
 *   4. Apply exclude_bots (remove specific bots)
 *   5. Merge additions (custom bots on top)
 *
 * === BACKWARD COMPATIBILITY ===
 *
 * If no bb_registry.php exists, RegistryFactory::default() is used.
 * No global state — each call returns a fresh tree of registries.
 */
class RegistryFactory
{
	/**
	 * Build a RegistryInterface from a config array.
	 *
	 * @param array $config Config array (same shape as config/bb_registry.php)
	 * @return RegistryInterface
	 */
	public static function from_array(array $config): RegistryInterface
	{
		$preset = $config['preset'] ?? 'full';

		// === Step 1: Load the preset base ===
		if ($preset === 'custom') {
			// Custom mode: start empty, populate from 'bots' key
			$registry = self::build_custom_registry($config['bots'] ?? []);
		} else {
			$registry = Presets::load($preset);
		}

		// === Step 2: Apply category filters ===
		$exclude_categories = self::ensure_array($config['exclude_categories'] ?? []);
		$include_categories = isset($config['include_categories'])
			? self::ensure_array($config['include_categories'])
			: null;

		if (!empty($exclude_categories) || $include_categories !== null) {
			$registry = new FilteredRegistry(
				$registry,
				include_categories: $include_categories,
				exclude_categories: $exclude_categories,
			);
		}

		// === Step 3: Apply exclude_bots ===
		$exclude_bots = self::ensure_array($config['exclude_bots'] ?? []);
		if (!empty($exclude_bots)) {
			$registry = new FilteredRegistry(
				$registry,
				exclude_bots: $exclude_bots,
			);
		}

		// === Step 4: Apply additions (merged on top) ===
		$additions = self::ensure_array($config['additions'] ?? []);
		if (!empty($additions)) {
			$custom = new CustomRegistry($additions);
			// Later sources win in MergedRegistry → put additions last
			$registry = new MergedRegistry([$registry, $custom]);
		}

		return $registry;
	}

	/**
	 * Build from a config file. Falls back to DefaultRegistry if file doesn't exist.
	 *
	 * @param string|null $path Optional explicit path. If null, searches standard locations.
	 * @return RegistryInterface
	 */
	public static function from_file(?string $path = null): RegistryInterface
	{
		$path = $path ?? self::default_path();

		if ($path === null || !file_exists($path)) {
			return self::default();
		}

		$config = require $path;
		if (!is_array($config)) {
			throw new \InvalidArgumentException(
				"Registry config must return an array: {$path}"
			);
		}

		return self::from_array($config);
	}

	/**
	 * Get the unmodified default registry (all ~100 shipped bots).
	 *
	 * Singleton: returns the same instance on repeated calls (safe because
	 * DefaultRegistry is read-only).
	 */
	public static function default(): RegistryInterface
	{
		static $instance = null;
		if ($instance === null) {
			$instance = new DefaultRegistry();
		}
		return $instance;
	}

	/**
	 * Find the standard config file path.
	 *
	 * Search order:
	 *   1. CONFIG_DIR/bb_registry.php (if CONFIG_DIR is defined)
	 *   2. config/bb_registry.php (CWD-relative)
	 *   3. {package_root}/config/bb_registry.php (relative to this file)
	 *
	 * Returns null if no candidate exists (caller should fall back to default()).
	 */
	public static function default_path(): ?string
	{
		$candidates = [
			defined('CONFIG_DIR') ? CONFIG_DIR . '/bb_registry.php' : null,
			'config/bb_registry.php',
			__DIR__ . '/../../config/bb_registry.php',
		];

		foreach (array_filter($candidates) as $path) {
			if (file_exists($path)) {
				return $path;
			}
		}

		return null;
	}

	// ========================================================================
	// Internal helpers
	// ========================================================================

	/**
	 * Build a CustomRegistry from the `bots` config key (preset='custom' mode).
	 *
	 * Each bot is validated individually via a single-entry CustomRegistry so
	 * errors are reported per-bot rather than aborting the whole load.
	 */
	private static function build_custom_registry(array $bots): RegistryInterface
	{
		$registry = new CustomRegistry();

		if (empty($bots)) {
			// Empty custom registry — useful as a starting point
			return $registry;
		}

		foreach ($bots as $bot_id => $definition) {
			// Wrap each bot as a single-entry registry for validation
			$single = new CustomRegistry([$bot_id => $definition]);

			// Skip invalid entries (already logged inside CustomRegistry)
			if ($single->has_errors()) {
				continue;
			}

			if ($single->count() === 1 && $single->has($bot_id)) {
				$registry->add($single->get($bot_id));
			}
		}

		return $registry;
	}

	/**
	 * Coerce a value to array (handle string CSV, null, already-array).
	 *
	 * @param mixed $value
	 * @return array<int|string, mixed>
	 */
	private static function ensure_array(mixed $value): array
	{
		if ($value === null) {
			return [];
		}
		if (is_array($value)) {
			return $value;
		}
		if (is_string($value) && $value !== '') {
			return preg_split('/\s*,\s*/', $value);
		}
		return [];
	}
}
