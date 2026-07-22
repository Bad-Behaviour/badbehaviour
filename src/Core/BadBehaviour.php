<?php
namespace BadBehaviour\Core;

class BadBehaviour
{
	private HostAdapterInterface $adapter;
	private array $settings;

	public function __construct(HostAdapterInterface $adapter, array $custom_settings = [])
	{
		$this->adapter = $adapter;

		// Register the adapter so procedural scripts can use it
		Runtime::set_adapter($adapter);

		// Load defaults, settings, then any custom overrides passed directly
		$settings = $adapter->read_settings();
		$this->settings = array_merge($settings, $custom_settings);

		// Define the CWD and Core constants if not already defined
		if (!defined('BB2_CWD'))
		{
			define('BB2_CWD', dirname(__DIR__, 2));
		}
		if (!defined('BB2_CORE'))
		{
			define('BB2_CORE', BB2_CWD . '/src');
		}
		if (!defined('BB2_VERSION'))
		{
			define('BB2_VERSION', '2.2.25');
		}
	}

	public function run(): bool
	{
		if (php_sapi_name() === 'cli')
		{
			return; // Do not run in CLI mode
		}

		$this->install();
		$this->settings['logging'] = $this->validate_logging();

		// Require helper functions
		require_once BB2_CORE . '/functions.inc.php';
		require_once BB2_CORE . '/core.inc.php';

		$result = bb2_start($this->settings);

		// If a ban occurred, bb2_display_denial handles output but don't die here.
		// Let the host handle it, or we handle it safely.
		if ($result)
		{
			// bb2_banned contains the die() statements in the original script.
			// That logic is now bypassed.
			// If you want the library to hard-stop execution, uncomment below:
			// die();

			return true;   // banned
		}

		return false;  // allowed
	}

	private function install(): void
	{
		if (defined('BB2_NO_CREATE')) return;
		if (!$this->settings['logging']) return;

		$table_struct = $this->adapter->get_table_structure($this->settings['log_table']);

		if (is_array($table_struct))
		{
			foreach ($table_struct as $query)
			{
				$this->adapter->query($query);
			}
		}
		else if (is_string($table_struct))
		{
			$this->adapter->query($table_struct);
		}
	}

	private function validate_logging(): bool
	{
		// In MediaWiki if class wasn't native DatabaseMysql, logging was disabled
		return (bool) $this->settings['logging'];
	}

	public function get_adapter(): HostAdapterInterface
	{
		return $this->adapter;
	}

	public function get_settings(): array
	{
		return $this->settings;
	}
}