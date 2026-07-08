<?php
// tests/BadBehaviourTest.php

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\HostAdapterInterface;

class FakeAdapter implements HostAdapterInterface
{
	public array $queries = [];
	public array $settings = [
		'log_table'					=> 'bad_behaviour',
		'display_stats'				=> false,
		'strict'					=> false,
		'verbose'					=> false,
		'logging'					=> false,
		'httpbl_key'				=> '',
		'httpbl_threat'				=> 25,
		'httpbl_maxage'				=> 30,
		'offsite_forms'				=> false,
		'reverse_proxy'				=> false,
		'reverse_proxy_header'		=> 'X-Forwarded-For',
		'reverse_proxy_addresses'	=> []
	];

	public function get_date_string(): string
	{
		return gmdate('Y-m-d H:i:s');
	}

	public function get_affected_rows($result): int
	{
		return 0;
	}

	public function escape_string(string $s): string
	{
		return addslashes($s);
	}

	public function get_num_rows($result): int
	{
		return is_array($result) ? count($result) : 0;
	}

	public function query(string $q)
	{
		$this->queries[] = $q;
		return true;
	}

	public function get_rows($result): array
	{
		return [];
	}

	public function get_insert_sql(array $s, array $p, string $k): string
	{
		return "INSERT INTO `bad_behaviour` (ip, status_key) VALUES ('{$p['ip']}', '$k')";
	}

	public function get_email(): string
	{
		return 'test@example.com';
	}

	public function read_whitelist(): array
	{
		return [];
	}

	public function read_settings(): array
	{
		return $this->settings;
	}

	public function write_settings(array $s): bool
	{
		return false;
	}

	public function install(): void
	{
	}

	public function get_relative_path(): string
	{
		return '/';
	}

	public function get_table_structure(string $n)
	{
		return '';
	}
}

class BadBehaviourTest extends PHPUnit\Framework\TestCase
{
	public function test_run_does_not_die_in_cli(): void
	{
		$_SERVER['REQUEST_METHOD']	= 'GET';
		$_SERVER['REQUEST_URI']		= '/';
		$_SERVER['SERVER_PROTOCOL']	= 'HTTP/1.1';
		$_SERVER['REMOTE_ADDR']		= '127.0.0.1';
		$_SERVER['HTTP_USER_AGENT']	= 'PHPUnit';

		$bb = new BadBehaviour(new FakeAdapter());
		$bb->run();

		$this->assertTrue(true);
	}

	public function test_blacklisted_user_agent_is_flagged(): void
	{
		$_SERVER['REQUEST_METHOD']	= 'GET';
		$_SERVER['REQUEST_URI']		= '/';
		$_SERVER['SERVER_PROTOCOL']	= 'HTTP/1.1';
		$_SERVER['REMOTE_ADDR']		= '127.0.0.1';
		$_SERVER['HTTP_USER_AGENT']	= ' Havij ';

		$adapter = new FakeAdapter();
		$adapter->settings['logging'] = true;

		$bb = new BadBehaviour($adapter);

		$reflection = new \ReflectionClass($bb);
		$settingsProp = $reflection->getProperty('settings');
		$settingsProp->setAccessible(true);
		$settings = $settingsProp->getValue($bb);

		require_once BB2_CORE . '/functions.inc.php';
		require_once BB2_CORE . '/core.inc.php';

		// Capture the output buffer to prevent the 403 HTML from printing to console
		ob_start();

		// Run the screening manually.
		// The @ operator silently suppresses the header() deprecation warning in CLI mode.
		// Note: sleep(2) will run natively, adding a 2-second delay to this test method.
		@bb2_start($settings);

		// Discard the buffer
		ob_end_clean();

		$this->assertNotEmpty($adapter->queries, 'A denial INSERT should have been issued');
		$this->assertStringContainsString('INSERT', $adapter->queries[0] ?? '');
	}
}
