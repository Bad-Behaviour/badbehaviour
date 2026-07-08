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
		return '';
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
		$this->assertTrue(true); // Did not exit or throw
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
		$result = $bb->run();

		$this->assertNotEmpty($adapter->queries, 'A denial INSERT should have been issued');
		$this->assertStringContainsString('INSERT', $adapter->queries[0] ?? '');
	}
}