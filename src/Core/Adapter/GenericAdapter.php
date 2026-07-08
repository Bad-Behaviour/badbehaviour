<?php
namespace BadBehaviour\Core\Adapter;

use BadBehaviour\Core\HostAdapterInterface;

class GenericAdapter implements HostAdapterInterface
{
	private array $defaults = [
		'log_table'					=> 'bad_behaviour',
		'display_stats'				=> false,
		'strict'					=> false,
		'verbose'					=> false,
		'logging'					=> true,
		'httpbl_key'				=> '',
		'httpbl_threat'				=> '25',
		'httpbl_maxage'				=> '30',
		'offsite_forms'				=> false,
		'reverse_proxy'				=> false,
		'reverse_proxy_header'		=> 'X-Forwarded-For',
		'reverse_proxy_addresses'	=> [],
	];

	public function get_date_string(): string
	{
		return gmdate('Y-m-d H:i:s');
	}

	public function get_affected_rows($result): int
	{
		return false;
	}

	public function escape_string(string $string): string
	{
		return $string;
	}

	public function get_num_rows($result): int
	{
		return $result !== false ? count($result) : 0;
	}

	public function query(string $query)
	{
		return false;
	}

	public function get_rows($result): array
	{
		return $result ?: [];
	}

	public function get_insert_sql(array $settings, array $package, string $key): string
	{
		return '--';
	}

	public function get_email(): string
	{
		return "example@example.com";
	}

	public function read_whitelist(): array
	{
		return @parse_ini_file(dirname(BB2_CORE) . "/whitelist.ini") ?: [];
	}

	public function read_settings(): array
	{
		return $this->defaults;
	}

	public function write_settings(array $settings): bool
	{
		return false;
	}

	public function install(): void
	{
		// No-op
	}

	public function get_relative_path(): string
	{
		return '/';
	}

	public function get_table_structure(string $name)
	{
		return "-- No table structure for Generic";
	}
}