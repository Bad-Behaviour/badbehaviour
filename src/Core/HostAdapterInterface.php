<?php
namespace BadBehaviour\Core;

interface HostAdapterInterface
{
	public function get_date_string(): string;
	public function get_affected_rows($result): int;
	public function escape_string(string $string): string;
	public function get_num_rows($result): int;
	public function query(string $query);
	public function get_rows($result): array;
	public function get_insert_sql(array $settings, array $package, string $key): string;
	public function get_email(): string;
	public function read_whitelist(): array;
	public function read_settings(): array;
	public function write_settings(array $settings): bool;
	public function install(): void;
	public function get_relative_path(): string;
	public function get_table_structure(string $name);
}