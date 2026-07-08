<?php
namespace BadBehaviour\Core\Adapter;

use BadBehaviour\Core\HostAdapterInterface;

class MediaWikiAdapter implements HostAdapterInterface
{
	private $db;
	private $emergency_email;
	private $script_path;
	private array $defaults;

	public function __construct($db, string $db_prefix, string $emergency_email, string $script_path)
	{
		$this->db = $db; // wfGetDB(DB_MASTER) passed externally
		$this->emergency_email = $emergency_email;
		$this->script_path = dirname($script_path) . "/";
		$this->defaults = [
			'log_table'					=> $db_prefix . 'bad_behaviour',
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
	}

	public function get_date_string(): string
	{
		return gmdate('Y-m-d H:i:s');
	}

	public function get_affected_rows($result): int
	{
		return $this->db->affectedRows();
	}

	public function escape_string(string $string): string
	{
		return addslashes($string);
	}

	public function get_num_rows($result): int
	{
		return $result->numRows();
	}

	public function query(string $query)
	{
		try
		{
			return $this->db->query($query);
		}
		catch (\DBQueryError $e)
		{
			trigger_error("Bad Behaviour DBQueryError " . $e->getMessage(), E_USER_WARNING);
			return false;
		}
	}

	public function get_rows($result): array
	{
		$rows = [];
		try
		{
			while ($row = $result->fetchRow())
			{
				$rows[] = $row;
			}
		}
		catch (\DBUnexpectedError $e)
		{
			trigger_error('Bad Behaviour DBUnexpectedError ' . $e->getMessage(), E_USER_WARNING);
		}
		return $rows;
	}

	public function get_insert_sql(array $settings, array $package, string $key): string
	{
		if (!$settings['logging']) return '';
		return $this->build_mysql_insert($settings, $package, $key);
	}

	public function get_email(): string
	{
		return $this->emergency_email;
	}

	public function read_whitelist(): array
	{
		return @parse_ini_file(dirname(BB2_CORE) . '/whitelist.ini') ?: [];
	}

	public function read_settings(): array
	{
		$settings = @parse_ini_file(dirname(__FILE__, 2) . '/settings.ini') ?: [];
		return array_merge($this->defaults, $settings);
	}

	public function write_settings(array $settings): bool
	{
		return false;
	}

	public function install(): void
	{
		// Expects adapter to handle install via core
	}

	public function get_relative_path(): string
	{
		return $this->script_path;
	}

	public function get_table_structure(string $name): string
	{
		$name_escaped = $this->escape_string($name);
		return "CREATE TABLE IF NOT EXISTS `$name_escaped` (
			`log_id` INT(11) NOT NULL AUTO_INCREMENT,
			`ip` VARCHAR(45) NOT NULL DEFAULT '',
			`host` VARCHAR(2083) NOT NULL DEFAULT '',
			`date` DATETIME DEFAULT NULL,
			`request_method` VARCHAR(8) NOT NULL DEFAULT '',
			`request_uri` VARCHAR(2083) NOT NULL DEFAULT '',
			`request_uri_hash` CHAR(40) NOT NULL DEFAULT '',
			`server_protocol` VARCHAR(12) NOT NULL DEFAULT '',
			`http_headers` TEXT NOT NULL,
			`user_agent` TEXT DEFAULT NULL,
			`user_agent_hash` CHAR(40) NOT NULL DEFAULT '',
			`request_entity` TEXT DEFAULT NULL,
			`status_key` VARCHAR(10) NOT NULL DEFAULT '',
			PRIMARY KEY (`log_id`),
			KEY `idx_staus_key` (`status_key`),
			KEY `idx_request_uri_hash` (`request_uri_hash`),
			KEY `idx_user_agent_hash` (`user_agent_hash`),
			KEY `idx_ip` (`ip`),
			KEY `idx_request_method` (`request_method`)
		);";
	}

	private function build_mysql_insert(array $settings, array $package, string $key): string
	{
		$ip = $this->escape_string($package['ip']);
		$host = $this->escape_string(@gethostbyaddr($package['ip']));
		$date = $this->get_date_string();
		$request_method = $this->escape_string($package['request_method']);
		$request_uri = $this->escape_string($package['request_uri']);
		$request_uri_hash = hash('sha1', $request_uri);
		$server_protocol = $this->escape_string($package['server_protocol']);
		$user_agent = $this->escape_string($package['user_agent']);
		$user_agent_hash = hash('sha1', $user_agent);
		$headers = "$request_method $request_uri $server_protocol\n";
		foreach ($package['headers'] as $h => $v)
		{
			$headers .= $this->escape_string("$h: $v\n");
		}
		$request_entity = '';
		if (!strcasecmp($request_method, 'POST'))
		{
			foreach ($package['request_entity'] as $h => $v)
			{
				$request_entity .= $this->escape_string("$h: $v\n");
			}
		}
		return "INSERT INTO `" . $this->escape_string($settings['log_table']) . "`
			(`ip`, `host`, `date`, `request_method`, `request_uri`, `request_uri_hash`, `server_protocol`, `http_headers`, `user_agent`, `user_agent_hash`, `request_entity`, `status_key`) VALUES
			('$ip', '$host', '$date', '$request_method', '$request_uri', '$request_uri_hash', '$server_protocol', '$headers', '$user_agent', '$user_agent_hash', '$request_entity', '$key')";
	}
}