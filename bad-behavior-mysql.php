<?php

// Our log table structure
function bb2_table_structure($name)
{
	// It's not paranoia if they really are out to get you.
	$name_escaped = bb2_db_escape($name);
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

// Insert a new record
function bb2_insert($settings, $package, $status_key)
{
	if (!$settings['logging']) return '';

	$ip					= bb2_db_escape($package['ip']);
	$host				= bb2_db_escape(@gethostbyaddr($package['ip']));
	$date				= bb2_db_date();
	$request_method		= bb2_db_escape($package['request_method']);
	$request_uri		= bb2_db_escape($package['request_uri']);
	$request_uri_hash	= hash('sha1', $request_uri);
	$server_protocol	= bb2_db_escape($package['server_protocol']);
	$user_agent			= bb2_db_escape($package['user_agent']);
	$user_agent_hash	= hash('sha1', $user_agent);
	$headers			= "$request_method $request_uri $server_protocol\n";

	foreach ($package['headers'] as $h => $v)
	{
		$headers .= bb2_db_escape("$h: $v\n");
	}

	$request_entity = '';

	if (!strcasecmp($request_method, 'POST'))
	{
		foreach ($package['request_entity'] as $h => $v)
		{
			$request_entity .= bb2_db_escape("$h: $v\n");
		}
	}

	return "INSERT INTO `" . bb2_db_escape($settings['log_table']) . "`
		(`ip`, `host`, `date`, `request_method`, `request_uri`, `request_uri_hash`, `server_protocol`, `http_headers`, `user_agent`, `user_agent_hash`, `request_entity`, `status_key`) VALUES
		('$ip', '$host', '$date', '$request_method', '$request_uri', '$request_uri_hash', '$server_protocol', '$headers', '$user_agent', '$user_agent_hash', '$request_entity', '$status_key')";
}
