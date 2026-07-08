<?php
/*
 * Legacy WackoWiki entry point. Forwarding shim.
 */

if (!defined('IN_WACKO')) die('I said no cheating!');
if (!defined('BB2_CWD')) define('BB2_CWD', __DIR__);

require_once BB2_CWD . '/vendor/autoload.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Adapter\WackoWikiAdapter;

$bb2_timer_start = microtime(true);

$adapter = new WackoWikiAdapter($db);
$bb = new BadBehaviour($adapter);
$bb->run();

$GLOBALS['bb2_timer_total'] = microtime(true) - $bb2_timer_start;

// Legacy helpers retained for existing templates / themes
function bb2_timer()
{
	global $bb2_timer_total;
	return '<!-- Bad Behaviour ' . BB2_VERSION . ' run time: '
		. number_format(1000 * $bb2_timer_total, 3) . " ms -->\n";
}

function bb2_insert_stats($force = false)
{
	$adapter = \BadBehaviour\Core\Runtime::get_adapter();
	$settings = $adapter->read_settings();

	if ($force || $settings['display_stats'])
	{
		$result = $adapter->query(
			"SELECT COUNT(log_id) AS n FROM " . $settings['log_table']
			. " WHERE `status_key` NOT LIKE '00000000'"
			);
		$rows = $adapter->get_rows($result);
		if ($rows !== false) return $rows[0]['n'];
	}
	return '';
}