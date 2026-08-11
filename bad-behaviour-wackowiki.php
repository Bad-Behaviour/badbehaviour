<?php
/**
 * Bad Behaviour 3.0 - WackoWiki Entry Point
 */

if (!defined('IN_WACKO')) die('I said no cheating!');
if (!defined('BB_CWD')) define('BB_CWD', __DIR__);

require_once BB_CWD . '/vendor/autoload.php';

use BadBehaviour\Bootstrap;
use BadBehaviour\Adapter\WackoWikiAdapter;
use BadBehaviour\Configuration;

global $db;

$raw = @parse_ini_file('config/bb_settings.conf', true) ?: [];
$adapter = new WackoWikiAdapter($db);
$config = Configuration::from_array($raw, $adapter);

$bb = new \BadBehaviour\Core\BadBehaviour($config);
$result = $bb->run();

if ($result->is_actionable()) {
	$bb->handle_result($result);
}

$GLOBALS['bb_timer_total'] = microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true));
