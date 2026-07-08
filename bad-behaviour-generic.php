<?php
/*
 * Legacy entry point. Now a thin shim around BadBehaviour\Core\BadBehaviour.
 * Existing callers that simply do require_once 'bad-behaviour-generic.php';
 * continue to work as before.
 */

if (!defined('BB2_CWD')) define('BB2_CWD', __DIR__);

require_once BB2_CWD . '/vendor/autoload.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Adapter\GenericAdapter;

$adapter = new GenericAdapter();
$bb = new BadBehaviour($adapter);

// Honour any legacy global $bb2_settings_defaults if defined by host
if (isset($GLOBALS['bb2_settings_defaults']) && is_array($GLOBALS['bb2_settings_defaults']))
{
	// Merged into adapter settings via read_settings() in most cases, so this
	// is purely for hosts that override defaults at runtime.
}

$bb->run();