<?php
/*
 * Legacy MediaWiki entry point. Forwarding shim.
 */

if (!defined('MEDIAWIKI')) die();
if (!defined('BB2_CWD')) define('BB2_CWD', __DIR__);

require_once BB2_CWD . '/vendor/autoload.php';

use BadBehaviour\Core\BadBehaviour;
use BadBehaviour\Core\Adapter\MediaWikiAdapter;

global $wgDBprefix, $wgEmergencyContact, $wgScript, $wgBadBehaviourTimer, $bb2_timer_total;

$wgBadBehaviourTimer = false;

$wgExtensionCredits['other'][] = [
	'name'			=> 'Bad Behaviour',
	'version'		=> BB2_VERSION,
	'author'		=> 'Michael Hampton',
	'description'	=> 'Detects and blocks unwanted Web accesses',
	'url'			=> 'https://github.com/Bad-Behaviour/badbehaviour'
];

// Defer the actual run until MediaWiki is fully bootstrapped
$wgExtensionFunctions[] = function () use ($wgDBprefix, $wgEmergencyContact, $wgScript)
{
	global $bb2_timer_total;

	$start = microtime(true);

	if (php_sapi_name() !== 'cli')
	{
		$db = wfGetDB(DB_MASTER);
		$adapter = new MediaWikiAdapter($db, $wgDBprefix, $wgEmergencyContact, $wgScript);
		$bb = new BadBehaviour($adapter);
		$bb->run();
	}

	$bb2_timer_total = microtime(true) - $start;
};

$wgHooks['BeforePageDisplay'][] = function (&$out, &$skin)
{
	global $bb2_timer_total, $wgBadBehaviourTimer;
	if ($wgBadBehaviourTimer)
	{
		$out->addHTML(
			"<!-- Bad Behaviour " . BB2_VERSION . " run time: "
			. number_format(1000 * $bb2_timer_total, 3) . " ms -->"
			);
	}
	return true;
};