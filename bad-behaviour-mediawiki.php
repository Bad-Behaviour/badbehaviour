<?php
/**
 * Bad Behaviour 3.0 - MediaWiki Extension
 */

if (!defined('MEDIAWIKI')) die();
if (!defined('BB2_CWD')) define('BB2_CWD', __DIR__);

require_once BB2_CWD . '/vendor/autoload.php';

use BadBehaviour\Bootstrap;
use BadBehaviour\Adapter\MediaWikiAdapter;
use BadBehaviour\Configuration;

global $wgDBprefix, $wgEmergencyContact, $wgScript, $wgBadBehaviourTimer, $bb2_timer_total;

$wgBadBehaviourTimer = false;

$wgExtensionCredits['other'][] = [
	'name' => 'Bad Behaviour',
	'version' => '3.0.0',
	'author' => 'Michael Hampton & Contributors',
	'description' => 'Modern bot detection and blocking',
	'url' => 'https://github.com/Bad-Behaviour/badbehaviour'
];

$wgExtensionFunctions[] = function () use ($wgDBprefix, $wgEmergencyContact, $wgScript) {
	global $bb2_timer_total, $wgDB, $wgOut, $wgBadBehaviourSettings;

	$start = microtime(true);

	if (php_sapi_name() !== 'cli') {
		$db = $wgDB ?? wfGetDB(DB_REPLICA);
		$adapter = new MediaWikiAdapter($db, $wgDBprefix, $wgEmergencyContact, $wgScript);

		$raw = $wgBadBehaviourSettings ?? [];
		$config = Configuration::from_array($raw, $adapter);

		$bb = new \BadBehaviour\Core\BadBehaviour($config);
		$result = $bb->run();

		if (!$result->is_allowed()) {
			if ($result->requires_challenge() && $config->challenge_enabled) {
				$challenge = $bb->create_challenge();
				if (!$challenge->verify($result->package)) {
					$output = $challenge->render($wgScript);
					wfDebugLog('badbehaviour', 'Challenge issued: ' . $result->code->value);
					$wgOut->addHTML($output);
					$wgOut->disable();
					return;
				}
			}
			$bb->handle_result($result);
		}
	}

	$bb2_timer_total = microtime(true) - $start;
};

$wgHooks['BeforePageDisplay'][] = function (&$out, &$skin) {
	global $bb2_timer_total, $wgBadBehaviourTimer;
	if ($wgBadBehaviourTimer && $bb2_timer_total) {
		$out->addHTML("<!-- Bad Behaviour 3.0 run time: " . number_format(1000 * $bb2_timer_total, 3) . " ms -->");
	}
	return true;
};
