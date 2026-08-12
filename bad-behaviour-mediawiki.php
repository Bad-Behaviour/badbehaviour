<?php
/**
 * Bad Behaviour 3.0 - MediaWiki Extension
 *
 * This shim exists because MediaWiki requires the
 * $wgExtensionFunctions / $wgHooks registration pattern — there is no
 * "inline this into LocalSettings.php" equivalent. The 3.0 entry point
 * is just `with_adapter() + run()`; everything else here is MediaWiki
 * boilerplate (credits, debug hooks, the global timer marker).
 */

if (!defined('MEDIAWIKI')) die();
if (!defined('BB_CWD')) define('BB_CWD', __DIR__);

require_once BB_CWD . '/vendor/autoload.php';

use BadBehaviour\Adapter\MediaWikiAdapter;
use BadBehaviour\Core\BadBehaviour;

global $wgDBprefix, $wgEmergencyContact, $wgScript, $wgBadBehaviourTimer, $wgDB;

$wgBadBehaviourTimer = false;

$wgExtensionCredits['other'][] = [
	'name'        => 'Bad Behaviour',
	'version'     => '3.0.0',
	'author'      => 'Michael Hampton & Contributors',
	'description' => 'Modern bot detection and blocking',
	'url'         => 'https://github.com/Bad-Behaviour/badbehaviour',
];

$wgExtensionFunctions[] = static function (): void {
	global $wgDB, $wgDBprefix, $wgEmergencyContact, $wgScript, $wgOut;
	global $wgBadBehaviourTimer;

	if (php_sapi_name() === 'cli') {
		return;
	}

	$bb_start = microtime(true);

	try {
		// === Adapter does config loading (config/bb_config.php)
		//     AND DB connection, table prefix, abuse email, script path
		//     in one constructor. No manual Settings() wiring. ===
		$adapter = new MediaWikiAdapter(
			$wgDB,
			$wgDBprefix,
			$wgEmergencyContact,
			$wgScript,
			);

		$bb = BadBehaviour::with_adapter($adapter);
		$result = $bb->run();

		if ($result->is_actionable()) {
			$bb->handle_result($result);
			// handle_result() exits; execution does not reach here.
		}
	} catch (\Throwable $e) {
		// Never let BadBehaviour crash MediaWiki. Log and continue —
		// the user gets served normally (defense in depth; BadBehaviour
		// itself already swallows exceptions internally, but a mediawiki-
		// specific wrapper here makes the integration contract explicit).
		wfDebugLog('badbehaviour', 'BadBehaviour threw: ' . $e->getMessage());
	}

	if ($wgBadBehaviourTimer) {
		$GLOBALS['bb_timer_total'] = microtime(true) - $bb_start;
	}
};

$wgHooks['BeforePageDisplay'][] = static function (&$out, &$skin): bool {
	global $bb_timer_total, $wgBadBehaviourTimer;
	if ($wgBadBehaviourTimer && $bb_timer_total) {
		$out->addHTML(
			'<!-- Bad Behaviour 3.0 run time: '
			. number_format(1000 * $bb_timer_total, 3)
			. ' ms -->'
			);
	}
	return true;
};
