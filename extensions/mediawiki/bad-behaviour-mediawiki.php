<?php
/**
 * Bad Behaviour 3.0 - MediaWiki Extension
 *
 * Integration shim for MediaWiki. NOT autoloaded by Composer — see
 * extensions/README.md for the install procedure.
 *
 * === GUARDS ===
 *
 *   1. Refuse to load outside MediaWiki (silent no-op via `return`)
 *   2. Refuse double-load (idempotent via BB_3_LOADED constant)
 *   3. Refuse to run from CLI (cron / maintenance scripts shouldn't
 *      be subject to bot detection — they have no IP semantics)
 *
 * === RESPONSIBILITIES ===
 *
 *   - $wgExtensionCredits: version metadata for Special:Version
 *   - $wgExtensionFunctions: the detection entry point
 *   - $wgHooks['BeforePageDisplay']: debug footer (gated by $wgBadBehaviourTimer)
 *
 * Detection itself is delegated to BadBehaviour::with_adapter($adapter),
 * which handles config loading, challenge rendering, and logging
 * entirely through the adapter — no manual wiring required.
 */

if (!defined('MEDIAWIKI')) {
    return;
}

if (defined('BB_3_LOADED')) {
    return;
}
define('BB_3_LOADED', true);

if (!defined('BB_CWD')) {
    define('BB_CWD', __DIR__);
}

require_once BB_CWD . '/../vendor/autoload.php';

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
    global $wgDB, $wgDBprefix, $wgEmergencyContact, $wgScript;
    global $wgBadBehaviourTimer;

    if (php_sapi_name() === 'cli') {
        return;
    }

    $bb_start = microtime(true);

    try {
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
            // handle_result() exits; control does not return here.
        }
    } catch (\Throwable $e) {
        // Never let BadBehaviour crash MediaWiki.
        if (function_exists('wfDebugLog')) {
            wfDebugLog('badbehaviour', 'BadBehaviour threw: ' . $e->getMessage());
        }
    }

    if ($wgBadBehaviourTimer) {
        $GLOBALS['bb_timer_total'] = microtime(true) - $bb_start;
    }
};

$wgHooks['BeforePageDisplay'][] = static function (&$out, &$skin): bool {
    global $bb_timer_total, $wgBadBehaviourTimer;
    if ($wgBadBehaviourTimer && !empty($bb_timer_total)) {
        $out->addHTML(
            '<!-- Bad Behaviour 3.0 run time: '
            . number_format(1000 * $bb_timer_total, 3)
            . ' ms -->'
        );
    }
    return true;
};