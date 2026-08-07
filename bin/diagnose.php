<?php
// bin/diagnose.php — dump library state

/* $ php bin/diagnose.php
{
	"safe_mode": false,
	"monitor_only_effective": true,
	"monitor_only": true,
	"strictness": "monitor-only",
	"preset": "minimal",
	"config_loaded": true,
	"logging_enabled": true,
	"detectors_active": {
	"blacklist": true,
	"bot": true,
	"dns_verify": false,        ← correctly off in monitor-only
	"rate_limit": false,        ← correctly off
	"behavioral": false,        ← correctly off
	...
},
"hint": "BadBehaviour is in monitor-only mode by configuration. ..."
} */

require __DIR__ . '/../vendor/autoload.php';

use BadBehaviour\Adapter\GenericAdapter;
use BadBehaviour\Configuration;
use BadBehaviour\Core\BadBehaviour;

$adapter = new GenericAdapter();
$config = Configuration::from_array(
    file_exists(__DIR__ . '/../config/bb_config.php')
        ? require __DIR__ . '/../config/bb_config.php'
        : [],
    $adapter
);

$bb = new BadBehaviour($config);
echo json_encode($bb->diagnostics(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";