<?php
/*
 * Legacy helper file. The functionality is now provided by
 * BadBehaviour\Core\Adapter\MediaWikiAdapter::get_table_structure() and
 * BadBehaviour\Core\Adapter\WackoWikiAdapter::get_table_structure().
 * This wrapper exists for backward compatibility only.
 */

if (!defined('BB2_CORE')) define('BB2_CORE', __DIR__ . '/src');

function bb2_table_structure($name)
{
	$adapter = new \BadBehaviour\Core\Adapter\MediaWikiAdapter(
		new class {
			public function query($q){}
			public function affectedRows(){return 0;}
			public function numRows(){return 0;}
			public function fetchRow(){return false;}
		},
		'', 'legacy@example.com', '/'
			);
	return $adapter->get_table_structure($name);
}

function bb2_insert($settings, $package, $key)
{
	$adapter = new \BadBehaviour\Core\Adapter\MediaWikiAdapter(
		new class {
			public function query($q){}
			public function affectedRows(){return 0;}
			public function numRows(){return 0;}
			public function fetchRow(){return false;}
		},
		'', 'legacy@example.com', '/'
			);
	return $adapter->get_insert_sql($settings, $package, $key);
}