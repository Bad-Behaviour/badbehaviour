<?php if (!defined('BB2_CORE')) die('I said no cheating!');

use BadBehaviour\Core\Runtime;

function bb2_run_whitelist($package)
{
	$adapter = Runtime::get_adapter();

	// Modern path: ask the adapter. Legacy platforms that previously
	// overrode bb2_read_whitelist() keep working because their adapter
	// implementation simply calls the same parse_ini_file internally.
	$whitelists = $adapter->read_whitelist();

	if (@!empty($whitelists['ip']))
	{
		foreach (array_filter($whitelists['ip']) as $range)
		{
			if (match_cidr($package['ip'], $range))
			{
				return true;
			}
		}
	}

	if (@!empty($whitelists['useragent']))
	{
		foreach (array_filter($whitelists['useragent']) as $user_agent)
		{
			if (!strcmp($package['headers_mixed']['User-Agent'], $user_agent))
			{
				return true;
			}
		}
	}

	if (@!empty($whitelists['url']))
	{
		if (!str_contains($package['request_uri'], '?'))
		{
			$request_uri = $package['request_uri'];
		}
		else
		{
			$request_uri = substr($package['request_uri'], 0, strpos($package['request_uri'], '?'));
		}

		foreach (array_filter($whitelists['url']) as $url)
		{
			$pos = strpos($request_uri, $url);

			if ($pos !== false && $pos == 0)
			{
				return true;
			}
		}
	}

	return false;
}