<?php
namespace BadBehaviour\Core;

class Runtime
{
	private static ?HostAdapterInterface $adapter = null;

	public static function set_adapter(HostAdapterInterface $adapter): void
	{
		self::$adapter = $adapter;
	}

	public static function get_adapter(): HostAdapterInterface
	{
		if (self::$adapter === null)
		{
			throw new \RuntimeException('Bad Behaviour HostAdapter not initialized.');
		}
		return self::$adapter;
	}
}