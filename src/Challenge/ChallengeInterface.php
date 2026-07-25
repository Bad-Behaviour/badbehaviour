<?php

namespace BadBehaviour\Challenge;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;

interface ChallengeInterface
{
	public function __construct(Configuration $config, ?AdapterInterface $adapter = null);
	public function verify(RequestPackage $package): bool;
	public function render(string $action_url): string;
}
