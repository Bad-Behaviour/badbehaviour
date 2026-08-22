<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Integration;

use PHPUnit\Framework\TestCase;

class WackoWikiAdapterTest extends TestCase
{

	public function test_skipped(): void
	{
		$this->markTestSkipped('WackoWiki not installed in test environment');
	}
}
