<?php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Integration;

use PHPUnit\Framework\TestCase;

class MediaWikiAdapterTest extends TestCase
{

	public function test_skipped(): void
	{
		$this->markTestSkipped('MediaWiki not installed in test environment');
	}
}
