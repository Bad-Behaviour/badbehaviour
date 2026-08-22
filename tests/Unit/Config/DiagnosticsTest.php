<?php
// tests/Unit/Config/DiagnosticsTest.php
declare(strict_types = 1);
namespace BadBehaviour\Tests\Unit\Config;

use BadBehaviour\Config\Diagnostics;
use BadBehaviour\Configuration;
use BadBehaviour\Adapter\GenericAdapter;
use PHPUnit\Framework\TestCase;

class DiagnosticsTest extends TestCase
{

	protected function setUp(): void
	{
		Diagnostics::reset();
	}

	protected function tearDown(): void
	{
		Diagnostics::reset();
	}

	// =====================================================================
	// unknown_keys() — typo detection
	// =====================================================================
	public function test_unknown_keys_empty_at_start(): void
	{
		$this->assertSame([], Diagnostics::unknown_keys());
	}

	public function test_from_array_collects_typos(): void
	{
		Configuration::from_array([
			'preset' => 'minimal',
			'dynamc_ip_ranges' => [
				'enabled' => true
			] // typo
		]);

		$unknown = Diagnostics::unknown_keys();

		$this->assertArrayHasKey('dynamc_ip_ranges.enabled', $unknown);
	}

	public function test_from_array_collects_multiple_typos(): void
	{
		Configuration::from_array([
			'dynamc_ip_ranges' => [
				'enabled' => true
			],
			'dns_verfiction' => [
				'enabled' => false
			],
			'preset' => 'minimal'
		]);

		$unknown = Diagnostics::unknown_keys();

		$this->assertCount(2, $unknown);
		$this->assertArrayHasKey('dynamc_ip_ranges.enabled', $unknown);
		$this->assertArrayHasKey('dns_verfiction.enabled', $unknown);
		$this->assertArrayNotHasKey('preset', $unknown);
	}

	public function test_valid_keys_not_collected(): void
	{
		Configuration::from_array([
			'preset' => 'minimal',
			'strictness' => 'monitor-only',
			'logging' => true,
			'verbose' => true,
			'dns_verification' => [
				'enabled' => true
			]
		]);

		$unknown = Diagnostics::unknown_keys();

		$this->assertEmpty($unknown);
	}

	public function test_reset_clears_unknown_keys(): void
	{
		Configuration::from_array([
			'dynamc_ip_ranges' => [
				'enabled' => true
			]
		]);

		$this->assertNotEmpty(Diagnostics::unknown_keys());

		Diagnostics::reset();

		$this->assertSame([], Diagnostics::unknown_keys());
	}

	public function test_unknown_keys_accumulate_across_calls(): void
	{
		Configuration::from_array([
			'dynamc_ip_ranges' => [
				'enabled' => true
			]
		]);

		Configuration::from_array([
			'dns_verfiction' => [
				'enabled' => false
			]
		]);

		$unknown = Diagnostics::unknown_keys();

		$this->assertArrayHasKey('dynamc_ip_ranges.enabled', $unknown);
		$this->assertArrayHasKey('dns_verfiction.enabled', $unknown);
	}

	// =====================================================================
	// Integration with Configuration::from_array()
	// =====================================================================
	public function test_nested_typo_with_multiple_subkeys(): void
	{
		Configuration::from_array([
			'bot_categoriez' => [ // typo: should be bot_categories
				'blocked' => [
					'malicious'
				],
				'challenge' => [
					'social_crawler'
				]
			]
		]);

		$unknown = Diagnostics::unknown_keys();

		// Both sub-keys are unknown (parent is unknown)
		$this->assertArrayHasKey('bot_categoriez.blocked', $unknown);
		$this->assertArrayHasKey('bot_categoriez.challenge', $unknown);
	}

	public function test_partial_typo_only_flags_typo_keys(): void
	{
		Configuration::from_array([
			'preset' => 'minimal', // valid
			'strictness' => 'normal', // valid
			'dns_verfiction' => [
				'enabled' => true
			], // typo
			'dns_verification' => [
				'enabled' => true
			] // valid
		]);

		$unknown = Diagnostics::unknown_keys();

		$this->assertArrayHasKey('dns_verfiction.enabled', $unknown);
		$this->assertArrayNotHasKey('preset', $unknown);
		$this->assertArrayNotHasKey('strictness', $unknown);
		$this->assertArrayNotHasKey('dns_verification.enabled', $unknown);
	}

	public function test_adapter_argument_does_not_affect_diagnostics(): void
	{
		// Calling with adapter should not break diagnostics
		$adapter = new GenericAdapter();
		Configuration::from_array([
			'preset' => 'minimal',
			'dynamc' => true // typo
		], $adapter);

		$unknown = Diagnostics::unknown_keys();

		$this->assertArrayHasKey('dynamc', $unknown);
	}

	public function test_diagnostics_state_isolated_between_test_methods(): void
	{
		// setUp() calls reset(), so this should start fresh
		$this->assertSame([], Diagnostics::unknown_keys());
	}
}