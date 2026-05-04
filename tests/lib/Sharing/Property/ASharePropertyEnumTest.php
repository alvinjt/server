<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace Test\Sharing\Property;

use OCP\Sharing\Property\ASharePropertyEnum;
use Test\TestCase;

final readonly class TestSharePropertyEnum extends ASharePropertyEnum {
	public function __construct(
		/** @var non-empty-list<string> $validValues */
		public array $validValues,
	) {
	}

	/**
	 * @return non-empty-list<string>
	 */
	#[\Override]
	public function getValidValues(): array {
		return $this->validValues;
	}

	#[\Override]
	public function getDisplayName(): string {
		throw new \RuntimeException();
	}

	#[\Override]
	public function getHint(): ?string {
		throw new \RuntimeException();
	}

	#[\Override]
	public function getPriority(): int {
		throw new \RuntimeException();
	}

	#[\Override]
	public function getRequired(): bool {
		throw new \RuntimeException();
	}

	#[\Override]
	public function getDefaultValue(): ?string {
		throw new \RuntimeException();
	}
}

final class ASharePropertyEnumTest extends TestCase {
	private ASharePropertyEnum $property;

	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->property = new TestSharePropertyEnum(['valid']);
	}

	public function testValidateValue(): void {
		$this->assertTrue($this->property->validateValue('valid'));
		$this->assertIsString($this->property->validateValue('invalid'));
	}
}
