<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace Test\Sharing\Property;

use OCP\Sharing\Property\ASharePropertyString;
use Test\TestCase;

final readonly class TestSharePropertyString extends ASharePropertyString {
	public function __construct(
		/** @var ?positive-int $minLength */
		public ?int $minLength,
		/** @var ?positive-int $maxLength */
		public ?int $maxLength,
	) {
	}

	#[\Override]
	public function getMinLength(): ?int {
		return $this->minLength;
	}

	#[\Override]
	public function getMaxLength(): ?int {
		return $this->maxLength;
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

final class ASharePropertyStringTest extends TestCase {
	private ASharePropertyString $property;

	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->property = new TestSharePropertyString(
			3,
			5,
		);
	}

	public function testValiStringValue(): void {
		$this->assertIsString($this->property->validateValue('ab'));
		$this->assertTrue($this->property->validateValue('abc'));
		$this->assertTrue($this->property->validateValue('abcd'));
		$this->assertTrue($this->property->validateValue('abcde'));
		$this->assertIsString($this->property->validateValue('abcdef'));
	}
}
