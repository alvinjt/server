<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace Test\Sharing\Property;

use OCP\Sharing\Property\ASharePropertyBoolean;
use Test\TestCase;

final readonly class TestSharePropertyBoolean extends ASharePropertyBoolean {
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

final class ASharePropertyBooleanTest extends TestCase {
	private ASharePropertyBoolean $property;

	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->property = new TestSharePropertyBoolean();
	}

	public function testValidateValue(): void {
		$this->assertTrue($this->property->validateValue('true'));
		$this->assertTrue($this->property->validateValue('false'));
		$this->assertIsString($this->property->validateValue(''));
		$this->assertIsString($this->property->validateValue('invalid'));
	}
}
