<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace Test\Sharing\Property;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use OCP\Sharing\Property\ASharePropertyDate;
use Test\TestCase;

final readonly class TestSharePropertyDate extends ASharePropertyDate {
	public function __construct(
		public ?DateTimeImmutable $minDate,
		public ?DateTimeImmutable $maxDate,
	) {
	}

	#[\Override]
	public function getMinDate(): ?DateTimeImmutable {
		return $this->minDate;
	}

	#[\Override]
	public function getMaxDate(): ?DateTimeImmutable {
		return $this->maxDate;
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

final class ASharePropertyDateTest extends TestCase {
	private DateTimeImmutable $now;

	private ASharePropertyDate $property;

	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->now = new DateTimeImmutable();
		$this->property = new TestSharePropertyDate(
			$this->now->sub(new DateInterval('PT1M')),
			$this->now->add(new DateInterval('PT1M')),
		);
	}

	public function testValidateValue(): void {
		$this->assertTrue($this->property->validateValue($this->now->format(DateTimeInterface::ATOM)));
		$this->assertIsString($this->property->validateValue($this->now->sub(new DateInterval('PT2M'))->format(DateTimeInterface::ATOM)));
		$this->assertIsString($this->property->validateValue($this->now->add(new DateInterval('PT2M'))->format(DateTimeInterface::ATOM)));
	}
}
