<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace Test\Sharing\Property;

use OCP\EventDispatcher\IEventDispatcher;
use OCP\HintException;
use OCP\Security\Events\ValidatePasswordPolicyEvent;
use OCP\Security\IHasher;
use OCP\Server;
use OCP\Sharing\Property\ASharePropertyPassword;
use RuntimeException;
use Test\TestCase;

final readonly class TestSharePropertyPassword extends ASharePropertyPassword {
	#[\Override]
	public function getDisplayName(): string {
		throw new RuntimeException();
	}

	#[\Override]
	public function getHint(): ?string {
		throw new RuntimeException();
	}

	#[\Override]
	public function getPriority(): int {
		throw new RuntimeException();
	}

	#[\Override]
	public function getRequired(): bool {
		throw new RuntimeException();
	}

	#[\Override]
	public function getDefaultValue(): ?string {
		throw new RuntimeException();
	}
}

final class ASharePropertyPasswordTest extends TestCase {
	private ASharePropertyPassword $property;

	private IEventDispatcher $eventDispatcher;

	/**
	 * @var callable(ValidatePasswordPolicyEvent):void $validatePasswordPolicyEventListener
	 */
	private $validatePasswordPolicyEventListener;


	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->property = new TestSharePropertyPassword();

		$this->eventDispatcher = Server::get(IEventDispatcher::class);
		$this->validatePasswordPolicyEventListener = static function (ValidatePasswordPolicyEvent $event): void {
			if ($event->getPassword() !== 'secure') {
				throw new HintException('insecure message', 'insecure hint');
			}
		};

		$this->eventDispatcher->addListener(ValidatePasswordPolicyEvent::class, $this->validatePasswordPolicyEventListener);
	}

	#[\Override]
	protected function tearDown(): void {
		$this->eventDispatcher->removeListener(ValidatePasswordPolicyEvent::class, $this->validatePasswordPolicyEventListener);

		parent::tearDown();
	}

	public function testValidateValue(): void {
		$this->assertTrue($this->property->validateValue('secure'));
		$this->assertIsString($this->property->validateValue('123'));
	}

	public function testModifyValueOnFetch(): void {
		$this->assertNull($this->property->modifyValueOnLoad(null));
		$this->assertEquals(ASharePropertyPassword::PLACEHOLDER, $this->property->modifyValueOnLoad(''));
	}

	public function testModifyValueOnSave(): void {
		$this->assertNull($this->property->modifyValueOnSave('old hash', null));

		$this->assertEquals('old hash', $this->property->modifyValueOnSave('old hash', ASharePropertyPassword::PLACEHOLDER));

		$newHash = $this->property->modifyValueOnSave('old hash', 'password');
		$this->assertNotNull($newHash);
		$this->assertNotEquals('old hash', $newHash);
		$this->assertTrue(Server::get(IHasher::class)->verify('password', $newHash));
	}
}
