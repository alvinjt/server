<?php

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace Test\Sharing;

use OCA\Sharing\Tests\TestSharePermission;
use OCA\Sharing\Tests\TestSharePermissionCategory;
use OCA\Sharing\Tests\TestShareProperty;
use OCA\Sharing\Tests\TestShareRecipientType;
use OCA\Sharing\Tests\TestShareRecipientType2;
use OCA\Sharing\Tests\TestShareSourceType;
use OCA\Sharing\Tests\TestShareSourceType2;
use OCP\Server;
use OCP\Sharing\IRegistry;
use RuntimeException;
use Test\TestCase;

final class RegistryTest extends TestCase {
	private IRegistry $registry;

	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->registry = Server::get(IRegistry::class);
		$this->registry->clear();
	}

	#[\Override]
	protected function tearDown(): void {
		$this->registry->clear();

		parent::tearDown();
	}

	public function testClear(): void {
		$this->registry->registerSourceType(new TestShareSourceType([]));
		$this->registry->registerRecipientType(new TestShareRecipientType([], [], []));
		$this->registry->registerProperty(new TestShareProperty(['']));
		$this->registry->registerPropertyCompatibleWithSourceType(TestShareProperty::class, TestShareSourceType::class);
		$this->registry->registerPropertyCompatibleWithRecipientType(TestShareProperty::class, TestShareRecipientType::class);
		$this->registry->registerPermissionCategory(new TestSharePermissionCategory());
		$this->registry->registerPermission(TestShareSourceType::class, new TestSharePermission());

		$this->registry->clear();

		$this->assertEquals([], $this->registry->getSourceTypes());
		$this->assertEquals([], $this->registry->getRecipientTypes());
		$this->assertEquals([], $this->registry->getProperties());
		$this->assertEquals([], $this->registry->getSourceTypesCompatibleWithProperty(TestShareProperty::class));
		$this->assertEquals([], $this->registry->getRecipientTypesCompatibleWithProperty(TestShareProperty::class));
		$this->assertEquals([], $this->registry->getPermissionCategories());
		$this->assertEquals([], $this->registry->getPermissions());
	}

	public function testRegisterSourceType(): void {
		$sourceType = new TestShareSourceType([]);
		$this->registry->registerSourceType($sourceType);

		$this->assertEquals([$sourceType::class => $sourceType], $this->registry->getSourceTypes());

		$this->expectException(RuntimeException::class);
		$this->registry->registerSourceType($sourceType);
	}

	public function testRegisterRecipientType(): void {
		$recipientType = new TestShareRecipientType([], [], []);
		$this->registry->registerRecipientType($recipientType);

		$this->assertEquals([$recipientType::class => $recipientType], $this->registry->getRecipientTypes());

		$this->expectException(RuntimeException::class);
		$this->registry->registerRecipientType($recipientType);
	}

	public function testRegisterProperty(): void {
		$property = new TestShareProperty(['']);
		$this->registry->registerProperty($property);

		$this->assertEquals([$property::class => $property], $this->registry->getProperties());

		$this->expectException(RuntimeException::class);
		$this->registry->registerProperty($property);
	}

	public function testRegisterPropertyCompatibleWithSourceType(): void {
		$sourceType = new TestShareSourceType([]);
		$this->registry->registerSourceType($sourceType);

		$property = new TestShareProperty(['']);
		$this->registry->registerProperty($property);
		$this->registry->registerPropertyCompatibleWithSourceType($property::class, $sourceType::class);
		$this->registry->registerPropertyCompatibleWithSourceType($property::class, $sourceType::class);

		$this->assertEquals([$sourceType::class], $this->registry->getSourceTypesCompatibleWithProperty($property::class));

		$this->registry->registerPropertyCompatibleWithSourceType($property::class, TestShareSourceType2::class);
		$this->expectException(RuntimeException::class);
		$this->registry->getSourceTypesCompatibleWithProperty($property::class);
	}

	public function testRegisterPropertyCompatibleWithRecipientType(): void {
		$recipientType = new TestShareRecipientType([], [], []);
		$this->registry->registerRecipientType($recipientType);

		$property = new TestShareProperty(['']);
		$this->registry->registerProperty($property);
		$this->registry->registerPropertyCompatibleWithRecipientType($property::class, $recipientType::class);
		$this->registry->registerPropertyCompatibleWithRecipientType($property::class, $recipientType::class);

		$this->assertEquals([$recipientType::class], $this->registry->getRecipientTypesCompatibleWithProperty($property::class));

		$this->registry->registerPropertyCompatibleWithRecipientType($property::class, TestShareRecipientType2::class);
		$this->expectException(RuntimeException::class);
		$this->registry->getRecipientTypesCompatibleWithProperty($property::class);
	}

	public function testRegisterPermissionCategory(): void {
		$permissionCategory = new TestSharePermissionCategory();
		$this->registry->registerPermissionCategory($permissionCategory);

		$this->assertEquals([$permissionCategory::class => $permissionCategory], $this->registry->getPermissionCategories());

		$this->expectException(RuntimeException::class);
		$this->registry->registerPermissionCategory($permissionCategory);
	}

	public function testRegisterPermission(): void {
		$sourceType = new TestShareSourceType([]);
		$this->registry->registerSourceType($sourceType);

		$permissionCategory = new TestSharePermissionCategory();
		$this->registry->registerPermissionCategory($permissionCategory);

		$permission = new TestSharePermission();
		$this->registry->registerPermission($sourceType::class, $permission);

		$this->assertEquals([$permission::class => $permission], $this->registry->getPermissions());

		$this->expectException(RuntimeException::class);
		$this->registry->registerPermission($sourceType::class, $permission);
	}
}
