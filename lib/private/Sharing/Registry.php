<?php

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OC\Sharing;

use OCP\Sharing\IRegistry;
use OCP\Sharing\Permission\ISharePermission;
use OCP\Sharing\Permission\ISharePermissionCategory;
use OCP\Sharing\Property\IShareProperty;
use OCP\Sharing\Recipient\IShareRecipientType;
use OCP\Sharing\Source\IShareSourceType;
use RuntimeException;

final class Registry implements IRegistry {
	/** @var array<class-string<IShareSourceType>, IShareSourceType> */
	private array $sourceTypes = [];

	/** @var array<class-string<IShareRecipientType>, IShareRecipientType> */
	private array $recipientTypes = [];

	/** @var array<class-string<IShareProperty>, IShareProperty> */
	private array $properties = [];

	/** @var array<class-string<IShareProperty>, array<class-string<IShareSourceType>, bool>> */
	private array $propertyCompatibleSourceTypes = [];

	/** @var array<class-string<IShareProperty>, array<class-string<IShareRecipientType>, bool>> */
	private array $propertyCompatibleRecipientTypes = [];

	/** @var array<class-string<ISharePermissionCategory>, ISharePermissionCategory> */
	private array $permissionCategories = [];

	/** @var array<class-string<ISharePermission>, ISharePermission> */
	private array $permissions = [];

	/** @var array<class-string<IShareSourceType>, list<class-string<ISharePermission>>> */
	private array $sourceTypePermissions = [];

	/** @var array<class-string<ISharePermission>, class-string<IShareSourceType>> */
	private array $permissionSourceType = [];

	#[\Override]
	public function clear(): void {
		$this->sourceTypes = [];
		$this->recipientTypes = [];
		$this->properties = [];
		$this->propertyCompatibleSourceTypes = [];
		$this->propertyCompatibleRecipientTypes = [];
		$this->permissionCategories = [];
		$this->permissions = [];
		$this->sourceTypePermissions = [];
		$this->permissionSourceType = [];
	}

	#[\Override]
	public function registerSourceType(IShareSourceType $sourceType): void {
		$class = $sourceType::class;

		if (isset($this->sourceTypes[$class])) {
			throw new RuntimeException('Share source type ' . $class . ' is already registered');
		}

		$this->sourceTypes[$class] = $sourceType;
	}

	/**
	 * @return array<class-string<IShareSourceType>, IShareSourceType>
	 */
	#[\Override]
	public function getSourceTypes(): array {
		return $this->sourceTypes;
	}

	#[\Override]
	public function getSourceTypesCompatibleWithProperty(string $propertyClass): array {
		$sourceTypeClasses = array_keys($this->propertyCompatibleSourceTypes[$propertyClass] ?? []);
		foreach ($sourceTypeClasses as $sourceTypeClass) {
			if (!isset($this->sourceTypes[$sourceTypeClass])) {
				// Because we can't control the order in which apps are booted, we need to check now if it has been registered.
				throw new RuntimeException('Share source type ' . $sourceTypeClass . ' is not registered');
			}
		}

		return $sourceTypeClasses;
	}

	#[\Override]
	public function registerRecipientType(IShareRecipientType $recipientType): void {
		$class = $recipientType::class;

		if (isset($this->recipientTypes[$class])) {
			throw new RuntimeException('Share recipient type ' . $class . ' is already registered');
		}

		$this->recipientTypes[$class] = $recipientType;
	}

	/**
	 * @return array<class-string<IShareRecipientType>, IShareRecipientType>
	 */
	#[\Override]
	public function getRecipientTypes(): array {
		return $this->recipientTypes;
	}

	#[\Override]
	public function getRecipientTypesCompatibleWithProperty(string $propertyClass): array {
		$recipientTypeClasses = array_keys($this->propertyCompatibleRecipientTypes[$propertyClass] ?? []);
		foreach ($recipientTypeClasses as $recipientTypeClass) {
			if (!isset($this->recipientTypes[$recipientTypeClass])) {
				// Because we can't control the order in which apps are booted, we need to check now if it has been registered.
				throw new RuntimeException('Share recipient type ' . $recipientTypeClass . ' is not registered');
			}
		}

		return $recipientTypeClasses;
	}

	#[\Override]
	public function registerProperty(IShareProperty $property): void {
		$class = $property::class;

		if (isset($this->properties[$class])) {
			throw new RuntimeException('Share property ' . $class . ' is already registered');
		}

		$this->properties[$class] = $property;
	}

	#[\Override]
	public function registerPropertyCompatibleWithSourceType(string $propertyClass, string $sourceTypeClass): void {
		// Because we can't control the order in which apps are booted, we can't ensure that the source type is already registered.
		$this->propertyCompatibleSourceTypes[$propertyClass] ??= [];
		$this->propertyCompatibleSourceTypes[$propertyClass][$sourceTypeClass] = true;
	}

	#[\Override]
	public function registerPropertyCompatibleWithRecipientType(string $propertyClass, string $recipientTypeClass): void {
		// Because we can't control the order in which apps are booted, we can't ensure that the source type is already registered.
		$this->propertyCompatibleRecipientTypes[$propertyClass] ??= [];
		$this->propertyCompatibleRecipientTypes[$propertyClass][$recipientTypeClass] = true;
	}

	/**
	 * @return array<class-string<IShareProperty>, IShareProperty>
	 */
	#[\Override]
	public function getProperties(): array {
		return $this->properties;
	}

	#[\Override]
	public function registerPermissionCategory(ISharePermissionCategory $permissionCategory): void {
		$class = $permissionCategory::class;

		if (isset($this->permissionCategories[$class])) {
			throw new RuntimeException('Share permission category ' . $class . ' is already registered');
		}

		$this->permissionCategories[$class] = $permissionCategory;
	}

	/**
	 * @return array<class-string<ISharePermissionCategory>, ISharePermissionCategory>
	 */
	#[\Override]
	public function getPermissionCategories(): array {
		return $this->permissionCategories;
	}

	#[\Override]
	public function registerPermission(string $sourceTypeClass, ISharePermission $permission): void {
		if (!isset($this->sourceTypes[$sourceTypeClass])) {
			throw new RuntimeException('Share source type ' . $sourceTypeClass . ' is not registered');
		}

		$class = $permission::class;
		if (isset($this->permissions[$class])) {
			throw new RuntimeException('Share permission ' . $class . ' is already registered');
		}

		$permissionCategoryClass = $permission->getCategory();
		if ($permissionCategoryClass !== null && !isset($this->permissionCategories[$permissionCategoryClass])) {
			throw new RuntimeException('Share permission category ' . $permissionCategoryClass . ' is not registered');
		}

		$this->permissions[$class] = $permission;
		$this->sourceTypePermissions[$sourceTypeClass] ??= [];
		$this->sourceTypePermissions[$sourceTypeClass][] = $class;
		$this->permissionSourceType[$class] = $sourceTypeClass;
	}

	/**
	 * @return array<class-string<ISharePermission>, ISharePermission>
	 */
	#[\Override]
	public function getPermissions(): array {
		return $this->permissions;
	}

	/**
	 * @return array<class-string<IShareSourceType>, list<class-string<ISharePermission>>>
	 */
	#[\Override]
	public function getSourceTypePermissions(): array {
		return $this->sourceTypePermissions;
	}

	/**
	 * @return array<class-string<ISharePermission>, class-string<IShareSourceType>>
	 */
	#[\Override]
	public function getPermissionSourceType(): array {
		return $this->permissionSourceType;
	}
}
