<?php

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCP\Sharing;

use OCP\AppFramework\Attribute\Consumable;
use OCP\Sharing\Permission\ISharePermission;
use OCP\Sharing\Permission\ISharePermissionCategory;
use OCP\Sharing\Property\IShareProperty;
use OCP\Sharing\Recipient\IShareRecipientType;
use OCP\Sharing\Source\IShareSourceType;

/**
 * @since 34.0.0
 */
#[Consumable(since: '34.0.0')]
interface IRegistry {

	public function clear(): void;

	public function registerSourceType(IShareSourceType $sourceType): void;

	/**
	 * @return array<class-string<IShareSourceType>, IShareSourceType>
	 */
	public function getSourceTypes(): array;

	/**
	 * @param class-string<IShareProperty> $propertyClass
	 * @return list<class-string<IShareSourceType>>
	 */
	public function getSourceTypesCompatibleWithProperty(string $propertyClass): array;

	public function registerRecipientType(IShareRecipientType $recipientType): void;


	/**
	 * @return array<class-string<IShareRecipientType>, IShareRecipientType>
	 */
	public function getRecipientTypes(): array;

	/**
	 * @param class-string<IShareProperty> $propertyClass
	 * @return list<class-string<IShareRecipientType>>
	 */
	public function getRecipientTypesCompatibleWithProperty(string $propertyClass): array;

	public function registerProperty(IShareProperty $property): void;

	/**
	 * @param class-string<IShareProperty> $propertyClass
	 * @param class-string<IShareSourceType> $sourceTypeClass
	 */
	public function registerPropertyCompatibleWithSourceType(string $propertyClass, string $sourceTypeClass): void;

	/**
	 * @param class-string<IShareProperty> $propertyClass
	 * @param class-string<IShareRecipientType> $recipientTypeClass
	 */
	public function registerPropertyCompatibleWithRecipientType(string $propertyClass, string $recipientTypeClass): void;

	/**
	 * @return array<class-string<IShareProperty>, IShareProperty>
	 */
	public function getProperties(): array;

	public function registerPermissionCategory(ISharePermissionCategory $permissionCategory): void;

	/**
	 * @return array<class-string<ISharePermissionCategory>, ISharePermissionCategory>
	 */
	public function getPermissionCategories(): array;

	/**
	 * @param class-string<IShareSourceType> $sourceTypeClass
	 */
	public function registerPermission(string $sourceTypeClass, ISharePermission $permission): void;

	/**
	 * @return array<class-string<ISharePermission>, ISharePermission>
	 */
	public function getPermissions(): array;

	/**
	 * @return array<class-string<IShareSourceType>, list<class-string<ISharePermission>>>
	 */
	public function getSourceTypePermissions(): array;

	/**
	 * @return array<class-string<ISharePermission>, class-string<IShareSourceType>>
	 */
	public function getPermissionSourceType(): array;
}
