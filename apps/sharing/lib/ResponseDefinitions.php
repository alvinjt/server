<?php

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCA\Sharing;

use OCP\Sharing\Permission\ISharePermission;
use OCP\Sharing\Permission\ISharePermissionCategory;
use OCP\Sharing\Property\IShareProperty;
use OCP\Sharing\Recipient\IShareRecipientType;
use OCP\Sharing\Source\IShareSourceType;

/**
 * Keep the following types in sync with lib/public/Sharing/Share.php:
 *
 * @psalm-type SharingSource = array{
 *     type: class-string<IShareSourceType>,
 *     value: non-empty-string,
 *     display_name: non-empty-string,
 * }
 *
 * @psalm-type SharingIconSVG = array{
 *     svg: non-empty-string,
 * }
 *
 * @psalm-type SharingIconURL = array{
 *     // An absolute URL to an image suitable for light theme.
 *     light: non-empty-string,
 *     // An absolute URL to an image suitable for dark theme.
 *     dark: non-empty-string,
 * }
 *
 * @psalm-type SharingIcon = SharingIconSVG|SharingIconURL
 *
 * @psalm-type SharingRecipient = array{
 *     type: class-string<IShareRecipientType>,
 *     value: non-empty-string,
 *     instance?: non-empty-string,
 *     display_name: non-empty-string,
 *     icon?: SharingIcon,
 * }
 *
 * @psalm-type SharingOwner = array{
 *     user_id: non-empty-string,
 *     instance?: non-empty-string,
 *     display_name: non-empty-string,
 *     icon: SharingIconURL,
 * }
 *
 * @psalm-type SharingState = 'active'|'draft'|'deleted'
 *
 * @psalm-type SharingProperty = array{
 *     type: class-string<IShareProperty>,
 *     display_name: non-empty-string,
 *     hint?: non-empty-string,
 *     priority: int<1, 100>,
 *     required: bool,
 *     value: ?string,
 * }
 *
 * @psalm-type SharingPropertyDate = SharingProperty&array{
 *     // ISO 8601
 *     min_date?: non-empty-string,
 *     // ISO 8601
 *     max_date?: non-empty-string,
 * }
 *
 * @psalm-type SharingPropertyEnum = SharingProperty&array{
 *     valid_values: non-empty-list<string>,
 * }
 *
 * @psalm-type SharingPropertyBoolean = SharingProperty
 *
 * @psalm-type SharingPropertyPassword = SharingProperty
 *
 * @psalm-type SharingPropertyString = SharingProperty&array{
 *     min_length?: positive-int,
 *     max_length?: positive-int,
 * }
 *
 * @psalm-type SharingPermission = array{
 *     type: class-string<ISharePermission>,
 *     display_name: non-empty-string,
 *     category: ?class-string<ISharePermissionCategory>,
 *     enabled: bool,
 * }
 *
 * @psalm-type SharingShare = array{
 *     id: non-empty-string,
 *     owner: SharingOwner,
 *     // Unix time in milliseconds
 *     last_updated: non-negative-int,
 *     state: SharingState,
 *     sources: list<SharingSource>,
 *     recipients: list<SharingRecipient>,
 *     properties: list<SharingPropertyDate|SharingPropertyEnum|SharingPropertyBoolean|SharingPropertyPassword|SharingPropertyString>,
 *     permissions: list<SharingPermission>,
 * }
 */
final class ResponseDefinitions {
}
