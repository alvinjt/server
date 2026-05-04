<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCA\Files\Sharing\Permission;

use OC\Core\AppInfo\Application;
use OC\Core\Sharing\Permission\UpdateSharePermissionCategory;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\Sharing\Permission\ISharePermission;

final class NodeUpdateSharePermission implements ISharePermission {
	#[\Override]
	public function getDisplayName(): string {
		return Server::get(IFactory::class)->get(Application::APP_ID)->t('Update and rename files and move and rename folders');
	}

	#[\Override]
	public function getCategory(): string {
		return UpdateSharePermissionCategory::class;
	}

	#[\Override]
	public function getDefault(): ?bool {
		return null;
	}
}
