<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCP\Sharing\Property;

use OCP\AppFramework\Attribute\Implementable;

/**
 * @since 34.0.0
 */
#[Implementable(since: '34.0.0')]
abstract readonly class ASharePropertyBoolean extends ASharePropertyEnum {
	/**
	 * @return non-empty-list<string>
	 */
	#[\Override]
	public function getValidValues(): array {
		return ['true', 'false'];
	}
}
