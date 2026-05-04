<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCA\Sharing\Tests;

use OCP\Sharing\Property\ISharePropertyFilter;
use OCP\Sharing\Share;
use OCP\Sharing\ShareAccessContext;

final class TestSharePropertyFilter implements ISharePropertyFilter {
	#[\Override]
	public function getDisplayName(): string {
		/** @var non-empty-list<non-empty-string> $parts */
		$parts = explode('\\', self::class);
		return end($parts);
	}

	#[\Override]
	public function getHint(): ?string {
		return null;
	}

	#[\Override]
	public function getPriority(): int {
		return 1;
	}

	#[\Override]
	public function getRequired(): bool {
		return false;
	}

	#[\Override]
	public function getDefaultValue(): ?string {
		return null;
	}

	#[\Override]
	public function validateValue(string $value): true|string {
		return true;
	}

	#[\Override]
	public function isFiltered(ShareAccessContext $accessContext, Share $share): bool {
		if (($accessContext->arguments[self::class] ?? null) === 'filtered') {
			return true;
		}

		foreach ($share->properties as $property) {
			if ($property->type === self::class && $property->value === 'filtered') {
				return true;
			}
		}

		return false;
	}

	#[\Override]
	public function format(array $property): array {
		return $property;
	}
}
