<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCA\Sharing\Tests;

use OCP\Sharing\Property\ISharePropertyModifyValue;

final class TestSharePropertyModifyValue implements ISharePropertyModifyValue {
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
	public function modifyValueOnSave(?string $oldValue, ?string $newValue): ?string {
		if ($newValue === 'modify-on-save') {
			return 'modified-on-save';
		}

		if ($newValue === 'modify-on-save-old-value') {
			return $oldValue;
		}

		return $newValue;
	}

	#[\Override]
	public function modifyValueOnLoad(?string $value): ?string {
		if ($value === 'modify-on-load') {
			return 'modified-on-load';
		}

		return $value;
	}

	#[\Override]
	public function format(array $property): array {
		return $property;
	}
}
