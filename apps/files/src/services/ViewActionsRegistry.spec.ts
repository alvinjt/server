/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, it } from 'vitest'
import { isActionAllowedInView, restrictViewActions } from './ViewActionsRegistry.ts'

describe('ViewActionsRegistry', () => {
	it('allows any action in views that have not been restricted', () => {
		expect(isActionAllowedInView('unrestricted-view', 'delete')).toBe(true)
		expect(isActionAllowedInView('unrestricted-view', 'download')).toBe(true)
	})

	it('allows any action when no view is active', () => {
		expect(isActionAllowedInView(undefined, 'delete')).toBe(true)
	})

	it('only allows actions in the allowlist for restricted views', () => {
		restrictViewActions('pendingshares', ['accept-share', 'reject-share'])

		expect(isActionAllowedInView('pendingshares', 'accept-share')).toBe(true)
		expect(isActionAllowedInView('pendingshares', 'reject-share')).toBe(true)
		expect(isActionAllowedInView('pendingshares', 'delete')).toBe(false)
		expect(isActionAllowedInView('pendingshares', 'download')).toBe(false)
		expect(isActionAllowedInView('pendingshares', 'sharing-status')).toBe(false)
	})

	it('does not affect siblings when one view is restricted', () => {
		restrictViewActions('deletedshares', ['restore-share'])

		expect(isActionAllowedInView('deletedshares', 'restore-share')).toBe(true)
		expect(isActionAllowedInView('deletedshares', 'delete')).toBe(false)
		// A sibling view that has not been restricted is still wide open.
		expect(isActionAllowedInView('files', 'delete')).toBe(true)
	})

	it('replaces the allowlist when called twice for the same view', () => {
		restrictViewActions('view-a', ['action-1'])
		restrictViewActions('view-a', ['action-2'])

		expect(isActionAllowedInView('view-a', 'action-1')).toBe(false)
		expect(isActionAllowedInView('view-a', 'action-2')).toBe(true)
	})
})
