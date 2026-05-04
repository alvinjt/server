/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

const allowlists = new Map<string, ReadonlySet<string>>()

/**
 * Restrict the file actions exposed in a given view to the listed action IDs.
 *
 * Useful for views that list metadata rather than mounted filesystem entries
 * (pending shares, deleted shares), where generic file operations cannot
 * succeed and produce a misleading "file is not available" error.
 *
 * Default (view never registered here): all actions are candidates.
 * The action's own `enabled()` predicate still applies on top.
 *
 * @param viewId - The view to restrict
 * @param actionIds - The IDs of the only actions allowed in that view
 */
export function restrictViewActions(viewId: string, actionIds: readonly string[]): void {
	allowlists.set(viewId, new Set(actionIds))
}

/**
 * Check if the given action is allowed in the given view.
 *
 * @param viewId - The view ID, or undefined when no view is active
 * @param actionId - The action ID
 */
export function isActionAllowedInView(viewId: string | undefined, actionId: string): boolean {
	if (viewId === undefined) {
		return true
	}
	const allowlist = allowlists.get(viewId)
	return allowlist === undefined || allowlist.has(actionId)
}
