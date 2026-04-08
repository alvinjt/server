<?php

namespace OCP\User\Backend;

/**
 * @since 34.0.0
 */
interface IGetUserNameFromLoginNameBackend {
	/**
	 * Returns the username for the given login name in the correct casing
	 *
	 * @since 34.0.0
	 */
	public function getUserNameFromLoginName(string $loginName): string|false;
}
