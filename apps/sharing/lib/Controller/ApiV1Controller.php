<?php

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace OCA\Sharing\Controller;

use OCA\Sharing\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\IUserSession;
use OCP\Sharing\Exception\ShareForbiddenException;
use OCP\Sharing\Exception\ShareInvalidException;
use OCP\Sharing\Exception\ShareNotFoundException;
use OCP\Sharing\IManager;
use OCP\Sharing\Permission\ISharePermission;
use OCP\Sharing\Permission\SharePermission;
use OCP\Sharing\Property\IShareProperty;
use OCP\Sharing\Property\ISharePropertyFilter;
use OCP\Sharing\Property\ShareProperty;
use OCP\Sharing\Recipient\IShareRecipientType;
use OCP\Sharing\Recipient\ShareRecipient;
use OCP\Sharing\Share;
use OCP\Sharing\ShareAccessContext;
use OCP\Sharing\ShareState;
use OCP\Sharing\Source\IShareSourceType;
use OCP\Sharing\Source\ShareSource;
use RuntimeException;
use ValueError;

// TODO: Add rate limiting
// TODO: Add federation

/**
 * @psalm-import-type SharingShare from ResponseDefinitions
 * @psalm-import-type SharingRecipient from ResponseDefinitions
 * @psalm-import-type SharingState from ResponseDefinitions
 */
final class ApiV1Controller extends OCSController {
	public ShareAccessContext $accessContext;

	public function __construct(
		string $appName,
		IRequest $request,
		IUserSession $userSession,
		private readonly IManager $manager,
	) {
		parent::__construct($appName, $request);

		$this->accessContext = new ShareAccessContext($userSession->getUser());
	}

	/**
	 * Search for recipients
	 *
	 * @param ?class-string<IShareRecipientType> $recipientType Type of the recipients
	 * @param non-empty-string $query The query to search for
	 * @param int<1, 100> $limit The maximum number of participants
	 * @param non-negative-int $offset The offset of the participants
	 * @return DataResponse<Http::STATUS_OK, list<SharingRecipient>, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, string, array{}>
	 *
	 * 200: Recipients returned
	 * 400: Invalid recipient search parameters
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/recipients')]
	public function searchRecipients(?string $recipientType, string $query, int $limit = 10, int $offset = 0): DataResponse {
		/** @psalm-suppress TypeDoesNotContainType */
		if ($query === '') {
			return new DataResponse('The query is empty.', Http::STATUS_BAD_REQUEST);
		}

		/** @psalm-suppress DocblockTypeContradiction */
		if ($limit < 1) {
			return new DataResponse('The limit is too low.', Http::STATUS_BAD_REQUEST);
		}

		/** @psalm-suppress DocblockTypeContradiction */
		if ($limit > 100) {
			return new DataResponse('The limit is too high.', Http::STATUS_BAD_REQUEST);
		}

		/** @psalm-suppress DocblockTypeContradiction */
		if ($offset < 0) {
			return new DataResponse('The offset is too low.', Http::STATUS_BAD_REQUEST);
		}

		try {
			$recipients = $this->manager->searchRecipients($this->accessContext, $recipientType, $query, $limit, $offset);
			return new DataResponse(ShareRecipient::formatMultiple($recipients));
		} catch (ShareInvalidException $shareInvalidException) {
			return new DataResponse($shareInvalidException->getMessage(), Http::STATUS_BAD_REQUEST);
		}
	}

	/**
	 * Create a new share
	 *
	 * @return DataResponse<Http::STATUS_CREATED, SharingShare, array{}>
	 *
	 * 201: Share created successfully
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'POST', url: '/api/v1/share')]
	public function createShare(): DataResponse {
		$id = $this->manager->createShare($this->accessContext);

		try {
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format(), Http::STATUS_CREATED);
		} catch (ShareNotFoundException $shareNotFoundException) {
			throw new RuntimeException($shareNotFoundException->getMessage(), $shareNotFoundException->getCode(), $shareNotFoundException);
		}
	}

	/**
	 * Update the state of a share
	 *
	 * @param string $id ID of the share
	 * @param SharingState $state New state of the share
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share state updated successfully
	 * 400: Invalid share state
	 * 403: Updating the share state is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'PUT', url: '/api/v1/share/{id}/state')]
	public function updateShareState(string $id, string $state): DataResponse {
		try {
			$shareState = ShareState::from($state);
		} catch (ValueError $valueError) {
			return new DataResponse($valueError->getMessage(), Http::STATUS_BAD_REQUEST);
		}

		try {
			$this->manager->updateShareState($this->accessContext, $id, $shareState);
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Add a source to a share
	 *
	 * @param string $id ID of the share
	 * @param class-string<IShareSourceType> $type Type of the source
	 * @param non-empty-string $value Value of the source
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share source added successfully
	 * 400: Invalid share source
	 * 403: Adding the share source is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'POST', url: '/api/v1/share/{id}/source')]
	public function addShareSource(string $id, string $type, string $value): DataResponse {
		try {
			$this->manager->addShareSource($this->accessContext, $id, new ShareSource($type, $value));
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareInvalidException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_BAD_REQUEST);
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Remove a source from a share
	 *
	 * @param string $id ID of the share
	 * @param class-string<IShareSourceType> $type Type of the source
	 * @param non-empty-string $value Value of the source
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share source removed successfully
	 * 403: Removing the share source is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/share/{id}/source')]
	public function removeShareSource(string $id, string $type, string $value): DataResponse {
		try {
			$this->manager->removeShareSource($this->accessContext, $id, new ShareSource($type, $value));
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Add a recipient to a share
	 *
	 * @param string $id ID of the share
	 * @param class-string<IShareRecipientType> $type Type of the recipient
	 * @param non-empty-string $value Value of the recipient
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share recipient added successfully
	 * 400: Invalid share recipient
	 * 403: Adding the share recipient is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'POST', url: '/api/v1/share/{id}/recipient')]
	public function addShareRecipient(string $id, string $type, string $value): DataResponse {
		try {
			$this->manager->addShareRecipient($this->accessContext, $id, new ShareRecipient($type, $value));
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareInvalidException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_BAD_REQUEST);
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Remove a recipient from a share
	 *
	 * @param string $id ID of the share
	 * @param class-string<IShareRecipientType> $type Type of the recipient
	 * @param non-empty-string $value Value of the recipient
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share recipient removed successfully
	 * 403: Removing the share recipient is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/share/{id}/recipient')]
	public function removeShareRecipient(string $id, string $type, string $value): DataResponse {
		try {
			$this->manager->removeShareRecipient($this->accessContext, $id, new ShareRecipient($type, $value));
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Update a property of a share
	 *
	 * @param string $id ID of the share
	 * @param class-string<IShareProperty> $type Type of the property
	 * @param ?string $value Value of the property
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share property updated successfully
	 * 400: Invalid share property
	 * 403: Updating the share property is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'PUT', url: '/api/v1/share/{id}/property')]
	public function updateShareProperty(string $id, string $type, ?string $value): DataResponse {
		try {
			$this->manager->updateShareProperty($this->accessContext, $id, new ShareProperty($type, $value));
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareInvalidException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_BAD_REQUEST);
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Update a permission of a share
	 *
	 * @param string $id ID of the share
	 * @param class-string<ISharePermission> $type Type of the permission
	 * @param bool $enabled Enabled state of the permission
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share permission updated successfully
	 * 400: Invalid share permission
	 * 403: Updating the share permission is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'PUT', url: '/api/v1/share/{id}/enabled')]
	public function updateSharePermission(string $id, string $type, bool $enabled): DataResponse {
		try {
			$this->manager->updateSharePermission($this->accessContext, $id, new SharePermission($type, $enabled));
			$share = $this->manager->getShare($this->accessContext, $id);
			return new DataResponse($share->format());
		} catch (ShareInvalidException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_BAD_REQUEST);
		} catch (ShareForbiddenException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_FORBIDDEN);
		} catch (ShareNotFoundException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * Gets a share
	 *
	 * @param string $id ID of the share
	 * @param array<class-string<IShareRecipientType|ISharePropertyFilter>, mixed> $arguments Arguments for accessing the share
	 * @return DataResponse<Http::STATUS_OK, SharingShare, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 200: Share returned
	 * 400: Invalid arguments
	 * 404: Share not found
	 */
	#[PublicPage]
	// This should be a GET, but GET doesn't allow a request body which is required for the $arguments.
	#[ApiRoute(verb: 'POST', url: '/api/v1/share/{id}')]
	public function getShare(string $id, array $arguments = []): DataResponse {
		try {
			$share = $this->manager->getShare(new ShareAccessContext($this->accessContext->currentUser, $arguments, $this->accessContext->force), $id);
			return new DataResponse($share->format());
		} catch (ShareInvalidException $e) {
			return new DataResponse($e->getMessage(), Http::STATUS_BAD_REQUEST);
		} catch (ShareNotFoundException $shareNotFoundException) {
			return new DataResponse($shareNotFoundException->getMessage(), Http::STATUS_NOT_FOUND);
		}
	}

	/**
	 * List shares
	 *
	 * @param ?class-string<IShareSourceType> $sourceType Filter by source type.
	 * @param ?string $lastShareID The ID of the previous share. This is used as an offset and only shares with higher IDs are returned.
	 * @param int<1, 100> $limit The number of shares to return.
	 * @return DataResponse<Http::STATUS_OK, list<SharingShare>, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, string, array{}>
	 *
	 * 200: Shares returned
	 * 400: Invalid parameters
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/shares')]
	public function listShares(?string $sourceType = null, ?string $lastShareID = null, int $limit = 100): DataResponse {
		/** @psalm-suppress DocblockTypeContradiction */
		if ($limit < 1) {
			return new DataResponse('The limit is too low.', Http::STATUS_BAD_REQUEST);
		}

		/** @psalm-suppress DocblockTypeContradiction */
		if ($limit > 100) {
			return new DataResponse('The limit is too high.', Http::STATUS_BAD_REQUEST);
		}

		try {
			$shares = $this->manager->listShares($this->accessContext, $sourceType, $lastShareID, $limit);
			return new DataResponse(array_map(static fn (Share $share): array => $share->format(), $shares));
		} catch (ShareInvalidException $shareInvalidException) {
			return new DataResponse($shareInvalidException->getMessage(), Http::STATUS_BAD_REQUEST);
		}
	}

	/**
	 * Delete a share
	 *
	 * @param string $id ID of the share
	 * @return DataResponse<Http::STATUS_NO_CONTENT, list<empty>, array{}>|DataResponse<Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, string, array{}>
	 *
	 * 204: Share deleted
	 * 403: Deleting the share is not allowed
	 * 404: Share not found
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/share/{id}')]
	public function deleteShare(string $id): DataResponse {
		try {
			$this->manager->deleteShare($this->accessContext, $id);
			return new DataResponse([], Http::STATUS_NO_CONTENT);
		} catch (ShareNotFoundException $shareNotFoundException) {
			return new DataResponse($shareNotFoundException->getMessage(), Http::STATUS_NOT_FOUND);
		} catch (ShareForbiddenException $shareOperationNotAllowedException) {
			return new DataResponse($shareOperationNotAllowedException->getMessage(), Http::STATUS_FORBIDDEN);
		}
	}
}
