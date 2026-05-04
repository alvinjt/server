<?php

/**
 * SPDX-FileCopyrightText: 2016-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OC\Core\AppInfo;

use OC\Authentication\Events\RemoteWipeFinished;
use OC\Authentication\Events\RemoteWipeStarted;
use OC\Authentication\Listeners\RemoteWipeActivityListener;
use OC\Authentication\Listeners\RemoteWipeEmailListener;
use OC\Authentication\Listeners\RemoteWipeNotificationsListener;
use OC\Authentication\Listeners\UserDeletedFilesCleanupListener;
use OC\Authentication\Listeners\UserDeletedStoreCleanupListener;
use OC\Authentication\Listeners\UserDeletedTokenCleanupListener;
use OC\Authentication\Listeners\UserDeletedWebAuthnCleanupListener;
use OC\Authentication\Notifications\Notifier as AuthenticationNotifier;
use OC\Core\Listener\AddMissingIndicesListener;
use OC\Core\Listener\AddMissingPrimaryKeyListener;
use OC\Core\Listener\BeforeTemplateRenderedListener;
use OC\Core\Listener\PasswordUpdatedListener;
use OC\Core\Notification\CoreNotifier;
use OC\Core\Sharing\Permission\CreateSharePermissionCategory;
use OC\Core\Sharing\Permission\DeleteSharePermissionCategory;
use OC\Core\Sharing\Permission\ReadSharePermissionCategory;
use OC\Core\Sharing\Permission\UpdateSharePermissionCategory;
use OC\Core\Sharing\Property\ExpirationDateShareProperty;
use OC\Core\Sharing\Property\LabelShareProperty;
use OC\Core\Sharing\Property\NoteShareProperty;
use OC\Core\Sharing\Property\PasswordShareProperty;
use OC\Core\Sharing\Recipient\GroupShareRecipientType;
use OC\Core\Sharing\Recipient\TokenShareRecipientType;
use OC\Core\Sharing\Recipient\UserShareRecipientType;
use OC\OCM\OCMDiscoveryHandler;
use OC\TagManager;
use OCA\Files\Sharing\Source\NodeShareSourceType;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\Http\Events\BeforeLoginTemplateRenderedEvent;
use OCP\AppFramework\Http\Events\BeforeTemplateRenderedEvent;
use OCP\DB\Events\AddMissingIndicesEvent;
use OCP\DB\Events\AddMissingPrimaryKeyEvent;
use OCP\Server;
use OCP\Sharing\IRegistry;
use OCP\User\Events\BeforeUserDeletedEvent;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserDeletedEvent;
use OCP\Util;

/**
 * Class Application
 *
 * @package OC\Core
 */
class Application extends App implements IBootstrap {

	public const APP_ID = 'core';

	/**
	 * Application constructor.
	 */
	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_ID, $urlParams);
	}

	#[\Override]
	public function register(IRegistrationContext $context): void {
		$context->registerService('defaultMailAddress', function () {
			return Util::getDefaultEmailAddress('lostpassword-noreply');
		});

		// register notifier
		$context->registerNotifierService(CoreNotifier::class);
		$context->registerNotifierService(AuthenticationNotifier::class);

		// register event listeners
		$context->registerEventListener(AddMissingIndicesEvent::class, AddMissingIndicesListener::class);
		$context->registerEventListener(AddMissingPrimaryKeyEvent::class, AddMissingPrimaryKeyListener::class);
		$context->registerEventListener(BeforeTemplateRenderedEvent::class, BeforeTemplateRenderedListener::class);
		$context->registerEventListener(BeforeLoginTemplateRenderedEvent::class, BeforeTemplateRenderedListener::class);
		$context->registerEventListener(RemoteWipeStarted::class, RemoteWipeActivityListener::class);
		$context->registerEventListener(RemoteWipeStarted::class, RemoteWipeNotificationsListener::class);
		$context->registerEventListener(RemoteWipeStarted::class, RemoteWipeEmailListener::class);
		$context->registerEventListener(RemoteWipeFinished::class, RemoteWipeActivityListener::class);
		$context->registerEventListener(RemoteWipeFinished::class, RemoteWipeNotificationsListener::class);
		$context->registerEventListener(RemoteWipeFinished::class, RemoteWipeEmailListener::class);
		$context->registerEventListener(UserDeletedEvent::class, UserDeletedStoreCleanupListener::class);
		$context->registerEventListener(UserDeletedEvent::class, UserDeletedTokenCleanupListener::class);
		$context->registerEventListener(BeforeUserDeletedEvent::class, UserDeletedFilesCleanupListener::class);
		$context->registerEventListener(UserDeletedEvent::class, UserDeletedFilesCleanupListener::class);
		$context->registerEventListener(UserDeletedEvent::class, UserDeletedWebAuthnCleanupListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, PasswordUpdatedListener::class);

		// Tags
		$context->registerEventListener(UserDeletedEvent::class, TagManager::class);

		// config lexicon
		$context->registerConfigLexicon(ConfigLexicon::class);

		$context->registerWellKnownHandler(OCMDiscoveryHandler::class);
		$context->registerCapability(Capabilities::class);

		$registry = Server::get(IRegistry::class);

		$registry->registerRecipientType(new GroupShareRecipientType());
		$registry->registerRecipientType(new UserShareRecipientType());
		$registry->registerRecipientType(new TokenShareRecipientType());

		$registry->registerProperty(new ExpirationDateShareProperty());
		$registry->registerPropertyCompatibleWithSourceType(ExpirationDateShareProperty::class, NodeShareSourceType::class);
		$registry->registerPropertyCompatibleWithRecipientType(ExpirationDateShareProperty::class, UserShareRecipientType::class);
		$registry->registerPropertyCompatibleWithRecipientType(ExpirationDateShareProperty::class, GroupShareRecipientType::class);
		$registry->registerPropertyCompatibleWithRecipientType(ExpirationDateShareProperty::class, TokenShareRecipientType::class);

		$registry->registerProperty(new LabelShareProperty());
		$registry->registerPropertyCompatibleWithSourceType(LabelShareProperty::class, NodeShareSourceType::class);
		$registry->registerPropertyCompatibleWithRecipientType(LabelShareProperty::class, UserShareRecipientType::class);
		$registry->registerPropertyCompatibleWithRecipientType(LabelShareProperty::class, GroupShareRecipientType::class);
		$registry->registerPropertyCompatibleWithRecipientType(LabelShareProperty::class, TokenShareRecipientType::class);

		$registry->registerProperty(new NoteShareProperty());
		$registry->registerPropertyCompatibleWithSourceType(NoteShareProperty::class, NodeShareSourceType::class);
		$registry->registerPropertyCompatibleWithRecipientType(NoteShareProperty::class, UserShareRecipientType::class);
		$registry->registerPropertyCompatibleWithRecipientType(NoteShareProperty::class, GroupShareRecipientType::class);
		$registry->registerPropertyCompatibleWithRecipientType(NoteShareProperty::class, TokenShareRecipientType::class);

		$registry->registerProperty(new PasswordShareProperty());
		$registry->registerPropertyCompatibleWithSourceType(PasswordShareProperty::class, NodeShareSourceType::class);
		$registry->registerPropertyCompatibleWithRecipientType(PasswordShareProperty::class, TokenShareRecipientType::class);

		$registry->registerPermissionCategory(new CreateSharePermissionCategory());
		$registry->registerPermissionCategory(new ReadSharePermissionCategory());
		$registry->registerPermissionCategory(new UpdateSharePermissionCategory());
		$registry->registerPermissionCategory(new DeleteSharePermissionCategory());
	}

	#[\Override]
	public function boot(IBootContext $context): void {
		// ...
	}

}
