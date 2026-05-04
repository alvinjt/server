<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\OCM\Listener;

use OC\OCM\OCMSignatoryManager;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IAppConfig;
use OCP\OCM\Events\LocalOCMDiscoveryEvent;

/**
 * Adds the `http-sig` capability to the local OCM discovery document so that
 * remote senders know they may use RFC 9421 HTTP Message Signatures with the
 * keys published at `/.well-known/jwks.json`. The capability is suppressed
 * when signing has been disabled outright via
 * {@see OCMSignatoryManager::APPCONFIG_SIGN_DISABLED}.
 *
 * @template-implements IEventListener<LocalOCMDiscoveryEvent>
 */
class HttpSigCapabilityListener implements IEventListener {
	public function __construct(
		private readonly IAppConfig $appConfig,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!($event instanceof LocalOCMDiscoveryEvent)) {
			return;
		}
		if ($this->appConfig->getValueBool('core', OCMSignatoryManager::APPCONFIG_SIGN_DISABLED, lazy: true)) {
			return;
		}
		$event->addCapability('http-sig');
	}
}
