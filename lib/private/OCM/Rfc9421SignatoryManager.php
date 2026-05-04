<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\OCM;

use OC\Security\Jwks\Jwk;
use OC\Security\Signature\Rfc9421\IJwkResolvingSignatoryManager;
use OCP\Security\Signature\Exceptions\IdentityNotFoundException;
use OCP\Security\Signature\Model\Signatory;

/**
 * Per-call wrapper around {@see OCMSignatoryManager} that swaps in the
 * Ed25519 signatory and turns on the `rfc9421.format` option. Constructed
 * by {@see OCMDiscoveryService::prepareOcmPayload} when the remote has
 * advertised the OCM `http-sig` capability.
 *
 * Wrapping rather than mutating OCMSignatoryManager keeps the underlying
 * service stateless — important because it lives in the DI container and
 * may be reused across requests.
 */
final class Rfc9421SignatoryManager implements IJwkResolvingSignatoryManager {
	public function __construct(
		private readonly OCMSignatoryManager $delegate,
	) {
	}

	#[\Override]
	public function getProviderId(): string {
		return $this->delegate->getProviderId();
	}

	#[\Override]
	public function getOptions(): array {
		return array_merge($this->delegate->getOptions(), ['rfc9421.format' => true]);
	}

	#[\Override]
	public function getLocalSignatory(): Signatory {
		$signatory = $this->delegate->getLocalEd25519Signatory();
		if ($signatory === null) {
			throw new IdentityNotFoundException('no Ed25519 signatory available');
		}
		return $signatory;
	}

	#[\Override]
	public function getRemoteSignatory(string $remote): ?Signatory {
		return $this->delegate->getRemoteSignatory($remote);
	}

	#[\Override]
	public function getRemoteJwk(string $origin, string $keyId): ?Jwk {
		return $this->delegate->getRemoteJwk($origin, $keyId);
	}
}
