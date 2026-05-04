<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Rfc9421;

use OC\Security\Jwks\Jwk;
use OCP\Security\Signature\ISignatoryManager;

/**
 * Optional capability that an {@see ISignatoryManager} can advertise to signal
 * it can resolve a remote JWK (RFC 7517) for RFC 9421 signature verification.
 *
 * The public {@see ISignatoryManager} interface only knows about the
 * cavage-style {@see \OCP\Security\Signature\Model\Signatory} carrier, which
 * does not generalise to JOSE keys. Implementers that participate in the
 * RFC 9421 path implement this internal interface in addition; the
 * {@see \OC\Security\Signature\SignatureManager} will use it via instanceof
 * when an incoming request is RFC 9421 formatted.
 */
interface IJwkResolvingSignatoryManager extends ISignatoryManager {
	/**
	 * Resolve the JWK identified by $keyId for the remote at $origin.
	 *
	 * @param string $origin host of the remote that signed the request
	 *                       (extracted from the keyid parameter)
	 * @param string $keyId raw `keyid` value taken from the Signature-Input
	 *                      parameters; matched against JWK `kid`
	 *
	 * @return Jwk|null null when no matching JWK could be resolved
	 */
	public function getRemoteJwk(string $origin, string $keyId): ?Jwk;
}
