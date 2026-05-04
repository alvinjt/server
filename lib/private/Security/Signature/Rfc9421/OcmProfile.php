<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Rfc9421;

/**
 * Constants encoding the OCM specification's choices on top of the RFC 9421
 * mechanics implemented elsewhere in this namespace.
 *
 * RFC 9421 §3.2 leaves the policy of selecting which signature to verify
 * (when a request carries more than one) up to the verifier. The OCM
 * specification fixes that policy by mandating a specific dictionary label.
 * Both the outgoing and incoming RFC 9421 model classes share that single
 * source of truth from here.
 */
final class OcmProfile {
	/**
	 * Signature label OCM mandates in the `Signature` and `Signature-Input`
	 * structured-fields dictionaries (RFC 8941 §3.2 dictionaries).
	 */
	public const SIGNATURE_LABEL = 'ocm';

	private function __construct() {
	}
}
