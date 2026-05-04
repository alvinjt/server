<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Model;

use JsonSerializable;
use OC\Security\Jwks\Jwk;
use OC\Security\Signature\Rfc9421\Algorithm;
use OC\Security\Signature\Rfc9421\ContentDigest;
use OC\Security\Signature\Rfc9421\OcmProfile;
use OC\Security\Signature\Rfc9421\SfParser;
use OC\Security\Signature\Rfc9421\SignatureBase;
use OC\Security\Signature\SignatureManager;
use OCP\IRequest;
use OCP\Security\Signature\Exceptions\IdentityNotFoundException;
use OCP\Security\Signature\Exceptions\IncomingRequestException;
use OCP\Security\Signature\Exceptions\InvalidSignatureException;
use OCP\Security\Signature\Exceptions\SignatoryNotFoundException;
use OCP\Security\Signature\Exceptions\SignatureException;
use OCP\Security\Signature\Exceptions\SignatureNotFoundException;
use OCP\Security\Signature\IIncomingSignedRequest;
use OCP\Security\Signature\Model\Signatory;

/**
 * RFC 9421 implementation of {@see IIncomingSignedRequest}.
 *
 * Reads `Signature-Input` and `Signature` from the inbound request, locates
 * the dictionary entry whose label matches the OCM convention ({@see
 * OcmProfile::SIGNATURE_LABEL}), and reconstructs the signature base per
 * RFC 9421 §2.5.
 * Other labels in the same dictionary (e.g. proxy-attached signatures) are
 * parsed by the structured-fields layer but ignored here: this class verifies
 * exactly the OCM-labeled signature, leaving any sibling signatures to other
 * verifiers if such a flow ever arises. RFC 9421 §3.2 explicitly allows the
 * verifier to pick a single applicable signature based on policy; the OCM
 * specification fixes that policy to the `ocm` label.
 *
 * The cryptographic check is deferred to {@see verify()} which requires that
 * a {@see Jwk} has been attached via {@see setJwk()}.
 *
 * Body integrity is enforced separately: if `content-digest` is present in the
 * covered components, the header value MUST hash to the body bytes per
 * RFC 9530. A mismatch throws before verify() is reached.
 */
class Rfc9421IncomingSignedRequest extends SignedRequest implements
	IIncomingSignedRequest,
	JsonSerializable {
	/**
	 * Components a signature MUST cover to be considered authentic for OCM.
	 * Missing any of these means the signer left a body or freshness window
	 * unprotected. Callers can override via the `rfc9421.requiredComponents`
	 * option — but tightening below this baseline is on them.
	 */
	private const DEFAULT_REQUIRED_COMPONENTS = [
		'@method',
		'@target-uri',
		'content-digest',
		'content-length',
		'date',
	];

	/**
	 * How far in the future a `created` timestamp may be before we treat
	 * the signature as forged or clock-skewed beyond plausibility. Callers
	 * may override via the `rfc9421.maxClockSkew` option.
	 */
	private const DEFAULT_MAX_FUTURE_SKEW = 60;

	private string $origin = '';
	/** @var list<string> */
	private array $components;
	/** @var array<string, scalar> */
	private array $signatureParams;
	private string $signatureBaseString;
	private string $rawSignature;
	private ?Jwk $jwk = null;

	/**
	 * @throws IncomingRequestException if anything looks wrong with the request structure
	 * @throws SignatureNotFoundException if the request is not signed
	 * @throws SignatureException if signature metadata is malformed or covered components reference missing fields
	 */
	public function __construct(
		string $body,
		private readonly IRequest $request,
		private readonly array $options = [],
	) {
		parent::__construct($body);

		$signatureInputHeader = $request->getHeader('Signature-Input');
		$signatureHeader = $request->getHeader('Signature');
		if ($signatureInputHeader === '') {
			throw new SignatureNotFoundException('missing Signature-Input header');
		}
		if ($signatureHeader === '') {
			throw new SignatureNotFoundException('missing Signature header');
		}

		$inputs = SfParser::parseSignatureInput($signatureInputHeader);
		$signatures = SfParser::parseSignature($signatureHeader);

		// OCM policy (stricter than RFC 8941 §4.2 last-wins): a duplicate
		// `ocm` entry is ambiguous; the entire request MUST be rejected.
		$inputDuplicates = SfParser::findDuplicateLabels($signatureInputHeader);
		$signatureDuplicates = SfParser::findDuplicateLabels($signatureHeader);
		if (in_array(OcmProfile::SIGNATURE_LABEL, $inputDuplicates, true)
			|| in_array(OcmProfile::SIGNATURE_LABEL, $signatureDuplicates, true)) {
			throw new IncomingRequestException(
				'multiple "' . OcmProfile::SIGNATURE_LABEL . '" entries in signature headers'
			);
		}

		if (!isset($inputs[OcmProfile::SIGNATURE_LABEL])) {
			throw new SignatureNotFoundException('missing "' . OcmProfile::SIGNATURE_LABEL . '" entry in Signature-Input');
		}
		if (!isset($signatures[OcmProfile::SIGNATURE_LABEL])) {
			throw new SignatureNotFoundException('missing "' . OcmProfile::SIGNATURE_LABEL . '" entry in Signature');
		}

		$entry = $inputs[OcmProfile::SIGNATURE_LABEL];
		$this->components = $entry['components'];
		$this->signatureParams = $entry['params'];
		$this->rawSignature = $signatures[OcmProfile::SIGNATURE_LABEL];

		$this->verifyRequiredComponents();
		$this->verifyTimestamps();
		$this->verifyContentDigestIfCovered($body);
		$this->verifyContentLengthIfCovered($body);

		$keyId = $this->signatureParams['keyid'] ?? null;
		if (!is_string($keyId) || $keyId === '') {
			throw new IncomingRequestException('missing keyid in Signature-Input');
		}
		try {
			$this->origin = Signatory::extractIdentityFromUri($keyId);
		} catch (IdentityNotFoundException) {
			// keyid may follow the OCM convention `<fqdn>#<id>`; the OCM layer
			// derives origin from the message body in that case.
			$this->origin = '';
		}

		$paramsLine = SignatureBase::serializeSignatureParams($this->components, $this->signatureParams);
		$this->signatureBaseString = SignatureBase::build(
			$request->getMethod(),
			$this->reconstructTargetUri(),
			$this->collectHeaders(),
			$this->components,
			$paramsLine,
		);

		$this->setSigningElements([
			'label' => OcmProfile::SIGNATURE_LABEL,
			'keyId' => $keyId,
			'algorithm' => isset($this->signatureParams['alg']) ? (string)$this->signatureParams['alg'] : '',
			'created' => isset($this->signatureParams['created']) ? (string)$this->signatureParams['created'] : '',
			'components' => implode(' ', $this->components),
			'params' => $paramsLine,
			'signature' => base64_encode($this->rawSignature),
		]);
		$this->setSignature(base64_encode($this->rawSignature));
		$this->setSignatureData([$this->signatureBaseString]);
	}

	#[\Override]
	public function getRequest(): IRequest {
		return $this->request;
	}

	#[\Override]
	public function getOrigin(): string {
		if ($this->origin === '') {
			throw new IncomingRequestException('empty origin');
		}
		return $this->origin;
	}

	#[\Override]
	public function getKeyId(): string {
		return $this->getSigningElement('keyId');
	}

	/**
	 * Attach the verification key. Required before {@see verify()} is called.
	 */
	public function setJwk(Jwk $jwk): self {
		$this->jwk = $jwk;
		return $this;
	}

	public function getJwk(): ?Jwk {
		return $this->jwk;
	}

	/**
	 * Algorithm identifier extracted from the `alg` parameter of the
	 * Signature-Input, or null when the parameter is omitted (the path
	 * RFC 9421 §3.3.7 permits when the JWK signals the algorithm).
	 */
	public function getAlgorithm(): ?string {
		return isset($this->signatureParams['alg']) ? (string)$this->signatureParams['alg'] : null;
	}

	/**
	 * @return array<string, scalar>
	 */
	public function getSignatureParams(): array {
		return $this->signatureParams;
	}

	/**
	 * @return list<string>
	 */
	public function getCoveredComponents(): array {
		return $this->components;
	}

	public function getSignatureBaseString(): string {
		return $this->signatureBaseString;
	}

	#[\Override]
	public function verify(): void {
		if ($this->jwk === null) {
			throw new SignatoryNotFoundException('no JWK set for verification');
		}
		try {
			$ok = Algorithm::verify(
				$this->signatureBaseString,
				$this->rawSignature,
				$this->jwk,
				$this->getAlgorithm(),
			);
		} catch (SignatureException $e) {
			throw new InvalidSignatureException($e->getMessage(), 0, $e);
		}
		if (!$ok) {
			throw new InvalidSignatureException('signature verification failed');
		}
	}

	/**
	 * Refuse signatures that don't cover the components OCM relies on for
	 * authenticity (request identity, body integrity, freshness). Without
	 * this check the sender could omit `content-digest` or `content-length`
	 * and leave the body unprotected even though the signature verifies.
	 *
	 * @throws IncomingRequestException
	 */
	private function verifyRequiredComponents(): void {
		/** @var list<string> $required */
		$required = $this->options['rfc9421.requiredComponents'] ?? self::DEFAULT_REQUIRED_COMPONENTS;
		$missing = array_values(array_diff($required, $this->components));
		if ($missing !== []) {
			throw new IncomingRequestException(
				'signature does not cover required components: ' . implode(', ', $missing)
			);
		}
	}

	/**
	 * Reject stale or future-dated signatures. The `created` parameter is
	 * required: without it there is no anchor to bound the replay window.
	 * `created` may sit at most `maxClockSkew` seconds in the future (clock
	 * drift tolerance) and at most `ttl` seconds in the past.
	 *
	 * @throws IncomingRequestException
	 */
	private function verifyTimestamps(): void {
		$ttl = (int)($this->options['ttl'] ?? SignatureManager::DATE_TTL);
		$skew = (int)($this->options['rfc9421.maxClockSkew'] ?? self::DEFAULT_MAX_FUTURE_SKEW);
		$now = time();

		if (!isset($this->signatureParams['created'])) {
			throw new IncomingRequestException('signature missing required `created` parameter');
		}
		$created = (int)$this->signatureParams['created'];
		if ($created > $now + $skew) {
			throw new IncomingRequestException('signature `created` is too far in the future');
		}
		if ($ttl > 0 && $created < $now - $ttl) {
			throw new IncomingRequestException('signature is too old');
		}

		if (isset($this->signatureParams['expires'])) {
			$expires = (int)$this->signatureParams['expires'];
			if ($expires < $now) {
				throw new IncomingRequestException('signature has expired');
			}
		}
	}

	private function verifyContentDigestIfCovered(string $body): void {
		if (!in_array('content-digest', $this->components, true)) {
			return;
		}
		$header = $this->request->getHeader('Content-Digest');
		if ($header === '') {
			throw new IncomingRequestException('content-digest covered but missing from request');
		}
		if (!ContentDigest::verify($header, $body)) {
			throw new IncomingRequestException('content-digest does not match body');
		}
	}

	private function verifyContentLengthIfCovered(string $body): void {
		if (!in_array('content-length', $this->components, true)) {
			return;
		}
		$header = $this->request->getHeader('Content-Length');
		if ($header === '') {
			throw new IncomingRequestException('content-length covered but missing from request');
		}
		if ((int)$header !== strlen($body)) {
			throw new IncomingRequestException('content-length does not match body size');
		}
	}

	private function reconstructTargetUri(): string {
		$scheme = $this->request->getServerProtocol();
		$host = $this->request->getServerHost();
		$path = $this->request->getRequestUri();
		return $scheme . '://' . $host . $path;
	}

	/**
	 * Collect the HTTP request fields covered by the signature, keyed by their
	 * lowercased name. Derived components (`@*`) are produced inside
	 * {@see SignatureBase}; we only collect plain fields here.
	 *
	 * @return array<string, string>
	 */
	private function collectHeaders(): array {
		$out = [];
		foreach ($this->components as $component) {
			if (str_starts_with($component, '@')) {
				continue;
			}
			$value = $this->request->getHeader($component);
			if ($value === '' && strtolower($component) === 'host') {
				$value = $this->request->getServerHost();
			}
			$out[strtolower($component)] = $value;
		}
		return $out;
	}

	#[\Override]
	public function jsonSerialize(): array {
		return array_merge(
			parent::jsonSerialize(),
			[
				'origin' => $this->origin,
				'label' => OcmProfile::SIGNATURE_LABEL,
				'components' => $this->components,
				'signatureParams' => $this->signatureParams,
				'signatureBase' => $this->signatureBaseString,
			]
		);
	}
}
