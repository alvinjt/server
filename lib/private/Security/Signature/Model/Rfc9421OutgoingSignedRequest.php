<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Model;

use JsonSerializable;
use OC\Security\Signature\Rfc9421\Algorithm;
use OC\Security\Signature\Rfc9421\ContentDigest;
use OC\Security\Signature\Rfc9421\OcmProfile;
use OC\Security\Signature\Rfc9421\SignatureBase;
use OC\Security\Signature\SignatureManager;
use OCP\Security\Signature\Enum\DigestAlgorithm;
use OCP\Security\Signature\Enum\SignatureAlgorithm;
use OCP\Security\Signature\Exceptions\SignatoryException;
use OCP\Security\Signature\Exceptions\SignatoryNotFoundException;
use OCP\Security\Signature\IOutgoingSignedRequest;
use OCP\Security\Signature\ISignatoryManager;

/**
 * RFC 9421 (HTTP Message Signatures) implementation of {@see IOutgoingSignedRequest}.
 *
 * Sits beside the draft-cavage {@see OutgoingSignedRequest}. The wire format
 * differs:
 *
 *   Signature-Input: sig1=("@method" "@target-uri" "content-digest"
 *                          "content-length" "date");created=1730815200;keyid="<keyId>"
 *   Signature: sig1=:<base64sig>:
 *   Content-Digest: sha-256=:<base64hash>:
 *
 * By default we sign with Ed25519 along the path RFC 9421 §3.3.7 permits for
 * JOSE algorithms (RFC 7518, RFC 8037): the `alg` parameter is intentionally
 * omitted from `Signature-Input` and the verifier recovers the algorithm from
 * our advertised JWK.
 *
 * Options consumed from {@see ISignatoryManager::getOptions()}:
 *   - `rfc9421.signingAlgorithm` (string, default `ed25519`)
 *   - `rfc9421.coveredComponents` (list<string>, default
 *     `['@method', '@target-uri', 'content-digest', 'content-length', 'date']`)
 *   - `rfc9421.contentDigestAlgorithm` (string, default `sha-256`)
 *   - `rfc9421.includeAlgParameter` (bool, default false; the default omits
 *     `alg` per RFC 9421 §3.3.7)
 *   - `dateHeader` (date-format string, default {@see SignatureManager::DATE_HEADER})
 */
class Rfc9421OutgoingSignedRequest extends SignedRequest implements
	IOutgoingSignedRequest,
	JsonSerializable {
	private const DEFAULT_COMPONENTS = ['@method', '@target-uri', 'content-digest', 'content-length', 'date'];

	private string $host = '';
	private array $headers = [];
	/** @var list<string> $headerList */
	private array $headerList = [];
	private SignatureAlgorithm $algorithm;
	private string $signingAlgorithm;
	/** @var array<string, scalar> */
	private array $signatureParams;
	private string $signatureBaseString;

	public function __construct(
		string $body,
		ISignatoryManager $signatoryManager,
		private readonly string $identity,
		private readonly string $method,
		private readonly string $uri,
	) {
		parent::__construct($body);

		$options = $signatoryManager->getOptions();
		$this->setHost($identity)
			->setAlgorithm($options['algorithm'] ?? SignatureAlgorithm::RSA_SHA256)
			->setSignatory($signatoryManager->getLocalSignatory())
			->setDigestAlgorithm($options['digestAlgorithm'] ?? DigestAlgorithm::SHA256);

		$this->signingAlgorithm = (string)($options['rfc9421.signingAlgorithm'] ?? 'ed25519');
		$contentDigestAlgorithm = (string)($options['rfc9421.contentDigestAlgorithm'] ?? ContentDigest::ALGO_SHA256);
		/** @var list<string> $components */
		$components = $options['rfc9421.coveredComponents'] ?? self::DEFAULT_COMPONENTS;
		$includeAlg = (bool)($options['rfc9421.includeAlgParameter'] ?? false);
		$dateHeaderFormat = (string)($options['dateHeader'] ?? SignatureManager::DATE_HEADER);

		$this->addHeader('Content-Digest', ContentDigest::compute($body, $contentDigestAlgorithm))
			->addHeader('Content-Length', strlen($body))
			->addHeader('Date', gmdate($dateHeaderFormat));
		if (in_array('host', $components, true)) {
			$this->addHeader('Host', $this->host);
		}

		$this->setHeaderList($components);
		$this->signatureParams = [
			'created' => time(),
			'keyid' => $this->getSignatory()->getKeyId(),
		];
		if ($includeAlg) {
			// Only set when explicitly opted in. The default leaves `alg` out
			// because RFC 9421 §3.3.7 lets the verifier resolve it from the
			// JWK metadata for JOSE algorithms.
			$this->signatureParams['alg'] = $this->signingAlgorithm;
		}

		$this->signatureBaseString = SignatureBase::build(
			$this->method,
			$this->uri,
			$this->headersByLowercaseName(),
			$this->headerList,
			SignatureBase::serializeSignatureParams($this->headerList, $this->signatureParams)
		);
		$this->setSignatureData([$this->signatureBaseString]);
	}

	#[\Override]
	public function setHost(string $host): self {
		$this->host = $host;
		return $this;
	}

	#[\Override]
	public function getHost(): string {
		return $this->host;
	}

	#[\Override]
	public function addHeader(string $key, string|int|float $value): self {
		$this->headers[$key] = $value;
		return $this;
	}

	#[\Override]
	public function getHeaders(): array {
		return $this->headers;
	}

	#[\Override]
	public function setHeaderList(array $list): self {
		$this->headerList = $list;
		return $this;
	}

	#[\Override]
	public function getHeaderList(): array {
		return $this->headerList;
	}

	#[\Override]
	public function setAlgorithm(SignatureAlgorithm $algorithm): self {
		$this->algorithm = $algorithm;
		return $this;
	}

	#[\Override]
	public function getAlgorithm(): SignatureAlgorithm {
		return $this->algorithm;
	}

	/**
	 * RFC 9421 signing algorithm string actually used (e.g. `ed25519`).
	 * Distinct from {@see getAlgorithm()} which is the cavage-flavoured enum
	 * required by the public interface.
	 */
	public function getSigningAlgorithm(): string {
		return $this->signingAlgorithm;
	}

	public function getSignatureBaseString(): string {
		return $this->signatureBaseString;
	}

	#[\Override]
	public function sign(): self {
		$privateKey = $this->getSignatory()->getPrivateKey();
		if ($privateKey === '') {
			throw new SignatoryException('empty private key');
		}

		$rawSignature = Algorithm::sign(
			$this->signatureBaseString,
			$privateKey,
			$this->signingAlgorithm,
		);
		$this->setSignature(base64_encode($rawSignature));

		$paramsLine = SignatureBase::serializeSignatureParams($this->headerList, $this->signatureParams);
		$this->addHeader('Signature-Input', OcmProfile::SIGNATURE_LABEL . '=' . $paramsLine);
		$this->addHeader('Signature', OcmProfile::SIGNATURE_LABEL . '=:' . base64_encode($rawSignature) . ':');

		$this->setSigningElements([
			'label' => OcmProfile::SIGNATURE_LABEL,
			'components' => implode(' ', $this->headerList),
			'params' => $paramsLine,
			'signature' => $this->getSignature(),
		]);

		return $this;
	}

	/**
	 * @return array<string, string>
	 */
	private function headersByLowercaseName(): array {
		$out = [];
		foreach ($this->headers as $name => $value) {
			$out[strtolower($name)] = (string)$value;
		}
		return $out;
	}

	/**
	 * @throws SignatoryNotFoundException
	 */
	#[\Override]
	public function jsonSerialize(): array {
		return array_merge(
			parent::jsonSerialize(),
			[
				'host' => $this->host,
				'headers' => $this->headers,
				'algorithm' => $this->algorithm->value,
				'signingAlgorithm' => $this->signingAlgorithm,
				'method' => $this->method,
				'identity' => $this->identity,
				'uri' => $this->uri,
				'components' => $this->headerList,
				'signatureBase' => $this->signatureBaseString,
				'signatureParams' => $this->signatureParams,
			]
		);
	}
}
