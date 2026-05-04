<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\OCM;

use OC\Security\IdentityProof\Manager;
use OC\Security\Jwks\Jwk;
use OCP\IAppConfig;
use OCP\IURLGenerator;
use OCP\OCM\Exceptions\OCMProviderException;
use OCP\Security\Signature\Enum\DigestAlgorithm;
use OCP\Security\Signature\Enum\SignatoryType;
use OCP\Security\Signature\Enum\SignatureAlgorithm;
use OCP\Security\Signature\Exceptions\IdentityNotFoundException;
use OCP\Security\Signature\ISignatoryManager;
use OCP\Security\Signature\ISignatureManager;
use OCP\Security\Signature\Model\Signatory;
use OCP\Server;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Log\LoggerInterface;

/**
 * @inheritDoc
 *
 * returns local signatory using IKeyPairManager
 * extract optional signatory (keyId+public key) from ocm discovery service on remote instance
 *
 * @since 31.0.0
 */
class OCMSignatoryManager implements ISignatoryManager {
	public const PROVIDER_ID = 'ocm';
	public const APPCONFIG_SIGN_IDENTITY_EXTERNAL = 'ocm_signed_request_identity_external';
	public const APPCONFIG_SIGN_DISABLED = 'ocm_signed_request_disabled';
	public const APPCONFIG_SIGN_ENFORCED = 'ocm_signed_request_enforced';
	private const APPKEY_CAVAGE = 'ocm_external';
	private const APPKEY_ED25519 = 'ocm_ed25519';
	private const KEYID_FRAGMENT_CAVAGE = 'signature';
	private const KEYID_FRAGMENT_ED25519 = 'ed25519';

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly ISignatureManager $signatureManager,
		private readonly IURLGenerator $urlGenerator,
		private readonly Manager $identityProofManager,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @inheritDoc
	 *
	 * @return string
	 * @since 31.0.0
	 */
	#[\Override]
	public function getProviderId(): string {
		return self::PROVIDER_ID;
	}

	/**
	 * @inheritDoc
	 *
	 * @return array
	 * @since 31.0.0
	 */
	#[\Override]
	public function getOptions(): array {
		return [
			'algorithm' => SignatureAlgorithm::RSA_SHA512,
			'digestAlgorithm' => DigestAlgorithm::SHA512,
			'extraSignatureHeaders' => [],
			'ttl' => 300,
			'dateHeader' => 'D, d M Y H:i:s T',
			'ttlSignatory' => 86400 * 3,
			'bodyMaxSize' => 50000,
		];
	}

	/**
	 * @inheritDoc
	 *
	 * @return Signatory
	 * @throws IdentityNotFoundException
	 * @since 31.0.0
	 */
	#[\Override]
	public function getLocalSignatory(): Signatory {
		/**
		 * TODO: manage multiple identity (external, internal, ...) to allow a limitation
		 * based on the requested interface (ie. only accept shares from globalscale)
		 */
		$keyId = $this->buildLocalKeyId(self::KEYID_FRAGMENT_CAVAGE);

		if (!$this->identityProofManager->hasAppKey('core', self::APPKEY_CAVAGE)) {
			$this->identityProofManager->generateAppKey('core', self::APPKEY_CAVAGE, [
				'algorithm' => 'rsa',
				'private_key_bits' => 2048,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
			]);
		}
		$keyPair = $this->identityProofManager->getAppKey('core', self::APPKEY_CAVAGE);

		$signatory = new Signatory(true);
		$signatory->setKeyId($keyId);
		$signatory->setPublicKey($keyPair->getPublic());
		$signatory->setPrivateKey($keyPair->getPrivate());
		return $signatory;

	}

	/**
	 * Local Ed25519 signing key, used for RFC 9421 HTTP Message Signatures.
	 * The keypair is generated lazily on first call.
	 *
	 * @return Signatory|null null if no identity can be derived for this instance
	 */
	public function getLocalEd25519Signatory(): ?Signatory {
		try {
			$keyId = $this->buildLocalKeyId(self::KEYID_FRAGMENT_ED25519);
		} catch (IdentityNotFoundException) {
			return null;
		}

		if (!$this->identityProofManager->hasAppKey('core', self::APPKEY_ED25519)) {
			$this->identityProofManager->generateAppKey('core', self::APPKEY_ED25519, [
				'private_key_type' => OPENSSL_KEYTYPE_ED25519,
			]);
		}
		$keyPair = $this->identityProofManager->getAppKey('core', self::APPKEY_ED25519);

		$signatory = new Signatory(true);
		$signatory->setKeyId($keyId);
		$signatory->setPublicKey($keyPair->getPublic());
		$signatory->setPrivateKey($keyPair->getPrivate());
		return $signatory;
	}

	/**
	 * JWK form of the local Ed25519 public key, suitable for inclusion in the
	 * `/.well-known/jwks.json` document.
	 *
	 * @return Jwk|null null if no Ed25519 signatory can be built (e.g. missing identity)
	 */
	public function getLocalEd25519Jwk(): ?Jwk {
		$signatory = $this->getLocalEd25519Signatory();
		if ($signatory === null) {
			return null;
		}
		return Jwk::fromEd25519PublicKeyPem($signatory->getPublicKey(), $signatory->getKeyId());
	}

	/**
	 * Resolve the keyId for one of this instance's local signing keys.
	 *
	 * @param string $fragment URL fragment that distinguishes the key (e.g. 'signature', 'ed25519')
	 * @throws IdentityNotFoundException when no instance identity can be derived
	 */
	private function buildLocalKeyId(string $fragment): string {
		if ($this->appConfig->hasKey('core', self::APPCONFIG_SIGN_IDENTITY_EXTERNAL, true)) {
			$identity = $this->appConfig->getValueString('core', self::APPCONFIG_SIGN_IDENTITY_EXTERNAL, lazy: true);
			return 'https://' . $identity . '/ocm#' . $fragment;
		}

		try {
			return $this->signatureManager->generateKeyIdFromConfig('/ocm#' . $fragment);
		} catch (IdentityNotFoundException) {
		}

		$url = $this->urlGenerator->linkToRouteAbsolute('cloud_federation_api.requesthandlercontroller.addShare');
		$identity = $this->signatureManager->extractIdentityFromUri($url);

		// catching possible subfolder to create a keyId like 'https://hostname/subfolder/ocm#<fragment>'
		$path = parse_url($url, PHP_URL_PATH);
		$pos = strpos($path, '/ocm/shares');
		$sub = ($pos) ? substr($path, 0, $pos) : '';

		return 'https://' . $identity . $sub . '/ocm#' . $fragment;
	}

	/**
	 * @inheritDoc
	 *
	 * @param string $remote
	 *
	 * @return Signatory|null must be NULL if no signatory is found
	 * @since 31.0.0
	 */
	#[\Override]
	public function getRemoteSignatory(string $remote): ?Signatory {
		try {
			$ocmProvider = Server::get(OCMDiscoveryService::class)->discover($remote, true);
			/**
			 * @experimental 31.0.0
			 * @psalm-suppress UndefinedInterfaceMethod
			 */
			$signatory = $ocmProvider->getSignatory();
			$signatory?->setSignatoryType(SignatoryType::TRUSTED);
			return $signatory;
		} catch (NotFoundExceptionInterface|ContainerExceptionInterface|OCMProviderException $e) {
			$this->logger->warning('fail to get remote signatory', ['exception' => $e, 'remote' => $remote]);
			return null;
		}
	}
}
