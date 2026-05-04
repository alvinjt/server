<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\OCM;

use JsonException;
use OC\Security\IdentityProof\Manager;
use OC\Security\Jwks\Jwk;
use OC\Security\Signature\Rfc9421\IJwkResolvingSignatoryManager;
use OCP\Http\Client\IClientService;
use OCP\IAppConfig;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IURLGenerator;
use OCP\OCM\Exceptions\OCMProviderException;
use OCP\Security\Signature\Enum\DigestAlgorithm;
use OCP\Security\Signature\Enum\SignatoryType;
use OCP\Security\Signature\Enum\SignatureAlgorithm;
use OCP\Security\Signature\Exceptions\IdentityNotFoundException;
use OCP\Security\Signature\ISignatureManager;
use OCP\Security\Signature\Model\Signatory;
use OCP\Server;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * @inheritDoc
 *
 * returns local signatory using IKeyPairManager
 * extract optional signatory (keyId+public key) from ocm discovery service on remote instance
 *
 * @since 31.0.0
 */
class OCMSignatoryManager implements IJwkResolvingSignatoryManager {
	public const PROVIDER_ID = 'ocm';
	public const APPCONFIG_SIGN_IDENTITY_EXTERNAL = 'ocm_signed_request_identity_external';
	public const APPCONFIG_SIGN_DISABLED = 'ocm_signed_request_disabled';
	public const APPCONFIG_SIGN_ENFORCED = 'ocm_signed_request_enforced';
	private const APPKEY_CAVAGE = 'ocm_external';
	private const KEYID_FRAGMENT_CAVAGE = 'signature';
	private const KEYID_FRAGMENT_ED25519 = 'ed25519';
	/**
	 * Each Ed25519 keypair lives in a numbered "pool" appkey. Three slot
	 * pointers (active/pending/retiring) reference pools by id, so rotation
	 * is just pointer reshuffling — no copying of keypair bytes.
	 */
	private const APPKEY_ED25519_POOL_PREFIX = 'ocm_ed25519_pool_';
	private const APPCONFIG_ED25519_POOL_COUNTER = 'ocm_ed25519_pool_counter';
	private const APPCONFIG_ED25519_POOL_KID_PREFIX = 'ocm_ed25519_pool_kid_';
	/**
	 * Identity portion of every Ed25519 kid we have ever published, captured
	 * the first time a key is generated. Reused for every subsequent rotation
	 * so kids remain on the same hostname even when rotation is triggered
	 * from CLI (where the request-context Host header is unavailable and the
	 * fallback would otherwise resolve to `overwrite.cli.url`).
	 */
	private const APPCONFIG_ED25519_KID_BASE = 'ocm_ed25519_kid_base';
	public const SLOT_ACTIVE = 'active';
	public const SLOT_PENDING = 'pending';
	public const SLOT_RETIRING = 'retiring';
	/** All slots in advertise order. */
	public const ED25519_SLOTS = [self::SLOT_ACTIVE, self::SLOT_PENDING, self::SLOT_RETIRING];
	/** Seconds to cache a remote JWKS document. Mirrors the cavage `SIGNATORY_TTL`-style horizon: long enough to amortise the round-trip, short enough that key rotations propagate within an hour. */
	private const JWKS_CACHE_TTL = 3600;

	private readonly ICache $jwksCache;

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly ISignatureManager $signatureManager,
		private readonly IURLGenerator $urlGenerator,
		private readonly Manager $identityProofManager,
		private readonly IClientService $clientService,
		private readonly IConfig $config,
		ICacheFactory $cacheFactory,
		private readonly LoggerInterface $logger,
	) {
		$this->jwksCache = $cacheFactory->createDistributed('ocm-jwks');
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
	 * Active Ed25519 signing key (used for outbound RFC 9421 signatures).
	 * Generated lazily on first call; subsequent calls return the same key
	 * until {@see activateStagedEd25519Key} promotes a new one.
	 *
	 * @return Signatory|null null if no instance identity can be derived
	 */
	public function getLocalEd25519Signatory(): ?Signatory {
		$poolId = $this->getSlotPool(self::SLOT_ACTIVE);
		if ($poolId === null) {
			$poolId = $this->generatePool($this->nextEd25519PoolKid());
			$this->setSlotPool(self::SLOT_ACTIVE, $poolId);
		}
		return $this->signatoryFromPool($poolId);
	}

	/**
	 * Every Ed25519 JWK currently advertised at /.well-known/jwks.json. This
	 * is the union of the populated active/pending/retiring slots, in that
	 * order. Pending and retiring keys are advertised so peers can verify
	 * signatures made just before/after a rotation switch without waiting
	 * for their JWKS cache to expire.
	 *
	 * The active key is provisioned on demand if it does not yet exist, so
	 * the first request to JWKS always returns at least one key — peers
	 * must be able to discover us before we have ever signed anything.
	 *
	 * @return list<Jwk>
	 */
	public function getLocalEd25519Jwks(): array {
		if ($this->getSlotPool(self::SLOT_ACTIVE) === null) {
			$this->getLocalEd25519Signatory();
		}

		$jwks = [];
		foreach (self::ED25519_SLOTS as $slot) {
			$poolId = $this->getSlotPool($slot);
			if ($poolId === null) {
				continue;
			}
			$signatory = $this->signatoryFromPool($poolId);
			if ($signatory !== null) {
				$jwks[] = Jwk::fromEd25519PublicKey($signatory->getPublicKey(), $signatory->getKeyId());
			}
		}
		return $jwks;
	}

	/**
	 * Stage a fresh Ed25519 keypair into the `pending` slot. The new key is
	 * advertised in JWKS so peers can refresh their cache before it starts
	 * signing, but it is NOT used for outbound signatures yet.
	 *
	 * @throws \RuntimeException if a pending key already exists, or if no
	 *                           instance identity can be derived
	 */
	public function stageEd25519Key(): Signatory {
		if ($this->getSlotPool(self::SLOT_PENDING) !== null) {
			throw new \RuntimeException('a pending Ed25519 key already exists; activate or retire it first');
		}
		// Make sure we have an active key to begin with — otherwise staging
		// a "next" key with nothing to switch from would be odd.
		if ($this->getSlotPool(self::SLOT_ACTIVE) === null) {
			$this->getLocalEd25519Signatory();
		}
		$poolId = $this->generatePool($this->nextEd25519PoolKid());
		$this->setSlotPool(self::SLOT_PENDING, $poolId);
		$signatory = $this->signatoryFromPool($poolId);
		if ($signatory === null) {
			throw new \RuntimeException('failed to materialise newly staged Ed25519 key');
		}
		return $signatory;
	}

	/**
	 * Promote the staged key: pending -> active, previous active -> retiring.
	 * The previous active stays in JWKS so peers verifying in-flight requests
	 * signed with it can still resolve the kid. Run {@see retireEd25519Key}
	 * once those in-flight verifications are no longer expected.
	 *
	 * @throws \RuntimeException if no pending key is staged, or if a key is
	 *                           still in the retiring slot
	 */
	public function activateStagedEd25519Key(): void {
		$pending = $this->getSlotPool(self::SLOT_PENDING);
		if ($pending === null) {
			throw new \RuntimeException('no pending Ed25519 key to activate; run `ocm:keys:stage` first');
		}
		if ($this->getSlotPool(self::SLOT_RETIRING) !== null) {
			throw new \RuntimeException('a retiring Ed25519 key still exists; retire it before activating a new one');
		}
		$active = $this->getSlotPool(self::SLOT_ACTIVE);

		$this->setSlotPool(self::SLOT_ACTIVE, $pending);
		$this->clearSlot(self::SLOT_PENDING);
		if ($active !== null) {
			$this->setSlotPool(self::SLOT_RETIRING, $active);
		}
	}

	/**
	 * Delete the retiring Ed25519 key. After this call peers can no longer
	 * resolve the retired kid from our JWKS, so any signature still in
	 * flight that referenced it will fail verification.
	 *
	 * @throws \RuntimeException if no key is in the retiring slot
	 */
	public function retireEd25519Key(): void {
		$poolId = $this->getSlotPool(self::SLOT_RETIRING);
		if ($poolId === null) {
			throw new \RuntimeException('no retiring Ed25519 key to remove');
		}
		$this->identityProofManager->deleteAppKey('core', self::APPKEY_ED25519_POOL_PREFIX . $poolId);
		$this->appConfig->deleteKey('core', self::APPCONFIG_ED25519_POOL_KID_PREFIX . $poolId);
		$this->clearSlot(self::SLOT_RETIRING);
	}

	/**
	 * Snapshot of all Ed25519 keys for diagnostics. Each entry carries the
	 * pool id, the kid published in JWKS, and the slot it currently occupies
	 * (`active`, `pending`, `retiring`, or `null` for orphaned pools).
	 *
	 * @return list<array{poolId: int, kid: string, slot: ?string}>
	 */
	public function listEd25519Keys(): array {
		$bySlot = [];
		foreach (self::ED25519_SLOTS as $slot) {
			$id = $this->getSlotPool($slot);
			if ($id !== null) {
				$bySlot[$id] = $slot;
			}
		}

		$max = $this->appConfig->getValueInt('core', self::APPCONFIG_ED25519_POOL_COUNTER, 0);
		$entries = [];
		for ($id = 1; $id <= $max; $id++) {
			if (!$this->identityProofManager->hasAppKey('core', self::APPKEY_ED25519_POOL_PREFIX . $id)) {
				continue;
			}
			$entries[] = [
				'poolId' => $id,
				'kid' => $this->canonicalKid(
					$this->appConfig->getValueString('core', self::APPCONFIG_ED25519_POOL_KID_PREFIX . $id, ''),
				),
				'slot' => $bySlot[$id] ?? null,
			];
		}
		return $entries;
	}

	/**
	 * Generate a fresh Ed25519 keypair into a new pool, recording the kid
	 * alongside. The kid is run through {@see Signatory::setKeyId} first so
	 * the stored value matches the canonical form (no `/index.php/`, https
	 * scheme) used on the wire — otherwise admin output from
	 * `occ ocm:keys:list` would diverge from the kid actually published in
	 * JWKS and used to sign requests.
	 *
	 * Returns the assigned pool id.
	 */
	private function generatePool(string $kid): int {
		$poolId = $this->appConfig->getValueInt('core', self::APPCONFIG_ED25519_POOL_COUNTER, 0) + 1;
		$this->appConfig->setValueInt('core', self::APPCONFIG_ED25519_POOL_COUNTER, $poolId);

		$this->identityProofManager->generateEd25519AppKey('core', self::APPKEY_ED25519_POOL_PREFIX . $poolId);
		$this->appConfig->setValueString('core', self::APPCONFIG_ED25519_POOL_KID_PREFIX . $poolId, $this->canonicalKid($kid));
		return $poolId;
	}

	/**
	 * Canonical wire-form of a kid: whatever {@see Signatory::setKeyId}
	 * normalises it to. Implemented as a transient signatory round-trip so
	 * the rules stay in one place.
	 */
	private function canonicalKid(string $kid): string {
		$probe = new Signatory(true);
		$probe->setKeyId($kid);
		return $probe->getKeyId();
	}

	/**
	 * Build a kid for a newly-generated key. The identity portion is derived
	 * once (from the first request that creates a key) and persisted, so
	 * later rotations — including those triggered from CLI where there is
	 * no Host header — produce kids on the same hostname instead of falling
	 * back to `overwrite.cli.url`.
	 *
	 * @throws \RuntimeException if no instance identity can be derived
	 */
	private function nextEd25519PoolKid(): string {
		$base = $this->resolveEd25519KidBase();
		$next = $this->appConfig->getValueInt('core', self::APPCONFIG_ED25519_POOL_COUNTER, 0) + 1;
		return $base . '-' . $next;
	}

	/**
	 * Stable identity portion (everything before the trailing `-N`) used in
	 * every Ed25519 kid this instance has ever published. Resolution order:
	 *
	 *   1. {@see APPCONFIG_ED25519_KID_BASE} if previously stored.
	 *   2. The active pool's kid (with the `-N` suffix stripped) — handles
	 *      instances upgraded from a single-key world without an explicit
	 *      base appconfig.
	 *   3. {@see buildLocalKeyId} as a fresh derivation from the request
	 *      context.
	 *
	 * Whatever path produces it, the result is persisted so subsequent
	 * rotations (which may run in CLI context with no Host header) reuse
	 * the same hostname.
	 *
	 * @throws \RuntimeException if no instance identity can be derived
	 */
	private function resolveEd25519KidBase(): string {
		$base = $this->appConfig->getValueString('core', self::APPCONFIG_ED25519_KID_BASE, '');
		if ($base !== '') {
			return $base;
		}

		$activePool = $this->getSlotPool(self::SLOT_ACTIVE);
		if ($activePool !== null) {
			$kid = $this->canonicalKid(
				$this->appConfig->getValueString('core', self::APPCONFIG_ED25519_POOL_KID_PREFIX . $activePool, ''),
			);
			$pos = strrpos($kid, '-');
			if ($pos !== false) {
				$base = substr($kid, 0, $pos);
			}
		}

		if ($base === '') {
			try {
				$base = $this->canonicalKid($this->buildLocalKeyId(self::KEYID_FRAGMENT_ED25519));
			} catch (IdentityNotFoundException $e) {
				throw new \RuntimeException('cannot derive instance identity for Ed25519 kid', 0, $e);
			}
		}

		$this->appConfig->setValueString('core', self::APPCONFIG_ED25519_KID_BASE, $base);
		return $base;
	}

	/**
	 * Look up the pool id assigned to a slot, or null if the slot is empty.
	 */
	private function getSlotPool(string $slot): ?int {
		$key = 'ocm_ed25519_slot_' . $slot;
		if (!$this->appConfig->hasKey('core', $key)) {
			return null;
		}
		$value = $this->appConfig->getValueInt('core', $key, 0);
		return $value > 0 ? $value : null;
	}

	private function setSlotPool(string $slot, int $poolId): void {
		$this->appConfig->setValueInt('core', 'ocm_ed25519_slot_' . $slot, $poolId);
	}

	private function clearSlot(string $slot): void {
		$this->appConfig->deleteKey('core', 'ocm_ed25519_slot_' . $slot);
	}

	/**
	 * Materialise a {@see Signatory} from a pool id. Returns null when the
	 * pool storage is missing, which only happens if an admin manually
	 * deleted the underlying appkey.
	 */
	private function signatoryFromPool(int $poolId): ?Signatory {
		$appKey = self::APPKEY_ED25519_POOL_PREFIX . $poolId;
		if (!$this->identityProofManager->hasAppKey('core', $appKey)) {
			return null;
		}
		$kid = $this->appConfig->getValueString('core', self::APPCONFIG_ED25519_POOL_KID_PREFIX . $poolId, '');
		if ($kid === '') {
			return null;
		}
		$keyPair = $this->identityProofManager->getAppKey('core', $appKey);
		$signatory = new Signatory(true);
		$signatory->setKeyId($kid);
		$signatory->setPublicKey($keyPair->getPublic());
		$signatory->setPrivateKey($keyPair->getPrivate());
		return $signatory;
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

	/**
	 * Fetch the remote's `/.well-known/jwks.json` (per the OCM specification)
	 * and return the JWK whose `kid` matches $keyId.
	 *
	 * Results are cached per-origin for {@see JWKS_CACHE_TTL} seconds so the
	 * common case of repeated inbound requests from the same peer doesn't
	 * trigger a fresh HTTPS round-trip each time. On a cache hit where the
	 * requested kid is missing, we refetch once — that lets a remote key
	 * rotation propagate without waiting out the TTL.
	 *
	 * @return Jwk|null null when the fetch fails or no key with that kid is published
	 */
	#[\Override]
	public function getRemoteJwk(string $origin, string $keyId): ?Jwk {
		$keys = $this->readCachedJwks($origin);
		$fromCache = $keys !== null;
		if (!$fromCache) {
			$keys = $this->fetchJwks($origin);
			if ($keys !== null) {
				$this->jwksCache->set($origin, json_encode($keys), self::JWKS_CACHE_TTL);
			}
		}

		$jwk = $this->findKid($keys, $keyId);
		if ($jwk !== null) {
			return $jwk;
		}
		// Only refetch if the answer came from the cache. A fresh fetch is
		// already authoritative — refetching it just hammers the peer.
		if (!$fromCache) {
			return null;
		}

		$keys = $this->fetchJwks($origin);
		if ($keys === null) {
			return null;
		}
		$this->jwksCache->set($origin, json_encode($keys), self::JWKS_CACHE_TTL);
		return $this->findKid($keys, $keyId);
	}

	/**
	 * @return list<array<string, mixed>>|null cached `keys` array, or null
	 *                                         when the cache is cold or holds a corrupt entry (callers
	 *                                         should fall through to {@see fetchJwks})
	 */
	private function readCachedJwks(string $origin): ?array {
		$cached = $this->jwksCache->get($origin);
		if (!is_string($cached)) {
			return null;
		}
		try {
			$decoded = json_decode($cached, true, 8, JSON_THROW_ON_ERROR);
		} catch (JsonException) {
			return null;
		}
		if (!is_array($decoded)) {
			return null;
		}
		/** @var list<array<string, mixed>> $decoded */
		return array_values(array_filter($decoded, 'is_array'));
	}

	/**
	 * @return list<array<string, mixed>>|null
	 */
	private function fetchJwks(string $origin): ?array {
		$url = 'https://' . $origin . '/.well-known/jwks.json';
		$options = [
			'timeout' => 10,
			'connect_timeout' => 10,
		];
		if ($this->config->getSystemValueBool('sharing.federation.allowSelfSignedCertificates') === true) {
			$options['verify'] = false;
		}

		try {
			$response = $this->clientService->newClient()->get($url, $options);
		} catch (Throwable $e) {
			$this->logger->warning('failed to fetch remote JWKS', ['exception' => $e, 'url' => $url]);
			return null;
		}

		try {
			$decoded = json_decode((string)$response->getBody(), true, 8, JSON_THROW_ON_ERROR);
		} catch (JsonException $e) {
			$this->logger->warning('remote JWKS is not valid JSON', ['exception' => $e, 'url' => $url]);
			return null;
		}

		if (!is_array($decoded) || !is_array($decoded['keys'] ?? null)) {
			return null;
		}
		return array_values(array_filter($decoded['keys'], 'is_array'));
	}

	/**
	 * @param list<array<string, mixed>>|null $keys
	 */
	private function findKid(?array $keys, string $keyId): ?Jwk {
		if ($keys === null) {
			return null;
		}
		foreach ($keys as $entry) {
			if (($entry['kid'] ?? null) === $keyId) {
				return Jwk::fromArray($entry);
			}
		}
		return null;
	}
}
