<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OC\Security\Jwks;

use InvalidArgumentException;

/**
 * Minimal JSON Web Key (RFC 7517) representation.
 *
 * Carries enough metadata to publish a public key over a JWKS endpoint and to
 * resolve algorithms during RFC 9421 signature verification. The model is
 * intentionally small: the full JWA algorithm registry is not enforced here,
 * but lookup of `kty`/`crv`/`alg` is sufficient to drive verification.
 */
final class Jwk {
	public function __construct(
		private readonly array $data,
	) {
	}

	/**
	 * Build a JWK from raw decoded JSON data.
	 */
	public static function fromArray(array $data): self {
		return new self($data);
	}

	/**
	 * Build a JWK from a raw 32-byte Ed25519 public key, as produced by
	 * {@see sodium_crypto_sign_publickey()}.
	 */
	public static function fromEd25519PublicKey(string $rawPublicKey, string $kid): self {
		if (strlen($rawPublicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
			throw new InvalidArgumentException('Ed25519 public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' bytes');
		}

		return new self([
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => $kid,
			'alg' => 'EdDSA',
			'use' => 'sig',
			'x' => self::base64UrlEncode($rawPublicKey),
		]);
	}

	public function toArray(): array {
		return $this->data;
	}

	public function getKid(): string {
		return (string)($this->data['kid'] ?? '');
	}

	public function getKty(): string {
		return (string)($this->data['kty'] ?? '');
	}

	public function get(string $member): ?string {
		$value = $this->data[$member] ?? null;
		return is_string($value) ? $value : null;
	}

	private static function base64UrlEncode(string $bin): string {
		return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
	}
}
