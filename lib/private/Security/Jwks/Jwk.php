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
	 * Build a JWK from an Ed25519 public key in SPKI PEM form (as returned by
	 * openssl_pkey_get_details for an OPENSSL_KEYTYPE_ED25519 key).
	 */
	public static function fromEd25519PublicKeyPem(string $pem, string $kid): self {
		$key = openssl_pkey_get_public($pem);
		if ($key === false) {
			throw new InvalidArgumentException('not a valid public key PEM');
		}
		$details = openssl_pkey_get_details($key);
		if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_ED25519) {
			throw new InvalidArgumentException('not an Ed25519 public key');
		}

		return new self([
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => $kid,
			'alg' => 'EdDSA',
			'use' => 'sig',
			'x' => self::base64UrlEncode($details['ed25519']['pub_key']),
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
