<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Rfc9421;

use InvalidArgumentException;
use OC\Security\Jwks\Jwk;
use OCP\Security\Signature\Exceptions\SignatureException;

/**
 * RFC 9421 §3.3 signing/verification primitives.
 *
 * Supports the asymmetric algorithms registered natively in RFC 9421 §3.3.2
 * (RSASSA-PKCS1-v1_5 SHA-256), RFC 9421 §3.3.4 (ECDSA P-256 SHA-256),
 * RFC 9421 §3.3.5 (ECDSA P-384 SHA-384), and RFC 9421 §3.3.6 (Ed25519), plus
 * the corresponding JOSE algorithm names from RFC 7518 (JWA) and RFC 8037
 * (EdDSA) accepted under RFC 9421 §3.3.7. Algorithm identifiers may arrive
 * as an explicit `alg` parameter on the signature or, when that parameter
 * is omitted as RFC 9421 §3.3.7 allows, be inferred from the resolved
 * JWK's `alg`/`kty`/`crv` members.
 *
 * RFC 9421 §3.3.1 (RSASSA-PSS SHA-512) and the JOSE PS256/PS384/PS512
 * aliases are intentionally not supported. The OpenSSL PSS padding mode
 * (OPENSSL_PKCS1_PSS_PADDING) was only exposed by PHP in 8.5; supporting
 * PSS would silently fail on the PHP 8.2 - PHP 8.4 versions we still
 * support. RFC 9421 lets verifiers expose a subset of the registered
 * algorithms and reject the rest, which we do.
 */
final class Algorithm {
	/** Asymmetric algorithm identifiers RFC 9421 §3.3 registers natively. */
	public const NATIVE = [
		'rsa-v1_5-sha256',
		'ecdsa-p256-sha256',
		'ecdsa-p384-sha384',
		'ed25519',
	];

	/**
	 * Sign the signature base with the given algorithm.
	 *
	 * For Ed25519 the second argument is the raw 64-byte libsodium secret key
	 * (as produced by sodium_crypto_sign_secretkey()). For every other
	 * algorithm it is a PEM private key. Returns raw signature bytes; the
	 * caller is responsible for any encoding.
	 *
	 * @throws SignatureException
	 */
	public static function sign(string $signatureBase, string $privateKey, string $algorithm): string {
		$normalized = self::normalize($algorithm);

		if ($normalized === 'ed25519') {
			if (strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
				throw new SignatureException('Ed25519 secret key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' bytes');
			}
			return sodium_crypto_sign_detached($signatureBase, $privateKey);
		}

		[$opensslAlgo, $encoding] = self::opensslParametersForAlgorithm($normalized);

		// We do not pass an explicit padding mode: openssl_sign's 5th argument
		// only became available in PHP 8.5, and the algorithms we still
		// support (RSA-PKCS1-v1_5, ECDSA) all use the function's default
		// padding behaviour (PKCS1 v1.5 for RSA, ignored for ECDSA).
		$ok = openssl_sign($signatureBase, $signature, $privateKey, $opensslAlgo);
		if (!$ok) {
			throw new SignatureException('openssl_sign failed for ' . $normalized);
		}

		if ($encoding === 'ecdsa') {
			$signature = self::ecdsaDerToRaw($signature, self::ecdsaCoordinateSize($normalized));
		}

		return $signature;
	}

	/**
	 * Verify a signature against a signature base.
	 *
	 * Either $algorithm OR $jwk's `alg`/`kty` may determine the algorithm. The
	 * explicit $algorithm wins if both are present; if neither resolves to a
	 * known algorithm, verification fails closed.
	 *
	 * @param string $signatureBase the bytes that were signed
	 * @param string $signature raw signature bytes (already base64-decoded)
	 * @param Jwk $jwk the resolved verification key
	 * @param string|null $algorithm optional algorithm hint from Signature-Input `alg=`
	 *
	 * @throws SignatureException when no algorithm can be determined or it is
	 *                            inconsistent with the key type
	 */
	public static function verify(string $signatureBase, string $signature, Jwk $jwk, ?string $algorithm): bool {
		$resolved = self::resolveAlgorithm($jwk, $algorithm);

		if ($resolved === 'ed25519') {
			$rawPublicKey = self::ed25519RawPublicKeyFromJwk($jwk);
			if ($rawPublicKey === null) {
				throw new SignatureException('cannot derive Ed25519 public key from JWK');
			}
			if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
				return false;
			}
			return sodium_crypto_sign_verify_detached($signature, $signatureBase, $rawPublicKey);
		}

		[$opensslAlgo, $encoding] = self::opensslParametersForAlgorithm($resolved);

		if ($encoding === 'ecdsa') {
			$signature = self::ecdsaRawToDer($signature, self::ecdsaCoordinateSize($resolved));
			if ($signature === null) {
				return false;
			}
		}

		$publicKey = self::publicKeyForVerify($jwk, $resolved);
		if ($publicKey === null) {
			throw new SignatureException('cannot derive public key from JWK');
		}

		// See comment in sign(): padding is the openssl_verify default for
		// the algorithms we still support, and the 5-arg form requires
		// PHP 8.5.
		return openssl_verify($signatureBase, $signature, $publicKey, $opensslAlgo) === 1;
	}

	/**
	 * Decode an Ed25519 JWK's `x` member to the raw 32-byte public key
	 * libsodium expects. Returns null if the member is missing or malformed.
	 */
	private static function ed25519RawPublicKeyFromJwk(Jwk $jwk): ?string {
		$x = $jwk->get('x');
		if ($x === null || $x === '') {
			return null;
		}
		$decoded = self::base64UrlDecode($x);
		if ($decoded === null || strlen($decoded) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
			return null;
		}
		return $decoded;
	}

	/**
	 * Normalize a JOSE algorithm name (RFC 7518, RFC 8037) to the equivalent
	 * RFC 9421 native identifier. Returns the input unchanged if it is
	 * already native.
	 *
	 * @throws SignatureException for unknown algorithm names
	 */
	public static function normalize(string $algorithm): string {
		$lower = strtolower($algorithm);
		if (in_array($lower, self::NATIVE, true)) {
			return $lower;
		}

		// JOSE algorithm identifiers (RFC 7518, RFC 8037) accepted per
		// RFC 9421 §3.3.7. PS256/PS384/PS512 (RSA-PSS) intentionally omitted;
		// see the class docblock.
		return match ($algorithm) {
			'EdDSA' => 'ed25519',
			'ES256' => 'ecdsa-p256-sha256',
			'ES384' => 'ecdsa-p384-sha384',
			'RS256' => 'rsa-v1_5-sha256',
			'RS384' => 'rsa-v1_5-sha384',
			'RS512' => 'rsa-v1_5-sha512',
			default => throw new SignatureException('unsupported signature algorithm: ' . $algorithm),
		};
	}

	/**
	 * @return array{0: int, 1: string} [openssl digest, wire encoding]
	 */
	private static function opensslParametersForAlgorithm(string $native): array {
		// Ed25519 is handled by libsodium upstream of this method and never
		// reaches it; only RSA-PKCS1-v1_5 and ECDSA go through OpenSSL.
		// RSA-PSS is not supported (see class docblock).
		return match ($native) {
			'rsa-v1_5-sha256' => [OPENSSL_ALGO_SHA256, 'raw'],
			'rsa-v1_5-sha384' => [OPENSSL_ALGO_SHA384, 'raw'],
			'rsa-v1_5-sha512' => [OPENSSL_ALGO_SHA512, 'raw'],
			'ecdsa-p256-sha256' => [OPENSSL_ALGO_SHA256, 'ecdsa'],
			'ecdsa-p384-sha384' => [OPENSSL_ALGO_SHA384, 'ecdsa'],
			default => throw new SignatureException('unsupported signature algorithm: ' . $native),
		};
	}

	private static function ecdsaCoordinateSize(string $native): int {
		return match ($native) {
			'ecdsa-p256-sha256' => 32,
			'ecdsa-p384-sha384' => 48,
			default => throw new InvalidArgumentException('not an ECDSA algorithm: ' . $native),
		};
	}

	/**
	 * Pick the algorithm to verify with, requiring every source that names one
	 * to agree per RFC 9421 §3.2 step 6 ("all sources MUST agree; mismatch
	 * fails verification"). The sources we consult are:
	 *   - the explicit `alg` parameter on the signature (when present),
	 *   - the JWK's `alg` member (when present),
	 *   - the JWK's `kty` and (for EC/OKP) `crv`.
	 *
	 * Each source independently normalises to a native identifier from
	 * RFC 9421 §3.3.1 - RFC 9421 §3.3.6; if any two disagree we fail closed.
	 *
	 * Cross-checking the JWK's `alg` against its `kty`/`crv` shape also has a
	 * normative basis: when a JOSE algorithm is in use, RFC 9421 §3.3.7 pulls
	 * in JWS validation, and RFC 7515 §10.12 says a JWS is invalid if "there
	 * is not a key for use with that algorithm" - i.e. a JWK that advertises
	 * an `alg` its key material cannot perform is malformed and must not
	 * verify.
	 */
	private static function resolveAlgorithm(Jwk $jwk, ?string $hint): string {
		$candidates = [];

		if ($hint !== null && $hint !== '') {
			$candidates['Signature-Input alg'] = self::normalize($hint);
		}

		$jwkAlg = $jwk->get('alg');
		if ($jwkAlg !== null && $jwkAlg !== '') {
			$candidates['JWK alg'] = self::normalize($jwkAlg);
		}

		$keyDerived = self::algorithmFromKeyShape($jwk);
		if ($keyDerived !== null) {
			$candidates['JWK kty/crv'] = $keyDerived;
		}

		if ($candidates === []) {
			throw new SignatureException('no algorithm source available');
		}

		$resolved = null;
		foreach ($candidates as $source => $value) {
			if ($resolved === null) {
				$resolved = $value;
				continue;
			}
			if ($resolved !== $value) {
				throw new SignatureException(
					'algorithm sources disagree: ' . $source . ' says ' . $value . ', earlier source said ' . $resolved
				);
			}
		}

		// Final consistency check: kty must match the family of the chosen
		// algorithm, even when kty/crv alone could not pin it down (e.g. an
		// RSA key with no `alg` member: we accept whatever the explicit hint
		// or JWK alg said, but kty must still be RSA).
		self::ensureKeyMatches($jwk, $resolved);
		return $resolved;
	}

	/**
	 * Algorithm a JWK signals through `kty`/`crv` alone, ignoring its `alg`
	 * member. Returns null when kty/crv cannot uniquely determine an
	 * algorithm (e.g. RSA, where kty/crv don't pin down PKCS1-v1.5 vs PSS or
	 * the hash function).
	 *
	 * The result is one input to the cross-source agreement check in
	 * {@see resolveAlgorithm}; combined with the JWK's `alg` member it
	 * implements the "key for use with that algorithm" requirement of
	 * RFC 7515 §10.12 (incorporated via RFC 9421 §3.3.7).
	 */
	private static function algorithmFromKeyShape(Jwk $jwk): ?string {
		return match ($jwk->getKty()) {
			'OKP' => match ($jwk->get('crv')) {
				'Ed25519' => 'ed25519',
				default => throw new SignatureException('unsupported OKP curve'),
			},
			'EC' => match ($jwk->get('crv')) {
				'P-256' => 'ecdsa-p256-sha256',
				'P-384' => 'ecdsa-p384-sha384',
				default => throw new SignatureException('unsupported EC curve'),
			},
			'RSA' => null,
			default => throw new SignatureException('cannot derive algorithm from JWK kty=' . $jwk->getKty()),
		};
	}

	private static function ensureKeyMatches(Jwk $jwk, string $algorithm): void {
		$expectKty = match ($algorithm) {
			'ed25519' => 'OKP',
			'ecdsa-p256-sha256', 'ecdsa-p384-sha384' => 'EC',
			default => 'RSA',
		};
		if ($jwk->getKty() !== $expectKty) {
			throw new SignatureException('algorithm ' . $algorithm . ' incompatible with JWK kty=' . $jwk->getKty());
		}
	}

	/**
	 * Convert an OpenSSL-style DER ECDSA signature (SEQUENCE of two INTEGERs)
	 * into the raw R||S concatenation required by RFC 9421 §3.3.4.
	 */
	public static function ecdsaDerToRaw(string $der, int $coordinateSize): string {
		$pos = 0;
		if (($der[$pos] ?? '') !== "\x30") {
			throw new SignatureException('malformed ECDSA DER');
		}
		$pos++;
		$pos += self::skipDerLength($der, $pos);

		[$r, $rEnd] = self::readDerInteger($der, $pos);
		[$s, ] = self::readDerInteger($der, $rEnd);

		return self::leftPad($r, $coordinateSize) . self::leftPad($s, $coordinateSize);
	}

	/**
	 * Convert a raw R||S ECDSA signature into the DER form OpenSSL expects.
	 * Returns null if the input length is not 2 * $coordinateSize.
	 */
	public static function ecdsaRawToDer(string $raw, int $coordinateSize): ?string {
		if (strlen($raw) !== $coordinateSize * 2) {
			return null;
		}
		$r = ltrim(substr($raw, 0, $coordinateSize), "\x00");
		$s = ltrim(substr($raw, $coordinateSize), "\x00");
		// DER INTEGER must be positive, so prepend 0x00 if high bit is set.
		if ($r === '' || (ord($r[0]) & 0x80) !== 0) {
			$r = "\x00" . $r;
		}
		if ($s === '' || (ord($s[0]) & 0x80) !== 0) {
			$s = "\x00" . $s;
		}
		$rEncoded = "\x02" . self::derLength(strlen($r)) . $r;
		$sEncoded = "\x02" . self::derLength(strlen($s)) . $s;
		$body = $rEncoded . $sEncoded;
		return "\x30" . self::derLength(strlen($body)) . $body;
	}

	/**
	 * @return int number of bytes consumed by the DER length field
	 */
	private static function skipDerLength(string $der, int $pos): int {
		$first = ord($der[$pos] ?? "\x00");
		if (($first & 0x80) === 0) {
			return 1;
		}
		return 1 + ($first & 0x7f);
	}

	/**
	 * @return array{0: string, 1: int} integer body bytes and end offset
	 */
	private static function readDerInteger(string $der, int $pos): array {
		if (($der[$pos] ?? '') !== "\x02") {
			throw new SignatureException('expected INTEGER in ECDSA DER');
		}
		$pos++;
		$lengthFirst = ord($der[$pos] ?? "\x00");
		if (($lengthFirst & 0x80) === 0) {
			$length = $lengthFirst;
			$pos++;
		} else {
			$lengthBytes = $lengthFirst & 0x7f;
			$pos++;
			$length = 0;
			for ($i = 0; $i < $lengthBytes; $i++) {
				$length = ($length << 8) | ord($der[$pos++] ?? "\x00");
			}
		}
		$value = substr($der, $pos, $length);
		// strip leading 0x00 added to keep the integer positive in DER
		$value = ltrim($value, "\x00");
		return [$value, $pos + $length];
	}

	private static function derLength(int $length): string {
		if ($length < 0x80) {
			return chr($length);
		}
		$bytes = '';
		while ($length > 0) {
			$bytes = chr($length & 0xff) . $bytes;
			$length >>= 8;
		}
		return chr(0x80 | strlen($bytes)) . $bytes;
	}

	private static function leftPad(string $value, int $size): string {
		if (strlen($value) > $size) {
			throw new SignatureException('ECDSA integer larger than coordinate size');
		}
		return str_repeat("\x00", $size - strlen($value)) . $value;
	}

	/**
	 * Materialise the JWK as a PEM SPKI string suitable for openssl_verify.
	 * Returns null if conversion is not possible. Ed25519 keys are not
	 * handled here — they take the libsodium path in {@see verify}.
	 */
	private static function publicKeyForVerify(Jwk $jwk, string $algorithm): ?string {
		return match ($jwk->getKty()) {
			'EC' => self::ecJwkToPem($jwk),
			'RSA' => self::rsaJwkToPem($jwk),
			default => null,
		};
	}

	private static function ecJwkToPem(Jwk $jwk): ?string {
		$crv = $jwk->get('crv');
		$curveOid = match ($crv) {
			// 1.2.840.10045.3.1.7 — secp256r1 / P-256
			'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
			// 1.3.132.0.34 — secp384r1 / P-384
			'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
			default => null,
		};
		$coordSize = match ($crv) {
			'P-256' => 32,
			'P-384' => 48,
			default => 0,
		};
		if ($curveOid === null || $coordSize === 0) {
			return null;
		}
		$x = self::base64UrlDecode($jwk->get('x') ?? '');
		$y = self::base64UrlDecode($jwk->get('y') ?? '');
		if ($x === null || $y === null || strlen($x) !== $coordSize || strlen($y) !== $coordSize) {
			return null;
		}
		// Uncompressed point encoding: 0x04 || X || Y
		$point = "\x04" . $x . $y;

		// 1.2.840.10045.2.1 — id-ecPublicKey
		$ecOid = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
		$algorithmId = "\x30" . self::derLength(strlen($ecOid . $curveOid)) . $ecOid . $curveOid;
		$bitString = "\x03" . self::derLength(strlen($point) + 1) . "\x00" . $point;
		$body = $algorithmId . $bitString;
		$spki = "\x30" . self::derLength(strlen($body)) . $body;
		return self::pemFromDer($spki, 'PUBLIC KEY');
	}

	private static function rsaJwkToPem(Jwk $jwk): ?string {
		$n = self::base64UrlDecode($jwk->get('n') ?? '');
		$e = self::base64UrlDecode($jwk->get('e') ?? '');
		if ($n === null || $e === null || $n === '' || $e === '') {
			return null;
		}
		// Strip leading zeros and re-pad so DER INTEGER stays positive.
		$n = self::trimAndPositiveInteger($n);
		$e = self::trimAndPositiveInteger($e);
		$nEncoded = "\x02" . self::derLength(strlen($n)) . $n;
		$eEncoded = "\x02" . self::derLength(strlen($e)) . $e;
		$rsaPublicKey = "\x30" . self::derLength(strlen($nEncoded . $eEncoded)) . $nEncoded . $eEncoded;

		// 1.2.840.113549.1.1.1 — rsaEncryption
		$rsaOid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
		$nullParams = "\x05\x00";
		$algorithmId = "\x30" . self::derLength(strlen($rsaOid . $nullParams)) . $rsaOid . $nullParams;
		$bitString = "\x03" . self::derLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
		$body = $algorithmId . $bitString;
		$spki = "\x30" . self::derLength(strlen($body)) . $body;
		return self::pemFromDer($spki, 'PUBLIC KEY');
	}

	private static function trimAndPositiveInteger(string $bytes): string {
		$bytes = ltrim($bytes, "\x00");
		if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
			$bytes = "\x00" . $bytes;
		}
		return $bytes;
	}

	private static function pemFromDer(string $der, string $label): string {
		return "-----BEGIN $label-----\n"
			. chunk_split(base64_encode($der), 64, "\n")
			. "-----END $label-----\n";
	}

	public static function base64UrlDecode(string $value): ?string {
		$value = strtr($value, '-_', '+/');
		$padding = strlen($value) % 4;
		if ($padding > 0) {
			$value .= str_repeat('=', 4 - $padding);
		}
		$decoded = base64_decode($value, true);
		return $decoded === false ? null : $decoded;
	}
}
