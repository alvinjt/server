<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\Security\Signature\Rfc9421;

use OC\Security\Jwks\Jwk;
use OC\Security\Signature\Rfc9421\Algorithm;
use OCP\Security\Signature\Exceptions\SignatureException;
use Test\TestCase;

class AlgorithmTest extends TestCase {
	public function testNormalizeNativeIsPassThrough(): void {
		$this->assertSame('ed25519', Algorithm::normalize('ed25519'));
		$this->assertSame('rsa-pss-sha512', Algorithm::normalize('rsa-pss-sha512'));
	}

	public function testNormalizeJoseAliases(): void {
		$this->assertSame('ed25519', Algorithm::normalize('EdDSA'));
		$this->assertSame('ecdsa-p256-sha256', Algorithm::normalize('ES256'));
		$this->assertSame('ecdsa-p384-sha384', Algorithm::normalize('ES384'));
		$this->assertSame('rsa-v1_5-sha256', Algorithm::normalize('RS256'));
		$this->assertSame('rsa-pss-sha512', Algorithm::normalize('PS512'));
	}

	public function testNormalizeRejectsUnknown(): void {
		$this->expectException(SignatureException::class);
		Algorithm::normalize('totally-not-real');
	}

	public function testEd25519RoundTrip(): void {
		[$priv, $jwk] = $this->ed25519KeyPair();
		$base = 'arbitrary signature base';
		$sig = Algorithm::sign($base, $priv, 'ed25519');
		$this->assertSame(64, strlen($sig));
		$this->assertTrue(Algorithm::verify($base, $sig, $jwk, 'ed25519'));
		// JOSE alias accepted (RFC 9421 §3.3.7)
		$this->assertTrue(Algorithm::verify($base, $sig, $jwk, 'EdDSA'));
		// alg-omitted path resolves through JWK metadata
		$this->assertTrue(Algorithm::verify($base, $sig, $jwk, null));
		// tamper detection
		$this->assertFalse(Algorithm::verify($base . 'x', $sig, $jwk, 'ed25519'));
	}

	public function testRsaPkcs1RoundTrip(): void {
		[$priv, $jwk] = $this->rsaKeyPair();
		$sig = Algorithm::sign('payload', $priv, 'rsa-v1_5-sha256');
		$this->assertSame(256, strlen($sig));
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'rsa-v1_5-sha256'));
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'RS256'));
	}

	public function testRsaPssRoundTrip(): void {
		[$priv, $jwk] = $this->rsaKeyPair();
		$sig = Algorithm::sign('payload', $priv, 'rsa-pss-sha512');
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'rsa-pss-sha512'));
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'PS512'));
	}

	public function testEcdsaP256RoundTrip(): void {
		[$priv, $jwk] = $this->ecKeyPair('prime256v1', 'P-256');
		$sig = Algorithm::sign('payload', $priv, 'ecdsa-p256-sha256');
		$this->assertSame(64, strlen($sig));
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'ecdsa-p256-sha256'));
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'ES256'));
	}

	public function testEcdsaP384RoundTrip(): void {
		[$priv, $jwk] = $this->ecKeyPair('secp384r1', 'P-384');
		$sig = Algorithm::sign('payload', $priv, 'ecdsa-p384-sha384');
		$this->assertSame(96, strlen($sig));
		$this->assertTrue(Algorithm::verify('payload', $sig, $jwk, 'ecdsa-p384-sha384'));
	}

	public function testKeyTypeMismatchFailsClosed(): void {
		[, $rsaJwk] = $this->rsaKeyPair();
		$this->expectException(SignatureException::class);
		Algorithm::verify('payload', random_bytes(64), $rsaJwk, 'ed25519');
	}

	public function testAlgHintConflictsWithJwkAlgRejected(): void {
		// JWK advertises EdDSA but the request claims ES256: per
		// RFC 9421 §3.2 step 6 the verifier MUST fail when sources disagree.
		[, $jwk] = $this->ed25519KeyPair();
		$this->expectException(SignatureException::class);
		Algorithm::verify('payload', random_bytes(64), $jwk, 'ES256');
	}

	public function testAlgHintConflictsWithJwkKtyCrvRejected(): void {
		// JWK has Ed25519 OKP shape but no `alg` member; explicit hint
		// disagrees with what the key shape signals.
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
		$details = openssl_pkey_get_details($key);
		$jwk = Jwk::fromArray([
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => 'k',
			// no `alg` advertised
			'x' => self::b64url($details['ed25519']['pub_key']),
		]);
		$this->expectException(SignatureException::class);
		Algorithm::verify('payload', random_bytes(64), $jwk, 'ES256');
	}

	public function testJwkAlgAndKtyCrvMustAgree(): void {
		// JWK kty=OKP/crv=Ed25519 but advertises alg=ES256: contradictory,
		// must be rejected even without an explicit hint.
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
		$details = openssl_pkey_get_details($key);
		$jwk = Jwk::fromArray([
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => 'k',
			'alg' => 'ES256',
			'x' => self::b64url($details['ed25519']['pub_key']),
		]);
		$this->expectException(SignatureException::class);
		Algorithm::verify('payload', random_bytes(64), $jwk, null);
	}

	public function testAlgHintAgreesWithJwkAlgViaJoseAlias(): void {
		// `EdDSA` on the JWK and `ed25519` in Signature-Input both normalise
		// to ed25519 — accepted.
		[$priv, $jwk] = $this->ed25519KeyPair();
		$base = 'agreement check';
		$sig = Algorithm::sign($base, $priv, 'ed25519');
		$this->assertTrue(Algorithm::verify($base, $sig, $jwk, 'ed25519'));
		$this->assertTrue(Algorithm::verify($base, $sig, $jwk, 'EdDSA'));
	}

	public function testEcdsaDerToRawAndBack(): void {
		// Build a recognisable DER: SEQUENCE { INTEGER 0x01, INTEGER 0x02 }
		// then round-trip into raw form and back.
		[$priv,] = $this->ecKeyPair('prime256v1', 'P-256');
		// Get a real signature (DER) and round-trip
		openssl_sign('msg', $derSig, $priv, OPENSSL_ALGO_SHA256);
		$raw = Algorithm::ecdsaDerToRaw($derSig, 32);
		$this->assertSame(64, strlen($raw));
		$der2 = Algorithm::ecdsaRawToDer($raw, 32);
		$this->assertNotNull($der2);
		// The re-encoded DER may differ in INTEGER padding bytes; check that
		// both decode to the same R||S.
		$this->assertSame($raw, Algorithm::ecdsaDerToRaw($der2, 32));
	}

	public function testEcdsaRawToDerWrongLength(): void {
		$this->assertNull(Algorithm::ecdsaRawToDer('short', 32));
	}

	private function ed25519KeyPair(): array {
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
		$priv = '';
		openssl_pkey_export($key, $priv);
		$details = openssl_pkey_get_details($key);
		$jwk = Jwk::fromArray([
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => 'k',
			'alg' => 'EdDSA',
			'x' => self::b64url($details['ed25519']['pub_key']),
		]);
		return [$priv, $jwk];
	}

	private function rsaKeyPair(): array {
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
		$priv = '';
		openssl_pkey_export($key, $priv);
		$details = openssl_pkey_get_details($key);
		$jwk = Jwk::fromArray([
			'kty' => 'RSA',
			'kid' => 'k',
			'n' => self::b64url($details['rsa']['n']),
			'e' => self::b64url($details['rsa']['e']),
		]);
		return [$priv, $jwk];
	}

	private function ecKeyPair(string $opensslCurve, string $jwkCurve): array {
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $opensslCurve]);
		$priv = '';
		openssl_pkey_export($key, $priv);
		$details = openssl_pkey_get_details($key);
		$jwk = Jwk::fromArray([
			'kty' => 'EC',
			'crv' => $jwkCurve,
			'kid' => 'k',
			'x' => self::b64url($details['ec']['x']),
			'y' => self::b64url($details['ec']['y']),
		]);
		return [$priv, $jwk];
	}

	private static function b64url(string $bin): string {
		return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
	}
}
