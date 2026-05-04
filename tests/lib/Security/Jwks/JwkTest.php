<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\Security\Jwks;

use InvalidArgumentException;
use OC\Security\Jwks\Jwk;
use Test\TestCase;

class JwkTest extends TestCase {
	private string $ed25519PublicPem;
	private string $rsaPublicPem;

	#[\Override]
	protected function setUp(): void {
		parent::setUp();

		$ed = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
		$this->ed25519PublicPem = openssl_pkey_get_details($ed)['key'];

		$rsa = openssl_pkey_new([
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
			'private_key_bits' => 2048,
		]);
		$this->rsaPublicPem = openssl_pkey_get_details($rsa)['key'];
	}

	public function testFromEd25519PublicKeyPem(): void {
		$kid = 'https://example.org/ocm#ed25519';
		$jwk = Jwk::fromEd25519PublicKeyPem($this->ed25519PublicPem, $kid);

		$arr = $jwk->toArray();
		$this->assertSame('OKP', $arr['kty']);
		$this->assertSame('Ed25519', $arr['crv']);
		$this->assertSame($kid, $arr['kid']);
		$this->assertSame('EdDSA', $arr['alg']);
		$this->assertSame('sig', $arr['use']);
		$this->assertArrayHasKey('x', $arr);

		// 32 raw bytes -> 43 base64url chars (no padding) for Ed25519 public key
		$this->assertSame(43, strlen($arr['x']));
		$this->assertMatchesRegularExpression('#^[A-Za-z0-9_-]+$#', $arr['x']);
	}

	public function testFromEd25519RejectsRsaKey(): void {
		$this->expectException(InvalidArgumentException::class);
		Jwk::fromEd25519PublicKeyPem($this->rsaPublicPem, 'kid');
	}

	public function testFromEd25519RejectsGarbage(): void {
		$this->expectException(InvalidArgumentException::class);
		Jwk::fromEd25519PublicKeyPem('not a pem', 'kid');
	}

	public function testFromArrayPreservesData(): void {
		$source = [
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => 'k1',
			'x' => 'AAAA',
		];
		$jwk = Jwk::fromArray($source);
		$this->assertSame($source, $jwk->toArray());
		$this->assertSame('k1', $jwk->getKid());
		$this->assertSame('OKP', $jwk->getKty());
		$this->assertSame('AAAA', $jwk->get('x'));
		$this->assertNull($jwk->get('missing'));
	}
}
