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
	private string $ed25519PublicKey;

	#[\Override]
	protected function setUp(): void {
		parent::setUp();

		$keypair = sodium_crypto_sign_keypair();
		$this->ed25519PublicKey = sodium_crypto_sign_publickey($keypair);
	}

	public function testFromEd25519PublicKey(): void {
		$kid = 'https://sender.example.org/ocm#ed25519';
		$jwk = Jwk::fromEd25519PublicKey($this->ed25519PublicKey, $kid);

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

	public function testFromEd25519RejectsWrongLength(): void {
		$this->expectException(InvalidArgumentException::class);
		Jwk::fromEd25519PublicKey(str_repeat("\0", 31), 'kid');
	}

	public function testFromEd25519RejectsEmpty(): void {
		$this->expectException(InvalidArgumentException::class);
		Jwk::fromEd25519PublicKey('', 'kid');
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
