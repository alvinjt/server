<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\OCM;

use OC\OCM\OCMSignatoryManager;
use OC\OCM\Rfc9421SignatoryManager;
use OC\Security\Jwks\Jwk;
use OCP\Security\Signature\Exceptions\IdentityNotFoundException;
use OCP\Security\Signature\Model\Signatory;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class Rfc9421SignatoryManagerTest extends TestCase {
	private OCMSignatoryManager&MockObject $delegate;
	private Rfc9421SignatoryManager $wrapper;

	#[\Override]
	protected function setUp(): void {
		parent::setUp();
		$this->delegate = $this->createMock(OCMSignatoryManager::class);
		$this->wrapper = new Rfc9421SignatoryManager($this->delegate);
	}

	public function testGetOptionsForcesRfc9421Format(): void {
		$this->delegate->method('getOptions')->willReturn([
			'algorithm' => 'rsa-sha512',
			'rfc9421.format' => false,
		]);

		$options = $this->wrapper->getOptions();
		$this->assertTrue($options['rfc9421.format']);
		$this->assertSame('rsa-sha512', $options['algorithm']);
	}

	public function testGetLocalSignatoryReturnsEd25519Key(): void {
		$signatory = $this->createMock(Signatory::class);
		$this->delegate->method('getLocalEd25519Signatory')->willReturn($signatory);

		$this->assertSame($signatory, $this->wrapper->getLocalSignatory());
	}

	public function testGetLocalSignatoryThrowsWhenEd25519Unavailable(): void {
		$this->delegate->method('getLocalEd25519Signatory')->willReturn(null);

		$this->expectException(IdentityNotFoundException::class);
		$this->wrapper->getLocalSignatory();
	}

	public function testProviderIdDelegated(): void {
		$this->delegate->method('getProviderId')->willReturn('ocm');
		$this->assertSame('ocm', $this->wrapper->getProviderId());
	}

	public function testRemoteSignatoryDelegated(): void {
		$signatory = $this->createMock(Signatory::class);
		$this->delegate->expects($this->once())
			->method('getRemoteSignatory')
			->with('sender.example.org')
			->willReturn($signatory);
		$this->assertSame($signatory, $this->wrapper->getRemoteSignatory('sender.example.org'));
	}

	public function testRemoteJwkDelegated(): void {
		$jwk = Jwk::fromArray(['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'k', 'x' => 'AAAA']);
		$this->delegate->expects($this->once())
			->method('getRemoteJwk')
			->with('sender.example.org', 'kid-1')
			->willReturn($jwk);
		$this->assertSame($jwk, $this->wrapper->getRemoteJwk('sender.example.org', 'kid-1'));
	}
}
