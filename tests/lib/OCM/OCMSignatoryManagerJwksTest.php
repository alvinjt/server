<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\OCM;

use OC\OCM\OCMSignatoryManager;
use OC\Security\IdentityProof\Manager as IdentityProofManager;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IURLGenerator;
use OCP\Security\Signature\ISignatureManager;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class OCMSignatoryManagerJwksTest extends TestCase {
	private IAppConfig&MockObject $appConfig;
	private ISignatureManager&MockObject $signatureManager;
	private IURLGenerator&MockObject $urlGenerator;
	private IdentityProofManager&MockObject $identityProofManager;
	private IClientService&MockObject $clientService;
	private IConfig&MockObject $config;
	private LoggerInterface&MockObject $logger;
	private IClient&MockObject $client;
	private OCMSignatoryManager $signatoryManager;

	#[\Override]
	protected function setUp(): void {
		parent::setUp();

		$this->appConfig = $this->createMock(IAppConfig::class);
		$this->signatureManager = $this->createMock(ISignatureManager::class);
		$this->urlGenerator = $this->createMock(IURLGenerator::class);
		$this->identityProofManager = $this->createMock(IdentityProofManager::class);
		$this->clientService = $this->createMock(IClientService::class);
		$this->config = $this->createMock(IConfig::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->client = $this->createMock(IClient::class);

		$this->clientService->method('newClient')->willReturn($this->client);

		$this->signatoryManager = new OCMSignatoryManager(
			$this->appConfig,
			$this->signatureManager,
			$this->urlGenerator,
			$this->identityProofManager,
			$this->clientService,
			$this->config,
			$this->logger,
		);
	}

	public function testGetRemoteJwkFetchesAndMatchesByKid(): void {
		$kid = 'sender.example.org#key1';
		$jwks = [
			'keys' => [
				['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'other', 'x' => 'AAAA'],
				['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $kid, 'x' => 'BBBB'],
			],
		];
		$this->respondWith($jwks);

		$jwk = $this->signatoryManager->getRemoteJwk('sender.example.org', $kid);
		$this->assertNotNull($jwk);
		$this->assertSame($kid, $jwk->getKid());
		$this->assertSame('BBBB', $jwk->get('x'));
	}

	public function testGetRemoteJwkReturnsNullWhenKidMissing(): void {
		$this->respondWith(['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'unrelated', 'x' => 'AAAA']]]);
		$this->assertNull($this->signatoryManager->getRemoteJwk('sender.example.org', 'other-kid'));
	}

	public function testGetRemoteJwkReturnsNullOnHttpError(): void {
		$this->client->method('get')->willThrowException(new \RuntimeException('boom'));
		$this->logger->expects($this->once())->method('warning');
		$this->assertNull($this->signatoryManager->getRemoteJwk('sender.example.org', 'kid'));
	}

	public function testGetRemoteJwkReturnsNullOnInvalidJson(): void {
		$response = $this->createMock(IResponse::class);
		$response->method('getBody')->willReturn('not json');
		$this->client->method('get')->willReturn($response);
		$this->logger->expects($this->once())->method('warning');
		$this->assertNull($this->signatoryManager->getRemoteJwk('sender.example.org', 'kid'));
	}

	public function testGetRemoteJwkReturnsNullWhenKeysMissing(): void {
		$this->respondWith(['no-keys-here' => []]);
		$this->assertNull($this->signatoryManager->getRemoteJwk('sender.example.org', 'kid'));
	}

	public function testGetRemoteJwkUsesWellKnownPath(): void {
		$this->client->expects($this->once())
			->method('get')
			->with(
				$this->equalTo('https://sender.example.org/.well-known/jwks.json'),
				$this->isType('array'),
			)
			->willReturn($this->jsonResponse(['keys' => []]));

		$this->signatoryManager->getRemoteJwk('sender.example.org', 'kid');
	}

	public function testGetRemoteJwkPassesSelfSignedFlagThrough(): void {
		$this->config->method('getSystemValueBool')
			->with('sharing.federation.allowSelfSignedCertificates')
			->willReturn(true);

		$this->client->expects($this->once())
			->method('get')
			->with(
				$this->anything(),
				$this->callback(static fn (array $opts): bool => ($opts['verify'] ?? null) === false),
			)
			->willReturn($this->jsonResponse(['keys' => []]));

		$this->signatoryManager->getRemoteJwk('sender.example.org', 'kid');
	}

	private function respondWith(array $body): void {
		$this->client->method('get')->willReturn($this->jsonResponse($body));
	}

	private function jsonResponse(array $body): IResponse {
		$response = $this->createMock(IResponse::class);
		$response->method('getBody')->willReturn(json_encode($body, JSON_THROW_ON_ERROR));
		return $response;
	}
}
