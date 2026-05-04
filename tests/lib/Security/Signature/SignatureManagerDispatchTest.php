<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\Security\Signature;

use OC\Security\Jwks\Jwk;
use OC\Security\Signature\Db\SignatoryMapper;
use OC\Security\Signature\Model\Rfc9421IncomingSignedRequest;
use OC\Security\Signature\Model\Rfc9421OutgoingSignedRequest;
use OC\Security\Signature\Rfc9421\IJwkResolvingSignatoryManager;
use OC\Security\Signature\Rfc9421\OcmProfile;
use OC\Security\Signature\SignatureManager;
use OCP\IAppConfig;
use OCP\IRequest;
use OCP\Security\Signature\Enum\DigestAlgorithm;
use OCP\Security\Signature\Enum\SignatureAlgorithm;
use OCP\Security\Signature\Exceptions\IncomingRequestException;
use OCP\Security\Signature\ISignatoryManager;
use OCP\Security\Signature\Model\Signatory;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class SignatureManagerDispatchTest extends TestCase {
	private IRequest&MockObject $request;
	private SignatoryMapper&MockObject $mapper;
	private IAppConfig&MockObject $appConfig;
	private LoggerInterface&MockObject $logger;
	private SignatureManager $signatureManager;

	#[\Override]
	protected function setUp(): void {
		parent::setUp();

		$this->request = $this->createMock(IRequest::class);
		$this->mapper = $this->createMock(SignatoryMapper::class);
		$this->appConfig = $this->createMock(IAppConfig::class);
		$this->logger = $this->createMock(LoggerInterface::class);

		$this->signatureManager = new SignatureManager(
			$this->request,
			$this->mapper,
			$this->appConfig,
			$this->logger,
		);
	}

	public function testOutgoingDispatchesToCavageByDefault(): void {
		[$signatoryManager,] = $this->ed25519SignatoryManager(rfc9421Format: false);

		$signed = $this->signatureManager->getOutgoingSignedRequest(
			$signatoryManager,
			'{}',
			'POST',
			'https://receiver.example.org/ocm/shares',
		);

		$this->assertNotInstanceOf(Rfc9421OutgoingSignedRequest::class, $signed);
	}

	public function testOutgoingDispatchesToRfc9421WhenOptionSet(): void {
		[$signatoryManager,] = $this->ed25519SignatoryManager(rfc9421Format: true);

		$signed = $this->signatureManager->getOutgoingSignedRequest(
			$signatoryManager,
			'{}',
			'POST',
			'https://receiver.example.org/ocm/shares',
		);

		$this->assertInstanceOf(Rfc9421OutgoingSignedRequest::class, $signed);
		$headers = $signed->getHeaders();
		$this->assertArrayHasKey('Signature-Input', $headers);
		$this->assertStringStartsWith(OcmProfile::SIGNATURE_LABEL . '=(', (string)$headers['Signature-Input']);
	}

	public function testInboundDispatchesToRfc9421WhenSignatureInputPresent(): void {
		[$signatoryManager, $jwk, $secret] = $this->ed25519SignatoryManager(rfc9421Format: true);

		// Build a real signed request and replay its headers as the inbound
		// request to exercise the full inbound path including verification.
		$body = '{"hello":"world"}';
		$out = new Rfc9421OutgoingSignedRequest(
			$body,
			$signatoryManager,
			'receiver.example.org',
			'POST',
			'https://receiver.example.org/ocm/shares',
		);
		$out->sign();
		$headers = $out->getHeaders();

		$this->primeRequest($headers, 'POST', '/ocm/shares', 'receiver.example.org');

		$resolver = $this->makeJwkResolver($signatoryManager, $jwk);

		$signed = $this->signatureManager->getIncomingSignedRequest($resolver, $body);
		$this->assertInstanceOf(Rfc9421IncomingSignedRequest::class, $signed);
	}

	public function testInboundRejectsRfc9421WhenSignatoryManagerCannotResolve(): void {
		[$signatoryManager,] = $this->ed25519SignatoryManager(rfc9421Format: true);

		$body = '{"hello":"world"}';
		$out = new Rfc9421OutgoingSignedRequest(
			$body,
			$signatoryManager,
			'receiver.example.org',
			'POST',
			'https://receiver.example.org/ocm/shares',
		);
		$out->sign();
		$this->primeRequest($out->getHeaders(), 'POST', '/ocm/shares', 'receiver.example.org');

		// $signatoryManager does NOT implement IJwkResolvingSignatoryManager.
		$this->expectException(IncomingRequestException::class);
		$this->signatureManager->getIncomingSignedRequest($signatoryManager, $body);
	}

	/**
	 * @return array{ISignatoryManager, Jwk, string} [manager, public JWK, raw secret key]
	 */
	private function ed25519SignatoryManager(bool $rfc9421Format): array {
		$keypair = sodium_crypto_sign_keypair();
		$publicKey = sodium_crypto_sign_publickey($keypair);
		$secretKey = sodium_crypto_sign_secretkey($keypair);
		$kid = 'https://sender.example.org/ocm#ed25519';

		$signatory = new Signatory(true);
		$signatory->setKeyId($kid);
		$signatory->setPublicKey($publicKey);
		$signatory->setPrivateKey($secretKey);

		$jwk = Jwk::fromEd25519PublicKey($publicKey, $kid);

		$manager = new class($signatory, $rfc9421Format) implements ISignatoryManager {
			public function __construct(
				private Signatory $signatory,
				private bool $rfc9421,
			) {
			}

			public function getProviderId(): string {
				return 'test';
			}

			public function getOptions(): array {
				return [
					'algorithm' => SignatureAlgorithm::RSA_SHA256,
					'digestAlgorithm' => DigestAlgorithm::SHA256,
					'rfc9421.format' => $this->rfc9421,
				];
			}

			public function getLocalSignatory(): Signatory {
				return $this->signatory;
			}

			public function getRemoteSignatory(string $remote): ?Signatory {
				return null;
			}
		};
		return [$manager, $jwk, $secretKey];
	}

	private function makeJwkResolver(ISignatoryManager $delegate, Jwk $jwk): IJwkResolvingSignatoryManager {
		return new class($delegate, $jwk) implements IJwkResolvingSignatoryManager {
			public function __construct(
				private ISignatoryManager $delegate,
				private Jwk $jwk,
			) {
			}

			public function getProviderId(): string {
				return $this->delegate->getProviderId();
			}

			public function getOptions(): array {
				return $this->delegate->getOptions();
			}

			public function getLocalSignatory(): Signatory {
				return $this->delegate->getLocalSignatory();
			}

			public function getRemoteSignatory(string $remote): ?Signatory {
				return $this->delegate->getRemoteSignatory($remote);
			}

			public function getRemoteJwk(string $origin, string $keyId): ?Jwk {
				return $keyId === $this->jwk->getKid() ? $this->jwk : null;
			}
		};
	}

	private function primeRequest(array $headers, string $method, string $path, string $host): void {
		$lowered = [];
		foreach ($headers as $name => $value) {
			$lowered[strtolower($name)] = (string)$value;
		}
		$this->request->method('getHeader')
			->willReturnCallback(static fn (string $name) => $lowered[strtolower($name)] ?? '');
		$this->request->method('getMethod')->willReturn($method);
		$this->request->method('getRequestUri')->willReturn($path);
		$this->request->method('getServerProtocol')->willReturn('https');
		$this->request->method('getServerHost')->willReturn($host);
	}
}
