<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\Security\Signature\Model;

use OC\Security\Jwks\Jwk;
use OC\Security\Signature\Model\Rfc9421IncomingSignedRequest;
use OC\Security\Signature\Model\Rfc9421OutgoingSignedRequest;
use OCP\IRequest;
use OCP\Security\Signature\Enum\DigestAlgorithm;
use OCP\Security\Signature\Enum\SignatureAlgorithm;
use OCP\Security\Signature\Exceptions\IncomingRequestException;
use OCP\Security\Signature\Exceptions\InvalidSignatureException;
use OCP\Security\Signature\Exceptions\SignatureNotFoundException;
use OCP\Security\Signature\ISignatoryManager;
use OCP\Security\Signature\Model\Signatory;
use Test\TestCase;

class Rfc9421RoundTripTest extends TestCase {
	public function testEd25519RoundTripVerifies(): void {
		[$signatory, $jwk] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$body = '{"hello":"world"}';
		$method = 'POST';
		$uri = 'https://receiver.example.org/ocm/shares';

		$out = new Rfc9421OutgoingSignedRequest($body, $signatoryManager, 'receiver.example.org', $method, $uri);
		$out->sign();

		$req = $this->mockRequestFromOutgoing($out, $method, '/ocm/shares', 'receiver.example.org');
		$in = new Rfc9421IncomingSignedRequest($body, $req);
		$in->setJwk($jwk);

		$this->assertSame($out->getSignatureBaseString(), $in->getSignatureBaseString());
		$in->verify(); // throws on failure
		$this->addToAssertionCount(1);
	}

	public function testTamperedBodyRejected(): void {
		[$signatory, $jwk] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$body = 'original';
		$out = new Rfc9421OutgoingSignedRequest($body, $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		$req = $this->mockRequestFromOutgoing($out, 'POST', '/ocm/shares', 'receiver.example.org');
		$this->expectException(IncomingRequestException::class);
		new Rfc9421IncomingSignedRequest('tampered', $req);
	}

	public function testTamperedSignatureRejected(): void {
		[$signatory, $jwk] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$body = 'msg';
		$out = new Rfc9421OutgoingSignedRequest($body, $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		$headers = $out->getHeaders();
		// Replace the inner base64 of the signature with a different valid base64.
		$headers['Signature'] = preg_replace('/=:[^:]+:/', '=:' . base64_encode(random_bytes(64)) . ':', (string)$headers['Signature']);

		$req = $this->mockRequest($headers, 'POST', '/ocm/shares', 'receiver.example.org');
		$in = new Rfc9421IncomingSignedRequest($body, $req);
		$in->setJwk($jwk);

		$this->expectException(InvalidSignatureException::class);
		$in->verify();
	}

	public function testOutgoingUsesOcmLabel(): void {
		[$signatory] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$out = new Rfc9421OutgoingSignedRequest('msg', $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		$headers = $out->getHeaders();
		$this->assertStringStartsWith('ocm=(', (string)$headers['Signature-Input']);
		$this->assertStringStartsWith('ocm=:', (string)$headers['Signature']);
	}

	public function testRequestWithoutOcmLabelRejected(): void {
		[$signatory, $jwk] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$out = new Rfc9421OutgoingSignedRequest('msg', $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		// Rename the OCM label to something else; verifier MUST reject.
		$headers = $out->getHeaders();
		$headers['Signature-Input'] = preg_replace('/^ocm=/', 'sig1=', (string)$headers['Signature-Input']);
		$headers['Signature'] = preg_replace('/^ocm=/', 'sig1=', (string)$headers['Signature']);

		$req = $this->mockRequest($headers, 'POST', '/ocm/shares', 'receiver.example.org');
		$this->expectException(SignatureNotFoundException::class);
		new Rfc9421IncomingSignedRequest('msg', $req);
	}

	public function testDuplicateOcmLabelRejected(): void {
		// RFC 8941 §4.2 last-wins on duplicate dictionary keys, but OCM
		// mandates that duplicate `ocm` entries cause the request to be
		// rejected outright. The model layer enforces that.
		[$signatory, $jwk] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$out = new Rfc9421OutgoingSignedRequest('msg', $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		$headers = $out->getHeaders();
		$headers['Signature-Input'] = (string)$headers['Signature-Input'] . ', ' . (string)$headers['Signature-Input'];
		$headers['Signature'] = (string)$headers['Signature'] . ', ' . (string)$headers['Signature'];

		$req = $this->mockRequest($headers, 'POST', '/ocm/shares', 'receiver.example.org');
		$this->expectException(IncomingRequestException::class);
		new Rfc9421IncomingSignedRequest('msg', $req);
	}

	public function testForeignSiblingLabelIgnored(): void {
		[$signatory, $jwk] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$out = new Rfc9421OutgoingSignedRequest('msg', $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		// Splice in a sibling proxy_sig1 entry; the verifier must ignore it
		// and still verify the ocm-labeled signature successfully.
		$headers = $out->getHeaders();
		$proxyParams = '("@method");created=1;keyid="proxy"';
		$proxySig = base64_encode(random_bytes(64));
		$headers['Signature-Input'] = (string)$headers['Signature-Input'] . ', proxy_sig1=' . $proxyParams;
		$headers['Signature'] = (string)$headers['Signature'] . ', proxy_sig1=:' . $proxySig . ':';

		$req = $this->mockRequest($headers, 'POST', '/ocm/shares', 'receiver.example.org');
		$in = new Rfc9421IncomingSignedRequest('msg', $req);
		$in->setJwk($jwk);
		$in->verify();
		$this->addToAssertionCount(1);
	}

	public function testTooOldSignatureRejected(): void {
		[$signatory] = $this->ed25519Material('https://sender.example.org/ocm#ed25519');
		$signatoryManager = $this->makeSignatoryManager($signatory);

		$body = 'msg';
		$out = new Rfc9421OutgoingSignedRequest($body, $signatoryManager, 'receiver.example.org', 'POST', 'https://receiver.example.org/ocm/shares');
		$out->sign();

		// Backdate `created` in Signature-Input by 10 minutes.
		$headers = $out->getHeaders();
		$pastCreated = time() - 600;
		$headers['Signature-Input'] = preg_replace('/created=\d+/', 'created=' . $pastCreated, (string)$headers['Signature-Input']);

		$req = $this->mockRequest($headers, 'POST', '/ocm/shares', 'receiver.example.org');
		$this->expectException(IncomingRequestException::class);
		new Rfc9421IncomingSignedRequest($body, $req, ['ttl' => 300]);
	}

	private function ed25519Material(string $kid): array {
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
		$priv = '';
		openssl_pkey_export($key, $priv);
		$details = openssl_pkey_get_details($key);
		$signatory = new Signatory(true);
		$signatory->setKeyId($kid);
		$signatory->setPublicKey($details['key']);
		$signatory->setPrivateKey($priv);
		$jwk = Jwk::fromArray([
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'kid' => $kid,
			'alg' => 'EdDSA',
			'x' => rtrim(strtr(base64_encode($details['ed25519']['pub_key']), '+/', '-_'), '='),
		]);
		return [$signatory, $jwk];
	}

	private function makeSignatoryManager(Signatory $signatory): ISignatoryManager {
		return new class($signatory) implements ISignatoryManager {
			public function __construct(private Signatory $sig) {
			}

			public function getProviderId(): string {
				return 'test';
			}

			public function getOptions(): array {
				return [
					'algorithm' => SignatureAlgorithm::RSA_SHA256,
					'digestAlgorithm' => DigestAlgorithm::SHA256,
				];
			}

			public function getLocalSignatory(): Signatory {
				return $this->sig;
			}

			public function getRemoteSignatory(string $remote): ?Signatory {
				return null;
			}
		};
	}

	private function mockRequestFromOutgoing(Rfc9421OutgoingSignedRequest $out, string $method, string $path, string $host): IRequest {
		return $this->mockRequest($out->getHeaders(), $method, $path, $host);
	}

	private function mockRequest(array $headers, string $method, string $path, string $host): IRequest {
		$lowered = [];
		foreach ($headers as $name => $value) {
			$lowered[strtolower($name)] = (string)$value;
		}
		$mock = $this->createMock(IRequest::class);
		$mock->method('getHeader')->willReturnCallback(static fn (string $h) => $lowered[strtolower($h)] ?? '');
		$mock->method('getMethod')->willReturn($method);
		$mock->method('getRequestUri')->willReturn($path);
		$mock->method('getServerProtocol')->willReturn('https');
		$mock->method('getServerHost')->willReturn($host);
		return $mock;
	}
}
