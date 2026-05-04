<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\Security\Signature\Rfc9421;

use OC\Security\Signature\Rfc9421\ContentDigest;
use Test\TestCase;

class ContentDigestTest extends TestCase {
	public function testComputeRoundTrip(): void {
		$body = '{"hello":"world"}';
		$header = ContentDigest::compute($body, ContentDigest::ALGO_SHA256);
		$this->assertStringStartsWith('sha-256=:', $header);
		$this->assertStringEndsWith(':', $header);
		$this->assertTrue(ContentDigest::verify($header, $body));
	}

	public function testDifferentBodyFails(): void {
		$header = ContentDigest::compute('hello', ContentDigest::ALGO_SHA256);
		$this->assertFalse(ContentDigest::verify($header, 'goodbye'));
	}

	public function testSha512(): void {
		$header = ContentDigest::compute('payload', ContentDigest::ALGO_SHA512);
		$this->assertStringStartsWith('sha-512=:', $header);
		$this->assertTrue(ContentDigest::verify($header, 'payload'));
	}

	public function testParseMultipleAlgorithmsAcceptsAnyMatch(): void {
		$body = 'data';
		$sha256 = ContentDigest::compute($body, ContentDigest::ALGO_SHA256);
		$sha512 = ContentDigest::compute($body, ContentDigest::ALGO_SHA512);
		$header = $sha256 . ', ' . $sha512;
		$this->assertTrue(ContentDigest::verify($header, $body));
	}

	public function testUnknownAlgorithmIsIgnored(): void {
		$body = 'data';
		$sha256 = ContentDigest::compute($body, ContentDigest::ALGO_SHA256);
		$header = 'md5=:abcd:, ' . $sha256;
		$this->assertTrue(ContentDigest::verify($header, $body));
	}

	public function testEmptyHeaderFails(): void {
		$this->assertFalse(ContentDigest::verify('', 'body'));
	}

	public function testGarbageHeaderFails(): void {
		$this->assertFalse(ContentDigest::verify('not a digest', 'body'));
	}

	public function testParseExtractsRawBytes(): void {
		$header = ContentDigest::compute('abc', ContentDigest::ALGO_SHA256);
		$parsed = ContentDigest::parse($header);
		$this->assertArrayHasKey('sha-256', $parsed);
		$this->assertSame(hash('sha256', 'abc', true), $parsed['sha-256']);
	}
}
