<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace Test\Security\Signature\Rfc9421;

use OC\Security\Signature\Rfc9421\SfParser;
use OCP\Security\Signature\Exceptions\SignatureException;
use Test\TestCase;

class SfParserTest extends TestCase {
	public function testParseSimpleSignatureInput(): void {
		$header = 'sig1=("@method" "@target-uri" "content-digest");created=1730815200;keyid="kid1"';
		$parsed = SfParser::parseSignatureInput($header);

		$this->assertArrayHasKey('sig1', $parsed);
		$this->assertSame(['@method', '@target-uri', 'content-digest'], $parsed['sig1']['components']);
		$this->assertSame(1730815200, $parsed['sig1']['params']['created']);
		$this->assertSame('kid1', $parsed['sig1']['params']['keyid']);
	}

	public function testParseSignatureInputWithAlgAndExpires(): void {
		$header = 'sig1=("@method");created=100;expires=200;keyid="k";alg="ed25519"';
		$parsed = SfParser::parseSignatureInput($header);
		$this->assertSame(100, $parsed['sig1']['params']['created']);
		$this->assertSame(200, $parsed['sig1']['params']['expires']);
		$this->assertSame('ed25519', $parsed['sig1']['params']['alg']);
	}

	public function testParseMultipleLabels(): void {
		$header = 'sig1=("@method");keyid="a", sig2=("@status");keyid="b"';
		$parsed = SfParser::parseSignatureInput($header);
		$this->assertSame(['sig1', 'sig2'], array_keys($parsed));
		$this->assertSame(['@method'], $parsed['sig1']['components']);
		$this->assertSame(['@status'], $parsed['sig2']['components']);
		$this->assertSame('a', $parsed['sig1']['params']['keyid']);
		$this->assertSame('b', $parsed['sig2']['params']['keyid']);
	}

	public function testParseSignatureBytes(): void {
		$raw = random_bytes(64);
		$header = 'sig1=:' . base64_encode($raw) . ':';
		$parsed = SfParser::parseSignature($header);
		$this->assertSame($raw, $parsed['sig1']);
	}

	public function testParseSignatureMultiple(): void {
		$a = random_bytes(32);
		$b = random_bytes(64);
		$header = 'sig1=:' . base64_encode($a) . ':, sig2=:' . base64_encode($b) . ':';
		$parsed = SfParser::parseSignature($header);
		$this->assertSame($a, $parsed['sig1']);
		$this->assertSame($b, $parsed['sig2']);
	}

	public function testRejectsTrailingComma(): void {
		$this->expectException(SignatureException::class);
		SfParser::parseSignatureInput('sig1=("@method");keyid="k",');
	}

	public function testRejectsUnterminatedString(): void {
		$this->expectException(SignatureException::class);
		SfParser::parseSignatureInput('sig1=("@method");keyid="k');
	}

	public function testRejectsUnterminatedInnerList(): void {
		$this->expectException(SignatureException::class);
		SfParser::parseSignatureInput('sig1=("@method"');
	}

	public function testStringEscapes(): void {
		$header = 'sig1=("x");keyid="he said \"hi\""';
		$parsed = SfParser::parseSignatureInput($header);
		$this->assertSame('he said "hi"', $parsed['sig1']['params']['keyid']);
	}

	public function testTokenInComponentRejected(): void {
		// Component identifiers must be strings (RFC 9421 §2.1).
		$this->expectException(SignatureException::class);
		SfParser::parseSignatureInput('sig1=(@method);keyid="k"');
	}

	public function testDuplicateLabelLastWinsPerRfc8941(): void {
		// RFC 8941 §4.2: "all but the last instance are ignored". The generic
		// parser MUST follow that rule; stricter OCM policy is enforced at
		// the model layer, not here.
		$parsed = SfParser::parseSignatureInput('ocm=("@method");keyid="a", ocm=("@status");keyid="b"');
		$this->assertSame(['ocm'], array_keys($parsed));
		$this->assertSame(['@status'], $parsed['ocm']['components']);
		$this->assertSame('b', $parsed['ocm']['params']['keyid']);
	}

	public function testFindDuplicateLabels(): void {
		$header = 'a=("x");keyid="1", b=("x");keyid="2", a=("y");keyid="3", c=("z");keyid="4", b=("z");keyid="5"';
		$this->assertSame(['a', 'b'], SfParser::findDuplicateLabels($header));
	}

	public function testFindDuplicateLabelsNoneIsEmptyList(): void {
		$header = 'sig1=("x");keyid="1", sig2=("y");keyid="2"';
		$this->assertSame([], SfParser::findDuplicateLabels($header));
	}

	public function testFindDuplicateLabelsReportsLabelOnce(): void {
		// Three occurrences of `ocm` are still reported once.
		$header = 'ocm=("x");keyid="1", ocm=("y");keyid="2", ocm=("z");keyid="3"';
		$this->assertSame(['ocm'], SfParser::findDuplicateLabels($header));
	}
}
