<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Rfc9421;

use InvalidArgumentException;

/**
 * RFC 9530 (Digest Fields) `Content-Digest` header helpers.
 *
 * The header is a Structured-Fields dictionary of byte-sequence values keyed by
 * algorithm name (`sha-256`, `sha-512`). RFC 9421 §7.2.5 recommends covering
 * `content-digest` in HTTP Message Signatures rather than the legacy `Digest`
 * header.
 */
final class ContentDigest {
	public const ALGO_SHA256 = 'sha-256';
	public const ALGO_SHA512 = 'sha-512';

	/**
	 * Compute a `Content-Digest` header value for the given body.
	 */
	public static function compute(string $body, string $algorithm = self::ALGO_SHA256): string {
		$hashAlgorithm = self::hashAlgorithmFor($algorithm);
		return $algorithm . '=:' . base64_encode(hash($hashAlgorithm, $body, true)) . ':';
	}

	/**
	 * Validate the header against the body. Returns true when:
	 *   - at least one digest algorithm in the header is recognised, AND
	 *   - every recognised algorithm's digest matches the body.
	 *
	 * Unsupported algorithms are skipped per RFC 9530 §2. We deliberately
	 * fail closed when any recognised algorithm mismatches: a mixed header
	 * like `sha-256=:correct:, sha-512=:wrong:` is treated as an attack on
	 * one algorithm rather than a successful match on the other. RFC 9530
	 * makes a single match sufficient, but for OCM we require the stronger
	 * property because the cost of false-accept is share/notification
	 * forgery.
	 */
	public static function verify(string $header, string $body): bool {
		$matched = false;
		foreach (self::parse($header) as $algorithm => $digest) {
			try {
				$hashAlgorithm = self::hashAlgorithmFor($algorithm);
			} catch (InvalidArgumentException) {
				continue;
			}
			if (!hash_equals(hash($hashAlgorithm, $body, true), $digest)) {
				return false;
			}
			$matched = true;
		}
		return $matched;
	}

	/**
	 * Parse a `Content-Digest` header into [algorithm => raw-bytes].
	 *
	 * @return array<string, string>
	 */
	public static function parse(string $header): array {
		$out = [];
		foreach (explode(',', $header) as $entry) {
			$entry = trim($entry);
			if ($entry === '') {
				continue;
			}
			if (!preg_match('#^([a-z0-9-]+)=:([A-Za-z0-9+/=]*):$#', $entry, $m)) {
				continue;
			}
			$decoded = base64_decode($m[2], true);
			if ($decoded === false) {
				continue;
			}
			$out[strtolower($m[1])] = $decoded;
		}
		return $out;
	}

	private static function hashAlgorithmFor(string $algorithm): string {
		return match (strtolower($algorithm)) {
			self::ALGO_SHA256 => 'sha256',
			self::ALGO_SHA512 => 'sha512',
			default => throw new InvalidArgumentException('unsupported content-digest algorithm: ' . $algorithm),
		};
	}
}
