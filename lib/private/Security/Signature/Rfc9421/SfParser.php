<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Security\Signature\Rfc9421;

use OCP\Security\Signature\Exceptions\SignatureException;

/**
 * Minimal Structured-Fields (RFC 8941) parser scoped to the headers RFC 9421
 * actually uses: dictionaries of inner-lists with parameters (Signature-Input)
 * and dictionaries of byte-sequences (Signature).
 *
 * Out of scope: lists, parameterised top-level items, decimals, and date items.
 */
final class SfParser {
	private string $input;
	private int $pos = 0;
	private int $len;

	private function __construct(string $input) {
		// Per RFC 8941 §4.2: leading SP is permitted.
		$this->input = ltrim($input, " \t");
		$this->len = strlen($this->input);
	}

	/**
	 * Parse a Signature-Input header. Per RFC 8941 §4.2, when a label is
	 * present more than once only the last instance is retained; callers that
	 * need to reject duplicates can detect them via {@see findDuplicateLabels}.
	 *
	 * @return array<string, array{components: list<string>, params: array<string, scalar>}>
	 * @throws SignatureException on malformed input
	 */
	public static function parseSignatureInput(string $header): array {
		$parser = new self($header);
		$dict = $parser->parseDictionary()['entries'];

		$out = [];
		foreach ($dict as $label => $entry) {
			$value = $entry['value'];
			if (!is_array($value) || ($value['type'] ?? null) !== 'inner-list') {
				throw new SignatureException('Signature-Input value for ' . $label . ' is not an inner list');
			}

			$components = [];
			foreach ($value['items'] as $item) {
				$bare = $item['value'];
				if ($bare['type'] !== 'string') {
					throw new SignatureException('component identifier in Signature-Input must be a string');
				}
				$components[] = $bare['value'];
			}

			$out[$label] = [
				'components' => $components,
				'params' => $entry['params'],
			];
		}
		return $out;
	}

	/**
	 * Parse a Signature header (dictionary of byte-sequences). Per RFC 8941
	 * §4.2, when a label is present more than once only the last instance is
	 * retained; callers that need to reject duplicates can detect them via
	 * {@see findDuplicateLabels}.
	 *
	 * @return array<string, string> raw signature bytes keyed by label
	 * @throws SignatureException on malformed input
	 */
	public static function parseSignature(string $header): array {
		$parser = new self($header);
		$dict = $parser->parseDictionary()['entries'];

		$out = [];
		foreach ($dict as $label => $entry) {
			$value = $entry['value'];
			if (!is_array($value) || ($value['type'] ?? null) !== 'byte-sequence') {
				throw new SignatureException('Signature value for ' . $label . ' is not a byte sequence');
			}
			$out[$label] = $value['value'];
		}
		return $out;
	}

	/**
	 * Return the set of dictionary labels that appear more than once in
	 * $header, in the order in which the duplicate was first observed. Useful
	 * for callers (e.g. OCM) that impose stricter rules than RFC 8941 §4.2.
	 *
	 * @return list<string>
	 * @throws SignatureException on malformed input
	 */
	public static function findDuplicateLabels(string $header): array {
		$parser = new self($header);
		return $parser->parseDictionary()['duplicates'];
	}

	/**
	 * @return array{entries: array<string, array{value: array, params: array<string, scalar>}>, duplicates: list<string>}
	 */
	private function parseDictionary(): array {
		$entries = [];
		$duplicates = [];
		while ($this->pos < $this->len) {
			$key = $this->parseKey();
			$value = ['type' => 'boolean', 'value' => true];
			if ($this->peek() === '=') {
				$this->pos++;
				$value = $this->parseMember();
			}
			$params = $this->parseParameters();
			// RFC 8941 §4.2: "all but the last instance are ignored". Stricter
			// caller-level policies (e.g. OCM rejecting duplicate `ocm`
			// signatures) are enforced via {@see findDuplicateLabels}.
			if (array_key_exists($key, $entries) && !in_array($key, $duplicates, true)) {
				$duplicates[] = $key;
			}
			$entries[$key] = ['value' => $value, 'params' => $params];

			$this->skipOWS();
			if ($this->pos >= $this->len) {
				break;
			}
			if ($this->peek() !== ',') {
				throw new SignatureException('expected "," between dictionary entries at offset ' . $this->pos);
			}
			$this->pos++;
			$this->skipOWS();
			if ($this->pos >= $this->len) {
				throw new SignatureException('trailing comma in dictionary');
			}
		}
		return ['entries' => $entries, 'duplicates' => $duplicates];
	}

	private function parseMember(): array {
		if ($this->peek() === '(') {
			return $this->parseInnerList();
		}
		return $this->parseBareItem();
	}

	private function parseInnerList(): array {
		$this->expect('(');
		$items = [];
		while (true) {
			$this->skipSP();
			if ($this->pos >= $this->len) {
				throw new SignatureException('unterminated inner list');
			}
			if ($this->peek() === ')') {
				$this->pos++;
				return ['type' => 'inner-list', 'items' => $items];
			}
			$bare = $this->parseBareItem();
			$params = $this->parseParameters();
			$items[] = ['value' => $bare, 'params' => $params];

			if ($this->pos >= $this->len) {
				throw new SignatureException('unterminated inner list');
			}
			$next = $this->peek();
			if ($next !== ' ' && $next !== ')') {
				throw new SignatureException('expected " " or ")" in inner list at offset ' . $this->pos);
			}
		}
	}

	private function parseBareItem(): array {
		$c = $this->peek();
		if ($c === null) {
			throw new SignatureException('unexpected end of input at offset ' . $this->pos);
		}
		return match (true) {
			$c === '"' => $this->parseString(),
			$c === ':' => $this->parseByteSequence(),
			$c === '?' => $this->parseBoolean(),
			$c === '-' || ctype_digit($c) => $this->parseNumber(),
			ctype_alpha($c) || $c === '*' => $this->parseToken(),
			default => throw new SignatureException('unexpected character "' . $c . '" at offset ' . $this->pos),
		};
	}

	private function parseString(): array {
		$this->expect('"');
		$out = '';
		while ($this->pos < $this->len) {
			$c = $this->input[$this->pos++];
			if ($c === '\\') {
				if ($this->pos >= $this->len) {
					throw new SignatureException('dangling escape in string');
				}
				$next = $this->input[$this->pos++];
				if ($next !== '"' && $next !== '\\') {
					throw new SignatureException('invalid escape sequence in string');
				}
				$out .= $next;
				continue;
			}
			if ($c === '"') {
				return ['type' => 'string', 'value' => $out];
			}
			$ord = ord($c);
			if ($ord < 0x20 || $ord >= 0x7f) {
				throw new SignatureException('invalid character in string');
			}
			$out .= $c;
		}
		throw new SignatureException('unterminated string');
	}

	private function parseByteSequence(): array {
		$this->expect(':');
		$end = strpos($this->input, ':', $this->pos);
		if ($end === false) {
			throw new SignatureException('unterminated byte sequence');
		}
		$b64 = substr($this->input, $this->pos, $end - $this->pos);
		$this->pos = $end + 1;
		$decoded = base64_decode($b64, true);
		if ($decoded === false) {
			throw new SignatureException('invalid base64 in byte sequence');
		}
		return ['type' => 'byte-sequence', 'value' => $decoded];
	}

	private function parseBoolean(): array {
		$this->expect('?');
		if ($this->pos >= $this->len) {
			throw new SignatureException('truncated boolean');
		}
		$c = $this->input[$this->pos++];
		return match ($c) {
			'0' => ['type' => 'boolean', 'value' => false],
			'1' => ['type' => 'boolean', 'value' => true],
			default => throw new SignatureException('invalid boolean'),
		};
	}

	private function parseNumber(): array {
		$start = $this->pos;
		if ($this->peek() === '-') {
			$this->pos++;
		}
		$digitsStart = $this->pos;
		while ($this->pos < $this->len && ctype_digit($this->input[$this->pos])) {
			$this->pos++;
		}
		if ($this->pos === $digitsStart) {
			throw new SignatureException('expected digits at offset ' . $start);
		}
		// Decimals are not used in the headers we care about; reject them so
		// we don't silently truncate.
		if ($this->peek() === '.') {
			throw new SignatureException('decimal numbers are not supported');
		}
		$lexeme = substr($this->input, $start, $this->pos - $start);
		return ['type' => 'integer', 'value' => (int)$lexeme];
	}

	private function parseToken(): array {
		$start = $this->pos;
		$first = $this->input[$this->pos];
		if (!ctype_alpha($first) && $first !== '*') {
			throw new SignatureException('invalid token start at offset ' . $this->pos);
		}
		$this->pos++;
		while ($this->pos < $this->len) {
			$c = $this->input[$this->pos];
			if (ctype_alnum($c) || strpos("!#$%&'*+-.^_`|~:/", $c) !== false) {
				$this->pos++;
				continue;
			}
			break;
		}
		return ['type' => 'token', 'value' => substr($this->input, $start, $this->pos - $start)];
	}

	private function parseParameters(): array {
		$out = [];
		while ($this->peek() === ';') {
			$this->pos++;
			$this->skipSP();
			$key = $this->parseKey();
			$value = true;
			if ($this->peek() === '=') {
				$this->pos++;
				$bare = $this->parseBareItem();
				$value = $bare['value'];
			}
			$out[$key] = $value;
		}
		return $out;
	}

	private function parseKey(): string {
		if ($this->pos >= $this->len) {
			throw new SignatureException('expected key, found end of input');
		}
		$first = $this->input[$this->pos];
		if (!ctype_lower($first) && $first !== '*') {
			throw new SignatureException('invalid key start "' . $first . '" at offset ' . $this->pos);
		}
		$start = $this->pos++;
		while ($this->pos < $this->len) {
			$c = $this->input[$this->pos];
			if (ctype_lower($c) || ctype_digit($c) || $c === '_' || $c === '-' || $c === '.' || $c === '*') {
				$this->pos++;
				continue;
			}
			break;
		}
		return substr($this->input, $start, $this->pos - $start);
	}

	private function expect(string $c): void {
		if ($this->pos >= $this->len || $this->input[$this->pos] !== $c) {
			throw new SignatureException('expected "' . $c . '" at offset ' . $this->pos);
		}
		$this->pos++;
	}

	private function skipSP(): void {
		while ($this->pos < $this->len && $this->input[$this->pos] === ' ') {
			$this->pos++;
		}
	}

	private function skipOWS(): void {
		while ($this->pos < $this->len) {
			$c = $this->input[$this->pos];
			if ($c !== ' ' && $c !== "\t") {
				break;
			}
			$this->pos++;
		}
	}

	private function peek(): ?string {
		return $this->pos < $this->len ? $this->input[$this->pos] : null;
	}
}
