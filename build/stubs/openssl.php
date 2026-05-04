<?php

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// Selected ext-openssl constants that psalm's bundled stubs do not provide.
// ext-openssl is required by composer.json so the constants are guaranteed to
// exist at runtime; this file just teaches the static analyser about them.

// Padding modes for openssl_sign / openssl_verify / openssl_*_encrypt.
// OPENSSL_PKCS1_PSS_PADDING is intentionally omitted: it was only exposed
// from PHP 8.5 onwards (see PHP migration notes), and we still target
// PHP 8.2; depending on it would silently break older runtimes.
const OPENSSL_PKCS1_PADDING = 1;
const OPENSSL_SSLV23_PADDING = 2;
const OPENSSL_NO_PADDING = 3;
const OPENSSL_PKCS1_OAEP_PADDING = 4;
