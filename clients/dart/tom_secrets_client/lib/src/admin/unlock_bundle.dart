// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The key bundle of the OS unlock (protocol.md 6.4, part-os-unlock): what
/// the app reads from the OS-gated store and hands to the service, sealed so
/// the plaintext never crosses the socket or the Windows TCP port.
///
/// - The bundle is the vault's composite key (the 32 bytes KDBX derives its
///   key from: the hash of the password and the key file) and, for a vault
///   with the outer encryption, its repository key; never the password text.
///   Its plaintext is the UTF-8 JSON object
///   `{"v": 1, "compositeKey": "...", "outerKey": "..."}`: the composite key
///   in base64, the repository key as kept (left out when there is none).
/// - The bundle key is `HKDF-SHA256(ikm = adminKey, salt = serviceNonce ||
///   adminNonce, info = "tsm-bundle-v1", 32 bytes)`: new for every admin
///   connection, never sent.
/// - The sealed bundle is AES-256-GCM under that key with a random 12-byte
///   nonce, the 16-byte tag appended to the ciphertext, and as associated
///   data the vault's name in UTF-8 followed by `serviceStart` as 8 bytes
///   big-endian.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import 'admin_auth.dart';

/// The HKDF info of the bundle key.
const String tomSecretsBundleInfo = 'tsm-bundle-v1';

/// The length of a bundle's nonce.
const int tomSecretsBundleNonceBytes = 12;

/// The length of a composite key.
const int tomSecretsCompositeKeyBytes = 32;

/// A sealed bundle did not open, or its plaintext is no bundle. Carries no
/// key material.
final class TomSecretsBundleException implements Exception {
  /// A failure saying [message].
  const TomSecretsBundleException(this.message);

  /// What failed.
  final String message;

  @override
  String toString() => 'TomSecretsBundleException: $message';
}

/// The key material of one vault's OS unlock: its [compositeKey] and, for a
/// vault with the outer encryption, its [outerKey] (the repository key as
/// the keychain keeps it).
final class TomSecretsUnlockBundle {
  /// A bundle of [compositeKey] (32 bytes; a copy is kept) and [outerKey].
  TomSecretsUnlockBundle({required List<int> compositeKey, this.outerKey})
    : compositeKey = Uint8List.fromList(compositeKey) {
    if (compositeKey.length != tomSecretsCompositeKeyBytes) {
      throw const TomSecretsBundleException('a composite key has 32 bytes');
    }
  }

  /// Reads the plaintext [bytes] (`encode`'s form).
  factory TomSecretsUnlockBundle.decode(List<int> bytes) {
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(bytes));
    } on FormatException {
      throw const TomSecretsBundleException('no bundle');
    }
    if (json is! Map || json['v'] != 1) {
      throw const TomSecretsBundleException('no bundle of version 1');
    }
    final composite = json['compositeKey'];
    final outer = json['outerKey'];
    if (composite is! String || (outer != null && outer is! String)) {
      throw const TomSecretsBundleException('no bundle');
    }
    final Uint8List key;
    try {
      key = base64.decode(composite);
    } on FormatException {
      throw const TomSecretsBundleException('no composite key');
    }
    try {
      return TomSecretsUnlockBundle(
        compositeKey: key,
        outerKey: outer as String?,
      );
    } finally {
      key.fillRange(0, key.length, 0);
    }
  }

  /// The composite key.
  final Uint8List compositeKey;

  /// The repository key, or null.
  final String? outerKey;

  /// The plaintext bytes; the caller wipes them after use.
  Uint8List encode() => Uint8List.fromList(
    utf8.encode(
      jsonEncode({
        'v': 1,
        'compositeKey': base64.encode(compositeKey),
        'outerKey': ?outerKey,
      }),
    ),
  );

  /// Overwrites the composite key.
  void dispose() => compositeKey.fillRange(0, compositeKey.length, 0);

  @override
  String toString() => 'TomSecretsUnlockBundle{***}';
}

/// The bundle key of one admin connection: `HKDF-SHA256(adminKey, salt =
/// serviceNonce || adminNonce, info = "tsm-bundle-v1")`, 32 bytes.
Uint8List tomSecretsBundleKey(
  List<int> adminKey,
  List<int> serviceNonce,
  List<int> adminNonce,
) {
  if (serviceNonce.length != tomSecretsKeyBytes ||
      adminNonce.length != tomSecretsKeyBytes) {
    throw ArgumentError('a nonce is $tomSecretsKeyBytes bytes');
  }
  // RFC 5869 with one block of output.
  final prk = crypto.Hmac(crypto.sha256, [
    ...serviceNonce,
    ...adminNonce,
  ]).convert(adminKey).bytes;
  final okm = crypto.Hmac(
    crypto.sha256,
    prk,
  ).convert([...ascii.encode(tomSecretsBundleInfo), 1]).bytes;
  return Uint8List.fromList(okm);
}

/// The associated data of [vault]'s bundle: its name's UTF-8 bytes and
/// [serviceStart] as 8 bytes big-endian.
Uint8List tomSecretsBundleAad(String vault, int serviceStart) {
  final start = ByteData(8)..setUint64(0, serviceStart);
  return Uint8List.fromList([
    ...utf8.encode(vault),
    ...start.buffer.asUint8List(),
  ]);
}

final AesGcm _aesGcm = AesGcm.with256bits();

/// Seals [plaintext] for [vault] under [bundleKey]: the `bundle` object of
/// `unlock` (`nonce`, `ciphertext` with the tag, both base64). [nonce] is
/// random unless given (test vectors).
Future<Map<String, String>> tomSecretsSealBundle({
  required List<int> bundleKey,
  required String vault,
  required int serviceStart,
  required List<int> plaintext,
  List<int>? nonce,
}) async {
  final n = nonce ?? tomSecretsRandomBytes(tomSecretsBundleNonceBytes);
  final box = await _aesGcm.encrypt(
    plaintext,
    secretKey: SecretKeyData(bundleKey),
    nonce: n,
    aad: tomSecretsBundleAad(vault, serviceStart),
  );
  return {
    'nonce': base64.encode(n),
    'ciphertext': base64.encode([...box.cipherText, ...box.mac.bytes]),
  };
}

/// Opens the `bundle` object of `unlock` for [vault]: the plaintext bytes,
/// which the caller wipes after use. Throws [TomSecretsBundleException] when
/// it is malformed or does not open (another key, vault or service start).
Future<Uint8List> tomSecretsOpenBundle({
  required List<int> bundleKey,
  required String vault,
  required int serviceStart,
  required Map<String, Object?> bundle,
}) async {
  final Uint8List nonce;
  final Uint8List sealed;
  try {
    nonce = base64.decode(bundle['nonce']! as String);
    sealed = base64.decode(bundle['ciphertext']! as String);
  } on Object {
    throw const TomSecretsBundleException('no sealed bundle');
  }
  const tag = 16;
  if (nonce.length != tomSecretsBundleNonceBytes || sealed.length < tag) {
    throw const TomSecretsBundleException('no sealed bundle');
  }
  try {
    final plain = await _aesGcm.decrypt(
      SecretBox(
        sealed.sublist(0, sealed.length - tag),
        nonce: nonce,
        mac: Mac(sealed.sublist(sealed.length - tag)),
      ),
      secretKey: SecretKeyData(bundleKey),
      aad: tomSecretsBundleAad(vault, serviceStart),
    );
    return Uint8List.fromList(plain);
  } on SecretBoxAuthenticationError {
    throw const TomSecretsBundleException('the bundle does not open');
  }
}
