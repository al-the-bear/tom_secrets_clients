// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The sealed key bundles of the OS unlock (protocol.md 6.4): the bundle
/// key by HKDF-SHA256, the associated data, and AES-256-GCM, written here
/// independently of the client library so the vectors check it.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import 'generate.dart' show derive;

/// HKDF-SHA256 (RFC 5869) with one block of output.
Uint8List bundleKey(List<int> adminKey, List<int> salt) {
  final prk = crypto.Hmac(crypto.sha256, salt).convert(adminKey).bytes;
  return Uint8List.fromList(
    crypto.Hmac(
      crypto.sha256,
      prk,
    ).convert([...ascii.encode('tsm-bundle-v1'), 1]).bytes,
  );
}

Uint8List aad(String vault, int serviceStart) {
  final start = ByteData(8)..setUint64(0, serviceStart);
  return Uint8List.fromList([
    ...utf8.encode(vault),
    ...start.buffer.asUint8List(),
  ]);
}

void _expect(bool condition, String what) {
  if (!condition) throw StateError('vector expectation failed: $what');
}

Future<Map<String, Object?>> bundleVectors() async {
  final gcm = AesGcm.with256bits();
  final adminKey = derive('bundle admin key');
  final serviceNonce = derive('bundle service nonce');
  final adminNonce = derive('bundle admin nonce');
  const serviceStart = 1794560400000;
  final key = bundleKey(adminKey, [...serviceNonce, ...adminNonce]);

  Future<Uint8List?> open(
    List<int> sealed,
    List<int> nonce,
    String vault,
    int start,
    List<int> k,
  ) async {
    try {
      return Uint8List.fromList(
        await gcm.decrypt(
          SecretBox(
            sealed.sublist(0, sealed.length - 16),
            nonce: nonce,
            mac: Mac(sealed.sublist(sealed.length - 16)),
          ),
          secretKey: SecretKeyData(k),
          aad: aad(vault, start),
        ),
      );
    } on SecretBoxAuthenticationError {
      return null;
    }
  }

  Future<Map<String, Object?>> sealed(
    String name,
    String vault,
    Map<String, Object?> plaintext,
  ) async {
    final nonce = derive('bundle nonce $name', 12);
    final plain = utf8.encode(jsonEncode(plaintext));
    final box = await gcm.encrypt(
      plain,
      secretKey: SecretKeyData(key),
      nonce: nonce,
      aad: aad(vault, serviceStart),
    );
    final ciphertext = [...box.cipherText, ...box.mac.bytes];
    final back = await open(ciphertext, nonce, vault, serviceStart, key);
    _expect(
      back != null && utf8.decode(back) == utf8.decode(plain),
      '$name opens',
    );
    _expect(
      await open(ciphertext, nonce, '${vault}x', serviceStart, key) == null,
      '$name refused for another vault',
    );
    _expect(
      await open(ciphertext, nonce, vault, serviceStart + 1, key) == null,
      '$name refused for another service start',
    );
    return {
      'name': name,
      'vault': vault,
      'plaintext': utf8.decode(plain),
      'aad': base64.encode(aad(vault, serviceStart)),
      'bundle': {
        'nonce': base64.encode(nonce),
        'ciphertext': base64.encode(ciphertext),
      },
    };
  }

  final plain = await sealed('the primary, composite key only', 'personal', {
    'v': 1,
    'compositeKey': base64.encode(derive('bundle composite personal')),
  });
  final outer = await sealed('a vault with the outer encryption', 'fleet', {
    'v': 1,
    'compositeKey': base64.encode(derive('bundle composite fleet')),
    'outerKey': base64.encode(derive('bundle outer key fleet')),
  });
  final otherConnection = bundleKey(derive('bundle admin key'), [
    ...derive('bundle service nonce 2'),
    ...adminNonce,
  ]);
  final first = plain['bundle']! as Map<String, String>;
  _expect(
    await open(
          base64.decode(first['ciphertext']!),
          base64.decode(first['nonce']!),
          'personal',
          serviceStart,
          otherConnection,
        ) ==
        null,
    'refused on another connection',
  );
  final tampered = base64.decode(first['ciphertext']!);
  tampered[tampered.length - 1] ^= 1;
  return {
    'note':
        'The sealed key bundles of the OS unlock (section 6.4): bundleKey = '
        'HKDF-SHA256(ikm = adminKey, salt = serviceNonce || adminNonce, info '
        '= "tsm-bundle-v1", 32 bytes); ciphertext = AES-256-GCM(bundleKey, '
        'nonce, plaintext, aad = vault UTF-8 || serviceStart as 8 bytes '
        'big-endian) with the 16-byte tag appended. Keys, nonces and the '
        'composite keys are demo values derived from labels.',
    'adminKey': base64.encode(adminKey),
    'serviceNonce': base64.encode(serviceNonce),
    'adminNonce': base64.encode(adminNonce),
    'serviceStart': serviceStart,
    'bundleKey': base64.encode(key),
    'cases': [plain, outer],
    'rejected': [
      {
        'name': 'another vault',
        'case': plain['name'],
        'vault': 'fleet',
        'serviceStart': serviceStart,
        'bundle': first,
      },
      {
        'name': 'another service start',
        'case': plain['name'],
        'vault': 'personal',
        'serviceStart': serviceStart + 1,
        'bundle': first,
      },
      {
        'name': 'another admin connection (serviceNonce)',
        'case': plain['name'],
        'vault': 'personal',
        'serviceStart': serviceStart,
        'serviceNonce': base64.encode(derive('bundle service nonce 2')),
        'bundle': first,
      },
      {
        'name': 'a changed tag',
        'case': plain['name'],
        'vault': 'personal',
        'serviceStart': serviceStart,
        'bundle': {
          'nonce': first['nonce'],
          'ciphertext': base64.encode(tampered),
        },
      },
    ],
  };
}
