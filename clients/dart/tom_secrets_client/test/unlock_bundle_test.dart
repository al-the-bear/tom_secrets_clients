// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The OS unlock's sealed key bundle (protocol.md 6.4) against
/// protocol/vectors/bundles.json: the bundle key, the associated data, the
/// sealed bytes, every rejected case refused; the plaintext's form.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  final v =
      jsonDecode(
            File('../../../protocol/vectors/bundles.json').readAsStringSync(),
          )
          as Map<String, Object?>;
  Uint8List b64(String k) => base64.decode(v[k]! as String);
  final key = tomSecretsBundleKey(
    b64('adminKey'),
    b64('serviceNonce'),
    b64('adminNonce'),
  );
  final start = v['serviceStart']! as int;

  test('the bundle key', () {
    expect(base64.encode(key), v['bundleKey']);
  });

  for (final c in (v['cases']! as List).cast<Map<String, Object?>>()) {
    test('${c['name']}: sealed and opened as the vector says', () async {
      final vault = c['vault']! as String;
      expect(base64.encode(tomSecretsBundleAad(vault, start)), c['aad']);
      final bundle = (c['bundle']! as Map).cast<String, Object?>();
      final sealed = await tomSecretsSealBundle(
        bundleKey: key,
        vault: vault,
        serviceStart: start,
        plaintext: utf8.encode(c['plaintext']! as String),
        nonce: base64.decode(bundle['nonce']! as String),
      );
      expect(sealed, bundle);
      final plain = await tomSecretsOpenBundle(
        bundleKey: key,
        vault: vault,
        serviceStart: start,
        bundle: bundle,
      );
      expect(utf8.decode(plain), c['plaintext']);
      final read = TomSecretsUnlockBundle.decode(plain);
      expect(read.encode(), plain);
    });
  }

  for (final r in (v['rejected']! as List).cast<Map<String, Object?>>()) {
    test('refused: ${r['name']}', () async {
      final k = r['serviceNonce'] == null
          ? key
          : tomSecretsBundleKey(
              b64('adminKey'),
              base64.decode(r['serviceNonce']! as String),
              b64('adminNonce'),
            );
      await expectLater(
        tomSecretsOpenBundle(
          bundleKey: k,
          vault: r['vault']! as String,
          serviceStart: r['serviceStart']! as int,
          bundle: (r['bundle']! as Map).cast<String, Object?>(),
        ),
        throwsA(isA<TomSecretsBundleException>()),
      );
    });
  }

  test('a fresh seal opens; a malformed bundle and plaintext are refused; '
      'the bundle hides its key', () async {
    final bundle = TomSecretsUnlockBundle(
      compositeKey: List.filled(32, 7),
      outerKey: 'demo-outer-key',
    );
    expect('$bundle', isNot(contains('demo')));
    final sealed = await tomSecretsSealBundle(
      bundleKey: key,
      vault: 'personal',
      serviceStart: start,
      plaintext: bundle.encode(),
    );
    final back = TomSecretsUnlockBundle.decode(
      await tomSecretsOpenBundle(
        bundleKey: key,
        vault: 'personal',
        serviceStart: start,
        bundle: sealed,
      ),
    );
    expect(back.compositeKey, List.filled(32, 7));
    expect(back.outerKey, 'demo-outer-key');
    back.dispose();
    expect(back.compositeKey, List.filled(32, 0));
    await expectLater(
      tomSecretsOpenBundle(
        bundleKey: key,
        vault: 'personal',
        serviceStart: start,
        bundle: {'nonce': 'AA==', 'ciphertext': 'AA=='},
      ),
      throwsA(isA<TomSecretsBundleException>()),
    );
    for (final text in ['{}', '{"v":1}', '{"v":1,"compositeKey":"AA=="}']) {
      expect(
        () => TomSecretsUnlockBundle.decode(utf8.encode(text)),
        throwsA(isA<TomSecretsBundleException>()),
      );
    }
  });

  test('a sealed field opens only as the field of the message it was sealed '
      'for, under the same key and service start', () async {
    final key = List<int>.generate(32, (i) => i);
    final sealed = await tomSecretsSealField(
      bundleKey: key,
      op: 'unlock',
      field: 'pin',
      serviceStart: 7,
      plaintext: utf8.encode('correct horse'),
    );
    final plain = await tomSecretsOpenField(
      bundleKey: key,
      op: 'unlock',
      field: 'pin',
      serviceStart: 7,
      sealed: sealed,
    );
    expect(utf8.decode(plain), 'correct horse');
    for (final (op, field, start) in [
      ('quickUnlock.set', 'pin', 7),
      ('unlock', 'quick', 7),
      ('unlock', 'pin', 8),
    ]) {
      await expectLater(
        tomSecretsOpenField(
          bundleKey: key,
          op: op,
          field: field,
          serviceStart: start,
          sealed: sealed,
        ),
        throwsA(isA<TomSecretsBundleException>()),
      );
    }
    await expectLater(
      tomSecretsOpenField(
        bundleKey: key,
        op: 'unlock',
        field: 'pin',
        serviceStart: 7,
        sealed: 'not sealed',
      ),
      throwsA(isA<TomSecretsBundleException>()),
    );
  });
}
