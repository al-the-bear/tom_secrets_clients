// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The admin keys in the keychain: kept with their index, forgotten when
/// their service stops, the others pruned when one is kept or used.
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  late Map<String, String> store;
  late TomSecretsAdminKeyring keyring;

  setUp(() {
    store = {};
    keyring = TomSecretsAdminKeyring(
      read: (h) async => store[h],
      write: (h, v) async => store[h] = v,
      delete: (h) async => store.remove(h),
    );
  });

  Uint8List key(int b) => Uint8List.fromList(List.filled(32, b));

  test('kept: the key under its start, the start in the index', () async {
    await keyring.keep(100, key(1));
    await keyring.keep(200, key(2));
    expect(await keyring.keyOf(100), key(1));
    expect(store[tomSecretsAdminKeyIndexHandle], '100,200');
    expect(await keyring.recorded(), {100, 200});
    await keyring.keep(200, key(3));
    expect(store[tomSecretsAdminKeyIndexHandle], '100,200', reason: 'once');
    expect(await keyring.keyOf(200), key(3));
  });

  test('forgotten: the key and its index entry; the last one takes the '
      'index with it', () async {
    await keyring.keep(100, key(1));
    await keyring.keep(200, key(2));
    await keyring.forget(100);
    expect(store.containsKey(tomSecretsAdminKeyHandle(100)), isFalse);
    expect(store[tomSecretsAdminKeyIndexHandle], '200');
    await keyring.forget(200);
    expect(store, isEmpty);
    await keyring.forget(300);
    expect(store, isEmpty, reason: 'an unknown start is no error');
  });

  test('pruned: every recorded key but the running service\'s; none '
      'running takes them all', () async {
    for (final s in [100, 200, 300]) {
      await keyring.keep(s, key(s % 250));
    }
    store['tsm.github-token.o:r'] = 'other item';
    expect(await keyring.pruneOthers(200), [100, 300]);
    expect(store.keys, containsAll([tomSecretsAdminKeyHandle(200)]));
    expect(store.containsKey(tomSecretsAdminKeyHandle(100)), isFalse);
    expect(store.containsKey(tomSecretsAdminKeyHandle(300)), isFalse);
    expect(store[tomSecretsAdminKeyIndexHandle], '200');
    expect(store['tsm.github-token.o:r'], 'other item');
    expect(await keyring.pruneOthers(200), isEmpty);
    expect(await keyring.pruneOthers(null), [200]);
    expect(store.keys, ['tsm.github-token.o:r']);
  });

  test('a damaged index or key reads as nothing', () async {
    store[tomSecretsAdminKeyIndexHandle] = 'x,12,,y';
    expect(await keyring.recorded(), {12});
    store[tomSecretsAdminKeyHandle(12)] = '***';
    expect(await keyring.keyOf(12), isNull);
    expect(await keyring.keyOf(13), isNull);
  });
}
