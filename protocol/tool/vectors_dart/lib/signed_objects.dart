// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Section 9.1 to 9.4 of protocol.md: the length-prefixed encoding, approver
/// keys and their ids, the signed bytes of each signed object and its
/// signature list (Ed25519 and ML-DSA-65, both required).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
// ignore: implementation_imports
import 'package:tom_pqc/src/pqc_backend.dart' show pqcBackend;
import 'package:tom_pqc/tom_pqc.dart';

/// `lp(x)`: the length of [bytes] as 4 bytes big-endian, then the bytes.
Uint8List lp(List<int> bytes) {
  final out = BytesBuilder()
    ..add([
      (bytes.length >> 24) & 0xff,
      (bytes.length >> 16) & 0xff,
      (bytes.length >> 8) & 0xff,
      bytes.length & 0xff,
    ])
    ..add(bytes);
  return out.toBytes();
}

/// `lp` of a string's UTF-8.
Uint8List lps(String text) => lp(utf8.encode(text));

/// The domain labels of the signed objects.
abstract final class Labels {
  static const grant = 'tsm-grant-v1';
  static const revoke = 'tsm-revoke-v1';
  static const approval = 'tsm-approval-v1';
  static const keyChange = 'tsm-keychange-v1';
  static const approverKey = 'tsm-approver-key-v1';
}

/// The members of each signed object, in the order they are signed.
const signedFields = <String, List<String>>{
  Labels.grant: [
    'id',
    'host',
    'subject',
    'secret',
    'decision',
    'created',
    'pin',
    'approver', //
  ],
  Labels.revoke: ['host', 'grantId', 'revoked', 'approver'],
  Labels.approval: ['host', 'code', 'decision', 'approver', 'created'],
  Labels.keyChange: [
    'device', 'oldKeyId', 'newKeyId', 'newEd25519', 'newMlDsa65', 'time', //
  ],
};

/// The text a `pin` member is signed as: `hash`, `off`, `relaxed:<time>`, or
/// empty when absent.
String pinText(Object? pin) => switch (pin) {
  null => '',
  String s => s,
  Map m => 'relaxed:${m['relaxedUntil']}',
  _ => throw ArgumentError.value(pin, 'pin'),
};

/// The signed bytes of [object] under [label]: `lp(label)` followed by
/// `lp(member)` for each member of [signedFields], an absent optional member
/// as the empty string.
Uint8List signedBytes(String label, Map<String, Object?> object) {
  final out = BytesBuilder()..add(lps(label));
  for (final name in signedFields[label]!) {
    final value = object[name];
    out.add(lps(name == 'pin' ? pinText(value) : (value as String?) ?? ''));
  }
  return out.toBytes();
}

/// An approver key pair: an Ed25519 and an ML-DSA-65 key used together.
final class ApproverKey {
  ApproverKey._(this.ed25519, this.ed25519Public, this.mlDsa, this.keyId);

  final SimpleKeyPair ed25519;
  final Uint8List ed25519Public;
  final MlDsa65KeyPair mlDsa;
  final String keyId;

  Uint8List get mlDsaPublic => mlDsa.publicKey;

  /// The pair from two 32-byte seeds.
  static Future<ApproverKey> fromSeeds(
    Uint8List ed25519Seed,
    Uint8List mlDsaSeed,
  ) async {
    final ed = await Ed25519().newKeyPairFromSeed(ed25519Seed);
    final edPublic = Uint8List.fromList((await ed.extractPublicKey()).bytes);
    final ml = MlDsa65.keyPairFromSeed(SecretBytes.fromBytes(mlDsaSeed));
    return ApproverKey._(ed, edPublic, ml, keyIdOf(edPublic, ml.publicKey));
  }

  /// The two signature items of [bytes] under [label], ML-DSA-65 in its
  /// deterministic mode (rnd all zero), as the vectors use it; an
  /// implementation signs hedged, which verifies the same way.
  Future<List<Map<String, String>>> signDeterministic(
    String label,
    Uint8List bytes,
  ) async {
    final ed = await Ed25519().sign(bytes, keyPair: ed25519);
    final ctx = utf8.encode(label);
    final ml = pqcBackend.mlDsa65SignInternal(
      bytes,
      mlDsa.secretKey,
      prefix: Uint8List.fromList([0, ctx.length, ...ctx]),
      rnd: Uint8List(32),
    );
    return [
      {'alg': 'ed25519', 'keyId': keyId, 'sig': base64.encode(ed.bytes)},
      {'alg': 'ml-dsa-65', 'keyId': keyId, 'sig': base64.encode(ml)},
    ];
  }
}

/// An approver key's id: the first 16 bytes, in lower-case hex, of
/// SHA-256(lp("tsm-approver-key-v1") || lp(ed25519 public) || lp(ML-DSA-65
/// public)).
String keyIdOf(List<int> ed25519Public, List<int> mlDsaPublic) {
  final digest = crypto.sha256.convert([
    ...lps(Labels.approverKey),
    ...lp(ed25519Public),
    ...lp(mlDsaPublic),
  ]);
  return digest.bytes
      .sublist(0, 16)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// A recorded approver public key.
typedef RecordedKey = ({List<int> ed25519, List<int> mlDsa65});

/// Whether [signatures] carry, for the key [keyId] of [keys], an Ed25519 item
/// and an ML-DSA-65 item that both verify over [bytes] under [label].
Future<bool> verifiedBy(
  String keyId,
  RecordedKey key,
  String label,
  Uint8List bytes,
  List<Map<String, Object?>> signatures,
) async {
  var ed = false;
  var ml = false;
  for (final item in signatures) {
    if (item['keyId'] != keyId) continue;
    final Uint8List sig;
    try {
      sig = base64.decode(item['sig'] as String);
    } on FormatException {
      continue;
    }
    if (item['alg'] == 'ed25519' && !ed) {
      ed = await Ed25519().verify(
        bytes,
        signature: Signature(
          sig,
          publicKey: SimplePublicKey(key.ed25519, type: KeyPairType.ed25519),
        ),
      );
    } else if (item['alg'] == 'ml-dsa-65' && !ml) {
      ml = MlDsa65.verify(
        bytes,
        sig,
        Uint8List.fromList(key.mlDsa65),
        context: Uint8List.fromList(utf8.encode(label)),
      );
    }
  }
  return ed && ml;
}

/// Whether [object] (a grant, revocation or approval record under [label])
/// is accepted: some key of [recorded] signed it with both algorithms.
Future<bool> accepts(
  String label,
  Map<String, Object?> object,
  Map<String, RecordedKey> recorded,
) async {
  final bytes = signedBytes(label, object);
  final signatures = (object['signatures'] as List)
      .cast<Map<String, Object?>>();
  for (final MapEntry(key: keyId, value: key) in recorded.entries) {
    if (await verifiedBy(keyId, key, label, bytes, signatures)) return true;
  }
  return false;
}

/// Whether a key-change [statement] is accepted: its old key is the recorded
/// [oldKey] and both the old and the new key (the statement's own public
/// keys) signed it with both algorithms, four signatures in all.
Future<bool> acceptsKeyChange(
  Map<String, Object?> statement,
  RecordedKey oldKey,
) async {
  final bytes = signedBytes(Labels.keyChange, statement);
  final signatures = (statement['signatures'] as List)
      .cast<Map<String, Object?>>();
  final newKey = (
    ed25519: base64.decode(statement['newEd25519'] as String),
    mlDsa65: base64.decode(statement['newMlDsa65'] as String),
  );
  if (keyIdOf(newKey.ed25519, newKey.mlDsa65) != statement['newKeyId'] ||
      keyIdOf(oldKey.ed25519, oldKey.mlDsa65) != statement['oldKeyId']) {
    return false;
  }
  return await verifiedBy(
        statement['oldKeyId'] as String,
        oldKey,
        Labels.keyChange,
        bytes,
        signatures,
      ) &&
      await verifiedBy(
        statement['newKeyId'] as String,
        newKey,
        Labels.keyChange,
        bytes,
        signatures,
      );
}
