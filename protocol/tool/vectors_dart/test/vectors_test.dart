// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tsm_protocol_vectors/approval_link.dart';
import 'package:tsm_protocol_vectors/generate.dart';
import 'package:tsm_protocol_vectors/signed_objects.dart';

Map<String, Object?> _load(String name) =>
    jsonDecode(File('../../vectors/$name').readAsStringSync())
        as Map<String, Object?>;

Map<String, RecordedKey> _recorded(Map<String, Object?> v) {
  final keys = (v['keys'] as Map).values.cast<Map<String, Object?>>();
  final recorded = (v['recorded'] as List).cast<String>();
  return {
    for (final k in keys)
      if (recorded.contains(k['keyId']))
        k['keyId'] as String: (
          ed25519: base64.decode(k['ed25519Public'] as String),
          mlDsa65: base64.decode(k['mlDsa65Public'] as String),
        ),
  };
}

void main() {
  group('the vector files', () {
    test(
      'signatures.json and link_handshake.json are what the generator writes',
      () async {
        final signatures = await signatureVectors();
        expect(_load('signatures.json'), jsonDecode(jsonEncode(signatures)));
        expect(
          _load('link_handshake.json'),
          jsonDecode(jsonEncode(await linkVectors(signatures))),
        );
      },
    );
  });

  group('signed objects', () {
    final v = _load('signatures.json');
    final recorded = _recorded(v);
    final approverKey = recorded.values.single;
    final accepted = (v['accepted'] as List).cast<Map<String, Object?>>();

    for (final c in accepted) {
      test('${c['name']}: signed bytes and acceptance', () async {
        final label = c['label'] as String;
        final object = c['object'] as Map<String, Object?>;
        expect(hex(signedBytes(label, object)), c['signedBytesHex']);
        final ok = label == Labels.keyChange
            ? await acceptsKeyChange(object, approverKey)
            : await accepts(label, object, recorded);
        expect(ok, isTrue);
      });
    }

    for (final c in (v['rejected'] as List).cast<Map<String, Object?>>()) {
      test('${c['name']}: rejected', () async {
        final label = c['label'] as String;
        final object = c['object'] as Map<String, Object?>;
        final ok = label == Labels.keyChange
            ? await acceptsKeyChange(object, approverKey)
            : await accepts(label, object, recorded);
        expect(ok, isFalse);
      });
    }

    test('every signed member of a grant is covered', () async {
      final grant =
          accepted.firstWhere((c) => c['name'] == 'grant')['object']!
              as Map<String, Object?>;
      for (final name in signedFields[Labels.grant]!) {
        final changed = {...grant, name: name == 'pin' ? 'off' : 'x'};
        expect(
          await accepts(Labels.grant, changed, recorded),
          isFalse,
          reason: name,
        );
      }
    });

    test('the length prefix keeps member boundaries apart', () {
      final a = signedBytes(Labels.revoke, {'host': 'ab', 'grantId': 'c'});
      final b = signedBytes(Labels.revoke, {'host': 'a', 'grantId': 'bc'});
      expect(hex(a), isNot(hex(b)));
    });

    test(
      'a key change whose old key is not the recorded one is refused',
      () async {
        final statement =
            accepted.firstWhere(
                  (c) => c['label'] == Labels.keyChange,
                )['object']!
                as Map<String, Object?>;
        final other = (v['keys'] as Map)['unpaired'] as Map<String, Object?>;
        final otherKey = (
          ed25519: base64.decode(other['ed25519Public'] as String),
          mlDsa65: base64.decode(other['mlDsa65Public'] as String),
        );
        expect(await acceptsKeyChange(statement, otherKey), isFalse);
      },
    );
  });

  group('the approval link', () {
    final v = _load('link_handshake.json');

    Future<(LinkKey, LinkPublic)> side(String name) async {
      final m = v[name]! as Map<String, Object?>;
      final key = await LinkKey.fromSeeds(
        base64.decode(m['x25519Seed'] as String),
        base64.decode(m['mlKem768Seed'] as String),
      );
      return (key, (x25519: key.x25519Public, mlKem: key.mlKemPublic));
    }

    InitiatorRandom fixedInitiator() {
      final r = v['approverRandom']! as Map<String, Object?>;
      return (
        ephemeralX25519Seed: base64.decode(r['ephemeralX25519Seed'] as String),
        ephemeralMlKemSeed: base64.decode(r['ephemeralMlKem768Seed'] as String),
        coinsToResponderStatic: base64.decode(r['coinsToHostStatic'] as String),
      );
    }

    ResponderRandom fixedResponder() {
      final r = v['hostRandom']! as Map<String, Object?>;
      return (
        ephemeralX25519Seed: base64.decode(r['ephemeralX25519Seed'] as String),
        coinsToInitiatorEphemeral: base64.decode(
          r['coinsToApproverEphemeral'] as String,
        ),
        coinsToInitiatorStatic: base64.decode(
          r['coinsToApproverStatic'] as String,
        ),
      );
    }

    test('each role reads the other role\'s message from the file', () async {
      final (approver, approverPublic) = await side('approver');
      final (host, hostPublic) = await side('host');
      final responder = Responder(
        host,
        hostPublic,
        approverPublic,
        fixedResponder(),
      );
      final payload1 = await responder.readMessage1(
        hex2bytes(v['message1Hex'] as String),
      );
      expect(utf8.decode(payload1), v['payload1Text']);
      final (m2, hostSession) = await responder.writeMessage2(
        utf8.encode(v['payload2Text'] as String),
      );
      expect(hex(m2), v['message2Hex']);

      final initiator = Initiator(
        approver,
        approverPublic,
        hostPublic,
        fixedInitiator(),
      );
      final m1 = await initiator.writeMessage1(
        utf8.encode(v['payload1Text'] as String),
      );
      expect(hex(m1), v['message1Hex']);
      final (payload2, approverSession) = await initiator.readMessage2(
        hex2bytes(v['message2Hex'] as String),
      );
      expect(utf8.decode(payload2), v['payload2Text']);
      expect(hex(approverSession.handshakeHash), v['handshakeHash']);
      expect(hex(hostSession.initiatorToResponder), v['approverToHostKey']);
      expect(hex(approverSession.responderToInitiator), v['hostToApproverKey']);
    });

    test('a message 2 the approver did not expect fails', () async {
      final (approver, approverPublic) = await side('approver');
      final (_, hostPublic) = await side('host');
      final initiator = Initiator(
        approver,
        approverPublic,
        hostPublic,
        fixedInitiator(),
      );
      await initiator.writeMessage1(utf8.encode(v['payload1Text'] as String));
      final m2 = hex2bytes(v['message2Hex'] as String);
      final altered = Uint8List.fromList(m2)
        ..[40] ^= 1; // its first ML-KEM ciphertext
      expect(
        () => initiator.readMessage2(altered),
        throwsA(isA<LinkHandshakeError>()),
      );
    });

    test('a host whose keys are not the recorded ones cannot answer', () async {
      final (approver, approverPublic) = await side('approver');
      final (_, hostPublic) = await side('host');
      final impostor = await LinkKey.fromSeeds(
        derive('link impostor x25519'),
        derive('link impostor ml-kem', 64),
      );
      final responder = Responder(
        impostor,
        (x25519: impostor.x25519Public, mlKem: impostor.mlKemPublic),
        approverPublic,
        fixedResponder(),
      );
      final initiator = Initiator(
        approver,
        approverPublic,
        hostPublic,
        fixedInitiator(),
      );
      final m1 = await initiator.writeMessage1(
        utf8.encode(v['payload1Text'] as String),
      );
      expect(
        () => responder.readMessage1(m1),
        throwsA(isA<LinkHandshakeError>()),
      );
    });

    test('a low-order X25519 ephemeral key is refused', () async {
      final (_, approverPublic) = await side('approver');
      final (host, hostPublic) = await side('host');
      final m1 = hex2bytes(v['message1Hex'] as String)..fillRange(0, 32, 0);
      final responder = Responder(
        host,
        hostPublic,
        approverPublic,
        fixedResponder(),
      );
      expect(
        () => responder.readMessage1(m1),
        throwsA(
          isA<LinkHandshakeError>().having(
            (e) => e.message,
            'message',
            contains('low-order'),
          ),
        ),
      );
    });

    test('the transport frames decrypt in order, with the rekeys', () async {
      final keys = {
        'approver': TransportCipher(
          hex2bytes(v['approverToHostKey'] as String),
        ),
        'host': TransportCipher(hex2bytes(v['hostToApproverKey'] as String)),
      };
      for (final f in (v['transport'] as List).cast<Map<String, Object?>>()) {
        final cipher = keys[f['from']]!;
        expect(cipher.n, f['n']);
        final plain = await cipher.decrypt(
          hex2bytes(f['ciphertextHex'] as String),
        );
        expect(utf8.decode(plain), f['plaintext']);
        expect(jsonDecode(utf8.decode(plain)), f['json']);
        if ((f['json'] as Map)['op'] == 'rekey') {
          await cipher.rekeyNow();
          expect(hex(cipher.key), f['keyAfterRekeyHex']);
        }
      }
    });

    test('a frame decrypted out of order fails', () async {
      final frames = (v['transport'] as List)
          .cast<Map<String, Object?>>()
          .where((f) => f['from'] == 'approver')
          .toList();
      final cipher = TransportCipher(
        hex2bytes(v['approverToHostKey'] as String),
      );
      expect(
        () => cipher.decrypt(hex2bytes(frames[1]['ciphertextHex'] as String)),
        throwsA(isA<LinkHandshakeError>()),
      );
    });

    test('the recorded failures name what failed', () {
      final names = (v['failures'] as List).cast<Map<String, Object?>>().map(
        (f) => f['name'],
      );
      expect(names, hasLength(5));
    });
  });
}
