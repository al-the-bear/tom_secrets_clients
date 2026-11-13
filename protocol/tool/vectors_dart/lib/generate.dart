// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Builds vectors/signatures.json and vectors/link_handshake.json from inputs
/// derived from labels (no randomness), asserting every expectation while it
/// builds: an accepted object is accepted, a rejected one is rejected, the
/// responder reads what the initiator wrote and the other way round.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'approval_link.dart';
import 'signed_objects.dart';

/// [n] bytes of SHA-256 in counter mode over [label], as gen_vectors.py
/// derives its inputs.
Uint8List derive(String label, [int n = 32]) {
  final out = <int>[];
  for (var block = 0; out.length < n; block++) {
    out.addAll(
      crypto.sha256
          .convert(utf8.encode('tsm protocol vector $label $block'))
          .bytes,
    );
  }
  return Uint8List.fromList(out.sublist(0, n));
}

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void _expect(bool condition, String what) {
  if (!condition) throw StateError('vector expectation failed: $what');
}

Future<Map<String, Object?>> _keyJson(String name, ApproverKey key) async => {
  'ed25519Seed': base64.encode(derive('$name ed25519 seed')),
  'mlDsa65Seed': base64.encode(derive('$name ml-dsa-65 seed')),
  'ed25519Public': base64.encode(key.ed25519Public),
  'mlDsa65Public': base64.encode(key.mlDsaPublic),
  'keyId': key.keyId,
};

Future<ApproverKey> _key(String name) => ApproverKey.fromSeeds(
  derive('$name ed25519 seed'),
  derive('$name ml-dsa-65 seed'),
);

RecordedKey _recorded(ApproverKey k) =>
    (ed25519: k.ed25519Public, mlDsa65: k.mlDsaPublic);

Future<Map<String, Object?>> signatureVectors() async {
  final approver = await _key('approver mbp');
  final rotated = await _key('approver mbp rotated');
  final stranger = await _key('approver unpaired');
  final recorded = {approver.keyId: _recorded(approver)};

  Future<Map<String, Object?>> signed(
    String label,
    Map<String, Object?> object,
    List<ApproverKey> keys,
  ) async {
    final bytes = signedBytes(label, object);
    final signatures = <Map<String, String>>[];
    for (final k in keys) {
      signatures.addAll(await k.signDeterministic(label, bytes));
    }
    return {...object, 'signatures': signatures};
  }

  final grant = await signed(
    Labels.grant,
    {
      'id': 'g-0001',
      'host': 'bigbeast',
      'subject': 'script /usr/bin/bash /home/demo/deploy.sh',
      'secret': '[env:prod]db.main',
      'decision': 'allow',
      'created': '2026-11-13T09:00:00Z',
      'pin': 'hash',
      'approver': 'mbp',
    },
    [approver],
  );
  final grantRelaxed = await signed(
    Labels.grant,
    {
      'id': 'g-0002',
      'host': 'bigbeast',
      'subject': 'folder /home/demo/Code /usr/bin/python3',
      'secret': 'store fleet',
      'decision': 'allow',
      'created': '2026-11-13T09:05:00Z',
      'pin': {'relaxedUntil': '2026-11-20T00:00:00Z'},
      'approver': 'mbp',
    },
    [approver],
  );
  final revocation = await signed(
    Labels.revoke,
    {
      'host': 'bigbeast',
      'grantId': 'g-0001',
      'revoked': '2026-11-14T10:00:00Z',
      'approver': 'mbp',
    },
    [approver],
  );
  final approval = await signed(
    Labels.approval,
    {
      'host': 'bigbeast',
      // The approval code of request a-17 (approval_codes.json, first case).
      'code': 'VFGQMBJBCG',
      'decision': 'once',
      'approver': 'mbp',
      'created': '2026-11-13T09:01:00Z',
    },
    [approver],
  );
  final keyChange = await signed(
    Labels.keyChange,
    {
      'device': 'mbp',
      'oldKeyId': approver.keyId,
      'newKeyId': rotated.keyId,
      'newEd25519': base64.encode(rotated.ed25519Public),
      'newMlDsa65': base64.encode(rotated.mlDsaPublic),
      'time': '2027-11-13T09:00:00Z',
    },
    [approver, rotated],
  );

  final accepted = <Map<String, Object?>>[];
  Future<void> accept(
    String name,
    String label,
    Map<String, Object?> object,
  ) async {
    final ok = label == Labels.keyChange
        ? await acceptsKeyChange(object, _recorded(approver))
        : await accepts(label, object, recorded);
    _expect(ok, '$name is accepted');
    accepted.add({
      'name': name,
      'label': label,
      'object': object,
      'signedBytesHex': hex(signedBytes(label, object)),
    });
  }

  await accept('grant', Labels.grant, grant);
  await accept('grant with a relaxed pin', Labels.grant, grantRelaxed);
  await accept('revocation', Labels.revoke, revocation);
  await accept(
    'approval record (the vault path of an approval code)',
    Labels.approval,
    approval,
  );
  await accept(
    'key-change statement, four signatures',
    Labels.keyChange,
    keyChange,
  );

  final rejected = <Map<String, Object?>>[];
  Future<void> reject(
    String name,
    String label,
    Map<String, Object?> object,
  ) async {
    final ok = label == Labels.keyChange
        ? await acceptsKeyChange(object, _recorded(approver))
        : await accepts(label, object, recorded);
    _expect(!ok, '$name is rejected');
    rejected.add({'name': name, 'label': label, 'object': object});
  }

  List<Map<String, Object?>> sigs(Map<String, Object?> o) =>
      (o['signatures'] as List).cast<Map<String, Object?>>();

  await reject('a signed member changed', Labels.grant, {
    ...grant,
    'secret': 'all',
  });
  await reject('only the Ed25519 signature', Labels.grant, {
    ...grant,
    'signatures': sigs(grant).where((s) => s['alg'] == 'ed25519').toList(),
  });
  await reject('only the ML-DSA-65 signature', Labels.grant, {
    ...grant,
    'signatures': sigs(grant).where((s) => s['alg'] == 'ml-dsa-65').toList(),
  });
  await reject(
    'signed by a key the host did not record',
    Labels.grant,
    await signed(
      Labels.grant,
      {
        for (final name in signedFields[Labels.grant]!) name: grant[name],
        'approver': 'unpaired',
      },
      [stranger],
    ),
  );
  await reject('a grant signature presented as a revocation', Labels.revoke, {
    'host': 'bigbeast',
    'grantId': 'g-0001',
    'revoked': '2026-11-13T09:00:00Z',
    'approver': 'mbp',
    'signatures': sigs(grant),
  });
  final mixed = await signed(
    Labels.grant,
    {
      for (final name in signedFields[Labels.grant]!) name: grant[name],
      'id': 'g-0003',
    },
    [approver],
  );
  await reject('Ed25519 of one object, ML-DSA-65 of another', Labels.grant, {
    ...grant,
    'signatures': [
      sigs(grant).firstWhere((s) => s['alg'] == 'ed25519'),
      sigs(mixed).firstWhere((s) => s['alg'] == 'ml-dsa-65'),
    ],
  });
  await reject('key change signed by the old key only', Labels.keyChange, {
    ...keyChange,
    'signatures': sigs(
      keyChange,
    ).where((s) => s['keyId'] == approver.keyId).toList(),
  });
  await reject(
    'key change whose newKeyId is not its keys\' id',
    Labels.keyChange,
    {...keyChange, 'newKeyId': stranger.keyId},
  );

  approver.mlDsa.dispose();
  rotated.mlDsa.dispose();
  stranger.mlDsa.dispose();
  return {
    'note':
        'Signed objects of section 9.4. Keys from seeds derived from labels; '
        'ML-DSA-65 in its deterministic mode (rnd all zero, the domain label '
        'as context), which an implementation verifies like a hedged '
        'signature. Every accepted object verifies under the recorded key '
        '`approver`; every rejected one does not. signedBytesHex is the '
        'length-prefixed encoding of 9.1.',
    'recorded': [approver.keyId],
    'keys': {
      'approver': await _keyJson('approver mbp', approver),
      'approverRotated': await _keyJson('approver mbp rotated', rotated),
      'unpaired': await _keyJson('approver unpaired', stranger),
    },
    'accepted': accepted,
    'rejected': rejected,
  };
}

/// The approval link's vectors; its transport carries the signed objects of
/// [signatures] (the result of [signatureVectors]).
Future<Map<String, Object?>> linkVectors(
  Map<String, Object?> signatures,
) async {
  Map<String, Object?> signedObject(String name) =>
      ((signatures['accepted'] as List).cast<Map<String, Object?>>().firstWhere(
            (c) => c['name'] == name,
          )['object']
          as Map<String, Object?>);
  final approverKey = await LinkKey.fromSeeds(
    derive('link approver x25519'),
    derive('link approver ml-kem', 64),
  );
  final hostKey = await LinkKey.fromSeeds(
    derive('link host x25519'),
    derive('link host ml-kem', 64),
  );
  final approverPublic = (
    x25519: approverKey.x25519Public,
    mlKem: approverKey.mlKemPublic,
  );
  final hostPublic = (x25519: hostKey.x25519Public, mlKem: hostKey.mlKemPublic);
  final iRandom = (
    ephemeralX25519Seed: derive('link approver ephemeral x25519'),
    ephemeralMlKemSeed: derive('link approver ephemeral ml-kem', 64),
    coinsToResponderStatic: derive('link coins to host static'),
  );
  final rRandom = (
    ephemeralX25519Seed: derive('link host ephemeral x25519'),
    coinsToInitiatorEphemeral: derive('link coins to approver ephemeral'),
    coinsToInitiatorStatic: derive('link coins to approver static'),
  );
  final payload1 = {'protocol': 1, 'device': 'mbp'};
  final payload2 = {'protocol': 1, 'host': 'bigbeast'};

  final initiator = Initiator(approverKey, approverPublic, hostPublic, iRandom);
  final responder = Responder(hostKey, hostPublic, approverPublic, rRandom);
  final m1 = await initiator.writeMessage1(utf8.encode(jsonEncode(payload1)));
  final read1 = await responder.readMessage1(m1);
  _expect(utf8.decode(read1) == jsonEncode(payload1), 'payload 1 round trip');
  final hAfter1 = hex(responder.state.h);
  final (m2, hostSession) = await responder.writeMessage2(
    utf8.encode(jsonEncode(payload2)),
  );
  final (read2, approverSession) = await initiator.readMessage2(m2);
  _expect(utf8.decode(read2) == jsonEncode(payload2), 'payload 2 round trip');
  _expect(
    hex(hostSession.initiatorToResponder) ==
            hex(approverSession.initiatorToResponder) &&
        hex(hostSession.responderToInitiator) ==
            hex(approverSession.responderToInitiator) &&
        hex(hostSession.handshakeHash) == hex(approverSession.handshakeHash),
    'both sides derive the same session',
  );

  // Transport: approver -> host is initiatorToResponder.
  final aSend = TransportCipher(approverSession.initiatorToResponder);
  final hRecv = TransportCipher(hostSession.initiatorToResponder);
  final hSend = TransportCipher(hostSession.responderToInitiator);
  final aRecv = TransportCipher(approverSession.responderToInitiator);
  final frames = <Map<String, Object?>>[];
  Future<void> send(String from, Map<String, Object?> message) async {
    final sender = from == 'approver' ? aSend : hSend;
    final receiver = from == 'approver' ? hRecv : aRecv;
    final n = sender.n;
    final plaintext = utf8.encode(jsonEncode(message));
    final c = await sender.encrypt(plaintext);
    final back = await receiver.decrypt(c);
    _expect(
      utf8.decode(back) == jsonEncode(message),
      'transport frame round trip',
    );
    frames.add({
      'from': from,
      'n': n,
      'json': message,
      'plaintext': jsonEncode(message),
      'ciphertextHex': hex(c),
      'frameHex': hex(channelFrame(c)),
    });
    if (message['op'] == 'rekey') {
      await sender.rekeyNow();
      await receiver.rekeyNow();
      frames.last['keyAfterRekeyHex'] = hex(sender.key);
    }
  }

  await send('approver', {'op': 'ready'});
  await send('host', {
    'op': 'approval_needed',
    'approvalId': 'a-18',
    'host': 'bigbeast',
    'identity': {
      'kind': 'exe',
      'exe': '/usr/local/bin/backup',
      'args': ['backup', '--nightly'],
      'cwd': '/srv',
      'uid': 1000,
    },
    'refs': ['store-key.backup'],
    'resolved': [
      {'store': 'fleet', 'path': 'Backup/Key', 'kind': 'api-token'},
    ],
  });
  await send('approver', {
    'op': 'approve',
    'id': 1,
    'approvalId': 'a-18',
    'decision': 'once',
    'secret': 'ref',
  });
  await send('host', {'op': 'ok', 'id': 1});
  await send('host', {
    'op': 'approval_closed',
    'approvalId': 'a-18',
    'outcome': 'approved',
  });
  await send('approver', {
    'op': 'grant',
    'id': 2,
    'grant': signedObject('grant'),
  });
  await send('host', {'op': 'ok', 'id': 2});
  await send('approver', {
    'op': 'revoke',
    'id': 3,
    ...signedObject('revocation'),
  });
  await send('host', {'op': 'ok', 'id': 3});
  await send('approver', {'op': 'rekey'});
  await send('approver', {
    'op': 'keychange',
    'id': 4,
    'statement': signedObject('key-change statement, four signatures'),
  });
  await send('host', {'op': 'ok', 'id': 4});
  await send('host', {'op': 'rekey'});
  await send('approver', {
    'op': 'linkKey',
    'id': 5,
    'device': 'mbp',
    'x25519': base64.encode(derive('link approver new x25519 public')),
    'mlKem768': base64.encode(derive('link approver new ml-kem public', 1184)),
  });
  await send('host', {'op': 'ok', 'id': 5});

  // Failures the responder must detect.
  final failures = <Map<String, Object?>>[];
  Future<void> mustFail(String name, Future<void> Function() action) async {
    try {
      await action();
    } on LinkHandshakeError catch (e) {
      failures.add({'name': name, 'error': e.message});
      return;
    }
    throw StateError('vector expectation failed: $name did not fail');
  }

  Future<Responder> freshResponder(LinkPublic expectedInitiator) async =>
      Responder(hostKey, hostPublic, expectedInitiator, rRandom);
  final altered = Uint8List.fromList(m1)..[m1.length - 1] ^= 1;
  await mustFail('message 1 with its last byte altered', () async {
    await (await freshResponder(approverPublic)).readMessage1(altered);
  });
  final alteredKem = Uint8List.fromList(m1)..[32 + 1184 + 10] ^= 1;
  await mustFail('message 1 with its ML-KEM ciphertext altered', () async {
    await (await freshResponder(approverPublic)).readMessage1(alteredKem);
  });
  final stranger = await LinkKey.fromSeeds(
    derive('link stranger x25519'),
    derive('link stranger ml-kem', 64),
  );
  await mustFail(
    'message 1 from an approver whose keys the host did not record',
    () async {
      final unknown = Initiator(
        stranger,
        (x25519: stranger.x25519Public, mlKem: stranger.mlKemPublic),
        hostPublic,
        iRandom,
      );
      final m = await unknown.writeMessage1(utf8.encode(jsonEncode(payload1)));
      await (await freshResponder(approverPublic)).readMessage1(m);
    },
  );
  await mustFail('message 1 truncated', () async {
    await (await freshResponder(
      approverPublic,
    )).readMessage1(m1.sublist(0, 2000));
  });
  await mustFail('a transport frame replayed', () async {
    final r = TransportCipher(hostSession.initiatorToResponder);
    final first = hex2bytes(frames.first['ciphertextHex'] as String);
    await r.decrypt(first);
    await r.decrypt(first);
  });

  approverKey.mlKem.dispose();
  hostKey.mlKem.dispose();
  stranger.mlKem.dispose();
  return {
    'note':
        'The approval link of section 9.7 from fixed keys and fixed '
        'randomness: the approver (initiator) and the host (responder), '
        'both handshake messages, the handshake hash after message 1 and at '
        'the end, the transport keys, transport frames with a rekey, and '
        'failures the receiver must detect.',
    'protocolName': linkProtocolName,
    'approver': {
      'x25519Seed': base64.encode(derive('link approver x25519')),
      'mlKem768Seed': base64.encode(derive('link approver ml-kem', 64)),
      'x25519Public': base64.encode(approverKey.x25519Public),
      'mlKem768Public': base64.encode(approverKey.mlKemPublic),
    },
    'host': {
      'x25519Seed': base64.encode(derive('link host x25519')),
      'mlKem768Seed': base64.encode(derive('link host ml-kem', 64)),
      'x25519Public': base64.encode(hostKey.x25519Public),
      'mlKem768Public': base64.encode(hostKey.mlKemPublic),
    },
    'approverRandom': {
      'ephemeralX25519Seed': base64.encode(iRandom.ephemeralX25519Seed),
      'ephemeralMlKem768Seed': base64.encode(iRandom.ephemeralMlKemSeed),
      'coinsToHostStatic': base64.encode(iRandom.coinsToResponderStatic),
    },
    'hostRandom': {
      'ephemeralX25519Seed': base64.encode(rRandom.ephemeralX25519Seed),
      'coinsToApproverEphemeral': base64.encode(
        rRandom.coinsToInitiatorEphemeral,
      ),
      'coinsToApproverStatic': base64.encode(rRandom.coinsToInitiatorStatic),
    },
    'payload1': payload1,
    'payload1Text': jsonEncode(payload1),
    'payload2': payload2,
    'payload2Text': jsonEncode(payload2),
    'message1Hex': hex(m1),
    'message1FrameHex': hex(channelFrame(m1)),
    'handshakeHashAfterMessage1': hAfter1,
    'message2Hex': hex(m2),
    'message2FrameHex': hex(channelFrame(m2)),
    'handshakeHash': hex(hostSession.handshakeHash),
    'approverToHostKey': hex(hostSession.initiatorToResponder),
    'hostToApproverKey': hex(hostSession.responderToInitiator),
    'transport': frames,
    'failures': failures,
  };
}

Uint8List hex2bytes(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);
