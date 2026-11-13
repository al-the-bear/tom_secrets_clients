// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The library against every vector of protocol/vectors/ that a client
/// computes: references (parse, canonical form, malformed reasons,
/// formatting), discovery and port files, and the frames of the client
/// endpoint.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

Map<String, Object?> _vectors(String name) =>
    jsonDecode(File('../../../protocol/vectors/$name').readAsStringSync())
        as Map<String, Object?>;

Uint8List _hex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

String _toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// A parse result in the vectors' JSON shape.
Map<String, Object?> _shape(TomSecretReference r) => {
  'qualifiers': [
    for (final q in r.qualifiers) {'dimension': q.dimension, 'value': q.value},
  ],
  'target': switch (r.target) {
    TomSecretKeyTarget(:final key) => {'kind': 'key', 'key': key},
    TomSecretPathTarget(:final store, :final segments) => {
      'kind': 'path',
      'store': store,
      'segments': segments,
    },
    TomSecretUuidTarget(:final store, :final uuid) => {
      'kind': 'uuid',
      'store': store,
      'uuid': uuid,
    },
  },
  'field': r.field,
  'fieldGiven': r.fieldGiven,
};

TomSecretReference _fromShape(Map<String, Object?> m) {
  final t = (m['target']! as Map).cast<String, Object?>();
  return TomSecretReference(
    qualifiers: [
      for (final q in (m['qualifiers']! as List).cast<Map<String, Object?>>())
        TomSecretBinding(q['dimension']! as String, q['value']! as String),
    ],
    target: switch (t['kind']) {
      'key' => TomSecretKeyTarget(t['key']! as String),
      'uuid' => TomSecretUuidTarget(
        t['store']! as String,
        t['uuid']! as String,
      ),
      _ => TomSecretPathTarget(
        t['store']! as String,
        (t['segments']! as List).cast<String>(),
      ),
    },
    field: m['field'] as String? ?? tomSecretsDefaultField,
  );
}

void main() {
  group('references.json', () {
    final v = _vectors('references.json');

    test('the reference limit', () {
      expect(v['maxReferenceBytes'], tomSecretsMaxReferenceBytes);
    });

    for (final c in (v['valid']! as List).cast<Map<String, Object?>>()) {
      final input = c['input']! as String;
      final label = input.length > 40 ? '${input.substring(0, 40)}…' : input;
      test('parses ${jsonEncode(label)}', () {
        final parsed = TomSecretReference.parse(c['input']! as String);
        expect(_shape(parsed), c['parsed']);
        expect(parsed.canonical, c['canonical']);
        expect(
          TomSecretReference.parse(parsed.canonical).canonical,
          parsed.canonical,
        );
      });
    }

    for (final c in (v['invalid']! as List).cast<Map<String, Object?>>()) {
      final input = c['input']! as String;
      final label = input.length > 40 ? '${input.substring(0, 40)}…' : input;
      test('refuses ${jsonEncode(label)} as ${c['reason']}', () {
        expect(
          () => TomSecretReference.parse(input),
          throwsA(
            isA<TomSecretsClientException>()
                .having((e) => e.kind, 'kind', TomSecretsErrorKind.malformed)
                .having((e) => e.reason, 'reason', c['reason']),
          ),
        );
      });
    }

    for (final c in (v['format']! as List).cast<Map<String, Object?>>()) {
      test('formats to ${c['formatted']}', () {
        final reference = _fromShape(
          (c['parsed']! as Map).cast<String, Object?>(),
        );
        expect(TomSecretReference.format(reference), c['formatted']);
        expect(
          _shape(TomSecretReference.parse(c['formatted']! as String)),
          c['reparsed'],
        );
      });
    }
  });

  group('discovery.json', () {
    final v = _vectors('discovery.json');
    for (final c in (v['cases']! as List).cast<Map<String, Object?>>()) {
      test('${c['os']} ${jsonEncode(c['env'])}', () {
        final location = discoverTomSecrets(
          operatingSystem: c['os']! as String,
          environment: (c['env']! as Map).cast<String, String>(),
          uid: () => c['uid'] as int?,
        );
        final expect_ = c['expect']! as Map<String, Object?>;
        switch (location) {
          case TomSecretsNoRuntimeDirectory(:final reason):
            expect({'notRunning': reason}, expect_);
          case TomSecretsEndpoints e:
            expect(e.directory, expect_['directory']);
            final client = (expect_['client']! as Map).cast<String, Object?>();
            final admin = (expect_['admin']! as Map).cast<String, Object?>();
            expect(e.clientSocket, client['socket']);
            expect(e.clientPortFile, client['portFile']);
            expect(e.clientTokenFile, client['tokenFile']);
            expect(e.adminSocket, admin['socket']);
            expect(e.adminPortFile, admin['portFile']);
        }
      });
    }
    for (final c in (v['portFiles']! as List).cast<Map<String, Object?>>()) {
      test('port file ${jsonEncode(c['text'])}', () {
        expect(readTomSecretsPortFile(c['text']! as String), c['port']);
      });
    }
  });

  group('frames.json', () {
    final v = _vectors('frames.json');
    final frames = (v['frames']! as List).cast<Map<String, Object?>>();

    test('the protocol version', () {
      expect(v['protocol'], tomSecretsProtocol);
    });

    for (final c in frames.where((f) => f['type'] == tomSecretsFrameJson)) {
      test('JSON frame: ${c['name']}', () {
        final bytes = _hex(c['hex']! as String);
        final reader = TomSecretsFrameReader(
          maxPayload: tomSecretsMaxAnswerPayload,
        );
        final read = reader.add(bytes);
        expect(read, hasLength(1));
        expect(tomSecretsDecodePayload(read.single.payload), c['json']);
        expect(
          _toHex(tomSecretsJsonFrame(c['json']! as Map<String, Object?>)),
          c['hex'],
        );
      });
    }

    for (final c in frames.where((f) => f['type'] == tomSecretsFrameBinary)) {
      test('binary frame: ${c['name']}', () {
        final reader = TomSecretsFrameReader(
          maxPayload: tomSecretsMaxAnswerPayload,
        );
        expect(
          () => reader.add(_hex(c['hex']! as String)),
          throwsA(isA<TomSecretsFrameException>()),
          reason: 'binary frames only once negotiated',
        );
        final negotiated = TomSecretsFrameReader(
          maxPayload: tomSecretsMaxAnswerPayload,
        )..binaryAllowed = true;
        final payload = negotiated
            .add(_hex(c['hex']! as String))
            .single
            .payload;
        expect(ByteData.sublistView(payload).getUint64(0), c['requestId']);
        expect(_toHex(payload.sublist(8)), c['chunkHex']);
      });
    }

    test('a frame split across reads is put together', () {
      final bytes = _hex(frames.first['hex']! as String);
      final reader = TomSecretsFrameReader(
        maxPayload: tomSecretsMaxRequestPayload,
      );
      expect(reader.add(bytes.sublist(0, 3)), isEmpty);
      expect(reader.add(bytes.sublist(3, 20)), isEmpty);
      expect(reader.add([...bytes.sublist(20), ...bytes]), hasLength(2));
    });

    for (final c in (v['invalid']! as List).cast<Map<String, Object?>>()) {
      test('invalid: ${c['name']}', () {
        final bytes = _hex(c['hex']! as String);
        final limit = c['direction'] == 'to service'
            ? tomSecretsMaxRequestPayload
            : tomSecretsMaxAnswerPayload;
        final reader = TomSecretsFrameReader(maxPayload: limit);
        switch (c['outcome']) {
          case 'close':
            expect(
              () => reader.add(bytes),
              throwsA(isA<TomSecretsFrameException>()),
            );
          case 'read':
            // The length passes; the payload is still to come.
            expect(reader.add(bytes), isEmpty);
          case 'malformed_close':
            final read = reader.add(bytes);
            final payload = read.single.payload;
            final firstFrameRule =
                c['name'] == 'a first frame that is not hello';
            if (firstFrameRule) {
              // Well-formed JSON; it is the order of frames that is wrong,
              // which the service checks (a client's first frame is hello).
              expect(tomSecretsDecodePayload(payload)['op'], 'get');
            } else {
              expect(
                () => tomSecretsDecodePayload(payload),
                throwsA(isA<TomSecretsFrameException>()),
              );
            }
          default:
            fail('unknown outcome ${c['outcome']}');
        }
      });
    }
  });

  test('the version sent in hello is the pubspec version', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final version = RegExp(
      r'^version: (\S+)$',
      multiLine: true,
    ).firstMatch(pubspec)!.group(1);
    expect(tomSecretsClientVersion, version);
  });
}
