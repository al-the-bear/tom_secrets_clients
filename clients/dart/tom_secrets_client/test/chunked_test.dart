// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Chunked members (protocol.md 2.7): a message within its limit goes whole;
// a larger one goes as the JSON naming its large members, then binary frames
// within the limit, and the assembler puts it back as it was; a chunk of no
// message, more bytes than announced and a member that does not match its
// SHA-256 are refused. Demo data only.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

/// The frames of [frames] read back as one stream.
List<TomSecretsFrame> _read(List<Uint8List> frames, int limit) {
  final reader = TomSecretsFrameReader(maxPayload: limit)..binaryAllowed = true;
  return [for (final f in frames) ...reader.add(f)];
}

void main() {
  const limit = 64 * 1024;

  test('a message within the limit goes whole', () {
    final frames = tomSecretsChunkedFrames({
      'op': 'save',
      'id': 1,
      'bytes': 'AAAA',
    }, limit: limit);
    expect(frames, hasLength(1));
    expect(frames.single[4], tomSecretsFrameJson);
  });

  test('a larger one: its large members as chunks within the limit, put '
      'back by the assembler as they were', () {
    final file = base64.encode(List.generate(300 * 1024, (i) => i % 251));
    final note = 'ü' * 5000; // not ASCII: the sizes are UTF-8 bytes
    final message = {
      'op': 'save',
      'id': 42,
      'store': 'primary',
      'bytes': file,
      'recipients': note,
      'baseRevision': 'abc',
    };
    final frames = tomSecretsChunkedFrames(message, limit: limit);
    expect(frames.length, greaterThan(2));
    final read = _read(frames, limit);
    expect(read.first.type, tomSecretsFrameJson);
    final head = tomSecretsDecodePayload(read.first.payload);
    expect(head.containsKey('bytes'), isFalse);
    expect(
      [for (final m in head['chunked']! as List) (m as Map)['name']],
      ['bytes', 'recipients'],
    );
    expect(read.skip(1).every((f) => f.type == tomSecretsFrameBinary), isTrue);
    expect(read.every((f) => f.payload.length <= limit), isTrue);

    final assembler = TomSecretsChunkAssembler();
    expect(TomSecretsChunkAssembler.isChunked(head), isTrue);
    expect(assembler.begin(head), isNull);
    Map<String, Object?>? whole;
    for (final f in read.skip(1)) {
      whole = assembler.add(f.payload);
    }
    expect(whole, message);
  });

  test('refused: a chunk of no message, more bytes than announced, a '
      'member that does not match', () {
    final assembler = TomSecretsChunkAssembler();
    final stray = Uint8List(12);
    ByteData.sublistView(stray).setUint64(0, 9);
    expect(
      () => assembler.add(stray),
      throwsA(isA<TomSecretsFrameException>()),
    );

    Map<String, Object?> head(String sha) => {
      'op': 'save',
      'id': 7,
      'chunked': [
        {'name': 'bytes', 'size': 4, 'sha256': sha},
      ],
    };
    Uint8List chunk(List<int> bytes) {
      final p = Uint8List(8 + bytes.length);
      ByteData.sublistView(p).setUint64(0, 7);
      p.setRange(8, p.length, bytes);
      return p;
    }

    assembler.begin(head('0' * 64));
    expect(
      () => assembler.add(chunk(utf8.encode('ABCDE'))),
      throwsA(isA<TomSecretsFrameException>()),
    );
    final other = TomSecretsChunkAssembler()..begin(head('0' * 64));
    expect(
      () => other.add(chunk(utf8.encode('ABCD'))),
      throwsA(isA<TomSecretsFrameException>()),
    );
    expect(
      () => TomSecretsChunkAssembler().begin({
        'op': 'save',
        'id': 1,
        'chunked': [
          {
            'name': 'bytes',
            'size': tomSecretsMaxChunkedBytes + 1,
            'sha256': '',
          },
        ],
      }),
      throwsA(isA<TomSecretsFrameException>()),
    );
  });

  test('the frame reader: a frame arriving in many small reads, frames '
      'split across reads and several frames in one read come out the '
      'same; an oversized length is refused as soon as its header is in', () {
    final random = Random(7);
    Uint8List payload(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    final payloads = [
      payload(tomSecretsMaxAnswerPayload),
      payload(0),
      payload(3),
      payload(70000),
      payload(1),
    ];
    final stream = BytesBuilder();
    for (final p in payloads) {
      stream.add(tomSecretsEncodeFrame(tomSecretsFrameBinary, p));
    }
    final bytes = stream.takeBytes();
    for (final step in [1 << 13, 4099, bytes.length, 7]) {
      // Reads of one byte over the megabyte would take too long here.
      if (step == 7 && bytes.length > 200000) continue;
      final reader = TomSecretsFrameReader(
        maxPayload: tomSecretsMaxAnswerPayload,
      )..binaryAllowed = true;
      final got = <TomSecretsFrame>[];
      for (var at = 0; at < bytes.length; at += step) {
        got.addAll(
          reader.add(
            Uint8List.sublistView(
              bytes,
              at,
              at + step < bytes.length ? at + step : bytes.length,
            ),
          ),
        );
      }
      expect(got, hasLength(payloads.length), reason: 'step $step');
      for (var i = 0; i < payloads.length; i++) {
        expect(got[i].type, tomSecretsFrameBinary);
        expect(got[i].payload, payloads[i], reason: 'step $step, frame $i');
      }
    }
    final small = TomSecretsFrameReader(maxPayload: 16);
    final frames = small.add([
      ...tomSecretsEncodeFrame(tomSecretsFrameJson, Uint8List(16)),
      0,
      0,
      0,
    ]);
    expect(frames, hasLength(1));
    expect(
      // The rest of the second frame's header says 17 bytes.
      () => small.add([17, 0]),
      throwsA(isA<TomSecretsFrameException>()),
      reason: 'a length of 17 over 16, refused before its payload',
    );
  });
}
