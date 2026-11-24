// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The admin client against a small admin endpoint in the test (TCP, as on
// Windows): it offers chunked members and sends a large request in chunks
// when the service offers them, whole when it does not; it reads a chunked
// answer back as one; and once the connection has ended, a request fails at
// once instead of waiting. Demo keys only.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

/// An admin endpoint that authenticates [adminKey] and hands every request
/// after that to [onRequest]; [features] are offered in the challenge.
final class _Endpoint {
  _Endpoint(this.server, this.runtime);

  final ServerSocket server;
  final TomSecretsRuntime runtime;
  final List<Map<String, Object?>> requests = [];
  Map<String, Object?>? auth;
  final List<int> frameSizes = [];
  Socket? peer;

  static Future<_Endpoint> start(
    Directory dir,
    Uint8List adminKey, {
    List<String> features = const [tomSecretsChunkedFeature],
    required void Function(_Endpoint e, Socket s, Map<String, Object?> m)
    onRequest,
  }) async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final runtime = TomSecretsRuntime(
      dir.path,
      transport: TomSecretsTransport.tcp,
    );
    await runtime.writePort(runtime.adminPortFile, server.port);
    final e = _Endpoint(server, runtime);
    server.listen((socket) {
      e.peer = socket;
      const start = 1700000000000;
      final serviceNonce = Uint8List(32);
      final reader = TomSecretsFrameReader(
        maxPayload: tomSecretsMaxRequestPayload,
      )..binaryAllowed = true;
      final chunks = TomSecretsChunkAssembler();
      socket.add(
        tomSecretsJsonFrame({
          'op': 'challenge',
          'serviceNonce': base64.encode(serviceNonce),
          'serviceStart': start,
          'protocol': 1,
          'features': features,
        }),
      );
      socket.listen((bytes) {
        for (final frame in reader.add(bytes)) {
          e.frameSizes.add(frame.payload.length);
          Map<String, Object?>? m;
          if (frame.type == tomSecretsFrameBinary) {
            m = chunks.add(frame.payload);
          } else {
            m = tomSecretsDecodePayload(frame.payload);
            if (TomSecretsChunkAssembler.isChunked(m)) m = chunks.begin(m);
          }
          if (m == null) continue;
          if (m['op'] == 'auth') {
            e.auth = m;
            socket.add(
              tomSecretsJsonFrame({
                'op': 'authed',
                'mac2': base64.encode(
                  tomSecretsChallengeMac(
                    adminKey,
                    tomSecretsServiceLabel,
                    serviceNonce,
                    base64.decode(m['adminNonce']! as String),
                    start,
                  ),
                ),
              }),
            );
          } else {
            e.requests.add(m);
            onRequest(e, socket, m);
          }
        }
      });
    });
    return e;
  }
}

void main() {
  late Directory dir;
  final adminKey = Uint8List.fromList(List.generate(32, (i) => i));
  final file = base64.encode(List.generate(2 * 1024 * 1024, (i) => i % 253));

  setUp(() {
    dir = Directory.systemTemp.createTempSync('tsmadm');
    addTearDown(() => dir.deleteSync(recursive: true));
  });

  test(
    'a large save goes in chunks, a large answer comes back whole',
    () async {
      final e = await _Endpoint.start(
        dir,
        adminKey,
        onRequest: (e, socket, m) {
          final answer = m['op'] == 'save'
              ? {
                  'op': 'ok',
                  'id': m['id'],
                  'size': (m['bytes']! as String).length,
                }
              : {'op': 'vaultFileData', 'id': m['id'], 'bytes': file};
          for (final f in tomSecretsChunkedFrames(
            answer,
            limit: tomSecretsMaxAnswerPayload,
          )) {
            socket.add(f);
          }
        },
      );
      addTearDown(e.server.close);
      final admin = await TomSecretsAdminClient.connect(e.runtime, adminKey);
      addTearDown(admin.close);
      expect(e.auth!['features'], contains(tomSecretsChunkedFeature));
      expect(admin.sendsChunked, isTrue);

      final saved = await admin.request('save', {
        'store': 'primary',
        'bytes': file,
      });
      expect(saved['size'], file.length);
      expect(e.requests.single['bytes'], file);
      expect(
        e.frameSizes.every((s) => s <= tomSecretsMaxRequestPayload),
        isTrue,
      );

      final read = await admin.request('vaultFile', {'store': 'primary'});
      expect(read['bytes'], file);
    },
  );

  test('a service without the feature is sent whole messages', () async {
    final e = await _Endpoint.start(
      dir,
      adminKey,
      features: const [],
      onRequest: (e, socket, m) =>
          socket.add(tomSecretsJsonFrame({'op': 'ok', 'id': m['id']})),
    );
    addTearDown(e.server.close);
    final admin = await TomSecretsAdminClient.connect(e.runtime, adminKey);
    addTearDown(admin.close);
    expect(admin.sendsChunked, isFalse);
    await admin.request('status');
    expect(e.requests.single.containsKey('chunked'), isFalse);
  });

  test('after the connection ended, a request fails at once', () async {
    final e = await _Endpoint.start(
      dir,
      adminKey,
      onRequest: (e, socket, m) => socket.destroy(),
    );
    addTearDown(e.server.close);
    final admin = await TomSecretsAdminClient.connect(e.runtime, adminKey);
    await expectLater(
      admin.request('save', {'store': 'primary', 'bytes': 'AAAA'}),
      throwsA(
        isA<TomSecretsAdminException>().having((x) => x.kind, 'kind', 'closed'),
      ),
    );
    // The next request: refused at once, not left waiting.
    await expectLater(
      admin.request('vaultKeys').timeout(const Duration(seconds: 2)),
      throwsA(
        isA<TomSecretsAdminException>().having((x) => x.kind, 'kind', 'closed'),
      ),
    );
  });
}
