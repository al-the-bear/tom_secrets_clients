// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The client against a scripted fake service over a real socket.
///
/// The runtime directory is `ztmp/test/client` under the package, named
/// relative to it (`TSM_RUNTIME_DIR=ztmp/test/client`): a Unix socket path
/// may not be longer than about 100 bytes, and the package's absolute path
/// is longer.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'support/fake_service.dart';

const _runtime = 'ztmp/test/client';
final Directory _root = Directory(_runtime);
const _env = {'TSM_RUNTIME_DIR': _runtime};

Matcher _fails(TomSecretsErrorKind kind, {String? reason}) => throwsA(
  isA<TomSecretsClientException>()
      .having((e) => e.kind, 'kind', kind)
      .having((e) => e.reason, 'reason', reason ?? anything),
);

void main() {
  setUpAll(() {
    if (_root.existsSync()) _root.deleteSync(recursive: true);
    _root.createSync(recursive: true);
  });

  tearDownAll(() => _root.deleteSync(recursive: true));

  late FakeService service;
  late TomSecretsClient client;

  Future<void> startWith(FakeHandler handler) async {
    // Windows has no Unix sockets: there the service is a localhost port.
    service = await FakeService.start(
      _root,
      onRequest: handler,
      windows: Platform.isWindows,
    );
    client = TomSecretsClient(clientName: 'deploy.sh', environment: _env);
  }

  tearDown(() async {
    await client.close();
    await service.stop();
  });

  group('connecting', () {
    test('hello names the client, the library and the features', () async {
      await startWith((_, _) {});
      await client.open();
      expect(service.hellos.single, {
        'op': 'hello',
        'protocol': 1,
        'client': {
          'name': 'deploy.sh',
          'version': tomSecretsClientVersion,
          'language': 'dart',
        },
        // Windows: the text of client.token, re-read at this connect.
        if (Platform.isWindows)
          'token': 'dG9rZW4tb2YtdGhpcy1zZXJ2aWNlLXN0YXJ0LTAwMDA=',
        'features': ['binary', 'getFile'],
      });
      expect(client.welcome!.host, 'bomber');
      expect(client.welcome!.platform, 'linux');
    });

    test('a client token the caller gives is sent in hello', () async {
      await startWith((_, _) {});
      await client.close();
      client = TomSecretsClient(
        environment: _env,
        clientToken: 'Y2xpZW50LXRva2VuLWRlbW8tMDAwMDAwMDAwMDAwMDA=',
      );
      await client.open();
      expect(
        service.hellos.single['clientToken'],
        'Y2xpZW50LXRva2VuLWRlbW8tMDAwMDAwMDAwMDAwMDA=',
      );
    });

    test('no socket is not_running', () async {
      await startWith((_, _) {});
      await service.stop();
      await expectLater(client.open(), _fails(TomSecretsErrorKind.notRunning));
    });

    test('no runtime directory on Windows is not_running', () async {
      await startWith((_, _) {});
      final windows = TomSecretsClient(
        environment: const {},
        operatingSystem: 'windows',
      );
      await expectLater(windows.open(), _fails(TomSecretsErrorKind.notRunning));
    });

    test('an unsupported protocol is unsupported, with the versions', () async {
      await startWith((_, _) {});
      service.onHello = (c, _) => c
        ..send({
          'op': 'error',
          'kind': 'unsupported',
          'message': 'protocol 1 is not spoken',
          'details': {
            'protocols': [2],
          },
        })
        ..close();
      await expectLater(
        client.open(),
        throwsA(
          isA<TomSecretsClientException>()
              .having((e) => e.kind, 'kind', TomSecretsErrorKind.unsupported)
              .having((e) => e.details['protocols'], 'protocols', [2]),
        ),
      );
    });

    test('a welcome of another protocol is unsupported', () async {
      await startWith((_, _) {});
      service.welcome = {...fakeWelcome(), 'protocol': 2};
      await expectLater(client.open(), _fails(TomSecretsErrorKind.unsupported));
    });

    test('after a restart the next call connects again', () async {
      await startWith((c, r) => c.send(fakeValue(r['id']! as int, 'v')));
      expect((await client.get('db.main')).text, 'v');
      service.dropConnections();
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect((await client.get('db.main')).text, 'v');
      expect(service.connections, 2);
    });

    test('a request open when the connection drops is not_running', () async {
      await startWith((c, _) => c.close());
      await expectLater(
        client.get('db.main'),
        _fails(TomSecretsErrorKind.notRunning),
      );
    });

    test(
      'Windows: a localhost port, the token re-read at every connect',
      () async {
        final dir = Directory('${_root.absolute.path}/win')..createSync();
        service = await FakeService.start(
          dir,
          windows: true,
          onRequest: (c, r) => c.send(fakeValue(r['id']! as int, 'w')),
        );
        client = TomSecretsClient(
          environment: {'TSM_RUNTIME_DIR': dir.path},
          operatingSystem: 'windows',
        );
        expect((await client.get('db.main')).text, 'w');
        expect(
          service.hellos.last['token'],
          'dG9rZW4tb2YtdGhpcy1zZXJ2aWNlLXN0YXJ0LTAwMDA=',
        );
        // A new service start: a new token.
        File(
          '${dir.path}\\client.token',
        ).writeAsStringSync('bmV3LXRva2VuLWFmdGVyLWEtcmVzdGFydC0wMDAwMDA=');
        service.dropConnections();
        await Future<void>.delayed(const Duration(milliseconds: 50));
        expect((await client.get('db.main')).text, 'w');
        expect(
          service.hellos.last['token'],
          'bmV3LXRva2VuLWFmdGVyLWEtcmVzdGFydC0wMDAwMDA=',
        );
      },
    );
  });

  group('get', () {
    test('a text value, its entry, bindings and version', () async {
      await startWith(
        (c, r) => c.send(
          fakeValue(
            r['id']! as int,
            'demo-password-1',
            extra: {'expires': '2027-01-01T00:00:00Z', 'newMember': true},
          ),
        ),
      );
      final value = await client.get('[env:prod]db.main');
      expect(value.text, 'demo-password-1');
      expect(value.bytes, utf8.encode('demo-password-1'));
      expect(value.encoding, TomSecretEncoding.utf8);
      expect(value.entry.store, 'fleet');
      expect(value.entry.source, TomSecretSource.github);
      expect(value.bound, {'env': 'prod'});
      expect(value.version.revision, 'b1946ac9');
      expect(value.expires, DateTime.utc(2027));
      expect(service.received.last, {
        'op': 'get',
        'ref': '[env:prod]db.main',
        'id': 1,
      });
    });

    test('the value never prints, and dispose overwrites it', () async {
      await startWith((c, r) => c.send(fakeValue(r['id']! as int, 'secret')));
      final value = await client.get('db.main');
      final view = value.bytes;
      expect(value.toString(), 'TomSecretValue(db.main: ***)');
      expect(value.toString(), isNot(contains('secret')));
      value.dispose();
      expect(view, everyElement(0));
      expect(() => value.text, throwsStateError);
    });

    test('a binary value is refused as text', () async {
      await startWith(
        (c, r) => c.send(
          fakeValue(r['id']! as int, 'AAFkZW1v/w==', encoding: 'base64'),
        ),
      );
      final value = await client.get('fleet/Keys/blob#attachment%3Akey.bin');
      expect(value.bytes, [0, 1, 0x64, 0x65, 0x6d, 0x6f, 0xff]);
      expect(() => value.text, throwsStateError);
    });

    test('options become members: field, dimensions, wait, timeoutMs, '
        'wantClientToken', () async {
      await startWith(
        (c, r) => c.send(
          fakeValue(r['id']! as int, 'v', extra: {'clientToken': 'dG9r'}),
        ),
      );
      final value = await client.get(
        'db.main',
        field: 'UserName',
        dimensions: {'env': 'prod'},
        wait: false,
        timeout: const Duration(seconds: 30),
        wantClientToken: true,
      );
      expect(value.clientToken, 'dG9r');
      expect(service.received.last, {
        'op': 'get',
        'ref': 'db.main',
        'dimensions': {'env': 'prod'},
        'field': 'UserName',
        'wait': false,
        'timeoutMs': 30000,
        'wantClientToken': true,
        'id': 1,
      });
    });

    test('the field named in the reference is not sent again; two different '
        'fields are field_twice', () async {
      await startWith((c, r) => c.send(fakeValue(r['id']! as int, 'v')));
      await client.get('db.main#UserName', field: 'UserName');
      expect(service.received.last.containsKey('field'), isFalse);
      await expectLater(
        client.get('db.main#UserName', field: 'Password'),
        _fails(TomSecretsErrorKind.malformed, reason: 'field_twice'),
      );
    });

    test('a malformed reference fails locally, without a round trip', () async {
      await startWith((c, r) => c.send(fakeValue(r['id']! as int, 'v')));
      await expectLater(
        client.get('Db.main'),
        _fails(TomSecretsErrorKind.malformed, reason: 'bad_key'),
      );
      expect(service.connections, 0);
    });

    test('a request over 64 KiB is refused locally', () async {
      await startWith((c, r) => c.send(fakeValue(r['id']! as int, 'v')));
      await expectLater(
        client.get('db.main', dimensions: {'env': 'x' * 70000}),
        _fails(TomSecretsErrorKind.malformed, reason: 'frame'),
      );
      expect(service.received.where((m) => m['op'] == 'get'), isEmpty);
    });

    test('overlapping requests, answered out of order', () async {
      final waiting = <Map<String, Object?>>[];
      await startWith((c, r) {
        waiting.add(r);
        if (waiting.length == 2) {
          for (final w in waiting.reversed) {
            c.send(fakeValue(w['id']! as int, w['ref']! as String));
          }
        }
      });
      final a = client.get('a.one');
      final b = client.get('b.two');
      expect((await a).text, 'a.one');
      expect((await b).text, 'b.two');
      expect(waiting.map((w) => w['id']), [1, 2]);
    });

    test(
      'progress notices reach the callback, with the approval code',
      () async {
        await startWith((c, r) {
          final id = r['id']! as int;
          c
            ..send({'op': 'progress', 'id': id, 'pending': 'unlock'})
            ..send({
              'op': 'progress',
              'id': id,
              'pending': 'approval',
              'approvalCode': 'VFGQMBJBCG',
            })
            ..send(fakeValue(id, 'v'));
        });
        final notices = <TomSecretsProgress>[];
        await client.get('db.main', onProgress: notices.add);
        expect(notices.map((n) => n.pending), [
          TomSecretsPending.unlock,
          TomSecretsPending.approval,
        ]);
        expect(notices.last.approvalCode, 'VFGQMBJBCG');
      },
    );

    test('the wait for an unlock ends locked when it times out', () async {
      await startWith((c, r) {
        final id = r['id']! as int;
        c.send({'op': 'progress', 'id': id, 'pending': 'unlock'});
        Timer(
          const Duration(milliseconds: 100),
          () => c.send({
            'op': 'error',
            'id': id,
            'kind': 'locked',
            'message': 'no unlock came in time',
          }),
        );
      });
      await expectLater(
        client.get('db.main', timeout: const Duration(milliseconds: 100)),
        _fails(TomSecretsErrorKind.locked),
      );
      expect(service.received.last['timeoutMs'], 100);
    });

    for (final kind in TomSecretsErrorKind.values.where(
      (k) => k != TomSecretsErrorKind.notRunning,
    )) {
      test('error ${kind.wireName} becomes its kind', () async {
        await startWith(
          (c, r) => c.send({
            'op': 'error',
            'id': r['id'],
            'kind': kind.wireName,
            'message': 'demo',
            'details': {'reason': 'demo_reason'},
          }),
        );
        await expectLater(
          client.get('db.main'),
          _fails(kind, reason: 'demo_reason'),
        );
      });
    }

    test('an unknown error kind is internal', () async {
      await startWith(
        (c, r) => c.send({
          'op': 'error',
          'id': r['id'],
          'kind': 'quota_exceeded',
          'message': 'a kind of a later version',
        }),
      );
      await expectLater(
        client.get('db.main'),
        _fails(TomSecretsErrorKind.internal),
      );
    });

    test('denied, ambiguous and not_found are never retried', () async {
      await startWith(
        (c, r) => c.send({
          'op': 'error',
          'id': r['id'],
          'kind': 'ambiguous',
          'message': 'two candidates',
          'details': {
            'candidates': [
              {'store': 'a', 'path': 'X', 'uuid': '0' * 32},
            ],
          },
        }),
      );
      await expectLater(
        client.get('db.main', waitOnRateLimit: true),
        throwsA(
          isA<TomSecretsClientException>().having(
            (e) => e.details['candidates'],
            'candidates',
            hasLength(1),
          ),
        ),
      );
      expect(service.received.where((m) => m['op'] == 'get'), hasLength(1));
    });

    test('rate_limited is waited out only when asked', () async {
      var calls = 0;
      await startWith((c, r) {
        calls++;
        c.send(
          calls == 1 || calls == 2
              ? {
                  'op': 'error',
                  'id': r['id'],
                  'kind': 'rate_limited',
                  'message': 'held back',
                  'details': {'retryAfterMs': 20},
                }
              : fakeValue(r['id']! as int, 'v'),
        );
      });
      await expectLater(
        client.get('db.main'),
        _fails(TomSecretsErrorKind.rateLimited),
      );
      expect((await client.get('db.main', waitOnRateLimit: true)).text, 'v');
      expect(calls, 3);
    });

    test(
      'an error without id closes the connection and fails what is open',
      () async {
        await startWith(
          (c, r) => c.send({
            'op': 'error',
            'kind': 'internal',
            'message': 'the service is shutting down',
          }),
        );
        await expectLater(
          client.get('db.main'),
          _fails(TomSecretsErrorKind.internal),
        );
        expect(client.welcome, isNull);
      },
    );

    test('an answer frame over 1 MiB closes the connection unread', () async {
      await startWith((c, r) => c.sendRaw([0x00, 0x10, 0x00, 0x01, 0x00]));
      await expectLater(
        client.get('db.main'),
        _fails(TomSecretsErrorKind.internal),
      );
      expect(client.welcome, isNull);
    });

    test(
      'a malformed answer (duplicate member) closes the connection',
      () async {
        await startWith(
          (c, r) => c.sendRaw(
            tomSecretsEncodeFrame(
              0,
              utf8.encode('{"op":"value","id":1,"id":1}'),
            ),
          ),
        );
        await expectLater(
          client.get('db.main'),
          _fails(TomSecretsErrorKind.internal),
        );
      },
    );
  });

  group('getMany', () {
    test('results in request order, values and errors', () async {
      await startWith(
        (c, r) => c.send({
          'op': 'values',
          'id': r['id'],
          'results': [
            {...fakeValue(0, 'one')..remove('id')},
            {
              'op': 'error',
              'kind': 'not_found',
              'message': 'no candidate',
              'details': {'dimensions': {}},
            },
          ],
        }),
      );
      final results = await client.getMany([
        const TomSecretRequest('a.one'),
        const TomSecretRequest('b.two', field: 'UserName'),
      ], timeout: const Duration(seconds: 5));
      expect(results[0].value!.text, 'one');
      expect(results[1].error!.kind, TomSecretsErrorKind.notFound);
      expect(service.received.last, {
        'op': 'getMany',
        'refs': [
          {'ref': 'a.one'},
          {'ref': 'b.two', 'field': 'UserName'},
        ],
        'timeoutMs': 5000,
        'id': 1,
      });
    });

    test('a malformed reference among them fails locally', () async {
      await startWith((_, _) {});
      await expectLater(
        client.getMany([
          const TomSecretRequest('a.one'),
          const TomSecretRequest('[env:]x'),
        ]),
        _fails(TomSecretsErrorKind.malformed, reason: 'empty_segment'),
      );
      expect(service.connections, 0);
    });

    test('1 to 256 references', () async {
      await startWith((_, _) {});
      expect(() => client.getMany([]), throwsArgumentError);
      expect(
        () => client.getMany(List.filled(257, const TomSecretRequest('a'))),
        throwsArgumentError,
      );
    });
  });

  group('getFile [B]', () {
    final content = Uint8List.fromList(List.generate(3000, (i) => i % 251));

    void serveFile(FakeConnection c, Map<String, Object?> r, {String? sha}) {
      final id = r['id']! as int;
      c.send({'op': 'file', 'id': id, 'name': 'id_ed25519', 'size': 3000});
      for (var at = 0; at < content.length; at += 1024) {
        final chunk = content.sublist(at, (at + 1024).clamp(0, content.length));
        final payload = Uint8List(8 + chunk.length);
        ByteData.sublistView(payload).setUint64(0, id);
        payload.setRange(8, payload.length, chunk);
        c.sendRaw(tomSecretsEncodeFrame(tomSecretsFrameBinary, payload));
      }
      c.send({
        'op': 'end',
        'id': id,
        'sha256': sha ?? crypto.sha256.convert(content).toString(),
      });
    }

    test('the chunks between file and end, checked against sha256', () async {
      await startWith(serveFile);
      service.welcome = fakeWelcome(features: ['binary', 'getFile']);
      final file = await client.getFile('fleet/SSH/bomber#attachment%3Aid');
      expect(file.name, 'id_ed25519');
      expect(file.bytes, content);
      expect(file.toString(), endsWith('id_ed25519: ***)'));
      file.dispose();
      expect(service.received.last['op'], 'getFile');
    });

    test('a wrong sha256 is refused', () async {
      await startWith((c, r) => serveFile(c, r, sha: '0' * 64));
      service.welcome = fakeWelcome(features: ['binary', 'getFile']);
      await expectLater(
        client.getFile('fleet/SSH/bomber#attachment%3Aid'),
        _fails(TomSecretsErrorKind.internal),
      );
    });

    test('a service without the features: unsupported, nothing sent', () async {
      await startWith(serveFile);
      await expectLater(
        client.getFile('fleet/SSH/bomber#attachment%3Aid'),
        _fails(TomSecretsErrorKind.unsupported),
      );
      expect(service.received.where((m) => m['op'] == 'getFile'), isEmpty);
    });
  });
}
