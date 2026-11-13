// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The fake service's script steps, over a raw socket (no client library).
/// The runtime directory is relative (`ztmp/test/fake`): a Unix socket path
/// may not be much longer than 100 bytes.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tom_secrets_fake_service/fake_service.dart';

const _dir = 'ztmp/test/fake';

Uint8List _frame(Map<String, Object?> m) {
  final payload = utf8.encode(jsonEncode(m));
  final out = Uint8List(5 + payload.length);
  ByteData.sublistView(out).setUint32(0, payload.length);
  out.setRange(5, out.length, payload);
  return out;
}

/// A raw client: frames out, frames in (type and payload).
final class _Raw {
  _Raw(this.socket) {
    socket.listen((bytes) {
      _buffer.add(bytes);
      var data = _buffer.takeBytes();
      var offset = 0;
      while (data.length - offset >= 5) {
        final length = ByteData.sublistView(data, offset).getUint32(0);
        if (data.length - offset - 5 < length) break;
        _frames.add((
          data[offset + 4],
          data.sublist(offset + 5, offset + 5 + length),
        ));
        offset += 5 + length;
      }
      _buffer.add(data.sublist(offset));
      data = Uint8List(0);
    }, onDone: () => _frames.close());
  }

  static Future<_Raw> connect(FakeService service) async {
    final Socket socket;
    if (service.transport == 'tcp') {
      final port = int.parse(
        File('${service.directory}\\client.port').readAsStringSync().trim(),
      );
      socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
    } else {
      socket = await Socket.connect(
        InternetAddress(
          '${service.directory}/client.sock',
          type: InternetAddressType.unix,
        ),
        0,
      );
    }
    return _Raw(socket);
  }

  final Socket socket;
  final BytesBuilder _buffer = BytesBuilder(copy: false);
  final StreamController<(int, Uint8List)> _frames = StreamController();
  late final StreamIterator<(int, Uint8List)> _next = StreamIterator(
    _frames.stream,
  );

  void send(Map<String, Object?> m) => socket.add(_frame(m));

  Future<(int, Uint8List)?> frame() async =>
      await _next.moveNext().timeout(const Duration(seconds: 5))
      ? _next.current
      : null;

  Future<Map<String, Object?>?> message() async {
    final f = await frame();
    return f == null
        ? null
        : jsonDecode(utf8.decode(f.$2)) as Map<String, Object?>;
  }
}

void main() {
  setUp(() {
    final d = Directory(_dir);
    if (d.existsSync()) d.deleteSync(recursive: true);
    d.createSync(recursive: true);
  });
  tearDownAll(() {
    final d = Directory(_dir);
    if (d.existsSync()) d.deleteSync(recursive: true);
  });

  final transports = [if (!Platform.isWindows) 'unix', 'tcp'];
  for (final transport in transports) {
    group(transport, () {
      test('welcome, a rule with \$id and \$ref, the record', () async {
        final service = await FakeService.start(
          directory: _dir,
          transport: transport,
          script: {
            'welcome': {'host': 'h1'},
            'rules': [
              {
                'match': {'op': 'get'},
                'reply': [
                  {
                    'send': {'op': 'x', 'id': r'$id', 'ref': r'$ref'},
                  },
                ],
              },
            ],
          },
        );
        final raw = await _Raw.connect(service);
        raw.send({'op': 'hello', 'protocol': 1});
        final welcome = await raw.message();
        expect(welcome!['op'], 'welcome');
        expect(welcome['host'], 'h1');
        expect(welcome['protocol'], 1);
        raw.send({'op': 'get', 'id': 41, 'ref': 'db.main'});
        expect(await raw.message(), {'op': 'x', 'id': 41, 'ref': 'db.main'});
        raw.send({'op': 'getMany', 'id': 42, 'refs': []});
        final noRule = await raw.message();
        expect(noRule!['kind'], 'internal');
        expect(noRule['id'], 42);
        await service.stop();
        final record = service.record();
        expect(record['connections'], 1);
        expect(
          (record['received']! as List).map((r) => (r as Map)['message']['op']),
          ['hello', 'get', 'getMany'],
        );
      });

      test('a first frame that is not hello is refused and closed', () async {
        final service = await FakeService.start(
          directory: _dir,
          transport: transport,
          script: {},
        );
        final raw = await _Raw.connect(service);
        raw.send({'op': 'get', 'id': 1, 'ref': 'x'});
        expect((await raw.message())!['kind'], 'malformed');
        expect(await raw.frame(), isNull);
        await service.stop();
      });

      test(
        'times, holdUntil (answered in reverse), close and restart',
        () async {
          final service = await FakeService.start(
            directory: _dir,
            transport: transport,
            script: {
              'rules': [
                {
                  'match': {'op': 'get', 'ref': 'held'},
                  'holdUntil': 2,
                  'reply': [
                    {
                      'send': {'op': 'value', 'id': r'$id'},
                    },
                  ],
                },
                {
                  'match': {'op': 'get', 'ref': 'once'},
                  'times': 1,
                  'reply': [
                    {
                      'send': {'op': 'value', 'id': r'$id'},
                    },
                    {'restart': true},
                  ],
                },
              ],
            },
          );
          final firstToken = service.token;
          final raw = await _Raw.connect(service);
          raw.send({'op': 'hello', 'protocol': 1});
          await raw.message();
          raw
            ..send({'op': 'get', 'id': 1, 'ref': 'held'})
            ..send({'op': 'get', 'id': 2, 'ref': 'held'});
          expect((await raw.message())!['id'], 2);
          expect((await raw.message())!['id'], 1);
          raw.send({'op': 'get', 'id': 3, 'ref': 'once'});
          expect((await raw.message())!['id'], 3);
          expect(await raw.frame(), isNull, reason: 'the restart dropped it');
          // The restart closes the connections before it binds again.
          for (var i = 0; i < 100 && service.starts < 2; i++) {
            await Future<void>.delayed(const Duration(milliseconds: 20));
          }
          expect(service.starts, 2);
          if (transport == 'tcp') expect(service.token, isNot(firstToken));
          final again = await _Raw.connect(service);
          again.send({'op': 'hello', 'protocol': 1});
          expect((await again.message())!['op'], 'welcome');
          again.send({'op': 'get', 'id': 4, 'ref': 'once'});
          expect((await again.message())!['details'], {'code': 'no_rule'});
          await service.stop();
        },
      );

      test('a file: binary chunks only when both sides named binary', () async {
        final content = List.generate(2500, (i) => i % 256);
        final script = {
          'welcome': {
            'features': ['binary', 'getFile'],
          },
          'rules': [
            {
              'match': {'op': 'getFile'},
              'reply': [
                {
                  'file': {
                    'name': 'k',
                    'contentHex': content
                        .map((b) => b.toRadixString(16).padLeft(2, '0'))
                        .join(),
                    'chunkSize': 1000,
                  },
                },
              ],
            },
          ],
        };
        final service = await FakeService.start(
          directory: _dir,
          transport: transport,
          script: script,
        );
        final raw = await _Raw.connect(service);
        raw.send({
          'op': 'hello',
          'protocol': 1,
          'features': ['binary'],
        });
        await raw.message();
        raw.send({'op': 'getFile', 'id': 7, 'ref': 'f/x#k'});
        expect((await raw.message())!['size'], 2500);
        final chunks = <int>[];
        for (var i = 0; i < 3; i++) {
          final (type, payload) = (await raw.frame())!;
          expect(type, 1);
          expect(ByteData.sublistView(payload).getUint64(0), 7);
          chunks.addAll(payload.sublist(8));
        }
        expect(chunks, content);
        expect(
          (await raw.message())!['sha256'],
          crypto.sha256.convert(content).toString(),
        );
        await service.stop();
      });

      test(
        'a request frame over 64 KiB is recorded invalid and closed',
        () async {
          final service = await FakeService.start(
            directory: _dir,
            transport: transport,
            script: {},
          );
          final raw = await _Raw.connect(service);
          raw.socket.add([0x00, 0x01, 0x00, 0x01, 0x00]);
          expect(await raw.frame(), isNull);
          await service.stop();
          expect((service.record()['received']! as List).single, {
            'connection': 1,
            'invalid': 'frame of 65537 bytes over 65536',
          });
        },
      );
    });
  }
}
