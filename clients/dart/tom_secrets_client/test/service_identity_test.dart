// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The service's identity key as an admin checks it (protocol.md 6.1, 6.2),
// against an admin endpoint in the test: a service that is not pinned gets
// nothing, a pinned one gets the claim sealed to its one-time key, another
// key stops the admin, a key-change statement re-pins; the words, the pin
// file and the sealing. The primitives are a stand-in (support/
// fake_identity.dart); the real ones are tested in tom_secrets_core and
// against the service. Demo keys only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'support/fake_identity.dart';

const _start = 1700000000000;
const _password = 'demo-master-password';

/// An admin endpoint with an identity key: it answers `identify`, opens a
/// sealed claim and checks an `auth`.
final class _Service {
  _Service(this.runtime, this.key, {this.features = const ['identity']});

  final TomSecretsRuntime runtime;
  FakeIdentityKey key;
  final List<String> features;
  List<TomSecretsIdentityChange> changes = const [];
  final adminKey = Uint8List.fromList(List.generate(32, (i) => i));

  /// Every message received, and every byte.
  final List<Map<String, Object?>> received = [];
  final BytesBuilder wire = BytesBuilder();

  /// The secrets of the claims opened.
  final List<String> passwords = [];

  /// What signs the exchange, when not [key] (a service that does not hold
  /// the key it presents).
  FakeIdentityKey? signer;

  ServerSocket? _server;

  Future<void> start() async {
    final server = _server = await ServerSocket.bind(
      InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
      0,
    );
    Process.runSync('chmod', ['600', runtime.adminSocket]);
    server.listen((socket) {
      final nonce = Uint8List(32)..[0] = 9;
      final oneTime = FakeOneTimeKey();
      Uint8List? transcript;
      final reader = TomSecretsFrameReader(
        maxPayload: tomSecretsMaxRequestPayload,
      );
      unawaited(socket.done.catchError((Object _) => socket));
      socket.add(
        tomSecretsJsonFrame({
          'op': 'challenge',
          'serviceNonce': base64.encode(nonce),
          'serviceStart': _start,
          'protocol': 1,
          'features': features,
        }),
      );
      socket.listen((bytes) async {
        wire.add(bytes);
        for (final frame in reader.add(bytes)) {
          final m = tomSecretsDecodePayload(frame.payload);
          received.add(m);
          switch (m['op']) {
            case 'identify':
              final answer = fakeIdentityAnswer(
                key: key,
                oneTime: oneTime,
                identify: m,
                serviceNonce: nonce,
                serviceStart: _start,
                changes: changes,
              );
              transcript = tomSecretsIdentityMessage(
                clientNonce: base64.decode(m['clientNonce']! as String),
                serviceNonce: nonce,
                serviceStart: _start,
                oneTimeKey: oneTime.publicKey,
              );
              if (signer != null) {
                answer['signature'] = base64.encode(
                  signer!.sign(transcript!, tomSecretsIdentityContext),
                );
              }
              socket.add(tomSecretsJsonFrame(answer));
            case 'claim':
              final sealed = (m['sealed']! as Map).cast<String, Object?>();
              final opened = await tomSecretsOpenClaim(
                sharedSecret: oneTime.decapsulate(
                  base64.decode(sealed['kem']! as String),
                ),
                transcript: transcript!,
                sealed: sealed,
              );
              passwords.add(opened.password);
              socket.add(
                tomSecretsJsonFrame({
                  'op': 'claimed',
                  'adminKey': base64.encode(adminKey),
                }),
              );
            case 'auth':
              final adminNonce = base64.decode(m['adminNonce']! as String);
              socket.add(
                tomSecretsJsonFrame({
                  'op': 'authed',
                  'mac2': base64.encode(
                    tomSecretsChallengeMac(
                      adminKey,
                      tomSecretsServiceLabel,
                      nonce,
                      adminNonce,
                      _start,
                    ),
                  ),
                }),
              );
            default:
              socket.add(tomSecretsJsonFrame({'op': 'ok', 'id': m['id']}));
          }
        }
      }, onError: (Object _) {});
    });
  }

  Future<void> stop() async => _server?.close();

  List<String> get ops => [for (final m in received) m['op']! as String];
}

void main() {
  late Directory dir;
  late TomSecretsRuntime runtime;
  late _Service service;
  late TomSecretsMemoryPins pins;

  TomSecretsServiceTrust trust({bool firstUse = false}) =>
      TomSecretsServiceTrust(
        identity: fakeIdentityTrust(pins: pins, firstUse: firstUse),
      );

  Future<TomSecretsAdminException> refused(Future<Object?> f) async {
    try {
      await f;
    } on TomSecretsAdminException catch (e) {
      return e;
    }
    fail('not refused');
  }

  Future<void> settle() =>
      Future<void>.delayed(const Duration(milliseconds: 80));

  setUp(() async {
    dir = Directory.systemTemp.createTempSync('tsm');
    Process.runSync('chmod', ['700', dir.path]);
    runtime = TomSecretsRuntime(dir.path, transport: TomSecretsTransport.unix);
    pins = TomSecretsMemoryPins();
    service = _Service(runtime, FakeIdentityKey());
    await service.start();
  });

  tearDown(() async {
    await service.stop();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  group('the claim', () {
    test('a service that is not pinned gets no claim: unpinned, with its '
        'words; nothing but the nonce was sent', () async {
      final e = await refused(
        TomSecretsAdminClient.claim(
          runtime,
          password: _password,
          trust: trust(),
        ),
      );
      expect(e.kind, tomSecretsServiceUntrusted);
      expect(e.details['reason'], 'unpinned');
      expect(
        e.details['words'],
        tomSecretsIdentityWords(service.key.publicKey),
      );
      expect(e.message, contains(e.details['words']! as String));
      expect(
        e.details['fingerprint'],
        tomSecretsIdentityFingerprint(service.key.publicKey),
      );
      await settle();
      expect(service.ops, ['identify']);
      expect(service.passwords, isEmpty);
    });

    test('pinned: the claim is sealed to the one-time key the service '
        'signed; the password is nowhere on the wire', () async {
      await pins.pin(
        'demo-host',
        runtime.directory,
        service.key.publicKey,
        TomSecretsPinSource.start,
      );
      final (admin, adminKey) = await TomSecretsAdminClient.claim(
        runtime,
        password: _password,
        keyFile: [1, 2, 3],
        trust: trust(),
      );
      addTearDown(admin.close);
      expect(adminKey, service.adminKey);
      expect(service.ops, ['identify', 'claim']);
      expect(service.passwords, [_password]);
      expect(
        admin.identity!.words,
        tomSecretsIdentityWords(service.key.publicKey),
      );
      final claim = service.received.last;
      expect(claim.containsKey('password'), isFalse);
      expect(claim.containsKey('keyFile'), isFalse);
      final wire = latin1.decode(service.wire.toBytes());
      expect(wire, isNot(contains(_password)));
      expect(wire, isNot(contains(base64.encode(utf8.encode(_password)))));
    });

    test('whoever relays the frames reads nothing: the sealed claim opens '
        'only with the one-time key\'s secret', () async {
      await pins.pin(
        'demo-host',
        runtime.directory,
        service.key.publicKey,
        TomSecretsPinSource.start,
      );
      final (admin, _) = await TomSecretsAdminClient.claim(
        runtime,
        password: _password,
        trust: trust(),
      );
      addTearDown(admin.close);
      // What a relay holds: every frame, and no secret of the one-time key.
      final sealed = (service.received.last['sealed']! as Map)
          .cast<String, Object?>();
      final transcript = admin.identity!.transcript;
      await expectLater(
        tomSecretsOpenClaim(
          sharedSecret: FakeOneTimeKey().decapsulate(
            base64.decode(sealed['kem']! as String),
          ),
          transcript: transcript,
          sealed: sealed,
        ),
        throwsFormatException,
      );
    });

    test('another key than the one pinned stops the admin: '
        'service_key_changed, nothing sent, and no way round it', () async {
      final pinned = FakeIdentityKey();
      await pins.pin(
        'demo-host',
        runtime.directory,
        pinned.publicKey,
        TomSecretsPinSource.start,
      );
      for (final attempt in [
        () => TomSecretsAdminClient.claim(
          runtime,
          password: _password,
          trust: trust(),
        ),
        () => TomSecretsAdminClient.connect(
          runtime,
          service.adminKey,
          trust: trust(),
        ),
        () => TomSecretsAdminClient.checkService(runtime, trust: trust()),
        // Not even for a caller that pins what it meets.
        () => TomSecretsAdminClient.claim(
          runtime,
          password: _password,
          trust: trust(firstUse: true),
        ),
      ]) {
        final e = await refused(attempt());
        expect(e.kind, tomSecretsServiceKeyChanged);
        expect(e.details['pinned'], tomSecretsIdentityWords(pinned.publicKey));
        expect(
          e.details['presented'],
          tomSecretsIdentityWords(service.key.publicKey),
        );
      }
      await settle();
      expect(service.ops.toSet(), {'identify'});
      expect(service.passwords, isEmpty);
      // The pin stays what it was.
      expect((await pins.all()).single.key, pinned.publicKey);
    });

    test('a service that does not hold the key it presents: '
        'service_impostor', () async {
      await pins.pin(
        'demo-host',
        runtime.directory,
        service.key.publicKey,
        TomSecretsPinSource.start,
      );
      service.signer = FakeIdentityKey();
      final e = await refused(
        TomSecretsAdminClient.claim(
          runtime,
          password: _password,
          trust: trust(),
        ),
      );
      expect(e.kind, 'service_impostor');
      await settle();
      expect(service.ops, ['identify']);
    });

    test('a service without an identity key (an older one), and an admin '
        'with no check configured: refused, nothing sent', () async {
      await service.stop();
      final left = File(runtime.adminSocket);
      if (FileSystemEntity.typeSync(left.path) !=
          FileSystemEntityType.notFound) {
        left.deleteSync();
      }
      service = _Service(runtime, FakeIdentityKey(), features: const []);
      await service.start();
      final old = await refused(
        TomSecretsAdminClient.claim(
          runtime,
          password: _password,
          trust: trust(firstUse: true),
        ),
      );
      expect(old.kind, tomSecretsServiceUntrusted);
      expect(old.details['reason'], 'no_identity');
      expect(tomSecretsUntrustedAdvice('no_identity'), contains('older'));

      final none = await refused(
        TomSecretsAdminClient.claim(runtime, password: _password),
      );
      expect(none.kind, tomSecretsServiceUntrusted);
      expect(none.details['reason'], 'unpinned');
      await settle();
      expect(service.received, isEmpty);
    });
  });

  group('the auth', () {
    test('checks the identity too: pinned it goes on, unpinned it does '
        'not', () async {
      final e = await refused(
        TomSecretsAdminClient.connect(
          runtime,
          service.adminKey,
          trust: trust(),
        ),
      );
      expect(e.details['reason'], 'unpinned');
      await settle();
      expect(service.ops, ['identify']);

      await pins.pin(
        'demo-host',
        runtime.directory,
        service.key.publicKey,
        TomSecretsPinSource.trust,
      );
      final admin = await TomSecretsAdminClient.connect(
        runtime,
        service.adminKey,
        trust: trust(),
      );
      addTearDown(admin.close);
      expect(admin.identity, isNotNull);
      expect(service.ops.sublist(1), ['identify', 'auth']);
    });

    test('the fallback check of the process holds where a connection names '
        'none', () async {
      TomSecretsServiceTrust.fallbackIdentity = fakeIdentityTrust(
        pins: pins,
        firstUse: true,
      );
      addTearDown(() => TomSecretsServiceTrust.fallbackIdentity = null);
      final admin = await TomSecretsAdminClient.connect(
        runtime,
        service.adminKey,
      );
      addTearDown(admin.close);
      // Pinned as it presented itself: only for a caller that says so.
      final pin = (await pins.all()).single;
      expect(pin.key, service.key.publicKey);
      expect(pin.runtime, runtime.directory);
    });
  });

  group('a rotated key', () {
    test('the pinned key signed its way to the new one: accepted, and '
        'pinned in its place; a statement by another key is not', () async {
      final first = service.key;
      await pins.pin(
        'demo-host',
        runtime.directory,
        first.publicKey,
        TomSecretsPinSource.start,
      );
      final second = FakeIdentityKey();
      final third = FakeIdentityKey();
      service
        ..key = third
        ..changes = [first.changeTo(second), second.changeTo(third)];
      final identity = await TomSecretsAdminClient.checkService(
        runtime,
        trust: trust(),
      );
      expect(identity.publicKey, third.publicKey);
      final pin = (await pins.all()).single;
      expect(pin.key, third.publicKey);
      expect(pin.source, TomSecretsPinSource.rotation);

      // A fourth key "signed" by someone who is not the third.
      final fourth = FakeIdentityKey();
      service
        ..key = fourth
        ..changes = [
          TomSecretsIdentityChange(
            from: third.publicKey,
            to: fourth.publicKey,
            signature: FakeIdentityKey().sign(
              fourth.publicKey,
              tomSecretsIdentityChangeContext,
            ),
          ),
        ];
      final e = await refused(
        TomSecretsAdminClient.checkService(runtime, trust: trust()),
      );
      expect(e.kind, tomSecretsServiceKeyChanged);
      expect((await pins.all()).single.key, third.publicKey);
    });
  });

  group('trusting by hand', () {
    test('presentedIdentity answers what the service presents whatever is '
        'pinned; checkService judges it', () async {
      final presented = await TomSecretsAdminClient.presentedIdentity(
        runtime,
        trust: trust(),
      );
      expect(presented.publicKey, service.key.publicKey);
      expect(await pins.all(), isEmpty, reason: 'nothing is pinned by it');
      expect(
        tomSecretsIdentityNamedBy(presented.words, presented.publicKey),
        isTrue,
      );
      await pins.pin(
        'demo-host',
        runtime.directory,
        presented.publicKey,
        TomSecretsPinSource.trust,
      );
      final checked = await TomSecretsAdminClient.checkService(
        runtime,
        trust: trust(),
      );
      expect(checked.words, presented.words);
      await settle();
      expect(service.ops.toSet(), {'identify'});
    });
  });

  group('the words', () {
    test('256 different words, one per byte', () {
      expect(tomSecretsIdentityWordList, hasLength(256));
      expect(tomSecretsIdentityWordList.toSet(), hasLength(256));
      for (final w in tomSecretsIdentityWordList) {
        expect(RegExp(r'^[a-z]{3,8}$').hasMatch(w), isTrue, reason: w);
      }
    });

    test('eight words of the fingerprint\'s first bytes; given back as '
        'words in any case, with spaces, or as the whole fingerprint', () {
      final key = FakeIdentityKey().publicKey;
      final words = tomSecretsIdentityWords(key);
      expect(words.split('-'), hasLength(8));
      final fingerprint = tomSecretsIdentityFingerprint(key);
      expect(fingerprint, hasLength(64));
      expect(
        words.split('-').first,
        tomSecretsIdentityWordList[int.parse(
          fingerprint.substring(0, 2),
          radix: 16,
        )],
      );
      expect(tomSecretsIdentityNamedBy(words, key), isTrue);
      expect(
        tomSecretsIdentityNamedBy(
          ' ${words.toUpperCase().replaceAll('-', '  ')} ',
          key,
        ),
        isTrue,
      );
      expect(tomSecretsIdentityNamedBy(fingerprint.toUpperCase(), key), isTrue);
      final other = FakeIdentityKey().publicKey;
      expect(tomSecretsIdentityNamedBy(words, other), isFalse);
      expect(tomSecretsIdentityNamedBy(fingerprint, other), isFalse);
      // Seven of the eight words name nothing.
      expect(
        tomSecretsIdentityNamedBy(words.split('-').take(7).join('-'), key),
        isFalse,
      );
      expect(tomSecretsIdentityNamedBy('', key), isFalse);
    });
  });

  group('the vectors and the device records', () {
    test('the word list and the examples of '
        'protocol/vectors/identity_words.json', () {
      final vectors =
          jsonDecode(
                File(
                  '../../../protocol/vectors/identity_words.json',
                ).readAsStringSync(),
              )
              as Map;
      expect(vectors['words'], tomSecretsIdentityWordList);
      for (final e in (vectors['examples'] as List).cast<Map>()) {
        final hex = e['publicKeyHex'] as String;
        final key = Uint8List.fromList([
          for (var i = 0; i < hex.length; i += 2)
            int.parse(hex.substring(i, i + 2), radix: 16),
        ]);
        expect(key, hasLength(tomSecretsIdentityKeyLength));
        expect(tomSecretsIdentityFingerprint(key), e['fingerprint']);
        expect(tomSecretsIdentityWords(key), e['words']);
      }
    });

    test('the service keys the device records name are pinned for their '
        'hosts: a new key replaces the old pin, a revoked device\'s pin '
        'goes, a pin for a runtime directory stays', () async {
      final pins = TomSecretsMemoryPins();
      final a = FakeIdentityKey();
      final b = FakeIdentityKey();
      await pins.pin(
        'bigbeast',
        '/run/x',
        a.publicKey,
        TomSecretsPinSource.start,
      );
      Map<String, Object?> record(FakeIdentityKey k, {bool revoked = false}) =>
          {
            'device': 'bigbeast',
            'serviceKey': base64.encode(k.publicKey),
            if (revoked) 'revoked': '2026-11-25T10:00:00.000Z',
          };
      expect(
        await tomSecretsPinDevices(pins, [
          record(a),
          {'device': 'phone'},
          {'device': 'bad', 'serviceKey': 'AAAA'},
          'no record',
        ]),
        1,
      );
      expect(await tomSecretsPinDevices(pins, [record(a)]), 0);
      var host = (await pins.all()).where((p) => p.runtime == null).single;
      expect(host.key, a.publicKey);
      expect(host.source, TomSecretsPinSource.pairing);
      expect(await tomSecretsPinDevices(pins, [record(b)]), 1);
      host = (await pins.all()).where((p) => p.runtime == null).single;
      expect(host.key, b.publicKey);
      expect(await tomSecretsPinDevices(pins, [record(b, revoked: true)]), 1);
      final left = (await pins.all()).single;
      expect(left.runtime, '/run/x');
      expect(left.key, a.publicKey);
    });
  });

  group('the pins', () {
    test('the file: written the user\'s alone, read back, replaced per '
        'host and runtime directory, removed', () async {
      final file = File('${dir.path}/config/tsm/services');
      final store = TomSecretsPinFile(file);
      expect(await store.all(), isEmpty);
      final a = FakeIdentityKey().publicKey;
      final b = FakeIdentityKey().publicKey;
      await store.pin('host-a', '/run/a', a, TomSecretsPinSource.start);
      await store.pin('host-a', null, b, TomSecretsPinSource.pairing);
      await store.pin('host-b', '/run/b', b, TomSecretsPinSource.trust);
      if (!Platform.isWindows) {
        expect(file.statSync().mode & 0x1FF, 0x180, reason: '0600');
        expect(file.parent.statSync().mode & 0x1FF, 0x1C0, reason: '0700');
      }
      final again = TomSecretsPinFile(file);
      expect((await again.all()).map((p) => p.host), [
        'host-a',
        'host-a',
        'host-b',
      ]);
      // The runtime directory's own pin, else the host's wherever it
      // answers.
      expect(
        (await tomSecretsPinsFor(again, 'host-a', '/run/a')).single.key,
        a,
      );
      final elsewhere = await tomSecretsPinsFor(again, 'host-a', '/run/x');
      expect(elsewhere.single.key, b);
      expect(elsewhere.single.source, TomSecretsPinSource.pairing);
      expect(await tomSecretsPinsFor(again, 'host-b', '/run/x'), isEmpty);
      expect(await tomSecretsPinsFor(again, 'host-c', '/run/a'), isEmpty);

      await again.pin('host-a', '/run/a', b, TomSecretsPinSource.rotation);
      expect(
        (await tomSecretsPinsFor(again, 'host-a', '/run/a')).single.key,
        b,
      );
      expect(await again.remove('host-a', '/run/a'), 1);
      expect(await again.remove('host-a', null), 1);
      expect(await again.remove('host-a', null), 0);
      expect((await again.all()).single.host, 'host-b');

      file.writeAsStringSync('not json');
      await expectLater(again.all(), throwsA(isA<FileSystemException>()));
    });

    test('where the file is', () {
      expect(
        tomSecretsPinFile(
          environment: const {'HOME': '/home/demo'},
          operatingSystem: 'linux',
        ),
        '/home/demo/.config/tsm/services',
      );
      expect(
        tomSecretsPinFile(
          environment: const {'HOME': '/home/demo', 'XDG_CONFIG_HOME': '/c'},
          operatingSystem: 'linux',
        ),
        '/c/tsm/services',
      );
      expect(
        tomSecretsPinFile(
          environment: const {'HOME': '/Users/demo'},
          operatingSystem: 'macos',
        ),
        '/Users/demo/.config/tsm/services',
      );
      expect(
        tomSecretsPinFile(
          environment: const {'APPDATA': r'C:\Users\demo\AppData\Roaming'},
          operatingSystem: 'windows',
        ),
        r'C:\Users\demo\AppData\Roaming\tsm\services',
      );
      expect(
        tomSecretsPinFile(
          environment: const {'TSM_CONFIG_DIR': '/t', 'HOME': '/home/demo'},
          operatingSystem: 'linux',
        ),
        '/t/services',
      );
    });
  });

  group('the sealing', () {
    test('opens with the shared secret and the transcript it was made '
        'for; not with another secret, another transcript or a changed '
        'byte', () async {
      final secret = List.generate(32, (i) => i);
      final transcript = List.generate(100, (i) => 255 - i);
      final sealed = await tomSecretsSealClaim(
        sharedSecret: secret,
        kemCiphertext: [7, 7, 7],
        transcript: transcript,
        password: _password,
        keyFile: [1, 2, 3],
      );
      expect(sealed.keys, {'kem', 'nonce', 'ciphertext'});
      final opened = await tomSecretsOpenClaim(
        sharedSecret: secret,
        transcript: transcript,
        sealed: sealed,
      );
      expect(opened.password, _password);
      expect(opened.keyFile, [1, 2, 3]);

      Future<void> fails(
        List<int> s,
        List<int> t,
        Map<String, Object?> sealed,
      ) => expectLater(
        tomSecretsOpenClaim(sharedSecret: s, transcript: t, sealed: sealed),
        throwsFormatException,
      );
      await fails([...secret]..[0] ^= 1, transcript, sealed);
      await fails(secret, [...transcript]..[5] ^= 1, sealed);
      final bytes = base64.decode(sealed['ciphertext']! as String);
      bytes[3] ^= 1;
      await fails(secret, transcript, {
        ...sealed,
        'ciphertext': base64.encode(bytes),
      });
      await fails(secret, transcript, const {'nonce': 'AA==', 'kem': 'AA=='});

      final plain = await tomSecretsSealClaim(
        sharedSecret: secret,
        kemCiphertext: const [],
        transcript: transcript,
        password: _password,
      );
      expect(
        (await tomSecretsOpenClaim(
          sharedSecret: secret,
          transcript: transcript,
          sealed: plain,
        )).keyFile,
        isNull,
      );
    });
  });
}
