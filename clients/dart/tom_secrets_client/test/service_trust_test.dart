// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Who answers on the admin endpoint (protocol.md 6.0): the decision with
// recorded facts (a directory or socket of another owner or mode, a peer of
// another user, a peer that is not the service executable, a hidden
// executable, Windows' grantees), `stat`'s lines, and on Linux and macOS
// the real thing: a Unix socket in the test, its directory and socket
// loosened, and another process answering in the service's place. In every
// refusal nothing was sent. Demo keys only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/src/admin/windows_acl.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

const _service = '/opt/tsm/bin/tom_secrets_service';

TomSecretsEndpointFacts _posix({
  int me = 1000,
  TomSecretsFileFacts? directory = (owner: 1000, mode: 448, type: 'directory'),
  TomSecretsFileFacts? socket = (owner: 1000, mode: 384, type: 'socket'),
  TomSecretsServicePeer? peer = const TomSecretsServicePeer(
    pid: 4711,
    user: 1000,
    executable: _service,
  ),
}) => TomSecretsEndpointFacts(
  operatingSystem: 'linux',
  ownUser: me,
  ownPid: 100,
  directory: directory,
  socket: socket,
  peer: peer,
);

TomSecretsEndpointFacts _windows({
  Set<String>? grantees = const {'demo', 'system'},
  TomSecretsServicePeer? peer = const TomSecretsServicePeer(
    pid: 4711,
    user: 'S-1-5-21-1-2-3-1001',
    executable: r'C:\Tools\tsm\bin\tom_secrets_service.exe',
  ),
}) => TomSecretsEndpointFacts(
  operatingSystem: 'windows',
  ownUser: 'S-1-5-21-1-2-3-1001',
  ownPid: 100,
  directoryGrantees: grantees,
  peer: peer,
);

String? _why(
  TomSecretsEndpointFacts facts, {
  Set<String> executables = const {_service},
}) => tomSecretsJudgeService(
  facts,
  executables: executables,
  userOnly: (g) => g.every((x) => x == 'demo' || x == 'system'),
)?.reason.wireName;

void main() {
  group('the decision, with recorded facts', () {
    test('this user\'s directory, socket and service pass', () {
      expect(_why(_posix()), isNull);
      expect(
        _why(
          _windows(),
          executables: {r'c:\tools\tsm\bin\TOM_SECRETS_SERVICE.EXE'},
        ),
        isNull,
        reason: 'Windows paths compare without case',
      );
    });

    test('a directory or socket of another owner: owner', () {
      expect(
        _why(_posix(directory: (owner: 1001, mode: 448, type: 'directory'))),
        'owner',
      );
      expect(
        _why(_posix(socket: (owner: 0, mode: 384, type: 'socket'))),
        'owner',
      );
      // What is there is not what is expected: a link in /tmp, a file.
      expect(
        _why(_posix(directory: (owner: 1000, mode: 511, type: 'link'))),
        'owner',
      );
      expect(
        _why(_posix(socket: (owner: 1000, mode: 384, type: 'file'))),
        'owner',
      );
      expect(_why(_posix(directory: null)), 'owner');
      expect(_why(_posix(socket: null)), 'owner');
    });

    test('a directory or socket open to others: mode', () {
      // 0750, 0701, 0660.
      for (final mode in [488, 449]) {
        expect(
          _why(_posix(directory: (owner: 1000, mode: mode, type: 'directory'))),
          'mode',
          reason: mode.toRadixString(8),
        );
      }
      expect(
        _why(_posix(socket: (owner: 1000, mode: 432, type: 'socket'))),
        'mode',
      );
      expect(_why(_windows(grantees: {'demo', 'system', 'users'})), 'mode');
      expect(_why(_windows(grantees: null)), 'owner');
    });

    test('a peer of another user, or one that cannot be read: peer_user', () {
      expect(
        _why(
          _posix(
            peer: const TomSecretsServicePeer(
              pid: 4711,
              user: 1001,
              executable: _service,
            ),
          ),
        ),
        'peer_user',
      );
      expect(_why(_posix(peer: null)), 'peer_user');
      expect(
        _why(
          _windows(
            peer: const TomSecretsServicePeer(
              pid: 4711,
              user: null,
              executable: r'C:\Tools\tsm\bin\tom_secrets_service.exe',
            ),
          ),
        ),
        'peer_user',
      );
    });

    test('a peer that is not the service executable: peer_executable', () {
      const impostor = TomSecretsServicePeer(
        pid: 4711,
        user: 1000,
        executable: '/tmp/x/tom_secrets_service',
      );
      final verdict = tomSecretsJudgeService(
        _posix(peer: impostor),
        executables: {_service},
      )!;
      expect(verdict.reason, TomSecretsUntrustedReason.peerExecutable);
      expect(verdict.message, contains('/tmp/x/tom_secrets_service'));
      expect(verdict.message, contains('TSM_SERVICE'));
      // No executable read, and not because the OS hides it.
      expect(
        _why(
          _posix(
            peer: const TomSecretsServicePeer(
              pid: 4711,
              user: 1000,
              executable: null,
            ),
          ),
        ),
        'peer_executable',
      );
      expect(_why(_posix(), executables: const {}), 'peer_executable');
    });

    test('Linux hides a hardened service\'s executable from its own user: '
        'the user is checked, the executable cannot be', () {
      const hidden = TomSecretsServicePeer(
        pid: 4711,
        user: 1000,
        executable: null,
        executableHidden: true,
      );
      expect(_why(_posix(peer: hidden)), isNull);
      expect(
        _why(
          _posix(
            peer: const TomSecretsServicePeer(
              pid: 4711,
              user: 1001,
              executable: null,
              executableHidden: true,
            ),
          ),
        ),
        'peer_user',
      );
    });

    test('this very process serving the endpoint passes', () {
      expect(
        _why(
          _posix(
            peer: const TomSecretsServicePeer(
              pid: 100,
              user: 1000,
              executable: '/usr/bin/dart',
            ),
          ),
        ),
        isNull,
      );
    });

    test('the files are judged before the peer', () {
      final facts = _posix(
        directory: (owner: 1001, mode: 448, type: 'directory'),
        peer: null,
      );
      expect(tomSecretsJudgeEndpointFiles(facts)!.reason.wireName, 'owner');
      expect(tomSecretsJudgeEndpointFiles(_posix(peer: null)), isNull);
    });
  });

  test('stat\'s lines: the owner and the raw mode in hex', () {
    expect(tomSecretsParseStat('501 41c0'), (
      owner: 501,
      mode: 448,
      type: 'directory',
    ));
    expect(tomSecretsParseStat('501 c180'), (
      owner: 501,
      mode: 384,
      type: 'socket',
    ));
    expect(tomSecretsParseStat('1000 a1ff')!.type, 'link');
    expect(tomSecretsParseStat('1000 81a4'), (
      owner: 1000,
      mode: 420,
      type: 'file',
    ));
    // /tmp itself (1777): open to others.
    expect(tomSecretsParseStat('0 43ff')!.mode % 64, isNot(0));
    expect(tomSecretsParseStat('0 21b6')!.type, 'other');
    expect(tomSecretsParseStat('x c180'), isNull);
    expect(tomSecretsParseStat('501 zz'), isNull);
    expect(tomSecretsParseStat('501 c180 Socket'), isNull);
    expect(tomSecretsParseStat(''), isNull);
  });

  test('the executables expected: beside this one, in its distribution, '
      'TSM_SERVICE and what is configured', () {
    final expected = tomSecretsExpectedServiceExecutables(
      ownExecutable: '/opt/demo/tsm',
      environment: const {'TSM_SERVICE': '/srv/demo/tom_secrets_service'},
      configured: const ['/usr/local/demo/service'],
      operatingSystem: 'linux',
    );
    expect(expected, {
      '/opt/demo/tom_secrets_service',
      '/opt/demo/tsm/bin/tom_secrets_service',
      '/srv/demo/tom_secrets_service',
      '/usr/local/demo/service',
    });
  });

  group('a real endpoint', () {
    late Directory dir;
    late TomSecretsRuntime runtime;
    final adminKey = Uint8List.fromList(List.generate(32, (i) => i));
    final sent = <Map<String, Object?>>[];
    ServerSocket? server;

    /// A challenge, then whatever arrives is recorded.
    Future<void> serve() async {
      final s = server = await ServerSocket.bind(
        InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
        0,
      );
      Process.runSync('chmod', ['600', runtime.adminSocket]);
      s.listen((socket) {
        final reader = TomSecretsFrameReader(
          maxPayload: tomSecretsMaxRequestPayload,
        );
        unawaited(socket.done.catchError((Object _) => socket));
        socket.add(
          tomSecretsJsonFrame({
            'op': 'challenge',
            'serviceNonce': base64.encode(Uint8List(32)),
            'serviceStart': 1700000000000,
            'protocol': 1,
          }),
        );
        socket.listen((bytes) {
          for (final frame in reader.add(bytes)) {
            sent.add(tomSecretsDecodePayload(frame.payload));
          }
          socket.destroy();
        }, onError: (Object _) {});
      });
    }

    Future<TomSecretsAdminException> refusedClaim({
      TomSecretsServiceTrust trust = const TomSecretsServiceTrust(),
    }) async {
      try {
        await TomSecretsAdminClient.claim(
          runtime,
          password: 'demo-password',
          trust: trust,
        );
      } on TomSecretsAdminException catch (e) {
        return e;
      }
      fail('the claim was sent');
    }

    setUp(() {
      // A short path: a Unix socket's is limited to about 100 bytes.
      dir = Directory.systemTemp.createTempSync('tsm');
      Process.runSync('chmod', ['700', dir.path]);
      runtime = TomSecretsRuntime(
        dir.path,
        transport: TomSecretsTransport.unix,
      );
      sent.clear();
    });

    tearDown(() async {
      await server?.close();
      server = null;
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });

    test('no endpoint: not running, before anything is judged', () async {
      Process.runSync('chmod', ['755', dir.path]);
      expect((await refusedClaim()).kind, 'not_running');
    });

    test('this user\'s directory and socket, this process answering: the '
        'claim is sent', () async {
      await serve();
      // The fake endpoint closes after the first message: the claim got
      // there.
      final e = await refusedClaim();
      expect(e.kind, 'closed');
      expect(sent.single['op'], 'claim');
    });

    test('a directory open to others: mode, nothing sent, not even '
        'connected', () async {
      await serve();
      Process.runSync('chmod', ['750', dir.path]);
      final e = await refusedClaim();
      expect(e.kind, tomSecretsServiceUntrusted);
      expect(e.details['reason'], 'mode');
      expect(e.message, contains('runtime directory'));
      expect(e.message, contains('750'));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(sent, isEmpty);
    });

    test('a socket open to others: mode, nothing sent', () async {
      await serve();
      Process.runSync('chmod', ['666', runtime.adminSocket]);
      final e = await refusedClaim();
      expect(e.kind, tomSecretsServiceUntrusted);
      expect(e.details['reason'], 'mode');
      expect(e.message, contains('admin socket'));
      expect(sent, isEmpty);
    });

    test('the runtime directory is a link (as another user could leave in '
        '/tmp): owner, nothing sent', () async {
      await serve();
      final link = Link('${dir.path}-link')..createSync(dir.path);
      addTearDown(link.deleteSync);
      runtime = TomSecretsRuntime(
        link.path,
        transport: TomSecretsTransport.unix,
      );
      final e = await refusedClaim();
      expect(e.kind, tomSecretsServiceUntrusted);
      expect(e.details['reason'], 'owner');
      expect(sent, isEmpty);
    });

    test('a file where the socket should be: owner', () async {
      File(runtime.adminSocket).writeAsStringSync('x');
      Process.runSync('chmod', ['600', runtime.adminSocket]);
      final e = await refusedClaim();
      expect(e.kind, tomSecretsServiceUntrusted);
      expect(e.details['reason'], 'owner');
    });

    test('another process answers in the service\'s place: '
        'peer_executable for a claim and for an auth, nothing sent; named '
        'as the service expected, it passes', () async {
      // The impostor: a Dart process of this user serving the socket, which
      // prints every message it is sent.
      final script = File('${dir.path}/impostor.dart')
        ..writeAsStringSync(_impostor);
      final process = await Process.start(Platform.resolvedExecutable, [
        script.path,
        runtime.adminSocket,
      ]);
      addTearDown(process.kill);
      final lines = <String>[];
      final ready = Completer<void>();
      process.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((line) {
            if (line == 'ready') {
              ready.complete();
            } else {
              lines.add(line);
            }
          });
      await ready.future.timeout(const Duration(seconds: 60));

      final e = await refusedClaim();
      expect(e.kind, tomSecretsServiceUntrusted);
      expect(e.details['reason'], 'peer_executable');
      expect(e.message, contains('pid ${process.pid}'));
      await expectLater(
        TomSecretsAdminClient.connect(runtime, adminKey),
        throwsA(
          isA<TomSecretsAdminException>()
              .having((x) => x.kind, 'kind', tomSecretsServiceUntrusted)
              .having((x) => x.details['reason'], 'reason', 'peer_executable'),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(lines, isEmpty, reason: 'nothing reached the impostor');

      // The same process, named as the service this admin expects (what
      // TSM_SERVICE does): measured as that executable, so the claim goes.
      // (The refusal names the executable measured: the Dart VM the `dart`
      // command started, not the command itself.)
      final measured = RegExp(
        r'\) is (.+), not the service expected',
      ).firstMatch(e.message)!.group(1)!;
      expect(File(measured).existsSync(), isTrue);
      final named = TomSecretsServiceTrust(executables: {measured});
      final sentOn = await refusedClaim(trust: named);
      expect(sentOn.kind, 'closed');
      for (var i = 0; i < 100 && lines.isEmpty; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      expect(lines.single, contains('"op":"claim"'));
    }, timeout: const Timeout(Duration(minutes: 2)));

    test(
      'Linux: a process that made itself not dumpable (as the service '
      'does) hides its executable from its own user; its user is still '
      'checked, and the claim goes',
      () async {
        final script = File('${dir.path}/hardened.dart')
          ..writeAsStringSync(_impostor);
        final process = await Process.start(Platform.resolvedExecutable, [
          script.path,
          runtime.adminSocket,
          'hardened',
        ]);
        addTearDown(process.kill);
        final lines = <String>[];
        final ready = Completer<void>();
        process.stdout
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .listen((line) {
              if (line == 'ready') {
                ready.complete();
              } else {
                lines.add(line);
              }
            });
        await ready.future.timeout(const Duration(seconds: 60));
        final socket = await Socket.connect(
          InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
          0,
        );
        final peer = tomSecretsServicePeerOf(socket)!;
        socket.destroy();
        expect(peer.user, tomSecretsOwnUser());
        expect(peer.executable, isNull);
        expect(peer.executableHidden, isTrue);
        expect((await refusedClaim()).kind, 'closed');
        for (var i = 0; i < 100 && lines.isEmpty; i++) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        expect(lines.single, contains('"op":"claim"'));
      },
      testOn: 'linux',
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }, testOn: '!windows');

  group('a real endpoint on Windows', () {
    late Directory dir;
    late TomSecretsRuntime runtime;

    setUp(() async {
      dir = Directory.systemTemp.createTempSync('tsm');
      await tomSecretsRestrictWindowsDirectory(dir.path);
      runtime = TomSecretsRuntime(dir.path, transport: TomSecretsTransport.tcp);
    });

    tearDown(() {
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });

    test('this process answering in a directory of the user alone passes; '
        'a directory granting others is refused (mode)', () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(server.close);
      final got = <List<int>>[];
      server.listen((s) => s.listen(got.add, onError: (Object _) {}));
      await runtime.writePort(runtime.adminPortFile, server.port);
      await TomSecretsAdminClient.checkService(runtime);

      final granted = Process.runSync('icacls', [
        dir.path,
        '/grant',
        // The Users group by its SID: its name follows the language.
        '*S-1-5-32-545:(OI)(CI)RX',
      ]);
      expect(granted.exitCode, 0, reason: '${granted.stderr}');
      await expectLater(
        TomSecretsAdminClient.checkService(runtime),
        throwsA(
          isA<TomSecretsAdminException>()
              .having((x) => x.kind, 'kind', tomSecretsServiceUntrusted)
              .having((x) => x.details['reason'], 'reason', 'mode'),
        ),
      );
      expect(got, isEmpty);
    });

    test(
      'another process on the port the port file names: '
      'peer_executable, with its path; named as the service, it passes',
      () async {
        final script = File('${dir.path}\\impostor.dart')
          ..writeAsStringSync(_tcpImpostor);
        final process = await Process.start(Platform.resolvedExecutable, [
          script.path,
        ]);
        addTearDown(process.kill);
        final port = int.parse(
          await process.stdout
              .transform(utf8.decoder)
              .transform(const LineSplitter())
              .first
              .timeout(const Duration(seconds: 60)),
        );
        await runtime.writePort(runtime.adminPortFile, port);
        TomSecretsAdminException? e;
        try {
          await TomSecretsAdminClient.checkService(runtime);
        } on TomSecretsAdminException catch (x) {
          e = x;
        }
        expect(e?.kind, tomSecretsServiceUntrusted);
        expect(e!.details['reason'], 'peer_executable');
        final measured = RegExp(
          r'\) is (.+), not the service expected',
        ).firstMatch(e.message)!.group(1)!;
        expect(File(measured).existsSync(), isTrue);
        await TomSecretsAdminClient.checkService(
          runtime,
          trust: TomSecretsServiceTrust(executables: {measured.toUpperCase()}),
        );
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }, testOn: 'windows');

  test('the service\'s own check at its start (TomSecretsRuntime.check): a '
      'directory open to others, and a link where the directory should be '
      '(as another user could leave in /tmp), are refused and left as they '
      'are', () async {
    final dir = Directory.systemTemp.createTempSync('tsm');
    addTearDown(() => dir.deleteSync(recursive: true));
    final real = Directory('${dir.path}/real')..createSync();
    Process.runSync('chmod', ['700', real.path]);
    await TomSecretsRuntime(
      real.path,
      transport: TomSecretsTransport.unix,
    ).check();

    final link = Link('${dir.path}/link')..createSync(real.path);
    final linked = TomSecretsRuntime(
      link.path,
      transport: TomSecretsTransport.unix,
    );
    await expectLater(
      linked.prepare(),
      throwsA(
        isA<TomSecretsRuntimeException>().having(
          (e) => e.message,
          'message',
          contains('is no directory (link)'),
        ),
      ),
    );
    expect(link.existsSync(), isTrue, reason: 'left as it is');

    Process.runSync('chmod', ['755', real.path]);
    await expectLater(
      TomSecretsRuntime(
        real.path,
        transport: TomSecretsTransport.unix,
      ).prepare(),
      throwsA(
        isA<TomSecretsRuntimeException>().having(
          (e) => e.message,
          'message',
          contains('open to others (mode 755)'),
        ),
      ),
    );
    expect(FileStat.statSync(real.path).mode % 512, 493, reason: 'not changed');
  }, testOn: '!windows');

  test('checkService sends nothing', () async {
    final dir = Directory.systemTemp.createTempSync('tsm');
    addTearDown(() => dir.deleteSync(recursive: true));
    Process.runSync('chmod', ['700', dir.path]);
    final runtime = TomSecretsRuntime(
      dir.path,
      transport: TomSecretsTransport.unix,
    );
    final server = await ServerSocket.bind(
      InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
      0,
    );
    addTearDown(server.close);
    Process.runSync('chmod', ['600', runtime.adminSocket]);
    final got = <List<int>>[];
    server.listen((s) => s.listen(got.add, onError: (Object _) {}));
    await TomSecretsAdminClient.checkService(runtime);
    Process.runSync('chmod', ['644', runtime.adminSocket]);
    await expectLater(
      TomSecretsAdminClient.checkService(runtime),
      throwsA(
        isA<TomSecretsAdminException>()
            .having((x) => x.kind, 'kind', tomSecretsServiceUntrusted)
            .having((x) => x.details['reason'], 'reason', 'mode'),
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(got, isEmpty);
    expect(tomSecretsUntrustedAdvice('mode'), contains('chmod 700'));
    for (final reason in TomSecretsUntrustedReason.values) {
      expect(tomSecretsUntrustedAdvice(reason.wireName), isNotEmpty);
    }
  }, testOn: '!windows');
}

/// A process that serves [the socket] as the service would: a challenge,
/// then every message it is sent printed as a line.
const _impostor = r'''
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

void main(List<String> args) async {
  if (args.length > 1) {
    // As the service hardens itself on Linux: prctl(PR_SET_DUMPABLE, 0).
    DynamicLibrary.process().lookupFunction<
      Int32 Function(Int32, Uint64, Uint64, Uint64, Uint64),
      int Function(int, int, int, int, int)
    >('prctl')(4, 0, 0, 0, 0);
  }
  final server = await ServerSocket.bind(
    InternetAddress(args.first, type: InternetAddressType.unix),
    0,
  );
  Process.runSync('chmod', ['600', args.first]);
  print('ready');
  server.listen((socket) {
    final challenge = utf8.encode(jsonEncode({
      'op': 'challenge',
      'serviceNonce': base64.encode(Uint8List(32)),
      'serviceStart': 1700000000000,
      'protocol': 1,
    }));
    // A frame: the length, then the type (0: JSON).
    final head = ByteData(5)..setUint32(0, challenge.length);
    // The admin may hang up without reading: no error ends this process.
    socket.done.catchError((Object _) => socket);
    socket.add([...head.buffer.asUint8List(), ...challenge]);
    socket.listen((bytes) {
      if (bytes.length > 5) print(utf8.decode(bytes.sublist(5)));
      socket.destroy();
    }, onError: (Object _) {});
  });
}
''';

/// A process listening on a localhost port, which it prints.
const _tcpImpostor = r'''
import 'dart:io';

void main() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  print(server.port);
  server.listen((socket) {
    socket.done.catchError((Object _) => socket);
    socket.listen((_) {}, onError: (Object _) {});
  });
}
''';
