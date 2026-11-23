// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// tsm against the service in this process (part-clients): reading (`get`,
/// `run`, `ref`), the admin commands with the admin key from the keychain or
/// a `claim` with the master password (DP-22), and the exit codes scripts
/// tell the cases apart by. The integration suite runs the built service.
/// Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomInMemorySecretStore;
import 'package:tom_secrets_service/tom_secrets_service.dart';
import 'package:tom_secrets_tsm/tom_secrets_tsm.dart' show tsmPairingAddress;

import 'support/demo.dart';

void main() {
  late Demo demo;
  late TomSecretsService service;
  late TomInMemorySecretStore keychain;

  /// A service, unlocked, its admin key in the keychain as `tsm start`
  /// leaves it.
  Future<void> running({bool unlock = true}) async {
    final key = tomSecretsRandomBytes();
    service = await demo.startInProcess(adminKey: key);
    await keychain.write(
      tomSecretsAdminKeyHandle(service.startedAt),
      base64.encode(key),
    );
    if (unlock) {
      expect((await demo.tsm(['unlock'], keychain: keychain)).code, 0);
    }
  }

  setUp(() async {
    demo = await Demo.create();
    keychain = TomInMemorySecretStore();
  });

  group('reading', () {
    test('get prints the value as it is, no line break unless -n', () async {
      await running();
      var r = await demo.tsm(['get', 'primary/Db/Main']);
      expect(r.code, 0, reason: '$r');
      expect(r.text, 'demo-db-pw');
      r = await demo.tsm([
        'get',
        'primary/Db/Main',
        '--field',
        'UserName',
        '-n',
      ]);
      expect(r.text, 'demo-user\n');
      r = await demo.tsm(['get', 'team/Api/Token', '--base64']);
      expect(utf8.decode(base64.decode(r.text)), 'demo-api-token');
    });

    test('the exit codes tell the cases apart', () async {
      var r = await demo.tsm(['get', 'primary/Db/Main']);
      expect(r.code, 3, reason: 'not_running');
      expect(r.out, isEmpty);
      await running(unlock: false);
      r = await demo.tsm(['get', 'primary/Db/Main', '--no-wait']);
      expect(r.code, 4, reason: 'locked: $r');
      expect(r.err, contains('locked'));
      await demo.tsm(['unlock'], keychain: keychain);
      r = await demo.tsm(['get', 'primary/Db/Nothing']);
      expect(r.code, 6, reason: 'not_found');
      r = await demo.tsm(['get', 'not a ref']);
      expect(r.code, 8, reason: 'malformed');
      r = await demo.tsm(['get']);
      expect(r.code, 2, reason: 'usage');
      r = await demo.tsm(['get', 'primary/Db/Main', '--timeout', 'soon']);
      expect(r.code, 2);
    });

    test('run fetches every reference at once and starts the command with '
        'them in its environment; its exit code is tsm\'s', () async {
      await running();
      final envFile = File('${demo.dir}/app.env')
        ..writeAsStringSync('# no secrets here\nTEAM_TOKEN=team/Api/Token\n');
      List<String>? command;
      Map<String, String>? environment;
      final r = await demo.tsm(
        [
          'run',
          '--map',
          'DB_PW=primary/Db/Main',
          '--env-file',
          envFile.path,
          '--',
          'deploy',
          '-v',
          '--prod',
        ],
        run: (cmd, env) async {
          command = cmd;
          environment = env;
          return 142;
        },
      );
      expect(r.code, 142, reason: 'the command\'s own, above 125 too');
      expect(command, ['deploy', '-v', '--prod']);
      expect(environment, {
        'DB_PW': 'demo-db-pw',
        'TEAM_TOKEN': 'demo-api-token',
      });
      expect(r.out, isEmpty);
    });

    test('run does not start the command when a reference fails', () async {
      await running();
      var started = false;
      var r = await demo.tsm(
        [
          'run',
          '--map',
          'A=primary/Db/Main',
          '--map',
          'B=primary/X',
          '--',
          'x',
        ],
        run: (_, _) async {
          started = true;
          return 0;
        },
      );
      expect(r.code, 6);
      expect(started, isFalse);
      expect(r.err, contains('B:'));
      r = await demo.tsm(['run', '--map', 'A=primary/Db/Main']);
      expect(r.code, 2, reason: 'no command after --');
      r = await demo.tsm(['run', '--map', '1A=primary/Db/Main', '--', 'x']);
      expect(r.code, 2, reason: 'no variable name');
      r = await demo.tsm(['run', '--file', 'A=team/Nothing', '--', 'x']);
      expect(r.code, 6, reason: 'no such entry');
      expect(r.err, contains('A:'));
    });

    test('run --file: a certificate\'s private key as a temporary file only '
        'this user reads, gone when the command ends', () async {
      final cert = await demo.addCertificate('team', 'Web');
      await running();
      String? keyPath;
      String? keyText;
      String? certText;
      int? mode;
      int? dirMode;
      final r = await demo.tsm(
        [
          'run',
          '--file',
          'TLS_KEY=team/Web',
          '--map',
          'TOKEN=team/Api/Token',
          '--',
          'server',
        ],
        run: (cmd, env) async {
          keyPath = env['TLS_KEY'];
          keyText = File(keyPath!).readAsStringSync();
          mode = File(keyPath!).statSync().mode & 0x1ff;
          dirMode = File(keyPath!).parent.parent.statSync().mode & 0x1ff;
          certText = env['TOKEN'];
          return 0;
        },
      );
      expect(r.code, 0, reason: '$r');
      expect(keyText, cert.privateKeyPem);
      expect(keyPath, endsWith('${Platform.pathSeparator}private-key.pem'));
      expect(certText, 'demo-api-token');
      if (!Platform.isWindows) {
        expect(mode, 0x180, reason: 'rw------- for the user alone');
        expect(dirMode, 0x1c0, reason: 'rwx------');
      }
      expect(File(keyPath!).existsSync(), isFalse);
      expect(File(keyPath!).parent.parent.existsSync(), isFalse);
    });

    test('ref parse and ref format', () async {
      var r = await demo.tsm([
        'ref',
        'parse',
        '[env:prod]fleet/Db/Main#UserName',
      ]);
      expect(r.code, 0);
      final parsed = jsonDecode(r.text) as Map;
      expect(parsed['canonical'], '[env:prod]fleet/Db/Main#UserName');
      expect(parsed['target'], {
        'kind': 'path',
        'store': 'fleet',
        'segments': ['Db', 'Main'],
      });
      expect(parsed['qualifiers'], [
        {'dimension': 'env', 'value': 'prod'},
      ]);
      r = await demo.tsm([
        'ref',
        'format',
        '--store',
        'fleet',
        '--path',
        'Db',
        '--path',
        'Main#1',
        '--field',
        'UserName',
      ]);
      expect(r.text, 'fleet/Db/Main%231#UserName\n');
      r = await demo.tsm(['ref', 'format', '--key', 'telegram.bot_token']);
      expect(r.text, 'telegram.bot_token\n');
      expect((await demo.tsm(['ref', 'parse', 'a//b'])).code, 8);
      expect((await demo.tsm(['ref', 'nonsense'])).code, 2);
    });
  });

  group('administering', () {
    test('unlock, status, lock and stop with the keychain\'s admin key: '
        'no password asked but for the unlock', () async {
      // Keys of two services that are gone, kept with their index.
      final keyring = TomSecretsAdminKeyring(
        read: keychain.read,
        write: keychain.write,
        delete: keychain.delete,
      );
      await keyring.keep(111, tomSecretsRandomBytes());
      await keyring.keep(222, tomSecretsRandomBytes());
      await running(unlock: false);
      var r = await demo.tsm(['unlock'], keychain: keychain);
      expect(r.code, 0, reason: '$r');
      expect(r.text, 'unlocked\n');
      expect(demo.passwordPrompts, 1);
      expect(await keychain.read(tomSecretsAdminKeyHandle(111)), isNull);
      expect(await keychain.read(tomSecretsAdminKeyHandle(222)), isNull);
      expect(await keyring.recorded(), isEmpty, reason: 'the gone pruned');
      r = await demo.tsm(['status'], keychain: keychain);
      expect(r.code, 0);
      expect(demo.passwordPrompts, 0);
      expect(r.text, contains('service  running, unlocked'));
      expect(r.text, contains('store    primary  current  file'));
      expect(r.text, contains('store    team  current  file'));
      if (!Platform.isWindows) {
        // The ssh-agent's socket, for SSH_AUTH_SOCK (protocol.md 7.6).
        expect(r.text, contains('agent    ${demo.runtime.agentSocket}'));
      }
      final json =
          jsonDecode(
                (await demo.tsm(['status', '--json'], keychain: keychain)).text,
              )
              as Map;
      expect(json['locked'], isFalse);
      expect((json['stores'] as List).length, 2);
      r = await demo.tsm(['lock'], keychain: keychain);
      expect(r.text, 'locked\n');
      expect(service.isLocked, isTrue);
      final start = service.startedAt;
      expect(await keychain.read(tomSecretsAdminKeyHandle(start)), isNotNull);
      r = await demo.tsm(['stop'], keychain: keychain);
      expect(r.text, 'stopped\n');
      await service.done;
      expect(
        await keychain.read(tomSecretsAdminKeyHandle(start)),
        isNull,
        reason: 'stop removes the stopped service\'s key',
      );
      r = await demo.tsm(['status'], keychain: keychain);
      expect(r.code, 3);
      expect(r.text, 'not running\n');
    });

    test('without a keychain each admin command claims with the master '
        'password (asked once); with one the claimed key is kept', () async {
      await running(unlock: false);
      var r = await demo.tsm(['unlock']);
      expect(r.code, 0, reason: '$r');
      expect(demo.passwordPrompts, 1, reason: 'one password: claim + unlock');
      r = await demo.tsm(['status']);
      expect(demo.passwordPrompts, 1, reason: 'claimed again');
      r = await demo.tsm(['status'], password: 'wrong');
      expect(r.code, 5, reason: 'denied: $r');
      r = await demo.tsm(
        ['--password-stdin', 'lock'],
        password: null,
        stdinLines: [primaryPassword],
      );
      expect(r.code, 0, reason: '$r');
      expect(demo.passwordPrompts, 0);
      // The keychain's key was revoked by the claims: claim, keep the new one.
      final fresh = TomInMemorySecretStore();
      r = await demo.tsm(['status'], keychain: fresh);
      expect(demo.passwordPrompts, 1);
      r = await demo.tsm(['status'], keychain: fresh);
      expect(r.code, 0);
      expect(demo.passwordPrompts, 0, reason: 'the kept key');
      expect(
        await fresh.read(tomSecretsAdminKeyIndexHandle),
        '${service.startedAt}',
        reason: 'a kept key is in the index',
      );
    });

    test('keys, approvals, reload and approve without a token', () async {
      await running();
      var r = await demo.tsm(['keys'], keychain: keychain);
      expect(r.code, 0);
      expect(r.text, contains('approver-key:demo-host  approver_key'));
      final keys =
          jsonDecode(
                (await demo.tsm(['keys', '--json'], keychain: keychain)).text,
              )
              as List;
      expect(keys.map((k) => (k as Map)['kind']), contains('link_key'));
      r = await demo.tsm(['approvals'], keychain: keychain);
      expect(r.text, 'no request waits\n');
      r = await demo.tsm(['reload'], keychain: keychain);
      expect(r.text, 'reloaded\n');
      r = await demo.tsm(['approve'], keychain: keychain);
      expect(r.code, 0);
      expect(r.text, contains('reloaded'));
    });

    test('approve takes a 26-character base32 token, or - for standard '
        'input; a token for no waiting request is denied', () async {
      await running();
      var r = await demo.tsm(['approve', 'short'], keychain: keychain);
      expect(r.code, 2);
      r = await demo.tsm([
        'approve',
        'abcd-efgh ijkl-mnop-qrst-uvwx-yz',
      ], keychain: keychain);
      expect(r.code, 5, reason: 'normalised, then denied: $r');
      expect(r.err, contains('bad_token'));
      r = await demo.tsm(
        ['approve', '-'],
        keychain: keychain,
        stdinLines: ['ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
      );
      expect(r.code, 5);
    });

    test('grants: allow, list, revoke', () async {
      await running();
      var r = await demo.tsm([
        'allow',
        'bigbeast',
        'exe /usr/bin/demo',
        'primary/Db/Main',
      ], keychain: keychain);
      expect(r.code, 0, reason: '$r');
      final grants =
          jsonDecode(
                (await demo.tsm([
                  'grants',
                  '--json',
                  '--host',
                  'bigbeast',
                ], keychain: keychain)).text,
              )
              as List;
      final grant = grants.single as Map;
      expect(grant['subject'], 'exe /usr/bin/demo');
      r = await demo.tsm(['grants'], keychain: keychain);
      expect(r.text, contains('bigbeast  allow  exe /usr/bin/demo'));
      r = await demo.tsm([
        'grants',
        'revoke',
        'bigbeast',
        grant['id'] as String,
      ], keychain: keychain);
      expect(r.text, 'revoked\n');
      expect(
        (await demo.tsm(['grants', 'nonsense'], keychain: keychain)).code,
        2,
      );
    });

    test('audit, compact and start report what they cannot do', () async {
      await running();
      var r = await demo.tsm(['audit', '--json'], keychain: keychain);
      expect(r.code, 0, reason: '$r');
      expect(jsonDecode(r.text), isA<List>());
      r = await demo.tsm(['compact', 'al-the-bear/vaults'], keychain: keychain);
      expect(r.code, 6, reason: 'no github: vault there');
      r = await demo.tsm(['start'], keychain: keychain);
      expect(r.code, 6, reason: 'no service executable: $r');
      expect(r.err, contains('no service executable'));
      File(demo.bootstrapPath).deleteSync();
      r = await demo.tsm(['start'], keychain: keychain);
      expect(r.code, 6);
      expect(r.err, contains('no bootstrap file'));
    });

    test('pair reports what it cannot do before anything runs', () async {
      var r = await demo.tsm(['pair', '10.8.0.7', '7-guitar-orbit']);
      expect(r.code, 2, reason: 'no port: $r');
      expect(r.err, contains('host:port'));
      r = await demo.tsm(['pair', '10.8.0.7:47900']);
      expect(r.code, 2, reason: 'no code: $r');
      r = await demo.tsm(['pair', '10.8.0.7:47900', '7-guitar-orbit']);
      expect(r.code, 5, reason: 'set up already: $r');
      expect(r.err, contains('set up already'));
      File(demo.bootstrapPath).deleteSync();
      r = await demo.tsm(['pair', '10.8.0.7:47900', '7-guitar-orbit']);
      expect(r.code, 6, reason: 'no service executable: $r');
      expect(r.err, contains('no service executable'));
      for (final bad in ['0.0.0.0:47731', '10.8.0.1', '[::]:47731']) {
        r = await demo.tsm([
          'pair',
          '10.8.0.7:47900',
          '7-guitar-orbit',
          '--link',
          bad,
        ]);
        expect(r.code, 2, reason: 'a link that is no approval link: $r');
        expect(r.err, contains('approval link'));
      }
      // Through a relay (part-relay): the token only from the environment.
      r = await demo.tsm([
        'pair',
        '42-guitar-orbit',
        '--relay',
        'github:demo-owner/demo-vaults',
      ]);
      expect(r.code, 2, reason: 'no --token-env: $r');
      expect(r.err, contains('--token-env'));
      r = await demo.tsm([
        'pair',
        '42-guitar-orbit',
        '--relay',
        'github:demo-owner/demo-vaults',
        '--token-env',
        'TSM_TEST_NO_SUCH_VARIABLE',
      ]);
      expect(r.code, 2, reason: 'no token in the variable: $r');
      expect(r.err, contains('TSM_TEST_NO_SUCH_VARIABLE holds no token'));
      demo.environmentOverrides = {'TSM_PAIR_TOKEN': 'github_pat_demo'};
      r = await demo.tsm([
        'pair',
        '42-guitar-orbit',
        '--relay',
        'tsm:https://relay.example',
        '--token-env',
        'TSM_PAIR_TOKEN',
      ]);
      expect(r.code, 2, reason: 'not a GitHub relay: $r');
      expect(r.err, contains('github:<owner>/<repo>'));
      r = await demo.tsm([
        'pair',
        '10.8.0.7:47900',
        '42-guitar-orbit',
        '--token-env',
        'TSM_PAIR_TOKEN',
      ]);
      expect(r.code, 2, reason: '--token-env without --relay: $r');
      r = await demo.tsm([
        'pair',
        '42-guitar-orbit',
        '--relay',
        'github:demo-owner/demo-vaults',
        '--token-env',
        'TSM_PAIR_TOKEN',
      ]);
      expect(r.code, 6, reason: 'the relay alone, no service here: $r');
      expect(r.err, contains('no service executable'));
      demo.environmentOverrides = const {};
      expect(tsmPairingAddress('[fd00::7]:47900'), ('fd00::7', 47900));
      expect(tsmPairingAddress('mbp.local:1'), ('mbp.local', 1));
      for (final bad in [':1', 'a:0', 'a:65536', 'a b:1', '10.8.0.7']) {
        expect(tsmPairingAddress(bad), isNull, reason: bad);
      }
    });

    test('help names the commands as they are typed', () async {
      final r = await demo.tsm(['--help']);
      expect(r.err, contains('tsm [global-options] command'));
      expect(r.err, contains('  get\n'));
      expect(r.err, isNot(contains(':get')));
      expect(r.out, isEmpty);
    });
  });
}
