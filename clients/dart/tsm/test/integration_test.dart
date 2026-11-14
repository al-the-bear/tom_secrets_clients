// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The integration suite against the real service (part-clients, "Against
/// the real service"): the service built as its binary (`dart build cli`),
/// started through `tsm start` with the admin-key handover, on demo vaults
/// in a scratch data directory, its default approvals in force; tsm and the
/// Dart client then read through it, wait on it, lose it and find it again.
/// The fake service proves the protocol, this proves the service keeps to
/// it. Run by `tom_secrets_build :integration` (`dart test --tags
/// integration`); `:test` leaves it out. Demo data only.
@Tags(['integration'])
@TestOn('vm')
@Timeout(Duration(minutes: 6))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomInMemorySecretStore;
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart'
    show tomSecretsIdentityOf, tomSecretsProcessInfo;
import 'package:tom_secrets_tsm/tom_secrets_tsm.dart' show tsmRunInheriting;

import 'support/demo.dart';

/// The service's package, beside this one's repository.
final String _servicePackage = Directory(
  '../../../../secrets_manager/tom_secrets_service',
).absolute.path;

void main() {
  late String serviceExe;
  late Directory build;

  setUpAll(() async {
    build = Directory.systemTemp.createTempSync('tsm_service_build');
    final result = await Process.run(Platform.resolvedExecutable, [
      'build',
      'cli',
      '--target',
      'bin/tom_secrets_service.dart',
      '-o',
      build.path,
    ], workingDirectory: _servicePackage);
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    serviceExe =
        '${build.path}/bundle/bin/tom_secrets_service'
        '${Platform.isWindows ? '.exe' : ''}';
    expect(File(serviceExe).existsSync(), isTrue);
  });

  tearDownAll(() => deleteWhenFree(build));

  test('tsm starts and unlocks the real service; tsm and the client read '
      'through it, wait on it, lose it and find it again', () async {
    // This process administers it (the test is no `tsm` beside the
    // service): named in the bootstrap's admin_executables.
    final self = tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!);
    final demo = await Demo.create(adminExecutables: [self.exe]);
    final keychain = TomInMemorySecretStore();
    Future<TsmRun> tsm(List<String> args) =>
        demo.tsm(args, keychain: keychain, executableDirectory: build.path);
    addTearDown(() async {
      await tsm(['stop']);
      await _gone(demo);
    });

    var r = await tsm(['start', '--unlock', '--service', serviceExe]);
    expect(r.code, 0, reason: '$r');
    expect(r.text, 'started\nunlocked\n');
    r = await tsm(['start', '--service', serviceExe]);
    expect(r.text, 'already running\n');
    r = await tsm(['status']);
    expect(r.text, contains('service  running, unlocked'));

    // The default approvals: this process may read once it has a grant.
    r = await tsm([
      'allow',
      'demo-host',
      self.kind == 'script'
          ? 'script ${self.interpreter} ${self.script}'
          : 'exe ${self.exe}',
      'all',
    ]);
    expect(r.code, 0, reason: '$r');

    r = await tsm(['get', 'primary/Db/Main']);
    expect(r.code, 0, reason: '$r');
    expect(r.text, 'demo-db-pw');

    final client = await TomSecretsClient.connect(
      clientName: 'integration',
      environment: demo.environment,
    );
    addTearDown(client.close);
    final many = await client.getMany(const [
      TomSecretRequest('primary/Db/Main', field: 'UserName'),
      TomSecretRequest('team/Api/Token'),
      TomSecretRequest('team/Api/Nothing'),
    ]);
    expect(many[0].value!.text, 'demo-user');
    expect(many[1].value!.text, 'demo-api-token');
    expect(many[2].error!.kind, TomSecretsErrorKind.notFound);

    // Locked with no one attached: answered `locked` at once (a headless
    // host). With an admin attached (the app) a request waits, tells so,
    // and is answered after the unlock.
    expect((await tsm(['lock'])).code, 0);
    await expectLater(
      client.get('team/Api/Token'),
      throwsA(
        isA<TomSecretsClientException>().having(
          (e) => e.kind,
          'kind',
          TomSecretsErrorKind.locked,
        ),
      ),
    );
    final start = (await demo.runtime.readInfo())!['start']! as int;
    final app = await TomSecretsAdminClient.connect(
      demo.runtime,
      base64.decode((await keychain.read(tomSecretsAdminKeyHandle(start)))!),
    );
    await app.request('subscribe');
    final progress = <TomSecretsPending>[];
    final waiting = client.get(
      'team/Api/Token',
      onProgress: (p) => progress.add(p.pending),
    );
    await Future<void>.delayed(const Duration(milliseconds: 500));
    expect((await tsm(['unlock'])).code, 0);
    expect((await waiting).text, 'demo-api-token');
    expect(progress, [TomSecretsPending.unlock]);
    await app.close();

    // tsm run, with a real child process.
    final out = File('${demo.dir}/run.out');
    final script = File('${demo.dir}/print_env.dart')
      ..writeAsStringSync(
        "import 'dart:io';\n"
        "void main() { File(r'${out.path}')"
        ".writeAsStringSync(Platform.environment['DB_PW'] ?? '-'); exit(7); }\n",
      );
    r = await demo.tsm(
      [
        'run',
        '--map',
        'DB_PW=primary/Db/Main',
        '--',
        Platform.resolvedExecutable,
        script.path,
      ],
      keychain: keychain,
      run: tsmRunInheriting,
    );
    expect(r.code, 7, reason: '$r');
    expect(out.readAsStringSync(), 'demo-db-pw');

    // Stopped: not_running, for tsm (3) and for the client.
    expect((await tsm(['stop'])).text, 'stopped\n');
    await _gone(demo);
    expect((await tsm(['get', 'primary/Db/Main'])).code, 3);
    await expectLater(
      client.get('primary/Db/Main'),
      throwsA(
        isA<TomSecretsClientException>().having(
          (e) => e.kind,
          'kind',
          TomSecretsErrorKind.notRunning,
        ),
      ),
    );

    // Started again (a new admin key, kept in the keychain): the same
    // client finds the new service; the grant is in the primary vault.
    r = await tsm(['start', '--unlock', '--service', serviceExe]);
    expect(r.code, 0, reason: '$r');
    expect((await client.get('primary/Db/Main')).text, 'demo-db-pw');
  });
}

/// Waits until the service's runtime files are gone.
Future<void> _gone(Demo demo) async {
  final info = File('${demo.runtimeDirectory}/service.json');
  for (var i = 0; i < 100 && info.existsSync(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
}
