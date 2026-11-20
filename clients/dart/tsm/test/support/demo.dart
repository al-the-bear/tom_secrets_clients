// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A demo installation for tsm's tests: a primary vault naming a team vault,
/// both `file:` vaults under demo keys, a bootstrap in a scratch data
/// directory, a runtime directory; tsm run over captured input and output.
/// Demo data only.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomSecretStore;
import 'package:tom_kdbx_store/tom_kdbx_store.dart'
    show KdbxArgon2, KdbxArgon2Type;
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';
import 'package:tom_secrets_tsm/tom_secrets_tsm.dart';

/// The primary's demo master password.
const primaryPassword = 'primary-demo-pw';

/// The team vault's demo password.
const teamPassword = 'team-demo-pw';

/// A light Argon2id, so a test opens a vault in milliseconds.
const testArgon2 = KdbxArgon2(
  type: KdbxArgon2Type.argon2id,
  memory: 1 << 20,
  iterations: 1,
);

/// Allows every value (tsm's tests are not of the allow list).
final class AllowAll implements TomSecretsAccessPolicy {
  /// The policy.
  const AllowAll();

  @override
  Future<List<TomSecretsAccess>> check(TomSecretsAccessBatch batch) async => [
    for (final _ in batch.items) const TomSecretsAccessAllowed(),
  ];
}

/// The identity of this process, for TCP runs on Linux and macOS.
final class SelfMeasurer implements TomSecretsPeerMeasurer {
  /// The measurer.
  const SelfMeasurer();

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async =>
      TomSecretsPeerMeasured(tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!));
}

void _add(KdbxFile file, String group, String title, Map<String, String> f) {
  final parent =
      file.body.rootGroup.groups
          .where((g) => g.name.get() == group)
          .firstOrNull ??
      file.createGroup(parent: file.body.rootGroup, name: group);
  final entry = KdbxEntry.create(file, parent)
    ..setString(KdbxKeyCommon.TITLE, PlainValue(title));
  for (final MapEntry(:key, :value) in f.entries) {
    entry.setString(
      KdbxKey(key),
      key == 'Password' ? ProtectedValue.fromString(value) : PlainValue(value),
    );
  }
  parent.addEntry(entry);
}

/// The output of one tsm run.
final class TsmRun {
  /// What it wrote and its exit [code].
  TsmRun(this.code, this.out, this.err);

  /// The exit code.
  final int code;

  /// Standard output, as bytes.
  final Uint8List out;

  /// Standard error.
  final String err;

  /// Standard output as text.
  String get text => utf8.decode(out);

  @override
  String toString() => 'TsmRun($code, out: "$text", err: "$err")';
}

/// A demo installation in a temporary directory (the system's: a Unix
/// socket path is limited to 104 bytes on macOS).
final class Demo {
  Demo._(this.dir);

  /// Makes the vaults and the bootstrap.
  static Future<Demo> create({List<String> adminExecutables = const []}) async {
    final dir = Directory.systemTemp.createTempSync('tsm');
    addTearDown(() => deleteWhenFree(dir));
    final demo = Demo._(dir.path);
    final team = tomSecretsNewVault(
      Credentials(ProtectedValue.fromString(teamPassword)),
      'team',
      argon2: testArgon2,
    );
    _add(team, 'Api', 'Token', {'Password': 'demo-api-token'});
    // A login git's credential helper finds by its host.
    _add(team, 'Code', 'Example git', {
      'URL': 'https://git.example.com',
      'UserName': 'demo-git-user',
      'Password': 'demo-git-token',
    });
    final logo = KdbxEntry.create(team, team.body.rootGroup)
      ..setString(KdbxKeyCommon.TITLE, PlainValue('Logo'))
      ..setString(const KdbxKey('tsm.key'), PlainValue('demo.logo'));
    team.body.rootGroup.addEntry(logo);
    await File(demo.teamPath).writeAsBytes(await team.save());

    final primary = tomSecretsNewVault(
      Credentials(ProtectedValue.fromString(primaryPassword)),
      'primary',
      argon2: testArgon2,
    );
    _add(primary, 'Db', 'Main', {
      'Password': 'demo-db-pw',
      'UserName': 'demo-user',
    });
    TomSecretsPrimaryVaults(primary).put(
      TomSecretsVaultKeys(
        name: 'team',
        locator: 'file:${demo.teamPath}',
        password: teamPassword,
      ),
    );
    await File(demo.primaryPath).writeAsBytes(await primary.save());
    Directory(demo.dataDirectory).createSync();
    File(demo.bootstrapPath).writeAsStringSync(
      'primary: file:${demo.primaryPath}\n'
      'device_key: keyfile\n'
      'runtime_dir: ${demo.runtimeDirectory}\n'
      'host: demo-host\n'
      '${adminExecutables.isEmpty ? '' : 'admin_executables:\n${[for (final e in adminExecutables) '  - $e\n'].join()}'}',
    );
    return demo;
  }

  /// **[C]** Adds a typed certificate entry [title] to the vault file of
  /// [store] (`team`), before the service starts; answers it.
  Future<TomSecretsGeneratedCertificate> addCertificate(
    String store,
    String title,
  ) async {
    final path = store == 'team' ? teamPath : primaryPath;
    final credentials = Credentials(
      ProtectedValue.fromString(store == 'team' ? teamPassword : primaryPassword),
    );
    final file = await KdbxFormat().read(
      File(path).readAsBytesSync(),
      credentials,
    );
    final cert = tomSecretsGenerateCertificate(commonName: 'web.example');
    final entry = KdbxEntry.create(file, file.body.rootGroup)
      ..setString(KdbxKeyCommon.TITLE, PlainValue(title));
    file.body.rootGroup.addEntry(entry);
    tomSecretsWriteCertificate(
      entry,
      certificatePem: cert.certificatePem,
      privateKeyPem: cert.privateKeyPem,
    );
    File(path).writeAsBytesSync(await file.save());
    return cert;
  }

  /// The directory.
  final String dir;

  /// The primary vault's file.
  String get primaryPath => '$dir/primary.kdbx';

  /// The team vault's file.
  String get teamPath => '$dir/team.kdbx';

  /// The data directory (`TSM_DATA_DIR`).
  String get dataDirectory => '$dir/data';

  /// The bootstrap file in it.
  String get bootstrapPath => '$dataDirectory/bootstrap.yaml';

  /// The runtime directory (`TSM_RUNTIME_DIR`).
  String get runtimeDirectory => '$dir/run';

  /// The runtime directory as the admin side reads it.
  TomSecretsRuntime get runtime =>
      TomSecretsRuntime(runtimeDirectory, transport: transport);

  /// The transport of this OS.
  TomSecretsTransport get transport =>
      Platform.isWindows ? TomSecretsTransport.tcp : TomSecretsTransport.unix;

  /// Variables a test adds to tsm's environment (`HOME`, `PATH`).
  Map<String, String> environmentOverrides = const {};

  /// The environment tsm runs with.
  Map<String, String> get environment => {
    ...Platform.environment,
    'TSM_RUNTIME_DIR': runtimeDirectory,
    'TSM_DATA_DIR': dataDirectory,
    ...environmentOverrides,
  };

  /// Starts the service in this process (the in-process half of the tests;
  /// the integration suite starts the binary).
  Future<TomSecretsService> startInProcess({
    required Uint8List adminKey,
    TomSecretsAccessPolicy? policy = const AllowAll(),
    Set<String>? helperExecutables,
    TomSecretStore? keychain,
    http.Client? githubClient,
  }) async {
    final service = await TomSecretsService.launch(
      TomSecretsServiceConfig(
        runtime: TomSecretsRuntime(runtimeDirectory, transport: transport),
        bootstrap: await TomSecretsBootstrap.read(bootstrapPath),
        adminKey: adminKey,
        policy: policy,
        host: 'demo-host',
        helperExecutables: helperExecutables,
        keychain: keychain,
        githubClient: githubClient,
        authDelay: (n) => Duration(milliseconds: 10 * n),
        peerMeasurer:
            transport == TomSecretsTransport.tcp && !Platform.isWindows
            ? const SelfMeasurer()
            : null,
      ),
    );
    addTearDown(service.stop);
    return service;
  }

  /// Runs tsm with [args]: [keychain] (null: none answers), [stdinLines]
  /// for `--password-stdin` and `approve -`, [password] for the terminal
  /// prompt, [run] for `tsm run`'s command.
  Future<TsmRun> tsm(
    List<String> args, {
    TomSecretStore? keychain,
    List<String> stdinLines = const [],
    String? password = primaryPassword,
    Future<int> Function(List<String>, Map<String, String>)? run,
    String executableDirectory = '/nonexistent',
    DateTime Function()? clock,
  }) async {
    final out = BytesBuilder();
    final err = StringBuffer();
    final lines = [...stdinLines];
    var prompts = 0;
    final code = await tsmMain(
      args,
      TsmIo(
        writeOut: out.add,
        err: err,
        readSecret: (prompt) async {
          prompts++;
          err.write(prompt);
          return password;
        },
        readLine: () async => lines.isEmpty ? null : lines.removeAt(0),
        environment: environment,
        keychain: () async => keychain,
        executableDirectory: executableDirectory,
        runCommand: run ?? (command, env) async => 0,
        clock: clock,
      ),
    );
    passwordPrompts = prompts;
    return TsmRun(code, out.takeBytes(), err.toString());
  }

  /// Runs tsm as `git-credential-tsm` with [args], git's [input] lines on
  /// standard input.
  Future<TsmRun> gitCredential(List<String> args, List<String> input) async {
    final out = BytesBuilder();
    final err = StringBuffer();
    final lines = [...input];
    final code = await tsmGitCredential(
      args,
      TsmIo(
        writeOut: out.add,
        err: err,
        readSecret: (_) async => null,
        readLine: () async => lines.isEmpty ? null : lines.removeAt(0),
        environment: environment,
        keychain: () async => null,
        executableDirectory: '/nonexistent',
        runCommand: (command, env) async => 0,
      ),
    );
    return TsmRun(code, out.takeBytes(), err.toString());
  }

  /// How often the last [tsm] run asked for the password on the terminal.
  int passwordPrompts = 0;
}

/// Deletes [dir], retrying while Windows still holds a file in it (a
/// service process that answered `shutdown` keeps its files until it has
/// exited).
Future<void> deleteWhenFree(Directory dir) async {
  for (var attempt = 0; ; attempt++) {
    if (!dir.existsSync()) return;
    try {
      dir.deleteSync(recursive: true);
      return;
    } on FileSystemException {
      if (attempt >= 100) rethrow;
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }
}
