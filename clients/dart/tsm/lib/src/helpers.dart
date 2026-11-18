// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The developer-tool helpers (part-os-integration): `git-credential-tsm`,
/// a second name of `tsm` (multi-call: `tsm` reads the name it was started
/// under), and `tsm integrations`, which writes and removes the tools'
/// configuration in marked blocks (`TomSecretsIntegrations`).
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'commands.dart';
import 'tsm_context.dart';
import 'tsm_io.dart';

/// The name git runs the helper under (`credential.helper tsm`).
const String tsmGitCredentialName = 'git-credential-tsm';

/// The name tsm was started under: [executable]'s file name (argv[0]),
/// without `.exe`.
String tsmInvokedName(String executable) {
  final name = executable.split(RegExp(r'[/\\]')).last;
  return name.toLowerCase().endsWith('.exe')
      ? name.substring(0, name.length - 4)
      : name;
}

/// `git-credential-tsm <get|store|erase>` (part-os-integration, DP-52,
/// DP-53): git writes `key=value` lines (`protocol`, `host`, `path`,
/// `username`, `password`) and a blank line to standard input.
///
/// - `get`: the login of `protocol://host[/path]` (with `username` when git
///   gives one) the service's `match` with `pick` answers: the one the
///   helper's grants decide, else the one the user picks in the app; its
///   password is read with `get` and `username=` and `password=` are
///   printed. Nothing matches, the user refuses, or the service is not
///   running: nothing is printed, and git asks its next helper or the user.
///   While the service is locked or the user is asked, "waiting for Tom
///   Secrets Manager…" goes to standard error (git shows a helper's).
/// - `store` (git saw the credential work): proposed to the app when the
///   vaults do not hold it; a known one is ignored. Clients only read: the
///   user saves the proposal in the app.
/// - `erase` (git saw it fail): ignored; a failed token is renewed in the
///   app.
///
/// The exit code is always 0: a helper that answers nothing lets git go on.
Future<int> tsmGitCredential(List<String> arguments, TsmIo io) async {
  final action = arguments.isEmpty ? '' : arguments.first;
  final input = <String, String>{};
  while (true) {
    final line = await io.readLine();
    if (line == null || line.isEmpty) break;
    final eq = line.indexOf('=');
    if (eq > 0) input[line.substring(0, eq)] = line.substring(eq + 1);
  }
  final protocol = input['protocol'];
  final host = input['host'];
  if ((action != 'get' && action != 'store') ||
      protocol == null ||
      host == null) {
    return 0;
  }
  final path = input['path'];
  final url = '$protocol://$host/${path ?? ''}';
  TomSecretsClient? client;
  var waited = false;
  void waiting(TomSecretsProgress _) {
    if (waited) return;
    waited = true;
    io.err.writeln('waiting for Tom Secrets Manager…');
  }

  try {
    client = await TomSecretsClient.connect(
      clientName: tsmGitCredentialName,
      environment: io.environment,
    );
    if (action == 'store') {
      final userName = input['username'];
      final password = input['password'];
      if (userName != null && password != null) {
        await client.propose(
          url: url,
          userName: userName,
          password: password,
          title: host,
        );
      }
      return 0;
    }
    final found = await client.match(
      url,
      userName: input['username'],
      pick: true,
      onProgress: waiting,
    );
    if (found.isEmpty) return 0;
    final login = found.first;
    final value = await client.get(login.entryId, onProgress: waiting);
    try {
      final userName = input['username'] ?? login.userName;
      io.out('username=$userName\n');
      io.out('password=');
      io.writeOut(value.bytes);
      io.out('\n');
    } finally {
      value.dispose();
    }
    return 0;
  } on TomSecretsClientException {
    // Not running, locked past the timeout, refused, unsupported: git falls
    // back to its next helper or a prompt.
    return 0;
  } finally {
    await client?.close();
  }
}

/// `tsm integrations [status | install <ssh|git> | uninstall <ssh|git>]
/// [--hosts PATTERNS] [--json]` (part-os-integration, "Installing and
/// checking"): the ssh block (`IdentityAgent` of the service's agent, for
/// `Host *` or `--hosts`) in `~/.ssh/config`, the git block
/// (`credential.helper tsm`) in `~/.gitconfig` with `git-credential-tsm`
/// beside tsm; nothing outside the blocks changes.
Future<int> tsmIntegrations(TsmContext c, TsmArgs a) async {
  final action = a.positional.isEmpty ? 'status' : a.positional.first;
  final env = c.io.environment;
  final home = env['HOME'] ?? env['USERPROFILE'];
  if (home == null || home.isEmpty) {
    throw TsmFailure.usage('no home folder (HOME or USERPROFILE)');
  }
  final windows = c.runtime.transport == TomSecretsTransport.tcp;
  final integrations = TomSecretsIntegrations(
    home: home,
    agentEndpoint: c.runtime.agentEndpoint,
    tsmExecutable:
        '${c.io.executableDirectory}${windows ? r'\' : '/'}'
        'tsm${windows ? '.exe' : ''}',
    operatingSystem: windows ? 'windows' : Platform.operatingSystem,
    path: env['PATH'],
  );
  TomSecretsIntegration kind() {
    final name = a.positionalAt(1, 'the integration (ssh or git)');
    return TomSecretsIntegration.values.firstWhere(
      (i) => i.name == name,
      orElse: () =>
          throw TsmFailure.usage('unknown integration $name: ssh or git'),
    );
  }

  final List<TomSecretsIntegrationState> states;
  switch (action) {
    case 'status':
      states = [
        for (final i in TomSecretsIntegration.values)
          await integrations.status(i),
      ];
    case 'install':
      states = [await integrations.install(kind(), hosts: a.option('hosts'))];
    case 'uninstall':
      states = [await integrations.uninstall(kind())];
    default:
      throw TsmFailure.usage('integrations status, install or uninstall');
  }
  if (a.flag('json')) {
    c.io.outln(jsonEncode([for (final s in states) s.toJson()]));
    return TsmExit.ok;
  }
  for (final s in states) {
    final word = !s.installed
        ? 'not installed'
        : s.current
        ? 'installed'
        : 'installed, needs repair';
    c.io.outln(
      '${s.integration.name.padRight(4)} $word  ${s.file}'
      '${s.hosts == null ? '' : '  (Host ${s.hosts})'}',
    );
    for (final p in s.problems) {
      c.io.outln('     $p');
    }
  }
  return TsmExit.ok;
}
