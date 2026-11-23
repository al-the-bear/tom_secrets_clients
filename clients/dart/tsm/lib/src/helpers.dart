// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The developer-tool helpers (part-os-integration): `git-credential-tsm`
/// and **[C]** `docker-credential-tsm`, further names of `tsm` (multi-call:
/// `tsm` reads the name it was started under), and `tsm integrations`, which
/// writes and removes the tools' configuration in marked blocks
/// (`TomSecretsIntegrations`). The AWS and kubectl helpers are `tsm`
/// commands (`aws-credentials`, `kube-credential`).
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'commands.dart';
import 'tsm_context.dart';
import 'tsm_io.dart';
import 'tsm_tool.dart' show tsmVersion;

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

/// `tsm integrations [status | install <kind> | uninstall <kind>]
/// [--hosts PATTERNS] [--profile NAME --ref REF] [--registry HOST]...
/// [--every-registry] [--json]` (part-os-integration, "Installing and
/// checking"): the ssh block (`IdentityAgent` of the service's agent, for
/// `Host *` or `--hosts`) in `~/.ssh/config`, the git block
/// (`credential.helper tsm`) in `~/.gitconfig` with `git-credential-tsm`
/// beside tsm; **[C]** the aws block (`credential_process` running
/// `tsm aws-credentials <ref>` per `--profile`) in `~/.aws/config`, and
/// Docker's `credHelpers` (`--registry`) or `credsStore`
/// (`--every-registry`) in `~/.docker/config.json` with
/// `docker-credential-tsm` beside tsm. `uninstall aws --profile` and
/// `uninstall docker --registry` remove one. Nothing outside the blocks (for
/// Docker: the product's keys) changes.
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
    final name = a.positionalAt(1, 'the integration (ssh, git, aws or docker)');
    return TomSecretsIntegration.values.firstWhere(
      (i) => i.name == name,
      orElse: () => throw TsmFailure.usage(
        'unknown integration $name: ssh, git, aws or docker',
      ),
    );
  }

  final profile = a.option('profile');
  final ref = a.option('ref');
  final registries = a.all('registry');
  final List<TomSecretsIntegrationState> states;
  try {
    switch (action) {
      case 'status':
        states = [
          for (final i in TomSecretsIntegration.values)
            await integrations.status(i),
        ];
      case 'install':
        final k = kind();
        if (k == TomSecretsIntegration.aws &&
            (profile == null) != (ref == null)) {
          throw TsmFailure.usage('--profile and --ref go together');
        }
        states = [
          await integrations.install(
            k,
            hosts: a.option('hosts'),
            awsProfiles: {if (profile != null && ref != null) profile: ref},
            dockerRegistries: registries,
            dockerEveryRegistry: a.flag('every-registry'),
          ),
        ];
      case 'uninstall':
        final k = kind();
        if (registries.length > 1) {
          throw TsmFailure.usage('uninstall takes one --registry');
        }
        states = [
          await integrations.uninstall(
            k,
            awsProfile: profile,
            dockerRegistry: registries.firstOrNull,
          ),
        ];
      default:
        throw TsmFailure.usage('integrations status, install or uninstall');
    }
  } on StateError catch (e) {
    throw TsmFailure.usage(e.message);
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
      '${s.integration.name.padRight(6)} $word  ${s.file}'
      '${s.hosts == null ? '' : '  (Host ${s.hosts})'}',
    );
    for (final MapEntry(key: name, value: r) in s.profiles.entries) {
      c.io.outln('       profile $name: $r');
    }
    for (final r in s.registries) {
      c.io.outln('       registry $r');
    }
    if (s.everyRegistry) c.io.outln('       every registry (credsStore)');
    for (final p in s.problems) {
      c.io.outln('     $p');
    }
  }
  return TsmExit.ok;
}

/// The name Docker runs the helper under (`credHelpers` value `tsm`).
const String tsmDockerCredentialName = tomSecretsDockerHelperName;

/// What a Docker credential helper prints when it has no credentials for a
/// registry: Docker knows this text (`credentials.errCredentialsNotFound`)
/// and goes on without them.
const String tsmDockerNotFound = 'credentials not found in native keychain';

/// The URL [serverUrl] (`ghcr.io`, `https://index.docker.io/v1/`) names
/// for `match`: https when it names no scheme.
String tsmRegistryUrl(String serverUrl) {
  final s = serverUrl.trim();
  return s.contains('://') ? s : 'https://$s';
}

/// **[C]** `docker-credential-tsm <get|list|store|erase|version>`
/// (part-os-integration, Docker's credential-helper protocol):
///
/// - `get`: the server URL on standard input; the login of that registry
///   the service's `match` with `pick` answers (the helper's grants decide,
///   else the user picks it in the app), printed as
///   `{"ServerURL":…,"Username":…,"Secret":…}`; none (nothing matches, the
///   user refuses, no service): [tsmDockerNotFound] and exit 1, and Docker
///   goes on without credentials.
/// - `list`: the registries `~/.docker/config.json` names the helper for,
///   each with the user name `match` finds there (no secret, no prompt):
///   `{"<server URL>":"<user name>"}`.
/// - `store` (`{"ServerURL","Username","Secret"}` on standard input):
///   proposed to the app when the vaults do not hold it; a known one is
///   ignored. Clients only read: the user saves it in the app (DP-52).
/// - `erase`: ignored; nothing is deleted.
/// - `version`: tsm's version.
Future<int> tsmDockerCredential(List<String> arguments, TsmIo io) async {
  final action = arguments.isEmpty ? '' : arguments.first;
  if (action == 'version') {
    io.out('$tsmDockerCredentialName (tsm $tsmVersion)\n');
    return 0;
  }
  final input = StringBuffer();
  if (action == 'get' || action == 'store' || action == 'erase') {
    while (true) {
      final line = await io.readLine();
      if (line == null) break;
      input.writeln(line);
    }
  }
  var waited = false;
  void waiting(TomSecretsProgress _) {
    if (waited) return;
    waited = true;
    io.err.writeln('waiting for Tom Secrets Manager…');
  }

  TomSecretsClient? client;
  Future<TomSecretsClient> connect() async =>
      client ??= await TomSecretsClient.connect(
        clientName: tsmDockerCredentialName,
        environment: io.environment,
      );
  try {
    switch (action) {
      case 'get':
        final server = input.toString().trim();
        if (server.isEmpty) {
          io.out('$tsmDockerNotFound\n');
          return 1;
        }
        try {
          final c = await connect();
          final found = await c.match(
            tsmRegistryUrl(server),
            pick: true,
            onProgress: waiting,
          );
          if (found.isEmpty) {
            io.out('$tsmDockerNotFound\n');
            return 1;
          }
          final login = found.first;
          final value = await c.get(login.entryId, onProgress: waiting);
          try {
            io.out(
              '${jsonEncode({'ServerURL': server, 'Username': login.userName, 'Secret': value.text})}\n',
            );
          } finally {
            value.dispose();
          }
          return 0;
        } on TomSecretsClientException {
          io.out('$tsmDockerNotFound\n');
          return 1;
        }
      case 'list':
        final listed = <String, String>{};
        for (final registry in _dockerRegistries(io.environment)) {
          try {
            final found = await (await connect()).match(
              tsmRegistryUrl(registry),
              wait: false,
            );
            if (found.isNotEmpty) listed[registry] = found.first.userName;
          } on TomSecretsClientException {
            // Not running, locked or not covered: not listed.
          }
        }
        io.out('${jsonEncode(listed)}\n');
        return 0;
      case 'store':
        final Object? json;
        try {
          json = jsonDecode(input.toString());
        } on FormatException {
          io.err.writeln('$tsmDockerCredentialName: store takes JSON');
          return 1;
        }
        if (json is Map &&
            json['ServerURL'] is String &&
            json['Username'] is String &&
            json['Secret'] is String) {
          try {
            await (await connect()).propose(
              url: tsmRegistryUrl(json['ServerURL'] as String),
              userName: json['Username'] as String,
              password: json['Secret'] as String,
              title: Uri.parse(
                tsmRegistryUrl(json['ServerURL'] as String),
              ).host,
            );
          } on TomSecretsClientException {
            // No app to propose to: Docker goes on.
          }
        }
        return 0;
      case 'erase':
        return 0;
      default:
        io.err.writeln(
          'usage: $tsmDockerCredentialName <get|list|store|erase|version>',
        );
        return 1;
    }
  } finally {
    await client?.close();
  }
}

/// The registries `~/.docker/config.json` names the helper for
/// (`credHelpers` value `tsm`).
List<String> _dockerRegistries(Map<String, String> environment) {
  final home = environment['HOME'] ?? environment['USERPROFILE'];
  if (home == null) return const [];
  final file = File(
    '$home${Platform.pathSeparator}.docker${Platform.pathSeparator}'
    'config.json',
  );
  if (!file.existsSync()) return const [];
  try {
    final json = jsonDecode(file.readAsStringSync());
    final helpers = json is Map ? json['credHelpers'] : null;
    return [
      if (helpers is Map)
        for (final e in helpers.entries)
          if (e.value == 'tsm') '${e.key}',
    ];
  } on FormatException {
    return const [];
  }
}
