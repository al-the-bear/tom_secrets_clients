// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// tsm's commands (part-clients): reading (`get`, `run`, `ref`) on the
/// client endpoint, setting a machine up by pairing (`pair`), administering
/// (`start`, `unlock`, `lock`, `stop`,
/// `status`, `reload`, `keys`, `approvals`, `approve`, `approve-code`,
/// `grants`, `allow`, `audit`, `compact`) on the admin endpoint. Each answers
/// its exit code ([TsmExit]); values go to standard output as they are,
/// everything else is told on standard error or, for the admin commands,
/// printed as lines (or JSON with `--json`).
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'tsm_context.dart';

/// The options and positional arguments a command was given.
final class TsmArgs {
  /// [positional] arguments, [options] by name, and the command line after
  /// `--` ([passthrough]).
  const TsmArgs({
    this.positional = const [],
    this.options = const {},
    this.passthrough = const [],
  });

  /// The positional arguments after the command.
  final List<String> positional;

  /// The options by long name.
  final Map<String, Object?> options;

  /// Everything after `--`.
  final List<String> passthrough;

  /// The single value of [name], or null.
  String? option(String name) {
    final v = options[name];
    if (v is List) return v.isEmpty ? null : '${v.last}';
    return v?.toString();
  }

  /// Every value of the repeatable [name].
  List<String> all(String name) {
    final v = options[name];
    if (v == null) return const [];
    if (v is List) return [for (final x in v) '$x'];
    return ['$v'];
  }

  /// Whether the flag [name] is set.
  bool flag(String name) => options[name] == true;

  /// The positional argument at [index], or a usage error naming [what].
  String positionalAt(int index, String what) {
    if (index >= positional.length) {
      throw TsmFailure.usage('missing $what');
    }
    return positional[index];
  }
}

/// `--dim name=value` options as a map.
Map<String, String>? _dimensions(TsmArgs a) {
  final dims = a.all('dim');
  if (dims.isEmpty) return null;
  return {for (final d in dims) _pair(d, 'dim').$1: _pair(d, 'dim').$2};
}

(String, String) _pair(String text, String option) {
  final i = text.indexOf('=');
  if (i <= 0 || i == text.length - 1) {
    throw TsmFailure.usage('--$option takes name=value, not "$text"');
  }
  return (text.substring(0, i), text.substring(i + 1));
}

Future<TomSecretsClient> _client(TsmContext c) =>
    TomSecretsClient.connect(clientName: 'tsm', environment: c.io.environment);

void _progress(TsmContext c, TomSecretsProgress p) {
  switch (p.pending) {
    case TomSecretsPending.unlock:
      c.io.err.writeln('tsm: waiting for the service to be unlocked…');
    case TomSecretsPending.approval:
      final code = p.approvalCode;
      c.io.err.writeln(
        code == null
            ? 'tsm: waiting for approval in Tom Secrets Manager…'
            : 'tsm: waiting for approval: approve code $code on a trusted '
                  'device, then run `tsm approve <token>` here',
      );
  }
}

// ── Reading ──────────────────────────────────────────────────────────────

/// `tsm get`: the value of a reference on standard output, without a
/// trailing line break unless `-n`; a binary value only with `--base64`.
/// Options: `--field`, `--dim name=value` (repeated), `--no-wait`,
/// `--timeout` (seconds).
Future<int> tsmGet(TsmContext c, TsmArgs a) async {
  final ref = a.positionalAt(0, 'the reference');
  final timeout = a.option('timeout');
  final seconds = timeout == null ? null : int.tryParse(timeout);
  if (timeout != null && (seconds == null || seconds <= 0)) {
    throw TsmFailure.usage('--timeout takes whole seconds');
  }
  final client = await _client(c);
  try {
    final value = await client.get(
      ref,
      field: a.option('field'),
      dimensions: _dimensions(a),
      wait: !a.flag('no-wait'),
      timeout: seconds == null ? null : Duration(seconds: seconds),
      onProgress: (p) => _progress(c, p),
    );
    try {
      if (a.flag('base64')) {
        c.io.out(base64.encode(value.bytes));
      } else if (value.encoding == TomSecretEncoding.base64) {
        c.io.err.writeln(
          'tsm: the value of $ref is binary: print it with --base64',
        );
        return TsmExit.usage;
      } else {
        c.io.writeOut(value.bytes);
      }
      if (a.flag('newline')) c.io.out('\n');
      return TsmExit.ok;
    } finally {
      value.dispose();
    }
  } on TomSecretsClientException catch (e) {
    return c.clientError(e);
  } finally {
    await client.close();
  }
}

final RegExp _variable = RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$');

/// `tsm run`: the variables of `--map VAR=ref` (repeated) and of
/// `--env-file`, every reference in one `getMany` (one approval); **[C]**
/// `--file VAR=ref` (repeated): the value as a temporary file (`getFile`;
/// a typed certificate's or PGP key's private key when the reference names
/// no field), the variable its path, in a directory only this user may
/// read, overwritten and deleted when the command ends. The command after
/// `--` is started with them in its environment only when all of them were
/// answered, and its exit code is tsm's.
Future<int> tsmRun(TsmContext c, TsmArgs a) async {
  final files = <(String, String)>[
    for (final f in a.all('file')) _pair(f, 'file'),
  ];
  final command = a.passthrough;
  if (command.isEmpty) {
    throw TsmFailure.usage('name the command after --');
  }
  final mapped = <(String, String)>[
    for (final m in a.all('map')) _pair(m, 'map'),
  ];
  final envFile = a.option('env-file');
  if (envFile != null) {
    final file = File(envFile);
    if (!await file.exists()) throw TsmFailure.usage('no env file $envFile');
    for (final line in await file.readAsLines()) {
      final text = line.trim();
      if (text.isEmpty || text.startsWith('#')) continue;
      mapped.add(_pair(text, 'env-file'));
    }
  }
  if (mapped.isEmpty && files.isEmpty) {
    throw TsmFailure.usage(
      'map at least one variable (--map, --env-file, --file)',
    );
  }
  for (final (name, _) in [...mapped, ...files]) {
    if (!_variable.hasMatch(name)) {
      throw TsmFailure.usage('"$name" is no environment variable name');
    }
  }
  final dims = _dimensions(a);
  final client = await _client(c);
  final Map<String, String> environment = {};
  Directory? temp;
  try {
    final results = mapped.isEmpty
        ? const <TomSecretResult>[]
        : await client.getMany([
            for (final (_, ref) in mapped)
              TomSecretRequest(ref, dimensions: dims),
          ], onProgress: (p) => _progress(c, p));
    int? failed;
    for (var i = 0; i < results.length; i++) {
      final error = results[i].error;
      if (error != null) {
        c.io.err.write('tsm: ${mapped[i].$1}: ');
        failed ??= c.clientError(error);
      }
    }
    for (var i = 0; i < results.length; i++) {
      final value = results[i].value;
      if (value == null) continue;
      if (value.encoding == TomSecretEncoding.base64) {
        c.io.err.writeln(
          'tsm: ${mapped[i].$1}: the value is binary and cannot be an '
          'environment variable',
        );
        failed ??= TsmExit.of('malformed');
      } else {
        environment[mapped[i].$1] = value.text;
      }
      value.dispose();
    }
    if (failed != null) return failed;
    for (final (name, ref) in files) {
      final TomSecretFile file;
      try {
        file = await client.getFile(
          ref,
          dimensions: dims,
          onProgress: (p) => _progress(c, p),
        );
      } on TomSecretsClientException catch (e) {
        c.io.err.write('tsm: $name: ');
        return c.clientError(e);
      }
      try {
        temp ??= _privateDirectory();
        environment[name] = _writePrivate(temp, name, file);
      } finally {
        file.dispose();
      }
    }
  } on TomSecretsClientException catch (e) {
    _removePrivate(temp);
    return c.clientError(e);
  } on Object {
    _removePrivate(temp);
    rethrow;
  } finally {
    await client.close();
  }
  try {
    final code = await c.io.runCommand(command, environment);
    c.processExitCode = code;
    return code;
  } finally {
    _removePrivate(temp);
  }
}

/// A new temporary directory only this user may enter (mode 700 on Unix;
/// the user's own temporary folder on Windows).
Directory _privateDirectory() {
  final dir = Directory.systemTemp.createTempSync('tsm-run-');
  if (!Platform.isWindows) {
    final r = Process.runSync('chmod', ['700', dir.path]);
    if (r.exitCode != 0) {
      dir.deleteSync(recursive: true);
      throw TsmFailure.usage('the temporary directory cannot be made private');
    }
  }
  return dir;
}

/// Writes [file] as `<dir>/<variable>/<its name>` (mode 600 on Unix) and
/// answers the path.
String _writePrivate(Directory dir, String variable, TomSecretFile file) {
  final sub = Directory('${dir.path}${Platform.pathSeparator}$variable')
    ..createSync();
  final base = file.name.split(RegExp(r'[/\\]')).last;
  final path =
      '${sub.path}${Platform.pathSeparator}${base.isEmpty ? 'value' : base}';
  final out = File(path)..createSync();
  if (!Platform.isWindows) Process.runSync('chmod', ['600', path]);
  out.writeAsBytesSync(file.bytes, flush: true);
  return path;
}

/// Overwrites every file under [dir] with zeros, then deletes it.
void _removePrivate(Directory? dir) {
  if (dir == null || !dir.existsSync()) return;
  for (final f in dir.listSync(recursive: true).whereType<File>()) {
    try {
      f.writeAsBytesSync(List<int>.filled(f.lengthSync(), 0), flush: true);
    } on FileSystemException {
      // Deleted below all the same.
    }
  }
  dir.deleteSync(recursive: true);
}

/// `tsm ref parse <ref>` (the parse result as JSON) and `tsm ref format
/// (--key K | --store S --path SEG… | --store S --uuid ~HEX) [--field F]
/// [--qualifier name:value]…` (the canonical reference).
Future<int> tsmRef(TsmContext c, TsmArgs a) async {
  final action = a.positionalAt(0, 'parse or format');
  switch (action) {
    case 'parse':
      final text = a.positionalAt(1, 'the reference');
      try {
        final r = TomSecretReference.parse(text);
        c.io.outln(
          const JsonEncoder.withIndent('  ').convert({
            'canonical': r.canonical,
            'target': switch (r.target) {
              TomSecretKeyTarget(:final key) => {'kind': 'key', 'key': key},
              TomSecretPathTarget(:final store, :final segments) => {
                'kind': 'path',
                'store': store,
                'segments': segments,
              },
              TomSecretUuidTarget(:final store, :final uuid) => {
                'kind': 'uuid',
                'store': store,
                'uuid': uuid,
              },
            },
            'field': r.field,
            'fieldGiven': r.fieldGiven,
            'qualifiers': [
              for (final q in r.qualifiers)
                {'dimension': q.dimension, 'value': q.value},
            ],
          }),
        );
        return TsmExit.ok;
      } on TomSecretsClientException catch (e) {
        return c.clientError(e);
      }
    case 'format':
      final key = a.option('key');
      final store = a.option('store');
      final uuid = a.option('uuid');
      final path = a.all('path');
      final TomSecretTarget target;
      if (key != null && store == null && uuid == null && path.isEmpty) {
        target = TomSecretKeyTarget(key);
      } else if (store != null && uuid != null && key == null && path.isEmpty) {
        target = TomSecretUuidTarget(store, uuid);
      } else if (store != null &&
          path.isNotEmpty &&
          key == null &&
          uuid == null) {
        target = TomSecretPathTarget(store, path);
      } else {
        throw TsmFailure.usage(
          'name --key, or --store with --path segments or --uuid',
        );
      }
      final field = a.option('field');
      final reference = TomSecretReference(
        target: target,
        field: field ?? tomSecretsDefaultField,
        fieldGiven: field != null,
        qualifiers: [
          for (final q in a.all('qualifier'))
            () {
              final i = q.indexOf(':');
              if (i <= 0) {
                throw TsmFailure.usage('--qualifier takes name:value');
              }
              return TomSecretBinding(q.substring(0, i), q.substring(i + 1));
            }(),
        ],
      );
      try {
        final canonical = reference.canonical;
        // What is printed reads back as the same reference.
        TomSecretReference.parse(canonical);
        c.io.outln(canonical);
        return TsmExit.ok;
      } on TomSecretsClientException catch (e) {
        return c.clientError(e);
      }
    default:
      throw TsmFailure.usage('ref takes parse or format, not "$action"');
  }
}

// ── Administering ────────────────────────────────────────────────────────

/// Runs [body] on an admin connection; an admin error is told and its exit
/// code answered.
Future<int> _withAdmin(
  TsmContext c,
  Future<int> Function(TomSecretsAdminClient admin) body,
) async {
  TomSecretsAdminClient? admin;
  try {
    admin = await c.admin();
    return await body(admin);
  } on TomSecretsAdminException catch (e) {
    return c.adminError(e);
  } finally {
    await admin?.close();
  }
}

void _json(TsmContext c, Object? value) =>
    c.io.outln(const JsonEncoder.withIndent('  ').convert(value));

/// The service executable: `--service`, else `TSM_SERVICE`, else
/// `tom_secrets_service` beside tsm; null (told) when it is not there.
Future<String?> _serviceExecutable(TsmContext c, TsmArgs a) async {
  final exe = Platform.isWindows ? '.exe' : '';
  final service =
      a.option('service') ??
      c.io.environment['TSM_SERVICE'] ??
      '${c.io.executableDirectory}${Platform.pathSeparator}'
          'tom_secrets_service$exe';
  if (!await File(service).exists()) {
    c.io.err.writeln('tsm: no service executable at $service');
    return null;
  }
  return service;
}

/// `tsm start [--unlock] [--bootstrap FILE] [--service EXE] [--key-file
/// F]`: starts the service (its admin key kept in the keychain) and with
/// `--unlock` unlocks it.
Future<int> tsmStart(TsmContext c, TsmArgs a) async {
  final env = c.io.environment;
  final bootstrap =
      a.option('bootstrap') ?? tomSecretsBootstrapPath(environment: env);
  if (!await File(bootstrap).exists()) {
    c.io.err.writeln('tsm: no bootstrap file at $bootstrap');
    return TsmExit.of('not_found');
  }
  final service = await _serviceExecutable(c, a);
  if (service == null) return TsmExit.of('not_found');
  final started = await _start(c, service, bootstrap);
  if (started != TsmExit.ok || !a.flag('unlock')) return started;
  return tsmUnlock(c, a);
}

Future<int> _start(TsmContext c, String service, String bootstrap) async {
  final result = await tomSecretsStartService(
    executable: service,
    bootstrap: bootstrap,
    environment: c.io.environment,
  );
  switch (result) {
    case TomSecretsStarted(:final adminKey):
      final start = (await c.runtime.readInfo())?['start'];
      if (start is int) await c.keepAdminKey(start, adminKey);
      c.io.outln('started');
    case TomSecretsAlreadyStarted():
      c.io.outln('already running');
    case TomSecretsStartFailed(:final code, :final message):
      c.io.err.writeln('tsm: the service did not start: $code $message');
      return TsmExit.of('internal');
  }
  return TsmExit.ok;
}

/// `host:port` as the giving machine's Pairing screen shows it (an IPv6
/// address in brackets), or null.
(String, int)? tsmPairingAddress(String text) {
  final t = text.trim();
  final at = t.lastIndexOf(':');
  final port = at < 0 ? null : int.tryParse(t.substring(at + 1));
  if (at <= 0 || port == null || port < 1 || port > 65535) return null;
  var host = t.substring(0, at);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
  }
  if (host.isEmpty || host.contains(RegExp(r'[\s/]'))) return null;
  return (host, port);
}

/// `tsm pair [<host:port>] <code> [--relay tsm:URL | --relay
/// github:OWNER/REPO --token-env VAR [--relay-api URL]] [--device NAME] [--device-key MODE] [--link
/// ADDRESS:PORT] [--service EXE]`: sets this machine up by pairing
/// (part-sharing, BP-13). The service executable receives the pairing in
/// its pairing mode (tsm links no core); tsm shows what the other machine
/// gave, asks for the master password, then starts the service and unlocks
/// it. `--link` is where this machine's approval link listens (the device
/// setting `approvalLink`): the other machine is told it, so its service
/// opens the link and its app answers this machine's prompts. `--relay`
/// (part-relay) pairs through that relay when the other machine's pairing
/// waits there too — after the address when one is given, else alone: a
/// GitHub repository (`github:<owner>/<repo>`) with this machine's own token
/// for it, read from the environment variable `--token-env` names (never a
/// command-line argument; `--relay-api` is the GitHub API's URL, GitHub
/// Enterprise Server), or a relay server (`tsm:<url>`), which needs no token
/// to pair.
Future<int> tsmPair(TsmContext c, TsmArgs a) async {
  final relay = a.option('relay')?.trim();
  final tokenEnv = a.option('token-env')?.trim();
  final relayApi = a.option('relay-api')?.trim();
  String? token;
  final server = relay != null && relay.startsWith('tsm:');
  if (server) {
    final url = Uri.tryParse(relay.substring(4));
    if (url == null ||
        (url.scheme != 'https' && url.scheme != 'http') ||
        url.host.isEmpty) {
      throw TsmFailure.usage(
        'a relay server is tsm:https://<host>[/<path>]: $relay',
      );
    }
    if (tokenEnv != null || relayApi != null) {
      throw TsmFailure.usage(
        '--token-env and --relay-api go with a GitHub relay; a relay server '
        'needs no token to pair',
      );
    }
  } else if (relay != null) {
    if (!RegExp(r'^github:[A-Za-z0-9-]+/[A-Za-z0-9._-]+$').hasMatch(relay)) {
      throw TsmFailure.usage(
        'a relay is a GitHub repository, github:<owner>/<repo>, or a relay '
        'server, tsm:<url>: $relay',
      );
    }
    if (tokenEnv == null || tokenEnv.isEmpty) {
      throw TsmFailure.usage(
        '--relay needs --token-env: the environment variable holding this '
        "machine's token for the repository",
      );
    }
    token = c.io.environment[tokenEnv]?.trim();
    if (token == null || token.isEmpty) {
      throw TsmFailure.usage(
        'the environment variable $tokenEnv holds no token',
      );
    }
  } else if (tokenEnv != null || relayApi != null) {
    throw TsmFailure.usage('--token-env and --relay-api go with --relay');
  }
  final alone = relay != null && a.positional.length == 1;
  final shown = alone
      ? null
      : a.positionalAt(0, "the other machine's address (host:port)");
  final code = alone
      ? a.positionalAt(0, 'the code its Pairing screen shows')
      : a.positionalAt(1, 'the code its Pairing screen shows');
  final address = shown == null ? null : tsmPairingAddress(shown);
  if (shown != null && address == null) {
    throw TsmFailure.usage('not an address and port (host:port): $shown');
  }
  final link = a.option('link')?.trim();
  if (link != null) {
    final problem = tomSecretsApprovalLinkProblem(link);
    if (problem != null) throw TsmFailure.usage(problem);
  }
  final env = c.io.environment;
  final bootstrap = tomSecretsBootstrapPath(environment: env);
  if (await File(bootstrap).exists()) {
    c.io.err.writeln('tsm: this machine is set up already ($bootstrap)');
    return TsmExit.of('denied');
  }
  final service = await _serviceExecutable(c, a);
  if (service == null) return TsmExit.of('not_found');
  final device =
      a.option('device') ??
      Platform.localHostname.split('.').first.toLowerCase();
  final pairing = await TomSecretsServicePairing.start(
    executable: service,
    environment: env,
    handover: TomSecretsPairingHandover(
      dataDirectory: tomSecretsDataDirectory(environment: env),
      address: address?.$1,
      port: address?.$2,
      code: code.trim(),
      device: device,
      deviceKey: a.option('device-key'),
      approvalLink: link,
      relay: relay,
      relayToken: token,
      relayApi: relayApi,
    ),
  );
  final String written;
  try {
    c.io.err.writeln(switch ((address, relay)) {
      ((final at?, final via?)) =>
        'tsm: pairing with ${at.$1}:${at.$2}, else through $via, as $device',
      ((final at?, null)) => 'tsm: pairing with ${at.$1}:${at.$2} as $device',
      _ => 'tsm: pairing through $relay as $device',
    });
    final report = await pairing.received();
    c.io.outln('paired with ${report.giver}; it gave:');
    for (final v in report.vaults) {
      c.io.outln('  ${v.name}${v.primary ? ' (primary)' : ''}  ${v.locator}');
    }
    if (report.config) c.io.outln('  the shared configuration');
    for (final t in report.tokens) {
      c.io.outln('  a GitHub token for $t');
    }
    String? path;
    for (var tried = 1; path == null; tried++) {
      try {
        path = await pairing.setUp(await c.password());
      } on TomSecretsPairingModeException catch (e) {
        if (e.code != tomSecretsPairingWrongPassword ||
            tried >= tomSecretsPairingPasswordTries ||
            c.passwordFromStdin) {
          rethrow;
        }
        c.io.err.writeln('tsm: wrong master password, try again');
        c.forgetPassword();
      }
    }
    written = path;
  } on TomSecretsPairingModeException catch (e) {
    c.io.err.writeln('tsm: ${e.code}: ${e.message}');
    return switch (e.code) {
      'pairing' || tomSecretsPairingWrongPassword => TsmExit.of('denied'),
      'handover' => TsmExit.usage,
      _ => TsmExit.of('internal'),
    };
  } finally {
    await pairing.close();
  }
  c.io.outln('set up ($written)');
  if (link != null) c.io.outln('approval link on $link');
  final started = await _start(c, service, written);
  if (started != TsmExit.ok) return started;
  return _withAdmin(c, (admin) async {
    await admin.unlock(await c.password());
    c.io.outln('unlocked');
    return TsmExit.ok;
  });
}

/// `tsm unlock [--key-file F]`: unlocks with the master password.
Future<int> tsmUnlock(TsmContext c, TsmArgs a) async {
  final keyFile = a.option('key-file');
  if (keyFile != null) await c.readKeyFile(keyFile);
  return _withAdmin(c, (admin) async {
    await admin.unlock(await c.password(), keyFile: c.keyFile);
    c.io.outln('unlocked');
    return TsmExit.ok;
  });
}

/// `tsm lock`.
Future<int> tsmLock(TsmContext c, TsmArgs a) => _withAdmin(c, (admin) async {
  await admin.request('lock');
  c.io.outln('locked');
  return TsmExit.ok;
});

/// `tsm stop`: locks and stops the service, and removes its admin key from
/// the keychain.
Future<int> tsmStop(TsmContext c, TsmArgs a) async {
  final start = (await c.runtime.readInfo())?['start'];
  final code = await _withAdmin(c, (admin) async {
    await admin.request('shutdown');
    c.io.outln('stopped');
    return TsmExit.ok;
  });
  if (code == TsmExit.ok && start is int) await c.forgetAdminKey(start);
  return code;
}

/// `tsm reload`: fetches every store now.
Future<int> tsmReload(TsmContext c, TsmArgs a) => _withAdmin(c, (admin) async {
  await admin.request('reload');
  c.io.outln('reloaded');
  return TsmExit.ok;
});

String _age(Duration d) {
  if (d.inMinutes < 1) return 'just now';
  if (d.inHours < 1) return '${d.inMinutes} min ago';
  if (d.inDays < 1) return '${d.inHours} h ago';
  return '${d.inDays} days ago';
}

/// The age after which an offline copy is shown as a warning (part-stores,
/// `TomSecretsCachedVault.isStaleAt`).
const Duration tsmStaleAfter = Duration(days: 7);

/// `tsm status [--json]`: the service, each store with its state, source
/// and the age of its copy (and why it is on its copy), and the keys due a
/// reminder.
Future<int> tsmStatus(TsmContext c, TsmArgs a) async {
  if ((await c.runtime.readInfo()) == null) {
    if (a.flag('json')) {
      _json(c, {'running': false});
    } else {
      c.io.outln('not running');
    }
    return TsmExit.of('not_running');
  }
  return _withAdmin(c, (admin) async {
    final report = await admin.request('status');
    if (a.flag('json')) {
      _json(c, {
        for (final e in report.entries)
          if (e.key != 'id') e.key: e.value,
      });
      return TsmExit.ok;
    }
    final now = c.io.clock().toUtc();
    final service = (report['service'] as Map?) ?? const {};
    c.io.outln(
      'service  running, ${report['locked'] == true ? 'locked' : 'unlocked'}, '
      'lock mode ${report['lockMode']}, version ${service['version']}',
    );
    // The ssh-agent's endpoint [B]: what SSH_AUTH_SOCK or IdentityAgent
    // names (protocol.md 7.6).
    final agent = report['agent'];
    if (agent is Map) {
      c.io.outln(
        'agent    ${agent['socket'] ?? agent['pipe']}  '
        '(SSH_AUTH_SOCK or IdentityAgent for ssh)',
      );
    }
    for (final s in (report['stores'] as List? ?? const []).cast<Map>()) {
      final fetched = s['fetchedAt'] == null
          ? null
          : DateTime.tryParse(s['fetchedAt'] as String);
      final age = fetched == null ? null : now.difference(fetched);
      final notes = [
        if (s['state'] == 'offline') 'GitHub not reachable',
        if (s['state'] == 'token_expired') 'token expired: enter a new one',
        if (s['source'] == 'cache' && age != null && age > tsmStaleAfter)
          'offline copy older than ${tsmStaleAfter.inDays} days',
      ];
      c.io.outln(
        'store    ${s['name']}  ${s['state']}  ${s['source']}'
        '${age == null ? '' : '  fetched ${_age(age)}'}'
        '${notes.isEmpty ? '' : '  (${notes.join('; ')})'}',
      );
    }
    for (final k in (report['expiring'] as List? ?? const []).cast<Map>()) {
      c.io.outln('expiring ${_keyLine(k)}');
    }
    return TsmExit.ok;
  });
}

String _keyLine(Map k) {
  final days = k['daysLeft'] as int;
  final when = days < 0
      ? 'expired ${-days} days ago'
      : days == 0
      ? 'expires today'
      : 'in $days days';
  return '${k['key']}  ${k['kind']}${k['vault'] == null ? '' : '  vault ${k['vault']}'}'
      '  ${(k['expiresAt'] as String).substring(0, 10)} ($when)';
}

/// `tsm keys [--json]`: every key with its due date; `*` marks those due a
/// reminder.
Future<int> tsmKeys(TsmContext c, TsmArgs a) => _withAdmin(c, (admin) async {
  final keys = ((await admin.request('keys'))['keys'] as List).cast<Map>();
  if (a.flag('json')) {
    _json(c, keys);
  } else {
    for (final k in keys) {
      c.io.outln('${k['reminding'] == true ? '*' : ' '} ${_keyLine(k)}');
    }
  }
  return TsmExit.ok;
});

/// `tsm approvals [--json]`: the requests waiting on this host with their
/// approval codes; tsm cannot answer them (DP-19).
Future<int> tsmApprovals(TsmContext c, TsmArgs a) => _withAdmin(c, (
  admin,
) async {
  final waiting = ((await admin.request('approvals.list'))['approvals'] as List)
      .cast<Map>();
  if (a.flag('json')) {
    _json(c, waiting);
  } else if (waiting.isEmpty) {
    c.io.outln('no request waits');
  } else {
    for (final w in waiting) {
      final identity = (w['identity'] as Map?) ?? const {};
      // An ssh-agent signature [B] names its key and destination.
      final ssh = w['ssh'];
      final what = ssh is Map
          ? 'SSH key ${ssh['title'] ?? ssh['key']}'
                '${ssh['host'] == null ? '' : ' for ${ssh['host']}'}'
          : (w['refs'] as List).join(', ');
      c.io.outln(
        '${w['approvalCode'] ?? '(an approver is attached)'}  '
        '$what  '
        '${identity['script'] ?? identity['exe'] ?? ''}',
      );
    }
  }
  return TsmExit.ok;
});

/// `tsm approve <token>`, `tsm approve -` (the token from standard input),
/// and `tsm approve` without a token (the service reloads the primary and
/// takes the approval records for waiting codes).
Future<int> tsmApprove(TsmContext c, TsmArgs a) async {
  var token = a.positional.isEmpty ? null : a.positional.first;
  if (token == '-') token = await c.io.readLine();
  if (token != null) {
    // Typed as shown: upper-cased, without spaces and dashes.
    token = token.toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
    if (!RegExp(r'^[A-Z2-7]{26}$').hasMatch(token)) {
      throw TsmFailure.usage('an approval token is 26 base32 characters');
    }
  }
  return _withAdmin(c, (admin) async {
    if (token == null) {
      await admin.request('reload');
      c.io.outln('reloaded: approvals recorded in the primary are taken');
    } else {
      await admin.request('approval.redeem', {'token': token});
      c.io.outln('approved');
    }
    return TsmExit.ok;
  });
}

/// `tsm approve-code <code> --host H [--decision once|always|never]
/// [--secret ref|store|all]`: on a trusted device where command-line
/// approvals are switched on, prints the token for a code shown on [host].
Future<int> tsmApproveCode(TsmContext c, TsmArgs a) async {
  final code = a.positionalAt(0, 'the approval code');
  final host = a.option('host') ?? (throw TsmFailure.usage('name the --host'));
  final decision = a.option('decision') ?? 'once';
  final secret = a.option('secret') ?? 'ref';
  if (!const ['once', 'always', 'never'].contains(decision)) {
    throw TsmFailure.usage('--decision is once, always or never');
  }
  if (!const ['ref', 'store', 'all'].contains(secret)) {
    throw TsmFailure.usage('--secret is ref, store or all');
  }
  return _withAdmin(c, (admin) async {
    final answer = await admin.request('approval.issue', {
      'host': host,
      'code': code,
      'decision': decision,
      'secret': secret,
    });
    c.io.outln('${answer['token']}');
    return TsmExit.ok;
  });
}

/// `tsm grants` (`list`, the default, with `--host` and `--json`) and
/// `tsm grants revoke HOST GRANT_ID`.
Future<int> tsmGrants(TsmContext c, TsmArgs a) async {
  final action = a.positional.isEmpty ? 'list' : a.positional.first;
  switch (action) {
    case 'list':
      return _withAdmin(c, (admin) async {
        final grants =
            ((await admin.request('grants.list', {
                      'host': ?a.option('host'),
                    }))['grants']
                    as List)
                .cast<Map>();
        if (a.flag('json')) {
          _json(c, grants);
        } else if (grants.isEmpty) {
          c.io.outln('no grant');
        } else {
          for (final g in grants) {
            c.io.outln(
              '${g['id']}  ${g['host']}  ${g['decision']}  ${g['subject']}  '
              '${g['secret']}${g['lastUsed'] == null ? '' : '  used ${g['lastUsed']}'}',
            );
          }
        }
        return TsmExit.ok;
      });
    case 'revoke':
      final host = a.positionalAt(1, 'the host');
      final grantId = a.positionalAt(2, 'the grant id');
      return _withAdmin(c, (admin) async {
        await admin.request('grants.revoke', {
          'host': host,
          'grantId': grantId,
        });
        c.io.outln('revoked');
        return TsmExit.ok;
      });
    default:
      throw TsmFailure.usage('grants takes list or revoke, not "$action"');
  }
}

/// `tsm allow <host> <subject> <ref> [--never] [--pin P]`: a pre-approval
/// for [host], where command-line approvals are switched on.
Future<int> tsmAllow(TsmContext c, TsmArgs a) async {
  final host = a.positionalAt(0, 'the host');
  final subject = a.positionalAt(1, 'the subject');
  final ref = a.positionalAt(2, 'the reference (or all)');
  return _withAdmin(c, (admin) async {
    await admin.request('grants.add', {
      'grant': {
        'host': host,
        'subject': subject,
        'secret': ref,
        'decision': a.flag('never') ? 'never' : 'allow',
        'pin': ?a.option('pin'),
      },
    });
    c.io.outln('granted');
    return TsmExit.ok;
  });
}

/// `tsm audit [--since T] [--until T] [--subject S] [--ref R] [--json]`:
/// the audit log, the last 7 days by default.
Future<int> tsmAudit(TsmContext c, TsmArgs a) async {
  final now = c.io.clock().toUtc();
  DateTime time(String? text, DateTime fallback) {
    if (text == null) return fallback;
    final parsed = DateTime.tryParse(text);
    if (parsed == null) throw TsmFailure.usage('"$text" is no time');
    return parsed.toUtc();
  }

  final from = time(a.option('since'), now.subtract(const Duration(days: 7)));
  final to = time(a.option('until'), now);
  return _withAdmin(c, (admin) async {
    final records =
        ((await admin.request('audit.query', {
                  'from': from.toIso8601String(),
                  'to': to.toIso8601String(),
                  'subject': ?a.option('subject'),
                  'ref': ?a.option('ref'),
                }))['records']
                as List)
            .cast<Map>();
    if (a.flag('json')) {
      _json(c, records);
    } else {
      for (final r in records) {
        final identity = (r['identity'] as Map?) ?? const {};
        c.io.outln(
          '${r['time']}  ${r['outcome']}  ${(r['refs'] as List).join(', ')}  '
          '${identity['script'] ?? identity['exe'] ?? ''}',
        );
      }
    }
    return TsmExit.ok;
  });
}

/// `tsm compact <owner/repository>`: cuts the history of a vault
/// repository now, with its own retention.
Future<int> tsmCompact(TsmContext c, TsmArgs a) async {
  final repository = a.positionalAt(0, 'the repository (owner/name)');
  return _withAdmin(c, (admin) async {
    final answer = await admin.request('compact', {'repository': repository});
    c.io.outln(
      answer['compacted'] == true
          ? 'compacted $repository: ${answer['kept']} commits kept '
                '(${answer['oldHead']} -> ${answer['newHead']})'
          : 'nothing to cut in $repository',
    );
    return TsmExit.ok;
  });
}

// ── GitHub sign-in (part-key-rotation §3, DP-83) ────────────────────────

/// `tsm login [--client-id ID]`: "Sign in with GitHub" on a headless
/// machine. The service starts the GitHub App's device flow; tsm prints the
/// code and the page to enter it on (on any device), then waits for the
/// outcome. The service keeps and renews the tokens (`github.signIn`).
Future<int> tsmLogin(TsmContext c, TsmArgs a) => _withAdmin(c, (admin) async {
  await admin.request('subscribe');
  final done = admin.events.firstWhere((e) => e['op'] == 'github_sign_in');
  final code = await admin.request('github.signIn', {
    'clientId': ?a.option('client-id'),
  });
  c.io.outln(
    'Open ${code['verificationUri']} and enter the code ${code['userCode']}',
  );
  c.io.err.writeln(
    'tsm: waiting for GitHub (the code is valid '
    '${((code['expiresIn'] as int?) ?? 900) ~/ 60} minutes)…',
  );
  final event = await done;
  final outcome = event['outcome'];
  if (outcome == 'signed_in') {
    final login = event['login'];
    c.io.outln(login == null ? 'signed in' : 'signed in as $login');
    return TsmExit.ok;
  }
  c.io.err.writeln('tsm: not signed in: $outcome');
  return TsmExit.of(outcome == 'expired' ? 'timeout' : 'denied');
});

/// `tsm logout`: the device's GitHub App tokens leave the keychain; its
/// pasted tokens are used again.
Future<int> tsmLogout(TsmContext c, TsmArgs a) => _withAdmin(c, (admin) async {
  await admin.request('github.signOut');
  c.io.outln('signed out');
  return TsmExit.ok;
});
