// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// tsm's commands (part-clients): reading (`get`, `run`, `ref`) on the
/// client endpoint, administering (`start`, `unlock`, `lock`, `stop`,
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
/// `--env-file`, every reference in one `getMany` (one approval); the
/// command after `--` is started with them in its environment only when all
/// of them were answered, and its exit code is tsm's.
Future<int> tsmRun(TsmContext c, TsmArgs a) async {
  if (a.all('file').isNotEmpty) {
    c.io.err.writeln('tsm: --file comes with getFile (phase B)');
    return TsmExit.of('unsupported');
  }
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
  if (mapped.isEmpty) {
    throw TsmFailure.usage('map at least one variable (--map, --env-file)');
  }
  for (final (name, _) in mapped) {
    if (!_variable.hasMatch(name)) {
      throw TsmFailure.usage('"$name" is no environment variable name');
    }
  }
  final dims = _dimensions(a);
  final client = await _client(c);
  final Map<String, String> environment;
  try {
    final results = await client.getMany([
      for (final (_, ref) in mapped) TomSecretRequest(ref, dimensions: dims),
    ], onProgress: (p) => _progress(c, p));
    int? failed;
    for (var i = 0; i < results.length; i++) {
      final error = results[i].error;
      if (error != null) {
        c.io.err.write('tsm: ${mapped[i].$1}: ');
        failed ??= c.clientError(error);
      }
    }
    environment = {};
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
  } on TomSecretsClientException catch (e) {
    return c.clientError(e);
  } finally {
    await client.close();
  }
  final code = await c.io.runCommand(command, environment);
  c.processExitCode = code;
  return code;
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
  final exe = Platform.isWindows ? '.exe' : '';
  final service =
      a.option('service') ??
      env['TSM_SERVICE'] ??
      '${c.io.executableDirectory}${Platform.pathSeparator}'
          'tom_secrets_service$exe';
  if (!await File(service).exists()) {
    c.io.err.writeln('tsm: no service executable at $service');
    return TsmExit.of('not_found');
  }
  final result = await tomSecretsStartService(
    executable: service,
    bootstrap: bootstrap,
    environment: env,
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
  if (!a.flag('unlock')) return TsmExit.ok;
  return tsmUnlock(c, a);
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

/// `tsm stop`: locks and stops the service.
Future<int> tsmStop(TsmContext c, TsmArgs a) => _withAdmin(c, (admin) async {
  await admin.request('shutdown');
  c.io.outln('stopped');
  return TsmExit.ok;
});

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
      c.io.outln(
        '${w['approvalCode'] ?? '(an approver is attached)'}  '
        '${(w['refs'] as List).join(', ')}  '
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
