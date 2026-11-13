// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The conformance runner of the Dart client (tom_secrets_client).
//
// Reads one case per line on standard input,
//   {"case": name, "runtimeDir": dir, "action": {...}}
// runs its action with the library against the service in runtimeDir, and
// writes one canonical result line per case on standard output,
//   {"case": name, "result": {...}}
// (keys sorted, compact). conformance/README.md defines the actions and the
// result shapes every runner writes.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/tom_secrets_client.dart';

Future<void> main() async {
  final lines = stdin.transform(utf8.decoder).transform(const LineSplitter());
  await for (final line in lines) {
    if (line.trim().isEmpty) continue;
    final request = jsonDecode(line) as Map<String, Object?>;
    final result = await _runCase(
      request['runtimeDir']! as String,
      (request['action']! as Map).cast<String, Object?>(),
    );
    stdout.writeln(_canonical({'case': request['case'], 'result': result}));
    await stdout.flush();
  }
}

Future<Map<String, Object?>> _runCase(
  String runtimeDir,
  Map<String, Object?> action,
) async {
  final options = (action['client'] as Map? ?? const {})
      .cast<String, Object?>();
  final client = TomSecretsClient(
    clientName: 'conformance-runner',
    clientToken: options['clientToken'] as String?,
    environment: {...Platform.environment, 'TSM_RUNTIME_DIR': runtimeDir},
    connectTimeout: const Duration(seconds: 5),
  );
  try {
    return await _run(client, action);
  } finally {
    await client.close();
  }
}

Future<Map<String, Object?>> _run(
  TomSecretsClient client,
  Map<String, Object?> action,
) async {
  switch (action['do']) {
    case 'parse':
      return _guard(() async {
        final r = TomSecretReference.parse(action['ref']! as String);
        return {'parsed': _shape(r), 'canonical': r.canonical};
      });
    case 'format':
      return _guard(() async {
        final r = _fromShape(
          (action['parsed']! as Map).cast<String, Object?>(),
        );
        return {'formatted': TomSecretReference.format(r)};
      });
    case 'connect':
      return _guard(() async {
        await client.open();
        final w = client.welcome!;
        return {
          'welcome': {
            'host': w.host,
            'platform': w.platform,
            'features': w.features.toList()..sort(),
          },
        };
      });
    case 'get':
      final progress = <Map<String, Object?>>[];
      final result = await _guard(() async {
        final v = await client.get(
          action['ref']! as String,
          field: action['field'] as String?,
          dimensions: (action['dimensions'] as Map?)?.cast<String, String>(),
          wait: action['wait'] as bool? ?? true,
          timeout: _ms(action['timeoutMs']),
          wantClientToken: action['wantClientToken'] as bool? ?? false,
          waitOnRateLimit: action['waitOnRateLimit'] as bool? ?? false,
          onProgress: (p) => progress.add(_progress(p)),
        );
        return {'value': _value(v)};
      });
      return {...result, if (progress.isNotEmpty) 'progress': progress};
    case 'getMany':
      final progress = <Map<String, Object?>>[];
      final result = await _guard(() async {
        final results = await client.getMany(
          [
            for (final r in (action['refs']! as List).cast<Map>())
              TomSecretRequest(
                r['ref']! as String,
                field: r['field'] as String?,
                dimensions: (r['dimensions'] as Map?)?.cast<String, String>(),
              ),
          ],
          wait: action['wait'] as bool? ?? true,
          timeout: _ms(action['timeoutMs']),
          onProgress: (p) => progress.add(_progress(p)),
        );
        return {
          'results': [
            for (final r in results)
              r.value != null
                  ? {'value': _value(r.value!)}
                  : {'error': _error(r.error!)},
          ],
        };
      });
      return {...result, if (progress.isNotEmpty) 'progress': progress};
    case 'getFile':
      return _guard(() async {
        final f = await client.getFile(
          action['ref']! as String,
          field: action['field'] as String?,
        );
        final out = {
          'file': {
            'name': f.name,
            'size': f.size,
            'base64': base64.encode(f.bytes),
          },
        };
        f.dispose();
        return out;
      });
    case 'concurrent':
      final actions = (action['actions']! as List).cast<Map>();
      final results = await Future.wait([
        for (final a in actions) _run(client, a.cast<String, Object?>()),
      ]);
      return {'results': results};
    case 'sequence':
      final steps = <Map<String, Object?>>[];
      for (final a in (action['actions']! as List).cast<Map>()) {
        final step = a.cast<String, Object?>();
        if (step['do'] == 'pause') {
          await Future<void>.delayed(_ms(step['ms'])!);
          continue;
        }
        steps.add(await _run(client, step));
      }
      return {'steps': steps};
    default:
      return {'unsupportedAction': action['do']};
  }
}

Duration? _ms(Object? ms) => ms is int ? Duration(milliseconds: ms) : null;

Future<Map<String, Object?>> _guard(
  Future<Map<String, Object?>> Function() body,
) async {
  try {
    return await body();
  } on TomSecretsClientException catch (e) {
    return {'error': _error(e)};
  }
}

Map<String, Object?> _error(TomSecretsClientException e) => {
  'kind': e.kind.wireName,
  if (e.reason != null) 'reason': e.reason,
};

Map<String, Object?> _progress(TomSecretsProgress p) => {
  'pending': p.pending.name,
  if (p.approvalCode != null) 'approvalCode': p.approvalCode,
};

Map<String, Object?> _value(TomSecretValue v) {
  var textRefused = false;
  String? text;
  try {
    text = v.text;
  } on StateError {
    textRefused = true;
  }
  final out = <String, Object?>{
    'encoding': v.encoding.name,
    'base64': base64.encode(v.bytes),
    'text': ?text,
    if (textRefused) 'textRefused': true,
    'entry': {
      'store': v.entry.store,
      'uuid': v.entry.uuid,
      'source': v.entry.source.name,
      'fetchedAtMs': v.entry.fetchedAt.millisecondsSinceEpoch,
    },
    'bound': v.bound,
    'version': {
      'modifiedMs': v.version.modified.millisecondsSinceEpoch,
      'revision': v.version.revision,
    },
    if (v.expires != null) 'expiresMs': v.expires!.millisecondsSinceEpoch,
    'clientToken': ?v.clientToken,
    // The printable form shows *** and never the value (README, Results);
    // a value that occurs in the reference itself cannot be told apart.
    'masked':
        v.toString().contains('***') &&
        (text == null ||
            v.reference.contains(text) ||
            !v.toString().contains(text)),
  };
  v.dispose();
  return out;
}

Map<String, Object?> _shape(TomSecretReference r) => {
  'qualifiers': [
    for (final q in r.qualifiers) {'dimension': q.dimension, 'value': q.value},
  ],
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
};

TomSecretReference _fromShape(Map<String, Object?> m) {
  final t = (m['target']! as Map).cast<String, Object?>();
  return TomSecretReference(
    qualifiers: [
      for (final q in (m['qualifiers']! as List).cast<Map>())
        TomSecretBinding(q['dimension']! as String, q['value']! as String),
    ],
    target: switch (t['kind']) {
      'key' => TomSecretKeyTarget(t['key']! as String),
      'uuid' => TomSecretUuidTarget(
        t['store']! as String,
        t['uuid']! as String,
      ),
      _ => TomSecretPathTarget(
        t['store']! as String,
        (t['segments']! as List).cast<String>(),
      ),
    },
    field: m['field'] as String? ?? tomSecretsDefaultField,
  );
}

/// Compact JSON with every object's keys sorted.
String _canonical(Object? value) => jsonEncode(_sorted(value));

Object? _sorted(Object? value) => switch (value) {
  Map m => {
    for (final k in (m.keys.cast<String>().toList()..sort())) k: _sorted(m[k]),
  },
  List l => [for (final v in l) _sorted(v)],
  _ => value,
};
