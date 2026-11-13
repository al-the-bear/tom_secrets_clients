// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Reads one secret from the local secrets service.
//
//   dart run example/tom_secrets_client_example.dart '[env:prod]db.main'
//
// Without a running service it says so (not_running) and exits 1.

import 'dart:io';

import 'package:tom_secrets_client/tom_secrets_client.dart';

Future<void> main(List<String> args) async {
  final text = args.isEmpty ? 'db.main' : args.first;

  // References are parsed locally; a malformed one never reaches the service.
  final TomSecretReference reference;
  try {
    reference = TomSecretReference.parse(text);
  } on TomSecretsClientException catch (e) {
    stderr.writeln('not a reference (${e.reason}): $text');
    exitCode = 2;
    return;
  }
  stdout.writeln('canonical form: ${reference.canonical}');

  final client = TomSecretsClient(clientName: 'tom_secrets_client_example');
  try {
    final value = await client.get(
      text,
      timeout: const Duration(seconds: 60),
      onProgress: (p) => stdout.writeln(
        'waiting for ${p.pending.name}'
        '${p.approvalCode == null ? '' : ' - approval code ${p.approvalCode}'}',
      ),
    );
    // Print where it came from, never the value itself.
    stdout.writeln(
      'read $value from store ${value.entry.store} '
      '(${value.entry.source.name}, ${value.bytes.length} bytes)',
    );
    value.dispose();
  } on TomSecretsClientException catch (e) {
    stderr.writeln('${e.kind.wireName}: ${e.message}');
    exitCode = 1;
  } finally {
    await client.close();
  }
}
