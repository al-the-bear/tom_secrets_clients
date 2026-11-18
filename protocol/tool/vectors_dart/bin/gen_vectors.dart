// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Writes protocol/vectors/signatures.json and link_handshake.json (section 9
/// of protocol.md) and bundles.json (the OS unlock's key bundle, 6.4), or with `--check` compares them with a fresh generation.
///
///     cd protocol/tool/vectors_dart
///     dart run bin/gen_vectors.dart [--check]
///
/// Run by hand after changing section 9. Exit 0 when the files were written,
/// or with `--check` when they are what this tool writes now.
library;

import 'dart:convert';
import 'dart:io';

import 'package:tsm_protocol_vectors/generate.dart';
import 'package:tsm_protocol_vectors/unlock_bundles.dart';

Future<void> main(List<String> args) async {
  final check = args.contains('--check');
  final unknown = args.where((a) => a != '--check');
  if (unknown.isNotEmpty) {
    stderr.writeln('usage: dart run bin/gen_vectors.dart [--check]');
    exit(64);
  }
  final vectorsDir = Directory.fromUri(
    Platform.script.resolve('../../../vectors/'),
  );
  final signatures = await signatureVectors();
  final files = {
    'signatures.json': signatures,
    'link_handshake.json': await linkVectors(signatures),
    'bundles.json': await bundleVectors(),
  };
  var differ = 0;
  for (final MapEntry(key: name, value: data) in files.entries) {
    final text = '${const JsonEncoder.withIndent('  ').convert(data)}\n';
    final file = File('${vectorsDir.path}$name');
    if (check) {
      if (!file.existsSync() || file.readAsStringSync() != text) {
        stderr.writeln('$name is not what gen_vectors.dart writes now');
        differ++;
      }
    } else {
      file.writeAsStringSync(text);
      stdout.writeln('wrote ${file.path}');
    }
  }
  if (check) {
    stdout.writeln(differ == 0 ? 'vectors current' : '$differ file(s) differ');
  }
  exit(differ == 0 ? 0 : 1);
}
