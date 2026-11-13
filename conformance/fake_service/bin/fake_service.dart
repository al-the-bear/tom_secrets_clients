// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The conformance suite's fake secrets service.
//
//   fake_service --dir <runtime dir> --script <script.json> --record <file>
//                [--transport unix|tcp]
//
// Listens in the runtime directory (a Unix socket, or with tcp - the default
// on Windows - a localhost port with client.port and client.token), prints
// `ready` on standard output, follows the script, and when its standard input
// closes writes everything it received to the record file and exits.

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_fake_service/fake_service.dart';

Future<void> main(List<String> args) async {
  String? option(String name) {
    final i = args.indexOf('--$name');
    return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
  }

  final dir = option('dir');
  final scriptPath = option('script');
  final recordPath = option('record');
  final transport =
      option('transport') ?? (Platform.isWindows ? 'tcp' : 'unix');
  if (dir == null ||
      scriptPath == null ||
      recordPath == null ||
      !{'unix', 'tcp'}.contains(transport)) {
    stderr.writeln(
      'usage: fake_service --dir <dir> --script <file> --record <file> '
      '[--transport unix|tcp]',
    );
    exit(64);
  }
  final script =
      jsonDecode(File(scriptPath).readAsStringSync()) as Map<String, Object?>;
  final service = await FakeService.start(
    directory: dir,
    script: script,
    transport: transport,
  );
  stdout.writeln('ready');
  await stdout.flush();
  await stdin.drain<void>();
  await service.stop();
  File(recordPath).writeAsStringSync(jsonEncode(service.record()));
  exit(0);
}
