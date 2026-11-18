// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `tsm` — built as a native executable (`dart build cli`): the service
/// identifies a client by its executable, and `dart run` would show up as
/// the Dart VM.
library;

import 'dart:io';

import 'package:tom_secrets_tsm/tom_secrets_tsm.dart';

Future<void> main(List<String> arguments) async {
  // Multi-call (part-os-integration): git runs tsm as git-credential-tsm.
  final io = TsmIo.system();
  final code = tsmInvokedName(Platform.executable) == tsmGitCredentialName
      ? await tsmGitCredential(arguments, io)
      : await tsmMain(arguments, io);
  await stdout.flush();
  await stderr.flush();
  exit(code);
}
