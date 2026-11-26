// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// What tsm reads from and writes to: standard output (bytes: a value goes
/// out as it is), standard error, the terminal for passwords, standard
/// input, the environment, the OS keychain, the clock, and the commands
/// `tsm run` starts. The command line uses the process's; tests pass their
/// own.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_build_base/tom_build_base_v2.dart' show ConsoleMarkdownSink;
import 'package:tom_core_storage/io.dart' show TomDesktopSecretStore;
import 'package:tom_core_storage/settings.dart'
    show TomSecretStore, TomSecretStoreAvailability;
import 'package:tom_secrets_client/admin.dart'
    show
        TomSecretsEndpointInspector,
        TomSecretsIdentityTrust,
        TomSecretsSystemEndpointInspector,
        TomSecretsSystemInstall,
        tomSecretsKeychainService;

/// tsm's input and output.
final class TsmIo {
  /// The streams and services tsm uses.
  TsmIo({
    required this.writeOut,
    required this.err,
    required this.readSecret,
    required this.readLine,
    required this.environment,
    required this.keychain,
    required this.executableDirectory,
    required this.runCommand,
    this.endpointInspector = const TomSecretsSystemEndpointInspector(),
    this.identity,
    this.systemInstall = TomSecretsSystemInstall.read,
    DateTime Function()? clock,
    StringSink? messages,
  }) : clock = clock ?? DateTime.now,
       messages = messages ?? err;

  /// The process's own: standard output and error, the terminal without
  /// echo for passwords, the OS keychain where one answers, the directory of
  /// tsm's executable, and commands started with tsm's standard streams.
  factory TsmIo.system() {
    final lines = stdin
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .asBroadcastStream();
    Future<String?> line() async {
      try {
        return await lines.first;
      } on StateError {
        return null;
      }
    }

    TomSecretStore? keychain;
    var keychainChecked = false;
    return TsmIo(
      writeOut: stdout.add,
      err: stderr,
      readSecret: (prompt) async {
        if (!stdin.hasTerminal) return line();
        stderr.write(prompt);
        final echo = stdin.echoMode;
        stdin.echoMode = false;
        try {
          return stdin.readLineSync();
        } finally {
          stdin.echoMode = echo;
          stderr.writeln();
        }
      },
      readLine: line,
      environment: Platform.environment,
      keychain: () async {
        if (keychainChecked) return keychain;
        keychainChecked = true;
        final store = TomDesktopSecretStore(service: tomSecretsKeychainService);
        keychain = await (store as TomSecretStoreAvailability).isAvailable()
            ? store
            : null;
        return keychain;
      },
      executableDirectory: File(Platform.resolvedExecutable).parent.path,
      runCommand: tsmRunInheriting,
      // The help and the runner's own messages, their markup rendered.
      messages: ConsoleMarkdownSink(stderr),
    );
  }

  /// Writes bytes to standard output.
  final void Function(List<int> bytes) writeOut;

  /// Standard error: messages, prompts, progress.
  final StringSink err;

  /// Where the help and the command line's own messages go (standard
  /// error, its console markup rendered).
  final StringSink messages;

  /// Reads a secret after [prompt], without echo on a terminal; null at the
  /// end of the input.
  final Future<String?> Function(String prompt) readSecret;

  /// Reads one line of standard input; null at its end.
  final Future<String?> Function() readLine;

  /// The environment (`TSM_RUNTIME_DIR`, `TSM_DATA_DIR`, `TSM_SERVICE`).
  final Map<String, String> environment;

  /// The OS keychain, or null where none answers (an SSH session without a
  /// D-Bus session, ...).
  final Future<TomSecretStore?> Function() keychain;

  /// The directory of tsm's executable, where the service's is looked for.
  final String executableDirectory;

  /// Reads who answers on the admin endpoint (protocol.md 6.0).
  final TomSecretsEndpointInspector endpointInspector;

  /// What the service's identity key is checked with (protocol.md 6.1);
  /// null (the command line): the pin file tsm shares with the app, and
  /// the primitives of the service executable's helper mode.
  final TomSecretsIdentityTrust? identity;

  /// The system install of this machine (`tsm install --system`), whose
  /// service tsm starts and expects; null where there is none.
  final TomSecretsSystemInstall? Function() systemInstall;

  /// Starts [command] with [environment] added to tsm's own, its standard
  /// streams tsm's, and answers its exit code.
  final Future<int> Function(
    List<String> command,
    Map<String, String> environment,
  )
  runCommand;

  /// The time.
  final DateTime Function() clock;

  /// Writes [text] to standard output.
  void out(String text) => writeOut(utf8.encode(text));

  /// Writes [text] and a line break to standard output.
  void outln([String text = '']) => out('$text\n');
}

/// Starts [command] with [environment] added, inheriting tsm's standard
/// streams; SIGINT and SIGTERM reach it (on Windows SIGINT: Ctrl-C and
/// Ctrl-Break),
/// and its exit code is answered.
Future<int> tsmRunInheriting(
  List<String> command,
  Map<String, String> environment,
) async {
  final process = await Process.start(
    command.first,
    command.sublist(1),
    environment: environment,
    mode: ProcessStartMode.inheritStdio,
    runInShell: Platform.isWindows,
  );
  final forwards = <StreamSubscription<ProcessSignal>>[
    for (final signal
        in Platform.isWindows
            ? [ProcessSignal.sigint]
            : [ProcessSignal.sigint, ProcessSignal.sigterm])
      signal.watch().listen(process.kill),
  ];
  try {
    return await process.exitCode;
  } finally {
    for (final f in forwards) {
      await f.cancel();
    }
  }
}
