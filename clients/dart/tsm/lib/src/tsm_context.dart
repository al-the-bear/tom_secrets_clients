// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// What every tsm command shares: its input and output, the runtime
/// directory, the admin connection (the admin key from the keychain, else a
/// `claim` with the master password, DP-22), the exit codes, and the way
/// errors are told.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:tom_core_storage/settings.dart' show TomSecretStoreException;
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'tsm_io.dart';

/// tsm's exit codes (part-clients): scripts can tell the cases apart.
abstract final class TsmExit {
  /// Success (for `run`, the command's own code).
  static const int ok = 0;

  /// A usage error.
  static const int usage = 2;

  /// The exit code of an error [kind] (protocol.md 10, or `not_running`).
  static int of(String kind) => switch (kind) {
    'not_running' => 3,
    'locked' => 4,
    'denied' => 5,
    'not_found' => 6,
    'ambiguous' => 7,
    'malformed' => 8,
    'timeout' || 'rate_limited' => 9,
    'unsupported' => 10,
    // The admin endpoint is not this user's service: nothing was sent.
    'service_untrusted' => 12,
    _ => 11, // internal, needs_unlock, unavailable, offline, token_expired
  };
}

/// A failure a command reports: its message on standard error and [code].
final class TsmFailure implements Exception {
  /// A failure with exit [code] and [message].
  TsmFailure(this.code, this.message);

  /// A usage error.
  factory TsmFailure.usage(String message) =>
      TsmFailure(TsmExit.usage, message);

  /// The exit code.
  final int code;

  /// What went wrong.
  final String message;

  @override
  String toString() => 'TsmFailure($code): $message';
}

/// The context of one tsm invocation.
final class TsmContext {
  /// A context over [io].
  TsmContext(this.io);

  /// The input and output.
  final TsmIo io;

  /// Whether passwords are read from standard input (`--password-stdin`).
  bool passwordFromStdin = false;

  /// The key file given (`--key-file`), with the master password.
  List<int>? keyFile;

  /// The exit code `tsm run` ends with, which may exceed what a tool
  /// result carries; the command line exits with it.
  int? processExitCode;

  String? _password;

  /// The service executable a command named (`--service`), which the
  /// check of who answers on the admin endpoint then expects too.
  String? namedService;

  /// The check an admin connection runs before it sends anything
  /// (protocol.md 6.0): the service expected is the one beside tsm, the
  /// one `TSM_SERVICE` names, or [namedService].
  TomSecretsServiceTrust get serviceTrust => TomSecretsServiceTrust(
    executables: tomSecretsExpectedServiceExecutables(
      ownExecutable: '${io.executableDirectory}${Platform.pathSeparator}tsm',
      environment: io.environment,
      configured: [?namedService],
    ),
    inspector: io.endpointInspector,
  );

  /// The runtime directory (`TSM_RUNTIME_DIR`, else protocol.md 3.1).
  TomSecretsRuntime get runtime =>
      TomSecretsRuntime.current(environment: io.environment);

  /// The master password: asked once per invocation (on the terminal
  /// without echo, or as the first line of standard input with
  /// `--password-stdin`).
  Future<String> password() async {
    if (_password != null) return _password!;
    final text = passwordFromStdin
        ? await io.readLine()
        : await io.readSecret('Master password: ');
    if (text == null || text.isEmpty) {
      throw TsmFailure.usage('no master password given');
    }
    return _password = text;
  }

  /// Forgets the master password read, so the next [password] asks again
  /// (a wrong one).
  void forgetPassword() => _password = null;

  /// Connects to the admin endpoint: with the admin key the keychain keeps
  /// for this start of the service, else by `claim` with the master
  /// password, keeping the new key in the keychain where there is one.
  Future<TomSecretsAdminClient> admin() async {
    final rt = runtime;
    final info = await rt.readInfo();
    final start = info?['start'];
    if (start is! int) {
      throw TsmFailure(TsmExit.of('not_running'), 'the service is not running');
    }
    final keyring = await adminKeyring();
    if (keyring != null) {
      Uint8List? stored;
      try {
        stored = await keyring.keyOf(start);
      } on TomSecretStoreException {
        stored = null;
      }
      if (stored != null) {
        try {
          final client = await TomSecretsAdminClient.connect(
            rt,
            stored,
            trust: serviceTrust,
          );
          await _pruneOthers(keyring, start);
          return client;
        } on TomSecretsAdminException catch (e) {
          // Another admin claimed the service since: claim again. An
          // endpoint that is not this user's service gets no claim.
          if (e.kind == 'not_running' || e.kind == tomSecretsServiceUntrusted) {
            rethrow;
          }
        }
      }
    }
    // Checked before the password is asked for, so it is never typed for
    // an endpoint that is not this user's service.
    await TomSecretsAdminClient.checkService(rt, trust: serviceTrust);
    final (client, key) = await TomSecretsAdminClient.claim(
      rt,
      password: await password(),
      keyFile: keyFile,
      trust: serviceTrust,
    );
    await keepAdminKey(start, key);
    return client;
  }

  /// The admin keys in the keychain, or null where there is none.
  Future<TomSecretsAdminKeyring?> adminKeyring() async {
    final keychain = await io.keychain();
    if (keychain == null) return null;
    return TomSecretsAdminKeyring(
      read: keychain.read,
      write: keychain.write,
      delete: keychain.delete,
    );
  }

  /// Keeps [key], the admin key of the service started at [start], in the
  /// keychain where there is one, and removes the keys of services that are
  /// gone.
  Future<void> keepAdminKey(int start, Uint8List key) async {
    final keyring = await adminKeyring();
    if (keyring == null) return;
    try {
      await keyring.keep(start, key);
    } on TomSecretStoreException {
      // Without the keychain the next command claims again (DP-22).
      return;
    }
    await _pruneOthers(keyring, start);
  }

  /// Removes the admin key of the service started at [start], which was
  /// stopped.
  Future<void> forgetAdminKey(int start) async {
    final keyring = await adminKeyring();
    if (keyring == null) return;
    try {
      await keyring.forget(start);
    } on TomSecretStoreException {
      // A key left behind is removed by the next prune.
    }
  }

  Future<void> _pruneOthers(TomSecretsAdminKeyring keyring, int start) async {
    try {
      await keyring.pruneOthers(start);
    } on TomSecretStoreException {
      // Tried again the next time a key is kept or used.
    }
  }

  /// Reads the key file at [path].
  Future<void> readKeyFile(String path) async {
    final file = File(path);
    if (!await file.exists()) {
      throw TsmFailure.usage('no key file at $path');
    }
    keyFile = await file.readAsBytes();
  }

  /// The exit code of an admin error, told on standard error.
  int adminError(TomSecretsAdminException e) =>
      _tell(e.kind, e.message, e.details);

  /// The exit code of a client error, told on standard error.
  int clientError(TomSecretsClientException e) =>
      _tell(e.kind.wireName, e.message, e.details);

  int _tell(String kind, String message, Map<String, Object?> details) {
    final extra = [
      if (details['reason'] != null) 'reason ${details['reason']}',
      if (details['stores'] is List)
        'stores ${(details['stores']! as List).join(', ')}',
      if (details['store'] != null) 'store ${details['store']}',
    ];
    io.err.writeln(
      'tsm: $kind: $message${extra.isEmpty ? '' : ' (${extra.join('; ')})'}',
    );
    if (kind == tomSecretsServiceUntrusted) {
      io.err.writeln(
        'tsm: ${tomSecretsUntrustedAdvice(details['reason'] as String?)}',
      );
    }
    return TsmExit.of(kind);
  }
}
