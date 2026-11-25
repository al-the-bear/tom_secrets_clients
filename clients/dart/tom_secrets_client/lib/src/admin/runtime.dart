// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The runtime directory (part-service, protocol.md 3): per OS user, the
/// user's alone (mode 0700; on Windows an ACL of the user and SYSTEM),
/// checked for owner and mode at every start; the single-instance lock
/// `service.lock`, `service.json`, and the endpoint files.
library;

import 'dart:convert';
import 'dart:io';

import '../../tom_secrets_client.dart';
import 'service_trust.dart';
import 'windows_acl.dart';

/// A runtime directory that is not the user's alone, or cannot be made.
final class TomSecretsRuntimeException implements Exception {
  /// A problem described by [message].
  TomSecretsRuntimeException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsRuntimeException: $message';
}

/// Another service already holds the lock: the starter attaches to it.
final class TomSecretsAlreadyRunning implements Exception {
  /// The running service's `service.json`, when it could be read.
  TomSecretsAlreadyRunning(this.info);

  /// `service.json` of the running service, or null.
  final Map<String, Object?>? info;

  @override
  String toString() => 'TomSecretsAlreadyRunning';
}

/// How the endpoints are offered: Unix domain sockets (Linux, macOS) or
/// localhost TCP ports with a client token (Windows).
enum TomSecretsTransport {
  /// `client.sock`, `admin.sock`.
  unix,

  /// `client.port` + `client.token`, `admin.port`.
  tcp,
}

/// The runtime directory of this OS user.
final class TomSecretsRuntime {
  /// The runtime directory at [directory], its endpoints offered over
  /// [transport]; its files joined with [separator] (default this
  /// platform's).
  TomSecretsRuntime(
    this.directory, {
    required this.transport,
    String? separator,
  }) : separator = separator ?? Platform.pathSeparator;

  /// The runtime directory protocol.md 3.1 names for this process (or
  /// [environment] and [operatingSystem]); Unix sockets except on Windows.
  factory TomSecretsRuntime.current({
    Map<String, String>? environment,
    String? operatingSystem,
  }) {
    final os = operatingSystem ?? Platform.operatingSystem;
    final location = discoverTomSecrets(
      operatingSystem: os,
      environment: environment ?? Platform.environment,
    );
    if (location is! TomSecretsEndpoints) {
      throw TomSecretsRuntimeException(
        'no runtime directory: neither LOCALAPPDATA nor USERPROFILE is set',
      );
    }
    return TomSecretsRuntime(
      location.directory,
      transport: os == 'windows'
          ? TomSecretsTransport.tcp
          : TomSecretsTransport.unix,
      // The paths of the OS asked for, not of the one this runs on.
      separator: os == 'windows' ? r'\' : '/',
    );
  }

  /// The directory.
  final String directory;

  /// How the endpoints are offered.
  final TomSecretsTransport transport;

  /// The path separator its files are joined with.
  final String separator;

  String _path(String name) => '$directory$separator$name';

  /// `client.sock`.
  String get clientSocket => _path('client.sock');

  /// `admin.sock`.
  String get adminSocket => _path('admin.sock');

  /// `agent.sock`, the ssh-agent's Unix domain socket (Linux, macOS; phase
  /// B): what `SSH_AUTH_SOCK` or `IdentityAgent` names.
  String get agentSocket => _path('agent.sock');

  /// The ssh-agent's named pipe on Windows (phase B), the same for every
  /// user (the pipe's ACL admits only the service's user).
  static const String agentPipe = r'\\.\pipe\tsm-ssh-agent';

  /// Where `ssh` finds the agent on this runtime's OS: [agentPipe] on
  /// Windows, else [agentSocket].
  String get agentEndpoint =>
      transport == TomSecretsTransport.tcp ? agentPipe : agentSocket;

  /// `client.port`.
  String get clientPortFile => _path('client.port');

  /// `client.token`.
  String get clientTokenFile => _path('client.token');

  /// `admin.port`.
  String get adminPortFile => _path('admin.port');

  /// `service.lock`.
  String get lockFile => _path('service.lock');

  /// `service.json`.
  String get infoFile => _path('service.json');

  /// The endpoint files of [transport], every one a start writes.
  List<String> get endpointFiles => switch (transport) {
    TomSecretsTransport.unix => [clientSocket, adminSocket, agentSocket],
    TomSecretsTransport.tcp => [clientPortFile, clientTokenFile, adminPortFile],
  };

  /// Makes the directory the user's alone when missing, then checks it:
  /// owned by this user with no access for anyone else (POSIX: mode 0700;
  /// Windows: the inheritance cut and only the user and SYSTEM granted).
  /// A directory of someone else, or one others can read, is refused.
  Future<void> prepare() async {
    final dir = Directory(directory);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      if (Platform.isWindows) {
        await tomSecretsRestrictWindowsDirectory(directory);
      } else {
        await _run('chmod', ['700', directory]);
      }
    }
    await check();
  }

  /// Checks owner and mode (see [prepare]): a directory that exists but is
  /// not this user's own is refused, never used or changed.
  Future<void> check() async {
    if (Platform.isWindows) {
      for (final who in await tomSecretsWindowsGrantees(directory)) {
        if (!tomSecretsWindowsUserOnly({who})) {
          throw TomSecretsRuntimeException(
            'the runtime directory grants $who access',
          );
        }
      }
      return;
    }
    // The directory itself, not what a link there points to: in `/tmp`
    // another user can leave a link, or the directory, first.
    final why = tomSecretsJudgeFile(
      'runtime directory',
      tomSecretsStatFiles([directory])[directory],
      'directory',
      currentUid(),
    );
    if (why != null) throw TomSecretsRuntimeException(why.message);
  }

  static Future<String> _run(String executable, List<String> args) async {
    final result = await Process.run(executable, args);
    if (result.exitCode != 0) {
      throw TomSecretsRuntimeException(
        '$executable ${args.first} failed: ${result.stderr}',
      );
    }
    return result.stdout as String;
  }

  RandomAccessFile? _lock;

  // POSIX record locks belong to the process: a second lock of the same file
  // from this process would succeed, so the locks held here are remembered.
  static final Set<String> _held = {};

  /// Takes the exclusive single-instance lock on `service.lock`; the OS
  /// releases it when the process dies. Throws [TomSecretsAlreadyRunning]
  /// when another service (another process, or this one) holds it.
  Future<void> acquire() async {
    final key = File(lockFile).absolute.path;
    if (_held.contains(key)) throw TomSecretsAlreadyRunning(await readInfo());
    final file = await File(lockFile).open(mode: FileMode.append);
    try {
      await file.lock(FileLock.exclusive);
    } on FileSystemException {
      await file.close();
      throw TomSecretsAlreadyRunning(await readInfo());
    }
    _lock = file;
    _held.add(key);
  }

  /// Releases the lock.
  Future<void> release() async {
    final lock = _lock;
    _lock = null;
    if (lock == null) return;
    _held.remove(File(lockFile).absolute.path);
    await lock.unlock();
    await lock.close();
  }

  /// Deletes the endpoint files a dead instance left (only after [acquire]).
  Future<void> removeStaleEndpoints() async {
    // A socket is not a File to `exists`; its type is asked instead.
    for (final name in endpointFiles) {
      if (await FileSystemEntity.type(name, followLinks: false) !=
          FileSystemEntityType.notFound) {
        await File(name).delete();
      }
    }
  }

  /// Deletes the endpoint files and `service.json` (a stop).
  Future<void> removeEndpoints() async {
    await removeStaleEndpoints();
    final info = File(infoFile);
    if (await info.exists()) await info.delete();
  }

  /// Writes `service.json`: PID, start, protocol, the endpoints (the
  /// ssh-agent's [agent] `{socket}` or `{pipe}` when it runs); no secret.
  Future<void> writeInfo({
    required int start,
    required Map<String, Object?> client,
    required Map<String, Object?> admin,
    Map<String, Object?>? agent,
  }) => _writeFile(
    infoFile,
    jsonEncode({
      'pid': pid,
      'start': start,
      'protocol': 1,
      'client': client,
      'admin': admin,
      'agent': ?agent,
    }),
  );

  /// `service.json`, or null.
  Future<Map<String, Object?>?> readInfo() async {
    try {
      return (jsonDecode(await File(infoFile).readAsString()) as Map)
          .cast<String, Object?>();
    } on Object {
      return null;
    }
  }

  /// Writes [text] to [path] through a temporary file and a rename.
  static Future<void> _writeFile(String path, String text) async {
    final temp = File('$path.tmp');
    await temp.writeAsString(text, flush: true);
    await temp.rename(path);
  }

  /// Writes a port file.
  Future<void> writePort(String path, int port) => _writeFile(path, '$port\n');

  /// Writes the client token.
  Future<void> writeToken(String token) =>
      _writeFile(clientTokenFile, '$token\n');
}
