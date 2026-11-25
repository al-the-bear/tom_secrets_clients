// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Where the Tom Secrets Manager keeps its data for one OS user: the
/// bootstrap file `bootstrap.yaml`, and by default the offline cache, the
/// device settings container, the audit log and the service's log. The app,
/// the service and `tsm` find the bootstrap file here unless told otherwise.
library;

import 'dart:io';

import '../discovery.dart' show currentUid;
import 'windows_acl.dart';

/// The data directory: `TSM_DATA_DIR` when set; on macOS
/// `~/Library/Application Support/TomSecretsManager`; on Windows
/// `%LOCALAPPDATA%\TomSecretsManager` (the runtime directory is its `run\`);
/// elsewhere `$XDG_DATA_HOME/tom-secrets-manager`, else
/// `~/.local/share/tom-secrets-manager`. [environment] and
/// [operatingSystem] default to this process's.
///
/// Throws [StateError] when the variables it is built from are not set.
String tomSecretsDataDirectory({
  Map<String, String>? environment,
  String? operatingSystem,
}) {
  final env = environment ?? Platform.environment;
  final os = operatingSystem ?? Platform.operatingSystem;
  final explicit = env['TSM_DATA_DIR'];
  if (explicit != null && explicit.isNotEmpty) return explicit;
  String need(String name) {
    final value = env[name];
    if (value == null || value.isEmpty) {
      throw StateError('no data directory: $name is not set');
    }
    return value;
  }

  switch (os) {
    case 'macos':
      return '${need('HOME')}/Library/Application Support/TomSecretsManager';
    case 'windows':
      return '${need('LOCALAPPDATA')}\\TomSecretsManager';
    default:
      final xdg = env['XDG_DATA_HOME'];
      return xdg != null && xdg.isNotEmpty
          ? '$xdg/tom-secrets-manager'
          : '${need('HOME')}/.local/share/tom-secrets-manager';
  }
}

/// The default bootstrap file: `bootstrap.yaml` in [tomSecretsDataDirectory].
String tomSecretsBootstrapPath({
  Map<String, String>? environment,
  String? operatingSystem,
}) {
  final os = operatingSystem ?? Platform.operatingSystem;
  final separator = os == 'windows' ? '\\' : '/';
  return '${tomSecretsDataDirectory(environment: environment, operatingSystem: os)}'
      '${separator}bootstrap.yaml';
}

/// A data directory that is not the user's alone and cannot be made so.
final class TomSecretsDataDirectoryException implements Exception {
  /// A problem described by [message].
  TomSecretsDataDirectoryException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsDataDirectoryException: $message';
}

/// What [tomSecretsPrepareDataDirectory] did.
final class TomSecretsDataDirectoryState {
  /// [created] when it made the folder; [tightened] the entries (the folder
  /// included) others could reach before.
  const TomSecretsDataDirectoryState({
    required this.created,
    required this.tightened,
  });

  /// Whether the folder was made.
  final bool created;

  /// How many entries others could reach before (the folder included); 0
  /// when it already was the user's alone.
  final int tightened;
}

/// Makes the data directory [path] the user's alone, as the runtime
/// directory is: a missing one is created with no access for anyone else
/// (POSIX: mode 0700; Windows: the inheritance cut, only the user and
/// SYSTEM granted, inherited by what is inside). An existing one that
/// others can reach is tightened: on POSIX group and others lose every bit
/// on the folder and on everything inside (`chmod -R go=`, so files are
/// 0600, folders 0700, the user's own bits kept); on Windows the ACL is
/// replaced as for a new one. The data directory holds the offline cache,
/// the audit log, the device settings, the service's log and the agent's
/// keys, none of them for another user.
///
/// Throws [TomSecretsDataDirectoryException] for a path that is not a
/// folder, a folder another user owns (POSIX), or one that cannot be
/// tightened.
Future<TomSecretsDataDirectoryState> tomSecretsPrepareDataDirectory(
  String path,
) async {
  final dir = Directory(path);
  final type = await FileSystemEntity.type(path);
  if (type != FileSystemEntityType.notFound &&
      type != FileSystemEntityType.directory) {
    throw TomSecretsDataDirectoryException('$path is not a folder');
  }
  final created = type == FileSystemEntityType.notFound;
  if (created) await dir.create(recursive: true);
  try {
    return Platform.isWindows
        ? await _prepareWindows(path, created)
        : await _preparePosix(path, created);
  } on FileSystemException catch (e) {
    throw TomSecretsDataDirectoryException(
      'the data directory $path could not be made the user\'s alone: '
      '${e.message}',
    );
  }
}

Future<TomSecretsDataDirectoryState> _preparePosix(
  String path,
  bool created,
) async {
  final owner = await _run('stat', [
    Platform.isMacOS ? '-f' : '-c',
    '%u',
    path,
  ]);
  final me = currentUid();
  if (me != null && int.tryParse(owner.trim()) != me) {
    throw TomSecretsDataDirectoryException(
      'the data directory $path belongs to user ${owner.trim()}, not to '
      'this user ($me)',
    );
  }
  var loose = 0;
  if ((await FileStat.stat(path)).mode & 0x3F != 0) loose++;
  await for (final entry in Directory(
    path,
  ).list(recursive: true, followLinks: false)) {
    if (entry is Link) continue;
    if ((await entry.stat()).mode & 0x3F != 0) loose++;
  }
  // Why: one chmod for the whole tree, not one process per file; the
  // user's own bits stay as they are.
  if (loose > 0) await _run('chmod', ['-R', 'go=', path]);
  return TomSecretsDataDirectoryState(
    created: created,
    tightened: created ? 0 : loose,
  );
}

Future<TomSecretsDataDirectoryState> _prepareWindows(
  String path,
  bool created,
) async {
  if (created) {
    await tomSecretsRestrictWindowsDirectory(path);
    return const TomSecretsDataDirectoryState(created: true, tightened: 0);
  }
  if (tomSecretsWindowsUserOnly(await tomSecretsWindowsGrantees(path))) {
    return const TomSecretsDataDirectoryState(created: false, tightened: 0);
  }
  await tomSecretsRestrictWindowsDirectory(path);
  if (!tomSecretsWindowsUserOnly(await tomSecretsWindowsGrantees(path))) {
    throw TomSecretsDataDirectoryException(
      'the data directory $path still grants others access',
    );
  }
  return const TomSecretsDataDirectoryState(created: false, tightened: 1);
}

// Why synchronous: `stat` and `chmod` return at once, and a caller running
// in a zone that only pumps its own microtasks (a widget test, the app's
// First run under one) would never see an asynchronous process finish.
Future<String> _run(String executable, List<String> args) async {
  final result = Process.runSync(executable, args);
  if (result.exitCode != 0) {
    throw FileSystemException(
      '$executable ${args.join(' ')} failed: ${result.stderr}',
    );
  }
  return result.stdout as String;
}
