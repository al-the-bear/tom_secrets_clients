// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Finding the service (protocol.md section 3).
library;

import 'dart:ffi';
import 'dart:io';

/// Where the service's endpoints are, by the rules of protocol.md 3.1.
sealed class TomSecretsLocation {
  const TomSecretsLocation();
}

/// The runtime directory and its endpoint files.
final class TomSecretsEndpoints extends TomSecretsLocation {
  /// The directory and the files of its OS.
  const TomSecretsEndpoints({
    required this.directory,
    this.clientSocket,
    this.adminSocket,
    this.clientPortFile,
    this.clientTokenFile,
    this.adminPortFile,
  });

  /// The runtime directory.
  final String directory;

  /// Linux and macOS: the client endpoint's Unix domain socket.
  final String? clientSocket;

  /// Linux and macOS: the admin endpoint's Unix domain socket.
  final String? adminSocket;

  /// Windows: the client endpoint's port file.
  final String? clientPortFile;

  /// Windows: the client token of this service start.
  final String? clientTokenFile;

  /// Windows: the admin endpoint's port file.
  final String? adminPortFile;
}

/// No runtime directory can be named (Windows without `LOCALAPPDATA` and
/// `USERPROFILE`): the service is `not_running`.
final class TomSecretsNoRuntimeDirectory extends TomSecretsLocation {
  /// Why: `no_runtime_directory`.
  const TomSecretsNoRuntimeDirectory(this.reason);

  /// `no_runtime_directory`.
  final String reason;
}

String _strip(String path, String sep) {
  var end = path.length;
  while (end > 0 &&
      (path[end - 1] == '/' || (sep == r'\' && path[end - 1] == r'\'))) {
    end--;
  }
  return end == 0 ? path : path.substring(0, end);
}

/// The location of the service for [operatingSystem] (`linux`, `macos`,
/// `windows`; others are treated as `linux`), [environment] and the numeric
/// user id [uid] (needed only for the `/tmp/tsm-<uid>` fallback).
TomSecretsLocation discoverTomSecrets({
  required String operatingSystem,
  required Map<String, String> environment,
  int? Function()? uid,
}) {
  final windows = operatingSystem == 'windows';
  final sep = windows ? r'\' : '/';
  String fallback() => '/tmp/tsm-${(uid ?? currentUid)()}';
  final override = environment['TSM_RUNTIME_DIR'] ?? '';
  final String directory;
  if (override.isNotEmpty) {
    directory = _strip(override, sep);
  } else if (windows) {
    final local = environment['LOCALAPPDATA'] ?? '';
    final profile = environment['USERPROFILE'] ?? '';
    final String base;
    if (local.isNotEmpty) {
      base = _strip(local, r'\');
    } else if (profile.isNotEmpty) {
      base = '${_strip(profile, r'\')}\\AppData\\Local';
    } else {
      return const TomSecretsNoRuntimeDirectory('no_runtime_directory');
    }
    directory = '$base\\TomSecretsManager\\run';
  } else {
    final variable = operatingSystem == 'macos' ? 'TMPDIR' : 'XDG_RUNTIME_DIR';
    final value = environment[variable] ?? '';
    directory = value.startsWith('/')
        ? '${_strip(value, '/')}/tsm'
        : fallback();
  }
  if (windows) {
    return TomSecretsEndpoints(
      directory: directory,
      clientPortFile: '$directory\\client.port',
      clientTokenFile: '$directory\\client.token',
      adminPortFile: '$directory\\admin.port',
    );
  }
  return TomSecretsEndpoints(
    directory: directory,
    clientSocket: '$directory/client.sock',
    adminSocket: '$directory/admin.sock',
  );
}

final RegExp _port = RegExp(r'^[1-9][0-9]{0,4}$');

/// The port of a port file's [text] (decimal 1-65535, no sign or leading
/// zero, at most one trailing LF or CR LF), or null when it is unreadable.
int? readTomSecretsPortFile(String text) {
  final body = text.endsWith('\r\n')
      ? text.substring(0, text.length - 2)
      : text.endsWith('\n')
      ? text.substring(0, text.length - 1)
      : text;
  if (!_port.hasMatch(body)) return null;
  final port = int.parse(body);
  return port <= 65535 ? port : null;
}

/// The numeric id of the process's user (POSIX `getuid`); null on Windows.
int? currentUid() {
  if (Platform.isWindows) return null;
  final getuid = DynamicLibrary.process()
      .lookupFunction<Uint32 Function(), int Function()>('getuid');
  return getuid();
}
