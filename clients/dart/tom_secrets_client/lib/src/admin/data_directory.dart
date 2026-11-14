// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Where the Tom Secrets Manager keeps its data for one OS user: the
/// bootstrap file `bootstrap.yaml`, and by default the offline cache, the
/// device settings container, the audit log and the service's log. The app,
/// the service and `tsm` find the bootstrap file here unless told otherwise.
library;

import 'dart:io';

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
