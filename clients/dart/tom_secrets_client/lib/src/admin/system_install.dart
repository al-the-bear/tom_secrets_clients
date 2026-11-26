// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The system install of the service on a shared Linux server
/// (`tsm install --system`, tsm_d11): the service installed root-owned and
/// set-group-ID to [tomSecretsSystemGroup], which alone reaches the
/// directory of the identity keys, and the record of the install the
/// programs of every user read to find and expect that service.
library;

import 'dart:convert';
import 'dart:io';

import 'service_trust.dart' show tomSecretsStatFiles;

/// The group the system-installed service runs with (set-group-ID): the
/// only one that reaches [tomSecretsSystemIdentityDirectory].
const String tomSecretsSystemGroup = 'tsm-identity';

/// Where a system install puts the service and `tsm` (`bin/`, `lib/`).
const String tomSecretsSystemPrefix = '/opt/tom-secrets-manager';

/// The directory of the system-installed service's identity keys, one per
/// user (`<uid>.json`): root's, of [tomSecretsSystemGroup], mode 2770, so
/// no user reaches it, the installed service does.
const String tomSecretsSystemIdentityDirectory =
    '/var/lib/tom-secrets-manager/identity';

/// The record of a system install, root's and readable by everyone.
const String tomSecretsSystemRecord = '/etc/tom-secrets-manager/system.json';

/// Where a system install links `tsm` for every user.
const String tomSecretsSystemTsmLink = '/usr/local/bin/tsm';

/// A system install as its record says.
final class TomSecretsSystemInstall {
  /// An install of [version] with [prefix] holding the service.
  const TomSecretsSystemInstall({
    required this.prefix,
    required this.version,
    required this.installed,
    this.group = tomSecretsSystemGroup,
    this.identityDirectory = tomSecretsSystemIdentityDirectory,
  });

  /// From the record's JSON; null when it is not one.
  static TomSecretsSystemInstall? fromJson(Object? json) {
    if (json is! Map || json['prefix'] is! String) return null;
    return TomSecretsSystemInstall(
      prefix: json['prefix'] as String,
      version: '${json['version'] ?? ''}',
      installed:
          DateTime.tryParse('${json['installed']}')?.toUtc() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      group: json['group'] as String? ?? tomSecretsSystemGroup,
      identityDirectory:
          json['identityDirectory'] as String? ??
          tomSecretsSystemIdentityDirectory,
    );
  }

  /// The system install of this machine, or null: on Linux only, and only
  /// from a record root owns that no one else may write (a record any user
  /// could write would let them name the service every program expects).
  static TomSecretsSystemInstall? read({
    String path = tomSecretsSystemRecord,
    bool requireRoot = true,
  }) {
    if (!Platform.isLinux && requireRoot) return null;
    final file = File(path);
    if (!file.existsSync()) return null;
    if (requireRoot) {
      final facts = tomSecretsStatFiles([path])[path];
      if (facts == null ||
          facts.owner != 0 ||
          facts.type != 'file' ||
          facts.mode & 0x12 != 0) {
        return null;
      }
    }
    try {
      return fromJson(jsonDecode(file.readAsStringSync()));
    } on FormatException {
      return null;
    }
  }

  /// The folder of `bin/` and `lib/`.
  final String prefix;

  /// The version installed.
  final String version;

  /// When it was installed.
  final DateTime installed;

  /// The group of the service.
  final String group;

  /// The directory of the identity keys.
  final String identityDirectory;

  /// The service executable.
  String get serviceExecutable => '$prefix/bin/tom_secrets_service';

  /// `tsm` beside it.
  String get tsmExecutable => '$prefix/bin/tsm';

  /// The record's JSON.
  Map<String, Object?> toJson() => {
    'version': version,
    'prefix': prefix,
    'group': group,
    'identityDirectory': identityDirectory,
    'installed': installed.toUtc().toIso8601String(),
  };
}
