// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service installed on its own for one user (`tsm install`, tsm_d12):
/// the command-line tools (`bin/`, `lib/`) copied out of the app's
/// distribution or a tools archive into a folder of the user's, started at
/// login, so the service keeps running when the app quits, is ended or is
/// updated. On Windows the folder is outside the app's MSIX package, so the
/// service never runs in the package's job.
///
/// | Platform | Folder |
/// | --- | --- |
/// | macOS | `~/Library/Application Support/TomSecretsManagerService` |
/// | Windows | `%LOCALAPPDATA%\Programs\TomSecretsManager` |
/// | Linux | `~/.local/lib/tom-secrets-manager` |
///
/// `TSM_INSTALL_DIR` names another folder (tests). The folder's
/// `install.json` records the install and the manager apps the installed
/// service admits as admins.
library;

import 'dart:convert';
import 'dart:io';

import 'distribution.dart';

/// The record's file name in the install folder.
const String tomSecretsUserInstallRecord = 'install.json';

/// The per-user install folder of [operatingSystem] (default this one's).
String tomSecretsUserInstallDirectory({
  Map<String, String>? environment,
  String? operatingSystem,
}) {
  final env = environment ?? Platform.environment;
  final os = operatingSystem ?? Platform.operatingSystem;
  final named = env['TSM_INSTALL_DIR'];
  if (named != null && named.isNotEmpty) return named;
  String need(String name) {
    final value = env[name];
    if (value == null || value.isEmpty) {
      throw StateError('no install folder: $name is not set');
    }
    return value;
  }

  return switch (os) {
    'macos' =>
      '${need('HOME')}/Library/Application Support/TomSecretsManagerService',
    'windows' => '${need('LOCALAPPDATA')}\\Programs\\TomSecretsManager',
    _ => '${need('HOME')}/.local/lib/tom-secrets-manager',
  };
}

/// The service installed on its own for this user, as its folder and
/// record say.
final class TomSecretsUserInstall {
  /// An install in [directory].
  const TomSecretsUserInstall({
    required this.directory,
    required this.version,
    required this.installed,
    this.apps = const [],
    this.operatingSystem,
  });

  /// The install of this user, or null when its folder holds no service.
  static TomSecretsUserInstall? read({
    Map<String, String>? environment,
    String? operatingSystem,
  }) {
    final os = operatingSystem ?? Platform.operatingSystem;
    final String directory;
    try {
      directory = tomSecretsUserInstallDirectory(
        environment: environment,
        operatingSystem: os,
      );
    } on StateError {
      return null;
    }
    final probe = TomSecretsUserInstall(
      directory: directory,
      version: '',
      installed: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      operatingSystem: os,
    );
    if (!File(probe.serviceExecutable).existsSync()) return null;
    final record = File(probe.recordPath);
    Object? json;
    try {
      json = record.existsSync() ? jsonDecode(record.readAsStringSync()) : null;
    } on FormatException {
      json = null;
    }
    if (json is! Map) return probe;
    return TomSecretsUserInstall(
      directory: directory,
      version: '${json['version'] ?? ''}',
      installed:
          DateTime.tryParse('${json['installed']}')?.toUtc() ?? probe.installed,
      apps: [for (final a in json['apps'] as List? ?? const []) '$a'],
      operatingSystem: os,
    );
  }

  /// The install folder.
  final String directory;

  /// The version installed.
  final String version;

  /// When it was installed.
  final DateTime installed;

  /// The programs the installed service admits as admins (their
  /// executables): the manager apps, and the `tsm` that installed it.
  final List<String> apps;

  /// The OS whose paths these are (default this one's).
  final String? operatingSystem;

  bool get _windows =>
      (operatingSystem ?? Platform.operatingSystem) == 'windows';

  String get _sep => _windows ? r'\' : '/';

  String get _exe => _windows ? '.exe' : '';

  /// The installed service.
  String get serviceExecutable =>
      '$directory${_sep}bin$_sep$tomSecretsServiceExecutable$_exe';

  /// `tsm` beside it.
  String get tsmExecutable => '$directory${_sep}bin${_sep}tsm$_exe';

  /// The record's path.
  String get recordPath => '$directory$_sep$tomSecretsUserInstallRecord';

  /// This install with [app] among the apps it admits.
  TomSecretsUserInstall withApp(String app) => apps.contains(app)
      ? this
      : TomSecretsUserInstall(
          directory: directory,
          version: version,
          installed: installed,
          apps: [...apps, app],
          operatingSystem: operatingSystem,
        );

  /// The record's JSON.
  Map<String, Object?> toJson() => {
    'version': version,
    'installed': installed.toUtc().toIso8601String(),
    'apps': apps,
  };

  /// Writes the record.
  void writeRecord() => File(recordPath).writeAsStringSync(
    '${const JsonEncoder.withIndent('  ').convert(toJson())}\n',
  );
}

/// Whether [exe] is the same packaged Windows app as [admitted], in another
/// version: both under `\WindowsApps\<name>_<version>_<arch>__<publisher>\`
/// with the same name, architecture, publisher and file. The WindowsApps
/// folder only takes packages Windows installed, so an app update (a new
/// version folder) stays admitted by a service that keeps running.
bool tomSecretsSamePackagedApp(String admitted, String exe) {
  final pattern = RegExp(
    r'^(.*\\windowsapps\\)([^\\_]+)_[^\\_]+_([^\\_]+)__([^\\]+)\\(.+)$',
    caseSensitive: false,
  );
  final a = pattern.firstMatch(admitted.toLowerCase());
  final b = pattern.firstMatch(exe.toLowerCase());
  if (a == null || b == null) return false;
  for (final g in [1, 2, 3, 4, 5]) {
    if (a[g] != b[g]) return false;
  }
  return true;
}
