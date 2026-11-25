// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A folder only the user (and SYSTEM) may reach on Windows, through
/// `icacls`: the runtime and the data directory.
library;

import 'dart:io';

/// Who [path]'s ACL grants, each account in lower case without its domain
/// (`alice`, `system`, `administrators`).
Future<Set<String>> tomSecretsWindowsGrantees(String path) async {
  final out = await _icacls([path]);
  return {
    for (final line in out.split(RegExp(r'\r?\n')))
      if (line.replaceFirst(path, '').trim().contains(':('))
        line
            .replaceFirst(path, '')
            .trim()
            .split(':(')
            .first
            .split(r'\')
            .last
            .toLowerCase(),
  };
}

/// Whether [grantees] are only this user and SYSTEM.
bool tomSecretsWindowsUserOnly(Set<String> grantees) {
  final user = (Platform.environment['USERNAME'] ?? '').toLowerCase();
  return grantees.every((g) => g == user || g == 'system' || g == 'system-');
}

/// Cuts [path]'s inheritance and grants only this user and SYSTEM, both
/// inherited by what is inside; then removes every other account granted
/// explicitly. What is inside, holding inherited grants, follows.
Future<void> tomSecretsRestrictWindowsDirectory(String path) async {
  final user = Platform.environment['USERNAME'] ?? '';
  await _icacls([
    path,
    '/inheritance:r',
    '/grant:r',
    '$user:(OI)(CI)F',
    '/grant:r',
    'SYSTEM:(OI)(CI)F',
  ]);
  for (final other in await tomSecretsWindowsGrantees(path)) {
    if (!tomSecretsWindowsUserOnly({other})) {
      await _icacls([path, '/remove:g', other]);
    }
  }
}

Future<String> _icacls(List<String> args) async {
  final result = await Process.run('icacls', args);
  if (result.exitCode != 0) {
    throw FileSystemException(
      'icacls ${args.skip(1).join(' ')} failed: ${result.stderr}',
      args.first,
    );
  }
  return result.stdout as String;
}
