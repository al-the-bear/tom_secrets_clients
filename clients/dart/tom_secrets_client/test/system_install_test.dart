// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The record of a system install (tsm_d11): read only when root owns it and
// no one else may write it; its service is one every program expects.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('tsmsys'));
  tearDown(() => dir.deleteSync(recursive: true));

  final install = TomSecretsSystemInstall(
    prefix: '/opt/tom-secrets-manager',
    version: '0.27.0',
    installed: DateTime.utc(2026, 11, 26),
  );

  test('the record round trip, and where the programs are', () {
    final again = TomSecretsSystemInstall.fromJson(
      jsonDecode(jsonEncode(install.toJson())),
    )!;
    expect(again.prefix, install.prefix);
    expect(again.version, '0.27.0');
    expect(again.group, tomSecretsSystemGroup);
    expect(again.identityDirectory, tomSecretsSystemIdentityDirectory);
    expect(again.installed, install.installed);
    expect(
      again.serviceExecutable,
      '/opt/tom-secrets-manager/bin/tom_secrets_service',
    );
    expect(again.tsmExecutable, '/opt/tom-secrets-manager/bin/tsm');
    expect(TomSecretsSystemInstall.fromJson({'version': 1}), isNull);
  });

  test('a record this user owns is not a system install\'s; read as one '
      'only where root\'s ownership is not asked for', () {
    final record = File('${dir.path}/system.json')
      ..writeAsStringSync(jsonEncode(install.toJson()));
    expect(TomSecretsSystemInstall.read(path: record.path), isNull);
    expect(
      TomSecretsSystemInstall.read(
        path: record.path,
        requireRoot: false,
      )!.prefix,
      install.prefix,
    );
    expect(
      TomSecretsSystemInstall.read(path: '${dir.path}/missing.json'),
      isNull,
    );
  });

  test('the system-installed service is expected beside the program\'s '
      'own', () {
    final expected = tomSecretsExpectedServiceExecutables(
      ownExecutable: '${dir.path}/tsm',
      environment: const {},
      operatingSystem: 'linux',
      systemInstall: () => install,
    );
    expect(expected, contains(install.serviceExecutable));
    expect(expected, contains('${dir.path}/tom_secrets_service'));
    expect(
      tomSecretsExpectedServiceExecutables(
        ownExecutable: '${dir.path}/tsm',
        environment: const {},
        operatingSystem: 'linux',
        systemInstall: () => null,
      ),
      isNot(contains(install.serviceExecutable)),
    );
  });
}
