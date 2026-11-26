// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The service installed on its own for a user (tsm_d12): its folder per
// OS, its record, and the packaged app it admits across app updates.
@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  test('the folder per OS; TSM_INSTALL_DIR names another', () {
    expect(
      tomSecretsUserInstallDirectory(
        environment: const {'HOME': '/Users/demo'},
        operatingSystem: 'macos',
      ),
      '/Users/demo/Library/Application Support/TomSecretsManagerService',
    );
    expect(
      tomSecretsUserInstallDirectory(
        environment: const {'HOME': '/home/demo'},
        operatingSystem: 'linux',
      ),
      '/home/demo/.local/lib/tom-secrets-manager',
    );
    expect(
      tomSecretsUserInstallDirectory(
        environment: const {'LOCALAPPDATA': r'C:\Users\demo\AppData\Local'},
        operatingSystem: 'windows',
      ),
      r'C:\Users\demo\AppData\Local\Programs\TomSecretsManager',
    );
    expect(
      tomSecretsUserInstallDirectory(
        environment: const {'TSM_INSTALL_DIR': '/x', 'HOME': '/h'},
        operatingSystem: 'linux',
      ),
      '/x',
    );
  });

  test('no service in the folder: no install; with one, the record read '
      'and written, the app added once', () {
    final dir = Directory.systemTemp.createTempSync('tsmuser');
    addTearDown(() => dir.deleteSync(recursive: true));
    final env = {'TSM_INSTALL_DIR': dir.path};
    expect(TomSecretsUserInstall.read(environment: env), isNull);
    final exe = Platform.isWindows ? '.exe' : '';
    File('${dir.path}/bin/tom_secrets_service$exe').createSync(recursive: true);
    final bare = TomSecretsUserInstall.read(environment: env)!;
    expect(bare.apps, isEmpty);
    expect(
      File(bare.serviceExecutable).absolute.path,
      File('${dir.path}/bin/tom_secrets_service$exe').absolute.path,
    );
    expect(bare.tsmExecutable, endsWith('tsm$exe'));
    TomSecretsUserInstall(
          directory: dir.path,
          version: '0.2.18',
          installed: DateTime.utc(2026, 11, 26),
        )
        .withApp('/Applications/A.app/Contents/MacOS/tom_secrets_app')
        .withApp('/Applications/A.app/Contents/MacOS/tom_secrets_app')
        .writeRecord();
    final read = TomSecretsUserInstall.read(environment: env)!;
    expect(read.version, '0.2.18');
    expect(read.installed, DateTime.utc(2026, 11, 26));
    expect(read.apps, ['/Applications/A.app/Contents/MacOS/tom_secrets_app']);
    expect(
      tomSecretsExpectedServiceExecutables(
        ownExecutable: '/elsewhere/tsm',
        environment: env,
        systemInstall: () => null,
      ),
      contains(tomSecretsRealExecutable(read.serviceExecutable)),
    );
  });

  test('a packaged Windows app stays admitted in another version, never '
      'another package, publisher, architecture or file', () {
    const admitted =
        r'C:\Program Files\WindowsApps\TomSecretsManager_0.1.1.0_x64__wfdps04423ncr\tom_secrets_app.exe';
    expect(
      tomSecretsSamePackagedApp(
        admitted,
        r'C:\Program Files\WindowsApps\TomSecretsManager_0.1.2.0_x64__wfdps04423ncr\tom_secrets_app.exe',
      ),
      isTrue,
    );
    for (final other in [
      r'C:\Program Files\WindowsApps\Other_0.1.2.0_x64__wfdps04423ncr\tom_secrets_app.exe',
      r'C:\Program Files\WindowsApps\TomSecretsManager_0.1.2.0_x64__zzzzzz\tom_secrets_app.exe',
      r'C:\Program Files\WindowsApps\TomSecretsManager_0.1.2.0_arm64__wfdps04423ncr\tom_secrets_app.exe',
      r'C:\Program Files\WindowsApps\TomSecretsManager_0.1.2.0_x64__wfdps04423ncr\tsm\bin\tsm.exe',
      r'C:\Users\demo\WindowsApps\TomSecretsManager_0.1.2.0_x64__wfdps04423ncr\tom_secrets_app.exe',
      r'C:\Users\demo\Downloads\tom_secrets_app.exe',
    ]) {
      expect(
        tomSecretsSamePackagedApp(admitted, other),
        isFalse,
        reason: other,
      );
    }
    expect(
      tomSecretsSamePackagedApp('/Applications/x', '/Applications/x'),
      isFalse,
    );
  });
}
