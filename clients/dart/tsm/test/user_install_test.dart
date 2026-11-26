// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// `tsm install` and `tsm uninstall` for one user (tsm_d12): the generated
// LaunchAgent, systemd unit and Windows Run entry; the steps per OS; an
// install into a scratch folder that tsm then starts first.
@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_tsm/src/user_install.dart';

import 'support/demo.dart';

void main() {
  final target = TomSecretsUserInstall(
    directory: '/home/demo/.local/lib/tom-secrets-manager',
    version: '0.2.18',
    installed: DateTime.utc(2026, 11, 26),
    operatingSystem: 'linux',
  );

  test('the LaunchAgent runs tsm start at load and leaves the service '
      'running', () {
    final plist = tsmLaunchAgentPlist(
      tsm:
          '/Users/demo/Library/Application Support/TomSecretsManagerService/bin/tsm',
      log: '/Users/demo/x & y/launchd.log',
    );
    expect(plist, contains('<string>$tsmLaunchAgentLabel</string>'));
    expect(
      plist,
      contains(
        'TomSecretsManagerService/bin/tsm</string>\n    <string>start</string>',
      ),
    );
    expect(plist, contains('<key>RunAtLoad</key>\n  <true/>'));
    expect(plist, contains('<key>AbandonProcessGroup</key>\n  <true/>'));
    expect(plist, contains('x &amp; y'));
    expect(
      tsmLaunchAgentPath('/Users/demo'),
      '/Users/demo/Library/LaunchAgents/com.althebear.tomsecrets.service.plist',
    );
    if (Platform.isMacOS) {
      final dir = Directory.systemTemp.createTempSync('tsmplist');
      addTearDown(() => dir.deleteSync(recursive: true));
      final file = File('${dir.path}/a.plist')..writeAsStringSync(plist);
      final lint = Process.runSync('plutil', ['-lint', file.path]);
      expect(lint.exitCode, 0, reason: '${lint.stdout}${lint.stderr}');
    }
  });

  test('launchd takes the LaunchAgent: its job runs at load, and the '
      'process it leaves behind keeps running after it ends', () async {
    final dir = Directory.systemTemp.createTempSync('tsmlaunchd');
    addTearDown(() => dir.deleteSync(recursive: true));
    final marker = '${dir.path}/started';
    // A stand-in for tsm start: it starts a long-lived child and ends.
    final script = File('${dir.path}/fake-tsm.sh')
      ..writeAsStringSync(
        '#!/bin/sh\n'
        'sleep 60 &\n'
        'echo \$! > "$marker"\n',
      );
    Process.runSync('chmod', ['755', script.path]);
    const label = 'com.althebear.tomsecrets.service.test';
    final plist = File('${dir.path}/$label.plist')
      ..writeAsStringSync(
        tsmLaunchAgentPlist(
          tsm: script.path,
          log: '${dir.path}/launchd.log',
          label: label,
        ),
      );
    final domain =
        'gui/${Process.runSync('id', ['-u']).stdout.toString().trim()}';
    Process.runSync('launchctl', ['bootout', '$domain/$label']);
    final boot = Process.runSync('launchctl', [
      'bootstrap',
      domain,
      plist.path,
    ]);
    if (boot.exitCode != 0) {
      markTestSkipped('no GUI launchd domain here: ${boot.stderr}');
      return;
    }
    addTearDown(
      () => Process.runSync('launchctl', ['bootout', '$domain/$label']),
    );
    for (var i = 0; i < 50 && !File(marker).existsSync(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(File(marker).existsSync(), isTrue, reason: 'run at load');
    await Future<void>.delayed(const Duration(seconds: 1));
    final child = File(marker).readAsStringSync().trim();
    final alive = Process.runSync('kill', ['-0', child]);
    expect(alive.exitCode, 0, reason: 'the child outlives the job');
    Process.runSync('kill', [child]);
  }, testOn: 'mac-os');

  test('the systemd user unit runs tsm start for the session', () {
    final unit = tsmSystemdUnit(
      tsm: '/home/demo/.local/lib/tom-secrets-manager/bin/tsm',
    );
    expect(unit, contains('Type=oneshot'));
    expect(unit, contains('RemainAfterExit=yes'));
    expect(
      unit,
      contains(
        'ExecStart="/home/demo/.local/lib/tom-secrets-manager/bin/tsm" start',
      ),
    );
    expect(unit, contains('WantedBy=default.target'));
    expect(
      tsmSystemdUnitPath(const {'HOME': '/home/demo'}),
      '/home/demo/.config/systemd/user/tom-secrets-manager.service',
    );
    expect(
      tsmSystemdUnitPath(const {
        'HOME': '/home/demo',
        'XDG_CONFIG_HOME': '/cfg',
      }),
      '/cfg/systemd/user/tom-secrets-manager.service',
    );
  });

  test('the Windows Run entry starts tsm without a window', () {
    expect(
      tsmWindowsRunCommand(
        r'C:\Users\demo\AppData\Local\Programs\TomSecretsManager\bin\tsm.exe',
      ),
      r'conhost.exe --headless "C:\Users\demo\AppData\Local\Programs\TomSecretsManager\bin\tsm.exe" start',
    );
  });

  test('the steps per OS: the tools copied and swapped in, the record with '
      'the app, the start at login; uninstall removes both', () {
    List<String> plan(String os, {bool login = true}) => [
      for (final s in tsmUserInstallPlan(
        serviceExecutable: '/rel/bin/tom_secrets_service',
        target: target,
        operatingSystem: os,
        environment: const {'HOME': '/home/demo'},
        login: login,
        admits: ['/opt/app/tom_secrets_app'],
        uid: 501,
      ))
        s.toString(),
    ];
    final linux = plan('linux');
    expect(
      linux,
      containsAllInOrder([
        'cp -a /rel/bin /home/demo/.local/lib/tom-secrets-manager.new/bin',
        'mv /home/demo/.local/lib/tom-secrets-manager.new /home/demo/.local/lib/tom-secrets-manager',
        'write /home/demo/.local/lib/tom-secrets-manager/install.json',
        'write /home/demo/.config/systemd/user/tom-secrets-manager.service',
        'systemctl --user daemon-reload',
        'systemctl --user enable tom-secrets-manager.service',
      ]),
    );
    expect(
      plan('linux', login: false).where((l) => l.contains('systemd')),
      isEmpty,
    );
    final mac = plan('macos');
    expect(
      mac,
      containsAllInOrder([
        'write /home/demo/Library/LaunchAgents/com.althebear.tomsecrets.service.plist',
        'launchctl bootout gui/501/com.althebear.tomsecrets.service',
        'launchctl bootstrap gui/501 /home/demo/Library/LaunchAgents/com.althebear.tomsecrets.service.plist',
      ]),
    );
    final windows = plan('windows');
    expect(windows.first, startsWith('copy /rel/bin'));
    expect(
      windows.last,
      startsWith(
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TomSecretsManagerService',
      ),
    );
    expect(windows.last, contains('conhost.exe --headless'));
    final record = tsmUserInstallPlan(
      serviceExecutable: '/rel/bin/tom_secrets_service',
      target: target,
      operatingSystem: 'linux',
      environment: const {'HOME': '/home/demo'},
      login: false,
      admits: ['/opt/app/tom_secrets_app'],
    ).firstWhere((s) => s.file != null);
    expect(record.content, contains('/opt/app/tom_secrets_app'));

    List<String> remove(String os) => [
      for (final s in tsmUserUninstallPlan(
        directory: '/home/demo/.local/lib/tom-secrets-manager',
        operatingSystem: os,
        environment: const {'HOME': '/home/demo'},
        uid: 501,
      ))
        s.toString(),
    ];
    expect(
      remove('linux'),
      containsAllInOrder([
        'systemctl --user disable tom-secrets-manager.service',
        'rm -f /home/demo/.config/systemd/user/tom-secrets-manager.service',
        'rm -rf /home/demo/.local/lib/tom-secrets-manager',
      ]),
    );
    expect(
      remove('macos').first,
      'launchctl bootout gui/501/com.althebear.tomsecrets.service',
    );
    // Windows: the folder first (a running service refuses it), then the
    // Run value.
    expect(remove('windows'), [
      'remove /home/demo/.local/lib/tom-secrets-manager',
      startsWith(
        r'reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TomSecretsManagerService',
      ),
    ]);
  });

  test('installed into a scratch folder (without the start at login): the '
      'tools copied, the record written with the app and kept by the next '
      'install; --plan changes nothing', () async {
    final demo = await Demo.create();
    final ext = Platform.isWindows ? '.exe' : '';
    final release = Directory('${demo.dir}/release')..createSync();
    File('${release.path}/bin/tom_secrets_service$ext')
      ..createSync(recursive: true)
      ..writeAsStringSync('demo');
    // The tsm running the install is beside the service it installs.
    File('${release.path}/bin/tsm$ext').writeAsStringSync('demo tsm');
    File('${release.path}/lib/libdemo.so')
      ..createSync(recursive: true)
      ..writeAsStringSync('demo');
    final into = '${demo.dir}/installed';
    demo.environmentOverrides = {'TSM_INSTALL_DIR': into};
    var r = await demo.tsm([
      'install',
      '--no-login',
      '--service',
      '${release.path}/bin/tom_secrets_service$ext',
      '--app',
      '/opt/app/tom_secrets_app',
    ], executableDirectory: '${release.path}/bin');
    expect(r.code, 0, reason: '$r');
    expect(r.text, contains('installed in $into'));
    final installed = TomSecretsUserInstall.read(
      environment: demo.environment,
    )!;
    expect(File(installed.serviceExecutable).readAsStringSync(), 'demo');
    expect(File('$into/lib/libdemo.so').existsSync(), isTrue);
    // The app and the tsm that installed it: the installed service admits
    // both, so `./bin/tsm start --unlock` from the release works.
    expect(installed.apps, [
      '/opt/app/tom_secrets_app',
      '${release.path}/bin/tsm$ext',
    ]);
    expect(installed.version, isNotEmpty);

    // Installed again: the record keeps the app.
    r = await demo.tsm([
      'install',
      '--no-login',
      '--service',
      '${release.path}/bin/tom_secrets_service$ext',
    ]);
    expect(r.code, 0, reason: '$r');
    expect(TomSecretsUserInstall.read(environment: demo.environment)!.apps, [
      '/opt/app/tom_secrets_app',
      '${release.path}/bin/tsm$ext',
    ]);

    r = await demo.tsm([
      'install',
      '--plan',
      '--no-login',
      '--service',
      '${release.path}/bin/tom_secrets_service$ext',
    ]);
    expect(r.text, contains('install.json'));

    r = await demo.tsm(['uninstall', '--plan']);
    expect(r.code, 0);
    expect(
      Directory(into).existsSync(),
      isTrue,
      reason: '--plan changes nothing',
    );
  });
}
