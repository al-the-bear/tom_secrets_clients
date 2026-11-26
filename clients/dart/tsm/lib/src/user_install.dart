// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `tsm install` and `tsm uninstall` for one user (tsm_d12): the
/// command-line tools copied into the user's install folder
/// (`tomSecretsUserInstallDirectory`), and `tsm start` from there at every
/// login, so the service keeps running when the app quits, is ended or is
/// updated:
///
/// - **macOS:** a LaunchAgent (`~/Library/LaunchAgents`) whose job runs
///   `tsm start` at load and leaves the service it starts running
///   (`AbandonProcessGroup`).
/// - **Linux:** a systemd user unit (`~/.config/systemd/user`), a oneshot
///   that runs `tsm start`, enabled for the session.
/// - **Windows:** the value `TomSecretsManagerService` of the user's Run
///   key, `tsm start` through a console host without a window; the folder
///   is outside the app's MSIX package, so the service never runs in the
///   package's job.
///
/// The steps are listed before they run (`--plan`).
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/admin.dart';

import 'system_install.dart';

/// The LaunchAgent's label.
const String tsmLaunchAgentLabel = 'com.althebear.tomsecrets.service';

/// The systemd user unit's name.
const String tsmSystemdUnitName = 'tom-secrets-manager.service';

/// The value of the user's Run key on Windows.
const String tsmWindowsRunValue = 'TomSecretsManagerService';

/// The user's Run key on Windows.
const String tsmWindowsRunKey =
    r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';

/// The LaunchAgent's file under [home].
String tsmLaunchAgentPath(String home) =>
    '$home/Library/LaunchAgents/$tsmLaunchAgentLabel.plist';

/// The systemd user unit's file ([environment]'s `XDG_CONFIG_HOME`, else
/// `~/.config`).
String tsmSystemdUnitPath(Map<String, String> environment) {
  final xdg = environment['XDG_CONFIG_HOME'] ?? '';
  final base = xdg.startsWith('/') ? xdg : '${environment['HOME']}/.config';
  return '$base/systemd/user/$tsmSystemdUnitName';
}

String _xml(String text) => text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');

/// The LaunchAgent that runs [tsm] `start` at login and leaves the service
/// running after `tsm` ends; its output goes to [log].
String tsmLaunchAgentPlist({
  required String tsm,
  required String log,
  String label = tsmLaunchAgentLabel,
}) =>
    '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${_xml(label)}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${_xml(tsm)}</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>AbandonProcessGroup</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${_xml(log)}</string>
  <key>StandardErrorPath</key>
  <string>${_xml(log)}</string>
</dict>
</plist>
''';

/// The systemd user unit that runs [tsm] `start` for the session; stopping
/// the unit stops the service (SIGTERM).
String tsmSystemdUnit({required String tsm}) =>
    '''
[Unit]
Description=Tom Secrets Manager service
Documentation=https://enterprise-flutter.dev

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart="$tsm" start

[Install]
WantedBy=default.target
''';

/// The Run key's command on Windows: [tsm] `start` in a console host
/// without a window.
String tsmWindowsRunCommand(String tsm) =>
    'conhost.exe --headless "$tsm" start';

String _sep(String os) => os == 'windows' ? r'\' : '/';

Future<void> _copyTree(String from, String to) async {
  final source = Directory(from);
  for (final e in source.listSync(recursive: true, followLinks: false)) {
    final relative = e.path.substring(source.path.length + 1);
    final target = '$to${Platform.pathSeparator}$relative';
    if (e is Directory) {
      Directory(target).createSync(recursive: true);
    } else if (e is File) {
      File(target).parent.createSync(recursive: true);
      e.copySync(target);
    } else if (e is Link) {
      Link(target).createSync(e.targetSync());
    }
  }
}

/// The steps that install the tools whose service is [serviceExecutable]
/// (`<root>/bin/`, `<root>/lib/`) for this user into [target]'s folder,
/// recording [app] among the apps the installed service admits; with
/// [login] the start at login. [home], [environment] and [uid] are this
/// user's; [linkFree]: `~/.local/bin/tsm` (Linux) may be made.
List<TsmInstallStep> tsmUserInstallPlan({
  required String serviceExecutable,
  required TomSecretsUserInstall target,
  required String operatingSystem,
  required Map<String, String> environment,
  required bool login,
  String? app,
  int? uid,
  bool linkFree = false,
}) {
  final os = operatingSystem;
  final sep = _sep(os);
  final bin = File(serviceExecutable).parent.path;
  final root = Directory(bin).parent.path;
  final dir = target.directory;
  final staged = '$dir.new';
  final old = '$dir.old';
  final hasLib = Directory('$root${sep}lib').existsSync();
  final record = app == null ? target : target.withApp(app);
  final home = environment['HOME'] ?? '';
  final tsm = target.tsmExecutable;
  return [
    if (os == 'windows') ...[
      TsmInstallStep.action(
        'copy the tools',
        'copy $bin to $staged${sep}bin',
        () async {
          if (Directory(staged).existsSync()) {
            Directory(staged).deleteSync(recursive: true);
          }
          await _copyTree(bin, '$staged${sep}bin');
          if (hasLib) await _copyTree('$root${sep}lib', '$staged${sep}lib');
        },
      ),
      TsmInstallStep.action(
        'replace the installed tools',
        'replace $dir',
        () async {
          if (Directory(old).existsSync()) {
            Directory(old).deleteSync(recursive: true);
          }
          if (Directory(dir).existsSync()) Directory(dir).renameSync(old);
          Directory(staged).renameSync(dir);
          if (Directory(old).existsSync()) {
            Directory(old).deleteSync(recursive: true);
          }
        },
      ),
    ] else ...[
      TsmInstallStep('copy the tools', ['rm', '-rf', staged]),
      TsmInstallStep('copy the tools', ['mkdir', '-p', staged]),
      TsmInstallStep('copy the tools', ['cp', '-a', bin, '$staged/bin']),
      if (hasLib)
        TsmInstallStep('copy the tools', [
          'cp',
          '-a',
          '$root/lib',
          '$staged/lib',
        ]),
      TsmInstallStep('replace the installed tools', ['rm', '-rf', old]),
      TsmInstallStep.action(
        'replace the installed tools',
        'mv $dir $old',
        () async {
          if (Directory(dir).existsSync()) Directory(dir).renameSync(old);
        },
      ),
      TsmInstallStep('replace the installed tools', ['mv', staged, dir]),
      TsmInstallStep('replace the installed tools', ['rm', '-rf', old]),
    ],
    TsmInstallStep.write(
      'write the record',
      record.recordPath,
      '${_json(record)}\n',
    ),
    if (login)
      ...switch (os) {
        'macos' => [
          TsmInstallStep.write(
            'start it at login',
            tsmLaunchAgentPath(home),
            tsmLaunchAgentPlist(tsm: tsm, log: '$dir/launchd.log'),
          ),
          TsmInstallStep('start it at login', [
            'launchctl',
            'bootout',
            'gui/$uid/$tsmLaunchAgentLabel',
          ], optional: true),
          TsmInstallStep('start it at login', [
            'launchctl',
            'bootstrap',
            'gui/$uid',
            tsmLaunchAgentPath(home),
          ], optional: true),
        ],
        'windows' => [
          TsmInstallStep('start it at login', [
            'reg',
            'add',
            tsmWindowsRunKey,
            '/v',
            tsmWindowsRunValue,
            '/t',
            'REG_SZ',
            '/d',
            tsmWindowsRunCommand(tsm),
            '/f',
          ]),
        ],
        _ => [
          TsmInstallStep.write(
            'start it at login',
            tsmSystemdUnitPath(environment),
            tsmSystemdUnit(tsm: tsm),
          ),
          TsmInstallStep('start it at login', [
            'systemctl',
            '--user',
            'daemon-reload',
          ], optional: true),
          TsmInstallStep('start it at login', [
            'systemctl',
            '--user',
            'enable',
            tsmSystemdUnitName,
          ], optional: true),
        ],
      },
    if (os == 'linux' && linkFree)
      TsmInstallStep('link tsm', [
        'ln',
        '-sfn',
        tsm,
        '$home/.local/bin/tsm',
      ], optional: true),
  ];
}

/// The steps that remove the install in [directory] and its start at
/// login; [linkOurs]: `~/.local/bin/tsm` points into it (Linux).
List<TsmInstallStep> tsmUserUninstallPlan({
  required String directory,
  required String operatingSystem,
  required Map<String, String> environment,
  int? uid,
  bool linkOurs = false,
}) {
  final home = environment['HOME'] ?? '';
  return [
    ...switch (operatingSystem) {
      'macos' => [
        TsmInstallStep('stop starting it at login', [
          'launchctl',
          'bootout',
          'gui/$uid/$tsmLaunchAgentLabel',
        ], optional: true),
        TsmInstallStep('stop starting it at login', [
          'rm',
          '-f',
          tsmLaunchAgentPath(home),
        ]),
      ],
      'windows' => [
        TsmInstallStep('stop starting it at login', [
          'reg',
          'delete',
          tsmWindowsRunKey,
          '/v',
          tsmWindowsRunValue,
          '/f',
        ], optional: true),
      ],
      _ => [
        TsmInstallStep('stop starting it at login', [
          'systemctl',
          '--user',
          'disable',
          tsmSystemdUnitName,
        ], optional: true),
        TsmInstallStep('stop starting it at login', [
          'rm',
          '-f',
          tsmSystemdUnitPath(environment),
        ]),
        TsmInstallStep('stop starting it at login', [
          'systemctl',
          '--user',
          'daemon-reload',
        ], optional: true),
        if (linkOurs)
          TsmInstallStep('remove the tsm link', [
            'rm',
            '-f',
            '$home/.local/bin/tsm',
          ]),
      ],
    },
    if (operatingSystem == 'windows')
      TsmInstallStep.action('remove the tools', 'remove $directory', () async {
        if (Directory(directory).existsSync()) {
          Directory(directory).deleteSync(recursive: true);
        }
      })
    else
      TsmInstallStep('remove the tools', ['rm', '-rf', directory]),
  ];
}

String _json(TomSecretsUserInstall record) =>
    const JsonEncoder.withIndent('  ').convert(record.toJson());
