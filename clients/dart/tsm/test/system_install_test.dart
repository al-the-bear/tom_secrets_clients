// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// `tsm install --system` and `tsm uninstall --system` (tsm_d11): the steps,
// and the refusals. The install itself runs as root in a container
// (tom_secrets_build `:system`).
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart' show currentUid;
import 'package:tom_secrets_tsm/src/system_install.dart';

import 'support/demo.dart';

void main() {
  List<String> lines(List<TsmInstallStep> steps) => [
    for (final s in steps) s.toString(),
  ];

  test('the install: the group made when missing, the programs root\'s, '
      'the service set-group-ID, the identity directory the group\'s alone, '
      'the record, the link', () {
    final steps = tsmSystemInstallPlan(
      serviceExecutable: '/tmp/release/bin/tom_secrets_service',
      version: '0.2.17',
      now: DateTime.utc(2026, 11, 26),
      groupExists: false,
      libExists: true,
      tsmBeside: true,
      linkFree: true,
    );
    final all = lines(steps);
    expect(all.first, 'groupadd --system tsm-identity');
    expect(
      all,
      contains('cp -a /tmp/release/bin /opt/tom-secrets-manager.new/bin'),
    );
    expect(
      all,
      contains('cp -a /tmp/release/lib /opt/tom-secrets-manager.new/lib'),
    );
    expect(all, contains('chown -R root:root /opt/tom-secrets-manager.new'));
    expect(
      all,
      containsAllInOrder([
        'chown root:tsm-identity /opt/tom-secrets-manager.new/bin/tom_secrets_service',
        'chmod 2755 /opt/tom-secrets-manager.new/bin/tom_secrets_service',
        'rm -rf /opt/tom-secrets-manager',
        'mv /opt/tom-secrets-manager.new /opt/tom-secrets-manager',
        'chown root:tsm-identity /var/lib/tom-secrets-manager/identity',
        'chmod 2770 /var/lib/tom-secrets-manager/identity',
        'write /etc/tom-secrets-manager/system.json',
        'chmod 644 /etc/tom-secrets-manager/system.json',
        'ln -sfn /opt/tom-secrets-manager/bin/tsm /usr/local/bin/tsm',
      ]),
    );
    final record = steps.firstWhere((s) => s.file != null);
    final install = TomSecretsSystemInstall.fromJson(
      jsonDecode(record.content!),
    )!;
    expect(install.prefix, tomSecretsSystemPrefix);
    expect(install.version, '0.2.17');

    final update = lines(
      tsmSystemInstallPlan(
        serviceExecutable: '/tmp/release/bin/tom_secrets_service',
        version: '0.2.17',
        now: DateTime.utc(2026, 11, 26),
        groupExists: true,
        libExists: false,
        tsmBeside: false,
        linkFree: true,
      ),
    );
    expect(update.where((l) => l.startsWith('groupadd')), isEmpty);
    expect(
      update.where((l) => l.startsWith('cp') && l.contains('/lib')),
      isEmpty,
    );
    expect(update.where((l) => l.startsWith('ln ')), isEmpty);
    // The identity keys are never touched by an install or an update.
    expect(
      update.where((l) => l.startsWith('rm') && l.contains('/var/lib')),
      isEmpty,
    );
  });

  test('the uninstall keeps the identity keys unless --purge', () {
    final keep = lines(tsmSystemUninstallPlan(purge: false, linkOurs: true));
    expect(keep.first, 'rm -f /usr/local/bin/tsm');
    expect(keep, contains('rm -rf /opt/tom-secrets-manager'));
    expect(keep.where((l) => l.contains('/var/lib')), isEmpty);
    final purge = lines(tsmSystemUninstallPlan(purge: true, linkOurs: false));
    expect(purge.where((l) => l.contains('/usr/local/bin/tsm')), isEmpty);
    expect(purge, contains('rm -rf /var/lib/tom-secrets-manager'));
    expect(purge.last, 'groupdel tsm-identity');
  });

  test('the steps run in order; a failure stops them, an optional one is '
      'told and passed', () async {
    final ran = <String>[];
    final told = <String>[];
    final dir = Directory.systemTemp.createTempSync('tsminst');
    addTearDown(() => dir.deleteSync(recursive: true));
    final failed = await tsmRunInstallSteps(
      [
        const TsmInstallStep('one', ['first']),
        TsmInstallStep.write('two', '${dir.path}/record.json', '{}\n'),
        const TsmInstallStep('three', ['link'], optional: true),
        const TsmInstallStep('four', ['broken']),
        const TsmInstallStep('five', ['never']),
      ],
      say: told.add,
      run: (exe, args) async {
        ran.add(exe);
        return ProcessResult(0, exe == 'first' ? 0 : 1, '', 'no');
      },
    );
    expect(ran, ['first', 'link', 'broken']);
    expect(File('${dir.path}/record.json').readAsStringSync(), '{}\n');
    expect(failed, contains('four'));
    expect(told.where((l) => l.contains('not done')), hasLength(1));
  });

  test('the system form is Linux\'s; not as root, nothing runs', () async {
    final demo = await Demo.create();
    final r = await demo.tsm(['install', '--system']);
    if (Platform.isMacOS) {
      expect(r.code, 10);
      expect(r.err, contains('keychain'));
    } else if (Platform.isLinux && currentUid() != 0) {
      // No service beside the test's tsm: said before anything else.
      expect(r.code, isNot(0));
    }
  });
}
