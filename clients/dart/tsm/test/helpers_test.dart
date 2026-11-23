// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The developer-tool helpers (part-os-integration, DP-52, DP-53):
/// `git-credential-tsm get` answering from the login of git's host (the
/// user picks it once in the app, the grant remembers it), `store`
/// proposing only an unknown credential, `erase` and a missing service
/// answering nothing; `tsm integrations` installing, showing and removing
/// the ssh and git blocks. This test process plays the helper. Demo data
/// only.
@TestOn('mac-os || linux')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';
import 'package:tom_secrets_tsm/tom_secrets_tsm.dart';

import 'support/demo.dart';

void main() {
  test('the name tsm runs under', () {
    expect(
      tsmInvokedName('/usr/local/bin/git-credential-tsm'),
      tsmGitCredentialName,
    );
    expect(
      tsmInvokedName(r'C:\tsm\git-credential-tsm.exe'),
      tsmGitCredentialName,
    );
    expect(tsmInvokedName('./tsm'), 'tsm');
  });

  group('git-credential-tsm', () {
    late Demo demo;

    setUp(() async => demo = await Demo.create());

    const get = ['protocol=https', 'host=git.example.com', ''];

    test('no service: nothing printed, exit 0 (git falls back)', () async {
      final r = await demo.gitCredential(['get'], get);
      expect(r.code, 0);
      expect(r.text, isEmpty);
    });

    test('get: the user picks the login once in the app, "always" '
        'remembers it; then answered without asking; another host: '
        'nothing', () async {
      final self = {tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!).exe};
      final adminKey = tomSecretsRandomBytes();
      await demo.startInProcess(
        adminKey: adminKey,
        policy: null,
        helperExecutables: self,
      );
      final admin = await TomSecretsAdminClient.connect(demo.runtime, adminKey);
      addTearDown(admin.close);
      await admin.unlock(primaryPassword);
      await admin.request('subscribe');
      final needed = admin.events.firstWhere(
        (e) => e['op'] == 'approval_needed',
      );
      final first = demo.gitCredential(['get'], get);
      final event = await needed;
      final pick = (event['pick']! as List).cast<Map>().single;
      expect(pick['title'], 'Example git');
      expect(event['url'], 'https://git.example.com/');
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
        'pick': pick['entryId'],
      });
      final r = await first;
      expect(r.code, 0);
      expect(r.text, 'username=demo-git-user\npassword=demo-git-token\n');
      expect(r.err, contains('waiting for Tom Secrets Manager'));

      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final again = await demo.gitCredential(
        ['get'],
        ['protocol=https', 'host=git.example.com', 'username=demo-git-user'],
      );
      expect(again.text, 'username=demo-git-user\npassword=demo-git-token\n');
      final other = await demo.gitCredential(
        ['get'],
        ['protocol=https', 'host=other.example.com'],
      );
      expect(other.text, isEmpty);
      await sub.cancel();
      expect(prompted, isFalse);

      // store: the known credential is ignored, a new password proposed;
      // erase answers nothing.
      var proposals = 0;
      final watch = admin.events.listen((e) {
        if (e['op'] == 'proposal') proposals++;
      });
      final known = await demo.gitCredential(
        ['store'],
        [...get.take(2), 'username=demo-git-user', 'password=demo-git-token'],
      );
      expect(known.code, 0);
      await demo.gitCredential(
        ['store'],
        [...get.take(2), 'username=demo-git-user', 'password=demo-new-token'],
      );
      final erase = await demo.gitCredential(
        ['erase'],
        [...get.take(2), 'username=demo-git-user'],
      );
      expect(erase.text, isEmpty);
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await watch.cancel();
      expect(proposals, 1);
    });
  });

  test('tsm integrations: status, install ssh and git, the blocks and the '
      'link, --json, uninstall', () async {
    final demo = await Demo.create();
    final home = Directory.systemTemp.createTempSync('tsm_home');
    addTearDown(() => home.deleteSync(recursive: true));
    final bin = Directory('${home.path}/bin')..createSync();
    File('${bin.path}/tsm').writeAsStringSync('demo');
    Future<TsmRun> integrations(List<String> args) async {
      final previous = demo.environmentOverrides;
      demo.environmentOverrides = {
        'HOME': home.path,
        'PATH': '/usr/bin:${bin.path}',
      };
      try {
        return await demo.tsm([
          'integrations',
          ...args,
        ], executableDirectory: bin.path);
      } finally {
        demo.environmentOverrides = previous;
      }
    }

    var r = await integrations([]);
    expect(r.code, 0, reason: '$r');
    expect(r.text, contains('ssh    not installed'));
    expect(r.text, contains('git    not installed'));
    r = await integrations(['install', 'ssh']);
    expect(r.text, contains('ssh    installed'));
    final config = File('${home.path}/.ssh/config').readAsStringSync();
    expect(config, contains('IdentityAgent ${demo.runtime.agentSocket}'));
    r = await integrations(['install', 'git']);
    expect(r.text, contains('git    installed'), reason: '$r');
    expect(
      Link('${bin.path}/git-credential-tsm').targetSync(),
      '${bin.path}/tsm',
    );
    final json = jsonDecode((await integrations(['--json'])).text) as List;
    expect(
      [for (final s in json) (s as Map)['current']],
      [true, true, false, false],
    );
    await integrations(['uninstall', 'ssh']);
    await integrations(['uninstall', 'git']);
    expect(File('${home.path}/.ssh/config').readAsStringSync(), isEmpty);
    r = await integrations(['install', 'nothing']);
    expect(r.code, 2);
  });
}
