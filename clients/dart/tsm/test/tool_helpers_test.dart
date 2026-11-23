// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The phase-C helpers (part-os-integration): `tsm aws-credentials`
/// as AWS's `credential_process` (an `api-token` entry's key id, secret,
/// session token and expiry), `tsm kube-credential` as kubectl's exec plugin
/// (a token, or a certificate entry's certificate and key, the apiVersion
/// kubectl asks for), `docker-credential-tsm` (get with the user's pick in
/// the app, list without secrets, store proposing only an unknown
/// credential, erase ignored, nothing found as Docker expects it), and
/// `tsm integrations` for aws and docker. This test process plays the
/// helpers. Demo data only.
@TestOn('mac-os || linux')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';
import 'package:tom_secrets_tsm/tom_secrets_tsm.dart';

import 'support/demo.dart';

void main() {
  test('expiry times in RFC 3339 to the second, in UTC', () {
    expect(
      tsmRfc3339(DateTime.utc(2031, 6, 1, 12, 30, 5, 123)),
      '2031-06-01T12:30:05Z',
    );
    expect(tsmRegistryUrl('ghcr.io'), 'https://ghcr.io');
    expect(
      tsmRegistryUrl('https://index.docker.io/v1/'),
      'https://index.docker.io/v1/',
    );
    expect(
      tsmInvokedName('/usr/local/bin/docker-credential-tsm'),
      tsmDockerCredentialName,
    );
  });

  group('aws-credentials and kube-credential', () {
    late Demo demo;

    setUp(() async {
      demo = await Demo.create();
      final adminKey = tomSecretsRandomBytes();
      await demo.startInProcess(adminKey: adminKey);
      final admin = await TomSecretsAdminClient.connect(demo.runtime, adminKey);
      addTearDown(admin.close);
      await admin.unlock(primaryPassword);
    });

    test('AWS keys as credential_process prints them: the session token and '
        'the expiry when the entry has them', () async {
      var r = await demo.tsm(['aws-credentials', 'team/Cloud/AWS session']);
      expect(r.code, 0, reason: '$r');
      expect(jsonDecode(r.text), {
        'Version': 1,
        'AccessKeyId': 'AKIADEMOSESSION',
        'SecretAccessKey': 'demo-aws-secret',
        'SessionToken': 'demo-aws-session-token',
        'Expiration': '2031-06-01T12:30:00Z',
      });
      r = await demo.tsm(['aws-credentials', 'team/Cloud/AWS static']);
      expect(jsonDecode(r.text), {
        'Version': 1,
        'AccessKeyId': 'AKIADEMOSTATIC',
        'SecretAccessKey': 'demo-aws-static-secret',
      });
    });

    test('an entry without a key id, a reference naming a field, a missing '
        'entry: said on standard error, nothing printed', () async {
      var r = await demo.tsm(['aws-credentials', 'team/Api/Token']);
      expect(r.code, TsmExit.of('not_found'));
      expect(r.text, isEmpty);
      expect(r.err, contains('UserName'));
      r = await demo.tsm(['aws-credentials', 'team/Cloud/AWS static#Password']);
      expect(r.code, TsmExit.usage);
      expect(r.err, contains('without #Password'));
      r = await demo.tsm(['aws-credentials', 'team/Cloud/None']);
      expect(r.code, TsmExit.of('not_found'));
      expect(r.text, isEmpty);
    });

    test('kubectl: a token entry gives its Password as the token; the '
        'apiVersion kubectl asks for is answered', () async {
      var r = await demo.tsm(['kube-credential', 'team/Api/Token']);
      expect(r.code, 0, reason: '$r');
      expect(jsonDecode(r.text), {
        'apiVersion': 'client.authentication.k8s.io/v1',
        'kind': 'ExecCredential',
        'status': {'token': 'demo-api-token'},
      });
      demo.environmentOverrides = {
        'KUBERNETES_EXEC_INFO': jsonEncode({
          'apiVersion': 'client.authentication.k8s.io/v1beta1',
          'kind': 'ExecCredential',
          'spec': {'interactive': false},
        }),
      };
      r = await demo.tsm(['kube-credential', 'team/Api/Token']);
      expect(
        (jsonDecode(r.text) as Map)['apiVersion'],
        'client.authentication.k8s.io/v1beta1',
      );
    });
  });

  test('kubectl: a certificate entry gives its certificate and private key, '
      'and its notAfter as the expiry', () async {
    final demo = await Demo.create();
    final cert = await demo.addCertificate('team', 'Kube admin');
    final adminKey = tomSecretsRandomBytes();
    await demo.startInProcess(adminKey: adminKey);
    final admin = await TomSecretsAdminClient.connect(demo.runtime, adminKey);
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final r = await demo.tsm(['kube-credential', 'team/Kube admin']);
    expect(r.code, 0, reason: '$r');
    final status = (jsonDecode(r.text) as Map)['status'] as Map;
    expect(status['clientCertificateData'], cert.certificatePem);
    expect(status['clientKeyData'], cert.privateKeyPem);
    expect(status.containsKey('token'), isFalse);
    expect(
      DateTime.parse(status['expirationTimestamp'] as String),
      cert.info.notAfter.toUtc().copyWith(millisecond: 0, microsecond: 0),
    );
  });

  group('docker-credential-tsm', () {
    late Demo demo;
    late Directory home;

    setUp(() async {
      demo = await Demo.create();
      home = Directory.systemTemp.createTempSync('tsm_docker_home');
      addTearDown(() => home.deleteSync(recursive: true));
      Directory('${home.path}/.docker').createSync();
      File('${home.path}/.docker/config.json').writeAsStringSync(
        jsonEncode({
          'credHelpers': {'ghcr.io': 'tsm', 'gcr.io': 'gcloud'},
        }),
      );
      demo.environmentOverrides = {'HOME': home.path};
    });

    test('no service: not found as Docker reads it, exit 1; version', () async {
      final r = await demo.dockerCredential(['get'], ['ghcr.io']);
      expect(r.code, 1);
      expect(r.text, '$tsmDockerNotFound\n');
      final v = await demo.dockerCredential(['version']);
      expect(v.text, contains('tsm $tsmVersion'));
    });

    test('get: the user picks the login once in the app, "always" remembers '
        'it; list names the registries without a secret; store proposes '
        'only an unknown credential; erase answers nothing; another '
        'registry: not found', () async {
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
      final first = demo.dockerCredential(['get'], ['ghcr.io']);
      final event = await needed;
      final pick = (event['pick']! as List).cast<Map>().single;
      expect(pick['title'], 'Registry');
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
        'pick': pick['entryId'],
      });
      final r = await first;
      expect(r.code, 0, reason: '$r');
      expect(jsonDecode(r.text), {
        'ServerURL': 'ghcr.io',
        'Username': 'demo-docker-user',
        'Secret': 'demo-docker-token',
      });
      expect(r.err, contains('waiting for Tom Secrets Manager'));

      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final again = await demo.dockerCredential(['get'], ['https://ghcr.io']);
      expect((jsonDecode(again.text) as Map)['Secret'], 'demo-docker-token');
      final listed = await demo.dockerCredential(['list']);
      expect(jsonDecode(listed.text), {'ghcr.io': 'demo-docker-user'});
      expect(listed.text, isNot(contains('demo-docker-token')));
      final other = await demo.dockerCredential(['get'], ['quay.io']);
      expect(other.code, 1);
      expect(other.text, '$tsmDockerNotFound\n');
      await sub.cancel();
      expect(prompted, isFalse);

      var proposals = 0;
      final watch = admin.events.listen((e) {
        if (e['op'] == 'proposal') proposals++;
      });
      final known = await demo.dockerCredential(
        ['store'],
        [
          jsonEncode({
            'ServerURL': 'ghcr.io',
            'Username': 'demo-docker-user',
            'Secret': 'demo-docker-token',
          }),
        ],
      );
      expect(known.code, 0);
      await demo.dockerCredential(
        ['store'],
        [
          jsonEncode({
            'ServerURL': 'ghcr.io',
            'Username': 'demo-docker-user',
            'Secret': 'demo-docker-new-token',
          }),
        ],
      );
      final erase = await demo.dockerCredential(['erase'], ['ghcr.io']);
      expect(erase.code, 0);
      expect(erase.text, isEmpty);
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await watch.cancel();
      expect(proposals, 1);
    });
  });

  test('tsm integrations: aws per profile and docker per registry, shown '
      'and removed', () async {
    final demo = await Demo.create();
    final home = Directory.systemTemp.createTempSync('tsm_home');
    addTearDown(() => home.deleteSync(recursive: true));
    final bin = Directory('${home.path}/bin')..createSync();
    File('${bin.path}/tsm').writeAsStringSync('demo');
    Future<TsmRun> integrations(List<String> args) async {
      demo.environmentOverrides = {
        'HOME': home.path,
        'PATH': '/usr/bin:${bin.path}',
      };
      return demo.tsm(['integrations', ...args], executableDirectory: bin.path);
    }

    var r = await integrations([
      'install',
      'aws',
      '--profile',
      'ci',
      '--ref',
      'team/Cloud/AWS session',
    ]);
    expect(r.code, 0, reason: '$r');
    expect(r.text, contains('aws    installed'));
    expect(r.text, contains('profile ci: team/Cloud/AWS session'));
    expect(
      File('${home.path}/.aws/config').readAsStringSync(),
      contains(
        "credential_process = ${bin.path}/tsm aws-credentials "
        "'team/Cloud/AWS session'",
      ),
    );
    r = await integrations(['install', 'aws', '--profile', 'ci']);
    expect(r.code, TsmExit.usage);
    r = await integrations(['install', 'aws']);
    expect(r.code, 0, reason: 'the profiles it has are kept: $r');
    r = await integrations([
      'install',
      'docker',
      '--registry',
      'ghcr.io',
      '--registry',
      'registry.example:5000',
    ]);
    expect(r.code, 0, reason: '$r');
    expect(r.text, contains('docker installed'));
    expect(r.text, contains('registry registry.example:5000'));
    expect(
      Link('${bin.path}/docker-credential-tsm').targetSync(),
      '${bin.path}/tsm',
    );
    final json = jsonDecode((await integrations(['--json'])).text) as List;
    expect(
      [for (final s in json) (s as Map)['integration']],
      ['ssh', 'git', 'aws', 'docker'],
    );
    expect((json[2] as Map)['profiles'], {'ci': 'team/Cloud/AWS session'});
    expect((json[3] as Map)['registries'], [
      'ghcr.io',
      'registry.example:5000',
    ]);
    r = await integrations(['install', 'docker']);
    expect(r.code, 0, reason: 'the registries it has are kept: $r');
    r = await integrations(['uninstall', 'aws', '--profile', 'ci']);
    expect(r.text, contains('aws    not installed'));
    r = await integrations(['uninstall', 'docker']);
    expect(r.text, contains('docker not installed'));
    expect(
      jsonDecode(File('${home.path}/.docker/config.json').readAsStringSync()),
      isEmpty,
    );
    r = await integrations(['install', 'docker']);
    expect(r.code, TsmExit.usage, reason: 'nothing to name: $r');
  });
}
