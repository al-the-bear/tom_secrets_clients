// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The developer-tool integrations (part-os-integration, "Installing and
/// checking"): the marked block written and removed with nothing outside it
/// changed, the ssh block at the top of `~/.ssh/config` with its editable
/// host patterns, the git block and the helper link, the check that they
/// still name this machine's agent and helper, and the repair. Demo paths
/// in a temporary home only.
@TestOn('mac-os || linux')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  group('the marked block', () {
    test('added at the top or the end, replaced in place, removed; every '
        'other line kept', () {
      const user = 'Host build\n  User demo\n';
      final top = tomSecretsWithBlock(user, ['Host *', '  X 1'], atTop: true);
      expect(
        top,
        '$tomSecretsBlockBegin\nHost *\n  X 1\n$tomSecretsBlockEnd\n\n$user',
      );
      expect(tomSecretsBlockOf(top), ['Host *', '  X 1']);
      final replaced = tomSecretsWithBlock(top, ['Host *', '  X 2']);
      expect(replaced, top.replaceAll('X 1', 'X 2'));
      expect(tomSecretsWithBlock(replaced, null), user);
      final end = tomSecretsWithBlock(user, ['[a]']);
      expect(end, '$user\n$tomSecretsBlockBegin\n[a]\n$tomSecretsBlockEnd\n');
      expect(tomSecretsWithBlock(end, null), user);
      expect(tomSecretsWithBlock('', ['x']), isNot(isEmpty));
      expect(tomSecretsWithBlock('a\r\nb\r\n', ['x']), contains('\r\nx\r\n'));
      expect(tomSecretsBlockOf(user), isNull);
    });

    test('on Windows the pipe is written with doubled backslashes, as '
        "ssh's config reader takes them", () {
      final windows = TomSecretsIntegrations(
        home: r'C:\Users\demo',
        agentEndpoint: r'\\.\pipe\tsm-ssh-agent',
        operatingSystem: 'windows',
      );
      expect(windows.sshBlock(), [
        'Host *',
        r'  IdentityAgent \\\\.\\pipe\\tsm-ssh-agent',
      ]);
      expect(windows.sshConfig, r'C:\Users\demo\.ssh\config');
      final spaced = TomSecretsIntegrations(
        home: '/home/demo',
        agentEndpoint: '/run/a dir/agent.sock',
        operatingSystem: 'linux',
      );
      expect(
        spaced.sshBlock(hosts: '*.example.com').last,
        '  IdentityAgent "/run/a dir/agent.sock"',
      );
    });
  });

  group('install, status, uninstall, repair', () {
    late Directory home;
    late String tsm;

    setUp(() {
      home = Directory.systemTemp.createTempSync('tsm_integrations');
      addTearDown(() => home.deleteSync(recursive: true));
      Directory('${home.path}/bin').createSync();
      tsm = '${home.path}/bin/tsm';
      File(tsm).writeAsStringSync('#!/bin/sh\necho demo tsm\n');
    });

    TomSecretsIntegrations integrations({
      String agent = '/run/demo/tsm/agent.sock',
      String? path,
    }) => TomSecretsIntegrations(
      home: home.path,
      agentEndpoint: agent,
      tsmExecutable: tsm,
      path: path ?? '/usr/bin:${home.path}/bin',
    );

    test('ssh: the block at the top of a config the user has, its host '
        'patterns kept when the agent moves; status names a stale '
        'endpoint; repair rewrites it; uninstall restores the file', () async {
      Directory('${home.path}/.ssh').createSync();
      final config = File('${home.path}/.ssh/config')
        ..writeAsStringSync('Host build\n  User demo\n');
      final i = integrations();
      expect((await i.status(TomSecretsIntegration.ssh)).installed, isFalse);
      var state = await i.install(TomSecretsIntegration.ssh);
      expect(state.installed, isTrue);
      expect(state.current, isTrue);
      expect(state.hosts, '*');
      expect(
        config.readAsStringSync(),
        '$tomSecretsBlockBegin\nHost *\n'
        '  IdentityAgent /run/demo/tsm/agent.sock\n'
        '$tomSecretsBlockEnd\n\nHost build\n  User demo\n',
      );
      await i.install(TomSecretsIntegration.ssh, hosts: '*.example.com');
      final moved = integrations(agent: '/run/other/agent.sock');
      state = await moved.status(TomSecretsIntegration.ssh);
      expect(state.current, isFalse);
      expect(state.problems.single, contains('/run/other/agent.sock'));
      expect(await moved.repair(), [TomSecretsIntegration.ssh]);
      state = await moved.status(TomSecretsIntegration.ssh);
      expect(state.current, isTrue);
      expect(state.hosts, '*.example.com');
      await moved.uninstall(TomSecretsIntegration.ssh);
      expect(config.readAsStringSync(), 'Host build\n  User demo\n');
    });

    test('ssh into a home without ~/.ssh: the folder made 0700, the file '
        '0600', () async {
      await integrations().install(TomSecretsIntegration.ssh);
      String mode(String p) =>
          (FileStat.statSync(p).mode & 0x1ff).toRadixString(8);
      expect(mode('${home.path}/.ssh'), '700');
      expect(mode('${home.path}/.ssh/config'), '600');
    });

    test('git: the block and git-credential-tsm beside tsm; git reads the '
        'helper; a missing link and tsm off PATH are problems; uninstall '
        'removes both', () async {
      final gitconfig = File('${home.path}/.gitconfig')
        ..writeAsStringSync('[user]\n\tname = Demo\n');
      final i = integrations();
      final state = await i.install(TomSecretsIntegration.git);
      expect(state.current, isTrue, reason: '${state.problems}');
      expect(Link('${home.path}/bin/git-credential-tsm').targetSync(), tsm);
      final git = await Process.run('git', [
        'config',
        '--file',
        gitconfig.path,
        '--get-all',
        'credential.helper',
      ]);
      expect('${git.stdout}'.trim(), 'tsm');
      expect(
        (await integrations(
          path: '/usr/bin',
        ).status(TomSecretsIntegration.git)).problems.single,
        contains('is not on PATH'),
      );
      File('${home.path}/bin/git-credential-tsm').deleteSync();
      expect(
        (await i.status(TomSecretsIntegration.git)).problems.single,
        contains('is missing'),
      );
      expect(await i.repair(), [TomSecretsIntegration.git]);
      await i.uninstall(TomSecretsIntegration.git);
      expect(gitconfig.readAsStringSync(), '[user]\n\tname = Demo\n');
      expect(
        FileSystemEntity.typeSync(
          '${home.path}/bin/git-credential-tsm',
          followLinks: false,
        ),
        FileSystemEntityType.notFound,
      );
    });

    test('aws: per profile credential_process naming tsm and the reference, '
        'at the end of a config the user has; as botocore reads it (Python\'s '
        'configparser and shlex); a profile the user defines outside the '
        'block is refused; repair names a moved tsm; one profile removed, '
        'then the block', () async {
      Directory('${home.path}/.aws').createSync();
      final config = File('${home.path}/.aws/config')
        ..writeAsStringSync('[profile own]\nregion = eu-central-1\n');
      final i = integrations();
      expect((await i.status(TomSecretsIntegration.aws)).installed, isFalse);
      var state = await i.install(
        TomSecretsIntegration.aws,
        awsProfiles: {'demo': "team/Cloud/AWS demo's key", 'default': 'aws.ci'},
      );
      expect(state.current, isTrue, reason: '${state.problems}');
      expect(state.profiles, {
        'demo': "team/Cloud/AWS demo's key",
        'default': 'aws.ci',
      });
      final text = config.readAsStringSync();
      expect(text, startsWith('[profile own]\nregion = eu-central-1\n\n'));
      expect(
        text,
        contains(
          '[default]\ncredential_process = $tsm '
          'aws-credentials aws.ci\n',
        ),
      );
      final python = await Process.run('python3', [
        '-c',
        'import configparser, shlex, sys\n'
            'c = configparser.RawConfigParser()\n'
            'c.read(sys.argv[1])\n'
            'for s in ("profile demo", "default"):\n'
            '    print(shlex.split(c.get(s, "credential_process")))\n',
        config.path,
      ]);
      expect(python.exitCode, 0, reason: '${python.stderr}');
      expect('${python.stdout}'.trim().split('\n'), [
        "['$tsm', 'aws-credentials', \"team/Cloud/AWS demo's key\"]",
        "['$tsm', 'aws-credentials', 'aws.ci']",
      ]);
      // A profile the user has outside the block.
      await expectLater(
        i.install(TomSecretsIntegration.aws, awsProfiles: {'own': 'x'}),
        throwsA(isA<StateError>()),
      );
      expect(
        () => i.install(TomSecretsIntegration.aws, awsProfiles: {'a b': 'x'}),
        throwsA(isA<StateError>()),
      );
      // tsm moved: the block is stale, repair rewrites it with the profiles.
      final moved = TomSecretsIntegrations(
        home: home.path,
        tsmExecutable: '${home.path}/bin2/tsm',
        path: '/usr/bin',
      );
      state = await moved.status(TomSecretsIntegration.aws);
      expect(state.current, isFalse);
      expect(state.problems.single, contains('${home.path}/bin2/tsm'));
      expect(await moved.repair(), contains(TomSecretsIntegration.aws));
      state = await moved.status(TomSecretsIntegration.aws);
      expect(state.current, isTrue);
      expect(state.profiles.keys, ['demo', 'default']);
      state = await moved.uninstall(
        TomSecretsIntegration.aws,
        awsProfile: 'demo',
      );
      expect(state.profiles.keys, ['default']);
      await moved.uninstall(TomSecretsIntegration.aws);
      expect(
        config.readAsStringSync(),
        '[profile own]\nregion = eu-central-1\n',
      );
    });

    test('docker: credHelpers per registry and credsStore, the user\'s keys '
        'kept, docker-credential-tsm beside tsm; one registry removed; '
        'uninstall restores the rest and removes the link', () async {
      Directory('${home.path}/.docker').createSync();
      final config = File('${home.path}/.docker/config.json')
        ..writeAsStringSync(
          '{"auths": {"old.example": {}}, "credHelpers": '
          '{"gcr.io": "gcloud"}}',
        );
      final i = integrations();
      expect((await i.status(TomSecretsIntegration.docker)).installed, isFalse);
      var state = await i.install(
        TomSecretsIntegration.docker,
        dockerRegistries: ['ghcr.io', 'registry.example:5000'],
      );
      expect(state.current, isTrue, reason: '${state.problems}');
      expect(state.registries, ['ghcr.io', 'registry.example:5000']);
      expect(state.everyRegistry, isFalse);
      expect(Link('${home.path}/bin/docker-credential-tsm').targetSync(), tsm);
      var json = jsonDecode(config.readAsStringSync()) as Map;
      expect(json['auths'], {'old.example': <String, Object?>{}});
      expect(json['credHelpers'], {
        'gcr.io': 'gcloud',
        'ghcr.io': 'tsm',
        'registry.example:5000': 'tsm',
      });
      state = await i.install(
        TomSecretsIntegration.docker,
        dockerEveryRegistry: true,
      );
      expect(state.everyRegistry, isTrue);
      expect(state.registries, hasLength(2));
      state = await i.uninstall(
        TomSecretsIntegration.docker,
        dockerRegistry: 'ghcr.io',
      );
      expect(state.registries, ['registry.example:5000']);
      expect(state.everyRegistry, isTrue);
      expect(
        File('${home.path}/bin/docker-credential-tsm').existsSync(),
        isTrue,
      );
      state = await i.uninstall(TomSecretsIntegration.docker);
      expect(state.installed, isFalse);
      json = jsonDecode(config.readAsStringSync()) as Map;
      expect(json, {
        'auths': {'old.example': <String, Object?>{}},
        'credHelpers': {'gcr.io': 'gcloud'},
      });
      expect(
        FileSystemEntity.typeSync(
          '${home.path}/bin/docker-credential-tsm',
          followLinks: false,
        ),
        FileSystemEntityType.notFound,
      );
      // A configuration that is no JSON is left alone.
      config.writeAsStringSync('not json');
      await expectLater(
        i.install(TomSecretsIntegration.docker, dockerRegistries: ['x.io']),
        throwsA(isA<StateError>()),
      );
      expect(config.readAsStringSync(), 'not json');
      expect(
        (await i.status(TomSecretsIntegration.docker)).problems.single,
        contains('no JSON'),
      );
    });
  });
}
