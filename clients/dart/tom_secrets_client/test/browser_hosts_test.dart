// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The browsers' native-messaging manifests (part-browser): the locations
/// per browser and OS, the manifest's content, installing, removing and the
/// start check, the Windows registry value, a Linux browser in a Flatpak or
/// a Snap; the development id fixed by its key.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

final class _Registry implements TomSecretsRegistry {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<void> delete(String key) async => values.remove(key);
}

void main() {
  late Directory home;

  setUp(() => home = Directory.systemTemp.createTempSync('tsm_browser_hosts'));
  tearDown(() => home.deleteSync(recursive: true));

  TomSecretsBrowserHosts hosts(
    String os, {
    String host = '/app/tsm/bin/tsm-browser-host',
    TomSecretsRegistry? registry,
  }) => TomSecretsBrowserHosts(
    home: home.path,
    hostExecutable: host,
    operatingSystem: os,
    environment: {
      'LOCALAPPDATA': '${home.path}/local',
      'APPDATA': '${home.path}/roaming',
    },
    registry: registry,
  );

  void mkdir(String path) => Directory(path).createSync(recursive: true);

  test('the development id is the one its key fixes', () {
    final digest = sha256
        .convert(base64.decode(tomSecretsChromiumDevelopmentKey))
        .toString()
        .substring(0, 32);
    final id = String.fromCharCodes([
      for (final c in digest.codeUnits)
        'a'.codeUnitAt(0) + int.parse(String.fromCharCode(c), radix: 16),
    ]);
    expect(id, tomSecretsChromiumDevelopmentId);
    expect(tomSecretsChromiumExtensionOrigins, [
      'chrome-extension://$tomSecretsChromiumDevelopmentId/',
    ]);
  });

  test('the folders per browser and OS', () {
    final mac = hosts('macos');
    expect(
      mac.manifestPath(TomSecretsBrowser.chrome),
      '${home.path}/Library/Application Support/Google/Chrome/'
      'NativeMessagingHosts/net.tom.secrets.json',
    );
    expect(
      mac.manifestFolder(TomSecretsBrowser.firefox),
      '${home.path}/Library/Application Support/Mozilla/NativeMessagingHosts',
    );
    expect(
      mac.manifestFolder(TomSecretsBrowser.brave),
      '${home.path}/Library/Application Support/BraveSoftware/Brave-Browser/'
      'NativeMessagingHosts',
    );
    final linux = hosts('linux');
    expect(
      linux.manifestFolder(TomSecretsBrowser.chrome),
      '${home.path}/.config/google-chrome/NativeMessagingHosts',
    );
    expect(
      linux.manifestFolder(TomSecretsBrowser.edge),
      '${home.path}/.config/microsoft-edge/NativeMessagingHosts',
    );
    expect(
      linux.manifestFolder(TomSecretsBrowser.firefox),
      '${home.path}/.mozilla/native-messaging-hosts',
    );
    final windows = hosts('windows');
    expect(
      windows.registryKey(TomSecretsBrowser.chrome),
      r'HKCU\Software\Google\Chrome\NativeMessagingHosts\net.tom.secrets',
    );
    expect(
      windows.registryKey(TomSecretsBrowser.edge),
      r'HKCU\Software\Microsoft\Edge\NativeMessagingHosts\net.tom.secrets',
    );
    expect(
      windows.registryKey(TomSecretsBrowser.firefox),
      r'HKCU\Software\Mozilla\NativeMessagingHosts\net.tom.secrets',
    );
    expect(
      windows.profileFolder(TomSecretsBrowser.chrome),
      '${home.path}/local\\Google\\Chrome\\User Data',
    );
    expect(linux.registryKey(TomSecretsBrowser.chrome), isNull);
  });

  test('the manifest: the host\'s path, stdio, the product\'s extensions', () {
    final h = hosts('macos');
    expect(h.manifest(TomSecretsBrowser.chrome), {
      'name': 'net.tom.secrets',
      'description': 'Tom Secrets Manager',
      'path': '/app/tsm/bin/tsm-browser-host',
      'type': 'stdio',
      'allowed_origins': tomSecretsChromiumExtensionOrigins,
    });
    expect(h.manifest(TomSecretsBrowser.firefox)['allowed_extensions'], [
      tomSecretsFirefoxExtensionId,
    ]);
    expect(
      h.manifest(TomSecretsBrowser.firefox).containsKey('allowed_origins'),
      isFalse,
    );
  });

  test('a browser is offered when its profile is there; installed, current, '
      'removed', () async {
    final h = hosts('linux');
    expect((await h.state(TomSecretsBrowser.chrome)).present, isFalse);
    mkdir('${home.path}/.config/google-chrome');
    var s = await h.state(TomSecretsBrowser.chrome);
    expect(s.present, isTrue);
    expect(s.installed, isFalse);

    await h.install(TomSecretsBrowser.chrome);
    s = await h.state(TomSecretsBrowser.chrome);
    expect(s.installed, isTrue);
    expect(s.current, isTrue);
    final written = jsonDecode(File(s.manifest).readAsStringSync()) as Map;
    expect(written['path'], '/app/tsm/bin/tsm-browser-host');

    await h.remove(TomSecretsBrowser.chrome);
    expect(File(s.manifest).existsSync(), isFalse);
    expect((await h.state(TomSecretsBrowser.chrome)).installed, isFalse);
  });

  test('the start check rewrites a manifest naming a moved host and leaves '
      'the others', () async {
    mkdir('${home.path}/.config/google-chrome');
    mkdir('${home.path}/.mozilla/firefox');
    await hosts(
      'linux',
      host: '/old/tsm-browser-host',
    ).install(TomSecretsBrowser.chrome);
    final h = hosts('linux');
    await h.install(TomSecretsBrowser.firefox);
    final before = await h.state(TomSecretsBrowser.chrome);
    expect(before.current, isFalse);
    expect(before.problems, ['the manifest names another host']);
    expect(await h.repair(), [TomSecretsBrowser.chrome]);
    expect((await h.state(TomSecretsBrowser.chrome)).current, isTrue);
    expect(await h.repair(), isEmpty);
  });

  test('Windows: the manifest file and the registry value naming it', () async {
    final registry = _Registry();
    final h = hosts(
      'windows',
      host: r'C:\Apps\TSM\tsm\bin\tsm-browser-host.exe',
      registry: registry,
    );
    await h.install(TomSecretsBrowser.edge);
    final key = h.registryKey(TomSecretsBrowser.edge)!;
    expect(registry.values[key], h.manifestPath(TomSecretsBrowser.edge));
    expect((await h.state(TomSecretsBrowser.edge)).current, isTrue);

    // A registry value naming another file is not current.
    registry.values[key] = r'C:\elsewhere\net.tom.secrets.json';
    expect(
      (await h.state(TomSecretsBrowser.edge)).problems,
      contains('the registry names another manifest'),
    );
    await h.remove(TomSecretsBrowser.edge);
    expect(registry.values.containsKey(key), isFalse);
  });

  test(
    'Linux: a Flatpak or Snap browser is named and not installed for',
    () async {
      mkdir('${home.path}/.var/app/org.mozilla.firefox');
      mkdir('${home.path}/snap/chromium');
      final h = hosts('linux');
      expect(
        (await h.state(TomSecretsBrowser.firefox)).sandboxed,
        contains('Flatpak'),
      );
      expect(
        (await h.state(TomSecretsBrowser.chromium)).sandboxed,
        contains('Snap'),
      );
      await expectLater(
        h.install(TomSecretsBrowser.firefox),
        throwsA(isA<StateError>()),
      );
    },
  );

  test('the host beside the service', () {
    expect(
      tomSecretsBrowserHostBeside(
        '/a/tsm/bin/tom_secrets_service',
        operatingSystem: 'macos',
      ),
      '/a/tsm/bin/tsm-browser-host',
    );
    expect(
      tomSecretsBrowserHostBeside(
        r'C:\a\tsm\bin\tom_secrets_service.exe',
        operatingSystem: 'windows',
      ),
      r'C:\a\tsm\bin\tsm-browser-host.exe',
    );
  });
}
