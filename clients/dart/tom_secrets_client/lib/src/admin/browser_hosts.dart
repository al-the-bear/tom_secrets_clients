// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The browsers' native-messaging manifests of the product's host
/// `tsm-browser-host` (part-browser), which the manager app installs per user
/// (Settings › Integrations) and checks at every start:
///
/// | Browser | macOS | Linux | Windows |
/// | --- | --- | --- | --- |
/// | Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` | `~/.config/google-chrome/NativeMessagingHosts/` | `HKCU\Software\Google\Chrome\NativeMessagingHosts\net.tom.secrets` |
/// | Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/` | `~/.config/chromium/NativeMessagingHosts/` | `HKCU\Software\Chromium\NativeMessagingHosts\…` |
/// | Edge | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` | `~/.config/microsoft-edge/NativeMessagingHosts/` | `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\…` |
/// | Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/` | `HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\…` |
/// | Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` | `~/.mozilla/native-messaging-hosts/` | `HKCU\Software\Mozilla\NativeMessagingHosts\…` |
///
/// The manifest `net.tom.secrets.json` names the host's absolute path and
/// the product's extensions (`allowed_origins` for Chromium browsers,
/// `allowed_extensions` for Firefox). On Windows the file is kept in
/// `%LOCALAPPDATA%\TomSecretsManager\NativeMessagingHosts\<browser>\` and the
/// registry key's default value names it. A browser is offered when its
/// profile folder exists; on Linux a browser installed only as a Flatpak or
/// a Snap is named as such and not installed for, since its sandbox cannot
/// start a host outside it.
library;

import 'dart:convert';
import 'dart:io';

/// The native-messaging host's name (the manifest's `name`, its file name
/// and the Windows registry key).
const String tomSecretsBrowserHostId = 'net.tom.secrets';

/// The Firefox extension's id (`browser_specific_settings.gecko.id`).
const String tomSecretsFirefoxExtensionId =
    'tom-secrets@enterprise-flutter.dev';

/// The public key of the Chromium development build (the extension
/// manifest's `key`, base64 of its SubjectPublicKeyInfo), which fixes its id
/// to [tomSecretsChromiumDevelopmentId]; its private key is not kept (an
/// unpacked build needs none).
const String tomSecretsChromiumDevelopmentKey =
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ZF3hVaz8f+yL/A28NvNBTBtbTkK'
    '1Mxrk138GVW3nFHVT1947v5f6cqwZFViQ8txUXVIQotWjGkeX9rKx6LAvf04kJdLU5wZmwNp'
    't8EMnWg+lHDEPr4BBbDfrcY0M5QNIGn33gXFF0z2aMjmecmI1NYmKEnPgXUW2mq4Sm+qeYlW'
    'bHx8biUf5cmgx6HPSCq1yW1B0E1hnTKrsm84i2UKDvrZRsVvIzOTV6krjjRn2lL7Ne7oUkcf'
    '4gQ/Den+a+L0+7VPnlv5bJoVVNlZUC+kfL+IVoVSIXdnnuognLC0Adm9o0xpenkeDVPaQv6r'
    'XW0iFIwNlfHV3dd9KBlaVC7YxwIDAQAB';

/// The Chromium development build's extension id (the first 32 hex digits of
/// the SHA-256 of [tomSecretsChromiumDevelopmentKey], each mapped to `a`–`p`).
const String tomSecretsChromiumDevelopmentId =
    'lcejninmlbnhfnpedlgjjfeelhbgmach';

/// The Chromium extension ids the host serves and the manifests allow: the
/// development build's; the Chrome Web Store's and Edge Add-ons' ids join
/// when the extension is published there (part-browser, Publishing).
const List<String> tomSecretsChromiumExtensionIds = [
  tomSecretsChromiumDevelopmentId,
];

/// The origins of [tomSecretsChromiumExtensionIds] (`allowed_origins`).
List<String> get tomSecretsChromiumExtensionOrigins => [
  for (final id in tomSecretsChromiumExtensionIds) 'chrome-extension://$id/',
];

/// A browser the host can be installed for.
enum TomSecretsBrowser {
  /// Google Chrome.
  chrome('Chrome'),

  /// Chromium.
  chromium('Chromium'),

  /// Microsoft Edge.
  edge('Edge'),

  /// Brave.
  brave('Brave'),

  /// Mozilla Firefox.
  firefox('Firefox');

  const TomSecretsBrowser(this.label);

  /// Its name for the user.
  final String label;

  /// Whether it is Firefox (its manifest lists extension ids, not origins).
  bool get isFirefox => this == firefox;
}

/// The Windows registry, as far as the manifests need it (`HKCU` keys and
/// their default value).
abstract interface class TomSecretsRegistry {
  /// The default value of [key], or null when the key is not there.
  Future<String?> read(String key);

  /// Sets the default value of [key] to [value], creating the key.
  Future<void> write(String key, String value);

  /// Deletes [key].
  Future<void> delete(String key);
}

/// [TomSecretsRegistry] through Windows' own `reg.exe`.
final class TomSecretsRegExe implements TomSecretsRegistry {
  /// The registry.
  const TomSecretsRegExe();

  @override
  Future<String?> read(String key) async {
    final r = await Process.run('reg', ['query', key, '/ve']);
    if (r.exitCode != 0) return null;
    for (final line in LineSplitter.split('${r.stdout}')) {
      final at = line.indexOf('REG_SZ');
      if (at >= 0) return line.substring(at + 'REG_SZ'.length).trim();
    }
    return null;
  }

  @override
  Future<void> write(String key, String value) async {
    final r = await Process.run('reg', [
      'add',
      key,
      '/ve',
      '/t',
      'REG_SZ',
      '/d',
      value,
      '/f',
    ]);
    if (r.exitCode != 0) {
      throw FileSystemException('reg add failed: ${r.stderr}'.trim(), key);
    }
  }

  @override
  Future<void> delete(String key) async {
    await Process.run('reg', ['delete', key, '/f']);
  }
}

/// Where the host stands for one browser.
final class TomSecretsBrowserHostState {
  /// The state of [browser].
  const TomSecretsBrowserHostState(
    this.browser, {
    required this.present,
    required this.installed,
    required this.current,
    required this.manifest,
    this.sandboxed,
    this.problems = const [],
  });

  /// The browser.
  final TomSecretsBrowser browser;

  /// Whether the browser is on this machine for this user (its profile
  /// folder exists).
  final bool present;

  /// Whether the product's manifest is installed for it.
  final bool installed;

  /// Whether the installed manifest names this host and the product's
  /// extensions (false when not installed).
  final bool current;

  /// The manifest file.
  final String manifest;

  /// Why the host cannot work for it (a Flatpak or a Snap), or null.
  final String? sandboxed;

  /// What is not right, in words (empty when [current]).
  final List<String> problems;

  /// As `toJson` writes it (the app's settings, tests).
  Map<String, Object?> toJson() => {
    'browser': browser.name,
    'present': present,
    'installed': installed,
    'current': current,
    'manifest': manifest,
    'sandboxed': ?sandboxed,
    if (problems.isNotEmpty) 'problems': problems,
  };
}

/// The host's manifests of this user: installed, removed, checked.
final class TomSecretsBrowserHosts {
  /// The manifests in [home] naming [hostExecutable] (its absolute path), on
  /// [operatingSystem] (default this one); [environment] (default the
  /// process's) gives Windows' `LOCALAPPDATA` and `APPDATA`; [registry]
  /// (default `reg.exe`) holds Windows' keys.
  TomSecretsBrowserHosts({
    required this.home,
    required this.hostExecutable,
    String? operatingSystem,
    Map<String, String>? environment,
    TomSecretsRegistry? registry,
  }) : operatingSystem = operatingSystem ?? Platform.operatingSystem,
       _environment = environment ?? Platform.environment,
       _registry = registry ?? const TomSecretsRegExe();

  /// The user's home folder.
  final String home;

  /// The host's executable, as the manifests name it.
  final String hostExecutable;

  /// `macos`, `linux` or `windows`.
  final String operatingSystem;

  final Map<String, String> _environment;
  final TomSecretsRegistry _registry;

  bool get _windows => operatingSystem == 'windows';
  String get _sep => _windows ? r'\' : '/';
  String _path(List<String> parts) => parts.join(_sep);

  String get _localAppData =>
      _environment['LOCALAPPDATA'] ?? _path([home, 'AppData', 'Local']);
  String get _appData =>
      _environment['APPDATA'] ?? _path([home, 'AppData', 'Roaming']);

  /// The browser's profile folder, whose presence offers it.
  String profileFolder(TomSecretsBrowser b) => switch (operatingSystem) {
    'macos' => _path([
      home,
      'Library',
      'Application Support',
      ...switch (b) {
        TomSecretsBrowser.chrome => ['Google', 'Chrome'],
        TomSecretsBrowser.chromium => ['Chromium'],
        TomSecretsBrowser.edge => ['Microsoft Edge'],
        TomSecretsBrowser.brave => ['BraveSoftware', 'Brave-Browser'],
        TomSecretsBrowser.firefox => ['Firefox'],
      },
    ]),
    'windows' => switch (b) {
      TomSecretsBrowser.chrome => _path([
        _localAppData,
        'Google',
        'Chrome',
        'User Data',
      ]),
      TomSecretsBrowser.chromium => _path([
        _localAppData,
        'Chromium',
        'User Data',
      ]),
      TomSecretsBrowser.edge => _path([
        _localAppData,
        'Microsoft',
        'Edge',
        'User Data',
      ]),
      TomSecretsBrowser.brave => _path([
        _localAppData,
        'BraveSoftware',
        'Brave-Browser',
        'User Data',
      ]),
      TomSecretsBrowser.firefox => _path([_appData, 'Mozilla', 'Firefox']),
    },
    _ => switch (b) {
      TomSecretsBrowser.chrome => _path([home, '.config', 'google-chrome']),
      TomSecretsBrowser.chromium => _path([home, '.config', 'chromium']),
      TomSecretsBrowser.edge => _path([home, '.config', 'microsoft-edge']),
      TomSecretsBrowser.brave => _path([
        home,
        '.config',
        'BraveSoftware',
        'Brave-Browser',
      ]),
      TomSecretsBrowser.firefox => _path([home, '.mozilla', 'firefox']),
    },
  };

  /// The folder the browser reads the manifest from (on Windows the one the
  /// registry value points into).
  String manifestFolder(TomSecretsBrowser b) => switch (operatingSystem) {
    'macos' => _path([
      home,
      'Library',
      'Application Support',
      ...switch (b) {
        TomSecretsBrowser.chrome => ['Google', 'Chrome'],
        TomSecretsBrowser.chromium => ['Chromium'],
        TomSecretsBrowser.edge => ['Microsoft Edge'],
        TomSecretsBrowser.brave => ['BraveSoftware', 'Brave-Browser'],
        TomSecretsBrowser.firefox => ['Mozilla'],
      },
      'NativeMessagingHosts',
    ]),
    'windows' => _path([
      _localAppData,
      'TomSecretsManager',
      'NativeMessagingHosts',
      b.name,
    ]),
    _ => switch (b) {
      TomSecretsBrowser.firefox => _path([
        home,
        '.mozilla',
        'native-messaging-hosts',
      ]),
      _ => _path([profileFolder(b), 'NativeMessagingHosts']),
    },
  };

  /// The manifest file.
  String manifestPath(TomSecretsBrowser b) =>
      _path([manifestFolder(b), '$tomSecretsBrowserHostId.json']);

  /// The Windows registry key naming the manifest, or null elsewhere.
  String? registryKey(TomSecretsBrowser b) => !_windows
      ? null
      : r'HKCU\Software\' +
            switch (b) {
              TomSecretsBrowser.chrome => r'Google\Chrome',
              TomSecretsBrowser.chromium => 'Chromium',
              TomSecretsBrowser.edge => r'Microsoft\Edge',
              TomSecretsBrowser.brave => r'BraveSoftware\Brave-Browser',
              TomSecretsBrowser.firefox => 'Mozilla',
            } +
            r'\NativeMessagingHosts\' +
            tomSecretsBrowserHostId;

  /// The manifest for [b].
  Map<String, Object?> manifest(TomSecretsBrowser b) => {
    'name': tomSecretsBrowserHostId,
    'description': 'Tom Secrets Manager',
    'path': hostExecutable,
    'type': 'stdio',
    if (b.isFirefox)
      'allowed_extensions': [tomSecretsFirefoxExtensionId]
    else
      'allowed_origins': tomSecretsChromiumExtensionOrigins,
  };

  /// Why [b] is only a sandboxed install on Linux (a Flatpak or a Snap)
  /// whose sandbox cannot start the host, or null.
  String? _sandboxed(TomSecretsBrowser b) {
    if (operatingSystem != 'linux') return null;
    final flatpak = switch (b) {
      TomSecretsBrowser.chrome => 'com.google.Chrome',
      TomSecretsBrowser.chromium => 'org.chromium.Chromium',
      TomSecretsBrowser.edge => 'com.microsoft.Edge',
      TomSecretsBrowser.brave => 'com.brave.Browser',
      TomSecretsBrowser.firefox => 'org.mozilla.firefox',
    };
    if (Directory(_path([home, '.var', 'app', flatpak])).existsSync()) {
      return '${b.label} is installed as a Flatpak, whose sandbox cannot '
          'start the host';
    }
    final snap = switch (b) {
      TomSecretsBrowser.chromium => 'chromium',
      TomSecretsBrowser.brave => 'brave',
      TomSecretsBrowser.firefox => 'firefox',
      _ => null,
    };
    if (snap != null && Directory(_path([home, 'snap', snap])).existsSync()) {
      return '${b.label} is installed as a Snap, whose sandbox cannot start '
          'the host';
    }
    return null;
  }

  /// Where the host stands for [b].
  Future<TomSecretsBrowserHostState> state(TomSecretsBrowser b) async {
    final present = Directory(profileFolder(b)).existsSync();
    final sandboxed = present ? null : _sandboxed(b);
    final path = manifestPath(b);
    final file = File(path);
    final key = registryKey(b);
    final registered = key == null ? null : await _registry.read(key);
    final installed = file.existsSync() && (key == null || registered != null);
    final problems = <String>[];
    if (installed) {
      try {
        final written = jsonDecode(file.readAsStringSync());
        if (written is! Map || written['path'] != hostExecutable) {
          problems.add('the manifest names another host');
        }
        final want = manifest(b);
        final allowed = b.isFirefox ? 'allowed_extensions' : 'allowed_origins';
        if (written is Map && '${written[allowed]}' != '${want[allowed]}') {
          problems.add('the manifest allows other extensions');
        }
      } on FormatException {
        problems.add('the manifest cannot be read');
      }
      if (key != null && registered != path) {
        problems.add('the registry names another manifest');
      }
    }
    return TomSecretsBrowserHostState(
      b,
      present: present,
      installed: installed,
      current: installed && problems.isEmpty,
      manifest: path,
      sandboxed: sandboxed,
      problems: problems,
    );
  }

  /// Every browser's state, in [TomSecretsBrowser]'s order.
  Future<List<TomSecretsBrowserHostState>> states() async => [
    for (final b in TomSecretsBrowser.values) await state(b),
  ];

  /// Writes the manifest for [b] (and on Windows its registry value).
  /// Throws [StateError] for a sandboxed browser.
  Future<void> install(TomSecretsBrowser b) async {
    final sandboxed = (await state(b)).sandboxed;
    if (sandboxed != null) throw StateError(sandboxed);
    final file = File(manifestPath(b));
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(
      '${const JsonEncoder.withIndent('  ').convert(manifest(b))}\n',
    );
    final key = registryKey(b);
    if (key != null) await _registry.write(key, file.path);
  }

  /// Removes the manifest for [b] (and its registry key); nothing else.
  Future<void> remove(TomSecretsBrowser b) async {
    final file = File(manifestPath(b));
    if (file.existsSync()) file.deleteSync();
    final key = registryKey(b);
    if (key != null) await _registry.delete(key);
  }

  /// The check at every start: rewrites each installed manifest that no
  /// longer names this host (the app moved or was updated); answers the
  /// browsers repaired.
  Future<List<TomSecretsBrowser>> repair() async {
    final repaired = <TomSecretsBrowser>[];
    for (final s in await states()) {
      if (s.installed && !s.current) {
        await install(s.browser);
        repaired.add(s.browser);
      }
    }
    return repaired;
  }
}
