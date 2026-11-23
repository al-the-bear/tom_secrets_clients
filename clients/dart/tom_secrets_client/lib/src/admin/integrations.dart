// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The developer-tool integrations (part-os-integration, "Installing and
/// checking"), shared by `tsm integrations` and the manager app's Settings ›
/// Integrations: each writes its configuration in a marked block
/// (`# >>> tom secrets >>>` … `# <<< tom secrets <<<`) of the tool's file and
/// removes it again; nothing outside the block changes.
///
/// | Integration | File | Block | Also |
/// | --- | --- | --- | --- |
/// | `ssh` | `~/.ssh/config` (at its top: ssh takes the first value) | `Host *` (editable), `IdentityAgent <the agent endpoint>` | — |
/// | `git` | `~/.gitconfig` | `[credential]`, `helper = tsm` | `git-credential-tsm` beside `tsm`: a symbolic link, on Windows a hard link or a copy |
/// | `aws` | `~/.aws/config` (at its end) | per profile `[profile <name>]` (`[default]`), `credential_process = <tsm> aws-credentials <ref>` | — |
/// | `docker` | `~/.docker/config.json` | none: JSON has no comments, so the product's own keys are its block — `credHelpers` entries `"<registry>": "tsm"`, or `"credsStore": "tsm"` for every registry; no other key changes | `docker-credential-tsm` beside `tsm`, as git's |
///
/// kubectl's kubeconfig is not written: a kubeconfig `user` names the exec
/// plugin itself (`tsm kube-credential <ref>`), as the tsm user guide shows.
///
/// The files are small and read and written synchronously (behind the
/// `Future` API), so a UI test's fake time does not hold them up.
library;

import 'dart:convert';
import 'dart:io';

/// The first line of a block the product writes.
const String tomSecretsBlockBegin = '# >>> tom secrets >>>';

/// The last line of a block the product writes.
const String tomSecretsBlockEnd = '# <<< tom secrets <<<';

/// The lines between the marks of [text]'s block, or null when it has none.
List<String>? tomSecretsBlockOf(String text) {
  final lines = text.split(RegExp(r'\r?\n'));
  final begin = lines.indexWhere((l) => l.trim() == tomSecretsBlockBegin);
  if (begin < 0) return null;
  final end = lines.indexWhere((l) => l.trim() == tomSecretsBlockEnd, begin);
  if (end < 0) return null;
  return lines.sublist(begin + 1, end);
}

/// [text] with its block's lines replaced by [block] (marks added), or the
/// block removed when [block] is null. A new block goes at the top when
/// [atTop], else at the end; an existing one stays where it is. Every line
/// outside the block is kept as it was (line ends as [text] has them).
String tomSecretsWithBlock(
  String text,
  List<String>? block, {
  bool atTop = false,
}) {
  final eol = text.contains('\r\n') ? '\r\n' : '\n';
  final lines = text.isEmpty ? <String>[] : text.split(RegExp(r'\r?\n'));
  // A final line end makes an empty last element.
  final endsWithEol = lines.isNotEmpty && lines.last.isEmpty;
  if (endsWithEol) lines.removeLast();
  final begin = lines.indexWhere((l) => l.trim() == tomSecretsBlockBegin);
  final end = begin < 0
      ? -1
      : lines.indexWhere((l) => l.trim() == tomSecretsBlockEnd, begin);
  final marked = block == null
      ? const <String>[]
      : [tomSecretsBlockBegin, ...block, tomSecretsBlockEnd];
  if (begin >= 0 && end >= 0) {
    lines.replaceRange(begin, end + 1, marked);
  } else if (block != null) {
    if (atTop) {
      lines.insertAll(0, [...marked, '']);
    } else {
      if (lines.isNotEmpty && lines.last.trim().isNotEmpty) lines.add('');
      lines.addAll(marked);
    }
  }
  // A removed block takes the blank line that set it apart with it.
  if (block == null && begin >= 0 && end >= 0) {
    final after = begin < lines.length ? lines[begin] : null;
    final before = begin > 0 ? lines[begin - 1] : null;
    if (after != null &&
        after.trim().isEmpty &&
        (before == null || before.trim().isEmpty)) {
      lines.removeAt(begin);
    } else if (before != null &&
        before.trim().isEmpty &&
        (after == null || after.trim().isEmpty)) {
      lines.removeAt(begin - 1);
    }
  }
  if (lines.isEmpty) return '';
  return '${lines.join(eol)}$eol';
}

/// An integration of a developer tool.
enum TomSecretsIntegration {
  /// `ssh` uses the service's agent (`IdentityAgent` in `~/.ssh/config`).
  ssh,

  /// `git` asks the credential helper `git-credential-tsm`
  /// (`credential.helper tsm` in `~/.gitconfig`).
  git,

  /// **[C]** AWS profiles take their keys from `tsm aws-credentials <ref>`
  /// (`credential_process` in `~/.aws/config`).
  aws,

  /// **[C]** Docker asks the credential helper `docker-credential-tsm`
  /// (`credHelpers` per registry, or `credsStore`, in
  /// `~/.docker/config.json`).
  docker,
}

/// The name Docker runs the helper under (`credHelpers` value `tsm`).
const String tomSecretsDockerHelperName = 'docker-credential-tsm';

/// The name git runs the helper under (`credential.helper tsm`).
const String tomSecretsGitHelperName = 'git-credential-tsm';

/// Where an integration stands.
final class TomSecretsIntegrationState {
  /// The state of [integration].
  const TomSecretsIntegrationState(
    this.integration, {
    required this.installed,
    required this.current,
    required this.file,
    this.problems = const [],
    this.hosts,
    this.profiles = const {},
    this.registries = const [],
    this.everyRegistry = false,
  });

  /// The integration.
  final TomSecretsIntegration integration;

  /// Whether its block is in the tool's file.
  final bool installed;

  /// Whether what it writes names this machine's own endpoint and helper
  /// (false when not installed).
  final bool current;

  /// The tool's file.
  final String file;

  /// What is not right, in words (empty when [current]).
  final List<String> problems;

  /// The ssh block's host patterns (`*` by default), when installed.
  final String? hosts;

  /// **[C]** The AWS profiles of the block: profile name → reference.
  final Map<String, String> profiles;

  /// **[C]** The Docker registries the helper is named for (`credHelpers`).
  final List<String> registries;

  /// **[C]** Whether the helper is Docker's store for every registry
  /// (`credsStore`).
  final bool everyRegistry;

  /// As `tsm integrations status --json` prints it.
  Map<String, Object?> toJson() => {
    'integration': integration.name,
    'installed': installed,
    'current': current,
    'file': file,
    if (problems.isNotEmpty) 'problems': problems,
    'hosts': ?hosts,
    if (profiles.isNotEmpty) 'profiles': profiles,
    if (registries.isNotEmpty) 'registries': registries,
    if (everyRegistry) 'everyRegistry': true,
  };
}

/// The integrations of one user on this machine.
final class TomSecretsIntegrations {
  /// The integrations under [home]: the ssh-agent at [agentEndpoint] (the
  /// service's `statusReport.agent`), the helper beside [tsmExecutable];
  /// [operatingSystem] and [path] (`PATH`) default to this process's.
  TomSecretsIntegrations({
    required this.home,
    this.agentEndpoint,
    this.tsmExecutable,
    String? operatingSystem,
    String? path,
  }) : operatingSystem = operatingSystem ?? Platform.operatingSystem,
       path = path ?? Platform.environment['PATH'] ?? '';

  /// The user's home folder.
  final String home;

  /// Where the service's agent listens, or null when it is not known.
  final String? agentEndpoint;

  /// `tsm`'s executable, or null when it is not known.
  final String? tsmExecutable;

  /// The OS the files are for.
  final String operatingSystem;

  /// The `PATH` git looks for the helper on.
  final String path;

  bool get _windows => operatingSystem == 'windows';

  String get _sep => _windows ? r'\' : '/';

  /// `~/.ssh/config`.
  String get sshConfig => '$home$_sep.ssh${_sep}config';

  /// `~/.gitconfig`.
  String get gitConfig => '$home$_sep.gitconfig';

  /// **[C]** `~/.aws/config`.
  String get awsConfig => '$home$_sep.aws${_sep}config';

  /// **[C]** `~/.docker/config.json`.
  String get dockerConfig => '$home$_sep.docker${_sep}config.json';

  /// The file of [integration].
  String fileOf(TomSecretsIntegration integration) => switch (integration) {
    TomSecretsIntegration.ssh => sshConfig,
    TomSecretsIntegration.git => gitConfig,
    TomSecretsIntegration.aws => awsConfig,
    TomSecretsIntegration.docker => dockerConfig,
  };

  /// `git-credential-tsm` beside `tsm`, or null when `tsm` is not known.
  String? get helperLink => helperLinkOf(tomSecretsGitHelperName);

  /// The helper [name] (`git-credential-tsm`, `docker-credential-tsm`)
  /// beside `tsm`, or null when `tsm` is not known.
  String? helperLinkOf(String name) {
    final tsm = tsmExecutable;
    if (tsm == null) return null;
    final cut = tsm.lastIndexOf(RegExp(r'[/\\]'));
    final dir = cut < 0 ? '.' : tsm.substring(0, cut);
    return '$dir$_sep${_windows ? '$name.exe' : name}';
  }

  /// The helper link [integration] needs, or null (ssh, aws).
  String? _helperNameOf(TomSecretsIntegration integration) =>
      switch (integration) {
        TomSecretsIntegration.git => tomSecretsGitHelperName,
        TomSecretsIntegration.docker => tomSecretsDockerHelperName,
        _ => null,
      };

  /// The ssh block for [hosts] (`Host *` by default).
  List<String> sshBlock({String hosts = '*'}) => [
    'Host $hosts',
    '  IdentityAgent ${_sshValue(agentEndpoint!)}',
  ];

  /// The git block.
  static const List<String> gitBlock = ['[credential]', '\thelper = tsm'];

  /// A value as `ssh_config` reads it: quoted when it holds a space; on
  /// Windows the pipe's backslashes doubled, since ssh's config reader takes
  /// a backslash as an escape.
  String _sshValue(String value) {
    final v = _windows ? value.replaceAll(r'\', r'\\') : value;
    return v.contains(' ') ? '"$v"' : v;
  }

  /// **[C]** The AWS block for [profiles] (profile name → reference): per
  /// profile its section (`[default]` for the default profile) and
  /// `credential_process` running tsm's `aws-credentials`.
  List<String> awsBlock(Map<String, String> profiles) => [
    for (final MapEntry(key: name, value: ref) in profiles.entries) ...[
      name == 'default' ? '[default]' : '[profile $name]',
      'credential_process = ${_shellWord(tsmExecutable!)} aws-credentials '
          '${_shellWord(ref)}',
    ],
  ];

  /// A word as AWS splits `credential_process` (botocore: shlex on POSIX,
  /// the Windows command-line rules on Windows).
  String _shellWord(String word) {
    if (RegExp(r'^[A-Za-z0-9_./:@%+=,-]+$').hasMatch(word)) return word;
    if (_windows) return '"${word.replaceAll('"', r'\"')}"';
    return "'${word.replaceAll("'", "'\"'\"'")}'";
  }

  /// The words of [line] as [_shellWord] writes them.
  List<String> _shellWords(String line) {
    final words = <String>[];
    final b = StringBuffer();
    var inWord = false;
    String? quote;
    for (var i = 0; i < line.length; i++) {
      final ch = line[i];
      if (quote != null) {
        if (ch == quote) {
          quote = null;
        } else if (quote == '"' && ch == r'\' && i + 1 < line.length) {
          b.write(line[++i]);
        } else {
          b.write(ch);
        }
      } else if (ch == "'" || ch == '"') {
        quote = ch;
        inWord = true;
      } else if (ch == ' ' || ch == '\t') {
        if (inWord) {
          words.add(b.toString());
          b.clear();
          inWord = false;
        }
      } else {
        b.write(ch);
        inWord = true;
      }
    }
    if (inWord) words.add(b.toString());
    return words;
  }

  /// The profiles of an AWS block: name → reference.
  Map<String, String> _awsProfilesOf(List<String> block) {
    final profiles = <String, String>{};
    String? section;
    for (final line in block) {
      final s = line.trim();
      final header = RegExp(r'^\[(?:profile\s+)?([^\]]+)\]$').firstMatch(s);
      if (header != null) {
        section = header[1]!.trim();
        continue;
      }
      final m = RegExp(r'^credential_process\s*=\s*(.*)$').firstMatch(s);
      if (section != null && m != null) {
        final words = _shellWords(m[1]!);
        final at = words.indexOf('aws-credentials');
        if (at >= 0 && at + 1 < words.length) {
          profiles[section] = words[at + 1];
        }
      }
    }
    return profiles;
  }

  /// The profiles [text] defines outside its block.
  static Set<String> _awsProfilesOutside(String text) {
    final block = tomSecretsBlockOf(text) ?? const <String>[];
    final inside = block.map((l) => l.trim()).toSet();
    return {
      for (final line in text.split(RegExp(r'\r?\n')))
        if (!inside.contains(line.trim()))
          if (RegExp(r'^\[(?:profile\s+)?([^\]]+)\]$').firstMatch(line.trim())
              case final m?)
            m[1]!.trim(),
    };
  }

  /// The Docker configuration, `{}` when there is none.
  Map<String, Object?> _dockerJson(String? text) {
    if (text == null || text.trim().isEmpty) return {};
    final Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException {
      throw StateError('$dockerConfig is no JSON: not changed');
    }
    if (json is! Map) throw StateError('$dockerConfig is no JSON object');
    return json.cast<String, Object?>();
  }

  /// The registries `credHelpers` names the helper for.
  static List<String> _dockerRegistriesOf(Map<String, Object?> json) {
    final helpers = json['credHelpers'];
    return [
      if (helpers is Map)
        for (final e in helpers.entries)
          if (e.value == 'tsm') '${e.key}',
    ];
  }

  /// The state of [integration].
  Future<TomSecretsIntegrationState> status(
    TomSecretsIntegration integration,
  ) async {
    final file = fileOf(integration);
    final text = await _read(file);
    if (integration == TomSecretsIntegration.docker) {
      return _dockerStatus(file, text);
    }
    final block = text == null ? null : tomSecretsBlockOf(text);
    if (block == null) {
      return TomSecretsIntegrationState(
        integration,
        installed: false,
        current: false,
        file: file,
      );
    }
    final problems = <String>[];
    String? hosts;
    var profiles = const <String, String>{};
    switch (integration) {
      case TomSecretsIntegration.ssh:
        hosts = _hostsOf(block);
        final endpoint = agentEndpoint;
        if (endpoint == null) {
          problems.add('the service names no agent (is it running?)');
        } else if (block.join('\n') !=
            sshBlock(hosts: hosts ?? '*').join('\n')) {
          problems.add('the block does not name this agent ($endpoint)');
        }
      case TomSecretsIntegration.git:
        if (block.join('\n') != gitBlock.join('\n')) {
          problems.add('the block does not name the helper tsm');
        }
        problems.addAll(await _linkProblems(tomSecretsGitHelperName));
      case TomSecretsIntegration.aws:
        profiles = _awsProfilesOf(block);
        if (tsmExecutable == null) {
          problems.add('tsm is not known here');
        } else if (block.join('\n') != awsBlock(profiles).join('\n')) {
          problems.add('the block does not name this tsm ($tsmExecutable)');
        }
        for (final p in _awsProfilesOutside(
          text!,
        ).intersection(profiles.keys.toSet())) {
          problems.add('the profile $p is also defined outside the block');
        }
      case TomSecretsIntegration.docker:
        throw StateError('unreachable');
    }
    return TomSecretsIntegrationState(
      integration,
      installed: true,
      current: problems.isEmpty,
      file: file,
      problems: problems,
      hosts: hosts,
      profiles: profiles,
    );
  }

  Future<TomSecretsIntegrationState> _dockerStatus(
    String file,
    String? text,
  ) async {
    final Map<String, Object?> json;
    try {
      json = _dockerJson(text);
    } on StateError catch (e) {
      return TomSecretsIntegrationState(
        TomSecretsIntegration.docker,
        installed: false,
        current: false,
        file: file,
        problems: [e.message],
      );
    }
    final registries = _dockerRegistriesOf(json);
    final every = json['credsStore'] == 'tsm';
    final installed = registries.isNotEmpty || every;
    final problems = installed
        ? await _linkProblems(tomSecretsDockerHelperName)
        : const <String>[];
    return TomSecretsIntegrationState(
      TomSecretsIntegration.docker,
      installed: installed,
      current: installed && problems.isEmpty,
      file: file,
      problems: problems,
      registries: registries,
      everyRegistry: every,
    );
  }

  /// Writes [integration]'s configuration and, for git and Docker, the
  /// helper link: an ssh block for [hosts] (the block's own patterns when
  /// it has some, else `*`); **[C]** the AWS block with [awsProfiles]
  /// (profile name → reference) added to the profiles it has; the Docker
  /// helper for [dockerRegistries] (`credHelpers`, added to those it has)
  /// and, with [dockerEveryRegistry], for every registry (`credsStore`).
  /// Throws [StateError] when the endpoint or `tsm` is not known, when AWS
  /// has no profile to write or a profile is defined outside the block (an
  /// AWS config may define a section once), or when the Docker
  /// configuration is no JSON object.
  Future<TomSecretsIntegrationState> install(
    TomSecretsIntegration integration, {
    String? hosts,
    Map<String, String> awsProfiles = const {},
    List<String> dockerRegistries = const [],
    bool dockerEveryRegistry = false,
  }) async {
    final file = fileOf(integration);
    final text = await _read(file) ?? '';
    switch (integration) {
      case TomSecretsIntegration.ssh:
        if (agentEndpoint == null) {
          throw StateError('the service names no agent (is it running?)');
        }
        final kept = _hostsOf(tomSecretsBlockOf(text) ?? const []);
        await _write(
          file,
          tomSecretsWithBlock(
            text,
            sshBlock(hosts: hosts ?? kept ?? '*'),
            atTop: true,
          ),
          privateDirectory: true,
        );
      case TomSecretsIntegration.git:
        await _link(tomSecretsGitHelperName);
        await _write(file, tomSecretsWithBlock(text, gitBlock));
      case TomSecretsIntegration.aws:
        if (tsmExecutable == null) throw StateError('tsm is not known here');
        for (final name in awsProfiles.keys) {
          if (!RegExp(r'^[A-Za-z0-9_.@+-]+$').hasMatch(name)) {
            throw StateError('not an AWS profile name: $name');
          }
        }
        final profiles = {
          ..._awsProfilesOf(tomSecretsBlockOf(text) ?? const []),
          ...awsProfiles,
        };
        if (profiles.isEmpty) {
          throw StateError('name a profile and the reference of its keys');
        }
        final twice = _awsProfilesOutside(
          text,
        ).intersection(profiles.keys.toSet());
        if (twice.isNotEmpty) {
          throw StateError(
            'the profile ${twice.join(', ')} is defined in $file outside '
            "the block already: remove it there first (an AWS config "
            'defines a profile once)',
          );
        }
        await _write(
          file,
          tomSecretsWithBlock(text, awsBlock(profiles)),
          privateDirectory: true,
        );
      case TomSecretsIntegration.docker:
        final json = _dockerJson(text);
        final registries = {
          ..._dockerRegistriesOf(json),
          ...dockerRegistries.map((r) => r.trim()).where((r) => r.isNotEmpty),
        };
        final every = dockerEveryRegistry || json['credsStore'] == 'tsm';
        if (registries.isEmpty && !every) {
          throw StateError('name a registry, or every registry');
        }
        await _link(tomSecretsDockerHelperName);
        if (registries.isNotEmpty) {
          final helpers = json['credHelpers'];
          json['credHelpers'] = {
            if (helpers is Map) ...helpers.cast<String, Object?>(),
            for (final r in registries) r: 'tsm',
          };
        }
        if (every) json['credsStore'] = 'tsm';
        await _writeDocker(file, json);
    }
    return status(integration);
  }

  /// Removes [integration]'s configuration (and for git and Docker the
  /// helper link); **[C]** with [awsProfile] only that AWS profile, with
  /// [dockerRegistry] only that registry (the link and the rest stay while
  /// something is left).
  Future<TomSecretsIntegrationState> uninstall(
    TomSecretsIntegration integration, {
    String? awsProfile,
    String? dockerRegistry,
  }) async {
    final file = fileOf(integration);
    final text = await _read(file);
    var gone = true;
    switch (integration) {
      case TomSecretsIntegration.docker:
        if (text == null) break;
        final json = _dockerJson(text);
        final helpers = json['credHelpers'];
        if (helpers is Map) {
          final kept = {
            for (final e in helpers.cast<String, Object?>().entries)
              if (e.value != 'tsm' ||
                  (dockerRegistry != null && e.key != dockerRegistry))
                e.key: e.value,
          };
          if (kept.isEmpty) {
            json.remove('credHelpers');
          } else {
            json['credHelpers'] = kept;
          }
        }
        if (dockerRegistry == null && json['credsStore'] == 'tsm') {
          json.remove('credsStore');
        }
        await _writeDocker(file, json);
        gone = _dockerRegistriesOf(json).isEmpty && json['credsStore'] != 'tsm';
      case TomSecretsIntegration.aws when awsProfile != null:
        if (text == null) break;
        final profiles = _awsProfilesOf(tomSecretsBlockOf(text) ?? const [])
          ..remove(awsProfile);
        await _write(
          file,
          tomSecretsWithBlock(
            text,
            profiles.isEmpty ? null : awsBlock(profiles),
          ),
        );
      default:
        if (text != null && tomSecretsBlockOf(text) != null) {
          await _write(file, tomSecretsWithBlock(text, null));
        }
    }
    final helper = _helperNameOf(integration);
    if (helper != null && gone) {
      final link = helperLinkOf(helper);
      if (link != null &&
          FileSystemEntity.typeSync(link, followLinks: false) !=
              FileSystemEntityType.notFound) {
        File(link).deleteSync();
      }
    }
    return status(integration);
  }

  /// Installs again every installed integration that no longer names this
  /// machine's agent, helper or tsm (the app's check at every start), with
  /// the hosts, profiles and registries it has; answers those it repaired.
  Future<List<TomSecretsIntegration>> repair() async {
    final repaired = <TomSecretsIntegration>[];
    for (final integration in TomSecretsIntegration.values) {
      final state = await status(integration);
      if (!state.installed || state.current) continue;
      if (integration == TomSecretsIntegration.ssh && agentEndpoint == null) {
        continue;
      }
      if (integration != TomSecretsIntegration.ssh && tsmExecutable == null) {
        continue;
      }
      try {
        await install(integration);
      } on StateError {
        // A profile also defined outside the block: the user's to settle.
        continue;
      }
      repaired.add(integration);
    }
    return repaired;
  }

  static String? _hostsOf(List<String> block) {
    for (final line in block) {
      final t = line.trim();
      if (t.toLowerCase().startsWith('host ')) return t.substring(5).trim();
    }
    return null;
  }

  Future<List<String>> _linkProblems(String name) async {
    final link = helperLinkOf(name);
    final tsm = tsmExecutable;
    if (link == null || tsm == null) return ['tsm is not known here'];
    final type = FileSystemEntity.typeSync(link, followLinks: false);
    if (type == FileSystemEntityType.notFound) {
      return ['$link is missing'];
    }
    final problems = <String>[];
    if (type == FileSystemEntityType.link) {
      final target = File(link).resolveSymbolicLinksSync();
      if (target != File(tsm).resolveSymbolicLinksSync()) {
        problems.add('$link does not lead to $tsm');
      }
    } else if (File(link).lengthSync() != File(tsm).lengthSync()) {
      problems.add('$link is not this tsm');
    }
    final dir = File(link).parent.path;
    final onPath = path
        .split(_windows ? ';' : ':')
        .any((p) => p.isNotEmpty && _same(p, dir));
    if (!onPath) {
      problems.add(
        '$dir is not on PATH: '
        '${name == tomSecretsDockerHelperName ? 'Docker' : 'git'} will not '
        'find it',
      );
    }
    return problems;
  }

  bool _same(String a, String b) {
    String n(String p) {
      var s = p.endsWith(_sep) && p.length > 1
          ? p.substring(0, p.length - 1)
          : p;
      if (_windows) s = s.toLowerCase();
      return s;
    }

    return n(a) == n(b);
  }

  Future<void> _link(String name) async {
    final link = helperLinkOf(name);
    final tsm = tsmExecutable;
    if (link == null || tsm == null) throw StateError('tsm is not known here');
    if (FileSystemEntity.typeSync(link, followLinks: false) !=
        FileSystemEntityType.notFound) {
      File(link).deleteSync();
    }
    if (!_windows) {
      Link(link).createSync(tsm);
      return;
    }
    // A symbolic link needs a privilege on Windows, and a .cmd shim would
    // make cmd.exe the parent: a hard link, else a copy.
    final made = Process.runSync('cmd', ['/c', 'mklink', '/H', link, tsm]);
    if (made.exitCode != 0) File(tsm).copySync(link);
  }

  static Future<String?> _read(String file) async {
    final f = File(file);
    return f.existsSync() ? f.readAsStringSync() : null;
  }

  Future<void> _write(
    String file,
    String text, {
    bool privateDirectory = false,
  }) async {
    final f = File(file);
    final dir = f.parent;
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
      if (privateDirectory && !_windows) {
        Process.runSync('chmod', ['700', dir.path]);
      }
    }
    final existed = f.existsSync();
    f.writeAsStringSync(text, flush: true);
    if (!existed && privateDirectory && !_windows) {
      Process.runSync('chmod', ['600', f.path]);
    }
  }
}

extension on TomSecretsIntegrations {
  /// Writes the Docker configuration [json] as Docker does (tab-indented).
  Future<void> _writeDocker(String file, Map<String, Object?> json) => _write(
    file,
    '${const JsonEncoder.withIndent('\t').convert(json)}\n',
    privateDirectory: true,
  );
}
