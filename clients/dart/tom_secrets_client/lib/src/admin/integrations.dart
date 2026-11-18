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
library;

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
}

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

  /// As `tsm integrations status --json` prints it.
  Map<String, Object?> toJson() => {
    'integration': integration.name,
    'installed': installed,
    'current': current,
    'file': file,
    if (problems.isNotEmpty) 'problems': problems,
    'hosts': ?hosts,
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

  /// The file of [integration].
  String fileOf(TomSecretsIntegration integration) => switch (integration) {
    TomSecretsIntegration.ssh => sshConfig,
    TomSecretsIntegration.git => gitConfig,
  };

  /// `git-credential-tsm` beside `tsm`, or null when `tsm` is not known.
  String? get helperLink {
    final tsm = tsmExecutable;
    if (tsm == null) return null;
    final cut = tsm.lastIndexOf(RegExp(r'[/\\]'));
    final dir = cut < 0 ? '.' : tsm.substring(0, cut);
    return '$dir$_sep${_windows ? 'git-credential-tsm.exe' : 'git-credential-tsm'}';
  }

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

  /// The state of [integration].
  Future<TomSecretsIntegrationState> status(
    TomSecretsIntegration integration,
  ) async {
    final file = fileOf(integration);
    final text = await _read(file);
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
        problems.addAll(await _linkProblems());
    }
    return TomSecretsIntegrationState(
      integration,
      installed: true,
      current: problems.isEmpty,
      file: file,
      problems: problems,
      hosts: hosts,
    );
  }

  /// Writes [integration]'s block (an ssh block for [hosts]: the block's
  /// own patterns when it has some, else `*`), and for git the helper link.
  /// Throws [StateError] when the endpoint or `tsm` is not known.
  Future<TomSecretsIntegrationState> install(
    TomSecretsIntegration integration, {
    String? hosts,
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
        await _link();
        await _write(file, tomSecretsWithBlock(text, gitBlock));
    }
    return status(integration);
  }

  /// Removes [integration]'s block (and for git the helper link).
  Future<TomSecretsIntegrationState> uninstall(
    TomSecretsIntegration integration,
  ) async {
    final file = fileOf(integration);
    final text = await _read(file);
    if (text != null && tomSecretsBlockOf(text) != null) {
      await _write(file, tomSecretsWithBlock(text, null));
    }
    if (integration == TomSecretsIntegration.git) {
      final link = helperLink;
      if (link != null &&
          await FileSystemEntity.type(link, followLinks: false) !=
              FileSystemEntityType.notFound) {
        await File(link).delete();
      }
    }
    return status(integration);
  }

  /// Installs again every installed integration that no longer names this
  /// machine's agent or helper (the app's check at every start); answers
  /// those it repaired.
  Future<List<TomSecretsIntegration>> repair() async {
    final repaired = <TomSecretsIntegration>[];
    for (final integration in TomSecretsIntegration.values) {
      final state = await status(integration);
      if (!state.installed || state.current) continue;
      if (integration == TomSecretsIntegration.ssh && agentEndpoint == null) {
        continue;
      }
      if (integration == TomSecretsIntegration.git && tsmExecutable == null) {
        continue;
      }
      await install(integration);
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

  Future<List<String>> _linkProblems() async {
    final link = helperLink;
    final tsm = tsmExecutable;
    if (link == null || tsm == null) return ['tsm is not known here'];
    final type = await FileSystemEntity.type(link, followLinks: false);
    if (type == FileSystemEntityType.notFound) {
      return ['$link is missing'];
    }
    final problems = <String>[];
    if (type == FileSystemEntityType.link) {
      final target = await File(link).resolveSymbolicLinks();
      if (target != await File(tsm).resolveSymbolicLinks()) {
        problems.add('$link does not lead to $tsm');
      }
    } else if (await File(link).length() != await File(tsm).length()) {
      problems.add('$link is not this tsm');
    }
    final dir = File(link).parent.path;
    final onPath = path
        .split(_windows ? ';' : ':')
        .any((p) => p.isNotEmpty && _same(p, dir));
    if (!onPath) problems.add('$dir is not on PATH: git will not find it');
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

  Future<void> _link() async {
    final link = helperLink;
    final tsm = tsmExecutable;
    if (link == null || tsm == null) throw StateError('tsm is not known here');
    if (await FileSystemEntity.type(link, followLinks: false) !=
        FileSystemEntityType.notFound) {
      await File(link).delete();
    }
    if (!_windows) {
      await Link(link).create(tsm);
      return;
    }
    // A symbolic link needs a privilege on Windows, and a .cmd shim would
    // make cmd.exe the parent: a hard link, else a copy.
    final made = await Process.run('cmd', ['/c', 'mklink', '/H', link, tsm]);
    if (made.exitCode != 0) await File(tsm).copy(link);
  }

  static Future<String?> _read(String file) async {
    final f = File(file);
    return await f.exists() ? f.readAsString() : null;
  }

  Future<void> _write(
    String file,
    String text, {
    bool privateDirectory = false,
  }) async {
    final f = File(file);
    final dir = f.parent;
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      if (privateDirectory && !_windows) {
        await Process.run('chmod', ['700', dir.path]);
      }
    }
    final existed = await f.exists();
    await f.writeAsString(text, flush: true);
    if (!existed && privateDirectory && !_windows) {
      await Process.run('chmod', ['600', f.path]);
    }
  }
}
