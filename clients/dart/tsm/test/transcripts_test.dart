// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The transcripts of the user guide (`doc/tsm_user_guide.md`): each block
/// marked `<!-- transcript <name> -->` is a session of `tsm` (or of its
/// helpers) run against the demo installation, and this test checks the
/// guide still shows what they print. `TSM_UPDATE_TRANSCRIPTS=1 dart test
/// test/transcripts_test.dart` writes the sessions into the guide instead.
///
/// A step prints the command line, then what the command wrote to standard
/// error (prompts, progress, messages), then its standard output, then
/// `[exit code N]` when it failed. The demo's scratch paths are written as
/// a user's paths would read (`/home/demo/…`), a grant's random id as
/// [transcriptGrantId], and dates that follow from today (keys made at the
/// start) as if today were [transcriptToday], so a transcript changes only
/// when tsm's output does. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomInMemorySecretStore;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/demo.dart';

/// The guide the transcripts are in.
const guide = 'doc/tsm_user_guide.md';

/// The day the transcripts are written as of.
final transcriptToday = DateTime.utc(2026, 11, 24);

/// The id a grant is shown with.
const transcriptGrantId = 'g-3f9c2a71e0b84d65';

/// Which program a step runs.
enum Program {
  /// `tsm`.
  tsm,

  /// `git-credential-tsm`.
  git,

  /// `docker-credential-tsm`.
  docker,
}

/// One command of a session.
final class Step {
  /// [args] of [program], [input] its standard input, [code] the exit code
  /// it must end with.
  const Step(
    this.args, {
    this.code = 0,
    this.input = const [],
    this.program = Program.tsm,
  });

  /// The arguments.
  final List<String> args;

  /// The exit code the step ends with.
  final int code;

  /// Its standard input, one line each.
  final List<String> input;

  /// The program.
  final Program program;

  /// The step as a shell line.
  String get line => switch (program) {
    Program.tsm => shellLine(args),
    Program.git =>
      "printf '${input.join(r'\n')}' | "
          '${shellLine(args, program: 'git-credential-tsm')}',
    Program.docker =>
      input.isEmpty
          ? shellLine(args, program: 'docker-credential-tsm')
          : 'echo ${input.single} | '
                '${shellLine(args, program: 'docker-credential-tsm')}',
  };
}

/// The sessions against the demo installation with every value allowed, by
/// name, in the order they run (later ones see what earlier ones did).
const sessions = <String, List<Step>>{
  'ref': [
    Step(['ref', 'parse', '[env:prod]team/Code/Example git#UserName']),
    Step([
      'ref',
      'format',
      '--store',
      'team',
      '--path',
      'Code',
      '--path',
      'Example git',
      '--field',
      'UserName',
      '--qualifier',
      'env:prod',
    ]),
    Step(['ref', 'parse', '[env:prod'], code: 8),
  ],
  'get-values': [
    Step(['get', 'team/Api/Token', '-n']),
    Step(['get', 'team/Code/Example git', '--field', 'UserName', '-n']),
    Step(['get', 'team/Code/Example git', '--field', 'URL', '-n']),
    Step(['get', 'demo.logo', '--field', 'Title', '-n']),
  ],
  'get-errors': [
    Step(['get', 'team/Api/Missing'], code: 6),
    Step(['get', 'demo.logo'], code: 6),
    Step(['get', '[env:prod'], code: 8),
  ],
  'run-map': [
    Step([
      'run',
      '--map',
      'API_TOKEN=team/Api/Token',
      '--map',
      'GIT_USER=team/Code/Example git#UserName',
      '--',
      'printenv',
      'API_TOKEN',
      'GIT_USER',
    ]),
  ],
  'run-file': [
    Step([
      'run',
      '--file',
      'TOKEN_FILE=team/Api/Token',
      '--',
      'sh',
      '-c',
      r'cat "$TOKEN_FILE"',
    ]),
  ],
  'status': [
    Step(['status']),
  ],
  'reload': [
    Step(['reload']),
  ],
  'trust': [
    Step(['trust']),
    Step(['trust', transcriptWords]),
    Step([
      'trust',
      'harbor',
      'violet',
      'cedar',
      'lantern',
      'maple',
      'orbit',
      'pebble',
      'wrong',
    ], code: 13),
  ],
  'lock-unlock': [
    Step(['lock']),
    Step(['get', 'team/Api/Token', '--no-wait'], code: 4),
    Step(['unlock']),
    Step(['get', 'team/Api/Token', '-n']),
  ],
  'keys': [
    Step(['keys']),
  ],
  'approvals': [
    Step(['approvals']),
  ],
  'approve': [
    Step(['approve', 'MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OB'], code: 5),
    Step(['approve']),
  ],
  'approve-code': [
    Step(['approve-code', 'K7QX2MBR4D', '--host', 'server1'], code: 6),
  ],
  'allow-grants': [
    Step(['allow', 'server1', 'exe /opt/app/bin/server', 'team/Api/Token']),
    Step(['grants']),
  ],
  'compact': [
    Step(['compact', 'demo-org/vaults'], code: 6),
  ],
  'login-logout': [
    Step(['login'], code: 6),
    Step(['logout']),
  ],
  'pair-set-up': [
    Step(['pair', '10.0.0.5:47900', '7-guitar-orbit'], code: 5),
  ],
  'aws-credentials': [
    Step(['aws-credentials', 'team/Cloud/AWS session']),
    Step(['aws-credentials', 'team/Cloud/AWS static']),
  ],
  'kube-credential': [
    Step(['kube-credential', 'team/Api/Token']),
  ],
  'integrations': [
    Step(['integrations']),
    Step(['integrations', 'install', 'ssh']),
    Step(['integrations', 'install', 'git']),
    Step([
      'integrations',
      'install',
      'aws',
      '--profile',
      'ci',
      '--ref',
      'team/Cloud/AWS session',
    ]),
    Step(['integrations', 'install', 'docker', '--registry', 'ghcr.io']),
    Step(['integrations']),
    Step(['integrations', 'uninstall', 'docker']),
  ],
  'docker-list': [
    Step(['list'], program: Program.docker),
  ],
};

/// The sessions with the service's own approval policy, an app attached
/// that answers each prompt "Always" with the first login offered.
const approvedSessions = <String, List<Step>>{
  'git-credential': [
    Step(
      ['get'],
      program: Program.git,
      input: ['protocol=https', 'host=git.example.com', ''],
    ),
    Step(
      ['get'],
      program: Program.git,
      input: ['protocol=https', 'host=other.example.com', ''],
    ),
  ],
  'docker-credential': [
    Step(['get'], program: Program.docker, input: ['ghcr.io']),
    Step(['get'], program: Program.docker, input: ['quay.io'], code: 1),
  ],
};

/// The service version a transcript shows.
const transcriptServiceVersion = '0.26.2';

/// The words a transcript shows for the demo service's identity.
const transcriptWords = 'harbor-violet-cedar-lantern-maple-orbit-pebble-quill';

/// The session that stops the service.
const stopSession = <String, List<Step>>{
  'stop': [
    Step(['stop']),
    Step(['status'], code: 3),
  ],
};

/// [args] as a shell line of [program], an argument with a space, a quote,
/// `$`, `[` or `#` quoted.
String shellLine(List<String> args, {String program = 'tsm'}) => [
  program,
  for (final a in args)
    RegExp(r'''[\s#'"$\[]''').hasMatch(a)
        ? "'${a.replaceAll("'", r"'\''")}'"
        : a,
].join(' ');

/// [text] with the fenced block after `<!-- transcript [name] -->` replaced
/// by [body]; throws when the marker or its block is missing.
String replaceTranscript(String text, String name, String body) {
  final marker = '<!-- transcript $name -->';
  final at = text.indexOf(marker);
  if (at < 0) throw StateError('$guide has no $marker');
  final open = text.indexOf('```text\n', at);
  // The closing fence's newline is the opening line's last character when
  // the block is empty.
  final close = open < 0 ? -1 : text.indexOf('\n```', open + 7);
  if (open < 0 ||
      close < 0 ||
      text.substring(at + marker.length, open).trim().isNotEmpty) {
    throw StateError('$marker is not followed by a ```text block');
  }
  return '${text.substring(0, open + 8)}$body${text.substring(close)}';
}

/// [text] with the scratch [paths] (longest first) replaced by the paths
/// they stand for, every grant id by [transcriptGrantId], and every date
/// within three years of [today] moved by the days between [today] and
/// [transcriptToday].
String normalize(String text, Map<String, String> paths, DateTime today) {
  var out = text;
  final ordered = paths.keys.toList()
    ..sort((a, b) => b.length.compareTo(a.length));
  for (final p in ordered) {
    out = out.replaceAll(p, paths[p]!);
  }
  out = out.replaceAll(RegExp(r'\bg-[0-9a-f]{16}\b'), transcriptGrantId);
  // The service's version is the one the tests resolve: the guide shows
  // one that stands for it.
  out = out.replaceAllMapped(
    RegExp(r'(lock mode \w+, version )\d+\.\d+\.\d+'),
    (m) => '${m[1]}$transcriptServiceVersion',
  );
  // The platform of the demo installation is the guide's, whatever the
  // tests run on.
  out = out.replaceAll(
    RegExp(r'\bplatform=(macos|linux|windows)\b'),
    'platform=linux',
  );
  // The identity key is made anew for every demo installation.
  out = out
      .replaceAllMapped(
        RegExp(r'^(identity|trusted) [a-z]+(-[a-z]+){7}$', multiLine: true),
        (m) => '${m[1]} $transcriptWords',
      )
      .replaceAll(
        RegExp(r'presents another identity: [a-z]+(-[a-z]+){7};'),
        'presents another identity: $transcriptWords;',
      )
      .replaceAll(
        RegExp(r'^fingerprint [0-9a-f]{64}$', multiLine: true),
        'fingerprint ${'5c1e' * 16}',
      );
  final shift = transcriptToday.difference(
    DateTime.utc(today.year, today.month, today.day),
  );
  return out.replaceAllMapped(RegExp(r'\b(\d{4})-(\d{2})-(\d{2})\b'), (m) {
    final date = DateTime.utc(
      int.parse(m[1]!),
      int.parse(m[2]!),
      int.parse(m[3]!),
    );
    if (date.difference(today).abs() > const Duration(days: 3 * 366)) {
      return m[0]!;
    }
    final moved = date.add(shift);
    String two(int n) => n.toString().padLeft(2, '0');
    return '${moved.year}-${two(moved.month)}-${two(moved.day)}';
  });
}

/// The command a `tsm run` step starts, played: `printenv NAME…` prints the
/// variables, `sh -c 'cat "$VAR"'` the file the variable names.
Future<int> Function(List<String>, Map<String, String>) playedCommand(
  StringBuffer out,
) => (command, env) async {
  if (command.first == 'printenv') {
    for (final name in command.skip(1)) {
      out.writeln(env[name]);
    }
    return 0;
  }
  final cat = RegExp(r'^cat "\$(\w+)"$');
  if (command.length == 3 && command[0] == 'sh' && command[1] == '-c') {
    final m = cat.firstMatch(command[2]);
    if (m != null) {
      out.writeln(File(env[m[1]!]!).readAsStringSync());
      return 0;
    }
  }
  throw UnsupportedError('no played command for $command');
};

/// One demo installation with the paths the transcripts show.
final class Installation {
  Installation._(this.demo, this.keychain, this.bin, this.adminKey);

  /// The demo, its service started in this process with [policy] and
  /// unlocked; its admin key in [keychain].
  static Future<Installation> start({
    TomSecretsAccessPolicy? policy = const AllowAll(),
    Set<String>? helperExecutables,
  }) async {
    final demo = await Demo.create();
    final keychain = TomInMemorySecretStore();
    final key = tomSecretsRandomBytes();
    final service = await demo.startInProcess(
      adminKey: key,
      policy: policy,
      helperExecutables: helperExecutables,
    );
    await keychain.write(
      tomSecretsAdminKeyHandle(service.startedAt),
      base64.encode(key),
    );
    final home = Directory('${demo.dir}/home')..createSync();
    final bin = Directory('${demo.dir}/bin')..createSync();
    File('${bin.path}/tsm').writeAsStringSync('');
    demo.environmentOverrides = {
      'HOME': home.path,
      'PATH': '${bin.path}:/usr/bin:/bin',
    };
    final installation = Installation._(demo, keychain, bin.path, key);
    expect((await installation.run(const Step(['unlock']))).code, 0);
    return installation;
  }

  /// The demo.
  final Demo demo;

  /// The keychain holding the admin key.
  final TomInMemorySecretStore keychain;

  /// The folder `tsm` is in.
  final String bin;

  /// The service's admin key.
  final List<int> adminKey;

  /// The scratch paths and the paths they are shown as.
  Map<String, String> get paths => {
    '${demo.dir}/home': '/home/demo',
    bin: '/opt/tsm/bin',
    demo.runtimeDirectory: '/run/user/1000/tsm',
    demo.dataDirectory: '/home/demo/.local/share/tom-secrets-manager',
    demo.dir: '/home/demo/vaults',
  };

  /// Runs [step]: what it wrote to standard error and output (the played
  /// command's after tsm's own output), and its exit code.
  Future<({int code, String err, String out})> run(Step step) async {
    final played = StringBuffer();
    // The words the guide shows stand for this installation's.
    final words = (await demo.pins.all()).firstOrNull?.words;
    final TsmRun r = switch (step.program) {
      Program.tsm => await demo.tsm(
        [
          for (final a in step.args)
            a == transcriptWords && words != null ? words : a,
        ],
        keychain: keychain,
        stdinLines: step.input,
        executableDirectory: bin,
        run: playedCommand(played),
      ),
      Program.git => await demo.gitCredential(step.args, step.input),
      Program.docker => await demo.dockerCredential(step.args, step.input),
    };
    return (code: r.code, err: r.err, out: '${r.text}$played');
  }

  /// The transcript of [steps].
  Future<String> transcript(List<Step> steps) async {
    final body = StringBuffer();
    for (final step in steps) {
      final r = await run(step);
      expect(r.code, step.code, reason: '${step.line}: $r');
      body.writeln('\$ ${step.line}');
      // A prompt is answered on the terminal: its line ends there.
      final err = r.err.replaceAll('Master password: ', 'Master password:\n');
      for (final part in [err, r.out]) {
        if (part.isEmpty) continue;
        body.write(part.endsWith('\n') ? part : '$part\n');
      }
      if (r.code != 0) body.writeln('[exit code ${r.code}]');
    }
    return normalize(body.toString().trimRight(), paths, DateTime.now());
  }
}

/// Checks (or with `TSM_UPDATE_TRANSCRIPTS=1` writes) the [sessions] of
/// [installation] in the guide.
Future<void> checkSessions(
  Installation installation,
  Map<String, List<Step>> sessions,
) async {
  final file = File(guide);
  var text = file.readAsStringSync();
  final update = Platform.environment['TSM_UPDATE_TRANSCRIPTS'] == '1';
  for (final MapEntry(key: name, value: steps) in sessions.entries) {
    final updated = replaceTranscript(
      text,
      name,
      await installation.transcript(steps),
    );
    if (!update) {
      expect(
        updated,
        text,
        reason:
            'the transcript $name changed: run '
            'TSM_UPDATE_TRANSCRIPTS=1 dart test test/transcripts_test.dart',
      );
    }
    text = updated;
  }
  if (update) file.writeAsStringSync(text);
}

void main() {
  test('the guide shows what tsm prints in its transcripts', () async {
    await checkSessions(await Installation.start(), sessions);
  });

  test('the helpers, with the approval asked of the app', () async {
    final installation = await Installation.start(
      policy: null,
      helperExecutables: {
        tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!).exe,
      },
    );
    // The app: every prompt answered "Always" with the first login offered.
    final admin = await TomSecretsAdminClient.connect(
      installation.demo.runtime,
      installation.adminKey,
    );
    addTearDown(admin.close);
    await admin.request('subscribe');
    final answered = admin.events
        .where((e) => e['op'] == 'approval_needed')
        .listen((event) async {
          final pick = (event['pick'] as List?)?.cast<Map>();
          await admin.request('approve', {
            'approvalId': event['approvalId'],
            'decision': 'always',
            'secret': 'ref',
            if (pick != null && pick.isNotEmpty) 'pick': pick.first['entryId'],
          });
        });
    addTearDown(answered.cancel);
    await checkSessions(installation, approvedSessions);
  });

  test('stopping the service', () async {
    await checkSessions(await Installation.start(), stopSession);
  });

  test('a marker without its block is refused', () {
    expect(
      () => replaceTranscript('<!-- transcript x -->\n\nprose\n', 'x', 'y'),
      throwsStateError,
    );
    expect(
      replaceTranscript(
        'a\n<!-- transcript x -->\n```text\nold\n```\nb\n',
        'x',
        r'$ tsm get a',
      ),
      'a\n<!-- transcript x -->\n```text\n\$ tsm get a\n```\nb\n',
    );
    // An empty block, followed by another block.
    expect(
      replaceTranscript(
        '<!-- transcript x -->\n```text\n```\n\nnext\n\n```sh\nls\n```\n',
        'x',
        'y',
      ),
      '<!-- transcript x -->\n```text\ny\n```\n\nnext\n\n```sh\nls\n```\n',
    );
    expect(
      shellLine(['get', 'team/Code/Example git']),
      "tsm get 'team/Code/Example git'",
    );
  });

  test('paths, grant ids and the dates that follow from today are '
      'normalized', () {
    final today = DateTime.utc(2027, 3, 1);
    expect(
      normalize(
        '/tmp/x/run/agent.sock 2029-02-28 (in 730 days) 2031-06-01 '
        'g-e3f993636f2e892b',
        {'/tmp/x': '/home/demo/vaults', '/tmp/x/run': '/run/user/1000/tsm'},
        today,
      ),
      '/run/user/1000/tsm/agent.sock 2028-11-23 (in 730 days) 2031-06-01 '
      '$transcriptGrantId',
    );
  });
}
