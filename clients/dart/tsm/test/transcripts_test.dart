// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The transcripts of the user guide (`doc/tsm_user_guide.md`): each block
/// marked `<!-- transcript <name> -->` is a `tsm` session run against the
/// demo installation, and this test checks the guide still shows what tsm
/// prints. `TSM_UPDATE_TRANSCRIPTS=1 dart test test/transcripts_test.dart`
/// writes the sessions into the guide instead. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomInMemorySecretStore;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/demo.dart';

/// The guide the transcripts are in.
const guide = 'doc/tsm_user_guide.md';

/// The sessions, by name: each a list of tsm's arguments.
const sessions = <String, List<List<String>>>{
  'get-values': [
    ['get', 'team/Api/Token', '-n'],
    ['get', 'team/Code/Example git', '--field', 'UserName', '-n'],
    ['get', 'team/Code/Example git', '--field', 'URL', '-n'],
  ],
};

/// [args] as a shell line, an argument with a space or `#` quoted.
String shellLine(List<String> args) => [
  'tsm',
  for (final a in args)
    RegExp(r'''[\s#'"$]''').hasMatch(a) ? "'${a.replaceAll("'", r"'\''")}'" : a,
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

void main() {
  late Demo demo;

  setUp(() async {
    demo = await Demo.create();
    final keychain = TomInMemorySecretStore();
    final key = tomSecretsRandomBytes();
    final service = await demo.startInProcess(adminKey: key);
    await keychain.write(
      tomSecretsAdminKeyHandle(service.startedAt),
      base64.encode(key),
    );
    expect((await demo.tsm(['unlock'], keychain: keychain)).code, 0);
  });

  test('the guide shows what tsm prints in its transcripts', () async {
    final file = File(guide);
    var text = file.readAsStringSync();
    final update = Platform.environment['TSM_UPDATE_TRANSCRIPTS'] == '1';
    for (final MapEntry(key: name, value: commands) in sessions.entries) {
      final body = StringBuffer();
      for (final args in commands) {
        final run = await demo.tsm(args);
        expect(run.code, 0, reason: '${shellLine(args)}: $run');
        body
          ..writeln('\$ ${shellLine(args)}')
          ..write(run.text.endsWith('\n') ? run.text : '${run.text}\n');
      }
      final transcript = body.toString().trimRight();
      final updated = replaceTranscript(text, name, transcript);
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
}
