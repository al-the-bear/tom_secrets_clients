// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The user guide (`doc/tsm_user_guide.md`) against `tsm --help`: every
/// command the help lists has a heading naming it (`` `tsm <command>` ``),
/// every option of `tsm <command> --help` is in that heading's section,
/// every global option in "Global options", and every error kind of the
/// help's exit codes in "Exit codes and troubleshooting".
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_tsm/tom_secrets_tsm.dart';

/// What `tsm` prints for [args] (help needs no service), its console
/// markup (`<yellow>**Title**</yellow>`) removed.
Future<String> help(List<String> args) async {
  final out = BytesBuilder();
  final err = StringBuffer();
  final printed = StringBuffer();
  await runZoned(
    () => tsmMain(
      args,
      TsmIo(
        writeOut: out.add,
        err: err,
        readSecret: (_) async => null,
        readLine: () async => null,
        environment: const {},
        keychain: () async => null,
        executableDirectory: '/nonexistent',
        runCommand: (command, env) async => 0,
      ),
    ),
    zoneSpecification: ZoneSpecification(
      print: (self, parent, zone, line) => printed.writeln(line),
    ),
  );
  return '${utf8.decode(out.takeBytes())}$err$printed'
      .replaceAll(RegExp(r'</?[a-z]+>'), '')
      .replaceAll('**', '');
}

/// The lines of [text] in the section that starts with the line [title]
/// and ends at the next line that starts at the left margin.
List<String> helpSection(String text, String title) {
  final lines = const LineSplitter().convert(text);
  final at = lines.indexOf(title);
  if (at < 0) throw StateError('the help has no section $title');
  return [
    for (final l
        in lines
            .skip(at + 1)
            .takeWhile((l) => l.trim().isEmpty || l.startsWith(' ')))
      l,
  ];
}

/// The long options (`--name`) of a help section's lines.
Set<String> options(List<String> section) => {
  for (final l in section)
    if (RegExp(r'^\s+(?:-\w, )?(--[a-z][a-z0-9-]*)').firstMatch(l)
        case final m?)
      m[1]!,
};

/// The guide's sections: each heading line with the text up to the next
/// heading of the same or a higher level.
Map<String, String> guideSections(String text) {
  final lines = const LineSplitter().convert(text);
  final sections = <String, String>{};
  var fence = false;
  final headings = <int>[];
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('```')) fence = !fence;
    if (!fence && RegExp(r'^#{2,4} ').hasMatch(lines[i])) headings.add(i);
  }
  int level(int i) => RegExp(r'^#+').firstMatch(lines[i])![0]!.length;
  for (final h in headings) {
    final end = headings.firstWhere(
      (n) => n > h && level(n) <= level(h),
      orElse: () => lines.length,
    );
    sections[lines[h]] = lines.sublist(h + 1, end).join('\n');
  }
  return sections;
}

void main() {
  late String top;
  late Map<String, String> sections;

  setUpAll(() async {
    top = await help(['--help']);
    sections = guideSections(File('doc/tsm_user_guide.md').readAsStringSync());
  });

  /// The commands `tsm --help` lists.
  List<String> commands() => [
    for (final l in helpSection(top, 'Commands'))
      if (RegExp(r'^  ([a-z][a-z-]*)$').firstMatch(l) case final m?) m[1]!,
  ];

  test('the help lists the commands', () {
    expect(commands(), containsAll(['get', 'run', 'pair', 'integrations']));
  });

  test(
    'every command has a heading, and its options are in its section',
    () async {
      for (final command in commands()) {
        final heading = sections.keys.where(
          (h) => h.contains('`tsm $command`'),
        );
        expect(
          heading,
          hasLength(1),
          reason: 'a heading naming `tsm $command`',
        );
        final text = await help([command, '--help']);
        expect(text, contains('tsm [global-options] $command'));
        // A command without options has no such section.
        final own = text.contains('\nCommand Options\n')
            ? options(helpSection(text, 'Command Options'))
            : const <String>{};
        for (final option in own) {
          expect(
            sections[heading.single],
            contains('`$option`'),
            reason: '${heading.single} names $option',
          );
        }
      }
    },
  );

  test('every global option is in "Global options"', () {
    final global = options(helpSection(top, 'Global Options'));
    expect(global, containsAll(['--password-stdin', '--version']));
    final section = sections['## Global options']!;
    for (final option in global) {
      expect(section, contains('`$option'), reason: option);
    }
  });

  test(
    'every error kind of the exit codes is in the troubleshooting table',
    () {
      final footer = const LineSplitter()
          .convert(top)
          .firstWhere((l) => l.startsWith('Exit codes:'));
      final kinds = RegExp(r'\b([a-z]+(?:_[a-z]+)*)\b')
          .allMatches(footer.substring(footer.indexOf('2 usage')))
          .map((m) => m[1]!)
          .where((k) => !const {'or'}.contains(k))
          .toSet();
      expect(kinds, containsAll(['usage', 'not_running', 'token_expired']));
      final section = sections['## Exit codes and troubleshooting']!;
      for (final kind in kinds) {
        expect(section, contains(kind), reason: kind);
      }
    },
  );
}
