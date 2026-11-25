// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The data directory is the user's alone: created 0700 (Windows: the
/// inheritance cut, the user and SYSTEM only), an existing looser one and
/// the files in it tightened (0700 / 0600 on POSIX), and one of another user
/// refused. Scratch folders under the package's `.dart_tool/`.
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

/// The permission bits of [path].
int _mode(String path) => FileStat.statSync(path).mode & 0x1FF;

/// Who [path]'s ACL grants (Windows), lower case without the domain.
Future<Set<String>> _grantees(String path) async {
  final out = (await Process.run('icacls', [path])).stdout as String;
  return {
    for (final line in out.split(RegExp(r'\r?\n')))
      if (line.replaceFirst(path, '').trim().contains(':('))
        line
            .replaceFirst(path, '')
            .trim()
            .split(':(')
            .first
            .split(r'\')
            .last
            .toLowerCase(),
  };
}

void main() {
  late Directory scratch;

  setUp(() {
    final root = Directory('.dart_tool/data_directory_private_test')
      ..createSync(recursive: true);
    scratch = root.createTempSync('run');
  });
  tearDown(() {
    if (scratch.existsSync()) scratch.deleteSync(recursive: true);
  });

  group('POSIX', () {
    test('a fresh data directory is 0700', () async {
      final path = '${scratch.path}/fresh/tom-secrets-manager';
      final result = await tomSecretsPrepareDataDirectory(path);
      expect(result.created, isTrue);
      expect(_mode(path), 0x1C0, reason: 'mode 0700');
    });

    test('an existing looser one is tightened: the folder 0700, its files '
        '0600, its folders 0700', () async {
      final path = '${scratch.path}/loose';
      Directory('$path/cache').createSync(recursive: true);
      File('$path/service.log').writeAsStringSync('demo log');
      File('$path/cache/primary.kdbx').writeAsStringSync('demo vault');
      for (final (p, mode) in [
        (path, '755'),
        ('$path/cache', '755'),
        ('$path/service.log', '644'),
        ('$path/cache/primary.kdbx', '644'),
      ]) {
        await Process.run('chmod', [mode, p]);
      }
      final result = await tomSecretsPrepareDataDirectory(path);
      expect(result.created, isFalse);
      expect(result.tightened, 4);
      expect(_mode(path), 0x1C0);
      expect(_mode('$path/cache'), 0x1C0);
      expect(_mode('$path/service.log'), 0x180, reason: 'mode 0600');
      expect(_mode('$path/cache/primary.kdbx'), 0x180);

      final again = await tomSecretsPrepareDataDirectory(path);
      expect(again.tightened, 0, reason: 'nothing left to tighten');
    });

    test('a file the user may run keeps its owner bits; only group and '
        'others lose theirs', () async {
      final path = '${scratch.path}/exec';
      Directory(path).createSync();
      File('$path/tool').writeAsStringSync('#!/bin/sh');
      await Process.run('chmod', ['755', '$path/tool']);
      await tomSecretsPrepareDataDirectory(path);
      expect(_mode('$path/tool'), 0x1C0, reason: 'mode 0700');
    });

    test('a data directory that is no folder is refused', () async {
      final path = '${scratch.path}/a-file';
      File(path).writeAsStringSync('');
      await expectLater(
        tomSecretsPrepareDataDirectory(path),
        throwsA(isA<TomSecretsDataDirectoryException>()),
      );
    });
  }, testOn: 'mac-os || linux');

  test('Windows: a fresh data directory grants only the user and SYSTEM, '
      'and a looser one is tightened', () async {
    final path = '${scratch.absolute.path}\\fresh';
    await tomSecretsPrepareDataDirectory(path);
    final user = Platform.environment['USERNAME']!.toLowerCase();
    expect(await _grantees(path), {user, 'system'});

    final loose = '${scratch.absolute.path}\\loose';
    Directory(loose).createSync();
    File('$loose\\service.log').writeAsStringSync('demo log');
    final result = await tomSecretsPrepareDataDirectory(loose);
    expect(result.tightened, greaterThan(0), reason: 'inherited grants cut');
    expect(await _grantees(loose), {user, 'system'});
    expect(await _grantees('$loose\\service.log'), {user, 'system'});
  }, testOn: 'windows');
}
