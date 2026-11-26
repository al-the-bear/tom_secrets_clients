// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `tsm install --system` and `tsm uninstall --system` on Linux (tsm_d11):
/// the service installed for every user of a shared server, root's and
/// set-group-ID to `tsm-identity`, which alone reaches the directory of the
/// identity keys. The steps are plain commands, listed before they run, so
/// the operator sees what changes; root runs them.
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/admin.dart';

/// One step of an install: what it does and the command that does it, or
/// a file it writes.
final class TsmInstallStep {
  /// A step running [command].
  const TsmInstallStep(this.what, this.command, {this.optional = false})
    : file = null,
      content = null;

  /// A step writing [content] into [file].
  const TsmInstallStep.write(this.what, this.file, this.content)
    : command = null,
      optional = false;

  /// What it does, for the operator.
  final String what;

  /// The command, or null for a file.
  final List<String>? command;

  /// The file it writes.
  final String? file;

  /// What it writes.
  final String? content;

  /// Whether a failure is told and the install goes on (a link that is
  /// another program's).
  final bool optional;

  @override
  String toString() => command == null ? 'write $file' : command!.join(' ');
}

/// The steps that install the service whose `dart build cli` bundle holds
/// [serviceExecutable] (`<root>/bin/tom_secrets_service`, its native
/// libraries in `<root>/lib`) as the system install of [version] under
/// [prefix]. [groupExists], [libExists], [tsmBeside] and [linkFree] are what
/// the machine has now; [now] dates the record.
List<TsmInstallStep> tsmSystemInstallPlan({
  required String serviceExecutable,
  required String version,
  required DateTime now,
  required bool groupExists,
  required bool libExists,
  required bool tsmBeside,
  required bool linkFree,
  String prefix = tomSecretsSystemPrefix,
}) {
  final bin = File(serviceExecutable).parent.path;
  final root = Directory(bin).parent.path;
  final staged = '$prefix.new';
  final identity = tomSecretsSystemIdentityDirectory;
  final record = TomSecretsSystemInstall(
    prefix: prefix,
    version: version,
    installed: now,
  );
  return [
    if (!groupExists)
      TsmInstallStep('make the group $tomSecretsSystemGroup', [
        'groupadd',
        '--system',
        tomSecretsSystemGroup,
      ]),
    TsmInstallStep('stage the new files', ['rm', '-rf', staged]),
    TsmInstallStep('stage the new files', ['mkdir', '-p', staged]),
    TsmInstallStep('copy the programs', ['cp', '-a', bin, '$staged/bin']),
    if (libExists)
      TsmInstallStep('copy their libraries', [
        'cp',
        '-a',
        '$root/lib',
        '$staged/lib',
      ]),
    TsmInstallStep('make them root\'s', ['chown', '-R', 'root:root', staged]),
    TsmInstallStep('make them root\'s', ['chmod', '-R', 'go-w', staged]),
    TsmInstallStep('give the service its group', [
      'chown',
      'root:$tomSecretsSystemGroup',
      '$staged/bin/tom_secrets_service',
    ]),
    TsmInstallStep('make the service set-group-ID', [
      'chmod',
      '2755',
      '$staged/bin/tom_secrets_service',
    ]),
    TsmInstallStep('replace the installed files', ['rm', '-rf', prefix]),
    TsmInstallStep('replace the installed files', ['mv', staged, prefix]),
    TsmInstallStep('make the identity directory', ['mkdir', '-p', identity]),
    TsmInstallStep('make the identity directory', [
      'chown',
      'root:root',
      Directory(identity).parent.path,
    ]),
    TsmInstallStep('make the identity directory', [
      'chmod',
      '755',
      Directory(identity).parent.path,
    ]),
    TsmInstallStep('make the identity directory the group\'s alone', [
      'chown',
      'root:$tomSecretsSystemGroup',
      identity,
    ]),
    TsmInstallStep('make the identity directory the group\'s alone', [
      'chmod',
      '2770',
      identity,
    ]),
    TsmInstallStep('write the record', [
      'mkdir',
      '-p',
      File(tomSecretsSystemRecord).parent.path,
    ]),
    TsmInstallStep.write(
      'write the record',
      tomSecretsSystemRecord,
      '${const JsonEncoder.withIndent('  ').convert(record.toJson())}\n',
    ),
    TsmInstallStep('write the record', [
      'chmod',
      '644',
      tomSecretsSystemRecord,
    ]),
    if (tsmBeside && linkFree)
      TsmInstallStep('link tsm for every user', [
        'ln',
        '-sfn',
        record.tsmExecutable,
        tomSecretsSystemTsmLink,
      ], optional: true),
  ];
}

/// The steps that remove the system install under [prefix]; with [purge]
/// also the identity keys and the group. [linkOurs]: the `tsm` link points
/// into the install.
List<TsmInstallStep> tsmSystemUninstallPlan({
  required bool purge,
  required bool linkOurs,
  String prefix = tomSecretsSystemPrefix,
}) => [
  if (linkOurs)
    TsmInstallStep('remove the tsm link', [
      'rm',
      '-f',
      tomSecretsSystemTsmLink,
    ]),
  TsmInstallStep('remove the programs', ['rm', '-rf', prefix]),
  TsmInstallStep('remove the record', ['rm', '-f', tomSecretsSystemRecord]),
  TsmInstallStep('remove the record', [
    'rmdir',
    '--ignore-fail-on-non-empty',
    File(tomSecretsSystemRecord).parent.path,
  ], optional: true),
  if (purge) ...[
    TsmInstallStep('remove the identity keys', [
      'rm',
      '-rf',
      Directory(tomSecretsSystemIdentityDirectory).parent.path,
    ]),
    TsmInstallStep('remove the group', [
      'groupdel',
      tomSecretsSystemGroup,
    ], optional: true),
  ],
];

/// Runs [steps] in order, telling each on [say]; stops at the first that
/// fails (an optional one is told and passed). Answers the failure, or null.
Future<String?> tsmRunInstallSteps(
  List<TsmInstallStep> steps, {
  required void Function(String line) say,
  Future<ProcessResult> Function(String executable, List<String> args)? run,
}) async {
  final exec = run ?? Process.run;
  for (final step in steps) {
    say('  $step');
    if (step.command == null) {
      try {
        File(step.file!).writeAsStringSync(step.content!);
      } on FileSystemException catch (e) {
        return '${step.what}: ${e.message}';
      }
      continue;
    }
    final command = step.command!;
    final result = await exec(command.first, command.sublist(1));
    if (result.exitCode != 0) {
      final why =
          '${step.what}: ${command.join(' ')} exited '
          '${result.exitCode} ${'${result.stderr}'.trim()}';
      if (step.optional) {
        say('  (not done: $why)');
        continue;
      }
      return why;
    }
  }
  return null;
}
