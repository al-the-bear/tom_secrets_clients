// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// tsm's command line as a `tom_build_base` tool (workspace rule): one
/// `CommandDefinition` per command, named without the colon
/// (`prefixlessCommands`), none walking projects; `tsm run`'s command after
/// `--`. Standard output carries values and listings only: the runner's own
/// messages go to standard error.
library;

import 'package:tom_build_base/tom_build_base_v2.dart';
import 'package:tom_secrets_client/admin.dart' show TomSecretsAdminException;
import 'package:tom_secrets_client/tom_secrets_client.dart'
    show TomSecretsClientException;

import 'commands.dart';
import 'helpers.dart';
import 'tsm_context.dart';
import 'tsm_io.dart';

/// tsm's version, as its pubspec declares it.
const String tsmVersion = '0.2.8';

const _json = OptionDefinition.flag(
  name: 'json',
  description: 'Print JSON instead of lines.',
);

const _dim = OptionDefinition.multi(
  name: 'dim',
  description: 'A dimension value for the resolution (name=value).',
  valueName: 'name=value',
);

const _keyFile = OptionDefinition.option(
  name: 'key-file',
  description: 'The key file the primary vault is opened with.',
  valueName: 'path',
);

CommandDefinition _command(
  String name,
  String description, {
  List<OptionDefinition> options = const [],
  List<String> examples = const [],
}) => CommandDefinition(
  name: name,
  description: description,
  options: options,
  examples: examples,
  requiresTraversal: false,
  supportsProjectTraversal: false,
);

/// The tool definition.
final ToolDefinition tsmTool = ToolDefinition(
  name: 'tsm',
  description:
      'The Tom Secrets Manager on the command line: reads secrets from the '
      'local secrets service and starts, unlocks and administers it.',
  version: tsmVersion,
  prefixlessCommands: true,
  features: NavigationFeatures.minimal,
  globalOptions: const [
    OptionDefinition.flag(
      name: 'password-stdin',
      description:
          'Read the master password from the first line of standard input '
          'instead of the terminal. For automation; the password then '
          'passes through whatever feeds standard input (a file, a pipe, '
          'the shell history), so keep that as safe as the password.',
    ),
  ],
  helpFooter:
      'Exit codes: 0 success (for run, the command\'s own), 2 usage, '
      '3 not_running, 4 locked, 5 denied, 6 not_found, 7 ambiguous, '
      '8 malformed, 9 timeout or rate_limited, 10 unsupported, 11 internal, '
      'needs_unlock, unavailable, offline or token_expired.\n'
      'The admin key is kept in the OS keychain between invocations; where '
      'none answers (an SSH session) each admin command asks for the master '
      'password and claims the service.',
  commands: [
    _command(
      'integrations',
      'Show, install or remove the developer-tool integrations: ssh (the '
          "service's agent as IdentityAgent in ~/.ssh/config) and git "
          '(credential.helper tsm in ~/.gitconfig, git-credential-tsm beside '
          'tsm). Each is a marked block; nothing outside it changes.',
      options: const [
        OptionDefinition.option(
          name: 'hosts',
          description: 'The ssh Host patterns the agent is used for.',
          valueName: 'patterns',
        ),
        _json,
      ],
      examples: const [
        'tsm integrations',
        'tsm integrations install ssh',
        "tsm integrations install ssh --hosts '*.example.com'",
        'tsm integrations install git',
        'tsm integrations uninstall git',
      ],
    ),
    _command(
      'get',
      'Print a value: the reference\'s field, without a trailing line break.',
      options: const [
        OptionDefinition.option(name: 'field', description: 'The field.'),
        _dim,
        OptionDefinition.flag(
          name: 'no-wait',
          description:
              'Answer at once instead of waiting for an unlock or '
              'an approval.',
        ),
        OptionDefinition.option(
          name: 'timeout',
          description: 'Wait at most this many seconds.',
          valueName: 'seconds',
        ),
        OptionDefinition.flag(
          name: 'base64',
          description: 'Print the value as base64 (needed for a binary one).',
        ),
        OptionDefinition.flag(
          name: 'newline',
          abbr: 'n',
          description: 'End the value with a line break.',
        ),
      ],
      examples: const [
        'tsm get telegram.bot_token',
        'tsm get fleet/Db/Main --field UserName -n',
      ],
    ),
    _command(
      'run',
      'Run a command with secrets in its environment: every reference '
          'fetched at once (one approval), the command started only when all '
          'were answered, its exit code tsm\'s.',
      options: const [
        OptionDefinition.multi(
          name: 'map',
          description: 'An environment variable and its reference (VAR=ref).',
          valueName: 'VAR=ref',
        ),
        OptionDefinition.option(
          name: 'env-file',
          description: 'A file of VAR=ref lines (no secrets: commit it).',
          valueName: 'path',
        ),
        _dim,
        OptionDefinition.multi(
          name: 'file',
          description:
              'A value as a temporary file (its path in VAR), deleted when '
              'the command ends; a certificate or PGP key entry gives its '
              'private key.',
          valueName: 'VAR=ref',
        ),
      ],
      examples: const [
        'tsm run --map BOT_TOKEN=telegram.bot_token -- ./bot',
        'tsm run --file TLS_KEY=web/Cert -- ./server',
      ],
    ),
    _command(
      'ref',
      'Parse a reference (ref parse <ref>) or format one (ref format --key K '
          '| --store S --path SEG… | --store S --uuid HEX, --field, '
          '--qualifier name:value).',
      options: const [
        OptionDefinition.option(name: 'key', description: 'A key.'),
        OptionDefinition.option(name: 'store', description: 'A store.'),
        OptionDefinition.multi(name: 'path', description: 'A path segment.'),
        OptionDefinition.option(name: 'uuid', description: 'An entry UUID.'),
        OptionDefinition.option(name: 'field', description: 'The field.'),
        OptionDefinition.multi(
          name: 'qualifier',
          description: 'A qualifier (name:value).',
        ),
      ],
    ),
    _command(
      'start',
      'Start the service (its admin key kept in the keychain).',
      options: const [
        OptionDefinition.flag(name: 'unlock', description: 'Unlock it too.'),
        OptionDefinition.option(
          name: 'bootstrap',
          description:
              'The bootstrap file (default: bootstrap.yaml in the '
              'data directory, TSM_DATA_DIR).',
          valueName: 'path',
        ),
        OptionDefinition.option(
          name: 'service',
          description:
              'The service executable (default: TSM_SERVICE, else '
              'tom_secrets_service beside tsm).',
          valueName: 'path',
        ),
        _keyFile,
      ],
    ),
    _command(
      'pair',
      "Set this machine up by pairing: pair <host:port> <code>, as the other "
          "machine's Pairing screen shows them (or pair <code> --relay … "
          'through a GitHub repository); then the master password, and the '
          'service is started and unlocked.',
      options: const [
        OptionDefinition.option(
          name: 'device',
          description: "This machine's name (default: its host name).",
          valueName: 'name',
        ),
        OptionDefinition.option(
          name: 'device-key',
          description:
              'Where the device settings key is kept: auto (default), '
              'keychain, vault or keyfile.',
          valueName: 'mode',
        ),
        OptionDefinition.option(
          name: 'link',
          description:
              "Where this machine's approval link listens (a VPN or LAN "
              'address and a port); the other machine opens the link to it '
              'and answers its prompts.',
          valueName: 'address:port',
        ),
        OptionDefinition.option(
          name: 'relay',
          description:
              'A GitHub repository the pairing goes through when the other '
              'machine is neither on this network nor the VPN (its Pairing '
              'screen names it): tried after the address, or alone.',
          valueName: 'github:owner/repo',
        ),
        OptionDefinition.option(
          name: 'token-env',
          description:
              "The environment variable holding this machine's own GitHub "
              'token for the relay\'s repository (never the token itself on '
              'the command line).',
          valueName: 'VAR',
        ),
        OptionDefinition.option(
          name: 'relay-api',
          description:
              "The GitHub API's URL for the relay (default "
              'https://api.github.com; GitHub Enterprise Server).',
          valueName: 'url',
        ),
        OptionDefinition.option(
          name: 'service',
          description:
              'The service executable (default: TSM_SERVICE, else '
              'tom_secrets_service beside tsm).',
          valueName: 'path',
        ),
      ],
      examples: const [
        'tsm pair 192.168.1.20:47900 7-guitar-orbit',
        'tsm pair 10.8.0.7:47900 7-guitar-orbit --link 10.8.0.1:47731',
        'TSM_PAIR_TOKEN=github_pat_… tsm pair 42-guitar-orbit '
            '--relay github:example-org/vaults --token-env TSM_PAIR_TOKEN',
      ],
    ),
    _command(
      'unlock',
      'Unlock with the master password.',
      options: const [_keyFile],
    ),
    _command('lock', 'Lock: drop every secret from memory.'),
    _command('stop', 'Lock and stop the service.'),
    _command('reload', 'Fetch every store now.'),
    _command(
      'status',
      'The service, its stores with their state and the age of their copy, '
          'and the keys due a reminder.',
      options: const [_json],
    ),
    _command(
      'keys',
      'Every key with its due date; * marks those due a reminder.',
      options: const [_json],
    ),
    _command(
      'approvals',
      'The requests waiting on this host, with their approval codes.',
      options: const [_json],
    ),
    _command(
      'approve',
      'Redeem a one-time approval token (approve <token>, or approve - to '
          'read it from standard input); without a token, have the service take '
          'the approvals recorded in the primary vault.',
    ),
    _command(
      'approve-code',
      'On a trusted device with command-line approvals on: print the token '
          'for an approval code shown on another host.',
      options: const [
        OptionDefinition.option(name: 'host', description: 'The host.'),
        OptionDefinition.option(
          name: 'decision',
          description: 'once, always or never (default once).',
        ),
        OptionDefinition.option(
          name: 'secret',
          description: 'ref, store or all (default ref).',
        ),
      ],
    ),
    _command(
      'grants',
      'Show the grants (grants [list] [--host H]) or revoke one (grants '
          'revoke <host> <grantId>).',
      options: const [
        OptionDefinition.option(name: 'host', description: 'Only this host.'),
        _json,
      ],
    ),
    _command(
      'allow',
      'Pre-approve: allow <host> <subject> <ref|all> (where command-line '
          'approvals are on).',
      options: const [
        OptionDefinition.flag(name: 'never', description: 'A never grant.'),
        OptionDefinition.option(
          name: 'pin',
          description: 'The pin: hash (the file as it is now) or off.',
        ),
      ],
    ),
    _command(
      'audit',
      'The audit log (default: the last 7 days).',
      options: const [
        OptionDefinition.option(name: 'since', description: 'From (ISO 8601).'),
        OptionDefinition.option(name: 'until', description: 'To (ISO 8601).'),
        OptionDefinition.option(name: 'subject', description: 'A subject.'),
        OptionDefinition.option(name: 'ref', description: 'A reference.'),
        _json,
      ],
    ),
    _command(
      'compact',
      'Cut the history of a vault repository now: compact <owner/name>.',
    ),
    _command(
      'login',
      'Sign in with GitHub: prints a code to enter on github.com (on any '
          'device); the service then keeps and renews the GitHub App\'s '
          'tokens for the vault repositories.',
      options: const [
        OptionDefinition.option(
          name: 'client-id',
          description:
              'The GitHub App\'s client id, while the primary vault (which '
              'names it) cannot be read yet.',
          valueName: 'id',
        ),
      ],
      examples: const ['tsm login'],
    ),
    _command(
      'logout',
      'Sign out of the GitHub App on this machine: its pasted tokens are used '
          'again.',
    ),
  ],
);

typedef _Command = Future<int> Function(TsmContext c, TsmArgs a);

const Map<String, _Command> _commands = {
  'get': tsmGet,
  'run': tsmRun,
  'ref': tsmRef,
  'start': tsmStart,
  'pair': tsmPair,
  'unlock': tsmUnlock,
  'lock': tsmLock,
  'stop': tsmStop,
  'reload': tsmReload,
  'status': tsmStatus,
  'keys': tsmKeys,
  'approvals': tsmApprovals,
  'approve': tsmApprove,
  'approve-code': tsmApproveCode,
  'grants': tsmGrants,
  'allow': tsmAllow,
  'audit': tsmAudit,
  'compact': tsmCompact,
  'login': tsmLogin,
  'logout': tsmLogout,
  'integrations': tsmIntegrations,
};

/// Runs tsm with [arguments] over [io]; answers the exit code.
Future<int> tsmMain(List<String> arguments, TsmIo io) async {
  final context = TsmContext(io);
  final runner = ToolRunner(
    tool: tsmTool,
    output: io.messages,
    executors: {
      for (final MapEntry(key: name, value: command) in _commands.entries)
        name: CallbackExecutor(
          onExecute: (_, _) async =>
              const ItemResult.success(path: '.', name: 'tsm'),
          onExecuteWithoutTraversal: (args) async {
            context.passwordFromStdin =
                args.extraOptions['password-stdin'] == true;
            final options = <String, Object?>{
              ...args.extraOptions,
              ...?args.commandArgs[name]?.options,
            };
            try {
              context.processExitCode ??= await command(
                context,
                TsmArgs(
                  positional: args.positionalArgs,
                  options: options,
                  passthrough: args.passthroughArgs,
                ),
              );
            } on TsmFailure catch (e) {
              io.err.writeln('tsm: ${e.message}');
              context.processExitCode = e.code;
            } on TomSecretsClientException catch (e) {
              context.processExitCode = context.clientError(e);
            } on TomSecretsAdminException catch (e) {
              context.processExitCode = context.adminError(e);
            }
            // The code is the command's (a run's may exceed what a tool
            // result carries); the runner adds no summary of its own.
            return const ToolResult.success();
          },
        ),
    },
  );
  final result = await runner.run(arguments);
  return context.processExitCode ?? (result.success ? 0 : TsmExit.usage);
}
