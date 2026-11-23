// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's pairing mode (part-sharing, 1. Pairing): `tsm pair` sets a
/// headless machine up by pairing without linking the core itself. It
/// starts the service executable (attached, not detached) and talks to it
/// in JSON lines:
///
/// 1. tsm writes the handover, `{"mode":"pair","dataDirectory","address"?,
///    "port"?,"code","device","deviceKey"?,"approvalLink"?,"relay"?,
///    "relayToken"?,"relayApi"?}`; `approvalLink` (`address:port`,
///    [tomSecretsApprovalLinkProblem]) goes into the device settings, and
///    the giving machine is told it so it opens the approval link to this
///    one. **[C]** `relay` (`github:<owner>/<repo>`, part-relay) is a
///    GitHub repository the pairing also goes through, tried after the
///    address (or alone, without one), with `relayToken`, this machine's
///    own token for that repository (from tsm's `--token-env`, never a
///    command-line argument); `relayApi` is the GitHub API's URL (default
///    `https://api.github.com`; GitHub Enterprise Server or a test).
/// 2. The service receives the pairing and answers `{"status":"received",
///    "giver","vaults":[{"name","locator","primary"}],"config","tokens"}`
///    (nothing stored yet), or `{"status":"error","code","message",
///    "failure"?}` and ends.
/// 3. tsm writes `{"password"}`; the service sets the machine up and
///    answers `{"status":"setUp","bootstrap"}` and ends, or
///    `{"status":"error","code":"wrong_password",…}` and waits for another
///    password (three in all), or another error and ends.
///
/// Then tsm starts the service as `tsm start` does and unlocks it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// The code of a wrong master password; another may be sent.
const String tomSecretsPairingWrongPassword = 'wrong_password';

/// How many master passwords the pairing mode takes.
const int tomSecretsPairingPasswordTries = 3;

/// Why [text] cannot be the device setting `approvalLink` (the address the
/// approval link listens on, protocol.md 9.7), or null: `host:port`, an
/// IPv6 address in brackets (`[fd00::1]:47731`), a port 1–65535 (with
/// [anyPort] also 0, the system picks one), and never every interface
/// (`0.0.0.0`, `::`): the link listens on a VPN or LAN address only.
String? tomSecretsApprovalLinkProblem(String text, {bool anyPort = false}) {
  final at = text.lastIndexOf(':');
  final port = at < 0 ? null : int.tryParse(text.substring(at + 1));
  if (at <= 0 ||
      port == null ||
      port < (anyPort ? 0 : 1) ||
      port > 65535 ||
      text.substring(at + 1).length > 5) {
    return 'the approval link is <VPN or LAN address>:<port>, not $text';
  }
  var host = text.substring(0, at);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
    if (!RegExp(r'^[0-9a-fA-F:]+$').hasMatch(host)) {
      return 'the approval link is <VPN or LAN address>:<port>, not $text';
    }
  } else if (!RegExp(r'^[A-Za-z0-9.-]+$').hasMatch(host)) {
    return 'the approval link is <VPN or LAN address>:<port>, not $text';
  }
  final parsed = InternetAddress.tryParse(host);
  if (parsed != null &&
      (parsed == InternetAddress.anyIPv4 ||
          parsed == InternetAddress.anyIPv6)) {
    return 'the approval link listens on a VPN or LAN address, not on every '
        'interface ($text)';
  }
  return null;
}

/// The pairing mode's handover line.
final class TomSecretsPairingHandover {
  /// A handover: set the machine up in [dataDirectory] by receiving the
  /// pairing at [address]:[port] with [code], as [device]; [deviceKey]
  /// names where the device settings container's key is kept (default
  /// `auto`); [approvalLink] is the address this machine's approval link
  /// listens on (none: no link). With [relay] (and [relayToken]) the
  /// pairing goes through that GitHub repository after the address, or
  /// alone when no address is given.
  const TomSecretsPairingHandover({
    required this.dataDirectory,
    this.address,
    this.port,
    required this.code,
    required this.device,
    this.deviceKey,
    this.approvalLink,
    this.relay,
    this.relayToken,
    this.relayApi,
  });

  /// The handover in [json], or null when it is not a pairing handover.
  /// Throws [FormatException] for a pairing handover that misses a member.
  static TomSecretsPairingHandover? fromJson(Object? json) {
    if (json is! Map || json['mode'] != 'pair') return null;
    final port = json['port'];
    for (final key in ['dataDirectory', 'code', 'device']) {
      if (json[key] is! String || (json[key] as String).isEmpty) {
        throw FormatException('the pairing handover names $key');
      }
    }
    final address = json['address'];
    final relay = json['relay'];
    final relayToken = json['relayToken'];
    final relayApi = json['relayApi'];
    if (address != null || port != null) {
      if (address is! String || address.isEmpty) {
        throw const FormatException('the pairing handover names an address');
      }
      if (port is! int || port < 1 || port > 65535) {
        throw const FormatException('the pairing handover names a port');
      }
    }
    if (relay != null || relayToken != null) {
      if (relay is! String || !relay.startsWith('github:')) {
        throw const FormatException(
          'the pairing handover\'s relay is github:<owner>/<repo>',
        );
      }
      if (relayToken is! String || relayToken.isEmpty) {
        throw const FormatException(
          'a pairing through a relay needs this machine\'s token for it',
        );
      }
    }
    if (relayApi != null && relayApi is! String) {
      throw const FormatException('relayApi is a URL');
    }
    if (address == null && relay == null) {
      throw const FormatException(
        'the pairing handover names an address and port, or a relay',
      );
    }
    final link = json['approvalLink'];
    if (link != null) {
      if (link is! String) {
        throw const FormatException('approvalLink is address:port');
      }
      final problem = tomSecretsApprovalLinkProblem(link);
      if (problem != null) throw FormatException(problem);
    }
    return TomSecretsPairingHandover(
      dataDirectory: json['dataDirectory'] as String,
      address: address as String?,
      port: port as int?,
      code: json['code'] as String,
      device: json['device'] as String,
      deviceKey: json['deviceKey'] as String?,
      approvalLink: link as String?,
      relay: relay as String?,
      relayToken: relayToken as String?,
      relayApi: relayApi as String?,
    );
  }

  /// The data directory the machine is set up in.
  final String dataDirectory;

  /// The giving machine's address, or null (a relay only).
  final String? address;

  /// Its pairing window's port, or null (a relay only).
  final int? port;

  /// The code its Pairing screen shows.
  final String code;

  /// This machine's name.
  final String device;

  /// Where the device settings container's key is kept, or null (`auto`).
  final String? deviceKey;

  /// The address this machine's approval link listens on (`address:port`),
  /// or null: it goes into the device settings, and the giving machine
  /// records it so its service opens the link at once.
  final String? approvalLink;

  /// **[C]** The GitHub repository the pairing also goes through
  /// (`github:<owner>/<repo>`), or null.
  final String? relay;

  /// **[C]** This machine's own token for [relay]'s repository (a pairing
  /// through GitHub needs the repository reachable first); it also opens
  /// the primary when that is there. Never a command-line argument.
  final String? relayToken;

  /// **[C]** The GitHub API's URL for [relay], or null
  /// (`https://api.github.com`).
  final String? relayApi;

  /// The JSON line.
  String toLine() => jsonEncode({
    'mode': 'pair',
    'dataDirectory': dataDirectory,
    'address': ?address,
    'port': ?port,
    'code': code,
    'device': device,
    'deviceKey': ?deviceKey,
    'approvalLink': ?approvalLink,
    'relay': ?relay,
    'relayToken': ?relayToken,
    'relayApi': ?relayApi,
  });
}

/// One vault a pairing gave, as the pairing mode reports it.
typedef TomSecretsPairedVault = ({String name, String locator, bool primary});

/// What a pairing gave, as the pairing mode reports it (no key, no token).
final class TomSecretsPairingReport {
  /// A report.
  const TomSecretsPairingReport({
    required this.giver,
    required this.vaults,
    required this.config,
    required this.tokens,
  });

  /// From the `received` line.
  factory TomSecretsPairingReport.fromJson(Map<String, Object?> json) =>
      TomSecretsPairingReport(
        giver: json['giver']! as String,
        vaults: [
          for (final v in (json['vaults'] as List? ?? const []).cast<Map>())
            (
              name: v['name']! as String,
              locator: v['locator']! as String,
              primary: v['primary'] == true,
            ),
        ],
        config: json['config'] == true,
        tokens: [for (final t in (json['tokens'] as List? ?? const [])) '$t'],
      );

  /// The giving device's name.
  final String giver;

  /// The vaults it gave.
  final List<TomSecretsPairedVault> vaults;

  /// Whether it gave the shared configuration.
  final bool config;

  /// The repositories it gave a token for.
  final List<String> tokens;

  /// The `received` line.
  Map<String, Object?> toJson() => {
    'status': 'received',
    'giver': giver,
    'vaults': [
      for (final v in vaults)
        {'name': v.name, 'locator': v.locator, 'primary': v.primary},
    ],
    'config': config,
    'tokens': tokens,
  };
}

/// The pairing mode answered an error.
final class TomSecretsPairingModeException implements Exception {
  /// An error of [code] with [message]; [failure] names the pairing's
  /// failure (`wrongCode`, `refused`, …) when the pairing failed.
  const TomSecretsPairingModeException(this.code, this.message, {this.failure});

  /// The error's code (`pairing`, `wrong_password`, `setup`, `handover`,
  /// `ended`).
  final String code;

  /// What happened, for the user.
  final String message;

  /// The pairing's failure, when [code] is `pairing`.
  final String? failure;

  @override
  String toString() => 'TomSecretsPairingModeException($code): $message';
}

/// A conversation with the service in its pairing mode.
final class TomSecretsServicePairing {
  TomSecretsServicePairing._(this._process, this._lines);

  /// Starts [executable] (with [arguments]) and hands it [handover].
  static Future<TomSecretsServicePairing> start({
    required String executable,
    List<String> arguments = const [],
    required TomSecretsPairingHandover handover,
    Map<String, String>? environment,
  }) async {
    final process = await Process.start(
      executable,
      arguments,
      environment: environment,
    );
    unawaited(process.stderr.drain<void>());
    process.stdin.writeln(handover.toLine());
    await process.stdin.flush();
    return TomSecretsServicePairing._(
      process,
      StreamIterator(
        process.stdout.transform(utf8.decoder).transform(const LineSplitter()),
      ),
    );
  }

  final Process _process;
  final StreamIterator<String> _lines;

  Future<Map<String, Object?>> _answer(String expected) async {
    if (!await _lines.moveNext()) {
      throw const TomSecretsPairingModeException(
        'ended',
        'the service ended without an answer',
      );
    }
    final json = jsonDecode(_lines.current);
    if (json is! Map) {
      throw const TomSecretsPairingModeException('ended', 'not an answer');
    }
    final m = json.cast<String, Object?>();
    if (m['status'] == expected) return m;
    throw TomSecretsPairingModeException(
      '${m['code'] ?? 'error'}',
      '${m['message'] ?? ''}',
      failure: m['failure'] as String?,
    );
  }

  /// Waits for the pairing: what it gave. Throws
  /// [TomSecretsPairingModeException] (the service has ended then).
  Future<TomSecretsPairingReport> received() async =>
      TomSecretsPairingReport.fromJson(await _answer('received'));

  /// Sets the machine up with [password]: the bootstrap file written.
  /// Throws [TomSecretsPairingModeException]; after
  /// [tomSecretsPairingWrongPassword] another password may be sent.
  Future<String> setUp(String password) async {
    _process.stdin.writeln(jsonEncode({'password': password}));
    await _process.stdin.flush();
    return (await _answer('setUp'))['bootstrap']! as String;
  }

  /// Ends the conversation; the service ends too. Its exit code.
  Future<int> close() async {
    try {
      await _process.stdin.close();
    } on Object {
      // Already closed by the service.
    }
    await _lines.cancel();
    return _process.exitCode;
  }
}
