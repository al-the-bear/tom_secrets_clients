// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's identity key as an admin sees it (protocol.md 6.1): every
/// service has a signing key pair of its own (ML-DSA-65 with Ed25519, one
/// composite signature), and an admin pins its public key as SSH pins a
/// host key. Before an `auth` or a `claim` the service signs the admin's
/// fresh nonce, its own nonce and start time, and a one-time public key
/// (ML-KEM-768 with X25519); the admin checks the signature against the key
/// it pinned and seals the master password of a claim to the one-time key,
/// so only that service process reads it.
///
/// This library holds what needs no post-quantum code: the bytes that are
/// signed, the fingerprint and its words, the pins and their file, the
/// sealing of a claim, and the decision. The two primitives it needs,
/// verifying a signature and encapsulating to the one-time key, are behind
/// [TomSecretsIdentityCrypto]: the manager app runs them in its own process,
/// `tsm` asks the service executable beside it ([TomSecretsIdentityHelper]).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import 'identity_words.dart';

/// The admin feature of the service's identity (`challenge.features`).
const String tomSecretsIdentityFeature = 'identity';

/// The admin error kind of a service whose identity key is not the one
/// pinned, and no statement of the pinned key leads to it: nothing was
/// sent, and nothing is, until the user removes the pin.
const String tomSecretsServiceKeyChanged = 'service_key_changed';

/// The length of the nonces of the identity exchange.
const int tomSecretsIdentityNonceLength = 32;

/// The length of a service's public identity key (ML-DSA-65's public key,
/// then Ed25519's).
const int tomSecretsIdentityKeyLength = 1952 + 32;

/// The length of the one-time public key (ML-KEM-768's encapsulation key,
/// then X25519's public key).
const int tomSecretsOneTimeKeyLength = 1216;

/// The two post-quantum primitives of the identity exchange.
abstract interface class TomSecretsIdentityCrypto {
  /// Whether [signature] is the composite signature (ML-DSA-65 with
  /// Ed25519) of [message] under [publicKey] with the [context].
  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List context,
  });

  /// A shared secret (32 bytes) and its ciphertext for the one-time
  /// [publicKey] (ML-KEM-768 with X25519).
  Future<({Uint8List ciphertext, Uint8List sharedSecret})> encapsulate(
    Uint8List publicKey,
  );
}

/// The context of the signature over the identity exchange.
final Uint8List tomSecretsIdentityContext = Uint8List.fromList(
  ascii.encode('tsm-identity-v1'),
);

/// The context of a key-change statement.
final Uint8List tomSecretsIdentityChangeContext = Uint8List.fromList(
  ascii.encode('tsm-identity-change-v1'),
);

/// What the service signs in the identity exchange: the admin's nonce, its
/// own nonce (32 bytes each), its start time (8 bytes, unsigned,
/// big-endian) and the one-time public key.
Uint8List tomSecretsIdentityMessage({
  required List<int> clientNonce,
  required List<int> serviceNonce,
  required int serviceStart,
  required List<int> oneTimeKey,
}) {
  if (clientNonce.length != tomSecretsIdentityNonceLength ||
      serviceNonce.length != tomSecretsIdentityNonceLength) {
    throw ArgumentError('the nonces are 32 bytes');
  }
  final start = ByteData(8)..setUint64(0, serviceStart);
  return Uint8List.fromList([
    ...clientNonce,
    ...serviceNonce,
    ...start.buffer.asUint8List(),
    ...oneTimeKey,
  ]);
}

/// The fingerprint of a public identity key: its SHA-256, lower-case hex.
String tomSecretsIdentityFingerprint(List<int> publicKey) =>
    crypto.sha256.convert(publicKey).toString();

/// The fingerprint of [publicKey] as words people compare: eight words of
/// [tomSecretsIdentityWordList], one per byte of the fingerprint's first
/// eight, joined by hyphens.
String tomSecretsIdentityWords(List<int> publicKey) => [
  for (final b in crypto.sha256.convert(publicKey).bytes.take(8))
    tomSecretsIdentityWordList[b],
].join('-');

/// Whether [given] (the words, separated by hyphens or spaces, in any case;
/// or the whole fingerprint in hex) names [publicKey].
bool tomSecretsIdentityNamedBy(String given, List<int> publicKey) {
  final text = given.trim().toLowerCase();
  if (RegExp(r'^[0-9a-f]{64}$').hasMatch(text)) {
    return text == tomSecretsIdentityFingerprint(publicKey);
  }
  final words = text.split(RegExp(r'[\s-]+')).where((w) => w.isNotEmpty);
  return words.join('-') == tomSecretsIdentityWords(publicKey);
}

/// A statement of a service that replaced its identity key: the key
/// [from] signed the key [to] (context
/// [tomSecretsIdentityChangeContext]).
final class TomSecretsIdentityChange {
  /// [from] signed [to] with [signature].
  const TomSecretsIdentityChange({
    required this.from,
    required this.to,
    required this.signature,
  });

  /// From the wire; null when it cannot be read.
  static TomSecretsIdentityChange? fromJson(Object? json) {
    if (json is! Map) return null;
    try {
      return TomSecretsIdentityChange(
        from: base64.decode(json['from'] as String),
        to: base64.decode(json['to'] as String),
        signature: base64.decode(json['signature'] as String),
      );
    } on Object {
      return null;
    }
  }

  /// The key that signed.
  final Uint8List from;

  /// The key it was replaced by.
  final Uint8List to;

  /// The signature of [to] by [from].
  final Uint8List signature;

  /// For the wire and the service's file.
  Map<String, Object?> toJson() => {
    'from': base64.encode(from),
    'to': base64.encode(to),
    'signature': base64.encode(signature),
  };
}

/// How a pin came to be.
enum TomSecretsPinSource {
  /// The process this admin started said it on its standard output.
  start('start'),

  /// A pairing, or a device record of the primary.
  pairing('pairing'),

  /// The user compared the words, or gave the key (`tsm trust`).
  trust('trust'),

  /// The pinned key signed the one that replaced it.
  rotation('rotation');

  const TomSecretsPinSource(this.wireName);

  /// As the pin file writes it.
  final String wireName;
}

/// One pinned service: the [host] and runtime directory it answers on, and
/// its public identity [key].
final class TomSecretsServicePin {
  /// A pin of [key] for [host] and [runtime].
  TomSecretsServicePin({
    required this.host,
    required this.runtime,
    required this.key,
    required this.source,
    required this.at,
  });

  /// The machine's name.
  final String host;

  /// The runtime directory, or null: the service of [host] wherever it
  /// answers (a pin from a device record).
  final String? runtime;

  /// The public identity key.
  final Uint8List key;

  /// How it came to be.
  final TomSecretsPinSource source;

  /// When it was pinned.
  final DateTime at;

  /// The key's words.
  String get words => tomSecretsIdentityWords(key);

  Map<String, Object?> _toJson() => {
    'host': host,
    'runtime': ?runtime,
    'key': base64.encode(key),
    'source': source.wireName,
    'at': at.toUtc().toIso8601String(),
  };

  static TomSecretsServicePin? _fromJson(Object? json) {
    if (json is! Map || json['host'] is! String || json['key'] is! String) {
      return null;
    }
    try {
      return TomSecretsServicePin(
        host: json['host'] as String,
        runtime: json['runtime'] as String?,
        key: base64.decode(json['key'] as String),
        source: TomSecretsPinSource.values.firstWhere(
          (s) => s.wireName == json['source'],
          orElse: () => TomSecretsPinSource.trust,
        ),
        at:
            DateTime.tryParse('${json['at']}') ??
            DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      );
    } on FormatException {
      return null;
    }
  }
}

bool _sameKey(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// The services an admin pinned.
abstract interface class TomSecretsServicePins {
  /// Every pin.
  Future<List<TomSecretsServicePin>> all();

  /// Pins [key] for [host] and [runtime] (null: wherever the host's
  /// service answers), in place of what was pinned for the two.
  Future<void> pin(
    String host,
    String? runtime,
    List<int> key,
    TomSecretsPinSource source,
  );

  /// Removes the pins of [host] and [runtime] (null: every pin of the
  /// host); answers how many.
  Future<int> remove(String host, String? runtime);
}

/// The pins of [pins] that hold for the service of [host] answering in
/// [runtime]: those of the runtime directory itself, else those of the
/// host wherever it answers.
Future<List<TomSecretsServicePin>> tomSecretsPinsFor(
  TomSecretsServicePins pins,
  String host,
  String runtime,
) async {
  final ofHost = [
    for (final p in await pins.all())
      if (p.host == host) p,
  ];
  final exact = [
    for (final p in ofHost)
      if (p.runtime == runtime) p,
  ];
  return exact.isNotEmpty
      ? exact
      : [
          for (final p in ofHost)
            if (p.runtime == null) p,
        ];
}

/// Pins the service keys the primary's device records name ([devices],
/// the `devices` of `pair.list`): each device's key as the pin of that
/// host wherever its service answers, in place of an older one. A revoked
/// device's pin of that kind is removed. Answers how many pins changed.
Future<int> tomSecretsPinDevices(
  TomSecretsServicePins pins,
  Iterable<Object?> devices,
) async {
  var changed = 0;
  for (final d in devices) {
    if (d is! Map) continue;
    final device = d['device'];
    final key = d['serviceKey'];
    if (device is! String || device.isEmpty) continue;
    final held = [
      for (final p in await pins.all())
        if (p.host == device && p.runtime == null) p,
    ];
    if (d['revoked'] != null || key is! String) {
      if (d['revoked'] != null && held.isNotEmpty) {
        final others = [
          for (final p in await pins.all())
            if (p.host == device && p.runtime != null) p,
        ];
        await pins.remove(device, null);
        for (final p in others) {
          await pins.pin(p.host, p.runtime, p.key, p.source);
        }
        changed++;
      }
      continue;
    }
    final Uint8List bytes;
    try {
      bytes = base64.decode(key);
    } on FormatException {
      continue;
    }
    if (bytes.length != tomSecretsIdentityKeyLength) continue;
    if (held.any((p) => _sameKey(p.key, bytes))) continue;
    await pins.pin(device, null, bytes, TomSecretsPinSource.pairing);
    changed++;
  }
  return changed;
}

/// Pins kept in memory (a test, or one invocation).
final class TomSecretsMemoryPins implements TomSecretsServicePins {
  final List<TomSecretsServicePin> _pins = [];

  @override
  Future<List<TomSecretsServicePin>> all() async => List.of(_pins);

  @override
  Future<void> pin(
    String host,
    String? runtime,
    List<int> key,
    TomSecretsPinSource source,
  ) async {
    _pins
      ..removeWhere((p) => p.host == host && p.runtime == runtime)
      ..add(
        TomSecretsServicePin(
          host: host,
          runtime: runtime,
          key: Uint8List.fromList(key),
          source: source,
          at: DateTime.now().toUtc(),
        ),
      );
  }

  @override
  Future<int> remove(String host, String? runtime) async {
    final before = _pins.length;
    _pins.removeWhere(
      (p) => p.host == host && (runtime == null || p.runtime == runtime),
    );
    return before - _pins.length;
  }
}

/// The pin file the app and `tsm` share: `services` in the product's
/// configuration directory ([tomSecretsPinFile]), JSON, the user's alone.
final class TomSecretsPinFile implements TomSecretsServicePins {
  /// The pins in [file].
  TomSecretsPinFile(this.file);

  /// The file.
  final File file;

  @override
  Future<List<TomSecretsServicePin>> all() async {
    if (!file.existsSync()) return [];
    final Object? json;
    try {
      json = jsonDecode(file.readAsStringSync());
    } on FormatException {
      throw FileSystemException('the pin file cannot be read', file.path);
    }
    final services = json is Map ? json['services'] : null;
    return [
      if (services is List)
        for (final s in services) ?TomSecretsServicePin._fromJson(s),
    ];
  }

  Future<void> _write(List<TomSecretsServicePin> pins) async {
    final dir = file.parent;
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
      if (!Platform.isWindows) Process.runSync('chmod', ['700', dir.path]);
    }
    final temp = File('${file.path}.tmp');
    temp.writeAsStringSync(
      '${const JsonEncoder.withIndent('  ').convert({
        'version': 1,
        'services': [for (final p in pins) p._toJson()],
      })}\n',
      flush: true,
    );
    if (!Platform.isWindows) Process.runSync('chmod', ['600', temp.path]);
    temp.renameSync(file.path);
  }

  @override
  Future<void> pin(
    String host,
    String? runtime,
    List<int> key,
    TomSecretsPinSource source,
  ) async {
    final pins = await all()
      ..removeWhere((p) => p.host == host && p.runtime == runtime)
      ..add(
        TomSecretsServicePin(
          host: host,
          runtime: runtime,
          key: Uint8List.fromList(key),
          source: source,
          at: DateTime.now().toUtc(),
        ),
      );
    await _write(pins);
  }

  @override
  Future<int> remove(String host, String? runtime) async {
    final pins = await all();
    final before = pins.length;
    pins.removeWhere(
      (p) => p.host == host && (runtime == null || p.runtime == runtime),
    );
    if (pins.length != before) await _write(pins);
    return before - pins.length;
  }
}

/// Where the pin file is: `$TSM_CONFIG_DIR/services` when that is set
/// (tests, containers); on Windows `%APPDATA%\tsm\services`; else
/// `$XDG_CONFIG_HOME/tsm/services`, or `~/.config/tsm/services`.
String tomSecretsPinFile({
  Map<String, String>? environment,
  String? operatingSystem,
}) {
  final env = environment ?? Platform.environment;
  final windows = (operatingSystem ?? Platform.operatingSystem) == 'windows';
  final sep = windows ? r'\' : '/';
  final named = env['TSM_CONFIG_DIR'] ?? '';
  if (named.isNotEmpty) return '$named${sep}services';
  if (windows) {
    final base =
        env['APPDATA'] ?? '${env['USERPROFILE'] ?? ''}\\AppData\\Roaming';
    return '$base\\tsm\\services';
  }
  final xdg = env['XDG_CONFIG_HOME'] ?? '';
  final base = xdg.startsWith('/') ? xdg : '${env['HOME'] ?? ''}/.config';
  return '$base/tsm/services';
}

/// What an admin checks a service's identity with.
final class TomSecretsIdentityTrust {
  /// The pins in [pins], checked with [crypto], for the service of [host]
  /// (default: this machine's name).
  TomSecretsIdentityTrust({
    required this.pins,
    required this.crypto,
    String? host,
    this.pinOnFirstUse = false,
  }) : host = host ?? Platform.localHostname;

  /// The pins.
  final TomSecretsServicePins pins;

  /// The primitives.
  final TomSecretsIdentityCrypto crypto;

  /// The machine whose service is asked.
  final String host;

  /// Whether a service that is not pinned yet is pinned as it presents
  /// itself, without anyone comparing: only for a caller that knows by
  /// other means whom it talks to (a test with its own service; never the
  /// app or `tsm`).
  final bool pinOnFirstUse;
}

/// What the service presented in the identity exchange, once its signature
/// was checked.
final class TomSecretsServiceIdentity {
  /// The service's key and one-time key.
  const TomSecretsServiceIdentity({
    required this.publicKey,
    required this.oneTimeKey,
    required this.transcript,
  });

  /// Its public identity key.
  final Uint8List publicKey;

  /// Its one-time public key of this connection.
  final Uint8List oneTimeKey;

  /// The bytes it signed ([tomSecretsIdentityMessage]).
  final Uint8List transcript;

  /// The key's words.
  String get words => tomSecretsIdentityWords(publicKey);
}

/// How a presented key stands against the pins.
enum TomSecretsPinVerdict {
  /// It is the key pinned.
  pinned,

  /// The pinned key signed its way to it: pin it in the old one's place.
  rotated,

  /// Nothing is pinned for this service.
  unpinned,

  /// Another key is pinned, and no statement leads from it to this one.
  changed,
}

/// How [presented] stands against [pinned], [changes] being the service's
/// key-change statements: followed from a pinned key, each checked with
/// [crypto].
Future<TomSecretsPinVerdict> tomSecretsJudgeIdentity({
  required List<TomSecretsServicePin> pinned,
  required Uint8List presented,
  required List<TomSecretsIdentityChange> changes,
  required TomSecretsIdentityCrypto crypto,
}) async {
  if (pinned.isEmpty) return TomSecretsPinVerdict.unpinned;
  for (final pin in pinned) {
    if (_sameKey(pin.key, presented)) return TomSecretsPinVerdict.pinned;
  }
  for (final pin in pinned) {
    var at = pin.key;
    // A chain is no longer than the statements there are.
    for (var step = 0; step < changes.length; step++) {
      final next = changes.where((c) => _sameKey(c.from, at)).firstOrNull;
      if (next == null) break;
      if (!await crypto.verify(
        publicKey: at,
        message: next.to,
        signature: next.signature,
        context: tomSecretsIdentityChangeContext,
      )) {
        break;
      }
      at = next.to;
      if (_sameKey(at, presented)) return TomSecretsPinVerdict.rotated;
    }
  }
  return TomSecretsPinVerdict.changed;
}

final AesGcm _aead = AesGcm.with256bits();

Future<SecretKey> _claimKey(List<int> sharedSecret, List<int> transcript) =>
    Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(sharedSecret),
      // Bound to this exchange: the nonces, the start and the one-time key.
      nonce: crypto.sha256.convert(transcript).bytes,
      info: ascii.encode('tsm-claim-v1'),
    );

/// A claim's secrets sealed for the service that holds the one-time key:
/// `{kem, nonce, ciphertext}` in base64. The key is HKDF-SHA-256 of the
/// [sharedSecret] of [kemCiphertext], salted with the SHA-256 of the
/// [transcript] the service signed, info `tsm-claim-v1`; the cipher is
/// AES-256-GCM over the JSON `{password, keyFile?}`.
Future<Map<String, Object?>> tomSecretsSealClaim({
  required List<int> sharedSecret,
  required List<int> kemCiphertext,
  required List<int> transcript,
  required String password,
  List<int>? keyFile,
}) async {
  final plain = utf8.encode(
    jsonEncode({
      'password': password,
      'keyFile': ?(keyFile == null ? null : base64.encode(keyFile)),
    }),
  );
  try {
    final box = await _aead.encrypt(
      plain,
      secretKey: await _claimKey(sharedSecret, transcript),
    );
    return {
      'kem': base64.encode(kemCiphertext),
      'nonce': base64.encode(box.nonce),
      'ciphertext': base64.encode([...box.cipherText, ...box.mac.bytes]),
    };
  } finally {
    plain.fillRange(0, plain.length, 0);
  }
}

/// The secrets of a sealed claim, opened with the [sharedSecret] the
/// service decapsulated from `sealed.kem`. Throws [FormatException] for a
/// claim that cannot be read or does not open.
Future<({String password, Uint8List? keyFile})> tomSecretsOpenClaim({
  required List<int> sharedSecret,
  required List<int> transcript,
  required Map<String, Object?> sealed,
}) async {
  try {
    final nonce = base64.decode(sealed['nonce'] as String);
    final bytes = base64.decode(sealed['ciphertext'] as String);
    if (bytes.length < 16) throw const FormatException('no tag');
    final plain = await _aead.decrypt(
      SecretBox(
        bytes.sublist(0, bytes.length - 16),
        nonce: nonce,
        mac: Mac(bytes.sublist(bytes.length - 16)),
      ),
      secretKey: await _claimKey(sharedSecret, transcript),
    );
    final json = jsonDecode(utf8.decode(plain)) as Map;
    plain.fillRange(0, plain.length, 0);
    final keyFile = json['keyFile'];
    return (
      password: json['password'] as String,
      keyFile: keyFile is String ? base64.decode(keyFile) : null,
    );
  } on Object {
    throw const FormatException('the sealed claim does not open');
  }
}

/// The marker the identity helper's handover line carries.
const String tomSecretsIdentityHelperHandover = 'identityHelper';

/// The primitives run by the service executable beside the admin
/// ([executable], started in its helper mode): one JSON line in, one out,
/// per call. `tsm` uses it, so that it links no post-quantum code itself.
/// The helper sees public keys, signatures and the shared secret of a
/// claim; never the master password.
final class TomSecretsIdentityHelper implements TomSecretsIdentityCrypto {
  /// The helper mode of [executable].
  TomSecretsIdentityHelper(this.executable, {this.environment});

  /// The service executable.
  final String executable;

  /// Its environment (default: this process's).
  final Map<String, String>? environment;

  Process? _process;
  StreamIterator<String>? _lines;

  Future<Map<String, Object?>> _ask(Map<String, Object?> request) async {
    var process = _process;
    if (process == null) {
      try {
        process = _process = await Process.start(
          executable,
          const [],
          environment: environment,
        );
      } on ProcessException {
        throw StateError('no service executable at $executable');
      }
      unawaited(process.stderr.drain<void>());
      _lines = StreamIterator(
        process.stdout.transform(utf8.decoder).transform(const LineSplitter()),
      );
      process.stdin.writeln(jsonEncode({tomSecretsIdentityHelperHandover: 1}));
    }
    process.stdin.writeln(jsonEncode(request));
    await process.stdin.flush();
    if (!await _lines!.moveNext()) {
      throw StateError('the identity helper ended without an answer');
    }
    final answer = jsonDecode(_lines!.current);
    if (answer is! Map || answer['error'] != null) {
      throw StateError('the identity helper refused: ${answer['error']}');
    }
    return answer.cast<String, Object?>();
  }

  @override
  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List context,
  }) async =>
      (await _ask({
        'op': 'verify',
        'publicKey': base64.encode(publicKey),
        'message': base64.encode(message),
        'signature': base64.encode(signature),
        'context': base64.encode(context),
      }))['valid'] ==
      true;

  @override
  Future<({Uint8List ciphertext, Uint8List sharedSecret})> encapsulate(
    Uint8List publicKey,
  ) async {
    final answer = await _ask({
      'op': 'encapsulate',
      'publicKey': base64.encode(publicKey),
    });
    return (
      ciphertext: base64.decode(answer['ciphertext']! as String),
      sharedSecret: base64.decode(answer['sharedSecret']! as String),
    );
  }

  /// Ends the helper process.
  Future<void> close() async {
    final process = _process;
    _process = null;
    if (process == null) return;
    await process.stdin.close();
    await _lines?.cancel();
    process.kill();
  }
}
