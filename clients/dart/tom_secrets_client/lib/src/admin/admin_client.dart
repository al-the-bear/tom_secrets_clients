// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The admin side of the admin endpoint (protocol.md 6), for the manager app
/// and `tsm`: the mutual challenge (the service's `mac2` is checked before
/// anything secret is sent), or `claim` with the master password; then
/// requests by id and the event stream. A request or an answer over its
/// frame limit (a vault file in `save`, `vaultFileData`) travels with its
/// large members as chunks (protocol.md 2.7) when the service offers it.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../../tom_secrets_client.dart';

import 'admin_auth.dart';
import 'chunked.dart';
import 'runtime.dart';
import 'service_identity.dart';
import 'service_trust.dart';
import 'unlock_bundle.dart';

/// The admin endpoint refused or broke the conversation.
final class TomSecretsAdminException implements Exception {
  /// A failure of [kind] (an error kind, or `closed`) with [message].
  TomSecretsAdminException(this.kind, this.message, {this.details = const {}});

  /// The error kind (`denied`, `locked`, ...) or `closed`, `not_running`,
  /// `service_impostor`, `service_untrusted` (the endpoint is not this
  /// user's service: `details.reason` `owner`, `mode`, `peer_user` or
  /// `peer_executable`; nothing was sent).
  final String kind;

  /// What happened.
  final String message;

  /// The error's details.
  final Map<String, Object?> details;

  @override
  String toString() => 'TomSecretsAdminException($kind): $message';
}

/// An authenticated admin connection.
final class TomSecretsAdminClient {
  TomSecretsAdminClient._(this._socket);

  /// Connects to the admin endpoint of [runtime] and proves both sides hold
  /// [adminKey]; throws `service_impostor` when the service's `mac2` is
  /// wrong, `denied` when the service refuses the key, and
  /// `service_untrusted` (before anything is sent) when [trust] finds the
  /// endpoint is not this user's service.
  static Future<TomSecretsAdminClient> connect(
    TomSecretsRuntime runtime,
    List<int> adminKey, {
    Map<String, Object?> client = const {'name': 'tsm'},
    TomSecretsServiceTrust trust = const TomSecretsServiceTrust(),
  }) async {
    final admin = await _open(runtime, trust);
    final challenge = await admin._next();
    admin._takeFeatures(challenge);
    // Who it is, by its pinned key, before the proof of the admin key.
    await admin._identify(challenge, runtime, trust);
    final serviceNonce = base64.decode(challenge['serviceNonce']! as String);
    final start = challenge['serviceStart']! as int;
    final adminNonce = tomSecretsRandomBytes();
    admin._send({
      'op': 'auth',
      'adminNonce': base64.encode(adminNonce),
      'mac': base64.encode(
        tomSecretsChallengeMac(
          adminKey,
          tomSecretsAdminLabel,
          serviceNonce,
          adminNonce,
          start,
        ),
      ),
      'client': client,
      'features': _features,
    });
    final answer = await admin._next();
    admin._throwIfError(answer);
    final expected = tomSecretsChallengeMac(
      adminKey,
      tomSecretsServiceLabel,
      serviceNonce,
      adminNonce,
      start,
    );
    final mac2 = base64.decode(answer['mac2'] as String? ?? '');
    if (answer['op'] != 'authed' ||
        !tomSecretsConstantTimeEquals(mac2, expected)) {
      await admin.close();
      throw TomSecretsAdminException(
        'service_impostor',
        'the service could not prove it holds the admin key',
      );
    }
    admin
      .._serviceStart = start
      .._bundleKey = tomSecretsBundleKey(adminKey, serviceNonce, adminNonce)
      .._listen();
    return admin;
  }

  /// Takes the service over with the master password (`claim`). The claim
  /// is sent only to an endpoint that is this user's service
  /// (`service_untrusted` otherwise) and whose identity key is the one
  /// pinned (`service_key_changed` otherwise), and the password is sealed
  /// to the one-time key that service signed (protocol.md 6.2): nothing
  /// else reads it. Answers the connection and the new admin key.
  static Future<(TomSecretsAdminClient, Uint8List)> claim(
    TomSecretsRuntime runtime, {
    required String password,
    List<int>? keyFile,
    Map<String, Object?> client = const {'name': 'tsm'},
    TomSecretsServiceTrust trust = const TomSecretsServiceTrust(),
  }) async {
    final admin = await _open(runtime, trust);
    // The challenge, unanswerable without the key; its features count.
    final challenge = await admin._next();
    admin._takeFeatures(challenge);
    final identity = await admin._identify(challenge, runtime, trust);
    final crypto = trust.identityTrust!.crypto;
    final sealed = await crypto.encapsulate(identity.oneTimeKey);
    try {
      admin._send({
        'op': 'claim',
        'sealed': await tomSecretsSealClaim(
          sharedSecret: sealed.sharedSecret,
          kemCiphertext: sealed.ciphertext,
          transcript: identity.transcript,
          password: password,
          keyFile: keyFile,
        ),
        'client': client,
        'features': _features,
      });
    } finally {
      sealed.sharedSecret.fillRange(0, sealed.sharedSecret.length, 0);
    }
    final answer = await admin._next();
    admin._throwIfError(answer);
    admin._listen();
    return (admin, base64.decode(answer['adminKey']! as String));
  }

  static Never _untrusted(TomSecretsUntrusted why) =>
      throw TomSecretsAdminException(
        tomSecretsServiceUntrusted,
        'the admin endpoint is not this user\'s service: ${why.message}',
        details: {'reason': why.reason.wireName},
      );

  /// Checks that the admin endpoint of [runtime] is this user's service
  /// and that its identity key is the one pinned ([trust]); sends nothing
  /// secret: what an admin does before it asks the user for the master
  /// password of a `claim`. Answers the service's identity. Throws
  /// `not_running`, `service_untrusted` or `service_key_changed`.
  static Future<TomSecretsServiceIdentity> checkService(
    TomSecretsRuntime runtime, {
    TomSecretsServiceTrust trust = const TomSecretsServiceTrust(),
  }) async {
    final admin = await _open(runtime, trust);
    try {
      final challenge = await admin._next();
      return await admin._identify(challenge, runtime, trust);
    } finally {
      await admin.close();
    }
  }

  /// The identity the service on [runtime] presents, its signature
  /// checked, whatever is pinned: what `tsm trust` compares with the words
  /// the user gives. The endpoint's files and process are checked as
  /// always ([trust]). Throws `not_running` or `service_untrusted`.
  static Future<TomSecretsServiceIdentity> presentedIdentity(
    TomSecretsRuntime runtime, {
    TomSecretsServiceTrust trust = const TomSecretsServiceTrust(),
  }) async {
    final admin = await _open(runtime, trust);
    try {
      final challenge = await admin._next();
      return await admin._identify(challenge, runtime, trust, judge: false);
    } finally {
      await admin.close();
    }
  }

  /// The service's identity as this connection checked it.
  TomSecretsServiceIdentity? get identity => _identity;
  TomSecretsServiceIdentity? _identity;

  /// The identity exchange (protocol.md 6.1): the service signs this
  /// admin's nonce, its own nonce and start, and a one-time key; the
  /// signature is checked, and with [judge] the key against the pins.
  Future<TomSecretsServiceIdentity> _identify(
    Map<String, Object?> challenge,
    TomSecretsRuntime runtime,
    TomSecretsServiceTrust trust, {
    bool judge = true,
  }) async {
    Never untrusted(String reason, String message, [Map<String, Object?>? d]) {
      unawaited(close());
      throw TomSecretsAdminException(
        tomSecretsServiceUntrusted,
        message,
        details: {'reason': reason, ...?d},
      );
    }

    final identityTrust = trust.identityTrust;
    if (identityTrust == null) {
      untrusted(
        'unpinned',
        'this program has no means to check the service\'s identity key',
      );
    }
    final features = challenge['features'];
    if (features is! List || !features.contains(tomSecretsIdentityFeature)) {
      untrusted(
        'no_identity',
        'the service has no identity key (it is older than this program)',
      );
    }
    final clientNonce = tomSecretsRandomBytes();
    _send({'op': 'identify', 'clientNonce': base64.encode(clientNonce)});
    final answer = await _next();
    _throwIfError(answer);
    final Uint8List publicKey, oneTimeKey, signature;
    final changes = <TomSecretsIdentityChange>[];
    try {
      publicKey = base64.decode(answer['publicKey']! as String);
      oneTimeKey = base64.decode(answer['oneTimeKey']! as String);
      signature = base64.decode(answer['signature']! as String);
      for (final c in answer['changes'] as List? ?? const []) {
        final change = TomSecretsIdentityChange.fromJson(c);
        if (change != null) changes.add(change);
      }
    } on Object {
      untrusted('peer_user', 'the service\'s identity cannot be read');
    }
    final transcript = tomSecretsIdentityMessage(
      clientNonce: clientNonce,
      serviceNonce: base64.decode(challenge['serviceNonce']! as String),
      serviceStart: challenge['serviceStart']! as int,
      oneTimeKey: oneTimeKey,
    );
    final crypto = identityTrust.crypto;
    if (publicKey.length != tomSecretsIdentityKeyLength ||
        oneTimeKey.length != tomSecretsOneTimeKeyLength ||
        !await crypto.verify(
          publicKey: publicKey,
          message: transcript,
          signature: signature,
          context: tomSecretsIdentityContext,
        )) {
      await close();
      throw TomSecretsAdminException(
        'service_impostor',
        'the service could not prove it holds its identity key',
      );
    }
    final presented = TomSecretsServiceIdentity(
      publicKey: publicKey,
      oneTimeKey: oneTimeKey,
      transcript: transcript,
    );
    _identity = presented;
    if (!judge) return presented;
    final pins = identityTrust.pins;
    final pinned = await tomSecretsPinsFor(
      pins,
      identityTrust.host,
      runtime.directory,
    );
    final verdict = await tomSecretsJudgeIdentity(
      pinned: pinned,
      presented: publicKey,
      changes: changes,
      crypto: crypto,
    );
    final words = presented.words;
    switch (verdict) {
      case TomSecretsPinVerdict.pinned:
        break;
      case TomSecretsPinVerdict.rotated:
        // The pinned key signed its way to this one: it takes its place.
        await pins.pin(
          identityTrust.host,
          pinned.first.runtime,
          publicKey,
          TomSecretsPinSource.rotation,
        );
      case TomSecretsPinVerdict.unpinned:
        if (identityTrust.pinOnFirstUse) {
          await pins.pin(
            identityTrust.host,
            runtime.directory,
            publicKey,
            TomSecretsPinSource.trust,
          );
          break;
        }
        untrusted(
          'unpinned',
          'this service is not known here yet; its identity is: $words',
          {
            'words': words,
            'fingerprint': tomSecretsIdentityFingerprint(publicKey),
            'key': base64.encode(publicKey),
          },
        );
      case TomSecretsPinVerdict.changed:
        await close();
        throw TomSecretsAdminException(
          tomSecretsServiceKeyChanged,
          'the service\'s identity key changed: pinned '
          '${pinned.first.words}, presented $words',
          details: {'pinned': pinned.first.words, 'presented': words},
        );
    }
    return presented;
  }

  static Future<TomSecretsAdminClient> _open(
    TomSecretsRuntime runtime,
    TomSecretsServiceTrust trust,
  ) async {
    final socket = await _connectChecked(runtime, trust);
    final admin = TomSecretsAdminClient._(socket);
    admin._subscription = socket.listen(
      admin._data,
      onDone: admin._done,
      onError: (Object _) => admin._done(),
    );
    return admin;
  }

  /// A connection to the admin endpoint of [runtime] that passed [trust];
  /// nothing was sent on it.
  static Future<Socket> _connectChecked(
    TomSecretsRuntime runtime,
    TomSecretsServiceTrust trust,
  ) async {
    // Nothing is running where there is no endpoint: said before the files
    // are judged, so a stopped service reads as stopped.
    final endpoint = runtime.transport == TomSecretsTransport.unix
        ? runtime.adminSocket
        : runtime.adminPortFile;
    if (await FileSystemEntity.type(endpoint, followLinks: false) ==
        FileSystemEntityType.notFound) {
      throw TomSecretsAdminException('not_running', 'no service answers');
    }
    // The files first: a directory or socket of someone else is never
    // connected to.
    final files = trust.inspector.files(runtime);
    final early = trust.judgeFiles(files);
    if (early != null) _untrusted(early);
    final Socket socket;
    try {
      socket = runtime.transport == TomSecretsTransport.unix
          ? await Socket.connect(
              InternetAddress(
                runtime.adminSocket,
                type: InternetAddressType.unix,
              ),
              0,
            )
          : await Socket.connect(
              InternetAddress.loopbackIPv4,
              readTomSecretsPortFile(
                    await File(runtime.adminPortFile).readAsString(),
                  ) ??
                  0,
            );
    } on Object {
      throw TomSecretsAdminException('not_running', 'no service answers');
    }
    // Then who answers, before a byte is sent.
    final why = trust.judgePeer(trust.inspector.withPeer(files, socket));
    if (why != null) {
      socket.destroy();
      _untrusted(why);
    }
    return socket;
  }

  final Socket _socket;

  /// The features this client offers the service.
  static const List<String> _features = [tomSecretsChunkedFeature];

  /// Whether the service offered chunked members (protocol.md 2.7): then
  /// a request over the request limit is sent chunked.
  bool get sendsChunked => _sendsChunked;
  bool _sendsChunked = false;

  void _takeFeatures(Map<String, Object?> challenge) {
    final features = challenge['features'];
    _sendsChunked =
        features is List && features.contains(tomSecretsChunkedFeature);
  }

  final TomSecretsChunkAssembler _chunks = TomSecretsChunkAssembler();

  /// The service's start time (from the challenge; 0 on a connection that
  /// claimed the service).
  int get serviceStart => _serviceStart;
  int _serviceStart = 0;

  /// The bundle key of this connection (protocol.md 6.4), or null on a
  /// connection that claimed the service.
  Uint8List? _bundleKey;

  late final StreamSubscription<List<int>> _subscription;
  // Binary frames are chunks of an answer (protocol.md 2.7).
  final TomSecretsFrameReader _reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxAnswerPayload,
  )..binaryAllowed = true;
  final Queue<Map<String, Object?>> _queue = Queue();
  final List<Completer<Map<String, Object?>>> _waiting = [];
  final Map<int, Completer<Map<String, Object?>>> _pending = {};
  final StreamController<Map<String, Object?>> _events =
      StreamController.broadcast();
  bool _routing = false;
  bool _closed = false;
  int _nextId = 1;

  /// The pushed events (after `subscribe`).
  Stream<Map<String, Object?>> get events => _events.stream;

  /// Whether the connection has ended.
  bool get isClosed => _closed;

  void _data(List<int> bytes) {
    final List<TomSecretsFrame> frames;
    try {
      frames = _reader.add(bytes);
    } on TomSecretsFrameException {
      unawaited(close());
      return;
    }
    for (final frame in frames) {
      Map<String, Object?>? message;
      try {
        if (frame.type == tomSecretsFrameBinary) {
          message = _chunks.add(frame.payload);
        } else {
          message = tomSecretsDecodePayload(frame.payload);
          if (TomSecretsChunkAssembler.isChunked(message)) {
            message = _chunks.begin(message);
          }
        }
      } on TomSecretsFrameException {
        // A chunk that does not belong, or a member that does not match.
        unawaited(close());
        return;
      }
      if (message == null) continue; // more chunks to come
      if (_routing) {
        _route(message);
      } else if (_waiting.isNotEmpty) {
        _waiting.removeAt(0).complete(message);
      } else {
        _queue.add(message);
      }
    }
  }

  void _done() {
    _closed = true;
    _chunks.clear();
    final error = TomSecretsAdminException('closed', 'the connection ended');
    for (final w in _waiting) {
      w.completeError(error);
    }
    _waiting.clear();
    for (final p in _pending.values) {
      p.completeError(error);
    }
    _pending.clear();
    unawaited(_events.close());
  }

  Future<Map<String, Object?>> _next() {
    if (_queue.isNotEmpty) return Future.value(_queue.removeFirst());
    if (_closed) {
      return Future.error(
        TomSecretsAdminException('closed', 'the connection ended'),
      );
    }
    final c = Completer<Map<String, Object?>>();
    _waiting.add(c);
    return c.future;
  }

  void _listen() {
    _routing = true;
    while (_queue.isNotEmpty) {
      _route(_queue.removeFirst());
    }
  }

  void _route(Map<String, Object?> message) {
    final id = message['id'];
    final pending = id is int ? _pending.remove(id) : null;
    if (pending != null) {
      pending.complete(message);
    } else if (!_events.isClosed) {
      _events.add(message);
    }
  }

  void _throwIfError(Map<String, Object?> answer) {
    if (answer['op'] == 'error') {
      throw TomSecretsAdminException(
        answer['kind'] as String? ?? 'internal',
        answer['message'] as String? ?? '',
        details:
            (answer['details'] as Map?)?.cast<String, Object?>() ?? const {},
      );
    }
  }

  /// The frames of [message] as this connection sends it: one JSON frame,
  /// or with chunked members (protocol.md 2.7) when the service offered
  /// them and it does not fit.
  List<Uint8List> _framesOf(Map<String, Object?> message) => _sendsChunked
      ? tomSecretsChunkedFrames(message, limit: tomSecretsMaxRequestPayload)
      : [tomSecretsJsonFrame(message)];

  // What is being written, in order: a chunked message is flushed as it
  // goes, and the socket takes nothing more while a flush is pending.
  Future<void> _sending = Future<void>.value();

  /// How many bytes are written between two flushes (and two progress
  /// reports) of a chunked message.
  static const int _progressStep = 256 * 1024;

  void _send(
    Map<String, Object?> message, {
    void Function(int sent, int total)? onProgress,
  }) {
    final frames = _framesOf(message);
    _sending = _sending.then((_) => _write(frames, onProgress));
  }

  Future<void> _write(
    List<Uint8List> frames,
    void Function(int sent, int total)? onProgress,
  ) async {
    if (_closed) return;
    try {
      if (frames.length == 1) {
        _socket.add(frames.single);
        return;
      }
      final total = frames.fold<int>(0, (n, f) => n + f.length);
      var sent = 0;
      var unflushed = 0;
      for (final frame in frames) {
        _socket.add(frame);
        sent += frame.length;
        unflushed += frame.length;
        if (unflushed >= _progressStep || sent == total) {
          // Handed to the OS: the progress is what has left this process.
          await _socket.flush();
          unflushed = 0;
          onProgress?.call(sent, total);
          if (_closed) return;
        }
      }
    } on Object {
      // The connection ended meanwhile: its requests fail as `closed`.
    }
  }

  /// Sends the admin request [op] with [fields]; answers the answer, or
  /// throws [TomSecretsAdminException] for an `error`.
  ///
  /// A request that goes in chunks (a large vault's `save`) reports
  /// [onProgress] as it is written: the bytes handed to the OS so far and
  /// the bytes in all, about every 256 KiB and at the end. A request that
  /// fits one frame reports nothing.
  Future<Map<String, Object?>> request(
    String op, [
    Map<String, Object?> fields = const {},
    void Function(int sent, int total)? onProgress,
  ]) async {
    // A connection that ended answers nothing more: waiting would never end.
    if (_closed) {
      throw TomSecretsAdminException('closed', 'the connection ended');
    }
    final id = _nextId++;
    final c = Completer<Map<String, Object?>>();
    _pending[id] = c;
    try {
      _send({...fields, 'op': op, 'id': id}, onProgress: onProgress);
    } on TomSecretsFrameException catch (e) {
      _pending.remove(id);
      throw TomSecretsAdminException(
        'malformed',
        'the request does not fit: ${e.message}',
        details: const {'reason': 'frame'},
      );
    }
    final answer = await c.future;
    _throwIfError(answer);
    return answer;
  }

  /// Unlocks with the master password (and key file).
  Future<void> unlock(String password, {List<int>? keyFile}) =>
      request('unlock', {
        'password': password,
        'keyFile': ?(keyFile == null ? null : base64.encode(keyFile)),
      });

  /// Unlocks [vault] (a store's name as `status` lists it: the primary
  /// unlocks the service, another store a locked store of an unlocked
  /// service) with [bundle], the key material the OS unlock read (protocol.md
  /// 6.4): sealed under this connection's bundle key. A bundle that no
  /// longer opens the vault (re-keyed) answers `denied` reason
  /// `bad_password`; one the service cannot open, `bad_bundle`.
  Future<void> unlockWithBundle(
    String vault,
    TomSecretsUnlockBundle bundle,
  ) async {
    final key = _bundleKey;
    if (key == null) {
      throw TomSecretsAdminException(
        'unsupported',
        'a connection that claimed the service cannot send a key bundle',
      );
    }
    final plaintext = bundle.encode();
    final Map<String, String> sealed;
    try {
      sealed = await tomSecretsSealBundle(
        bundleKey: key,
        vault: vault,
        serviceStart: serviceStart,
        plaintext: plaintext,
      );
    } finally {
      plaintext.fillRange(0, plaintext.length, 0);
    }
    await request('unlock', {'vault': vault, 'bundle': sealed});
  }

  /// Ends the connection.
  Future<void> close() async {
    _bundleKey?.fillRange(0, _bundleKey!.length, 0);
    await _subscription.cancel();
    _socket.destroy();
    if (!_closed) _done();
  }
}
