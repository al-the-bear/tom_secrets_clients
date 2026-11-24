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
import 'unlock_bundle.dart';

/// The admin endpoint refused or broke the conversation.
final class TomSecretsAdminException implements Exception {
  /// A failure of [kind] (an error kind, or `closed`) with [message].
  TomSecretsAdminException(this.kind, this.message, {this.details = const {}});

  /// The error kind (`denied`, `locked`, ...) or `closed`, `not_running`,
  /// `service_impostor`.
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
  /// wrong, `denied` when the service refuses the key.
  static Future<TomSecretsAdminClient> connect(
    TomSecretsRuntime runtime,
    List<int> adminKey, {
    Map<String, Object?> client = const {'name': 'tsm'},
  }) async {
    final admin = await _open(runtime);
    final challenge = await admin._next();
    admin._takeFeatures(challenge);
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

  /// Takes the service over with the master password (`claim`): the service
  /// cannot prove itself here, so the caller warns the user first. Answers
  /// the connection and the new admin key.
  static Future<(TomSecretsAdminClient, Uint8List)> claim(
    TomSecretsRuntime runtime, {
    required String password,
    List<int>? keyFile,
    Map<String, Object?> client = const {'name': 'tsm'},
  }) async {
    final admin = await _open(runtime);
    // The challenge, unanswerable without the key; its features count.
    admin._takeFeatures(await admin._next());
    admin._send({
      'op': 'claim',
      'password': password,
      'keyFile': ?(keyFile == null ? null : base64.encode(keyFile)),
      'client': client,
      'features': _features,
    });
    final answer = await admin._next();
    admin._throwIfError(answer);
    admin._listen();
    return (admin, base64.decode(answer['adminKey']! as String));
  }

  static Future<TomSecretsAdminClient> _open(TomSecretsRuntime runtime) async {
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
    final admin = TomSecretsAdminClient._(socket);
    admin._subscription = socket.listen(
      admin._data,
      onDone: admin._done,
      onError: (Object _) => admin._done(),
    );
    return admin;
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

  void _send(Map<String, Object?> message) {
    if (!_sendsChunked) {
      _socket.add(tomSecretsJsonFrame(message));
      return;
    }
    for (final frame in tomSecretsChunkedFrames(
      message,
      limit: tomSecretsMaxRequestPayload,
    )) {
      _socket.add(frame);
    }
  }

  /// Sends the admin request [op] with [fields]; answers the answer, or
  /// throws [TomSecretsAdminException] for an `error`.
  Future<Map<String, Object?>> request(
    String op, [
    Map<String, Object?> fields = const {},
  ]) async {
    // A connection that ended answers nothing more: waiting would never end.
    if (_closed) {
      throw TomSecretsAdminException('closed', 'the connection ended');
    }
    final id = _nextId++;
    final c = Completer<Map<String, Object?>>();
    _pending[id] = c;
    try {
      _send({...fields, 'op': op, 'id': id});
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
