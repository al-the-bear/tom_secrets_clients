// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Chunked members on the admin endpoint (protocol.md 2.7): a message whose
/// JSON would exceed its frame limit (a request's 64 KiB, an answer's 1 MiB)
/// carries its large string members as binary frames instead. The JSON
/// message names them in `chunked` (`[{name, size, sha256}]`, in order, the
/// size and SHA-256 of each member's UTF-8) and goes first; the members'
/// UTF-8 follows, joined in that order, as binary frames of the message's
/// `id` (8 bytes big-endian, then the chunk). The receiver puts the members
/// back before it reads the message. Both sides announce the feature
/// [tomSecretsChunkedFeature]; a peer that did not is sent whole messages.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../frames.dart';

/// The admin feature of chunked members.
const String tomSecretsChunkedFeature = 'chunked';

/// The most a chunked message may carry in all (a vault with large
/// attachments fits; a peer cannot make the other side hold more).
const int tomSecretsMaxChunkedBytes = 512 * 1024 * 1024;

/// A string member is moved into chunks from this many UTF-8 bytes on.
const int _smallestChunked = 1024;

/// [message] (with its `id`) as the frames to send within [limit] (a
/// frame's payload limit): one JSON frame when it fits, else the JSON frame
/// naming its chunked members, then the binary frames. Throws
/// [TomSecretsFrameException] when even the remaining JSON does not fit.
List<Uint8List> tomSecretsChunkedFrames(
  Map<String, Object?> message, {
  required int limit,
}) {
  final whole = tomSecretsJsonPayload(message);
  if (whole.length <= limit) {
    return [tomSecretsEncodeFrame(tomSecretsFrameJson, whole)];
  }
  final id = message['id'];
  if (id is! int) {
    throw TomSecretsFrameException('a chunked message carries an id');
  }
  final members = [
    for (final MapEntry(:key, :value) in message.entries)
      if (value is String && key != 'op' && value.length >= _smallestChunked)
        key,
  ];
  final rest = Map<String, Object?>.of(message);
  final named = <Map<String, Object?>>[];
  final bytes = BytesBuilder(copy: false);
  for (final name in members) {
    final data = utf8.encode(rest.remove(name)! as String);
    named.add({
      'name': name,
      'size': data.length,
      'sha256': crypto.sha256.convert(data).toString(),
    });
    bytes.add(data);
  }
  rest['chunked'] = named;
  final head = tomSecretsJsonPayload(rest);
  if (head.length > limit || named.isEmpty) {
    throw TomSecretsFrameException(
      'a message of ${whole.length} bytes does not fit a frame of $limit',
    );
  }
  final body = bytes.takeBytes();
  if (body.length > tomSecretsMaxChunkedBytes) {
    throw TomSecretsFrameException(
      'a message of ${body.length} bytes is over $tomSecretsMaxChunkedBytes',
    );
  }
  final frames = [tomSecretsEncodeFrame(tomSecretsFrameJson, head)];
  final step = limit - 8;
  for (var at = 0; at < body.length; at += step) {
    final end = at + step < body.length ? at + step : body.length;
    final payload = Uint8List(8 + end - at);
    ByteData.sublistView(payload).setUint64(0, id);
    payload.setRange(8, payload.length, body, at);
    frames.add(tomSecretsEncodeFrame(tomSecretsFrameBinary, payload));
  }
  body.fillRange(0, body.length, 0);
  return frames;
}

/// Puts chunked messages back together on the receiving side.
final class TomSecretsChunkAssembler {
  final Map<int, _Pending> _pending = {};

  /// Whether [message] names chunked members: hand it to [begin].
  static bool isChunked(Map<String, Object?> message) =>
      message['chunked'] is List;

  /// Starts [message], whose members follow as binary frames; answers it
  /// whole at once when its members are all empty (no frame follows), else
  /// null. Throws [TomSecretsFrameException] for a malformed `chunked`
  /// list, a second message of the same id, or more than
  /// [tomSecretsMaxChunkedBytes].
  Map<String, Object?>? begin(Map<String, Object?> message) {
    final id = message['id'];
    if (id is! int) {
      throw TomSecretsFrameException('a chunked message carries an id');
    }
    if (_pending.containsKey(id)) {
      throw TomSecretsFrameException('chunks of request $id are pending');
    }
    final members = <({String name, int size, String sha256})>[];
    var total = 0;
    for (final m in message['chunked']! as List) {
      if (m is! Map ||
          m['name'] is! String ||
          m['size'] is! int ||
          (m['size'] as int) < 0 ||
          m['sha256'] is! String) {
        throw TomSecretsFrameException('a chunked member is malformed');
      }
      members.add((
        name: m['name'] as String,
        size: m['size'] as int,
        sha256: m['sha256'] as String,
      ));
      total += m['size'] as int;
    }
    if (total > tomSecretsMaxChunkedBytes) {
      throw TomSecretsFrameException(
        'a message of $total bytes is over $tomSecretsMaxChunkedBytes',
      );
    }
    final rest = Map<String, Object?>.of(message)..remove('chunked');
    final pending = _Pending(rest, members, total);
    if (total == 0) return pending.complete();
    _pending[id] = pending;
    return null;
  }

  /// The binary frame [payload] (the id, then a chunk); answers the whole
  /// message once its last chunk is in, else null. Throws
  /// [TomSecretsFrameException] for a chunk of no pending message, more
  /// bytes than announced, or a member whose SHA-256 differs.
  Map<String, Object?>? add(Uint8List payload) {
    if (payload.length < 8) {
      throw TomSecretsFrameException('a binary frame without its id');
    }
    final id = ByteData.sublistView(payload).getUint64(0);
    final pending = _pending[id];
    if (pending == null) {
      throw TomSecretsFrameException('a chunk of no pending message ($id)');
    }
    pending.add(Uint8List.sublistView(payload, 8));
    if (!pending.isComplete) return null;
    _pending.remove(id);
    return pending.complete();
  }

  /// Forgets everything pending (the connection ended).
  void clear() {
    for (final p in _pending.values) {
      p.wipe();
    }
    _pending.clear();
  }
}

final class _Pending {
  _Pending(this.rest, this.members, this.total) : buffer = Uint8List(total);

  final Map<String, Object?> rest;
  final List<({String name, int size, String sha256})> members;
  final int total;
  final Uint8List buffer;
  int filled = 0;

  bool get isComplete => filled == total;

  void add(Uint8List chunk) {
    if (filled + chunk.length > total) {
      wipe();
      throw TomSecretsFrameException('more chunk bytes than announced');
    }
    buffer.setRange(filled, filled + chunk.length, chunk);
    filled += chunk.length;
  }

  Map<String, Object?> complete() {
    var at = 0;
    final message = Map<String, Object?>.of(rest);
    for (final m in members) {
      final data = Uint8List.sublistView(buffer, at, at + m.size);
      at += m.size;
      if (crypto.sha256.convert(data).toString() != m.sha256) {
        wipe();
        throw TomSecretsFrameException('the member ${m.name} does not match');
      }
      try {
        message[m.name] = utf8.decode(data);
      } on FormatException {
        wipe();
        throw TomSecretsFrameException('the member ${m.name} is not UTF-8');
      }
    }
    wipe();
    return message;
  }

  void wipe() => buffer.fillRange(0, buffer.length, 0);
}
