// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Frames and JSON payloads (protocol.md section 2).
library;

import 'dart:convert';
import 'dart:typed_data';

/// Frame type of a JSON payload.
const int tomSecretsFrameJson = 0;

/// Frame type of a binary chunk ([B], 2.5).
const int tomSecretsFrameBinary = 1;

/// The largest payload of a frame sent to the service.
const int tomSecretsMaxRequestPayload = 64 * 1024;

/// The largest payload of a frame sent by the service.
const int tomSecretsMaxAnswerPayload = 1024 * 1024;

/// A frame or payload that breaks section 2; the connection is closed.
final class TomSecretsFrameException implements Exception {
  /// A violation described by [message].
  TomSecretsFrameException(this.message);

  /// What broke section 2.
  final String message;
  @override
  String toString() => 'TomSecretsFrameException: $message';
}

/// The compact UTF-8 JSON of [message], as the vectors write it.
Uint8List tomSecretsJsonPayload(Map<String, Object?> message) =>
    utf8.encode(jsonEncode(message));

/// A frame: the payload length (4 bytes big-endian), the type, the payload.
Uint8List tomSecretsEncodeFrame(int type, List<int> payload) {
  final out = Uint8List(5 + payload.length);
  ByteData.sublistView(out).setUint32(0, payload.length);
  out[4] = type;
  out.setRange(5, out.length, payload);
  return out;
}

/// The JSON frame of [message].
Uint8List tomSecretsJsonFrame(Map<String, Object?> message) =>
    tomSecretsEncodeFrame(tomSecretsFrameJson, tomSecretsJsonPayload(message));

/// The message of a JSON payload, or [TomSecretsFrameException] when it is
/// malformed (2.2): empty, not UTF-8, not JSON, not an object, an object with
/// a duplicate member name, or without a string `op`.
Map<String, Object?> tomSecretsDecodePayload(List<int> payload) {
  if (payload.isEmpty) throw TomSecretsFrameException('empty payload');
  final String text;
  try {
    text = const Utf8Decoder().convert(payload);
  } on FormatException {
    throw TomSecretsFrameException('payload is not UTF-8');
  }
  if (text.startsWith('﻿')) {
    throw TomSecretsFrameException('payload starts with a byte order mark');
  }
  final Object? value;
  try {
    value = _StrictJson(text).parseDocument();
  } on FormatException catch (e) {
    throw TomSecretsFrameException('payload is not JSON: ${e.message}');
  }
  if (value is! Map<String, Object?>) {
    throw TomSecretsFrameException('payload is not a JSON object');
  }
  if (value['op'] is! String) {
    throw TomSecretsFrameException('payload has no op');
  }
  return value;
}

/// One frame read from a connection.
final class TomSecretsFrame {
  /// A frame of [type] carrying [payload].
  TomSecretsFrame(this.type, this.payload);

  /// [tomSecretsFrameJson] or [tomSecretsFrameBinary].
  final int type;

  /// The payload bytes.
  final Uint8List payload;
}

/// Splits a byte stream into frames, checking every length against
/// [maxPayload] before the payload is read and refusing a frame type that is
/// neither JSON nor (with [binaryAllowed]) binary.
final class TomSecretsFrameReader {
  /// A reader refusing payloads over [maxPayload].
  TomSecretsFrameReader({required this.maxPayload});

  /// The largest payload accepted.
  final int maxPayload;

  /// Whether binary frames were negotiated (both sides named `binary`).
  bool binaryAllowed = false;

  // The bytes not yet consumed are `_data[_start.._end]`. One growing
  // buffer, appended to and consumed from the front: a frame arriving in
  // many reads is copied once, not once per read (a 1 MiB frame comes in
  // more than a hundred of them).
  Uint8List _data = Uint8List(0);
  int _start = 0;
  int _end = 0;

  void _append(List<int> bytes) {
    final pending = _end - _start;
    if (_data.length - _end < bytes.length) {
      final needed = pending + bytes.length;
      // Room in front is reused before the buffer grows; it grows by
      // doubling, so appending stays linear.
      final grown = needed > _data.length
          ? Uint8List(needed > _data.length * 2 ? needed : _data.length * 2)
          : _data;
      if (identical(grown, _data)) {
        _data.setRange(0, pending, _data, _start);
        _data.fillRange(pending, _end, 0);
      } else {
        grown.setRange(0, pending, _data, _start);
        // What a connection carried does not stay behind in a dropped
        // buffer.
        _data.fillRange(0, _data.length, 0);
        _data = grown;
      }
      _start = 0;
      _end = pending;
    }
    _data.setRange(_end, _end + bytes.length, bytes);
    _end += bytes.length;
  }

  /// Adds [bytes] and returns the frames now complete; throws
  /// [TomSecretsFrameException] on an oversized length or a bad type.
  List<TomSecretsFrame> add(List<int> bytes) {
    _append(bytes);
    final frames = <TomSecretsFrame>[];
    while (_end - _start >= 5) {
      final length = ByteData.sublistView(
        _data,
        _start,
        _start + 4,
      ).getUint32(0);
      final type = _data[_start + 4];
      if (length > maxPayload) {
        throw TomSecretsFrameException(
          'frame of $length bytes over $maxPayload',
        );
      }
      if (type != tomSecretsFrameJson &&
          !(type == tomSecretsFrameBinary && binaryAllowed)) {
        throw TomSecretsFrameException('frame type $type');
      }
      if (_end - _start - 5 < length) break;
      final from = _start + 5;
      frames.add(
        TomSecretsFrame(
          type,
          Uint8List.fromList(Uint8List.sublistView(_data, from, from + length)),
        ),
      );
      // The frame is its own copy now: its bytes leave the buffer.
      _data.fillRange(_start, from + length, 0);
      _start = from + length;
    }
    if (_start == _end) _start = _end = 0;
    return frames;
  }
}

/// A JSON parser that refuses duplicate member names (RFC 8259 leaves them
/// open; protocol.md 2.2 makes them malformed). Scalars are decoded by
/// `dart:convert`.
final class _StrictJson {
  _StrictJson(this.text);
  final String text;
  int _i = 0;

  Object? parseDocument() {
    final value = _value();
    _ws();
    if (_i != text.length) throw FormatException('trailing text', text, _i);
    return value;
  }

  void _ws() {
    while (_i < text.length && ' \t\n\r'.contains(text[_i])) {
      _i++;
    }
  }

  Object? _value() {
    _ws();
    if (_i >= text.length) throw FormatException('unexpected end', text, _i);
    switch (text[_i]) {
      case '{':
        return _object();
      case '[':
        return _array();
      case '"':
        return _string();
      default:
        return _scalar();
    }
  }

  Map<String, Object?> _object() {
    final out = <String, Object?>{};
    _i++;
    _ws();
    if (_peek('}')) return out;
    while (true) {
      _ws();
      if (_i >= text.length || text[_i] != '"') {
        throw FormatException('member name expected', text, _i);
      }
      final name = _string();
      if (out.containsKey(name)) {
        throw FormatException('duplicate member "$name"', text, _i);
      }
      _ws();
      _expect(':');
      out[name] = _value();
      _ws();
      if (_peek('}')) return out;
      _expect(',');
    }
  }

  List<Object?> _array() {
    final out = <Object?>[];
    _i++;
    _ws();
    if (_peek(']')) return out;
    while (true) {
      out.add(_value());
      _ws();
      if (_peek(']')) return out;
      _expect(',');
    }
  }

  String _string() {
    final start = _i;
    _i++;
    while (_i < text.length && text[_i] != '"') {
      if (text[_i] == r'\') _i++;
      _i++;
    }
    if (_i >= text.length) {
      throw FormatException('unclosed string', text, start);
    }
    _i++;
    return jsonDecode(text.substring(start, _i)) as String;
  }

  Object? _scalar() {
    final start = _i;
    while (_i < text.length && !',]} \t\n\r'.contains(text[_i])) {
      _i++;
    }
    final token = text.substring(start, _i);
    final value = jsonDecode(token);
    if (value is Map || value is List || value is String) {
      throw FormatException('bad value', text, start);
    }
    return value;
  }

  bool _peek(String ch) {
    if (_i < text.length && text[_i] == ch) {
      _i++;
      return true;
    }
    return false;
  }

  void _expect(String ch) {
    if (!_peek(ch)) throw FormatException('"$ch" expected', text, _i);
  }
}
