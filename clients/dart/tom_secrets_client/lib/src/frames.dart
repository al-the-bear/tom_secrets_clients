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

  final BytesBuilder _buffer = BytesBuilder(copy: false);
  Uint8List _pending = Uint8List(0);

  /// Adds [bytes] and returns the frames now complete; throws
  /// [TomSecretsFrameException] on an oversized length or a bad type.
  List<TomSecretsFrame> add(List<int> bytes) {
    _buffer
      ..add(_pending)
      ..add(bytes);
    var data = _buffer.takeBytes();
    final frames = <TomSecretsFrame>[];
    var offset = 0;
    while (data.length - offset >= 5) {
      final view = ByteData.sublistView(data, offset);
      final length = view.getUint32(0);
      final type = data[offset + 4];
      if (length > maxPayload) {
        throw TomSecretsFrameException(
          'frame of $length bytes over $maxPayload',
        );
      }
      if (type != tomSecretsFrameJson &&
          !(type == tomSecretsFrameBinary && binaryAllowed)) {
        throw TomSecretsFrameException('frame type $type');
      }
      if (data.length - offset - 5 < length) break;
      frames.add(
        TomSecretsFrame(
          type,
          Uint8List.fromList(data.sublist(offset + 5, offset + 5 + length)),
        ),
      );
      offset += 5 + length;
    }
    _pending = Uint8List.fromList(data.sublist(offset));
    data = Uint8List(0);
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
