// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The reference grammar (protocol.md section 4): parse and format.
library;

import 'dart:convert';

import 'errors.dart';

/// The field a reference without `#field` names.
const String tomSecretsDefaultField = 'Password';

/// The longest reference, in bytes of UTF-8 as sent.
const int tomSecretsMaxReferenceBytes = 1024;

const String _reserved = '/#[],:%';
final RegExp _name = RegExp(r'^[a-z][a-z0-9_-]*$');
final RegExp _store = RegExp(r'^[a-z0-9][a-z0-9_-]*$');
final RegExp _uuid = RegExp(r'^~[0-9A-Fa-f]{32}$');
final RegExp _hexPair = RegExp(r'^[0-9a-fA-F]{2}$');

bool _isControl(int rune) => rune < 0x20 || rune == 0x7f;

TomSecretsClientException _malformed(String reason, [String detail = '']) =>
    TomSecretsClientException(
      TomSecretsErrorKind.malformed,
      detail.isEmpty
          ? 'the reference is malformed: $reason'
          : 'the reference is malformed: $reason ($detail)',
      details: {'reason': reason},
    );

/// What a reference names: a key, a path or a uuid reference.
sealed class TomSecretTarget {
  const TomSecretTarget();
}

/// A key: the value of an entry's `tsm.key` field (`telegram.bot_token`).
final class TomSecretKeyTarget extends TomSecretTarget {
  /// The target of [key].
  const TomSecretKeyTarget(this.key);

  /// The dotted key.
  final String key;

  @override
  bool operator ==(Object other) =>
      other is TomSecretKeyTarget && other.key == key;
  @override
  int get hashCode => key.hashCode;
}

/// A path: a store, the group path below its root group and the entry title,
/// each segment unescaped.
final class TomSecretPathTarget extends TomSecretTarget {
  /// The entry [segments] (groups, then the title) of [store].
  TomSecretPathTarget(this.store, List<String> segments)
    : segments = List.unmodifiable(segments);

  /// The store name.
  final String store;

  /// The groups below the root group, then the entry title, unescaped.
  final List<String> segments;

  @override
  bool operator ==(Object other) =>
      other is TomSecretPathTarget &&
      other.store == store &&
      _listEquals(other.segments, segments);
  @override
  int get hashCode => Object.hash(store, Object.hashAll(segments));
}

/// A uuid reference: an entry of a store by its KDBX UUID (lower case).
final class TomSecretUuidTarget extends TomSecretTarget {
  /// The entry [uuid] of [store].
  const TomSecretUuidTarget(this.store, this.uuid);

  /// The store name.
  final String store;

  /// 32 lower-case hex digits.
  final String uuid;

  @override
  bool operator ==(Object other) =>
      other is TomSecretUuidTarget &&
      other.store == store &&
      other.uuid == uuid;
  @override
  int get hashCode => Object.hash(store, uuid);
}

/// One binding `<dimension>:<value>` of a reference's qualifiers.
final class TomSecretBinding {
  /// [dimension] bound to [value].
  const TomSecretBinding(this.dimension, this.value);

  /// The dimension name.
  final String dimension;

  /// Its value, unescaped.
  final String value;

  @override
  bool operator ==(Object other) =>
      other is TomSecretBinding &&
      other.dimension == dimension &&
      other.value == value;
  @override
  int get hashCode => Object.hash(dimension, value);
}

bool _listEquals<T>(List<T> a, List<T> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// A parsed reference. [parse] refuses a malformed one with a
/// [TomSecretsClientException] of kind `malformed` whose `reason` is the
/// rule of protocol.md 4.6 it broke; [format] gives the canonical form (4.5).
final class TomSecretReference {
  /// A reference from its parts.
  TomSecretReference({
    List<TomSecretBinding> qualifiers = const [],
    required this.target,
    this.field = tomSecretsDefaultField,
    this.fieldGiven = false,
  }) : qualifiers = List.unmodifiable(qualifiers);

  /// The bindings in the order written.
  final List<TomSecretBinding> qualifiers;

  /// What the reference names.
  final TomSecretTarget target;

  /// The effective field: the one written, else `Password`.
  final String field;

  /// Whether the reference wrote `#field`.
  final bool fieldGiven;

  /// The canonical form ([format]).
  String get canonical => format(this);

  /// Parses [reference] (protocol.md 4.1-4.4, 4.6).
  static TomSecretReference parse(String reference) {
    if (utf8.encode(reference).length > tomSecretsMaxReferenceBytes) {
      throw _malformed('too_long');
    }
    if (reference.isEmpty) throw _malformed('empty');
    var rest = reference;
    final qualifiers = <TomSecretBinding>[];
    if (rest.startsWith('[')) {
      final end = rest.indexOf(']');
      if (end < 0) throw _malformed('unclosed_qualifiers');
      final body = rest.substring(1, end);
      rest = rest.substring(end + 1);
      if (body.isEmpty) throw _malformed('empty_segment', '[]');
      final seen = <String>{};
      for (final binding in body.split(',')) {
        final parts = binding.split(':');
        if (parts.length != 2) throw _malformed('bad_binding', binding);
        final [name, value] = parts;
        if (!_name.hasMatch(name)) throw _malformed('bad_dimension', name);
        if (!seen.add(name)) throw _malformed('duplicate_dimension', name);
        qualifiers.add(TomSecretBinding(name, _decodeSegment(value)));
      }
    }
    if ('#'.allMatches(rest).length > 1) {
      throw _malformed('reserved_character', '#');
    }
    final hash = rest.indexOf('#');
    final fieldGiven = hash >= 0;
    final targetText = fieldGiven ? rest.substring(0, hash) : rest;
    if (targetText.isEmpty) throw _malformed('empty_target');
    final field = fieldGiven
        ? _decodeSegment(rest.substring(hash + 1))
        : tomSecretsDefaultField;
    final TomSecretTarget target;
    if (!targetText.contains('/')) {
      if (!targetText.split('.').every(_name.hasMatch)) {
        throw _malformed('bad_key', targetText);
      }
      target = TomSecretKeyTarget(targetText);
    } else {
      final parts = targetText.split('/');
      final store = parts.first;
      if (!_store.hasMatch(store)) throw _malformed('bad_store', store);
      final raw = parts.sublist(1);
      if (raw.length == 1 && raw.single.startsWith('~')) {
        if (!_uuid.hasMatch(raw.single)) {
          throw _malformed('bad_uuid', raw.single);
        }
        target = TomSecretUuidTarget(
          store,
          raw.single.substring(1).toLowerCase(),
        );
      } else {
        final segments = <String>[];
        for (final segment in raw) {
          if (segment.isEmpty) throw _malformed('empty_segment');
          if (segment.startsWith('@') || segment.startsWith('~')) {
            throw _malformed('reserved_prefix', segment[0]);
          }
          segments.add(_decodeSegment(segment));
        }
        target = TomSecretPathTarget(store, segments);
      }
    }
    return TomSecretReference(
      qualifiers: qualifiers,
      target: target,
      field: field,
      fieldGiven: fieldGiven,
    );
  }

  /// The canonical text of [reference]: bindings sorted by dimension name,
  /// every segment escaped in exactly what it must be, the uuid in lower case,
  /// the field omitted when it is `Password`.
  static String format(TomSecretReference reference) {
    final out = StringBuffer();
    final bindings = [...reference.qualifiers]
      ..sort((a, b) => _compareUtf8(a.dimension, b.dimension));
    if (bindings.isNotEmpty) {
      if (bindings.map((b) => b.dimension).toSet().length != bindings.length) {
        throw ArgumentError('a dimension is bound once');
      }
      out
        ..write('[')
        ..write(
          bindings
              .map((b) => '${b.dimension}:${_encodeSegment(b.value)}')
              .join(','),
        )
        ..write(']');
    }
    switch (reference.target) {
      case TomSecretKeyTarget(:final key):
        out.write(key);
      case TomSecretUuidTarget(:final store, :final uuid):
        out.write('$store/~${uuid.toLowerCase()}');
      case TomSecretPathTarget(:final store, :final segments):
        out
          ..write(store)
          ..write('/')
          ..write(segments.map((s) => _encodeSegment(s, path: true)).join('/'));
    }
    if (reference.field != tomSecretsDefaultField) {
      out.write('#${_encodeSegment(reference.field)}');
    }
    return out.toString();
  }

  @override
  bool operator ==(Object other) =>
      other is TomSecretReference &&
      _listEquals(other.qualifiers, qualifiers) &&
      other.target == target &&
      other.field == field &&
      other.fieldGiven == fieldGiven;

  @override
  int get hashCode =>
      Object.hash(Object.hashAll(qualifiers), target, field, fieldGiven);

  @override
  String toString() => canonical;
}

int _compareUtf8(String a, String b) {
  final x = utf8.encode(a);
  final y = utf8.encode(b);
  for (var i = 0; i < x.length && i < y.length; i++) {
    if (x[i] != y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

String _decodeSegment(String raw) {
  if (raw.isEmpty) throw _malformed('empty_segment');
  final bytes = <int>[];
  final runes = raw.runes.toList();
  for (var i = 0; i < runes.length; i++) {
    final rune = runes[i];
    if (rune == 0x25) {
      final pair = String.fromCharCodes(runes.skip(i + 1).take(2));
      if (!_hexPair.hasMatch(pair)) {
        throw _malformed('bad_escape', '%$pair');
      }
      bytes.add(int.parse(pair, radix: 16));
      i += 2;
      continue;
    }
    final ch = String.fromCharCode(rune);
    if (_reserved.contains(ch)) throw _malformed('reserved_character', ch);
    if (_isControl(rune)) {
      throw _malformed(
        'control_character',
        'U+${rune.toRadixString(16).toUpperCase().padLeft(4, '0')}',
      );
    }
    bytes.addAll(utf8.encode(ch));
  }
  try {
    return const Utf8Decoder().convert(bytes);
  } on FormatException catch (e) {
    throw _malformed('bad_utf8', e.message);
  }
}

String _encodeSegment(String text, {bool path = false}) {
  if (text.isEmpty) throw ArgumentError('a segment is never empty');
  final out = StringBuffer();
  var first = true;
  for (final rune in text.runes) {
    final ch = String.fromCharCode(rune);
    if (_reserved.contains(ch) ||
        _isControl(rune) ||
        (path && first && (ch == '@' || ch == '~'))) {
      for (final b in utf8.encode(ch)) {
        out.write('%${b.toRadixString(16).toUpperCase().padLeft(2, '0')}');
      }
    } else {
      out.write(ch);
    }
    first = false;
  }
  return out.toString();
}
