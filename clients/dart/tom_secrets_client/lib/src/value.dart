// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// What a `get` answers (protocol.md 5.2), and what `getFile` answers [B].
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

/// How the service sent a value.
enum TomSecretEncoding {
  /// Text.
  utf8,

  /// Bytes (base64 on the wire).
  base64,
}

/// Where a value came from: `github` when its store was fetched from GitHub
/// in this refresh cycle, `file` when it was read from a `file:` vault on the
/// local disk in this cycle, `cache` when the service serves its offline copy.
enum TomSecretSource {
  /// Fetched from GitHub in this refresh cycle.
  github,

  /// Read from a `file:` vault on the local disk in this refresh cycle.
  file,

  /// The service's offline copy.
  cache;

  /// The source a protocol `source` names; an unknown one is [cache]
  /// (section 8: the most general one known, no claim to be fresh).
  static TomSecretSource fromWire(Object? name) => switch (name) {
    'github' => github,
    'file' => file,
    _ => cache,
  };
}

/// The entry a value was read from.
final class TomSecretEntry {
  /// The entry's members.
  const TomSecretEntry({
    required this.store,
    required this.uuid,
    required this.source,
    required this.fetchedAt,
  });

  /// The store holding it.
  final String store;

  /// Its KDBX UUID.
  final String uuid;

  /// Where the service read it from.
  final TomSecretSource source;

  /// The last successful fetch of the store.
  final DateTime fetchedAt;
}

/// The entry's last modification and the store file revision it was read
/// from; a caller caching a value compares it to see a change.
final class TomSecretVersion {
  /// The version's members.
  const TomSecretVersion({required this.modified, required this.revision});

  /// The entry's last modification.
  final DateTime modified;

  /// The store file revision it was read from.
  final String revision;

  @override
  bool operator ==(Object other) =>
      other is TomSecretVersion &&
      other.modified == modified &&
      other.revision == revision;
  @override
  int get hashCode => Object.hash(modified, revision);
}

/// A secret. Its [toString] never shows it, and [dispose] overwrites its
/// buffer. A [text] the caller takes out is an immutable Dart string the
/// library cannot overwrite: the caller handles it.
final class TomSecretValue {
  TomSecretValue._({
    required this.reference,
    required Uint8List bytes,
    required this.encoding,
    required this.entry,
    required this.bound,
    required this.version,
    this.expires,
    this.clientToken,
  }) : _bytes = bytes;

  /// The value of a `value` message (or a `values` result) for [reference].
  factory TomSecretValue.fromMessage(String reference, Map<String, Object?> m) {
    try {
      final encoding = m['encoding'] == 'base64'
          ? TomSecretEncoding.base64
          : TomSecretEncoding.utf8;
      final raw = m['value']! as String;
      final entry = (m['entry']! as Map).cast<String, Object?>();
      final version = (m['version']! as Map).cast<String, Object?>();
      final bound = m['bound'];
      return TomSecretValue._(
        reference: reference,
        bytes: encoding == TomSecretEncoding.base64
            ? base64.decode(raw)
            : utf8.encode(raw),
        encoding: encoding,
        entry: TomSecretEntry(
          store: entry['store']! as String,
          uuid: entry['uuid']! as String,
          source: TomSecretSource.fromWire(entry['source']),
          fetchedAt: DateTime.parse(entry['fetchedAt']! as String),
        ),
        bound: Map.unmodifiable(
          bound is Map
              ? bound.cast<String, String>()
              : const <String, String>{},
        ),
        version: TomSecretVersion(
          modified: DateTime.parse(version['modified']! as String),
          revision: version['revision']! as String,
        ),
        expires: m['expires'] is String
            ? DateTime.parse(m['expires']! as String)
            : null,
        clientToken: m['clientToken'] as String?,
      );
    } on Object catch (e) {
      if (e is TomSecretsClientException) rethrow;
      throw TomSecretsClientException(
        TomSecretsErrorKind.internal,
        'the service sent a value message this library cannot read',
        details: {'code': 'bad_value'},
      );
    }
  }

  /// The reference the value was asked for, as given.
  final String reference;
  final Uint8List _bytes;

  /// How the service sent it.
  final TomSecretEncoding encoding;

  /// The entry it was read from.
  final TomSecretEntry entry;

  /// The bindings the winning entry carries, `{dimension: value}`.
  final Map<String, String> bound;

  /// The entry's version.
  final TomSecretVersion version;

  /// The entry's expiry, when it has one.
  final DateTime? expires;

  /// The client token the service granted, when one was asked for: the
  /// caller's to keep (7.4); the library never stores it.
  final String? clientToken;

  bool _disposed = false;

  /// Whether [dispose] was called.
  bool get isDisposed => _disposed;

  /// The value as text. A binary value ([TomSecretEncoding.base64]) is
  /// refused with a [StateError] rather than decoded into a corrupt string.
  String get text {
    _check();
    if (encoding == TomSecretEncoding.base64) {
      throw StateError(
        'the value of $reference is binary: read it with bytes, not text',
      );
    }
    return utf8.decode(_bytes);
  }

  /// The value as bytes (text as its UTF-8). A view of the buffer that
  /// [dispose] overwrites; copy it to keep it.
  Uint8List get bytes {
    _check();
    return Uint8List.view(_bytes.buffer, _bytes.offsetInBytes, _bytes.length);
  }

  /// Overwrites the buffer with zeros; the value cannot be read afterwards.
  void dispose() {
    _bytes.fillRange(0, _bytes.length, 0);
    _disposed = true;
  }

  void _check() {
    if (_disposed) throw StateError('the value of $reference was disposed');
  }

  @override
  String toString() => 'TomSecretValue($reference: ***)';
}

/// What a `getFile` answers [B]: an attachment or a typed key as bytes.
final class TomSecretFile {
  /// The file [name] of [reference] with its [bytes].
  TomSecretFile(this.reference, this.name, Uint8List bytes) : _bytes = bytes;

  /// The reference it was asked for.
  final String reference;

  /// The attachment's name.
  final String name;
  final Uint8List _bytes;
  bool _disposed = false;

  /// Its size in bytes.
  int get size => _bytes.length;

  /// A view of the buffer that [dispose] overwrites.
  Uint8List get bytes {
    if (_disposed) throw StateError('the file of $reference was disposed');
    return Uint8List.view(_bytes.buffer, _bytes.offsetInBytes, _bytes.length);
  }

  /// Overwrites the buffer with zeros.
  void dispose() {
    _bytes.fillRange(0, _bytes.length, 0);
    _disposed = true;
  }

  @override
  String toString() => 'TomSecretFile($reference, $name: ***)';
}

/// Why a request waits (`progress`, 5.4).
enum TomSecretsPending {
  /// The service is locked and an admin was told.
  unlock,

  /// The request went to approval.
  approval,
}

/// A progress notice: passed to a call's `onProgress`.
final class TomSecretsProgress {
  /// A notice that the request waits for [pending].
  const TomSecretsProgress(this.pending, {this.approvalCode});

  /// Why it waits.
  final TomSecretsPending pending;

  /// The one-time approval code, on a host with no approver connected (7.5);
  /// show it so the user can approve it on a trusted device.
  final String? approvalCode;

  @override
  String toString() =>
      'TomSecretsProgress(${pending.name}'
      '${approvalCode == null ? '' : ', $approvalCode'})';
}

/// One reference of a `getMany`.
final class TomSecretRequest {
  /// [reference], with [field] and [dimensions] as for `get`.
  const TomSecretRequest(this.reference, {this.field, this.dimensions});

  /// The reference.
  final String reference;

  /// The field, when the reference names none.
  final String? field;

  /// Values for dimensions, beside the reference.
  final Map<String, String>? dimensions;
}

/// One result of a `getMany`, in request order: a [value] or an [error].
final class TomSecretResult {
  /// A result that is a value.
  const TomSecretResult.value(TomSecretValue this.value) : error = null;

  /// A result that is an error.
  const TomSecretResult.error(TomSecretsClientException this.error)
    : value = null;

  /// The value, or null.
  final TomSecretValue? value;

  /// The error, or null.
  final TomSecretsClientException? error;
}

/// A login entry `match` found for a page (protocol.md 5.5): never a value.
final class TomSecretsLoginCandidate {
  /// A candidate.
  const TomSecretsLoginCandidate({
    required this.entryId,
    required this.title,
    required this.userName,
    required this.matchedUrl,
    required this.hasTotp,
  });

  /// From a `matches` candidate.
  factory TomSecretsLoginCandidate.fromJson(Map<String, Object?> json) =>
      TomSecretsLoginCandidate(
        entryId: json['entryId'] is String ? json['entryId']! as String : '',
        title: json['title'] is String ? json['title']! as String : '',
        userName: json['userName'] is String ? json['userName']! as String : '',
        matchedUrl: json['matchedUrl'] is String
            ? json['matchedUrl']! as String
            : '',
        hasTotp: json['hasTotp'] == true,
      );

  /// The entry as a uuid reference (`store/~<32 hex>`): what a fill reads
  /// with `get` (`field: 'UserName'`, `'Password'`, `'totp'`).
  final String entryId;

  /// The entry's title.
  final String title;

  /// Its user name.
  final String userName;

  /// The entry URL that matched, as written in the entry.
  final String matchedUrl;

  /// Whether it carries a TOTP secret.
  final bool hasTotp;
}
