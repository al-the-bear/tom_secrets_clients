// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The one error type of the library and its kinds (protocol.md section 10,
/// plus `not_running`, section 3).
library;

/// What went wrong: the protocol's error kinds plus [notRunning].
enum TomSecretsErrorKind {
  /// The service is locked and no unlock came in time, or `wait` was false.
  locked('locked'),

  /// The client may not have this, or the connection was refused.
  denied('denied'),

  /// No candidate, or the winning entry lacks the field.
  notFound('not_found'),

  /// Several candidates rank equal (`details['candidates']`).
  ambiguous('ambiguous'),

  /// The store holding the answer could not be reopened since its key
  /// changed.
  needsUnlock('needs_unlock'),

  /// The store holding the answer could not be fetched and has no offline
  /// copy.
  unavailable('unavailable'),

  /// Admin only: a fetch failed for a network reason.
  offline('offline'),

  /// Admin only: GitHub refused the token.
  tokenExpired('token_expired'),

  /// A frame, a reference, a binding or a request cannot be read; a
  /// reference refused locally carries `details['reason']` (section 4.6).
  malformed('malformed'),

  /// An approval was not answered in time.
  timeout('timeout'),

  /// The identity is held back (`details['retryAfterMs']`).
  rateLimited('rate_limited'),

  /// An unknown request or protocol, or a feature the service does not offer.
  unsupported('unsupported'),

  /// A failure of the service, or a service that broke the protocol; also any
  /// kind this library does not know (section 8).
  internal('internal'),

  /// No service: no socket or port file, an unreadable port file, a refused
  /// connection, or a connection that dropped. Sent by nobody.
  notRunning('not_running');

  const TomSecretsErrorKind(this.wireName);

  /// The kind as the protocol writes it.
  final String wireName;

  /// The kind of a protocol `kind`; an unknown one is [internal]
  /// (section 8: the most general kind known).
  static TomSecretsErrorKind fromWire(Object? kind) {
    for (final k in values) {
      if (k.wireName == kind && k != notRunning) return k;
    }
    return internal;
  }
}

/// A call that failed. Never carries a value or a token.
final class TomSecretsClientException implements Exception {
  /// An exception of [kind] with [message] and [details].
  TomSecretsClientException(
    this.kind,
    this.message, {
    Map<String, Object?>? details,
  }) : details = Map.unmodifiable(details ?? const {});

  /// The exception of a protocol `error` message (or a `values` result).
  factory TomSecretsClientException.fromError(Map<String, Object?> error) {
    final details = error['details'];
    return TomSecretsClientException(
      TomSecretsErrorKind.fromWire(error['kind']),
      error['message'] is String ? error['message']! as String : '',
      details: details is Map ? details.cast<String, Object?>() : null,
    );
  }

  /// What went wrong.
  final TomSecretsErrorKind kind;

  /// For people; the service never puts a value, a token or a key into it.
  final String message;

  /// `reason`, `candidates`, `retryAfterMs`, `dimensions`, ... (section 10).
  final Map<String, Object?> details;

  /// `details['reason']`, when there is one.
  String? get reason => details['reason'] as String?;

  @override
  String toString() =>
      'TomSecretsClientException(${kind.wireName}'
      '${reason == null ? '' : ', $reason'}): $message';
}
