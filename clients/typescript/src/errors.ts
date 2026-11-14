// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/**
 * The error kinds: the protocol's (protocol.md section 10) plus
 * `not_running`, which a library reports when it finds no service or loses
 * the connection.
 */
export type SecretsErrorKind =
  | 'locked'
  | 'denied'
  | 'not_found'
  | 'ambiguous'
  | 'needs_unlock'
  | 'unavailable'
  | 'offline'
  | 'token_expired'
  | 'malformed'
  | 'timeout'
  | 'rate_limited'
  | 'unsupported'
  | 'internal'
  | 'not_running';

const wireKinds: ReadonlySet<string> = new Set<SecretsErrorKind>([
  'locked',
  'denied',
  'not_found',
  'ambiguous',
  'needs_unlock',
  'unavailable',
  'offline',
  'token_expired',
  'malformed',
  'timeout',
  'rate_limited',
  'unsupported',
  'internal',
]);

/**
 * The kind an `error` message names: an unknown kind (from a later service)
 * is `internal`; `not_running` is never the service's to send.
 */
export function errorKindFromWire(kind: unknown): SecretsErrorKind {
  return typeof kind === 'string' && wireKinds.has(kind)
    ? (kind as SecretsErrorKind)
    : 'internal';
}

/** Every failure of the library. */
export class SecretsError extends Error {
  /** What went wrong. */
  readonly kind: SecretsErrorKind;

  /** `details` of the protocol's error: `reason`, `candidates`, `retryAfterMs`, ... */
  readonly details: Readonly<Record<string, unknown>>;

  constructor(
    kind: SecretsErrorKind,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'SecretsError';
    this.kind = kind;
    this.details = Object.freeze({ ...details });
  }

  /** The error an `error` message carries. */
  static fromError(error: Record<string, unknown>): SecretsError {
    const details = error['details'];
    return new SecretsError(
      errorKindFromWire(error['kind']),
      typeof error['message'] === 'string' ? error['message'] : '',
      details !== null && typeof details === 'object' && !Array.isArray(details)
        ? (details as Record<string, unknown>)
        : {},
    );
  }

  /** `details.reason`, when there is one. */
  get reason(): string | undefined {
    const r = this.details['reason'];
    return typeof r === 'string' ? r : undefined;
  }

  override toString(): string {
    return `SecretsError(${this.kind}${this.reason === undefined ? '' : `, ${this.reason}`}): ${this.message}`;
  }
}
