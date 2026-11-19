// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/**
 * The client library of the Tom Secrets Manager for TypeScript and
 * JavaScript on Node.js: reads secrets from the local secrets service.
 *
 * ```ts
 * const client = await SecretsClient.connect();
 * const token = await client.get('telegram.bot_token');
 * ```
 */

export {
  SecretsClient,
  clientFeatures,
  maxGetMany,
  protocolVersion,
  type ClientOptions,
  type GetFileOptions,
  type GetOptions,
  type RequestOptions,
  type Welcome,
} from './client';
export {
  currentOperatingSystem,
  discover,
  readPortFile,
  type Endpoints,
  type Location,
  type NoRuntimeDirectory,
  type OperatingSystem,
} from './discovery';
export { SecretsError, errorKindFromWire, type SecretsErrorKind } from './errors';
export {
  SecretReference,
  defaultField,
  maxReferenceBytes,
  type KeyTarget,
  type PathTarget,
  type SecretBinding,
  type SecretTarget,
  type UuidTarget,
} from './reference';
export {
  SecretFile,
  SecretValue,
  sourceFromWire,
  type Pending,
  type Progress,
  type ProgressCallback,
  type SecretEncoding,
  type SecretEntry,
  type SecretRequest,
  type SecretResult,
  type SecretSource,
  type SecretVersion,
} from './value';
export { clientVersion } from './version';
