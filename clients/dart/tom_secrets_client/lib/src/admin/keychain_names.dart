// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The names the product's items have in the OS keychain, shared by the
/// manager app, the service and `tsm` (part-service, DP-22).
library;

/// The service name of the product's items in the OS keychain.
const String tomSecretsKeychainService = 'tom-secrets-manager';

/// The handle of the admin key of the service started at [serviceStart]
/// (`service.json`'s `start`, milliseconds since the epoch): the app and
/// `tsm` keep the key there between invocations; a new start has a new key.
String tomSecretsAdminKeyHandle(int serviceStart) => 'tsm.admin.$serviceStart';
