// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The admin side of the Tom Secrets Manager's local protocol (protocol.md
/// 6): the admin client with its mutual challenge and `claim`, the runtime
/// directory, starting the service with its admin-key handover, and where the
/// product keeps its data. Used by the manager app, `tsm` and the service
/// itself; a client that only reads secrets needs none of it.
library;

export 'src/admin/admin_auth.dart';
export 'src/admin/admin_client.dart';
export 'src/admin/admin_keyring.dart';
export 'src/admin/data_directory.dart';
export 'src/admin/distribution.dart';
export 'src/admin/integrations.dart';
export 'src/admin/keychain_names.dart';
export 'src/admin/pairing_mode.dart';
export 'src/admin/runtime.dart';
export 'src/admin/starter.dart';
