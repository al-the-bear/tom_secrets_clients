// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The Dart client of the Tom Secrets Manager: reads secrets from the local
/// secrets service over its client protocol.
///
/// ```dart
/// final client = await TomSecretsClient.connect();
/// final value = await client.get('[env:prod]db.main', field: 'UserName');
/// print(value.text);
/// value.dispose();
/// ```
library;

export 'src/client.dart'
    show
        TomSecretsClient,
        TomSecretsProgressCallback,
        TomSecretsWelcome,
        tomSecretsClientFeatures,
        tomSecretsMaxGetMany,
        tomSecretsProtocol;
export 'src/discovery.dart';
export 'src/errors.dart';
export 'src/frames.dart';
export 'src/reference.dart';
export 'src/value.dart';
export 'src/version.dart';
