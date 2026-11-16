// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Starting the service: a status line that is not one (not JSON, or not an
/// object) is a failed start, not an exception. Demo data only.
@TestOn('mac-os || linux')
library;

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  for (final (what, line) in [
    ('not JSON', 'hello'),
    ('not an object', '[1]'),
  ]) {
    test('a status line that is $what is a failed start', () async {
      final result = await tomSecretsStartService(
        executable: '/bin/sh',
        arguments: ['-c', 'read handover; echo \'$line\''],
        bootstrap: '/nonexistent/bootstrap.yaml',
      );
      expect(
        result,
        isA<TomSecretsStartFailed>().having((r) => r.code, 'code', 'no_answer'),
      );
    });
  }
}
