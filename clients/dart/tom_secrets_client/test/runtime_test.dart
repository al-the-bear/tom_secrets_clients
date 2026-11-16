// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The runtime directory's files for an OS other than the one the test runs
/// on: joined with that OS's separator. Demo data only.
library;

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  test('Windows paths computed anywhere use backslashes', () {
    final runtime = TomSecretsRuntime.current(
      operatingSystem: 'windows',
      environment: const {'LOCALAPPDATA': r'C:\Users\demo\AppData\Local'},
    );
    expect(runtime.transport, TomSecretsTransport.tcp);
    expect(
      runtime.clientPortFile,
      r'C:\Users\demo\AppData\Local\TomSecretsManager\run\client.port',
    );
    expect(runtime.separator, r'\');
  });

  test('Linux paths computed anywhere use slashes', () {
    final runtime = TomSecretsRuntime.current(
      operatingSystem: 'linux',
      environment: const {'XDG_RUNTIME_DIR': '/run/user/1000'},
    );
    expect(runtime.transport, TomSecretsTransport.unix);
    expect(runtime.clientSocket, '/run/user/1000/tsm/client.sock');
    expect(runtime.separator, '/');
  });
}
