// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The manager app's distribution layout: where the app finds the service,
/// and where the service finds the app it admits.
library;

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  test('macOS: the tools in Contents/Resources/tsm/bin, the app in '
      'Contents/MacOS; the two point at each other', () {
    const app = '/Applications/Tom Secrets Manager.app/Contents/MacOS';
    final candidates = tomSecretsServiceCandidates(
      app,
      operatingSystem: 'macos',
    );
    expect(candidates, [
      '$app/tom_secrets_service',
      '$app/../Resources/tsm/bin/tom_secrets_service',
    ]);
    const tools =
        '/Applications/Tom Secrets Manager.app/Contents/Resources/tsm/bin';
    expect(
      tomSecretsDistributionApp(tools, operatingSystem: 'macos'),
      '$tools/../../../MacOS/tom_secrets_app',
    );
  });

  test('Linux and Windows: the tools in <folder>/tsm/bin, the app in '
      '<folder>', () {
    expect(
      tomSecretsServiceCandidates('/opt/tsm-app', operatingSystem: 'linux'),
      [
        '/opt/tsm-app/tom_secrets_service',
        '/opt/tsm-app/tsm/bin/tom_secrets_service',
      ],
    );
    expect(
      tomSecretsDistributionApp(
        '/opt/tsm-app/tsm/bin',
        operatingSystem: 'linux',
      ),
      '/opt/tsm-app/tsm/bin/../../tom_secrets_app',
    );
    expect(
      tomSecretsServiceCandidates(
        r'C:\Apps\TSM',
        operatingSystem: 'windows',
      ).last,
      r'C:\Apps\TSM\tsm\bin\tom_secrets_service.exe',
    );
    expect(
      tomSecretsDistributionApp(
        r'C:\Apps\TSM\tsm\bin',
        operatingSystem: 'windows',
      ),
      r'C:\Apps\TSM\tsm\bin\..\..\tom_secrets_app.exe',
    );
  });
}
