// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `tsm login` and `tsm logout` (part-key-rotation §3, DP-83): on a
/// headless machine tsm prints the GitHub App's device code, waits for the
/// service's outcome, and signs out again; the service keeps the tokens.
/// GitHub's device flow is a fake. Demo data only.
@TestOn('vm')
library;

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomInMemorySecretStore;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/demo.dart';

/// GitHub's device flow for the App `Iv23demo`: one pending poll, then a
/// user token.
final class _GitHub extends http.BaseClient {
  int polls = 0;
  bool refuse = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    Map<String, Object?> body;
    if (request.url.path == '/login/device/code') {
      body = {
        'device_code': 'demo-device-code',
        'user_code': 'WDJB-MJHT',
        'verification_uri': 'https://github.com/login/device',
        'expires_in': 900,
        'interval': 0,
      };
    } else if (request.url.path == '/login/oauth/access_token') {
      body = refuse
          ? {'error': 'access_denied'}
          : polls++ == 0
          ? {'error': 'authorization_pending'}
          : {
              'access_token': 'ghu_demo',
              'expires_in': 28800,
              'refresh_token': 'ghr_demo',
              'refresh_token_expires_in': 15897600,
            };
    } else if (request.url.path == '/user') {
      body = {'login': 'demo-user'};
    } else {
      return http.StreamedResponse(const Stream.empty(), 404);
    }
    return http.StreamedResponse(
      Stream.value(utf8.encode(jsonEncode(body))),
      200,
      headers: {'content-type': 'application/json'},
    );
  }
}

void main() {
  test('tsm login prints the code and waits: signed in as the user; tsm '
      'logout signs out; refused on GitHub: exit 5', () async {
    final demo = await Demo.create();
    final keychain = TomInMemorySecretStore();
    final github = _GitHub();
    final adminKey = tomSecretsRandomBytes();
    final service = await demo.startInProcess(
      adminKey: adminKey,
      keychain: keychain,
      githubClient: github,
    );
    final admin = await TomSecretsAdminClient.connect(demo.runtime, adminKey);
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    await admin.request('github.app.configure', {'clientId': 'Iv23demo'});
    expect(service.githubAppClientId, 'Iv23demo');

    var r = await demo.tsm(['login'], keychain: keychain);
    expect(r.code, 0, reason: '$r');
    expect(
      r.text,
      'Open https://github.com/login/device and enter the code WDJB-MJHT\n'
      'signed in as demo-user\n',
    );
    expect(r.err, contains('waiting for GitHub'));
    expect(
      await keychain.read(tomSecretsGitHubAppHandle),
      contains('ghu_demo'),
    );

    r = await demo.tsm(['logout'], keychain: keychain);
    expect(r.text, 'signed out\n');
    expect(await keychain.read(tomSecretsGitHubAppHandle), isNull);

    github.refuse = true;
    r = await demo.tsm(['login'], keychain: keychain);
    expect(r.code, 5);
    expect(r.err, contains('not signed in: denied'));
  });
}
