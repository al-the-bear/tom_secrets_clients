// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's pairing mode lines (`tsm pair`): the handover and the
/// report read back as written; a start handover is no pairing handover; a
/// pairing handover missing a member is refused. Demo data only.
library;

import 'dart:convert';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';

void main() {
  test('the handover reads back; a start handover is none', () {
    const h = TomSecretsPairingHandover(
      dataDirectory: '/demo/data',
      address: '10.8.0.7',
      port: 47900,
      code: '7-guitar-orbit',
      device: 'bigbeast',
      deviceKey: 'vault',
    );
    final line = h.toLine();
    final back = TomSecretsPairingHandover.fromJson(jsonDecode(line))!;
    expect(back.toLine(), line);
    expect(back.deviceKey, 'vault');
    expect(
      TomSecretsPairingHandover.fromJson({
        'adminKey': 'AAAA',
        'bootstrap': '/demo/bootstrap.yaml',
      }),
      isNull,
    );
    expect(
      () => TomSecretsPairingHandover.fromJson({
        'mode': 'pair',
        'dataDirectory': '/demo/data',
        'address': '10.8.0.7',
        'port': 0,
        'code': '7-guitar-orbit',
        'device': 'bigbeast',
      }),
      throwsFormatException,
    );
    expect(
      () => TomSecretsPairingHandover.fromJson({'mode': 'pair', 'port': 1}),
      throwsFormatException,
    );
  });

  test('the report reads back', () {
    const r = TomSecretsPairingReport(
      giver: 'mbp',
      vaults: [
        (name: 'primary', locator: 'file:/demo/primary.kdbx', primary: true),
        (
          name: 'team',
          locator: 'github:al-the-bear/demo-vaults/team.kdbx',
          primary: false,
        ),
      ],
      config: true,
      tokens: ['al-the-bear/demo-vaults'],
    );
    final back = TomSecretsPairingReport.fromJson(
      (jsonDecode(jsonEncode(r.toJson())) as Map).cast(),
    );
    expect(back.toJson(), r.toJson());
    expect(back.vaults.first.primary, isTrue);
  });
}
