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

  test('the handover carries the approval link, checked', () {
    const h = TomSecretsPairingHandover(
      dataDirectory: '/demo/data',
      address: '10.8.0.7',
      port: 47900,
      code: '7-guitar-orbit',
      device: 'bigbeast',
      approvalLink: '10.8.0.1:47731',
    );
    final back = TomSecretsPairingHandover.fromJson(jsonDecode(h.toLine()))!;
    expect(back.approvalLink, '10.8.0.1:47731');
    for (final bad in ['0.0.0.0:47731', '[::]:47731', '10.8.0.1', 'x:0']) {
      expect(
        () => TomSecretsPairingHandover.fromJson({
          ...jsonDecode(h.toLine()) as Map<String, Object?>,
          'approvalLink': bad,
        }),
        throwsFormatException,
        reason: bad,
      );
    }
  });

  test('an approval link is address:port, never every interface; port 0 '
      'only where the system may pick one', () {
    for (final good in [
      '10.8.0.1:47731',
      'bigbeast.vpn:47731',
      '[fd00::1]:47731',
      '127.0.0.1:1',
    ]) {
      expect(tomSecretsApprovalLinkProblem(good), isNull, reason: good);
    }
    for (final bad in [
      '10.8.0.1',
      ':47731',
      '10.8.0.1:0',
      '10.8.0.1:65536',
      '10.8.0.1:x',
      '0.0.0.0:47731',
      '[::]:47731',
      '[fd00::zz]:47731',
      'a b:47731',
      'host/x:47731',
    ]) {
      expect(tomSecretsApprovalLinkProblem(bad), isNotNull, reason: bad);
    }
    expect(tomSecretsApprovalLinkProblem('127.0.0.1:0', anyPort: true), isNull);
    expect(
      tomSecretsApprovalLinkProblem('0.0.0.0:0', anyPort: true),
      contains('every interface'),
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
