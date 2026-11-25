// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A stand-in for the identity primitives, for this package's tests (which
/// link no post-quantum code): keys of the right lengths, a "signature"
/// anyone holding the *secret* can make and anyone holding the public key
/// can check, and a "KEM" whose shared secret both sides compute. It is no
/// cryptography; the real primitives are tested in `tom_secrets_core` and
/// against the service. Demo keys only.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';

final Random _random = Random(4711);

Uint8List _bytes(int n) =>
    Uint8List.fromList(List.generate(n, (_) => _random.nextInt(256)));

/// A fake identity key pair: the public key is the secret's hash, padded
/// to the real length.
final class FakeIdentityKey {
  FakeIdentityKey() : secret = _bytes(32) {
    publicKey = Uint8List(tomSecretsIdentityKeyLength)
      ..setRange(0, 32, crypto.sha256.convert(secret).bytes);
  }

  final Uint8List secret;
  late final Uint8List publicKey;

  /// The secret itself, then a hash binding it to the message: checked by
  /// hashing the first part back to the public key.
  Uint8List sign(List<int> message, List<int> context) => Uint8List.fromList([
    ...secret,
    ...crypto.sha256.convert([...secret, ...context, ...message]).bytes,
  ]);

  /// The statement that this key was replaced by [next].
  TomSecretsIdentityChange changeTo(FakeIdentityKey next) =>
      TomSecretsIdentityChange(
        from: publicKey,
        to: next.publicKey,
        signature: sign(next.publicKey, tomSecretsIdentityChangeContext),
      );
}

/// A fake one-time key: the shared secret is the hash of the public key
/// and the ciphertext.
final class FakeOneTimeKey {
  FakeOneTimeKey() : publicKey = _bytes(tomSecretsOneTimeKeyLength);

  final Uint8List publicKey;

  Uint8List decapsulate(List<int> ciphertext) => Uint8List.fromList(
    crypto.sha256.convert([...publicKey, ...ciphertext]).bytes,
  );
}

final class FakeIdentityCrypto implements TomSecretsIdentityCrypto {
  const FakeIdentityCrypto();

  @override
  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List context,
  }) async {
    if (signature.length != 64) return false;
    final secret = signature.sublist(0, 32);
    final key = crypto.sha256.convert(secret).bytes;
    final bound = crypto.sha256.convert([
      ...secret,
      ...context,
      ...message,
    ]).bytes;
    return base64.encode(key) == base64.encode(publicKey.sublist(0, 32)) &&
        base64.encode(bound) == base64.encode(signature.sublist(32));
  }

  @override
  Future<({Uint8List ciphertext, Uint8List sharedSecret})> encapsulate(
    Uint8List publicKey,
  ) async {
    final ciphertext = _bytes(48);
    return (
      ciphertext: ciphertext,
      sharedSecret: Uint8List.fromList(
        crypto.sha256.convert([...publicKey, ...ciphertext]).bytes,
      ),
    );
  }
}

/// What a fake service answers an `identify` with.
Map<String, Object?> fakeIdentityAnswer({
  required FakeIdentityKey key,
  required FakeOneTimeKey oneTime,
  required Map<String, Object?> identify,
  required List<int> serviceNonce,
  required int serviceStart,
  List<TomSecretsIdentityChange> changes = const [],
}) => {
  'op': 'identity',
  'publicKey': base64.encode(key.publicKey),
  'oneTimeKey': base64.encode(oneTime.publicKey),
  'signature': base64.encode(
    key.sign(
      tomSecretsIdentityMessage(
        clientNonce: base64.decode(identify['clientNonce']! as String),
        serviceNonce: serviceNonce,
        serviceStart: serviceStart,
        oneTimeKey: oneTime.publicKey,
      ),
      tomSecretsIdentityContext,
    ),
  ),
  if (changes.isNotEmpty) 'changes': [for (final c in changes) c.toJson()],
};

/// An identity check over pins in memory; [firstUse] pins what it meets.
TomSecretsIdentityTrust fakeIdentityTrust({
  TomSecretsServicePins? pins,
  bool firstUse = false,
  String host = 'demo-host',
}) => TomSecretsIdentityTrust(
  pins: pins ?? TomSecretsMemoryPins(),
  crypto: const FakeIdentityCrypto(),
  host: host,
  pinOnFirstUse: firstUse,
);

/// A fake admin endpoint on [runtime] (its Unix socket made the user's
/// alone, or a localhost port in its port file): it sends the challenge,
/// answers `identify` with [key], and hands every other message to
/// [onMessage]; every message is added to [received].
Future<ServerSocket> fakeIdentityEndpoint(
  TomSecretsRuntime runtime, {
  FakeIdentityKey? key,
  List<Map<String, Object?>>? received,
  void Function(Map<String, Object?> message, Socket socket)? onMessage,
}) async {
  final identity = key ?? FakeIdentityKey();
  final ServerSocket server;
  if (runtime.transport == TomSecretsTransport.unix) {
    server = await ServerSocket.bind(
      InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
      0,
    );
    Process.runSync('chmod', ['600', runtime.adminSocket]);
  } else {
    server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    await runtime.writePort(runtime.adminPortFile, server.port);
  }
  server.listen((socket) {
    final nonce = Uint8List(32);
    const start = 1700000000000;
    final reader = TomSecretsFrameReader(
      maxPayload: tomSecretsMaxRequestPayload,
    );
    unawaited(socket.done.catchError((Object _) => socket));
    socket.add(
      tomSecretsJsonFrame({
        'op': 'challenge',
        'serviceNonce': base64.encode(nonce),
        'serviceStart': start,
        'protocol': 1,
        'features': const [tomSecretsIdentityFeature],
      }),
    );
    socket.listen((bytes) {
      for (final frame in reader.add(bytes)) {
        final m = tomSecretsDecodePayload(frame.payload);
        received?.add(m);
        if (m['op'] == 'identify') {
          socket.add(
            tomSecretsJsonFrame(
              fakeIdentityAnswer(
                key: identity,
                oneTime: FakeOneTimeKey(),
                identify: m,
                serviceNonce: nonce,
                serviceStart: start,
              ),
            ),
          );
        } else {
          onMessage?.call(m, socket);
        }
      }
    }, onError: (Object _) {});
  });
  return server;
}
