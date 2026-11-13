// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Section 9.7 of protocol.md: the approval link's handshake (Noise KK with
/// every Diffie-Hellman paired with an ML-KEM-768 encapsulation) and its
/// transport. Both roles, so the vectors are produced by one side and read
/// back by the other.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
// ignore: implementation_imports
import 'package:tom_pqc/src/pqc_backend.dart' show pqcBackend;
import 'package:tom_pqc/tom_pqc.dart';

/// The protocol name hashed into the handshake.
const linkProtocolName =
    'tsm-link-v1_KK-hybrid_25519+MLKEM768_ChaChaPoly_SHA256';

/// The handshake failed: a message that does not decrypt, a wrong length, a
/// low-order X25519 point.
final class LinkHandshakeError implements Exception {
  LinkHandshakeError(this.message);
  final String message;
  @override
  String toString() => 'LinkHandshakeError: $message';
}

Uint8List _hmac(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

Uint8List _sha256(List<int> data) =>
    Uint8List.fromList(crypto.sha256.convert(data).bytes);

/// Noise's HKDF with HMAC-SHA256: two 32-byte outputs.
(Uint8List, Uint8List) noiseHkdf(List<int> chainingKey, List<int> ikm) {
  final temp = _hmac(chainingKey, ikm);
  final out1 = _hmac(temp, [1]);
  final out2 = _hmac(temp, [...out1, 2]);
  return (out1, out2);
}

/// The nonce of ChaCha20-Poly1305 in Noise: 4 zero bytes, then the counter
/// as 8 bytes little-endian.
Uint8List noiseNonce(int n) {
  final nonce = Uint8List(12);
  var v = n;
  for (var i = 4; i < 12; i++) {
    nonce[i] = v & 0xff;
    v >>= 8;
  }
  return nonce;
}

final _aead = Chacha20.poly1305Aead();

Future<Uint8List> aeadEncrypt(
  List<int> key,
  int n,
  List<int> ad,
  List<int> plaintext,
) async {
  final box = await _aead.encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: noiseNonce(n),
    aad: ad,
  );
  return Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
}

Future<Uint8List> aeadDecrypt(
  List<int> key,
  int n,
  List<int> ad,
  List<int> ciphertext,
) async {
  if (ciphertext.length < 16) throw LinkHandshakeError('short ciphertext');
  try {
    return Uint8List.fromList(
      await _aead.decrypt(
        SecretBox(
          ciphertext.sublist(0, ciphertext.length - 16),
          nonce: noiseNonce(n),
          mac: Mac(ciphertext.sublist(ciphertext.length - 16)),
        ),
        secretKey: SecretKey(key),
        aad: ad,
      ),
    );
  } on SecretBoxAuthenticationError {
    throw LinkHandshakeError('a frame does not decrypt');
  }
}

/// Noise's REKEY: the first 32 bytes of ENCRYPT(k, 2^64 - 1, empty, zeros).
Future<Uint8List> rekey(List<int> key) async {
  final box = await _aead.encrypt(
    Uint8List(32),
    secretKey: SecretKey(key),
    nonce: Uint8List.fromList([
      0,
      0,
      0,
      0,
      255,
      255,
      255,
      255,
      255,
      255,
      255,
      255,
    ]),
  );
  return Uint8List.fromList(box.cipherText.sublist(0, 32));
}

/// Noise's symmetric state with SHA-256, plus a record of every step for the
/// vectors.
final class SymmetricState {
  SymmetricState() {
    final name = utf8.encode(linkProtocolName);
    h = name.length <= 32
        ? Uint8List.fromList([...name, ...Uint8List(32 - name.length)])
        : _sha256(name);
    ck = Uint8List.fromList(h);
  }

  late Uint8List h;
  late Uint8List ck;
  Uint8List? k;
  int n = 0;

  void mixHash(List<int> data) => h = _sha256([...h, ...data]);

  void mixKey(List<int> ikm) {
    final (newCk, tempK) = noiseHkdf(ck, ikm);
    ck = newCk;
    k = tempK;
    n = 0;
  }

  Future<Uint8List> encryptAndHash(List<int> plaintext) async {
    final c = await aeadEncrypt(k!, n++, h, plaintext);
    mixHash(c);
    return c;
  }

  Future<Uint8List> decryptAndHash(List<int> ciphertext) async {
    final p = await aeadDecrypt(k!, n++, h, ciphertext);
    mixHash(ciphertext);
    return p;
  }

  (Uint8List, Uint8List) split() => noiseHkdf(ck, const []);
}

/// One side's static link key pair: X25519 and ML-KEM-768.
final class LinkKey {
  LinkKey._(this.x25519, this.x25519Public, this.mlKem);

  final SimpleKeyPair x25519;
  final Uint8List x25519Public;
  final MlKem768KeyPair mlKem;

  Uint8List get mlKemPublic => mlKem.publicKey;

  static Future<LinkKey> fromSeeds(
    Uint8List x25519Seed,
    Uint8List mlKemSeed,
  ) async {
    final x = await X25519().newKeyPairFromSeed(x25519Seed);
    final xp = Uint8List.fromList((await x.extractPublicKey()).bytes);
    return LinkKey._(
      x,
      xp,
      MlKem768.keyPairFromSeed(SecretBytes.fromBytes(mlKemSeed)),
    );
  }
}

/// The public halves the peer recorded at pairing.
typedef LinkPublic = ({Uint8List x25519, Uint8List mlKem});

Future<Uint8List> _dh(SimpleKeyPair mine, List<int> theirs) async {
  if (theirs.length != 32) throw LinkHandshakeError('X25519 key length');
  final secret = await X25519().sharedSecretKey(
    keyPair: mine,
    remotePublicKey: SimplePublicKey(theirs, type: KeyPairType.x25519),
  );
  final bytes = Uint8List.fromList(await secret.extractBytes());
  if (bytes.every((b) => b == 0)) {
    throw LinkHandshakeError('low-order X25519 point');
  }
  return bytes;
}

/// The randomness of one side's handshake, fixed in the vectors.
typedef InitiatorRandom = ({
  Uint8List ephemeralX25519Seed,
  Uint8List ephemeralMlKemSeed,
  Uint8List coinsToResponderStatic,
});
typedef ResponderRandom = ({
  Uint8List ephemeralX25519Seed,
  Uint8List coinsToInitiatorEphemeral,
  Uint8List coinsToInitiatorStatic,
});

/// The keys a finished handshake yields.
typedef LinkSession = ({
  Uint8List initiatorToResponder,
  Uint8List responderToInitiator,
  Uint8List handshakeHash,
});

void _mixStatics(SymmetricState s, LinkPublic initiator, LinkPublic responder) {
  s
    ..mixHash(initiator.x25519)
    ..mixHash(initiator.mlKem)
    ..mixHash(responder.x25519)
    ..mixHash(responder.mlKem);
}

/// The approver's side (the initiator, who connects).
final class Initiator {
  Initiator(this.me, this.mePublic, this.responder, this.random);

  final LinkKey me;
  final LinkPublic mePublic;
  final LinkPublic responder;
  final InitiatorRandom random;
  final state = SymmetricState();
  late SimpleKeyPair _e;
  late MlKem768KeyPair _eKem;

  /// Message 1: e (32) || ephemeral ML-KEM key (1,184) || ciphertext to the
  /// responder's static ML-KEM key (1,088) || encrypted payload.
  Future<Uint8List> writeMessage1(List<int> payload) async {
    _mixStatics(state, mePublic, responder);
    _e = await X25519().newKeyPairFromSeed(random.ephemeralX25519Seed);
    final ePub = (await _e.extractPublicKey()).bytes;
    state.mixHash(ePub);
    _eKem = MlKem768.keyPairFromSeed(
      SecretBytes.fromBytes(random.ephemeralMlKemSeed),
    );
    state.mixHash(_eKem.publicKey);
    state.mixKey(await _dh(_e, responder.x25519)); // es
    state.mixKey(await _dh(me.x25519, responder.x25519)); // ss
    final sent = pqcBackend.mlKem768Encapsulate(
      responder.mlKem,
      coins: random.coinsToResponderStatic,
    );
    state.mixHash(sent.ciphertext);
    state.mixKey(sent.sharedSecret.extractBytes());
    sent.sharedSecret.dispose();
    final c = await state.encryptAndHash(payload);
    return Uint8List.fromList([
      ...ePub,
      ..._eKem.publicKey,
      ...sent.ciphertext,
      ...c,
    ]);
  }

  /// Reads message 2 and returns its payload and the session.
  Future<(Uint8List, LinkSession)> readMessage2(Uint8List message) async {
    const fixed = 32 + 1088 + 1088;
    if (message.length < fixed + 16) {
      throw LinkHandshakeError('message 2 length');
    }
    final re = message.sublist(0, 32);
    final c1 = message.sublist(32, 32 + 1088);
    final c2 = message.sublist(32 + 1088, fixed);
    state.mixHash(re);
    state.mixKey(await _dh(_e, re)); // ee
    state.mixKey(await _dh(me.x25519, re)); // se
    state.mixHash(c1);
    final k1 = MlKem768.decapsulate(c1, _eKem.secretKey);
    state.mixKey(k1.extractBytes());
    k1.dispose();
    state.mixHash(c2);
    final k2 = MlKem768.decapsulate(c2, me.mlKem.secretKey);
    state.mixKey(k2.extractBytes());
    k2.dispose();
    final payload = await state.decryptAndHash(message.sublist(fixed));
    final (i2r, r2i) = state.split();
    _eKem.dispose();
    return (
      payload,
      (
        initiatorToResponder: i2r,
        responderToInitiator: r2i,
        handshakeHash: state.h,
      ),
    );
  }
}

/// The host's side (the responder).
final class Responder {
  Responder(this.me, this.mePublic, this.initiator, this.random);

  final LinkKey me;
  final LinkPublic mePublic;
  final LinkPublic initiator;
  final ResponderRandom random;
  final state = SymmetricState();
  late Uint8List _re;
  late Uint8List _reKem;

  Future<Uint8List> readMessage1(Uint8List message) async {
    const fixed = 32 + 1184 + 1088;
    if (message.length < fixed + 16) {
      throw LinkHandshakeError('message 1 length');
    }
    _mixStatics(state, initiator, mePublic);
    _re = message.sublist(0, 32);
    _reKem = message.sublist(32, 32 + 1184);
    final c = message.sublist(32 + 1184, fixed);
    state.mixHash(_re);
    state.mixHash(_reKem);
    state.mixKey(await _dh(me.x25519, _re)); // es
    state.mixKey(await _dh(me.x25519, initiator.x25519)); // ss
    state.mixHash(c);
    final k = MlKem768.decapsulate(c, me.mlKem.secretKey);
    state.mixKey(k.extractBytes());
    k.dispose();
    return state.decryptAndHash(message.sublist(fixed));
  }

  /// Message 2: e (32) || ciphertext to the initiator's ephemeral ML-KEM key
  /// (1,088) || ciphertext to its static ML-KEM key (1,088) || encrypted
  /// payload.
  Future<(Uint8List, LinkSession)> writeMessage2(List<int> payload) async {
    final e = await X25519().newKeyPairFromSeed(random.ephemeralX25519Seed);
    final ePub = (await e.extractPublicKey()).bytes;
    state.mixHash(ePub);
    state.mixKey(await _dh(e, _re)); // ee
    state.mixKey(await _dh(e, initiator.x25519)); // se
    final s1 = pqcBackend.mlKem768Encapsulate(
      _reKem,
      coins: random.coinsToInitiatorEphemeral,
    );
    state.mixHash(s1.ciphertext);
    state.mixKey(s1.sharedSecret.extractBytes());
    s1.sharedSecret.dispose();
    final s2 = pqcBackend.mlKem768Encapsulate(
      initiator.mlKem,
      coins: random.coinsToInitiatorStatic,
    );
    state.mixHash(s2.ciphertext);
    state.mixKey(s2.sharedSecret.extractBytes());
    s2.sharedSecret.dispose();
    final c = await state.encryptAndHash(payload);
    final (i2r, r2i) = state.split();
    return (
      Uint8List.fromList([...ePub, ...s1.ciphertext, ...s2.ciphertext, ...c]),
      (
        initiatorToResponder: i2r,
        responderToInitiator: r2i,
        handshakeHash: state.h,
      ),
    );
  }
}

/// One direction of the transport: ChaCha20-Poly1305 with a counter nonce,
/// empty associated data, and REKEY on a `rekey` message.
final class TransportCipher {
  TransportCipher(this.key);

  Uint8List key;
  int n = 0;

  Future<Uint8List> encrypt(List<int> plaintext) =>
      aeadEncrypt(key, n++, const [], plaintext);

  Future<Uint8List> decrypt(List<int> ciphertext) =>
      aeadDecrypt(key, n++, const [], ciphertext);

  Future<void> rekeyNow() async => key = await rekey(key);
}

/// A frame on the ApprovalChannel: the length as 4 bytes big-endian, then the
/// bytes.
Uint8List channelFrame(List<int> bytes) => Uint8List.fromList([
  (bytes.length >> 24) & 0xff,
  (bytes.length >> 16) & 0xff,
  (bytes.length >> 8) & 0xff,
  bytes.length & 0xff,
  ...bytes,
]);
