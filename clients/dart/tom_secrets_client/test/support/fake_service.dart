// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A scripted stand-in for the secrets service's client endpoint: a Unix
/// socket (or, as on Windows, a localhost port with client.port and
/// client.token) in a runtime directory, answering `hello` with `welcome`
/// and every other request through [FakeService.onRequest]. It records every
/// message it receives.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/tom_secrets_client.dart';

/// Answers one request on [connection].
typedef FakeHandler =
    FutureOr<void> Function(
      FakeConnection connection,
      Map<String, Object?> request,
    );

/// The welcome the fake sends unless told otherwise.
Map<String, Object?> fakeWelcome({List<String> features = const []}) => {
  'op': 'welcome',
  'protocol': 1,
  'service': {'version': '0.1.0'},
  'features': features,
  'host': 'bomber',
  'platform': 'linux',
  'unknownMember': 'ignored by the client',
};

/// A value message for [id].
Map<String, Object?> fakeValue(
  int id,
  String value, {
  String encoding = 'utf8',
  Map<String, Object?> extra = const {},
}) => {
  'op': 'value',
  'id': id,
  'value': value,
  'encoding': encoding,
  'entry': {
    'store': 'fleet',
    'uuid': '0f3c2a1b4d5e6f708192a3b4c5d6e7f8',
    'source': 'github',
    'fetchedAt': '2026-11-13T08:59:30Z',
  },
  'bound': {'env': 'prod'},
  'version': {'modified': '2026-11-01T12:00:00Z', 'revision': 'b1946ac9'},
  ...extra,
};

/// One accepted connection.
final class FakeConnection {
  FakeConnection._(this._socket, this._service);
  final Socket _socket;
  final FakeService _service;
  final TomSecretsFrameReader _reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxRequestPayload,
  );

  /// Sends a JSON message.
  void send(Map<String, Object?> message) => _socket.add(
    tomSecretsEncodeFrame(
      tomSecretsFrameJson,
      utf8.encode(jsonEncode(message)),
    ),
  );

  /// Sends raw bytes.
  void sendRaw(List<int> bytes) => _socket.add(bytes);

  /// Closes the connection.
  void close() => _socket.destroy();

  void _onData(List<int> bytes) {
    for (final frame in _reader.add(bytes)) {
      final message = tomSecretsDecodePayload(frame.payload);
      _service.received.add(message);
      if (message['op'] == 'hello') {
        _service.hellos.add(message);
        final onHello = _service.onHello;
        if (onHello != null) {
          final result = onHello(this, message);
          if (result is Future) unawaited(result);
        } else {
          send(_service.welcome);
        }
      } else {
        final result = _service.onRequest(this, message);
        if (result is Future) unawaited(result);
      }
    }
  }
}

/// The fake service.
final class FakeService {
  FakeService._(this._server, this.directory, this.onRequest);

  /// Starts it in [directory]: a Unix socket `client.sock`, or with
  /// [windows] a localhost port in `client.port` and [token] in
  /// `client.token`.
  static Future<FakeService> start(
    Directory directory, {
    required FakeHandler onRequest,
    bool windows = false,
    String token = 'dG9rZW4tb2YtdGhpcy1zZXJ2aWNlLXN0YXJ0LTAwMDA=',
  }) async {
    final ServerSocket server;
    if (windows) {
      server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      // The names the client derives with Windows separators; on a POSIX
      // test host they are literal file names beside the directory.
      File(
        '${directory.path}\\client.port',
      ).writeAsStringSync('${server.port}\n');
      File('${directory.path}\\client.token').writeAsStringSync('$token\r\n');
    } else {
      final socket = File('${directory.path}/client.sock');
      if (socket.existsSync()) socket.deleteSync();
      server = await ServerSocket.bind(
        InternetAddress(socket.path, type: InternetAddressType.unix),
        0,
      );
    }
    final service = FakeService._(server, directory, onRequest);
    server.listen((socket) {
      service.connections++;
      final connection = FakeConnection._(socket, service);
      service._open.add(connection);
      socket.listen(
        connection._onData,
        onError: (_) {},
        onDone: socket.destroy,
      );
    });
    return service;
  }

  final ServerSocket _server;

  /// The runtime directory.
  final Directory directory;

  /// Answers every request but `hello`.
  FakeHandler onRequest;

  /// Answers `hello` instead of [welcome], when set.
  FakeHandler? onHello;

  /// The `welcome` sent to a `hello`.
  Map<String, Object?> welcome = fakeWelcome();

  /// Every message received, in order.
  final List<Map<String, Object?>> received = [];

  /// Every `hello` received.
  final List<Map<String, Object?>> hellos = [];

  /// How many connections were accepted.
  int connections = 0;
  final List<FakeConnection> _open = [];

  /// Drops every open connection (a service restart, seen by the client).
  void dropConnections() {
    for (final c in _open) {
      c.close();
    }
    _open.clear();
  }

  /// Stops listening and drops every connection.
  Future<void> stop() async {
    dropConnections();
    await _server.close();
    final socket = File('${directory.path}/client.sock');
    if (socket.existsSync()) socket.deleteSync();
  }
}
