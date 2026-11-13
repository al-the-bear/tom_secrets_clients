// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The fake secrets service of the conformance suite: it speaks the client
/// endpoint of the protocol from a script and records every frame it
/// receives. It needs no vault and no client library: its framing is its own,
/// written from protocol.md section 2, so a library is measured against the
/// document, not against itself.
///
/// The script (a JSON object, conformance/README.md):
///
/// - `welcome`: members merged into the default `welcome`;
/// - `hello`: steps sent instead of the `welcome` (e.g. an `error`);
/// - `rules`: `{match: {op, ref?}, times?, holdUntil?, reply: [step]}`, the
///   first rule that matches a request and still has `times` left answers it.
///
/// A step is `{send: message}` (`"$id"` becomes the request's id, `"$ref"`
/// its reference),
/// `{raw: hex}`, `{delayMs: n}`, `{close: true}` (this connection),
/// `{restart: true}` (every connection dropped, a new socket or port and a
/// new client token, as at a service start) or `{file: {name, contentHex,
/// chunkSize?, sha256?}}` (a getFile answer: `file`, binary chunks, `end`).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// The largest payload a client may send (protocol.md 2.3).
const int maxRequestPayload = 64 * 1024;

/// The welcome sent unless the script overrides members of it.
const Map<String, Object?> defaultWelcome = {
  'op': 'welcome',
  'protocol': 1,
  'service': {'version': 'conformance'},
  'features': <String>[],
  'host': 'conformance-host',
  'platform': 'linux',
};

/// One frame received, as recorded.
final class Received {
  Received(this.connection, {this.message, this.invalid});

  /// Which connection (1, 2, ...) it came on.
  final int connection;

  /// The JSON message, or null when the frame was invalid.
  final Map<String, Object?>? message;

  /// Why the frame was invalid.
  final String? invalid;

  /// As written to the record file.
  Map<String, Object?> toJson() => {
    'connection': connection,
    'message': ?message,
    'invalid': ?invalid,
  };
}

/// The fake service.
final class FakeService {
  FakeService._(this.directory, this.script, this.transport);

  /// Starts it in [directory] with [script]; [transport] is `unix` (a
  /// socket `client.sock`) or `tcp` (a localhost port in `client.port` and a
  /// token in `client.token`, as on Windows).
  static Future<FakeService> start({
    required String directory,
    required Map<String, Object?> script,
    required String transport,
  }) async {
    final service = FakeService._(directory, script, transport);
    final rules = (script['rules'] as List? ?? const []).cast<Map>();
    service._rules.addAll([
      for (final r in rules) _Rule(r.cast<String, Object?>()),
    ]);
    await service._bind();
    return service;
  }

  /// The runtime directory.
  final String directory;

  /// The script.
  final Map<String, Object?> script;

  /// `unix` or `tcp`.
  final String transport;

  /// Every frame received, in order.
  final List<Received> received = [];

  /// How many connections were accepted.
  int connections = 0;

  /// How many times the service started (1 + restarts).
  int starts = 0;

  /// The client token of the current start (tcp).
  String token = '';

  final List<_Rule> _rules = [];
  final Set<_Connection> _open = {};
  ServerSocket? _server;

  String get _socketPath => '$directory/client.sock';

  Future<void> _bind() async {
    starts++;
    if (transport == 'tcp') {
      _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      token = base64.encode(
        List.generate(32, (i) => (starts * 31 + i * 7) & 0xff),
      );
      // The names a client derives with Windows separators.
      File('$directory\\client.port').writeAsStringSync('${_server!.port}\n');
      File('$directory\\client.token').writeAsStringSync('$token\r\n');
    } else {
      final socket = File(_socketPath);
      if (socket.existsSync()) socket.deleteSync();
      _server = await ServerSocket.bind(
        InternetAddress(_socketPath, type: InternetAddressType.unix),
        0,
      );
    }
    _server!.listen((socket) {
      connections++;
      final connection = _Connection(this, socket, connections);
      _open.add(connection);
    });
  }

  /// A service start: every connection dropped, a new socket or port and a
  /// new token.
  Future<void> restart() async {
    for (final c in [..._open]) {
      c.close();
    }
    await _server?.close();
    await _bind();
  }

  /// Stops listening and drops every connection.
  Future<void> stop() async {
    for (final c in [..._open]) {
      c.close();
    }
    await _server?.close();
    final socket = File(_socketPath);
    if (transport == 'unix' && socket.existsSync()) socket.deleteSync();
  }

  /// The record written for the harness.
  Map<String, Object?> record() => {
    'connections': connections,
    'starts': starts,
    'received': [for (final r in received) r.toJson()],
  };

  _Rule? _ruleFor(Map<String, Object?> request) {
    for (final rule in _rules) {
      if (rule.matches(request)) return rule;
    }
    return null;
  }
}

final class _Rule {
  _Rule(this.spec)
    : match = (spec['match'] as Map? ?? const {}).cast<String, Object?>(),
      remaining = spec['times'] as int? ?? -1,
      holdUntil = spec['holdUntil'] as int? ?? 0;

  final Map<String, Object?> spec;
  final Map<String, Object?> match;
  int remaining;
  final int holdUntil;
  final List<(_Connection, Map<String, Object?>)> held = [];

  List<Map<String, Object?>> get reply =>
      (spec['reply'] as List? ?? const []).cast<Map>().map((m) {
        return m.cast<String, Object?>();
      }).toList();

  bool matches(Map<String, Object?> request) {
    if (remaining == 0) return false;
    for (final MapEntry(:key, :value) in match.entries) {
      if (request[key] != value) return false;
    }
    return true;
  }
}

final class _Connection {
  _Connection(this.service, this.socket, this.number) {
    _subscription = socket.listen(
      _onData,
      onError: (Object _) => close(),
      onDone: close,
    );
  }

  final FakeService service;
  final Socket socket;
  final int number;
  late final StreamSubscription<Uint8List> _subscription;
  final BytesBuilder _buffer = BytesBuilder(copy: false);
  bool _closed = false;
  bool _helloSeen = false;
  bool _binary = false;
  Future<void> _queue = Future.value();

  void close() {
    if (_closed) return;
    _closed = true;
    service._open.remove(this);
    unawaited(_subscription.cancel());
    socket.destroy();
  }

  void _record(Map<String, Object?>? message, [String? invalid]) {
    service.received.add(Received(number, message: message, invalid: invalid));
  }

  void _onData(Uint8List bytes) {
    _buffer.add(bytes);
    var data = _buffer.takeBytes();
    var offset = 0;
    while (data.length - offset >= 5) {
      final length = ByteData.sublistView(data, offset).getUint32(0);
      final type = data[offset + 4];
      if (length > maxRequestPayload) {
        _record(null, 'frame of $length bytes over $maxRequestPayload');
        close();
        return;
      }
      if (type != 0) {
        _record(null, 'frame type $type');
        close();
        return;
      }
      if (data.length - offset - 5 < length) break;
      final payload = data.sublist(offset + 5, offset + 5 + length);
      offset += 5 + length;
      Map<String, Object?>? message;
      try {
        final decoded = jsonDecode(utf8.decode(payload));
        if (decoded is Map<String, Object?> && decoded['op'] is String) {
          message = decoded;
        }
      } on FormatException {
        message = null;
      }
      if (message == null) {
        _record(null, 'malformed payload');
        _sendNow({'op': 'error', 'kind': 'malformed', 'message': 'malformed'});
        close();
        return;
      }
      _record(message);
      _enqueue(() => _handle(message!));
    }
    _buffer.add(data.sublist(offset));
    data = Uint8List(0);
  }

  void _enqueue(Future<void> Function() step) {
    _queue = _queue.then((_) => _closed ? null : step());
  }

  Future<void> _handle(Map<String, Object?> message) async {
    if (!_helloSeen) {
      _helloSeen = true;
      if (message['op'] != 'hello') {
        _sendNow({'op': 'error', 'kind': 'malformed', 'message': 'not hello'});
        close();
        return;
      }
      final features = message['features'];
      final hello = service.script['hello'];
      if (hello is List) {
        await _run(hello.cast<Map>(), message);
        return;
      }
      final welcome = {
        ...defaultWelcome,
        ...(service.script['welcome'] as Map? ?? const {})
            .cast<String, Object?>(),
      };
      final offered = (welcome['features']! as List).cast<String>();
      _binary =
          offered.contains('binary') &&
          features is List &&
          features.contains('binary');
      _sendNow(welcome);
      return;
    }
    final rule = service._ruleFor(message);
    if (rule == null) {
      _sendNow({
        'op': 'error',
        if (message['id'] != null) 'id': message['id'],
        'kind': 'internal',
        'message': 'the fake service has no rule for ${message['op']}',
        'details': {'code': 'no_rule'},
      });
      return;
    }
    if (rule.remaining > 0) rule.remaining--;
    if (rule.holdUntil > 0) {
      rule.held.add((this, message));
      if (rule.held.length < rule.holdUntil) return;
      // Answer the held requests in reverse order: overlapping requests whose
      // answers come out of order.
      for (final (connection, request) in rule.held.reversed.toList()) {
        await connection._run(rule.reply.cast<Map>(), request);
      }
      rule.held.clear();
      return;
    }
    await _run(rule.reply.cast<Map>(), message);
  }

  Future<void> _run(List<Map> steps, Map<String, Object?> request) async {
    for (final raw in steps) {
      final step = raw.cast<String, Object?>();
      if (_closed && !step.containsKey('restart')) return;
      if (step['send'] case final Map send) {
        _sendNow(_substitute(send, request) as Map<String, Object?>);
      } else if (step['raw'] case final String hex) {
        socket.add(_hex(hex));
      } else if (step['delayMs'] case final int ms) {
        await Future<void>.delayed(Duration(milliseconds: ms));
      } else if (step['close'] == true) {
        close();
      } else if (step['restart'] == true) {
        await service.restart();
      } else if (step['file'] case final Map file) {
        _sendFile(file.cast<String, Object?>(), request['id']! as int);
      } else {
        throw StateError('unknown script step $step');
      }
    }
  }

  void _sendFile(Map<String, Object?> file, int id) {
    final content = _hex(file['contentHex']! as String);
    final chunkSize = file['chunkSize'] as int? ?? 1024;
    _sendNow({
      'op': 'file',
      'id': id,
      'name': file['name'],
      'size': content.length,
    });
    if (!_binary) return; // a service sends no binary frame un-negotiated
    for (var at = 0; at < content.length; at += chunkSize) {
      final chunk = content.sublist(at, min(at + chunkSize, content.length));
      final payload = Uint8List(8 + chunk.length);
      ByteData.sublistView(payload).setUint64(0, id);
      payload.setRange(8, payload.length, chunk);
      socket.add(_frame(1, payload));
    }
    _sendNow({
      'op': 'end',
      'id': id,
      'sha256': file['sha256'] ?? crypto.sha256.convert(content).toString(),
    });
  }

  void _sendNow(Map<String, Object?> message) {
    if (_closed) return;
    socket.add(_frame(0, utf8.encode(jsonEncode(message))));
  }

  /// `"$id"` becomes the request's id, `"$ref"` its reference.
  Object? _substitute(Object? value, Map<String, Object?> request) =>
      switch (value) {
        '\$id' => request['id'],
        '\$ref' => request['ref'],
        Map m => {
          for (final MapEntry(:key, :value) in m.entries)
            key as String: _substitute(value, request),
        },
        List l => [for (final v in l) _substitute(v, request)],
        _ => value,
      };
}

Uint8List _frame(int type, List<int> payload) {
  final out = Uint8List(5 + payload.length);
  ByteData.sublistView(out).setUint32(0, payload.length);
  out[4] = type;
  out.setRange(5, out.length, payload);
  return out;
}

Uint8List _hex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);
