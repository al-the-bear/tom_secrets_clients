// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The client endpoint (protocol.md section 5): the connection, `hello`,
/// `get`, `getMany` and `getFile` [B].
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'discovery.dart';
import 'errors.dart';
import 'frames.dart';
import 'reference.dart';
import 'value.dart';
import 'version.dart';

/// Receives the progress notices of a waiting request.
typedef TomSecretsProgressCallback = void Function(TomSecretsProgress progress);

/// What the service said in `welcome`.
final class TomSecretsWelcome {
  /// The welcome's members.
  const TomSecretsWelcome({
    required this.protocol,
    required this.serviceVersion,
    required this.features,
    required this.host,
    required this.platform,
  });

  /// The protocol version spoken on this connection.
  final int protocol;

  /// The service's version.
  final String serviceVersion;

  /// The optional features the service offers (section 8).
  final Set<String> features;

  /// The service's host name (the current value of the `host` dimension).
  final String host;

  /// `macos`, `linux`, `windows`, `ios` or `android`.
  final String platform;
}

/// The protocol version this library speaks.
const int tomSecretsProtocol = 1;

/// The features this library takes: binary frames and `getFile` [B].
const List<String> tomSecretsClientFeatures = ['binary', 'getFile'];

/// The most references one `getMany` carries.
const int tomSecretsMaxGetMany = 256;

/// A client of the Tom Secrets Manager's secrets service.
///
/// One connection, opened by the first call (or [open]); after `not_running`
/// or a dropped connection the next call connects again. Calls may overlap.
/// A Dart isolate has its own client; there is no `fork` to guard against.
/// The library logs nothing: no value, token or payload.
final class TomSecretsClient {
  /// A client that connects on its first call.
  ///
  /// - [clientName]: shown in approval prompts, never trusted; default the
  ///   executable's name.
  /// - [clientToken]: a client token the program was given before (7.4),
  ///   sent in every `hello`; the library never stores one itself.
  /// - [environment] and [operatingSystem]: where the service is looked for
  ///   (default the process's; `TSM_RUNTIME_DIR` names the directory for
  ///   containers and tests).
  /// - [connectTimeout]: how long connecting and the `welcome` may take.
  TomSecretsClient({
    String? clientName,
    this.clientToken,
    Map<String, String>? environment,
    String? operatingSystem,
    this.connectTimeout = const Duration(seconds: 10),
  }) : clientName = clientName ?? _executableName(),
       _environment = environment ?? Platform.environment,
       _operatingSystem = operatingSystem ?? Platform.operatingSystem;

  /// Creates a client and connects it, so a missing service shows at once
  /// (`not_running`).
  static Future<TomSecretsClient> connect({
    String? clientName,
    String? clientToken,
    Map<String, String>? environment,
    String? operatingSystem,
    Duration connectTimeout = const Duration(seconds: 10),
  }) async {
    final client = TomSecretsClient(
      clientName: clientName,
      clientToken: clientToken,
      environment: environment,
      operatingSystem: operatingSystem,
      connectTimeout: connectTimeout,
    );
    await client.open();
    return client;
  }

  /// The process's shared client, created on first use with the defaults.
  static TomSecretsClient get shared => _shared ??= TomSecretsClient();
  static TomSecretsClient? _shared;

  /// The name `hello` gives the program.
  final String clientName;

  /// The client token sent in every `hello`, when the program has one.
  final String? clientToken;

  /// How long connecting and the `welcome` may take.
  final Duration connectTimeout;
  final Map<String, String> _environment;
  final String _operatingSystem;

  _Connection? _connection;
  Future<_Connection>? _connecting;

  /// The `welcome` of the current connection, or null when not connected.
  TomSecretsWelcome? get welcome =>
      _connection?.closed ?? true ? null : _connection!.welcome;

  /// Connects, unless a connection is open.
  Future<void> open() async {
    await _ensureConnection();
  }

  /// Closes the connection; a later call connects again.
  Future<void> close() async {
    final connection = _connection;
    _connection = null;
    await connection?.close();
  }

  /// Reads one secret.
  ///
  /// [reference] is parsed locally first; a malformed one fails as
  /// `malformed` without a round trip. [field] names the field when the
  /// reference names none (the same field in both is sent once; two
  /// different ones are `malformed`, reason `field_twice`). With [wait]
  /// (default true) the service waits for an unlock or an approval, up to
  /// [timeout] (sent as `timeoutMs`, capped by the service); [onProgress]
  /// hears why it waits, with the approval code when there is one.
  /// [wantClientToken] asks for a client token with an "always" approval.
  /// With [waitOnRateLimit] a `rate_limited` answer is waited out and the
  /// request sent again; `denied`, `ambiguous` and `not_found` are never
  /// retried.
  Future<TomSecretValue> get(
    String reference, {
    String? field,
    Map<String, String>? dimensions,
    bool wait = true,
    Duration? timeout,
    bool wantClientToken = false,
    TomSecretsProgressCallback? onProgress,
    bool waitOnRateLimit = false,
  }) async {
    final item = _item(reference, field, dimensions);
    final answer = await _request(
      {
        'op': 'get',
        ...item,
        if (!wait) 'wait': false,
        if (timeout != null) 'timeoutMs': timeout.inMilliseconds,
        if (wantClientToken) 'wantClientToken': true,
      },
      onProgress: onProgress,
      waitOnRateLimit: waitOnRateLimit,
    );
    return _valueOf(reference, answer);
  }

  /// Reads several secrets under one approval prompt (1 to 256); the results
  /// come in request order, each a value or an error. Every reference is
  /// parsed locally first.
  Future<List<TomSecretResult>> getMany(
    List<TomSecretRequest> requests, {
    bool wait = true,
    Duration? timeout,
    TomSecretsProgressCallback? onProgress,
    bool waitOnRateLimit = false,
  }) async {
    if (requests.isEmpty || requests.length > tomSecretsMaxGetMany) {
      throw ArgumentError.value(
        requests.length,
        'requests',
        'a getMany carries 1 to $tomSecretsMaxGetMany references',
      );
    }
    final items = [
      for (final r in requests) _item(r.reference, r.field, r.dimensions),
    ];
    final answer = await _request(
      {
        'op': 'getMany',
        'refs': items,
        if (!wait) 'wait': false,
        if (timeout != null) 'timeoutMs': timeout.inMilliseconds,
      },
      onProgress: onProgress,
      waitOnRateLimit: waitOnRateLimit,
    );
    if (answer['op'] != 'values' || answer['results'] is! List) {
      throw _protocolError('getMany was answered ${answer['op']}');
    }
    final results = (answer['results']! as List).cast<Object?>();
    if (results.length != requests.length) {
      throw _protocolError('getMany got ${results.length} results');
    }
    return [
      for (var i = 0; i < results.length; i++)
        _resultOf(requests[i].reference, results[i]),
    ];
  }

  /// **[B]** Reads an attachment or a typed key as bytes, over binary
  /// frames. Fails as `unsupported` when the service does not offer the
  /// features `binary` and `getFile`.
  Future<TomSecretFile> getFile(
    String reference, {
    String? field,
    Map<String, String>? dimensions,
    bool wait = true,
    Duration? timeout,
    TomSecretsProgressCallback? onProgress,
  }) async {
    final item = _item(reference, field, dimensions);
    final connection = await _ensureConnection();
    final missing = tomSecretsClientFeatures.where(
      (f) => !connection.welcome.features.contains(f),
    );
    if (missing.isNotEmpty) {
      throw TomSecretsClientException(
        TomSecretsErrorKind.unsupported,
        'the service does not offer getFile (features ${missing.join(', ')})',
        details: {'features': missing.toList()},
      );
    }
    final answer = await _request({
      'op': 'getFile',
      ...item,
      if (!wait) 'wait': false,
      if (timeout != null) 'timeoutMs': timeout.inMilliseconds,
    }, onProgress: onProgress);
    if (answer['op'] != 'end') {
      throw _protocolError('getFile was answered ${answer['op']}');
    }
    final file = answer['_file']! as Map<String, Object?>;
    final bytes = answer['_bytes']! as Uint8List;
    final sha = crypto.sha256.convert(bytes).toString();
    if (file['size'] != bytes.length || answer['sha256'] != sha) {
      bytes.fillRange(0, bytes.length, 0);
      throw _protocolError('the file does not match its size or sha256');
    }
    return TomSecretFile(reference, file['name']! as String, bytes);
  }

  Map<String, Object?> _item(
    String reference,
    String? field,
    Map<String, String>? dimensions,
  ) {
    final parsed = TomSecretReference.parse(reference);
    if (field != null && parsed.fieldGiven && field != parsed.field) {
      throw TomSecretsClientException(
        TomSecretsErrorKind.malformed,
        'the field is named in the reference and as field',
        details: {'reason': 'field_twice'},
      );
    }
    return {
      'ref': reference,
      if (dimensions != null && dimensions.isNotEmpty) 'dimensions': dimensions,
      if (field != null && !parsed.fieldGiven) 'field': field,
    };
  }

  Future<Map<String, Object?>> _request(
    Map<String, Object?> request, {
    TomSecretsProgressCallback? onProgress,
    bool waitOnRateLimit = false,
  }) async {
    while (true) {
      final connection = await _ensureConnection();
      final answer = await connection.send(request, onProgress);
      if (answer['op'] != 'error') return answer;
      final error = TomSecretsClientException.fromError(answer);
      if (error.kind == TomSecretsErrorKind.rateLimited && waitOnRateLimit) {
        final ms = error.details['retryAfterMs'];
        await Future<void>.delayed(
          Duration(milliseconds: ms is int && ms > 0 ? ms : 1000),
        );
        continue;
      }
      throw error;
    }
  }

  TomSecretValue _valueOf(String reference, Map<String, Object?> answer) {
    if (answer['op'] != 'value') {
      throw _protocolError('get was answered ${answer['op']}');
    }
    return TomSecretValue.fromMessage(reference, answer);
  }

  TomSecretResult _resultOf(String reference, Object? result) {
    if (result is! Map) throw _protocolError('a getMany result is no object');
    final m = result.cast<String, Object?>();
    if (m['op'] == 'error') {
      return TomSecretResult.error(TomSecretsClientException.fromError(m));
    }
    return TomSecretResult.value(_valueOf(reference, m));
  }

  Future<_Connection> _ensureConnection() async {
    final open = _connection;
    if (open != null && !open.closed) return open;
    return _connecting ??= _connect().whenComplete(() => _connecting = null);
  }

  Future<_Connection> _connect() async {
    final location = discoverTomSecrets(
      operatingSystem: _operatingSystem,
      environment: _environment,
    );
    if (location is! TomSecretsEndpoints) {
      throw _notRunning('no runtime directory can be named');
    }
    final windows = _operatingSystem == 'windows';
    final Socket socket;
    String? token;
    try {
      if (windows) {
        final port = _readFile(location.clientPortFile!);
        final number = port == null ? null : readTomSecretsPortFile(port);
        if (number == null) throw _notRunning('no readable client.port');
        token = _readFile(location.clientTokenFile!);
        if (token == null) throw _notRunning('no client.token');
        token = token.endsWith('\r\n')
            ? token.substring(0, token.length - 2)
            : token.endsWith('\n')
            ? token.substring(0, token.length - 1)
            : token;
        socket = await Socket.connect(
          InternetAddress.loopbackIPv4,
          number,
          timeout: connectTimeout,
        );
      } else {
        final path = location.clientSocket!;
        if (FileSystemEntity.typeSync(path) == FileSystemEntityType.notFound) {
          throw _notRunning('no client.sock in ${location.directory}');
        }
        socket = await Socket.connect(
          InternetAddress(path, type: InternetAddressType.unix),
          0,
          timeout: connectTimeout,
        );
      }
    } on SocketException {
      throw _notRunning('the connection was refused');
    }
    final connection = _Connection(socket);
    try {
      connection.sendFrame({
        'op': 'hello',
        'protocol': tomSecretsProtocol,
        'client': {
          'name': clientName,
          'version': tomSecretsClientVersion,
          'language': 'dart',
        },
        'token': ?token,
        'clientToken': ?clientToken,
        'features': tomSecretsClientFeatures,
      });
      await connection.welcomed.timeout(connectTimeout);
    } on TimeoutException {
      await connection.close();
      throw _notRunning('no welcome within $connectTimeout');
    } on Object {
      await connection.close();
      rethrow;
    }
    _connection = connection;
    return connection;
  }

  static String? _readFile(String path) {
    try {
      return File(path).readAsStringSync();
    } on FileSystemException {
      return null;
    }
  }

  static String _executableName() {
    final parts = Platform.resolvedExecutable.split(RegExp(r'[/\\]'));
    final name = parts.last;
    return name.toLowerCase().endsWith('.exe')
        ? name.substring(0, name.length - 4)
        : name;
  }
}

TomSecretsClientException _notRunning(String why) => TomSecretsClientException(
  TomSecretsErrorKind.notRunning,
  'the secrets service is not running: $why',
);

TomSecretsClientException _protocolError(String why) =>
    TomSecretsClientException(
      TomSecretsErrorKind.internal,
      'the service broke the protocol: $why',
      details: {'code': 'protocol'},
    );

final class _Pending {
  _Pending(this.onProgress);
  final TomSecretsProgressCallback? onProgress;
  final Completer<Map<String, Object?>> answer = Completer();
  Map<String, Object?>? file;
  BytesBuilder? chunks;
}

/// One connection: frames in and out, the open requests by id.
final class _Connection {
  _Connection(this._socket) {
    _subscription = _socket.listen(
      _onData,
      onError: (Object _) => _fail(_dropped()),
      onDone: () => _fail(_dropped()),
      cancelOnError: true,
    );
  }

  final Socket _socket;
  late final StreamSubscription<Uint8List> _subscription;
  final TomSecretsFrameReader _reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxAnswerPayload,
  );
  final Completer<void> _welcomed = Completer();
  final Map<int, _Pending> _pending = {};
  late TomSecretsWelcome welcome;
  int _nextId = 1;
  bool closed = false;

  Future<void> get welcomed => _welcomed.future;

  static TomSecretsClientException _dropped() =>
      _notRunning('the connection to the service dropped');

  void sendFrame(Map<String, Object?> message) {
    final payload = tomSecretsJsonPayload(message);
    if (payload.length > tomSecretsMaxRequestPayload) {
      throw TomSecretsClientException(
        TomSecretsErrorKind.malformed,
        'the request is ${payload.length} bytes, over '
        '$tomSecretsMaxRequestPayload',
        details: {'reason': 'frame'},
      );
    }
    _socket.add(tomSecretsEncodeFrame(tomSecretsFrameJson, payload));
  }

  Future<Map<String, Object?>> send(
    Map<String, Object?> request,
    TomSecretsProgressCallback? onProgress,
  ) {
    if (closed) return Future.error(_dropped());
    final id = _nextId++;
    final pending = _Pending(onProgress);
    sendFrame({...request, 'id': id});
    _pending[id] = pending;
    return pending.answer.future;
  }

  void _onData(Uint8List bytes) {
    try {
      for (final frame in _reader.add(bytes)) {
        if (frame.type == tomSecretsFrameBinary) {
          _onChunk(frame.payload);
        } else {
          _onMessage(tomSecretsDecodePayload(frame.payload));
        }
        if (closed) return;
      }
    } on TomSecretsFrameException catch (e) {
      _fail(_protocolError(e.message));
    } on TomSecretsClientException catch (e) {
      _fail(e);
    }
  }

  void _onMessage(Map<String, Object?> message) {
    final op = message['op'];
    final id = message['id'];
    if (!_welcomed.isCompleted) {
      if (op == 'welcome') {
        welcome = _welcomeOf(message);
        _reader.binaryAllowed = welcome.features.contains('binary');
        _welcomed.complete();
      } else if (op == 'error' && id == null) {
        _fail(TomSecretsClientException.fromError(message));
      } else {
        _fail(_protocolError('the first frame is $op, not welcome'));
      }
      return;
    }
    if (op == 'error' && id == null) {
      _fail(TomSecretsClientException.fromError(message));
      return;
    }
    final pending = id is int ? _pending[id] : null;
    if (pending == null) return; // an answer nobody waits for; ignored
    switch (op) {
      case 'progress':
        pending.onProgress?.call(
          TomSecretsProgress(
            message['pending'] == 'unlock'
                ? TomSecretsPending.unlock
                : TomSecretsPending.approval,
            approvalCode: message['approvalCode'] as String?,
          ),
        );
      case 'file':
        pending
          ..file = message
          ..chunks = BytesBuilder(copy: false);
      case 'end':
        if (pending.file == null) {
          throw _protocolError('end without file');
        }
        _complete(id! as int, {
          ...message,
          '_file': pending.file,
          '_bytes': pending.chunks!.takeBytes(),
        });
      case 'value' || 'values' || 'error':
        _complete(id! as int, message);
      default:
        // An answer this library does not know; section 8 says ignore it.
        break;
    }
  }

  void _onChunk(Uint8List payload) {
    if (payload.length < 8) throw _protocolError('a binary chunk without id');
    final id = ByteData.sublistView(payload).getUint64(0);
    final pending = _pending[id];
    if (pending?.chunks == null) throw _protocolError('a chunk without file');
    pending!.chunks!.add(Uint8List.sublistView(payload, 8));
  }

  void _complete(int id, Map<String, Object?> message) {
    _pending.remove(id)?.answer.complete(message);
  }

  static TomSecretsWelcome _welcomeOf(Map<String, Object?> m) {
    final protocol = m['protocol'];
    if (protocol != tomSecretsProtocol) {
      throw TomSecretsClientException(
        TomSecretsErrorKind.unsupported,
        'the service speaks protocol $protocol',
        details: {
          'protocols': [protocol],
        },
      );
    }
    final service = m['service'];
    final features = m['features'];
    return TomSecretsWelcome(
      protocol: tomSecretsProtocol,
      serviceVersion: service is Map ? '${service['version']}' : '',
      features: features is List ? features.whereType<String>().toSet() : {},
      host: m['host'] is String ? m['host']! as String : '',
      platform: m['platform'] is String ? m['platform']! as String : '',
    );
  }

  void _fail(TomSecretsClientException error) {
    if (closed) return;
    closed = true;
    if (!_welcomed.isCompleted) _welcomed.completeError(error);
    for (final pending in _pending.values) {
      final partial = pending.chunks?.takeBytes();
      partial?.fillRange(0, partial.length, 0);
      pending.answer.completeError(error);
    }
    _pending.clear();
    unawaited(_subscription.cancel());
    _socket.destroy();
  }

  Future<void> close() async {
    _fail(_notRunning('the client closed the connection'));
  }
}
