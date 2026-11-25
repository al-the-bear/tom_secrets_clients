// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Who answers on the admin endpoint (protocol.md 6.0): before an admin
/// sends anything (the `auth`, and above all the `claim` with the master
/// password), it checks that the endpoint is this user's service:
///
/// - the runtime directory and the admin socket belong to this user and are
///   closed to everyone else (0700 / 0600; on Windows the directory's ACL
///   grants only the user and SYSTEM);
/// - the process at the other end runs as this user (`SO_PEERCRED` on
///   Linux, `LOCAL_PEERPID` and `LOCAL_PEERCRED` on macOS, on Windows the
///   owner of the TCP connection's other end, `GetExtendedTcpTable`, and
///   its token's SID);
/// - that process is the service executable expected here.
///
/// A check that fails ends the connection with `service_untrusted` before a
/// byte is sent. What is measured ([TomSecretsEndpointFacts]) is kept apart
/// from the decision ([tomSecretsJudgeService]), which is tested with
/// recorded facts.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../discovery.dart';
import 'distribution.dart';
import 'runtime.dart';
import 'service_identity.dart';
import 'windows_acl.dart';

/// The admin error kind of an endpoint that is not this user's service.
const String tomSecretsServiceUntrusted = 'service_untrusted';

/// Why an endpoint is not trusted (`details.reason`).
enum TomSecretsUntrustedReason {
  /// The runtime directory or the socket belongs to another user, or is no
  /// directory / socket.
  owner('owner'),

  /// The runtime directory or the socket is open to others.
  mode('mode'),

  /// The process answering runs as another user, or cannot be measured.
  peerUser('peer_user'),

  /// The process answering is not the service executable expected here.
  peerExecutable('peer_executable');

  const TomSecretsUntrustedReason(this.wireName);

  /// The reason as `details.reason` carries it.
  final String wireName;
}

/// What the user can do about an endpoint refused for [reason] (a
/// `details.reason` of `service_untrusted`), in a sentence or two; the
/// refusal's message says what is wrong.
String tomSecretsUntrustedAdvice(String? reason) => switch (reason) {
  'owner' =>
    'Another user\'s directory or file is where this user\'s service '
        'would be. Do not enter the master password. Point '
        'XDG_RUNTIME_DIR (or TSM_RUNTIME_DIR) at a directory of your own, '
        'or have the one named removed, then start the service again.',
  'mode' =>
    'Others can reach the service\'s directory or socket. Close them to '
        'others and run this again: chmod 700 on the runtime directory and '
        'chmod 600 on its sockets (a service older than 0.25.7 left its '
        'sockets open inside its closed directory); on Windows only you '
        'and SYSTEM in the directory\'s access list.',
  'peer_user' =>
    'A process of another user answers where this user\'s service would. '
        'Do not enter the master password. Find out what runs under the '
        'process id named, and start your own service once it is gone.',
  'unpinned' =>
    'This program has not met this service before. Compare the words above '
        'with the ones the service\'s machine shows in the manager app '
        '(Pairing, the device list) or in `tsm status` there; when they '
        'are the same, trust it: `tsm trust <the words>`.',
  'no_identity' =>
    'The service running is older than this program and cannot prove who '
        'it is. Stop it (end its process, named in service.json) and start '
        'the one that came with this program.',
  'peer_executable' =>
    'Something other than the service that belongs to this program '
        'answers. If it is a service you installed elsewhere, name its '
        'executable in TSM_SERVICE; else stop that process and start the '
        'service again.',
  _ => 'Nothing was sent. Stop whatever answers there and start the service.',
};

/// What the user can do about a service whose identity key is not the one
/// pinned (`service_key_changed`).
const String tomSecretsKeyChangedAdvice =
    'The service presents another identity key than the one this program '
    'pinned. Nothing was sent. If you set this service up anew, or moved '
    'its data directory, remove the old pin (`tsm trust --remove`) and '
    'compare the new words; if you did not, something else answers in its '
    'place: do not enter the master password.';

/// A file as the check reads it: its owner's numeric id, its permission
/// bits and what it is.
typedef TomSecretsFileFacts = ({int owner, int mode, String type});

/// The process at the other end of the admin connection.
final class TomSecretsServicePeer {
  /// The peer [pid] of [user] running [executable].
  const TomSecretsServicePeer({
    required this.pid,
    required this.user,
    required this.executable,
    this.executableHidden = false,
  });

  /// Its process id.
  final int pid;

  /// Its OS user (a number on Linux and macOS, a SID string on Windows), or
  /// null when it could not be read.
  final Object? user;

  /// Its executable's real path, or null when it could not be read.
  final String? executable;

  /// Whether the OS refuses to show the executable of this process to its
  /// own user: Linux, for a process that made itself not dumpable (as the
  /// service does at its start, so no process of the user reads its
  /// memory). Such a peer's executable cannot be checked.
  final bool executableHidden;
}

/// What was measured of an endpoint.
final class TomSecretsEndpointFacts {
  /// The facts.
  const TomSecretsEndpointFacts({
    required this.operatingSystem,
    required this.ownUser,
    required this.ownPid,
    this.directory,
    this.socket,
    this.directoryGrantees,
    this.peer,
  });

  /// `linux`, `macos` or `windows`.
  final String operatingSystem;

  /// This process's OS user (as [TomSecretsServicePeer.user]), or null.
  final Object? ownUser;

  /// This process's id.
  final int ownPid;

  /// Linux and macOS: the runtime directory itself (not what a link there
  /// points to), or null when it could not be read.
  final TomSecretsFileFacts? directory;

  /// Linux and macOS: the admin socket, or null when it could not be read.
  final TomSecretsFileFacts? socket;

  /// Windows: who the runtime directory's ACL grants, or null when it could
  /// not be read.
  final Set<String>? directoryGrantees;

  /// The process at the other end, or null when it could not be measured.
  final TomSecretsServicePeer? peer;
}

/// A verdict against an endpoint: the reason and a sentence for the user.
typedef TomSecretsUntrusted = ({
  TomSecretsUntrustedReason reason,
  String message,
});

/// Why the endpoint of [facts] is not this user's service, or null when it
/// is: its files ([tomSecretsJudgeEndpointFiles]), then the process
/// answering ([tomSecretsJudgeServicePeer]).
TomSecretsUntrusted? tomSecretsJudgeService(
  TomSecretsEndpointFacts facts, {
  required Set<String> executables,
  bool Function(Set<String> grantees) userOnly = tomSecretsWindowsUserOnly,
}) =>
    tomSecretsJudgeEndpointFiles(facts, userOnly: userOnly) ??
    tomSecretsJudgeServicePeer(facts, executables: executables);

/// Why the files of [facts]' endpoint are not this user's alone (the
/// runtime directory and the admin socket; on Windows the directory's
/// ACL, [userOnly] saying whether its grantees are only this user and
/// SYSTEM), or null when they are. Judged before the connection is opened.
TomSecretsUntrusted? tomSecretsJudgeEndpointFiles(
  TomSecretsEndpointFacts facts, {
  bool Function(Set<String> grantees) userOnly = tomSecretsWindowsUserOnly,
}) {
  if (facts.operatingSystem == 'windows') {
    final grantees = facts.directoryGrantees;
    if (grantees == null) {
      return (
        reason: TomSecretsUntrustedReason.owner,
        message: 'the runtime directory\'s access list cannot be read',
      );
    }
    if (!userOnly(grantees)) {
      return (
        reason: TomSecretsUntrustedReason.mode,
        message:
            'the runtime directory grants others access '
            '(${grantees.join(', ')})',
      );
    }
  } else {
    for (final (what, file, type) in [
      ('runtime directory', facts.directory, 'directory'),
      ('admin socket', facts.socket, 'socket'),
    ]) {
      final why = tomSecretsJudgeFile(what, file, type, facts.ownUser);
      if (why != null) return why;
    }
  }
  return null;
}

/// Why [file] (the [what], on Linux or macOS) is not [ownUser]'s alone, or
/// null when it is: it is a [type] itself (no link to one), belongs to the
/// user and gives group and others nothing.
TomSecretsUntrusted? tomSecretsJudgeFile(
  String what,
  TomSecretsFileFacts? file,
  String type,
  Object? ownUser,
) {
  if (file == null) {
    return (
      reason: TomSecretsUntrustedReason.owner,
      message: 'the $what cannot be read',
    );
  }
  if (file.type != type) {
    return (
      reason: TomSecretsUntrustedReason.owner,
      message: 'the $what is no $type (${file.type})',
    );
  }
  if (ownUser == null || file.owner != ownUser) {
    return (
      reason: TomSecretsUntrustedReason.owner,
      message:
          'the $what belongs to user ${file.owner}, not to this user '
          '($ownUser)',
    );
  }
  if (file.mode & 0x3F != 0) {
    return (
      reason: TomSecretsUntrustedReason.mode,
      message:
          'the $what is open to others (mode '
          '${(file.mode & 0x1FF).toRadixString(8)})',
    );
  }
  return null;
}

/// Why the process answering on [facts]' endpoint is not the service
/// expected, or null when it is: it runs as this user and is one of
/// [executables] (real paths). Judged once connected, before anything is
/// sent.
TomSecretsUntrusted? tomSecretsJudgeServicePeer(
  TomSecretsEndpointFacts facts, {
  required Set<String> executables,
}) {
  final windows = facts.operatingSystem == 'windows';
  final peer = facts.peer;
  if (peer == null) {
    return (
      reason: TomSecretsUntrustedReason.peerUser,
      message: 'the process answering on the admin endpoint cannot be read',
    );
  }
  if (peer.user == null ||
      facts.ownUser == null ||
      peer.user != facts.ownUser) {
    return (
      reason: TomSecretsUntrustedReason.peerUser,
      message:
          'the process answering (pid ${peer.pid}) runs as '
          '${peer.user ?? 'a user that cannot be read'}, not as this user',
    );
  }
  // This very process serves the endpoint (a service run in-process).
  if (peer.pid == facts.ownPid) return null;
  final exe = peer.executable;
  if (exe == null) {
    // The one case the OS hides it from its own user (see
    // TomSecretsServicePeer.executableHidden): nothing to compare.
    if (peer.executableHidden) return null;
    return (
      reason: TomSecretsUntrustedReason.peerExecutable,
      message:
          'the executable of the process answering (pid ${peer.pid}) '
          'cannot be read',
    );
  }
  bool same(String a, String b) =>
      windows ? a.toLowerCase() == b.toLowerCase() : a == b;
  if (!executables.any((e) => same(e, exe))) {
    return (
      reason: TomSecretsUntrustedReason.peerExecutable,
      message:
          'the process answering (pid ${peer.pid}) is $exe, not the '
          'service expected '
          '(${executables.isEmpty ? 'none found' : executables.join(', ')}). '
          'If that is your service, name it in TSM_SERVICE',
    );
  }
  return null;
}

/// The service executables an admin whose own executable is
/// [ownExecutable] expects, as real paths: `tom_secrets_service` beside it
/// and in its distribution's tools folder ([tomSecretsServiceCandidates]),
/// the one `TSM_SERVICE` names in [environment], and [configured] (a
/// `--service` option).
Set<String> tomSecretsExpectedServiceExecutables({
  String? ownExecutable,
  Map<String, String>? environment,
  Iterable<String> configured = const [],
  String? operatingSystem,
}) {
  final os = operatingSystem ?? Platform.operatingSystem;
  final own = ownExecutable ?? Platform.resolvedExecutable;
  final named = (environment ?? Platform.environment)['TSM_SERVICE'];
  return {
    for (final path in [
      ...tomSecretsServiceCandidates(
        File(own).parent.path,
        operatingSystem: os,
      ),
      if (named != null && named.isNotEmpty) named,
      ...configured,
    ])
      tomSecretsRealExecutable(path),
  };
}

/// [path] with its links resolved, or as it is when it does not exist.
String tomSecretsRealExecutable(String path) {
  try {
    return File(path).resolveSymbolicLinksSync();
  } on FileSystemException {
    return path;
  }
}

/// Reads the facts of an endpoint.
abstract interface class TomSecretsEndpointInspector {
  /// The facts of [runtime]'s files before the connection is opened.
  TomSecretsEndpointFacts files(TomSecretsRuntime runtime);

  /// [facts] with the process at the other end of [socket].
  TomSecretsEndpointFacts withPeer(
    TomSecretsEndpointFacts facts,
    Socket socket,
  );
}

/// The inspector of this OS.
final class TomSecretsSystemEndpointInspector
    implements TomSecretsEndpointInspector {
  /// The inspector.
  const TomSecretsSystemEndpointInspector();

  @override
  TomSecretsEndpointFacts files(TomSecretsRuntime runtime) {
    final own = tomSecretsOwnUser();
    if (Platform.isWindows) {
      Set<String>? grantees;
      try {
        grantees = tomSecretsWindowsGranteesSync(runtime.directory);
      } on FileSystemException {
        grantees = null;
      }
      return TomSecretsEndpointFacts(
        operatingSystem: 'windows',
        ownUser: own,
        ownPid: pid,
        directoryGrantees: grantees,
      );
    }
    final stats = tomSecretsStatFiles([runtime.directory, runtime.adminSocket]);
    return TomSecretsEndpointFacts(
      operatingSystem: Platform.operatingSystem,
      ownUser: own,
      ownPid: pid,
      directory: stats[runtime.directory],
      socket: stats[runtime.adminSocket],
    );
  }

  @override
  TomSecretsEndpointFacts withPeer(
    TomSecretsEndpointFacts facts,
    Socket socket,
  ) {
    TomSecretsServicePeer? peer;
    try {
      peer = tomSecretsServicePeerOf(socket);
    } on Object {
      peer = null;
    }
    return TomSecretsEndpointFacts(
      operatingSystem: facts.operatingSystem,
      ownUser: facts.ownUser,
      ownPid: facts.ownPid,
      directory: facts.directory,
      socket: facts.socket,
      directoryGrantees: facts.directoryGrantees,
      peer: peer,
    );
  }
}

/// The check an admin connection runs before it sends anything.
final class TomSecretsServiceTrust {
  /// A check expecting [executables] (default:
  /// [tomSecretsExpectedServiceExecutables] of this process), reading the
  /// endpoint through [inspector].
  const TomSecretsServiceTrust({
    this.executables,
    this.inspector = const TomSecretsSystemEndpointInspector(),
    this.identity,
  });

  /// What the service's identity key is checked with (protocol.md 6.1):
  /// the pins and the primitives. Null: [fallbackIdentity].
  final TomSecretsIdentityTrust? identity;

  /// The identity check of a process that sets its admin connections up in
  /// one place (the app, `tsm`, a test's set-up), used where a check names
  /// none. Without either, an admin connection is refused
  /// (`service_untrusted`, `unpinned`): no service is trusted unchecked.
  static TomSecretsIdentityTrust? fallbackIdentity;

  /// The identity check that holds.
  TomSecretsIdentityTrust? get identityTrust => identity ?? fallbackIdentity;

  /// The service executables expected, as real paths; null: those of this
  /// process.
  final Set<String>? executables;

  /// Reads the endpoint.
  final TomSecretsEndpointInspector inspector;

  /// The executables expected.
  Set<String> get expected =>
      executables ?? tomSecretsExpectedServiceExecutables();

  /// Why the files of [facts]' endpoint are not trusted, or null.
  TomSecretsUntrusted? judgeFiles(TomSecretsEndpointFacts facts) =>
      tomSecretsJudgeEndpointFiles(facts);

  /// Why the process answering on [facts]' endpoint is not trusted, or
  /// null.
  TomSecretsUntrusted? judgePeer(TomSecretsEndpointFacts facts) =>
      tomSecretsJudgeServicePeer(facts, executables: expected);
}

/// This process's OS user: a number on Linux and macOS, a SID string on
/// Windows; null when it cannot be read.
Object? tomSecretsOwnUser() {
  try {
    return Platform.isWindows ? _windowsSid(pid) : currentUid();
  } on Object {
    return null;
  }
}

/// Owner, permission bits and type (`directory`, `socket`, `link`, `file`,
/// `other`) of each of [paths] itself (a link is not followed), read with
/// `stat`; a path that cannot be read is left out.
Map<String, TomSecretsFileFacts> tomSecretsStatFiles(List<String> paths) {
  final out = <String, TomSecretsFileFacts>{};
  for (final path in paths) {
    // Why synchronous: see data_directory.dart. One call per path: a path
    // that is missing fails alone. The raw mode in hex, not the type in
    // words: those follow the user's language.
    final result = Process.runSync(
      'stat',
      Platform.isMacOS ? ['-f', '%u %Xp', path] : ['-c', '%u %f', path],
    );
    if (result.exitCode != 0) continue;
    final parsed = tomSecretsParseStat((result.stdout as String).trim());
    if (parsed != null) out[path] = parsed;
  }
  return out;
}

/// A line `<uid> <raw mode in hex>` of `stat` (`st_mode`: the file type
/// and the permission bits) as the facts, or null.
TomSecretsFileFacts? tomSecretsParseStat(String line) {
  final parts = line.split(RegExp(r'\s+'));
  if (parts.length != 2) return null;
  final owner = int.tryParse(parts[0]);
  final raw = int.tryParse(parts[1], radix: 16);
  if (owner == null || raw == null) return null;
  // S_IFMT: S_IFDIR 0x4000, S_IFSOCK 0xC000, S_IFLNK 0xA000, S_IFREG 0x8000.
  final type = switch (raw & 0xF000) {
    0x4000 => 'directory',
    0xC000 => 'socket',
    0xA000 => 'link',
    0x8000 => 'file',
    _ => 'other',
  };
  return (owner: owner, mode: raw & 0xFFF, type: type);
}

/// The process at the other end of [socket], a connection this process
/// opened; null when the OS names none.
TomSecretsServicePeer? tomSecretsServicePeerOf(Socket socket) {
  if (Platform.isLinux) {
    // SO_PEERCRED (SOL_SOCKET 1, option 17): struct ucred {pid, uid, gid}.
    final raw = socket.getRawOption(RawSocketOption(1, 17, Uint8List(12)));
    final data = ByteData.sublistView(raw);
    final peer = data.getInt32(0, Endian.host);
    if (peer <= 0) return null;
    String? exe;
    var hidden = false;
    try {
      exe = tomSecretsRealExecutable(Link('/proc/$peer/exe').targetSync());
    } on FileSystemException catch (e) {
      // EACCES (13) / EPERM (1): the process is not dumpable.
      final code = e.osError?.errorCode;
      hidden = code == 13 || code == 1;
    }
    return TomSecretsServicePeer(
      pid: peer,
      user: data.getUint32(4, Endian.host),
      executable: exe,
      executableHidden: hidden,
    );
  }
  if (Platform.isMacOS) {
    // LOCAL_PEERPID (SOL_LOCAL 0, option 2) and LOCAL_PEERCRED (option 1):
    // struct xucred {cr_version, cr_uid, ...}.
    final pidRaw = socket.getRawOption(RawSocketOption(0, 2, Uint8List(4)));
    final peer = ByteData.sublistView(pidRaw).getInt32(0, Endian.host);
    if (peer <= 0) return null;
    final cred = socket.getRawOption(RawSocketOption(0, 1, Uint8List(76)));
    final path = _macPath(peer);
    return TomSecretsServicePeer(
      pid: peer,
      user: ByteData.sublistView(cred).getUint32(4, Endian.host),
      executable: path == null ? null : tomSecretsRealExecutable(path),
    );
  }
  if (Platform.isWindows) {
    // The other end's row: its local port is the service's, its remote
    // port this connection's.
    final peer = tomSecretsWindowsTcpOwner(
      localPort: socket.remotePort,
      remotePort: socket.port,
    );
    if (peer == null) return null;
    final path = _windowsExe(peer);
    return TomSecretsServicePeer(
      pid: peer,
      user: _windowsSid(peer),
      executable: path == null ? null : tomSecretsRealExecutable(path),
    );
  }
  return null;
}

// ── macOS ────────────────────────────────────────────────────────────────

String? _macPath(int pid) {
  final procPidPath = DynamicLibrary.process()
      .lookupFunction<
        Int32 Function(Int32, Pointer<Uint8>, Uint32),
        int Function(int, Pointer<Uint8>, int)
      >('proc_pidpath');
  final buf = calloc<Uint8>(4096);
  try {
    final n = procPidPath(pid, buf, 4096);
    return n <= 0 ? null : utf8.decode(buf.asTypedList(n));
  } finally {
    calloc.free(buf);
  }
}

// ── Windows ──────────────────────────────────────────────────────────────

const int _processQueryLimitedInformation = 0x1000;

DynamicLibrary get _kernel32 => DynamicLibrary.open('kernel32.dll');
DynamicLibrary get _advapi32 => DynamicLibrary.open('advapi32.dll');

int _openProcess(int access, int pid) =>
    _kernel32.lookupFunction<
      IntPtr Function(Uint32, Int32, Uint32),
      int Function(int, int, int)
    >('OpenProcess')(access, 0, pid);

void _closeHandle(int handle) =>
    _kernel32.lookupFunction<Int32 Function(IntPtr), int Function(int)>(
      'CloseHandle',
    )(handle);

/// Windows: the PID owning the localhost TCP connection end whose local
/// port is [localPort] and whose remote port is [remotePort]
/// (`GetExtendedTcpTable`, `TCP_TABLE_OWNER_PID_CONNECTIONS`), or null.
int? tomSecretsWindowsTcpOwner({
  required int localPort,
  required int remotePort,
}) {
  final getTable = DynamicLibrary.open('iphlpapi.dll')
      .lookupFunction<
        Uint32 Function(
          Pointer<Void>,
          Pointer<Uint32>,
          Int32,
          Uint32,
          Uint32,
          Uint32,
        ),
        int Function(Pointer<Void>, Pointer<Uint32>, int, int, int, int)
      >('GetExtendedTcpTable');
  const afInet = 2;
  const ownerPidConnections = 4;
  final size = calloc<Uint32>();
  try {
    getTable(nullptr, size, 0, afInet, ownerPidConnections, 0);
    final buf = calloc<Uint8>(size.value + 1024);
    try {
      size.value += 1024;
      if (getTable(buf.cast(), size, 0, afInet, ownerPidConnections, 0) != 0) {
        return null;
      }
      final data = ByteData.sublistView(buf.asTypedList(size.value));
      final count = data.getUint32(0, Endian.little);
      int port(int dw) => ((dw & 0xff) << 8) | ((dw >> 8) & 0xff);
      for (var r = 0; r < count; r++) {
        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr,
        // remotePort, owningPid; 24 bytes.
        final o = 4 + r * 24;
        if (port(data.getUint32(o + 8, Endian.little)) == localPort &&
            port(data.getUint32(o + 16, Endian.little)) == remotePort) {
          return data.getUint32(o + 20, Endian.little);
        }
      }
      return null;
    } finally {
      calloc.free(buf);
    }
  } finally {
    calloc.free(size);
  }
}

String? _windowsSid(int pid) {
  final handle = _openProcess(_processQueryLimitedInformation, pid);
  if (handle == 0) return null;
  final openToken = _advapi32
      .lookupFunction<
        Int32 Function(IntPtr, Uint32, Pointer<IntPtr>),
        int Function(int, int, Pointer<IntPtr>)
      >('OpenProcessToken');
  final getInfo = _advapi32
      .lookupFunction<
        Int32 Function(IntPtr, Int32, Pointer<Void>, Uint32, Pointer<Uint32>),
        int Function(int, int, Pointer<Void>, int, Pointer<Uint32>)
      >('GetTokenInformation');
  final toString = _advapi32
      .lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<Pointer<Utf16>>),
        int Function(Pointer<Void>, Pointer<Pointer<Utf16>>)
      >('ConvertSidToStringSidW');
  final localFree = _kernel32
      .lookupFunction<
        Pointer<Void> Function(Pointer<Void>),
        Pointer<Void> Function(Pointer<Void>)
      >('LocalFree');
  final token = calloc<IntPtr>();
  final buf = calloc<Uint8>(256);
  final length = calloc<Uint32>();
  final text = calloc<Pointer<Utf16>>();
  try {
    if (openToken(handle, 0x0008, token) == 0) return null; // TOKEN_QUERY
    try {
      // TokenUser (1): TOKEN_USER {SID_AND_ATTRIBUTES {PSID, attributes}}.
      if (getInfo(token.value, 1, buf.cast(), 256, length) == 0) return null;
      final sid = buf.cast<Pointer<Void>>().value;
      if (toString(sid, text) == 0) return null;
      final result = text.value.toDartString();
      localFree(text.value.cast());
      return result;
    } finally {
      _closeHandle(token.value);
    }
  } finally {
    _closeHandle(handle);
    calloc
      ..free(token)
      ..free(buf)
      ..free(length)
      ..free(text);
  }
}

String? _windowsExe(int pid) {
  final handle = _openProcess(_processQueryLimitedInformation, pid);
  if (handle == 0) return null;
  final query = _kernel32
      .lookupFunction<
        Int32 Function(IntPtr, Uint32, Pointer<Utf16>, Pointer<Uint32>),
        int Function(int, int, Pointer<Utf16>, Pointer<Uint32>)
      >('QueryFullProcessImageNameW');
  final buf = calloc<Uint16>(32768);
  final size = calloc<Uint32>()..value = 32768;
  try {
    if (query(handle, 0, buf.cast(), size) == 0) return null;
    return buf.cast<Utf16>().toDartString(length: size.value);
  } finally {
    _closeHandle(handle);
    calloc
      ..free(buf)
      ..free(size);
  }
}
