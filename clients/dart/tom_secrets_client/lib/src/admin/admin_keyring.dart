// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The admin keys the app and `tsm` keep in the OS keychain, one per start
/// of the service (`tomSecretsAdminKeyHandle`), and the index of the starts
/// they were kept for ([tomSecretsAdminKeyIndexHandle]): an OS keychain
/// cannot be listed, so the index is what lets a key whose service is gone be
/// found and removed. Whoever keeps or uses a key removes the others
/// ([TomSecretsAdminKeyring.pruneOthers]); whoever stops the service removes
/// its key ([TomSecretsAdminKeyring.forget]).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'keychain_names.dart';

/// The handle of the index of the starts whose admin key is kept: their
/// start times, comma-separated.
const String tomSecretsAdminKeyIndexHandle = 'tsm.admin.index';

/// The admin keys in a keychain reached through [read], [write] and
/// [delete] (the keychain's own operations; their failures pass through).
final class TomSecretsAdminKeyring {
  /// A keyring over the keychain operations [read], [write] and [delete].
  TomSecretsAdminKeyring({
    required Future<String?> Function(String handle) read,
    required Future<void> Function(String handle, String value) write,
    required Future<void> Function(String handle) delete,
  }) : _read = read,
       _write = write,
       _delete = delete;

  final Future<String?> Function(String handle) _read;
  final Future<void> Function(String handle, String value) _write;
  final Future<void> Function(String handle) _delete;

  /// The admin key kept for the service started at [start], or null.
  Future<Uint8List?> keyOf(int start) async {
    final text = await _read(tomSecretsAdminKeyHandle(start));
    if (text == null || text.isEmpty) return null;
    try {
      return base64.decode(text);
    } on FormatException {
      return null;
    }
  }

  /// Keeps [key] for the service started at [start] and records the start
  /// in the index.
  Future<void> keep(int start, Uint8List key) async {
    await _write(tomSecretsAdminKeyHandle(start), base64.encode(key));
    final starts = await _starts();
    if (starts.add(start)) await _writeStarts(starts);
  }

  /// Removes the key of the service started at [start] (it was stopped) and
  /// its index entry.
  Future<void> forget(int start) async {
    await _delete(tomSecretsAdminKeyHandle(start));
    final starts = await _starts();
    if (starts.remove(start)) await _writeStarts(starts);
  }

  /// Removes every recorded key but the one of the service started at
  /// [running] (null: none runs, every key goes); answers the starts whose
  /// key was removed.
  Future<List<int>> pruneOthers(int? running) async {
    final starts = await _starts();
    final stale = [
      for (final s in starts)
        if (s != running) s,
    ]..sort();
    if (stale.isEmpty) return const [];
    for (final s in stale) {
      await _delete(tomSecretsAdminKeyHandle(s));
    }
    await _writeStarts(starts..removeAll(stale));
    return stale;
  }

  /// The starts the index records.
  Future<Set<int>> recorded() async => _starts();

  Future<Set<int>> _starts() async {
    final text = await _read(tomSecretsAdminKeyIndexHandle);
    return {
      for (final part in (text ?? '').split(',')) ?int.tryParse(part.trim()),
    };
  }

  Future<void> _writeStarts(Set<int> starts) async {
    if (starts.isEmpty) {
      await _delete(tomSecretsAdminKeyIndexHandle);
    } else {
      await _write(
        tomSecretsAdminKeyIndexHandle,
        (starts.toList()..sort()).join(','),
      );
    }
  }
}
