// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/** Finding the service (protocol.md section 3). */

/** The operating systems the rules name. */
export type OperatingSystem = 'linux' | 'macos' | 'windows';

/** The runtime directory and its endpoint files. */
export interface Endpoints {
  readonly kind: 'endpoints';
  /** The runtime directory. */
  readonly directory: string;
  /** Linux and macOS: the client endpoint's Unix domain socket. */
  readonly clientSocket?: string;
  /** Linux and macOS: the admin endpoint's Unix domain socket. */
  readonly adminSocket?: string;
  /** Windows: the client endpoint's port file. */
  readonly clientPortFile?: string;
  /** Windows: the client token of this service start. */
  readonly clientTokenFile?: string;
  /** Windows: the admin endpoint's port file. */
  readonly adminPortFile?: string;
}

/**
 * No runtime directory can be named (Windows without `LOCALAPPDATA` and
 * `USERPROFILE`): the service is `not_running`.
 */
export interface NoRuntimeDirectory {
  readonly kind: 'noRuntimeDirectory';
  /** `no_runtime_directory`. */
  readonly reason: string;
}

/** Where the service's endpoints are. */
export type Location = Endpoints | NoRuntimeDirectory;

/** The operating system of this process, as the rules name it. */
export function currentOperatingSystem(): OperatingSystem {
  switch (process.platform) {
    case 'win32':
      return 'windows';
    case 'darwin':
      return 'macos';
    default:
      return 'linux';
  }
}

function strip(path: string, windows: boolean): string {
  let end = path.length;
  while (end > 0 && (path[end - 1] === '/' || (windows && path[end - 1] === '\\'))) {
    end--;
  }
  return end === 0 ? path : path.substring(0, end);
}

/**
 * The location of the service (protocol.md 3.1) for [operatingSystem]
 * (others than `macos` and `windows` are treated as `linux`), [environment]
 * and the numeric user id [uid] (needed only for the `/tmp/tsm-<uid>`
 * fallback).
 */
export function discover(
  operatingSystem: string,
  environment: Readonly<Record<string, string | undefined>>,
  uid: () => number | undefined = () => process.getuid?.(),
): Location {
  const windows = operatingSystem === 'windows';
  const override = environment['TSM_RUNTIME_DIR'] ?? '';
  let directory: string;
  if (override !== '') {
    directory = strip(override, windows);
  } else if (windows) {
    const local = environment['LOCALAPPDATA'] ?? '';
    const profile = environment['USERPROFILE'] ?? '';
    let base: string;
    if (local !== '') {
      base = strip(local, true);
    } else if (profile !== '') {
      base = `${strip(profile, true)}\\AppData\\Local`;
    } else {
      return { kind: 'noRuntimeDirectory', reason: 'no_runtime_directory' };
    }
    directory = `${base}\\TomSecretsManager\\run`;
  } else {
    const variable = operatingSystem === 'macos' ? 'TMPDIR' : 'XDG_RUNTIME_DIR';
    const value = environment[variable] ?? '';
    directory = value.startsWith('/')
      ? `${strip(value, false)}/tsm`
      : `/tmp/tsm-${uid()}`;
  }
  if (windows) {
    return {
      kind: 'endpoints',
      directory,
      clientPortFile: `${directory}\\client.port`,
      clientTokenFile: `${directory}\\client.token`,
      adminPortFile: `${directory}\\admin.port`,
    };
  }
  return {
    kind: 'endpoints',
    directory,
    clientSocket: `${directory}/client.sock`,
    adminSocket: `${directory}/admin.sock`,
  };
}

/** [text] without one trailing LF or CR LF. */
export function stripLineEnd(text: string): string {
  if (text.endsWith('\r\n')) return text.substring(0, text.length - 2);
  if (text.endsWith('\n')) return text.substring(0, text.length - 1);
  return text;
}

/**
 * The port of a port file's [text] (decimal 1-65535, no sign or leading
 * zero, at most one trailing LF or CR LF), or undefined when unreadable.
 */
export function readPortFile(text: string): number | undefined {
  const body = stripLineEnd(text);
  if (!/^[1-9][0-9]{0,4}$/.test(body)) return undefined;
  const port = Number.parseInt(body, 10);
  return port <= 65535 ? port : undefined;
}
