// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! Finding the service (protocol.md section 3).

use std::collections::HashMap;

/// The runtime directory and its endpoint files: the Unix domain sockets on
/// Linux and macOS, the port and token files on Windows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// The runtime directory.
    pub directory: String,
    /// `client.sock` (Linux, macOS).
    pub client_socket: Option<String>,
    /// `admin.sock` (Linux, macOS).
    pub admin_socket: Option<String>,
    /// `client.port` (Windows).
    pub client_port_file: Option<String>,
    /// `client.token` (Windows).
    pub client_token_file: Option<String>,
    /// `admin.port` (Windows).
    pub admin_port_file: Option<String>,
}

/// `linux`, `macos` or `windows`, as the rules name this process's.
pub fn current_operating_system() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn strip(path: &str, windows: bool) -> &str {
    let stripped = path.trim_end_matches(|c| c == '/' || (windows && c == '\\'));
    if stripped.is_empty() {
        path
    } else {
        stripped
    }
}

/// The location of the service (3.1) for `operating_system` (others than
/// `macos` and `windows` are treated as `linux`), `environment` and the
/// numeric user id (`uid` is called only for the `/tmp/tsm-<uid>`
/// fallback). None when no runtime directory can be named (Windows without
/// `LOCALAPPDATA` and `USERPROFILE`): the service is not running.
pub fn discover(
    operating_system: &str,
    environment: &HashMap<String, String>,
    uid: impl FnOnce() -> u32,
) -> Option<Endpoints> {
    let windows = operating_system == "windows";
    let var = |name: &str| environment.get(name).map(String::as_str).unwrap_or("");
    let directory = if !var("TSM_RUNTIME_DIR").is_empty() {
        strip(var("TSM_RUNTIME_DIR"), windows).to_owned()
    } else if windows {
        let base = if !var("LOCALAPPDATA").is_empty() {
            strip(var("LOCALAPPDATA"), true).to_owned()
        } else if !var("USERPROFILE").is_empty() {
            format!("{}\\AppData\\Local", strip(var("USERPROFILE"), true))
        } else {
            return None;
        };
        format!("{base}\\TomSecretsManager\\run")
    } else {
        let variable = if operating_system == "macos" {
            "TMPDIR"
        } else {
            "XDG_RUNTIME_DIR"
        };
        let value = var(variable);
        if value.starts_with('/') {
            format!("{}/tsm", strip(value, false))
        } else {
            format!("/tmp/tsm-{}", uid())
        }
    };
    Some(if windows {
        Endpoints {
            client_port_file: Some(format!("{directory}\\client.port")),
            client_token_file: Some(format!("{directory}\\client.token")),
            admin_port_file: Some(format!("{directory}\\admin.port")),
            directory,
            ..Endpoints::default()
        }
    } else {
        Endpoints {
            client_socket: Some(format!("{directory}/client.sock")),
            admin_socket: Some(format!("{directory}/admin.sock")),
            directory,
            ..Endpoints::default()
        }
    })
}

pub(crate) fn strip_line_end(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

/// The port of a port file's text (decimal 1-65535, no sign or leading zero,
/// at most one trailing LF or CR LF), or None when unreadable.
pub fn read_port_file(text: &str) -> Option<u16> {
    let body = strip_line_end(text);
    let bytes = body.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 5
        || bytes[0] == b'0'
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    body.parse::<u32>()
        .ok()
        .filter(|p| *p <= 65535)
        .map(|p| p as u16)
}

/// The process's user id, for the `/tmp/tsm-<uid>` fallback.
#[cfg(unix)]
pub(crate) fn process_uid() -> u32 {
    extern "C" {
        // POSIX getuid(2): uid_t is a 32-bit unsigned integer on Linux and
        // macOS. std links the C library already; the crate takes no libc
        // dependency for one call.
        fn getuid() -> u32;
    }
    // SAFETY: getuid takes no arguments, cannot fail and has no side
    // effects.
    unsafe { getuid() }
}

/// Windows names no `/tmp/tsm-<uid>`.
#[cfg(not(unix))]
pub(crate) fn process_uid() -> u32 {
    0
}
