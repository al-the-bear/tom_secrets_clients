// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! What a `get` answers (protocol.md 5.2), what a `getFile` answers (5.5),
//! and the progress notices of a waiting request (5.4).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::SystemTime;

use crate::error::{Error, ErrorInfo};
use crate::json::{Object, Value as Json};
use crate::time::parse_time;

/// The entry a value was read from: its store and KDBX UUID, where the
/// service read it (`github`, `file` or `cache`), and the last successful
/// fetch of the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The store.
    pub store: String,
    /// The entry's KDBX UUID.
    pub uuid: String,
    /// `github`, `file` or `cache`.
    pub source: String,
    /// The last successful fetch of the store.
    pub fetched_at: SystemTime,
}

/// The entry's last modification and the store file revision it was read
/// from; a caller caching a value compares it to see a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// The entry's last modification.
    pub modified: SystemTime,
    /// The store file revision.
    pub revision: String,
}

/// Overwrites `bytes` with zeros in a way the optimiser keeps.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: b is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A secret. No printable form shows it: `Display` and `Debug` give
/// `SecretValue(<ref>: ***)`. Dropping it overwrites its buffer. A `String`
/// the caller copies out of [`Value::text`] is the caller's to handle.
pub struct Value {
    /// The reference the value was asked for, as given.
    pub reference: String,
    /// How the service sent it: `utf8` (text) or `base64` (bytes).
    pub encoding: String,
    /// The entry it was read from.
    pub entry: Entry,
    /// The bindings the winning entry carries, dimension → value.
    pub bound: BTreeMap<String, String>,
    /// The entry's version.
    pub version: Version,
    /// The entry's expiry, when it has one.
    pub expires: Option<SystemTime>,
    /// The client token the service granted when one was asked for: the
    /// caller's to keep (7.4); the library never stores it.
    pub client_token: Option<String>,
    data: Vec<u8>,
}

fn bad_value() -> Error {
    let mut details = Object::new();
    details.insert("code".into(), "bad_value".into());
    Error::Internal(ErrorInfo::new(
        "the service sent a value message this library cannot read",
        details,
    ))
}

/// The source a protocol `source` names; an unknown one is `cache`
/// (section 8: the most general one known, no claim to be fresh).
fn source_from_wire(name: Option<&Json>) -> String {
    match name.and_then(Json::as_str) {
        Some(s @ ("github" | "file")) => s.to_owned(),
        _ => "cache".to_owned(),
    }
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    if text.len() - trimmed.len() > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in trimmed.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // A single leftover character carries fewer than 8 bits: not base64.
    if bits >= 6 {
        return None;
    }
    Some(out)
}

impl Value {
    /// The value of a `value` message (or a `values` result).
    pub(crate) fn from_message(reference: &str, m: &Object) -> Result<Value, Error> {
        let raw = m
            .get("value")
            .and_then(Json::as_str)
            .ok_or_else(bad_value)?;
        let entry = m
            .get("entry")
            .and_then(Json::as_object)
            .ok_or_else(bad_value)?;
        let version = m
            .get("version")
            .and_then(Json::as_object)
            .ok_or_else(bad_value)?;
        let text = |o: &Object, k: &str| o.get(k).and_then(Json::as_str).map(str::to_owned);
        let time = |o: &Object, k: &str| o.get(k).and_then(Json::as_str).and_then(parse_time);
        let mut bound = BTreeMap::new();
        if let Some(b) = m.get("bound").and_then(Json::as_object) {
            for (k, v) in b {
                bound.insert(k.clone(), v.as_str().ok_or_else(bad_value)?.to_owned());
            }
        }
        let (encoding, data) = if m.get("encoding").and_then(Json::as_str) == Some("base64") {
            ("base64", decode_base64(raw).ok_or_else(bad_value)?)
        } else {
            ("utf8", raw.as_bytes().to_vec())
        };
        let expires = match m.get("expires") {
            Some(Json::String(s)) => Some(parse_time(s).ok_or_else(bad_value)?),
            _ => None,
        };
        Ok(Value {
            reference: reference.to_owned(),
            encoding: encoding.to_owned(),
            entry: Entry {
                store: text(entry, "store").ok_or_else(bad_value)?,
                uuid: text(entry, "uuid").ok_or_else(bad_value)?,
                source: source_from_wire(entry.get("source")),
                fetched_at: time(entry, "fetchedAt").ok_or_else(bad_value)?,
            },
            bound,
            version: Version {
                modified: time(version, "modified").ok_or_else(bad_value)?,
                revision: text(version, "revision").ok_or_else(bad_value)?,
            },
            expires,
            client_token: text(m, "clientToken"),
            data,
        })
    }

    /// The value as text; None for a binary value (`base64`), which is read
    /// with [`Value::bytes`] rather than decoded into a corrupt string.
    pub fn text(&self) -> Option<&str> {
        if self.encoding == "base64" {
            return None;
        }
        std::str::from_utf8(&self.data).ok()
    }

    /// The value as bytes (text as its UTF-8).
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        wipe(&mut self.data);
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue({}: ***)", self.reference)
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An attachment or a typed key read with `get_file`: its name and bytes.
/// Its printable forms never show the bytes, and dropping it overwrites
/// them.
pub struct File {
    /// The reference the file was asked for, as given.
    pub reference: String,
    /// The field's name (an attachment's file name).
    pub name: String,
    data: Vec<u8>,
}

impl File {
    pub(crate) fn new(reference: &str, name: String, data: Vec<u8>) -> File {
        File {
            reference: reference.to_owned(),
            name,
            data,
        }
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// The size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        wipe(&mut self.data);
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretFile({}: {}, {} bytes)",
            self.reference,
            self.name,
            self.data.len()
        )
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A progress notice: why a request waits, `unlock` (the service is locked
/// and an admin was told) or `approval` (the request went to approval),
/// with the one-time approval code on a host with no approver connected
/// (7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Progress {
    /// `unlock` or `approval`.
    pub pending: String,
    /// The approval code, when the service sent one.
    pub approval_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::decode_base64;

    #[test]
    fn base64() {
        assert_eq!(decode_base64("AAEC/w==").unwrap(), [0, 1, 2, 0xff]);
        assert_eq!(decode_base64("AAEC/w").unwrap(), [0, 1, 2, 0xff]);
        assert_eq!(decode_base64("").unwrap(), Vec::<u8>::new());
        assert!(decode_base64("A").is_none());
        assert!(decode_base64("AA===").is_none());
        assert!(decode_base64("A-A=").is_none());
    }
}
