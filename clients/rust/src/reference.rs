// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The reference grammar (protocol.md section 4): parse and format.

use std::fmt::{self, Write as _};

use crate::error::{Error, Result};

/// The field a reference without `#field` names.
pub const DEFAULT_FIELD: &str = "Password";
/// The longest reference, in bytes of UTF-8.
pub const MAX_REFERENCE_BYTES: usize = 1024;

const RESERVED: &str = "/#[],:%";

/// What a reference names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A key: the value of an entry's `tsm.key` field (`telegram.bot_token`).
    Key(String),
    /// A store, the group path below its root group and the entry title,
    /// each segment unescaped.
    Path {
        /// The store.
        store: String,
        /// The segments.
        segments: Vec<String>,
    },
    /// An entry of a store by its KDBX UUID (lower case).
    Uuid {
        /// The store.
        store: String,
        /// The UUID, 32 hex digits.
        uuid: String,
    },
}

/// One binding `<dimension>:<value>` of a reference's qualifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The dimension.
    pub dimension: String,
    /// The value, unescaped.
    pub value: String,
}

/// A parsed reference. [`Reference::parse`] refuses a malformed one with an
/// [`Error::Malformed`] whose `reason` is the rule of protocol.md 4.6 it
/// broke; [`Reference::format`] gives the canonical form (4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// What it names.
    pub target: Target,
    /// The bindings, in the order written.
    pub qualifiers: Vec<Binding>,
    /// The effective field: [`DEFAULT_FIELD`] when none is written.
    pub field: String,
    /// Whether a field was written.
    pub field_given: bool,
}

fn malformed(reason: &str, detail: &str) -> Error {
    let mut message = format!("the reference is malformed: {reason}");
    if !detail.is_empty() {
        let _ = write!(message, " ({detail})");
    }
    Error::malformed(reason, message)
}

fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
}

fn is_store(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z' | '0'..='9'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
}

fn is_control(c: char) -> bool {
    (c as u32) < 0x20 || c as u32 == 0x7f
}

impl Reference {
    /// A reference to `target` with no qualifiers and the default field.
    pub fn new(target: Target) -> Self {
        Reference {
            target,
            qualifiers: Vec::new(),
            field: DEFAULT_FIELD.to_owned(),
            field_given: false,
        }
    }

    /// Parses `reference` (protocol.md 4.1-4.4, 4.6).
    pub fn parse(reference: &str) -> Result<Reference> {
        if reference.len() > MAX_REFERENCE_BYTES {
            return Err(malformed("too_long", ""));
        }
        if reference.is_empty() {
            return Err(malformed("empty", ""));
        }
        let mut rest = reference;
        let mut qualifiers = Vec::new();
        if let Some(after) = rest.strip_prefix('[') {
            let end = after
                .find(']')
                .ok_or_else(|| malformed("unclosed_qualifiers", ""))?;
            let body = &after[..end];
            rest = &after[end + 1..];
            if body.is_empty() {
                return Err(malformed("empty_segment", "[]"));
            }
            let mut seen: Vec<&str> = Vec::new();
            for binding in body.split(',') {
                let parts: Vec<&str> = binding.split(':').collect();
                if parts.len() != 2 {
                    return Err(malformed("bad_binding", binding));
                }
                let name = parts[0];
                if !is_name(name) {
                    return Err(malformed("bad_dimension", name));
                }
                if seen.contains(&name) {
                    return Err(malformed("duplicate_dimension", name));
                }
                seen.push(name);
                qualifiers.push(Binding {
                    dimension: name.to_owned(),
                    value: decode_segment(parts[1])?,
                });
            }
        }
        if rest.matches('#').count() > 1 {
            return Err(malformed("reserved_character", "#"));
        }
        let (target_text, field, field_given) = match rest.find('#') {
            Some(at) => (&rest[..at], Some(&rest[at + 1..]), true),
            None => (rest, None, false),
        };
        if target_text.is_empty() {
            return Err(malformed("empty_target", ""));
        }
        let field = match field {
            Some(raw) => decode_segment(raw)?,
            None => DEFAULT_FIELD.to_owned(),
        };
        let target = if !target_text.contains('/') {
            if !target_text.split('.').all(is_name) {
                return Err(malformed("bad_key", target_text));
            }
            Target::Key(target_text.to_owned())
        } else {
            let mut parts = target_text.split('/');
            let store = parts.next().unwrap_or("");
            let raw: Vec<&str> = parts.collect();
            if !is_store(store) {
                return Err(malformed("bad_store", store));
            }
            if raw.len() == 1 && raw[0].starts_with('~') {
                let hex = &raw[0][1..];
                if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(malformed("bad_uuid", raw[0]));
                }
                Target::Uuid {
                    store: store.to_owned(),
                    uuid: hex.to_ascii_lowercase(),
                }
            } else {
                let mut segments = Vec::with_capacity(raw.len());
                for segment in raw {
                    if segment.is_empty() {
                        return Err(malformed("empty_segment", ""));
                    }
                    if segment.starts_with('@') || segment.starts_with('~') {
                        return Err(malformed("reserved_prefix", &segment[..1]));
                    }
                    segments.push(decode_segment(segment)?);
                }
                Target::Path {
                    store: store.to_owned(),
                    segments,
                }
            }
        };
        Ok(Reference {
            target,
            qualifiers,
            field,
            field_given,
        })
    }

    /// The canonical text: bindings sorted by dimension name (by UTF-8
    /// bytes), every segment escaped in exactly what it must be, the uuid
    /// in lower case, the field omitted when it is [`DEFAULT_FIELD`]. A
    /// reference with no canonical text (a dimension bound twice, an empty
    /// segment) is an [`Error::InvalidArgument`].
    pub fn format(&self) -> Result<String> {
        let mut out = String::new();
        if !self.qualifiers.is_empty() {
            let mut bindings: Vec<&Binding> = self.qualifiers.iter().collect();
            bindings.sort_by(|a, b| a.dimension.as_bytes().cmp(b.dimension.as_bytes()));
            out.push('[');
            for (i, b) in bindings.iter().enumerate() {
                if i > 0 {
                    if bindings[i - 1].dimension == b.dimension {
                        return Err(Error::InvalidArgument("a dimension is bound once".into()));
                    }
                    out.push(',');
                }
                let _ = write!(out, "{}:{}", b.dimension, encode_segment(&b.value, false)?);
            }
            out.push(']');
        }
        match &self.target {
            Target::Key(key) => out.push_str(key),
            Target::Uuid { store, uuid } => {
                let _ = write!(out, "{store}/~{}", uuid.to_ascii_lowercase());
            }
            Target::Path { store, segments } => {
                out.push_str(store);
                for s in segments {
                    out.push('/');
                    out.push_str(&encode_segment(s, true)?);
                }
            }
        }
        if !self.field.is_empty() && self.field != DEFAULT_FIELD {
            out.push('#');
            out.push_str(&encode_segment(&self.field, false)?);
        }
        Ok(out)
    }

    /// The canonical form, or an empty string when it has none.
    pub fn canonical(&self) -> String {
        self.format().unwrap_or_default()
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

fn decode_segment(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(malformed("empty_segment", ""));
    }
    let bytes = raw.as_bytes();
    let mut data = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3);
            match pair {
                Some(p) if p.iter().all(u8::is_ascii_hexdigit) => {
                    let text = std::str::from_utf8(p).expect("hex digits");
                    data.push(u8::from_str_radix(text, 16).expect("hex pair"));
                    i += 3;
                    continue;
                }
                _ => {
                    let end = (i + 3).min(bytes.len());
                    return Err(malformed(
                        "bad_escape",
                        &String::from_utf8_lossy(&bytes[i..end]),
                    ));
                }
            }
        }
        let c = raw[i..].chars().next().expect("a char at a boundary");
        if RESERVED.contains(c) {
            return Err(malformed("reserved_character", &c.to_string()));
        }
        if is_control(c) {
            return Err(malformed(
                "control_character",
                &format!("U+{:04X}", c as u32),
            ));
        }
        data.extend_from_slice(&bytes[i..i + c.len_utf8()]);
        i += c.len_utf8();
    }
    String::from_utf8(data).map_err(|_| malformed("bad_utf8", ""))
}

fn encode_segment(text: &str, path: bool) -> Result<String> {
    if text.is_empty() {
        return Err(Error::InvalidArgument("a segment is never empty".into()));
    }
    let mut out = String::new();
    for (index, c) in text.chars().enumerate() {
        if RESERVED.contains(c) || is_control(c) || (path && index == 0 && (c == '@' || c == '~')) {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{b:02X}");
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}
