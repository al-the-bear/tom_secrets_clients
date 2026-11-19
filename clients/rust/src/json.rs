// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The JSON the protocol speaks (protocol.md 2.3): a strict parser (one
//! value, no duplicate member names, numbers in range, no control
//! characters in strings) and a compact writer. The crate needs nothing
//! more, so it carries no JSON dependency.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

/// A JSON value. Objects keep their members sorted by name, so writing one
/// gives the canonical (sorted, compact) form.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A number (every JSON number the protocol uses fits an `f64`).
    Number(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(BTreeMap<String, Value>),
}

/// A JSON object.
pub type Object = BTreeMap<String, Value>;

/// Why a text is not strict JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

impl Value {
    /// The string, when this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The object, when this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The array, when this is one.
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The boolean, when this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number as an `i64`, when it is a whole number in range.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) if n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_992.0 => {
                Some(*n as i64)
            }
            _ => None,
        }
    }

    /// The number, when this is one.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The member `key` of an object, when this is one and has it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }

    /// The compact JSON text (members sorted by name, nothing escaped that
    /// need not be).
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self);
        out
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Number(n as f64)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Number(n as f64)
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Number(n as f64)
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Self {
        Value::Object(o)
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e16 {
                let _ = write!(out, "{}", *n as i64);
            } else {
                let _ = write!(out, "{n}");
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, v);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, v);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

const MAX_DEPTH: usize = 512;

/// Parses `text` strictly: one value, surrounded by whitespace at most; no
/// duplicate member names; numbers in the JSON grammar and inside `f64`;
/// no unescaped control characters. A lone surrogate escape becomes
/// U+FFFD.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.at != p.bytes.len() {
        return Err(p.error("data after the value"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn error(&self, why: &str) -> ParseError {
        ParseError(format!("{why} at byte {}", self.at))
    }

    fn skip_ws(&mut self) {
        while self.at < self.bytes.len()
            && matches!(self.bytes[self.at], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn expect(&mut self, word: &str) -> Result<(), ParseError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(())
        } else {
            Err(self.error("unexpected character"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nested too deeply"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.expect("true").map(|_| Value::Bool(true)),
            Some(b'f') => self.expect("false").map(|_| Value::Bool(false)),
            Some(b'n') => self.expect("null").map(|_| Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
            None => Err(self.error("unexpected end")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.at += 1;
        let mut object = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(object));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.error("member name is no string"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.error("expected :"));
            }
            self.at += 1;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            if object.contains_key(&key) {
                return Err(self.error(&format!("duplicate member {key:?}")));
            }
            object.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(object));
                }
                _ => return Err(self.error("expected , or }")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.at += 1;
        let mut array = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(array));
        }
        loop {
            self.skip_ws();
            array.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(array));
                }
                _ => return Err(self.error("expected , or ]")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| self.error("short \\u escape"))?;
        let text = std::str::from_utf8(digits).map_err(|_| self.error("bad \\u escape"))?;
        let n = u32::from_str_radix(text, 16).map_err(|_| self.error("bad \\u escape"))?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.error("bad \\u escape"));
        }
        self.at += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let start = self.at;
            while self.at < self.bytes.len()
                && !matches!(self.bytes[self.at], b'"' | b'\\' | 0..=0x1f)
            {
                self.at += 1;
            }
            // The input is a &str: any run between ASCII delimiters is UTF-8.
            out.push_str(std::str::from_utf8(&self.bytes[start..self.at]).expect("utf-8 run"));
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escape = self.peek().ok_or_else(|| self.error("unexpected end"))?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let c = if (0xD800..0xDC00).contains(&first)
                                && self.bytes[self.at..].starts_with(b"\\u")
                            {
                                let save = self.at;
                                self.at += 2;
                                let second = self.hex4()?;
                                if (0xDC00..0xE000).contains(&second) {
                                    char::from_u32(
                                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00),
                                    )
                                } else {
                                    self.at = save;
                                    None
                                }
                            } else {
                                char::from_u32(first)
                            };
                            out.push(c.unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err(self.error("bad escape")),
                    }
                }
                Some(_) => return Err(self.error("control character in a string")),
                None => return Err(self.error("unterminated string")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(self.error("bad number")),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("bad number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("bad number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).expect("ascii");
        let n: f64 = text.parse().map_err(|_| self.error("bad number"))?;
        if n.is_infinite() {
            return Err(self.error("number out of range"));
        }
        Ok(Value::Number(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict() {
        for bad in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1} {}"#,
            r#"{"n":1e999}"#,
            r#"{"n":01}"#,
            r#"{"n":NaN}"#,
            "{\"s\":\"a\u{1}b\"}",
            r#"{"s":"\x"}"#,
            "[1,]",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn round_trip() {
        let v = parse(r#" {"b":[1,2.5,-3e2,true,null],"a":"é😀\n\"","c":{}} "#).unwrap();
        assert_eq!(v.get("a").unwrap().as_str(), Some("é😀\n\""));
        assert_eq!(
            v.to_json(),
            r#"{"a":"é😀\n\"","b":[1,2.5,-300,true,null],"c":{}}"#
        );
        assert_eq!(parse(&v.to_json()).unwrap(), v);
        assert_eq!(parse(r#""\ud800""#).unwrap().as_str(), Some("\u{FFFD}"));
    }
}
