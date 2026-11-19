// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! Frames and JSON payloads (protocol.md section 2).

use crate::json::{self, Object, Value};

/// Frame type of a JSON payload.
pub const FRAME_JSON: u8 = 0;
/// Frame type of a binary chunk.
pub const FRAME_BINARY: u8 = 1;
/// The largest payload of a frame sent to the service.
pub const MAX_REQUEST_PAYLOAD: usize = 64 * 1024;
/// The largest payload of a frame the service sends.
pub const MAX_ANSWER_PAYLOAD: usize = 1024 * 1024;

/// A frame or payload that breaks section 2; the connection is closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameError(pub String);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A frame: the payload length (4 bytes big-endian), the type, the payload.
pub fn encode_frame(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.push(frame_type);
    out.extend_from_slice(payload);
    out
}

/// The message of a JSON payload; an error when it is empty, not UTF-8,
/// starts with a byte order mark, is not strict JSON, not an object, or has
/// no string `op`.
pub fn decode_payload(payload: &[u8]) -> Result<Object, FrameError> {
    if payload.is_empty() {
        return Err(FrameError("empty payload".into()));
    }
    let text =
        std::str::from_utf8(payload).map_err(|_| FrameError("payload is not UTF-8".into()))?;
    if text.starts_with('\u{FEFF}') {
        return Err(FrameError("payload starts with a byte order mark".into()));
    }
    match json::parse(text) {
        Ok(Value::Object(o)) => {
            if o.get("op").and_then(Value::as_str).is_none() {
                return Err(FrameError("payload has no op".into()));
            }
            Ok(o)
        }
        Ok(_) => Err(FrameError("payload is not a JSON object".into())),
        Err(e) => Err(FrameError(format!("payload is not JSON: {e}"))),
    }
}

/// Splits a byte stream into frames, checking every length against
/// `max_payload` before the payload is read and refusing a frame type that
/// is neither JSON nor (once negotiated) binary.
#[derive(Debug)]
pub struct FrameReader {
    max_payload: usize,
    /// Whether binary frames were negotiated (the peer offered `binary`).
    pub binary_allowed: bool,
    pending: Vec<u8>,
}

impl FrameReader {
    /// A reader for frames of at most `max_payload` bytes.
    pub fn new(max_payload: usize) -> Self {
        FrameReader {
            max_payload,
            binary_allowed: false,
            pending: Vec::new(),
        }
    }

    /// Adds `data` and returns the frames now complete, `(type, payload)`.
    pub fn add(&mut self, data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, FrameError> {
        self.pending.extend_from_slice(data);
        let mut frames = Vec::new();
        let mut offset = 0;
        while self.pending.len() - offset >= 5 {
            let head = &self.pending[offset..offset + 5];
            let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
            let frame_type = head[4];
            if length > self.max_payload {
                return Err(FrameError(format!(
                    "frame of {length} bytes over {}",
                    self.max_payload
                )));
            }
            if frame_type != FRAME_JSON && !(frame_type == FRAME_BINARY && self.binary_allowed) {
                return Err(FrameError(format!("frame type {frame_type}")));
            }
            if self.pending.len() - offset - 5 < length {
                break;
            }
            frames.push((
                frame_type,
                self.pending[offset + 5..offset + 5 + length].to_vec(),
            ));
            offset += 5 + length;
        }
        // The bytes handed out held frames (values among them): overwritten
        // before the buffer moves on.
        self.pending[..offset].fill(0);
        self.pending.drain(..offset);
        Ok(frames)
    }
}
