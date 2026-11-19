// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The error kinds and the library's error type (protocol.md section 10).

use std::fmt;

use crate::json::{Object, Value};

/// What went wrong: the protocol's kinds plus [`ErrorKind::NotRunning`],
/// which the library reports when it finds no service or loses the
/// connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// `locked`
    Locked,
    /// `denied`
    Denied,
    /// `not_found`
    NotFound,
    /// `ambiguous`
    Ambiguous,
    /// `needs_unlock`
    NeedsUnlock,
    /// `unavailable`
    Unavailable,
    /// `offline`
    Offline,
    /// `token_expired`
    TokenExpired,
    /// `malformed`
    Malformed,
    /// `timeout`
    Timeout,
    /// `rate_limited`
    RateLimited,
    /// `unsupported`
    Unsupported,
    /// `internal`
    Internal,
    /// `not_running`: no service found, or the connection lost.
    NotRunning,
}

const WIRE: [(ErrorKind, &str); 14] = [
    (ErrorKind::Locked, "locked"),
    (ErrorKind::Denied, "denied"),
    (ErrorKind::NotFound, "not_found"),
    (ErrorKind::Ambiguous, "ambiguous"),
    (ErrorKind::NeedsUnlock, "needs_unlock"),
    (ErrorKind::Unavailable, "unavailable"),
    (ErrorKind::Offline, "offline"),
    (ErrorKind::TokenExpired, "token_expired"),
    (ErrorKind::Malformed, "malformed"),
    (ErrorKind::Timeout, "timeout"),
    (ErrorKind::RateLimited, "rate_limited"),
    (ErrorKind::Unsupported, "unsupported"),
    (ErrorKind::Internal, "internal"),
    (ErrorKind::NotRunning, "not_running"),
];

impl ErrorKind {
    /// The protocol's name (`not_found`).
    pub fn as_str(self) -> &'static str {
        WIRE.iter()
            .find(|(k, _)| *k == self)
            .map(|(_, s)| *s)
            .unwrap_or("internal")
    }

    /// The kind an error message names: an unknown kind (from a later
    /// service) is [`ErrorKind::Internal`]; `not_running` is never the
    /// service's to send.
    pub fn from_wire(name: &str) -> ErrorKind {
        match WIRE.iter().find(|(_, s)| *s == name) {
            Some((ErrorKind::NotRunning, _)) | None => ErrorKind::Internal,
            Some((k, _)) => *k,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What an error says: a message for people (never a value, token or key)
/// and the details (`reason`, `candidates`, `retryAfterMs`, ...).
#[derive(Clone, Debug, PartialEq)]
pub struct ErrorInfo {
    /// For people.
    pub message: String,
    /// The error's details.
    pub details: Object,
}

impl ErrorInfo {
    /// An error with `message` and `details`.
    pub fn new(message: impl Into<String>, details: Object) -> Self {
        ErrorInfo {
            message: message.into(),
            details,
        }
    }
}

/// Every failure of the library: one variant per [`ErrorKind`], and
/// [`Error::InvalidArgument`] for a call the program gets wrong (a
/// `get_many` of no references).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// `locked`
    Locked(ErrorInfo),
    /// `denied`
    Denied(ErrorInfo),
    /// `not_found`
    NotFound(ErrorInfo),
    /// `ambiguous`
    Ambiguous(ErrorInfo),
    /// `needs_unlock`
    NeedsUnlock(ErrorInfo),
    /// `unavailable`
    Unavailable(ErrorInfo),
    /// `offline`
    Offline(ErrorInfo),
    /// `token_expired`
    TokenExpired(ErrorInfo),
    /// `malformed`
    Malformed(ErrorInfo),
    /// `timeout`
    Timeout(ErrorInfo),
    /// `rate_limited`
    RateLimited(ErrorInfo),
    /// `unsupported`
    Unsupported(ErrorInfo),
    /// `internal`
    Internal(ErrorInfo),
    /// `not_running`
    NotRunning(ErrorInfo),
    /// The program called the library wrongly; no protocol kind.
    InvalidArgument(String),
}

impl Error {
    /// The error of `kind`.
    pub fn new(kind: ErrorKind, info: ErrorInfo) -> Error {
        match kind {
            ErrorKind::Locked => Error::Locked(info),
            ErrorKind::Denied => Error::Denied(info),
            ErrorKind::NotFound => Error::NotFound(info),
            ErrorKind::Ambiguous => Error::Ambiguous(info),
            ErrorKind::NeedsUnlock => Error::NeedsUnlock(info),
            ErrorKind::Unavailable => Error::Unavailable(info),
            ErrorKind::Offline => Error::Offline(info),
            ErrorKind::TokenExpired => Error::TokenExpired(info),
            ErrorKind::Malformed => Error::Malformed(info),
            ErrorKind::Timeout => Error::Timeout(info),
            ErrorKind::RateLimited => Error::RateLimited(info),
            ErrorKind::Unsupported => Error::Unsupported(info),
            ErrorKind::Internal => Error::Internal(info),
            ErrorKind::NotRunning => Error::NotRunning(info),
        }
    }

    /// The kind, or None for [`Error::InvalidArgument`].
    pub fn kind(&self) -> Option<ErrorKind> {
        Some(match self {
            Error::Locked(_) => ErrorKind::Locked,
            Error::Denied(_) => ErrorKind::Denied,
            Error::NotFound(_) => ErrorKind::NotFound,
            Error::Ambiguous(_) => ErrorKind::Ambiguous,
            Error::NeedsUnlock(_) => ErrorKind::NeedsUnlock,
            Error::Unavailable(_) => ErrorKind::Unavailable,
            Error::Offline(_) => ErrorKind::Offline,
            Error::TokenExpired(_) => ErrorKind::TokenExpired,
            Error::Malformed(_) => ErrorKind::Malformed,
            Error::Timeout(_) => ErrorKind::Timeout,
            Error::RateLimited(_) => ErrorKind::RateLimited,
            Error::Unsupported(_) => ErrorKind::Unsupported,
            Error::Internal(_) => ErrorKind::Internal,
            Error::NotRunning(_) => ErrorKind::NotRunning,
            Error::InvalidArgument(_) => return None,
        })
    }

    /// The message and details, or None for [`Error::InvalidArgument`].
    pub fn info(&self) -> Option<&ErrorInfo> {
        match self {
            Error::Locked(i)
            | Error::Denied(i)
            | Error::NotFound(i)
            | Error::Ambiguous(i)
            | Error::NeedsUnlock(i)
            | Error::Unavailable(i)
            | Error::Offline(i)
            | Error::TokenExpired(i)
            | Error::Malformed(i)
            | Error::Timeout(i)
            | Error::RateLimited(i)
            | Error::Unsupported(i)
            | Error::Internal(i)
            | Error::NotRunning(i) => Some(i),
            Error::InvalidArgument(_) => None,
        }
    }

    /// `details.reason`, when there is one.
    pub fn reason(&self) -> Option<&str> {
        self.info()?.details.get("reason")?.as_str()
    }

    pub(crate) fn from_message(message: &Object) -> Error {
        let kind = ErrorKind::from_wire(message.get("kind").and_then(Value::as_str).unwrap_or(""));
        let text = message.get("message").and_then(Value::as_str).unwrap_or("");
        let details = message
            .get("details")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Error::new(kind, ErrorInfo::new(text, details))
    }

    pub(crate) fn not_running(why: &str) -> Error {
        Error::NotRunning(ErrorInfo::new(
            format!("the secrets service is not running: {why}"),
            Object::new(),
        ))
    }

    pub(crate) fn protocol(why: &str) -> Error {
        let mut details = Object::new();
        details.insert("code".into(), "protocol".into());
        Error::Internal(ErrorInfo::new(
            format!("the service broke the protocol: {why}"),
            details,
        ))
    }

    pub(crate) fn malformed(reason: &str, message: impl Into<String>) -> Error {
        let mut details = Object::new();
        details.insert("reason".into(), reason.into());
        Error::Malformed(ErrorInfo::new(message, details))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind(), self.info()) {
            (Some(kind), Some(info)) => match self.reason() {
                Some(reason) => write!(f, "tsm: {kind} ({reason}): {}", info.message),
                None => write!(f, "tsm: {kind}: {}", info.message),
            },
            _ => match self {
                Error::InvalidArgument(m) => write!(f, "tsm: invalid argument: {m}"),
                _ => f.write_str("tsm: error"),
            },
        }
    }
}

impl std::error::Error for Error {}

/// The library's result.
pub type Result<T> = std::result::Result<T, Error>;
