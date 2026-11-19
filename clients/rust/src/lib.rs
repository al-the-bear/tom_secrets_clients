// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The Rust client of the Tom Secrets Manager's secrets service. A program
//! reads its secrets from the secrets service that runs for its user on the
//! same machine:
//!
//! ```no_run
//! use tom_secrets_client::{Client, GetOptions};
//!
//! # fn main() -> Result<(), tom_secrets_client::Error> {
//! let c = Client::connect()?;
//! let v = c.get("[env:prod]db.main", GetOptions::default().field("UserName"))?;
//! let user_name = v.text().unwrap_or_default();
//! # let _ = user_name;
//! # Ok(())
//! # }
//! ```
//!
//! The client blocks; the `tokio` feature adds [`tokio::Client`] for async
//! code. Every failure is an [`Error`], one variant per protocol kind. A
//! [`Value`] never prints its secret, and dropping it overwrites its buffer.
//! The library is written from the protocol document (protocol.md), takes
//! no dependency without the `tokio` feature, and logs nothing.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod client;
pub mod discovery;
mod error;
pub mod frames;
pub mod json;
mod reference;
mod sha256;
mod time;
#[cfg(feature = "tokio")]
pub mod tokio;
mod value;

pub use client::{
    Client, ClientOptions, GetOptions, ProgressCallback, Request, RequestOptions, Welcome,
    CLIENT_FEATURES, CLIENT_VERSION, MAX_GET_MANY, PROTOCOL_VERSION,
};
pub use discovery::{current_operating_system, discover, read_port_file, Endpoints};
pub use error::{Error, ErrorInfo, ErrorKind, Result};
pub use reference::{Binding, Reference, Target, DEFAULT_FIELD, MAX_REFERENCE_BYTES};
pub use value::{Entry, File, Progress, Value, Version};

// The README's examples compile with the crate (`rust,no_run` blocks).
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
