// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The async client for tokio (feature `tokio`): the blocking
//! [`crate::Client`] run on tokio's blocking pool, so a call never blocks a
//! runtime worker.
//!
//! ```no_run
//! # async fn read() -> Result<(), tom_secrets_client::Error> {
//! use tom_secrets_client::GetOptions;
//!
//! let c = tom_secrets_client::tokio::Client::connect().await?;
//! let v = c.get("telegram.bot_token", GetOptions::default()).await?;
//! # let _ = v;
//! # Ok(())
//! # }
//! ```
//!
//! Dropping a call's future does not stop the request: it runs to its end
//! on the blocking pool and its answer is dropped. Bound the service's wait
//! with [`GetOptions::timeout`] instead.

use std::sync::Arc;

use crate::error::{Error, ErrorInfo, Result};
use crate::{ClientOptions, File, GetOptions, Request, RequestOptions, Value, Welcome};

/// An async client of the secrets service: the blocking client shared with
/// tokio's blocking pool. Cloning it shares the one connection.
#[derive(Clone, Debug)]
pub struct Client {
    inner: Arc<crate::Client>,
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    ::tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
        Err(Error::Internal(ErrorInfo::new(
            format!("the blocking call ended without an answer: {e}"),
            Default::default(),
        )))
    })
}

impl Client {
    /// A client with `options` that connects on its first call.
    pub fn new(options: ClientOptions) -> Client {
        Client {
            inner: Arc::new(crate::Client::new(options)),
        }
    }

    /// A client with the defaults, connected at once.
    pub async fn connect() -> Result<Client> {
        Client::connect_with(ClientOptions::default()).await
    }

    /// A client with `options`, connected at once.
    pub async fn connect_with(options: ClientOptions) -> Result<Client> {
        let client = Client::new(options);
        client.open().await?;
        Ok(client)
    }

    /// The blocking client underneath.
    pub fn blocking(&self) -> &crate::Client {
        &self.inner
    }

    /// The service's `welcome` on the current connection, or None.
    pub fn welcome(&self) -> Option<Welcome> {
        self.inner.welcome()
    }

    /// Connects, unless a connection is open.
    pub async fn open(&self) -> Result<()> {
        let inner = self.inner.clone();
        blocking(move || inner.open()).await
    }

    /// Closes the connection; a later call connects again.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Reads one secret; see [`crate::Client::get`].
    pub async fn get(&self, reference: &str, options: GetOptions) -> Result<Value> {
        let inner = self.inner.clone();
        let reference = reference.to_owned();
        blocking(move || inner.get(&reference, options)).await
    }

    /// Reads several secrets under one approval prompt; see
    /// [`crate::Client::get_many`].
    pub async fn get_many(
        &self,
        requests: Vec<Request>,
        options: RequestOptions,
    ) -> Result<Vec<Result<Value>>> {
        let inner = self.inner.clone();
        blocking(move || inner.get_many(&requests, options)).await
    }

    /// Reads an attachment or a typed key as bytes; see
    /// [`crate::Client::get_file`].
    pub async fn get_file(&self, reference: &str, options: GetOptions) -> Result<File> {
        let inner = self.inner.clone();
        let reference = reference.to_owned();
        blocking(move || inner.get_file(&reference, options)).await
    }
}
