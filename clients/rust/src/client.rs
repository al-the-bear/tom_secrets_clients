// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The blocking client (protocol.md section 5): the connection, `hello`,
//! `get`, `getMany` and `getFile`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::discovery::{self, discover, read_port_file, strip_line_end};
use crate::error::{Error, ErrorInfo, ErrorKind, Result};
use crate::frames::{
    decode_payload, encode_frame, FrameReader, FRAME_BINARY, FRAME_JSON, MAX_ANSWER_PAYLOAD,
    MAX_REQUEST_PAYLOAD,
};
use crate::json::{Object, Value as Json};
use crate::reference::Reference;
use crate::sha256::{hex, sha256};
use crate::value::{wipe, File, Progress, Value};

/// The protocol version this library speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// The most references one `get_many` carries.
pub const MAX_GET_MANY: usize = 256;
/// This library's version, sent in `hello`.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The optional features (section 8) this library takes: binary frames and
/// `getFile`.
pub const CLIENT_FEATURES: [&str; 2] = ["binary", "getFile"];

/// Receives the progress notices of a waiting request. It is called on the
/// connection's reader thread: it must return quickly.
pub type ProgressCallback = Arc<dyn Fn(&Progress) + Send + Sync>;

/// What the service said in `welcome`: the protocol, its version, the
/// optional features it offers (sorted), its host name (the current value
/// of the `host` dimension) and platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    /// The protocol version (1).
    pub protocol: u32,
    /// The service's version.
    pub service_version: String,
    /// The optional features the service offers, sorted.
    pub features: Vec<String>,
    /// The service's host name.
    pub host: String,
    /// The service's platform.
    pub platform: String,
}

impl Welcome {
    /// Whether the service offers `feature`.
    pub fn offers(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

/// How a [`Client`] finds and greets the service. Every field is optional.
#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    /// The name `hello` gives the program, shown in approval prompts and
    /// never trusted (the service measures the process). Default: the
    /// executable's name.
    pub client_name: Option<String>,
    /// A client token the program was granted before (7.4), sent with every
    /// connection.
    pub client_token: Option<String>,
    /// Where `TSM_RUNTIME_DIR` and the OS variables are read from. Default:
    /// the process's environment.
    pub environment: Option<HashMap<String, String>>,
    /// `linux`, `macos` or `windows`. Default: this process's.
    pub operating_system: Option<String>,
    /// How long connecting and the service's `welcome` may take. Default
    /// 10 seconds.
    pub connect_timeout: Option<Duration>,
}

/// The options of one [`Client::get`] or [`Client::get_file`]; build them
/// with the methods (`GetOptions::default().field("UserName")`).
#[derive(Clone, Default)]
pub struct GetOptions {
    /// The field, when the reference names none. The same field in both is
    /// sent once; two different ones are malformed, reason `field_twice`.
    pub field: Option<String>,
    /// Values for dimensions beside the reference (`env` → `prod`).
    pub dimensions: BTreeMap<String, String>,
    /// Answer at once instead of waiting for an unlock or an approval
    /// (`locked` when the service is locked).
    pub no_wait: bool,
    /// How long the service may wait, in whole milliseconds, capped by the
    /// service.
    pub timeout: Option<Duration>,
    /// Receives the progress notices while the request waits.
    pub on_progress: Option<ProgressCallback>,
    /// Ask for a client token with an "always" approval (`get` only; not
    /// sent by `get_file`).
    pub want_client_token: bool,
    /// Wait out a `rate_limited` answer (its `retryAfterMs`, else one
    /// second) and send the request again.
    pub wait_on_rate_limit: bool,
}

impl fmt::Debug for GetOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetOptions")
            .field("field", &self.field)
            .field("dimensions", &self.dimensions)
            .field("no_wait", &self.no_wait)
            .field("timeout", &self.timeout)
            .field("on_progress", &self.on_progress.is_some())
            .field("want_client_token", &self.want_client_token)
            .field("wait_on_rate_limit", &self.wait_on_rate_limit)
            .finish()
    }
}

impl GetOptions {
    /// With the field `field`.
    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// With the dimension `dimension` set to `value`.
    pub fn dimension(mut self, dimension: impl Into<String>, value: impl Into<String>) -> Self {
        self.dimensions.insert(dimension.into(), value.into());
        self
    }

    /// Without waiting for an unlock or an approval.
    pub fn no_wait(mut self) -> Self {
        self.no_wait = true;
        self
    }

    /// With the service's wait bounded by `timeout`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// With `f` receiving the progress notices.
    pub fn on_progress(mut self, f: impl Fn(&Progress) + Send + Sync + 'static) -> Self {
        self.on_progress = Some(Arc::new(f));
        self
    }

    /// Asking for a client token.
    pub fn want_client_token(mut self) -> Self {
        self.want_client_token = true;
        self
    }

    /// Waiting out `rate_limited` answers.
    pub fn wait_on_rate_limit(mut self) -> Self {
        self.wait_on_rate_limit = true;
        self
    }

    fn waiting(&self) -> RequestOptions {
        RequestOptions {
            no_wait: self.no_wait,
            timeout: self.timeout,
            on_progress: self.on_progress.clone(),
            wait_on_rate_limit: self.wait_on_rate_limit,
        }
    }
}

/// The options of one [`Client::get_many`] (each [`Request`] carries its
/// field and dimensions).
#[derive(Clone, Default)]
pub struct RequestOptions {
    /// As [`GetOptions::no_wait`].
    pub no_wait: bool,
    /// As [`GetOptions::timeout`].
    pub timeout: Option<Duration>,
    /// As [`GetOptions::on_progress`].
    pub on_progress: Option<ProgressCallback>,
    /// As [`GetOptions::wait_on_rate_limit`].
    pub wait_on_rate_limit: bool,
}

impl fmt::Debug for RequestOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestOptions")
            .field("no_wait", &self.no_wait)
            .field("timeout", &self.timeout)
            .field("on_progress", &self.on_progress.is_some())
            .field("wait_on_rate_limit", &self.wait_on_rate_limit)
            .finish()
    }
}

impl RequestOptions {
    /// Without waiting for an unlock or an approval.
    pub fn no_wait(mut self) -> Self {
        self.no_wait = true;
        self
    }

    /// With the service's wait bounded by `timeout`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// With `f` receiving the progress notices.
    pub fn on_progress(mut self, f: impl Fn(&Progress) + Send + Sync + 'static) -> Self {
        self.on_progress = Some(Arc::new(f));
        self
    }

    /// Waiting out `rate_limited` answers.
    pub fn wait_on_rate_limit(mut self) -> Self {
        self.wait_on_rate_limit = true;
        self
    }

    fn add_waiting(&self, request: &mut Object) {
        if self.no_wait {
            request.insert("wait".into(), false.into());
        }
        if let Some(t) = self.timeout {
            request.insert("timeoutMs".into(), (t.as_millis() as u64).into());
        }
    }
}

/// One reference of a [`Client::get_many`]: the reference, the field when
/// the reference names none, and values for dimensions beside it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// The reference.
    pub reference: String,
    /// The field, when the reference names none.
    pub field: Option<String>,
    /// Values for dimensions beside the reference.
    pub dimensions: BTreeMap<String, String>,
}

impl Request {
    /// A request for `reference`.
    pub fn new(reference: impl Into<String>) -> Self {
        Request {
            reference: reference.into(),
            ..Request::default()
        }
    }

    /// With the field `field`.
    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// With the dimension `dimension` set to `value`.
    pub fn dimension(mut self, dimension: impl Into<String>, value: impl Into<String>) -> Self {
        self.dimensions.insert(dimension.into(), value.into());
        self
    }
}

#[derive(Clone)]
struct Resolved {
    name: String,
    token: Option<String>,
    environment: HashMap<String, String>,
    operating_system: String,
    connect_timeout: Duration,
}

/// A blocking client of the Tom Secrets Manager's secrets service: one
/// connection, opened by the first call (or [`Client::open`]); after
/// `not_running` or a dropped connection the next call connects again. It
/// is `Send` and `Sync`: calls from several threads overlap on the one
/// connection. Dropping it closes the connection. The library logs
/// nothing: no value, token or payload.
pub struct Client {
    options: Resolved,
    connection: Mutex<Option<Arc<Connection>>>,
    connecting: Mutex<()>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic in a progress callback must not poison the client.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn executable_name() -> String {
    let name = std::env::args_os()
        .next()
        .and_then(|a| {
            std::path::Path::new(&a)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    if name.is_empty() {
        "rust".to_owned()
    } else {
        name
    }
}

impl Client {
    /// A client with `options` that connects on its first call.
    pub fn new(options: ClientOptions) -> Client {
        Client {
            options: Resolved {
                name: options.client_name.unwrap_or_else(executable_name),
                token: options.client_token,
                environment: options
                    .environment
                    .unwrap_or_else(|| std::env::vars().collect()),
                operating_system: options
                    .operating_system
                    .unwrap_or_else(|| discovery::current_operating_system().to_owned()),
                connect_timeout: options.connect_timeout.unwrap_or(Duration::from_secs(10)),
            },
            connection: Mutex::new(None),
            connecting: Mutex::new(()),
        }
    }

    /// A client with the defaults, connected at once, so a missing service
    /// shows as `not_running` right away.
    pub fn connect() -> Result<Client> {
        Client::connect_with(ClientOptions::default())
    }

    /// A client with `options`, connected at once.
    pub fn connect_with(options: ClientOptions) -> Result<Client> {
        let client = Client::new(options);
        client.open()?;
        Ok(client)
    }

    /// The name `hello` gives the program.
    pub fn client_name(&self) -> &str {
        &self.options.name
    }

    /// The service's `welcome` on the current connection, or None.
    pub fn welcome(&self) -> Option<Welcome> {
        let connection = lock(&self.connection).clone()?;
        let shared = lock(&connection.shared);
        if shared.closed {
            None
        } else {
            shared.welcome.clone()
        }
    }

    /// Connects, unless a connection is open.
    pub fn open(&self) -> Result<()> {
        self.ensure().map(|_| ())
    }

    /// Closes the connection; a later call connects again.
    pub fn close(&self) {
        if let Some(connection) = lock(&self.connection).take() {
            connection.fail(Error::not_running("the client closed the connection"));
        }
    }

    /// Reads one secret. The reference is parsed locally first: a
    /// malformed one fails as [`Error::Malformed`] without a round trip, and
    /// so does a request over 64 KiB (reason `frame`).
    pub fn get(&self, reference: &str, options: GetOptions) -> Result<Value> {
        let mut request = request_item(reference, options.field.as_deref(), &options.dimensions)?;
        request.insert("op".into(), "get".into());
        let waiting = options.waiting();
        waiting.add_waiting(&mut request);
        if options.want_client_token {
            request.insert("wantClientToken".into(), true.into());
        }
        let answer = self.request(request, &waiting)?;
        if op(&answer.message) != "value" {
            return Err(Error::protocol(&format!(
                "get was answered {}",
                op(&answer.message)
            )));
        }
        Value::from_message(reference, &answer.message)
    }

    /// Reads 1 to [`MAX_GET_MANY`] secrets under one approval prompt; the
    /// results come in request order, each a value or an error. Every
    /// reference is parsed locally first. A count out of range is an
    /// [`Error::InvalidArgument`].
    pub fn get_many(
        &self,
        requests: &[Request],
        options: RequestOptions,
    ) -> Result<Vec<Result<Value>>> {
        if requests.is_empty() || requests.len() > MAX_GET_MANY {
            return Err(Error::InvalidArgument(format!(
                "a get_many carries 1 to {MAX_GET_MANY} references, not {}",
                requests.len()
            )));
        }
        let mut items = Vec::with_capacity(requests.len());
        for r in requests {
            items.push(Json::Object(request_item(
                &r.reference,
                r.field.as_deref(),
                &r.dimensions,
            )?));
        }
        let mut request = Object::new();
        request.insert("op".into(), "getMany".into());
        request.insert("refs".into(), Json::Array(items));
        options.add_waiting(&mut request);
        let answer = self.request(request, &options)?;
        let results = match (op(&answer.message), answer.message.get("results")) {
            ("values", Some(Json::Array(results))) => results,
            _ => {
                return Err(Error::protocol(&format!(
                    "getMany was answered {}",
                    op(&answer.message)
                )))
            }
        };
        if results.len() != requests.len() {
            return Err(Error::protocol(&format!(
                "getMany got {} results",
                results.len()
            )));
        }
        let mut out = Vec::with_capacity(results.len());
        for (request, result) in requests.iter().zip(results) {
            let result = result
                .as_object()
                .ok_or_else(|| Error::protocol("a getMany result is no object"))?;
            if op(result) == "error" {
                out.push(Err(Error::from_message(result)));
            } else {
                out.push(Ok(Value::from_message(&request.reference, result)?));
            }
        }
        Ok(out)
    }

    /// Reads an attachment or a typed key as bytes (5.5), over binary
    /// frames, checked against its size and SHA-256. Fails as
    /// [`Error::Unsupported`] when the service does not offer the features
    /// `binary` and `getFile` (`details.features` names the missing ones).
    pub fn get_file(&self, reference: &str, options: GetOptions) -> Result<File> {
        let mut request = request_item(reference, options.field.as_deref(), &options.dimensions)?;
        let connection = self.ensure()?;
        let welcome = lock(&connection.shared)
            .welcome
            .clone()
            .unwrap_or_else(|| Welcome {
                protocol: PROTOCOL_VERSION,
                service_version: String::new(),
                features: Vec::new(),
                host: String::new(),
                platform: String::new(),
            });
        let missing: Vec<&str> = CLIENT_FEATURES
            .iter()
            .copied()
            .filter(|f| !welcome.offers(f))
            .collect();
        if !missing.is_empty() {
            let mut details = Object::new();
            details.insert(
                "features".into(),
                Json::Array(missing.iter().map(|f| Json::from(*f)).collect()),
            );
            return Err(Error::Unsupported(ErrorInfo::new(
                format!(
                    "the service does not offer getFile (features {})",
                    missing.join(", ")
                ),
                details,
            )));
        }
        request.insert("op".into(), "getFile".into());
        let waiting = options.waiting();
        waiting.add_waiting(&mut request);
        let mut answer = self.request(request, &waiting)?;
        let file = match (op(&answer.message), answer.file.take()) {
            ("end", Some(file)) => file,
            _ => {
                return Err(Error::protocol(&format!(
                    "getFile was answered {}",
                    op(&answer.message)
                )))
            }
        };
        let data = std::mem::take(&mut answer.data);
        let name = file.get("name").and_then(Json::as_str);
        let size = file.get("size").and_then(Json::as_i64);
        let sum = answer.message.get("sha256").and_then(Json::as_str);
        match (name, size, sum) {
            (Some(name), Some(size), Some(sum))
                if size == data.len() as i64 && sum == hex(&sha256(&data)) =>
            {
                Ok(File::new(reference, name.to_owned(), data))
            }
            _ => {
                let mut data = data;
                wipe(&mut data);
                Err(Error::protocol(
                    "the file does not match its size or sha256",
                ))
            }
        }
    }

    fn request(&self, request: Object, options: &RequestOptions) -> Result<Answer> {
        loop {
            let connection = self.ensure()?;
            let answer = connection.send(request.clone(), options.on_progress.clone())?;
            if op(&answer.message) != "error" {
                return Ok(answer);
            }
            let error = Error::from_message(&answer.message);
            if error.kind() != Some(ErrorKind::RateLimited) || !options.wait_on_rate_limit {
                return Err(error);
            }
            let ms = error
                .info()
                .and_then(|i| i.details.get("retryAfterMs"))
                .and_then(Json::as_i64)
                .filter(|ms| *ms > 0)
                .unwrap_or(1000);
            thread::sleep(Duration::from_millis(ms as u64));
        }
    }

    fn ensure(&self) -> Result<Arc<Connection>> {
        if let Some(c) = lock(&self.connection).as_ref() {
            if !lock(&c.shared).closed {
                return Ok(c.clone());
            }
        }
        let _connecting = lock(&self.connecting);
        if let Some(c) = lock(&self.connection).as_ref() {
            if !lock(&c.shared).closed {
                return Ok(c.clone());
            }
        }
        let connection = self.connect_once()?;
        *lock(&self.connection) = Some(connection.clone());
        Ok(connection)
    }

    fn connect_once(&self) -> Result<Arc<Connection>> {
        let o = &self.options;
        let location = discover(&o.operating_system, &o.environment, discovery::process_uid)
            .ok_or_else(|| Error::not_running("no runtime directory can be named"))?;
        let mut token = None;
        let stream = if o.operating_system == "windows" {
            let read =
                |path: &Option<String>| std::fs::read_to_string(path.as_deref().unwrap_or("")).ok();
            let port = read(&location.client_port_file)
                .as_deref()
                .and_then(read_port_file)
                .ok_or_else(|| Error::not_running("no readable client.port"))?;
            let raw = read(&location.client_token_file)
                .ok_or_else(|| Error::not_running("no client.token"))?;
            token = Some(strip_line_end(&raw).to_owned());
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            Stream::Tcp(
                std::net::TcpStream::connect_timeout(&address, o.connect_timeout)
                    .map_err(|_| Error::not_running("the connection was refused"))?,
            )
        } else {
            unix_stream(
                &location.client_socket.unwrap_or_default(),
                &location.directory,
            )?
        };
        let connection = Connection::start(stream)?;
        let mut client = Object::new();
        client.insert("name".into(), o.name.clone().into());
        client.insert("version".into(), CLIENT_VERSION.into());
        client.insert("language".into(), "rust".into());
        let mut hello = Object::new();
        hello.insert("op".into(), "hello".into());
        hello.insert("protocol".into(), u64::from(PROTOCOL_VERSION).into());
        hello.insert("client".into(), client.into());
        hello.insert(
            "features".into(),
            Json::Array(CLIENT_FEATURES.iter().map(|f| Json::from(*f)).collect()),
        );
        if let Some(t) = token {
            hello.insert("token".into(), t.into());
        }
        if let Some(t) = &o.token {
            hello.insert("clientToken".into(), t.clone().into());
        }
        if let Err(e) = connection.write(&hello) {
            connection.fail(dropped());
            return Err(e);
        }
        let deadline = Instant::now() + o.connect_timeout;
        let mut shared = lock(&connection.shared);
        loop {
            if shared.welcome.is_some() && !shared.closed {
                drop(shared);
                return Ok(connection);
            }
            if shared.closed {
                return Err(shared.error.clone().unwrap_or_else(dropped));
            }
            let now = Instant::now();
            if now >= deadline {
                drop(shared);
                connection.fail(Error::not_running("no welcome"));
                return Err(Error::not_running(&format!(
                    "no welcome within {} ms",
                    o.connect_timeout.as_millis()
                )));
            }
            shared = connection
                .changed
                .wait_timeout(shared, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("client_name", &self.options.name)
            .finish()
    }
}

#[cfg(unix)]
fn unix_stream(path: &str, directory: &str) -> Result<Stream> {
    if !std::path::Path::new(path).exists() {
        return Err(Error::not_running(&format!(
            "no client.sock in {directory}"
        )));
    }
    std::os::unix::net::UnixStream::connect(path)
        .map(Stream::Unix)
        .map_err(|_| Error::not_running("the connection was refused"))
}

#[cfg(not(unix))]
fn unix_stream(_path: &str, _directory: &str) -> Result<Stream> {
    Err(Error::not_running(
        "Unix sockets are not available on this platform",
    ))
}

fn op(message: &Object) -> &str {
    message.get("op").and_then(Json::as_str).unwrap_or("")
}

fn dropped() -> Error {
    Error::not_running("the connection to the service dropped")
}

fn request_item(
    reference: &str,
    field: Option<&str>,
    dimensions: &BTreeMap<String, String>,
) -> Result<Object> {
    let parsed = Reference::parse(reference)?;
    if let Some(field) = field {
        if parsed.field_given && field != parsed.field {
            return Err(Error::malformed(
                "field_twice",
                "the field is named in the reference and as field",
            ));
        }
    }
    let mut item = Object::new();
    item.insert("ref".into(), reference.into());
    if !dimensions.is_empty() {
        item.insert(
            "dimensions".into(),
            Json::Object(
                dimensions
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::from(v.as_str())))
                    .collect(),
            ),
        );
    }
    if let (Some(field), false) = (field, parsed.field_given) {
        item.insert("field".into(), field.into());
    }
    Ok(item)
}

enum Stream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Tcp(std::net::TcpStream),
}

impl Stream {
    fn try_clone(&self) -> std::io::Result<Stream> {
        Ok(match self {
            #[cfg(unix)]
            Stream::Unix(s) => Stream::Unix(s.try_clone()?),
            Stream::Tcp(s) => Stream::Tcp(s.try_clone()?),
        })
    }

    fn shutdown(&self) {
        let _ = match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.shutdown(Shutdown::Both),
            Stream::Tcp(s) => s.shutdown(Shutdown::Both),
        };
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.read(buf),
            Stream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.write(buf),
            Stream::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Stream::Unix(s) => s.flush(),
            Stream::Tcp(s) => s.flush(),
        }
    }
}

/// A request's last message; for `getFile` also the file message and the
/// bytes of its chunks.
struct Answer {
    message: Object,
    file: Option<Object>,
    data: Vec<u8>,
}

impl Drop for Answer {
    fn drop(&mut self) {
        wipe(&mut self.data);
    }
}

struct Pending {
    tx: mpsc::Sender<Result<Answer>>,
    on_progress: Option<ProgressCallback>,
    file: Option<Object>,
    chunks: Vec<u8>,
}

struct Shared {
    closed: bool,
    error: Option<Error>,
    welcome: Option<Welcome>,
    pending: HashMap<u64, Pending>,
    next_id: u64,
}

/// One connection: frames in and out, the open requests by id.
struct Connection {
    writer: Mutex<Stream>,
    shared: Mutex<Shared>,
    changed: Condvar,
}

impl Connection {
    fn start(stream: Stream) -> Result<Arc<Connection>> {
        let reader = stream.try_clone().map_err(|_| dropped())?;
        let connection = Arc::new(Connection {
            writer: Mutex::new(stream),
            shared: Mutex::new(Shared {
                closed: false,
                error: None,
                welcome: None,
                pending: HashMap::new(),
                next_id: 1,
            }),
            changed: Condvar::new(),
        });
        let c = connection.clone();
        thread::Builder::new()
            .name("tsm-client".into())
            .spawn(move || c.read(reader))
            .map_err(|_| Error::not_running("the reader thread could not start"))?;
        Ok(connection)
    }

    fn write(&self, message: &Object) -> Result<()> {
        let payload = Json::Object(message.clone()).to_json().into_bytes();
        if payload.len() > MAX_REQUEST_PAYLOAD {
            return Err(Error::malformed(
                "frame",
                format!(
                    "the request is {} bytes, over {MAX_REQUEST_PAYLOAD}",
                    payload.len()
                ),
            ));
        }
        let frame = encode_frame(FRAME_JSON, &payload);
        lock(&self.writer).write_all(&frame).map_err(|_| dropped())
    }

    fn send(&self, mut request: Object, on_progress: Option<ProgressCallback>) -> Result<Answer> {
        let (tx, rx) = mpsc::channel();
        let id = {
            let mut shared = lock(&self.shared);
            if shared.closed {
                return Err(dropped());
            }
            let id = shared.next_id;
            shared.next_id += 1;
            shared.pending.insert(
                id,
                Pending {
                    tx,
                    on_progress,
                    file: None,
                    chunks: Vec::new(),
                },
            );
            id
        };
        request.insert("id".into(), id.into());
        if let Err(e) = self.write(&request) {
            lock(&self.shared).pending.remove(&id);
            if e.kind() == Some(ErrorKind::NotRunning) {
                self.fail(dropped());
            }
            return Err(e);
        }
        rx.recv().unwrap_or_else(|_| Err(dropped()))
    }

    fn read(&self, mut stream: Stream) {
        let mut frames = FrameReader::new(MAX_ANSWER_PAYLOAD);
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = match stream.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    self.fail(dropped());
                    return;
                }
                Ok(n) => n,
            };
            let result = frames.add(&buffer[..n]);
            wipe(&mut buffer[..n]);
            let read = match result {
                Ok(read) => read,
                Err(e) => {
                    self.fail(Error::protocol(&e.0));
                    return;
                }
            };
            for (frame_type, mut payload) in read {
                let outcome = if frame_type == FRAME_BINARY {
                    self.on_chunk(&payload)
                } else {
                    match decode_payload(&payload) {
                        Ok(message) => self.on_message(message, &mut frames),
                        Err(e) => Err(Error::protocol(&e.0)),
                    }
                };
                wipe(&mut payload);
                if let Err(e) = outcome {
                    self.fail(e);
                    return;
                }
                if lock(&self.shared).closed {
                    return;
                }
            }
        }
    }

    fn on_message(&self, message: Object, frames: &mut FrameReader) -> Result<()> {
        let op = op(&message).to_owned();
        let id = message.get("id");
        let mut shared = lock(&self.shared);
        if shared.welcome.is_none() {
            return match op.as_str() {
                "welcome" => {
                    let welcome = welcome_of(&message)?;
                    frames.binary_allowed = welcome.offers("binary");
                    shared.welcome = Some(welcome);
                    self.changed.notify_all();
                    Ok(())
                }
                "error" if id.is_none() => Err(Error::from_message(&message)),
                _ => Err(Error::protocol(&format!(
                    "the first frame is {op}, not welcome"
                ))),
            };
        }
        if op == "error" && id.is_none() {
            return Err(Error::from_message(&message));
        }
        let Some(id) = id
            .and_then(Json::as_i64)
            .filter(|i| *i >= 0)
            .map(|i| i as u64)
        else {
            return Ok(()); // an answer nobody waits for; ignored
        };
        match op.as_str() {
            "progress" => {
                let callback = shared.pending.get(&id).and_then(|p| p.on_progress.clone());
                drop(shared);
                if let Some(callback) = callback {
                    let pending = if message.get("pending").and_then(Json::as_str) == Some("unlock")
                    {
                        "unlock"
                    } else {
                        "approval"
                    };
                    callback(&Progress {
                        pending: pending.to_owned(),
                        approval_code: message
                            .get("approvalCode")
                            .and_then(Json::as_str)
                            .map(str::to_owned),
                    });
                }
            }
            "file" => {
                if let Some(p) = shared.pending.get_mut(&id) {
                    p.file = Some(message);
                    p.chunks = Vec::new();
                }
            }
            "end" => {
                if let Some(mut p) = shared.pending.remove(&id) {
                    let Some(file) = p.file.take() else {
                        return Err(Error::protocol("end without file"));
                    };
                    let data = std::mem::take(&mut p.chunks);
                    let _ = p.tx.send(Ok(Answer {
                        message,
                        file: Some(file),
                        data,
                    }));
                }
            }
            "value" | "values" | "error" => {
                if let Some(p) = shared.pending.remove(&id) {
                    let _ = p.tx.send(Ok(Answer {
                        message,
                        file: None,
                        data: Vec::new(),
                    }));
                }
            }
            // Any other answer is one this library does not know: section 8
            // says ignore it.
            _ => {}
        }
        Ok(())
    }

    fn on_chunk(&self, payload: &[u8]) -> Result<()> {
        if payload.len() < 8 {
            return Err(Error::protocol("a binary chunk without id"));
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&payload[..8]);
        let id = u64::from_be_bytes(id);
        let mut shared = lock(&self.shared);
        match shared.pending.get_mut(&id) {
            Some(p) if p.file.is_some() => {
                p.chunks.extend_from_slice(&payload[8..]);
                Ok(())
            }
            _ => Err(Error::protocol("a chunk without file")),
        }
    }

    fn fail(&self, error: Error) {
        let pending = {
            let mut shared = lock(&self.shared);
            if shared.closed {
                return;
            }
            shared.closed = true;
            shared.error = Some(error.clone());
            self.changed.notify_all();
            std::mem::take(&mut shared.pending)
        };
        for (_, mut p) in pending {
            wipe(&mut p.chunks);
            let _ = p.tx.send(Err(error.clone()));
        }
        // Unblocks the reader thread, which then ends.
        lock(&self.writer).shutdown();
    }
}

fn welcome_of(m: &Object) -> Result<Welcome> {
    let protocol = m.get("protocol");
    if protocol.and_then(Json::as_i64) != Some(i64::from(PROTOCOL_VERSION)) {
        let mut details = Object::new();
        details.insert(
            "protocols".into(),
            Json::Array(vec![protocol.cloned().unwrap_or(Json::Null)]),
        );
        let shown = protocol.map(Json::to_json).unwrap_or_else(|| "none".into());
        return Err(Error::Unsupported(ErrorInfo::new(
            format!("the service speaks protocol {shown}"),
            details,
        )));
    }
    let text = |k: &str| m.get(k).and_then(Json::as_str).unwrap_or("").to_owned();
    let mut features: Vec<String> = m
        .get("features")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    features.sort();
    Ok(Welcome {
        protocol: PROTOCOL_VERSION,
        service_version: m
            .get("service")
            .and_then(|s| s.get("version"))
            .map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_json()))
            .unwrap_or_default(),
        features,
        host: text("host"),
        platform: text("platform"),
    })
}
