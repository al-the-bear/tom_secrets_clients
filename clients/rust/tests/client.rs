// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The client against a small service in the test, on a Unix socket:
//! hello and welcome, get with progress and a rate limit, getMany, getFile
//! over binary frames, a dropped connection, values that never print, and
//! the tokio client. The full behaviour is the conformance suite's
//! (conformance/README.md).

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use tom_secrets_client::frames::{
    decode_payload, encode_frame, FrameReader, FRAME_BINARY, FRAME_JSON, MAX_REQUEST_PAYLOAD,
};
use tom_secrets_client::json::{self, Object, Value as Json};
use tom_secrets_client::{
    Client, ClientOptions, Error, ErrorKind, GetOptions, Progress, Request, RequestOptions,
    CLIENT_VERSION,
};

struct FakeService {
    dir: PathBuf,
    hellos: Arc<Mutex<Vec<Object>>>,
    streams: Arc<Mutex<Vec<UnixStream>>>,
}

impl Drop for FakeService {
    fn drop(&mut self) {
        for s in self.streams.lock().unwrap().iter() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn parse_object(text: &str) -> Object {
    json::parse(text).unwrap().as_object().unwrap().clone()
}

fn value_message(id: &Json, value: &str) -> Object {
    let mut m = parse_object(
        r#"{"op":"value","entry":{"store":"demo","uuid":"8f1c0f0e000040008000000000000002","source":"file","fetchedAt":"2026-11-19T10:00:00Z"},"bound":{"env":"prod"},"version":{"modified":"2026-11-19T09:00:00.250+01:00","revision":"r1"}}"#,
    );
    m.insert("id".into(), id.clone());
    m.insert("value".into(), value.into());
    m
}

impl FakeService {
    fn start(features: &[&str]) -> FakeService {
        // The system's temporary folder: a Unix socket's path is short.
        // One directory per service: the tests run in parallel threads.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tsm-rs-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = UnixListener::bind(dir.join("client.sock")).unwrap();
        let hellos: Arc<Mutex<Vec<Object>>> = Arc::default();
        let streams: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
        let features: Vec<Json> = features.iter().map(|f| Json::from(*f)).collect();
        let limited = Arc::new(Mutex::new(0));
        {
            let (hellos, streams) = (hellos.clone(), streams.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    streams.lock().unwrap().push(stream.try_clone().unwrap());
                    let (hellos, streams, features, limited) = (
                        hellos.clone(),
                        streams.clone(),
                        features.clone(),
                        limited.clone(),
                    );
                    std::thread::spawn(move || serve(stream, hellos, streams, features, limited));
                }
            });
        }
        FakeService {
            dir,
            hellos,
            streams,
        }
    }

    fn client(&self) -> Client {
        let mut env = HashMap::new();
        env.insert(
            "TSM_RUNTIME_DIR".to_owned(),
            self.dir.to_string_lossy().into_owned(),
        );
        Client::new(ClientOptions {
            client_name: Some("unit-test".into()),
            environment: Some(env),
            ..ClientOptions::default()
        })
    }
}

fn serve(
    mut stream: UnixStream,
    hellos: Arc<Mutex<Vec<Object>>>,
    streams: Arc<Mutex<Vec<UnixStream>>>,
    features: Vec<Json>,
    limited: Arc<Mutex<u32>>,
) {
    let writer = Arc::new(Mutex::new(stream.try_clone().unwrap()));
    let send = move |frame_type: u8, payload: &[u8]| {
        let _ = writer
            .lock()
            .unwrap()
            .write_all(&encode_frame(frame_type, payload));
    };
    let send_json = |m: Object| send(FRAME_JSON, Json::Object(m).to_json().as_bytes());
    let mut reader = FrameReader::new(MAX_REQUEST_PAYLOAD);
    let mut buffer = [0u8; 65536];
    loop {
        let n = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        for (_, payload) in reader.add(&buffer[..n]).unwrap() {
            let m = decode_payload(&payload).unwrap();
            let id = m.get("id").cloned().unwrap_or(Json::Null);
            match m.get("op").and_then(Json::as_str).unwrap() {
                "hello" => {
                    hellos.lock().unwrap().push(m.clone());
                    let mut w = parse_object(
                        r#"{"op":"welcome","protocol":1,"service":{"version":"0.0.0-test"},"host":"testhost","platform":"macos"}"#,
                    );
                    w.insert("features".into(), Json::Array(features.clone()));
                    send_json(w);
                }
                "get" => match m.get("ref").and_then(Json::as_str).unwrap() {
                    "missing.entry" => {
                        let mut e = parse_object(
                            r#"{"op":"error","kind":"not_found","message":"no entry","details":{"reason":"no_entry"}}"#,
                        );
                        e.insert("id".into(), id);
                        send_json(e);
                    }
                    "slow.entry" => {
                        let mut p = parse_object(
                            r#"{"op":"progress","pending":"approval","approvalCode":"123-456"}"#,
                        );
                        p.insert("id".into(), id.clone());
                        send_json(p);
                        std::thread::sleep(Duration::from_millis(20));
                        send_json(value_message(&id, "slow-secret"));
                    }
                    "limited.entry" => {
                        let first = {
                            let mut l = limited.lock().unwrap();
                            *l += 1;
                            *l == 1
                        };
                        if first {
                            let mut e = parse_object(
                                r#"{"op":"error","kind":"rate_limited","message":"slow down","details":{"retryAfterMs":10}}"#,
                            );
                            e.insert("id".into(), id);
                            send_json(e);
                        } else {
                            send_json(value_message(&id, "limited-secret"));
                        }
                    }
                    "drop.entry" => {
                        for s in streams.lock().unwrap().iter() {
                            let _ = s.shutdown(std::net::Shutdown::Both);
                        }
                    }
                    reference => {
                        let mut value = format!("secret-of-{reference}");
                        if let Some(field) = m.get("field").and_then(Json::as_str) {
                            value = format!("{value}#{field}");
                        }
                        send_json(value_message(&id, &value));
                    }
                },
                "getMany" => {
                    let results = m
                        .get("refs")
                        .and_then(Json::as_array)
                        .unwrap()
                        .iter()
                        .map(|r| {
                            let reference = r.get("ref").and_then(Json::as_str).unwrap();
                            if reference == "missing.entry" {
                                Json::Object(parse_object(
                                    r#"{"op":"error","kind":"not_found","message":"no entry"}"#,
                                ))
                            } else {
                                let mut v =
                                    value_message(&Json::Null, &format!("secret-of-{reference}"));
                                v.remove("id");
                                Json::Object(v)
                            }
                        })
                        .collect();
                    let mut out = parse_object(r#"{"op":"values"}"#);
                    out.insert("id".into(), id);
                    out.insert("results".into(), Json::Array(results));
                    send_json(out);
                }
                "getFile" => {
                    let content =
                        b"-----BEGIN DEMO KEY-----\nnot a real key\n-----END DEMO KEY-----\n";
                    let number = id.as_i64().unwrap() as u64;
                    let mut file = parse_object(r#"{"op":"file","name":"demo.pem"}"#);
                    file.insert("id".into(), id.clone());
                    file.insert("size".into(), content.len().into());
                    send_json(file);
                    for chunk in content.chunks(16) {
                        let mut frame = number.to_be_bytes().to_vec();
                        frame.extend_from_slice(chunk);
                        send(FRAME_BINARY, &frame);
                    }
                    let mut end = parse_object(r#"{"op":"end"}"#);
                    end.insert("id".into(), id);
                    // The SHA-256 of the demo content.
                    end.insert(
                        "sha256".into(),
                        "188b0b77b09b59b3026f9d05bd672d91e4978e636c61632c75ad66be4da704cf".into(),
                    );
                    send_json(end);
                }
                _ => {}
            }
        }
    }
}

#[test]
fn get_and_hello() {
    let s = FakeService::start(&[]);
    let c = s.client();
    let v = c
        .get("db.main", GetOptions::default().field("UserName"))
        .unwrap();
    assert_eq!(v.text(), Some("secret-of-db.main#UserName"));
    assert_eq!(v.entry.source, "file");
    assert_eq!(v.bound.get("env").map(String::as_str), Some("prod"));
    assert_eq!(
        v.version
            .modified
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        1_795_075_200_250
    );
    let w = c.welcome().unwrap();
    assert_eq!(
        (w.host.as_str(), w.service_version.as_str()),
        ("testhost", "0.0.0-test")
    );
    let hello = s.hellos.lock().unwrap()[0].clone();
    let client = hello.get("client").unwrap();
    assert_eq!(client.get("name").and_then(Json::as_str), Some("unit-test"));
    assert_eq!(client.get("language").and_then(Json::as_str), Some("rust"));
    assert_eq!(
        client.get("version").and_then(Json::as_str),
        Some(CLIENT_VERSION)
    );
    assert_eq!(
        hello.get("features").unwrap().to_json(),
        r#"["binary","getFile"]"#
    );
}

#[test]
fn concurrent_gets_share_one_connection() {
    let s = FakeService::start(&[]);
    let c = s.client();
    std::thread::scope(|scope| {
        for i in 0..20 {
            let c = &c;
            scope.spawn(move || {
                let reference = format!("k{i}.entry");
                let v = c.get(&reference, GetOptions::default()).unwrap();
                assert_eq!(v.text(), Some(format!("secret-of-{reference}").as_str()));
            });
        }
    });
    assert_eq!(s.hellos.lock().unwrap().len(), 1);
}

#[test]
fn progress_and_rate_limit() {
    let s = FakeService::start(&[]);
    let c = s.client();
    let seen: Arc<Mutex<Vec<Progress>>> = Arc::default();
    let log = seen.clone();
    let v = c
        .get(
            "slow.entry",
            GetOptions::default().on_progress(move |p| log.lock().unwrap().push(p.clone())),
        )
        .unwrap();
    assert_eq!(v.text(), Some("slow-secret"));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].pending, "approval");
    assert_eq!(seen[0].approval_code.as_deref(), Some("123-456"));
    let e = c.get("limited.entry", GetOptions::default()).unwrap_err();
    assert_eq!(e.kind(), Some(ErrorKind::RateLimited));
    let v = c
        .get("limited.entry", GetOptions::default().wait_on_rate_limit())
        .unwrap();
    assert_eq!(v.text(), Some("limited-secret"));
}

#[test]
fn errors() {
    let s = FakeService::start(&[]);
    let c = s.client();
    match c.get("missing.entry", GetOptions::default()) {
        Err(Error::NotFound(info)) => assert_eq!(info.message, "no entry"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        c.get("Bad Key", GetOptions::default()).unwrap_err().kind(),
        Some(ErrorKind::Malformed)
    );
    let twice = c
        .get(
            "fleet/Db/Main#UserName",
            GetOptions::default().field("Password"),
        )
        .unwrap_err();
    assert_eq!(twice.reason(), Some("field_twice"));
    let big = c
        .get(
            "db.main",
            GetOptions::default().dimension("env", "x".repeat(MAX_REQUEST_PAYLOAD)),
        )
        .unwrap_err();
    assert_eq!(big.reason(), Some("frame"));
}

#[test]
fn get_many() {
    let s = FakeService::start(&[]);
    let c = s.client();
    let results = c
        .get_many(
            &[Request::new("a.entry"), Request::new("missing.entry")],
            RequestOptions::default(),
        )
        .unwrap();
    assert_eq!(
        results[0].as_ref().unwrap().text(),
        Some("secret-of-a.entry")
    );
    assert_eq!(
        results[1].as_ref().unwrap_err().kind(),
        Some(ErrorKind::NotFound)
    );
    assert!(matches!(
        c.get_many(&[], RequestOptions::default()),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn get_file() {
    let s = FakeService::start(&["binary", "getFile"]);
    let c = s.client();
    let f = c
        .get_file("fleet/Ssh/Deploy#demo.pem", GetOptions::default())
        .unwrap();
    assert_eq!(f.name, "demo.pem");
    assert!(String::from_utf8_lossy(f.bytes()).contains("not a real key"));
    assert!(!format!("{f} {f:?}").contains("real key"));

    let plain = FakeService::start(&[]);
    match plain
        .client()
        .get_file("fleet/Ssh/Deploy#demo.pem", GetOptions::default())
    {
        Err(Error::Unsupported(info)) => {
            assert_eq!(
                info.details.get("features").unwrap().to_json(),
                r#"["binary","getFile"]"#
            )
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn values_never_print() {
    let s = FakeService::start(&[]);
    let v = s.client().get("db.main", GetOptions::default()).unwrap();
    for printed in [
        format!("{v}"),
        format!("{v:?}"),
        format!("{v:#?}"),
        v.to_string(),
    ] {
        assert!(
            printed.contains("***") && !printed.contains("secret-of"),
            "{printed}"
        );
    }
}

#[test]
fn dropped_connection_reconnects() {
    let s = FakeService::start(&[]);
    let c = s.client();
    assert_eq!(
        c.get("drop.entry", GetOptions::default())
            .unwrap_err()
            .kind(),
        Some(ErrorKind::NotRunning)
    );
    assert!(c.get("again.entry", GetOptions::default()).is_ok());
    assert_eq!(s.hellos.lock().unwrap().len(), 2);
}

#[test]
fn not_running() {
    let dir = std::env::temp_dir().join(format!("tsm-rs-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut env = HashMap::new();
    env.insert(
        "TSM_RUNTIME_DIR".to_owned(),
        dir.to_string_lossy().into_owned(),
    );
    let e = Client::connect_with(ClientOptions {
        environment: Some(env),
        operating_system: Some("linux".into()),
        ..ClientOptions::default()
    })
    .unwrap_err();
    assert_eq!(e.kind(), Some(ErrorKind::NotRunning));
    let windows = Client::new(ClientOptions {
        environment: Some(HashMap::new()),
        operating_system: Some("windows".into()),
        ..ClientOptions::default()
    });
    assert_eq!(
        windows.open().unwrap_err().kind(),
        Some(ErrorKind::NotRunning)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client() {
    // A runtime built by hand: the crate takes tokio with its `rt` feature
    // only, no macros.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let s = FakeService::start(&["binary", "getFile"]);
        let mut env = HashMap::new();
        env.insert(
            "TSM_RUNTIME_DIR".to_owned(),
            s.dir.to_string_lossy().into_owned(),
        );
        let c = tom_secrets_client::tokio::Client::connect_with(ClientOptions {
            environment: Some(env),
            ..ClientOptions::default()
        })
        .await
        .unwrap();
        // Two calls in flight at once on the one connection.
        let (c1, c2) = (c.clone(), c.clone());
        let a = tokio::spawn(async move { c1.get("a.entry", GetOptions::default()).await });
        let b = tokio::spawn(async move {
            c2.get_file("fleet/Ssh/Deploy#demo.pem", GetOptions::default())
                .await
        });
        assert_eq!(a.await.unwrap().unwrap().text(), Some("secret-of-a.entry"));
        assert_eq!(b.await.unwrap().unwrap().name, "demo.pem");
        let many = c
            .get_many(vec![Request::new("x.entry")], RequestOptions::default())
            .await
            .unwrap();
        assert!(many[0].is_ok());
        assert_eq!(s.hellos.lock().unwrap().len(), 1);
    });
}
