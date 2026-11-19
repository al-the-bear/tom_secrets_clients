// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The conformance runner of the Rust client (crate tom-secrets-client).
//!
//! It reads one case per line on standard input,
//! `{"case": name, "runtimeDir": dir, "action": {...}}`, runs its action
//! with the library's blocking client against the service in `runtimeDir`,
//! and writes one canonical result line per case on standard output,
//! `{"case": name, "result": {...}}` (keys sorted, compact).
//! conformance/README.md defines the actions and the result shapes every
//! runner writes. `concurrent` actions run on threads, overlapping on the
//! client's one connection.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tom_secrets_client::json::{self, Object, Value as Json};
use tom_secrets_client::{
    Binding, Client, ClientOptions, Error, GetOptions, Progress, Reference, Request,
    RequestOptions, Target, Value, DEFAULT_FIELD,
};

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.expect("a case line");
        if line.trim().is_empty() {
            continue;
        }
        let request = json::parse(&line).expect("a JSON case line");
        let runtime_dir = request
            .get("runtimeDir")
            .and_then(Json::as_str)
            .unwrap_or("");
        let action = request
            .get("action")
            .and_then(Json::as_object)
            .cloned()
            .unwrap_or_default();
        let result = run_case(runtime_dir, &action);
        let mut out = Object::new();
        out.insert(
            "case".into(),
            request.get("case").cloned().unwrap_or(Json::Null),
        );
        out.insert("result".into(), Json::Object(result));
        writeln!(stdout, "{}", Json::Object(out).to_json()).expect("stdout");
        stdout.flush().expect("stdout");
    }
}

fn run_case(runtime_dir: &str, action: &Object) -> Object {
    let mut environment: HashMap<String, String> = std::env::vars().collect();
    environment.insert("TSM_RUNTIME_DIR".into(), runtime_dir.into());
    let token = action
        .get("client")
        .and_then(|c| c.get("clientToken"))
        .and_then(Json::as_str)
        .map(str::to_owned);
    let client = Client::new(ClientOptions {
        client_name: Some("conformance-runner".into()),
        client_token: token,
        environment: Some(environment),
        connect_timeout: Some(Duration::from_secs(5)),
        ..ClientOptions::default()
    });
    let result = run(&client, action);
    client.close();
    result
}

fn object(pairs: Vec<(&str, Json)>) -> Object {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn text(action: &Object, key: &str) -> Option<String> {
    action.get(key).and_then(Json::as_str).map(str::to_owned)
}

fn dimensions(value: Option<&Json>) -> BTreeMap<String, String> {
    value
        .and_then(Json::as_object)
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

type ProgressLog = Arc<Mutex<Vec<Json>>>;

fn log_progress(log: &ProgressLog) -> impl Fn(&Progress) + Send + Sync + 'static {
    let log = log.clone();
    move |p: &Progress| {
        let mut entry = object(vec![("pending", p.pending.clone().into())]);
        if let Some(code) = &p.approval_code {
            entry.insert("approvalCode".into(), code.clone().into());
        }
        log.lock().unwrap().push(Json::Object(entry));
    }
}

fn with_progress(mut result: Object, log: &ProgressLog) -> Object {
    let entries = log.lock().unwrap();
    if !entries.is_empty() {
        result.insert("progress".into(), Json::Array(entries.clone()));
    }
    result
}

fn run(client: &Client, action: &Object) -> Object {
    let reference = text(action, "ref").unwrap_or_default();
    let wait = action.get("wait").and_then(Json::as_bool) != Some(false);
    let timeout = action
        .get("timeoutMs")
        .and_then(Json::as_i64)
        .map(|ms| Duration::from_millis(ms as u64));
    match action.get("do").and_then(Json::as_str).unwrap_or("") {
        "parse" => match Reference::parse(&reference) {
            Ok(r) => object(vec![
                ("parsed", shape(&r)),
                ("canonical", r.canonical().into()),
            ]),
            Err(e) => error_result(&e),
        },
        "format" => {
            let parsed = action
                .get("parsed")
                .and_then(Json::as_object)
                .cloned()
                .unwrap_or_default();
            match from_shape(&parsed).format() {
                Ok(f) => object(vec![("formatted", f.into())]),
                Err(e) => error_result(&e),
            }
        }
        "connect" => match client.open() {
            Ok(()) => {
                let w = client.welcome().expect("a welcome after open");
                let features = w.features.iter().map(|f| Json::from(f.as_str())).collect();
                object(vec![(
                    "welcome",
                    Json::Object(object(vec![
                        ("host", w.host.into()),
                        ("platform", w.platform.into()),
                        ("features", Json::Array(features)),
                    ])),
                )])
            }
            Err(e) => error_result(&e),
        },
        "get" => {
            let log: ProgressLog = Arc::default();
            let mut options = GetOptions {
                field: text(action, "field"),
                dimensions: dimensions(action.get("dimensions")),
                no_wait: !wait,
                timeout,
                want_client_token: action.get("wantClientToken").and_then(Json::as_bool)
                    == Some(true),
                wait_on_rate_limit: action.get("waitOnRateLimit").and_then(Json::as_bool)
                    == Some(true),
                ..GetOptions::default()
            };
            options = options.on_progress(log_progress(&log));
            let result = match client.get(&reference, options) {
                Ok(v) => object(vec![("value", Json::Object(value_shape(v)))]),
                Err(e) => error_result(&e),
            };
            with_progress(result, &log)
        }
        "getMany" => {
            let log: ProgressLog = Arc::default();
            let requests: Vec<Request> = action
                .get("refs")
                .and_then(Json::as_array)
                .map(|refs| {
                    refs.iter()
                        .map(|r| Request {
                            reference: r.get("ref").and_then(Json::as_str).unwrap_or("").to_owned(),
                            field: r.get("field").and_then(Json::as_str).map(str::to_owned),
                            dimensions: dimensions(r.get("dimensions")),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let options = RequestOptions {
                no_wait: !wait,
                timeout,
                ..RequestOptions::default()
            }
            .on_progress(log_progress(&log));
            let result = match client.get_many(&requests, options) {
                Ok(results) => {
                    let list = results
                        .into_iter()
                        .map(|r| match r {
                            Ok(v) => {
                                Json::Object(object(vec![("value", Json::Object(value_shape(v)))]))
                            }
                            Err(e) => {
                                Json::Object(object(vec![("error", Json::Object(error_shape(&e)))]))
                            }
                        })
                        .collect();
                    object(vec![("results", Json::Array(list))])
                }
                Err(e) => error_result(&e),
            };
            with_progress(result, &log)
        }
        "getFile" => {
            let options = GetOptions {
                field: text(action, "field"),
                ..GetOptions::default()
            };
            match client.get_file(&reference, options) {
                Ok(f) => object(vec![(
                    "file",
                    Json::Object(object(vec![
                        ("name", f.name.clone().into()),
                        ("size", f.size().into()),
                        ("base64", base64(f.bytes()).into()),
                    ])),
                )]),
                Err(e) => error_result(&e),
            }
        }
        "concurrent" => {
            let actions = action
                .get("actions")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default();
            let results: Vec<Json> = std::thread::scope(|scope| {
                let handles: Vec<_> = actions
                    .iter()
                    .map(|a| {
                        let a = a.as_object().cloned().unwrap_or_default();
                        scope.spawn(move || Json::Object(run(client, &a)))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("a concurrent action"))
                    .collect()
            });
            object(vec![("results", Json::Array(results))])
        }
        "sequence" => {
            let mut steps = Vec::new();
            for step in action
                .get("actions")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default()
            {
                let step = step.as_object().cloned().unwrap_or_default();
                if step.get("do").and_then(Json::as_str) == Some("pause") {
                    let ms = step.get("ms").and_then(Json::as_i64).unwrap_or(0);
                    std::thread::sleep(Duration::from_millis(ms as u64));
                    continue;
                }
                steps.push(Json::Object(run(client, &step)));
            }
            object(vec![("steps", Json::Array(steps))])
        }
        other => object(vec![("unsupportedAction", other.into())]),
    }
}

fn error_result(e: &Error) -> Object {
    object(vec![("error", Json::Object(error_shape(e)))])
}

fn error_shape(e: &Error) -> Object {
    let kind = e.kind().map(|k| k.as_str()).unwrap_or("runner");
    let mut out = object(vec![("kind", kind.into())]);
    if let Some(reason) = e.reason() {
        out.insert("reason".into(), reason.into());
    } else if e.kind().is_none() {
        out.insert("reason".into(), e.to_string().into());
    }
    out
}

fn ms(t: SystemTime) -> Json {
    let ms = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    };
    Json::from(ms)
}

fn value_shape(v: Value) -> Object {
    let text = v.text().map(str::to_owned);
    let printed = [
        format!("{v}"),
        format!("{v:?}"),
        format!("{v:#?}"),
        v.to_string(),
    ];
    // Every printable form shows *** and never the value (README, Results);
    // a value that occurs in the reference cannot be told apart.
    let masked = printed.iter().all(|p| {
        p.contains("***")
            && match &text {
                Some(t) => v.reference.contains(t.as_str()) || !p.contains(t.as_str()),
                None => true,
            }
    });
    let bound = v
        .bound
        .iter()
        .map(|(k, b)| (k.clone(), Json::from(b.as_str())))
        .collect();
    let mut out = object(vec![
        ("encoding", v.encoding.clone().into()),
        ("base64", base64(v.bytes()).into()),
        (
            "entry",
            Json::Object(object(vec![
                ("store", v.entry.store.clone().into()),
                ("uuid", v.entry.uuid.clone().into()),
                ("source", v.entry.source.clone().into()),
                ("fetchedAtMs", ms(v.entry.fetched_at)),
            ])),
        ),
        ("bound", Json::Object(bound)),
        (
            "version",
            Json::Object(object(vec![
                ("modifiedMs", ms(v.version.modified)),
                ("revision", v.version.revision.clone().into()),
            ])),
        ),
        ("masked", masked.into()),
    ]);
    match text {
        Some(t) => out.insert("text".into(), t.into()),
        None => out.insert("textRefused".into(), true.into()),
    };
    if let Some(e) = v.expires {
        out.insert("expiresMs".into(), ms(e));
    }
    if let Some(t) = &v.client_token {
        out.insert("clientToken".into(), t.clone().into());
    }
    out
}

fn shape(r: &Reference) -> Json {
    let target = match &r.target {
        Target::Key(key) => object(vec![("kind", "key".into()), ("key", key.clone().into())]),
        Target::Uuid { store, uuid } => object(vec![
            ("kind", "uuid".into()),
            ("store", store.clone().into()),
            ("uuid", uuid.clone().into()),
        ]),
        Target::Path { store, segments } => object(vec![
            ("kind", "path".into()),
            ("store", store.clone().into()),
            (
                "segments",
                Json::Array(segments.iter().map(|s| Json::from(s.as_str())).collect()),
            ),
        ]),
    };
    let qualifiers = r
        .qualifiers
        .iter()
        .map(|q| {
            Json::Object(object(vec![
                ("dimension", q.dimension.clone().into()),
                ("value", q.value.clone().into()),
            ]))
        })
        .collect();
    Json::Object(object(vec![
        ("qualifiers", Json::Array(qualifiers)),
        ("target", Json::Object(target)),
        ("field", r.field.clone().into()),
        ("fieldGiven", r.field_given.into()),
    ]))
}

fn from_shape(m: &Object) -> Reference {
    let t = m
        .get("target")
        .and_then(Json::as_object)
        .cloned()
        .unwrap_or_default();
    let s = |k: &str| t.get(k).and_then(Json::as_str).unwrap_or("").to_owned();
    let target = match t.get("kind").and_then(Json::as_str) {
        Some("key") => Target::Key(s("key")),
        Some("uuid") => Target::Uuid {
            store: s("store"),
            uuid: s("uuid"),
        },
        _ => Target::Path {
            store: s("store"),
            segments: t
                .get("segments")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Json::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        },
    };
    let qualifiers = m
        .get("qualifiers")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .map(|q| Binding {
                    dimension: q
                        .get("dimension")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    value: q
                        .get("value")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                        .to_owned(),
                })
                .collect()
        })
        .unwrap_or_default();
    let mut reference = Reference::new(target);
    reference.qualifiers = qualifiers;
    reference.field = m
        .get("field")
        .and_then(Json::as_str)
        .unwrap_or(DEFAULT_FIELD)
        .to_owned();
    reference
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
