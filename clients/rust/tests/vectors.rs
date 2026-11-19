// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! The library against every vector of protocol/vectors/ that a client
//! computes: references (parse, canonical form, malformed reasons,
//! formatting), discovery and port files, and the frames of the client
//! endpoint.

use std::collections::HashMap;

use tom_secrets_client::frames::{
    decode_payload, encode_frame, FrameReader, FRAME_BINARY, FRAME_JSON, MAX_ANSWER_PAYLOAD,
    MAX_REQUEST_PAYLOAD,
};
use tom_secrets_client::json::{self, Object, Value as Json};
use tom_secrets_client::{
    discover, read_port_file, Binding, ErrorKind, Reference, Target, MAX_REFERENCE_BYTES,
    PROTOCOL_VERSION,
};

fn vectors(name: &str) -> Json {
    let path = format!(
        "{}/../../protocol/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn list<'a>(v: &'a Json, key: &str) -> &'a Vec<Json> {
    v.get(key).and_then(Json::as_array).unwrap()
}

fn s<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

fn shape(r: &Reference) -> Json {
    let mut target = Object::new();
    match &r.target {
        Target::Key(key) => {
            target.insert("kind".into(), "key".into());
            target.insert("key".into(), key.clone().into());
        }
        Target::Uuid { store, uuid } => {
            target.insert("kind".into(), "uuid".into());
            target.insert("store".into(), store.clone().into());
            target.insert("uuid".into(), uuid.clone().into());
        }
        Target::Path { store, segments } => {
            target.insert("kind".into(), "path".into());
            target.insert("store".into(), store.clone().into());
            target.insert(
                "segments".into(),
                Json::Array(segments.iter().map(|x| Json::from(x.as_str())).collect()),
            );
        }
    }
    let mut out = Object::new();
    out.insert(
        "qualifiers".into(),
        Json::Array(
            r.qualifiers
                .iter()
                .map(|q| {
                    let mut b = Object::new();
                    b.insert("dimension".into(), q.dimension.clone().into());
                    b.insert("value".into(), q.value.clone().into());
                    Json::Object(b)
                })
                .collect(),
        ),
    );
    out.insert("target".into(), Json::Object(target));
    out.insert("field".into(), r.field.clone().into());
    out.insert("fieldGiven".into(), r.field_given.into());
    Json::Object(out)
}

fn reference_of(m: &Json) -> Reference {
    let t = m.get("target").unwrap();
    let target = match s(t, "kind") {
        "key" => Target::Key(s(t, "key").into()),
        "uuid" => Target::Uuid {
            store: s(t, "store").into(),
            uuid: s(t, "uuid").into(),
        },
        _ => Target::Path {
            store: s(t, "store").into(),
            segments: list(t, "segments")
                .iter()
                .map(|x| x.as_str().unwrap().into())
                .collect(),
        },
    };
    let mut r = Reference::new(target);
    r.qualifiers = list(m, "qualifiers")
        .iter()
        .map(|q| Binding {
            dimension: s(q, "dimension").into(),
            value: s(q, "value").into(),
        })
        .collect();
    if let Some(field) = m.get("field").and_then(Json::as_str) {
        r.field = field.into();
    }
    r
}

#[test]
fn references() {
    let v = vectors("references.json");
    assert_eq!(
        v.get("maxReferenceBytes").and_then(Json::as_i64),
        Some(MAX_REFERENCE_BYTES as i64)
    );
    for c in list(&v, "valid") {
        let input = s(c, "input");
        let r = Reference::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(&shape(&r), c.get("parsed").unwrap(), "{input}");
        assert_eq!(r.canonical(), s(c, "canonical"), "{input}");
        assert_eq!(
            Reference::parse(&r.canonical()).unwrap().canonical(),
            r.canonical()
        );
    }
    for c in list(&v, "invalid") {
        let input = s(c, "input");
        let e = Reference::parse(input).expect_err(input);
        assert_eq!(e.kind(), Some(ErrorKind::Malformed), "{input}");
        assert_eq!(e.reason(), Some(s(c, "reason")), "{input}");
    }
    for c in list(&v, "format") {
        let formatted = reference_of(c.get("parsed").unwrap()).format().unwrap();
        assert_eq!(formatted, s(c, "formatted"));
        assert_eq!(
            &shape(&Reference::parse(&formatted).unwrap()),
            c.get("reparsed").unwrap()
        );
    }
}

#[test]
fn discovery() {
    let v = vectors("discovery.json");
    for c in list(&v, "cases") {
        let env: HashMap<String, String> = c
            .get("env")
            .and_then(Json::as_object)
            .unwrap()
            .iter()
            .map(|(k, x)| (k.clone(), x.as_str().unwrap().to_owned()))
            .collect();
        let uid = c.get("uid").and_then(Json::as_i64).unwrap_or(0) as u32;
        let found = discover(s(c, "os"), &env, || uid);
        let expect = c.get("expect").unwrap();
        let Some(e) = found else {
            assert_eq!(s(expect, "notRunning"), "no_runtime_directory", "{c:?}");
            continue;
        };
        let client = expect.get("client").unwrap();
        let admin = expect.get("admin").unwrap();
        let opt = |m: &Json, k: &str| m.get(k).and_then(Json::as_str).map(str::to_owned);
        assert_eq!(e.directory, s(expect, "directory"), "{c:?}");
        assert_eq!(e.client_socket, opt(client, "socket"), "{c:?}");
        assert_eq!(e.client_port_file, opt(client, "portFile"), "{c:?}");
        assert_eq!(e.client_token_file, opt(client, "tokenFile"), "{c:?}");
        assert_eq!(e.admin_socket, opt(admin, "socket"), "{c:?}");
        assert_eq!(e.admin_port_file, opt(admin, "portFile"), "{c:?}");
    }
    for c in list(&v, "portFiles") {
        let port = read_port_file(s(c, "text")).map(i64::from);
        assert_eq!(
            port,
            c.get("port").and_then(Json::as_i64),
            "{:?}",
            s(c, "text")
        );
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn frames() {
    let v = vectors("frames.json");
    assert_eq!(
        v.get("protocol").and_then(Json::as_i64),
        Some(i64::from(PROTOCOL_VERSION))
    );
    for c in list(&v, "frames") {
        let name = s(c, "name");
        let data = hex(s(c, "hex"));
        if c.get("type").and_then(Json::as_i64) == Some(i64::from(FRAME_JSON)) {
            let frames = FrameReader::new(MAX_ANSWER_PAYLOAD).add(&data).unwrap();
            assert_eq!(frames.len(), 1, "{name}");
            let message = decode_payload(&frames[0].1).unwrap();
            assert_eq!(
                &Json::Object(message.clone()),
                c.get("json").unwrap(),
                "{name}"
            );
            // Written again (members sorted), it reads as the same message.
            let again = Json::Object(message).to_json();
            assert_eq!(
                &json::parse(&again).unwrap(),
                c.get("json").unwrap(),
                "{name}"
            );
            continue;
        }
        assert!(
            FrameReader::new(MAX_ANSWER_PAYLOAD).add(&data).is_err(),
            "{name}"
        );
        let mut negotiated = FrameReader::new(MAX_ANSWER_PAYLOAD);
        negotiated.binary_allowed = true;
        let frames = negotiated.add(&data).unwrap();
        assert_eq!(frames[0].0, FRAME_BINARY);
        let payload = &frames[0].1;
        let mut id = [0u8; 8];
        id.copy_from_slice(&payload[..8]);
        assert_eq!(
            Some(u64::from_be_bytes(id) as i64),
            c.get("requestId").and_then(Json::as_i64),
            "{name}"
        );
        assert_eq!(payload[8..], hex(s(c, "chunkHex"))[..], "{name}");
    }
    for c in list(&v, "invalid") {
        let name = s(c, "name");
        let data = hex(s(c, "hex"));
        let max = if s(c, "direction") == "to service" {
            MAX_REQUEST_PAYLOAD
        } else {
            MAX_ANSWER_PAYLOAD
        };
        let read = FrameReader::new(max).add(&data);
        match s(c, "outcome") {
            "close" => assert!(read.is_err(), "{name}"),
            "read" => assert!(read.unwrap().is_empty(), "{name}"),
            _ => {
                let frames = read.unwrap();
                assert_eq!(frames.len(), 1, "{name}");
                let decoded = decode_payload(&frames[0].1);
                if name == "a first frame that is not hello" {
                    // Well-formed JSON: the order of frames is wrong, which
                    // the service checks.
                    assert!(decoded.is_ok(), "{name}");
                } else {
                    assert!(decoded.is_err(), "{name}");
                }
            }
        }
    }
}

#[test]
fn split_reads() {
    let data = encode_frame(FRAME_JSON, br#"{"op":"x"}"#);
    let mut reader = FrameReader::new(MAX_REQUEST_PAYLOAD);
    assert!(reader.add(&data[..3]).unwrap().is_empty());
    assert!(reader.add(&data[3..8]).unwrap().is_empty());
    let mut rest = data[8..].to_vec();
    rest.extend_from_slice(&data);
    assert_eq!(reader.add(&rest).unwrap().len(), 2);
}

#[test]
fn strict_payloads() {
    for bad in [
        "\u{FEFF}{\"op\":\"x\"}",
        r#"{"op":"x","op":"y"}"#,
        r#"{"op":1}"#,
        "[]",
        r#"{"op":"x","n":1e999}"#,
    ] {
        assert!(decode_payload(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(decode_payload(&[0xff, 0xfe]).is_err());
}
