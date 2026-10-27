//! The Socket.IO codec reads a frame as the reference's `socket.io-parser`
//! reads it (Calhooon/bsv-rs#110). The reference's `decodeString` reads the
//! run after the namespace as the packet's id on every type and its
//! `isPayloadValid` judges the payload by the type; this crate read the id
//! only to drop it on CONNECT, DISCONNECT and CONNECT_ERROR and took any JSON
//! as their payload, so `0\n0\n` decoded to a CONNECT carrying `0`, which
//! encoded as `00`, a CONNECT with an id and no payload.
//!
//! The verdicts are `tests/vectors/socketio_packet_validity_110.json`,
//! written by `tests/support/socketio_packet_validity_110.mjs`
//! (`socket.io-parser` 4.2.7 under Node v22.18.0).
//!
//! Run with: `cargo test --features socketio --test socketio_packet_validity_110`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "socketio")]

use bsv_rs::auth::transports::socketio::codec::{CodecError, SocketIoPacket};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Vector {
    reference: String,
    id_run_units: Vec<u32>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    frame: String,
    accepted: bool,
    error: Option<String>,
    #[serde(rename = "type")]
    packet_type: Option<u8>,
    nsp: Option<String>,
    id: Option<String>,
    data_text: Option<String>,
    encoding: Option<String>,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("vectors/socketio_packet_validity_110.json")).unwrap()
}

/// The frames the reference reads and this crate refuses, each with its
/// reason (the stated difference of `CLAUDE.md`'s divergence list).
const REFUSED_HERE: [(&str, &str); 14] = [
    (
        "the issue's second fuzz input",
        "the id run's text is NaN, which the reference encodes as `0NaN` and cannot read back",
    ),
    ("a space inside the digit run", "the id is NaN"),
    (
        "a 20-digit id past u64",
        "an id past u64::MAX; the reference keeps the nearest double",
    ),
    (
        "a 21-digit id",
        "an id past u64::MAX; the reference keeps the nearest double",
    ),
    (
        "EVENT, no payload",
        "an EVENT's data is a Vec: no payload is not carried",
    ),
    (
        "EVENT, an id and no payload",
        "an EVENT's data is a Vec: no payload is not carried",
    ),
    (
        "ACK with no id",
        "an ACK's id is a u64: no id is not carried",
    ),
    (
        "ACK with an id and no payload",
        "an ACK's data is a Vec: no payload is not carried",
    ),
    (
        "ACK with no id and no payload",
        "an ACK's id is a u64: no id is not carried",
    ),
    ("a BINARY_EVENT", "the binary types are not decoded"),
    ("a BINARY_ACK", "the binary types are not decoded"),
    (
        "an empty frame",
        "the reference's `Number(\"\")` is 0, a CONNECT",
    ),
    (
        "a space as the type",
        "the reference's `Number(\" \")` is 0, a CONNECT",
    ),
    (
        "a lone surrogate escape",
        "a JSON string here is UTF-8 and holds no lone surrogate",
    ),
];

/// The frames both read whose encoding differs: an id above 2^53 is exact
/// here and the nearest double in the reference.
const ENCODED_OTHERWISE: [&str; 2] = ["a 20-digit id within u64", "an id past 2^53 within u64"];

fn type_code(packet: &SocketIoPacket) -> u8 {
    match packet {
        SocketIoPacket::Connect { .. } => 0,
        SocketIoPacket::Disconnect { .. } => 1,
        SocketIoPacket::Event { .. } => 2,
        SocketIoPacket::Ack { .. } => 3,
        SocketIoPacket::ConnectError { .. } => 4,
    }
}

fn data(packet: &SocketIoPacket) -> Option<Value> {
    match packet {
        SocketIoPacket::Connect { data, .. } | SocketIoPacket::ConnectError { data, .. } => {
            data.clone()
        }
        SocketIoPacket::Event { data, .. } | SocketIoPacket::Ack { data, .. } => {
            Some(Value::Array(data.clone()))
        }
        SocketIoPacket::Disconnect { .. } => None,
    }
}

#[test]
fn the_vector_is_the_reference_parser_s_and_the_stated_differences_are_refused() {
    let v = vector();
    assert_eq!(v.reference, "socket.io-parser 4.2.7 under Node v22.18.0");
    assert_eq!(v.cases.len(), 59);
    for (name, _) in REFUSED_HERE {
        let case = v.cases.iter().find(|c| c.name == name).expect(name);
        assert!(case.accepted, "{name}: the reference reads it");
        assert!(
            SocketIoPacket::decode(&case.frame).is_err(),
            "{name}: refused here"
        );
    }
}

#[test]
fn every_frame_the_reference_refuses_is_refused_in_its_words() {
    for case in vector().cases.iter().filter(|c| !c.accepted) {
        let err = SocketIoPacket::decode(&case.frame).expect_err(&case.name);
        let words = case.error.as_deref().unwrap();
        match err {
            CodecError::Malformed(text) => {
                assert_eq!(words, "invalid payload", "{}", case.name);
                assert!(text.starts_with("invalid payload"), "{}: {text}", case.name);
            }
            CodecError::UnknownType(_) => {
                assert!(words.starts_with("unknown packet type"), "{}", case.name)
            }
            CodecError::EmptyPacket => panic!("{}: refused as empty", case.name),
        }
    }
}

#[test]
fn every_frame_both_read_is_the_reference_s_packet_and_encoding() {
    let mut read = 0;
    for case in vector().cases.iter().filter(|c| c.accepted) {
        if REFUSED_HERE.iter().any(|(n, _)| *n == case.name) {
            continue;
        }
        read += 1;
        let packet =
            SocketIoPacket::decode(&case.frame).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(Some(type_code(&packet)), case.packet_type, "{}", case.name);
        assert_eq!(Some(packet.nsp()), case.nsp.as_deref(), "{}", case.name);
        let reference_data = case
            .data_text
            .as_deref()
            .map(|t| serde_json::from_str::<Value>(t).unwrap());
        assert_eq!(data(&packet), reference_data, "{}", case.name);
        let encoded = packet.encode();
        if ENCODED_OTHERWISE.contains(&case.name.as_str()) {
            assert_ne!(Some(&encoded), case.encoding.as_ref(), "{}", case.name);
            assert_eq!(
                packet.ack_id().map(|id| id.to_string()),
                Some(case.frame[1..].split('[').next().unwrap().to_string()),
                "{}: the id read exactly",
                case.name
            );
        } else {
            assert_eq!(
                packet.ack_id().map(|id| id.to_string()),
                case.id,
                "{}",
                case.name
            );
            assert_eq!(Some(&encoded), case.encoding.as_ref(), "{}", case.name);
        }
        // The encoding is a fixed point: it reads back to the packet
        let again = SocketIoPacket::decode(&encoded).unwrap();
        assert_eq!(again, packet, "{}", case.name);
        assert_eq!(again.encode(), encoded, "{}", case.name);
    }
    assert_eq!(read, 59 - 15 - REFUSED_HERE.len());
}

#[test]
fn the_issue_s_first_input_is_a_connect_with_an_id() {
    let packet = SocketIoPacket::decode("0\n0\n").unwrap();
    assert_eq!(
        packet,
        SocketIoPacket::Connect {
            nsp: "/".into(),
            ack_id: Some(0),
            data: None,
        }
    );
    assert_eq!(packet.encode(), "00");
    assert_eq!(SocketIoPacket::decode("00").unwrap(), packet);
}

#[test]
fn a_connect_carrying_other_json_than_an_object_is_refused() {
    for frame in ["0[1]", "0\"x\"", "0null", "0true", "0 \"x\""] {
        assert_eq!(
            SocketIoPacket::decode(frame),
            Err(CodecError::Malformed("invalid payload".into())),
            "{frame}"
        );
    }
}

#[test]
fn the_ids_of_connect_disconnect_and_connect_error_are_written_back() {
    for (packet, frame) in [
        (
            SocketIoPacket::Connect {
                nsp: "/nsp".into(),
                ack_id: Some(7),
                data: Some(serde_json::json!({"a": 1})),
            },
            "0/nsp,7{\"a\":1}",
        ),
        (
            SocketIoPacket::Disconnect {
                nsp: "/".into(),
                ack_id: Some(3),
            },
            "13",
        ),
        (
            SocketIoPacket::ConnectError {
                nsp: "/".into(),
                ack_id: Some(5),
                data: Some(Value::String("msg".into())),
            },
            "45\"msg\"",
        ),
    ] {
        assert_eq!(packet.encode(), frame);
        assert_eq!(SocketIoPacket::decode(frame).unwrap(), packet);
    }
}

#[test]
fn the_id_run_takes_the_reference_s_characters() {
    let units = vector().id_run_units;
    for u in 0..=0xffff_u32 {
        let Some(c) = char::from_u32(u) else {
            continue; // a lone surrogate is no char
        };
        let read = SocketIoPacket::decode(&format!("0{c}"));
        let in_run = matches!(
            read,
            Ok(SocketIoPacket::Connect {
                ack_id: Some(_),
                ..
            })
        );
        assert_eq!(in_run, units.contains(&u), "U+{u:04X}: {read:?}");
    }
}
