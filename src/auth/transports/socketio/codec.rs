//! Engine.IO v4 + Socket.IO v5 packet codec.
//!
//! Target-agnostic (no WS substrate, no async) — encodes and decodes
//! both server-bound and client-bound packets. It is the wire-format
//! foundation under [`SocketIoTransport`](super::SocketIoTransport): the
//! transport encodes a BRC-103 `AuthMessage` as a Socket.IO `EVENT`
//! whose data array is `["authMessage", <json>]`, and the inbound
//! dispatch loop decodes Engine.IO `Message(4)` frames back through this
//! codec.
//!
//! # Attribution
//!
//! Vendored byte-identical from the Calhooon Socket.IO relay codec
//! (`bsv-messagebox-cloudflare`, MIT licensed) so client and server
//! agree on the wire byte-for-byte. Upstreamed here so any bsv-rs
//! consumer can speak Engine.IO 4 / Socket.IO 5 without re-deriving it.
//!
//! # Engine.IO packets
//!
//! Each packet on the wire is `<type-digit>[<payload>]`:
//!
//! | Type    | Code | Direction       | Notes                                              |
//! |---------|------|-----------------|----------------------------------------------------|
//! | open    | `0`  | server → client | handshake JSON: `{sid,upgrades,pingInterval,...}`  |
//! | close   | `1`  | bidirectional   | terminate transport                                |
//! | ping    | `2`  | bidirectional   | heartbeat (or `2probe` during transport upgrade)   |
//! | pong    | `3`  | bidirectional   | heartbeat reply (or `3probe` during upgrade)       |
//! | message | `4`  | bidirectional   | carries a Socket.IO packet in the payload          |
//! | upgrade | `5`  | client → server | client commits to the upgraded transport           |
//! | noop    | `6`  | server → client | flushes a pending HTTP poll (used during upgrade)  |
//!
//! Polling format: when an HTTP body carries multiple Engine.IO packets,
//! they are concatenated using the U+001E "record separator" (`\x1e`).
//!
//! # Socket.IO packets (carried in Engine.IO `4` payloads)
//!
//! Format: `<type-digit>[<nsp>,][<ack-id>][<json-payload>]`
//!
//! | Type           | Code |
//! |----------------|------|
//! | CONNECT        | `0`  |
//! | DISCONNECT     | `1`  |
//! | EVENT          | `2`  |
//! | ACK            | `3`  |
//! | CONNECT_ERROR  | `4`  |
//!
//! The namespace is OMITTED when it is the default `/`. When present it
//! is followed by a single `,` separator. Examples:
//!   - `0`              → CONNECT to default namespace (client → server)
//!   - `0{"sid":"x"}`   → server CONNECT ack to default ns
//!   - `0/admin,`       → CONNECT to /admin
//!   - `2["foo","bar"]` → EVENT `[foo, bar]` on default ns
//!   - `2/admin,["x"]`  → EVENT `[x]` on /admin
//!   - `212["foo"]`     → EVENT `[foo]` on default ns with ack id 12
//!
//! The reader is the reference's, `socket.io-parser` 4.2.7's
//! `decodeString` (bsv-rs#110): the run after the namespace is the id on
//! every type (`00` is a CONNECT with the id 0, written back by
//! [`SocketIoPacket::encode`]), and the payload must have the type's shape
//! (`isPayloadValid`: CONNECT an object, DISCONNECT none, CONNECT_ERROR a
//! string or an object, EVENT an array headed by a number or an unreserved
//! name, ACK an array), else `invalid payload`. The rules are in
//! `packet_rules.rs`; the frames the reference reads and this codec refuses
//! are listed in `CLAUDE.md`'s cross-SDK divergences.
//!
//! Only the no-namespace and default-`/` namespace cases are exercised
//! by [`SocketIoTransport`](super::SocketIoTransport), but the parser
//! handles arbitrary namespaces correctly so non-standard clients still
//! parse.
//!
//! # Numbers
//!
//! A packet's JSON goes through `serde_json` with its `float_roundtrip`
//! feature (the crate's `Cargo.toml`): a number reads to the correctly
//! rounded double, as the reference's `JSON.parse` reads it, and is written
//! as the shortest text that reads back to it, so every finite `f64`
//! survives a decode and an encode and a frame's encoding is a fixed point
//! (bsv-rs#285). The text may differ from `JSON.stringify`'s (`100.0` for
//! `100`, `-0.0` for `0`, an integer within `u64` kept exact); a number past
//! the double range is a `Malformed` refusal, where the reference's
//! `JSON.parse` reads it as `Infinity` and `JSON.stringify` writes `null`
//! back (a divergence, stated in `CLAUDE.md`).

use serde_json::value::RawValue;
use serde_json::Value;

use super::packet_rules;

/// U+001E record separator used between concatenated Engine.IO
/// packets in HTTP polling bodies.
pub const RECORD_SEP: char = '\x1e';

// ============================================================================
// Engine.IO
// ============================================================================

/// One Engine.IO packet in decoded form. The payload (when present) is
/// kept as `String` because the polling/WS transports always speak text
/// for the AuthSocket use-case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineIoPacket {
    /// Server → client open packet. Payload is the handshake JSON.
    Open(String),
    /// Close (transport teardown).
    Close,
    /// Engine.IO ping. The probe variant carries `"probe"` as payload
    /// during the WS upgrade dance; bare heartbeats have no payload.
    Ping(String),
    /// Engine.IO pong, mirror of [`EngineIoPacket::Ping`].
    Pong(String),
    /// Engine.IO message packet. Payload is the Socket.IO-encoded packet
    /// as a string (encoded by [`SocketIoPacket::encode`]).
    Message(String),
    /// Client → server upgrade commit packet. No payload.
    Upgrade,
    /// Server → client noop, used to flush a pending HTTP poll mid-upgrade.
    Noop,
}

impl EngineIoPacket {
    /// Encode this packet to its on-the-wire string form.
    pub fn encode(&self) -> String {
        match self {
            EngineIoPacket::Open(payload) => format!("0{payload}"),
            EngineIoPacket::Close => "1".to_string(),
            EngineIoPacket::Ping(payload) => format!("2{payload}"),
            EngineIoPacket::Pong(payload) => format!("3{payload}"),
            EngineIoPacket::Message(payload) => format!("4{payload}"),
            EngineIoPacket::Upgrade => "5".to_string(),
            EngineIoPacket::Noop => "6".to_string(),
        }
    }

    /// Decode a single Engine.IO packet from a string. Returns an error
    /// for empty input or unknown leading digit.
    pub fn decode(raw: &str) -> Result<Self, CodecError> {
        let mut chars = raw.chars();
        let head = chars.next().ok_or(CodecError::EmptyPacket)?;
        let rest: String = chars.collect();
        Ok(match head {
            '0' => EngineIoPacket::Open(rest),
            '1' => EngineIoPacket::Close,
            '2' => EngineIoPacket::Ping(rest),
            '3' => EngineIoPacket::Pong(rest),
            '4' => EngineIoPacket::Message(rest),
            '5' => {
                if !rest.is_empty() {
                    return Err(CodecError::Malformed(format!(
                        "upgrade packet must have no payload, got {rest:?}"
                    )));
                }
                EngineIoPacket::Upgrade
            }
            '6' => {
                if !rest.is_empty() {
                    return Err(CodecError::Malformed(format!(
                        "noop packet must have no payload, got {rest:?}"
                    )));
                }
                EngineIoPacket::Noop
            }
            other => return Err(CodecError::UnknownType(other)),
        })
    }
}

/// Encode a batch of packets into a single HTTP polling body using
/// the `\x1e` record separator.
pub fn encode_polling_batch(packets: &[EngineIoPacket]) -> String {
    let mut out = String::new();
    for (i, p) in packets.iter().enumerate() {
        if i > 0 {
            out.push(RECORD_SEP);
        }
        out.push_str(&p.encode());
    }
    out
}

/// Decode an HTTP polling body that may contain one or more concatenated
/// Engine.IO packets. Empty input yields an empty `Vec`, which represents
/// an empty body (treated as "client poll with no inbound data" by
/// callers).
pub fn decode_polling_batch(raw: &str) -> Result<Vec<EngineIoPacket>, CodecError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(RECORD_SEP).map(EngineIoPacket::decode).collect()
}

// ============================================================================
// Socket.IO
// ============================================================================

/// Decoded Socket.IO packet. `BINARY_EVENT` / `BINARY_ACK` are
/// intentionally omitted because the AuthSocket transport never sends
/// binary attachments — the JSON payload carries everything.
#[derive(Debug, Clone, PartialEq)]
pub enum SocketIoPacket {
    /// CONNECT (type 0). Client → server: optional auth payload.
    /// Server → client: `{ sid: <socket-sid> }`.
    Connect {
        /// Namespace this packet targets (`/` for default).
        nsp: String,
        /// The id the frame carries after the namespace: the reference
        /// reads and writes one on every packet type (bsv-rs#110).
        ack_id: Option<u64>,
        /// Optional JSON object (auth on client side, `{sid}` on server side).
        data: Option<Value>,
    },
    /// DISCONNECT (type 1). No payload.
    Disconnect {
        /// Namespace being disconnected.
        nsp: String,
        /// The id the frame carries after the namespace (bsv-rs#110).
        ack_id: Option<u64>,
    },
    /// EVENT (type 2). Payload is the JSON array `[event_name, ...args]`.
    Event {
        /// Namespace the event was emitted on.
        nsp: String,
        /// Optional ack correlation id.
        ack_id: Option<u64>,
        /// The event JSON array — `data[0]` is the event name.
        data: Vec<Value>,
    },
    /// ACK (type 3). Same shape as EVENT but `ack_id` is mandatory.
    Ack {
        /// Namespace the ack was emitted on.
        nsp: String,
        /// Ack correlation id (mirrors the originating EVENT's ack id).
        ack_id: u64,
        /// The ack JSON array of return arguments.
        data: Vec<Value>,
    },
    /// CONNECT_ERROR (type 4). Payload is the rejection reason object.
    ConnectError {
        /// Namespace the connection was rejected on.
        nsp: String,
        /// The id the frame carries after the namespace (bsv-rs#110).
        ack_id: Option<u64>,
        /// Optional rejection reason: a JSON string or object.
        data: Option<Value>,
    },
}

const DEFAULT_NSP: &str = "/";

impl SocketIoPacket {
    /// Borrow the namespace string for this packet.
    pub fn nsp(&self) -> &str {
        match self {
            SocketIoPacket::Connect { nsp, .. }
            | SocketIoPacket::Disconnect { nsp, .. }
            | SocketIoPacket::Event { nsp, .. }
            | SocketIoPacket::Ack { nsp, .. }
            | SocketIoPacket::ConnectError { nsp, .. } => nsp,
        }
    }

    /// The packet's id, on every type as the reference carries it.
    pub fn ack_id(&self) -> Option<u64> {
        match self {
            SocketIoPacket::Connect { ack_id, .. }
            | SocketIoPacket::Disconnect { ack_id, .. }
            | SocketIoPacket::Event { ack_id, .. }
            | SocketIoPacket::ConnectError { ack_id, .. } => *ack_id,
            SocketIoPacket::Ack { ack_id, .. } => Some(*ack_id),
        }
    }

    /// Encode this packet to the on-the-wire string form (without the
    /// surrounding Engine.IO `4` prefix — wrap with
    /// `EngineIoPacket::Message(s.encode())` to send).
    pub fn encode(&self) -> String {
        let mut out = String::new();
        let type_code = match self {
            SocketIoPacket::Connect { .. } => '0',
            SocketIoPacket::Disconnect { .. } => '1',
            SocketIoPacket::Event { .. } => '2',
            SocketIoPacket::Ack { .. } => '3',
            SocketIoPacket::ConnectError { .. } => '4',
        };
        out.push(type_code);

        // Namespace prefix: only present when non-default (the reference
        // omits an empty one too, `encodeAsString`). Followed by `,`.
        let nsp = self.nsp();
        if !nsp.is_empty() && nsp != DEFAULT_NSP {
            out.push_str(nsp);
            out.push(',');
        }

        // Ack id (decimal), on every type that carries one, between the
        // namespace and the JSON payload with no separator.
        if let Some(id) = self.ack_id() {
            out.push_str(&id.to_string());
        }

        // JSON payload — only present for some packet types.
        match self {
            SocketIoPacket::Connect { data, .. } | SocketIoPacket::ConnectError { data, .. } => {
                if let Some(v) = data {
                    out.push_str(&serde_json::to_string(v).unwrap_or_default());
                }
            }
            SocketIoPacket::Event { data, .. } | SocketIoPacket::Ack { data, .. } => {
                // Always serialize as a JSON array (mandatory per spec).
                let arr = Value::Array(data.clone());
                out.push_str(&serde_json::to_string(&arr).unwrap_or_default());
            }
            SocketIoPacket::Disconnect { .. } => {}
        }
        out
    }

    /// Decode a Socket.IO packet from the payload of an Engine.IO message
    /// packet (i.e. without the leading `4`), as the reference's
    /// `decodeString` reads it (bsv-rs#110): the namespace, the id on every
    /// type, the payload judged by `isPayloadValid` (`invalid payload`).
    pub fn decode(raw: &str) -> Result<Self, CodecError> {
        let mut chars = raw.chars();
        let type_ch = chars.next().ok_or(CodecError::EmptyPacket)?;
        if !('0'..='4').contains(&type_ch) {
            return Err(CodecError::UnknownType(type_ch));
        }
        let (nsp, rest) = split_namespace(chars.as_str());
        let (run, payload) = packet_rules::split_id_run(rest);
        let ack_id = packet_rules::read_id(run)?;
        let data = packet_rules::read_payload(type_ch, payload)?;
        let nsp = nsp.to_string();
        Ok(match type_ch {
            '0' => SocketIoPacket::Connect { nsp, ack_id, data },
            '1' => SocketIoPacket::Disconnect { nsp, ack_id },
            '2' => SocketIoPacket::Event {
                nsp,
                ack_id,
                data: carried_array(data, "EVENT")?,
            },
            '3' => SocketIoPacket::Ack {
                nsp,
                ack_id: ack_id.ok_or_else(|| {
                    CodecError::Malformed("socket.io ACK requires an ack id".into())
                })?,
                data: carried_array(data, "ACK")?,
            },
            _ => SocketIoPacket::ConnectError { nsp, ack_id, data },
        })
    }
}

/// The namespace and the text after it: a leading `/` up to the first `,`
/// (consumed) or the end, else the default namespace (`decodeString`,
/// `:206-219`).
fn split_namespace(rest: &str) -> (&str, &str) {
    if !rest.starts_with('/') {
        return (DEFAULT_NSP, rest);
    }
    match rest.find(',') {
        Some(comma) => (&rest[..comma], &rest[comma + 1..]),
        None => (rest, ""),
    }
}

/// An EVENT's or ACK's array, already judged by `isPayloadValid`. A frame
/// without a payload is a packet the reference reads (its `data`
/// undefined) and this crate's `Vec` cannot tell from an empty array, so it
/// is refused.
fn carried_array(data: Option<Value>, kind: &str) -> Result<Vec<Value>, CodecError> {
    match data {
        Some(Value::Array(a)) => Ok(a),
        _ => Err(CodecError::Malformed(format!(
            "socket.io {kind} requires a payload"
        ))),
    }
}

/// The arguments of an EVENT or ACK packet (the payload of an Engine.IO
/// message, without the leading `4`) as their JSON texts on the wire.
///
/// [`SocketIoPacket::decode`] reads the arguments into `serde_json::Value`,
/// whose objects sort their keys; a BRC-103 certificateRequest or
/// certificateResponse is signed over the text as transmitted (#280), so
/// the transport reads an `authMessage` argument from its text here.
pub fn decode_event_args_text(raw: &str) -> Result<Vec<Box<RawValue>>, CodecError> {
    match raw.as_bytes().first() {
        None => return Err(CodecError::EmptyPacket),
        Some(b'2') | Some(b'3') => {}
        Some(_) => {
            return Err(CodecError::Malformed(
                "socket.io packet carries no event arguments".into(),
            ))
        }
    }
    // The type digit is one ASCII byte
    let (_, rest) = split_namespace(&raw[1..]);
    let (_, rest) = packet_rules::split_id_run(rest);
    serde_json::from_str(rest)
        .map_err(|e| CodecError::Malformed(format!("invalid JSON in socket.io payload: {e}")))
}

// ============================================================================
// Errors
// ============================================================================

/// Error returned by the Engine.IO / Socket.IO codec on malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The packet string was empty (no leading type digit).
    EmptyPacket,
    /// The leading type digit did not match any known packet type.
    UnknownType(char),
    /// The packet was structurally invalid (bad JSON, missing ack id, ...).
    Malformed(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::EmptyPacket => write!(f, "empty packet"),
            CodecError::UnknownType(c) => write!(f, "unknown packet type: {c:?}"),
            CodecError::Malformed(s) => write!(f, "malformed packet: {s}"),
        }
    }
}

impl std::error::Error for CodecError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_args_text_keeps_each_argument_as_written() {
        for raw in [
            r#"2["authMessage",{"b":1,"a":[2, 3]}]"#,
            r#"2/chat,["authMessage",{"b":1,"a":[2, 3]}]"#,
            r#"212["authMessage",{"b":1,"a":[2, 3]}]"#,
            r#"3/chat,7["authMessage",{"b":1,"a":[2, 3]}]"#,
        ] {
            let args = decode_event_args_text(raw).unwrap();
            assert_eq!(args.len(), 2, "{raw}");
            assert_eq!(args[0].get(), r#""authMessage""#);
            assert_eq!(args[1].get(), r#"{"b":1,"a":[2, 3]}"#);
        }
        assert_eq!(
            decode_event_args_text("").unwrap_err(),
            CodecError::EmptyPacket
        );
        for raw in ["0{}", "é[]", "2", "2[", "2/chat"] {
            assert!(decode_event_args_text(raw).is_err(), "{raw}");
        }
    }

    // ---------- Engine.IO ----------

    #[test]
    fn engineio_open_round_trips() {
        let payload =
            r#"{"sid":"x","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000}"#;
        let p = EngineIoPacket::Open(payload.to_string());
        let s = p.encode();
        assert!(s.starts_with('0'));
        assert_eq!(EngineIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn engineio_close_round_trips() {
        let p = EngineIoPacket::Close;
        assert_eq!(p.encode(), "1");
        assert_eq!(EngineIoPacket::decode("1").unwrap(), p);
    }

    #[test]
    fn engineio_ping_pong_no_payload() {
        assert_eq!(EngineIoPacket::Ping("".into()).encode(), "2");
        assert_eq!(EngineIoPacket::Pong("".into()).encode(), "3");
        assert_eq!(
            EngineIoPacket::decode("2").unwrap(),
            EngineIoPacket::Ping("".into())
        );
        assert_eq!(
            EngineIoPacket::decode("3").unwrap(),
            EngineIoPacket::Pong("".into())
        );
    }

    #[test]
    fn engineio_ping_pong_probe() {
        // The transport-upgrade probe sequence sends `2probe` / `3probe`
        // — these MUST round-trip through the codec or upgrade fails.
        assert_eq!(EngineIoPacket::Ping("probe".into()).encode(), "2probe");
        assert_eq!(EngineIoPacket::Pong("probe".into()).encode(), "3probe");
        assert_eq!(
            EngineIoPacket::decode("2probe").unwrap(),
            EngineIoPacket::Ping("probe".into())
        );
        assert_eq!(
            EngineIoPacket::decode("3probe").unwrap(),
            EngineIoPacket::Pong("probe".into())
        );
    }

    #[test]
    fn engineio_message_round_trips() {
        let p = EngineIoPacket::Message("2[\"hello\"]".into());
        assert_eq!(p.encode(), "42[\"hello\"]");
        assert_eq!(EngineIoPacket::decode("42[\"hello\"]").unwrap(), p);
    }

    #[test]
    fn engineio_upgrade_and_noop() {
        assert_eq!(EngineIoPacket::Upgrade.encode(), "5");
        assert_eq!(EngineIoPacket::Noop.encode(), "6");
        assert_eq!(
            EngineIoPacket::decode("5").unwrap(),
            EngineIoPacket::Upgrade
        );
        assert_eq!(EngineIoPacket::decode("6").unwrap(), EngineIoPacket::Noop);
    }

    #[test]
    fn engineio_decode_rejects_empty() {
        assert_eq!(EngineIoPacket::decode(""), Err(CodecError::EmptyPacket));
    }

    #[test]
    fn engineio_decode_rejects_unknown() {
        assert!(matches!(
            EngineIoPacket::decode("9foo"),
            Err(CodecError::UnknownType('9'))
        ));
    }

    #[test]
    fn polling_batch_single_packet() {
        let pkts = vec![EngineIoPacket::Message("2[\"a\"]".into())];
        let s = encode_polling_batch(&pkts);
        assert_eq!(s, "42[\"a\"]");
        assert_eq!(decode_polling_batch(&s).unwrap(), pkts);
    }

    #[test]
    fn polling_batch_multi_packet_uses_record_separator() {
        // Spec sample from the protocol README: `42["hello"]\x1e42["world"]`.
        let pkts = vec![
            EngineIoPacket::Message("2[\"hello\"]".into()),
            EngineIoPacket::Message("2[\"world\"]".into()),
        ];
        let s = encode_polling_batch(&pkts);
        assert_eq!(s, "42[\"hello\"]\u{1e}42[\"world\"]");
        assert_eq!(decode_polling_batch(&s).unwrap(), pkts);
    }

    #[test]
    fn polling_batch_empty_string_yields_empty_vec() {
        assert!(decode_polling_batch("").unwrap().is_empty());
    }

    // ---------- Socket.IO ----------

    #[test]
    fn socketio_connect_default_namespace_no_payload() {
        // Client→server CONNECT: bare `0` (default namespace, no auth).
        let p = SocketIoPacket::Connect {
            nsp: "/".into(),
            ack_id: None,
            data: None,
        };
        assert_eq!(p.encode(), "0");
        assert_eq!(SocketIoPacket::decode("0").unwrap(), p);
    }

    #[test]
    fn socketio_connect_default_namespace_with_sid() {
        // Server→client CONNECT ack: `0{"sid":"..."}`.
        let p = SocketIoPacket::Connect {
            nsp: "/".into(),
            ack_id: None,
            data: Some(json!({"sid":"wZX3oN0bSVIhsaknAAAI"})),
        };
        let s = p.encode();
        assert_eq!(s, r#"0{"sid":"wZX3oN0bSVIhsaknAAAI"}"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_connect_custom_namespace_with_payload() {
        let p = SocketIoPacket::Connect {
            nsp: "/admin".into(),
            ack_id: None,
            data: Some(json!({"token":"123"})),
        };
        let s = p.encode();
        assert_eq!(s, r#"0/admin,{"token":"123"}"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_disconnect_default_namespace() {
        let p = SocketIoPacket::Disconnect {
            nsp: "/".into(),
            ack_id: None,
        };
        assert_eq!(p.encode(), "1");
        assert_eq!(SocketIoPacket::decode("1").unwrap(), p);
    }

    #[test]
    fn socketio_disconnect_custom_namespace_round_trips() {
        let p = SocketIoPacket::Disconnect {
            nsp: "/admin".into(),
            ack_id: None,
        };
        // Wire form per spec sample: `1/admin,`
        assert_eq!(p.encode(), "1/admin,");
        assert_eq!(SocketIoPacket::decode("1/admin,").unwrap(), p);
    }

    #[test]
    fn socketio_event_default_namespace_round_trips() {
        let p = SocketIoPacket::Event {
            nsp: "/".into(),
            ack_id: None,
            data: vec![json!("foo"), json!("bar")],
        };
        let s = p.encode();
        assert_eq!(s, r#"2["foo","bar"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_event_custom_namespace_with_ack() {
        let p = SocketIoPacket::Event {
            nsp: "/admin".into(),
            ack_id: Some(13),
            data: vec![json!("foo")],
        };
        let s = p.encode();
        assert_eq!(s, r#"2/admin,13["foo"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_event_with_ack_id_default_namespace() {
        // Spec example: `212["foo"]` with ack id 12.
        let p = SocketIoPacket::Event {
            nsp: "/".into(),
            ack_id: Some(12),
            data: vec![json!("foo")],
        };
        let s = p.encode();
        assert_eq!(s, r#"212["foo"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_ack_round_trips() {
        let p = SocketIoPacket::Ack {
            nsp: "/".into(),
            ack_id: 12,
            data: vec![json!("ok")],
        };
        let s = p.encode();
        assert_eq!(s, r#"312["ok"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_connect_error_round_trips() {
        let p = SocketIoPacket::ConnectError {
            nsp: "/".into(),
            ack_id: None,
            data: Some(json!({"message":"Not authorized"})),
        };
        let s = p.encode();
        assert_eq!(s, r#"4{"message":"Not authorized"}"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_event_rejects_non_array_payload() {
        // `isPayloadValid`: an EVENT's payload is an array with a head.
        assert!(SocketIoPacket::decode("2{\"foo\":1}").is_err());
        assert!(SocketIoPacket::decode("2[]").is_err());
    }

    #[test]
    fn socketio_full_engineio_wrapped_event_decodes() {
        // The full wire form a client sends for `socket.emit("test","hi")`
        // on the default namespace: `42["test","hi"]`.
        let eio = EngineIoPacket::decode("42[\"test\",\"hi\"]").unwrap();
        let payload = match eio {
            EngineIoPacket::Message(p) => p,
            _ => panic!("expected message"),
        };
        let sio = SocketIoPacket::decode(&payload).unwrap();
        match sio {
            SocketIoPacket::Event { nsp, ack_id, data } => {
                assert_eq!(nsp, "/");
                assert_eq!(ack_id, None);
                assert_eq!(data, vec![json!("test"), json!("hi")]);
            }
            _ => panic!("expected event"),
        }
    }
}
