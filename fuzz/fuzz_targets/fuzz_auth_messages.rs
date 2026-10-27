#![no_main]
//! The BRC-103 message decoders (`auth`) on arbitrary input, as each
//! transport reads it: an `AuthMessage` from JSON (the HTTP and WebSocket
//! transports' `serde_json::from_str`, the Socket.IO transport's
//! `from_str` on an event's second argument as its text, and `from_value`
//! on it as a `Value`, as the message box reads it), then its `validate`,
//! `signing_data` and key id, the signed bytes the same after a write and a
//! read (#280); the Engine.IO and Socket.IO frames; the
//! General message's HTTP request and response payloads (bytes); a
//! certificate from bytes and from JSON; a requested certificate set (its
//! JSON a fixed point, `types` in insertion order, #288); the
//! auth headers; a nonce's format. The assertion is that each returns; the
//! target also checks round trips: a payload, a certificate and a frame that
//! parse encode to bytes that parse back to the same encoding.
use bsv_rs::auth::transports::socketio::codec::{
    decode_event_args_text, decode_polling_batch, EngineIoPacket, SocketIoPacket,
};
use bsv_rs::auth::transports::socketio::parse_app_event_payload;
use bsv_rs::auth::transports::{HttpRequest, HttpResponse, SimplifiedFetchTransport};
use bsv_rs::auth::utils::{get_nonce_random, validate_nonce_format};
use bsv_rs::auth::{
    validate_certificate_encoding, validate_requested_certificate_set, AuthMessage, Certificate,
    RequestedCertificateSet, VerifiableCertificate,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn message(message: &AuthMessage) {
    let _ = message.validate();
    let _ = message.signing_data();
    let _ = message.get_key_id(None);
    let _ = message.get_key_id(Some("peer"));
    let text = serde_json::to_string(message).expect("a message serializes");
    let again: AuthMessage = serde_json::from_str(&text).expect("a message's JSON parses");
    assert_eq!(again.signing_data(), message.signing_data());
    assert_eq!(
        serde_json::to_string(&again).expect("a message serializes"),
        text
    );
    let _ = transport().message_to_headers(message);
}

fn transport() -> &'static SimplifiedFetchTransport {
    static TRANSPORT: OnceLock<SimplifiedFetchTransport> = OnceLock::new();
    TRANSPORT.get_or_init(|| SimplifiedFetchTransport::new("http://127.0.0.1:9"))
}

fn certificate(certificate: &Certificate) {
    let _ = validate_certificate_encoding(certificate);
    let _ = certificate.verify();
    let _ = certificate.signing_hash();
    let _ = certificate.to_wallet_certificate();
    for signed in [false, true] {
        // A value over the 1 MiB bound is refused (bsv-rs#275); the
        // reader refuses one, so only a JSON-read certificate meets it.
        let Ok(bytes) = certificate.to_binary(signed) else {
            continue;
        };
        if let Ok(again) = Certificate::from_binary(&bytes) {
            assert_eq!(again.to_binary(signed).ok(), Some(bytes));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Bytes: the General message's HTTP payloads and a certificate.
    if let Ok(request) = HttpRequest::from_payload(data) {
        let bytes = request.to_payload();
        let again = HttpRequest::from_payload(&bytes).expect("a request's payload parses");
        assert_eq!(again.to_payload(), bytes);
        let _ = request.url_postfix();
    }
    if let Ok(response) = HttpResponse::from_payload(data) {
        let bytes = response.to_payload();
        let again = HttpResponse::from_payload(&bytes).expect("a response's payload parses");
        assert_eq!(again.to_payload(), bytes);
    }
    if let Ok(parsed) = Certificate::from_binary(data) {
        certificate(&parsed);
    }
    let _ = parse_app_event_payload(data);

    // JSON: the message as each transport reads it.
    if let Ok(parsed) = serde_json::from_slice::<AuthMessage>(data) {
        message(&parsed);
    }
    if let Ok(parsed) = serde_json::from_slice::<Certificate>(data) {
        certificate(&parsed);
    }
    if let Ok(parsed) = serde_json::from_slice::<VerifiableCertificate>(data) {
        let _ = parsed.revealable_fields();
        certificate(&parsed.certificate);
    }
    if let Ok(parsed) = serde_json::from_slice::<RequestedCertificateSet>(data) {
        let _ = validate_requested_certificate_set(&parsed);
        // `types` in insertion order (#288): written, read and written again,
        // the same bytes
        let text = serde_json::to_string(&parsed).expect("a set serializes");
        let again: RequestedCertificateSet =
            serde_json::from_str(&text).expect("a set's JSON parses");
        assert_eq!(
            serde_json::to_string(&again).expect("a set serializes"),
            text
        );
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Text: the frames, the headers and a nonce.
    if let Ok(packet) = EngineIoPacket::decode(text) {
        let encoded = packet.encode();
        assert_eq!(EngineIoPacket::decode(&encoded).ok(), Some(packet));
    }
    if let Ok(packets) = decode_polling_batch(text) {
        for packet in &packets {
            let _ = packet.encode();
        }
    }
    if let Ok(packet) = SocketIoPacket::decode(text) {
        let encoded = packet.encode();
        // bsv-rs#110: a CONNECT's payload of another JSON type than an object
        // re-reads as an ack id, and the rest may not decode; skipped until
        // the ruling.
        let known = matches!(
            &packet,
            SocketIoPacket::Connect { data: Some(v), .. }
                | SocketIoPacket::ConnectError { data: Some(v), .. } if !v.is_object()
        );
        if !known {
            let again = SocketIoPacket::decode(&encoded).expect("a frame's encoding decodes");
            assert_eq!(again.encode(), encoded);
        }
        if let SocketIoPacket::Event { data: args, .. } = &packet {
            if let Some(value) = args.get(1) {
                if let Ok(parsed) = serde_json::from_value::<AuthMessage>(value.clone()) {
                    message(&parsed);
                }
            }
        }
    }
    if let Ok(args) = decode_event_args_text(text) {
        if let Some(arg) = args.get(1) {
            if let Ok(parsed) = serde_json::from_str::<AuthMessage>(arg.get()) {
                message(&parsed);
            }
        }
    }
    let headers: Vec<(String, String)> = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let _ = transport().headers_to_message_fields(&headers);
    let _ = validate_nonce_format(text);
    let _ = get_nonce_random(text);
});
