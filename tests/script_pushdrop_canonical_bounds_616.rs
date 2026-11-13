//! #616: `decodeCanonicalPushDrop` checks the field count, then each field's
//! bound and the running payload's, then the envelope (`ts-stack@edf6e03`
//! `PushDropValidation.ts:54-79`, the bounds at `:63-73`). A token without
//! `OP_CHECKSIG` second, which this crate's lock-before read refuses, took
//! the envelope's words from `canonical_refusal` whatever its fields; it now
//! takes the bounds' words where a field or the payload is past its bound, as
//! the reference does, and the envelope's where both are in bounds. Read at
//! the registry's public reader (`decode_and_verify_registry_token`, a basket
//! token: seven fields, 16 KiB a field, 64 KiB the payload,
//! `registryTokenValidation.ts:10-31`) and, for the strength fold's second
//! site, at the overlay admin token's static decode
//! (`decode_overlay_admin_token`, five fields, 4096 and 8192 bytes,
//! `OverlayAdminTokenTemplate.ts:29-30,159-167,237-239`). The tokens are built
//! by this crate's PushDrop writer, the second chunk replaced, and their bytes
//! pinned by the SHA-256 the reference recorded for the same shape
//! (`tests/support/pushdrop_canonical_bounds_616.mjs`, Node v22.18.0, into
//! `tests/vectors/pushdrop_canonical_bounds_616.json`).
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::decode_overlay_admin_token;
use bsv_rs::primitives::{sha256, to_hex, PublicKey};
use bsv_rs::registry::{decode_and_verify_registry_token, DefinitionType};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, ScriptChunk};
use bsv_rs::Error;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/pushdrop_canonical_bounds_616.json")).unwrap()
}

fn case(name: &str) -> Value {
    vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .cloned()
        .unwrap()
}

/// The case's token by this crate's writer: `PushDrop::lock` of the key and
/// the fields (the last one the single `last_field_byte` when the case names
/// one, which the writer pushes minimally, `OP_1` for 1), its second chunk the
/// case's opcode.
fn token(case: &Value) -> LockingScript {
    let v = vector();
    let key = PublicKey::from_hex(v["key"].as_str().unwrap()).unwrap();
    let byte = v["field_byte"].as_u64().unwrap() as u8;
    let mut fields: Vec<Vec<u8>> = case["field_lengths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|length| vec![byte; length.as_u64().unwrap() as usize])
        .collect();
    if let Some(last) = case["last_field_byte"].as_u64() {
        *fields.last_mut().unwrap() = vec![last as u8];
    }
    let mut chunks = PushDrop::new(key, fields).lock().chunks().to_vec();
    chunks[1] = ScriptChunk::new_opcode(case["second_op"].as_u64().unwrap() as u8);
    let script = LockingScript::from_chunks(chunks);
    let bytes = script.to_binary();
    assert_eq!(bytes.len() as u64, case["script_bytes"].as_u64().unwrap());
    assert_eq!(
        to_hex(&sha256(&bytes)),
        case["script_sha256"].as_str().unwrap()
    );
    script
}

/// The case read by its site's public reader, beside the reference's words as
/// that site's error.
fn refusal(name: &str) -> (Error, Error) {
    let case = case(name);
    let script = token(&case);
    let words = case["site_words"].as_str().unwrap();
    assert_eq!(case["canonical_words"].as_str().unwrap(), words);
    match case["site"].as_str().unwrap() {
        "registry" => (
            decode_and_verify_registry_token(DefinitionType::Basket, &script).unwrap_err(),
            Error::RegistryError(words.into()),
        ),
        "overlay_admin_token" => (
            decode_overlay_admin_token(&script).unwrap_err(),
            Error::OverlayError(words.into()),
        ),
        site => panic!("no reader for {site}"),
    }
}

const COUNT: &str = "Unexpected PushDrop token field count";
const OVERSIZED: &str = "PushDrop token contains an oversized field";
const PAYLOAD: &str = "PushDrop token payload is too large";
const ENVELOPE: &str = "PushDrop token must use the canonical PushDrop envelope";

#[test]
fn a_no_checksig_token_with_an_oversized_field_is_refused_in_the_bounds_words_616() {
    let (read, reference) = refusal("no_checksig_oversized_field");
    assert_eq!(
        reference,
        Error::RegistryError("PushDrop token contains an oversized field".into())
    );
    assert_eq!(read, reference);
}

#[test]
fn a_no_checksig_token_past_the_payload_bound_is_refused_in_the_bounds_words_616() {
    let (read, reference) = refusal("no_checksig_payload_too_large");
    assert_eq!(
        reference,
        Error::RegistryError("PushDrop token payload is too large".into())
    );
    assert_eq!(read, reference);
}

#[test]
fn a_no_checksig_token_in_bounds_keeps_the_envelope_words_616() {
    let (read, reference) = refusal("no_checksig_in_bounds");
    assert_eq!(
        reference,
        Error::RegistryError("PushDrop token must use the canonical PushDrop envelope".into())
    );
    assert_eq!(read, reference);
}

/// The control: with `OP_CHECKSIG` second the lock-before read succeeds and
/// the reader's own bound check speaks, before and after #616.
#[test]
fn a_checksig_token_with_an_oversized_field_keeps_the_bounds_words_616() {
    let (read, reference) = refusal("checksig_oversized_field");
    assert_eq!(read, reference);
}

// The strength fold: five shapes on which a wrong order or bound would pass
// the four above.

/// Six fields, one of 16,385 bytes: the count is judged before the bounds
/// (`PushDropValidation.ts:60-62` before `:63-73`), so a reading that checks
/// the bounds ahead of it answers the oversized field.
#[test]
fn a_wrong_count_with_an_oversized_field_is_refused_in_the_count_words_616() {
    let (read, reference) = refusal("no_checksig_wrong_count_oversized_field");
    assert_eq!(reference, Error::RegistryError(COUNT.into()));
    assert_eq!(read, reference);
}

/// A payload of exactly 65,536 bytes, every field at or under 16,384: the
/// payload bound is `>` (`:68-71`), so the envelope's words; `>=` answers the
/// payload's.
#[test]
fn a_payload_exactly_at_its_bound_keeps_the_envelope_words_616() {
    let (read, reference) = refusal("no_checksig_payload_at_bound");
    assert_eq!(reference, Error::RegistryError(ENVELOPE.into()));
    assert_eq!(read, reference);
}

/// The fourth field 16,385 bytes, which also takes the payload to 65,537: the
/// field's bound is judged before the running payload's inside the loop
/// (`:64-67` before `:68-71`), so a reading with the two swapped answers the
/// payload.
#[test]
fn a_field_past_its_bound_crossing_the_payload_is_refused_as_oversized_616() {
    let (read, reference) = refusal("no_checksig_oversized_field_crossing_payload");
    assert_eq!(reference, Error::RegistryError(OVERSIZED.into()));
    assert_eq!(read, reference);
}

/// Data fields at exactly 65,536 bytes, then an `OP_1` field: `PushDrop.decode`
/// reads the opcode as the one byte `[1]` (`PushDrop.ts:101-104`), so the
/// payload passes its bound; a reading that counts an opcode field as no byte
/// answers the envelope.
#[test]
fn an_op_1_field_counts_one_byte_toward_the_payload_616() {
    let (read, reference) = refusal("no_checksig_op_1_field_crossing_payload");
    assert_eq!(reference, Error::RegistryError(PAYLOAD.into()));
    assert_eq!(read, reference);
}

/// The second site, the overlay admin token (4096 a field, 8192 the payload,
/// five fields): both bounds at their edge keep the envelope's words, a
/// 4,097-byte field and an 8,195-byte payload refused in the bounds' words, so
/// the site's two limits reach the shared check as the reference's.
#[test]
fn the_admin_token_site_passes_its_own_bounds_to_the_canonical_refusal_616() {
    for (name, words) in [
        ("admin_token_no_checksig_at_bounds", ENVELOPE),
        ("admin_token_no_checksig_oversized_field", OVERSIZED),
        ("admin_token_no_checksig_payload_too_large", PAYLOAD),
    ] {
        let (read, reference) = refusal(name);
        assert_eq!(reference, Error::OverlayError(words.into()), "{name}");
        assert_eq!(read, reference, "{name}");
    }
}
