//! `KVStoreInterpreter::verify_signature_legacy` answers `true` only for a
//! KVStore token whose controller field is the key checked and whose last
//! field is that key's signature over the others.
//!
//! Every token is built by this crate's own writers' derivations (the plain
//! protocol name with the key ID `kvstore-token` and the controller's lock;
//! the `[1, "kvstore"]` namespace with the key as the key ID and the
//! controller-derived lock), signed by a `ProtoWallet` of a seeded key,
//! locked by `PushDrop::lock` and read back by `PushDrop::decode`, as a
//! caller of the door holds it. A token no controller signed, a token with
//! no fields, a signed token checked against another key and every
//! one-change copy of a signed token answer `false`; a signed token, tagged
//! or not, in either derivation, answers `true`.
#![cfg(feature = "kvstore")]
#![allow(deprecated, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::kvstore::KVStoreInterpreter;
use bsv_rs::primitives::{sha256, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel,
};

const NAMESPACE: &str = r#"[1,"kvstore"]"#;

/// A seeded key: the SHA-256 of the label and the index, never zero.
fn key(label: &str, index: u32) -> PrivateKey {
    let mut seed = label.as_bytes().to_vec();
    seed.extend_from_slice(&index.to_be_bytes());
    PrivateKey::from_bytes(&sha256(&seed)).unwrap()
}

fn sign(wallet: &ProtoWallet, data: Vec<u8>, protocol_id: Protocol, key_id: &str) -> Vec<u8> {
    wallet
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            hash_to_directly_sign: None,
            protocol_id,
            key_id: key_id.to_owned(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature
}

/// A token `controller` signed: `protocol` is `NAMESPACE` or a plain name.
fn signed_token(
    controller: &PrivateKey,
    protocol: &str,
    key_text: &str,
    value: &str,
    tags: Option<&str>,
) -> PushDrop {
    let wallet = ProtoWallet::new(Some(controller.clone()));
    let public = controller.public_key();
    let mut fields = vec![
        protocol.as_bytes().to_vec(),
        key_text.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        public.to_compressed().to_vec(),
    ];
    if let Some(tags) = tags {
        fields.push(tags.as_bytes().to_vec());
    }
    let (derivation, key_id, lock) = if protocol == NAMESPACE {
        let derivation = Protocol::new(SecurityLevel::App, "kvstore");
        let lock = wallet
            .key_deriver()
            .derive_public_key(&derivation, key_text, &Counterparty::Anyone, true)
            .unwrap();
        (derivation, key_text.to_owned(), lock)
    } else {
        let derivation = Protocol::new(SecurityLevel::App, protocol);
        (derivation, "kvstore-token".to_owned(), public)
    };
    let signature = sign(&wallet, fields.concat(), derivation, &key_id);
    fields.push(signature);
    held(PushDrop::new(lock, fields))
}

/// The PushDrop a caller holds: the token's script read back by the decoder.
fn held(token: PushDrop) -> PushDrop {
    PushDrop::decode(&token.lock()).unwrap()
}

fn verdict(token: &PushDrop, controller: &PublicKey) -> bool {
    KVStoreInterpreter::verify_signature_legacy(token, controller)
}

/// The four shapes: two derivations, each with and without tags.
fn shapes() -> [(&'static str, Option<&'static str>); 4] {
    [
        ("kvstore", None),
        ("kvstore", Some(r#"["t"]"#)),
        (NAMESPACE, None),
        (NAMESPACE, Some(r#"["t"]"#)),
    ]
}

#[test]
fn a_token_no_controller_signed_is_refused_by_the_legacy_verdict() {
    for (index, (protocol, tags)) in shapes().into_iter().enumerate() {
        let stranger = key("stranger", index as u32).public_key();
        let mut fields = vec![
            protocol.as_bytes().to_vec(),
            b"k".to_vec(),
            b"v".to_vec(),
            stranger.to_compressed().to_vec(),
        ];
        if let Some(tags) = tags {
            fields.push(tags.as_bytes().to_vec());
        }
        fields.push(vec![0x30, 0x01, 0x02]);
        let forged = held(PushDrop::new(stranger.clone(), fields));
        assert!(!verdict(&forged, &stranger), "{protocol} {tags:?}");
    }
}

#[test]
fn a_token_with_no_fields_is_refused_by_the_legacy_verdict() {
    let controller = key("controller", 0).public_key();
    let empty = PushDrop::new(controller.clone(), Vec::new());
    assert!(!verdict(&empty, &controller));
    assert!(!verdict(&held(empty), &controller));
}

#[test]
fn a_signed_token_checked_against_another_key_is_refused_by_the_legacy_verdict() {
    let controller = key("controller", 1);
    let other = key("other", 1).public_key();
    for (protocol, tags) in shapes() {
        let token = signed_token(&controller, protocol, "k", "v", tags);
        assert!(verdict(&token, &controller.public_key()), "{protocol}");
        assert!(!verdict(&token, &other), "{protocol} {tags:?}");
        if protocol == NAMESPACE {
            let lock = token.locking_public_key.clone();
            assert!(!verdict(&token, &lock), "a namespace token's lock");
        }
    }
}

#[test]
fn a_signed_token_changed_in_one_respect_is_refused_by_the_legacy_verdict() {
    let controller = key("controller", 2);
    let public = controller.public_key();
    for (protocol, tags) in shapes() {
        let token = signed_token(&controller, protocol, "k", "v", tags);
        assert!(verdict(&token, &public));
        let count = token.fields.len();

        let mut value = token.clone();
        value.fields[2] = b"w".to_vec();
        assert!(!verdict(&value, &public), "value {protocol} {tags:?}");

        let mut unsigned = token.clone();
        unsigned.fields[count - 1].clear();
        assert!(!verdict(&unsigned, &public), "empty signature {protocol}");

        let mut short = token.clone();
        short.fields.remove(2);
        assert!(
            !verdict(&short, &public),
            "a field fewer {protocol} {tags:?}"
        );

        let mut long = token.clone();
        long.fields.insert(4, b"x".to_vec());
        assert!(!verdict(&long, &public), "a field more {protocol} {tags:?}");
    }
    let namespace = signed_token(&controller, NAMESPACE, "k", "v", None);
    let mut relocked = namespace.clone();
    relocked.locking_public_key = public.clone();
    assert!(
        !verdict(&held(relocked), &public),
        "a namespace lock not derived"
    );
    let mut spaced = namespace;
    spaced.fields[0] = br#"[1, "kvstore"]"#.to_vec();
    assert!(
        !verdict(&spaced, &public),
        "a namespace not in canonical JSON"
    );
}

#[test]
fn a_signed_token_answers_true_whatever_its_tags() {
    let controller = key("controller", 3);
    let public = controller.public_key();
    for protocol in ["kvstore", NAMESPACE] {
        for tags in [None, Some(r#"["a","b"]"#), Some(r#"["a","a"]"#), Some("[]")] {
            let token = signed_token(&controller, protocol, "key", "value", tags);
            assert!(verdict(&token, &public), "{protocol} {tags:?}");
        }
    }
}

#[test]
fn a_signed_token_with_an_empty_or_zero_field_answers_true() {
    let controller = key("controller", 4);
    let public = controller.public_key();
    for protocol in ["kvstore", NAMESPACE] {
        for value in ["", "\0"] {
            let token = signed_token(&controller, protocol, "key", value, Some(r#"["t"]"#));
            assert_eq!(token.fields[2], vec![0], "OP_0 reads back as one zero byte");
            assert!(verdict(&token, &public), "{protocol} {value:?}");
            let mut changed = token.clone();
            changed.fields[1] = b"other".to_vec();
            assert!(!verdict(&changed, &public), "{protocol} {value:?} changed");
        }
    }
}

/// The invariant over generated tokens: each of 25 signed tokens of each
/// shape answers `true` against its controller, and every copy with one byte
/// of one field changed, or checked against the next token's controller,
/// answers `false`.
#[test]
fn the_legacy_verdict_is_true_exactly_for_its_controllers_signature() {
    let mut seen = [0usize; 4];
    for index in 0..100u32 {
        let shape = (index % 4) as usize;
        let (protocol, tags) = shapes()[shape];
        let controller = key("generated", index);
        let public = controller.public_key();
        let key_text = format!("key-{index}");
        let value = format!("value-{}", index * 7919);
        let token = signed_token(&controller, protocol, &key_text, &value, tags);
        assert!(verdict(&token, &public), "token {index}");
        for field in 0..token.fields.len() {
            let mut changed = token.clone();
            let bytes = &mut changed.fields[field];
            let at = index as usize % bytes.len();
            bytes[at] ^= 0x01;
            assert!(!verdict(&changed, &public), "token {index} field {field}");
        }
        let next = key("generated", index + 1).public_key();
        assert!(!verdict(&token, &next), "token {index} another key");
        seen[shape] += 1;
    }
    assert!(seen.iter().all(|&count| count >= 25), "{seen:?}");
}

/// The reference's kvstore tokens of `tests/vectors/token_envelope_544.json`
/// (recorded by `tests/support/token_envelope_544.mjs`) against the context's
/// controller: its two signed tokens `true`, and the signed fields in a loose
/// push encoding `true` (the door judges the signature, not the envelope);
/// the unsigned, the badly signed and the unlinked token `false`, and the
/// plain-name field signed under the namespace's derivation `false` (neither
/// derivation the field names verifies it).
#[test]
fn the_recorded_kvstore_tokens_take_the_legacy_verdict_of_their_signature() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap();
    let kvstore = &vector["kvstore"];
    let controller =
        PublicKey::from_hex(kvstore["context"]["controller"].as_str().unwrap()).unwrap();
    let mut answers = Vec::new();
    for case in kvstore["cases"].as_array().unwrap() {
        let script =
            bsv_rs::script::LockingScript::from_hex(case["locking_script"].as_str().unwrap())
                .unwrap();
        let answer = PushDrop::decode(&script).is_ok_and(|token| verdict(&token, &controller));
        answers.push((case["name"].as_str().unwrap().to_owned(), answer));
    }
    let expected = [
        ("reference", true),
        ("reference_tags", true),
        ("raw_protocol", false),
        ("unsigned", false),
        ("noncanonical_envelope", true),
        ("wrong_lock_key", false),
        ("bad_signature", false),
    ];
    let answers: Vec<(&str, bool)> = answers.iter().map(|(n, a)| (n.as_str(), *a)).collect();
    assert_eq!(answers, expected);
}

/// The derivation `controller` signs `protocol`'s token under: the protocol,
/// the key ID and the locking key this crate's writers use for it.
fn derivation_of(
    controller: &PrivateKey,
    protocol: &str,
    key_text: &str,
) -> (Protocol, String, PublicKey) {
    let wallet = ProtoWallet::new(Some(controller.clone()));
    if protocol.starts_with('[') {
        let derivation = Protocol::new(SecurityLevel::App, "kvstore");
        let lock = wallet
            .key_deriver()
            .derive_public_key(&derivation, key_text, &Counterparty::Anyone, true)
            .unwrap();
        (derivation, key_text.to_owned(), lock)
    } else {
        let derivation = Protocol::new(SecurityLevel::App, protocol);
        (
            derivation,
            "kvstore-token".to_owned(),
            controller.public_key(),
        )
    }
}

/// `fields` signed by `controller` under the derivation `fields[0]` and
/// `fields[1]` name (their writer's), the signature appended, locked by
/// that derivation's key and read back by the decoder.
fn signed_fields(controller: &PrivateKey, mut fields: Vec<Vec<u8>>) -> PushDrop {
    let protocol = String::from_utf8(fields[0].clone()).unwrap();
    let key_text = String::from_utf8(fields[1].clone()).unwrap();
    let (derivation, key_id, lock) = derivation_of(controller, &protocol, &key_text);
    let wallet = ProtoWallet::new(Some(controller.clone()));
    let signature = sign(&wallet, fields.concat(), derivation, &key_id);
    fields.push(signature);
    held(PushDrop::new(lock, fields))
}

/// A token with an empty key field, an empty tags field, or both with an
/// empty value, each pushed as `OP_0` and read back as one zero byte, keeps
/// `true` against its controller and is `false` once the key changes.
#[test]
fn a_signed_token_with_an_empty_key_or_tags_field_answers_true() {
    let controller = key("controller", 5);
    let public = controller.public_key();
    let mut cases = vec![
        ("kvstore", "", "value", Some(r#"["t"]"#)),
        ("kvstore", "", "", None),
        ("kvstore", "", "", Some("")),
    ];
    for protocol in ["kvstore", NAMESPACE] {
        cases.push((protocol, "key", "value", Some("")));
        cases.push((protocol, "key", "", Some("")));
    }
    for (protocol, key_text, value, tags) in cases {
        let token = signed_token(&controller, protocol, key_text, value, tags);
        let zeros = token
            .fields
            .iter()
            .filter(|field| field.as_slice() == [0])
            .count();
        let expected = [key_text, value, tags.unwrap_or("x")]
            .iter()
            .filter(|text| text.is_empty())
            .count();
        assert_eq!(
            zeros, expected,
            "{protocol} {key_text:?} {value:?} {tags:?}"
        );
        assert!(
            verdict(&token, &public),
            "{protocol} {key_text:?} {value:?} {tags:?}"
        );
        let mut changed = token.clone();
        changed.fields[1] = b"other".to_vec();
        assert!(
            !verdict(&changed, &public),
            "{protocol} {key_text:?} changed"
        );
    }
}

/// A plain-name token keeps `true` whatever key locks it: the door judges
/// the signature, and a plain-name token's lock is not judged (as
/// `verify_signature` does not judge it).
#[test]
fn a_signed_plain_name_token_answers_true_whatever_its_lock() {
    let controller = key("controller", 6);
    let public = controller.public_key();
    for tags in [None, Some(r#"["t"]"#)] {
        let token = signed_token(&controller, "kvstore", "k", "v", tags);
        let mut relocked = token.clone();
        relocked.locking_public_key = key("stranger", 6).public_key();
        let relocked = held(relocked);
        assert_ne!(relocked.locking_public_key, public);
        assert!(verdict(&relocked, &public), "{tags:?}");
    }
}

/// A token of four or seven fields answers `false`, the controller's
/// signature over its other fields valid: the count is five or six.
#[test]
fn a_token_of_four_or_seven_fields_the_controller_signed_is_refused() {
    let controller = key("controller", 7);
    let public = controller.public_key();
    let c = public.to_compressed().to_vec();
    for protocol in ["kvstore", NAMESPACE] {
        let p = protocol.as_bytes().to_vec();
        let seven = signed_fields(
            &controller,
            vec![
                p.clone(),
                b"k".to_vec(),
                b"v".to_vec(),
                c.clone(),
                br#"["t"]"#.to_vec(),
                b"x".to_vec(),
            ],
        );
        assert_eq!(seven.fields.len(), 7);
        assert!(!verdict(&seven, &public), "seven {protocol}");
        let four = signed_fields(&controller, vec![p.clone(), b"k".to_vec(), c.clone()]);
        assert_eq!(four.fields.len(), 4);
        assert!(!verdict(&four, &public), "four {protocol}");
        let five = signed_fields(
            &controller,
            vec![p, b"k".to_vec(), b"v".to_vec(), c.clone()],
        );
        assert!(verdict(&five, &public), "the five-field control {protocol}");
    }
}

/// A namespace token whose protocol field is not canonical JSON answers
/// `false`, signed as such by the controller and locked by the
/// controller-derived key.
#[test]
fn a_namespace_token_signed_in_noncanonical_json_is_refused() {
    let controller = key("controller", 8);
    let public = controller.public_key();
    for protocol in [
        r#"[1, "kvstore"]"#,
        r#"[ 1,"kvstore"]"#,
        r#"[01,"kvstore"]"#,
    ] {
        for tags in [None, Some(br#"["t"]"#.to_vec())] {
            let mut fields = vec![
                protocol.as_bytes().to_vec(),
                b"k".to_vec(),
                b"v".to_vec(),
                public.to_compressed().to_vec(),
            ];
            fields.extend(tags);
            let token = signed_fields(&controller, fields);
            let (_, _, lock) = derivation_of(&controller, NAMESPACE, "k");
            assert_eq!(token.locking_public_key, lock);
            assert!(!verdict(&token, &public), "{protocol}");
        }
    }
    let canonical = signed_fields(
        &controller,
        vec![
            NAMESPACE.as_bytes().to_vec(),
            b"k".to_vec(),
            b"v".to_vec(),
            public.to_compressed().to_vec(),
        ],
    );
    assert!(verdict(&canonical, &public), "the canonical control");
}

/// A token the controller signed whose controller field names another key
/// answers `false` against the controller and against that key.
#[test]
fn a_signed_token_whose_controller_field_is_another_key_is_refused() {
    let controller = key("controller", 9);
    let public = controller.public_key();
    let stranger = key("stranger", 9).public_key();
    for (protocol, tags) in shapes() {
        let mut fields = vec![
            protocol.as_bytes().to_vec(),
            b"k".to_vec(),
            b"v".to_vec(),
            stranger.to_compressed().to_vec(),
        ];
        fields.extend(tags.map(|tags| tags.as_bytes().to_vec()));
        let token = signed_fields(&controller, fields);
        assert!(!verdict(&token, &public), "{protocol} {tags:?}");
        assert!(
            !verdict(&token, &stranger),
            "{protocol} {tags:?} the named key"
        );
    }
}
