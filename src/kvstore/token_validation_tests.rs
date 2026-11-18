//! The reader's verdicts and words on the kvstore cases of
//! `tests/vectors/token_envelope_544.json` (#544), each the reference's
//! `decodeAndVerifyKVStoreToken` at `ts-stack@edf6e03` under Node v22.18.0.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn the_reader_gives_the_reference_verdict_in_its_words_544() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/token_envelope_544.json")).unwrap();
    let cases = v["kvstore"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let read = decode_and_verify(&script);
        match (case["words"].as_str(), case["name"].as_str().unwrap()) {
            (None, name) => assert_eq!(read.unwrap().value, case["value"], "{name}"),
            // V8's `JSON.parse` words for a protocol text that is no JSON;
            // serde's here, the same refusal.
            (Some(words), "raw_protocol") => {
                assert!(words.contains("is not valid JSON"));
                assert!(read.is_err());
            }
            (Some(words), name) => {
                assert_eq!(read.unwrap_err(), refused(words), "{name}");
            }
        }
    }
}

/// #550: the reference's token with its locking key's or its controller
/// field's tag set to `05` (the compact form k256 read as `02 || x`), refused
/// in `Point.fromDER`'s words, as `tests/vectors/sec1_tag_05_550.json` records
/// the reference refusing both (`kvStoreTokenValidation.ts:76-81`, `:88`).
#[test]
fn a_tag_05_key_is_refused_in_the_reference_words_550() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/sec1_tag_05_550.json")).unwrap();
    for name in ["kvstore_lock_key", "kvstore_controller"] {
        let case = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        let script = LockingScript::from_hex(case["input"].as_str().unwrap()).unwrap();
        let words = case["words"].as_str().unwrap();
        assert_eq!(words, "Unknown point format");
        assert_eq!(
            decode_and_verify(&script).unwrap_err(),
            refused(words),
            "{name}"
        );
    }
}

/// A controller's token, written by this crate's writer (`ProtoWallet`'s
/// signature, `KeyDeriver`'s lock, `PushDrop`'s script), whose protocol field
/// is `protocol_text` and whose signature and lock are honest for the
/// protocol that text names.
fn token_with_protocol_text(protocol_text: &str, tags: bool) -> LockingScript {
    let controller =
        crate::primitives::PrivateKey::from_bytes(&crate::primitives::sha256(b"controller"))
            .unwrap();
    let protocol = Protocol::new(crate::wallet::SecurityLevel::App, "kvstore");
    let mut fields = vec![
        protocol_text.as_bytes().to_vec(),
        b"k".to_vec(),
        b"v".to_vec(),
        controller.public_key().to_compressed().to_vec(),
    ];
    if tags {
        fields.push(br#"["t"]"#.to_vec());
    }
    let signature = ProtoWallet::new(Some(controller.clone()))
        .create_signature(crate::wallet::CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: "k".to_owned(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = KeyDeriver::new(Some(controller))
        .derive_public_key(&protocol, "k", &Counterparty::Anyone, true)
        .unwrap();
    PushDrop::new(lock, fields).lock()
}

/// A token whose protocol field names the protocol `[1,"kvstore"]` in a text
/// other than its canonical JSON is refused in the reference's words, though
/// its lock is the controller's derived key and its signature verifies over
/// the text as written: the canonical-text check alone refuses it, as
/// `decodeAndVerifyKVStoreToken` does (`ts-stack@edf6e03`
/// `kvStoreTokenValidation.ts:97-98`). The canonical text is read.
#[test]
fn a_token_whose_protocol_text_is_not_canonical_json_is_refused_in_the_reference_words() {
    for tags in [false, true] {
        for text in [
            r#"[1, "kvstore"]"#,
            r#"[ 1,"kvstore"]"#,
            r#"[1,"kvstore"] "#,
            "[1,\"kvstore\"]\n",
            "[1,\"kvst\\u006fre\"]",
        ] {
            assert_eq!(
                decode_and_verify(&token_with_protocol_text(text, tags)).unwrap_err(),
                Error::KvStoreError("KVStore protocol ID must use canonical JSON".into()),
                "{text:?} {tags}"
            );
        }
        let read = decode_and_verify(&token_with_protocol_text(r#"[1,"kvstore"]"#, tags)).unwrap();
        assert_eq!(
            (
                read.protocol_id_text.as_str(),
                read.key.as_str(),
                read.value.as_str()
            ),
            (r#"[1,"kvstore"]"#, "k", "v"),
            "the canonical control {tags}"
        );
    }
}

/// A five- or six-field token in the canonical envelope (this crate's
/// `PushDrop` writer), its last field a signature that is never read: every
/// refusal below comes before the lock and the signature are judged.
fn envelope(fields: Vec<Vec<u8>>) -> LockingScript {
    let controller =
        crate::primitives::PrivateKey::from_bytes(&crate::primitives::sha256(b"controller"))
            .unwrap();
    let mut fields = fields;
    fields.push(vec![0x30; 8]);
    PushDrop::new(controller.public_key(), fields).lock()
}

/// Each refusal of the reader ahead of the lock, one token for each, in the
/// reference's words where `decodeAndVerifyKVStoreToken` makes the same
/// refusal (`ts-stack@edf6e03` `kvStoreTokenValidation.ts:28-74`, `:85-105`;
/// `toUTF8Strict`'s words for bytes that are not UTF-8): the field count past
/// six, a field past 1 MiB, the data past 1 MiB and 64 KiB, each text field
/// not UTF-8, the protocol's shape, level and name, a key past 800 bytes, the
/// controller's length, and the tags' four rules; tags that are no JSON
/// refused as `KvStoreError` in `serde_json`'s words. An empty key or value
/// has no cell: the writer writes an empty field as `OP_0`, read back as
/// `[0]`, and a zero-length push fails the envelope, so no canonical token
/// carries one.
#[test]
fn each_refusal_ahead_of_the_lock_is_made_in_its_words() {
    let controller =
        crate::primitives::PrivateKey::from_bytes(&crate::primitives::sha256(b"controller"))
            .unwrap()
            .public_key()
            .to_compressed()
            .to_vec();
    let fields = |protocol: &[u8], key: &[u8], value: &[u8], tags: Option<&[u8]>| {
        let mut fields = vec![
            protocol.to_vec(),
            key.to_vec(),
            value.to_vec(),
            controller.clone(),
        ];
        fields.extend(tags.map(<[u8]>::to_vec));
        fields
    };
    let canonical = br#"[1,"kvstore"]"#.as_slice();
    let mib = vec![b'v'; MAX_VALUE_BYTES];
    let mut seven = fields(canonical, b"k", b"v", Some(br#"["t"]"#));
    seven.push(b"x".to_vec());
    let thirty_three: Vec<String> = (0..33).map(|i| i.to_string()).collect();
    let thirty_three = serde_json::to_vec(&thirty_three).unwrap();
    let long_tag = serde_json::to_vec(&["t".repeat(257)]).unwrap();
    let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
        (
            "seven fields",
            seven,
            "Unexpected PushDrop token field count",
        ),
        (
            "a field past 1 MiB",
            fields(canonical, b"k", &[mib.as_slice(), b"v"].concat(), None),
            "PushDrop token contains an oversized field",
        ),
        (
            "the data past 1 MiB and 64 KiB",
            fields(canonical, &vec![b'k'; 64 * 1024], &mib, None),
            "PushDrop token payload is too large",
        ),
        (
            "the protocol not UTF-8",
            fields(b"[1,\"kvst\xffre\"]", b"k", b"v", None),
            "The encoded data was not valid for encoding utf-8",
        ),
        (
            "the key not UTF-8",
            fields(canonical, b"\xff", b"v", None),
            "The encoded data was not valid for encoding utf-8",
        ),
        (
            "the value not UTF-8",
            fields(canonical, b"k", b"\xff", None),
            "The encoded data was not valid for encoding utf-8",
        ),
        (
            "the tags not UTF-8",
            fields(canonical, b"k", b"v", Some(b"[\"\xff\"]")),
            "The encoded data was not valid for encoding utf-8",
        ),
        (
            "three protocol members",
            fields(br#"[1,"kvstore",1]"#, b"k", b"v", None),
            "KVStore protocol ID must contain exactly two fields",
        ),
        (
            "a protocol object",
            fields(br#"{"a":1}"#, b"k", b"v", None),
            "KVStore protocol ID must contain exactly two fields",
        ),
        (
            "level 3",
            fields(br#"[3,"kvstore"]"#, b"k", b"v", None),
            "KVStore protocol ID is invalid",
        ),
        (
            "a numeric name",
            fields(br#"[1,7]"#, b"k", b"v", None),
            "KVStore protocol ID is invalid",
        ),
        (
            "a name of four bytes",
            fields(br#"[1,"kvst"]"#, b"k", b"v", None),
            "KVStore protocol name is invalid",
        ),
        (
            "a name of 401 bytes",
            fields(
                format!("[1,\"{}\"]", "n".repeat(401)).as_bytes(),
                b"k",
                b"v",
                None,
            ),
            "KVStore protocol name is invalid",
        ),
        (
            "a key of 801 bytes",
            fields(canonical, &[b'k'; 801], b"v", None),
            "KVStore key has an invalid length",
        ),
        (
            "a controller of 32 bytes",
            {
                let mut short = fields(canonical, b"k", b"v", None);
                short[3].pop();
                short
            },
            "KVStore controller is invalid",
        ),
        (
            "tags an object",
            fields(canonical, b"k", b"v", Some(b"{}")),
            "KVStore tags must be a bounded array",
        ),
        (
            "33 tags",
            fields(canonical, b"k", b"v", Some(&thirty_three)),
            "KVStore tags must be a bounded array",
        ),
        (
            "an empty tag",
            fields(canonical, b"k", b"v", Some(br#"[""]"#)),
            "KVStore tag has an invalid length",
        ),
        (
            "a tag of 257 bytes",
            fields(canonical, b"k", b"v", Some(&long_tag)),
            "KVStore tag has an invalid length",
        ),
        (
            "a tag that is no string",
            fields(canonical, b"k", b"v", Some(b"[1]")),
            "KVStore tag has an invalid length",
        ),
        (
            "a tag twice",
            fields(canonical, b"k", b"v", Some(br#"["t","t"]"#)),
            "KVStore tags must be unique",
        ),
    ];
    for (name, fields, words) in cases {
        assert_eq!(
            decode_and_verify(&envelope(fields)).unwrap_err(),
            refused(words),
            "{name}"
        );
    }
    let no_json = decode_and_verify(&envelope(fields(canonical, b"k", b"v", Some(b"t"))));
    assert!(
        matches!(no_json, Err(Error::KvStoreError(_))),
        "tags that are no JSON: {no_json:?}"
    );
}
