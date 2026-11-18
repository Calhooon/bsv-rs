//! A `GlobalKVStore` token authenticates only in the form whose signature
//! binds its key (GHSA-4mcm-g5xq-jv3r): the protocol field canonical JSON
//! `[level, name]`, the key as the key ID, the lock the controller's key
//! linked to `anyone` under that protocol and key (BRC-35; the form this
//! crate's `GlobalKVStore::set` writes since 0.9.0-beta.4).
//!
//! The form this crate's `GlobalKVStore::set` wrote before (the protocol as
//! raw text, the constant key ID `kvstore-token`, the controller's own key as
//! the lock) signs the fields' bytes without the key: the same bytes divided
//! into other fields kept the controller's signature. Every door that judges
//! a token now refuses that form, an honest one included: the public
//! signature check, the interpreter, the
//! store's read and its history walk. A door asked under a protocol refuses
//! a token whose protocol field names another (the names compared as the
//! derivation reads them). Every token here is built by this crate's own
//! signer (`ProtoWallet`) and `PushDrop`, as each writer builds it.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

use bsv_rs::kvstore::{
    GlobalKVStore, KVStoreConfig, KVStoreContext, KVStoreGetOptions, KVStoreInterpreter,
};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::{sha256, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel,
};
use std::sync::Arc;

const NAMESPACE: &str = r#"[1,"kvstore"]"#;

/// A seeded key: the SHA-256 of the label and the index.
fn key(label: &str, index: u32) -> PrivateKey {
    let mut seed = label.as_bytes().to_vec();
    seed.extend_from_slice(&index.to_be_bytes());
    PrivateKey::from_bytes(&sha256(&seed)).unwrap()
}

/// The two forms: `earlier` is the one `set` wrote before (raw protocol
/// text, the key ID `kvstore-token`, the controller's lock); otherwise the
/// key-bound form under `NAMESPACE`.
fn token(
    controller: &PrivateKey,
    earlier: bool,
    key_text: &str,
    value: &str,
    tags: bool,
) -> PushDrop {
    let wallet = ProtoWallet::new(Some(controller.clone()));
    let protocol = Protocol::new(SecurityLevel::App, "kvstore");
    let field0 = if earlier { "kvstore" } else { NAMESPACE };
    let mut fields = vec![
        field0.as_bytes().to_vec(),
        key_text.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.public_key().to_compressed().to_vec(),
    ];
    if tags {
        fields.push(br#"["t"]"#.to_vec());
    }
    let key_id = if earlier { "kvstore-token" } else { key_text };
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: key_id.to_owned(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = if earlier {
        controller.public_key()
    } else {
        wallet
            .key_deriver()
            .derive_public_key(&protocol, key_text, &Counterparty::Anyone, true)
            .unwrap()
    };
    PushDrop::decode(&PushDrop::new(lock, fields).lock()).unwrap()
}

/// `token`'s data bytes divided again: `shift` bytes moved from field `at`
/// to field `at + 1` (or back, negative), the signature and lock kept.
fn divided(token: &PushDrop, at: usize, shift: isize) -> Option<PushDrop> {
    let mut fields = token.fields.clone();
    let (left, right) = (fields[at].clone(), fields[at + 1].clone());
    let joined = [left.as_slice(), right.as_slice()].concat();
    let cut = left.len() as isize - shift;
    if cut < 1 || cut >= joined.len() as isize {
        return None;
    }
    fields[at] = joined[..cut as usize].to_vec();
    fields[at + 1] = joined[cut as usize..].to_vec();
    PushDrop::decode(&PushDrop::new(token.locking_public_key.clone(), fields).lock()).ok()
}

fn script(token: &PushDrop) -> LockingScript {
    token.lock()
}

/// What each judging door answers for `token`.
fn doors(token: &PushDrop, asked: &str) -> [bool; 2] {
    let script = script(token);
    let checked = KVStoreInterpreter::extract_fields(&script)
        .is_some_and(|fields| KVStoreInterpreter::verify_signature(&fields, asked));
    let read = KVStoreInterpreter::interpret_script(&script, None).is_some();
    [checked, read]
}

#[test]
fn a_token_whose_signature_does_not_bind_its_key_authenticates_at_no_door() {
    let controller = key("controller", 1);
    for tags in [false, true] {
        let honest = token(&controller, true, "address_backup", "1value", tags);
        for asked in ["kvstore", " KVStore"] {
            assert_eq!(doors(&honest, asked), [false; 2], "{tags} {asked}");
        }
        for (at, shift) in [(1, 3), (1, -3), (0, 2), (0, -2)] {
            let moved = divided(&honest, at, shift).unwrap();
            assert_eq!(doors(&moved, "kvstore"), [false; 2], "{tags} {at} {shift}");
        }
    }
}

#[test]
fn a_key_bound_token_is_read_at_every_door_and_no_division_of_it_is() {
    let mut seen = [0usize; 2];
    for index in 0..40u32 {
        let tags = index % 2 == 1;
        let controller = key("generated", index);
        let honest = token(
            &controller,
            false,
            &format!("key-{index}"),
            &format!("v{index}"),
            tags,
        );
        assert_eq!(doors(&honest, "kvstore"), [true; 2], "{index}");
        for at in 0..3 {
            for shift in [-2isize, -1, 1, 2] {
                if let Some(moved) = divided(&honest, at, shift) {
                    assert_eq!(doors(&moved, "kvstore"), [false; 2], "{index} {at} {shift}");
                }
            }
        }
        seen[tags as usize] += 1;
    }
    assert!(seen.iter().all(|&n| n >= 20), "{seen:?}");
}

#[test]
fn a_door_asked_under_a_protocol_refuses_a_token_naming_another() {
    let controller = key("controller", 2);
    for tags in [false, true] {
        let honest = token(&controller, false, "k1", "v", tags);
        let fields = KVStoreInterpreter::extract_fields(&script(&honest)).unwrap();
        for asked in ["kvstore", " KVStore ", NAMESPACE] {
            assert!(
                KVStoreInterpreter::verify_signature(&fields, asked),
                "{asked}"
            );
        }
        for asked in ["another store", r#"[2,"kvstore"]"#, r#"[0,"kvstore"]"#] {
            assert!(
                !KVStoreInterpreter::verify_signature(&fields, asked),
                "{asked}"
            );
        }
    }
}

/// A lookup host answering one output.
struct TokenLookup(Vec<u8>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for TokenLookup {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![OutputListItem {
                beef: self.0.clone(),
                output_index: 0,
                context: None,
                txid: None,
            }],
        })
    }
}

async fn read_by_the_store(token: &PushDrop, key_text: &str, host: &str) -> Option<String> {
    let config = KVStoreConfig::default();
    let source = signaction_reference_326::source_of(&script(token).to_binary(), 1);
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        host_overrides: Some(std::collections::HashMap::from([(
            config.service_name.clone(),
            vec![format!("https://{host}.invalid")],
        )])),
        slap_trackers: Some(Vec::new()),
        facilitator: Some(Arc::new(TokenLookup(source.to_beef(true).unwrap()))),
        ..Default::default()
    });
    let store = GlobalKVStore::with_resolver(
        identity_reveal_wallet::Counting::of_scalar(9),
        config,
        NetworkPreset::Local,
        resolver,
    );
    let options = KVStoreGetOptions::new().with_history(true);
    store
        .get(key_text, Some(options))
        .await
        .unwrap()
        .map(|entry| entry.value)
}

#[tokio::test]
async fn the_store_reads_the_key_bound_form_alone() {
    let controller = key("controller", 3);
    let honest = token(&controller, false, "k1", "v", true);
    assert_eq!(
        read_by_the_store(&honest, "k1", "kv-bound-4mcm-1")
            .await
            .as_deref(),
        Some("v")
    );
    let earlier = token(&controller, true, "k1", "v", true);
    assert_eq!(
        read_by_the_store(&earlier, "k1", "kv-bound-4mcm-2").await,
        None
    );
    let moved = divided(&earlier, 1, 1).unwrap();
    assert_eq!(
        read_by_the_store(&moved, "k", "kv-bound-4mcm-3").await,
        None
    );
    let ctx = KVStoreContext::new("k1", "kvstore");
    assert!(KVStoreInterpreter::interpret_script(&script(&honest), Some(&ctx)).is_some());
}

/// `set` writes no token its reader refuses: tags the reader refuses (a
/// repeated tag, an empty one) are refused in the reader's words before the
/// wallet is asked anything; the same call with unique tags writes.
#[tokio::test]
async fn set_refuses_tags_its_reader_refuses_before_the_wallet_is_asked() {
    for (tags, words) in [
        (vec!["a", "a"], "KVStore tags must be unique"),
        (vec!["a", ""], "KVStore tag has an invalid length"),
    ] {
        let wallet = identity_reveal_wallet::Counting::of_scalar(9);
        let config = KVStoreConfig::default();
        let resolver = LookupResolver::new(LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            host_overrides: Some(std::collections::HashMap::from([(
                config.service_name.clone(),
                vec![format!("https://kv-tags-4mcm-{}.invalid", tags.len())],
            )])),
            slap_trackers: Some(Vec::new()),
            facilitator: Some(Arc::new(TokenLookup(Vec::new()))),
            ..Default::default()
        });
        let store =
            GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver);
        let options = bsv_rs::kvstore::KVStoreSetOptions {
            tags: Some(tags.iter().map(|t| t.to_string()).collect()),
            ..Default::default()
        };
        let result = store.set("k1", "v", Some(options)).await;
        assert_eq!(result, Err(bsv_rs::Error::KvStoreError(words.into())));
        assert!(wallet.calls().is_empty(), "{:?}", wallet.calls());
    }
}

/// A key-bound token under the protocol `[1, name]` as `name` is written
/// (its case and spaces kept): the lock derived under that protocol.
fn token_named(controller: &PrivateKey, name: &str, key_text: &str, value: &str) -> PushDrop {
    let wallet = ProtoWallet::new(Some(controller.clone()));
    let protocol = Protocol::new(SecurityLevel::App, name);
    let mut fields = vec![
        serde_json::to_vec(&(1u8, name)).unwrap(),
        key_text.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.public_key().to_compressed().to_vec(),
    ];
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: key_text.to_owned(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = wallet
        .key_deriver()
        .derive_public_key(&protocol, key_text, &Counterparty::Anyone, true)
        .unwrap();
    PushDrop::decode(&PushDrop::new(lock, fields).lock()).unwrap()
}

/// The asked protocol and the token's own compare as the derivation reads
/// them on BOTH sides (trimmed, lowercase): a token whose protocol field
/// names `KVStore` is the protocol a caller configured as `kvstore`, and one
/// naming another protocol is not.
#[test]
fn the_tokens_protocol_name_is_compared_as_the_derivation_reads_it() {
    let controller = key("controller", 4);
    let written = token_named(&controller, "KVStore", "k1", "v");
    let fields = KVStoreInterpreter::extract_fields(&script(&written)).unwrap();
    for asked in ["kvstore", "KVSTORE", " kvstore "] {
        assert!(
            KVStoreInterpreter::verify_signature(&fields, asked),
            "{asked}"
        );
    }
    let other = token_named(&controller, "Another Store", "k1", "v");
    let fields = KVStoreInterpreter::extract_fields(&script(&other)).unwrap();
    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
    assert!(KVStoreInterpreter::verify_signature(
        &fields,
        "another store"
    ));
}

/// The store's read refuses a key-bound token divided into fields otherwise
/// and a key-bound token of another protocol, each signed by its controller.
#[tokio::test]
async fn the_store_refuses_a_divided_key_bound_token_and_one_of_another_protocol() {
    let controller = key("controller", 5);
    let honest = token(&controller, false, "k12", "vv", true);
    assert_eq!(
        read_by_the_store(&honest, "k12", "kv-bound-4mcm-s3-honest")
            .await
            .as_deref(),
        Some("vv")
    );
    for (at, shift, key_text) in [(1, 1, "k1"), (1, -1, "k12v")] {
        let moved = divided(&honest, at, shift).unwrap();
        assert_eq!(
            read_by_the_store(&moved, key_text, &format!("kv-bound-4mcm-s3-{shift}")).await,
            None,
            "{at} {shift}"
        );
    }
    let other = token_named(&controller, "another store", "k12", "v");
    assert_eq!(
        read_by_the_store(&other, "k12", "kv-bound-4mcm-s3-other").await,
        None
    );
}

/// `set`'s bounds are its reader's, at the boundary: a key of 800 bytes and
/// a value of 1 MiB reach the wallet; one byte more is refused in the
/// reader's words before the wallet is asked anything.
#[tokio::test]
async fn set_refuses_one_byte_past_the_readers_key_and_value_bounds() {
    const MIB: usize = 1024 * 1024;
    for (key_len, value_len, refusal) in [
        (800, 1, None),
        (801, 1, Some("KVStore key has an invalid length")),
        (1, MIB, None),
        (1, MIB + 1, Some("KVStore value has an invalid length")),
    ] {
        let wallet = identity_reveal_wallet::Counting::of_scalar(9);
        let config = KVStoreConfig::default();
        let resolver = LookupResolver::new(LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            host_overrides: Some(std::collections::HashMap::from([(
                config.service_name.clone(),
                vec![format!(
                    "https://kv-bounds-4mcm-{key_len}-{value_len}.invalid"
                )],
            )])),
            slap_trackers: Some(Vec::new()),
            facilitator: Some(Arc::new(TokenLookup(Vec::new()))),
            ..Default::default()
        });
        let store =
            GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver);
        let result = store
            .set(&"k".repeat(key_len), &"v".repeat(value_len), None)
            .await;
        match refusal {
            Some(words) => {
                assert_eq!(result, Err(bsv_rs::Error::KvStoreError(words.into())));
                assert!(wallet.calls().is_empty(), "{key_len} {value_len}");
            }
            None => {
                assert!(!wallet.calls().is_empty(), "{key_len} {value_len}");
            }
        }
    }
}

// The verdicts of the removed `verify_signature_legacy` (0.9.0, #843) on
// the shared derivation (`src/kvstore/token_derivation.rs`), ported onto
// the door that stays (#843's fold): the legacy door's tests were the only
// pins on the canonical-JSON check and the derived lock at this door.

/// `fields` signed by `controller` under `[1, "kvstore"]` and the key ID
/// `fields[1]` names, the signature appended, locked by `lock` (the
/// controller-derived key when `None`) and read back by the decoder.
fn signed_fields(
    controller: &PrivateKey,
    mut fields: Vec<Vec<u8>>,
    lock: Option<PublicKey>,
) -> PushDrop {
    let wallet = ProtoWallet::new(Some(controller.clone()));
    let protocol = Protocol::new(SecurityLevel::App, "kvstore");
    let key_id = String::from_utf8(fields[1].clone()).unwrap();
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: key_id.clone(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = lock.unwrap_or_else(|| {
        wallet
            .key_deriver()
            .derive_public_key(&protocol, &key_id, &Counterparty::Anyone, true)
            .unwrap()
    });
    PushDrop::decode(&PushDrop::new(lock, fields).lock()).unwrap()
}

/// `verify_signature`'s answer for `token` under `kvstore`, `false` where
/// `extract_fields` reads no fields.
fn checked(token: &PushDrop) -> bool {
    KVStoreInterpreter::extract_fields(&script(token))
        .is_some_and(|fields| KVStoreInterpreter::verify_signature(&fields, "kvstore"))
}

/// A namespace token whose protocol field is not canonical JSON is refused,
/// signed as such by the controller and locked by the controller-derived
/// key; the canonical control is read (the reference refuses the same,
/// `kvStoreTokenValidation.ts:97-98` at `ts-stack@edf6e03`).
#[test]
fn a_namespace_token_signed_in_noncanonical_json_is_refused() {
    let controller = key("controller", 8);
    let public = controller.public_key().to_compressed().to_vec();
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
                public.clone(),
            ];
            fields.extend(tags.clone());
            let token = signed_fields(&controller, fields, None);
            assert!(!checked(&token), "{protocol} {tags:?}");
        }
    }
    let canonical = signed_fields(
        &controller,
        vec![
            NAMESPACE.as_bytes().to_vec(),
            b"k".to_vec(),
            b"v".to_vec(),
            public,
        ],
        None,
    );
    assert!(checked(&canonical), "the canonical control");
}

/// A signed key-bound token changed in one respect is refused: its value,
/// its signature emptied, a field fewer or more, its lock the controller's
/// own key or a stranger's (not the derived one).
#[test]
fn a_signed_token_changed_in_one_respect_is_refused() {
    let controller = key("controller", 2);
    let public = controller.public_key();
    for tags in [false, true] {
        let honest = token(&controller, false, "k", "v", tags);
        assert!(checked(&honest), "{tags}");
        let count = honest.fields.len();
        let relock = |fields: Vec<Vec<u8>>, lock: PublicKey| {
            PushDrop::decode(&PushDrop::new(lock, fields).lock()).unwrap()
        };
        let lock = honest.locking_public_key.clone();

        let mut value = honest.fields.clone();
        value[2] = b"w".to_vec();
        assert!(!checked(&relock(value, lock.clone())), "value {tags}");

        let mut unsigned = honest.fields.clone();
        unsigned[count - 1].clear();
        assert!(
            !checked(&relock(unsigned, lock.clone())),
            "empty signature {tags}"
        );

        let mut short = honest.fields.clone();
        short.remove(2);
        assert!(
            !checked(&relock(short, lock.clone())),
            "a field fewer {tags}"
        );

        let mut long = honest.fields.clone();
        long.insert(4, b"x".to_vec());
        assert!(!checked(&relock(long, lock)), "a field more {tags}");

        for other in [public.clone(), key("stranger", 2).public_key()] {
            let relocked = relock(honest.fields.clone(), other);
            assert!(!checked(&relocked), "a lock not derived {tags}");
        }
    }
}

/// A token the controller signed whose controller field names another key
/// is refused.
#[test]
fn a_signed_token_whose_controller_field_is_another_key_is_refused() {
    let controller = key("controller", 9);
    let stranger = key("stranger", 9).public_key();
    for tags in [None, Some(br#"["t"]"#.to_vec())] {
        let mut fields = vec![
            NAMESPACE.as_bytes().to_vec(),
            b"k".to_vec(),
            b"v".to_vec(),
            stranger.to_compressed().to_vec(),
        ];
        fields.extend(tags.clone());
        assert!(
            !checked(&signed_fields(&controller, fields, None)),
            "{tags:?}"
        );
    }
}

/// The reference's kvstore tokens of `tests/vectors/token_envelope_544.json`
/// (recorded by `tests/support/token_envelope_544.mjs`) at the check: its
/// two signed tokens read and the signed fields in a loose push encoding
/// read (the check judges the signature, the envelope is the interpreter's);
/// the raw protocol, the unsigned, the unlinked lock and the bad signature
/// refused.
#[test]
fn the_recorded_kvstore_tokens_take_the_checks_verdict() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap();
    let mut answers = Vec::new();
    for case in vector["kvstore"]["cases"].as_array().unwrap() {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let answer = KVStoreInterpreter::extract_fields(&script)
            .is_some_and(|fields| KVStoreInterpreter::verify_signature(&fields, "kvstore"));
        answers.push((case["name"].as_str().unwrap().to_owned(), answer));
    }
    let answers: Vec<(&str, bool)> = answers.iter().map(|(n, a)| (n.as_str(), *a)).collect();
    assert_eq!(
        answers,
        [
            ("reference", true),
            ("reference_tags", true),
            ("raw_protocol", false),
            ("unsigned", false),
            ("noncanonical_envelope", true),
            ("wrong_lock_key", false),
            ("bad_signature", false),
        ]
    );
}
