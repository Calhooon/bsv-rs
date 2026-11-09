//! #782: `PushDrop::lock_with_wallet`, the reference's wallet-aware
//! `new PushDrop(wallet, originator).lock(fields, protocolID, keyID,
//! counterparty, forSelf, includeSignature, lockPosition)` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:130-202`): the wallet's
//! `getPublicKey` answer pushed as the wallet returned it (#545), then, when
//! `includeSignature`, its `createSignature` over the fields concatenated,
//! pushed as the last field as returned. The raw `PushDrop::lock` is
//! unchanged.
//!
//! The recording is `tests/vectors/pushdrop_wallet_lock_782.json`
//! (`tests/support/pushdrop_wallet_lock_782.mjs`, the reference's own
//! template over a ProtoWallet of the scalar 9 under Node 22).
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 that records each call; no network, no port.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::primitives::{from_hex, to_hex, PublicKey};
use bsv_rs::script::templates::{LockPosition, PushDrop};
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{Counterparty, Protocol, SecurityLevel};
use identity_reveal_wallet::Counting;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/pushdrop_wallet_lock_782.json");
const KEYS_545: &str = include_str!("vectors/pushdrop_key_bytes_545.json");

fn cases() -> Vec<Value> {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(vector["issue"], 782);
    let cases = vector["cases"].as_array().unwrap().clone();
    assert_eq!(cases.len(), 48, "the recording's case count");
    cases
}

fn case(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

fn uncompressed(answer: &str) -> String {
    PublicKey::from_hex(answer).unwrap().to_hex_uncompressed()
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, "pushdrop wallet lock")
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn counterparty(text: &str) -> Counterparty {
    match text {
        "self" => Counterparty::Self_,
        "anyone" => Counterparty::Anyone,
        hex => Counterparty::Other(PublicKey::from_hex(hex).unwrap()),
    }
}

fn counterparty_text(counterparty: &Counterparty) -> String {
    match counterparty {
        Counterparty::Self_ => "self".into(),
        Counterparty::Anyone => "anyone".into(),
        Counterparty::Other(key) => key.to_hex(),
    }
}

fn fields(case: &Value) -> Vec<Vec<u8>> {
    case["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| from_hex(text(field)).unwrap())
        .collect()
}

fn position(case: &Value) -> LockPosition {
    match text(&case["lock_position"]) {
        "before" => LockPosition::Before,
        "after" => LockPosition::After,
        other => panic!("lock position {other}"),
    }
}

/// The scalar 9's wallet, its derived key answered as the case's form.
fn wallet(case: &Value) -> Counting {
    let wallet = Counting::of_scalar(9);
    match text(&case["key_form"]) {
        "as_derived" => {}
        "uncompressed" => *wallet.key_form.lock().unwrap() = Some(uncompressed),
        other => panic!("key form {other}"),
    }
    wallet
}

/// The case through the door, with the wallet that served it.
async fn lock(case: &Value) -> (Counting, LockingScript) {
    let wallet = wallet(case);
    let script = PushDrop::lock_with_wallet(
        &wallet,
        case["originator"].as_str(),
        fields(case),
        protocol(),
        text(&case["key_id"]),
        counterparty(text(&case["counterparty"])),
        case["for_self"].as_bool().unwrap(),
        case["include_signature"].as_bool().unwrap(),
        position(case),
    )
    .await
    .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
    (wallet, script)
}

#[tokio::test]
async fn the_wallet_lock_writes_the_references_bytes_782() {
    for case in cases() {
        let name = &case["name"];
        assert_eq!(case["protocol_id"][0], 2, "{name}");
        assert_eq!(case["protocol_id"][1], "pushdrop wallet lock", "{name}");
        let (wallet, script) = lock(&case).await;
        assert_eq!(script.to_hex(), text(&case["locking_script"]), "{name}");
        // The wallet built here answers the key the reference's answered.
        let key_args = wallet.public_key_args.lock().unwrap()[0].clone();
        let key = bsv_rs::wallet::WalletInterface::get_public_key(&wallet, key_args, None)
            .await
            .unwrap();
        assert_eq!(key.public_key, text(&case["wallet_answer"]), "{name}");
        // The last field is the signature the reference's wallet returned.
        if case["include_signature"].as_bool().unwrap() {
            let signature = from_hex(text(&case["signature"])).unwrap();
            let decoded_at = PushDrop::decode(&script).unwrap();
            assert_eq!(
                to_hex(decoded_at.fields.last().unwrap()),
                to_hex(&signature),
                "{name}"
            );
        } else {
            assert!(case["signature"].is_null(), "{name}");
        }
    }
}

#[tokio::test]
async fn the_wallet_lock_asks_the_key_then_the_signature_with_the_references_arguments_782() {
    for case in cases() {
        let name = &case["name"];
        let (wallet, _) = lock(&case).await;
        let recorded = case["calls"].as_array().unwrap();
        let methods: Vec<&str> = recorded
            .iter()
            .map(|call| match text(&call["method"]) {
                "getPublicKey" => "get_public_key",
                "createSignature" => "create_signature",
                other => panic!("method {other}"),
            })
            .collect();
        assert_eq!(wallet.calls(), methods, "{name}: the order of the calls");
        let originators: Vec<Option<String>> = recorded
            .iter()
            .map(|call| call["originator"].as_str().map(str::to_string))
            .collect();
        assert_eq!(wallet.originators(), originators, "{name}: the originator");

        let key_args = wallet.public_key_args.lock().unwrap().clone();
        assert_eq!(key_args.len(), 1, "{name}");
        let asked = &recorded[0]["args"];
        assert!(!key_args[0].identity_key, "{name}");
        assert_eq!(key_args[0].protocol_id, Some(protocol()), "{name}");
        assert_eq!(key_args[0].key_id.as_deref(), asked["keyID"].as_str());
        assert_eq!(
            key_args[0].counterparty.as_ref().map(counterparty_text),
            asked["counterparty"].as_str().map(str::to_string),
            "{name}"
        );
        assert_eq!(key_args[0].for_self, asked["forSelf"].as_bool(), "{name}");
        assert_eq!(key_args[0].for_self, case["for_self"].as_bool(), "{name}");

        let signature_args = wallet.signature_args.lock().unwrap().clone();
        if case["include_signature"].as_bool().unwrap() {
            assert_eq!(signature_args.len(), 1, "{name}");
            let asked = &recorded[1]["args"];
            // The reference sends no forSelf with the signature; this
            // crate's arguments have no such member.
            assert!(asked.get("forSelf").is_none(), "{name}");
            assert_eq!(
                signature_args[0].data.as_deref().map(to_hex),
                asked["data"].as_str().map(str::to_string),
                "{name}: the fields concatenated"
            );
            assert_eq!(
                signature_args[0].data,
                Some(fields(&case).concat()),
                "{name}"
            );
            assert_eq!(signature_args[0].hash_to_directly_sign, None, "{name}");
            assert_eq!(signature_args[0].protocol_id, protocol(), "{name}");
            assert_eq!(
                Some(signature_args[0].key_id.as_str()),
                asked["keyID"].as_str()
            );
            assert_eq!(
                signature_args[0]
                    .counterparty
                    .as_ref()
                    .map(counterparty_text),
                asked["counterparty"].as_str().map(str::to_string),
                "{name}"
            );
        } else {
            assert_eq!(recorded.len(), 1, "{name}");
            assert!(signature_args.is_empty(), "{name}");
        }
    }
}

#[tokio::test]
async fn no_signature_is_asked_when_include_signature_is_false_782() {
    let case = case("grid_anyone_forself_true_signed_false_before");
    let (wallet, script) = lock(&case).await;
    assert_eq!(wallet.calls(), ["get_public_key"]);
    assert!(wallet.signature_args.lock().unwrap().is_empty());
    // The fields are the caller's three, no signature after them.
    let decoded = PushDrop::decode(&script).unwrap();
    assert_eq!(decoded.fields.len(), 3);

    // No field and no signature: the key and OP_CHECKSIG alone.
    let case = case_named_bare();
    let (wallet, script) = lock(&case).await;
    assert_eq!(wallet.calls(), ["get_public_key"]);
    let key = text(&case["wallet_answer"]);
    assert_eq!(script.to_hex(), format!("21{key}ac"));
    assert_eq!(script.to_hex(), text(&case["locking_script"]));
}

fn case_named_bare() -> Value {
    case("shape_no_fields_signed_false_before")
}

#[tokio::test]
async fn a_wallet_key_error_returns_before_any_signature_782() {
    let wallet = Counting::of_scalar(9);
    // A protocol name under five bytes: the wallet's getPublicKey refuses it.
    let refused = Protocol::new(SecurityLevel::Counterparty, "bad");
    let direct = bsv_rs::wallet::WalletInterface::get_public_key(
        &Counting::of_scalar(9),
        bsv_rs::wallet::GetPublicKeyArgs {
            protocol_id: Some(refused.clone()),
            key_id: Some("1".into()),
            counterparty: Some(Counterparty::Self_),
            for_self: Some(true),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap_err();
    let error = PushDrop::lock_with_wallet(
        &wallet,
        None,
        vec![vec![0x68, 0x69]],
        refused,
        "1",
        Counterparty::Self_,
        true,
        true,
        LockPosition::Before,
    )
    .await
    .unwrap_err();
    assert_eq!(error, direct, "the wallet's error as it came");
    assert_eq!(wallet.calls(), ["get_public_key"]);
    assert!(wallet.signature_args.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_wallet_key_in_an_uncompressed_form_is_pushed_as_returned_782() {
    for name in [
        "uncompressed_answer_signed_before",
        "uncompressed_answer_signed_after",
    ] {
        let case = case(name);
        let answer = text(&case["wallet_answer"]);
        assert!(answer.starts_with("04") && answer.len() == 130, "{name}");
        let (_, script) = lock(&case).await;
        assert_eq!(script.to_hex(), text(&case["locking_script"]), "{name}");
        let pushes: Vec<Vec<u8>> = script
            .chunks()
            .into_iter()
            .filter_map(|chunk| chunk.data)
            .filter(|data| data.len() == 65)
            .collect();
        assert_eq!(pushes.len(), 1, "{name}: one 65-byte push");
        assert_eq!(to_hex(&pushes[0]), answer, "{name}");
        if name.ends_with("before") {
            assert_eq!(&script.to_hex()[..2], "41", "{name}");
        }
    }
}

fn no_key(_: &str) -> String {
    "zz".to_string()
}

fn tag_05(answer: &str) -> String {
    format!("05{}", &answer[2..])
}

/// The stated residue (a): the reference decodes the wallet's text as hex
/// and pushes it unparsed as a key (`PushDrop.ts:166-172`); this door reads
/// it with `PublicKey::from_hex` and refuses a text that is no key in that
/// parser's words, before any signature is asked (#782's fold): `zz` the
/// reference refuses too (`Invalid hex string`), the `05` key it pushes.
#[tokio::test]
async fn a_wallet_answer_that_is_no_key_is_refused_782() {
    for form in [no_key as fn(&str) -> String, tag_05] {
        let wallet = Counting::of_scalar(9);
        *wallet.key_form.lock().unwrap() = Some(form);
        let answer = form("027f04d8ef56518c7940ebd25a81856164557964651175ff969406182c8f338329");
        let parser = PublicKey::from_hex(&answer).unwrap_err();
        let error = PushDrop::lock_with_wallet(
            &wallet,
            None,
            vec![vec![0x68, 0x69]],
            protocol(),
            "1",
            Counterparty::Self_,
            true,
            true,
            LockPosition::Before,
        )
        .await
        .unwrap_err();
        assert_eq!(error, parser, "the parser's words for {answer}");
        // The text is judged before the signature is asked (#782's fold).
        assert_eq!(wallet.calls(), ["get_public_key"], "{answer}");
        assert!(wallet.signature_args.lock().unwrap().is_empty(), "{answer}");
    }
}

fn empty(_: &str) -> String {
    String::new()
}

fn odd_not_hex(_: &str) -> String {
    "zzz".to_string()
}

/// The recording's three key texts that are no key (`key_texts`).
fn key_text(name: &str) -> Value {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let texts = vector["key_texts"].as_array().unwrap();
    assert_eq!(texts.len(), 3, "the recording's key texts");
    texts
        .iter()
        .find(|text| text["name"] == name)
        .unwrap_or_else(|| panic!("no key text {name}"))
        .clone()
}

/// The door on a wallet whose key answer `form` rewrites, the fields and
/// arguments the recorder's key texts were locked with.
async fn refused(form: fn(&str) -> String) -> (Counting, bsv_rs::Error) {
    let wallet = Counting::of_scalar(9);
    *wallet.key_form.lock().unwrap() = Some(form);
    let error = PushDrop::lock_with_wallet(
        &wallet,
        None,
        vec![vec![0x68, 0x69]],
        protocol(),
        "1",
        Counterparty::Self_,
        true,
        true,
        LockPosition::Before,
    )
    .await
    .unwrap_err();
    (wallet, error)
}

/// The reference decodes the key text, `toArray(publicKey, 'hex')`, before
/// it asks the signature (`PushDrop.ts:166-172`, then `:173-185` at
/// `ts-stack@edf6e03`); `assertValidHex` (`primitives/hex.ts:6-17`) throws
/// `Invalid hex string` for `zz`, after the key call alone. This door
/// refuses the text after the same one call, in `PublicKey::from_hex`'s
/// words (residue (a)).
#[tokio::test]
async fn a_key_text_that_is_not_hex_is_refused_before_any_signature_is_asked_782() {
    let recorded = key_text("not_hex");
    assert_eq!(recorded["wallet_answer"], "zz");
    assert_eq!(recorded["rejected"], "Invalid hex string");
    assert_eq!(recorded["calls"], serde_json::json!(["getPublicKey"]));
    let (wallet, error) = refused(no_key).await;
    assert_eq!(wallet.calls(), ["get_public_key"]);
    assert_eq!(error, PublicKey::from_hex("zz").unwrap_err());
}

/// An odd-length text that is not hex: the reference's `assertValidHex`
/// runs before `hexToUint8Array` pads it (`utils.ts:126-128`), so it throws
/// `Invalid hex string` after the key call alone, as here.
#[tokio::test]
async fn an_odd_length_key_text_that_is_not_hex_is_refused_after_one_call_782() {
    let recorded = key_text("odd_not_hex");
    assert_eq!(recorded["wallet_answer"], "zzz");
    assert_eq!(recorded["rejected"], "Invalid hex string");
    assert_eq!(recorded["calls"], serde_json::json!(["getPublicKey"]));
    let (wallet, error) = refused(odd_not_hex).await;
    assert_eq!(wallet.calls(), ["get_public_key"]);
    assert_eq!(error, PublicKey::from_hex("zzz").unwrap_err());
}

/// The empty text, stated: `assertValidHex` admits it (`hex.ts:12`), so the
/// reference pushes `OP_0` as the key, asks the signature and resolves
/// (`00ac...`, recorded); this door refuses the text that is no key after
/// the key call alone (residue (a): a valid-hex text that is no key).
#[tokio::test]
async fn an_empty_key_text_is_refused_here_where_the_reference_signs_and_pushes_it_stated_782() {
    let recorded = key_text("empty");
    assert_eq!(recorded["wallet_answer"], "");
    assert_eq!(
        recorded["calls"],
        serde_json::json!(["getPublicKey", "createSignature"])
    );
    assert!(text(&recorded["resolved"]).starts_with("00ac"));
    let (wallet, error) = refused(empty).await;
    assert_eq!(wallet.calls(), ["get_public_key"]);
    assert_eq!(error, PublicKey::from_hex("").unwrap_err());
}

/// A createSignature error is returned as the wallet gave it, unwrapped, as
/// the reference's awaited call rejects (`PushDrop.ts:175-184`); go-sdk at
/// `2ca481c` wraps it (`transaction/template/pushdrop/pushdrop.go:158`,
/// `fmt.Errorf("error creating wallet signature for lock: %w", err)`).
#[tokio::test]
async fn a_signature_error_is_returned_as_the_wallet_gave_it_782() {
    let wallet = Counting::of_scalar(9);
    let given = bsv_rs::Error::WalletError("the user refused the signature".into());
    *wallet.signature_error.lock().unwrap() = Some(given.clone());
    let error = PushDrop::lock_with_wallet(
        &wallet,
        Some("pushdrop.example.com"),
        vec![vec![0x68, 0x69]],
        protocol(),
        "1",
        Counterparty::Self_,
        true,
        true,
        LockPosition::Before,
    )
    .await
    .unwrap_err();
    assert_eq!(error, given);
    assert_eq!(error.to_string(), given.to_string());
    assert_eq!(wallet.calls(), ["get_public_key", "create_signature"]);
}

#[test]
fn the_raw_lock_is_unchanged_782() {
    let vector: Value = serde_json::from_str(KEYS_545).unwrap();
    let fields: Vec<Vec<u8>> = vector["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| from_hex(text(field)).unwrap())
        .collect();
    let mut seen = 0;
    for case in vector["cases"].as_array().unwrap() {
        if case["form"] != "compressed" {
            continue;
        }
        seen += 1;
        let key = PublicKey::from_hex(text(&case["wallet_answer"])).unwrap();
        let script = PushDrop::new(key, fields.clone())
            .with_position(position(case))
            .lock();
        assert_eq!(script.to_hex(), text(&case["locking_script"]));
    }
    assert_eq!(seen, 2, "the compressed cases at both positions");
    // An uncompressed key handed to the raw lock is still pushed compressed.
    let uncompressed_case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["form"] == "uncompressed" && case["lock_position"] == "before")
        .unwrap();
    let key = PublicKey::from_hex(text(&uncompressed_case["wallet_answer"])).unwrap();
    let raw = PushDrop::new(key.clone(), fields).lock().to_hex();
    assert_eq!(&raw[..68], format!("21{}", key.to_hex()));
}
