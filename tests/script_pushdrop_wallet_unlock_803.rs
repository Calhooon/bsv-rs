//! #803: `PushDrop::unlock_with_wallet`, the reference's wallet-aware
//! `new PushDrop(wallet, originator).unlock(protocolID, keyID, counterparty,
//! signOutputs, anyoneCanPay, sourceSatoshis, lockingScript)` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:205-262`): its `sign` asks
//! the wallet's `createSignature` for SHA-256 of the BIP143 preimage under
//! the scope `computeSignatureScope` gives (`SignatureUtils.ts:44-68`), reads
//! the answer as DER and pushes it with the scope byte; its estimate is 73.
//! Until #803 the signer was crate-private, so a token minted through
//! `PushDrop::lock_with_wallet` (#782) had no public wallet-aware unlock.
//!
//! The recording is `tests/vectors/pushdrop_wallet_unlock_803.json`
//! (`tests/support/pushdrop_wallet_unlock_803.mjs`, the reference's own
//! template over a ProtoWallet of the scalar 9 under Node 22).
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! a ProtoWallet of the scalar 9 that records each call; no network, no port.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::primitives::{from_hex, to_hex, PublicKey};
use bsv_rs::script::template::{SignOutputs, SigningContext};
use bsv_rs::script::templates::{LockPosition, PushDrop};
use bsv_rs::script::{Script, UnlockingScript};
use bsv_rs::transaction::{verify_input, InputRules, Transaction};
use bsv_rs::wallet::{Counterparty, Protocol, SecurityLevel};
use bsv_rs::Error;
use identity_reveal_wallet::Counting;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/pushdrop_wallet_unlock_803.json");

fn group(name: &str, count: usize) -> Vec<Value> {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(vector["issue"], 803);
    let cases = vector[name].as_array().unwrap().clone();
    assert_eq!(cases.len(), count, "the recording's {name} count");
    cases
}

fn cases() -> Vec<Value> {
    group("cases", 23)
}

fn named(group_name: &str, count: usize, name: &str) -> Value {
    group(group_name, count)
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, "pushdrop wallet unlock")
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

fn sign_outputs(case: &Value) -> SignOutputs {
    match text(&case["sign_outputs"]) {
        "all" => SignOutputs::All,
        "none" => SignOutputs::None,
        "single" => SignOutputs::Single,
        other => panic!("sign outputs {other}"),
    }
}

/// The case through the door over `wallet`: the estimate and what `sign`
/// answers.
async fn unlock_over(wallet: &Counting, case: &Value) -> (usize, bsv_rs::Result<UnlockingScript>) {
    let raw_tx = from_hex(text(&case["transaction"])).unwrap();
    let lock = Script::from_hex(text(&case["locking_script"])).unwrap();
    let context = SigningContext::new(
        &raw_tx,
        case["input_index"].as_u64().unwrap() as usize,
        case["source_satoshis"].as_u64().unwrap(),
        &lock,
    );
    let template = PushDrop::unlock_with_wallet(
        wallet,
        case["originator"].as_str(),
        protocol(),
        text(&case["key_id"]),
        counterparty(text(&case["counterparty"])),
        sign_outputs(case),
        case["anyone_can_pay"].as_bool().unwrap(),
    );
    (template.estimate_length(), template.sign(context).await)
}

/// The case through the door over the scalar 9's wallet.
async fn unlock(case: &Value) -> (Counting, bsv_rs::Result<UnlockingScript>) {
    let wallet = Counting::of_scalar(9);
    let (estimate, script) = unlock_over(&wallet, case).await;
    assert_eq!(estimate, 73, "{}", case["name"]);
    assert_eq!(case["estimate_length"], 73, "{}", case["name"]);
    (wallet, script)
}

#[tokio::test]
async fn the_wallet_unlock_writes_the_references_bytes_803() {
    for case in cases() {
        let name = &case["name"];
        assert_eq!(case["protocol_id"][0], 2, "{name}");
        assert_eq!(case["protocol_id"][1], "pushdrop wallet unlock", "{name}");
        assert_eq!(case["accepted"], true, "{name}");
        let (_, script) = unlock(&case).await;
        let script = script.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(script.to_hex(), text(&case["unlocking_script"]), "{name}");
    }
}

#[tokio::test]
async fn the_scope_byte_is_the_references_at_each_crossing_803() {
    // ALL, NONE and SINGLE with FORKID, ANYONECANPAY or-ed in
    // (`SignatureUtils.ts:44-68`).
    let expected = [
        ("all", false, 0x41u8),
        ("all", true, 0xc1),
        ("none", false, 0x42),
        ("none", true, 0xc2),
        ("single", false, 0x43),
        ("single", true, 0xc3),
    ];
    let mut seen = 0;
    for case in cases() {
        let name = &case["name"];
        let byte = expected
            .iter()
            .find(|(outputs, anyone, _)| {
                case["sign_outputs"] == *outputs && case["anyone_can_pay"] == *anyone
            })
            .unwrap()
            .2;
        let recorded = from_hex(text(&case["unlocking_script"])).unwrap();
        assert_eq!(recorded.last(), Some(&byte), "{name}: the recording");
        let (_, script) = unlock(&case).await;
        let written = script.unwrap().to_binary();
        assert_eq!(written.last(), Some(&byte), "{name}");
        // One push: its opcode the length of the signature and its byte.
        assert_eq!(written[0] as usize, written.len() - 1, "{name}");
        seen += 1;
    }
    assert_eq!(seen, 23);
    // Every crossing is recorded at each of the three inputs.
    for (outputs, anyone, _) in expected {
        let count = cases()
            .iter()
            .filter(|case| case["sign_outputs"] == outputs && case["anyone_can_pay"] == anyone)
            .count();
        assert!(count >= 3, "{outputs} {anyone}: {count}");
    }
}

#[tokio::test]
async fn the_wallet_is_asked_one_signature_over_the_preimage_hash_803() {
    for case in cases() {
        let name = &case["name"];
        let (wallet, script) = unlock(&case).await;
        script.unwrap();
        let recorded = case["calls"].as_array().unwrap();
        assert_eq!(recorded.len(), 1, "{name}");
        assert_eq!(recorded[0]["method"], "createSignature", "{name}");
        assert_eq!(wallet.calls(), ["create_signature"], "{name}");
        assert_eq!(
            wallet.originators(),
            [recorded[0]["originator"].as_str().map(str::to_string)],
            "{name}: the originator"
        );
        let asked = &recorded[0]["args"];
        let args = wallet.signature_args.lock().unwrap().clone();
        assert_eq!(args.len(), 1, "{name}");
        assert_eq!(
            args[0].data.as_deref().map(to_hex),
            asked["data"].as_str().map(str::to_string),
            "{name}: SHA-256 of the preimage"
        );
        assert_eq!(args[0].data.as_ref().map(Vec::len), Some(32), "{name}");
        assert_eq!(args[0].hash_to_directly_sign, None, "{name}");
        assert_eq!(args[0].protocol_id, protocol(), "{name}");
        assert_eq!(Some(args[0].key_id.as_str()), asked["keyID"].as_str());
        assert_eq!(
            args[0].counterparty.as_ref().map(counterparty_text),
            asked["counterparty"].as_str().map(str::to_string),
            "{name}"
        );
    }
}

#[tokio::test]
async fn each_recorded_unlocking_script_spends_the_recorded_lock_803() {
    for case in cases() {
        let name = &case["name"];
        let (_, script) = unlock(&case).await;
        let script = script.unwrap();
        let mut tx = Transaction::from_hex(text(&case["transaction"])).unwrap();
        let index = case["input_index"].as_u64().unwrap() as usize;
        tx.inputs_mut()[index].unlocking_script = Some(script);
        let lock = from_hex(text(&case["locking_script"])).unwrap();
        let verdict = verify_input(
            &lock,
            case["source_satoshis"].as_u64().unwrap(),
            &tx.to_binary(),
            index,
            &InputRules::reference_default(),
        );
        assert!(verdict.is_ok(), "{name}: {verdict:?}");
    }
}

#[tokio::test]
async fn a_token_minted_through_the_wallet_lock_is_spent_through_the_wallet_unlock_803() {
    // The issue's sentence: both doors public, no private signer between.
    let wallet = Counting::of_scalar(9);
    let lock = PushDrop::lock_with_wallet(
        &wallet,
        None,
        vec![b"token".to_vec()],
        protocol(),
        "7",
        Counterparty::Self_,
        false,
        true,
        LockPosition::Before,
    )
    .await
    .unwrap();
    let case = named("cases", 23, "input_1_all");
    let mut tx = Transaction::from_hex(text(&case["transaction"])).unwrap();
    let raw_tx = tx.to_binary();
    let script = Script::from_binary(&lock.to_binary()).unwrap();
    let template = PushDrop::unlock_with_wallet(
        &wallet,
        None,
        protocol(),
        "7",
        Counterparty::Self_,
        SignOutputs::All,
        false,
    );
    let unlocking = template
        .sign(SigningContext::new(&raw_tx, 1, 546, &script))
        .await
        .unwrap();
    assert!(unlocking.to_binary().len() <= template.estimate_length());
    tx.inputs_mut()[1].unlocking_script = Some(unlocking);
    let rules = InputRules::reference_default();
    verify_input(&lock.to_binary(), 546, &tx.to_binary(), 1, &rules).unwrap();
    // Another key ID's signature does not spend it.
    let other = PushDrop::unlock_with_wallet(
        &wallet,
        None,
        protocol(),
        "8",
        Counterparty::Self_,
        SignOutputs::All,
        false,
    )
    .sign(SigningContext::new(&raw_tx, 1, 546, &script))
    .await
    .unwrap();
    tx.inputs_mut()[1].unlocking_script = Some(other);
    assert!(verify_input(&lock.to_binary(), 546, &tx.to_binary(), 1, &rules).is_err());
}

fn refusal(error: &Error) -> String {
    match error {
        Error::TransactionError(words) => words.clone(),
        other => panic!("not a TransactionError: {other:?}"),
    }
}

#[tokio::test]
async fn an_input_index_past_the_inputs_is_refused_in_the_references_words_before_the_wallet_803() {
    let case = named("refusals", 3, "input_index_past_the_inputs");
    assert_eq!(case["accepted"], false);
    assert!(case["calls"].as_array().unwrap().is_empty());
    let (wallet, script) = unlock(&case).await;
    let error = script.unwrap_err();
    assert_eq!(refusal(&error), text(&case["refusal"]));
    assert_eq!(
        refusal(&error),
        "inputIndex 3 is outside the transaction input range"
    );
    assert!(wallet.calls().is_empty(), "no wallet call");
}

#[tokio::test]
async fn a_source_amount_past_21e14_is_refused_in_the_references_words_before_the_wallet_803() {
    let case = named("refusals", 3, "amount_past_21e14");
    assert_eq!(case["accepted"], false);
    assert!(case["calls"].as_array().unwrap().is_empty());
    assert_eq!(case["source_satoshis"], 2_100_000_000_000_001u64);
    let (wallet, script) = unlock(&case).await;
    let error = script.unwrap_err();
    assert_eq!(refusal(&error), text(&case["refusal"]));
    assert_eq!(
        refusal(&error),
        "sourceSatoshis must be a valid number of satoshis"
    );
    assert!(wallet.calls().is_empty(), "no wallet call");
    // Exactly 21e14 is signed, as recorded (`amount_at_21e14` of `cases`).
    let at = named("cases", 23, "amount_at_21e14");
    assert_eq!(at["source_satoshis"], 2_100_000_000_000_000u64);
}

#[tokio::test]
async fn a_wallet_error_is_returned_as_it_came_803() {
    let case = named("refusals", 3, "wallet_throws");
    assert_eq!(case["calls"].as_array().unwrap().len(), 1);
    let wallet = Counting::of_scalar(9);
    let thrown = Error::WalletError(text(&case["refusal"]).to_string());
    *wallet.signature_error.lock().unwrap() = Some(thrown.clone());
    let (_, script) = unlock_over(&wallet, &case).await;
    assert_eq!(script.unwrap_err(), thrown);
    assert_eq!(wallet.calls(), ["create_signature"]);
}

/// The secp256k1 group order.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `n - s`, 32 bytes big-endian.
fn order_minus(s: &[u8; 32]) -> [u8; 32] {
    let mut twin = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let digit = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(digit < 0);
        twin[i] = (digit + 256 * borrow) as u8;
    }
    twin
}

/// The DER of `(r, s)`, written by hand: `Signature::to_der` writes the
/// low-S form, so a high-S signature built through it is its low-S twin
/// again (the cold read's finding: the test passed under the reference's
/// own behaviour).
fn der_by_hand(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let integer = |bytes: &[u8]| {
        let mut v: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
        if v.is_empty() || v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    };
    let mut body = integer(r);
    body.extend(integer(s));
    let mut der = vec![0x30, body.len() as u8];
    der.extend(body);
    der
}

/// The signature's high-S twin: `(r, n - s)`, DER.
fn high_s(der: Vec<u8>) -> Vec<u8> {
    let signature = bsv_rs::primitives::Signature::from_der(&der).unwrap();
    let der = der_by_hand(signature.r(), &order_minus(signature.s()));
    assert!(!bsv_rs::primitives::Signature::from_der(&der)
        .unwrap()
        .is_low_s());
    der
}

/// 2^255 - 1, the largest S of 32 DER bytes: above `n / 2`, so high.
const S_UNDER_TWO_TO_THE_255: [u8; 32] = {
    let mut s = [0xff; 32];
    s[0] = 0x7f;
    s
};

/// The wallet's R over an S of 2^255 - 1, DER by hand: a high-S answer
/// whose DER is as long as its low-S twin's (`n - s` is 32 bytes too). A
/// high S of 32 DER bytes lies between `n / 2` and 2^255, a range 2^127
/// wide that no signer reaches by chance, so the S is chosen, not signed:
/// the signature verifies under no key, which the door does not ask.
fn high_s_of_equal_der_length(der: Vec<u8>) -> Vec<u8> {
    let signature = bsv_rs::primitives::Signature::from_der(&der).unwrap();
    let der = der_by_hand(signature.r(), &S_UNDER_TWO_TO_THE_255);
    assert!(!bsv_rs::primitives::Signature::from_der(&der)
        .unwrap()
        .is_low_s());
    der
}

#[tokio::test]
async fn a_high_s_answer_as_long_as_its_low_s_form_is_written_low_803() {
    // The re-read's plant: a signer that pushes the wallet's answer as given
    // only when its DER is as long as its low-S form's passed the one high-S
    // sample below, whose DER is a byte longer than its twin's. Here the two
    // are of one length, so that signer writes the recorded script and this
    // test fails.
    let case = named("fold2", 1, "answer_high_s_of_equal_der_length");
    assert_eq!(case["accepted"], true);
    let wallet = Counting::of_scalar(9);
    *wallet.signature_form.lock().unwrap() = Some(high_s_of_equal_der_length);
    let (_, script) = unlock_over(&wallet, &case).await;
    assert_eq!(wallet.calls(), ["create_signature"]);
    let script = script.unwrap().to_binary();
    // The reference pushes the answer as given: one push of the DER (R of
    // 33 bytes, S 2^255 - 1 in 32) and the scope byte.
    let recorded = from_hex(text(&case["unlocking_script"])).unwrap();
    assert_eq!(recorded.len(), 73, "the recording");
    assert_eq!(recorded[38..40], [0x02, 0x20], "the recording's S header");
    assert_eq!(recorded[40..72], S_UNDER_TWO_TO_THE_255, "the recording");
    // This crate writes the low-S twin: the same bytes through S's header,
    // then `n - s`, then the scope byte; the same length.
    let low = order_minus(&S_UNDER_TWO_TO_THE_255);
    assert_eq!(
        to_hex(&low),
        "7ffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
    );
    let mut expected = recorded[..40].to_vec();
    expected.extend(low);
    expected.push(0x41);
    assert_eq!(to_hex(&script), to_hex(&expected));
    assert_eq!(script.len(), recorded.len(), "one length, low or high");
    assert_ne!(
        script, recorded,
        "the stated row: written low, not as given"
    );
}

#[tokio::test]
async fn a_wallet_answer_no_der_is_refused_and_a_high_s_one_is_written_low_803() {
    let forms: [(&str, identity_reveal_wallet::SignatureForm); 4] = [
        ("answer_not_der", |_| vec![1, 2, 3]),
        ("answer_empty", |_| Vec::new()),
        ("answer_with_a_byte_after", |mut der| {
            der.push(0);
            der
        }),
        ("answer_high_s", high_s),
    ];
    for (name, form) in forms {
        let case = named("answers", 4, name);
        let wallet = Counting::of_scalar(9);
        *wallet.signature_form.lock().unwrap() = Some(form);
        let (_, script) = unlock_over(&wallet, &case).await;
        assert_eq!(wallet.calls(), ["create_signature"], "{name}");
        if case["accepted"] == true {
            // The stated row: the reference pushes the high-S twin as
            // answered (74 bytes, one past its estimate); this crate's
            // `Signature::to_der` writes the low-S form, so the script is
            // the plain case's, inside the estimate.
            assert_eq!(name, "answer_high_s");
            let recorded = from_hex(text(&case["unlocking_script"])).unwrap();
            assert_eq!(recorded.len(), 74, "{name}: the recording");
            let script = script.unwrap_or_else(|error| panic!("{name}: {error}"));
            let plain = named("cases", 23, "input_0_all");
            assert_eq!(script.to_hex(), text(&plain["unlocking_script"]), "{name}");
            assert_eq!(script.to_binary().len(), 73, "{name}");
            // The same r, the other s.
            assert_eq!(script.to_binary()[3..38], recorded[3..38], "{name}");
        } else {
            let error = script.unwrap_err().to_string();
            assert!(
                error.ends_with(text(&case["refusal"])),
                "{name}: {error} against {}",
                case["refusal"]
            );
        }
    }
}

#[tokio::test]
async fn both_faults_at_once_are_refused_for_the_index_before_the_amount_803() {
    // The fold's recorded case: an input index past the inputs and an
    // amount past 21e14 on one call. The reference names the index
    // (`SignatureUtils.ts:89-91` ahead of `:16-21`), and so does the door.
    let case = named(
        "fold",
        2,
        "input_index_past_the_inputs_and_amount_past_21e14",
    );
    assert_eq!(case["accepted"], false);
    assert_eq!(case["input_index"], 3);
    assert_eq!(case["source_satoshis"], 2_100_000_000_000_001u64);
    assert!(case["calls"].as_array().unwrap().is_empty());
    let (wallet, script) = unlock(&case).await;
    let error = script.unwrap_err();
    assert_eq!(refusal(&error), text(&case["refusal"]));
    assert_eq!(
        refusal(&error),
        "inputIndex 3 is outside the transaction input range"
    );
    assert!(wallet.calls().is_empty(), "no wallet call");
}

/// The signature with its R one byte longer: `01` ahead of the 32 bytes,
/// the value 2^256 + r, DER written by hand.
fn r_past_32_bytes(der: Vec<u8>) -> Vec<u8> {
    let signature = bsv_rs::primitives::Signature::from_der(&der).unwrap();
    let integer = |bytes: &[u8]| {
        let mut v: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
        if v.is_empty() || v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    };
    let mut r = vec![1u8];
    r.extend(signature.r());
    let mut body = integer(&r);
    body.extend(integer(signature.s()));
    let mut der = vec![0x30, body.len() as u8];
    der.extend(body);
    der
}

#[tokio::test]
async fn a_wallet_answer_with_r_past_32_bytes_is_refused_where_the_reference_pushes_it_stated_803()
{
    // #842's stated row at this door: the reference holds an R of 2^256 or
    // more as a `BigNumber` and pushes the answer as it came; this crate's
    // `Signature` holds 32 bytes and its reader refuses the integer.
    let case = named("fold", 2, "answer_r_past_32_bytes");
    assert_eq!(case["accepted"], true, "the reference pushes it");
    let wallet = Counting::of_scalar(9);
    *wallet.signature_form.lock().unwrap() = Some(r_past_32_bytes);
    let (_, script) = unlock_over(&wallet, &case).await;
    assert_eq!(wallet.calls(), ["create_signature"]);
    assert_eq!(
        script.unwrap_err().to_string(),
        "invalid signature: Integer component too large"
    );
    // The answer the door refused is the one the reference pushed: its
    // script is one push of that DER and the scope byte.
    let plain = from_hex(text(&named("cases", 23, "input_0_all")["unlocking_script"])).unwrap();
    let answered = r_past_32_bytes(plain[1..plain.len() - 1].to_vec());
    let recorded = from_hex(text(&case["unlocking_script"])).unwrap();
    assert_eq!(recorded[0] as usize, recorded.len() - 1);
    assert_eq!(recorded[1..recorded.len() - 1], answered[..]);
    assert_eq!(recorded.last(), Some(&0x41));
    assert_eq!(answered[3], 33, "R is 33 bytes");
}

#[tokio::test]
async fn a_named_script_code_is_the_one_signed_803() {
    // `SigningContext::with_script_code`, as every template's `sign` reads
    // it: naming the locking script itself changes nothing, naming another
    // script signs that one.
    let case = named("cases", 23, "input_0_all");
    let raw_tx = from_hex(text(&case["transaction"])).unwrap();
    let lock = Script::from_hex(text(&case["locking_script"])).unwrap();
    let other = Script::from_hex(text(
        &named("cases", 23, "counterparty_anyone")["locking_script"],
    ))
    .unwrap();
    let data = |context: SigningContext<'_>| {
        let wallet = Counting::of_scalar(9);
        let raw_tx = context.raw_tx.to_vec();
        let lock = context.locking_script.clone();
        let code = context.script_code.cloned();
        async move {
            let mut context = SigningContext::new(&raw_tx, 0, 1000, &lock);
            if let Some(code) = &code {
                context = context.with_script_code(code);
            }
            PushDrop::unlock_with_wallet(
                &wallet,
                None,
                protocol(),
                "1",
                Counterparty::Self_,
                SignOutputs::All,
                false,
            )
            .sign(context)
            .await
            .unwrap();
            let args = wallet.signature_args.lock().unwrap();
            args[0].data.clone().unwrap()
        }
    };
    let plain = data(SigningContext::new(&raw_tx, 0, 1000, &lock)).await;
    assert_eq!(to_hex(&plain), text(&case["calls"][0]["args"]["data"]));
    let same = data(SigningContext::new(&raw_tx, 0, 1000, &lock).with_script_code(&lock)).await;
    assert_eq!(same, plain);
    let named_other =
        data(SigningContext::new(&raw_tx, 0, 1000, &lock).with_script_code(&other)).await;
    let over_other = data(SigningContext::new(&raw_tx, 0, 1000, &other)).await;
    assert_eq!(named_other, over_other);
    assert_ne!(named_other, plain);
}

/// A future that may cross threads: what `#[async_trait]`'s default and a
/// multi-threaded server's handler ask of the futures they hold.
fn sendable<F: std::future::Future + Send>(future: F) -> F {
    future
}

/// A dependent's shape: a method of an `#[async_trait]` trait (its future
/// boxed as `Send`) that signs a token input through the door, the lock
/// parsed and owned inside it.
#[async_trait::async_trait]
trait SpendsTokens {
    async fn unlocking(&self, raw_tx: &[u8], lock_hex: &str) -> bsv_rs::Result<UnlockingScript>;
}

struct Holder {
    wallet: std::sync::Arc<dyn bsv_rs::wallet::WalletInterface>,
}

#[async_trait::async_trait]
impl SpendsTokens for Holder {
    async fn unlocking(&self, raw_tx: &[u8], lock_hex: &str) -> bsv_rs::Result<UnlockingScript> {
        let lock = bsv_rs::script::LockingScript::from_hex(lock_hex)?;
        PushDrop::unlock_with_wallet(
            &*self.wallet,
            None,
            protocol(),
            "1",
            Counterparty::Self_,
            SignOutputs::All,
            false,
        )
        .sign(SigningContext::new(raw_tx, 0, 1000, lock.as_script()))
        .await
    }
}

fn template_over(
    wallet: &Counting,
) -> bsv_rs::script::templates::PushDropWalletUnlock<'_, Counting> {
    PushDrop::unlock_with_wallet(
        wallet,
        None,
        protocol(),
        "1",
        Counterparty::Self_,
        SignOutputs::All,
        false,
    )
}

/// The context built in the call. The lock is owned by the future, as a
/// caller that parsed it holds it: a `Script` is `Send` and not `Sync`.
async fn inline(wallet: &Counting, raw_tx: &[u8], lock: Script) -> bsv_rs::Result<UnlockingScript> {
    template_over(wallet)
        .sign(SigningContext::new(raw_tx, 0, 1000, &lock))
        .await
}

/// The context bound, then given.
async fn bound(wallet: &Counting, raw_tx: &[u8], lock: Script) -> bsv_rs::Result<UnlockingScript> {
    let template = template_over(wallet);
    let context = SigningContext::new(raw_tx, 0, 1000, &lock);
    template.sign(context).await
}

/// The future made in a scope of its own, then awaited; the future alone
/// is `Send` too.
async fn made(wallet: &Counting, raw_tx: &[u8], lock: Script) -> bsv_rs::Result<UnlockingScript> {
    let template = template_over(wallet);
    let future = {
        let context = SigningContext::new(raw_tx, 0, 1000, &lock);
        sendable(template.sign(context))
    };
    future.await
}

#[tokio::test]
async fn the_future_sign_returns_is_send_in_each_caller_form_803() {
    // The design read's finding: with `sign(&self, &SigningContext)` as an
    // `async fn` the future kept the context, which borrows a `Script` (its
    // caches are `RefCell`s, so it is not `Sync`), and no caller form was
    // `Send`. Each form here is a compile-time claim; each is also run, and
    // writes the recorded script.
    let case = named("cases", 23, "input_0_all");
    let raw_tx = from_hex(text(&case["transaction"])).unwrap();
    let lock = Script::from_hex(text(&case["locking_script"])).unwrap();
    let wallet = Counting::of_scalar(9);
    // The template itself crosses threads.
    fn send_and_sync<T: Send + Sync>(_: &T) {}
    send_and_sync(&template_over(&wallet));
    let scripts = [
        sendable(inline(&wallet, &raw_tx, lock.clone())).await,
        sendable(bound(&wallet, &raw_tx, lock.clone())).await,
        sendable(made(&wallet, &raw_tx, lock.clone())).await,
        // Under `#[async_trait]`, over a `dyn` wallet behind an `Arc`.
        Holder {
            wallet: std::sync::Arc::new(Counting::of_scalar(9)),
        }
        .unlocking(&raw_tx, text(&case["locking_script"]))
        .await,
    ];
    for script in scripts {
        assert_eq!(script.unwrap().to_hex(), text(&case["unlocking_script"]));
    }
}

#[test]
fn the_template_prints_no_argument_803() {
    let wallet = Counting::of_scalar(9);
    let template = PushDrop::unlock_with_wallet(
        &wallet,
        Some("pushdrop.example.com"),
        protocol(),
        "a key id",
        Counterparty::Self_,
        SignOutputs::Single,
        true,
    );
    assert_eq!(
        format!("{template:?}"),
        "PushDropWalletUnlock { scope: 195, estimate_length: 73, .. }"
    );
}
