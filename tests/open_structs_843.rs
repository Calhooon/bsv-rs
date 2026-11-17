//! The structs #843's structs lane opened, built through their doors.
//!
//! Each is `#[non_exhaustive]` since #843 (the captain's rulings of
//! 2026-11-17): a context or parameter block, a configuration, or a record
//! this crate produces. A struct literal outside the crate no longer builds
//! one (each type's `compile_fail` doc test, held by
//! `tests/arch_non_exhaustive_pins_819.rs`); this file pins what each
//! constructor and setter builds, field by field, and the three doors whose
//! behaviour moved with their shapes: `ChainTip` (no Genesis height),
//! `CreateActionOptionsRaw` (`trustSelf`, the reference's rule) and
//! `auth::Certificate::to_wallet_certificate` (the wallet's record).
#![cfg(all(feature = "identity", feature = "kvstore", feature = "storage"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::auth::{AppEvent, Response};
use bsv_rs::error::WalletRefusalClass;
use bsv_rs::identity::{DisplayableIdentity, IdentityResolutionResult};
use bsv_rs::overlay::{HostResponse, OutputListItem, RankChangeEvent};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::{
    ExecutionContext, Script, ScriptEvaluationError, ScriptResource, ScriptResourceLimit,
    SigningContext,
};
use bsv_rs::storage::UploadMetadata;
use bsv_rs::transaction::beef_stream::ChainTip;
use bsv_rs::transaction::{
    AlwaysValidChainTracker, BeefValidationResult, Reason, Refusal, SortResult,
};
use bsv_rs::wallet::types::{Outpoint, TrustSelf};
use bsv_rs::wallet::validation::{
    validate_create_action_options, CreateActionArgsRaw, CreateActionInputRaw,
    CreateActionOptionsRaw, CreateActionOutputRaw, SignActionSpendRaw,
};
use bsv_rs::wallet::{ReviewActionsRefusal, WalletCertificate};
use bsv_rs::Error;
use std::collections::HashMap;

/// A tip is its height and median time past; `new` takes mainnet's CSV
/// activation height and no candidate block time, and it names no Genesis
/// height (the field deprecated by #451 is removed).
#[test]
fn a_chain_tip_is_built_by_new_and_its_two_setters_843() {
    let tip = ChainTip::new(900_000, 1_700_000_000);
    let ChainTip {
        height,
        median_time_past,
        csv_height,
        next_block_time,
        ..
    } = tip;
    assert_eq!(
        (height, median_time_past, csv_height, next_block_time),
        (900_000, 1_700_000_000, 419_328, None)
    );
    let regtest = ChainTip::new(120, 7)
        .with_csv_height(0)
        .with_next_block_time(9);
    assert_eq!(
        (
            regtest.height,
            regtest.median_time_past,
            regtest.csv_height,
            regtest.next_block_time
        ),
        (120, 7, 0, Some(9))
    );
    // A `const` door, as its fields are plain values.
    const TIP: ChainTip = ChainTip::new(1, 2).with_csv_height(3);
    assert_eq!(TIP, ChainTip::new(1, 2).with_csv_height(3));
}

#[test]
fn the_script_records_are_built_by_their_doors_843() {
    let limit = ScriptResourceLimit::new(ScriptResource::Stack, 10, 11);
    assert_eq!(
        (
            limit.resource,
            limit.limit,
            limit.attempted,
            limit.work_spent
        ),
        (ScriptResource::Stack, 10, 11, None)
    );
    let work = ScriptResourceLimit::new(ScriptResource::Work, 10, 11).with_work_spent(9);
    assert_eq!(work.work_spent, Some(9));
    assert_eq!(
        work.to_string(),
        "Work budget exhausted: spent 9 units, budget 10"
    );

    let error = ScriptEvaluationError::new(
        "words",
        "ab".repeat(32),
        3,
        ExecutionContext::LockingScript,
        4,
        vec![vec![1]],
        vec![vec![2]],
        vec![true],
        5,
        6,
    );
    assert!(!error.is_resource_limit());
    let declined = error.clone().with_resource_limit(limit);
    assert_eq!(declined.resource_limit, Some(limit));
    assert_eq!(
        (
            declined.message.as_str(),
            declined.source_output_index,
            declined.program_counter
        ),
        ("words", 3, 4)
    );

    let raw = [0u8; 10];
    let lock = Script::from_hex("51").unwrap();
    let code = Script::from_hex("52").unwrap();
    let context = SigningContext::new(&raw, 1, 2, &lock);
    assert!(context.script_code.is_none());
    let context = context.with_script_code(&code);
    assert_eq!(
        (
            context.raw_tx.len(),
            context.input_index,
            context.source_satoshis
        ),
        (10, 1, 2)
    );
    assert_eq!(
        context.script_code.map(Script::to_hex).as_deref(),
        Some("52")
    );
}

#[test]
fn the_transaction_records_are_built_by_their_doors_843() {
    let refusal = Refusal::new(7, Reason::TrailingBytes);
    assert_eq!(
        (refusal.offset, &refusal.reason),
        (7, &Reason::TrailingBytes)
    );

    let ids = |n: u8| vec![format!("{n:02x}").repeat(32)];
    let sorted = SortResult::new()
        .with_missing_inputs(ids(1))
        .with_not_valid(ids(2))
        .with_valid(ids(3))
        .with_with_missing_inputs(ids(4))
        .with_txid_only(ids(5));
    assert_eq!(
        [
            &sorted.missing_inputs,
            &sorted.not_valid,
            &sorted.valid,
            &sorted.with_missing_inputs,
            &sorted.txid_only
        ],
        [&ids(1), &ids(2), &ids(3), &ids(4), &ids(5)]
    );
    assert!(SortResult::new().valid.is_empty());

    let roots = HashMap::from([(9u32, "root".to_string())]);
    let verdict = BeefValidationResult::new(true, roots.clone());
    assert_eq!((verdict.valid, &verdict.roots), (true, &roots));

    assert_eq!(AlwaysValidChainTracker::new(8).height, 8);
}

#[test]
fn the_overlay_and_auth_records_are_built_by_their_doors_843() {
    let item = OutputListItem::new(vec![1, 2], 3);
    assert_eq!(
        (
            item.beef.as_slice(),
            item.output_index,
            &item.context,
            &item.txid
        ),
        (&[1u8, 2][..], 3, &None, &None)
    );
    let item = item.with_context(vec![4]).with_txid("ab".repeat(32));
    assert_eq!(item.context.as_deref(), Some(&[4u8][..]));
    assert_eq!(item.txid, Some("ab".repeat(32)));
    // The wire's JSON is unchanged: the two optional members absent when unset.
    assert_eq!(
        serde_json::to_string(&OutputListItem::new(vec![1], 0)).unwrap(),
        r#"{"beef":[1],"outputIndex":0}"#
    );

    let event = RankChangeEvent::new("https://host.invalid", 1.5, 2.5, "failure");
    assert_eq!(
        (
            event.host.as_str(),
            event.old_rank,
            event.new_rank,
            event.reason.as_str()
        ),
        ("https://host.invalid", 1.5, 2.5, "failure")
    );

    let ok = HostResponse::success("h".to_string(), HashMap::new());
    assert!(ok.success && ok.steak.is_some() && ok.error.is_none());
    let failed = HostResponse::failure("h".to_string(), "words".to_string());
    assert!(!failed.success && failed.steak.is_none());
    assert_eq!(failed.error.as_deref(), Some("words"));

    let sender = PrivateKey::from_bytes(&[5; 32]).unwrap().public_key();
    let app = AppEvent::new(sender.clone(), "ping", serde_json::json!({ "n": 1 }));
    assert_eq!(
        (&app.sender, app.event_name.as_str(), &app.data),
        (&sender, "ping", &serde_json::json!({ "n": 1 }))
    );

    let headers =
        indexmap::IndexMap::from([("content-type".to_string(), "text/plain".to_string())]);
    let response = Response::new(200, headers.clone(), b"ok".to_vec());
    assert_eq!(
        (response.status, &response.headers, response.body.as_slice()),
        (200, &headers, &b"ok"[..])
    );
    assert_eq!(response.header("Content-Type"), Some("text/plain"));

    let upload = UploadMetadata::new("uhrp://file", 99);
    assert_eq!(
        (upload.uhrp_url.as_str(), upload.expiry_time),
        ("uhrp://file", 99)
    );

    let identity = DisplayableIdentity::from_key("02abc123");
    let resolved = IdentityResolutionResult::new(identity.clone(), Vec::new());
    assert_eq!(resolved.identity.identity_key, identity.identity_key);
    assert!(resolved.certificates.is_empty());
}

#[test]
fn the_review_refusal_is_built_by_its_doors_843() {
    let refusal = ReviewActionsRefusal::new(Vec::new());
    assert_eq!(
        refusal.message,
        "Undelayed createAction or signAction results require review."
    );
    assert!(refusal.txid.is_none() && refusal.tx.is_none() && refusal.no_send_change.is_none());
    let outpoint = Outpoint::new([7; 32], 1);
    let refusal = refusal
        .with_message("words")
        .with_send_with_results(Vec::new())
        .with_txid([9; 32])
        .with_tx(vec![1, 2, 3])
        .with_no_send_change(vec![outpoint.clone()]);
    assert_eq!(refusal.message, "words");
    assert_eq!(refusal.txid, Some([9; 32]));
    assert_eq!(refusal.tx.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(refusal.no_send_change, Some(vec![outpoint]));
    assert_eq!(
        refusal,
        ReviewActionsRefusal::with_members(
            Vec::new(),
            Vec::new(),
            Some([9; 32]),
            Some(vec![1, 2, 3]),
            Some(vec![Outpoint::new([7; 32], 1)])
        )
        .with_message("words")
    );
}

/// The five raw records of the action validators: `new` takes the
/// reference's required members and each optional member has its setter.
#[test]
fn the_raw_action_records_are_built_by_their_doors_843() {
    let input = CreateActionInputRaw::new(format!("{}.0", "ab".repeat(32)), "an input");
    assert!(
        input.unlocking_script.is_none()
            && input.unlocking_script_length.is_none()
            && input.sequence_number.is_none()
    );
    let input = input
        .with_unlocking_script("51")
        .with_unlocking_script_length(1)
        .with_sequence_number(7);
    assert_eq!(
        (
            input.unlocking_script.as_deref(),
            input.unlocking_script_length,
            input.sequence_number
        ),
        (Some("51"), Some(1), Some(7))
    );

    let output = CreateActionOutputRaw::new("51", 9, "an output")
        .with_basket("basket")
        .with_custom_instructions("{}")
        .with_tags(vec!["t".to_string()]);
    assert_eq!(
        (
            output.locking_script.as_str(),
            output.satoshis,
            output.output_description.as_str()
        ),
        ("51", 9, "an output")
    );
    assert_eq!(
        (
            output.basket.as_deref(),
            output.custom_instructions.as_deref(),
            output.tags.len()
        ),
        (Some("basket"), Some("{}"), 1)
    );

    let options = CreateActionOptionsRaw::new()
        .with_sign_and_process(false)
        .with_accept_delayed_broadcast(false)
        .with_trust_self("known")
        .with_known_txids(vec!["ab".repeat(32)])
        .with_return_txid_only(true)
        .with_no_send(true)
        .with_no_send_change(vec![format!("{}.1", "cd".repeat(32))])
        .with_send_with(vec!["ef".repeat(32)])
        .with_randomize_outputs(false);
    let valid = validate_create_action_options(Some(&options)).unwrap();
    assert!(!valid.sign_and_process && !valid.accept_delayed_broadcast && !valid.randomize_outputs);
    assert!(valid.return_txid_only && valid.no_send);
    assert_eq!(valid.trust_self, Some(TrustSelf::Known));
    assert_eq!(valid.known_txids, vec![[0xab; 32]]);
    assert_eq!(valid.no_send_change, vec![Outpoint::new([0xcd; 32], 1)]);
    assert_eq!(valid.send_with, vec![[0xef; 32]]);

    let spend = SignActionSpendRaw::new("51").with_sequence_number(3);
    assert_eq!(
        (spend.unlocking_script.as_str(), spend.sequence_number),
        ("51", Some(3))
    );

    let args = CreateActionArgsRaw::new("an action")
        .with_input_beef(vec![1])
        .with_inputs(vec![input])
        .with_outputs(vec![output])
        .with_lock_time(4)
        .with_version(2)
        .with_labels(vec!["label".to_string()])
        .with_options(options);
    assert_eq!(
        (
            args.description.as_str(),
            args.input_beef.as_deref(),
            args.lock_time,
            args.version
        ),
        ("an action", Some(&[1u8][..]), Some(4), Some(2))
    );
    assert_eq!(
        (args.inputs.len(), args.outputs.len(), args.labels.len()),
        (1, 1, 1)
    );
    assert!(args.options.is_some());
    let bare = CreateActionArgsRaw::new("an action");
    assert!(bare.inputs.is_empty() && bare.outputs.is_empty() && bare.options.is_none());
}

/// `trustSelf` is absent or `known`, any other text refused in the
/// reference's words (`validationHelpers.ts:668-674`: `invalid('trustSelf',
/// "undefined or 'known'")`, `WERR_INVALID_PARAMETER`'s sentence).
#[test]
fn trust_self_is_absent_or_known_as_the_reference_reads_it_843() {
    let absent = validate_create_action_options(Some(&CreateActionOptionsRaw::new())).unwrap();
    assert_eq!(absent.trust_self, None);
    assert_eq!(
        validate_create_action_options(None).unwrap().trust_self,
        None
    );
    for text in ["", "Known", "all", " known"] {
        let options = CreateActionOptionsRaw::new().with_trust_self(text);
        match validate_create_action_options(Some(&options)) {
            Err(Error::WalletRefusal { class, message }) => {
                assert_eq!(class, WalletRefusalClass::InvalidParameter, "{text:?}");
                assert_eq!(
                    message, "The trustSelf parameter must be undefined or 'known'",
                    "{text:?}"
                );
            }
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

/// `to_wallet_certificate` answers the wallet's record, text for text: the
/// type and the serial number in base64, the keys in compressed hex, the
/// outpoint as `txid.vout`, the signature in hex; where the certificate
/// holds no outpoint or no signature, the empty text.
#[test]
fn a_certificate_converts_to_the_wallets_record_843() {
    let certifier = PrivateKey::from_bytes(&[3; 32]).unwrap();
    let subject = PrivateKey::from_bytes(&[4; 32]).unwrap().public_key();
    let mut certificate =
        Certificate::new([1; 32], [2; 32], subject.clone(), certifier.public_key());
    certificate
        .fields
        .insert("name".to_string(), "dmFsdWU=".to_string());
    let unsigned: WalletCertificate = certificate.to_wallet_certificate();
    assert_eq!(
        (
            unsigned.signature.as_str(),
            unsigned.revocation_outpoint.as_str()
        ),
        ("", "")
    );

    certificate.revocation_outpoint = Some(Outpoint::new([0xcc; 32], 7));
    certificate.sign(&certifier).unwrap();
    let wallet = certificate.to_wallet_certificate();
    assert_eq!(
        wallet.certificate_type,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    assert_eq!(
        wallet.serial_number,
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    );
    assert_eq!(wallet.subject, subject.to_hex());
    assert_eq!(wallet.certifier, certifier.public_key().to_hex());
    assert_eq!(wallet.revocation_outpoint, format!("{}.7", "cc".repeat(32)));
    assert_eq!(
        wallet.signature,
        bsv_rs::primitives::to_hex(certificate.signature.as_ref().unwrap())
    );
    assert_eq!(
        wallet.fields.get("name").map(String::as_str),
        Some("dmFsdWU=")
    );
    // The record is the one a wallet's JSON carries: `type`, and text members.
    let json = serde_json::to_value(&wallet).unwrap();
    assert_eq!(json["type"], wallet.certificate_type);
    assert_eq!(json["revocationOutpoint"], wallet.revocation_outpoint);
}
