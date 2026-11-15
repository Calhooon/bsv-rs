//! #843, W1: no JSON text and no refusal sentence moved when the wallet's
//! `TxId` alias went.
//!
//! `Txid` has no serde of its own. The three field-level adapters
//! (`hex_txid`, `hex_txid_vec_option`, `hex_txid_option`), `Outpoint`'s own
//! serde and the certificate's revocation-outpoint module are retyped over
//! it: written `txid.to_string()`, read with the same decode and the same
//! length check in the same order as before, so each refusal is the base's
//! sentence. The text doors (`Outpoint::from_string`, `parse_wallet_outpoint`,
//! `validate_create_action_options`, `WireWriter::write_txid_hex`,
//! `write_outpoint_string`) run their own checks as before and build the id
//! from the text they decoded before (for the validators, the trimmed and
//! lower-cased text), so no accepted set moved.
//!
//! One test per type and per door, each against
//! `vectors/wallet_txid_wires_843w1.json`, recorded on the base `471bdaf6`
//! by `wallet_txid_wires_843w1.rs`' recorder through the same text-only
//! source (`support/wallet_txid_843w1.rs`). RED: the plants of the lane
//! record (`docs/lanes/fix-843w1.md`).

#![cfg(all(feature = "wallet", feature = "auth"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/wallet_txid_843w1.rs"]
mod support;

use serde_json::Value;
use support::{cells, door_cells, id, json_cells, json_forms, recorded, vout, IDS};

/// One type's JSON, for every recorded id in lower and in upper case: the
/// text written is the recording's, and an upper-case text is read and
/// written back in lower case.
fn json_of(name: &str) {
    let base = recorded();
    let entries = base["ids"].as_array().unwrap();
    assert_eq!(entries.len(), IDS as usize);
    for (counter, entry) in entries.iter().enumerate() {
        let counter = counter as u32;
        let (text, n) = (id(counter), vout(counter));
        assert_eq!(entry["id"], text);
        let lower = &json_forms(&text, n)[name];
        let upper = &json_forms(&text.to_uppercase(), n)[name];
        assert!(lower.get("ok").is_some(), "{name} of {text}: {lower}");
        assert_eq!(lower, &entry["json"][name], "{name} of {text}");
        assert_eq!(upper, &entry["json_upper"][name], "{name} of {text}, upper");
        assert_eq!(upper, lower, "{name}: upper case is written back lower");
        let written = lower["ok"].as_str().unwrap();
        assert!(
            written.contains(&text),
            "{name}: the text written carries the id"
        );
        assert!(!written.contains(&text.to_uppercase()));
    }
}

/// One reader or door on every cell: the answer (the text written back, or
/// the refusal's sentence) is the base's.
fn cells_of(section: &str, name: &str, now: fn(&str) -> Value) {
    let base = recorded();
    let recorded_cells = base["cells"].as_array().unwrap();
    let asked = cells();
    assert_eq!(recorded_cells.len(), asked.len());
    let (mut accepted, mut refused) = (0, 0);
    for ((cell, text), base) in asked.iter().zip(recorded_cells) {
        assert_eq!(base["cell"], *cell);
        assert_eq!(base["text"], *text);
        let answer = &now(text)[name];
        assert_eq!(answer, &base[section][name], "{name}, cell {cell:?}");
        if answer.get("ok").is_some() {
            accepted += 1;
        } else {
            assert!(answer["err"].is_string(), "{name}, cell {cell:?}");
            refused += 1;
        }
    }
    // Lower, upper, mixed and the null txid are read by every door (the
    // certificate's txid-alone form reads the null txid as no outpoint);
    // the cells that are no txid are refused by all but the trimming ones.
    assert!(accepted >= 4, "{name}: {accepted} accepted");
    assert!(refused >= 6, "{name}: {refused} refused");
}

macro_rules! json {
    ($($test:ident => $name:literal;)*) => { $(
        #[test]
        fn $test() { json_of($name); }
    )* };
}

macro_rules! readers {
    ($($test:ident => $name:literal;)*) => { $(
        #[test]
        fn $test() { cells_of("json", $name, json_cells); }
    )* };
}

macro_rules! doors {
    ($($test:ident => $name:literal;)*) => { $(
        #[test]
        fn $test() { cells_of("doors", $name, door_cells); }
    )* };
}

json! {
    an_outpoint_as_a_string_keeps_its_json_843w1 => "Outpoint (string)";
    an_outpoint_as_an_object_keeps_its_json_843w1 => "Outpoint (object)";
    create_action_options_known_txids_keep_their_json_843w1 => "CreateActionOptions.knownTxids";
    create_action_options_send_with_keeps_its_json_843w1 => "CreateActionOptions.sendWith";
    create_action_options_no_send_change_keeps_its_json_843w1 => "CreateActionOptions.noSendChange";
    send_with_result_txid_keeps_its_json_843w1 => "SendWithResult.txid";
    review_action_result_txid_keeps_its_json_843w1 => "ReviewActionResult.txid";
    review_action_result_competing_txs_keep_their_json_843w1 => "ReviewActionResult.competingTxs";
    create_action_result_txid_keeps_its_json_843w1 => "CreateActionResult.txid";
    create_action_result_no_send_change_keeps_its_json_843w1 => "CreateActionResult.noSendChange";
    wallet_action_txid_keeps_its_json_843w1 => "WalletAction.txid";
    sign_action_options_send_with_keeps_its_json_843w1 => "SignActionOptions.sendWith";
    sign_action_result_txid_keeps_its_json_843w1 => "SignActionResult.txid";
    create_action_input_outpoint_keeps_its_json_843w1 => "CreateActionInput.outpoint";
    the_wallet_certificates_revocation_outpoint_keeps_its_json_843w1 => "wallet Certificate.revocationOutpoint";
    wallet_action_input_source_outpoint_keeps_its_json_843w1 => "WalletActionInput.sourceOutpoint";
    wallet_output_outpoint_keeps_its_json_843w1 => "WalletOutput.outpoint";
    relinquish_output_args_output_keeps_its_json_843w1 => "RelinquishOutputArgs.output";
    the_auth_certificates_revocation_outpoint_keeps_its_json_843w1 => "auth Certificate.revocationOutpoint";
    the_auth_certificates_txid_alone_is_read_as_index_0_as_before_843w1 => "auth Certificate.revocationOutpoint (txid alone)";
    the_auth_certificates_outpoint_object_keeps_its_json_843w1 => "auth Certificate.revocationOutpoint (object)";
}

readers! {
    hex_txid_refuses_in_the_bases_sentences_on_send_with_result_843w1 => "hex_txid (SendWithResult.txid)";
    hex_txid_refuses_in_the_bases_sentences_on_wallet_action_843w1 => "hex_txid (WalletAction.txid)";
    hex_txid_refuses_in_the_bases_sentences_on_review_action_result_843w1 => "hex_txid (ReviewActionResult.txid)";
    hex_txid_vec_option_refuses_in_the_bases_sentences_on_known_txids_843w1 => "hex_txid_vec_option (knownTxids)";
    hex_txid_vec_option_refuses_in_the_bases_sentences_on_send_with_843w1 => "hex_txid_vec_option (sendWith)";
    hex_txid_vec_option_refuses_in_the_bases_sentences_on_competing_txs_843w1 => "hex_txid_vec_option (competingTxs)";
    hex_txid_option_refuses_in_the_bases_sentences_on_create_action_result_843w1 => "hex_txid_option (CreateActionResult.txid)";
    hex_txid_option_refuses_in_the_bases_sentences_on_sign_action_result_843w1 => "hex_txid_option (SignActionResult.txid)";
    an_outpoint_string_refuses_in_the_bases_sentences_843w1 => "Outpoint (string)";
    an_outpoint_object_refuses_in_the_bases_sentences_843w1 => "Outpoint (object)";
    an_outpoint_in_a_holder_refuses_in_the_bases_sentences_843w1 => "Outpoint in a holder (WalletOutput)";
    the_auth_certificates_outpoint_refuses_in_the_bases_sentences_843w1 => "auth Certificate.revocationOutpoint";
    the_auth_certificates_outpoint_object_refuses_in_the_bases_sentences_843w1 => "auth Certificate.revocationOutpoint (object)";
    the_wallet_certificates_outpoint_refuses_in_the_bases_sentences_843w1 => "wallet Certificate.revocationOutpoint";
}

doors! {
    outpoint_from_string_accepts_and_refuses_as_before_843w1 => "Outpoint::from_string";
    parse_wallet_outpoint_accepts_and_refuses_as_before_843w1 => "parse_wallet_outpoint";
    the_validated_known_txids_accept_and_refuse_as_before_843w1 => "validate_create_action_options (knownTxids)";
    the_validated_send_with_accepts_and_refuses_as_before_843w1 => "validate_create_action_options (sendWith)";
    the_validated_no_send_change_accepts_and_refuses_as_before_843w1 => "validate_create_action_options (noSendChange)";
    write_txid_hex_accepts_and_refuses_as_before_843w1 => "WireWriter::write_txid_hex";
    write_outpoint_string_accepts_and_refuses_as_before_843w1 => "WireWriter::write_outpoint_string";
}

/// The certificate's txid-alone form on the cells: only exactly 64 hex
/// digits read as a txid alone, the null txid as no outpoint.
#[test]
fn the_auth_certificates_txid_alone_reads_the_cells_as_before_843w1() {
    let base = recorded();
    let name = "auth Certificate.revocationOutpoint (txid alone)";
    for ((cell, text), base) in cells().iter().zip(base["cells"].as_array().unwrap()) {
        assert_eq!(
            &json_cells(text)[name],
            &base["json"][name],
            "cell {cell:?}"
        );
    }
}

/// The validators trim and lower-case before they judge, so a space-padded
/// txid is accepted there, as on the base, and refused by every other door.
#[test]
fn a_space_padded_txid_is_accepted_by_the_trimming_validators_alone_843w1() {
    let padded = cells()
        .into_iter()
        .find(|(cell, _)| *cell == "space-padded")
        .unwrap()
        .1;
    let (doors, readers) = (door_cells(&padded), json_cells(&padded));
    let good = padded.trim();
    for door in [
        "parse_wallet_outpoint",
        "validate_create_action_options (knownTxids)",
        "validate_create_action_options (sendWith)",
        "validate_create_action_options (noSendChange)",
    ] {
        let answer = doors[door]["ok"]
            .as_str()
            .unwrap_or_else(|| panic!("{door}: {}", doors[door]));
        // The validated change outpoints are shown as a string array's bytes.
        let as_bytes = hex::encode(format!("{good}.3"));
        assert!(
            answer.contains(good) || answer.contains(&as_bytes),
            "{door}: {answer}"
        );
    }
    for door in [
        "Outpoint::from_string",
        "WireWriter::write_txid_hex",
        "WireWriter::write_outpoint_string",
    ] {
        assert!(doors[door].get("err").is_some(), "{door}: {}", doors[door]);
    }
    for (reader, answer) in readers.as_object().unwrap() {
        assert!(answer.get("err").is_some(), "{reader}: {answer}");
    }
}
