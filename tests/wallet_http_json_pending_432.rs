//! #432: one regression per Pending inventory row, using reference-recorded words.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

#[path = "support/http_json_cases.rs"]
mod cases;
#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use bsv_rs::{wallet::substrates::HttpWalletJson, Error};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn check(row: usize) {
    let cases: Vec<_> = cases::cases()
        .into_iter()
        .filter(|c| c.group == format!("row_{row}"))
        .collect();
    assert!(
        !cases.is_empty(),
        "inventory row {row} has no recorded case"
    );
    let server = MockServer::start().await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    let mut mismatches = Vec::new();
    for c in &cases {
        server.reset().await;
        let mut response = ResponseTemplate::new(c.status.unwrap_or(200))
            .set_body_raw(c.body(), "application/json");
        for (name, value) in c.headers.iter().flatten() {
            response = response.insert_header(name.as_str(), value.as_str());
        }
        Mock::given(method("POST"))
            .and(path(format!("/{}", c.call)))
            .respond_with(response)
            .mount(&server)
            .await;
        let override_wallet = c.headers.as_ref().map(|_| {
            let client = reqwest::Client::builder()
                .http2_prior_knowledge()
                .build()
                .unwrap();
            HttpWalletJson::with_client(client, Some("fixtures.invalid".into()), Some(server.uri()))
                .unwrap()
        });
        let ours = cases::invoke(override_wallet.as_ref().unwrap_or(&wallet), c).await;
        let matches = if let Some(residue) = &c.residue {
            assert!(!residue.is_empty());
            c.reference["accepted"] == true
                && matches!(&ours, Err(Error::WalletError(words)) if
                if c.call == "getVersion" {
                    words == "Invalid getVersion result version: expected a string"
                } else {
                    words.contains("invalid value")
                })
        } else {
            match &ours {
                Ok(()) => c.reference["accepted"] == true,
                Err(Error::WalletError(words)) => {
                    c.reference["error"].as_str() == Some(words.as_str())
                }
                _ => false,
            }
        };
        if !matches {
            mismatches.push(format!("{}: {ours:?}; reference {}", c.name, c.reference));
        }
    }
    assert!(
        mismatches.is_empty(),
        "row {row}: {} cases\n{}",
        cases.len(),
        mismatches.join("\n")
    );
}

macro_rules! row {
    ($name:ident, $number:literal) => {
        #[tokio::test]
        async fn $name() {
            check($number).await;
        }
    };
}

row!(row_03_global_bounds_and_keys, 3);
row!(row_06_aborted_boolean, 6);
row!(row_07_accepted_verdict, 7);
row!(row_08_relinquished_verdict, 8);
row!(row_09_valid_verdict, 9);
row!(row_10_authenticated_verdict, 10);
row!(row_11_public_key, 11);
row!(row_15_linkage_keys, 15);
row!(row_17_linkage_time, 17);
row!(row_18_linkage_request, 18);
row!(row_19_specific_scalars, 19);
row!(row_20_specific_parties, 20);
row!(row_21_specific_protocol, 21);
row!(row_22_height_without_truncation, 22);
row!(row_23_header, 23);
row!(row_24_network, 24);
row!(row_25_version, 25);
row!(row_26_action_txid, 26);
row!(row_28_action_beef, 28);
row!(row_29_change_outpoints, 29);
row!(row_30_batch_results, 30);
row!(row_32_signable_reference, 32);
row!(row_33_deferred_or_completed, 33);
row!(row_34_signed_txid_required, 34);
row!(row_35_request_beef_evidence, 35);
row!(row_36_version_and_lock_time, 36);
row!(row_37_unique_transaction_inputs, 37);
row!(row_38_requested_inputs, 38);
row!(row_39_requested_outputs, 39);
row!(row_40_source_values, 40);
row!(row_41_conservation, 41);
row!(row_42_requested_spends, 42);
row!(row_43_change_subject, 43);
row!(row_44_submitted_batch, 44);
row!(row_45_evidence_required, 45);
row!(row_46_action_outcome, 46);
row!(row_47_safe_totals, 47);
row!(row_49_page_limits, 49);
row!(row_50_action_scalars, 50);
row!(row_51_history_descriptions, 51);
row!(row_52_label_filter, 52);
row!(row_53_history_version, 53);
row!(row_54_requested_history_inputs, 54);
row!(row_55_history_source, 55);
row!(row_56_history_scripts, 56);
row!(row_57_history_sequence, 57);
row!(row_58_requested_history_outputs, 58);
row!(row_59_history_output_value, 59);
row!(row_60_history_output_metadata, 60);
row!(row_61_absent_tags_and_bounds, 61);
row!(row_62_output_beef, 62);
row!(row_63_required_output_beef, 63);
row!(row_64_unique_outputs, 64);
row!(row_65_output_scalars, 65);
row!(row_66_output_commitments, 66);
row!(row_67_output_metadata, 67);
row!(row_68_output_filter, 68);
row!(row_73_certificate_unsafe_fields, 73);
row!(row_76_certificate_filter, 76);
row!(row_77_certificate_keyring, 77);
row!(row_78_certificate_verifier, 78);
row!(row_79_certifier_metadata, 79);
row!(row_80_discovery_maps, 80);
row!(row_81_any_attributes, 81);
row!(row_82_named_attributes, 82);
row!(row_83_acquired_certificate, 83);
row!(row_84_partial_certificate, 84);
row!(row_85_proof_keyring, 85);
row!(row_86_revealed_field_set, 86);
row!(row_87_proof_verifier, 87);
row!(row_88_request_snapshot, 88);
