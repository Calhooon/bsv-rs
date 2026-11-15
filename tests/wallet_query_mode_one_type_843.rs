//! One `QueryMode` in the wallet (#843, the duplicate wallet types; the
//! captain's ruling of 2026-11-15): `wallet::validation::QueryMode` is
//! `wallet::types::QueryMode`, re-exported, so `validate_query_mode`'s answer
//! goes into a wallet argument with no conversion. Until this lane
//! `validation.rs` declared a second enum of the same two variants, which no
//! other code named, and each test below failed to compile (E0308). The
//! validator's verdicts and words are unchanged and pinned beside them.
#![cfg(feature = "wallet")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use bsv_rs::wallet::validation::{validate_query_mode, ValidListActionsArgs, ValidListOutputsArgs};
use bsv_rs::wallet::{ListActionsArgs, ListOutputsArgs};
use bsv_rs::Error;

/// Compiles only where both arguments are one type.
fn one_type<T>(_: &T, _: &T) {}

#[test]
fn validate_query_modes_answer_goes_into_a_wallet_argument_843() {
    let mode = validate_query_mode(Some("all"), "tagQueryMode").unwrap();
    let outputs = ListOutputsArgs {
        basket: "tokens".to_string(),
        tags: None,
        tag_query_mode: Some(mode),
        include: None,
        include_custom_instructions: None,
        include_tags: None,
        include_labels: None,
        limit: None,
        offset: None,
        seek_permission: None,
    };
    assert_eq!(outputs.tag_query_mode, Some(bsv_rs::wallet::QueryMode::All));

    let mode = validate_query_mode(None, "labelQueryMode").unwrap();
    let actions = ListActionsArgs {
        labels: Vec::new(),
        label_query_mode: Some(mode),
        include_labels: None,
        include_inputs: None,
        include_input_source_locking_scripts: None,
        include_input_unlocking_scripts: None,
        include_outputs: None,
        include_output_locking_scripts: None,
        limit: None,
        offset: None,
        seek_permission: None,
    };
    assert_eq!(
        actions.label_query_mode,
        Some(bsv_rs::wallet::types::QueryMode::Any)
    );
}

#[test]
fn the_validation_path_and_the_types_path_name_one_query_mode_843() {
    one_type(
        &bsv_rs::wallet::validation::QueryMode::Any,
        &bsv_rs::wallet::types::QueryMode::Any,
    );
    one_type(
        &bsv_rs::wallet::validation::QueryMode::All,
        &bsv_rs::wallet::QueryMode::All,
    );
    let at_validation: bsv_rs::wallet::validation::QueryMode = bsv_rs::wallet::QueryMode::All;
    assert_eq!(at_validation, bsv_rs::wallet::types::QueryMode::All);

    // What the type at the `validation` path has since it is the `types` one.
    assert_eq!(
        bsv_rs::wallet::validation::QueryMode::default(),
        bsv_rs::wallet::validation::QueryMode::Any
    );
    assert_eq!(bsv_rs::wallet::validation::QueryMode::All.as_str(), "all");
    assert_eq!(
        serde_json::to_string(&validate_query_mode(Some("all"), "tagQueryMode").unwrap()).unwrap(),
        "\"all\""
    );
    let mut set = std::collections::HashSet::new();
    set.insert(bsv_rs::wallet::validation::QueryMode::Any);
    assert!(set.contains(&bsv_rs::wallet::types::QueryMode::Any));
}

#[test]
fn the_validated_argument_records_hold_the_wallets_query_mode_843() {
    fn tag_mode(valid: &ValidListOutputsArgs) -> bsv_rs::wallet::types::QueryMode {
        valid.tag_query_mode
    }
    fn label_mode(valid: &ValidListActionsArgs) -> bsv_rs::wallet::types::QueryMode {
        valid.label_query_mode
    }
    // The two readers are the witness: they compile only with one type.
    let _ = (tag_mode, label_mode);
}

#[test]
fn validate_query_mode_keeps_its_verdicts_and_words_843() {
    use bsv_rs::wallet::QueryMode;
    assert_eq!(validate_query_mode(None, "m").unwrap(), QueryMode::Any);
    assert_eq!(
        validate_query_mode(Some("any"), "m").unwrap(),
        QueryMode::Any
    );
    assert_eq!(
        validate_query_mode(Some("all"), "m").unwrap(),
        QueryMode::All
    );
    for refused in ["", "ALL", "Any", " all", "both"] {
        assert_eq!(
            validate_query_mode(Some(refused), "tagQueryMode"),
            Err(Error::WalletError(format!(
                "Invalid tagQueryMode: must be 'any' or 'all', got '{refused}'"
            )))
        );
    }
}
