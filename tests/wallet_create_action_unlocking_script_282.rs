//! The createAction argument gate on an input's unlocking script (#282):
//! `validate_create_action_args` refuses an empty `unlockingScript` as the
//! reference's `validateOptionalHexString` does (`ts-stack@edf6e03`
//! `validationHelpers.ts:595`, `:522-530`), in its words and class, and an
//! `unlockingScriptLength` of 0 as BRC-100's positive integer (`brcs@5119a9b`
//! `wallet/0100.md:649`), which the reference's helper permits (`:598`).
//!
//! The witnesses are `tests/vectors/wallet_create_action_unlocking_script_282.json`;
//! each carries the reference's verdict and words, recorded by
//! `tests/support/create_action_unlocking_script_282.mjs` under Node v22.18.0.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "wallet")]

use bsv_rs::wallet::validation::{
    validate_create_action_args, CreateActionArgsRaw, CreateActionInputRaw,
};
use bsv_rs::{Error, WalletRefusalClass};
use serde::Deserialize;

#[derive(Deserialize)]
struct Witnesses {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    unlocking_script: Option<String>,
    unlocking_script_length: Option<u32>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    input: Input,
    reference_accepted: bool,
    reference_error: Option<String>,
    reference_code: Option<u8>,
    reference_message: Option<String>,
}

fn witnesses() -> Vec<Witness> {
    let data =
        std::fs::read_to_string("tests/vectors/wallet_create_action_unlocking_script_282.json")
            .expect("read the #282 witnesses");
    let file: Witnesses = serde_json::from_str(&data).expect("parse the #282 witnesses");
    file.witnesses
}

fn validate(input: &Input) -> bsv_rs::Result<()> {
    validate_create_action_args(&CreateActionArgsRaw {
        description: "pay the invoice".to_string(),
        input_beef: None,
        inputs: vec![CreateActionInputRaw {
            outpoint: format!("{}.0", "11".repeat(32)),
            input_description: "spend the coin".to_string(),
            unlocking_script: input.unlocking_script.clone(),
            unlocking_script_length: input.unlocking_script_length,
            sequence_number: None,
        }],
        outputs: vec![],
        lock_time: None,
        version: None,
        labels: vec![],
        options: None,
    })
    .map(|_| ())
}

#[test]
fn an_empty_unlocking_script_is_refused_in_the_reference_words_and_class() {
    let mut refused = 0;
    for w in witnesses().iter().filter(|w| !w.reference_accepted) {
        let err = validate(&w.input).expect_err(&w.name);
        let Error::WalletRefusal { class, message } = err else {
            panic!("{}: not a wallet refusal: {err:?}", w.name);
        };
        assert_eq!(
            Some(class.name()),
            w.reference_error.as_deref(),
            "{}",
            w.name
        );
        assert_eq!(class.code(), w.reference_code, "{}", w.name);
        assert_eq!(Some(message), w.reference_message.clone(), "{}", w.name);
        refused += 1;
    }
    assert_eq!(refused, 2, "the two empty-script witnesses");
}

#[test]
fn a_zero_unlocking_script_length_the_reference_accepts_is_refused_as_brc100_positive_integer() {
    let w = witnesses()
        .into_iter()
        .find(|w| w.name == "zero_unlocking_script_length")
        .expect("the zero-length witness");
    assert!(w.reference_accepted, "the reference's helper permits 0");
    assert_eq!(
        validate(&w.input).unwrap_err(),
        Error::WalletRefusal {
            class: WalletRefusalClass::InvalidParameter,
            message: "Invalid createAction input unlockingScriptLength: expected an integer \
                      from 1 to 4294967295, received 0"
                .to_string(),
        }
    );
}

#[test]
fn a_one_byte_unlocking_script_and_a_length_of_one_are_accepted_as_the_reference_accepts_them() {
    for name in ["one_byte_unlocking_script", "unlocking_script_length_one"] {
        let w = witnesses()
            .into_iter()
            .find(|w| w.name == name)
            .expect(name);
        assert!(w.reference_accepted, "{name}");
        validate(&w.input).expect(name);
    }
}
