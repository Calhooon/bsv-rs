//! `WalletRefusalClass::ALL` and `Kind::ALL` are slices (#843dall, the freeze
//! plan's Q4): `&'static [Self]`, so a variant added to either
//! `#[non_exhaustive]` enum changes no public type. Until #843dall they were
//! `[Self; 20]` and `[Kind; 26]`, and each variant added changed the
//! constant's type (`Kind::ALL` was `[Kind; 18]` at v0.4.0, 19 at v0.4.1, 20
//! at v0.4.3, 24 from v0.5.0, 25 at v0.9.0-beta.1 and 26 since beta.2).
//!
//! The typed bindings are the witness: on the base each is E0308 (an array is
//! no `&'static [T]`), so this file does not compile there. The entries and
//! their order are unchanged, pinned here by name; that each table holds
//! every variant of its definition is the in-crate tests'
//! (`all_holds_every_variant_once_in_the_definitions_order_819`, #819).
#![cfg(feature = "wallet")]

use std::collections::HashSet;

use bsv_rs::transaction::beef_stream::Kind;
use bsv_rs::WalletRefusalClass;

#[test]
fn wallet_refusal_class_all_is_a_static_slice_of_its_twenty_each_once_843dall() {
    let all: &'static [WalletRefusalClass] = WalletRefusalClass::ALL;
    let names: Vec<String> = all.iter().map(|class| format!("{class:?}")).collect();
    assert_eq!(
        names,
        [
            "UnsupportedAction",
            "InvalidHmac",
            "InvalidSignature",
            "ReviewActions",
            "InvalidParameter",
            "InsufficientFunds",
            "AbortRefused",
            "NotImplemented",
            "Internal",
            "InvalidOperation",
            "UtxoReviewInconclusive",
            "ActionBatchState",
            "BroadcastUnavailable",
            "InvalidMerkleRoot",
            "MissingParameter",
            "BadRequest",
            "NetworkChain",
            "Unauthorized",
            "NotActive",
            "InvalidPublicKey",
        ]
    );
    let distinct: HashSet<WalletRefusalClass> = all.iter().copied().collect();
    assert_eq!(distinct.len(), 20);
}

#[test]
fn kind_all_is_a_static_slice_of_its_twenty_six_each_once_843dall() {
    let all: &'static [Kind] = Kind::ALL;
    let names: Vec<String> = all.iter().map(|kind| format!("{kind:?}")).collect();
    assert_eq!(
        names,
        [
            "BadVersion",
            "BadVarint",
            "Truncated",
            "BadFlag",
            "TreeHeightOver64",
            "TreeHeightZero",
            "OffsetOutsideTree",
            "NoTxidAtLevelZero",
            "MissingSibling",
            "MismatchedNode",
            "DuplicateOffset",
            "LeftDuplicateBelow",
            "RootNotCarried",
            "BumpIndexNamesNoBump",
            "TxidNotInBump",
            "InputNamesNoElement",
            "StubNotProven",
            "TrailingBytes",
            "SubjectMissing",
            "UnrelatedTransaction",
            "NoInputs",
            "NoOutputs",
            "UnprovenCoinbase",
            "NullOutpoint",
            "DuplicateInput",
            "ValueOutOfRange",
        ]
    );
    let distinct: HashSet<Kind> = all.iter().copied().collect();
    assert_eq!(distinct.len(), 26);
}

/// The Migration lines of the CHANGELOG entry, each compiled: the forms a
/// caller of the array is moved to.
#[test]
fn the_migration_forms_compile_and_agree_843dall() {
    let mut by_pattern = Vec::new();
    for &class in WalletRefusalClass::ALL {
        by_pattern.push(class);
    }
    let mut by_copied = Vec::new();
    for class in WalletRefusalClass::ALL.iter().copied() {
        by_copied.push(class);
    }
    assert_eq!(by_pattern, by_copied);
    assert_eq!(by_pattern.len(), WalletRefusalClass::ALL.len());
    fn takes(kinds: &[Kind]) -> usize {
        kinds.len()
    }
    assert_eq!(takes(Kind::ALL), 26);
    assert_eq!(Kind::ALL[0], Kind::BadVersion);
    assert!(matches!(
        Kind::ALL,
        [Kind::BadVersion, .., Kind::ValueOutOfRange]
    ));
}
