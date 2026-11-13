//! #819: the wallet error family's enums keep the derives they ship with, so
//! a host may key a map by them; dropping `Hash` (or another value derive)
//! fails this file's build, and so does dropping `Error`, `Clone`, `Eq` or
//! `Debug` from the two structs. The enums' `#[non_exhaustive]` is pinned by
//! the doc tests `non_exhaustive_enum!` writes from each definition, the two
//! structs' by a functional-update `compile_fail` doc test beside each
//! (`src/error/wallet_fault.rs`, `src/error/wallet_refusal.rs`,
//! `src/util/non_exhaustive.rs`; `tests/arch_non_exhaustive_pins_819.rs`).
#![cfg(feature = "wallet")]

use bsv_rs::{AbortAcceptance, AbortKind, WalletFault, WalletFaultFamily, WalletRefusalClass};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

const KINDS: [AbortKind; 3] = [
    AbortKind::OnChain,
    AbortKind::AcceptedInStore,
    AbortKind::Other,
];

const FAMILIES: [WalletFaultFamily; 4] = [
    WalletFaultFamily::Transport,
    WalletFaultFamily::Service,
    WalletFaultFamily::Storage,
    WalletFaultFamily::Internal,
];

/// Each value a distinct entry, a repeated insert adding none, and a map
/// built from them answering each by its key.
fn hashes_as_it_compares<T: Copy + Eq + Hash + Debug>(values: &[T]) {
    let mut set: HashSet<T> = values.iter().copied().collect();
    assert_eq!(set.len(), values.len(), "{values:?}");
    for value in values {
        assert!(!set.insert(*value), "{value:?} was not held by the set");
    }
    assert_eq!(set.len(), values.len());
    let map: HashMap<T, usize> = values.iter().copied().zip(0..).collect();
    for (index, value) in values.iter().enumerate() {
        assert_eq!(map.get(value), Some(&index), "{value:?}");
    }
}

#[test]
fn the_abort_kind_hashes_as_it_compares_819() {
    hashes_as_it_compares(&KINDS);
    let names: HashMap<AbortKind, &str> = KINDS
        .into_iter()
        .zip(["on chain", "accepted in store", "other"])
        .collect();
    assert_eq!(names[&AbortKind::OnChain], "on chain");
    assert_eq!(names[&AbortKind::AcceptedInStore], "accepted in store");
    assert_eq!(names[&AbortKind::Other], "other");
    assert_eq!(names[&AbortKind::default()], "other");
}

#[test]
fn the_wallet_fault_family_hashes_as_it_compares_819() {
    hashes_as_it_compares(&FAMILIES);
}

#[test]
fn the_wallet_refusal_class_hashes_as_it_compares_819() {
    let sdk: Vec<WalletRefusalClass> = (2..=8)
        .map(|code| WalletRefusalClass::from_code(code).expect("an SDK code"))
        .collect();
    assert_eq!(sdk.len(), 7);
    hashes_as_it_compares(&sdk);
    hashes_as_it_compares(&WalletRefusalClass::ALL);
}

/// `ALL` holds twenty classes, each once, each found again by its name. That
/// `ALL` holds every class of the enum is the in-crate test's
/// (`all_holds_every_variant_once_in_the_definitions_order_819`,
/// `src/error/wallet_refusal.rs`).
#[test]
fn the_wallet_refusal_classes_are_twenty_each_once_and_found_by_name_819() {
    assert_eq!(WalletRefusalClass::ALL.len(), 20);
    let distinct: HashSet<WalletRefusalClass> = WalletRefusalClass::ALL.into_iter().collect();
    assert_eq!(distinct.len(), 20);
    for class in WalletRefusalClass::ALL {
        assert_eq!(WalletRefusalClass::from_name(class.name()), Some(class));
    }
}

fn held<T: Copy + Eq + Hash + Default + Debug>() -> T {
    T::default()
}

fn held_without_default<T: Copy + Eq + Hash + Debug>(value: T) -> T {
    value
}

#[test]
fn the_three_enums_keep_their_value_derives_819() {
    assert_eq!(held::<AbortKind>(), AbortKind::Other);
    assert_eq!(
        held_without_default(WalletFaultFamily::Storage),
        WalletFaultFamily::Storage
    );
    assert_eq!(
        held_without_default(WalletRefusalClass::AbortRefused),
        WalletRefusalClass::AbortRefused
    );
}

fn an_error_value<T: std::error::Error + Clone + Eq + Debug>(value: T) -> T {
    let copy = value.clone();
    assert_eq!(copy, value);
    assert!(!format!("{value:?}").is_empty());
    let as_error: &dyn std::error::Error = &value;
    assert!(as_error.source().is_none());
    copy
}

#[test]
fn the_two_structs_are_errors_and_keep_their_value_derives_819() {
    let fault = an_error_value(WalletFault::new(WalletFaultFamily::Storage, "disk"));
    assert_eq!(fault.to_string(), "disk");
    let record = an_error_value(AbortAcceptance::new(
        "ref",
        WalletRefusalClass::InvalidOperation,
        "refused",
    ));
    assert_eq!(record.to_string(), "refused");
}
