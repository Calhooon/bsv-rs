//! #908, line 2: four public types keep the value derives they ship with, so
//! a dependent may key a map or a set by them. `TransportFault`,
//! `InputVerified`, `HmacKeyEncoding` and `HmacVerifyPolicy` each derive
//! `Hash` beside `Eq` and `Copy`, and until this file no test named the
//! bound: `Hash` dropped from one derive passed every test, and a dependent
//! keying a map by the type stopped compiling. Dropping `Hash`, `Eq`, `Copy`
//! or `Debug` from one of the four now fails this file's build, as
//! `tests/wallet_fault_shapes_819.rs` holds the wallet error family.
//!
//! `InputVerified` has no public constructor (`#[non_exhaustive]`, built by
//! the one-input door alone), so its bound is the compiler's and its values
//! come from the door.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: fixture assertions.

use bsv_rs::script::UnlockingScript;
use bsv_rs::transaction::{verify_input, InputRules, InputVerified, Transaction, TransactionInput};
use bsv_rs::wallet::{HmacKeyEncoding, HmacVerifyPolicy};
use bsv_rs::TransportFault;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

/// The bound a dependent's `HashMap<T, _>` or `HashSet<T>` needs, held by the
/// compiler for the type named at the call.
fn keys_a_map<T: Copy + Eq + Hash + Debug>() {}

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
fn the_four_types_keep_the_bound_a_map_key_needs_908() {
    keys_a_map::<TransportFault>();
    keys_a_map::<InputVerified>();
    keys_a_map::<HmacKeyEncoding>();
    keys_a_map::<HmacVerifyPolicy>();
}

#[test]
fn a_transport_fault_hashes_as_it_compares_908() {
    hashes_as_it_compares(&[
        TransportFault::NeverSent,
        TransportFault::MayHaveBeenReceived,
        TransportFault::RateLimited {
            retry_after_ms: None,
        },
        TransportFault::RateLimited {
            retry_after_ms: Some(0),
        },
        TransportFault::RateLimited {
            retry_after_ms: Some(1_500),
        },
    ]);
}

#[test]
fn an_hmac_key_encoding_hashes_as_it_compares_908() {
    hashes_as_it_compares(&[
        HmacKeyEncoding::MinimalLength,
        HmacKeyEncoding::Legacy {
            leading_zero_bytes: 1,
        },
        HmacKeyEncoding::Legacy {
            leading_zero_bytes: 2,
        },
    ]);
}

#[test]
fn an_hmac_verify_policy_hashes_as_it_compares_908() {
    hashes_as_it_compares(&[
        HmacVerifyPolicy::BothEncodings,
        HmacVerifyPolicy::MinimalLengthOnly,
    ]);
    let names: HashMap<HmacVerifyPolicy, &str> = HashMap::from([
        (HmacVerifyPolicy::BothEncodings, "both"),
        (HmacVerifyPolicy::MinimalLengthOnly, "minimal"),
    ]);
    assert_eq!(names[&HmacVerifyPolicy::default()], "both");
}

/// One spend of an output, judged by the one-input door: the only way a
/// caller holds an `InputVerified`. The spending transaction is one input of
/// the zero outpoint with an empty unlocking script, no output, lock time 0.
fn verified(locking_script: &[u8]) -> InputVerified {
    let mut input = TransactionInput::new("00".repeat(32).parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_binary(&[]).unwrap());
    let spending = Transaction::with_params(2, vec![input], vec![], 0).to_binary();
    verify_input(
        locking_script,
        1,
        &spending,
        0,
        &InputRules::reference_default(),
    )
    .expect("the locking script leaves a true value")
}

#[test]
fn an_input_verified_hashes_as_it_compares_908() {
    let one = verified(&[0x51]);
    let again = verified(&[0x51]);
    let longer = verified(&[0x61, 0x51]);
    assert_eq!(one, again);
    assert_ne!(one.work_spent, longer.work_spent);
    hashes_as_it_compares(&[one, longer]);
    let by_verdict: HashMap<InputVerified, &str> =
        HashMap::from([(one, "OP_1"), (longer, "OP_NOP OP_1")]);
    assert_eq!(by_verdict[&again], "OP_1");
}
