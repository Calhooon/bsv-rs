//! #603: two crate-contract pins of `raw_tree.rs`, no reference recording
//! (an HTTP body cannot reach the copied-byte pin, `HTTPWalletJSON.ts:59`'s 256 MiB body
//! cap at two characters a byte; the second is this file's own contract).
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

use super::*;

fn raw(text: &str) -> &RawValue {
    serde_json::from_str(text).unwrap()
}

// Crate contract: `src/wallet/substrates/CLAUDE.md` R03, "total copied bytes
// 256 MiB", the reference's aggregate at `WalletResultValidation.ts:726-736`
// for a dense array, as here (`:689-692` for the historical object;
// `ts-stack@edf6e03`): the sum of the byte arrays copied is judged, a sum
// equal to the bound admitted and one past it refused.
#[test]
fn the_copied_byte_budget_is_judged_on_the_sum_crate_contract_pin_603() {
    let body = raw("[0,0]");
    let snapshot = Snapshot::read(body, "getHeight").unwrap();
    let mut at = Walk {
        copied: MAX_BYTES - 2,
        ..Walk::default()
    };
    assert_eq!(snapshot.visit(0, false, "getHeight", &mut at), Ok(()));
    assert_eq!(at.copied, MAX_BYTES);
    let mut past = Walk {
        copied: MAX_BYTES - 1,
        ..Walk::default()
    };
    assert_eq!(
        snapshot.visit(0, false, "getHeight", &mut past),
        Err(invalid(
            "getHeight",
            "byte arrays",
            &format!("at most {MAX_BYTES} total bytes")
        ))
    );
}

// Crate contract: `raw_tree.rs:294-295`, "Normalize only token spellings and
// historical bytes. Ignored values stay raw": the signable reference's token
// is re-encoded, and a token of the same length elsewhere is kept.
#[cfg(feature = "http")]
#[test]
fn only_the_reference_token_is_replaced_crate_contract_pin_603() {
    let body = raw(r#"{"signableTransaction":{"reference":"AR=="},"a":"abcd"}"#);
    let normalized = Snapshot::read(body, "createAction").unwrap().normalized();
    assert_eq!(
        normalized,
        r#"{"signableTransaction":{"reference":"AQ=="},"a":"abcd"}"#
    );
}
