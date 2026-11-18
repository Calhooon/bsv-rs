//! #843: the local store carries the wallet's 64-bit `totalOutputs` without
//! narrowing it: `count` answers a total past `2^32 - 1` (an error where the
//! target's `usize` cannot hold it, never a truncation), and a listing whose
//! total is past the store's 10,000 is refused whatever its low 32 bits are.
//!
//! The listings are read from JSON, so the file compiles against the `u32`
//! field too and its failures there are runs, not builds.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
use bsv_rs::wallet::ListOutputsResult;
use bsv_rs::Error;
use identity_reveal_wallet::Counting;

fn listing(total: u64) -> ListOutputsResult {
    serde_json::from_str(&format!(r#"{{"totalOutputs":{total},"outputs":[]}}"#)).unwrap()
}

fn store(total: u64) -> LocalKVStore<Counting> {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(listing(total));
    LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap()
}

#[tokio::test]
async fn count_answers_a_wallet_total_past_two_to_the_32_843() {
    for total in [0u64, 7, u64::from(u32::MAX), (1 << 32) + 7, 1 << 53] {
        let counted = store(total).count().await;
        match usize::try_from(total) {
            Ok(expected) => assert_eq!(counted.unwrap(), expected, "{total}"),
            Err(_) => assert_eq!(
                counted.unwrap_err(),
                Error::KvStoreLocalError(format!(
                    "Wallet totalOutputs {total} exceeds the platform"
                )),
            ),
        }
    }
}

#[tokio::test]
async fn a_listing_total_past_two_to_the_32_is_refused_not_read_by_its_low_bits_843() {
    // 2^32 and 2^32 + 1 narrow to 0 and 1, totals the store accepts.
    for total in [1u64 << 32, (1 << 32) + 1, u64::MAX] {
        let refusal = store(total).remove("alpha", None).await.unwrap_err();
        assert_eq!(
            refusal,
            Error::KvStoreLocalError("Wallet returned an invalid KVStore output list".into()),
            "{total}"
        );
    }
}

/// A listing at the store's 10,000 passes the list check, as the reference's
/// `> MAX_LOCAL_OUTPUTS` lets it (`LocalKVStore.ts:193-198` at `ts-stack@edf6e03`,
/// `:200-201` at `11faa7d16`), and reaches the check after it; one past it is
/// refused at the list check. The total and the page each at the edge.
#[tokio::test]
async fn a_listing_at_the_stores_ten_thousand_passes_the_list_check_843() {
    let invalid = Error::KvStoreLocalError("Wallet returned an invalid KVStore output list".into());
    // A total of 10,000 and an empty page: the #479 refusal after the check.
    assert_eq!(
        store(10_000).remove("alpha", None).await.unwrap_err(),
        Error::KvStoreLocalError(
            "Wallet returned an inconsistent KVStore output list: totalOutputs is 10000, but page at offset 0 is empty for key alpha"
                .into()
        ),
    );
    assert_eq!(
        store(10_001).remove("alpha", None).await.unwrap_err(),
        invalid
    );
    // A page of 10,000 outputs with no BEEF: the BEEF's refusal after the check.
    for (length, words) in [
        (10_000usize, "Wallet KVStore BEEF is invalid"),
        (10_001, "Wallet returned an invalid KVStore output list"),
    ] {
        let outputs: Vec<String> = (0..length)
            .map(|i| {
                format!(
                    r#"{{"outpoint":"{}.{i}","satoshis":1,"spendable":true}}"#,
                    "ab".repeat(32)
                )
            })
            .collect();
        let text = format!(
            r#"{{"totalOutputs":{length},"outputs":[{}]}}"#,
            outputs.join(",")
        );
        let wallet = Counting::of_scalar(9);
        *wallet.listed.lock().unwrap() = Some(serde_json::from_str(&text).unwrap());
        let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();
        assert_eq!(
            store.remove("alpha", None).await.unwrap_err(),
            Error::KvStoreLocalError(words.into()),
            "{length}"
        );
    }
}
