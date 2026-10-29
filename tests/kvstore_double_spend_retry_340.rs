//! #340: global wallet-evidence retry and local single-attempt mutations.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_retry_340.rs"]
mod support;
use bsv_rs::Error;
use std::sync::atomic::Ordering;
use support::{assert_attempts, review, setup};

async fn accepted(name: &str) {
    let h = setup(name);
    let result = h.run().await;
    assert!(
        result.is_ok(),
        "a double spend answered once must retry: {result:?}"
    );
    assert_attempts(&h, 2, 1);
    let sent = h.sent.lock().unwrap();
    assert_eq!(sent[0], h.case["competing"]["txid"]);
    assert_eq!(sent.len(), 2);
}

async fn exhausted(name: &str) {
    let h = setup(name);
    let result = h.run().await;
    assert_attempts(&h, 5, 5);
    assert_eq!(
        result,
        Err(review(&h.case)),
        "the final wallet error must be preserved"
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        h.case["review_error"]["message"]
    );
    assert_eq!(
        h.sent.lock().unwrap().as_slice(),
        vec![h.case["competing"]["txid"].as_str().unwrap(); 4]
    );
}

async fn local_single_attempt(name: &str) {
    let h = setup(name);
    let result = h.run().await;
    assert_attempts(&h, 1, 1);
    assert_eq!(h.case["create_actions"].as_array().unwrap().len(), 1);
    assert_eq!(h.case["abort_actions"].as_array().unwrap().len(), 1);
    assert_eq!(result.unwrap_err().to_string(), h.case["error"]["message"]);
    assert!(h.sent.lock().unwrap().is_empty());
    assert!(h.case["broadcasts"].as_array().unwrap().is_empty());
}

macro_rules! retry_case {
    ($name:ident, $run:ident, $case:literal) => {
        #[tokio::test]
        async fn $name() {
            $run($case).await;
        }
    };
}

retry_case!(
    global_set_retries_with_fresh_tokens_340,
    accepted,
    "global_set_once"
);
retry_case!(
    global_remove_retries_with_fresh_tokens_340,
    accepted,
    "global_remove_once"
);
retry_case!(
    local_set_does_not_retry_one_double_spend_340,
    local_single_attempt,
    "local_set_once"
);
retry_case!(
    local_remove_does_not_retry_one_double_spend_340,
    local_single_attempt,
    "local_remove_once"
);
retry_case!(
    global_set_stops_after_five_attempts_340,
    exhausted,
    "global_set_always"
);
retry_case!(
    global_remove_stops_after_five_attempts_340,
    exhausted,
    "global_remove_always"
);
retry_case!(
    local_set_does_not_retry_repeated_double_spends_340,
    local_single_attempt,
    "local_set_always"
);
retry_case!(
    local_remove_does_not_retry_repeated_double_spends_340,
    local_single_attempt,
    "local_remove_always"
);

#[tokio::test]
async fn double_spend_words_without_review_evidence_are_not_retried_340() {
    for name in [
        "global_set_once",
        "global_remove_once",
        "local_set_once",
        "local_remove_once",
    ] {
        let h = setup(name);
        let error = Error::WalletError("txn-mempool-conflict: double spend".into());
        *h.wallet.sign_answers.lock().unwrap() = [Err(error.clone())].into();
        assert_eq!(h.run().await, Err(local_error(&h, error)));
        assert_attempts(&h, 1, 1);
        assert!(h.sent.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn malformed_review_evidence_is_not_retried_340() {
    for name in [
        "global_set_once",
        "global_remove_once",
        "local_set_once",
        "local_remove_once",
    ] {
        let h = setup(name);
        let mut error = review(&h.case);
        if let Error::WalletReviewActions(review) = &mut error {
            review.review_action_results[0].competing_txs = None;
        }
        *h.wallet.sign_answers.lock().unwrap() = [Err(error.clone())].into();
        assert_eq!(h.run().await, Err(local_error(&h, error)));
        assert_attempts(&h, 1, 1);
        assert!(h.sent.lock().unwrap().is_empty());
    }
}

fn local_error(h: &support::Harness, error: Error) -> Error {
    if h.case["kind"] != "local" {
        return error;
    }
    let message = match error {
        Error::WalletError(message) => message,
        error => error.to_string(),
    };
    Error::KvStoreLocalError(format!(
        "There are 1 outputs with tag alpha that cannot be unlocked. Original error: {message}"
    ))
}

#[tokio::test]
async fn an_unacknowledged_competing_transaction_prevents_retry_340() {
    for name in ["global_set_once", "global_remove_once"] {
        let h = setup(name);
        h.fail.store(true, Ordering::SeqCst);
        let error = h.run().await.unwrap_err();
        let Error::KvStoreError(words) = error else {
            panic!("unexpected synchronization error: {error:?}")
        };
        assert!(
            words.starts_with("Failed to synchronize competing transaction: "),
            "{words}"
        );
        assert_attempts(&h, 1, 1);
        assert_eq!(h.sent.lock().unwrap().len(), 1);
    }
}
