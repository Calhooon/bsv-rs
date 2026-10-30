//! #423: payment action, labels, known ancestors, refusal words and retry budget.
#![cfg(all(feature = "auth", feature = "http", feature = "wallet"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.
#[path = "support/auth_fetch_423/mod.rs"]
mod support;
use support::{words, Environment};

#[tokio::test]
async fn a_402_creates_a_labeled_payment_and_retries_with_its_bytes_423() {
    let env = Environment::new("payment").await;
    let response = env.fetch().await.unwrap();
    env.assert_response(&response);
    env.assert_frames();
    let actions = env.actions.lock().unwrap();
    assert_eq!(actions.len(), 1);
    let action = &actions[0];
    assert_eq!(
        action["description"],
        format!("Payment for request to {}", env.mock.uri())
    );
    assert_eq!(action["options"], env.row["actions"][0]["options"]);
    assert_eq!(action["outputs"][0]["satoshis"], 7);
    assert_eq!(
        action["outputs"][0]["outputDescription"],
        "HTTP request payment"
    );
    assert_eq!(action["labels"][1], "app:test");
    let instructions: serde_json::Value =
        serde_json::from_str(action["outputs"][0]["customInstructions"].as_str().unwrap()).unwrap();
    let prefix = instructions["derivationPrefix"].as_str().unwrap();
    let suffix = instructions["derivationSuffix"].as_str().unwrap();
    assert_eq!(
        *env.payment_keys.lock().unwrap(),
        [format!("{prefix} {suffix}")]
    );
    assert_eq!(
        action["labels"][0],
        format!(
            "brc105 {} {}",
            hex::encode(bsv_rs::primitives::from_base64(prefix).unwrap()),
            hex::encode(bsv_rs::primitives::from_base64(suffix).unwrap())
        )
    );
    assert_eq!(
        instructions["payee"],
        env.row["actions"][0]["outputs"][0]["customInstructions"]
            .as_str()
            .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap()["payee"].clone())
            .unwrap()
    );
    let mut expected = env.row["actions"][0].clone();
    let original: serde_json::Value = serde_json::from_str(
        expected["outputs"][0]["customInstructions"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let old_suffix = original["derivationSuffix"].as_str().unwrap();
    expected["outputs"][0]["customInstructions"] = expected["outputs"][0]["customInstructions"]
        .as_str()
        .unwrap()
        .replace(old_suffix, suffix)
        .into();
    expected["labels"] = action["labels"].clone();
    expected["description"] = action["description"].clone();
    assert_eq!(
        *action, expected,
        "complete action with the recorded wallet-derived public key"
    );
}

#[tokio::test]
async fn exhausted_fetch_counter_cannot_dispatch_a_paid_retry_423() {
    let env = Environment::new("payment_exhausted").await;
    let expected = env.row["error"]
        .as_str()
        .unwrap()
        .replace("https://auth-fetch-423.invalid", &env.mock.uri());
    assert_eq!(words(env.fetch().await), expected);
    assert_eq!(
        env.actions.lock().unwrap().len(),
        1,
        "reuse the same payment for all three failures"
    );
    env.assert_frames();
    assert_eq!(env.mock.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn malformed_payment_headers_keep_each_reference_text_423() {
    for name in [
        "payment_bad_version",
        "payment_bad_amount",
        "payment_bad_prefix",
    ] {
        let env = Environment::new(name).await;
        assert_eq!(words(env.fetch().await), env.row["error"]);
        assert!(env.actions.lock().unwrap().is_empty());
        env.assert_frames();
    }
}

#[tokio::test]
async fn repeated_402_reuses_the_action_and_stops_after_three_paid_attempts_423() {
    let env = Environment::new("payment_always").await;
    let expected = env.row["error"]
        .as_str()
        .unwrap()
        .replace("https://auth-fetch-423.invalid", &env.mock.uri());
    assert_eq!(words(env.fetch().await), expected);
    assert_eq!(env.actions.lock().unwrap().len(), 1);
    assert_eq!(env.mock.received_requests().await.unwrap().len(), 5);
    env.assert_frames();
}

#[tokio::test]
async fn paid_backoff_shares_the_decremented_fetch_counter_423() {
    let env = Environment::new("payment_network").await;
    let expected = env.row["error"]
        .as_str()
        .unwrap()
        .replace("https://auth-fetch-423.invalid", &env.mock.uri());
    assert_eq!(words(env.fetch().await), expected);
    assert_eq!(
        env.mock.received_requests().await.unwrap().len(),
        env.row["requests"].as_array().unwrap().len()
    );
    assert_eq!(env.actions.lock().unwrap().len(), 1);
    env.assert_frames();
}
