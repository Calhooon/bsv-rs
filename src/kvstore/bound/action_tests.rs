//! Recording-wallet check of unused signer coverage.
#![cfg(test)]
use super::*;

fn words(mode: &str) -> String {
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/kvstore_bound_action_341_342.json"
    ))
    .unwrap();
    recorded["refusals"][mode]["error"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn an_unused_input_signer_is_refused_in_the_recorded_words_341() {
    let wallet = crate::kvstore::local::tests::MockWallet::new();
    let args = CreateActionArgs {
        description: "Empty request".into(),
        inputs: None,
        outputs: None,
        input_beef: None,
        lock_time: None,
        version: None,
        labels: None,
        options: None,
    };
    let signers = [(Outpoint::new([2; 32], 0), InputSigner::Bytes(vec![]))].into();
    assert_eq!(
        complete_with_signers(&wallet, args, signers, None)
            .await
            .unwrap_err(),
        refusal(words("unused_signer"))
    );
    assert_eq!(
        *wallet.events.lock().unwrap(),
        ["createAction", "abortAction"]
    );
}
