//! The shared rule's classification tests, independent of an identity client.
use super::*;
use crate::overlay::{LookupResolver, LookupResolverConfig};
use crate::wallet::{ReviewActionResult, ReviewActionsRefusal};

fn review() -> Error {
    Error::WalletReviewActions(Box::new(ReviewActionsRefusal::new(vec![
        ReviewActionResult {
            txid: [0x22; 32],
            status: ReviewActionResultStatus::DoubleSpend,
            competing_txs: Some(vec![[0x33; 32]]),
            competing_beef: Some(vec![1]),
        },
    ])))
}

#[test]
fn only_structured_double_spend_evidence_qualifies_for_retry() {
    assert!(evidence(&review()).is_some());
    assert!(evidence(&Error::WalletError("double spend".into())).is_none());
    let Error::WalletReviewActions(mut error) = review() else {
        unreachable!()
    };
    error.review_action_results[0].status = ReviewActionResultStatus::Success;
    assert!(evidence(&Error::WalletReviewActions(error)).is_none());
}

#[test]
fn absent_empty_or_duplicate_competing_evidence_is_not_retried() {
    let Error::WalletReviewActions(error) = review() else {
        unreachable!()
    };
    for (txids, beef) in [
        (None, Some(vec![1])),
        (Some(vec![]), Some(vec![1])),
        (Some(vec![[0x33; 32]; 2]), Some(vec![1])),
        (Some(vec![[0x33; 32]]), None),
        (Some(vec![[0x33; 32]]), Some(vec![])),
    ] {
        let mut error = error.clone();
        error.review_action_results[0].competing_txs = txids;
        error.review_action_results[0].competing_beef = beef;
        assert!(evidence(&Error::WalletReviewActions(error)).is_none());
    }
}

#[test]
fn review_result_and_competing_transaction_counts_are_bounded() {
    let Error::WalletReviewActions(mut error) = review() else {
        unreachable!()
    };
    error.review_action_results = vec![error.review_action_results[0].clone(); 257];
    assert!(evidence(&Error::WalletReviewActions(error.clone())).is_none());
    error.review_action_results.truncate(256);
    assert!(evidence(&Error::WalletReviewActions(error.clone())).is_some());
    error.review_action_results.truncate(1);
    error.review_action_results[0].competing_txs = Some(vec![[0x33; 32]; 257]);
    assert!(evidence(&Error::WalletReviewActions(error)).is_none());
}

#[tokio::test]
async fn success_and_unrelated_errors_never_request_a_broadcaster() {
    let result = with_wallet_double_spend_retry(
        || async { Ok(42) },
        || panic!("successful operation must not synchronize"),
        Error::OverlayError,
    )
    .await;
    assert_eq!(result, Ok(42));
    let error = Error::WalletError("double spend".into());
    let result = with_wallet_double_spend_retry(
        || async { Err::<(), _>(error.clone()) },
        || panic!("unstructured error must not synchronize"),
        Error::OverlayError,
    )
    .await;
    assert_eq!(result, Err(error));
}

#[tokio::test]
async fn malformed_competing_beef_keeps_the_callers_error_category() {
    let result = with_wallet_double_spend_retry(
        || async { Err::<(), _>(review()) },
        || {
            // No host or tracker exists even if malformed evidence reached discovery.
            let resolver = LookupResolver::new(LookupResolverConfig {
                host_overrides: Some([("ls_ship".into(), vec![])].into()),
                slap_trackers: Some(vec![]),
                ..Default::default()
            });
            TopicBroadcaster::new(
                vec!["tm_test".into()],
                crate::overlay::TopicBroadcasterConfig {
                    resolver: Some(Arc::new(resolver)),
                    ..Default::default()
                },
            )
            .map(Arc::new)
        },
        Error::OverlayError,
    )
    .await;
    assert_eq!(
        result,
        Err(Error::OverlayError(
            "Wallet returned malformed competing transaction evidence.".into()
        ))
    );
}
