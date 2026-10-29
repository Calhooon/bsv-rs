//! The reference's `withDoubleSpendRetry` (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/withDoubleSpendRetry.ts`; #327), the rule
//! shared by identity revocation and both key-value stores: an attempt that fails with a
//! wallet's `WERR_REVIEW_ACTIONS` carrying double-spend evidence
//! ([`Error::WalletReviewActions`]) is repeated, at most five attempts in
//! all, after every competing transaction it names is read from its BEEF,
//! bound to its txid and acknowledged by the topic broadcaster; any other
//! failure, malformed evidence or a failed acknowledgement ends the spend.
//!
//! [`crate::overlay::with_double_spend_retry`] is another rule: it repeats
//! on any error whose words name a double spend, synchronizes nothing and
//! makes four attempts by default.

use crate::overlay::TopicBroadcaster;
use crate::primitives::to_hex;
use crate::transaction::Transaction;
use crate::wallet::ReviewActionResultStatus;
use crate::{Error, Result};
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

/// `MAX_DOUBLE_SPEND_RETRIES` (`withDoubleSpendRetry.ts:8`): attempts in all.
const MAX_DOUBLE_SPEND_RETRIES: u32 = 5;
/// `MAX_REVIEW_RESULTS` (`:10`).
const MAX_REVIEW_RESULTS: usize = 256;
/// `MAX_COMPETING_TRANSACTIONS` (`:11`), per result and across them.
const MAX_COMPETING_TRANSACTIONS: usize = 256;
/// `MAX_COMPETING_BEEF_BYTES` (`:12`), per result and across them.
const MAX_COMPETING_BEEF_BYTES: usize = 64 * 1024 * 1024;

/// One double-spend result's competing BEEF and txids (`DoubleSpendEvidence`, `:15-18`).
struct Evidence<'a> {
    beef: &'a [u8],
    txids: Vec<String>,
}

/// `extractDoubleSpendEvidence` (`:64-99`): the double-spend results of a
/// `WERR_REVIEW_ACTIONS`, each with its BEEF (1 byte to 64 MiB) and txids
/// (1 to 256, none repeated), at most 256 results, 64 MiB and 256 distinct
/// txids across them; `None` (no retry) for any other error, a malformed
/// double-spend result, or none.
fn evidence(error: &Error) -> Option<Vec<Evidence<'_>>> {
    let Error::WalletReviewActions(review) = error else {
        return None;
    };
    if review.review_action_results.len() > MAX_REVIEW_RESULTS {
        return None;
    }
    let (mut evidence, mut bytes, mut all) = (Vec::new(), 0usize, HashSet::new());
    for result in &review.review_action_results {
        if result.status != ReviewActionResultStatus::DoubleSpend {
            continue;
        }
        let beef = result.competing_beef.as_deref()?;
        let txids = result.competing_txs.as_deref()?;
        if beef.is_empty() || beef.len() > MAX_COMPETING_BEEF_BYTES {
            return None;
        }
        if txids.is_empty() || txids.len() > MAX_COMPETING_TRANSACTIONS {
            return None;
        }
        let txids: Vec<String> = txids.iter().map(|t| to_hex(t)).collect();
        if txids.iter().collect::<HashSet<_>>().len() != txids.len() {
            return None;
        }
        bytes += beef.len();
        all.extend(txids.iter().cloned());
        if bytes > MAX_COMPETING_BEEF_BYTES || all.len() > MAX_COMPETING_TRANSACTIONS {
            return None;
        }
        evidence.push(Evidence { beef, txids });
    }
    (!evidence.is_empty()).then_some(evidence)
}

/// `synchronizeCompetingTransactions` (`:101-128`): each competing txid
/// once, its transaction read from the BEEF by txid, broadcast, and the
/// broadcaster's success for that txid required.
async fn synchronize(
    evidence: &[Evidence<'_>],
    broadcaster: &TopicBroadcaster,
    refused: fn(String) -> Error,
) -> Result<()> {
    let mut synchronized = HashSet::new();
    for item in evidence {
        for txid in &item.txids {
            if synchronized.contains(txid) {
                continue;
            }
            let competing = Transaction::from_beef(item.beef, Some(txid)).map_err(|_| {
                refused("Wallet returned malformed competing transaction evidence.".into())
            })?;
            if competing.id() != *txid {
                return Err(refused(
                    "Wallet competing transaction evidence does not match its transaction ID."
                        .into(),
                ));
            }
            let failure = match broadcaster.broadcast_tx(&competing).await {
                Ok(success) if success.txid.eq_ignore_ascii_case(txid) => None,
                Ok(_) => Some((
                    "ERR_INVALID_RESPONSE".to_string(),
                    "Broadcaster returned a malformed or transaction-mismatched response."
                        .to_string(),
                )),
                Err(failure) => Some((failure.code, failure.description)),
            };
            if let Some((code, description)) = failure {
                return Err(refused(format!(
                    "Failed to synchronize competing transaction: {code}: {description}"
                )));
            }
            synchronized.insert(txid.clone());
        }
    }
    Ok(())
}

/// `withDoubleSpendRetry(operation, broadcaster)` (`:140-165`) at its
/// default of five attempts: the last attempt's failure, or any failure
/// without double-spend evidence, is the answer as it came. The broadcaster
/// is obtained only when synchronization is needed. `refused` retains the
/// caller's error category for synchronization failures; it never changes a
/// wallet error. The operation owns any abort and must repeat its lookup.
pub(crate) async fn with_wallet_double_spend_retry<T, F, Fut, B>(
    mut operation: F,
    broadcaster: B,
    refused: fn(String) -> Error,
) -> Result<T>
where
    B: Fn() -> Result<Arc<TopicBroadcaster>>,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 1;
    loop {
        let error = match operation().await {
            Ok(answer) => return Ok(answer),
            Err(error) => error,
        };
        if attempt == MAX_DOUBLE_SPEND_RETRIES {
            return Err(error);
        }
        let Some(evidence) = evidence(&error) else {
            return Err(error);
        };
        let broadcaster = broadcaster()?;
        synchronize(&evidence, &broadcaster, refused).await?;
        attempt += 1;
    }
}

#[cfg(test)]
#[path = "wallet_retry_tests.rs"]
mod tests;
