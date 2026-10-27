//! A wallet's `WERR_REVIEW_ACTIONS` with the results it carries (#327).

use super::{Outpoint, ReviewActionResult, SendWithResult, TxId};

/// The reference's `WERR_REVIEW_ACTIONS` as an error with its evidence
/// (`ts-stack@edf6e03` `packages/sdk/src/wallet/WERR_REVIEW_ACTIONS.ts`):
/// an undelayed createAction or signAction whose results require review,
/// each result's status and, for a double spend, the competing
/// transactions' txids and BEEF. [`crate::Error::WalletReviewActions`]
/// carries it; the identity revocation's double-spend retry reads it as
/// `withDoubleSpendRetry` reads the reference's
/// (`overlay-tools/withDoubleSpendRetry.ts:64-99`). A refusal of the
/// `ReviewActions` class without results
/// ([`crate::Error::WalletRefusal`]) is never retried, as the reference
/// never retries a `WalletError` of code 5.
///
/// The reference's five members, in its names (#339): the results, then
/// the `createAction` or `signAction` result members the refusal carries
/// in their place (`sendWithResults`, `txid`, `tx`, `noSendChange`). The
/// HTTP JSON substrate reads all five from a wallet's code-5 body
/// (`HTTPWalletJSON.ts:199-241`); the binary wire carries the class and
/// its words alone, as the reference's does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewActionsRefusal {
    /// The wallet's words; the reference's are `Undelayed createAction or
    /// signAction results require review.`
    pub message: String,
    /// The results the wallet asks to be reviewed (`reviewActionResults`).
    pub review_action_results: Vec<ReviewActionResult>,
    /// The batch's send results (`sendWithResults`, #339).
    pub send_with_results: Vec<SendWithResult>,
    /// The transaction the action made, when the wallet names it (`txid`, #339).
    pub txid: Option<TxId>,
    /// Its atomic BEEF, when the wallet returns it (`tx`, #339).
    pub tx: Option<Vec<u8>>,
    /// A noSend createAction's change outpoints (`noSendChange`, #339).
    pub no_send_change: Option<Vec<Outpoint>>,
}

/// The reference's words (`WERR_REVIEW_ACTIONS.ts:24`).
const REVIEW_ACTIONS_WORDS: &str = "Undelayed createAction or signAction results require review.";

impl ReviewActionsRefusal {
    /// The reference's message with the results given, no send results
    /// and no transaction.
    #[must_use]
    pub fn new(review_action_results: Vec<ReviewActionResult>) -> Self {
        Self::with_members(review_action_results, Vec::new(), None, None, None)
    }

    /// The reference's constructor (`new WERR_REVIEW_ACTIONS(reviewActionResults,
    /// sendWithResults, txid, tx, noSendChange)`) and its message (#339).
    #[must_use]
    pub fn with_members(
        review_action_results: Vec<ReviewActionResult>,
        send_with_results: Vec<SendWithResult>,
        txid: Option<TxId>,
        tx: Option<Vec<u8>>,
        no_send_change: Option<Vec<Outpoint>>,
    ) -> Self {
        Self {
            message: REVIEW_ACTIONS_WORDS.to_string(),
            review_action_results,
            send_with_results,
            txid,
            tx,
            no_send_change,
        }
    }
}
