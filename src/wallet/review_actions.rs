//! A wallet's `WERR_REVIEW_ACTIONS` with the results it carries (#327).

use super::ReviewActionResult;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewActionsRefusal {
    /// The wallet's words; the reference's are `Undelayed createAction or
    /// signAction results require review.`
    pub message: String,
    /// The results the wallet asks to be reviewed (`reviewActionResults`).
    pub review_action_results: Vec<ReviewActionResult>,
}

impl ReviewActionsRefusal {
    /// The reference's message with the results given.
    pub fn new(review_action_results: Vec<ReviewActionResult>) -> Self {
        Self {
            message: "Undelayed createAction or signAction results require review.".to_string(),
            review_action_results,
        }
    }
}
