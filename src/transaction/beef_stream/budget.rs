//! The caller's LOCAL budgets for an unproven transaction's scripts:
//! work per input and per transaction (bsv-rs#519), and memory per input's
//! stacks (`set_memory_limit`, bsv-rs#373), the third parameter of
//! `Transaction::verify` (bsv-rs#331) on the stream.
//!
//! Limits are absent from the [`Cursor`](super::Cursor) and set again after
//! `resume`, a decoded cursor's included. Charged work is cursor state. None
//! bounds the reader: the reader's own bound per element is the charter's
//! structural guarantee (a valid BEEF is never refused for its size or its
//! counts, NL-3), not a cap on a script. Exhausted work is
//! [`Verdict::NotJudged`](super::Verdict::NotJudged) with
//! [`crate::script::NotJudgedCause::WorkBudgetExceeded`]; exhausted memory is
//! [`SpendRefusal::Resource`](super::SpendRefusal::Resource). Neither judges
//! the script; the structure-only reader runs no script and spends none.

use std::io::Read;

use super::{AsyncStreamVerifier, Headers, StreamVerifier};

/// Accounting state, unlike the local limits, survives a cursor round trip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WorkSpent {
    pub(super) txid: Option<super::Hash32>,
    pub(super) total: u64,
}

impl WorkSpent {
    pub(super) fn start(&mut self, txid: super::Hash32, from: u32, metered: bool) -> u32 {
        if from == 0 || (metered && self.txid != Some(txid)) {
            *self = Self {
                txid: metered.then_some(txid),
                total: 0,
            };
            // An old or unmetered cursor has no saved charges: replay its prefix.
            return 0;
        }
        from
    }
}

impl super::Verdict {
    /// The transaction's total when its work budget stopped verification.
    ///
    /// Returns the `total` from `TransactionWorkBudgetExceeded`. Other
    /// verdicts carry no transaction-work measurement and return `None`;
    /// [`StreamVerifier::work_spent`] also exposes the total on successful runs.
    pub fn work_spent(&self) -> Option<u64> {
        match self {
            Self::NotJudged {
                cause: crate::script::NotJudgedCause::TransactionWorkBudgetExceeded { total, .. },
                ..
            } => Some(*total),
            _ => None,
        }
    }
}

impl<R: Read, H: Headers> StreamVerifier<R, H> {
    /// Sets the local work bound per input using `SpendParams::work_limit` accounting.
    ///
    /// Exhaustion is `Verdict::NotJudged` with
    /// `NotJudgedCause::WorkBudgetExceeded`, naming the input, work already
    /// charged and budget. `None` is the default, matching the reference's
    /// `verify`, which has no work bound. This is a service door's policy,
    /// not an elapsed-time bound. This configuration is not cursor state:
    /// reapply it after `resume`, including a decoded cursor.
    ///
    /// `with_work_budget` and `set_work_limit` write the same per-input work limit:
    /// whichever is called last wins.
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.evaluation.work.per_input = limit;
    }

    /// Configures an optional local work budget per input before verification.
    ///
    /// As [`Self::set_work_limit`]: the existing `SpendParams::work_limit`
    /// accounting, `None` by default, with no work bound in the reference's
    /// `verify`. Combine with `with_chain_params` for a live service door,
    /// and reapply after `resume`; no budget is stored in the cursor.
    ///
    /// `with_work_budget` and `set_work_limit` write the same per-input work limit:
    /// whichever is called last wins.
    #[must_use]
    pub fn with_work_budget(mut self, limit: Option<u64>) -> Self {
        self.set_work_limit(limit);
        self
    }

    /// Configures a local work bound across each unproven transaction's inputs.
    ///
    /// Each input's charged work is added in verification order. A total above
    /// `limit` returns `Verdict::NotJudged` with
    /// `NotJudgedCause::TransactionWorkBudgetExceeded { input, limit, total }`.
    /// `None` (the default) leaves this bound off. The per-input budget is
    /// independent. Reapply both policies after resuming a cursor; recorded
    /// work survives a pause, but the policies are not cursor state.
    #[must_use]
    pub fn with_transaction_work_budget(mut self, limit: Option<u64>) -> Self {
        self.evaluation.work.per_transaction = limit;
        self
    }

    /// Work charged in the current or most recently evaluated transaction.
    ///
    /// Includes the crossing input or work charged before an input refusal.
    /// Zero until an input runs with either work bound configured. The total
    /// resets for each unproven transaction, including a deferred one.
    pub fn work_spent(&self) -> u64 {
        self.judge.index.script_work.total
    }

    /// Sets the LOCAL memory budget per input, in bytes per stack, as
    /// `Transaction::verify`'s `memory_limit` (bsv-rs#331, #373): `None`, the
    /// default, uncapped; `Some(n)` stops an input whose stacks would pass
    /// `n` bytes before the allocation, a decline,
    /// `Verdict::SpendRefused { txid, input, why: SpendRefusal::Resource(limit) }`
    /// naming the transaction, the input and the figures, never a verdict on
    /// the script. Not cursor state: reapply it after `resume`.
    pub fn set_memory_limit(&mut self, limit: Option<usize>) {
        self.evaluation.memory = limit;
    }
}

impl AsyncStreamVerifier {
    /// Configures an optional local work budget per input before verification.
    ///
    /// As [`StreamVerifier::with_work_budget`]; reapply after `resume` and
    /// set before feeding any transaction.
    #[must_use]
    pub fn with_work_budget(mut self, limit: Option<u64>) -> Self {
        self.set_work_limit(limit);
        self
    }

    /// As [`StreamVerifier::with_transaction_work_budget`].
    #[must_use]
    pub fn with_transaction_work_budget(mut self, limit: Option<u64>) -> Self {
        self.evaluation.work.per_transaction = limit;
        self
    }

    /// As [`StreamVerifier::work_spent`].
    pub fn work_spent(&self) -> u64 {
        self.judge.index.script_work.total
    }

    /// As [`StreamVerifier::set_memory_limit`].
    pub fn set_memory_limit(&mut self, limit: Option<usize>) {
        self.evaluation.memory = limit;
    }

    /// As [`StreamVerifier::set_work_limit`].
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.evaluation.work.per_input = limit;
    }
}
