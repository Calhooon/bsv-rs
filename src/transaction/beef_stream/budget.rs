//! The caller's two LOCAL budgets for an unproven transaction's scripts
//! (bsv-rs#373): the work bound per input (`set_work_limit`) and the memory
//! budget per input's stacks (`set_memory_limit`), the third parameter of
//! `Transaction::verify` (bsv-rs#331) on the stream.
//!
//! Neither is reader state: both are absent from the [`Cursor`](super::Cursor)
//! and are set again after `resume`, a decoded cursor's included. Neither
//! bounds the reader: the reader's own bound per element is the charter's
//! structural guarantee (a valid BEEF is never refused for its size or its
//! counts, NL-3), not a cap on a script. Exhausted work is
//! [`Verdict::NotJudged`](super::Verdict::NotJudged) with
//! [`crate::script::NotJudgedCause::WorkBudgetExceeded`]; exhausted memory is
//! [`SpendRefusal::Resource`](super::SpendRefusal::Resource). Neither judges
//! the script; the structure-only reader runs no script and spends none.

use std::io::Read;

use super::{AsyncStreamVerifier, Headers, StreamVerifier};

impl<R: Read, H: Headers> StreamVerifier<R, H> {
    /// Sets the local work bound per input using `SpendParams::work_limit` accounting.
    ///
    /// Exhaustion is `Verdict::NotJudged` with
    /// `NotJudgedCause::WorkBudgetExceeded`, naming the input, work already
    /// charged and budget. `None` is the default, matching the reference's
    /// `verify`, which has no work bound. This is a service door's policy,
    /// not an elapsed-time bound. This configuration is not cursor state:
    /// reapply it after `resume`, including a decoded cursor.
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.evaluation.work = limit;
    }

    /// Configures an optional local work budget per input before verification.
    ///
    /// As [`Self::set_work_limit`]: the existing `SpendParams::work_limit`
    /// accounting, `None` by default, with no work bound in the reference's
    /// `verify`. Combine with `with_chain_params` for a live service door,
    /// and reapply after `resume`; no budget is stored in the cursor.
    #[must_use]
    pub fn with_work_budget(mut self, limit: Option<u64>) -> Self {
        self.set_work_limit(limit);
        self
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
    /// As [`StreamVerifier::set_memory_limit`].
    pub fn set_memory_limit(&mut self, limit: Option<usize>) {
        self.evaluation.memory = limit;
    }

    /// As [`StreamVerifier::set_work_limit`].
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.evaluation.work = limit;
    }
}
