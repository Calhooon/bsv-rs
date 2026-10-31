//! Local work policy shared by whole-transaction and streaming verification.

use crate::script::NotJudgedCause;

/// Optional work bounds for each input and for each unproven transaction.
///
/// Both bounds default to `None`. Units are those of
/// [`crate::script::Spend::work_spent`]: reached opcodes and bytes hashed.
/// The transaction total is charged after each input, in input order. These
/// are local evaluator policies, never consensus rules or elapsed-time bounds.
///
/// Construct a policy with [`Self::new`] and its field setters; fields remain
/// readable, and destructuring outside this crate requires `..`.
///
/// ```compile_fail
/// let _ = bsv_rs::transaction::WorkBudget { per_input: None, per_transaction: None };
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkBudget {
    /// Maximum work charged within one input; `None` leaves it unbounded.
    pub per_input: Option<u64>,
    /// Maximum total work charged across one transaction's inputs.
    pub per_transaction: Option<u64>,
}

impl WorkBudget {
    /// Creates a local work policy with both bounds unbounded.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            per_input: None,
            per_transaction: None,
        }
    }

    /// Sets the local per-input work bound.
    #[must_use]
    pub const fn with_per_input(mut self, limit: Option<u64>) -> Self {
        self.per_input = limit;
        self
    }

    /// Sets the local work bound across each transaction's inputs.
    #[must_use]
    pub const fn with_per_transaction(mut self, limit: Option<u64>) -> Self {
        self.per_transaction = limit;
        self
    }

    pub(super) const NONE: Self = Self::new();

    // A transaction-only bound still needs the interpreter's existing counter.
    pub(super) fn input_limit(self) -> Option<u64> {
        self.per_input
            .or_else(|| self.per_transaction.map(|_| u64::MAX))
    }

    /// Charges one input's work to a transaction's running total: the
    /// per-transaction rule's one implementation (#567).
    ///
    /// `total` is the caller's running sum for one transaction, starting at
    /// zero; `input` is the input's index in that transaction; `work` is what
    /// the input spent, in [`crate::script::Spend::work_spent`]'s units. Call
    /// it once per judged input, after the input runs, in the transaction's
    /// input order. The work is added (saturating at `u64::MAX`) before the
    /// bound is read, so `total` holds the charged sum even on a refusal. A
    /// total above [`Self::per_transaction`], or a sum past `u64::MAX` under
    /// any bound, is [`NotJudgedCause::TransactionWorkBudgetExceeded`] naming
    /// this `input`, the `limit` and the `total`; with no transaction bound it
    /// always answers `Ok(())`.
    ///
    /// [`Self::per_input`] is not read here: an input over its own bound is
    /// refused by the interpreter while it runs
    /// ([`NotJudgedCause::WorkBudgetExceeded`]), before its work reaches the
    /// total. [`crate::transaction::Transaction::verify_with_work_budgets`] and
    /// both stream verifiers call this method, so a host that runs each input
    /// itself charges the same rule and answers the same cause.
    ///
    /// ```
    /// use bsv_rs::script::NotJudgedCause;
    /// use bsv_rs::transaction::WorkBudget;
    ///
    /// let budget = WorkBudget::new().with_per_transaction(Some(70));
    /// let mut total = 0;
    /// assert_eq!(budget.charge(&mut total, 0, 68), Ok(()));
    /// assert_eq!(
    ///     budget.charge(&mut total, 1, 6),
    ///     Err(NotJudgedCause::TransactionWorkBudgetExceeded { input: 1, limit: 70, total: 74 })
    /// );
    /// assert_eq!(total, 74);
    /// ```
    pub fn charge(self, total: &mut u64, input: u32, work: u64) -> Result<(), NotJudgedCause> {
        let next = total.checked_add(work);
        *total = next.unwrap_or(u64::MAX);
        if let Some(limit) = self.per_transaction {
            if next.is_none() || *total > limit {
                return Err(NotJudgedCause::TransactionWorkBudgetExceeded {
                    input,
                    limit,
                    total: *total,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transaction_total_cannot_wrap_back_inside_its_budget() {
        let policy = WorkBudget::default().with_per_transaction(Some(u64::MAX));
        let mut total = u64::MAX - 1;
        assert_eq!(policy.charge(&mut total, 0, 1), Ok(()));
        assert_eq!(
            policy.charge(&mut total, 1, 1),
            Err(NotJudgedCause::TransactionWorkBudgetExceeded {
                input: 1,
                limit: u64::MAX,
                total: u64::MAX,
            })
        );
    }

    #[test]
    fn a_per_input_bound_alone_never_refuses_through_charge_567() {
        let policy = WorkBudget::new().with_per_input(Some(1));
        let mut total = 0;
        assert_eq!(policy.charge(&mut total, 0, 68), Ok(()));
        assert_eq!(policy.charge(&mut total, 1, u64::MAX), Ok(()));
        assert_eq!(total, u64::MAX);
    }
}
