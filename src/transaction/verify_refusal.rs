//! What `Transaction::verify` answers for an input's script evaluation that
//! ended in an `Err` (bsv-rs#38).

use crate::script::{NotJudgedCause, ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::Error;

/// A decline ([`ScriptEvaluationError::resource_limit`] `Some`: the evaluator
/// stopped at a local budget and did not judge the script) is
/// [`Error::ScriptEvaluationDeclined`], its class kept, as the reference's
/// `Transaction.verify` lets `Spend`'s `ScriptResourceLimitError` propagate
/// apart from its `ScriptEvaluationError` (`ts-stack@edf6e03`
/// `packages/sdk/src/transaction/Transaction.ts:1441-1458`,
/// `packages/sdk/src/script/Spend.ts:2020-2021`); a verdict on the script is
/// `TransactionError("Script validation failed for input N: …")`, as before.
/// Until bsv-rs#38 both were the latter. Work exhaustion instead uses
/// `TransactionNotJudged` with `WorkBudgetExceeded` (#378); the memory class
/// and the interpreter's own errors are unchanged.
pub(super) fn script_refusal(
    txid: &str,
    input_index: usize,
    error: ScriptEvaluationError,
) -> Error {
    if let Some(cause) = error
        .resource_limit
        .and_then(|limit| work_budget_cause(input_index as u32, limit))
    {
        return Error::TransactionNotJudged {
            txid: txid.to_owned(),
            input_index,
            cause,
        };
    }
    match error.resource_limit {
        Some(limit) => Error::ScriptEvaluationDeclined { input_index, limit },
        None => Error::TransactionError(format!(
            "Script validation failed for input {}: {}",
            input_index, error.message
        )),
    }
}

/// Both verification paths translate the same interpreter charge into #452's class.
pub(super) fn work_budget_cause(input: u32, limit: ScriptResourceLimit) -> Option<NotJudgedCause> {
    match limit {
        ScriptResourceLimit {
            resource: ScriptResource::Work,
            limit: budget,
            work_spent: Some(work_done),
            ..
        } => Some(NotJudgedCause::WorkBudgetExceeded {
            input,
            budget,
            work_done,
        }),
        _ => None,
    }
}
