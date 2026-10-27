//! What `Transaction::verify` answers for an input's script evaluation that
//! ended in an `Err` (bsv-rs#38).

use crate::script::ScriptEvaluationError;
use crate::Error;

/// A decline ([`ScriptEvaluationError::resource_limit`] `Some`: the evaluator
/// stopped at a local budget and did not judge the script) is
/// [`Error::ScriptEvaluationDeclined`], its class kept, as the reference's
/// `Transaction.verify` lets `Spend`'s `ScriptResourceLimitError` propagate
/// apart from its `ScriptEvaluationError` (`ts-stack@edf6e03`
/// `packages/sdk/src/transaction/Transaction.ts:1441-1458`,
/// `packages/sdk/src/script/Spend.ts:2020-2021`); a verdict on the script is
/// `TransactionError("Script validation failed for input N: …")`, as before.
/// Until bsv-rs#38 both were the latter.
pub(super) fn script_refusal(input_index: usize, error: ScriptEvaluationError) -> Error {
    match error.resource_limit {
        Some(limit) => Error::ScriptEvaluationDeclined { input_index, limit },
        None => Error::TransactionError(format!(
            "Script validation failed for input {}: {}",
            input_index, error.message
        )),
    }
}
