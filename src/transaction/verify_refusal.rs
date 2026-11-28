//! What `Transaction::verify` answers for an input's script evaluation that
//! ended in an `Err` (bsv-rs#38, ported to the stable line: the memory/decline
//! branch alone — this line has no work budget on `verify` and no
//! block-path consensus budget, so the 0.9 line's other arms do not travel).

use crate::script::ScriptEvaluationError;
use crate::Error;

/// A decline ([`ScriptEvaluationError::resource_limit`] `Some`: the evaluator
/// stopped at a local memory budget or the allocator and did not judge the
/// script) is [`Error::ScriptEvaluationDeclined`], its resource class kept, so a
/// caller tells "too expensive / out of memory" from "the peer's data is
/// invalid"; a verdict on the script stays `Error::TransactionError("Script
/// validation failed for input N: …")`, as before. Until bsv-rs#38 (ported
/// here) both were the latter, erasing the resource class the contract says is
/// never read as invalid.
pub(super) fn script_refusal(input_index: usize, error: ScriptEvaluationError) -> Error {
    match error.resource_limit {
        Some(limit) => Error::ScriptEvaluationDeclined { input_index, limit },
        None => Error::TransactionError(format!(
            "Script validation failed for input {}: {}",
            input_index, error.message
        )),
    }
}
