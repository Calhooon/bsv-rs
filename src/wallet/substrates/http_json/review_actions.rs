//! A wallet's code-5 body read as the reference's `HTTPWalletJSON` reads it
//! (#339; `ts-stack@edf6e03` `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:117-241`):
//! the envelope, the message, the call, the four action-result members
//! through `validateWalletResult`'s action checks
//! (`WalletResultValidation.ts:1242-1374`, under `returnTXIDOnly: true`),
//! then `reviewActionResults`, each refusal in the reference's words, the
//! five members carried by [`ReviewActionsRefusal`].
//!
//! #432 applies the shared result validator to these four members before the
//! error envelope is decoded, including transaction evidence and request binding.

use super::byte_fields::byte_array;
use crate::primitives::{from_hex, to_hex};
use crate::transaction::Beef;
use crate::wallet::{
    CreateActionArgs, Outpoint, ReviewActionResult, ReviewActionResultStatus, ReviewActionsRefusal,
    SendWithResult, SendWithResultStatus, SignActionArgs, TxId,
};
use crate::Error;
use serde_json::{Map, Value};
use std::collections::HashSet;

/// `MAXIMUM_SEND_WITH_TRANSACTIONS` (`validationHelpers.ts:69`).
const MAXIMUM_SEND_WITH_TRANSACTIONS: usize = 1000;
/// `requireErrorString`'s default bound (`HTTPWalletJSON.ts:117`).
const MAX_ERROR_STRING_BYTES: usize = 4096;

/// The call and submitted txids used to bind review outcomes. Transaction
/// validation uses the complete request captured by the common result path.
pub(super) struct ReviewRequest {
    call: &'static str,
    send_with: Vec<TxId>,
}

impl ReviewRequest {
    pub(super) fn create_action(args: &CreateActionArgs) -> Self {
        Self {
            call: "createAction",
            send_with: args
                .options
                .as_ref()
                .and_then(|o| o.send_with.clone())
                .unwrap_or_default(),
        }
    }

    pub(super) fn sign_action(args: &SignActionArgs) -> Self {
        Self {
            call: "signAction",
            send_with: args
                .options
                .as_ref()
                .and_then(|o| o.send_with.clone())
                .unwrap_or_default(),
        }
    }
}

/// The reference's plain `Error` with its words.
fn refused(words: impl Into<String>) -> Error {
    Error::WalletError(words.into())
}

/// `invalid(call, field, expectation)` (`WalletResultValidation.ts:510-512`).
fn invalid(call: &str, field: &str, expectation: impl std::fmt::Display) -> Error {
    refused(format!(
        "Invalid {call} result {field}: expected {expectation}"
    ))
}

/// The body this reader answers: a 400's object with an own `isError`, a
/// code of 5 and `reviewActionResults` present. Any other (a refusal of the
/// class without results among them) is the class reading's (#137).
pub(super) fn is_review_body(status: u16, body: &Value) -> bool {
    let Some(data) = body.as_object() else {
        return false;
    };
    status == 400
        && data.contains_key("isError")
        && data.get("code").and_then(Value::as_f64) == Some(5.0)
        && data.contains_key("reviewActionResults")
}

/// `deserializeWalletError` (`HTTPWalletJSON.ts:199-241`) for code 5:
/// `call` the method answered, `request` its binding when it is
/// createAction or signAction.
pub(super) fn read(
    body: &Value,
    call: &str,
    request: Option<&ReviewRequest>,
    binding: &Value,
) -> Error {
    match read_members(body, call, request, binding) {
        Ok(refusal) => Error::WalletReviewActions(Box::new(refusal)),
        Err(error) => error,
    }
}

fn read_members(
    body: &Value,
    call: &str,
    request: Option<&ReviewRequest>,
    binding: &Value,
) -> Result<ReviewActionsRefusal, Error> {
    let data = (body.as_object()).ok_or_else(|| refused("Invalid wallet error envelope"))?;
    if data.get("isError") != Some(&Value::Bool(true)) || !safe_integer(data.get("code")) {
        return Err(refused("Invalid wallet error envelope"));
    }
    if let Some(message) = data.get("message") {
        match message.as_str() {
            Some(m) if m.len() <= MAX_ERROR_STRING_BYTES => {}
            _ => return Err(refused("Invalid wallet error message")),
        }
    }
    let Some(request) = request else {
        return Err(refused(format!("Invalid {call} wallet error code")));
    };
    if !matches!(data.get("sendWithResults"), Some(Value::Array(_))) {
        return Err(refused("Invalid wallet error sendWithResults"));
    }
    super::result_values::review(data, call, binding)?;
    let action = action_result(data, request)?;
    let mut allowed: HashSet<String> = request.send_with.iter().map(|t| to_hex(t)).collect();
    allowed.extend(action.txid.map(|t| to_hex(&t)));
    let results = review_action_results(data.get("reviewActionResults"), &allowed)?;
    Ok(ReviewActionsRefusal::with_members(
        results,
        action.send_with_results,
        action.txid,
        action.tx,
        action.no_send_change,
    ))
}

/// `Number.isSafeInteger`.
fn safe_integer(value: Option<&Value>) -> bool {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    value
        .and_then(Value::as_f64)
        .is_some_and(|n| n.fract() == 0.0 && n.abs() <= MAX_SAFE)
}

struct ActionMembers {
    txid: Option<TxId>,
    tx: Option<Vec<u8>>,
    no_send_change: Option<Vec<Outpoint>>,
    send_with_results: Vec<SendWithResult>,
}

/// `string(value, call, field)` then `hex(.., 32)` (`WalletResultValidation.ts:908-925`).
fn hex32(value: &Value, call: &str, field: &str) -> Result<TxId, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(call, field, "a string"))?;
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(call, field, "an even-length hex string"));
    }
    if text.len() != 64 {
        return Err(invalid(call, field, "32 hexadecimal bytes"));
    }
    txid_of(text).ok_or_else(|| invalid(call, field, "32 hexadecimal bytes"))
}

fn txid_of(text: &str) -> Option<TxId> {
    from_hex(text).ok()?.try_into().ok()
}

/// `optionalArray` (`WalletResultValidation.ts:971-976`).
fn optional_array<'a>(
    value: Option<&'a Value>,
    call: &str,
    field: &str,
) -> Result<Option<&'a Vec<Value>>, Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .ok_or_else(|| invalid(call, field, "an array"))?;
    if items.len() > 100_000 {
        return Err(invalid(call, field, "at most 100000 entries"));
    }
    Ok(Some(items))
}

/// `requireOutpoint` (`WalletResultValidation.ts:1430-1441`).
fn outpoint(value: &Value, call: &str, field: &str) -> Result<Outpoint, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(call, field, "a string"))?;
    let canonical = || invalid(call, field, "a canonical transaction outpoint");
    let (txid, index) = text.split_once('.').ok_or_else(canonical)?;
    let digits = index.bytes().all(|b| b.is_ascii_digit());
    if txid.len() != 64
        || !txid.bytes().all(|b| b.is_ascii_hexdigit())
        || index.is_empty()
        || !digits
        || (index.len() > 1 && index.starts_with('0'))
    {
        return Err(canonical());
    }
    let vout = index.parse::<u32>().map_err(|_| canonical())?;
    Ok(Outpoint {
        txid: txid_of(txid).ok_or_else(canonical)?,
        vout,
    })
}

/// Decode the four members after the common result validator has checked
/// their structure, transaction framing, source values and request binding.
fn action_result(
    data: &Map<String, Value>,
    request: &ReviewRequest,
) -> Result<ActionMembers, Error> {
    let call = request.call;
    let txid = data
        .get("txid")
        .map(|v| hex32(v, call, "txid"))
        .transpose()?;
    let tx = data
        .get("tx")
        .map(|value| byte_array(value).ok_or_else(|| invalid(call, "tx", "an array of bytes")))
        .transpose()?;
    let no_send_change = match optional_array(data.get("noSendChange"), call, "noSendChange")? {
        None => None,
        Some(items) => Some(
            items
                .iter()
                .enumerate()
                .map(|(i, v)| outpoint(v, call, &format!("noSendChange[{i}]")))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    Ok(ActionMembers {
        txid,
        tx,
        no_send_change,
        send_with_results: send_with_results(data.get("sendWithResults"), call)?,
    })
}

/// `validateSendWithResults` (`WalletResultValidation.ts:1013-1031`).
fn send_with_results(value: Option<&Value>, call: &str) -> Result<Vec<SendWithResult>, Error> {
    let Some(items) = optional_array(value, call, "sendWithResults")? else {
        return Ok(Vec::new());
    };
    if items.len() > MAXIMUM_SEND_WITH_TRANSACTIONS + 1 {
        return Err(invalid(
            call,
            "sendWithResults",
            format!(
                "at most {} transaction results",
                MAXIMUM_SEND_WITH_TRANSACTIONS + 1
            ),
        ));
    }
    let mut results = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let field = format!("sendWithResults[{i}]");
        let result = item
            .as_object()
            .ok_or_else(|| invalid(call, &field, "an object"))?;
        let txid = hex32(
            result.get("txid").unwrap_or(&Value::Null),
            call,
            &format!("{field}.txid"),
        )?;
        let status = match result.get("status").and_then(Value::as_str) {
            Some("unproven") => SendWithResultStatus::Unproven,
            Some("sending") => SendWithResultStatus::Sending,
            Some("failed") => SendWithResultStatus::Failed,
            _ => {
                return Err(invalid(
                    call,
                    &format!("{field}.status"),
                    "a supported status",
                ))
            }
        };
        results.push(SendWithResult { txid, status });
    }
    Ok(results)
}

/// `validateReviewActionResults` (`HTTPWalletJSON.ts:131-197`).
fn review_action_results(
    value: Option<&Value>,
    allowed: &HashSet<String>,
) -> Result<Vec<ReviewActionResult>, Error> {
    let whole = || refused("Invalid wallet error reviewActionResults");
    let items = value.and_then(Value::as_array).ok_or_else(whole)?;
    if items.len() > MAXIMUM_SEND_WITH_TRANSACTIONS + 1 {
        return Err(whole());
    }
    let mut reviewed = HashSet::new();
    (items.iter().enumerate())
        .map(|(index, item)| review_action_result(index, item, allowed, &mut reviewed))
        .collect()
}

/// `reviewActionResults[index]`'s refusal, `member` named after it.
fn at(index: usize, member: &str) -> Error {
    refused(format!(
        "Invalid wallet error reviewActionResults[{index}]{member}"
    ))
}

/// One result (`HTTPWalletJSON.ts:139-195`): an object, its txid one of the
/// action's and not repeated, its status, and for a double spend alone the
/// competing txids and their BEEF.
fn review_action_result(
    index: usize,
    item: &Value,
    allowed: &HashSet<String>,
    reviewed: &mut HashSet<String>,
) -> Result<ReviewActionResult, Error> {
    let result = item.as_object().ok_or_else(|| at(index, ""))?;
    let txid = (result.get("txid").and_then(Value::as_str))
        .filter(|t| is_txid_hex(t))
        .ok_or_else(|| at(index, ".txid"))?
        .to_ascii_lowercase();
    if !allowed.contains(&txid) || !reviewed.insert(txid.clone()) {
        return Err(at(index, ".txid"));
    }
    let status = match result.get("status").and_then(Value::as_str) {
        Some("success") => ReviewActionResultStatus::Success,
        Some("doubleSpend") => ReviewActionResultStatus::DoubleSpend,
        Some("serviceError") => ReviewActionResultStatus::ServiceError,
        Some("invalidTx") => ReviewActionResultStatus::InvalidTx,
        _ => return Err(at(index, ".status")),
    };
    let (txs, beef) = (result.get("competingTxs"), result.get("competingBeef"));
    if status != ReviewActionResultStatus::DoubleSpend && (txs.is_some() || beef.is_some()) {
        return Err(at(index, ".competingTxs"));
    }
    let competing_txs = txs.map(|v| competing_txs(index, v, &txid)).transpose()?;
    let competing_beef = (beef)
        .map(|v| competing_beef(index, v, competing_txs.as_deref()))
        .transpose()?;
    Ok(ReviewActionResult {
        txid: txid_of(&txid).ok_or_else(|| at(index, ".txid"))?,
        status,
        competing_txs: competing_txs.map(|t| t.iter().filter_map(|t| txid_of(t)).collect()),
        competing_beef,
    })
}

/// `competingTxs` (`HTTPWalletJSON.ts:160-178`): at most 1000 txids, each
/// 64 hex digits, lower-cased, neither the reviewed one nor repeated.
fn competing_txs(index: usize, value: &Value, reviewed: &str) -> Result<Vec<String>, Error> {
    let list = (value.as_array())
        .filter(|l| l.len() <= MAXIMUM_SEND_WITH_TRANSACTIONS)
        .ok_or_else(|| at(index, ".competingTxs"))?;
    let mut unique = HashSet::new();
    let mut txids = Vec::with_capacity(list.len());
    for (j, competing) in list.iter().enumerate() {
        let normalized = (competing.as_str())
            .filter(|t| is_txid_hex(t))
            .ok_or_else(|| at(index, &format!(".competingTxs[{j}]")))?
            .to_ascii_lowercase();
        if normalized == reviewed || !unique.insert(normalized.clone()) {
            return Err(at(index, ".competingTxs"));
        }
        txids.push(normalized);
    }
    Ok(txids)
}

/// `competingBeef` (`HTTPWalletJSON.ts:179-194`): with one competing txid
/// at least, bytes, a BEEF read whole (`Beef.fromBinaryStrict`) holding
/// every competing txid.
fn competing_beef(index: usize, value: &Value, txids: Option<&[String]>) -> Result<Vec<u8>, Error> {
    let refused = || at(index, ".competingBeef");
    let txids = txids.filter(|t| !t.is_empty()).ok_or_else(refused)?;
    let bytes = byte_array(value).ok_or_else(refused)?;
    let beef = Beef::from_binary(&bytes).map_err(|_| refused())?;
    if txids.iter().any(|t| beef.find_txid(t).is_none()) {
        return Err(refused());
    }
    Ok(bytes)
}

/// `/^[0-9a-fA-F]{64}$/`.
fn is_txid_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}
