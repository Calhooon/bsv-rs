//! A wallet's code-5 body read as the reference's `HTTPWalletJSON` reads it
//! (#339; `ts-stack@edf6e03` `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:117-241`):
//! the envelope, the message, the call, the four action-result members
//! through `validateWalletResult`'s action checks
//! (`WalletResultValidation.ts:1242-1374`, under `returnTXIDOnly: true`),
//! then `reviewActionResults`, each refusal in the reference's words, the
//! five members carried by [`ReviewActionsRefusal`].
//!
//! Not ported: the checks `validateWalletResult` makes of a returned `tx`'s
//! transaction against the request (`validateCreateActionTransaction`,
//! `validateSignActionTransaction`, `validateTransactionValueConservation`),
//! which this substrate's success path does not make either; the `tx` is
//! read as a BEEF and bound to `txid`.

use crate::primitives::{from_hex, to_hex};
use crate::transaction::{Beef, BeefTx};
use crate::wallet::{
    CreateActionArgs, Outpoint, ReviewActionResult, ReviewActionResultStatus, ReviewActionsRefusal,
    SendWithResult, SendWithResultStatus, SignActionArgs, TxId,
};
use crate::Error;
use serde_json::{Map, Value};
use std::collections::HashSet;

/// `MAXIMUM_SEND_WITH_TRANSACTIONS` (`validationHelpers.ts:69`).
const MAXIMUM_SEND_WITH_TRANSACTIONS: usize = 1000;
/// `MAX_WALLET_WIRE_FRAME_BYTES`, `bytes`'s default bound.
const MAX_BYTES: usize = 256 * 1024 * 1024;
/// `requireErrorString`'s default bound (`HTTPWalletJSON.ts:117`).
const MAX_ERROR_STRING_BYTES: usize = 4096;

/// What a code-5 body is bound to: the call, its `sendWith`, and for a
/// createAction whether it asks for a transaction and whether one is to be
/// signed later (`validateActionResult`'s request checks).
pub(super) struct ReviewRequest {
    call: &'static str,
    send_with: Vec<TxId>,
    create: Option<CreateShape>,
}

struct CreateShape {
    creates_transaction: bool,
    deferred_signing: bool,
}

impl ReviewRequest {
    pub(super) fn create_action(args: &CreateActionArgs) -> Self {
        let options = args.options.as_ref();
        let send_with = options
            .and_then(|o| o.send_with.clone())
            .unwrap_or_default();
        let inputs = args.inputs.as_deref().unwrap_or_default();
        let outputs = args.outputs.as_deref().map_or(0, <[_]>::len);
        let creates_transaction = !inputs.is_empty() || outputs > 0 || send_with.is_empty();
        let unsigned_input = inputs.iter().any(|i| i.unlocking_script.is_none());
        let deferred = options.and_then(|o| o.sign_and_process) == Some(false) || unsigned_input;
        Self {
            call: "createAction",
            send_with,
            create: Some(CreateShape {
                creates_transaction,
                deferred_signing: creates_transaction && deferred,
            }),
        }
    }

    pub(super) fn sign_action(args: &SignActionArgs) -> Self {
        Self {
            call: "signAction",
            send_with: (args.options.as_ref())
                .and_then(|o| o.send_with.clone())
                .unwrap_or_default(),
            create: None,
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
pub(super) fn read(body: &Value, call: &str, request: Option<&ReviewRequest>) -> Error {
    match read_members(body, call, request) {
        Ok(refusal) => Error::WalletReviewActions(Box::new(refusal)),
        Err(error) => error,
    }
}

fn read_members(
    body: &Value,
    call: &str,
    request: Option<&ReviewRequest>,
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

/// `normalizeBRC100ByteArray` (`BRC100ByteEncoding.ts:81-86`), which the
/// reference's `normalizeBRC100WalletByteFields` runs on the body's `tx`
/// and `competingBeef` before the error is read (`HTTPWalletJSON.ts:326-328`),
/// then `bytes(value, call, field)` (`WalletResultValidation.ts:868-906`): an
/// array of integers 0 to 255, or the historical object form, at most 256 MiB.
fn byte_array(value: &Value) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = match value {
        Value::Array(items) if items.len() <= MAX_BYTES => {
            items.iter().map(byte).collect::<Option<_>>()?
        }
        Value::Object(_) => historical_bytes(value)?,
        _ => return None,
    };
    (bytes.len() <= MAX_BYTES).then_some(bytes)
}

/// A 200 createAction or signAction answer's `tx` read by [`byte_array`],
/// the one reader for both paths: the reference normalizes the success
/// body as it does the error body (`HTTPWalletJSON.ts:322-341`), so the
/// historical object form and an integral float (`1.0`) are bytes there
/// too. A `tx` it does not read is left to the result's own reader.
pub(super) fn normalize_success_tx(body: &mut Value) {
    if let Some(tx) = body.get_mut("tx") {
        if let Some(bytes) = byte_array(tx) {
            *tx = Value::from(bytes);
        }
    }
}

/// `normalizeHistoricalByteObject` (`BRC100ByteEncoding.ts:52-71`): the
/// object `JSON.stringify(new Uint8Array(..))` writes, at least one key, its
/// keys exactly `"0"` to `"n-1"`, each a byte. `Object.keys` lists integer
/// keys ascending whatever their order in the text, so each index is looked
/// up; `n` keys holding every index below `n` are exactly those. An empty
/// object is refused, as the reference refuses it at these two fields.
fn historical_bytes(value: &Value) -> Option<Vec<u8>> {
    let keys = value.as_object().filter(|keys| !keys.is_empty())?;
    (0..keys.len())
        .map(|i| keys.get(&i.to_string()).and_then(byte))
        .collect()
}

/// `isByte` (`BRC100ByteEncoding.ts:32-34`): `Number.isInteger` from 0 to
/// 255, so `1.0` and `-0` are bytes as `JSON.parse` reads them.
fn byte(value: &Value) -> Option<u8> {
    if let Some(n) = value.as_u64() {
        return u8::try_from(n).ok();
    }
    // an integral float in range: the first byte not below it is its value
    let n = (value.as_f64()).filter(|n| (0.0..=255.0).contains(n) && n.fract() == 0.0)?;
    (0..=u8::MAX).find(|&b| f64::from(b) >= n)
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

/// The transaction a result's `tx` carries (`actionBeefTransaction`,
/// `WalletResultValidation.ts:1376-1420`): a BEEF this crate reads whole,
/// its transaction the one of `txid`, else the atomic subject, else the
/// last full transaction; its txid.
fn beef_subject(bytes: &[u8], txid: Option<&TxId>) -> Option<String> {
    let beef = Beef::from_binary(bytes).ok()?;
    let full = |id: &str| beef.find_txid(id).is_some_and(|t| t.tx().is_some());
    let requested = txid.map(|t| to_hex(t)).filter(|id| full(id));
    let atomic = beef.atomic_txid.clone().filter(|id| full(id));
    let last = beef
        .txs
        .iter()
        .rev()
        .find(|t| t.tx().is_some())
        .map(BeefTx::txid);
    requested.or(atomic).or(last)
}

/// `validateActionResult` (`WalletResultValidation.ts:1242-1374`) on
/// `{ txid, tx, noSendChange, sendWithResults }` under the request with
/// `returnTXIDOnly: true` (`HTTPWalletJSON.ts:211-228`): each member's
/// shape, then the members bound to the request and to one another.
fn action_result(
    data: &Map<String, Value>,
    request: &ReviewRequest,
) -> Result<ActionMembers, Error> {
    let call = request.call;
    let txid = (data.get("txid"))
        .map(|v| hex32(v, call, "txid"))
        .transpose()?;
    let tx = (data.get("tx"))
        .map(|v| tx_member(v, txid.as_ref(), call))
        .transpose()?;
    let no_send_change = match optional_array(data.get("noSendChange"), call, "noSendChange")? {
        None => None,
        Some(items) => Some(
            (items.iter().enumerate())
                .map(|(i, v)| outpoint(v, call, &format!("noSendChange[{i}]")))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    let members = ActionMembers {
        txid,
        tx,
        no_send_change,
        send_with_results: send_with_results(data.get("sendWithResults"), call)?,
    };
    bind(&members, request)?;
    Ok(members)
}

/// A result's `tx`: `bytes`, then `actionBeefTransaction` and the txid it
/// must match (`WalletResultValidation.ts:1248-1257`).
fn tx_member(value: &Value, txid: Option<&TxId>, call: &str) -> Result<Vec<u8>, Error> {
    if value
        .as_array()
        .is_some_and(|items| items.len() > MAX_BYTES)
    {
        return Err(invalid(call, "tx", format!("at most {MAX_BYTES} bytes")));
    }
    let bytes = byte_array(value).ok_or_else(|| invalid(call, "tx", "an array of bytes"))?;
    let subject = beef_subject(&bytes, txid)
        .ok_or_else(|| invalid(call, "tx", "a complete, exactly framed BEEF transaction"))?;
    if txid.is_some_and(|txid| !subject.eq_ignore_ascii_case(&to_hex(txid))) {
        return Err(invalid(call, "tx", "a BEEF transaction matching txid"));
    }
    Ok(bytes)
}

/// The request checks of `validateActionResult` (`:1280-1373`) in its
/// order; a code-5 body carries no `signableTransaction`.
fn bind(members: &ActionMembers, request: &ReviewRequest) -> Result<(), Error> {
    let call = request.call;
    let txid = members.txid;
    match &request.create {
        Some(create) if create.creates_transaction && create.deferred_signing => {
            let expected = "the requested deferred-signing transaction";
            return Err(invalid(call, "signableTransaction", expected));
        }
        Some(create) if create.creates_transaction && txid.is_none() => {
            return Err(invalid(call, "txid", "the requested completed transaction"));
        }
        None if txid.is_none() => {
            return Err(invalid(call, "txid", "the completed signed transaction"));
        }
        _ => {}
    }
    if let Some(change) = &members.no_send_change {
        let Some(subject) = txid else {
            return Err(invalid(
                call,
                "noSendChange",
                "associated with a transaction",
            ));
        };
        if let Some(i) = change.iter().position(|o| o.txid != subject) {
            let field = format!("noSendChange[{i}]");
            return Err(invalid(
                call,
                &field,
                "an outpoint of the returned transaction",
            ));
        }
    }
    let mut allowed: HashSet<TxId> = request.send_with.iter().copied().collect();
    allowed.extend(txid);
    let mut seen = HashSet::new();
    for (i, result) in members.send_with_results.iter().enumerate() {
        let field = format!("sendWithResults[{i}].txid");
        if !seen.insert(result.txid) {
            return Err(invalid(call, &field, "a unique transaction"));
        }
        if !allowed.is_empty() && !allowed.contains(&result.txid) {
            return Err(invalid(call, &field, "a submitted or returned transaction"));
        }
    }
    if members.tx.is_some() && txid.is_none() {
        return Err(invalid(call, "txid", "present with tx"));
    }
    if request.create.is_none() && members.no_send_change.is_some() {
        return Err(invalid(call, "noSendChange", "an absent field"));
    }
    if txid.is_none() && members.send_with_results.is_empty() {
        let expected = "a transaction, signable transaction, or batch-send result";
        return Err(invalid(call, "outcome", expected));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_historical_object_form_is_read_by_its_indexes_in_any_text_order() {
        let read = |text: &str| byte_array(&serde_json::from_str(text).unwrap());
        assert_eq!(read(r#"{"0":1,"1":2,"2":255}"#), Some(vec![1, 2, 255]));
        assert_eq!(read(r#"{"2":255,"0":1,"1":2}"#), Some(vec![1, 2, 255]));
        // a repeated key is its last value, as JSON.parse keeps it
        assert_eq!(read(r#"{"0":9,"0":1}"#), Some(vec![1]));
        assert_eq!(read("[1,2,255]"), Some(vec![1, 2, 255]));
        assert_eq!(read("[]"), Some(vec![]));
        // `Number.isInteger`: an integral float and negative zero are bytes
        assert_eq!(read("[1.0,-0.0,2e0]"), Some(vec![1, 0, 2]));
        assert_eq!(read(r#"{"0":255.0}"#), Some(vec![255]));
    }

    #[test]
    fn an_object_not_the_historical_form_is_refused() {
        for text in [
            "{}",
            r#"{"1":1}"#,
            r#"{"0":1,"2":2}"#,
            r#"{"00":1}"#,
            r#"{"0":1,"01":2}"#,
            r#"{"0":1,"length":1}"#,
            r#"{"0":256}"#,
            r#"{"0":-1}"#,
            r#"{"0":"1"}"#,
            r#"{"0":null}"#,
            r#"{"0":1.5}"#,
        ] {
            assert_eq!(
                byte_array(&serde_json::from_str(text).unwrap()),
                None,
                "{text}"
            );
        }
        assert_eq!(byte_array(&json!("0102")), None);
        assert_eq!(byte_array(&json!([1, 256])), None);
    }
}
