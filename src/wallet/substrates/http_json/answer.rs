//! The wallet's answer read, moved out of `http_json.rs` (#339): an error
//! status's body by its busy word, its code-5 results (`review_actions`),
//! a 429's wait, its class by name or code (#137) and a gateway status, in
//! that order; a success body's value checks (`result_values`, #408),
//! then its type, with #365's byte normalization on the fallback path.

use super::review_actions::{self, ReviewRequest};
use super::{byte_fields, result_values};
use super::{wallet_busy_from_response, wallet_error_from_body};
use crate::transaction::broadcasters::transport_fault as fault;
use crate::{Error, TransportFault};
use reqwest::{Response, StatusCode};
use serde::Deserialize;

/// The error an answer with an error status is, read against `review`, the
/// createAction or signAction asked, when its body is a code-5 one.
pub(super) async fn refusal(
    response: Response,
    method: &str,
    review: Option<&ReviewRequest>,
    binding: &serde_json::Value,
) -> Error {
    let status = response.status();
    let transport = fault::status_fault(status, response.headers());
    let retry_after = fault::retry_after(response.headers()).map(str::to_owned);
    let text = match result_values::response_bytes(response).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => return error,
    };
    if let Err(error) = result_values::snapshot(method, text.as_bytes()) {
        return error;
    }

    // The body's busy word, at any status, is the wallet's promise
    // that it took no action; the status alone promises nothing
    if let Some(busy) = wallet_busy_from_response(&text, retry_after.as_deref()) {
        return busy;
    }
    // A 400's code-5 body with its results is the reference's
    // WERR_REVIEW_ACTIONS, every member read as it reads them (#339)
    if let Some(body) = result_values::review_body(&text) {
        if review_actions::is_review_body(status.as_u16(), &body) {
            return review_actions::read(&body, method, review, binding);
        }
    }
    let detail = format!("HTTP {} for {}: {}", status, method, text);

    // A 429, whatever the body, is a rate limit with its wait
    if let (Some(fault @ TransportFault::RateLimited { .. }), StatusCode::TOO_MANY_REQUESTS) =
        (transport, status)
    {
        let status = Some(status.as_u16());
        return Error::TransportFault {
            fault,
            status,
            detail,
        };
    }

    // The wallet's error body: its class by name or code (#137), else
    // a numeric code with its description
    if let Some(error) = wallet_error_from_body(&text) {
        return error;
    }

    // A gateway status without the wallet's word is the edge's
    // answer: the way failed, and nothing is promised
    if transport.is_some() {
        return Error::WalletTransport {
            status: Some(status.as_u16()),
            detail,
        };
    }

    Error::WalletError(detail)
}

/// A success answer's value checks, then its reading as `R`; one the typed
/// reading refuses read again with its byte fields normalized (#339, #365).
pub(super) async fn success<R: for<'de> Deserialize<'de>>(
    response: Response,
    call: &str,
    request: &serde_json::Value,
) -> Result<R, Error> {
    // #408 borrows field slices and checks ordinary bytes without a Value
    // per byte. Only #365's fallback constructs the normalized Value tree.
    let text = result_values::response_bytes(response).await?;
    let snapshot = result_values::validate(call, &text, request)?;
    let typed = match serde_json::from_slice::<R>(&text) {
        Ok(result) => return Ok(result),
        Err(e) => e,
    };
    let parse_error = |e| Error::WalletError(format!("failed to parse JSON response: {e}"));
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&text) else {
        // JSON.parse has neither serde Value's number range nor its depth
        // bound. Normalize the indexed raw body when unrelated data exceeds
        // either; R still uses serde's ordinary typed depth guard.
        return match snapshot {
            Some(snapshot) => serde_json::from_str(&snapshot.normalized()).map_err(parse_error),
            None => Err(parse_error(typed)),
        };
    };
    drop(snapshot);
    drop(text);
    byte_fields::normalize(&mut body);
    result_values::normalize_numbers(&mut body);
    if let Some(refusal) = byte_fields::refusal(call, &body) {
        return Err(refusal);
    }
    serde_json::from_value(body).map_err(parse_error)
}
