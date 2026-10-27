//! The wallet's answer read, moved out of `http_json.rs` (#339): an error
//! status's body by its busy word, its code-5 results (`review_actions`),
//! a 429's wait, its class by name or code (#137) and a gateway status, in
//! that order; a success body by its type, createAction's and signAction's
//! `tx` by the code-5 reader's byte reader when the typed reading refuses it.

use super::review_actions::{self, ReviewRequest};
use super::{request_error, wallet_busy_from_response, wallet_error_from_body};
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
) -> Error {
    let status = response.status();
    let transport = fault::status_fault(status, response.headers());
    let retry_after = fault::retry_after(response.headers()).map(str::to_owned);
    let text = response.text().await.unwrap_or_default();

    // The body's busy word, at any status, is the wallet's promise
    // that it took no action; the status alone promises nothing
    if let Some(busy) = wallet_busy_from_response(&text, retry_after.as_deref()) {
        return busy;
    }
    // A 400's code-5 body with its results is the reference's
    // WERR_REVIEW_ACTIONS, every member read as it reads them (#339)
    if let Ok(body) = serde_json::from_str::<serde_json::Value>(&text) {
        if review_actions::is_review_body(status.as_u16(), &body) {
            return review_actions::read(&body, method, review);
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

/// A success answer read as `R`; with `review` (createAction, signAction)
/// a `tx` the typed reading refuses is read by the byte reader (#339).
pub(super) async fn success<R: for<'de> Deserialize<'de>>(
    response: Response,
    review: Option<&ReviewRequest>,
) -> Result<R, Error> {
    if review.is_none() {
        return response
            .json::<R>()
            .await
            .map_err(|e| request_error(e, "failed to parse JSON response"));
    }
    // createAction's and signAction's `tx` read by the error path's
    // byte reader, as the reference normalizes both (#339); the answer
    // the typed reading takes costs what it cost, the byte reader's
    // `Value` tree (about 32 bytes a byte) built only for one it refuses
    let text = response
        .bytes()
        .await
        .map_err(|e| request_error(e, "failed to parse JSON response"))?;
    let typed = match serde_json::from_slice::<R>(&text) {
        Ok(result) => return Ok(result),
        Err(e) => e,
    };
    let parse_error = |e| Error::WalletError(format!("failed to parse JSON response: {e}"));
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&text) else {
        return Err(parse_error(typed));
    };
    drop(text);
    review_actions::normalize_success_tx(&mut body);
    serde_json::from_value(body).map_err(parse_error)
}
