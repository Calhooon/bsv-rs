//! The one transport-fault classifier (Calhooon/bsv-rs#87).
//!
//! Every HTTP site of the wallet substrates, the auth transports, the
//! broadcasters and the chain trackers asks these functions what a failure
//! was; none classifies by text. The class reads the error's kind and the
//! answer's status, before the body: a connection never made is
//! [`TransportFault::NeverSent`]; a timeout, a connection lost or a body cut
//! after the request was written, and a 502, 503 or 504, are
//! [`TransportFault::MayHaveBeenReceived`]; a 429, and a 503 carrying
//! `Retry-After`, is [`TransportFault::RateLimited`] with its wait. Every
//! other status is the far side's answer (`None`), read by the site.

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Response, StatusCode};
use serde_json::json;

use crate::error::TransportFault;
use crate::transaction::{BroadcastFailure, BroadcastStatus, ChainTrackerError};

/// Whether the connection was refused, reset or not made before any byte of
/// the request left. On wasm32 the fetch API does not say, so it is never
/// read as unsent there.
#[cfg(not(target_arch = "wasm32"))]
fn not_connected(e: &reqwest::Error) -> bool {
    e.is_connect()
}

#[cfg(target_arch = "wasm32")]
fn not_connected(_: &reqwest::Error) -> bool {
    false
}

/// Whether any byte of the request may have left: `NeverSent` only for a
/// request that could not be built or a connection never made; every other
/// error (a timeout included) may follow the written body.
pub(crate) fn delivery(e: &reqwest::Error) -> TransportFault {
    if e.is_builder() || not_connected(e) {
        TransportFault::NeverSent
    } else {
        TransportFault::MayHaveBeenReceived
    }
}

/// The fault of a send or body-read error, as `request_error` of the JSON
/// substrate reads one: a connection error, a timeout, a request or body
/// failure. `None` for a request that could not be built, a redirect
/// refused and a body that is not the expected shape, which are not faults
/// of the way.
pub(crate) fn error_fault(e: &reqwest::Error) -> Option<TransportFault> {
    (not_connected(e) || e.is_timeout() || e.is_request() || e.is_body()).then(|| delivery(e))
}

/// The fault an answer's status reports, read before its body; `None` when
/// the status is the far side's answer.
pub(crate) fn status_fault(status: StatusCode, headers: &HeaderMap) -> Option<TransportFault> {
    let retry_after = retry_after(headers);
    match status.as_u16() {
        429 => Some(rate_limited(retry_after)),
        503 if retry_after.is_some() => Some(rate_limited(retry_after)),
        502..=504 => Some(TransportFault::MayHaveBeenReceived),
        _ => None,
    }
}

fn rate_limited(retry_after: Option<&str>) -> TransportFault {
    let now = crate::util::time::current_time_secs();
    TransportFault::RateLimited {
        retry_after_ms: retry_after.and_then(|value| retry_after_ms(value, now)),
    }
}

/// The first `Retry-After` header's value, when it is text.
pub(crate) fn retry_after(headers: &HeaderMap) -> Option<&str> {
    headers.get(RETRY_AFTER).and_then(|v| v.to_str().ok())
}

/// Reads `Retry-After` (RFC 9110 section 10.2.3) as milliseconds from `now`
/// (seconds since the epoch): delta seconds, or an HTTP date (a date passed
/// is 0); saturating; `None` when unreadable.
pub(crate) fn retry_after_ms(value: &str, now: u64) -> Option<u64> {
    delta_seconds_ms(value).or_else(|| {
        let at = http_date_secs(value, now)?;
        Some(at.saturating_sub(now).saturating_mul(1000))
    })
}

/// Reads delta seconds (`1*DIGIT`) as milliseconds, saturating; anything
/// else is `None`.
pub(crate) fn delta_seconds_ms(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // A delay too long for a u64 of seconds is still a delay: saturate
    let seconds = value.parse::<u64>().unwrap_or(u64::MAX);
    Some(seconds.saturating_mul(1000))
}

/// Reads an HTTP date (RFC 9110 section 5.6.7: IMF-fixdate, and the
/// obsolete RFC 850 and asctime forms a recipient must accept) as seconds
/// since the epoch; a date before it is 0. `now` places a two-digit year.
fn http_date_secs(value: &str, now: u64) -> Option<u64> {
    let parts: Vec<&str> = value.split_ascii_whitespace().collect();
    let (day, month, year, time) = match parts.as_slice() {
        [_, day, month, year, time, "GMT"] => (*day, *month, number(year, 4)?, *time),
        [_, date, time, "GMT"] => {
            let mut fields = date.split('-');
            let (day, month, short) = (fields.next()?, fields.next()?, fields.next()?);
            (day, month, two_digit_year(number(short, 2)?, now), *time)
        }
        [_, month, day, time, year] => (*day, *month, number(year, 4)?, *time),
        _ => return None,
    };
    let day = number(day, 2).or_else(|| number(day, 1))?;
    let month = month_number(month)?;
    let mut clock = time.split(':').map(|field| number(field, 2));
    let (hour, minute, second) = (clock.next()??, clock.next()??, clock.next()??);
    if clock.next().is_some() || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    Some(u64::try_from(seconds).unwrap_or(0))
}

/// A two-digit year more than 50 years ahead of `now` is the most recent
/// past year with those digits (RFC 9110 section 5.6.7).
fn two_digit_year(short: u32, now: u64) -> u32 {
    let this_year = u32::try_from(1970 + now / 31_556_952).unwrap_or(9999);
    let year = this_year - this_year % 100 + short;
    if year > this_year.saturating_add(50) {
        year - 100
    } else {
        year
    }
}

fn number(text: &str, digits: usize) -> Option<u32> {
    if text.len() != digits || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn month_number(name: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let index = MONTHS.iter().position(|month| *month == name)?;
    u32::try_from(index + 1).ok()
}

/// Days from 1970-01-01 to a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`); `year` is at most four digits, so nothing overflows.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let (year, month, day) = (i64::from(year), i64::from(month), i64::from(day));
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// ---------------------------------------------------------------------------
// The crate's error at the wallet substrates and the auth transports
// ---------------------------------------------------------------------------

/// [`crate::Error::TransportFault`] when there is a fault, with the answer's
/// status when one arrived, else `otherwise(detail)`.
#[cfg(feature = "auth")]
pub(crate) fn fault_or(
    fault: Option<TransportFault>,
    status: Option<StatusCode>,
    detail: String,
    otherwise: fn(String) -> crate::Error,
) -> crate::Error {
    match fault {
        Some(fault) => crate::Error::TransportFault {
            fault,
            status: status.map(|status| status.as_u16()),
            detail,
        },
        None => otherwise(detail),
    }
}

/// The auth transports' error of a failed send or body read:
/// [`crate::Error::TransportFault`] when it is a fault, else
/// [`crate::Error::AuthError`], both `"{context}: {e}"`.
#[cfg(feature = "auth")]
pub(crate) fn auth_error(e: &reqwest::Error, context: &str) -> crate::Error {
    let detail = format!("{}: {}", context, e);
    fault_or(error_fault(e), None, detail, crate::Error::AuthError)
}

/// The auth handshake's error for an answer that is not a success, the
/// status read before the body: [`crate::Error::TransportFault`] when the
/// status is a fault, else [`crate::Error::AuthError`], both
/// `"Auth endpoint returned {status}: {body}"`.
#[cfg(feature = "auth")]
pub(crate) async fn auth_status_error(response: Response) -> crate::Error {
    let status = response.status();
    let fault = status_fault(status, response.headers());
    let body = response.text().await.unwrap_or_default();
    let detail = format!("Auth endpoint returned {}: {}", status, body);
    fault_or(fault, Some(status), detail, crate::Error::AuthError)
}

/// The wallet substrates' error of a failed send or body read:
/// [`crate::Error::WalletTransport`] with no status when it is a fault (0.8.2's
/// shape), else [`crate::Error::WalletError`].
#[cfg(feature = "wallet")]
pub(crate) fn wallet_error(e: &reqwest::Error, detail: String) -> crate::Error {
    match error_fault(e) {
        Some(_) => crate::Error::WalletTransport {
            status: None,
            detail,
        },
        None => crate::Error::WalletError(detail),
    }
}

// ---------------------------------------------------------------------------
// The broadcasters' failure
// ---------------------------------------------------------------------------

fn broadcast_fault(
    fault: TransportFault,
    txid: &str,
    description: String,
    more: Option<serde_json::Value>,
) -> BroadcastFailure {
    BroadcastFailure {
        status: BroadcastStatus::Error,
        code: fault.code().to_string(),
        txid: Some(txid.to_string()),
        description,
        more,
    }
}

/// A broadcaster's failure to send: `NEVER_SENT` or `MAY_HAVE_BEEN_RECEIVED`.
pub(crate) fn send_failure(e: &reqwest::Error, txid: &str) -> BroadcastFailure {
    broadcast_fault(delivery(e), txid, format!("Network error: {}", e), None)
}

/// A broadcaster's failure to read the answer's body: the fault when the
/// way failed, else `PARSE_ERROR` with `context`.
pub(crate) fn body_failure(e: &reqwest::Error, txid: &str, context: &str) -> BroadcastFailure {
    let description = format!("{}: {}", context, e);
    match error_fault(e) {
        Some(fault) => broadcast_fault(fault, txid, description, None),
        None => BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "PARSE_ERROR".to_string(),
            txid: Some(txid.to_string()),
            description,
            more: None,
        },
    }
}

/// The answer back when its status is the service's word; when the status
/// is a fault, the failure, whatever the body is: `RATE_LIMITED` with
/// `more` `{"status", "retry_after_ms"}` (`null` when unknown), or
/// `MAY_HAVE_BEEN_RECEIVED` with `more` `{"status"}`. The body, read after
/// the status, is the description (the status line when it is empty).
pub(crate) async fn answered(response: Response, txid: &str) -> Result<Response, BroadcastFailure> {
    let status = response.status();
    let Some(fault) = status_fault(status, response.headers()) else {
        return Ok(response);
    };
    let more = match fault {
        TransportFault::RateLimited { retry_after_ms } => {
            json!({ "status": status.as_u16(), "retry_after_ms": retry_after_ms })
        }
        _ => json!({ "status": status.as_u16() }),
    };
    let body = response.text().await.unwrap_or_default();
    let description = if body.is_empty() {
        format!("HTTP {}", status)
    } else {
        body
    };
    Err(broadcast_fault(fault, txid, description, Some(more)))
}

// ---------------------------------------------------------------------------
// The chain trackers' error (`ChainTrackerError` is exhaustive: the class is
// stated in the detail until it may carry a typed one)
// ---------------------------------------------------------------------------

/// A tracker's failure to send: `NetworkError`, its class stated.
pub(crate) fn tracker_send_error(e: &reqwest::Error) -> ChainTrackerError {
    ChainTrackerError::NetworkError(format!("{} ({})", e, delivery(e)))
}

/// A tracker's failure to read the body: `NetworkError` when the way failed,
/// else `InvalidResponse`.
pub(crate) fn tracker_body_error(e: &reqwest::Error) -> ChainTrackerError {
    match error_fault(e) {
        Some(fault) => ChainTrackerError::NetworkError(format!("{} ({})", e, fault)),
        None => ChainTrackerError::InvalidResponse(e.to_string()),
    }
}

/// A tracker's error for an answer that is not a success: `InvalidResponse`
/// with the status, and the class and wait when the status is a fault.
pub(crate) fn tracker_status_error(response: &Response) -> ChainTrackerError {
    let status = response.status();
    let detail = match status_fault(status, response.headers()) {
        Some(TransportFault::RateLimited {
            retry_after_ms: Some(ms),
        }) => format!("HTTP {} (RATE_LIMITED, retry_after_ms {})", status, ms),
        Some(fault) => format!("HTTP {} ({})", status, fault),
        None => format!("HTTP {}", status),
    };
    ChainTrackerError::InvalidResponse(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_792_000_000; // 2026-10-14T17:46:40Z

    #[test]
    fn retry_after_reads_delta_seconds_saturating() {
        assert_eq!(retry_after_ms("5", NOW), Some(5000));
        assert_eq!(retry_after_ms(" 0 ", NOW), Some(0));
        assert_eq!(retry_after_ms("99999999999999999999", NOW), Some(u64::MAX));
    }

    #[test]
    fn retry_after_reads_the_three_http_date_forms() {
        // 1_792_000_005 is 2026-10-14T17:46:45Z, five seconds after NOW
        for date in [
            "Wed, 14 Oct 2026 17:46:45 GMT",
            "Wednesday, 14-Oct-26 17:46:45 GMT",
            "Wed Oct 14 17:46:45 2026",
        ] {
            assert_eq!(retry_after_ms(date, NOW), Some(5000), "{date}");
        }
        assert_eq!(
            http_date_secs("Sun, 06 Nov 1994 08:49:37 GMT", NOW),
            Some(784_111_777)
        );
        assert_eq!(
            http_date_secs("Sun Nov  6 08:49:37 1994", NOW),
            Some(784_111_777)
        );
    }

    #[test]
    fn a_retry_after_date_passed_is_no_wait() {
        assert_eq!(
            retry_after_ms("Wed, 21 Oct 2015 07:28:00 GMT", NOW),
            Some(0)
        );
        assert_eq!(
            retry_after_ms("Mon, 01 Jan 1900 00:00:00 GMT", NOW),
            Some(0)
        );
    }

    #[test]
    fn an_unreadable_retry_after_is_none() {
        for value in [
            "",
            "-1",
            "1.5",
            "soon",
            "Thu, 15 Oct 2026 15:06:45 UTC",
            "Thu, 15 Foo 2026 15:06:45 GMT",
            "Thu, 32 Oct 2026 15:06:45 GMT",
            "Thu, 15 Oct 2026 24:00:00 GMT",
            "Thu, 15 Oct 2026 15:06 GMT",
            "Thu, 15 Oct 2026 15:06:45:00 GMT",
        ] {
            assert_eq!(retry_after_ms(value, NOW), None, "{value:?}");
        }
    }

    #[test]
    fn a_two_digit_year_more_than_fifty_years_ahead_is_in_the_past_century() {
        assert_eq!(two_digit_year(26, NOW), 2026);
        assert_eq!(two_digit_year(76, NOW), 2076);
        assert_eq!(two_digit_year(77, NOW), 1977);
        assert_eq!(two_digit_year(94, NOW), 1994);
    }

    #[test]
    fn statuses_classify_before_the_body() {
        let none = HeaderMap::new();
        let mut waiting = HeaderMap::new();
        waiting.insert(RETRY_AFTER, reqwest::header::HeaderValue::from_static("5"));
        let at = |code: u16, headers: &HeaderMap| {
            StatusCode::from_u16(code)
                .ok()
                .and_then(|status| status_fault(status, headers))
        };
        let limited = |ms| Some(TransportFault::RateLimited { retry_after_ms: ms });
        assert_eq!(at(429, &none), limited(None));
        assert_eq!(at(429, &waiting), limited(Some(5000)));
        assert_eq!(at(503, &waiting), limited(Some(5000)));
        for code in [502, 503, 504] {
            assert_eq!(at(code, &none), Some(TransportFault::MayHaveBeenReceived));
        }
        for code in [200, 400, 404, 500, 501] {
            assert_eq!(at(code, &waiting), None, "{code} is the far side's answer");
        }
    }
}
