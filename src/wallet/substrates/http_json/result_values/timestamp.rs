//! ISO timestamp shape and V8 Date.parse ranges, shared with the wire.

use super::{invalid, Result};

pub(crate) fn validate(value: &str, call: &str, field: &str) -> Result<()> {
    if !(1..=64).contains(&value.len()) {
        return Err(invalid(call, field, "1–64 UTF-8 bytes"));
    }
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .filter(|d| d.iter().all(u8::is_ascii_digit))
    };
    let zone_ok = match bytes.last() {
        Some(b'Z') => true,
        _ => {
            let n = bytes.len();
            n >= 6
                && matches!(bytes[n - 6], b'+' | b'-')
                && digits(n - 5..n - 3).is_some()
                && bytes[n - 3] == b':'
                && digits(n - 2..n).is_some()
        }
    };
    let pattern = digits(0..4).is_some()
        && bytes.get(4) == Some(&b'-')
        && digits(5..7).is_some()
        && bytes.get(7) == Some(&b'-')
        && digits(8..10).is_some()
        && bytes.get(10) == Some(&b'T')
        && bytes.len() >= 12
        && zone_ok
        && !value[11..].contains(['\n', '\r', '\u{2028}', '\u{2029}']);
    if !pattern {
        return Err(invalid(call, field, "an ISO timestamp with a timezone"));
    }
    if !date_time_parses(value) {
        return Err(invalid(call, field, "a valid ISO timestamp"));
    }
    Ok(())
}

/// The ECMAScript date-time string format after a `YYYY-MM-DDT` prefix,
/// as V8's `Date.parse` ranges it.
fn date_time_parses(value: &str) -> bool {
    let number = |s: &str| -> Option<u32> {
        (s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let (month, day) = (number(&value[5..7]), number(&value[8..10]));
    if !matches!(month, Some(1..=12)) || !matches!(day, Some(1..=31)) {
        return false;
    }
    let time = &value[11..];
    let (clock, zone) = match time.strip_suffix('Z') {
        Some(clock) => (clock, None),
        None => {
            let (clock, zone) = time.split_at(time.len() - 6);
            (clock, Some(zone))
        }
    };
    if let Some(zone) = zone {
        if !matches!(number(&zone[1..3]), Some(0..=23))
            || !matches!(number(&zone[4..6]), Some(0..=59))
        {
            return false;
        }
    }
    let (clock, fraction) = match clock.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (clock, None),
    };
    if let Some(fraction) = fraction {
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    let parts: Vec<&str> = clock.split(':').collect();
    let fields: Option<Vec<u32>> = parts.iter().map(|p| number(p)).collect();
    let Some(fields) = fields else {
        return false;
    };
    let (hour, minute, second) = match fields[..] {
        [hour, minute] if fraction.is_none() => (hour, minute, 0),
        [hour, minute, second] => (hour, minute, second),
        _ => return false,
    };
    let fraction_zero = fraction.is_none_or(|f| f.bytes().all(|b| b == b'0'));
    let end_of_day = hour == 24 && minute == 0 && second == 0 && fraction_zero;
    (hour <= 23 || end_of_day) && minute <= 59 && second <= 59
}
