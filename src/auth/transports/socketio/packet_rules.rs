//! The reference's reading of a Socket.IO packet's id and payload (bsv-rs#110).
//!
//! The reference is `socket.io-parser` 4.2.7 (the parser `socket.io` ^4.8.3
//! ships, which `@bsv/authsocket` reaches): its `decodeString`
//! (`build/cjs/index.js:178-247`) reads the run after the namespace as the
//! packet's id on every type, a character belonging to the run when
//! `Number(c) == c` (`:222`, `:226`): an ASCII digit, or a character
//! JavaScript's `Number` trims as white space, which reads as `0`. The id is
//! `Number(run)` (`:233`): the run trimmed, `0` when nothing is left, the
//! digits' value otherwise, `NaN` when white space sits between digits. The
//! payload after the run must be JSON of the type's shape (`isPayloadValid`,
//! `:256-274`), else `invalid payload` (`:242`).

use serde_json::Value;

use super::codec::CodecError;

/// The words the reference throws for a payload it refuses (`:242`).
const INVALID_PAYLOAD: &str = "invalid payload";

/// The event names the reference refuses at the head of an EVENT (`:16-23`).
const RESERVED_EVENTS: [&str; 6] = [
    "connect",
    "connect_error",
    "disconnect",
    "disconnecting",
    "newListener",
    "removeListener",
];

/// A character JavaScript's `Number` trims as white space (`WhiteSpace` and
/// `LineTerminator`): the code units besides the digits for which the
/// reference's `Number(c) == c` holds, recorded under Node v22.18.0 in
/// `tests/vectors/socketio_packet_validity_110.json` (`id_run_units`).
pub(crate) fn is_js_white_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// Split the text after the namespace into the id run and the payload.
pub(crate) fn split_id_run(rest: &str) -> (&str, &str) {
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || is_js_white_space(c)))
        .unwrap_or(rest.len());
    rest.split_at(end)
}

/// The id a run names, as the reference's `Number(run)` reads it.
///
/// An empty run is no id. A run of white space alone is `0`. A run whose
/// trimmed text holds white space between digits is `NaN` in the reference,
/// a packet whose encoding (`NaN` written as text) it cannot read back: it is
/// refused here, as is an id past `u64::MAX`, which the reference keeps as
/// the nearest double and no Socket.IO peer issues (ids count from 0 on each
/// socket).
pub(crate) fn read_id(run: &str) -> Result<Option<u64>, CodecError> {
    if run.is_empty() {
        return Ok(None);
    }
    let digits = run.trim_matches(is_js_white_space);
    if digits.is_empty() {
        return Ok(Some(0));
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CodecError::Malformed(format!(
            "socket.io ack id {run:?} is not a number"
        )));
    }
    digits
        .parse()
        .map(Some)
        .map_err(|_| CodecError::Malformed(format!("socket.io ack id {digits} exceeds u64::MAX")))
}

/// The payload after the id, parsed and judged by the reference's
/// `isPayloadValid` for the packet type `type_ch` (`'0'` to `'4'`); `None`
/// when the frame ends before it.
pub(crate) fn read_payload(type_ch: char, payload: &str) -> Result<Option<Value>, CodecError> {
    if payload.is_empty() {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(payload)
        .map_err(|e| CodecError::Malformed(format!("{INVALID_PAYLOAD} (invalid JSON: {e})")))?;
    if payload_valid(type_ch, &value) {
        Ok(Some(value))
    } else {
        Err(CodecError::Malformed(INVALID_PAYLOAD.into()))
    }
}

/// `isPayloadValid` (`:256-274`): CONNECT an object, DISCONNECT none,
/// CONNECT_ERROR a string or an object, EVENT an array whose head is a
/// number or a string outside [`RESERVED_EVENTS`], ACK an array.
fn payload_valid(type_ch: char, value: &Value) -> bool {
    match type_ch {
        '0' => value.is_object(),
        '4' => value.is_string() || value.is_object(),
        '2' => match value.as_array().and_then(|a| a.first()) {
            Some(Value::Number(_)) => true,
            Some(Value::String(name)) => !RESERVED_EVENTS.contains(&name.as_str()),
            _ => false,
        },
        '3' => value.is_array(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_reads_as_number_reads_it() {
        assert_eq!(read_id(""), Ok(None));
        assert_eq!(read_id("007"), Ok(Some(7)));
        assert_eq!(read_id(" "), Ok(Some(0)));
        assert_eq!(read_id("\n0\n"), Ok(Some(0)));
        assert_eq!(read_id("\u{feff}12\u{3000}"), Ok(Some(12)));
        assert_eq!(read_id("18446744073709551615"), Ok(Some(u64::MAX)));
        assert!(read_id("18446744073709551616").is_err());
        assert!(read_id("1 2").is_err());
    }

    #[test]
    fn the_run_stops_at_the_first_other_character() {
        assert_eq!(split_id_run("12 [1]"), ("12 ", "[1]"));
        assert_eq!(split_id_run("{}"), ("", "{}"));
        assert_eq!(split_id_run("\u{a0}5"), ("\u{a0}5", ""));
    }
}
