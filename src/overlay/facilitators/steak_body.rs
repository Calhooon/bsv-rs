//! A host's answer to `/submit` read as the reference reads it (#815's
//! fold; `ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`): the body by
//! `readSHIPJSON` (`:271-320`: a declared length that is not canonical
//! digits or passes 1 MiB, a body past 1 MiB, bytes that are no UTF-8, text
//! that is no JSON), then the value by the broadcaster's empty check
//! (`:486-488`) and `validateSTEAK` over the topics sent (`:240-269`,
//! `:222-238`), each refusal in the reference's words.
//!
//! The reference's facilitator hands the parsed JSON to its broadcaster,
//! which judges it. Here the typed [`Steak`] cannot carry what the JSON
//! held (an instruction field other than the three, a `null` list, an index
//! written `1.0`), so the HTTPS facilitator judges the JSON itself, before
//! it builds the type; the broadcaster judges the typed value again for
//! every facilitator (`topic_broadcaster/steak.rs`). A typed read
//! (`response.json::<Steak>()`) took an instruction with a fourth field, a
//! `coinsRemoved` of `null` and a body of any size until the fold.
//!
//! Stated: `{}` is handed back as the empty STEAK, which the broadcaster
//! refuses in the same words; the object's entries are walked in
//! `serde_json`'s order (sorted), the reference's in the body's, so of
//! several bad entries the one named can differ; a number past the double
//! range, an array nested past `serde_json`'s 128 levels and a lone
//! surrogate escape are refused as no JSON, where the reference parses them
//! and refuses the value.

use crate::overlay::types::{AdmittanceInstructions, Steak};
use crate::{Error, Result};
use serde_json::{Map, Value};
use std::collections::HashSet;

/// `MAX_SHIP_RESPONSE_BYTES` (`:93`).
const MAX_SHIP_RESPONSE_BYTES: usize = 1024 * 1024;
/// `MAX_SHIP_TOPICS` (`:95`).
const MAX_SHIP_TOPICS: usize = 64;
/// `MAX_SHIP_INSTRUCTION_INDEXES` (`:96`).
const MAX_SHIP_INSTRUCTION_INDEXES: usize = 4096;

fn refusal(words: &str) -> Error {
    Error::OverlayError(words.into())
}

/// The size refusal (`:277`, `:283`, `:297`).
fn too_large() -> Error {
    refusal("SHIP response exceeds the maximum permitted size.")
}

/// `:272-278`: a declared length that is not `0` or digits without a
/// leading zero, or names more than 1 MiB, is refused before the body is
/// read.
fn assert_declared_length(declared: Option<&[u8]>) -> Result<()> {
    let Some(declared) = declared else {
        return Ok(());
    };
    let canonical = declared == b"0"
        || (declared.first().is_some_and(|b| (b'1'..=b'9').contains(b))
            && declared.iter().all(u8::is_ascii_digit));
    // Eight digits already pass 1 MiB (1,048,576)
    let within = canonical
        && declared.len() <= 7
        && std::str::from_utf8(declared)
            .ok()
            .and_then(|text| text.parse::<usize>().ok())
            .is_some_and(|length| length <= MAX_SHIP_RESPONSE_BYTES);
    if within {
        Ok(())
    } else {
        Err(too_large())
    }
}

/// A `/submit` answer as it is read (`readSHIPJSON`, `:271-320`): the
/// declared length judged before any byte, each chunk under the 1 MiB
/// bound, then the STEAK over the topics sent. The facilitator feeds it
/// the response's chunks; never `reqwest`'s `.json()` or `.bytes()`, which
/// buffer a body of any size, `.json()` into a typed STEAK that cannot show
/// what the JSON held.
pub(super) struct Answer(Vec<u8>);

impl Answer {
    /// `:272-278`: the answer whose `Content-Length` is `declared`.
    pub(super) fn declared(declared: Option<&[u8]>) -> Result<Self> {
        assert_declared_length(declared)?;
        Ok(Self(Vec::new()))
    }

    /// `:291-298`: one more chunk, refused where it passes 1 MiB.
    pub(super) fn push(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.len() > MAX_SHIP_RESPONSE_BYTES - self.0.len() {
            return Err(too_large());
        }
        self.0.extend_from_slice(chunk);
        Ok(())
    }

    /// `:311-320` then `:486-496`: the body's STEAK over the topics `sent`.
    pub(super) fn steak(self, sent: &[String]) -> Result<Steak> {
        read_steak(&self.0, sent)
    }
}

/// `:311-320` then `:486-496`: the body's STEAK over the topics `sent`.
/// `TextDecoder` drops one leading BOM (`ignoreBOM` false).
fn read_steak(body: &[u8], sent: &[String]) -> Result<Steak> {
    let text =
        std::str::from_utf8(body).map_err(|_| refusal("SHIP response is not valid UTF-8."))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let value: Value =
        serde_json::from_str(text).map_err(|_| refusal("SHIP response is not valid JSON."))?;
    steak_of_value(&value, sent).map_err(refusal)
}

/// `steak == null || Object.keys(steak).length === 0` (`:486`), then
/// `validateSTEAK(steak, [...topics])` (`:240-269`).
fn steak_of_value(value: &Value, sent: &[String]) -> std::result::Result<Steak, &'static str> {
    const NO_TOPICS: &str = "Steak has no topics.";
    let entries = match value {
        // `Object.keys` of a number or a boolean is empty
        Value::Null | Value::Bool(_) | Value::Number(_) => return Err(NO_TOPICS),
        Value::String(text) if text.is_empty() => return Err(NO_TOPICS),
        Value::Array(items) if items.is_empty() => return Err(NO_TOPICS),
        Value::String(_) | Value::Array(_) => {
            return Err("SHIP response is not a valid STEAK object.")
        }
        Value::Object(entries) => entries,
    };
    if entries.len() > MAX_SHIP_TOPICS {
        return Err("SHIP response contains too many topics.");
    }
    let mut steak = Steak::with_capacity(entries.len());
    for (topic, raw) in entries {
        let instructions = match raw {
            Value::Object(fields) if sent.contains(topic) => fields,
            _ => return Err("SHIP response acknowledged an unexpected topic."),
        };
        if instructions.keys().any(|key| {
            !matches!(
                key.as_str(),
                "outputsToAdmit" | "coinsToRetain" | "coinsRemoved"
            )
        }) {
            return Err("SHIP response contains unexpected instruction fields.");
        }
        steak.insert(
            topic.clone(),
            AdmittanceInstructions {
                outputs_to_admit: indexes(instructions, "outputsToAdmit")?
                    .ok_or("SHIP outputsToAdmit is invalid.")?,
                coins_to_retain: indexes(instructions, "coinsToRetain")?
                    .ok_or("SHIP coinsToRetain is invalid.")?,
                coins_removed: indexes(instructions, "coinsRemoved")?,
            },
        );
    }
    Ok(steak)
}

/// `validateInstructionIndexes(value, label)` (`:222-238`) of the member
/// `label`, `None` when the member is absent (`undefined`; a `null` is a
/// value, and no array): an array of at most 4096 numbers, each an integer
/// from 0 to `0xffffffff` however it is written (`1.0`, `1e2` and `-0` are
/// integers to `Number.isSafeInteger`), none twice.
fn indexes(
    instructions: &Map<String, Value>,
    label: &'static str,
) -> std::result::Result<Option<Vec<u32>>, &'static str> {
    let invalid = match label {
        "outputsToAdmit" => "SHIP outputsToAdmit is invalid.",
        "coinsToRetain" => "SHIP coinsToRetain is invalid.",
        _ => "SHIP coinsRemoved is invalid.",
    };
    let items = match instructions.get(label) {
        None => return Ok(None),
        Some(Value::Array(items)) if items.len() <= MAX_SHIP_INSTRUCTION_INDEXES => items,
        Some(_) => return Err(invalid),
    };
    let mut seen = HashSet::with_capacity(items.len());
    let mut list = Vec::with_capacity(items.len());
    for item in items {
        let index = item.as_number().and_then(index_of).ok_or(invalid)?;
        if !seen.insert(index) {
            return Err(invalid);
        }
        list.push(index);
    }
    Ok(Some(list))
}

/// A JSON number as an index: an integer from 0 to `0xffffffff`.
fn index_of(number: &serde_json::Number) -> Option<u32> {
    if let Some(whole) = number.as_u64() {
        return u32::try_from(whole).ok();
    }
    let float = number.as_f64()?;
    // `-0` is 0 (`SameValueZero` in the reference's `Set`)
    (float.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&float)).then_some(float as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(result: Result<Steak>) -> String {
        match result {
            Err(Error::OverlayError(words)) => words,
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn a_declared_length_is_canonical_digits_within_one_mib_815() {
        for taken in [None, Some("0"), Some("5"), Some("1048576")] {
            assert_eq!(assert_declared_length(taken.map(str::as_bytes)), Ok(()));
        }
        for refused in [
            "1048577",
            "05",
            "+5",
            " 5",
            "5 ",
            "",
            "-1",
            "1e3",
            "5, 5",
            "99999999999999999999999",
        ] {
            assert_eq!(
                assert_declared_length(Some(refused.as_bytes())),
                Err(too_large()),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn an_instruction_field_other_than_the_three_is_refused_815() {
        let sent = ["tm_a".to_string()];
        let body = br#"{"tm_a":{"outputsToAdmit":[0],"coinsToRetain":[],"extra":1}}"#;
        assert_eq!(
            words(read_steak(body, &sent)),
            "SHIP response contains unexpected instruction fields."
        );
        let body = br#"{"tm_a":{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[1]}}"#;
        let steak = read_steak(body, &sent).unwrap();
        assert_eq!(steak["tm_a"].coins_removed, Some(vec![1]));
    }

    #[test]
    fn an_index_is_an_integer_however_it_is_written_815() {
        let sent = ["tm_a".to_string()];
        let body = br#"{"tm_a":{"outputsToAdmit":[1.0,2e0,-0,4294967295],"coinsToRetain":[]}}"#;
        let steak = read_steak(body, &sent).unwrap();
        assert_eq!(steak["tm_a"].outputs_to_admit, vec![1, 2, 0, u32::MAX]);
        for list in [
            "[0.5]",
            "[-1]",
            "[4294967296]",
            "[0,-0]",
            "[1,1.0]",
            "null",
            "[\"0\"]",
        ] {
            let body = format!(r#"{{"tm_a":{{"outputsToAdmit":{list},"coinsToRetain":[]}}}}"#);
            assert_eq!(
                words(read_steak(body.as_bytes(), &sent)),
                "SHIP outputsToAdmit is invalid.",
                "{list}"
            );
        }
    }
}
