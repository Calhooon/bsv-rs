//! A lookup answer's body read as the reference reads it (#815;
//! `ts-stack@edf6e03` `packages/sdk/src/overlay-tools/`):
//!
//! - the content type (`LookupResolver.ts:512-516`, `isOctetStream`): the
//!   text before the earliest `;`, trimmed by ECMAScript's `trim` set
//!   (`trim_js`, which keeps U+0085 and takes U+FEFF) and lower-cased, equal to
//!   `application/octet-stream`; where this crate asked whether the case-kept
//!   text contained `octet-stream`;
//! - the declared length (`LookupResponseReader.ts:27-35`,
//!   `assertDeclaredLengthIsWithinLimit`): the text trimmed by the same set,
//!   digits alone,
//!   else no length; digits past `2^53 - 1` or past the bound refused
//!   `maxResponseBytes`; where this crate read it by `u64`'s parser (a sign
//!   read as a number, 21 digits as no length);
//! - the JSON body (`LookupResolver.ts:847-854`): `TextDecoder('utf-8',
//!   { fatal: true })`, which drops one leading U+FEFF and refuses bytes
//!   that are not UTF-8 (`Overlay response is not valid UTF-8.`), then
//!   `JSON.parse`; where a leading BOM failed the parse here;
//! - and, hardening with no reference twin, the output count judged before
//!   the tree is built: a counting pass reads the top-level `type` and the
//!   length of `outputs` (the last of a repeated key, as `Value` keeps it),
//!   every value checked as `Value`'s reader checks it (its depth, its
//!   strings, its numbers) and none held, and refuses only where the tree
//!   path refuses for the count, in its order and words (`maxOutputs` past
//!   the configured count, then the normalizer's 4096); every other body
//!   goes to the tree path unchanged. A 32 MiB body of `0,` items was about
//!   512 MiB of `Value` before its count was read.
//!
//! Header bytes are read as `fetch` reads them, one character per byte.

use super::parse_json_lookup_answer;
use crate::overlay::lookup_limits::{normalized_output_count, resource_limit};
use crate::overlay::LookupAnswer;
use crate::wallet::validation::trim_js;
use crate::{Error, Result};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

/// The scalar arms of a visitor that reads everything but a map or an
/// array as `$value`.
macro_rules! not_object {
    ($value:expr) => {
        fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
            Ok($value)
        }
    };
}

/// A header value as `Headers.get` hands it to the reference: each byte one
/// character (a `ByteString`).
pub(super) fn header_text(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// `isOctetStream(contentType)` (`LookupResolver.ts:512-516`), the base
/// type trimmed by ECMAScript's `trim` set (`trim_js`: U+0085 kept, as a
/// type ending in byte `0x85` keeps it there; #815's second fold).
pub(super) fn is_octet_stream(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let base = content_type.split(';').next().unwrap_or("");
    trim_js(base).to_lowercase() == "application/octet-stream"
}

/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// `assertDeclaredLengthIsWithinLimit` (`LookupResponseReader.ts:23-36`):
/// no header, or a trimmed text that is not digits alone (`/^\d+$/`), is no
/// length; digits whose value is not a safe integer, or is past `max`, are
/// refused `maxResponseBytes`.
pub(super) fn assert_declared_length(content_length: Option<&str>, max: usize) -> Result<()> {
    let Some(text) = content_length else {
        return Ok(());
    };
    let digits = trim_js(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(());
    }
    // `Number(normalized)`: leading zeros read as nothing; more than 16
    // significant digits is past 2^53 - 1 (16 digits), so never safe.
    let significant = digits.trim_start_matches('0');
    let safe = significant.len() <= 16
        && significant
            .parse::<u64>()
            .map_or(significant.is_empty(), |v| v <= MAX_SAFE_INTEGER);
    let value = significant.parse::<u64>().unwrap_or(0);
    if !safe || value > max as u64 {
        return Err(resource_limit("maxResponseBytes"));
    }
    Ok(())
}

/// The JSON path (`LookupResolver.ts:847-854`, then the facilitator's count
/// and the normalizer, `:856-867`): strict UTF-8 with one leading BOM
/// dropped, the counting pass, then the tree.
pub(super) fn read_json_answer(payload: &[u8], max_outputs: usize) -> Result<LookupAnswer> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| Error::OverlayError("Overlay response is not valid UTF-8.".into()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    count_before_tree(text, max_outputs)?;
    tree_path(text, max_outputs)
}

/// The tree path: the whole body a `Value`, then `parse_json_lookup_answer`.
fn tree_path(text: &str, max_outputs: usize) -> Result<LookupAnswer> {
    #[cfg(test)]
    TREE_BUILDS.with(|n| n.set(n.get() + 1));
    let json: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| Error::OverlayError(format!("Failed to parse JSON: {}", e)))?;
    parse_json_lookup_answer(json, max_outputs)
}

#[cfg(test)]
thread_local! {
    /// Tree builds on this thread (the unit tests' witness).
    static TREE_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The counting pass: `Err` only where the tree path refuses for the count
/// (a top-level object whose last `type` is the string `output-list` and
/// whose last `outputs` is an array, every byte of the body one `Value`'s
/// reader reads), in the tree path's order and words; `Ok` otherwise, the
/// tree path to judge.
fn count_before_tree(text: &str, max_outputs: usize) -> Result<()> {
    let Ok(Shape::Object {
        output_list: true,
        outputs: Some(count),
    }) = serde_json::from_str::<Shape>(text)
    else {
        return Ok(());
    };
    if count > max_outputs {
        return Err(resource_limit("maxOutputs"));
    }
    normalized_output_count(count)
}

/// What the counting pass keeps of a body.
enum Shape {
    NotObject,
    Object {
        /// The last `type` member is the string `output-list`.
        output_list: bool,
        /// The last `outputs` member's length when it is an array.
        outputs: Option<usize>,
    },
}

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ShapeVisitor;
        impl<'de> Visitor<'de> for ShapeVisitor {
            type Value = Shape;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Shape, A::Error> {
                let mut output_list = false;
                let mut outputs = None;
                while let Some(key) = map.next_key::<Key>()? {
                    match key {
                        Key::Type => output_list = map.next_value::<TypeMember>()?.0,
                        Key::Outputs => outputs = map.next_value::<OutputsMember>()?.0,
                        Key::Other => {
                            map.next_value::<Checked>()?;
                        }
                    }
                }
                Ok(Shape::Object {
                    output_list,
                    outputs,
                })
            }
            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<Shape, A::Error> {
                CheckedVisitor.visit_seq(seq).map(|()| Shape::NotObject)
            }
            not_object!(Shape::NotObject);
        }
        deserializer.deserialize_any(ShapeVisitor)
    }
}

/// A top-level member's name, the two the count reads by name.
enum Key {
    Type,
    Outputs,
    Other,
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = Key;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a member name")
            }
            fn visit_str<E>(self, name: &str) -> std::result::Result<Key, E> {
                Ok(match name {
                    "type" => Key::Type,
                    "outputs" => Key::Outputs,
                    _ => Key::Other,
                })
            }
        }
        deserializer.deserialize_str(KeyVisitor)
    }
}

/// The `type` member: whether it is the string `output-list`.
struct TypeMember(bool);

impl<'de> Deserialize<'de> for TypeMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct TypeVisitor;
        impl<'de> Visitor<'de> for TypeVisitor {
            type Value = TypeMember;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_str<E>(self, text: &str) -> std::result::Result<TypeMember, E> {
                Ok(TypeMember(text == "output-list"))
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<TypeMember, E> {
                Ok(TypeMember(false))
            }
            fn visit_i64<E>(self, _: i64) -> std::result::Result<TypeMember, E> {
                Ok(TypeMember(false))
            }
            fn visit_u64<E>(self, _: u64) -> std::result::Result<TypeMember, E> {
                Ok(TypeMember(false))
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<TypeMember, E> {
                Ok(TypeMember(false))
            }
            fn visit_unit<E>(self) -> std::result::Result<TypeMember, E> {
                Ok(TypeMember(false))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                seq: A,
            ) -> std::result::Result<TypeMember, A::Error> {
                CheckedVisitor.visit_seq(seq).map(|()| TypeMember(false))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<TypeMember, A::Error> {
                CheckedVisitor.visit_map(map).map(|()| TypeMember(false))
            }
        }
        deserializer.deserialize_any(TypeVisitor)
    }
}

/// The `outputs` member: its length when it is an array, each item read
/// as `Value` reads it and dropped.
struct OutputsMember(Option<usize>);

impl<'de> Deserialize<'de> for OutputsMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct OutputsVisitor;
        impl<'de> Visitor<'de> for OutputsVisitor {
            type Value = OutputsMember;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<OutputsMember, A::Error> {
                let mut count = 0usize;
                while seq.next_element::<Checked>()?.is_some() {
                    count += 1;
                }
                Ok(OutputsMember(Some(count)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<OutputsMember, A::Error> {
                CheckedVisitor.visit_map(map).map(|()| OutputsMember(None))
            }
            not_object!(OutputsMember(None));
        }
        deserializer.deserialize_any(OutputsVisitor)
    }
}

/// Any value, read through `deserialize_any` as `Value`'s `Deserialize`
/// reads it (so its depth, strings and numbers are checked alike) and
/// held as nothing. serde's `IgnoredAny` is not enough: serde_json skips it without
/// the depth limit or the string checks `Value` makes.
struct Checked;

struct CheckedVisitor;

impl<'de> Visitor<'de> for CheckedVisitor {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while seq.next_element::<Checked>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while map.next_key::<IgnoredKey>()?.is_some() {
            map.next_value::<Checked>()?;
        }
        Ok(())
    }
    not_object!(());
}

impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer
            .deserialize_any(CheckedVisitor)
            .map(|()| Checked)
    }
}

/// A member name read as `Value` reads one (a string, its escapes checked)
/// and dropped.
struct IgnoredKey;

impl<'de> Deserialize<'de> for IgnoredKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = IgnoredKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a member name")
            }
            fn visit_str<E>(self, _: &str) -> std::result::Result<IgnoredKey, E> {
                Ok(IgnoredKey)
            }
        }
        deserializer.deserialize_str(KeyVisitor)
    }
}

#[cfg(test)]
#[path = "answer_body_tests.rs"]
mod tests;
