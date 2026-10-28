//! The requestedCertificates preimage: JSON.stringify(JSON.parse(text)),
//! as ts-stack@edf6e03 Peer.ts:1068 does (#426). This body is byte-compared
//! (#400), so neither a sorted Value nor the typed set (which drops extra
//! properties) can represent it. Objects keep insertion order, except JS
//! array-index keys, and duplicate names replace the value in its first slot.

use std::{fmt::Write as _, iter::Peekable, str::Chars};

use indexmap::IndexMap;
use serde_json::value::RawValue;

// Child indexes make both parsing and dropping deeply nested data iterative.
enum Node {
    Scalar(String),
    Array(Vec<usize>),
    Object(IndexMap<Vec<u16>, usize>),
}

enum Frame {
    Array(Vec<usize>),
    Object(IndexMap<Vec<u16>, usize>, Option<Vec<u16>>),
}

impl Frame {
    fn push(&mut self, value: usize) {
        match self {
            Self::Array(values) => values.push(value),
            Self::Object(values, key) => {
                if let Some(key) = key.take() {
                    values.insert(key, value);
                }
            }
        }
    }

    fn finish(self) -> Node {
        match self {
            Self::Array(values) => Node::Array(values),
            Self::Object(values, _) => Node::Object(values),
        }
    }
}

enum Write<'a> {
    Node(usize),
    Key(&'a [u16]),
    Text(&'static str),
}

fn stringify_valid(text: &str) -> Option<String> {
    let nodes = parse(text)?;
    let mut pending = vec![Write::Node(nodes.len().checked_sub(1)?)];
    let mut output = String::with_capacity(text.len());
    while let Some(next) = pending.pop() {
        match next {
            Write::Text(text) => output.push_str(text),
            Write::Key(key) => output.push_str(&quote(key)),
            Write::Node(index) => match nodes.get(index)? {
                Node::Scalar(text) => output.push_str(text),
                Node::Array(values) => {
                    output.push('[');
                    pending.push(Write::Text("]"));
                    for (i, value) in values.iter().enumerate().rev() {
                        pending.push(Write::Node(*value));
                        if i != 0 {
                            pending.push(Write::Text(","));
                        }
                    }
                }
                Node::Object(values) => {
                    output.push('{');
                    enqueue_object(values, &mut pending);
                }
            },
        }
    }
    Some(output)
}

fn enqueue_object<'a>(values: &'a IndexMap<Vec<u16>, usize>, pending: &mut Vec<Write<'a>>) {
    let mut entries: Vec<_> = values.iter().collect();
    // Stable sorting leaves non-index names in their insertion order.
    entries.sort_by_cached_key(|(key, _)| array_index(key).map_or((1, 0), |index| (0, index)));
    pending.push(Write::Text("}"));
    for (i, (key, value)) in entries.into_iter().enumerate().rev() {
        pending.push(Write::Node(*value));
        pending.push(Write::Text(":"));
        pending.push(Write::Key(key));
        if i != 0 {
            pending.push(Write::Text(","));
        }
    }
}

fn array_index(key: &[u16]) -> Option<u32> {
    let text = String::from_utf16(key).ok()?;
    let index: u32 = text.parse().ok()?;
    (index != u32::MAX && index.to_string() == text).then_some(index)
}

/// `RawValue` has already checked the grammar. Parse on a heap stack, retaining
/// UTF-16 (including lone surrogates) and every property before stringifying.
pub(super) fn stringify(raw: &RawValue) -> Vec<u8> {
    stringify_valid(raw.get()).unwrap_or_default().into_bytes()
}

fn parse(text: &str) -> Option<Vec<Node>> {
    let mut nodes = Vec::new();
    let mut chars = text.chars().peekable();
    let mut frames = Vec::new();
    while let Some(ch) = chars.next() {
        let value = match ch {
            '{' => {
                frames.push(Frame::Object(IndexMap::new(), None));
                continue;
            }
            '[' => {
                frames.push(Frame::Array(Vec::new()));
                continue;
            }
            '}' | ']' => frames.pop()?.finish(),
            '"' => {
                let value = read_string(&mut chars)?;
                if let Some(Frame::Object(_, key @ None)) = frames.last_mut() {
                    *key = Some(value);
                    continue;
                }
                Node::Scalar(quote(&value))
            }
            ':' | ',' | ' ' | '\t' | '\r' | '\n' => continue,
            _ => Node::Scalar(scalar(ch, &mut chars)?),
        };
        let index = nodes.len();
        nodes.push(value);
        match frames.last_mut() {
            Some(frame) => frame.push(index),
            None => return Some(nodes),
        }
    }
    None
}

fn scalar(first: char, chars: &mut Peekable<Chars<'_>>) -> Option<String> {
    let mut text = String::from(first);
    while let Some(ch) = chars.peek() {
        if matches!(ch, ',' | ']' | '}' | ' ' | '\t' | '\r' | '\n') {
            break;
        }
        text.push(chars.next()?);
    }
    match first {
        't' | 'f' | 'n' => Some(text),
        _ => {
            let value: f64 = text.parse().ok()?;
            if value.is_finite() {
                Some(ryu_js::Buffer::new().format_finite(value).to_owned())
            } else {
                Some("null".into())
            }
        }
    }
}

fn read_string(chars: &mut Peekable<Chars<'_>>) -> Option<Vec<u16>> {
    let mut units = Vec::new();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Some(units),
            '\\' => units.push(match chars.next()? {
                'u' => {
                    let mut unit = 0;
                    for _ in 0..4 {
                        unit = unit * 16 + u16::try_from(chars.next()?.to_digit(16)?).ok()?;
                    }
                    unit
                }
                'b' => 8,
                'f' => 12,
                'n' => 10,
                'r' => 13,
                't' => 9,
                '"' => 34,
                '/' => 47,
                '\\' => 92,
                _ => return None, // RawValue already validated the escape.
            }),
            ch => units.extend_from_slice(ch.encode_utf16(&mut [0; 2])),
        }
    }
    None
}

fn quote(units: &[u16]) -> String {
    let mut text = String::from('"');
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Err(surrogate) => {
                let _ = write!(text, "\\u{:04x}", surrogate.unpaired_surrogate());
            }
            Ok(ch) => match ch {
                '"' => text.push_str("\\\""),
                '\\' => text.push_str("\\\\"),
                '\u{08}' => text.push_str("\\b"),
                '\u{0c}' => text.push_str("\\f"),
                '\n' => text.push_str("\\n"),
                '\r' => text.push_str("\\r"),
                '\t' => text.push_str("\\t"),
                '\u{00}'..='\u{1f}' => {
                    let _ = write!(text, "\\u{:04x}", u32::from(ch));
                }
                ch => text.push(ch),
            },
        }
    }
    text.push('"');
    text
}
