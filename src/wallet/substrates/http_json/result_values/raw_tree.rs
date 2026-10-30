//! A flat index of a syntactically checked JSON body. Descendants are scanned
//! once, never reparsed through each ancestor. Arrays keep only container
//! children and byte statistics, not an allocation for every scalar byte.

use super::{boundary::unsafe_key, invalid, key_order, Result};
use indexmap::IndexMap;
use num_traits::ToPrimitive;
use serde_json::value::RawValue;
use std::ops::Range;

const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;

enum Member<'a> {
    Scalar(&'a str),
    Container(usize),
}

enum Kind<'a> {
    Array {
        length: usize,
        bytes: bool,
        children: Vec<usize>,
    },
    Object(IndexMap<String, Member<'a>>),
}

struct Node<'a> {
    range: Range<usize>,
    kind: Kind<'a>,
    keys_valid: bool,
}

#[derive(Default)]
struct Walk {
    nodes: usize,
    copied: usize,
    pending: Vec<usize>,
}

struct Frame<'a> {
    start: usize,
    kind: Kind<'a>,
    key: Option<String>,
    keys_valid: bool,
}

impl<'a> Frame<'a> {
    fn new(start: usize, opener: u8) -> Self {
        Self {
            start,
            kind: if opener == b'{' {
                Kind::Object(IndexMap::new())
            } else {
                Kind::Array {
                    length: 0,
                    bytes: true,
                    children: Vec::new(),
                }
            },
            key: None,
            keys_valid: true,
        }
    }

    fn finish(mut self, end: usize) -> Node<'a> {
        if let Kind::Object(fields) = &mut self.kind {
            fields.sort_by(|a, _, b, _| key_order(a).cmp(&key_order(b)));
        }
        Node {
            range: self.start..end,
            kind: self.kind,
            keys_valid: self.keys_valid,
        }
    }

    fn capture_key(&mut self, token: &str) -> bool {
        if !matches!(self.kind, Kind::Object(_)) || self.key.is_some() {
            return false;
        }
        // Defer the representation residue until this object is visited.
        self.key = Some(serde_json::from_str(token).unwrap_or_else(|_| {
            self.keys_valid = false;
            token.to_owned()
        }));
        true
    }

    fn push(&mut self, member: Member<'a>) {
        match &mut self.kind {
            Kind::Array {
                length,
                bytes,
                children,
            } => {
                *length += 1;
                *bytes &= matches!(&member, Member::Scalar(text) if is_byte(text));
                if let Member::Container(index) = member {
                    children.push(index);
                }
            }
            Kind::Object(fields) => {
                if let Some(key) = self.key.take() {
                    fields.insert(key, member);
                }
            }
        }
    }
}

enum Part<'a> {
    Node(usize, bool),
    Raw(&'a str),
    Key(&'a str),
    Text(&'static str),
}

pub(in crate::wallet::substrates::http_json) struct Snapshot<'a> {
    text: &'a str,
    // Children are indices, so even destruction has no recursive stack use.
    nodes: Vec<Node<'a>>,
}

fn is_byte(text: &str) -> bool {
    text.parse::<f64>()
        .is_ok_and(|n| n.fract() == 0.0 && (0.0..=255.0).contains(&n))
}

fn token_end(text: &[u8], start: usize) -> usize {
    let mut end = start + 1;
    if text.get(start) == Some(&b'"') {
        while let Some(byte) = text.get(end) {
            end += 1;
            match byte {
                b'"' => break,
                b'\\' => end += 1,
                _ => {}
            }
        }
    } else {
        while text.get(end).is_some_and(|b| !b",]} \t\r\n".contains(b)) {
            end += 1;
        }
    }
    end
}

impl<'a> Snapshot<'a> {
    pub(super) fn read(raw: &'a RawValue, call: &str) -> Result<Self> {
        let text = raw.get();
        let mut nodes = Vec::new();
        let mut frames: Vec<Frame<'a>> = Vec::new();
        let mut offset = 0;
        while let Some(byte) = text.as_bytes().get(offset) {
            let member = match byte {
                b'{' | b'[' => {
                    frames.push(Frame::new(offset, *byte));
                    offset += 1;
                    continue;
                }
                b'}' | b']' => {
                    let frame = frames
                        .pop()
                        .ok_or_else(|| invalid(call, "value", "an object"))?;
                    let index = nodes.len();
                    nodes.push(frame.finish(offset + 1));
                    offset += 1;
                    Member::Container(index)
                }
                b':' | b',' | b' ' | b'\n' | b'\r' | b'\t' => {
                    offset += 1;
                    continue;
                }
                _ => {
                    let end = token_end(text.as_bytes(), offset);
                    let token = &text[offset..end];
                    offset = end;
                    if frames
                        .last_mut()
                        .is_some_and(|frame| frame.capture_key(token))
                    {
                        continue;
                    }
                    Member::Scalar(token)
                }
            };
            if let Some(frame) = frames.last_mut() {
                frame.push(member);
            }
        }
        let snapshot = Self { text, nodes };
        snapshot.check(call)?;
        Ok(snapshot)
    }

    fn bytes(&self, index: usize, historical: bool) -> Option<usize> {
        if !self.nodes[index].keys_valid {
            return None;
        }
        match &self.nodes[index].kind {
            Kind::Array {
                length,
                bytes: true,
                ..
            } => Some(*length),
            Kind::Object(fields) if historical && !fields.is_empty() => fields
                .iter()
                .enumerate()
                .all(|(i, (key, value))| {
                    key == &i.to_string() && matches!(value, Member::Scalar(text) if is_byte(text))
                })
                .then_some(fields.len()),
            _ => None,
        }
    }

    fn check(&self, call: &str) -> Result<()> {
        let Some(root) = self.nodes.len().checked_sub(1) else {
            return Ok(());
        };
        let mut walk = Walk::default();
        self.visit(root, false, call, &mut walk)?;
        while let Some(index) = walk.pending.pop() {
            if !self.nodes[index].keys_valid {
                return Err(invalid(call, "value", "an object"));
            }
            match &self.nodes[index].kind {
                Kind::Array {
                    length, children, ..
                } => {
                    walk.nodes += length + 1;
                    check_nodes(walk.nodes, MAX_NODES + 2, call)?;
                    for child in children {
                        self.visit(*child, false, call, &mut walk)?;
                    }
                }
                Kind::Object(fields) => {
                    walk.nodes += fields.len();
                    check_nodes(walk.nodes, MAX_NODES + 2, call)?;
                    for (key, member) in fields {
                        if unsafe_key(key) {
                            return Err(invalid(
                                call,
                                &format!("object key {key}"),
                                "a safe record key",
                            ));
                        }
                        if let Member::Container(child) = member {
                            self.visit(*child, historical_field(key), call, &mut walk)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn visit(&self, index: usize, historical: bool, call: &str, walk: &mut Walk) -> Result<()> {
        walk.nodes += 1;
        check_nodes(walk.nodes, MAX_NODES, call)?;
        if let Some(length) = self.bytes(index, historical).filter(|n| *n <= MAX_BYTES) {
            walk.copied += length;
            if walk.copied > MAX_BYTES {
                return Err(invalid(
                    call,
                    "byte arrays",
                    "at most 268435456 total bytes",
                ));
            }
        } else {
            if matches!(&self.nodes[index].kind, Kind::Array { length, .. } if *length > MAX_NODES)
            {
                return Err(invalid(call, "array length", "at most 1000000 entries"));
            }
            walk.pending.push(index);
        }
        Ok(())
    }

    /// Normalize only token spellings and historical bytes. Ignored values stay
    /// raw: Infinity and arbitrary JSON depth need no serde Value representation.
    pub(in crate::wallet::substrates::http_json) fn normalized(&self) -> String {
        let Some(root) = self.nodes.len().checked_sub(1) else {
            return self.text.to_owned();
        };
        let mut reference = Vec::new();
        self.reference_edit(&mut reference);
        let mut pending = vec![Part::Node(root, false)];
        let mut output = String::with_capacity(self.text.len());
        while let Some(part) = pending.pop() {
            match part {
                Part::Text(text) => output.push_str(text),
                Part::Key(key) => output.push_str(&serde_json::to_string(key).unwrap_or_default()),
                Part::Raw(text) => self.write_raw(text, &reference, &mut output),
                Part::Node(index, historical) => {
                    self.enqueue(index, historical, &mut pending, &mut output)
                }
            }
        }
        output
    }

    fn enqueue<'b>(
        &'b self,
        index: usize,
        historical: bool,
        pending: &mut Vec<Part<'b>>,
        output: &mut String,
    ) {
        let node = &self.nodes[index];
        match &node.kind {
            Kind::Object(fields) if historical && self.bytes(index, true).is_some() => {
                let values: Vec<_> = fields
                    .values()
                    .filter_map(|v| match v {
                        Member::Scalar(text) => text.parse::<f64>().ok().and_then(|n| n.to_u8()),
                        _ => None,
                    })
                    .collect();
                output.push_str(&format!("{values:?}"));
            }
            Kind::Object(fields) => {
                output.push('{');
                Self::object_parts(fields, pending);
            }
            Kind::Array { children, .. } => {
                output.push('[');
                pending.push(Part::Text("]"));
                let mut end = node.range.end - 1;
                for child in children.iter().rev() {
                    let child_node = &self.nodes[*child];
                    pending.push(Part::Raw(&self.text[child_node.range.end..end]));
                    pending.push(Part::Node(*child, false));
                    end = child_node.range.start;
                }
                pending.push(Part::Raw(&self.text[node.range.start + 1..end]));
            }
        }
    }

    fn object_parts<'b>(fields: &'b IndexMap<String, Member<'a>>, pending: &mut Vec<Part<'b>>) {
        pending.push(Part::Text("}"));
        // The final value stays in the original key slot, as in JSON.parse.
        for (position, (key, value)) in fields.iter().enumerate().rev() {
            pending.push(match value {
                Member::Scalar(text) => Part::Raw(text),
                Member::Container(child) => Part::Node(*child, historical_field(key)),
            });
            pending.push(Part::Text(":"));
            pending.push(Part::Key(key));
            if position != 0 {
                pending.push(Part::Text(","));
            }
        }
    }

    fn write_raw(&self, text: &str, reference: &[(Range<usize>, String)], output: &mut String) {
        let start = text.as_ptr() as usize - self.text.as_ptr() as usize;
        if let Some((_, value)) = reference
            .iter()
            .find(|(range, _)| range.start == start && range.len() == text.len())
        {
            output.push_str(value);
            return;
        }
        let mut offset = 0;
        while let Some(byte) = text.as_bytes().get(offset) {
            if matches!(byte, b'"' | b'-' | b'0'..=b'9') {
                let end = token_end(text.as_bytes(), offset);
                let token = &text[offset..end];
                if let Some(integer) = integer_token(token) {
                    output.push_str(&integer);
                } else {
                    output.push_str(token);
                }
                offset = end;
            } else {
                output.push(char::from(*byte));
                offset += 1;
            }
        }
    }

    fn reference_edit(&self, edits: &mut Vec<(Range<usize>, String)>) {
        use base64::{engine::general_purpose, Engine};
        let Some(Node {
            kind: Kind::Object(root),
            ..
        }) = self.nodes.last()
        else {
            return;
        };
        let Some(Member::Container(index)) = root.get("signableTransaction") else {
            return;
        };
        let Kind::Object(fields) = &self.nodes[*index].kind else {
            return;
        };
        let Some(Member::Scalar(raw)) = fields.get("reference") else {
            return;
        };
        let engine = general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        );
        let Some(bytes) = serde_json::from_str::<String>(raw)
            .ok()
            .and_then(|s| engine.decode(s).ok())
        else {
            return;
        };
        let start = raw.as_ptr() as usize - self.text.as_ptr() as usize;
        edits.push((
            start..start + raw.len(),
            format!("\"{}\"", general_purpose::STANDARD.encode(bytes)),
        ));
    }
}

fn check_nodes(nodes: usize, limit: usize, call: &str) -> Result<()> {
    if nodes > limit {
        return Err(invalid(call, "object graph", "a bounded result"));
    }
    Ok(())
}

fn historical_field(name: &str) -> bool {
    matches!(
        name,
        "BEEF"
            | "atomicBEEF"
            | "beef"
            | "ciphertext"
            | "competingBeef"
            | "data"
            | "encryptedLinkage"
            | "encryptedLinkageProof"
            | "hashToDirectlySign"
            | "hashToDirectlyVerify"
            | "hmac"
            | "inputBEEF"
            | "payload"
            | "plaintext"
            | "signature"
            | "transaction"
            | "tx"
    )
}

fn integer_token(token: &str) -> Option<String> {
    if token != "-0" && !token.contains(['.', 'e', 'E']) {
        return None;
    }
    let number: f64 = token.parse().ok()?;
    if number.fract() != 0.0 {
        return None;
    }
    number
        .to_i64()
        .map(|n| n.to_string())
        .or_else(|| number.to_u64().map(|n| n.to_string()))
}
