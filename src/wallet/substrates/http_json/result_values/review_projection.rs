//! Materialize only the finite-depth code-5 schema, skipping extensions on raw
//! JSON at every record. Scalar type errors stay errors without walking a
//! malformed field's arbitrary descendants into serde Value.

use super::Object;
use serde_json::{value::RawValue, Value};

pub(in crate::wallet::substrates) fn body(text: &str) -> Option<Value> {
    let raw = serde_json::from_str(text).ok()?;
    project(raw, Shape::Envelope)
}

#[derive(Clone, Copy)]
enum Shape {
    Scalar,
    Bytes,
    Strings,
    Envelope,
    Sends,
    Reviews,
    Send,
    Review,
}

impl Shape {
    fn fields(self) -> &'static [(&'static str, Self)] {
        match self {
            Shape::Envelope => &[
                ("isError", Shape::Scalar),
                ("code", Shape::Scalar),
                ("message", Shape::Scalar),
                ("txid", Shape::Scalar),
                ("tx", Shape::Bytes),
                ("noSendChange", Shape::Strings),
                ("sendWithResults", Shape::Sends),
                ("reviewActionResults", Shape::Reviews),
            ],
            Shape::Send => &[("txid", Shape::Scalar), ("status", Shape::Scalar)],
            Shape::Review => &[
                ("txid", Shape::Scalar),
                ("status", Shape::Scalar),
                ("competingTxs", Shape::Strings),
                ("competingBeef", Shape::Bytes),
            ],
            _ => &[],
        }
    }
}

fn project(raw: &RawValue, shape: Shape) -> Option<Value> {
    let text = raw.get();
    if text.starts_with('{') {
        let object: Object<'_> = serde_json::from_str(text).ok()?;
        let mut result = serde_json::Map::new();
        if matches!(shape, Shape::Bytes) {
            for (key, value) in object {
                result.insert(key, project(value, Shape::Scalar)?);
            }
        } else {
            for (key, shape) in shape.fields() {
                if let Some(value) = object.get(*key) {
                    result.insert((*key).into(), project(value, *shape)?);
                }
            }
        }
        return Some(Value::Object(result));
    }
    if text.starts_with('[') {
        let element = match shape {
            Shape::Sends => Shape::Send,
            Shape::Reviews => Shape::Review,
            Shape::Strings | Shape::Bytes => Shape::Scalar,
            _ => return Some(Value::Array(Vec::new())),
        };
        let items: Vec<&RawValue> = serde_json::from_str(text).ok()?;
        return items
            .into_iter()
            .map(|v| project(v, element))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array);
    }
    // Nonfinite numbers cannot satisfy any scalar error predicate. Null has
    // the same rejection there; strings retain their representation residue.
    serde_json::from_str(text).ok().or_else(|| {
        text.as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_digit() || *b == b'-')
            .then_some(Value::Null)
    })
}
