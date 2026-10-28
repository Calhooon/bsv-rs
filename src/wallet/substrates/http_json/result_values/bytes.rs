//! `bytes` (`WalletResultValidation.ts:868-906`), without a Value per byte
//! on the ordinary array path. The historical object path is #365's reader.

use super::{invalid, Result};
use crate::wallet::substrates::http_json::byte_fields;
use num_traits::ToPrimitive;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

pub(super) fn read(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    exact: Option<usize>,
    maximum: Option<usize>,
) -> Result<Vec<u8>> {
    let maximum = maximum.unwrap_or(byte_fields::MAX_BYTES);
    let raw = raw.ok_or_else(|| invalid(call, field, "an array of bytes"))?;
    let checked =
        ByteArray(maximum).deserialize(&mut serde_json::Deserializer::from_str(raw.get()));
    let bytes = match checked {
        Ok((_, length)) if length > maximum => {
            return Err(invalid(call, field, &format!("at most {maximum} bytes")));
        }
        Ok((Some(bytes), _)) => Some(bytes),
        _ => serde_json::from_str(raw.get())
            .ok()
            .and_then(|value| byte_fields::byte_array(&value)),
    }
    .ok_or_else(|| invalid(call, field, "an array of bytes"))?;
    if bytes.len() > maximum {
        return Err(invalid(call, field, &format!("at most {maximum} bytes")));
    }
    if exact.is_some_and(|length| bytes.len() != length) {
        return Err(invalid(
            call,
            field,
            &format!("{} bytes", exact.unwrap_or(0)),
        ));
    }
    Ok(bytes)
}

struct ByteArray(usize);

impl<'de> DeserializeSeed<'de> for ByteArray {
    type Value = (Option<Vec<u8>>, usize);

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ByteArray {
    type Value = (Option<Vec<u8>>, usize);

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of bytes")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut bytes = Some(Vec::new());
        let mut length = 0;
        while let Some(raw) = sequence.next_element::<&RawValue>()? {
            length += 1;
            if length > self.0 {
                continue;
            }
            let number = serde_json::from_str::<f64>(raw.get()).ok();
            let byte = number
                .filter(|n| (0.0..=255.0).contains(n) && n.fract() == 0.0)
                .and_then(|n| n.to_u8());
            match (&mut bytes, byte) {
                (Some(bytes), Some(n)) => bytes.push(n),
                _ => bytes = None,
            }
        }
        Ok((bytes, length))
    }
}
