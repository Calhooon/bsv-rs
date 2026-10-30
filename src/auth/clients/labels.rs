//! The reference's permissive base64-to-hex payment labels, without changing wire nonces.

use super::{auth_fetch::AuthFetchOptions, response::words};
use crate::Result;

/// ECMAScript String.trim, including BOM and excluding NEL.
pub(super) fn trim(text: &str) -> &str {
    text.trim_matches(|c| matches!(c, '\u{0009}'..='\u{000d}' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'))
}

impl AuthFetchOptions {
    /// Builds the BRC-105 wallet labels, preserving caller labels unchanged.
    /// Base64 normalization and refusal words match the reference's label helper;
    /// this conversion does not validate or alter either nonce on the wire.
    ///
    /// # Errors
    /// Refuses invalid base64 characters or padding with the reference texts.
    pub fn payment_labels(
        &self,
        derivation_prefix: &str,
        derivation_suffix: &str,
    ) -> Result<Vec<String>> {
        let mut labels = vec![format!(
            "brc105 {} {}",
            label_hex(derivation_prefix)?,
            label_hex(derivation_suffix)?
        )];
        labels.extend(self.labels.clone());
        Ok(labels)
    }
}

fn label_hex(text: &str) -> Result<String> {
    let normalized: String = trim(text)
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\t' | '\u{000c}' | '\u{000b}' | ' '))
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    let data = if let Some(at) = normalized.find('=') {
        let padding = &normalized[at..];
        if padding != "=" && padding != "==" {
            return Err(words("Invalid base64 padding"));
        }
        &normalized[..at]
    } else {
        &normalized
    };
    let mut output = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for (index, character) in data.chars().enumerate() {
        let value = match character {
            'A'..='Z' => character as u32 - 'A' as u32,
            'a'..='z' => character as u32 - 'a' as u32 + 26,
            '0'..='9' => character as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(words(&format!("Invalid base64 character at index {index}"))),
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(hex::encode(output))
}
