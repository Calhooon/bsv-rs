//! The frame of an Electrum ECIES envelope, read the reference's way (bsv-rs#109).
//!
//! `"BIE1" || [sender key] || ciphertext || mac (32)`: whether a key is
//! embedded is decided by the byte after the magic and the bytes left over,
//! as `ts-stack@edf6e03` `packages/sdk/src/compat/ECIES.ts:607-646` decides
//! it, never by the length alone. A ciphertext is a whole number of AES
//! blocks and a key is 33 or 65 bytes, so a key is taken only where its
//! length leaves the rest block-aligned.

use crate::error::{Error, Result};
use crate::primitives::ec::PublicKey;
use subtle::ConstantTimeEq;

const MAGIC_LEN: usize = 4;
const MAC_LEN: usize = 32;
const BLOCK: usize = 16;
const COMPRESSED: usize = 33;
const UNCOMPRESSED: usize = 65;

/// An envelope's sender key and ciphertext, before its MAC is checked.
pub(super) struct Frame<'a> {
    /// The key the shared secret is derived with: the expected sender when
    /// given, else the embedded one.
    pub(super) sender: PublicKey,
    /// The bytes between the key (or the magic) and the MAC.
    pub(super) ciphertext: &'a [u8],
}

/// The length of the key embedded at byte 4, or `None` when the envelope
/// embeds none (`ECIES.ts:609-621`).
fn embedded_key_len(data: &[u8]) -> Option<usize> {
    let available = data.len().saturating_sub(MAGIC_LEN + MAC_LEN);
    let fits = |len: usize| available >= len + BLOCK && (available - len).is_multiple_of(BLOCK);
    match data.get(MAGIC_LEN)? {
        0x02 | 0x03 if fits(COMPRESSED) => Some(COMPRESSED),
        0x04 if fits(UNCOMPRESSED) => Some(UNCOMPRESSED),
        _ => None,
    }
}

fn refused(reason: &str) -> Error {
    Error::EciesDecryptionFailed(reason.to_string())
}

/// Reads the frame of `data`, whose length and magic the caller has checked
/// (a shorter input is refused as out of framing, never indexed past), in
/// the reference's order: the key, the sender, the ciphertext's framing
/// (`ECIES.ts:623-646`).
pub(super) fn read_frame<'a>(data: &'a [u8], expected: Option<&PublicKey>) -> Result<Frame<'a>> {
    let key_len = embedded_key_len(data).unwrap_or(0);
    let sender = if key_len == 0 {
        expected
            .cloned()
            .ok_or_else(|| refused("Sender public key is required"))?
    } else {
        let embedded = PublicKey::from_bytes(&data[MAGIC_LEN..MAGIC_LEN + key_len])?;
        match expected {
            Some(expected) => {
                let same: bool = embedded
                    .to_compressed()
                    .ct_eq(&expected.to_compressed())
                    .into();
                if !same {
                    return Err(refused(
                        "Embedded sender public key does not match the expected sender",
                    ));
                }
                expected.clone()
            }
            None => embedded,
        }
    };
    let end = data.len().saturating_sub(MAC_LEN);
    let ciphertext = data.get(MAGIC_LEN + key_len..end).unwrap_or_default();
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
        return Err(refused("Invalid Electrum ECIES ciphertext framing"));
    }
    Ok(Frame { sender, ciphertext })
}
