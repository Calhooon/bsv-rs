//! The node's lax DER signature parse, ported whole (#842's fold, #847):
//! `ecdsa_signature_parse_der_lax`, bitcoin-sv v1.2.2 `src/pubkey.cpp:32-175`,
//! the reading `CPubKey::CheckLowS` (`:353-363`) and `CPubKey::Verify`
//! (`:183-214`) give a signature after `CheckSignatureEncoding`
//! (`interpreter.cpp:265-306`) has judged its encoding. Under a word the
//! interpreter reads every signature through it (its parent,
//! `signature_read`),
//! so a signature the strict encoding check passes and the node's verify
//! reads as the all-zero signature is a failed check here too, never a
//! refusal of its format.
//!
//! Crate-private: [`crate::primitives::ec::Signature::from_der`] stays the
//! reference's strict reader, the SDK's door. Every byte is read with `get`
//! (rule 5); the node's `input[pos]` reads that its own bounds keep inside
//! the input are `get`s whose `None` is the branch the node would take for a
//! byte it never reads.

/// R and S as the node holds them after the parse: 32 bytes each,
/// big-endian, `([0; 32], [0; 32])` where a value overflowed (a length past
/// 32 bytes, or a value at or above the order, `:145-173`).
pub(super) type LaxSignature = ([u8; 32], [u8; 32]);

/// The order of secp256k1, big-endian (`secp256k1_ecdsa_signature_parse_compact`
/// refuses a scalar at or above it, the overflow `:165-166` reads); the crate's
/// one copy, `BigNumber::secp256k1_order`'s bytes (the stable line's port).
const ORDER: [u8; 32] = crate::primitives::BigNumber::SECP256K1_ORDER_BYTES;

/// An integer's length byte and the long form after it (`:67-94` for R,
/// `:106-134` for S): `None` is the node's `return 0`. `pos` is the length
/// byte's position; the answer is the length and the position after it.
fn integer_length(input: &[u8], pos: usize) -> Option<(usize, usize)> {
    // `if (pos == inputlen) return 0;` (`:69-71`, `:109-111`)
    let mut lenbyte = usize::from(*input.get(pos)?);
    let mut pos = pos + 1;
    if lenbyte & 0x80 == 0 {
        // The short form: the byte is the length (`:92-94`, `:132-134`).
        return Some((lenbyte, pos));
    }
    // The long form: the count of length bytes after it (`:74-78`).
    lenbyte -= 0x80;
    if pos + lenbyte > input.len() {
        return None;
    }
    // Leading zero length bytes skipped (`:79-82`).
    while lenbyte > 0 && input.get(pos) == Some(&0) {
        pos += 1;
        lenbyte -= 1;
    }
    // `if (lenbyte >= sizeof(size_t)) return 0;` (`:83-85`): eight bytes on
    // the node's 64-bit targets, the figure here on every target.
    if lenbyte >= 8 {
        return None;
    }
    // The length, big-endian (`:86-91`); seven bytes at most fit a `u64`.
    let mut len: u64 = 0;
    while lenbyte > 0 {
        len = (len << 8) + u64::from(*input.get(pos)?);
        pos += 1;
        lenbyte -= 1;
    }
    Some((usize::try_from(len).unwrap_or(usize::MAX), pos))
}

/// An integer's value into its 32-byte slot (`:139-162`): its leading zeros
/// ignored, `None` (the overflow) past 32 bytes.
fn integer_value(bytes: &[u8]) -> Option<[u8; 32]> {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let value = bytes.get(start..)?;
    if value.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.get_mut(32 - value.len()..)?.copy_from_slice(value);
    Some(out)
}

/// `ecdsa_signature_parse_der_lax` on the DER without its hash type byte:
/// `None` where the node returns 0 (a tag missing, a length past the input),
/// else the signature it holds. The sequence's length is read and skipped,
/// never compared (`:48-60`); bytes after S are ignored, never read
/// (`:135-137` bounds S by the input, not the sequence).
pub(super) fn parse(input: &[u8]) -> Option<LaxSignature> {
    // The sequence tag (`:41-46`).
    if input.first() != Some(&0x30) {
        return None;
    }
    // The sequence length, its long form skipped (`:48-60`).
    let mut lenbyte = usize::from(*input.get(1)?);
    let mut pos = 2;
    if lenbyte & 0x80 != 0 {
        lenbyte -= 0x80;
        if pos + lenbyte > input.len() {
            return None;
        }
        pos += lenbyte;
    }
    // R's tag and length (`:62-100`).
    if input.get(pos) != Some(&0x02) {
        return None;
    }
    let (rlen, after) = integer_length(input, pos + 1)?;
    pos = after;
    // `if (rlen > inputlen - pos) return 0;` (`:95-97`; S's at `:135-137`)
    if rlen > input.len() - pos {
        return None;
    }
    let rpos = pos;
    pos += rlen;
    // S's tag and length (`:102-137`).
    if input.get(pos) != Some(&0x02) {
        return None;
    }
    let (slen, after) = integer_length(input, pos + 1)?;
    pos = after;
    if slen > input.len() - pos {
        return None;
    }
    let r = input.get(rpos..rpos + rlen).and_then(integer_value);
    let s = input.get(pos..pos + slen).and_then(integer_value);
    // A value past 32 bytes (`:146-150`, `:159-163`) or at or above the
    // order (`:165-167`) overwrites the whole signature with zeros
    // (`:168-173`): a signature that parses and verifies nothing.
    Some(match (r, s) {
        (Some(r), Some(s)) if r < ORDER && s < ORDER => (r, s),
        _ => ([0; 32], [0; 32]),
    })
}

#[cfg(test)]
#[path = "der_lax_tests.rs"]
mod tests;
