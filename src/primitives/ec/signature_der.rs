//! The reference's DER signature reading, one implementation for the crate
//! (#842): `Signature.fromDER` (`ts-stack@edf6e03`
//! `packages/sdk/src/primitives/Signature.ts:44-97`), its checks in its order
//! and its words. [`Signature::from_der`](super::Signature::from_der) and the
//! interpreter's default-mode reading (`signature_read::by_default`) read
//! through it (beta's `wallet::wire::reference_der`, #305, is not here).
//!
//! Every byte is read with `get`: an input of any length, the empty one
//! included, is an answer, never a panic. A read past the end is the
//! reference's `undefined`, and the words are those of the check that
//! `undefined` fails next (`getLength` returns it, the arithmetic after it is
//! `NaN`, the comparison that follows throws).

/// `Signature DER must start with 0x30` (`Signature.ts:60-62`).
pub(crate) const NOT_A_SEQUENCE: &str = "Signature DER must start with 0x30";
/// `Signature DER invalid` (`:64-66`, `:67-69`, `:73-75`).
pub(crate) const INVALID: &str = "Signature DER invalid";
/// `getLength`'s refusal of a long-form length (`:45-52`).
pub(crate) const LONG_FORM_LENGTH: &str = "Invalid DER entity length";
/// The S length's check, in the reference's words (`:76-78`).
pub(crate) const S_LENGTH: &str = "Invalid R-length in signature DER";
/// An R padded with a zero it did not need (`:80-86`).
pub(crate) const R_PADDED: &str = "Invalid R-value in signature DER";
/// An S padded with a zero it did not need (`:87-93`).
pub(crate) const S_PADDED: &str = "Invalid S-value in signature DER";

/// The two integers of a DER signature as the reference reads them: each
/// without the one leading zero its next byte's high bit needed, so neither
/// starts with a zero byte (an empty integer is zero).
pub(crate) struct DerIntegers<'a> {
    pub(crate) r: &'a [u8],
    pub(crate) s: &'a [u8],
}

/// `getLength` (`Signature.ts:45-52`): the short form alone; `None` is the
/// reference's `undefined`, a byte past the end.
fn length(der: &[u8], at: usize) -> Result<Option<usize>, &'static str> {
    match der.get(at) {
        Some(b) if b & 0x80 == 0 => Ok(Some(usize::from(*b))),
        Some(_) => Err(LONG_FORM_LENGTH),
        None => Ok(None),
    }
}

/// `r[0] === 0` then `(r[1] & 0x80) === 0` (`:80-93`): a zero byte is kept
/// only before a high bit, and dropped; a lone `00` is refused
/// (`undefined & 0x80` is 0).
fn integer<'a>(bytes: &'a [u8], padded: &'static str) -> Result<&'a [u8], &'static str> {
    match bytes {
        [0, rest @ ..] if rest.first().map_or(0, |b| b & 0x80) == 0 => Err(padded),
        [0, rest @ ..] => Ok(rest),
        _ => Ok(bytes),
    }
}

/// `Signature.fromDER`'s reading (`Signature.ts:44-97`), verdict for verdict:
/// the sequence tag, its short-form length naming exactly the bytes after it,
/// R's tag and short-form length, S's tag and short-form length ending the
/// input, then each integer's padding. The refusal is the reference's words.
pub(crate) fn read(der: &[u8]) -> Result<DerIntegers<'_>, &'static str> {
    if der.first() != Some(&0x30) {
        return Err(NOT_A_SEQUENCE);
    }
    // `len + p.place !== data.length`: `undefined + 2` is `NaN`, never equal.
    if length(der, 1)?.map(|len| len + 2) != Some(der.len()) {
        return Err(INVALID);
    }
    if der.get(2) != Some(&0x02) {
        return Err(INVALID);
    }
    // An R length past the end makes the next position `NaN`, whose byte
    // is `undefined`: the tag check after it throws.
    let r_end = 4 + length(der, 3)?.ok_or(INVALID)?;
    if der.get(r_end) != Some(&0x02) {
        return Err(INVALID);
    }
    // An S length past the end fails the length check that follows.
    let s_len = length(der, r_end + 1)?.ok_or(S_LENGTH)?;
    if der.len() != r_end + 2 + s_len {
        return Err(S_LENGTH);
    }
    // `der[r_end] == 0x02` above puts `4..r_end` inside the input, and the
    // length check puts S's bytes at its end.
    let r = der.get(4..r_end).ok_or(INVALID)?;
    let s = der.get(r_end + 2..).ok_or(S_LENGTH)?;
    Ok(DerIntegers {
        r: integer(r, R_PADDED)?,
        s: integer(s, S_PADDED)?,
    })
}

#[cfg(test)]
#[path = "signature_der_tests.rs"]
mod tests;
