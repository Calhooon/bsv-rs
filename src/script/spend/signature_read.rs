//! How the interpreter reads a signature (#842's fold, #847): one reading,
//! used at the encoding check and at the signature check alike, so the
//! signature a check verifies is the one its encoding was judged on.
//!
//! - Under a word, the node's: `ecdsa_signature_parse_der_lax`
//!   (`der_lax.rs`, bitcoin-sv v1.2.2 `pubkey.cpp:32-175`), the reading
//!   `CPubKey::CheckLowS` (`:353-363`) and `CPubKey::Verify` (`:183-214`) give
//!   the DER after `CheckSignatureEncoding` (`interpreter.cpp:265-306`) has
//!   judged its bytes. An R or S that is a lone `00`, or longer than 32
//!   bytes, or at or above the order, passes BIP 66 and is a signature that
//!   verifies nothing (zero, or the all-zero signature the overflow writes),
//!   low for the low-S rule: a failed check, with NULLFAIL's words where
//!   NULLFAIL applies, never a refusal of its format.
//! - Without a word, the reference's: `TransactionSignature.fromChecksigFormat`
//!   through `Signature.fromDER` (`ts-stack@edf6e03` `Spend.ts:606-629`,
//!   `Signature.ts:44-97`; `primitives::ec::signature_der::read` here): its
//!   refusal is the format refusal, a lone `00` among them; an R or S longer
//!   than 32 bytes is a `BigNumber` there, above the order, so it verifies
//!   false (`ECDSA.ts:236-239`) and its S is high (`hasLowS`), recorded in
//!   `tests/vectors/script_signature_der_842.json`. #14's order exception
//!   (an S of 32 bytes at or above the order read as low, the node's
//!   reading, a stated row) is kept for the values a 32-byte slot holds.

use crate::primitives::bsv::sighash::SIGHASH_FORKID;
use crate::primitives::ec::signature_der;
use crate::primitives::ec::Signature;
use crate::primitives::BigNumber;

/// The node's lax parse, this reading's alone.
#[path = "der_lax.rs"]
mod der_lax;

/// A signature as the interpreter judges and verifies it.
pub(super) struct ScriptSignature {
    /// The R and S the signature check verifies: zero where the signature
    /// verifies nothing (the node's overflow, the reference's value past 32
    /// bytes).
    pub(super) signature: Signature,
    /// The hash type byte (`GetHashType`, `interpreter.cpp:246-252`).
    pub(super) scope: u32,
    /// Whether the low-S rule passes it, as the mode's judge reads S.
    pub(super) low_s: bool,
}

impl ScriptSignature {
    /// Whether the hash type carries `SIGHASH_FORKID`.
    pub(super) fn has_forkid(&self) -> bool {
        self.scope & SIGHASH_FORKID != 0
    }
}

/// `s <= n / 2` on a 32-byte S (`secp256k1_ecdsa_signature_normalize`
/// answers 0, `CheckLowS`'s low; the reference's `hasLowS`).
fn at_most_half_order(s: &[u8; 32]) -> bool {
    Signature::new([1; 32], *s).is_low_s()
}

/// At or above the order (#14's exception: the node's lax parse writes the
/// all-zero signature, which is low).
fn at_or_above_order(v: &[u8]) -> bool {
    BigNumber::from_bytes_be(v) >= BigNumber::secp256k1_order()
}

/// The empty signature's reading (the reference's blank signature, R = S = 1,
/// scope 1, `TransactionSignature.ts:460-466`): it verifies nothing.
fn blank() -> ScriptSignature {
    let mut one = [0u8; 32];
    one[31] = 1;
    ScriptSignature {
        signature: Signature::new(one, one),
        scope: 1,
        low_s: true,
    }
}

/// The node's reading of a non-empty checksig signature under a word: `None`
/// where its lax parse returns 0 (`CheckLowS` false, `Verify` false), which
/// no signature that passed BIP 66 reaches.
pub(super) fn under_word(checksig: &[u8]) -> Option<ScriptSignature> {
    let Some((&scope, der)) = checksig.split_last() else {
        return Some(blank());
    };
    let (r, s) = der_lax::parse(der)?;
    Some(ScriptSignature {
        signature: Signature::new(r, s),
        scope: u32::from(scope),
        low_s: at_most_half_order(&s),
    })
}

/// The reference's reading in the default mode: `Err` where `fromDER`
/// refuses (the format refusal).
pub(super) fn by_default(checksig: &[u8]) -> Result<ScriptSignature, &'static str> {
    let Some((&scope, der)) = checksig.split_last() else {
        return Ok(blank());
    };
    let read = signature_der::read(der)?;
    let slot = |v: &[u8]| -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        out.get_mut(32usize.checked_sub(v.len())?..)?
            .copy_from_slice(v);
        Some(out)
    };
    let (signature, low_s) = match (slot(read.r), slot(read.s)) {
        (Some(r), Some(s)) => (
            Signature::new(r, s),
            at_most_half_order(&s) || at_or_above_order(&r) || at_or_above_order(&s),
        ),
        // A value past 32 bytes verifies false; an S past 32 bytes is high.
        (_, s) => (
            Signature::new([0; 32], [0; 32]),
            s.is_some_and(|s| at_most_half_order(&s) || at_or_above_order(&s)),
        ),
    };
    Ok(ScriptSignature {
        signature,
        scope: u32::from(scope),
        low_s,
    })
}

impl super::Spend {
    /// The signature as the mode's judge reads it, at the encoding check and
    /// at the signature check alike: under a word the node's lax parse,
    /// without one the reference's `fromDER`. `None` is a reading that
    /// refuses: the reference's refusal in the default mode, the lax parse's 0
    /// under a word (which BIP 66 leaves no signature to reach).
    pub(super) fn read_signature(&self, sig: &[u8]) -> Option<ScriptSignature> {
        if self.flags.is_some() {
            under_word(sig)
        } else {
            by_default(sig).ok()
        }
    }
}
