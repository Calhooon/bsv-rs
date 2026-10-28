//! The default mode's read limit: a script number the reference cannot read
//! is invalid there, and so invalid here in that mode (bsv-rs#331, the
//! keeper's word of 2026-10-27). The figures are V8's longest string under
//! Node 22 at the reference's pin (`ts-stack@edf6e03`), not a BRC's rule:
//! `BigNumber.fromSm` writes the operand's bytes as hex text and parses
//! `'0x' + hex` (`BigNumber.ts:1518-1527`), then `#_finishInitialization`
//! takes `toString(2)` of the magnitude (`:450`); a string past 536,870,888
//! characters throws, and `#readScriptNumber` rethrows the words as a script
//! error (`Spend.ts:525-535`). So an operand whose magnitude passes
//! 536,870,888 bits (a minimal encoding past 67,108,862 bytes) is refused.
//! The hex text's own bound (an operand past 268,435,443 bytes) is not
//! followed: the reference cannot hold such an element (a `number[]` of 2^27
//! entries is `RangeError: Invalid array length` under Node 22), so no
//! script reaches it there.
//! The node's number length after Chronicle is 32,000,000 bytes
//! (`ScriptFlags::max_script_num_length`): the reference reads numbers the
//! node refuses, and the default mode follows the reference. Under a word
//! the node's rules alone apply.
//!
//! The same figure bounds a result where the reference builds it through
//! `toString(2)` (the keeper's word of 2026-10-27, the symmetric reading: a
//! number the reference cannot encode is one it never judges valid): `add`
//! and `sub` (`OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`) set their result
//! with `#_setValueFromSigned` (`BigNumber.ts:771-781`, `:912-924`), and
//! `OP_LSHIFTNUM` with `new BigNumber(value << bits)` (`Spend.ts:1066`):
//! past 536,870,888 bits each throws `RangeError: Invalid string length`,
//! uncaught, out of the reference's `verify`; here it is a verdict in those
//! words at the push ([`result_refusal`]). The shift's `BigInt` is built
//! first, and V8 caps a `BigInt` at 2^30 bits of magnitude: past it the
//! shift throws `RangeError: Maximum BigInt size exceeded` before any
//! string is written, so a shifted magnitude past 2^30 bits is invalid in
//! those words, one from 536,870,889 to 2^30 bits in the string's
//! ([`shift_refusal`]). No other result can pass 2^30 bits in one step:
//! two readable operands' product is at most 2^30 - 48 bits. `mul` sets its
//! magnitude without
//! a string (`BigNumber.ts:926-933`), so an `OP_MUL` or `OP_2MUL` result past
//! the figure is pushed there and here (and invalid at its next read); no
//! other result can pass its operands' magnitude.

/// V8's longest string, `String::kMaxLength` on a 64-bit host (Node's
/// `buffer.constants.MAX_STRING_LENGTH`, v22.18.0).
const MAX_STRING_LENGTH: u64 = 536_870_888;

/// V8's largest `BigInt`, `BigInt::kMaxLengthBits` on a 64-bit host: 2^30
/// bits of magnitude (Node v22.18.0: `1n << (2n ** 30n - 1n)` builds,
/// `1n << (2n ** 30n)` throws).
const MAX_BIGINT_BITS: u64 = 1 << 30;

/// The reference's words for an operand it cannot read, or `None`; after
/// its minimal-encoding check, which the caller makes first.
pub(super) fn refusal(bytes: &[u8]) -> Option<&'static str> {
    // `toString(2)` of the magnitude (`BigNumber.ts:450`)
    result_refusal(magnitude_bits(bytes))
}

/// The reference's words for a number of `bits` bits of magnitude it cannot
/// build, or `None`: an operand's read, or a result `add`, `sub` or the
/// left shift's constructor builds.
pub(super) fn result_refusal(bits: u64) -> Option<&'static str> {
    (bits > MAX_STRING_LENGTH).then_some("Invalid string length")
}

/// The reference's words for a left shift whose result has `bits` bits of
/// magnitude, or `None`: `value << bits` past V8's largest `BigInt`, else
/// the constructor's string (`Spend.ts:1066`).
pub(super) fn shift_refusal(bits: u64) -> Option<&'static str> {
    if bits > MAX_BIGINT_BITS {
        return Some("Maximum BigInt size exceeded");
    }
    result_refusal(bits)
}

/// The bits of a script number's magnitude, read from its bytes without
/// decoding them (a non-minimal encoding's padding counts nothing).
pub(super) fn magnitude_bits(bytes: &[u8]) -> u64 {
    let last = bytes.len().saturating_sub(1);
    for (i, &byte) in bytes.iter().enumerate().rev() {
        let byte = if i == last { byte & 0x7f } else { byte };
        if byte != 0 {
            return 8 * i as u64 + u64::from(8 - byte.leading_zeros());
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary on one 67,108,862-byte buffer, changed in place: 536,870,888
    /// bits of ones and a sign byte is read; a 536,870,889th bit is refused,
    /// as is any minimal encoding one byte longer.
    #[test]
    fn a_magnitude_past_v8s_longest_string_is_refused() {
        let mut bytes = vec![0xff; 67_108_862];
        bytes[67_108_861] = 0x00;
        assert_eq!(magnitude_bits(&bytes), 536_870_888);
        assert_eq!(refusal(&bytes), None);
        bytes[67_108_861] = 0x80;
        assert_eq!(refusal(&bytes), None, "the sign bit adds no bit");
        bytes[67_108_861] = 0x01;
        assert_eq!(magnitude_bits(&bytes), 536_870_889);
        assert_eq!(refusal(&bytes), Some("Invalid string length"));
        bytes[67_108_861] = 0x00;
        bytes.push(0x01);
        assert_eq!(refusal(&bytes), Some("Invalid string length"));
    }

    /// A result's bits on the same figure.
    #[test]
    fn a_result_past_v8s_longest_string_is_refused() {
        assert_eq!(result_refusal(536_870_888), None);
        assert_eq!(result_refusal(536_870_889), Some("Invalid string length"));
    }

    /// A shift's bits on both figures: the string's past 536,870,888, the
    /// `BigInt`'s past 2^30.
    #[test]
    fn a_shift_past_v8s_largest_bigint_has_the_bigint_words() {
        assert_eq!(shift_refusal(536_870_888), None);
        assert_eq!(shift_refusal(536_870_889), Some("Invalid string length"));
        assert_eq!(shift_refusal(1 << 30), Some("Invalid string length"));
        assert_eq!(
            shift_refusal((1 << 30) + 1),
            Some("Maximum BigInt size exceeded")
        );
        assert_eq!(
            shift_refusal(u64::MAX),
            Some("Maximum BigInt size exceeded")
        );
    }

    /// Padding counts no bit: a long non-minimal zero is read.
    #[test]
    fn padding_is_not_magnitude() {
        assert_eq!(magnitude_bits(&[0x00; 1000]), 0);
        assert_eq!(magnitude_bits(&[0x01, 0x00, 0x80]), 1);
        assert_eq!(refusal(&vec![0x00; 67_108_870]), None);
    }
}
