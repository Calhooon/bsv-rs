//! Index arithmetic shared by the two script-chunk walkers (`parse_chunks` and
//! `truncated_push_index` in `script.rs`) so that no push arm ever forms
//! `pos + declared` — a sum that wraps a 32-bit `usize` when an `OP_PUSHDATA4`
//! declares a length near `u32::MAX`, reversing the data slice and aborting the
//! process on the `wasm32` production target (a crafted five-byte script).
//! `pos <= length` is a walker invariant and `declared` is the push length read
//! from the script. The trait keeps the arithmetic generic over the index width
//! so the tests drive it at the production target's 32-bit width on a 64-bit
//! host; both walkers call the one copy, so a test cannot drift from the door.

/// An index type a push length is bounded in. `bytes_left` is a saturating
/// subtraction, the bytes a buffer still holds at a position.
pub(crate) trait PushIndex: Copy + Ord + core::ops::Add<Output = Self> {
    /// `self` minus `rhs`, never below zero.
    fn bytes_left(self, rhs: Self) -> Self;
}

impl PushIndex for usize {
    #[inline]
    fn bytes_left(self, rhs: Self) -> Self {
        self.saturating_sub(rhs)
    }
}

#[cfg(test)]
impl PushIndex for u32 {
    #[inline]
    fn bytes_left(self, rhs: Self) -> Self {
        self.saturating_sub(rhs)
    }
}

/// The end index of a push of `declared` bytes starting at `pos`, clamped to
/// `length`. Computed as `pos + declared.min(length - pos)` so the sum
/// `pos + declared` is never formed. Equal to `(pos + declared).min(length)`
/// for every push that fits the index type, so no in-range parse changes.
#[inline]
pub(crate) fn push_end<I: PushIndex>(length: I, pos: I, declared: I) -> I {
    pos + declared.min(length.bytes_left(pos))
}

/// Whether a push of `declared` bytes starting at `pos` runs past `length`.
/// Compares `declared` with the bytes remaining rather than forming
/// `pos + declared`. Equal to `pos + declared > length` for every push that
/// fits the index type.
#[inline]
pub(crate) fn push_overflows<I: PushIndex>(length: I, pos: I, declared: I) -> bool {
    declared > length.bytes_left(pos)
}

#[cfg(test)]
mod tests {
    use super::{push_end, push_overflows};
    use crate::script::op::OP_PUSHDATA4;
    use crate::script::Script;

    #[test]
    fn a_pushdata4_length_near_the_u32_max_clamps_the_push_end_without_wrapping() {
        // A five-byte `OP_PUSHDATA4` declares a length of 0xffff_ffff at pos 5,
        // driven at `u32` (the production target's index width).
        let length: u32 = 5;
        let pos: u32 = 5;
        let declared: u32 = u32::MAX;
        let end = push_end(length, pos, declared);
        assert!(
            pos <= end && end <= length,
            "end {end} escaped pos..=length"
        );
        assert_eq!(end, length); // clamped to the buffer, as 64-bit native is
    }

    #[test]
    fn a_pushdata4_length_near_the_u32_max_reads_as_a_truncated_push_at_32_bits() {
        let length: u32 = 5;
        let pos: u32 = 5;
        let declared: u32 = u32::MAX;
        assert!(push_overflows(length, pos, declared));
    }

    #[test]
    fn push_end_and_push_overflows_match_the_plain_clamp_for_in_range_pushes() {
        // For every push that fits the index type the bounded forms equal the
        // plain ones, so no honest parse moves.
        for (length, pos, declared) in [
            (0usize, 0, 0),
            (5, 5, 0),
            (10, 1, 3),
            (10, 8, 5),
            (75, 1, 75),
        ] {
            assert_eq!(
                push_end(length, pos, declared),
                (pos + declared).min(length)
            );
            assert_eq!(
                push_overflows(length, pos, declared),
                pos + declared > length
            );
        }
    }

    #[test]
    fn a_pushdata4_script_that_overdeclares_its_length_parses_clean_to_one_chunk() {
        // The public door: a crafted `OP_PUSHDATA4` with a 0xffff_ffff length
        // parses to one chunk with empty data and names index 0 as truncated,
        // matching 64-bit native, on every target (no abort).
        let crafted = [0x4e, 0xff, 0xff, 0xff, 0xff];
        let script = Script::from_binary(&crafted).unwrap();
        let chunks = script.chunks();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].op, OP_PUSHDATA4);
        assert!(chunks[0].data.as_deref().unwrap_or_default().is_empty());
        assert_eq!(script.truncated_push(), Some(0));
    }
}
