//! The one rule the SPV/BEEF proof doors share against the merkle inner-node
//! ambiguity (CVE-2017-12842).
//!
//! A merkle inner node is two concatenated 32-byte child hashes — exactly 64
//! bytes — and its double SHA-256 is taken the same way a transaction's txid
//! is. A transaction that serializes to exactly 64 bytes therefore has a txid
//! indistinguishable from a merkle inner node, so a merkle path that binds
//! such a transaction to a block by its txid alone cannot be told from a path
//! over a shallower tree (nor its mirror, a deeper path read over a real
//! 64-byte leaf's two halves).
//!
//! The rule every door shares is NOT a refusal of the length. It is this: a
//! transaction of this length is never taken as PROVEN by a merkle path. At
//! every door it is judged exactly as an UNPROVEN transaction is — by that
//! door's own rules, with that door's own answers — and the path offered for
//! it is simply not used. A forged entry of this shape then meets whatever the
//! door already answers for an unproven transaction whose inputs' sources are
//! absent or do not verify (its serialized input prevout is pinned by its own
//! bytes to a value no supplied source can carry without a second-preimage, so
//! that answer is a refusal); an honest holder of a genuine 64-byte
//! transaction still verifies it by supplying its inputs' sources, the way any
//! unproven transaction's are supplied. No new refusal name is added at any
//! door, on either line.
//!
//! Every door that holds a proven transaction's bytes reads this rule through
//! [`is_ambiguous_merkle_leaf`]; a door that holds only a hash cannot apply it
//! (the bytes are not there to measure), which is why the rule lives at the
//! bytes-holding doors and not in `MerklePath::compute_root` or the chain
//! tracker.

/// The serialized length at which a transaction's txid collides with a merkle
/// inner node, so its merkle path cannot be used as proof.
pub(crate) const AMBIGUOUS_MERKLE_LEAF_LEN: usize = 64;

/// True when a serialized transaction of `serialized_len` bytes has the
/// [`AMBIGUOUS_MERKLE_LEAF_LEN`] that collides with a merkle inner node. The
/// single place every proof door reads the rule: a transaction of this length
/// is judged as unproven (its path is not used), never proven by that path.
pub(crate) fn is_ambiguous_merkle_leaf(serialized_len: usize) -> bool {
    serialized_len == AMBIGUOUS_MERKLE_LEAF_LEN
}
