//! The refusal's names: [`Kind`] and [`Reason`], the Lean's `Kind` and
//! `Reason` (`BeefOfAnySize.lean`), re-exported from the parent.

use super::Hash32;

/// The twenty-four kinds of refusal, the Lean's `Kind`. None is a size or a
/// count: no byte is wrong by being one of many.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The version word is neither `0100BEEF` nor `0200BEEF`.
    BadVersion,
    /// A varint cut short or encoded non-canonically.
    BadVarint,
    /// A fixed-width field cut short.
    Truncated,
    /// A flag byte outside its table.
    BadFlag,
    /// A BUMP's tree-height byte over 64.
    TreeHeightOver64,
    /// A BUMP's tree-height byte 0.
    TreeHeightZero,
    /// A leaf's offset at or beyond the width of its level.
    OffsetOutsideTree,
    /// A BUMP whose level 0 carries no hash.
    NoTxidAtLevelZero,
    /// A path needs a node the BUMP neither carries nor determines.
    MissingSibling,
    /// A node the level below determines differs from the one carried, or a repeated offset.
    MismatchedNode,
    /// A BUMP's root is not the root the headers carry at its height.
    RootNotCarried,
    /// A transaction's BUMP index names no BUMP.
    BumpIndexNamesNoBump,
    /// A transaction's BUMP does not carry its txid at level 0.
    TxidNotInBump,
    /// An input of an unproven transaction names no earlier transaction.
    InputNamesNoElement,
    /// A txid-only entry no BUMP proves.
    StubNotProven,
    /// A byte after the frame's end.
    TrailingBytes,
    /// Atomic: the subject is not a raw transaction of the BEEF.
    SubjectMissing,
    /// Atomic: an entry outside the subject's dependency graph (BRC-95): one
    /// the walk from the subject over the inputs of raw entries does not
    /// reach. The stream names the earliest such entry by the trie order
    /// (the txid's bytes, each byte's bits reversed, least first), at its
    /// offset.
    UnrelatedTransaction,
    /// A raw transaction with no input (since 0.4.1).
    NoInputs,
    /// A raw transaction with an input and no output (since 0.4.3).
    NoOutputs,
    /// An unproven single null-outpoint input, at the transaction's leading byte.
    /// \[SRC\] sibling@87f0461 TxRules.lean:35-38,102 (#68).
    UnprovenCoinbase,
    /// A null outpoint in a regular transaction, at the input's previous txid.
    /// \[SRC\] sibling@87f0461 TxRules.lean:31-32,107 (#68).
    NullOutpoint,
    /// A repeated outpoint, at the repeating input's previous txid.
    /// \[SRC\] sibling@87f0461 TxRules.lean:108 (#68).
    DuplicateInput,
    /// An output value or running total outside MoneyRange, at the value field.
    /// \[SRC\] sibling@87f0461 TxRules.lean:25,88-93 (#68).
    ValueOutOfRange,
}

impl Kind {
    /// The twenty-four kinds, each once, in the Lean's order (`Kind.all`).
    pub const ALL: [Kind; 24] = [
        Kind::BadVersion,
        Kind::BadVarint,
        Kind::Truncated,
        Kind::BadFlag,
        Kind::TreeHeightOver64,
        Kind::TreeHeightZero,
        Kind::OffsetOutsideTree,
        Kind::NoTxidAtLevelZero,
        Kind::MissingSibling,
        Kind::MismatchedNode,
        Kind::RootNotCarried,
        Kind::BumpIndexNamesNoBump,
        Kind::TxidNotInBump,
        Kind::InputNamesNoElement,
        Kind::StubNotProven,
        Kind::TrailingBytes,
        Kind::SubjectMissing,
        Kind::UnrelatedTransaction,
        Kind::NoInputs,
        Kind::NoOutputs,
        Kind::UnprovenCoinbase,
        Kind::NullOutpoint,
        Kind::DuplicateInput,
        Kind::ValueOutOfRange,
    ];
}

/// A refusal's reason with its data, the Lean's `Reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The version word read.
    BadVersion {
        /// The word, little-endian.
        word: u32,
    },
    /// A varint cut short or encoded non-canonically.
    BadVarint,
    /// A fixed-width field cut short.
    Truncated {
        /// The bytes that were due.
        needed: u64,
    },
    /// A BUMP leaf flag not `00`, `01` or `02`, or `01` at an even offset; a
    /// has-BUMP byte not `00` or `01`; a V2 format byte not 0, 1 or 2.
    BadFlag {
        /// The byte read.
        byte: u8,
    },
    /// The tree-height byte read.
    TreeHeightOver64 {
        /// The byte.
        height: u8,
    },
    /// A tree height of 0: no level 0, no txid, no root.
    TreeHeightZero,
    /// A leaf outside its level.
    OffsetOutsideTree {
        /// The level.
        level: u8,
        /// The leaf's offset.
        offset: u64,
    },
    /// Nothing to prove.
    NoTxidAtLevelZero,
    /// The node a path needs.
    MissingSibling {
        /// The level.
        level: u8,
        /// The node's offset at that level.
        offset: u64,
    },
    /// The node that disagrees, or a second leaf at an offset, at its offset varint.
    MismatchedNode {
        /// The level.
        level: u8,
        /// The node's offset at that level.
        offset: u64,
    },
    /// The root computed and the height the BUMP claims.
    RootNotCarried {
        /// The block height.
        height: u64,
        /// The root, in wire order.
        root: Hash32,
    },
    /// The index read.
    BumpIndexNamesNoBump {
        /// The index.
        index: u64,
    },
    /// The BUMP named and the txid it does not carry.
    TxidNotInBump {
        /// The index.
        index: u64,
        /// The transaction's txid.
        txid: Hash32,
    },
    /// The previous txid an input names.
    InputNamesNoElement {
        /// The txid.
        txid: Hash32,
    },
    /// The txid of the entry.
    StubNotProven {
        /// The txid.
        txid: Hash32,
    },
    /// The byte at the offset belongs to no field.
    TrailingBytes,
    /// The subject that is not a raw transaction of the BEEF.
    SubjectMissing {
        /// The subject.
        subject: Hash32,
    },
    /// An entry outside the subject's graph that no raw transaction spends.
    UnrelatedTransaction {
        /// Its txid.
        txid: Hash32,
    },
    /// A raw transaction whose input count is 0, named at the transaction's
    /// leading byte. It is no transaction: the node refuses one before any
    /// script runs (the sibling's rule, bsv-script-lean
    /// `lean/BsvScript/TxRules.lean`, `checkTransactionCommon_vinEmpty`), so
    /// no block holds it, a BUMP that claims it proves nothing, and an
    /// unproven one has no input for the reader to hold it by.
    NoInputs,
    /// A raw transaction with at least one input and an output count of 0,
    /// named at the transaction's leading byte. The node refuses it beside
    /// one with no input, after it (bsv-script-lean@87f0461
    /// `lean/BsvScript/TxRules.lean:86`, `checkTransactionCommon_voutEmpty`),
    /// so a transaction with neither is [`Reason::NoInputs`]. An unproven
    /// coinbase is [`Reason::UnprovenCoinbase`] ahead of this check.
    NoOutputs,
    /// An unproven single null-outpoint input, at the transaction's leading byte.
    /// \[SRC\] sibling@87f0461 TxRules.lean:35-38,102 (#68).
    UnprovenCoinbase,
    /// A null outpoint in a regular transaction, at the input's previous txid.
    /// \[SRC\] sibling@87f0461 TxRules.lean:31-32,107 (#68).
    NullOutpoint,
    /// A repeated outpoint, at the repeating input's previous txid.
    /// \[SRC\] sibling@87f0461 TxRules.lean:108 (#68).
    DuplicateInput,
    /// An output value or running total outside MoneyRange, at the value field.
    /// \[SRC\] sibling@87f0461 TxRules.lean:25,88-93 (#68).
    ValueOutOfRange,
}

impl Reason {
    /// The reason without its data.
    pub fn kind(&self) -> Kind {
        match self {
            Reason::BadVersion { .. } => Kind::BadVersion,
            Reason::BadVarint => Kind::BadVarint,
            Reason::Truncated { .. } => Kind::Truncated,
            Reason::BadFlag { .. } => Kind::BadFlag,
            Reason::TreeHeightOver64 { .. } => Kind::TreeHeightOver64,
            Reason::TreeHeightZero => Kind::TreeHeightZero,
            Reason::OffsetOutsideTree { .. } => Kind::OffsetOutsideTree,
            Reason::NoTxidAtLevelZero => Kind::NoTxidAtLevelZero,
            Reason::MissingSibling { .. } => Kind::MissingSibling,
            Reason::MismatchedNode { .. } => Kind::MismatchedNode,
            Reason::RootNotCarried { .. } => Kind::RootNotCarried,
            Reason::BumpIndexNamesNoBump { .. } => Kind::BumpIndexNamesNoBump,
            Reason::TxidNotInBump { .. } => Kind::TxidNotInBump,
            Reason::InputNamesNoElement { .. } => Kind::InputNamesNoElement,
            Reason::StubNotProven { .. } => Kind::StubNotProven,
            Reason::TrailingBytes => Kind::TrailingBytes,
            Reason::SubjectMissing { .. } => Kind::SubjectMissing,
            Reason::UnrelatedTransaction { .. } => Kind::UnrelatedTransaction,
            Reason::NoInputs => Kind::NoInputs,
            Reason::NoOutputs => Kind::NoOutputs,
            Reason::ValueOutOfRange => Kind::ValueOutOfRange,
            Reason::DuplicateInput => Kind::DuplicateInput,
            Reason::NullOutpoint => Kind::NullOutpoint,
            Reason::UnprovenCoinbase => Kind::UnprovenCoinbase,
        }
    }
}
