//! A BEEF of any size: the streaming reader.
//!
//! A valid BEEF is never refused for its size or its counts. A refusal is for
//! invalid bytes only, and names them: the offset of the byte and one of
//! twenty-five kinds, none of which is a size or a count.
//!
//! The specification is the Lean definition `BeefOfAnySize` of bsv-stack-lean
//! (`lean/BeefOfAnySize.lean`, its report `docs/p0/nl-1.md`), which states six
//! theorems about a reader that is a state machine over the elements of a
//! BEEF. This module is that reader over a byte source:
//!
//! - [`BeefDecoder`] cuts a byte stream into the header and the elements
//!   (the Lean's `cut` and `parseElement`, interleaved). It is fed slices and
//!   holds at most the one element it is building, so it serves a
//!   [`std::io::Read`] ([`BeefStream`]) and an asynchronous body
//!   ([`AsyncByteSource`], [`verify_stream_async`]) alike.
//! - [`BeefIndex`] is the reader's state (the Lean's `Index` and `fold`): the
//!   BUMPs by position, the txids their level 0 carries, the transactions by
//!   txid, the last raw transaction, and under a subject the txids each raw
//!   transaction's inputs name (the edges the atomic walk follows). One
//!   entry per element and one per level-0 txid, plus, only under a subject,
//!   32 bytes per input of a raw transaction (0.8.1, the Lean's `prevs`; an
//!   input is 41 bytes or more on the wire, so this too is linear in the
//!   bytes read); never a sibling hash, never a transaction's bytes after its
//!   step.
//! - [`verify_stream`] is one pass: one step per element, each BUMP's root
//!   checked against the [`Headers`] as it streams, each unproven
//!   transaction's inputs resolved against the index and executed against the
//!   parent output the index retained. The verdict is [`Verdict`].
//!   [`verify_stream_two_pass`] reads a source at rest twice and keeps only
//!   the outputs that are spent.
//! - [`Cursor`] is the state after `k` elements, serializable;
//!   [`StreamVerifier::resume`] over the rest of the stream yields the verdict
//!   of the whole.
//!
//! # The format, at the pin
//!
//! BEEF: `BRCs@5119a9b transactions/0062.md:63-69` (the version word, nBUMPs,
//! the BUMPs, nTransactions, each raw transaction then the has-BUMP byte and
//! the index), `:172-191` (the validation; the soonest failure stops). BUMP:
//! `transactions/0074.md:50-68` (block height, tree height "max 64", the
//! levels, a leaf's offset, flags and hash). Atomic BEEF:
//! `transactions/0095.md:31-43,65-69`. The raw transaction:
//! `transactions/0012.md:15-41`. BEEF V2 and the txid-only entry:
//! `ts-stack@edf6e03 packages/sdk/src/transaction/BeefTx.ts:288-312`.
//!
//! # What is and is not the Lean's
//!
//! The twenty-five [`Kind`]s, the offsets and the order of the checks inside one
//! element are the Lean's. Two things are outside it and say so in the type:
//!
//! - Script execution and the value rule are the interpreter's verdict on a
//!   spend, not a rule about the BEEF's bytes (the Lean leaves them to the
//!   node). A spend that fails is [`Verdict::SpendRefused`], never one of the
//!   twenty-five kinds. [`StreamVerifier::structure_only`] turns the spend
//!   checks off and leaves exactly the Lean's validity.
//! - Next-block mining context: P2SH's Genesis era, finality and coinbase
//!   maturity are spend checks. Missing finality or maturity context yields
//!   [`Verdict::Unverifiable`], a decline outside the Lean's byte validity.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::beef_stream::{verify_stream, Verdict};
//!
//! let verdict = verify_stream(body, &headers, None)?;
//! match verdict {
//!     Verdict::Valid { subject, roots } => { /* every root was carried */ }
//!     Verdict::Invalid { offset, kind, .. } => { /* the byte and the kind */ }
//!     Verdict::SpendRefused { offset, why, .. } => { /* a spend said no */ }
//!     Verdict::Unverifiable { check, .. } => { /* supply the mining context */ }
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::primitives::bsv::sighash::{TxInput, TxOutput, TxSighashCache};
use crate::primitives::{to_hex, Reader, Writer};
use crate::script::{LockingScript, ScriptResource, Spend, TxSpendParams, UnlockingScript};

use super::beef_tx::{ATOMIC_BEEF, BEEF_V1, BEEF_V2};
use super::chain_tracker::{ChainTracker, ChainTrackerError};

/// A 32-byte digest in the order the wire carries it (a txid or a merkle
/// node; its display form is the bytes reversed, in hex).
pub use crate::primitives::Hash32;

/// The display form of a digest: the bytes reversed, in hex.
pub fn display_hex(hash: &Hash32) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}

// ---------------------------------------------------------------------------
// The refusal: invalid bytes, named
// ---------------------------------------------------------------------------

mod reason;
pub use reason::{Kind, Reason};

/// A refusal: the offset of the byte it names, and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The stream offset of the byte the refusal names.
    pub offset: u64,
    /// What was wrong with the bytes there.
    pub reason: Reason,
}

impl Refusal {
    fn new(offset: u64, reason: Reason) -> Self {
        Self { offset, reason }
    }

    /// The reason without its data.
    pub fn kind(&self) -> Kind {
        self.reason.kind()
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid BEEF at byte {}: {:?}", self.offset, self.reason)
    }
}

impl std::error::Error for Refusal {}

/// The two counts that make a transaction's bytes no transaction, in the
/// node's order: no input ([`Reason::NoInputs`]), then no output
/// ([`Reason::NoOutputs`]). The rule is the sibling's, cited not restated:
/// bsv-script-lean@87f0461 `lean/BsvScript/TxRules.lean:85-86`
/// (`checkTransactionCommon_vinEmpty`, `checkTransactionCommon_voutEmpty`).
/// Every path of this crate that judges a transaction asks this.
pub(crate) fn no_transaction(inputs: usize, outputs: usize) -> Option<Reason> {
    if inputs == 0 {
        Some(Reason::NoInputs)
    } else if outputs == 0 {
        Some(Reason::NoOutputs)
    } else {
        None
    }
}

// [SRC] sibling@87f0461 TxRules.lean:25.
const MAX_MONEY: u64 = 2_100_000_000_000_000;

// [SRC] sibling@87f0461 TxRules.lean:31-38,101-110; reading #68.
fn is_coinbase(inputs: &[InputRef]) -> bool {
    matches!(inputs, [i] if i.prev == [0; 32] && i.vout == u32::MAX)
}

pub(crate) fn check_transaction(
    offset: u64,
    inputs: &[InputRef],
    outputs: &[OutputRef],
    bump_index: Option<u64>,
) -> Result<(), Refusal> {
    if bump_index.is_none() && is_coinbase(inputs) {
        return Err(Refusal::new(offset, Reason::UnprovenCoinbase));
    }
    if let Some(reason) = no_transaction(inputs.len(), outputs.len()) {
        return Err(Refusal::new(offset, reason));
    }
    // [SRC] sibling@87f0461 TxRules.lean:25,88-93. Output checks precede inputs.
    let mut total = 0;
    for output in outputs {
        if output.satoshis > MAX_MONEY || output.satoshis > MAX_MONEY - total {
            return Err(Refusal::new(output.at, Reason::ValueOutOfRange));
        }
        total += output.satoshis;
    }
    if !is_coinbase(inputs) {
        let mut seen = HashSet::with_capacity(inputs.len());
        for input in inputs {
            if input.prev == [0; 32] && input.vout == u32::MAX {
                return Err(Refusal::new(input.at, Reason::NullOutpoint));
            }
            if !seen.insert((input.prev, input.vout)) {
                return Err(Refusal::new(input.at, Reason::DuplicateInput));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The elements
// ---------------------------------------------------------------------------

/// What a BUMP leaf carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    /// A hash (flags `00` and `02`), in wire order.
    Hash(Hash32),
    /// The instruction to pair the working hash with itself (flag `01`).
    Duplicate,
}

/// One leaf of a BUMP level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    /// The stream offset of the leaf's offset varint.
    pub at: u64,
    /// The leaf's offset within its level.
    pub offset: u64,
    /// The hash or the duplicate marker.
    pub node: Node,
    /// Flag `02`: a client txid. Informational; every hash of level 0 is a
    /// txid the BUMP proves.
    pub client: bool,
}

/// A BUMP read from the stream, its root computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bump {
    /// The stream offset of the BUMP's leading byte.
    pub offset: u64,
    /// The block height the BUMP claims.
    pub block_height: u64,
    /// The levels, level 0 leading; as many as the tree-height byte said.
    pub levels: Vec<Vec<Leaf>>,
    /// The root every hashed leaf of level 0 climbs to, in wire order.
    pub root: Hash32,
    /// The bytes the BUMP occupied on the wire.
    pub wire_len: u64,
}

impl Bump {
    /// The txids the BUMP proves: every hash of level 0, in wire order.
    pub fn proven(&self) -> impl Iterator<Item = &Hash32> {
        self.levels.first().into_iter().flatten().filter_map(|l| {
            if let Node::Hash(h) = &l.node {
                Some(h)
            } else {
                None
            }
        })
    }
}

/// One input of a streamed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRef {
    /// The stream offset of the 32-byte previous txid.
    pub at: u64,
    /// The previous txid, in wire order.
    pub prev: Hash32,
    /// The previous output's index.
    pub vout: u32,
    /// The unlocking script's place in the raw bytes.
    pub script: std::ops::Range<usize>,
    /// The sequence number.
    pub sequence: u32,
}

/// One output of a streamed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRef {
    /// The absolute stream offset of the output value field (since 0.5.0).
    pub at: u64,
    /// The value in satoshis.
    pub satoshis: u64,
    /// The locking script's place in the raw bytes.
    pub script: std::ops::Range<usize>,
}

/// A raw transaction read from the stream: its bytes, read once, and where
/// its fields lie in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    /// The raw transaction (BRC-12).
    pub raw: Vec<u8>,
    /// The version field.
    pub version: u32,
    /// The inputs, in order.
    pub inputs: Vec<InputRef>,
    /// The outputs, in order.
    pub outputs: Vec<OutputRef>,
    /// The lock time.
    pub lock_time: u32,
}

/// An element of a BEEF, as the stream yields it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    /// A BUMP, its root computed by the linear walk.
    Bump(Bump),
    /// A raw transaction, its txid hashed while its bytes passed.
    Tx {
        /// The stream offset of the raw transaction's leading byte.
        offset: u64,
        /// The double SHA-256 of the raw bytes, in wire order.
        txid: Hash32,
        /// The BUMP index the frame gave it, if any.
        bump_index: Option<u64>,
        /// The transaction.
        body: TxBody,
    },
    /// A txid-only entry (V2).
    TxidOnly {
        /// The stream offset of the 32 bytes.
        offset: u64,
        /// The txid, in wire order.
        txid: Hash32,
    },
}

impl Element {
    /// The stream offset of the element.
    pub fn offset(&self) -> u64 {
        match self {
            Element::Bump(b) => b.offset,
            Element::Tx { offset, .. } | Element::TxidOnly { offset, .. } => *offset,
        }
    }

    /// The bytes the element occupies on the wire, framing aside.
    pub fn wire_len(&self) -> u64 {
        match self {
            Element::Bump(b) => b.wire_len,
            Element::Tx { body, .. } => body.raw.len() as u64,
            Element::TxidOnly { .. } => 32,
        }
    }
}

// ---------------------------------------------------------------------------
// The root of a BUMP
// ---------------------------------------------------------------------------

/// The parent of two nodes: the double SHA-256 of left then right.
fn pair(left: &Hash32, right: &Hash32) -> Hash32 {
    crate::block::merkle_parent(left, right)
}

/// A node on a hashed leaf's path: its offset at the current level, its hash,
/// and the stream offset of the level-0 leaf whose path it is on.
struct PathNode {
    offset: u64,
    hash: Hash32,
    at: u64,
}

/// The root of a BUMP, bottom up, one level at a time (the Lean's `Bump.root`
/// and `climb`). The path nodes of a level are the nodes the hashed leaves of
/// level 0 climb through; each one's sibling is the leaf the level carries at
/// `offset ^ 1` or, when the level carries none there, the path node computed
/// at that offset from the level below; every path node agrees with whatever
/// the level carries at its own offset. Two map operations per leaf and a
/// constant number per path node per level: linear in the BUMP.
///
/// The maps are keyed by offsets a stranger chose, so they keep the standard
/// library's keyed hasher.
pub(crate) fn bump_root(offset: u64, levels: &[Vec<Leaf>]) -> Result<Hash32, Refusal> {
    let Some(level0) = levels.first() else {
        return Err(Refusal::new(offset, Reason::TreeHeightZero));
    };
    let mut needed: Vec<PathNode> = level0
        .iter()
        .filter_map(|l| match l.node {
            Node::Hash(hash) => Some(PathNode {
                offset: l.offset,
                hash,
                at: l.at,
            }),
            Node::Duplicate => None,
        })
        .collect();
    let Some(first_at) = needed.first().map(|n| n.at) else {
        return Err(Refusal::new(offset, Reason::NoTxidAtLevelZero));
    };

    // The Lean's Bump.lone?: a block with only one transaction. Its merkle root is that txid, so its
    // BUMP is one level holding the one leaf at offset 0 and nothing to pair
    // it with (the reference, `ts-stack@edf6e03 MerklePath.ts:345,390-391`;
    // `MerklePath::from_coinbase_txid` writes this shape). Other lone-leaf
    // shapes still require their sibling.
    if let [only] = levels {
        if let [Leaf {
            offset: 0,
            node: Node::Hash(txid),
            ..
        }] = only.as_slice()
        {
            return Ok(*txid);
        }
    }

    for (level, leaves) in levels.iter().enumerate() {
        let level = level as u8;
        // The level's leaves by offset, one at each (a second is refused before, `DuplicateOffset`).
        let mut given: HashMap<u64, Node> = HashMap::with_capacity(leaves.len());
        for l in leaves {
            given.entry(l.offset).or_insert(l.node);
        }
        // The path nodes of this level by offset.
        let mut computed: HashMap<u64, Hash32> = HashMap::with_capacity(needed.len());
        for n in &needed {
            computed.insert(n.offset, n.hash);
        }
        let mut parents: HashMap<u64, Hash32> = HashMap::with_capacity(needed.len());
        let mut next: Vec<PathNode> = Vec::with_capacity(needed.len());
        for n in &needed {
            match given.get(&n.offset) {
                Some(Node::Hash(g)) if *g == n.hash => {}
                Some(_) => {
                    return Err(Refusal::new(
                        n.at,
                        Reason::MismatchedNode {
                            level,
                            offset: n.offset,
                        },
                    ))
                }
                None => {}
            }
            let s = n.offset ^ 1;
            let sibling: Option<Hash32> = match given.get(&s) {
                Some(Node::Hash(h)) => Some(*h),
                Some(Node::Duplicate) => None,
                None => match computed.get(&s) {
                    Some(h) => Some(*h),
                    None => {
                        return Err(Refusal::new(
                            n.at,
                            Reason::MissingSibling { level, offset: s },
                        ))
                    }
                },
            };
            let parent = match sibling {
                None => pair(&n.hash, &n.hash),
                Some(h) if s % 2 == 1 => pair(&n.hash, &h),
                Some(h) => pair(&h, &n.hash),
            };
            let up = n.offset / 2;
            match parents.get(&up) {
                Some(p) if *p == parent => {}
                Some(_) => {
                    return Err(Refusal::new(
                        n.at,
                        Reason::MismatchedNode {
                            level: level + 1,
                            offset: up,
                        },
                    ))
                }
                None => {
                    parents.insert(up, parent);
                    next.push(PathNode {
                        offset: up,
                        hash: parent,
                        at: n.at,
                    });
                }
            }
        }
        needed = next;
    }

    let height = levels.len() as u8;
    match needed.as_slice() {
        [root] => Ok(root.hash),
        [] => Err(Refusal::new(
            first_at,
            Reason::MissingSibling {
                level: height,
                offset: 0,
            },
        )),
        [r, ..] => Err(Refusal::new(
            r.at,
            Reason::OffsetOutsideTree {
                level: height,
                offset: r.offset,
            },
        )),
    }
}

// ---------------------------------------------------------------------------
// The decoder
// ---------------------------------------------------------------------------

/// Where the frame stands between two elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing read: the version word is next.
    Head,
    /// Among the BUMPs.
    Bumps,
    /// Among the transactions.
    Txs,
}

/// The decoder's position between two elements: what a [`Cursor`] keeps of
/// the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    /// The offset of the next byte.
    pos: u64,
    /// The elements yielded.
    k: u64,
    phase: Phase,
    version: u32,
    /// The atomic subject, when the prefix led.
    subject: Option<Hash32>,
    bumps_left: u64,
    txs_left: u64,
}

impl Frame {
    fn start() -> Self {
        Self {
            pos: 0,
            k: 0,
            phase: Phase::Head,
            version: 0,
            subject: None,
            bumps_left: 0,
            txs_left: 0,
        }
    }
}

/// The field the decoder reads next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    /// Between two elements: the frame decides what comes.
    Boundary,
    Word,
    Subject,
    Version,
    NBumps,
    BumpHeight,
    TreeHeight,
    NLeaves,
    LeafOffset,
    LeafFlag,
    LeafHash,
    NTxs,
    V2Format,
    V2Index,
    StubTxid,
    TxVersion,
    NIn,
    InPrev,
    InVout,
    InScriptLen,
    InScript,
    InSequence,
    NOut,
    OutValue,
    OutScriptLen,
    OutScript,
    LockTime,
    V1Has,
    V1Index,
    Done,
}

/// The shape of a field.
enum Field {
    /// Exactly this many bytes, at most 32.
    Fixed(usize),
    /// A varint.
    Varint,
    /// A script: this many bytes, passed into the element as they arrive.
    Run,
}

impl St {
    fn field(self) -> Field {
        match self {
            St::Word | St::Version | St::TxVersion | St::InVout | St::InSequence | St::LockTime => {
                Field::Fixed(4)
            }
            St::Subject | St::LeafHash | St::StubTxid | St::InPrev => Field::Fixed(32),
            St::TreeHeight | St::LeafFlag | St::V2Format | St::V1Has => Field::Fixed(1),
            St::OutValue => Field::Fixed(8),
            St::InScript | St::OutScript => Field::Run,
            _ => Field::Varint,
        }
    }

    /// The field is part of a raw transaction: its bytes are hashed and kept.
    fn in_raw_tx(self) -> bool {
        matches!(
            self,
            St::TxVersion
                | St::NIn
                | St::InPrev
                | St::InVout
                | St::InScriptLen
                | St::InScript
                | St::InSequence
                | St::NOut
                | St::OutValue
                | St::OutScriptLen
                | St::OutScript
                | St::LockTime
        )
    }
}

/// The BUMP under construction.
struct BumpBuilder {
    offset: u64,
    block_height: u64,
    tree_height: u8,
    levels: Vec<Vec<Leaf>>,
    leaves_left: u64,
    leaf_at: u64,
    leaf_offset: u64,
    leaf_client: bool,
    offsets_seen: HashSet<(u8, u64)>,
}

/// The transaction under construction.
struct TxBuilder {
    offset: u64,
    bump_index: Option<u64>,
    hasher: Sha256,
    raw: Vec<u8>,
    version: u32,
    inputs: Vec<InputRef>,
    outputs: Vec<OutputRef>,
    ins_left: u64,
    outs_left: u64,
    in_at: u64,
    in_prev: Hash32,
    in_vout: u32,
    script_start: usize,
    out_satoshis: u64,
    out_at: u64,
    txid: Hash32,
    lock_time: u32,
}

/// What a call to [`BeefDecoder::next`] came to.
#[derive(Debug)]
pub enum Step {
    /// One element, complete.
    Element(Element),
    /// The input is used up and the frame is not complete.
    NeedMore,
    /// The frame is complete. A byte after this is a trailing byte.
    Done,
}

/// The frame and the elements of a BEEF, read from slices as they arrive.
///
/// The decoder never reads ahead of the element it is building and holds
/// nothing of the elements it has yielded. A count read from the stream
/// reserves nothing: the bytes it promises are either there or the refusal
/// names where they ran out.
pub struct BeefDecoder {
    frame: Frame,
    st: St,
    /// The bytes of the small field in hand.
    scratch: [u8; 32],
    have: usize,
    /// The offset of the leading byte of the field in hand.
    field_at: u64,
    /// The length of the script in hand, and what is left of it.
    run_len: u64,
    run_left: u64,
    bump: Option<BumpBuilder>,
    tx: Option<TxBuilder>,
    /// Collecting (the whole-BEEF reader, bsv-rs#86): a transaction whose
    /// content is refused is yielded, its refusal kept here.
    collect: bool,
    deferred: Option<Refusal>,
}

impl Default for BeefDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl BeefDecoder {
    /// A decoder at the start of a stream.
    pub fn new() -> Self {
        Self::at(Frame::start())
    }

    fn at(frame: Frame) -> Self {
        let st = if frame.phase == Phase::Head {
            St::Word
        } else {
            St::Boundary
        };
        Self {
            field_at: frame.pos,
            frame,
            st,
            scratch: [0u8; 32],
            have: 0,
            run_len: 0,
            run_left: 0,
            bump: None,
            tx: None,
            collect: false,
            deferred: None,
        }
    }

    /// A decoder for the whole-BEEF reader: the frame and each BUMP refused
    /// as the stream refuses them, each transaction yielded whatever its
    /// content (the node's rules, [`check_transaction`]), the refusal of its
    /// content kept for [`take_deferred`](Self::take_deferred).
    pub(crate) fn collecting() -> Self {
        Self {
            collect: true,
            ..Self::new()
        }
    }

    /// The refusal of the content of the transaction just yielded, when
    /// collecting.
    pub(crate) fn take_deferred(&mut self) -> Option<Refusal> {
        self.deferred.take()
    }

    /// A transaction's content refused: the error, or, collecting, kept.
    fn judged(&mut self, judged: Result<(), Refusal>) -> Result<(), Refusal> {
        match judged {
            Err(r) if self.collect => {
                self.deferred = Some(r);
                Ok(())
            }
            judged => judged,
        }
    }

    /// The offset of the next byte the decoder will read.
    pub fn offset(&self) -> u64 {
        self.frame.pos
    }

    /// The elements yielded so far.
    pub fn elements_read(&self) -> u64 {
        self.frame.k
    }

    /// The version word, once the header is read.
    pub fn version(&self) -> Option<u32> {
        (self.frame.phase != Phase::Head).then_some(self.frame.version)
    }

    /// The atomic subject, when the prefix led, once the header is read.
    pub fn subject(&self) -> Option<Hash32> {
        self.frame.subject
    }

    /// The header is read.
    fn header_read(&self) -> bool {
        self.frame.phase != Phase::Head
    }

    /// Reads from `input` until one element is complete, the frame is
    /// complete or the input is used up, and advances `input` past what it
    /// read.
    pub fn next(&mut self, input: &mut &[u8]) -> Result<Step, Refusal> {
        loop {
            if self.st == St::Boundary {
                self.leave_boundary();
            }
            if self.st == St::Done {
                return if input.is_empty() {
                    Ok(Step::Done)
                } else {
                    Err(Refusal::new(self.frame.pos, Reason::TrailingBytes))
                };
            }
            let produced = match self.st.field() {
                Field::Fixed(n) => {
                    if !self.fill(input, n) {
                        return Ok(Step::NeedMore);
                    }
                    self.absorb_scratch(n);
                    self.have = 0;
                    self.on_fixed(n)?
                }
                Field::Varint => {
                    if !self.fill(input, 1) {
                        return Ok(Step::NeedMore);
                    }
                    let n = match self.scratch[0] {
                        0xFD => 3,
                        0xFE => 5,
                        0xFF => 9,
                        _ => 1,
                    };
                    if !self.fill(input, n) {
                        return Ok(Step::NeedMore);
                    }
                    let value = Reader::new(&self.scratch[..n])
                        .read_var_int()
                        .map_err(|_| Refusal::new(self.field_at, Reason::BadVarint))?;
                    self.absorb_scratch(n);
                    self.have = 0;
                    self.on_varint(value)?
                }
                Field::Run => {
                    let take = self.run_left.min(input.len() as u64) as usize;
                    let (chunk, rest) = input.split_at(take);
                    *input = rest;
                    self.frame.pos += take as u64;
                    self.run_left -= take as u64;
                    if let Some(tx) = self.tx.as_mut() {
                        tx.hasher.update(chunk);
                        tx.raw.extend_from_slice(chunk);
                    }
                    if self.run_left > 0 {
                        return Ok(Step::NeedMore);
                    }
                    self.on_run_done();
                    None
                }
            };
            if let Some(element) = produced {
                self.frame.k += 1;
                self.st = St::Boundary;
                return Ok(Step::Element(element));
            }
        }
    }

    /// The stream has ended: the frame is complete, or the refusal names the
    /// field the bytes ran out in.
    pub fn finish(&mut self) -> Result<(), Refusal> {
        if self.st == St::Boundary {
            self.leave_boundary();
        }
        if self.st == St::Done {
            return Ok(());
        }
        let reason = match self.st.field() {
            Field::Fixed(n) => Reason::Truncated { needed: n as u64 },
            Field::Varint => Reason::BadVarint,
            Field::Run => Reason::Truncated {
                needed: self.run_len,
            },
        };
        Err(Refusal::new(self.field_at, reason))
    }

    /// Moves bytes from `input` into the scratch until it holds `n`.
    fn fill(&mut self, input: &mut &[u8], n: usize) -> bool {
        if self.have == 0 {
            self.field_at = self.frame.pos;
        }
        // A varint asks for its lead byte and then for its whole: on a
        // second call the lead byte, and more, may already be in hand.
        let take = n.saturating_sub(self.have).min(input.len());
        self.scratch[self.have..self.have + take].copy_from_slice(&input[..take]);
        *input = &input[take..];
        self.have += take;
        self.frame.pos += take as u64;
        self.have >= n
    }

    /// The bytes of a raw transaction's field go to its hash and its body.
    fn absorb_scratch(&mut self, n: usize) {
        if self.st.in_raw_tx() {
            if let Some(tx) = self.tx.as_mut() {
                tx.hasher.update(&self.scratch[..n]);
                tx.raw.extend_from_slice(&self.scratch[..n]);
            }
        }
    }

    /// What follows the element just yielded.
    fn leave_boundary(&mut self) {
        self.field_at = self.frame.pos;
        self.st = match self.frame.phase {
            Phase::Head => St::Word,
            Phase::Bumps if self.frame.bumps_left > 0 => {
                self.bump = Some(BumpBuilder {
                    offset: self.frame.pos,
                    block_height: 0,
                    tree_height: 0,
                    levels: Vec::new(),
                    leaves_left: 0,
                    leaf_at: 0,
                    leaf_offset: 0,
                    leaf_client: false,
                    offsets_seen: HashSet::new(),
                });
                St::BumpHeight
            }
            Phase::Bumps => St::NTxs,
            Phase::Txs if self.frame.txs_left > 0 => {
                if self.frame.version == BEEF_V2 {
                    St::V2Format
                } else {
                    self.begin_tx(None);
                    St::TxVersion
                }
            }
            Phase::Txs => St::Done,
        };
    }

    fn begin_tx(&mut self, bump_index: Option<u64>) {
        self.tx = Some(TxBuilder {
            offset: self.frame.pos,
            bump_index,
            hasher: Sha256::new(),
            raw: Vec::new(),
            version: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            ins_left: 0,
            outs_left: 0,
            in_at: 0,
            in_prev: [0u8; 32],
            in_vout: 0,
            script_start: 0,
            out_satoshis: 0,
            out_at: 0,
            txid: [0u8; 32],
            lock_time: 0,
        });
    }

    fn u32_field(&self) -> u32 {
        u32::from_le_bytes([
            self.scratch[0],
            self.scratch[1],
            self.scratch[2],
            self.scratch[3],
        ])
    }

    fn hash_field(&self) -> Hash32 {
        self.scratch
    }

    fn check_version(&self, word: u32) -> Result<(), Refusal> {
        if word == BEEF_V1 || word == BEEF_V2 {
            Ok(())
        } else {
            Err(Refusal::new(self.field_at, Reason::BadVersion { word }))
        }
    }

    /// A fixed-width field is complete.
    #[allow(clippy::expect_used)] // #134: each state holds what it reads by the machine's invariant; a Reason for a broken one is a public enum change
    fn on_fixed(&mut self, _n: usize) -> Result<Option<Element>, Refusal> {
        match self.st {
            St::Word => {
                let word = self.u32_field();
                if word == ATOMIC_BEEF {
                    self.st = St::Subject;
                } else {
                    self.check_version(word)?;
                    self.frame.version = word;
                    self.st = St::NBumps;
                }
            }
            St::Subject => {
                self.frame.subject = Some(self.hash_field());
                self.st = St::Version;
            }
            St::Version => {
                let word = self.u32_field();
                self.check_version(word)?;
                self.frame.version = word;
                self.st = St::NBumps;
            }
            St::TreeHeight => {
                let height = self.scratch[0];
                if height > 64 {
                    return Err(Refusal::new(
                        self.field_at,
                        Reason::TreeHeightOver64 { height },
                    ));
                }
                if height == 0 {
                    return Err(Refusal::new(self.field_at, Reason::TreeHeightZero));
                }
                let bump = self.bump.as_mut().expect("a BUMP is in hand");
                bump.tree_height = height;
                self.st = St::NLeaves;
            }
            St::LeafFlag => {
                let flag = self.scratch[0];
                let bump = self.bump.as_mut().expect("a BUMP is in hand");
                match (flag, bump.leaf_offset % 2) {
                    (1, 1) => {
                        let leaf = Leaf {
                            at: bump.leaf_at,
                            offset: bump.leaf_offset,
                            node: Node::Duplicate,
                            client: false,
                        };
                        return self.leaf_done(leaf);
                    }
                    (0 | 2, _) => {
                        bump.leaf_client = flag == 2;
                        self.st = St::LeafHash;
                    }
                    (byte, _) => return Err(Refusal::new(self.field_at, Reason::BadFlag { byte })),
                }
            }
            St::LeafHash => {
                let hash = self.hash_field();
                let bump = self.bump.as_ref().expect("a BUMP is in hand");
                let leaf = Leaf {
                    at: bump.leaf_at,
                    offset: bump.leaf_offset,
                    node: Node::Hash(hash),
                    client: bump.leaf_client,
                };
                return self.leaf_done(leaf);
            }
            St::V2Format => match self.scratch[0] {
                2 => self.st = St::StubTxid,
                1 => self.st = St::V2Index,
                0 => {
                    self.begin_tx(None);
                    self.st = St::TxVersion;
                }
                byte => return Err(Refusal::new(self.field_at, Reason::BadFlag { byte })),
            },
            St::StubTxid => {
                self.frame.txs_left -= 1;
                return Ok(Some(Element::TxidOnly {
                    offset: self.field_at,
                    txid: self.hash_field(),
                }));
            }
            St::TxVersion => {
                let version = self.u32_field();
                self.tx.as_mut().expect("a transaction is in hand").version = version;
                self.st = St::NIn;
            }
            St::InPrev => {
                let prev = self.hash_field();
                let at = self.field_at;
                let tx = self.tx.as_mut().expect("a transaction is in hand");
                tx.in_at = at;
                tx.in_prev = prev;
                self.st = St::InVout;
            }
            St::InVout => {
                let vout = self.u32_field();
                self.tx.as_mut().expect("a transaction is in hand").in_vout = vout;
                self.st = St::InScriptLen;
            }
            St::InSequence => {
                let sequence = self.u32_field();
                let tx = self.tx.as_mut().expect("a transaction is in hand");
                tx.inputs.push(InputRef {
                    at: tx.in_at,
                    prev: tx.in_prev,
                    vout: tx.in_vout,
                    script: tx.script_start..tx.raw.len() - 4,
                    sequence,
                });
                tx.ins_left -= 1;
                self.st = if tx.ins_left > 0 {
                    St::InPrev
                } else {
                    St::NOut
                };
            }
            St::OutValue => {
                self.tx.as_mut().expect("a transaction is in hand").out_at = self.field_at;
                let mut le = [0u8; 8];
                le.copy_from_slice(&self.scratch[..8]);
                self.tx
                    .as_mut()
                    .expect("a transaction is in hand")
                    .out_satoshis = u64::from_le_bytes(le);
                self.st = St::OutScriptLen;
            }
            St::LockTime => {
                let lock_time = self.u32_field();
                let v1 = self.frame.version == BEEF_V1;
                let tx = self.tx.as_mut().expect("a transaction is in hand");
                tx.lock_time = lock_time;
                let once: [u8; 32] = tx.hasher.finalize_reset().into();
                tx.txid = Sha256::digest(once).into();
                if v1 {
                    self.st = St::V1Has;
                } else {
                    return self.tx_done().map(Some);
                }
            }
            St::V1Has => match self.scratch[0] {
                0 => return self.tx_done().map(Some),
                1 => self.st = St::V1Index,
                byte => return Err(Refusal::new(self.field_at, Reason::BadFlag { byte })),
            },
            _ => unreachable!("not a fixed-width field"),
        }
        Ok(None)
    }

    /// A varint is complete.
    #[allow(clippy::expect_used)] // #134: each state holds what it reads by the machine's invariant; a Reason for a broken one is a public enum change
    fn on_varint(&mut self, value: u64) -> Result<Option<Element>, Refusal> {
        match self.st {
            St::NBumps => {
                self.frame.bumps_left = value;
                self.frame.phase = Phase::Bumps;
                self.st = St::Boundary;
                self.leave_boundary();
            }
            St::BumpHeight => {
                self.bump.as_mut().expect("a BUMP is in hand").block_height = value;
                self.st = St::TreeHeight;
            }
            St::NLeaves => {
                let bump = self.bump.as_mut().expect("a BUMP is in hand");
                bump.levels.push(Vec::new());
                bump.leaves_left = value;
                return self.next_leaf();
            }
            St::LeafOffset => {
                let at = self.field_at;
                let bump = self.bump.as_mut().expect("a BUMP is in hand");
                let level = (bump.levels.len() - 1) as u8;
                // The level's width is 2 ^ (tree height - level); at 64 no u64 is outside it.
                let (shift, offset) = (bump.tree_height - level, value);
                if shift < 64 && offset >> shift != 0 {
                    let reason = Reason::OffsetOutsideTree { level, offset };
                    return Err(Refusal::new(at, reason));
                }
                // A second leaf at an offset, agreeing or not (`MerklePath.ts:221`).
                if !bump.offsets_seen.insert((level, offset)) {
                    return Err(Refusal::new(at, Reason::DuplicateOffset { level, offset }));
                }
                bump.leaf_at = at;
                bump.leaf_offset = offset;
                self.st = St::LeafFlag;
            }
            St::NTxs => {
                self.frame.txs_left = value;
                self.frame.phase = Phase::Txs;
                self.st = St::Boundary;
                self.leave_boundary();
            }
            St::V2Index => {
                self.begin_tx(Some(value));
                self.st = St::TxVersion;
            }
            St::NIn => {
                let tx = self.tx.as_mut().expect("a transaction is in hand");
                tx.ins_left = value;
                self.st = if value > 0 { St::InPrev } else { St::NOut };
            }
            St::InScriptLen | St::OutScriptLen => {
                let tx = self.tx.as_mut().expect("a transaction is in hand");
                tx.script_start = tx.raw.len();
                self.run_len = value;
                self.run_left = value;
                self.field_at = self.frame.pos;
                self.st = if self.st == St::InScriptLen {
                    St::InScript
                } else {
                    St::OutScript
                };
                if value == 0 {
                    self.on_run_done();
                }
            }
            St::NOut => {
                let tx = self.tx.as_mut().expect("a transaction is in hand");
                tx.outs_left = value;
                self.st = if value > 0 {
                    St::OutValue
                } else {
                    St::LockTime
                };
            }
            St::V1Index => {
                self.tx
                    .as_mut()
                    .expect("a transaction is in hand")
                    .bump_index = Some(value);
                return self.tx_done().map(Some);
            }
            _ => unreachable!("not a varint"),
        }
        Ok(None)
    }

    /// A script has passed.
    #[allow(clippy::expect_used)] // #134: each state holds what it reads by the machine's invariant; a Reason for a broken one is a public enum change
    fn on_run_done(&mut self) {
        let tx = self.tx.as_mut().expect("a transaction is in hand");
        if self.st == St::InScript {
            self.st = St::InSequence;
        } else {
            tx.outputs.push(OutputRef {
                at: tx.out_at,
                satoshis: tx.out_satoshis,
                script: tx.script_start..tx.raw.len(),
            });
            tx.outs_left -= 1;
            self.st = if tx.outs_left > 0 {
                St::OutValue
            } else {
                St::LockTime
            };
        }
    }

    /// A leaf is complete.
    #[allow(clippy::expect_used)] // #134: each state holds what it reads by the machine's invariant; a Reason for a broken one is a public enum change
    fn leaf_done(&mut self, leaf: Leaf) -> Result<Option<Element>, Refusal> {
        let bump = self.bump.as_mut().expect("a BUMP is in hand");
        bump.levels
            .last_mut()
            .expect("a level is in hand")
            .push(leaf);
        bump.leaves_left -= 1;
        self.next_leaf()
    }

    /// The next leaf, the next level, or the BUMP's end and its root.
    #[allow(clippy::expect_used)] // #134: each state holds what it reads by the machine's invariant; a Reason for a broken one is a public enum change
    fn next_leaf(&mut self) -> Result<Option<Element>, Refusal> {
        let bump = self.bump.as_mut().expect("a BUMP is in hand");
        if bump.leaves_left > 0 {
            self.st = St::LeafOffset;
            return Ok(None);
        }
        if bump.levels.len() < bump.tree_height as usize {
            self.st = St::NLeaves;
            return Ok(None);
        }
        let bump = self.bump.take().expect("a BUMP is in hand");
        let root = bump_root(bump.offset, &bump.levels)?;
        self.frame.bumps_left -= 1;
        Ok(Some(Element::Bump(Bump {
            offset: bump.offset,
            block_height: bump.block_height,
            levels: bump.levels,
            root,
            wire_len: self.frame.pos - bump.offset,
        })))
    }

    /// A transaction and its frame bytes are complete. The mining byte
    /// checks run in the Lean's parseElement order, naming the transaction,
    /// output value field or input's previous txid.
    #[allow(clippy::expect_used)] // #134: each state holds what it reads by the machine's invariant; a Reason for a broken one is a public enum change
    fn tx_done(&mut self) -> Result<Element, Refusal> {
        let tx = self.tx.take().expect("a transaction is in hand");
        let judged = check_transaction(tx.offset, &tx.inputs, &tx.outputs, tx.bump_index);
        self.judged(judged)?;
        self.frame.txs_left -= 1;
        Ok(Element::Tx {
            offset: tx.offset,
            txid: tx.txid,
            bump_index: tx.bump_index,
            body: TxBody {
                raw: tx.raw,
                version: tx.version,
                inputs: tx.inputs,
                outputs: tx.outputs,
                lock_time: tx.lock_time,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// The stream over a reader
// ---------------------------------------------------------------------------

/// What stops a [`BeefStream`]: the source failed, or the bytes are invalid.
#[derive(Debug)]
pub enum StreamError {
    /// The source returned an error. Nothing is said about the bytes.
    Io(std::io::Error),
    /// The bytes are invalid.
    Refused(Refusal),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Io(e) => write!(f, "the BEEF source failed: {e}"),
            StreamError::Refused(r) => r.fmt(f),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e)
    }
}

impl From<Refusal> for StreamError {
    fn from(r: Refusal) -> Self {
        StreamError::Refused(r)
    }
}

/// The bytes a [`BeefStream`] reads from its source at a time.
const CHUNK: usize = 16 * 1024;

/// The elements of a BEEF from a [`Read`], one at a time.
///
/// The stream holds one chunk of the source and the one element in hand. An
/// element handed out is the caller's; the stream keeps nothing of it.
pub struct BeefStream<R> {
    source: R,
    decoder: BeefDecoder,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    ended: bool,
}

impl<R: Read> BeefStream<R> {
    /// A stream over a source positioned at the BEEF's leading byte.
    pub fn new(source: R) -> Self {
        Self::with_decoder(source, BeefDecoder::new())
    }

    fn with_decoder(source: R, decoder: BeefDecoder) -> Self {
        Self {
            source,
            decoder,
            buf: vec![0u8; CHUNK].into_boxed_slice(),
            start: 0,
            end: 0,
            ended: false,
        }
    }

    /// The offset of the next byte the decoder will read: after an element,
    /// the offset a resumed source is positioned at.
    pub fn offset(&self) -> u64 {
        self.decoder.offset()
    }

    /// The elements yielded so far.
    pub fn elements_read(&self) -> u64 {
        self.decoder.elements_read()
    }

    /// The version word, once the header is read.
    pub fn version(&self) -> Option<u32> {
        self.decoder.version()
    }

    /// The atomic subject, when the prefix led, once the header is read.
    pub fn subject(&self) -> Option<Hash32> {
        self.decoder.subject()
    }

    /// The next element, `None` at the frame's end, or what stopped the
    /// stream.
    pub fn next_element(&mut self) -> Result<Option<Element>, StreamError> {
        if self.ended {
            return Ok(None);
        }
        loop {
            let mut input = &self.buf[self.start..self.end];
            let before = input.len();
            let step = self.decoder.next(&mut input);
            self.start += before - input.len();
            match step? {
                Step::Element(element) => return Ok(Some(element)),
                Step::Done | Step::NeedMore => {}
            }
            // The chunk is used up: the next one, or the stream's end.
            let n = loop {
                match self.source.read(&mut self.buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(StreamError::Io(e)),
                }
            };
            self.start = 0;
            self.end = n;
            if n == 0 {
                self.decoder.finish()?;
                self.ended = true;
                return Ok(None);
            }
        }
    }
}

impl<R: Read> Iterator for BeefStream<R> {
    type Item = Result<Element, StreamError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_element().transpose()
    }
}

// ---------------------------------------------------------------------------
// The headers
// ---------------------------------------------------------------------------

/// Header context for checking mining in the next block (since 0.5.0).
/// The activation heights belong to the caller's network. After CSV activation,
/// finality uses median time past; before it the candidate block's time is needed.
/// \[SRC\] bsv-script-lean@87f0461 docs/BLOCK-CONSENSUS.md:83-88.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// Active chain tip's height.
    pub height: u32,
    /// Tip's median time past, in seconds.
    pub median_time_past: u32,
    /// This network's Genesis activation height.
    pub genesis_height: u32,
    /// This network's CSV activation height.
    pub csv_height: u32,
    /// Candidate block time, required only for time locks before CSV.
    pub next_block_time: Option<u32>,
}

/// Active-chain roots and optional mining context. Missing roots fail closed;
/// missing tip context declines checks that need it.
pub trait Headers {
    /// The header at `height` carries `root` (wire order).
    fn carries(&self, height: u64, root: &Hash32) -> bool;
    /// The caller's active tip and network; none means no contextual evidence.
    fn mining_tip(&self) -> Option<ChainTip> {
        None
    }
}

impl<H: Headers + ?Sized> Headers for &H {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        (**self).carries(height, root)
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        (**self).mining_tip()
    }
}

/// Roots by height, in wire order.
impl Headers for HashMap<u64, Hash32> {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        self.get(&height) == Some(root)
    }
}

/// A function as the headers.
pub struct HeadersFn<F>(pub F);

impl<F: Fn(u64, &Hash32) -> bool> Headers for HeadersFn<F> {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        (self.0)(height, root)
    }
}

// ---------------------------------------------------------------------------
// The index
// ---------------------------------------------------------------------------

/// An output a later input may spend: kept until it is spent, then dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Retained {
    satoshis: u64,
    script: Box<[u8]>,
}

/// A transaction the index knows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxEntry {
    /// The stream offset of its earliest entry.
    at: u64,
    /// The txids its inputs name, in input order, when it is raw and the
    /// index is held to a subject: the edges the atomic walk follows (the
    /// Lean's `prevs`, 0.8.1). Empty otherwise.
    prevs: Box<[Hash32]>,
    /// Its raw bytes were read (a txid-only entry leaves this false).
    raw: bool,
    /// The atomic walk's mark ([`atomic_unreached`]): false between walks,
    /// never stored.
    reached: bool,
    /// Verified height of a proven coinbase; no other transaction has one.
    coinbase_height: Option<u64>,
    /// Its unspent outputs by index, when spends are checked. A spent output
    /// is `None`; the whole table goes when the last one is spent.
    outputs: Option<Box<[Option<Retained>]>>,
    /// The outputs of the table still unspent: the table goes at zero, with
    /// no walk over it per spend (bsv-low #591). Derived; never stored.
    live: usize,
}

/// The unspent outputs of a table.
fn live_of(outputs: &Option<Box<[Option<Retained>]>>) -> usize {
    outputs
        .as_ref()
        .map_or(0, |o| o.iter().filter(|slot| slot.is_some()).count())
}

/// Why a spend was refused. This is the interpreter's verdict on a
/// transaction, not a rule about the BEEF's bytes, and it is not one of the
/// twenty-five [`Kind`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRefusal {
    /// The parent is a txid-only entry: its output is not in the BEEF.
    ParentIsTxidOnly,
    /// The parent has no unspent output at the index the input names: it
    /// never had one, or an earlier input of this BEEF spent it.
    OutputNotAvailable {
        /// The index.
        vout: u32,
    },
    /// The script interpreter refused the spend.
    Script(String),
    /// The evaluator declined on a LOCAL resource, never an invalid script.
    Resource(crate::script::ScriptResourceLimit),
    /// The transaction's outputs are worth more than its inputs.
    CreatesValue,
    /// An input value or running input total outside the sibling's MoneyRange.
    InputValueOutOfRange,
    /// An exact P2SH output template in a regular transaction mined after Genesis.
    P2shOutput {
        /// Output index, named at the output value field.
        vout: u32,
    },
    /// Not final for mining in the next block under the supplied headers.
    NonFinal {
        /// Transaction lock time, named at its leading byte.
        lock_time: u32,
    },
    /// A proven coinbase output has not matured for the next block.
    PrematureCoinbase {
        /// The coinbase's verified block height; named at the spending input.
        height: u64,
    },
}

/// The refusal as one sentence (#213): the interpreter's words for a script,
/// the interpreter's resource sentence for a decline, each other arm its
/// rule. The texts are pinned (`tests/beef_stream.rs`,
/// `a_spend_refusal_prints_*`): a host matches on them.
impl fmt::Display for SpendRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpendRefusal::ParentIsTxidOnly => write!(
                f,
                "the parent is a txid-only entry: its output is not in the BEEF"
            ),
            SpendRefusal::OutputNotAvailable { vout } => {
                write!(f, "the parent has no unspent output at vout {vout}")
            }
            SpendRefusal::Script(reason) => f.write_str(reason),
            // `ScriptResourceLimit` has no `Display`: the sentence is the
            // interpreter's own (`src/script/spend/limits.rs`,
            // `resource_error` and `work_error`), from the fields it carries.
            SpendRefusal::Resource(limit) => {
                let budget = limit.limit;
                match limit.resource {
                    ScriptResource::Stack => {
                        write!(f, "Stack memory usage has exceeded {budget} bytes")
                    }
                    ScriptResource::AltStack => {
                        write!(f, "Alt stack memory usage has exceeded {budget} bytes")
                    }
                    ScriptResource::ElementSize => {
                        write!(f, "Script element allocation has exceeded {budget} bytes")
                    }
                    ScriptResource::Work => write!(
                        f,
                        "Work budget exhausted: spent {} units, budget {budget}",
                        limit.work_spent.unwrap_or(0)
                    ),
                }
            }
            SpendRefusal::CreatesValue => {
                write!(f, "the transaction's outputs are worth more than its inputs")
            }
            SpendRefusal::InputValueOutOfRange => write!(
                f,
                "an input value or running input total is outside MoneyRange"
            ),
            SpendRefusal::P2shOutput { vout } => write!(
                f,
                "an exact P2SH output template at vout {vout} in a regular transaction mined after Genesis"
            ),
            SpendRefusal::NonFinal { lock_time } => write!(
                f,
                "the transaction is not final for mining in the next block under the supplied headers: lock_time {lock_time}"
            ),
            SpendRefusal::PrematureCoinbase { height } => write!(
                f,
                "a proven coinbase output at height {height} has not matured for the next block"
            ),
        }
    }
}

/// A mining check that cannot be judged without header context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningCheck {
    /// Next-block transaction finality.
    Finality,
    /// Coinbase maturity at the next block's height.
    CoinbaseMaturity,
}

/// What stops a step: invalid bytes, or a spend the interpreter refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The reader declined: missing context is never invalid bytes or an invalid spend.
    Unverifiable {
        /// Transaction or input offset.
        offset: u64,
        /// Spending transaction.
        txid: Hash32,
        /// Input, when named.
        input: Option<u32>,
        /// Check whose context is absent.
        check: MiningCheck,
    },
    /// The bytes are invalid.
    Invalid(Refusal),
    /// A spend was refused.
    Spend {
        /// The offset of the input (or of the transaction, for the value rule).
        offset: u64,
        /// The spending transaction.
        txid: Hash32,
        /// The input, when one input is named.
        input: Option<u32>,
        /// Why.
        why: SpendRefusal,
    },
}

impl From<Refusal> for Stop {
    fn from(r: Refusal) -> Self {
        Stop::Invalid(r)
    }
}

/// The reader's state: what it keeps of the elements it has read.
///
/// One entry per BUMP, one per transaction, and one per txid a BUMP carries
/// at level 0. When spends are checked, each transaction's unspent outputs
/// are kept until a later input spends them: every output in one pass (the
/// reader cannot know which will be spent), or only the outputs a first pass
/// named ([`BeefIndex::retaining`]). Never a sibling hash, never an
/// unlocking script, never a transaction's bytes after its step.
///
/// The tables are keyed by digests a stranger chose (a BUMP's leaves are not
/// hashed here), so they keep the standard library's keyed hasher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeefIndex {
    /// Height and root of each BUMP, by position.
    bumps: Vec<(u64, Hash32)>,
    /// Each level-0 txid and the earliest BUMP that carries it.
    proven: HashMap<Hash32, u64>,
    /// A txid carried again by a later BUMP.
    proven_again: HashSet<(Hash32, u64)>,
    txs: HashMap<Hash32, TxEntry>,
    /// The last raw transaction and its offset.
    last_raw: Option<(Hash32, u64)>,
    /// A subject is known, so the atomic rule will be judged and each raw
    /// transaction's `prevs` are kept ([`BeefIndex::hold_to_subject`]).
    atomic: bool,
    /// The inputs of the raw transactions folded in, a repeat counted again:
    /// the Lean's `edges`, kept or not (a count, not a table).
    inputs: u64,
    steps: u64,
    work: u64,
    check_spends: bool,
    /// The outputs worth keeping, when a first pass named them: the outpoints
    /// the unproven inputs of the BEEF spend, less the ones spent so far.
    /// `None` keeps every output until it is spent.
    wanted: Option<HashSet<(Hash32, u32)>>,
}

/// The outpoints the unproven transactions of a BEEF spend: what a first
/// pass over the stream learns, so that the verifying pass keeps the outputs
/// that will be spent and no others ([`referenced_outpoints`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Referenced(HashSet<(Hash32, u32)>);

impl Referenced {
    /// The outpoints named.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No outpoint is named.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl BeefIndex {
    /// An empty index that checks spends.
    pub fn new() -> Self {
        Self::with_spend_checks(true)
    }

    /// An empty index for the BEEF's structure alone: the Lean's validity.
    pub fn structure_only() -> Self {
        Self::with_spend_checks(false)
    }

    fn with_spend_checks(check_spends: bool) -> Self {
        Self {
            bumps: Vec::new(),
            proven: HashMap::new(),
            proven_again: HashSet::new(),
            txs: HashMap::new(),
            last_raw: None,
            atomic: false,
            inputs: 0,
            steps: 0,
            work: 0,
            check_spends,
            wanted: None,
        }
    }

    /// An empty index that checks spends and keeps only the outputs
    /// `referenced` names. With the set a first pass over the same stream
    /// gave, the verdict is the verdict of [`BeefIndex::new`]; with any other
    /// set an output a spend needs may be missing, which refuses the spend
    /// and never accepts one.
    pub fn retaining(referenced: Referenced) -> Self {
        let mut index = Self::with_spend_checks(true);
        index.wanted = Some(referenced.0);
        index
    }

    /// The outpoints still waited for, when a first pass named them.
    pub fn wanted_outpoints(&self) -> Option<u64> {
        self.wanted.as_ref().map(|w| w.len() as u64)
    }

    /// The elements folded in.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Keeps what the atomic rule needs: the txids each raw transaction's
    /// inputs name, the edges of the subject's graph (0.8.1). The readers
    /// call it when a subject is known (the caller's, or the prefix's once
    /// the header is read), before the first element; a transaction folded
    /// without it carries no edges, so [`finish`](Self::finish) under a
    /// subject reaches less and refuses more, never accepts wrongly.
    pub fn hold_to_subject(&mut self) {
        self.atomic = true;
    }

    /// The entries the index holds: one per BUMP, one per transaction, one
    /// per (level-0 txid, BUMP) pair, and, under a subject, one per input of
    /// a raw transaction (its edge, 41 bytes or more on the wire).
    pub fn entries(&self) -> u64 {
        let edges: usize = self.txs.values().map(|e| e.prevs.len()).sum();
        (self.bumps.len() + self.proven.len() + self.proven_again.len() + self.txs.len() + edges)
            as u64
    }

    /// The Lean's `Index.size` for this state: its index keeps a BUMP's
    /// level-0 txids twice (the BUMP's own set and the proven set) and one
    /// edge per input of every raw transaction read, a repeat's again, with
    /// or without a subject (0.8.1). So this is the BUMPs, the transactions,
    /// the (level-0 txid, BUMP) pairs, the distinct proven txids once more,
    /// and the inputs counted. The bound `memory_bounded_per_element` is
    /// stated on this number; this index keeps the edges only under a
    /// subject, and a repeat's once.
    pub fn spec_size(&self) -> u64 {
        (self.bumps.len() + 2 * self.proven.len() + self.proven_again.len() + self.txs.len()) as u64
            + self.inputs
    }

    /// The Lean cost model's count for the elements folded in: one unit per
    /// byte, per table operation and per hash (`Parsed.cost`). A count, for
    /// comparison with the Lean's rows; not a measurement.
    pub fn model_work(&self) -> u64 {
        self.work
    }

    /// The outputs kept for later inputs, and their script bytes.
    pub fn retained_outputs(&self) -> (u64, u64) {
        let mut count = 0u64;
        let mut bytes = 0u64;
        for entry in self.txs.values() {
            for out in entry.outputs.iter().flat_map(|o| o.iter()).flatten() {
                count += 1;
                bytes += out.script.len() as u64;
            }
        }
        (count, bytes)
    }

    /// The roots checked, by BUMP position: height and root (wire order).
    pub fn roots(&self) -> &[(u64, Hash32)] {
        &self.bumps
    }

    /// BUMP `index` carries `txid` at level 0.
    fn bump_carries(&self, index: u64, txid: &Hash32) -> bool {
        self.proven.get(txid) == Some(&index) || self.proven_again.contains(&(*txid, index))
    }

    /// Folds one element in (the Lean's `fold`): the checks against the
    /// index and the headers, then the index grown by what the element adds.
    /// On a refusal the index is unchanged.
    pub fn fold<H: Headers + ?Sized>(
        &mut self,
        element: &Element,
        headers: &H,
    ) -> Result<(), Stop> {
        match element {
            Element::Bump(bump) => {
                let carried = headers.carries(bump.block_height, &bump.root);
                self.fold_bump(bump, carried)
            }
            other => self.fold_checked(other, headers.mining_tip()),
        }
    }

    /// [`fold`](Self::fold) for a BUMP whose header answer the caller already
    /// has (an asynchronous header lookup).
    pub fn fold_bump(&mut self, bump: &Bump, carried: bool) -> Result<(), Stop> {
        if !carried {
            return Err(Refusal::new(
                bump.offset,
                Reason::RootNotCarried {
                    height: bump.block_height,
                    root: bump.root,
                },
            )
            .into());
        }
        let position = self.bumps.len() as u64;
        self.bumps.push((bump.block_height, bump.root));
        let mut hashed = 0u64;
        for txid in bump.proven() {
            hashed += 1;
            match self.proven.get(txid) {
                None => {
                    self.proven.insert(*txid, position);
                }
                Some(earliest) if *earliest != position => {
                    self.proven_again.insert((*txid, position));
                }
                Some(_) => {}
            }
        }
        let leaves: u64 = bump.levels.iter().map(|l| l.len() as u64).sum();
        let walk = 2 * leaves + 6 * bump.levels.len() as u64 * hashed;
        self.steps += 1;
        self.work += bump.wire_len + walk + 1 + 2 * hashed;
        Ok(())
    }

    /// A transaction or a txid-only entry.
    fn fold_checked(&mut self, element: &Element, tip: Option<ChainTip>) -> Result<(), Stop> {
        self.fold_checked_from(element, 0, &mut || false, None, tip)
            .map(|paused| debug_assert!(paused.is_none(), "a budget never spent"))
    }

    /// [`fold_checked`](Self::fold_checked) with the scripts run from input
    /// `from` and `spent` asked between inputs. `Ok(Some(i))` is a pause
    /// before input `i`: the index is unchanged.
    fn fold_checked_from(
        &mut self,
        element: &Element,
        from: u32,
        spent: &mut dyn FnMut() -> bool,
        work_limit: Option<u64>,
        tip: Option<ChainTip>,
    ) -> Result<Option<u32>, Stop> {
        match element {
            Element::Bump(_) => unreachable!("a BUMP is folded with its header answer"),
            Element::TxidOnly { offset, txid } => {
                if !self.proven.contains_key(txid) {
                    return Err(Refusal::new(*offset, Reason::StubNotProven { txid: *txid }).into());
                }
                self.txs.entry(*txid).or_insert(TxEntry {
                    at: *offset,
                    prevs: Box::default(),
                    raw: false,
                    reached: false,
                    coinbase_height: None,
                    outputs: None,
                    live: 0,
                });
                self.steps += 1;
                self.work += 32 + 3;
                Ok(None)
            }
            Element::Tx {
                offset,
                txid,
                bump_index,
                body,
            } => {
                // Hand-built elements obey the decoder's mining byte checks
                // in the same order, even when the index has seen this txid.
                check_transaction(*offset, &body.inputs, &body.outputs, *bump_index)?;
                // The Lean's `checkTx`: with a BUMP index, the BUMP carries
                // the txid and its proof vouches for the inputs; without one,
                // each input names an earlier transaction of this BEEF.
                match bump_index {
                    Some(index) => {
                        if *index >= self.bumps.len() as u64 {
                            return Err(Refusal::new(
                                *offset,
                                Reason::BumpIndexNamesNoBump { index: *index },
                            )
                            .into());
                        }
                        if !self.bump_carries(*index, txid) {
                            return Err(Refusal::new(
                                *offset,
                                Reason::TxidNotInBump {
                                    index: *index,
                                    txid: *txid,
                                },
                            )
                            .into());
                        }
                    }
                    None => {
                        for input in &body.inputs {
                            if !self.txs.contains_key(&input.prev) {
                                return Err(Refusal::new(
                                    input.at,
                                    Reason::InputNamesNoElement { txid: input.prev },
                                )
                                .into());
                            }
                        }
                    }
                }

                // A transaction read before was judged then; its bytes are
                // the same bytes.
                let seen = self.txs.get(txid).is_some_and(|e| e.raw);
                if self.check_spends && !seen {
                    if bump_index.is_none() {
                        // [SRC] sibling@87f0461 Properties/P2SH.lean:198-204.
                        let after_genesis = tip
                            .is_none_or(|t| u64::from(t.height) + 1 >= u64::from(t.genesis_height));
                        if after_genesis {
                            for (vout, output) in body.outputs.iter().enumerate() {
                                let script = &body.raw[output.script.clone()];
                                if script.len() == 23
                                    && script[0] == 0xa9
                                    && script[1] == 0x14
                                    && script[22] == 0x87
                                {
                                    return Err(Stop::Spend {
                                        offset: output.at,
                                        txid: *txid,
                                        input: None,
                                        why: SpendRefusal::P2shOutput { vout: vout as u32 },
                                    });
                                }
                            }
                        }
                        // [SRC] sibling@87f0461 BLOCK-CONSENSUS.md:83-88,
                        // node@879fc8b42 validation.cpp:228-248 as cited there.
                        if body.lock_time != 0 && body.inputs.iter().any(|i| i.sequence != u32::MAX)
                        {
                            let unavailable = || Stop::Unverifiable {
                                offset: *offset,
                                txid: *txid,
                                input: None,
                                check: MiningCheck::Finality,
                            };
                            let context = tip.ok_or_else(unavailable)?;
                            let next_height = u64::from(context.height) + 1;
                            let limit = if body.lock_time < 500_000_000 {
                                next_height
                            } else if next_height >= u64::from(context.csv_height) {
                                u64::from(context.median_time_past)
                            } else {
                                u64::from(context.next_block_time.ok_or_else(unavailable)?)
                            };
                            if u64::from(body.lock_time) >= limit {
                                return Err(Stop::Spend {
                                    offset: *offset,
                                    txid: *txid,
                                    input: None,
                                    why: SpendRefusal::NonFinal {
                                        lock_time: body.lock_time,
                                    },
                                });
                            }
                        }
                        if let Some(next) =
                            self.check_spends_of(*offset, txid, body, from, spent, work_limit, tip)?
                        {
                            return Ok(Some(next));
                        }
                    }
                    for input in &body.inputs {
                        self.spend_output(&input.prev, input.vout);
                    }
                }
                self.inputs += body.inputs.len() as u64;
                let atomic = self.atomic;
                let prevs = move || -> Box<[Hash32]> {
                    if atomic {
                        body.inputs.iter().map(|input| input.prev).collect()
                    } else {
                        Box::default()
                    }
                };
                let keep = |vout: usize| match &self.wanted {
                    Some(wanted) => u32::try_from(vout).is_ok_and(|v| wanted.contains(&(*txid, v))),
                    None => true,
                };
                let outputs = (self.check_spends && !seen)
                    .then(|| {
                        body.outputs
                            .iter()
                            .enumerate()
                            .map(|(vout, o)| {
                                keep(vout).then(|| Retained {
                                    satoshis: o.satoshis,
                                    script: body.raw[o.script.clone()].into(),
                                })
                            })
                            .collect::<Box<[_]>>()
                    })
                    .filter(|outputs| outputs.iter().any(Option::is_some));
                let coinbase_height = if is_coinbase(&body.inputs) {
                    bump_index.map(|index| self.bumps[index as usize].0)
                } else {
                    None
                };
                match self.txs.get_mut(txid) {
                    Some(entry) => {
                        if !entry.raw {
                            entry.raw = true;
                            entry.prevs = prevs();
                            entry.coinbase_height = coinbase_height;
                            entry.live = live_of(&outputs);
                            entry.outputs = outputs;
                        }
                    }
                    None => {
                        let prevs = prevs();
                        self.txs.insert(
                            *txid,
                            TxEntry {
                                at: *offset,
                                prevs,
                                raw: true,
                                reached: false,
                                coinbase_height,
                                live: live_of(&outputs),
                                outputs,
                            },
                        );
                    }
                }
                self.last_raw = Some((*txid, *offset));
                self.steps += 1;
                self.work += body.raw.len() as u64 + 5 + 2 * body.inputs.len() as u64;
                Ok(None)
            }
        }
    }

    /// The output an input names is spent: dropped, and its table with it
    /// when it was the last.
    fn spend_output(&mut self, prev: &Hash32, vout: u32) {
        if let Some(wanted) = self.wanted.as_mut() {
            wanted.remove(&(*prev, vout));
        }
        let Some(parent) = self.txs.get_mut(prev) else {
            return;
        };
        let Some(outputs) = parent.outputs.as_mut() else {
            return;
        };
        if let Some(slot) = outputs.get_mut(vout as usize) {
            if slot.take().is_some() {
                parent.live -= 1;
            }
        }
        if parent.live == 0 {
            parent.outputs = None;
        }
    }

    /// The spends of an unproven transaction: each input's script executed
    /// against the parent output the index kept, and the value rule
    /// (`Transaction::verify`'s checks, in its order). Nothing is changed.
    ///
    /// The scripts run from input `from` on (the inputs before it were run by
    /// an earlier slice of the same reading, against the same index), and
    /// `spent` is asked between two inputs: `Ok(Some(i))` is a pause before
    /// input `i`, at least one input after `from` having run.
    #[allow(clippy::too_many_arguments)] // One resumed spend and its caller's mining context.
    #[allow(clippy::expect_used)] // #134: the reader indexed every parent before its spend; a SpendRefusal for a broken invariant is a public enum change
    fn check_spends_of(
        &self,
        offset: u64,
        txid: &Hash32,
        body: &TxBody,
        from: u32,
        spent: &mut dyn FnMut() -> bool,
        work_limit: Option<u64>,
        tip: Option<ChainTip>,
    ) -> Result<Option<u32>, Stop> {
        let refuse = |at: u64, input: Option<u32>, why: SpendRefusal| Stop::Spend {
            offset: at,
            txid: *txid,
            input,
            why,
        };
        let mut sources: Vec<&Retained> = Vec::with_capacity(body.inputs.len());
        let mut input_total: u64 = 0;
        for (vin, input) in body.inputs.iter().enumerate() {
            let vin = Some(vin as u32);
            let vout = input.vout;
            let parent = self
                .txs
                .get(&input.prev)
                .expect("the input names an earlier transaction");
            if !parent.raw {
                return Err(refuse(input.at, vin, SpendRefusal::ParentIsTxidOnly));
            }
            let slot = parent.outputs.as_ref().and_then(|o| o.get(vout as usize));
            let source = match slot {
                Some(Some(source)) => source,
                _ => {
                    return Err(refuse(
                        input.at,
                        vin,
                        SpendRefusal::OutputNotAvailable { vout },
                    ))
                }
            };
            // [SRC] sibling@87f0461 BLOCK-CONSENSUS.md:68,
            // node@879fc8b42 consensus/consensus.h:75 as cited there.
            if let Some(height) = parent.coinbase_height {
                let context = tip.ok_or(Stop::Unverifiable {
                    offset: input.at,
                    txid: *txid,
                    input: vin,
                    check: MiningCheck::CoinbaseMaturity,
                })?;
                if (u64::from(context.height) + 1)
                    .checked_sub(height)
                    .is_none_or(|depth| depth < 100)
                {
                    return Err(refuse(
                        input.at,
                        vin,
                        SpendRefusal::PrematureCoinbase { height },
                    ));
                }
            }
            if source.satoshis > MAX_MONEY || source.satoshis > MAX_MONEY - input_total {
                return Err(refuse(input.at, vin, SpendRefusal::InputValueOutOfRange));
            }
            input_total += source.satoshis;
            sources.push(source);
        }
        let mut output_total: u64 = 0;
        for output in &body.outputs {
            // check_transaction bounded every prefix by MAX_MONEY.
            output_total += output.satoshis;
            debug_assert!(output_total <= MAX_MONEY);
        }

        // One input list and one output list for the transaction, shared by
        // every input's spend with the sighash midstates: hashPrevouts,
        // hashSequence and hashOutputs are computed at most once per scope
        // class here, never once per input (bsv-low #591). The digest reads
        // no input's script, so the shared inputs carry none.
        let outputs: Vec<TxOutput> = body
            .outputs
            .iter()
            .map(|o| TxOutput {
                satoshis: o.satoshis,
                script: body.raw[o.script.clone()].to_vec(),
            })
            .collect();
        let inputs: Vec<TxInput> = body
            .inputs
            .iter()
            .map(|i| TxInput {
                txid: i.prev,
                output_index: i.vout,
                script: Vec::new(),
                sequence: i.sequence,
            })
            .collect();
        let shared = Arc::new(TxSighashCache::new(
            body.version as i32,
            inputs,
            outputs,
            body.lock_time,
        ));
        for (vin, (input, source)) in body
            .inputs
            .iter()
            .zip(sources)
            .enumerate()
            .skip(from as usize)
        {
            // The clock between inputs (bsv-low #591): one transaction of
            // many inputs is no longer one uninterruptible step.
            if vin > from as usize && spent() {
                return Ok(Some(vin as u32));
            }
            let script_error =
                |message: String| refuse(input.at, Some(vin as u32), SpendRefusal::Script(message));
            let locking_script = LockingScript::from_binary(&source.script)
                .map_err(|e| script_error(e.to_string()))?;
            let unlocking_script = UnlockingScript::from_binary(&body.raw[input.script.clone()])
                .map_err(|e| script_error(e.to_string()))?;
            let mut spend = Spend::with_transaction(TxSpendParams {
                transaction: shared.clone(),
                input_index: vin,
                source_satoshis: source.satoshis,
                locking_script,
                unlocking_script,
                memory_limit: None,
                work_limit,
            })
            .map_err(|e| script_error(e.to_string()))?;
            match spend.validate() {
                Ok(true) => {}
                Ok(false) => return Err(script_error("the script did not succeed".to_string())),
                Err(e) => {
                    return Err(match e.resource_limit {
                        Some(limit) => {
                            refuse(input.at, Some(vin as u32), SpendRefusal::Resource(limit))
                        }
                        None => script_error(e.message),
                    })
                }
            }
        }
        // The reference's value rule: an unmined transaction may not create
        // satoshis. (A transaction with no inputs never comes this far: it
        // is `NoInputs` at the fold.)
        if output_total > input_total {
            return Err(refuse(offset, None, SpendRefusal::CreatesValue));
        }
        Ok(None)
    }

    /// The atomic check at the end (the Lean's `finish`), on the subject's
    /// graph (BRC-95, 0.8.1): the subject is a raw transaction of the BEEF,
    /// else `SubjectMissing` at `subject_at`; then one walk from the subject
    /// over the inputs of raw entries (the `prevs` kept under the subject),
    /// and every entry, raw or txid-only, must be reached. Position is not
    /// judged. The entry a refusal names is the earliest the walk does not
    /// reach in the Lean's trie order (the txid's bytes, each byte's bits
    /// reversed, least first), at its offset.
    pub fn finish(&mut self, subject: Option<&Hash32>, subject_at: u64) -> Result<(), Refusal> {
        let Some(subject) = subject else {
            return Ok(());
        };
        let unreached = atomic_unreached(subject, &mut self.txs)
            .map_err(|_| Refusal::new(subject_at, Reason::SubjectMissing { subject: *subject }))?;
        if let Some(txid) = unreached {
            return Err(Refusal::new(
                self.txs[&txid].at,
                Reason::UnrelatedTransaction { txid },
            ));
        }
        // The pass over the table and the walk's fuel three times (one per
        // entry, one per edge, two for the subject).
        let entries = self.txs.len() as u64;
        self.work += entries + 3 * (entries + self.inputs + 2);
        Ok(())
    }
}

impl Default for BeefIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// BRC-95's atomic rule on the subject's dependency graph: the one walk of
/// both readers ([`BeefIndex::finish`] and `Beef::verify_structure`, 0.8.1;
/// the Lean's `finish`). `table` holds the BEEF's entries by txid (internal
/// byte order), each read as raw or not, with the txids its inputs name
/// ([`AtomicNode`]). The subject is a raw entry, else [`Kind::SubjectMissing`]; then
/// one walk from the subject over the inputs of raw entries, and the answer
/// is the entry it does not reach that comes earliest in the Lean's trie
/// order (the txid's bytes, each byte's bits reversed, least first), or
/// none when it reaches every entry.
///
/// Position is not judged: BRC-95 (`BRCs transactions/0095.md`) defines the
/// rule on the graph, the TypeScript writer puts every proven transaction
/// before the unproven ones (a raw unproven ancestor can follow its proven
/// descendant), and the Go writer puts the subject last. Until 0.8.0 both
/// readers counted a spend only by a transaction read after its parent, and
/// refused the first shape (the bsv-dd x402 refund, P0-65). The graph
/// follows the inputs of every raw entry, proven or not (the owner's ruling,
/// 2026-10-22); `@bsv/sdk` 3 cuts it at each proven transaction (ts-stack
/// `Beef.ts:420-434`) and refuses a raw ancestor behind a proof, a stated
/// divergence. This crate's writer emits the cut closure
/// (`Beef::to_binary_atomic`), which every reader accepts.
pub(crate) fn atomic_unreached<T: AtomicNode>(
    subject: &Hash32,
    table: &mut HashMap<Hash32, T>,
) -> Result<Option<Hash32>, Kind> {
    if !table.get(subject).is_some_and(|e| e.raw()) {
        return Err(Kind::SubjectMissing);
    }
    // The Lean's `walk`: a txid the table carries and the walk has not
    // reached is reached, and the txids its inputs name are to be taken. The
    // mark is the entry's own: the walk allocates no table beside it.
    let mut todo: Vec<Hash32> = vec![*subject];
    while let Some(txid) = todo.pop() {
        if let Some(entry) = table.get_mut(&txid) {
            if !*entry.reached() {
                *entry.reached() = true;
                todo.extend_from_slice(entry.prevs());
            }
        }
    }
    // The Lean's `failing` over the table, the marks cleared as it passes.
    let trie_order = |txid: &Hash32| txid.map(u8::reverse_bits);
    let mut unreached: Option<Hash32> = None;
    for (txid, entry) in table.iter_mut() {
        let reached = std::mem::take(entry.reached());
        if !reached && unreached.is_none_or(|u| trie_order(txid) < trie_order(&u)) {
            unreached = Some(*txid);
        }
    }
    Ok(unreached)
}

/// An entry as the atomic walk reads it ([`atomic_unreached`]).
pub(crate) trait AtomicNode {
    /// Its raw bytes are in the BEEF (a txid-only entry's are not).
    fn raw(&self) -> bool;
    /// The txids its inputs name, when it is raw.
    fn prevs(&self) -> &[Hash32];
    /// The walk's mark, false between walks.
    fn reached(&mut self) -> &mut bool;
}

impl AtomicNode for TxEntry {
    fn raw(&self) -> bool {
        self.raw
    }
    fn prevs(&self) -> &[Hash32] {
        &self.prevs
    }
    fn reached(&mut self) -> &mut bool {
        &mut self.reached
    }
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// The verdict of a reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A decline for missing mining context, never a transaction verdict.
    Unverifiable {
        /// Transaction or input offset.
        offset: u64,
        /// Spending transaction.
        txid: Hash32,
        /// Input, when named.
        input: Option<u32>,
        /// Check whose context is absent.
        check: MiningCheck,
    },
    /// Every element checked, every root carried.
    Valid {
        /// The subject the atomic rule was held to, if there was one.
        subject: Option<Hash32>,
        /// The roots checked, by BUMP position: block height and root (wire
        /// order).
        roots: Vec<(u64, Hash32)>,
    },
    /// The bytes are invalid: the offset of the byte and one of the twenty-five
    /// kinds.
    Invalid {
        /// The stream offset of the byte the refusal names.
        offset: u64,
        /// The kind.
        kind: Kind,
        /// The kind with its data.
        reason: Reason,
    },
    /// The BEEF's bytes are well formed up to here and the interpreter
    /// refused a spend. Not one of the twenty-five kinds: the verdict is the
    /// script's, on a transaction. `SpendRefusal::Resource` is a LOCAL
    /// evaluator decline: this spend was not judged invalid.
    SpendRefused {
        /// The offset of the input (or of the transaction, for the value
        /// rule).
        offset: u64,
        /// The spending transaction.
        txid: Hash32,
        /// The input, when one input is named.
        input: Option<u32>,
        /// Why.
        why: SpendRefusal,
    },
}

impl Verdict {
    /// The reading ended without a refusal.
    pub fn is_valid(&self) -> bool {
        matches!(self, Verdict::Valid { .. })
    }
}

impl From<Refusal> for Verdict {
    fn from(r: Refusal) -> Self {
        Verdict::Invalid {
            offset: r.offset,
            kind: r.reason.kind(),
            reason: r.reason,
        }
    }
}

impl From<Stop> for Verdict {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::Unverifiable {
                offset,
                txid,
                input,
                check,
            } => Verdict::Unverifiable {
                offset,
                txid,
                input,
                check,
            },
            Stop::Invalid(r) => r.into(),
            Stop::Spend {
                offset,
                txid,
                input,
                why,
            } => Verdict::SpendRefused {
                offset,
                txid,
                input,
                why,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The cursor
// ---------------------------------------------------------------------------

/// The reader's state after `k` elements: the frame's position, the index,
/// and nothing of the elements read.
///
/// A cursor is the verifier's own state. Its bytes are trusted as the state
/// they encode: keep them where the party sending the BEEF cannot write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    frame: Frame,
    index: BeefIndex,
    /// The subject the caller named.
    subject: Option<Hash32>,
    /// A reading paused inside a transaction: the frame and the index are
    /// the state before it, and this names it and the input reached.
    pending: Option<Pending>,
}

/// The transaction a paused reading stands in and the input it reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    /// The transaction's stream offset (its raw bytes' leading byte; the
    /// frame stands at the element's first byte, at or before it).
    offset: u64,
    txid: Hash32,
    /// The first input whose script has not run.
    input: u32,
}

const CURSOR_MAGIC: &[u8; 4] = b"BSC3";
/// 0.5.0 to 0.8.0's layout: BSC3 without the input count and the edges,
/// and a transaction's flags byte carrying a spent bit (ignored).
const CURSOR_MAGIC_BSC2: &[u8; 4] = b"BSC2";

impl Cursor {
    /// The elements read.
    pub fn elements_read(&self) -> u64 {
        self.frame.k
    }

    /// The stream offset the rest of the BEEF starts at: where the source
    /// handed to [`StreamVerifier::resume`] must be positioned.
    pub fn offset(&self) -> u64 {
        self.frame.pos
    }

    /// The index.
    pub fn index(&self) -> &BeefIndex {
        &self.index
    }

    /// The input a reading paused inside a transaction reached: the
    /// transaction starts at [`offset`](Self::offset), the scripts of the
    /// inputs before this one have run, and a resume runs them from this one
    /// on. `None` between two elements.
    pub fn input_reached(&self) -> Option<u32> {
        self.pending.map(|p| p.input)
    }

    /// The cursor's bytes. Equal states give equal bytes; a cursor between
    /// two elements encodes the verified coinbase heights as well, and (BSC3,
    /// 0.8.1) the inputs counted and the edges the atomic walk follows: each
    /// raw transaction's prevs, by txid strictly ascending.
    /// [`from_binary`](Self::from_binary) reads a BSC2 cursor as BSC3 with no
    /// edge for a transaction read before it: the walk reaches less, so it
    /// only refuses more, never accepts wrongly. BSC1 is refused: restart
    /// its reading.
    /// A paused cursor appends the transaction and the input reached.
    pub fn to_binary(&self) -> Vec<u8> {
        fn put_hash(w: &mut Writer, h: &Option<Hash32>) {
            match h {
                Some(h) => {
                    w.write_u8(1);
                    w.write_bytes(h);
                }
                None => {
                    w.write_u8(0);
                }
            }
        }
        let mut w = Writer::new();
        w.write_bytes(CURSOR_MAGIC);
        w.write_u8(self.index.check_spends as u8);
        put_hash(&mut w, &self.subject);
        w.write_u64_le(self.frame.pos);
        w.write_u64_le(self.frame.k);
        w.write_u8(match self.frame.phase {
            Phase::Head => 0,
            Phase::Bumps => 1,
            Phase::Txs => 2,
        });
        w.write_u32_le(self.frame.version);
        put_hash(&mut w, &self.frame.subject);
        w.write_u64_le(self.frame.bumps_left);
        w.write_u64_le(self.frame.txs_left);

        let index = &self.index;
        w.write_u64_le(index.steps);
        w.write_u64_le(index.work);
        match &index.last_raw {
            Some((txid, at)) => {
                w.write_u8(1);
                w.write_bytes(txid);
                w.write_u64_le(*at);
            }
            None => {
                w.write_u8(0);
            }
        }
        w.write_var_int(index.bumps.len() as u64);
        for (height, root) in &index.bumps {
            w.write_u64_le(*height);
            w.write_bytes(root);
        }
        let mut proven: Vec<(&Hash32, &u64)> = index.proven.iter().collect();
        proven.sort_unstable();
        w.write_var_int(proven.len() as u64);
        for (txid, position) in proven {
            w.write_bytes(txid);
            w.write_u64_le(*position);
        }
        let mut again: Vec<&(Hash32, u64)> = index.proven_again.iter().collect();
        again.sort_unstable();
        w.write_var_int(again.len() as u64);
        for (txid, position) in again {
            w.write_bytes(txid);
            w.write_u64_le(*position);
        }
        let mut txs: Vec<(&Hash32, &TxEntry)> = index.txs.iter().collect();
        txs.sort_unstable_by_key(|(txid, _)| *txid);
        w.write_var_int(txs.len() as u64);
        for (txid, entry) in txs {
            w.write_bytes(txid);
            w.write_u64_le(entry.at);
            w.write_u8((entry.raw as u8) << 1);
            match entry.coinbase_height {
                Some(height) => {
                    w.write_u8(1);
                    w.write_u64_le(height);
                }
                None => {
                    w.write_u8(0);
                }
            }
            match &entry.outputs {
                None => {
                    w.write_var_int(0);
                }
                Some(outputs) => {
                    w.write_var_int(outputs.len() as u64);
                    for slot in outputs.iter() {
                        match slot {
                            None => {
                                w.write_u8(0);
                            }
                            Some(out) => {
                                w.write_u8(1);
                                w.write_u64_le(out.satoshis);
                                w.write_var_bytes(&out.script);
                            }
                        }
                    }
                }
            }
        }
        // The atomic walk's edges (0.8.1): the inputs counted, then each raw
        // transaction's prevs, by txid ascending.
        w.write_u64_le(index.inputs);
        let mut edges: Vec<(&Hash32, &TxEntry)> = index
            .txs
            .iter()
            .filter(|(_, e)| !e.prevs.is_empty())
            .collect();
        edges.sort_unstable_by_key(|(txid, _)| *txid);
        w.write_var_int(edges.len() as u64);
        for (txid, entry) in edges {
            w.write_bytes(txid);
            w.write_var_int(entry.prevs.len() as u64);
            for prev in entry.prevs.iter() {
                w.write_bytes(prev);
            }
        }
        match &index.wanted {
            None => {
                w.write_u8(0);
            }
            Some(wanted) => {
                w.write_u8(1);
                let mut wanted: Vec<&(Hash32, u32)> = wanted.iter().collect();
                wanted.sort_unstable();
                w.write_var_int(wanted.len() as u64);
                for (txid, vout) in wanted {
                    w.write_bytes(txid);
                    w.write_u32_le(*vout);
                }
            }
        }
        if let Some(pending) = &self.pending {
            w.write_u8(1);
            w.write_u64_le(pending.offset);
            w.write_bytes(&pending.txid);
            w.write_u32_le(pending.input);
        }
        w.into_bytes()
    }

    /// A cursor from its bytes.
    pub fn from_binary(bin: &[u8]) -> crate::Result<Self> {
        fn bad(what: &str) -> crate::Error {
            crate::Error::BeefError(format!("not a cursor: {what}"))
        }
        fn hash(r: &mut Reader) -> crate::Result<Hash32> {
            let mut h = [0u8; 32];
            h.copy_from_slice(r.read_bytes(32)?);
            Ok(h)
        }
        fn opt_hash(r: &mut Reader) -> crate::Result<Option<Hash32>> {
            match r.read_u8()? {
                0 => Ok(None),
                1 => Ok(Some(hash(r)?)),
                _ => Err(bad("a presence byte")),
            }
        }
        let mut r = Reader::new(bin);
        let bsc3 = match r.read_bytes(4)? {
            magic if magic == CURSOR_MAGIC => true,
            magic if magic == CURSOR_MAGIC_BSC2 => false,
            _ => return Err(bad("the leading word")),
        };
        let check_spends = match r.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(bad("the mode byte")),
        };
        let subject = opt_hash(&mut r)?;
        let pos = r.read_u64_le()?;
        let k = r.read_u64_le()?;
        let phase = match r.read_u8()? {
            0 => Phase::Head,
            1 => Phase::Bumps,
            2 => Phase::Txs,
            _ => return Err(bad("the phase byte")),
        };
        let version = r.read_u32_le()?;
        let frame_subject = opt_hash(&mut r)?;
        let bumps_left = r.read_u64_le()?;
        let txs_left = r.read_u64_le()?;
        let frame = Frame {
            pos,
            k,
            phase,
            version,
            subject: frame_subject,
            bumps_left,
            txs_left,
        };

        let mut index = BeefIndex::with_spend_checks(check_spends);
        index.steps = r.read_u64_le()?;
        index.work = r.read_u64_le()?;
        index.last_raw = match r.read_u8()? {
            0 => None,
            1 => {
                let txid = hash(&mut r)?;
                Some((txid, r.read_u64_le()?))
            }
            _ => return Err(bad("a presence byte")),
        };
        for _ in 0..r.read_var_int()? {
            let height = r.read_u64_le()?;
            index.bumps.push((height, hash(&mut r)?));
        }
        for _ in 0..r.read_var_int()? {
            let txid = hash(&mut r)?;
            index.proven.insert(txid, r.read_u64_le()?);
        }
        for _ in 0..r.read_var_int()? {
            let txid = hash(&mut r)?;
            index.proven_again.insert((txid, r.read_u64_le()?));
        }
        for _ in 0..r.read_var_int()? {
            let txid = hash(&mut r)?;
            let at = r.read_u64_le()?;
            let flags = r.read_u8()?;
            // BSC2's spent bit (bit 0) is read and dropped; BSC3 writes none.
            if flags > 3 || (bsc3 && flags & 1 == 1) {
                return Err(bad("a transaction's flags"));
            }
            let coinbase_height = match r.read_u8()? {
                0 => None,
                1 => Some(r.read_u64_le()?),
                _ => return Err(bad("a coinbase height presence byte")),
            };
            let n = r.read_var_int()?;
            let outputs = if n == 0 {
                None
            } else {
                let mut outputs = Vec::new();
                for _ in 0..n {
                    outputs.push(match r.read_u8()? {
                        0 => None,
                        1 => {
                            let satoshis = r.read_u64_le()?;
                            Some(Retained {
                                satoshis,
                                script: r.read_var_bytes()?.into(),
                            })
                        }
                        _ => return Err(bad("a presence byte")),
                    });
                }
                Some(outputs.into_boxed_slice())
            };
            index.txs.insert(
                txid,
                TxEntry {
                    at,
                    prevs: Box::default(),
                    raw: flags & 2 == 2,
                    reached: false,
                    coinbase_height,
                    live: live_of(&outputs),
                    outputs,
                },
            );
        }
        // A BSC2 cursor carries no edges: the walk from it reaches less and
        // refuses more, never accepts wrongly.
        if bsc3 {
            index.inputs = r.read_u64_le()?;
            let mut previous: Option<Hash32> = None;
            for _ in 0..r.read_var_int()? {
                let txid = hash(&mut r)?;
                if previous.is_some_and(|p| p >= txid) {
                    return Err(bad("edges out of order"));
                }
                previous = Some(txid);
                let n = r.read_var_int()?;
                let mut prevs = Vec::new();
                for _ in 0..n {
                    prevs.push(hash(&mut r)?);
                }
                match index.txs.get_mut(&txid) {
                    Some(entry) if entry.raw && !prevs.is_empty() => {
                        entry.prevs = prevs.into_boxed_slice();
                    }
                    _ => return Err(bad("edges of no raw transaction")),
                }
            }
        }
        // The readers hold the index to a subject once one is known: the
        // caller's, or the prefix's once the header is read.
        index.atomic = subject.is_some() || frame_subject.is_some();
        index.wanted = match r.read_u8()? {
            0 => None,
            1 => {
                let mut wanted = HashSet::new();
                for _ in 0..r.read_var_int()? {
                    let txid = hash(&mut r)?;
                    wanted.insert((txid, r.read_u32_le()?));
                }
                Some(wanted)
            }
            _ => return Err(bad("a presence byte")),
        };
        let pending = if r.is_empty() {
            None
        } else {
            if r.read_u8()? != 1 {
                return Err(bad("a presence byte"));
            }
            let offset = r.read_u64_le()?;
            let txid = hash(&mut r)?;
            let input = r.read_u32_le()?;
            if offset < frame.pos {
                return Err(bad("a pause before its frame"));
            }
            Some(Pending {
                offset,
                txid,
                input,
            })
        };
        if !r.is_empty() {
            return Err(bad("bytes after its end"));
        }
        Ok(Self {
            frame,
            index,
            subject,
            pending,
        })
    }
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

/// The index and the subject: the half of the reader that judges, shared by
/// the reader over a [`Read`] and the asynchronous one.
struct Judge {
    index: BeefIndex,
    /// The subject the caller named.
    subject: Option<Hash32>,
    /// The caller's subject was held against the prefix's.
    subject_checked: bool,
    /// A resumed reading's transaction paused inside, until it is read.
    resume_at: Option<Pending>,
}

impl Judge {
    fn new(subject: Option<Hash32>, mut index: BeefIndex) -> Self {
        if subject.is_some() {
            index.hold_to_subject();
        }
        Self {
            index,
            subject,
            subject_checked: false,
            resume_at: None,
        }
    }

    fn resumed(cursor: Cursor) -> (Frame, Self) {
        let mut judge = Self::new(cursor.subject, cursor.index);
        if cursor.frame.subject.is_some() {
            judge.index.hold_to_subject();
        }
        judge.resume_at = cursor.pending;
        (cursor.frame, judge)
    }

    fn cursor(&self, decoder: &BeefDecoder) -> Cursor {
        Cursor {
            frame: decoder.frame.clone(),
            index: self.index.clone(),
            subject: self.subject,
            pending: self.resume_at,
        }
    }

    /// The input the scripts of `element` run from: the input a paused
    /// reading reached, when `element` is the transaction it paused in, else
    /// the first.
    fn start_of(&mut self, element: &Element) -> u32 {
        match (self.resume_at.take(), element) {
            (Some(p), Element::Tx { offset, txid, .. })
                if p.offset == *offset && p.txid == *txid =>
            {
                p.input
            }
            _ => 0,
        }
    }

    /// A subject the caller named and a prefix that names another: the 32
    /// bytes at offset 4 are not the subject asked for.
    fn check_named_subject(&mut self, decoder: &BeefDecoder) -> Result<(), Refusal> {
        if self.subject_checked || !decoder.header_read() {
            return Ok(());
        }
        self.subject_checked = true;
        // The header precedes the first element: a prefix's subject is known
        // before anything is folded.
        if decoder.subject().is_some() {
            self.index.hold_to_subject();
        }
        match (self.subject, decoder.subject()) {
            (Some(named), Some(prefixed)) if named != prefixed => {
                Err(Refusal::new(4, Reason::SubjectMissing { subject: named }))
            }
            _ => Ok(()),
        }
    }

    /// The end of the stream: the atomic rule, then the verdict.
    fn conclude(&mut self, decoder: &BeefDecoder) -> Verdict {
        if let Err(r) = self.check_named_subject(decoder) {
            return r.into();
        }
        let subject = self.subject.or(decoder.subject());
        // A missing subject is named at the prefix's 32 bytes; without a
        // prefix, at the last raw transaction instead, or at the stream's end
        // when there is none.
        let subject_at = if decoder.subject().is_some() {
            4
        } else {
            self.index.last_raw.map_or(decoder.offset(), |(_, at)| at)
        };
        match self.index.finish(subject.as_ref(), subject_at) {
            Ok(()) => Verdict::Valid {
                subject,
                roots: self.index.bumps.clone(),
            },
            Err(r) => r.into(),
        }
    }
}

/// What one call to [`StreamVerifier::step`] came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// One element was read and folded in.
    Stepped,
    /// The reading is over.
    Verdict(Verdict),
}

/// What one call to [`StreamVerifier::step_until`] came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Timed {
    /// As [`StreamVerifier::step`].
    Progress(Progress),
    /// The budget was spent between two inputs of an unproven transaction:
    /// [`StreamVerifier::cursor`] stands before the transaction and names
    /// the input reached ([`Cursor::input_reached`]).
    Paused,
}

/// The reader over a [`Read`]: one step per element, a cursor between any
/// two, and, under a budget, between two inputs of a transaction.
pub struct StreamVerifier<R, H> {
    source: BeefStream<R>,
    judge: Judge,
    headers: H,
    verdict: Option<Verdict>,
    /// The frame before the element in hand: after the last element folded.
    boundary: Frame,
    /// The transaction a pause left in hand and the input it reached.
    held: Option<(Element, u32)>,
    work_limit: Option<u64>,
}

impl<R: Read, H: Headers> StreamVerifier<R, H> {
    /// A reader at the start of a stream. `subject` holds the reading to the
    /// atomic rule for that txid (wire order) whether or not the Atomic
    /// prefix leads; `None` holds it to the prefix's subject when there is
    /// one.
    pub fn new(source: R, headers: H, subject: Option<Hash32>) -> Self {
        Self::from_parts(
            BeefDecoder::new(),
            Judge::new(subject, BeefIndex::new()),
            source,
            headers,
        )
    }

    /// Sets the LOCAL work bound per input, before its scripts run. A
    /// resource decline is `SpendRefusal::Resource`, naming the input, work
    /// spent and budget. `None` is the default. This configuration is not
    /// cursor state: reapply it after `resume`, including a decoded cursor.
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.work_limit = limit;
    }

    /// The same reader for the BEEF's structure alone: no script is run and
    /// no output is kept. Exactly the Lean's validity.
    pub fn structure_only(source: R, headers: H, subject: Option<Hash32>) -> Self {
        Self::from_parts(
            BeefDecoder::new(),
            Judge::new(subject, BeefIndex::structure_only()),
            source,
            headers,
        )
    }

    /// The reader of [`new`](Self::new) that keeps only the outputs
    /// `referenced` names: the second of two passes (see
    /// [`referenced_outpoints`]).
    pub fn retaining(
        source: R,
        headers: H,
        subject: Option<Hash32>,
        referenced: Referenced,
    ) -> Self {
        Self::from_parts(
            BeefDecoder::new(),
            Judge::new(subject, BeefIndex::retaining(referenced)),
            source,
            headers,
        )
    }

    /// A reader resumed from a cursor. `source` is positioned at
    /// [`Cursor::offset`]; the verdict is the verdict of the whole.
    ///
    /// A cursor paused inside a transaction is positioned at that
    /// transaction: it is read again and its scripts run from the input
    /// reached, the inputs before it never again.
    pub fn resume(cursor: Cursor, source: R, headers: H) -> Self {
        let (frame, judge) = Judge::resumed(cursor);
        Self::from_parts(BeefDecoder::at(frame), judge, source, headers)
    }

    fn from_parts(decoder: BeefDecoder, judge: Judge, source: R, headers: H) -> Self {
        Self {
            boundary: decoder.frame.clone(),
            source: BeefStream::with_decoder(source, decoder),
            judge,
            headers,
            verdict: None,
            held: None,
            work_limit: None,
        }
    }

    /// The state after the elements read so far, or, paused inside a
    /// transaction, the state before it and the input reached.
    pub fn cursor(&self) -> Cursor {
        match &self.held {
            Some((Element::Tx { offset, txid, .. }, input)) => Cursor {
                frame: self.boundary.clone(),
                index: self.judge.index.clone(),
                subject: self.judge.subject,
                pending: Some(Pending {
                    offset: *offset,
                    txid: *txid,
                    input: *input,
                }),
            },
            _ => self.judge.cursor(&self.source.decoder),
        }
    }

    /// The index.
    pub fn index(&self) -> &BeefIndex {
        &self.judge.index
    }

    /// Reads and folds one element, or ends the reading.
    pub fn step(&mut self) -> std::io::Result<Progress> {
        match self.step_until(&mut || false)? {
            Timed::Progress(progress) => Ok(progress),
            Timed::Paused => unreachable!("a budget never spent never pauses"),
        }
    }

    /// [`step`](Self::step) under a budget: `spent` is asked between two
    /// inputs of an unproven transaction, and when it answers `true` the
    /// reading pauses there ([`Timed::Paused`]) with at least one input of
    /// the step run. The next call continues the same transaction from the
    /// input reached; so does a reader resumed from [`cursor`](Self::cursor).
    /// Between two elements the caller asks its own clock.
    pub fn step_until(&mut self, spent: &mut dyn FnMut() -> bool) -> std::io::Result<Timed> {
        if let Some(verdict) = &self.verdict {
            return Ok(Timed::Progress(Progress::Verdict(verdict.clone())));
        }
        let (element, from) = match self.held.take() {
            Some(held) => held,
            None => {
                let element = match self.source.next_element() {
                    Err(StreamError::Io(e)) => return Err(e),
                    Err(StreamError::Refused(r)) => return Ok(self.latch(r.into())),
                    Ok(element) => element,
                };
                if let Err(r) = self.judge.check_named_subject(&self.source.decoder) {
                    return Ok(self.latch(r.into()));
                }
                let Some(element) = element else {
                    let verdict = self.judge.conclude(&self.source.decoder);
                    return Ok(self.latch(verdict));
                };
                let from = self.judge.start_of(&element);
                (element, from)
            }
        };
        let folded = match &element {
            Element::Bump(_) => self
                .judge
                .index
                .fold(&element, &self.headers)
                .map(|()| None),
            other => self.judge.index.fold_checked_from(
                other,
                from,
                spent,
                self.work_limit,
                self.headers.mining_tip(),
            ),
        };
        match folded {
            Ok(None) => {
                self.boundary = self.source.decoder.frame.clone();
                Ok(Timed::Progress(Progress::Stepped))
            }
            Ok(Some(next)) => {
                self.held = Some((element, next));
                Ok(Timed::Paused)
            }
            Err(stop) => Ok(self.latch(stop.into())),
        }
    }

    fn latch(&mut self, verdict: Verdict) -> Timed {
        self.verdict = Some(verdict.clone());
        Timed::Progress(Progress::Verdict(verdict))
    }

    /// Reads to the end.
    pub fn run(mut self) -> std::io::Result<Verdict> {
        loop {
            if let Progress::Verdict(verdict) = self.step()? {
                return Ok(verdict);
            }
        }
    }
}

/// Verifies a BEEF from a byte source in one pass: each BUMP's root checked
/// against `headers` as it streams, each unproven transaction's inputs
/// resolved against the index and their scripts executed against the parent
/// output the index kept, the subject held to the atomic rule.
///
/// Memory is the one element in hand and the index; nothing is refused for
/// its size or its counts. `Err` is the source's failure and says nothing
/// about the bytes.
pub fn verify_stream<R: Read, H: Headers>(
    source: R,
    headers: H,
    subject: Option<Hash32>,
) -> std::io::Result<Verdict> {
    StreamVerifier::new(source, headers, subject).run()
}

/// [`verify_stream`] for the BEEF's structure alone (no script is run).
pub fn verify_stream_structure<R: Read, H: Headers>(
    source: R,
    headers: H,
    subject: Option<Hash32>,
) -> std::io::Result<Verdict> {
    StreamVerifier::structure_only(source, headers, subject).run()
}

/// The first of two passes: the outpoints the unproven transactions of the
/// stream spend. Nothing is verified; the stream is cut into its elements and
/// each input of a transaction without a BUMP index is noted (36 bytes an
/// input). A refusal here is the refusal the verifying pass would give for
/// the frame.
pub fn referenced_outpoints<R: Read>(source: R) -> Result<Referenced, StreamError> {
    let mut referenced = HashSet::new();
    for element in BeefStream::new(source) {
        if let Element::Tx {
            bump_index: None,
            body,
            ..
        } = element?
        {
            referenced.extend(body.inputs.iter().map(|i| (i.prev, i.vout)));
        }
    }
    Ok(Referenced(referenced))
}

/// [`verify_stream`] in two passes over a source that can be read again (an
/// object at rest): the first learns which outputs are spent, the second
/// verifies and keeps those outputs alone until they are spent. One pass
/// keeps every unspent output's script, which for transactions that carry
/// large outputs nothing spends is their bytes; two passes keep one entry per
/// element and one outpoint per input, never a script nothing spends.
pub fn verify_stream_two_pass<R: Read + Seek, H: Headers>(
    mut source: R,
    headers: H,
    subject: Option<Hash32>,
) -> std::io::Result<Verdict> {
    let start = source.stream_position()?;
    let referenced = match referenced_outpoints(&mut source) {
        Ok(referenced) => referenced,
        Err(StreamError::Io(e)) => return Err(e),
        Err(StreamError::Refused(r)) => return Ok(r.into()),
    };
    source.seek(SeekFrom::Start(start))?;
    StreamVerifier::retaining(source, headers, subject, referenced).run()
}

/// Resumes a reading from a cursor over the rest of the stream (`source`
/// positioned at [`Cursor::offset`]): the verdict of the whole.
pub fn resume<R: Read, H: Headers>(
    cursor: Cursor,
    source: R,
    headers: H,
) -> std::io::Result<Verdict> {
    StreamVerifier::resume(cursor, source, headers).run()
}

// ---------------------------------------------------------------------------
// The asynchronous source
// ---------------------------------------------------------------------------

/// A byte source that yields its chunks asynchronously: a request body, an
/// object store's body stream. The crate ships the reader over [`Read`]; a
/// Worker implements this over its body.
pub trait AsyncByteSource {
    /// The next chunk, or `None` at the stream's end.
    fn next_chunk(&mut self) -> impl Future<Output = std::io::Result<Option<Vec<u8>>>>;
}

/// What stops an asynchronous reading short of a verdict. Neither says
/// anything about the bytes, and neither is an acceptance.
#[derive(Debug)]
pub enum AsyncVerifyError {
    /// The source failed.
    Source(std::io::Error),
    /// The header lookup failed.
    Headers(ChainTrackerError),
}

impl fmt::Display for AsyncVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsyncVerifyError::Source(e) => write!(f, "the BEEF source failed: {e}"),
            AsyncVerifyError::Headers(e) => write!(f, "the header lookup failed: {e}"),
        }
    }
}

impl std::error::Error for AsyncVerifyError {}

/// The asynchronous reader: the decoder and the index between two chunks.
pub struct AsyncStreamVerifier {
    decoder: BeefDecoder,
    judge: Judge,
    work_limit: Option<u64>,
}

impl AsyncStreamVerifier {
    /// A reader at the start of a stream (see [`StreamVerifier::new`]).
    pub fn new(subject: Option<Hash32>) -> Self {
        Self {
            decoder: BeefDecoder::new(),
            judge: Judge::new(subject, BeefIndex::new()),
            work_limit: None,
        }
    }

    /// Sets the LOCAL work bound per input, before its scripts run. A
    /// resource decline is `SpendRefusal::Resource`, naming the input, work
    /// spent and budget. `None` is the default. This configuration is not
    /// cursor state: reapply it after `resume`, including a decoded cursor.
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.work_limit = limit;
    }

    /// The same for the BEEF's structure alone.
    pub fn structure_only(subject: Option<Hash32>) -> Self {
        Self {
            decoder: BeefDecoder::new(),
            judge: Judge::new(subject, BeefIndex::structure_only()),
            work_limit: None,
        }
    }

    /// A reader resumed from a cursor; the source continues at
    /// [`Cursor::offset`].
    pub fn resume(cursor: Cursor) -> Self {
        let (frame, judge) = Judge::resumed(cursor);
        Self {
            decoder: BeefDecoder::at(frame),
            judge,
            work_limit: None,
        }
    }

    /// The state after the elements read so far: meaningful between two
    /// elements, so take it only when [`run`](Self::run) has returned.
    pub fn cursor(&self) -> Cursor {
        self.judge.cursor(&self.decoder)
    }

    /// Reads the source to its end, asking `tracker` for each BUMP's root as
    /// it streams.
    pub async fn run<S: AsyncByteSource>(
        &mut self,
        source: &mut S,
        tracker: &dyn ChainTracker,
    ) -> Result<Verdict, AsyncVerifyError> {
        loop {
            let chunk = source
                .next_chunk()
                .await
                .map_err(AsyncVerifyError::Source)?;
            let Some(chunk) = chunk else {
                if let Err(r) = self.decoder.finish() {
                    return Ok(r.into());
                }
                return Ok(self.judge.conclude(&self.decoder));
            };
            let mut input = chunk.as_slice();
            loop {
                let step = match self.decoder.next(&mut input) {
                    Ok(step) => step,
                    Err(r) => return Ok(r.into()),
                };
                if let Err(r) = self.judge.check_named_subject(&self.decoder) {
                    return Ok(r.into());
                }
                let folded = match step {
                    Step::NeedMore | Step::Done => break,
                    Step::Element(Element::Bump(bump)) => {
                        let carried = match u32::try_from(bump.block_height) {
                            Ok(height) => tracker
                                .is_valid_root_for_height(&display_hex(&bump.root), height)
                                .await
                                .map_err(AsyncVerifyError::Headers)?,
                            Err(_) => false,
                        };
                        self.judge.index.fold_bump(&bump, carried)
                    }
                    Step::Element(other) => {
                        let from = self.judge.start_of(&other);
                        let tip = if self.judge.index.check_spends
                            && matches!(
                                &other,
                                Element::Tx {
                                    bump_index: None,
                                    ..
                                }
                            ) {
                            tracker
                                .mining_tip()
                                .await
                                .map_err(AsyncVerifyError::Headers)?
                        } else {
                            None
                        };
                        self.judge
                            .index
                            .fold_checked_from(&other, from, &mut || false, self.work_limit, tip)
                            .map(|_| ())
                    }
                };
                if let Err(stop) = folded {
                    return Ok(stop.into());
                }
            }
        }
    }
}

/// [`verify_stream`] over an asynchronous source and the crate's
/// [`ChainTracker`]. A tracker that answers `false` is a root not carried; a
/// tracker that fails is an `Err`, never an acceptance.
pub async fn verify_stream_async<S: AsyncByteSource>(
    source: &mut S,
    tracker: &dyn ChainTracker,
    subject: Option<Hash32>,
) -> Result<Verdict, AsyncVerifyError> {
    AsyncStreamVerifier::new(subject).run(source, tracker).await
}
