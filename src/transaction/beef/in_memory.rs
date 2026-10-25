//! The streaming reader's rules on the in-memory forms (bsv-rs#86): a
//! [`MerklePath`] walked by the stream's [`bump_root`], a [`BeefTx`] judged
//! by the stream's [`check_transaction`], the entries of a [`Beef`] as the
//! atomic walk reads them, and the in-memory form of a streamed [`Bump`].
//! [`Beef::verify_structure`] answers with these what the stream answers on
//! the same bytes; a refusal names the kind, its offset being the stream's
//! alone.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use super::super::beef_stream::{
    bump_root, check_transaction, display_hex, AtomicNode, Bump, Hash32, InputRef, Kind, Leaf,
    Node, OutputRef, Reason, Refusal,
};
use super::super::beef_tx::BeefTx;
use super::super::merkle_path::{MerklePath, MerklePathLeaf};
use super::super::Transaction;

impl Bump {
    /// The BUMP as the in-memory [`MerklePath`] (hashes as display hex). A
    /// block height above `u32::MAX` has no in-memory form.
    pub fn to_merkle_path(&self) -> crate::Result<MerklePath> {
        let block_height = u32::try_from(self.block_height).map_err(|_| {
            crate::Error::MerklePathError(format!(
                "block height {} has no in-memory form",
                self.block_height
            ))
        })?;
        let path = self
            .levels
            .iter()
            .map(|level| {
                level
                    .iter()
                    .map(|l| match &l.node {
                        Node::Hash(h) => MerklePathLeaf {
                            offset: l.offset,
                            hash: Some(display_hex(h)),
                            txid: l.client,
                            duplicate: false,
                        },
                        Node::Duplicate => MerklePathLeaf::new_duplicate(l.offset),
                    })
                    .collect()
            })
            .collect();
        Ok(MerklePath { block_height, path })
    }
}

/// The root of an in-memory BUMP by the same walk ([`bump_root`]): the one
/// walker under the stream and under [`Beef::verify_valid`](super::Beef::verify_valid)
/// (0.4.2; at 0.4.1 the whole path walked the BUMP once per leaf, NL-8 W1).
/// The levels keep their in-memory order; a hash that is not 32 bytes of hex
/// (only a BUMP built by hand holds one) is a node the BUMP does not carry.
/// A second leaf at an offset of a level is refused ahead of the walk, as
/// the decoder refuses it on the wire (`MismatchedNode`, bsv-rs#86). A
/// refusal names the kind; its offset is 0, there being no stream.
pub(super) fn merkle_path_root(path: &MerklePath) -> Result<Hash32, Refusal> {
    for (level, leaves) in path.path.iter().enumerate() {
        let mut seen = HashSet::with_capacity(leaves.len());
        if let Some(repeated) = leaves.iter().find(|l| !seen.insert(l.offset)) {
            let level = u8::try_from(level).unwrap_or(u8::MAX);
            let reason = Reason::MismatchedNode {
                level,
                offset: repeated.offset,
            };
            return Err(Refusal { offset: 0, reason });
        }
    }
    let levels: Vec<Vec<Leaf>> = path
        .path
        .iter()
        .map(|level| {
            level
                .iter()
                .filter_map(|l| {
                    let node = if l.duplicate {
                        Node::Duplicate
                    } else {
                        Node::Hash(wire_hash(l.hash.as_deref()?)?)
                    };
                    Some(Leaf {
                        at: 0,
                        offset: l.offset,
                        node,
                        client: l.txid,
                    })
                })
                .collect()
        })
        .collect();
    bump_root(0, &levels)
}

/// A display-hex hash in wire order (a txid as the stream's tables key it),
/// if it is 32 bytes of hex.
pub(super) fn wire_hash(display: &str) -> Option<Hash32> {
    let mut h: Hash32 = crate::primitives::from_hex(display).ok()?.try_into().ok()?;
    h.reverse();
    Some(h)
}

/// The transaction of a raw entry: the parse it holds, or its bytes parsed.
fn parsed(tx: &BeefTx) -> Option<Cow<'_, Transaction>> {
    match tx.tx() {
        Some(t) => Some(Cow::Borrowed(t)),
        None => Transaction::from_binary(tx.raw_tx()?).ok().map(Cow::Owned),
    }
}

/// The txids a raw transaction's inputs spend (display hex), proven or not.
pub(super) fn spent_txids(tx: &BeefTx) -> Vec<String> {
    parsed(tx).map_or_else(Vec::new, |t| {
        t.inputs
            .iter()
            .filter_map(|i| i.get_source_txid().ok())
            .collect()
    })
}

/// The stream's rules on a raw entry's content ([`check_transaction`], the
/// node's checks in the Lean's order): an unproven coinbase, no input, no
/// output, a value outside `MoneyRange`, a null outpoint, a repeated outpoint.
/// A txid-only entry has no content to judge.
pub(super) fn content_refused(tx: &BeefTx) -> Option<Kind> {
    let t = parsed(tx)?;
    let inputs: Vec<InputRef> = t
        .inputs
        .iter()
        .map(|i| InputRef {
            at: 0,
            // A hand-built input naming no txid is no outpoint the rules know.
            prev: match &i.source_txid {
                Some(txid) => wire_hash(txid),
                None => i.get_source_txid().ok().as_deref().and_then(wire_hash),
            }
            .unwrap_or([0xEE; 32]),
            vout: i.source_output_index,
            script: 0..0,
            sequence: i.sequence,
        })
        .collect();
    let outputs: Vec<OutputRef> = t
        .outputs
        .iter()
        .map(|o| OutputRef {
            at: 0,
            satoshis: o.satoshis.unwrap_or(0),
            script: 0..0,
        })
        .collect();
    let bump_index = tx.bump_index().map(|i| i as u64);
    check_transaction(0, &inputs, &outputs, bump_index)
        .err()
        .map(|r| r.kind())
}

/// An entry of a BEEF as the atomic walk reads it.
#[derive(Default)]
pub(super) struct AtomicEntry {
    raw: bool,
    prevs: Vec<Hash32>,
    reached: bool,
}

impl AtomicNode for AtomicEntry {
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

/// The entries by txid (wire order): raw when any of its entries is, with
/// the txids a raw entry's inputs name, proven or not.
pub(super) fn atomic_table(txs: &[BeefTx]) -> HashMap<Hash32, AtomicEntry> {
    let mut table: HashMap<Hash32, AtomicEntry> = HashMap::new();
    for tx in txs {
        let Some(txid) = wire_hash(&tx.txid()) else {
            continue;
        };
        let entry = table.entry(txid).or_default();
        if !tx.is_txid_only() && !entry.raw {
            entry.raw = true;
            entry.prevs = spent_txids(tx)
                .iter()
                .filter_map(|t| wire_hash(t))
                .collect();
        }
    }
    table
}
