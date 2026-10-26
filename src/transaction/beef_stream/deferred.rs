//! What the stream holds for a parent it has not read yet (bsv-rs#240): the
//! held transactions ([`Deferred`]), the caller's bound on them
//! ([`DeferredLimit`]) and the decline past it ([`DeferredOverLimit`]), and
//! the held transactions read again from a cursor ([`read_held`]).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::fmt;

use crate::primitives::Reader;

use super::{BeefDecoder, BeefIndex, Element, Frame, Hash32, Phase, Step, BEEF_V1};

/// The unproven transactions read ahead of a parent (bsv-rs#240): each held
/// as read (the element the decoder yielded: its raw bytes and the places of
/// its fields) until every txid its inputs name is in the index, then folded
/// in, in wire order. A BEEF in BRC-62's order (parents
/// before children) holds none.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Deferred {
    /// The transactions held, by stream offset.
    pub(super) held: BTreeMap<u64, Element>,
    /// For each one held, the distinct txids it still waits on.
    pub(super) missing: HashMap<u64, usize>,
    /// For each txid waited on, the offsets of the transactions waiting.
    pub(super) waiting: HashMap<Hash32, Vec<u64>>,
    /// The raw bytes held.
    pub(super) bytes: u64,
}

impl Deferred {
    /// Holds `element` until each txid of `missing` is in the index.
    pub(super) fn hold(&mut self, element: Element, missing: HashSet<Hash32>) {
        let at = element.offset();
        for txid in &missing {
            self.waiting.entry(*txid).or_default().push(at);
        }
        self.missing.insert(at, missing.len());
        self.bytes += element.wire_len();
        self.held.insert(at, element);
    }

    /// `txid` is in the index: each transaction it was the last wait of is
    /// ready.
    pub(super) fn wake(&mut self, txid: &Hash32, ready: &mut BinaryHeap<Reverse<u64>>) {
        let Some(waiters) = self.waiting.remove(txid) else {
            return;
        };
        for at in waiters {
            if let Some(left) = self.missing.get_mut(&at) {
                *left -= 1;
                if *left == 0 {
                    self.missing.remove(&at);
                    ready.push(Reverse(at));
                }
            }
        }
    }

    /// The transaction held at `at`, released.
    pub(super) fn take(&mut self, at: u64) -> Option<Element> {
        let element = self.held.remove(&at)?;
        self.bytes -= element.wire_len();
        Some(element)
    }
}

/// A bound on what a reading holds for a parent it has not read yet
/// (bsv-rs#240): the transactions held at once and their raw bytes. A BEEF
/// in BRC-62's order (parents before children, as every SDK's writer writes
/// it) holds none; one written children first holds each unproven
/// transaction until its parents are in, at most the bytes read. No bound is
/// the default ([`StreamVerifier::set_deferred_limit`]): a valid BEEF is
/// never refused for its size or its counts. A door that must bound its
/// memory sets one, and a reading past it is declined, never judged
/// ([`DeferredOverLimit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeferredLimit {
    /// The most transactions held at once.
    pub transactions: u64,
    /// The most raw bytes held at once.
    pub bytes: u64,
}

impl DeferredLimit {
    /// At most `transactions` held at once, of at most `bytes` raw bytes.
    pub fn new(transactions: u64, bytes: u64) -> Self {
        Self {
            transactions,
            bytes,
        }
    }
}

/// A reading declined for its [`DeferredLimit`] (bsv-rs#240): holding the
/// transaction at `offset` for a parent not read yet passed the bound. A
/// LOCAL resource decline, never a verdict: it says nothing about the bytes,
/// and the BEEF may be valid. It is the [`std::io::Error`] the reader
/// returns (kind [`std::io::ErrorKind::OutOfMemory`]), this its inner error
/// ([`DeferredOverLimit::of`]); the asynchronous reader returns it as
/// [`AsyncVerifyError::Source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeferredOverLimit {
    /// The stream offset of the transaction whose holding passed the bound.
    pub offset: u64,
    /// The transactions held with it.
    pub transactions: u64,
    /// Their raw bytes.
    pub bytes: u64,
    /// The bound.
    pub limit: DeferredLimit,
}

impl DeferredOverLimit {
    /// The decline an error of the reader carries, if it is one.
    pub fn of(error: &std::io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref::<Self>()
    }

    /// The decline when `index` holds more than `limit` allows, the
    /// element in hand at `offset`.
    pub(super) fn check(
        index: &BeefIndex,
        limit: Option<DeferredLimit>,
        offset: u64,
    ) -> Option<Self> {
        let limit = limit?;
        let (transactions, bytes) = index.deferred();
        (transactions > limit.transactions || bytes > limit.bytes).then_some(Self {
            offset,
            transactions,
            bytes,
            limit,
        })
    }

    pub(super) fn to_io(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::OutOfMemory, self)
    }
}

impl fmt::Display for DeferredOverLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the BEEF reader declined at byte {}: {} transactions ({} bytes) held for a parent \
             not read yet, over the limit of {} ({} bytes); the BEEF was not judged",
            self.offset, self.transactions, self.bytes, self.limit.transactions, self.limit.bytes
        )
    }
}

impl std::error::Error for DeferredOverLimit {}

/// A held transaction's raw bytes at stream offset `at`, read again by the
/// decoder as an unproven V1 entry: the element the stream yielded, its
/// fields at the same offsets, or `None` when the bytes are not one
/// transaction the stream would hold.
fn reread_held(at: u64, raw: &[u8]) -> Option<Element> {
    let mut decoder = BeefDecoder::at(Frame {
        pos: at,
        k: 0,
        phase: Phase::Txs,
        version: BEEF_V1,
        subject: None,
        bumps_left: 0,
        txs_left: 1,
    });
    let mut entry = raw.to_vec();
    entry.push(0); // V1's has-BUMP byte: no BUMP.
    let mut input = entry.as_slice();
    match decoder.next(&mut input) {
        Ok(Step::Element(element @ Element::Tx { .. })) if input.is_empty() => Some(element),
        _ => None,
    }
}

/// A BSC4 cursor's held transactions (after the outputs named), into
/// `index`: by offset strictly ascending, each its raw bytes read again by
/// the decoder, each waiting on a txid `index` does not hold. `Err` names
/// what is not a cursor.
pub(super) fn read_held(r: &mut Reader, index: &mut BeefIndex) -> Result<(), &'static str> {
    let underflow = |_| "bytes cut short";
    let n = r.read_var_int().map_err(underflow)?;
    if n == 0 {
        return Err("a BSC4 cursor that holds nothing");
    }
    let mut previous: Option<u64> = None;
    for _ in 0..n {
        let at = r.read_u64_le().map_err(underflow)?;
        if previous.is_some_and(|p| p >= at) {
            return Err("held transactions out of order");
        }
        previous = Some(at);
        let raw = r.read_var_bytes().map_err(underflow)?;
        let element = reread_held(at, raw).ok_or("a held transaction")?;
        let Element::Tx { body, .. } = &element else {
            return Err("a held transaction");
        };
        let missing: HashSet<Hash32> = body
            .inputs
            .iter()
            .map(|input| input.prev)
            .filter(|prev| !index.txs.contains_key(prev))
            .collect();
        if missing.is_empty() {
            return Err("a held transaction that waits on nothing");
        }
        index.deferred.hold(element, missing);
    }
    Ok(())
}
