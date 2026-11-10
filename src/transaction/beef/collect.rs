//! The whole-BEEF reader as a mode of the streaming reader (bsv-rs#86).
//!
//! [`Beef::from_binary`] and [`Beef::from_reader`] do not parse a BEEF of
//! their own: the streaming reader's decoder in its collect mode
//! ([`BeefDecoder::collecting`]) cuts the bytes into the header and the
//! elements, and this collects each element into the in-memory [`Beef`] as
//! it is yielded, in one pass: the BUMPs as [`MerklePath`]s (each level's
//! leaves by offset, as the in-memory form keeps them), the transactions and
//! txid-only entries in the order written, the version and the atomic
//! subject from the header. One parser, one set of bounds, one set of
//! refusals: bytes that are no frame (a version, a varint, a field cut
//! short, a flag, a tree height, an offset outside its level, a byte after
//! the frame) and a BUMP whose walk fails are refused as the stream refuses
//! them, in its words (`invalid BEEF at byte N: Reason`).
//!
//! The collect mode yields a transaction whatever its content (the node's
//! rules: no input, no output, an unproven coinbase, a value outside
//! `MoneyRange`, a null or repeated outpoint), so that a BEEF that carries one
//! is returned and [`Beef::verify_structure`] judges it, as it has since
//! 0.4.1. The stream's judgement of each element is kept beside the
//! collection: the decoder's refusal of a transaction's content, else the
//! fold of a structure-only [`BeefIndex`] with the root of the leading BUMP
//! at each height as the one root the headers carry there (the rule
//! [`Beef::verify_structure`] reads from the BEEF alone). A BEEF whose bytes
//! are refused is refused with the stream's verdict on them: the earliest
//! refusal of the reading, which is an element's when one before the bad
//! bytes was refused already, as the stream stops there.

use std::collections::HashMap;

use crate::primitives::encoding::bounded_capacity;
use crate::primitives::Writer;
use crate::Result;

use super::super::beef_stream::{
    display_hex, BeefDecoder, BeefIndex, Bump, Element, Hash32, Reason, Refusal, Step, Stop,
};
use super::super::beef_tx::BeefTx;
use super::super::merkle_path::MerklePath;
use super::super::Transaction;
use super::{Beef, BeefLimits};

/// A byte after the frame: refused ([`Beef::from_binary`]), or left to the
/// caller ([`Beef::from_reader`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AfterFrame {
    Refuse,
    Leave,
}

/// The stream's judge over the elements collected: the index and the root
/// of the leading BUMP at each height, and the earliest refusal.
struct Judge {
    index: BeefIndex,
    leading_roots: HashMap<u64, Hash32>,
    refused: Option<Refusal>,
}

impl Judge {
    fn new() -> Self {
        Self {
            index: BeefIndex::structure_only(),
            leading_roots: HashMap::new(),
            refused: None,
        }
    }

    /// Folds `element` in, as the stream folds it, until one is refused.
    fn fold(&mut self, element: &Element) {
        if self.refused.is_some() {
            return;
        }
        let folded = match element {
            Element::Bump(bump) => {
                let root = *self
                    .leading_roots
                    .entry(bump.block_height)
                    .or_insert(bump.root);
                self.index.fold_bump(bump, root == bump.root)
            }
            other => self.index.fold(other, &self.leading_roots),
        };
        // A structure-only index stops for invalid bytes alone.
        if let Err(Stop::Invalid(refusal)) = folded {
            self.refused = Some(refusal);
        }
    }

    /// The decoder refused the content of the element just yielded.
    fn note(&mut self, refusal: Refusal) {
        self.refused.get_or_insert(refusal);
    }

    /// The error for bytes that do not parse: the earliest refusal of the
    /// reading in the stream's words, else `error`.
    fn refuse(&mut self, error: crate::Error) -> crate::Error {
        match self.refused.take() {
            Some(refusal) => refusal_error(&refusal),
            None => error,
        }
    }
}

fn refusal_error(refusal: &Refusal) -> crate::Error {
    crate::Error::BeefError(refusal.to_string())
}

impl Beef {
    /// The whole-BEEF reader: `bin` cut by the stream's decoder and
    /// collected, with the bytes the frame took. `hints` reserves room for
    /// that many BUMPs and transactions, never more than the bytes could
    /// fill (a BUMP is at least 3 bytes, an entry at least 10); it refuses
    /// nothing.
    pub(super) fn collect(
        bin: &[u8],
        after: AfterFrame,
        hints: Option<&BeefLimits>,
    ) -> Result<(Self, usize)> {
        let mut decoder = BeefDecoder::collecting();
        let mut judge = Judge::new();
        let mut beef = Self::new();
        if let Some(hints) = hints {
            beef.bumps
                .reserve(bounded_capacity(hints.max_bumps, bin.len(), 3));
            beef.txs
                .reserve(bounded_capacity(hints.max_txs, bin.len(), 10));
        }
        let mut input = bin;
        loop {
            match decoder.next(&mut input) {
                Ok(Step::Element(element)) => {
                    match decoder.take_deferred() {
                        Some(refusal) => judge.note(refusal),
                        None => judge.fold(&element),
                    }
                    beef.collect_element(element).map_err(|e| judge.refuse(e))?;
                }
                Ok(Step::NeedMore) => match decoder.finish() {
                    Ok(()) => break,
                    Err(r) => return Err(judge.refuse(refusal_error(&r))),
                },
                Ok(Step::Done) => break,
                Err(r) if after == AfterFrame::Leave && r.reason == Reason::TrailingBytes => break,
                Err(r) => return Err(judge.refuse(refusal_error(&r))),
            }
        }
        if let Some(version) = decoder.version() {
            beef.version = version;
        }
        beef.atomic_txid = decoder.subject().as_ref().map(display_hex);
        beef.needs_sort = true;
        beef.wire_order = true;
        let used = usize::try_from(decoder.offset()).unwrap_or(bin.len());
        Ok((beef, used))
    }

    /// What [`from_binary`](Self::from_binary) refuses among this BEEF's
    /// BUMPs on the bytes the writers would write for it, judged without the
    /// entries' bytes (#621, after #817): `merge_beef`'s pre-pass, after the
    /// writers' check ([`check_writable_in`](Self::check_writable_in)).
    ///
    /// Each BUMP is written alone ([`MerklePath::write_unchecked`], the
    /// writers' bytes) and read by the reader's own decoder
    /// ([`Bump::read_alone`](super::super::beef_stream::Bump::read_alone)),
    /// its offsets moved to where the BUMP sits in the frame (the version
    /// word, the BUMP count's varint, the BUMPs before it); then folded into
    /// the reader's [`Judge`] and taken to its in-memory form, in
    /// [`collect`](Self::collect)'s order, so a refusal is the reader's: the
    /// earliest refusal of the reading (a BUMP whose root a leading BUMP of
    /// its height contradicts, `RootNotCarried`, ahead of a later BUMP's
    /// decoder refusal), in its words and at its offset.
    ///
    /// Nothing after the BUMPs can be refused by the reader once the check
    /// passed: the frame's words are V1 or V2 (checked), the counts are
    /// varints the writer writes, every txid-only entry is 64 hex digits
    /// (checked), and every entry's written bytes are exactly one
    /// transaction (checked by `one_transaction`, which takes exactly the
    /// bytes `Transaction`'s reader takes: the bytes held, else a parsed
    /// transaction's cached serialization, one transaction from every door
    /// since #840, where `Transaction::from_binary` set it to the whole
    /// buffer it read a prefix of until then; else none, a
    /// serialization of the fields being one transaction by construction;
    /// #621's fold, where a parsed entry was taken on trust and one caching
    /// a transaction and more passed here and failed the round trip); and
    /// the judge's refusals of an entry
    /// (its content, its BUMP index) are returned only beside a later
    /// refusal of the bytes, which no entry's bytes give. The differential
    /// against the literal round trip pins it
    /// (`beef/prepass_621_tests.rs`, `fuzz_beef_parser`).
    pub(super) fn bumps_as_read(&self) -> Result<()> {
        let mut judge = Judge::new();
        let mut head = Writer::new();
        head.write_u32_le(self.version);
        head.write_var_int(self.bumps.len() as u64);
        let mut at = head.len() as u64;
        for path in &self.bumps {
            let mut writer = Writer::new();
            path.write_unchecked(&mut writer);
            let bytes = writer.into_bytes();
            let moved = |r: Refusal| Refusal {
                offset: r.offset + at,
                ..r
            };
            let mut bump =
                Bump::read_alone(&bytes).map_err(|r| judge.refuse(refusal_error(&moved(r))))?;
            bump.offset = at;
            for leaf in bump.levels.iter_mut().flatten() {
                leaf.at += at;
            }
            let element = Element::Bump(bump);
            judge.fold(&element);
            if let Element::Bump(bump) = &element {
                in_memory_bump(bump).map_err(|e| judge.refuse(e))?;
            }
            at += bytes.len() as u64;
        }
        Ok(())
    }

    /// One element of the stream, in its in-memory form.
    fn collect_element(&mut self, element: Element) -> Result<()> {
        match element {
            Element::Bump(bump) => self.bumps.push(in_memory_bump(&bump)?),
            Element::Tx {
                txid,
                bump_index,
                body,
                ..
            } => {
                // An index past `usize` names no BUMP, as the stream reads it.
                let bump_index = bump_index.map(|i| usize::try_from(i).unwrap_or(usize::MAX));
                // The bytes the decoder read, kept as the transaction's own,
                // and the txid it hashed from them (its hash is theirs, not a
                // serialization's, and computed once).
                let tx = Transaction::from_binary(&body.raw)?;
                let txid = display_hex(&txid);
                self.push_tx(
                    BeefTx::from_parts(tx, body.raw, bump_index).with_txid(txid.clone()),
                    txid,
                );
            }
            Element::TxidOnly { txid, .. } => {
                let txid = display_hex(&txid);
                self.push_tx(BeefTx::from_txid(txid.clone()), txid);
            }
        }
        Ok(())
    }
}

/// A streamed BUMP as the in-memory [`MerklePath`] ([`Bump::in_memory`]):
/// each level's leaves by offset, a height above a `u32` refused. Through
/// 0.8.3 the height was cut to its low 32 bits and the root keyed there.
fn in_memory_bump(bump: &Bump) -> Result<MerklePath> {
    bump.in_memory().map_err(|r| refusal_error(&r))
}
