//! The BEEF writers' check and `merge_beef`'s verdict (#817): one read-only
//! pass, run before any byte, shared by `Beef::to_writer` (so `to_binary`,
//! `to_hex`, the atomic closure) and `merge_beef`; and the two fallible merge
//! doors, `merge_raw_tx` and `merge_beef` (moved from `beef.rs`, #817).
//!
//! The rule (the eleven design reads, the owner's standard of 2026-11-10): a
//! writer refuses only a state it cannot write faithfully, bytes that would
//! not frame or would read back as another state; it writes every other
//! state, valid or not, as the reference does, and validity is the readers'
//! and `verify`'s. Where the reference refuses, its words; where it writes
//! bytes no reader reads back as written, this crate's, a stated row.
//!
//! The order is the reference's (`ts-stack@edf6e03` `Beef.ts:360-373`,
//! `#getSerializedBytes`): its writer's own throws in the order it meets them
//! (a txid-only entry with an empty txid ahead of everything,
//! `#ensureSerializableState`; then a non-hex BUMP hash, the BUMPs before the
//! transactions; then each entry's throw in written order), then the version
//! word its reader refuses at byte 0 (`:1251-1254`, what `mergeBeef`'s
//! snapshot throws), then, in written order, the states it writes that its
//! reader cannot read back as written: the BUMPs' (`MerklePath`'s check and
//! words) before the entries'.

use super::super::beef_tx::BeefTx;
use super::super::beef_tx::{BEEF_V1, BEEF_V2};
use super::Beef;
use crate::primitives::{to_hex, Writer};
use crate::Result;

impl Beef {
    /// Merges raw transaction bytes into this BEEF.
    ///
    /// # Errors
    ///
    /// Refuses what [`BeefTx::from_raw_tx`] refuses (#817): bytes that are not
    /// exactly one transaction, with or without `bump_index`, the BEEF
    /// untouched. The reference's `mergeRawTx` throws only without an index,
    /// its scan's words (`Beef.ts:835-845`, `BeefTx.ts:16-48`), and keeps
    /// bytes after the lock time (stated rows, the root `CLAUDE.md`).
    pub fn merge_raw_tx(&mut self, raw_tx: Vec<u8>, bump_index: Option<usize>) -> Result<&BeefTx> {
        let new_tx = BeefTx::from_raw_tx(raw_tx, bump_index)?;
        let txid = new_tx.txid();
        let idx = self.store_raw_entry(new_tx, txid);
        Ok(&self.txs[idx])
    }

    /// Merges another BEEF into this one, as the reference's `mergeBeef`
    /// does (`ts-stack@edf6e03` `Beef.ts:971-990`): from a snapshot of the
    /// source, the BEEF its serialization writes, never the source's objects.
    ///
    /// Bumps are merged before the entries, each with every level sorted
    /// by offset as the snapshot reads it (#621's third fold), and may
    /// receive new indices in self. The entries are walked in the order the source's
    /// [`to_binary`](Self::to_binary) writes them (its sort when the source
    /// needs one, computed on the side: `other` is not sorted, #621's second
    /// fold; held order until then), each merged as its written form, its
    /// bytes or its txid alone: a parsed source entry contributes the bytes
    /// the writer writes for it, no transaction object, source link or
    /// merkle path of its own (#621's second fold; its transaction cloned
    /// until then). Each is merged without the source's bump index (found
    /// by scanning self.bumps), and only where self holds nothing under its
    /// txid or holds the txid alone: an entry self holds raw or parsed is
    /// left as it is, its BUMP index and source links kept (#621's fold;
    /// replaced until then). A raw entry is filed under the txid it holds,
    /// hashed no second time (#621).
    ///
    /// # Errors
    ///
    /// What the reference's snapshot refuses, before `self` changes (#817):
    /// the source's write as [`to_writer`](Self::to_writer) judges it (its
    /// words, the entries met in the order the snapshot writes them), then
    /// what this crate's strict reader of those bytes refuses
    /// ([`from_binary`](Self::from_binary), in its words), judged by a
    /// pre-pass that writes no entry (#621's pre-pass, after #817: each BUMP
    /// read by the reader's decoder at its place in the frame; from #817 to
    /// it the literal round trip, one write and one read of the source per
    /// merge, about twice the merge's cost), proven equal to that round trip
    /// by its differential and fuzz target. Until #817 such a source was
    /// merged (a V1 source holding a txid-only entry, a BUMP the snapshot's
    /// reader refuses, the #764 row's residues).
    pub fn merge_beef(&mut self, other: &Beef) -> Result<()> {
        let order = other.written_order();
        other.snapshot_verdict(&order)?;
        self.refresh_mutated(); // The target re-keyed (`Beef.ts:976`, #621's fourth fold).
        self.mark_mutated();
        for bump in &other.bumps {
            // Each level by offset, as the snapshot reads it (`MerklePath.ts:148-149`, #621's third fold).
            let mut bump = bump.clone();
            for level in &mut bump.path {
                level.sort_by_key(|leaf| leaf.offset);
            }
            self.merge_bump(bump);
        }

        for i in order {
            self.merge_beef_entry(&other.txs[i]);
        }
        Ok(())
    }

    /// Serializes this BEEF to binary, sorted first when it needs a sort, as
    /// the reference's `toBinary` sorts before it writes (`Beef.ts:366-373`).
    ///
    /// # Errors
    ///
    /// Refuses what [`to_writer`](Self::to_writer) refuses (#817), in the
    /// reference's order around its sort (`#getSerializedBytes`,
    /// `Beef.ts:360-373`): an entry holding a transaction with an output of
    /// 2^53 or more is refused first, in the reference's writer's words, as
    /// its `synchronizeNestedTransactionMutations` serializes every held
    /// transaction before anything else (#844's fold); a txid-only entry whose txid is empty is refused
    /// before the sort, the entries left as held, as the reference's
    /// `#ensureSerializableState` throws `Internal` ahead of
    /// `#ensureSortedForSerialization`; every other refusal after it, the
    /// entries sorted, as the reference's `toWriter` throws after its sort
    /// (and as it sorts before writing a state this crate refuses in its own
    /// words). Until #817's fold the empty txid was refused after the sort.
    pub fn to_binary(&mut self) -> Result<Vec<u8>> {
        self.refresh_mutated();
        self.refuse_unsafe_amount()?;
        self.refuse_empty_txid()?;
        if self.needs_sort {
            self.sort_txs();
        }

        let mut writer = Writer::new();
        self.to_writer(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// Serializes this BEEF to a hex string.
    ///
    /// # Errors
    ///
    /// Refuses what [`to_writer`](Self::to_writer) refuses (#817).
    pub fn to_hex(&mut self) -> Result<String> {
        Ok(to_hex(&self.to_binary()?))
    }

    /// Writes this BEEF to a Writer, the entries in held order.
    ///
    /// Every state the format can carry is written, valid or not (validity is
    /// the readers' and [`verify_valid`](Self::verify_valid)'s): a BUMP index
    /// naming no BUMP, an unsorted or unproven entry, a BUMP whose roots do
    /// not agree.
    ///
    /// # Errors
    ///
    /// `Error::BeefError`, or a BUMP's `Error::MerklePathError`, for a BEEF
    /// whose bytes would not frame or would read back as another BEEF (#817),
    /// judged before any byte is written, so `writer` is untouched on `Err`;
    /// the earliest in the order the reference meets them:
    ///
    /// - an entry holding a transaction with an output of 2^53 satoshis or
    ///   more, ahead of everything: `The number is larger than 2 ^ 53
    ///   (unsafe)`, the reference's writer's (`BigNumber.ts:462`, its BEEF
    ///   writers serializing every held transaction first, `Beef.ts:360-362`;
    ///   #844's fold, recorded);
    /// - a txid-only entry whose txid is empty (the
    ///   reference's `Internal`, `BeefTx.ts:105-116`, at `Beef.ts:334-340`):
    ///   `Invalid txid-only entry txid: expected 64 hex digits, got 0`;
    /// - a BUMP hash with a character that is not a hex digit:
    ///   `Invalid hex string`, the reference's (`MerklePath.ts:289`);
    /// - in held order, a txid-only entry under a word other than V2:
    ///   `a valid serialized Transaction is expected`, the reference's
    ///   (`BeefTx.ts:253-258`); one under V2 whose txid has a character that
    ///   is not a hex digit: `Invalid hex string`, the reference's;
    /// - a version word other than V1 or V2: `Serialized BEEF must start
    ///   with 4022206465 or 4022206466 but starts with N`, the reference
    ///   reader's (`Beef.ts:1251-1254`), whose writer writes the word;
    /// - a BUMP [`MerklePath::to_writer`](crate::transaction::MerklePath::to_writer) refuses, in its words;
    /// - in held order, a txid-only entry's txid of other than 64 hex digits:
    ///   `Invalid txid-only entry txid: expected 64 hex digits, got N`; an
    ///   entry whose written bytes are not exactly one transaction (held
    ///   raw, or a parsed transaction caching a transaction and more, as
    ///   `Transaction::from_binary` of a longer buffer left it until #840;
    ///   #621's fold), in [`BeefTx::from_raw_tx`](crate::transaction::BeefTx::from_raw_tx)'s words.
    ///
    /// The last two classes and the version word are written by the
    /// reference as bytes no reader reads back as written (stated rows, the
    /// root `CLAUDE.md`). Until #817 a txid-only entry outside V2 panicked
    /// and the rest were written.
    pub fn to_writer(&self, writer: &mut Writer) -> Result<()> {
        self.check_writable()?;
        self.write_checked(writer);
        Ok(())
    }

    /// The writers' check over the entries in held order (the order
    /// [`to_writer`](Self::to_writer) writes them).
    pub(super) fn check_writable(&self) -> Result<()> {
        self.check_writable_in(&(0..self.txs.len()).collect::<Vec<_>>())
    }

    /// An entry holding a transaction with an output of 2^53 or more, refused
    /// ahead of everything in the reference's writer's words (#844's fold),
    /// as its `#getSerializedBytes` serializes every held transaction first
    /// (`synchronizeNestedTransactionMutations`, `Beef.ts:360-362`), before
    /// its `#ensureSerializableState` and its sort. The words name no entry,
    /// so the order the entries are met in moves nothing.
    pub(super) fn refuse_unsafe_amount(&self) -> Result<()> {
        self.txs.iter().try_for_each(BeefTx::amount_refusal)
    }

    /// A txid-only entry whose txid is empty, refused ahead of everything
    /// save an unsafe amount, where the reference's `txid` getter throws
    /// `Internal` (`BeefTx.ts:105-116`) from `#ensureSerializableState`,
    /// before its sort (`Beef.ts:367-368`).
    fn refuse_empty_txid(&self) -> Result<()> {
        match self.txs.iter().find(|tx| tx.empty_txid()) {
            Some(tx) => tx.own_refusal(),
            None => Ok(()),
        }
    }

    /// The writers' check with the entries met in `order` (positions in
    /// `txs`), the order they would be written.
    pub(super) fn check_writable_in(&self, order: &[usize]) -> Result<()> {
        self.refuse_unsafe_amount()?;
        self.refuse_empty_txid()?;
        if let Some(bump) = self.bumps.iter().find(|bump| bump.writes_non_hex()) {
            return bump.check_writable(); // `Invalid hex string`, the refusal it checks ahead
        }
        for &i in order {
            self.txs[i].reference_refusal(self.version)?;
        }
        if self.version != BEEF_V1 && self.version != BEEF_V2 {
            return Err(crate::Error::BeefError(format!(
                "Serialized BEEF must start with {BEEF_V1} or {BEEF_V2} but starts with {}",
                self.version
            )));
        }
        for bump in &self.bumps {
            bump.check_writable()?;
        }
        for &i in order {
            self.txs[i].own_refusal()?;
        }
        Ok(())
    }

    /// The bytes of a BEEF the check accepted, the entries in held order, as
    /// 0.9.0-beta wrote every BEEF.
    pub(super) fn write_checked(&self, writer: &mut Writer) {
        self.write_entries(writer, &(0..self.txs.len()).collect::<Vec<_>>());
    }

    /// The version, the BUMPs and the entries in `order`, each entry's
    /// transaction as its `written_tx_bytes` (what `merge_beef` merges).
    fn write_entries(&self, writer: &mut Writer, order: &[usize]) {
        writer.write_u32_le(self.version);
        writer.write_var_int(self.bumps.len() as u64);
        for bump in &self.bumps {
            bump.write_unchecked(writer);
        }
        writer.write_var_int(order.len() as u64);
        for &i in order {
            self.txs[i].write_unchecked(writer, self.version);
        }
    }

    /// `merge_beef`'s verdict on `self` as its source: what the reference's
    /// snapshot refuses (`mergeBeef`, `Beef.ts:971-990`:
    /// `fromBinaryStrict(beef.toBinary())`, before the target changes), from
    /// a pre-pass that writes no entry (#621, after #817): the writer's check
    /// over the entries in the order the reference's `toBinary` writes them
    /// (`order`, `written_order`), then what this crate's strict reader
    /// ([`from_binary`](Self::from_binary)) refuses on those bytes, which
    /// after the check is a BUMP's alone ([`bumps_as_read`](Self::bumps_as_read):
    /// each BUMP's bytes read by the reader's decoder and folded by its
    /// judge, at its offset in the frame, in its words). Proven equal to the
    /// literal round trip it replaces ([`snapshot_round_trip`](Self::snapshot_round_trip),
    /// the oracle, kept for the tests and the fuzz target): the same `Ok`,
    /// or the same `Err` in the same words. The source is not changed.
    pub(super) fn snapshot_verdict(&self, order: &[usize]) -> Result<()> {
        self.check_writable_in(order)?;
        self.bumps_as_read()
    }

    /// The literal round trip `merge_beef` decided by until the pre-pass
    /// (#817 to #621's pre-pass), kept as the oracle the pre-pass is proven
    /// against: the writer's check over `order`, the bytes written in that
    /// order (each entry as `merge_beef` merges it), and this crate's strict
    /// reader of them; the snapshot read back on `Ok`.
    #[cfg(any(test, feature = "internal-test-doors"))]
    pub(super) fn snapshot_round_trip(&self, order: &[usize]) -> Result<Beef> {
        self.check_writable_in(order)?;
        let mut writer = Writer::new();
        self.write_entries(&mut writer, order);
        Beef::from_binary(&writer.into_bytes())
    }

    /// The oracle of `merge_beef`'s verdict for the fuzz target (#621):
    /// [`snapshot_round_trip`](Self::snapshot_round_trip) over this BEEF's
    /// written order. Built only for the crate's own tests and under the
    /// `internal-test-doors` feature, which this repository's fuzz crate
    /// turns on and which is no part of the API (#869's second fold: under
    /// `cfg(fuzzing)` until then, which cargo-fuzz sets for every crate of
    /// a build, a dependent's included).
    #[cfg(any(test, feature = "internal-test-doors"))]
    #[doc(hidden)]
    pub fn merge_snapshot_oracle(&self) -> Result<Beef> {
        self.snapshot_round_trip(&self.written_order())
    }
}
