//! What the stream holds for a parent it has not read yet (bsv-rs#240): each
//! transaction held by its index entry ([`HeldTx`]), never its raw bytes,
//! the set of them under no bound ([`Deferred`]), and the entries written to
//! and read from a cursor ([`write_held`], [`read_held`]).
//!
//! A held entry is what the index keeps for a transaction plus what its
//! scripts will need once its parents are in: its txid and offset; per input
//! the outpoint, the sequence and the input's offset (48 bytes); with spends
//! checked, per input the unlocking script, and the version, the lock time
//! and the outputs as the index retains them (value, locking script, the
//! output's offset). The outputs are held whole because a signature whose
//! hash type carries the CHRONICLE bit dispatches to the original digest
//! (`TxSighashCache::sighash_dispatched_for_signing`), which hashes every
//! output after the scriptCode the parent supplies: no midstate taken before
//! the parent arrives stands in for them, and the default mode admits the bit
//! at every version. That template is one per transaction, not one per input:
//! the input's slot in it is the outpoint and sequence already held. The
//! outputs resolve no parent: they are held for the original digest alone.
//! Under a word that refuses the CHRONICLE bit (STRICTENC without CHRONICLE,
//! the previous era's) a 32-byte `hashOutputs` and one hash per input for
//! SINGLE could stand in for them, and still not for the unlocking scripts;
//! the stream runs the default mode, which admits the bit at every version,
//! and mainnet is past Chronicle, so the outputs stay. The FORKID midstates
//! are computed from the held fields when the scripts run, as for a
//! transaction read in order.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::primitives::{bounded_capacity, Reader, Writer};
use crate::transaction::chain_tracker::ChainTracker;

use super::{
    AsyncStreamVerifier, AsyncVerifyError, BeefIndex, Budget, ChainTip, Folded, Hash32, InputRef,
    Judge, Pending, Stop, TxBody, Verdict, MAX_MONEY,
};
/// An input of a held transaction: where it lies and the outpoint it spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HeldInput {
    /// The stream offset of its 32-byte previous txid.
    pub(super) at: u64,
    pub(super) prev: Hash32,
    pub(super) vout: u32,
    pub(super) sequence: u32,
}

/// The bytes a [`HeldInput`] holds.
const INPUT_BYTES: u64 = 48;

/// An output of a held transaction, as the index retains one, and the
/// offset of its value field (the P2SH refusal names it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HeldOutput {
    pub(super) at: u64,
    pub(super) satoshis: u64,
    pub(super) script: Box<[u8]>,
}

/// What the scripts of a held transaction need: kept only by an index that
/// checks spends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HeldSpends {
    pub(super) version: u32,
    pub(super) lock_time: u32,
    /// Each input's unlocking script, in input order.
    pub(super) unlocking: Box<[Box<[u8]>]>,
    pub(super) outputs: Box<[HeldOutput]>,
}

/// An unproven transaction read ahead of a parent, by its index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HeldTx {
    pub(super) offset: u64,
    pub(super) txid: Hash32,
    /// The bytes it took on the wire (the work it is charged when folded).
    pub(super) wire_len: u64,
    pub(super) inputs: Box<[HeldInput]>,
    pub(super) spends: Option<Box<HeldSpends>>,
}

impl HeldTx {
    /// The entry of `body`, its raw bytes dropped: the scripts and outputs
    /// copied out when `spends`.
    pub(super) fn of(offset: u64, txid: Hash32, body: &TxBody, spends: bool) -> Self {
        let inputs = body
            .inputs
            .iter()
            .map(|i| HeldInput {
                at: i.at,
                prev: i.prev,
                vout: i.vout,
                sequence: i.sequence,
            })
            .collect();
        let spends = spends.then(|| {
            Box::new(HeldSpends {
                version: body.version,
                lock_time: body.lock_time,
                unlocking: body
                    .inputs
                    .iter()
                    .map(|i: &InputRef| body.raw[i.script.clone()].into())
                    .collect(),
                outputs: body
                    .outputs
                    .iter()
                    .map(|o| HeldOutput {
                        at: o.at,
                        satoshis: o.satoshis,
                        script: body.raw[o.script.clone()].into(),
                    })
                    .collect(),
            })
        });
        Self {
            offset,
            txid,
            wire_len: body.raw.len() as u64,
            inputs,
            spends,
        }
    }

    /// The bytes it holds: 56 for its offset, txid, wire length and the held
    /// set's key, 48 per
    /// input, and with spends 8 for the version and lock time, each
    /// unlocking script, 16 per output and each locking script.
    pub(super) fn held_bytes(&self) -> u64 {
        let mut bytes = 56 + INPUT_BYTES * self.inputs.len() as u64;
        if let Some(spends) = &self.spends {
            bytes += 8;
            bytes += spends.unlocking.iter().map(|s| s.len() as u64).sum::<u64>();
            bytes += spends
                .outputs
                .iter()
                .map(|o| 16 + o.script.len() as u64)
                .sum::<u64>();
        }
        bytes
    }
}

/// The fields of an unproven transaction the fold reads after the inputs
/// resolve: a transaction read in order ([`TxBody`]) or one released from
/// the held set ([`HeldTx`]), so both run through one fold.
pub(super) trait TxFields {
    fn version(&self) -> u32;
    fn lock_time(&self) -> u32;
    fn wire_len(&self) -> u64;
    fn input_count(&self) -> usize;
    fn input(&self, i: usize) -> HeldInput;
    fn unlocking(&self, i: usize) -> &[u8];
    fn output_count(&self) -> usize;
    /// The output's offset, value and locking script.
    fn output(&self, i: usize) -> (u64, u64, &[u8]);
}

impl TxFields for TxBody {
    fn version(&self) -> u32 {
        self.version
    }
    fn lock_time(&self) -> u32 {
        self.lock_time
    }
    fn wire_len(&self) -> u64 {
        self.raw.len() as u64
    }
    fn input_count(&self) -> usize {
        self.inputs.len()
    }
    fn input(&self, i: usize) -> HeldInput {
        let input = &self.inputs[i];
        HeldInput {
            at: input.at,
            prev: input.prev,
            vout: input.vout,
            sequence: input.sequence,
        }
    }
    fn unlocking(&self, i: usize) -> &[u8] {
        &self.raw[self.inputs[i].script.clone()]
    }
    fn output_count(&self) -> usize {
        self.outputs.len()
    }
    fn output(&self, i: usize) -> (u64, u64, &[u8]) {
        let output = &self.outputs[i];
        (output.at, output.satoshis, &self.raw[output.script.clone()])
    }
}

/// A held entry without spends answers no script field: the index that
/// holds it never runs one.
impl TxFields for HeldTx {
    fn version(&self) -> u32 {
        self.spends.as_ref().map_or(0, |s| s.version)
    }
    fn lock_time(&self) -> u32 {
        self.spends.as_ref().map_or(0, |s| s.lock_time)
    }
    fn wire_len(&self) -> u64 {
        self.wire_len
    }
    fn input_count(&self) -> usize {
        self.inputs.len()
    }
    fn input(&self, i: usize) -> HeldInput {
        self.inputs[i]
    }
    fn unlocking(&self, i: usize) -> &[u8] {
        self.spends
            .as_ref()
            .and_then(|s| s.unlocking.get(i))
            .map_or(&[], |s| s)
    }
    fn output_count(&self) -> usize {
        self.spends.as_ref().map_or(0, |s| s.outputs.len())
    }
    fn output(&self, i: usize) -> (u64, u64, &[u8]) {
        match self.spends.as_ref().and_then(|s| s.outputs.get(i)) {
            Some(output) => (output.at, output.satoshis, &output.script),
            None => (0, 0, &[]),
        }
    }
}

/// The unproven transactions read ahead of a parent (bsv-rs#240): each held
/// by its entry ([`HeldTx`]) until every txid its inputs name is in the
/// index, then ready, and folded in one per step, in wire order. A BEEF in
/// BRC-62's order (parents before children) holds none.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Deferred {
    /// The transactions held, by stream offset.
    pub(super) held: BTreeMap<u64, HeldTx>,
    /// For each one held and not ready, the distinct txids it still waits on.
    missing: HashMap<u64, usize>,
    /// For each txid waited on, the offsets of the transactions waiting.
    waiting: HashMap<Hash32, Vec<u64>>,
    /// The held transactions that wait on nothing, by offset.
    ready: BTreeSet<u64>,
    /// The bytes held ([`HeldTx::held_bytes`]).
    pub(super) bytes: u64,
}

impl Deferred {
    /// Holds `tx` until each txid of `missing` is in the index (ready at
    /// once when there is none).
    pub(super) fn hold(&mut self, tx: HeldTx, missing: HashSet<Hash32>) {
        let at = tx.offset;
        if missing.is_empty() {
            self.ready.insert(at);
        } else {
            for txid in &missing {
                self.waiting.entry(*txid).or_default().push(at);
            }
            self.missing.insert(at, missing.len());
        }
        self.bytes += tx.held_bytes();
        self.held.insert(at, tx);
    }

    /// `txid` is in the index: each transaction it was the last wait of is
    /// ready.
    pub(super) fn wake(&mut self, txid: &Hash32) {
        let Some(waiters) = self.waiting.remove(txid) else {
            return;
        };
        for at in waiters {
            if let Some(left) = self.missing.get_mut(&at) {
                *left -= 1;
                if *left == 0 {
                    self.missing.remove(&at);
                    self.ready.insert(at);
                }
            }
        }
    }

    /// A held transaction waits on nothing.
    pub(super) fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// The transaction at `at` is held, waits on nothing, and is `txid`.
    pub(super) fn is_ready(&self, at: u64, txid: &Hash32) -> bool {
        self.ready.contains(&at) && self.held.get(&at).is_some_and(|tx| tx.txid == *txid)
    }

    /// The earliest ready transaction on the wire: its offset and txid.
    pub(super) fn next_ready(&self) -> Option<(u64, Hash32)> {
        let at = *self.ready.first()?;
        self.held.get(&at).map(|tx| (at, tx.txid))
    }

    /// The ready transaction at `at`, taken out to be folded.
    pub(super) fn take_ready(&mut self, at: u64) -> Option<HeldTx> {
        if !self.ready.contains(&at) {
            return None;
        }
        self.held.remove(&at)
    }

    /// A transaction taken out and not folded (a pause, a refusal): held
    /// again, still ready.
    pub(super) fn put_back(&mut self, tx: HeldTx) {
        self.held.insert(tx.offset, tx);
    }

    /// The earliest held transaction on the wire and its earliest input that
    /// names a txid `known` does not hold (its offset and that txid), or the
    /// transaction's offset and zeros: what the end refuses.
    pub(super) fn unresolved(&self, known: impl Fn(&Hash32) -> bool) -> Option<(u64, Hash32)> {
        let held = self.held.values().next()?;
        let input = held.inputs.iter().find(|input| !known(&input.prev));
        Some(input.map_or((held.offset, [0u8; 32]), |i| (i.at, i.prev)))
    }

    /// The transaction taken out at `at` was folded in.
    pub(super) fn folded(&mut self, at: u64, tx: &HeldTx) {
        self.ready.remove(&at);
        self.bytes -= tx.held_bytes();
    }
}

/// The index's side of the deferral: a transaction held for a parent, and
/// one released, folded in.
impl BeefIndex {
    /// Holds an unproven transaction an input of which names a txid the
    /// index does not hold yet, by its entry: true when it is held.
    pub(super) fn held_for_a_parent(&mut self, offset: u64, txid: &Hash32, body: &TxBody) -> bool {
        let missing: HashSet<Hash32> = body
            .inputs
            .iter()
            .map(|input| input.prev)
            .filter(|prev| !self.txs.contains_key(prev))
            .collect();
        if missing.is_empty() {
            return false;
        }
        self.note_raw(txid, offset);
        let held = HeldTx::of(offset, *txid, body, self.check_spends);
        self.deferred.hold(held, missing);
        true
    }

    /// The earliest ready transaction of the held set folded in, its scripts
    /// run from input `from` with `spent` asked between inputs: `None` when
    /// none is ready. A pause or a refusal leaves it held and the index
    /// unchanged; folded in, its txid wakes what waits on it.
    pub(super) fn release_one(
        &mut self,
        from: u32,
        spent: &mut dyn FnMut() -> bool,
        budget: Budget,
        tip: Option<ChainTip>,
    ) -> Result<Option<Folded>, Stop> {
        let Some((at, _)) = self.deferred.next_ready() else {
            return Ok(None);
        };
        let Some(held) = self.deferred.take_ready(at) else {
            return Ok(None);
        };
        let folded = self.fold_tx(
            held.offset,
            &held.txid,
            None,
            false,
            &held,
            from,
            spent,
            budget,
            tip,
        );
        match folded {
            Ok(Folded::Paused(input)) => {
                self.deferred.put_back(held);
                Ok(Some(Folded::Paused(input)))
            }
            Ok(folded) => {
                self.deferred.folded(at, &held);
                if let Folded::In { txid, new: true } = folded {
                    self.deferred.wake(&txid);
                }
                Ok(Some(folded))
            }
            Err(stop) => {
                self.deferred.put_back(held);
                Err(stop)
            }
        }
    }
}

/// The reader's side: one released transaction per step.
impl Judge {
    /// Folds in the earliest held transaction that waits on nothing
    /// (bsv-rs#240), its scripts run under `spent` from the input a paused
    /// reading reached in it, else from its input 0: `None` when none waits on
    /// nothing, `Some(Ok(true))` a pause, which `resume_at` then names.
    pub(super) fn release_next(
        &mut self,
        spent: &mut dyn FnMut() -> bool,
        budget: Budget,
        tip: Option<ChainTip>,
    ) -> Option<Result<bool, Stop>> {
        let (at, txid) = self.index.deferred.next_ready()?;
        let from = match self.resume_at {
            Some(p) if p.offset == at && p.txid == txid => {
                self.resume_at = None;
                p.input
            }
            _ => 0,
        };
        Some(match self.index.release_one(from, spent, budget, tip) {
            Ok(Some(Folded::Paused(input))) => {
                self.resume_at = Some(Pending {
                    offset: at,
                    txid,
                    input,
                });
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(stop) => Err(stop),
        })
    }
}

/// The asynchronous reader's side: every released transaction at once.
impl AsyncStreamVerifier {
    /// Folds in every held transaction that waits on nothing (bsv-rs#240),
    /// in wire order, with the mining tip asked once: this reader has no
    /// step budget.
    pub(super) async fn release_all(
        &mut self,
        tracker: &dyn ChainTracker,
    ) -> Result<Option<Verdict>, AsyncVerifyError> {
        if !self.judge.index.deferred.has_ready() {
            return Ok(None);
        }
        let tip = if self.judge.index.check_spends {
            tracker
                .mining_tip()
                .await
                .map_err(AsyncVerifyError::Headers)?
        } else {
            None
        };
        while let Some(released) = self.judge.release_next(&mut || false, self.budget, tip) {
            if let Err(stop) = released {
                return Ok(Some(stop.into()));
            }
        }
        Ok(None)
    }
}

/// The held entries in a cursor (BSC4, after the outputs named): their
/// count, then by offset each one's offset, txid, wire length and inputs
/// (offset, outpoint, sequence), and a byte saying whether its spends
/// follow (version, lock time, each unlocking script, the outputs: offset,
/// value, locking script).
pub(super) fn write_held(w: &mut Writer, deferred: &Deferred) {
    w.write_var_int(deferred.held.len() as u64);
    for tx in deferred.held.values() {
        w.write_u64_le(tx.offset);
        w.write_bytes(&tx.txid);
        w.write_var_int(tx.wire_len);
        w.write_var_int(tx.inputs.len() as u64);
        for input in tx.inputs.iter() {
            w.write_u64_le(input.at);
            w.write_bytes(&input.prev);
            w.write_u32_le(input.vout);
            w.write_u32_le(input.sequence);
        }
        match &tx.spends {
            None => {
                w.write_u8(0);
            }
            Some(spends) => {
                w.write_u8(1);
                w.write_u32_le(spends.version);
                w.write_u32_le(spends.lock_time);
                for script in spends.unlocking.iter() {
                    w.write_var_bytes(script);
                }
                w.write_var_int(spends.outputs.len() as u64);
                for output in spends.outputs.iter() {
                    w.write_u64_le(output.at);
                    w.write_u64_le(output.satoshis);
                    w.write_var_bytes(&output.script);
                }
            }
        }
    }
}

/// A count of at least one item of at least `min` bytes each, bounded by
/// the bytes left.
fn count(r: &mut Reader, min: usize) -> Result<usize, &'static str> {
    let n = r.read_var_int().map_err(|_| "bytes cut short")?;
    let n = usize::try_from(n).map_err(|_| "a count past the bytes")?;
    if n == 0 {
        return Err("an empty list");
    }
    if n > r.remaining() / min {
        return Err("a count past the bytes");
    }
    Ok(n)
}

/// A BSC4 cursor's held entries into `index`'s deferred set, each held on
/// the txids of `known` it does not hold (`pos` the frame's: every entry was
/// read before it). `Err` names what is not a cursor.
pub(super) fn read_held(
    r: &mut Reader,
    deferred: &mut Deferred,
    spends: bool,
    pos: u64,
    known: impl Fn(&Hash32) -> bool,
) -> Result<(), &'static str> {
    let underflow = |_| "bytes cut short";
    let hash = |r: &mut Reader| -> Result<Hash32, &'static str> {
        let mut h = [0u8; 32];
        h.copy_from_slice(r.read_bytes(32).map_err(underflow)?);
        Ok(h)
    };
    let n = count(r, 8 + 32 + 1 + 1 + 48 + 1)?;
    let mut previous: Option<u64> = None;
    for _ in 0..n {
        let offset = r.read_u64_le().map_err(underflow)?;
        if previous.is_some_and(|p| p >= offset) {
            return Err("held transactions out of order");
        }
        if offset >= pos {
            return Err("a held transaction after its frame");
        }
        previous = Some(offset);
        let txid = hash(r)?;
        let wire_len = r.read_var_int().map_err(underflow)?;
        let n_inputs = count(r, 48)?;
        let mut inputs = Vec::with_capacity(bounded_capacity(n_inputs, r.remaining(), 48));
        for _ in 0..n_inputs {
            inputs.push(HeldInput {
                at: r.read_u64_le().map_err(underflow)?,
                prev: hash(r)?,
                vout: r.read_u32_le().map_err(underflow)?,
                sequence: r.read_u32_le().map_err(underflow)?,
            });
        }
        let held_spends = match r.read_u8().map_err(underflow)? {
            0 if !spends => None,
            1 if spends => {
                let version = r.read_u32_le().map_err(underflow)?;
                let lock_time = r.read_u32_le().map_err(underflow)?;
                let mut unlocking =
                    Vec::with_capacity(bounded_capacity(n_inputs, r.remaining(), 1));
                for _ in 0..n_inputs {
                    unlocking.push(r.read_var_bytes().map_err(underflow)?.into());
                }
                let n_outputs = count(r, 17)?;
                let mut outputs =
                    Vec::with_capacity(bounded_capacity(n_outputs, r.remaining(), 17));
                let mut total = 0u64;
                for _ in 0..n_outputs {
                    let at = r.read_u64_le().map_err(underflow)?;
                    let satoshis = r.read_u64_le().map_err(underflow)?;
                    // The fold's sums hold under MoneyRange, as the decoder
                    // checked it of the bytes this entry was held from.
                    if satoshis > MAX_MONEY || satoshis > MAX_MONEY - total {
                        return Err("an output value outside MoneyRange");
                    }
                    total += satoshis;
                    let script = r.read_var_bytes().map_err(underflow)?.into();
                    outputs.push(HeldOutput {
                        at,
                        satoshis,
                        script,
                    });
                }
                Some(Box::new(HeldSpends {
                    version,
                    lock_time,
                    unlocking: unlocking.into(),
                    outputs: outputs.into(),
                }))
            }
            _ => return Err("a held transaction's spends byte"),
        };
        let missing: HashSet<Hash32> = inputs
            .iter()
            .map(|input| input.prev)
            .filter(|prev| !known(prev))
            .collect();
        // One that waits on nothing was released by the step that took the
        // cursor and is folded in, one per step, before the next element.
        deferred.hold(
            HeldTx {
                offset,
                txid,
                wire_len,
                inputs: inputs.into(),
                spends: held_spends,
            },
            missing,
        );
    }
    Ok(())
}
