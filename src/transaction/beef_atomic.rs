//! The Atomic BEEF writer (moved from `beef.rs`, 0.8.8's fold): the BRC-95
//! closure of a subject, cut from the entries as held, and its two doors.
//!
//! `Beef::to_binary_atomic` is the Beef-level door, on a BEEF a caller
//! assembles by hand: its closure keeps the documented dependency sort (#798's
//! fold; the reference's `#getBeefForAtomic` sorts what it leaves, `Beef.ts:
//! 385-389` at ts-stack@edf6e03). [`to_binary_atomic_subject_last`](Beef::to_binary_atomic_subject_last)
//! is the transaction door's form (`Transaction::to_atomic_beef` and
//! `legacy_to_beef`'s atomic leg): the same closure and the same sort, then
//! the subject moved last, each entry's sources above it — BRC-62's rule for
//! the form, as the plain transaction doors end with theirs since 0.8.8 — so
//! a graph holding a proven branch beside a missing source ends with the
//! subject and the no-txid read takes it back. The closure is the subject's
//! ancestry, so the move changes no other entry's place: the bytes are the
//! sorted closure's wherever its subject was already last.

use std::collections::{HashMap, HashSet};

use super::super::beef_tx::{BeefTx, ATOMIC_BEEF};
use super::in_memory;
use super::Beef;
use crate::primitives::{from_hex, Writer};
use crate::Result;

impl Beef {
    /// Serializes this BEEF as Atomic BEEF for a specific transaction.
    ///
    /// The BEEF written is the subject's BRC-95 closure, not every entry this
    /// one holds (0.8.1): from the subject, the inputs of each raw entry are
    /// followed, stopping at an entry carrying a BUMP index (matching or not,
    /// #798) and at a txid-only entry; every other entry is dropped. The BUMPs
    /// kept are those that prove a kept entry, renumbered; an index naming no
    /// BUMP holding its entry's txid is dropped unless another kept entry's
    /// proof is the BUMP it names (the reference's `#copySelectedTransactions`). The order is
    /// the reference's sort: the subject last when every kept entry's inputs
    /// are kept or proven, else the entries with an input outside and those
    /// resting on them ahead of the proven ones, the subject among them
    /// (#798's fold; an entry held as a transaction alone has its inputs
    /// re-scanned when its index is dropped, the reference's `BeefTx.fromTx`).
    /// This is what `@bsv/sdk` 3
    /// (`Beef.#collectAtomicTransactions`) and go-sdk (`selectAtomicBeef`)
    /// write, and every reader accepts it: the readers of this crate, of
    /// 0.8.0, of TS 2, TS 3 and Go. [`to_binary`](Self::to_binary) still
    /// writes every entry. A BEEF a transaction door assembled takes the
    /// transaction door's form, `to_binary_atomic_subject_last`, through the
    /// door that collected it (0.8.8's fold).
    pub fn to_binary_atomic(&mut self, txid: &str) -> Result<Vec<u8>> {
        self.atomic_bytes(txid, false)
    }

    /// The transaction door's form of [`to_binary_atomic`](Self::to_binary_atomic):
    /// the same closure and the same sort, then the subject moved last
    /// (BRC-62's rule for the form), each entry's sources above it, so the
    /// no-txid read of the bytes takes the subject back (0.8.8's fold).
    ///
    /// The `&mut self` is its pub siblings' own: the doors refresh the
    /// mutated entries before they write (`to_binary`, `to_binary_atomic`).
    #[allow(clippy::wrong_self_convention)] // crate-private, so the lint's pub exemption does not reach it
    pub(crate) fn to_binary_atomic_subject_last(&mut self, txid: &str) -> Result<Vec<u8>> {
        self.atomic_bytes(txid, true)
    }

    /// The shared body of the two Atomic BEEF doors: a batch of one.
    fn atomic_bytes(&mut self, txid: &str, subject_last: bool) -> Result<Vec<u8>> {
        self.atomic_batch()?.bytes(txid, subject_last)
    }

    /// Prepares this BEEF for any number of Atomic BEEFs cut from it: what
    /// [`to_binary_atomic`](Self::to_binary_atomic) does ahead of looking
    /// for its subject, done once (#817).
    ///
    /// Each call of the per-call door refreshes every entry, checks every
    /// held transaction's amounts and maps every entry's txid to its
    /// position, so k subjects cost k passes of each over the whole BEEF;
    /// the batch runs the three once and lends the BEEF shared, so nothing
    /// can move under the closures it cuts. Its
    /// [`to_binary_atomic`](AtomicBatch::to_binary_atomic) answers, for each
    /// txid, what the per-call door answers on this BEEF: the same bytes,
    /// the same refusal, in the same order (the amount refusal here, ahead
    /// of any subject, as the per-call door refuses it ahead of
    /// `does not exist in this Beef`).
    pub(crate) fn atomic_batch(&mut self) -> Result<AtomicBatch<'_>> {
        // The closure is copied from the entries as held and the copy alone
        // sorted, as the reference's `#getBeefForAtomic` does
        // (`Beef.ts:375-390`); until #798's second fold the source was sorted
        // first, which moved the closure's order where entries with inputs
        // outside lead.
        self.refresh_mutated();
        // Every held transaction is serialized first, an output of 2^53 or
        // more refused in the writer's words before the subject is looked
        // for, even outside the closure, as the reference's
        // `#getAtomicSerializedBytes` synchronizes every entry before
        // `#getBeefForAtomic` (`Beef.ts:392-404`; #844's fold).
        self.refuse_unsafe_amount()?;
        // Every entry's position by its txid, the last position of a txid
        // held twice winning: the closure's walk reads the entries through
        // this map and not the BEEF's index, which differs from it after
        // some hand edits of `txs` (the stated window of `beef/index.rs`),
        // so the bytes are the per-call door's in every state.
        let at = self.positions();
        Ok(AtomicBatch { beef: self, at })
    }

    /// Every entry's position by its txid, the last position of a txid held
    /// twice winning: one pass over every entry, a `String` and an insert
    /// each ([`atomic_batch`](Self::atomic_batch), once a batch).
    fn positions(&self) -> HashMap<String, usize> {
        let mut at = HashMap::with_capacity(self.txs.len());
        for (i, tx) in self.txs.iter().enumerate() {
            #[cfg(test)]
            cost::mapped();
            at.insert(tx.txid(), i);
        }
        at
    }

    /// The entries the atomic doors' loops visited on this thread since the
    /// last call, for a test outside this module ([`cost::Cost`]).
    #[cfg(test)]
    pub(crate) fn atomic_cost_taken() -> cost::Cost {
        cost::take()
    }

    /// A BUMP of this BEEF proves `tx`: its BUMP index names a BUMP whose
    /// level 0 carries the txid (the reference's `#hasMatchingBump`).
    fn proves(&self, tx: &BeefTx) -> bool {
        tx.bump_index()
            .and_then(|i| self.bumps.get(i))
            .is_some_and(|bump| bump.contains(&tx.txid()))
    }

    /// The BEEF of `subject`'s BRC-95 closure
    /// ([`to_binary_atomic`](Self::to_binary_atomic)): sorted as the Beef-level
    /// door documents, and for the transaction door the subject then moved
    /// last ([`to_binary_atomic_subject_last`](Self::to_binary_atomic_subject_last)).
    ///
    /// `at` is every entry's position by its txid
    /// ([`atomic_batch`](Self::atomic_batch)). The cost is the closure's:
    /// the entries kept are walked and copied in entry order, no other
    /// entry visited (#817; every entry of the BEEF was visited twice a
    /// closure until then).
    fn atomic_closure(
        &self,
        at: &HashMap<String, usize>,
        subject: &str,
        subject_last: bool,
    ) -> Beef {
        let mut included: HashSet<usize> = HashSet::new();
        let mut stack: Vec<usize> = at.get(subject).copied().into_iter().collect();
        while let Some(i) = stack.pop() {
            if !included.insert(i) {
                continue;
            }
            let tx = &self.txs[i];
            // Any index stops the walk, matching or not: the reference's
            // `bumpIndex` setter empties `inputTxids` (`BeefTx.ts:90-92`,
            // `:219-221`), so `:427-431` has nothing to descend (#798).
            if tx.is_txid_only() || tx.has_proof() {
                continue;
            }
            stack.extend(in_memory::spent_txids(tx).iter().filter_map(|t| at.get(t)));
        }

        // The BUMPs of the included entries a BUMP of this BEEF proves, in
        // entry order, renumbered (`#copySelectedTransactions`, `Beef.ts:453-456`).
        let mut kept: Vec<usize> = included.into_iter().collect();
        kept.sort_unstable();
        let mut beef = Beef::with_version(self.version);
        let mut renumbered: HashMap<usize, usize> = HashMap::new();
        for tx in kept.iter().map(|&i| &self.txs[i]) {
            #[cfg(test)]
            cost::bump_loop();
            if !self.proves(tx) {
                continue;
            }
            if let Some(index) = tx.bump_index() {
                renumbered.entry(index).or_insert_with(|| {
                    beef.bumps.push(self.bumps[index].clone());
                    beef.bumps.len() - 1
                });
            }
        }
        // Each included entry with its index mapped through those alone
        // (`:462`): an index naming no BUMP holding its txid (another BUMP or
        // none at all) is dropped unless another included entry's matching
        // BUMP is the one it names, where the mapped index stays, as the
        // reference writes it. A copy of an entry held raw keeps the
        // source's `input_txids` (`:464-465`), which the sort reads; one held
        // as a transaction alone, no bytes (`merge_transaction`), has them
        // re-scanned with its mapped index, as `BeefTx.fromTx` does (`:466-467`),
        // so an unmapped one whose parents lie outside joins the entries with
        // missing inputs, sorted ahead (#798's fold). An entry held raw and
        // mutated through `tx_mut` is one held raw (`held_raw`): the
        // reference keeps its `_rawTx`, re-synced (`BeefTx.ts:160-169`;
        // #798's second fold). Until #798 a raw entry's
        // BUMP was kept whatever it held (#766 for a txid-only one) and an
        // index out of range was an `Err`.
        for tx in kept.iter().map(|&i| &self.txs[i]) {
            #[cfg(test)]
            cost::copy_loop();
            let mut copy = tx.clone();
            copy.set_bump_index(tx.bump_index().and_then(|i| renumbered.get(&i).copied()));
            if tx.held_raw() {
                copy.input_txids = tx.input_txids.clone();
            }
            beef.txs.push(copy);
        }
        // The reference's sort as it leaves the entries (`#getBeefForAtomic`,
        // `Beef.ts:385-389`): the subject last when every entry links, else
        // with the entries whose inputs lie outside, ahead of the proven ones
        // (#798's fold; until then moved last after the sort). The
        // transaction door's closure is the subject's ancestry alone, so the
        // subject is moved last after the same sort (0.8.8's fold): every
        // other entry keeps the sorted place it had, each entry's sources
        // stay above it, and the bytes are those the stable line's atomic
        // door has written since 0.8.1.
        beef.sort_txs();
        if subject_last {
            if let Some(i) = beef.txs.iter().position(|tx| tx.txid() == subject) {
                let tx = beef.txs.remove(i);
                beef.txs.push(tx);
                beef.rebuild_index();
            }
        }
        beef
    }
}

/// A BEEF prepared for the Atomic BEEFs of several subjects
/// ([`Beef::atomic_batch`]): refreshed and its amounts checked once, every
/// entry's position by its txid held beside it (#817).
pub(crate) struct AtomicBatch<'a> {
    beef: &'a Beef,
    at: HashMap<String, usize>,
}

impl AtomicBatch<'_> {
    /// The bytes [`Beef::to_binary_atomic`] answers for `txid` on the
    /// prepared BEEF, or its refusal. Compiled where its one caller is (the
    /// binary lookup answer, `overlay` with `http`) and for the tests: a
    /// slice without them has no dead door.
    #[cfg(any(test, all(feature = "overlay", feature = "http")))]
    pub(crate) fn to_binary_atomic(&self, txid: &str) -> Result<Vec<u8>> {
        self.bytes(txid, false)
    }

    /// One subject's Atomic BEEF: the subject looked for, its closure cut
    /// and checked, the bytes written.
    fn bytes(&self, txid: &str, subject_last: bool) -> Result<Vec<u8>> {
        if self.beef.find_txid(txid).is_none() {
            return Err(crate::Error::BeefError(format!(
                "{} does not exist in this Beef",
                txid
            )));
        }
        let closure = self.beef.atomic_closure(&self.at, txid, subject_last);
        // The closure's bytes are built before the subject's, as the
        // reference's are (`Beef.ts:409-410`), so its refusals come first
        // (#817; until then a txid-only entry under V1 panicked here).
        closure.check_writable()?;

        let mut writer = Writer::new();
        writer.write_u32_le(ATOMIC_BEEF);

        // Write txid (reversed)
        let txid_bytes = from_hex(txid)?;
        let mut reversed = txid_bytes;
        reversed.reverse();
        writer.write_bytes(&reversed);

        closure.write_checked(&mut writer);
        Ok(writer.into_bytes())
    }
}

/// What the atomic doors spent, counted for the tests (#817): one for each
/// entry a loop VISITS, at the loop's own turn, so a loop put back over
/// every entry of the BEEF at a counted turn, or a whole-BEEF pass run again
/// a closure through its counted door (`positions`,
/// `refuse_unsafe_amount`), moves a figure; a scan spelled where no turn is
/// counted (a `filter` on the iterator ahead of the loop's body, a map
/// collected inline, `BeefTx::amount_refusal` called directly) is not seen
/// (the fold of the strength read: until it the counts were of
/// `atomic_batch` calls and of the entries a closure kept, which read the
/// same under a full scan). A count, never a time; no item of it exists
/// outside `cfg(test)`, so a build that is not the unit tests' holds no
/// call of it.
#[cfg(test)]
pub(super) mod cost {
    use std::cell::Cell;

    /// The entries visited, by the loop that visited them.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct Cost {
        /// `refresh_mutated`'s loop (`beef/index.rs`), any door's: a batch's
        /// whole BEEF once, and each closure's own entries at its sort.
        pub(crate) refreshed: usize,
        /// The entries handed to `refuse_unsafe_amount` (`beef_writable.rs`),
        /// any door's: a batch's whole BEEF once, and each closure's own
        /// entries at its `check_writable`.
        pub(crate) amounts: usize,
        /// The position map's loop (`Beef::positions`).
        pub(crate) mapped: usize,
        /// The closure's loop that renumbers the BUMPs.
        pub(crate) bump_loop: usize,
        /// The closure's loop that copies the entries.
        pub(crate) copy_loop: usize,
    }

    impl Cost {
        /// The three whole-BEEF passes: `(refreshed, amounts, mapped)`.
        pub(crate) fn passes(self) -> (usize, usize, usize) {
            (self.refreshed, self.amounts, self.mapped)
        }

        /// The closure's two loops: `(bump_loop, copy_loop)`.
        pub(crate) fn loops(self) -> (usize, usize) {
            (self.bump_loop, self.copy_loop)
        }
    }

    thread_local! {
        static SPENT: Cell<Cost> = const {
            Cell::new(Cost {
                refreshed: 0,
                amounts: 0,
                mapped: 0,
                bump_loop: 0,
                copy_loop: 0,
            })
        };
    }

    fn add(count: impl FnOnce(&mut Cost)) {
        SPENT.with(|s| {
            let mut spent = s.get();
            count(&mut spent);
            s.set(spent);
        });
    }

    /// One entry visited by `refresh_mutated`'s loop.
    pub(in crate::transaction::beef) fn refreshed() {
        add(|c| c.refreshed += 1);
    }

    /// `entries` handed to one amount check.
    pub(in crate::transaction::beef) fn amounts(entries: usize) {
        add(|c| c.amounts += entries);
    }

    /// One entry visited by the position map's loop.
    pub(super) fn mapped() {
        add(|c| c.mapped += 1);
    }

    /// One entry visited by the closure's BUMP loop.
    pub(super) fn bump_loop() {
        add(|c| c.bump_loop += 1);
    }

    /// One entry visited by the closure's copy loop.
    pub(super) fn copy_loop() {
        add(|c| c.copy_loop += 1);
    }

    /// This thread's counts since the last call.
    pub(super) fn take() -> Cost {
        SPENT.with(|s| s.replace(Cost::default()))
    }
}

#[cfg(test)]
#[path = "beef/atomic_batch_817_tests.rs"]
mod batch_tests;
