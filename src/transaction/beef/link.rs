//! Linking a BEEF's input ancestry, and the #749 bound on how far it may
//! re-materialize a shared parent.
//!
//! `add_input_proof` links each distinct parent once and hands every later
//! input that spends the same parent a clone of its stub — the parent without
//! its ancestry but with all of its outputs. A child whose M inputs each spend
//! one output of a single parent of N outputs therefore holds M copies of all N
//! outputs: the cost grows with the PRODUCT M×N, not the sum. An untrusted
//! answer within a resolver's byte bound could force multi-gigabyte heap before
//! any evidence check (an out-of-memory kill, a wasm32 abort). So linking meters
//! the output slots the repeats re-materialize and refuses a BEEF past
//! [`BeefLinkLimits`]; the full links (one per distinct parent) are the BEEF's
//! own outputs and are not counted.

use std::collections::HashMap;

use crate::transaction::beef_tx::BeefTx;
use crate::transaction::merkle_path::MerklePath;
use crate::transaction::Transaction;
use crate::Result;

use super::Beef;

/// The default [`BeefLinkLimits::max_amplification`]: linking may re-materialize
/// up to this multiple of a BEEF's own output count before it is refused. Set
/// well above the amplification of every honest BEEF the test corpus holds
/// (their repeats re-materialize far fewer slots than the BEEF's own outputs)
/// and far below the #749 denial of service's (thousands).
const DEFAULT_LINK_AMPLIFICATION: u64 = 64;

/// The default [`BeefLinkLimits::floor`]: a BEEF may always re-materialize this
/// many output slots regardless of its own output count, so a small honest BEEF
/// with a few repeats is never refused for its size. 4096 slots is well under a
/// megabyte of heap.
const DEFAULT_LINK_FLOOR: u64 = 4096;

/// Bounds on how far linking a BEEF's input ancestry may re-materialize the
/// BEEF's own outputs, applied by [`Beef::find_atomic_transaction`] and
/// [`Transaction::from_beef`](crate::transaction::Transaction::from_beef).
///
/// Linking hands every repeat input that spends an already-linked parent a
/// clone of that parent (its outputs are what the input spends); a BEEF whose
/// one parent of N outputs is spent by M separate inputs therefore holds M
/// copies of all N outputs — a cost that grows with the PRODUCT M×N, not the
/// sum, so a small answer well within a resolver's byte bound can force
/// multi-gigabyte heap (bsv-rs #749). These limits cap the re-materialized
/// output count at a multiple of the BEEF's own output count plus a floor,
/// restoring the crate's rule that every allocation is bounded by the input.
///
/// An honest BEEF re-materializes far fewer slots than its own outputs, so the
/// [default](BeefLinkLimits::default) refuses none of them. A caller that must
/// link a large ancestry it TRUSTS opts out with
/// [`BeefLinkLimits::unbounded`].
///
/// Build from [`default`](Self::default) or [`unbounded`](Self::unbounded) and
/// adjust with [`with_max_amplification`](Self::with_max_amplification) /
/// [`with_floor`](Self::with_floor); the struct is `#[non_exhaustive]` so a
/// later bound can be added without a break. No struct expression builds one
/// outside this crate, a functional update included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::transaction::BeefLinkLimits) -> bsv_rs::transaction::BeefLinkLimits {
///     bsv_rs::transaction::BeefLinkLimits { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::transaction::BeefLinkLimits) -> bsv_rs::transaction::BeefLinkLimits {
///     value
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BeefLinkLimits {
    /// The multiple of the BEEF's own output count that linking may
    /// re-materialize before it is refused. `None` disables the bound (link
    /// whatever the bytes hold — for a source the caller trusts).
    pub max_amplification: Option<u64>,
    /// A floor, in re-materialized output slots, added to the budget so a small
    /// honest BEEF is never refused for its size.
    pub floor: u64,
}

impl Default for BeefLinkLimits {
    fn default() -> Self {
        Self {
            max_amplification: Some(DEFAULT_LINK_AMPLIFICATION),
            floor: DEFAULT_LINK_FLOOR,
        }
    }
}

impl BeefLinkLimits {
    /// No bound: link whatever the bytes hold. Only for a BEEF whose source the
    /// caller trusts — an untrusted answer linked unbounded is the #749 denial
    /// of service.
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            max_amplification: None,
            floor: 0,
        }
    }

    /// Sets [`max_amplification`](Self::max_amplification) (`None` disables the
    /// bound).
    #[must_use]
    pub fn with_max_amplification(mut self, max_amplification: Option<u64>) -> Self {
        self.max_amplification = max_amplification;
        self
    }

    /// Sets [`floor`](Self::floor), the re-materialized output slots a BEEF may
    /// always reach regardless of its own output count.
    #[must_use]
    pub fn with_floor(mut self, floor: u64) -> Self {
        self.floor = floor;
        self
    }

    /// The budget, in re-materialized output slots, for a BEEF whose own
    /// transactions carry `total_outputs` outputs, or `None` when the bound is
    /// disabled.
    fn budget(&self, total_outputs: u64) -> Option<u64> {
        self.max_amplification
            .map(|k| total_outputs.saturating_mul(k).saturating_add(self.floor))
    }
}

impl Beef {
    /// Builds the proof tree rooted at a specific transaction, under the
    /// [default](BeefLinkLimits::default) link bound: a BEEF whose linking
    /// would re-materialize a shared parent far beyond the BEEF's own size
    /// (bsv-rs #749) yields `None`, as a BEEF whose `txid` is absent does. Use
    /// [`find_atomic_transaction_limited`](Self::find_atomic_transaction_limited)
    /// to tell the two apart or to raise the bound.
    #[must_use]
    pub fn find_atomic_transaction(&self, txid: &str) -> Option<Transaction> {
        self.find_atomic_transaction_limited(txid, &BeefLinkLimits::default())
            .ok()
            .flatten()
    }

    /// As [`find_atomic_transaction`](Self::find_atomic_transaction), but with
    /// an explicit [`BeefLinkLimits`]: `Ok(None)` when `txid` is not in this
    /// BEEF, `Err(`[`BeefError`](crate::Error::BeefError)`)` when linking would
    /// re-materialize more output slots than the limits allow (bsv-rs #749),
    /// and `Ok(Some(_))` with the linked transaction otherwise.
    #[allow(clippy::missing_errors_doc)] // the Errors are stated in the summary
    pub fn find_atomic_transaction_limited(
        &self,
        txid: &str,
        limits: &BeefLinkLimits,
    ) -> Result<Option<Transaction>> {
        let Some(beef_tx) = self.find_txid(txid) else {
            return Ok(None);
        };
        let Some(mut tx) = beef_tx.tx().cloned() else {
            return Ok(None);
        };
        self.add_input_proof(&mut tx, limits)?;
        Ok(Some(tx))
    }

    /// The total number of outputs the BEEF's own transactions carry — the
    /// measure a [`BeefLinkLimits`] budget is a multiple of.
    fn total_output_slots(&self) -> u64 {
        self.txs
            .iter()
            .filter_map(BeefTx::tx)
            .map(|t| t.outputs.len() as u64)
            .sum()
    }

    /// Attach merkle paths and source transactions to `tx` and its whole
    /// input ancestry, LINEARLY: every distinct unproven parent is linked in
    /// full exactly once (memoized by txid), and every later input that
    /// sources the same txid gets a BARE STUB of it: the parent transaction
    /// itself (its outputs are what the input spends), carrying its BUMP when
    /// this BEEF proves it, with every one of ITS inputs' `source_transaction`
    /// left `None`.
    ///
    /// Port of the TypeScript `Beef.addInputProof` (`@bsv/sdk`
    /// `transaction/Beef.ts`): a transaction with a BUMP in this BEEF gets it
    /// as its `merkle_path` and is not descended (a proven transaction needs
    /// no ancestry); an unproven one has each input's `source_transaction`
    /// linked from this BEEF and is descended in turn.
    ///
    /// The TS walk keeps one `Transaction` object per txid and assigns it to
    /// every input by reference, so linking it once links it everywhere.
    /// Rust stores `source_transaction` as an owned `Box`, one copy per input,
    /// so the reference structure cannot be reproduced exactly and the two
    /// naive answers are both wrong:
    ///
    /// - link only the first occurrence and hand later inputs a bare clone
    ///   (0.3.20): the structure stays linear, but the old object-graph
    ///   `Transaction::verify` reached the bare clone and refused a complete
    ///   BEEF with "Input N has no source transaction", and two inputs
    ///   sourcing the same unproven parent (a covenant output plus that
    ///   transaction's own change) is the ordinary shape of a wallet's
    ///   second spend;
    /// - link every input in full by cloning the memoized parent (0.3.21):
    ///   correct for that walk, but EXPONENTIAL. On a diamond chain, where
    ///   each level spends both outputs of the previous unproven level (a
    ///   wallet's ordinary change chain), every level then carries two full
    ///   copies of the level below it: 24 levels = 2^24 subtrees, and
    ///   `from_beef` died on memory before verification even started.
    ///
    /// So the structure stays linear as in 0.3.20 (one full link per txid plus
    /// one cheap stub per repeat), and [`Transaction::verify`] no longer cares
    /// which copy it reaches: it gathers the reachable transactions by txid and
    /// looks every input's source up in that map.
    ///
    /// The walk is ITERATIVE (0.3.35, bsv-stack-lean #57): an explicit stack of
    /// frames replaces the call that recursed once per unproven link, so a
    /// stranger's chain of unproven transactions costs heap, not stack (a
    /// 1 MiB stack, the order of a WASM stack in a Worker, overflowed at a few
    /// hundred links and the abort took every request in flight with it). The
    /// frames are visited in the recursion's order (depth first, inputs in
    /// order), so which input gets the full link and which a stub, and the
    /// resulting `source_transaction` shape, are exactly the recursive walk's.
    /// The reference walks iteratively too (`@bsv/sdk` `Beef.#addInputProof`).
    /// Bumps are looked up through an index built once, so the walk is linear
    /// in the BEEF rather than in transactions times bumps.
    ///
    /// The re-materialization the repeat inputs cost is metered against
    /// `limits` (the #749 bound; `BeefLinkLimits::unbounded` lifts it).
    fn add_input_proof(&self, tx: &mut Transaction, limits: &BeefLinkLimits) -> Result<()> {
        /// One transaction being linked, and the next input to link.
        struct Frame {
            tx: Transaction,
            next_input: usize,
        }

        // The #749 bound: every repeat input that spends an already-linked
        // parent is handed a clone of that parent's outputs, so a shared parent
        // of N outputs spent by M inputs re-materializes M×N output slots. Cap
        // the running total at the limits' budget; the full links (one per
        // distinct parent) are the BEEF's own outputs and are not counted.
        let budget = limits.budget(self.total_output_slots());
        let mut materialized: u64 = 0;

        // `find_bump`'s answer for every hash at level 0: the FIRST bump whose
        // leaf level carries it, as `find_bump`'s scan returns.
        let mut bump_by_txid: HashMap<&str, &MerklePath> = HashMap::new();
        for bump in &self.bumps {
            for leaf in bump.path.first().into_iter().flatten() {
                if let Some(hash) = leaf.hash.as_deref() {
                    bump_by_txid.entry(hash).or_insert(bump);
                }
            }
        }
        let find_bump = |txid: &str| bump_by_txid.get(txid).copied();

        // Attach a transaction's own proof; a proven transaction is not
        // descended (its frame starts with no input left to link).
        let enter = |mut tx: Transaction| -> Frame {
            if tx.merkle_path.is_none() {
                if let Some(mp) = find_bump(&tx.id()) {
                    tx.merkle_path = Some(mp.clone());
                }
            }
            let next_input = if tx.merkle_path.is_some() {
                tx.inputs.len()
            } else {
                0
            };
            Frame { tx, next_input }
        };

        // Keyed by txid, the value being the stub handed to later inputs.
        // Presence also means "this txid has been linked in full once".
        let mut stubs: HashMap<String, Transaction> = HashMap::new();
        let mut stack: Vec<Frame> = vec![enter(std::mem::take(tx))];

        while let Some(top) = stack.last_mut() {
            if top.next_input == top.tx.inputs.len() {
                // Every input of this transaction is linked: hand it to the
                // input of its parent that it sources, or back to the caller.
                let Some(Frame { tx: done, .. }) = stack.pop() else {
                    break;
                };
                match stack.last_mut() {
                    Some(parent) => {
                        parent.tx.inputs[parent.next_input - 1].source_transaction =
                            Some(Box::new(done));
                    }
                    None => *tx = done,
                }
                continue;
            }
            let input = &mut top.tx.inputs[top.next_input];
            top.next_input += 1;
            let Some(src_txid) = input.source_txid.clone() else {
                continue;
            };
            if let Some(stub) = stubs.get(&src_txid) {
                // Already linked in full once: this input gets the stub, which
                // carries the output being spent (and the proof when there is
                // one) without repeating the ancestry underneath it.
                if let Some(budget) = budget {
                    materialized = materialized.saturating_add(stub.outputs.len() as u64);
                    if materialized > budget {
                        return Err(crate::Error::BeefError(format!(
                            "BEEF linking would re-materialize more than {budget} output slots: a \
                             shared parent spent by many inputs (bsv-rs #749). Raise or disable \
                             the bound with Transaction::from_beef_with_limits / BeefLinkLimits."
                        )));
                    }
                }
                input.source_transaction = Some(Box::new(stub.clone()));
                continue;
            }
            // Take the caller's own source when it carries one, else this BEEF's.
            let mut src = match input.source_transaction.take() {
                Some(own) => *own,
                None => match self.find_txid(&src_txid).and_then(|b| b.tx().cloned()) {
                    Some(found) => found,
                    None => continue, // not in this BEEF: left unlinked, as before
                },
            };
            // Memoize the stub BEFORE descending: a BEEF whose source links
            // form a cycle then terminates instead of walking forever, and for
            // the honest DAG case the order makes no difference (a transaction
            // is never reachable from inside its own ancestry).
            let stub = Self::bare_stub(&mut src, find_bump(&src_txid));
            stubs.insert(src_txid, stub);
            stack.push(enter(src));
        }
        Ok(())
    }

    /// A bare copy of `tx`: the transaction with its BUMP when the BEEF proves
    /// it, and with every input's `source_transaction` dropped, so no ancestry
    /// is duplicated. The ancestry is lifted out before the clone and put back
    /// after, so building a stub never copies a subtree.
    pub(super) fn bare_stub(tx: &mut Transaction, bump: Option<&MerklePath>) -> Transaction {
        let ancestry: Vec<Option<Box<Transaction>>> = tx
            .inputs
            .iter_mut()
            .map(|input| input.source_transaction.take())
            .collect();
        let mut stub = tx.clone();
        for (input, source) in tx.inputs.iter_mut().zip(ancestry) {
            input.source_transaction = source;
        }
        if stub.merkle_path.is_none() {
            if let Some(mp) = bump {
                stub.merkle_path = Some(mp.clone());
            }
        }
        stub
    }
}
