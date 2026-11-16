//! Linking a BEEF's input ancestry, and the #749 bound on how far it may
//! re-materialize a shared parent (bsv-rs #749): a child module of `beef`, so
//! the linker and its bound live outside `beef.rs`.

use std::collections::HashMap;

use crate::transaction::merkle_path::MerklePath;
use crate::transaction::Transaction;
use crate::Result;

use super::Beef;

/// The default [`BeefLinkLimits::max_link_bytes`]: linking may re-materialize up
/// to this many bytes of repeated shared-parent stubs beyond the BEEF's own
/// bytes before it is refused. 32 MiB matches the overlay lookup resolver's own
/// `LookupLimits::max_response_bytes`, so the heap a linked answer costs stays a
/// small multiple of the wire the caller already chose to read: the answer
/// itself (≤ 32 MiB at the resolver) plus at most another 32 MiB of
/// re-materialization, well within a 128 MB Worker. It sits far below the #749
/// denial of service (a 128 KiB answer re-materializing ~1.69 GB) and far above
/// every honest BEEF the corpus holds (their repeats re-materialize a few
/// hundred KiB at most).
const DEFAULT_MAX_LINK_BYTES: u64 = 32 * 1024 * 1024;

/// Bounds on how many bytes linking a BEEF's input ancestry may re-materialize
/// for a shared parent, applied by [`Beef::find_atomic_transaction`] and
/// [`Transaction::from_beef`](crate::transaction::Transaction::from_beef).
///
/// Linking hands every repeat input that spends an already-linked parent a
/// clone of that parent (its outputs are what the input spends); a BEEF whose
/// one parent of N outputs is spent by M separate inputs therefore holds M
/// copies of all N outputs — a cost that grows with the PRODUCT M×N, not the
/// sum, so a small answer well within a resolver's byte bound can force
/// multi-gigabyte heap (bsv-rs #749). These limits cap, in ABSOLUTE BYTES, how
/// far the repeats may re-materialize beyond the answer's own bytes, restoring
/// the crate's rule that every allocation is bounded by the input. A byte
/// budget (not a count of output slots) charges a parent of a few large outputs
/// its true weight, so a sub-megabyte BEEF of few large outputs cannot slip a
/// Worker-OOM re-materialization past the bound.
///
/// An honest BEEF re-materializes a few hundred KiB at most, far under the
/// [default](BeefLinkLimits::default) 32 MiB, so the default refuses none of
/// them. A caller that must link a large ancestry it TRUSTS opts out with
/// [`BeefLinkLimits::unbounded`].
///
/// Build from [`default`](Self::default) or [`unbounded`](Self::unbounded) and
/// adjust with [`with_max_link_bytes`](Self::with_max_link_bytes); the struct is
/// `#[non_exhaustive]` so a later bound can be added without a break. No struct
/// expression builds one outside this crate, a functional update included:
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
    /// The maximum number of bytes linking may re-materialize for repeat inputs
    /// that spend an already-linked shared parent, beyond the BEEF's own bytes,
    /// before it is refused. `None` disables the bound (link whatever the bytes
    /// hold — for a source the caller trusts).
    pub max_link_bytes: Option<u64>,
}

crate::util::non_exhaustive::assert_no_drop!(BeefLinkLimits, bsv_rs::transaction::BeefLinkLimits);

impl Default for BeefLinkLimits {
    fn default() -> Self {
        Self {
            max_link_bytes: Some(DEFAULT_MAX_LINK_BYTES),
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
            max_link_bytes: None,
        }
    }

    /// Sets [`max_link_bytes`](Self::max_link_bytes) (`None` disables the
    /// bound).
    #[must_use]
    pub fn with_max_link_bytes(mut self, max_link_bytes: Option<u64>) -> Self {
        self.max_link_bytes = max_link_bytes;
        self
    }
}

impl Beef {
    /// Builds the proof tree rooted at a specific transaction, under the
    /// [default](BeefLinkLimits::default) link bound: a BEEF whose linking
    /// would re-materialize a shared parent far beyond the BEEF's own size
    /// (bsv-rs #749) yields `None`, as a BEEF whose `txid` is absent does. Use
    /// [`find_atomic_transaction_limited`](Self::find_atomic_transaction_limited),
    /// which returns `Err(`[`BeefResourceLimit`](crate::Error::BeefResourceLimit)`)`
    /// on a refusal, to tell the two apart or to raise the bound.
    // No `#[must_use]`: a public attribute added to this pre-existing method is a
    // semver MINOR (`inherent_method_must_use_added`); the stable line cannot
    // carry it as a patch (bsv-rs #749 fold, ruling 1), so both lines drop it;
    // the local allow silences the pedantic lint without touching the public API.
    #[allow(clippy::must_use_candidate)]
    pub fn find_atomic_transaction(&self, txid: &str) -> Option<Transaction> {
        self.find_atomic_transaction_limited(txid, &BeefLinkLimits::default())
            .ok()
            .flatten()
    }

    /// As [`find_atomic_transaction`](Self::find_atomic_transaction), but with
    /// an explicit [`BeefLinkLimits`]: `Ok(None)` when `txid` is not in this
    /// BEEF, `Err(`[`BeefResourceLimit`](crate::Error::BeefResourceLimit)`)`
    /// when linking would re-materialize more bytes than the limits allow
    /// (bsv-rs #749) — a resource decline of its own class, told apart from an
    /// absent txid and from a malformed BEEF — and `Ok(Some(_))` with the
    /// linked transaction otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`BeefResourceLimit`](crate::Error::BeefResourceLimit) when
    /// linking `txid`'s ancestry would re-materialize more bytes than `limits`
    /// allow (bsv-rs #749).
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
    /// The bytes the repeat inputs re-materialize are metered against `limits`
    /// (the #749 bound; `BeefLinkLimits::unbounded` lifts it), and a BEEF that
    /// would cross the budget is refused with
    /// [`Error::BeefResourceLimit`](crate::Error::BeefResourceLimit) BEFORE the
    /// clone that would allocate past it.
    fn add_input_proof(&self, tx: &mut Transaction, limits: &BeefLinkLimits) -> Result<()> {
        /// One transaction being linked, and the next input to link.
        struct Frame {
            tx: Transaction,
            next_input: usize,
        }

        // The #749 bound, in ABSOLUTE BYTES: every repeat input that spends an
        // already-linked parent is handed a clone of that parent (its outputs
        // are what the input spends), so the heap the repeats re-materialize is
        // the sum of each stub's wire size over the repeats. Cap that running
        // sum at the limits' budget and refuse BEFORE the clone that would
        // cross it; the full links (one per distinct parent) are the BEEF's own
        // bytes and are not counted. A byte budget (not a count of slots)
        // charges a parent of a few large outputs its true weight.
        let budget = limits.max_link_bytes;
        let mut materialized_bytes: u64 = 0;

        // `find_bump`'s answer for every hash at level 0: the LAST bump whose
        // leaf level carries it, as the reference's index keeps it
        // (`Beef.ts:576-585` at `ts-stack@edf6e03`, `Map.set` over the bumps
        // in order; the earliest until #732).
        let mut bump_by_txid: HashMap<&str, &MerklePath> = HashMap::new();
        for bump in &self.bumps {
            for leaf in bump.path.first().into_iter().flatten() {
                if let Some(hash) = leaf.hash.as_deref() {
                    bump_by_txid.insert(hash, bump);
                }
            }
        }
        let find_bump = |txid: &str| bump_by_txid.get(txid).copied();

        // This BEEF's proof replaces any path the transaction carries, and a
        // transaction it proves is not descended; one it does not prove is,
        // a caller's path kept (`Beef.ts:658-666` at `ts-stack@edf6e03`;
        // until #757 a caller's path was kept and ended the walk).
        let enter = |mut tx: Transaction| -> Frame {
            let next_input = match find_bump(&tx.id()) {
                Some(mp) => {
                    tx.merkle_path = Some(mp.clone());
                    tx.inputs().len()
                }
                None => 0,
            };
            Frame { tx, next_input }
        };

        // Keyed by txid, the value being the stub handed to later inputs and
        // its wire-byte weight (computed once, the cost each repeat clone adds).
        // Presence also means "this txid has been linked in full once".
        let mut stubs: HashMap<String, (Transaction, u64)> = HashMap::new();
        let mut stack: Vec<Frame> = vec![enter(std::mem::take(tx))];

        while let Some(top) = stack.last_mut() {
            if top.next_input == top.tx.inputs().len() {
                // Every input of this transaction is linked: hand it to the
                // input of its parent that it sources, or back to the caller.
                let Some(Frame { tx: done, .. }) = stack.pop() else {
                    break;
                };
                // Every link goes through the linking door, which keeps the
                // caches where the input names its txid (#869's second fold:
                // `inputs_mut` emptied them, and `verify` re-serialized).
                match stack.last_mut() {
                    Some(parent) => {
                        parent
                            .tx
                            .replace_source(parent.next_input - 1, Some(Box::new(done)));
                    }
                    None => *tx = done,
                }
                continue;
            }
            let i = top.next_input;
            top.next_input += 1;
            let input = &top.tx.inputs()[i];
            // Keyed by what the input links, its own source's id, named or not (#869's
            // fourth fold), else its text (`Beef.ts:649-679` at `ts-stack@edf6e03`).
            let src_txid = match (&input.source_transaction, &input.source_txid) {
                (Some(own), _) => own.id(),
                (None, Some(text)) => text.clone(),
                (None, None) => continue, // links and names nothing: left as it is
            };
            if let Some((stub, stub_bytes)) = stubs.get(&src_txid) {
                // Already linked in full once: this input gets the stub, which
                // carries the output being spent (and the proof when there is
                // one) without repeating the ancestry underneath it. Meter the
                // stub's byte weight and refuse BEFORE the clone that would
                // allocate past the budget.
                if let Some(budget) = budget {
                    materialized_bytes = materialized_bytes.saturating_add(*stub_bytes);
                    if materialized_bytes > budget {
                        return Err(crate::Error::BeefResourceLimit(format!(
                            "linking would re-materialize more than {budget} bytes for a shared \
                             parent spent by many inputs (bsv-rs #749). Raise or disable the bound \
                             with Transaction::from_beef_with_limits / BeefLinkLimits::unbounded."
                        )));
                    }
                }
                top.tx.replace_source(i, Some(Box::new(stub.clone())));
                continue;
            }
            // Take the caller's own source when it carries one, else this BEEF's.
            let own = if top.tx.inputs()[i].source_transaction.is_some() {
                top.tx.replace_source(i, None)
            } else {
                None
            };
            let src = match own {
                Some(own) => *own,
                None => match self.find_txid(&src_txid).and_then(|b| b.tx().cloned()) {
                    Some(found) => found,
                    None => continue, // not in this BEEF: left unlinked, as before
                },
            };
            // Memoize the stub BEFORE descending: a BEEF whose source links
            // form a cycle then terminates instead of walking forever, and for
            // the honest DAG case the order makes no difference (a transaction
            // is never reachable from inside its own ancestry). Its wire size,
            // computed once here, is the byte weight each later repeat adds.
            let stub = Self::bare_stub(&src, find_bump(&src_txid));
            let stub_bytes = stub.to_binary().len() as u64;
            stubs.insert(src_txid, (stub, stub_bytes));
            stack.push(enter(src));
        }
        Ok(())
    }

    /// A bare copy of `tx`: the transaction with this BEEF's BUMP in place of
    /// its own path when the BEEF proves it (#757), and with every input's `source_transaction` dropped, so no ancestry
    /// is duplicated; building a stub never copies a subtree.
    pub(super) fn bare_stub(tx: &Transaction, bump: Option<&MerklePath>) -> Transaction {
        // `clone_for_beef` copies the transaction without its sources, each
        // unnamed source's txid written in its place, so the stub's bytes and
        // id are the transaction's (#843: until then the stub's inputs held
        // neither, and a copied cache stood in for what its fields wrote).
        let mut stub = tx.clone_for_beef();
        if let Some(mp) = bump {
            stub.merkle_path = Some(mp.clone());
        }
        stub
    }
}
