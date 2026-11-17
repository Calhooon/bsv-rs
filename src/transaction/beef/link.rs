//! Linking a BEEF's input ancestry, and the #749 bound on how many bytes it
//! may re-materialize for a shared parent.
//!
//! `add_input_proof` links each distinct parent once and hands every later
//! input that spends the same parent a clone of its stub — the parent without
//! its ancestry but with all of its outputs. A child whose M inputs each spend
//! one output of a single parent of N outputs therefore holds M copies of all N
//! outputs: the cost grows with the PRODUCT M×N, not the sum. An untrusted
//! answer within a resolver's byte bound could force multi-gigabyte heap before
//! any evidence check (an out-of-memory kill, a wasm32 abort). So linking meters
//! the BYTES the repeats re-materialize — the wire size of each stub clone,
//! which is also its heap weight — and refuses a BEEF past [`BeefLinkLimits`]
//! BEFORE the clone that would cross it. The full links (one per distinct
//! parent) are the BEEF's own bytes and are not counted; only the repeats, the
//! bytes materialized beyond the answer's own, are.
//!
//! The meter also charges the proof (`MerklePath`) cloned into every proven
//! transaction and every stub (bsv-rs #749 fold): a transaction's `to_binary`
//! leaves the attached path out, so a BEEF of K parents sharing one K-leaf BUMP
//! would otherwise hold ~2K deep copies of that O(K) path, uncounted — the DoS
//! sibling of the shared-parent output amplification. See [`bump_bytes`].

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::transaction::merkle_path::MerklePath;
use crate::transaction::Transaction;
use crate::Result;

use super::link_limits::BeefLinkLimits;
use super::Beef;

/// A link budget in one of three forms, for a caller that links a BEEF through
/// [`Transaction::from_beef_with_budget`](crate::transaction::Transaction::from_beef_with_budget)
/// or [`Beef::find_atomic_transaction_with_budget`] (bsv-rs #749 fold2,
/// ruling 2).
///
/// [`BeefLinkLimits`] bounds ONE link in isolation; a service that links k
/// untrusted answers AT THE SAME TIME (k concurrent calls) under that default
/// gets k independent budgets, so its peak heap grows with k and two
/// near-budget concurrent links can exceed a 128 MB Worker. A shared budget
/// caps the TOTAL bytes every link sharing the same handle may re-materialize
/// at once, against one pool, so the peak is bounded no matter how many links
/// run concurrently.
///
/// The three forms:
///
/// - [`per_link`](Self::per_link) — the default: each link gets its own
///   [`BeefLinkLimits::DEFAULT_MAX_LINK_BYTES`] budget, exactly as a plain
///   [`Transaction::from_beef`](crate::transaction::Transaction::from_beef).
/// - [`shared`](Self::shared) — a pool of a fixed size, drawn down by every
///   link given the SAME handle (clone it into each concurrent task), and
///   handed back when the [`LinkedTransaction`] it produced is dropped (its
///   re-materialized bytes are freed then). Each link is additionally capped at
///   the per-link default, so a single answer cannot be larger than one
///   isolated link. The first link whose reservation would overdraw the pool is
///   refused with [`Error::BeefResourceLimit`](crate::Error::BeefResourceLimit)
///   BEFORE it allocates; once an earlier link is dropped, the next is
///   admitted.
/// - [`unbounded`](Self::unbounded) — no bound, for a source the caller trusts.
///
/// Size a shared pool so its worst-case peak, `≈ 2 × pool + baseline`, fits the
/// host: on a 128 MB Worker (~30 MiB baseline) a 32 MiB pool peaks at ~94 MiB
/// regardless of concurrency, where k independent per-link budgets instead grow
/// with the number of concurrent links (measured k = 2/3/5 retained links at
/// 41/59/95 MiB on the test harness, versus 41/57/57 MiB flat under a 24 MiB
/// shared pool).
#[derive(Debug, Clone)]
pub struct BeefLinkBudget(BudgetRepr);

#[derive(Debug, Clone)]
enum BudgetRepr {
    /// Each link independent; `None` disables the bound (unbounded).
    PerLink(Option<u64>),
    /// A pool shared by every clone of the handle: `pool` is the bytes still
    /// available, `capacity` the size it was built with (for the error text).
    Shared { pool: Arc<AtomicU64>, capacity: u64 },
}

impl Default for BeefLinkBudget {
    fn default() -> Self {
        Self::per_link()
    }
}

impl BeefLinkBudget {
    /// Each link gets its own [`BeefLinkLimits::DEFAULT_MAX_LINK_BYTES`] budget
    /// (16 MiB) — the same bound a plain
    /// [`Transaction::from_beef`](crate::transaction::Transaction::from_beef)
    /// applies, and the form a caller gets by passing nothing.
    #[must_use]
    pub fn per_link() -> Self {
        Self(BudgetRepr::PerLink(Some(
            BeefLinkLimits::DEFAULT_MAX_LINK_BYTES,
        )))
    }

    /// Each link gets its own budget of `max_link_bytes` (`None` disables the
    /// bound for every link).
    #[must_use]
    pub fn per_link_bytes(max_link_bytes: Option<u64>) -> Self {
        Self(BudgetRepr::PerLink(max_link_bytes))
    }

    /// A pool of `total_bytes` shared by every link given THIS handle or a
    /// clone of it. The sum of the bytes all the links sharing the pool
    /// re-materialize at once cannot exceed `total_bytes`; the link that would
    /// overdraw it is refused before it allocates, and a link's share is
    /// returned to the pool when its [`LinkedTransaction`] is dropped.
    ///
    /// Clone this value (or the whole handle) into each concurrent task: a
    /// clone shares the same pool. Each individual link is also capped at
    /// [`BeefLinkLimits::DEFAULT_MAX_LINK_BYTES`], so one answer can be at most
    /// one isolated link's worth however large the pool.
    #[must_use]
    pub fn shared(total_bytes: u64) -> Self {
        Self(BudgetRepr::Shared {
            pool: Arc::new(AtomicU64::new(total_bytes)),
            capacity: total_bytes,
        })
    }

    /// No bound: link whatever the bytes hold. Only for a BEEF whose source the
    /// caller trusts.
    #[must_use]
    pub fn unbounded() -> Self {
        Self(BudgetRepr::PerLink(None))
    }

    /// The bytes still available in a shared pool, or `None` for a per-link or
    /// unbounded budget. For tests and observability; a concurrent link may
    /// change it at any moment.
    #[must_use]
    pub fn remaining(&self) -> Option<u64> {
        match &self.0 {
            BudgetRepr::Shared { pool, .. } => Some(pool.load(Ordering::Acquire)),
            BudgetRepr::PerLink(_) => None,
        }
    }
}

/// A caller's claim on a shared [`BeefLinkBudget`] pool: the bytes one link
/// reserved, returned to the pool when this is dropped. Reserving is atomic, so
/// concurrent links on clones of the handle cannot together overdraw the pool;
/// dropping always returns exactly what was reserved, once, so a pool can
/// neither leak nor double-count across any sequence of links and releases.
#[derive(Debug)]
struct SharedReservation {
    pool: Arc<AtomicU64>,
    capacity: u64,
    reserved: u64,
}

impl SharedReservation {
    /// Atomically take `bytes` from the pool, or refuse before any allocation
    /// if the pool cannot cover it.
    fn charge(&mut self, bytes: u64) -> Result<()> {
        let mut available = self.pool.load(Ordering::Acquire);
        loop {
            let Some(remaining) = available.checked_sub(bytes) else {
                return Err(crate::Error::BeefResourceLimit(format!(
                    "linking would hold more than the shared link budget's remaining heap bytes \
                     ({available} of {capacity}) in re-materialized shared-parent stubs and proofs \
                     (bsv-rs #749). Drop a linked transaction to return its share, raise the pool, \
                     or link the source you trust unbounded.",
                    capacity = self.capacity
                )));
            };
            match self.pool.compare_exchange_weak(
                available,
                remaining,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.reserved = self.reserved.saturating_add(bytes);
                    return Ok(());
                }
                Err(actual) => available = actual,
            }
        }
    }
}

impl Drop for SharedReservation {
    fn drop(&mut self) {
        // Return exactly the bytes this link reserved. Runs on both the error
        // path (a refused link returns the partial reservation it had taken)
        // and the success path (when the LinkedTransaction is dropped, freeing
        // the re-materialized bytes this reservation accounted for).
        self.pool.fetch_add(self.reserved, Ordering::Release);
    }
}

/// How one `add_input_proof` walk meters the bytes its repeat inputs
/// re-materialize: against a per-link budget, or against a shared pool (plus
/// the per-link cap).
enum LinkMeter<'r> {
    /// A budget local to this one link; `None` on a dimension is unbounded.
    /// `wire` is the published `max_link_bytes` (the stub wire bytes each repeat
    /// re-materializes); `heap` is `max_link_heap_bytes` (the heap each clone
    /// holds — the struct backings and proof leaves the wire count does not see).
    PerLink {
        wire_budget: Option<u64>,
        heap_budget: Option<u64>,
        wire_used: u64,
        heap_used: u64,
    },
    /// A shared pool bounding the TOTAL heap of every concurrent link, with
    /// per-link wire and heap caps on this one link besides.
    Shared {
        per_link_wire: Option<u64>,
        per_link_heap: Option<u64>,
        wire_used: u64,
        heap_used: u64,
        reservation: &'r mut SharedReservation,
    },
}

impl LinkMeter<'_> {
    fn per_link(wire_budget: Option<u64>, heap_budget: Option<u64>) -> Self {
        LinkMeter::PerLink {
            wire_budget,
            heap_budget,
            wire_used: 0,
            heap_used: 0,
        }
    }

    /// Charge one clone's `wire` bytes (the stub's `to_binary` length) and `heap`
    /// bytes (the heap the clone holds) to this meter, refusing BEFORE the clone
    /// that would allocate past either bound (or overdraw the shared heap pool).
    /// The two dimensions accumulate independently; a link is refused the moment
    /// EITHER crosses its bound. The wire dimension keeps the published
    /// `max_link_bytes` meaning (so no honest onset moves); the heap dimension
    /// bounds the memory held, the shape the wire count alone did not catch
    /// (bsv-rs #749 fold-c).
    fn charge(&mut self, wire: u64, heap: u64) -> Result<()> {
        match self {
            LinkMeter::PerLink {
                wire_budget,
                heap_budget,
                wire_used,
                heap_used,
            } => {
                *wire_used = wire_used.saturating_add(wire);
                if let Some(b) = wire_budget {
                    if *wire_used > *b {
                        return Err(wire_limit_error(*b));
                    }
                }
                *heap_used = heap_used.saturating_add(heap);
                if let Some(b) = heap_budget {
                    if *heap_used > *b {
                        return Err(heap_limit_error(*b));
                    }
                }
                Ok(())
            }
            LinkMeter::Shared {
                per_link_wire,
                per_link_heap,
                wire_used,
                heap_used,
                reservation,
            } => {
                *wire_used = wire_used.saturating_add(wire);
                if let Some(cap) = per_link_wire {
                    if *wire_used > *cap {
                        return Err(wire_limit_error(*cap));
                    }
                }
                *heap_used = heap_used.saturating_add(heap);
                if let Some(cap) = per_link_heap {
                    if *heap_used > *cap {
                        return Err(heap_limit_error(*cap));
                    }
                }
                // The pool bounds the TOTAL heap of every link sharing it, so a
                // service linking many untrusted answers at once caps its peak
                // heap against one handle, not each link alone.
                reservation.charge(heap)
            }
        }
    }
}

fn wire_limit_error(budget: u64) -> crate::Error {
    crate::Error::BeefResourceLimit(format!(
        "linking would re-materialize more than {budget} wire bytes for a shared parent spent by \
         many inputs (bsv-rs #749). Raise or disable the bound with \
         Transaction::from_beef_with_limits / BeefLinkLimits::with_max_link_bytes / \
         BeefLinkLimits::unbounded."
    ))
}

fn heap_limit_error(budget: u64) -> crate::Error {
    crate::Error::BeefResourceLimit(format!(
        "linking would hold more than {budget} heap bytes of re-materialized shared-parent stubs \
         and proofs at once (bsv-rs #749). Raise or disable the bound with \
         Transaction::from_beef_with_limits / BeefLinkLimits::with_max_link_heap_bytes / \
         BeefLinkLimits::unbounded."
    ))
}

/// The HEAP a cloned `MerklePath` holds: the leaf structs its level `Vec`s carry
/// plus the hash each leaf owns.
///
/// Linking clones the proof (`MerklePath`) into every proven transaction it
/// links and into every stub a repeat input spends, but [`Transaction`]'s
/// `to_binary` serializes only its four fields, never the attached path, so the
/// stub byte-meter did not weigh the BUMP: a BEEF of K parents sharing one
/// K-leaf BUMP holds ~2K copies of that O(K) path, uncounted, the DoS sibling
/// of the shared-parent output amplification (bsv-rs #749 fold). A
/// `MerklePathLeaf` holds far more heap than the ~34 wire bytes it serializes to
/// — its struct, and a hash kept as a 64-character hex `String` whose buffer
/// `size_of` does not see — so the charge is the struct size plus that buffer
/// per leaf, an upper bound (a duplicate leaf owns no hash) that brings the
/// proof's clone within the budget the heap it costs on native and wasm32 alike
/// (bsv-rs #749 fold-c). Charging this at each BUMP clone brings the proof under
/// the [`max_link_heap_bytes`](BeefLinkLimits::max_link_heap_bytes) bound.
fn bump_heap(mp: &MerklePath) -> u64 {
    // The hex hash a hash-bearing leaf owns on the heap, beyond its struct: 32
    // bytes rendered as 64 hex characters.
    const LEAF_HASH_HEAP: u64 = 64;
    let per_leaf = core::mem::size_of::<crate::transaction::merkle_path::MerklePathLeaf>() as u64
        + LEAF_HASH_HEAP;
    let leaves: u64 = mp.path.iter().map(|level| level.len() as u64).sum();
    leaves.saturating_mul(per_leaf)
}

/// The HEAP a cloned stub re-materializes beyond its wire bytes: the `Vec`
/// backings of its inputs and outputs, and the box each repeat input holds it
/// in. A transaction's `to_binary` is a flat byte count — a one-byte-locked
/// output is ~10 wire bytes but holds ~150 heap bytes once cloned (its struct in
/// the output `Vec`, its script's own container) — so the stub byte-meter
/// under-weighed each repeat clone, letting a 16 MiB budget admit hundreds of MB
/// of heap, past the 128 MB Worker isolate. Adding the struct backings brings
/// the charge within a small factor of the heap the clone holds, so the budget
/// bounds the heap the default link re-materializes, on native and on wasm32
/// alike (bsv-rs #749 fold-c — the declined-late / accepted sibling of the
/// shared-proof fold).
fn stub_struct_heap(tx: &Transaction) -> u64 {
    use core::mem::size_of;
    (size_of::<Transaction>() as u64)
        .saturating_add(
            (tx.inputs.len() as u64)
                .saturating_mul(size_of::<crate::transaction::TransactionInput>() as u64),
        )
        .saturating_add(
            (tx.outputs.len() as u64)
                .saturating_mul(size_of::<crate::transaction::TransactionOutput>() as u64),
        )
}

// The struct backings a clone re-materializes are target-sized: wasm32's
// pointers and `usize` are 4 bytes where native's are 8, so every `size_of`
// above only SHRINKS on wasm32 — the native-sized charge over-weighs the wasm32
// clone, and the same budget bounds the (smaller) wasm32 heap too. These
// assertions are recompiled on every target the crate builds (the CI wasm32
// slice among them), so a struct that grew past these native-side bounds —
// which would make the heap accounting above stale — fails the build rather than
// silently loosening the bound.
const _: () = assert!(core::mem::size_of::<Transaction>() <= 1024);
const _: () = assert!(core::mem::size_of::<crate::transaction::TransactionInput>() <= 512);
const _: () = assert!(core::mem::size_of::<crate::transaction::TransactionOutput>() <= 512);
const _: () =
    assert!(core::mem::size_of::<crate::transaction::merkle_path::MerklePathLeaf>() <= 256);

/// A transaction linked under a [`BeefLinkBudget`], holding its claim on the
/// budget's shared pool (when it has one) until it is dropped.
///
/// It derefs to the [`Transaction`], so a caller reads it as one. When the
/// budget was [`BeefLinkBudget::shared`], the re-materialized bytes this link
/// accounts for are returned to the pool the moment this value is dropped — so
/// keep it alive for as long as the linked ancestry is in use, and the pool
/// then bounds the total heap of every concurrent link, not each one alone.
///
/// [`into_transaction`](Self::into_transaction) hands back the bare
/// [`Transaction`] and releases the pool claim early; the linked bytes are
/// still alive, so the pool then undercounts until the transaction is dropped —
/// use it only when the budget is no longer shared with other in-flight links.
#[derive(Debug)]
pub struct LinkedTransaction {
    tx: Transaction,
    _reservation: Option<SharedReservation>,
}

impl LinkedTransaction {
    /// The linked transaction.
    #[must_use]
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// Takes the linked [`Transaction`], releasing any shared-pool claim early
    /// (see the type's note).
    #[must_use]
    pub fn into_transaction(self) -> Transaction {
        self.tx
    }
}

impl Deref for LinkedTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Transaction {
        &self.tx
    }
}

impl Beef {
    /// Builds the proof tree rooted at a specific transaction, under the
    /// [default](BeefLinkLimits::default) link bound: a BEEF whose linking
    /// would re-materialize a shared parent past the byte budget (bsv-rs #749)
    /// yields `None`, as a BEEF whose `txid` is absent does. Use
    /// [`find_atomic_transaction_limited`](Self::find_atomic_transaction_limited),
    /// which returns `Err(`[`BeefResourceLimit`](crate::Error::BeefResourceLimit)`)`
    /// on a refusal, to tell the two apart or to raise the bound.
    // No `#[must_use]`: a public attribute added to this pre-existing method is a
    // semver MINOR (`inherent_method_must_use_added`), which the stable line
    // cannot carry as a patch (bsv-rs #749 fold, ruling 1); the local allow
    // silences the pedantic lint without touching the public API.
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
        let mut meter = LinkMeter::per_link(limits.max_link_bytes, limits.max_link_heap_bytes);
        self.add_input_proof(&mut tx, &mut meter)?;
        Ok(Some(tx))
    }

    /// As [`find_atomic_transaction_limited`](Self::find_atomic_transaction_limited),
    /// but under a [`BeefLinkBudget`], which can be a budget SHARED across every
    /// link given the same handle (bsv-rs #749 fold2, ruling 2). Returns
    /// `Ok(None)` when `txid` is absent, `Err(`[`BeefResourceLimit`](crate::Error::BeefResourceLimit)`)`
    /// when linking would overdraw the budget, and otherwise a
    /// [`LinkedTransaction`] that holds its share of a shared pool until it is
    /// dropped.
    ///
    /// # Errors
    ///
    /// Returns [`BeefResourceLimit`](crate::Error::BeefResourceLimit) when
    /// linking `txid`'s ancestry would re-materialize more bytes than `budget`
    /// (per link, or across the shared pool) allows (bsv-rs #749).
    pub fn find_atomic_transaction_with_budget(
        &self,
        txid: &str,
        budget: &BeefLinkBudget,
    ) -> Result<Option<LinkedTransaction>> {
        let Some(beef_tx) = self.find_txid(txid) else {
            return Ok(None);
        };
        let Some(mut tx) = beef_tx.tx().cloned() else {
            return Ok(None);
        };
        match &budget.0 {
            BudgetRepr::PerLink(max) => {
                // A per-link budget caps the wire dimension at the caller's
                // number (`None` unbounded); the heap dimension takes the default
                // heap bound when the budget is bounded, and is lifted with it.
                let heap = max.map(|_| BeefLinkLimits::DEFAULT_MAX_LINK_HEAP_BYTES);
                let mut meter = LinkMeter::per_link(*max, heap);
                self.add_input_proof(&mut tx, &mut meter)?;
                Ok(Some(LinkedTransaction {
                    tx,
                    _reservation: None,
                }))
            }
            BudgetRepr::Shared { pool, capacity } => {
                let mut reservation = SharedReservation {
                    pool: Arc::clone(pool),
                    capacity: *capacity,
                    reserved: 0,
                };
                // Meter in a block so the `&mut reservation` borrow ends before
                // the reservation moves into the result. On the `?` error path
                // the reservation drops here, returning the heap it had taken.
                {
                    let mut meter = LinkMeter::Shared {
                        per_link_wire: Some(BeefLinkLimits::DEFAULT_MAX_LINK_BYTES),
                        per_link_heap: Some(BeefLinkLimits::DEFAULT_MAX_LINK_HEAP_BYTES),
                        wire_used: 0,
                        heap_used: 0,
                        reservation: &mut reservation,
                    };
                    self.add_input_proof(&mut tx, &mut meter)?;
                }
                Ok(Some(LinkedTransaction {
                    tx,
                    _reservation: Some(reservation),
                }))
            }
        }
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
    /// The bytes the repeat inputs re-materialize are metered against `meter`
    /// (the #749 bound; an unbounded budget lifts it), and a BEEF that would
    /// cross the budget — per link, or across a shared pool — is refused with
    /// [`Error::BeefResourceLimit`](crate::Error::BeefResourceLimit) BEFORE the
    /// clone that would allocate past it.
    fn add_input_proof(&self, tx: &mut Transaction, meter: &mut LinkMeter) -> Result<()> {
        /// One transaction being linked, and the next input to link.
        struct Frame {
            tx: Transaction,
            next_input: usize,
        }

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
        let enter = |mut tx: Transaction, meter: &mut LinkMeter| -> Result<Frame> {
            if tx.merkle_path.is_none() {
                if let Some(mp) = find_bump(&tx.id()) {
                    // The BUMP is cloned into this proven transaction, one deep
                    // copy per distinct proven txid. One copy is in the BEEF's
                    // own bytes, so it does not count toward the wire bound (the
                    // first full link is free); but a BEEF of K parents sharing
                    // one K-leaf BUMP holds K heap copies of that O(K) path, the
                    // shared-proof amplification, which the heap bound must see
                    // (bsv-rs #749 fold / fold-c).
                    meter.charge(0, bump_heap(mp))?;
                    tx.merkle_path = Some(mp.clone());
                }
            }
            let next_input = if tx.merkle_path.is_some() {
                tx.inputs.len()
            } else {
                0
            };
            Ok(Frame { tx, next_input })
        };

        // Keyed by txid, the value being the stub handed to later inputs and its
        // (wire, heap) weight (computed once, the cost each repeat clone adds):
        // the wire bytes the published `max_link_bytes` meters, and the heap the
        // clone holds that `max_link_heap_bytes` meters. Presence also means
        // "this txid has been linked in full once".
        let mut stubs: HashMap<String, (Transaction, u64, u64)> = HashMap::new();
        let mut stack: Vec<Frame> = vec![enter(std::mem::take(tx), meter)?];

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
            if let Some((stub, stub_wire, stub_heap)) = stubs.get(&src_txid) {
                // Already linked in full once: this input gets the stub, which
                // carries the output being spent (and the proof when there is
                // one) without repeating the ancestry underneath it. Meter the
                // stub's wire weight (the published bound) and the heap it holds,
                // and refuse BEFORE the clone that would allocate past either
                // bound (per link, or across a shared heap pool).
                meter.charge(*stub_wire, *stub_heap)?;
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
            // is never reachable from inside its own ancestry). Its wire size,
            // computed once here, is the byte weight each later repeat adds.
            let bump = find_bump(&src_txid);
            // The stub carries a proof — the source's own path when it has one,
            // else this BEEF's BUMP (as `bare_stub` attaches it) — which
            // `to_binary` leaves out. One deep copy goes into the map-held stub
            // here and one into every repeat input that spends it; the first copy
            // is the BEEF's own bytes, so it is heap-only (wire 0). Charge its
            // heap once for the map-held copy (refuse BEFORE the clone) and fold
            // it into `stub_heap`, so each later repeat is charged the proof too
            // (bsv-rs #749 fold / fold-c).
            let path_weight = src
                .merkle_path
                .as_ref()
                .map(bump_heap)
                .or_else(|| bump.map(bump_heap))
                .unwrap_or(0);
            meter.charge(0, path_weight)?;
            let stub = Self::bare_stub(&mut src, bump);
            // Each repeat input re-materializes this stub in full. Its WIRE weight
            // (the published `max_link_bytes`) is its `to_binary` length, exactly
            // as 0.8.11 metered — so no honest onset moves. Its HEAP weight (the
            // new `max_link_heap_bytes`) is that wire plus the proof it carries
            // plus the struct backings of its inputs and outputs the wire count
            // does not see — a one-byte-locked output is ~10 wire bytes but holds
            // ~150 heap bytes (bsv-rs #749 fold-c).
            let stub_wire = stub.to_binary().len() as u64;
            let stub_heap = stub_wire
                .saturating_add(path_weight)
                .saturating_add(stub_struct_heap(&stub));
            stubs.insert(src_txid, (stub, stub_wire, stub_heap));
            stack.push(enter(src, meter)?);
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

impl Transaction {
    /// As [`from_beef`](Transaction::from_beef), but under a [`BeefLinkBudget`]
    /// — which can be a budget SHARED across every link given the same handle,
    /// so a service linking several untrusted answers at once caps its TOTAL
    /// re-materialized heap against one pool instead of paying an independent
    /// budget per link (bsv-rs #749 fold2, ruling 2). Returns a
    /// [`LinkedTransaction`] (derefs to the [`Transaction`]); when the budget is
    /// [`BeefLinkBudget::shared`] keep it alive while the linked ancestry is in
    /// use, as its share of the pool is returned when it is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`BeefResourceLimit`](crate::Error::BeefResourceLimit) when
    /// linking would overdraw the budget, or a parse/lookup error as
    /// [`from_beef`](Transaction::from_beef) does.
    pub fn from_beef_with_budget(
        beef: &[u8],
        txid: Option<&str>,
        budget: &BeefLinkBudget,
    ) -> Result<LinkedTransaction> {
        let parsed = Beef::from_binary(beef)?;
        let target = match txid {
            Some(id) => id.to_string(),
            None => match parsed.atomic_txid.clone() {
                Some(atomic) => atomic,
                None => parsed
                    .txs
                    .last()
                    .map(crate::transaction::beef_tx::BeefTx::txid)
                    .ok_or_else(|| {
                        crate::Error::TransactionError("No transactions in BEEF".to_string())
                    })?,
            },
        };
        parsed
            .find_atomic_transaction_with_budget(&target, budget)?
            .ok_or_else(|| {
                crate::Error::TransactionError(format!("Transaction {target} not found in BEEF"))
            })
    }
}
