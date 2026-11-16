//! Linking a BEEF's input ancestry, and the #749 bound on how far it may
//! re-materialize a shared parent (bsv-rs #749): a child module of `beef`, so
//! the linker and its bound live outside `beef.rs`.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::transaction::merkle_path::MerklePath;
use crate::transaction::Transaction;
use crate::Result;

use super::Beef;

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
/// [default](BeefLinkLimits::DEFAULT_MAX_LINK_BYTES) 16 MiB, so the default
/// refuses none of them. A caller that must link a large ancestry it TRUSTS
/// opts out with [`BeefLinkLimits::unbounded`].
///
/// These limits bound ONE link in isolation. A caller that links several
/// untrusted answers AT THE SAME TIME (k concurrent `from_beef` calls) gets k
/// independent budgets, so its peak heap grows with k; to cap the TOTAL across
/// concurrent links against one pool, use [`BeefLinkBudget::shared`] with
/// [`Transaction::from_beef_with_budget`](crate::transaction::Transaction::from_beef_with_budget).
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
            max_link_bytes: Some(Self::DEFAULT_MAX_LINK_BYTES),
        }
    }
}

impl BeefLinkLimits {
    /// The default per-link byte budget (bsv-rs #749 fold2, ruling 3): linking
    /// may re-materialize up to this many bytes of repeated shared-parent stubs
    /// beyond the BEEF's own bytes before one link is refused.
    ///
    /// 16 MiB. The heap a declined link peaks at follows `≈ 2 × budget +
    /// baseline` (the re-materialized bytes plus one in-flight stub clone, over
    /// the host's resident baseline): ~37 MiB measured on the test harness,
    /// ~62 MiB on a 128 MB Worker (~30 MiB baseline) — well within the Worker
    /// with room to spare. It sits far below the #749 denial of service (a
    /// 128 KiB answer re-materializing ~1.69 GB) and far above every honest
    /// BEEF: the largest shared-parent fan any real dependent's BEEF carries is
    /// 20, and the default admits an honest single child sweeping many outputs
    /// of one parent — up to 702 plain-payment (P2PKH) outputs, 251
    /// data-carrying outputs of 256 B, or 127 of 1 KiB, before one such sweep is
    /// refused (at 32 MiB: 993 / 354 / 180). There is no single "general"
    /// figure: the onset falls as the output grows, so the reach is stated per
    /// output size. The default refuses no honest input while leaving generous
    /// single-link headroom above anything a wallet or the overlay engine
    /// builds. Raising it erases that headroom; the headroom pin in
    /// `tests/beef_link_bound.rs`, which fixes those per-output-size cells, turns
    /// red if this value moves.
    pub const DEFAULT_MAX_LINK_BYTES: u64 = 16 * 1024 * 1024;

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
                    "linking would re-materialize more than the shared link budget's remaining \
                     bytes ({available} of {capacity}) for a shared parent spent by many inputs \
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
    /// A budget local to this one link; `None` is unbounded.
    PerLink { budget: Option<u64>, used: u64 },
    /// A shared pool, with a per-link cap on this one link besides.
    Shared {
        per_link: Option<u64>,
        used: u64,
        reservation: &'r mut SharedReservation,
    },
}

impl LinkMeter<'_> {
    fn per_link(budget: Option<u64>) -> Self {
        LinkMeter::PerLink { budget, used: 0 }
    }

    /// Charge `stub_bytes` to this meter, refusing BEFORE the clone that would
    /// allocate past the budget (or overdraw the shared pool).
    fn charge(&mut self, stub_bytes: u64) -> Result<()> {
        match self {
            LinkMeter::PerLink { budget: None, .. } => Ok(()),
            LinkMeter::PerLink {
                budget: Some(budget),
                used,
            } => {
                *used = used.saturating_add(stub_bytes);
                if *used > *budget {
                    return Err(per_link_limit_error(*budget));
                }
                Ok(())
            }
            LinkMeter::Shared {
                per_link,
                used,
                reservation,
            } => {
                *used = used.saturating_add(stub_bytes);
                if let Some(cap) = per_link {
                    if *used > *cap {
                        return Err(per_link_limit_error(*cap));
                    }
                }
                reservation.charge(stub_bytes)
            }
        }
    }
}

fn per_link_limit_error(budget: u64) -> crate::Error {
    crate::Error::BeefResourceLimit(format!(
        "linking would re-materialize more than {budget} bytes for a shared parent spent by many \
         inputs (bsv-rs #749). Raise or disable the bound with \
         Transaction::from_beef_with_limits / BeefLinkLimits::unbounded."
    ))
}

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
        let mut meter = LinkMeter::per_link(limits.max_link_bytes);
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
                let mut meter = LinkMeter::per_link(*max);
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
                // the reservation drops here, returning the bytes it had taken.
                {
                    let mut meter = LinkMeter::Shared {
                        per_link: Some(BeefLinkLimits::DEFAULT_MAX_LINK_BYTES),
                        used: 0,
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
                // allocate past the budget (per link, or across a shared pool).
                meter.charge(*stub_bytes)?;
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
