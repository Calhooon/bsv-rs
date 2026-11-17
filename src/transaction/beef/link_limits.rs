//! The public link-ancestry bounds — [`BeefLinkLimits`], the per-link WIRE and
//! HEAP budgets a [`Transaction::from_beef`](crate::transaction::Transaction::from_beef)
//! applies against the #749 shared-parent re-materialization (bsv-rs #749): a
//! child module of `beef` beside [`link`](super::link), so the bounds live
//! apart from the linker that applies them.

/// Bounds on how many bytes linking a BEEF's input ancestry may re-materialize
/// for a shared parent, applied by [`Beef::find_atomic_transaction`](crate::transaction::Beef::find_atomic_transaction) and
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
/// concurrent links against one pool, use [`BeefLinkBudget::shared`](crate::transaction::BeefLinkBudget::shared) with
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
    /// The maximum number of WIRE bytes linking may re-materialize for repeat
    /// inputs that spend an already-linked shared parent, beyond the BEEF's own
    /// bytes, before it is refused — a stub's [`to_binary`](crate::transaction::Transaction::to_binary)
    /// length per repeat clone, exactly as 0.8.11 metered it. `None` disables the
    /// bound (link whatever the bytes hold — for a source the caller trusts).
    ///
    /// This is the published number: a caller that set it to cap an honest
    /// answer's reach by wire size keeps that exact meaning, and the per-output
    /// onsets the 0.8.11 record states (702 / 251 / 127 plain / 256 B / 1 KiB
    /// outputs at the default, 993 / 354 / 180 at 32 MiB) are unchanged. Memory
    /// held is bounded separately by [`max_link_heap_bytes`](Self::max_link_heap_bytes),
    /// so this number need not — and does not — change what it counts.
    pub max_link_bytes: Option<u64>,

    /// The maximum number of HEAP bytes linking may hold in re-materialized
    /// shared-parent stubs and proofs at once, before one link is refused
    /// (bsv-rs #749 fold-c). A cloned stub holds far more heap than its wire
    /// length — the `Vec` backings of its inputs and outputs, and a proof's leaf
    /// structs — so a wide fan-in of one-byte-locked outputs, or many proven
    /// parents sharing one wide proof, can hold hundreds of MB while
    /// [`max_link_bytes`](Self::max_link_bytes) sees only a small wire count.
    /// This bound weighs that heap and refuses BEFORE the clone that would
    /// allocate past it, so the default link holds its memory inside a 128 MB
    /// isolate. `None` disables it (for a source the caller trusts).
    ///
    /// It sits ABOVE every honest single-parent sweep the wire bound already
    /// admits (those are bounded by `max_link_bytes` first, so this never lowers
    /// an onset the published record states) and BELOW the memory-exhaustion
    /// shapes the wire count alone did not catch. A caller that set a larger
    /// explicit `max_link_bytes` and wants its full wire reach raises this in
    /// step.
    pub max_link_heap_bytes: Option<u64>,
}

impl Default for BeefLinkLimits {
    fn default() -> Self {
        Self {
            max_link_bytes: Some(Self::DEFAULT_MAX_LINK_BYTES),
            max_link_heap_bytes: Some(Self::DEFAULT_MAX_LINK_HEAP_BYTES),
        }
    }
}

impl BeefLinkLimits {
    /// The default per-link WIRE budget (bsv-rs #749 fold2, ruling 3): linking
    /// may re-materialize up to this many WIRE bytes of repeated shared-parent
    /// stubs beyond the BEEF's own bytes before one link is refused.
    ///
    /// 16 MiB — the stub's [`to_binary`](crate::transaction::Transaction::to_binary) length per
    /// repeat clone, exactly what 0.8.11 metered. A byte budget (not a count of
    /// output slots) charges a parent of a few large outputs its true weight. The
    /// full links (one per distinct parent) are the BEEF's own bytes and are not
    /// counted; only the repeats are. It sits far below the #749 denial of
    /// service and far above every honest BEEF: the largest shared-parent fan any
    /// real dependent's BEEF carries is 20, and the default admits an honest
    /// single child sweeping many outputs of one parent — up to 702
    /// plain-payment (P2PKH) outputs, 251 data-carrying outputs of 256 B, or 127
    /// of 1 KiB, before one such sweep is refused (at 32 MiB: 993 / 354 / 180;
    /// measured by the crate's own writer). There is no single "general" figure:
    /// the onset falls as the output grows, so the reach is stated per output
    /// size. The memory a declined link holds is bounded separately by
    /// [`DEFAULT_MAX_LINK_HEAP_BYTES`](Self::DEFAULT_MAX_LINK_HEAP_BYTES), so this
    /// wire figure keeps the meaning the published record states and no honest
    /// onset moves. The per-output-size headroom pin in `tests/beef_link_bound.rs`
    /// turns red if this value moves.
    pub const DEFAULT_MAX_LINK_BYTES: u64 = 16 * 1024 * 1024;

    /// The default per-link HEAP budget (bsv-rs #749 fold-c): linking may hold up
    /// to this many HEAP bytes in re-materialized shared-parent stubs and proofs
    /// at once before one link is refused.
    ///
    /// 56 MiB — of the HEAP each clone holds, not its wire bytes. A transaction's
    /// `to_binary` is a flat byte count, but a cloned stub holds far more: the
    /// `Vec` backings of its inputs and outputs (a one-byte-locked output is ~10
    /// wire bytes yet ~150 heap bytes), and a proof's leaf structs (a BUMP leaf
    /// is far larger in heap than the ~34 wire bytes it serializes to). Metering
    /// that heap, under its own bound, catches the two shapes the wire count
    /// alone did not: a wide fan-in of tiny-locked outputs (which held hundreds
    /// of MB under a small wire count), and many proven parents sharing one wide
    /// proof.
    ///
    /// For the lowest-heap-density output a single parent carries — a
    /// plain-payment (P2PKH) output, the most of them that fit a given WIRE
    /// budget — this HEAP bound is reached BEFORE the
    /// [`max_link_bytes`](Self::max_link_bytes) wire bound, so it, not the wire
    /// bound, sets the default onset of an honest single-parent P2PKH sweep:
    /// **586** outputs, where the 16 MiB wire bound alone admitted **702** (the
    /// figure the GHSA-gvmh-f5gf-5vjj / 0.8.11 record states for the default).
    /// The data-carrying onsets stay wire-bound and unchanged (251 outputs of
    /// 256 B, 127 of 1 KiB), because their heavier outputs hit the wire bound
    /// first. This is the one default onset that moves (bsv-rs #749 fold-c): it
    /// is stated, pinned by `the_default_headroom_is_stated_per_output_size`, and
    /// the price of holding the memory a wide plain-payment sweep re-materializes
    /// inside a 128 MB isolate.
    ///
    /// The peak LIVE heap a single link holds under this bound, measured with
    /// `dhat::Alloc` on a native host: ~65 MiB accepting the 586-output P2PKH
    /// sweep at the onset, ~58 MiB declining a 4,000-output one-byte fan-in spent
    /// 420 ways (where the wire-only meter held ~248 MB), ~95 MiB declining a
    /// 16,384-parent shared-BUMP answer (the worst shape, refused by this bound).
    /// The `size_of` charge below is native-sized — an upper bound, since
    /// wasm32's pointers and `usize` are half the width — so the real wasm32 peak
    /// is lower, and with a ~30 MiB Worker baseline the default link stays inside
    /// a 128 MB isolate. The largest shared-parent fan any real dependent's BEEF
    /// carries is 20, far under any onset, so the default refuses no honest input
    /// any dependent builds. A caller that set a larger explicit `max_link_bytes`
    /// (e.g. 32 MiB, wire onset 993 P2PKH) and wants its full reach raises this
    /// in step. The heap headroom pin in `tests/beef_link_heap_749c.rs` turns red
    /// if this value moves.
    pub const DEFAULT_MAX_LINK_HEAP_BYTES: u64 = 56 * 1024 * 1024;

    /// No bound: link whatever the bytes hold. Only for a BEEF whose source the
    /// caller trusts — an untrusted answer linked unbounded is the #749 denial
    /// of service.
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            max_link_bytes: None,
            max_link_heap_bytes: None,
        }
    }

    /// Sets [`max_link_bytes`](Self::max_link_bytes) (`None` disables the wire
    /// bound). The heap bound is unchanged.
    #[must_use]
    pub fn with_max_link_bytes(mut self, max_link_bytes: Option<u64>) -> Self {
        self.max_link_bytes = max_link_bytes;
        self
    }

    /// Sets [`max_link_heap_bytes`](Self::max_link_heap_bytes) (`None` disables
    /// the heap bound). The wire bound is unchanged. Raise this in step with a
    /// larger explicit [`max_link_bytes`](Self::max_link_bytes) to keep the full
    /// wire reach that figure admits (bsv-rs #749 fold-c).
    #[must_use]
    pub fn with_max_link_heap_bytes(mut self, max_link_heap_bytes: Option<u64>) -> Self {
        self.max_link_heap_bytes = max_link_heap_bytes;
        self
    }
}
