//! The doors to a [`Transaction`]'s four serialized fields (#843).
//!
//! The four fields and the three caches derived from them live in
//! [`Fields`], declared in the inline module `sealed` below, its fields
//! private to that module (#869's sixth fold): no other code can name one,
//! so every write of a serialized field goes through `Fields::write`, which
//! empties the caches before it lends `&mut`, or does not compile (E0616,
//! E0451). A cache is filled only through `&self`, and no `&self` read can
//! run while `write`'s borrow lives: the IDENTITY law
//! (`docs/design/843-identity-and-framing.md`, section 2), held by the
//! compiler. `tests/arch_field_writes_843.rs` pins `sealed`'s text and
//! where a cache is filled; a wrong value put into a cache through `&self`
//! is what the identity property and the fuzz invariant catch.

use std::collections::HashMap;

use serde_json::Value;

use super::{sha256d, to_hex, Transaction, Writer, TRAILING_DATA};
use crate::transaction::{MerklePath, TransactionInput, TransactionOutput};
use crate::Result;

pub(super) use sealed::Fields;

/// The four serialized fields and the three caches derived from them (#869's
/// sixth fold). Every field is private to this module, so the one way to a
/// `&mut` of a serialized field is [`Fields::write`], which empties the
/// caches first; a `Fields` is built only by [`Fields::new`] (no cache) or by
/// a copy here whose caches are its own fields'. No macro, no derive and
/// no attribute but doc comments inside, so nothing expands into it.
mod sealed {
    use std::sync::OnceLock;

    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};

    /// The four fields and their caches; the name visible to the owner
    /// `Transaction`'s module, every field private to `sealed`.
    pub(in crate::transaction::transaction) struct Fields {
        version: u32,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: u32,
        cached_hash: OnceLock<[u8; 32]>,
        raw_bytes_cache: OnceLock<Vec<u8>>,
        hex_cache: OnceLock<String>,
    }

    /// Whether `text` is 64 ASCII hex digits, the texts the serializer writes
    /// an outpoint from (its bytes, never a linked source's): the outpoint
    /// rule's one test, which `super::outpoint_txid` reads too.
    pub(super) fn names_32_bytes(text: &str) -> bool {
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Whether the serializer writes `input`'s outpoint from its text.
    fn named(input: &TransactionInput) -> bool {
        input.source_txid.as_deref().is_some_and(names_32_bytes)
    }

    impl Fields {
        /// The four fields, no cache.
        pub(super) fn new(
            version: u32,
            inputs: Vec<TransactionInput>,
            outputs: Vec<TransactionOutput>,
            lock_time: u32,
        ) -> Self {
            Self {
                version,
                inputs,
                outputs,
                lock_time,
                cached_hash: OnceLock::new(),
                raw_bytes_cache: OnceLock::new(),
                hex_cache: OnceLock::new(),
            }
        }

        /// The four fields, shared.
        pub(super) fn read(&self) -> (u32, &[TransactionInput], &[TransactionOutput], u32) {
            (self.version, &self.inputs, &self.outputs, self.lock_time)
        }

        /// The three caches, shared: filled through `&self`, never emptied.
        pub(super) fn caches(
            &self,
        ) -> (&OnceLock<[u8; 32]>, &OnceLock<Vec<u8>>, &OnceLock<String>) {
            (&self.cached_hash, &self.raw_bytes_cache, &self.hex_cache)
        }

        /// The one exclusive door: empties every cache, then lends the four
        /// fields mutably.
        pub(super) fn write(
            &mut self,
        ) -> (
            &mut u32,
            &mut Vec<TransactionInput>,
            &mut Vec<TransactionOutput>,
            &mut u32,
        ) {
            self.cached_hash.take();
            self.raw_bytes_cache.take();
            self.hex_cache.take();
            (
                &mut self.version,
                &mut self.inputs,
                &mut self.outputs,
                &mut self.lock_time,
            )
        }

        /// The four fields, moved out; the caches dropped with the value.
        pub(super) fn into_four(self) -> (u32, Vec<TransactionInput>, Vec<TransactionOutput>, u32) {
            (self.version, self.inputs, self.outputs, self.lock_time)
        }

        /// Links `source` to input `index` and returns the source it held:
        /// the linking door, which lends nothing. The caches are kept exactly
        /// when the input's `source_txid` is 64 hex digits, the outpoint
        /// rule's `Named` arm, under which the serializer writes the text and
        /// never reads the source, and the text is not touched here, so no
        /// byte moves; else they are emptied through `write`. Panics when
        /// `index` is not an input's.
        pub(super) fn replace_source(
            &mut self,
            index: usize,
            source: Option<Box<Transaction>>,
        ) -> Option<Box<Transaction>> {
            if !named(&self.inputs[index]) {
                self.write();
            }
            std::mem::replace(&mut self.inputs[index].source_transaction, source)
        }

        /// A copy with each input's source the given one (`Clone`'s step).
        /// The caches are copied exactly when every input writes the same
        /// outpoint bytes, known without hashing: a `Named` input, an input
        /// linking nothing on both sides, or a source whose cached hash
        /// equals the original source's cached hash; else the copy has none.
        pub(super) fn copy_relinked(&self, sources: Vec<Option<Box<Transaction>>>) -> Self {
            let hash = |tx: &Transaction| tx.fields.cached_hash.get().copied();
            let keep = sources.len() == self.inputs.len()
                && self.inputs.iter().zip(&sources).all(|(input, new)| {
                    named(input)
                        || match (input.source_transaction.as_deref(), new.as_deref()) {
                            (None, None) => true,
                            (Some(old), Some(new)) => hash(old).is_some() && hash(old) == hash(new),
                            _ => false,
                        }
                });
            let mut sources = sources.into_iter();
            let inputs = self
                .inputs
                .iter()
                .map(|input| {
                    let mut copy = input.clone_without_source();
                    copy.source_transaction = sources.next().flatten();
                    copy
                })
                .collect();
            self.copy_with(inputs, keep)
        }

        /// A copy with no source, each input whose outpoint the serializer
        /// read through its source (not `Named`, a source linked) named by
        /// that source's id, which `Named` writes as that source's hash: the
        /// same bytes, so the caches are copied (the copy a BEEF stores).
        pub(super) fn copy_named(&self) -> Self {
            let inputs = self
                .inputs
                .iter()
                .map(|input| {
                    let mut copy = input.clone_without_source();
                    if let (false, Some(source)) =
                        (named(input), input.source_transaction.as_deref())
                    {
                        copy.source_txid = Some(source.id());
                    }
                    copy
                })
                .collect();
            self.copy_with(inputs, true)
        }

        /// A copy of the other three fields beside `inputs`, its caches the
        /// original's when `keep` holds, else none.
        fn copy_with(&self, inputs: Vec<TransactionInput>, keep: bool) -> Self {
            let mut copy = Self::new(self.version, inputs, self.outputs.clone(), self.lock_time);
            if keep {
                copy.cached_hash = self.cached_hash.clone();
                copy.raw_bytes_cache = self.raw_bytes_cache.clone();
                copy.hex_cache = self.hex_cache.clone();
            }
            copy
        }
    }
}

/// A transaction's fields, owned: what [`Transaction::from_parts`] takes and
/// [`Transaction::into_parts`] gives, all six of them, so
/// `Transaction::from_parts(tx.into_parts())` is `tx` in every field, its
/// merkle path and metadata included (#869's fold).
///
/// Named fields, not a tuple, so the two `u32`s cannot be swapped silently.
/// `Default` is [`Transaction::new`]'s parts: version 1, lock time 0, no
/// input, no output, no metadata, no merkle path, as the reference's
/// constructor defaults `version = 1` and `lockTime = 0`
/// (`ts-stack@edf6e03` `Transaction.ts:581-595`), so a `..Default::default()`
/// literal never builds a version-0 transaction by omission (#869's second
/// fold; a derived `Default` gave version 0 until then):
///
/// ```
/// use bsv_rs::transaction::{Transaction, TransactionParts};
/// let tx = Transaction::from_parts(TransactionParts {
///     lock_time: 7,
///     ..Default::default()
/// });
/// assert_eq!((tx.version(), tx.lock_time(), tx.merkle_path.is_none()), (1, 7, true));
/// assert_eq!(Transaction::from_parts(TransactionParts::default()), Transaction::new());
/// ```
#[derive(Debug, Clone)]
pub struct TransactionParts {
    /// The version number (1 standard; 2 enables BIP 68/112/113).
    pub version: u32,
    /// The inputs.
    pub inputs: Vec<TransactionInput>,
    /// The outputs.
    pub outputs: Vec<TransactionOutput>,
    /// The lock time.
    pub lock_time: u32,
    /// The metadata ([`Transaction::metadata`]), not serialized.
    pub metadata: HashMap<String, Value>,
    /// The merkle path ([`Transaction::merkle_path`]), not serialized.
    pub merkle_path: Option<MerklePath>,
}

impl Default for TransactionParts {
    /// [`Transaction::new`]'s parts: version 1, lock time 0, the rest empty.
    fn default() -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            metadata: HashMap::new(),
            merkle_path: None,
        }
    }
}

/// A transaction's six fields lent at once, for a caller that writes one
/// while it reads another: what [`Transaction::parts_mut`] lends, after it
/// has cleared the caches.
#[derive(Debug)]
pub struct TransactionPartsMut<'a> {
    /// The version number.
    pub version: &'a mut u32,
    /// The inputs.
    pub inputs: &'a mut Vec<TransactionInput>,
    /// The outputs.
    pub outputs: &'a mut Vec<TransactionOutput>,
    /// The lock time.
    pub lock_time: &'a mut u32,
    /// The metadata, not serialized.
    pub metadata: &'a mut HashMap<String, Value>,
    /// The merkle path, not serialized.
    pub merkle_path: &'a mut Option<MerklePath>,
}

impl Transaction {
    /// The version number.
    ///
    /// The field is private since #843; it is written by
    /// [`set_version`](Self::set_version):
    ///
    /// ```compile_fail,E0615
    /// let mut tx = bsv_rs::transaction::Transaction::new();
    /// tx.version = 2;
    /// ```
    pub fn version(&self) -> u32 {
        self.fields.read().0
    }

    /// The lock time: if non-zero, the earliest time or block height at
    /// which the transaction can be added to the blockchain.
    ///
    /// The field is private since #843; it is written by
    /// [`set_lock_time`](Self::set_lock_time), so this does not compile:
    ///
    /// ```compile_fail,E0615
    /// let mut tx = bsv_rs::transaction::Transaction::new();
    /// tx.lock_time = 7;
    /// ```
    pub fn lock_time(&self) -> u32 {
        self.fields.read().3
    }

    /// The inputs.
    ///
    /// The field is private since #843; an input is pushed through
    /// [`inputs_mut`](Self::inputs_mut) or [`add_input`](Self::add_input), so
    /// this does not compile:
    ///
    /// ```compile_fail,E0615
    /// use bsv_rs::transaction::{Transaction, TransactionInput};
    /// let mut tx = Transaction::new();
    /// tx.inputs.push(TransactionInput::new("00".repeat(32), 0));
    /// ```
    pub fn inputs(&self) -> &[TransactionInput] {
        self.fields.read().1
    }

    /// The outputs.
    ///
    /// The field is private since #843; an output is pushed through
    /// [`outputs_mut`](Self::outputs_mut) or [`add_output`](Self::add_output),
    /// so this does not compile:
    ///
    /// ```compile_fail,E0615
    /// use bsv_rs::transaction::{Transaction, TransactionOutput};
    /// let mut tx = Transaction::new();
    /// tx.outputs.push(TransactionOutput::default());
    /// ```
    ///
    /// and the slice it lends is read-only, so neither does a write through
    /// it:
    ///
    /// ```compile_fail,E0594
    /// use bsv_rs::transaction::{Transaction, TransactionOutput};
    /// let mut tx = Transaction::new();
    /// tx.add_output(TransactionOutput::default()).unwrap();
    /// tx.outputs()[0].satoshis = Some(1);
    /// ```
    pub fn outputs(&self) -> &[TransactionOutput] {
        self.fields.read().2
    }

    /// Sets the version number, clearing every cache first.
    ///
    /// ```
    /// let mut tx = bsv_rs::transaction::Transaction::new();
    /// let before = tx.id();
    /// tx.set_version(2);
    /// assert_ne!(tx.id(), before);
    /// assert_eq!(tx.to_binary()[..4], [2, 0, 0, 0]);
    /// ```
    pub fn set_version(&mut self, version: u32) {
        *self.fields.write().0 = version;
    }

    /// Sets the lock time, clearing every cache first.
    ///
    /// ```
    /// let mut tx = bsv_rs::transaction::Transaction::new();
    /// let before = tx.id();
    /// tx.set_lock_time(7);
    /// assert_ne!(tx.id(), before);
    /// assert!(tx.to_binary().ends_with(&[7, 0, 0, 0]));
    /// ```
    ///
    /// There is no cache for a caller to repair, so the method that did so
    /// before #843 is gone:
    ///
    /// ```compile_fail,E0599
    /// let tx = bsv_rs::transaction::Transaction::new();
    /// tx.invalidate_caches();
    /// ```
    pub fn set_lock_time(&mut self, lock_time: u32) {
        *self.fields.write().3 = lock_time;
    }

    /// Lends the inputs mutably, every cache cleared first. While the borrow
    /// lives no `&self` read can refill a cache; an edit of a linked
    /// `source_transaction` goes through here, so the child's id follows it.
    ///
    /// A read takes [`inputs`](Self::inputs): each call here clears the
    /// cached id, so a walk that reads through it re-hashes.
    ///
    /// A read held across a door does not compile, so no read sees the
    /// fields before an edit and the id after it:
    ///
    /// ```compile_fail,E0502
    /// let mut tx = bsv_rs::transaction::Transaction::new();
    /// let read = tx.inputs();
    /// tx.inputs_mut().clear();
    /// let _ = read.len();
    /// ```
    pub fn inputs_mut(&mut self) -> &mut Vec<TransactionInput> {
        self.fields.write().1
    }

    /// Lends the outputs mutably, every cache cleared first. While the borrow
    /// lives no `&self` read can refill a cache.
    ///
    /// A read takes [`outputs`](Self::outputs): each call here clears the
    /// cached id, so a walk that reads through it re-hashes.
    pub fn outputs_mut(&mut self) -> &mut Vec<TransactionOutput> {
        self.fields.write().2
    }

    /// Lends the six fields at once, every cache cleared first, for a caller
    /// that writes one field while it reads another.
    ///
    /// A read takes the accessors ([`inputs`](Self::inputs) and the rest):
    /// each call here clears the cached id, so a walk that reads through it
    /// re-hashes.
    ///
    /// ```
    /// use bsv_rs::transaction::{Transaction, TransactionInput};
    /// let mut tx = Transaction::new();
    /// tx.inputs_mut().push(TransactionInput::new("11".repeat(32), 0));
    /// let parts = tx.parts_mut();
    /// *parts.lock_time = parts.inputs.len() as u32;
    /// assert_eq!(tx.lock_time(), 1);
    /// ```
    pub fn parts_mut(&mut self) -> TransactionPartsMut<'_> {
        let Transaction {
            fields,
            metadata,
            merkle_path,
        } = self;
        let (version, inputs, outputs, lock_time) = fields.write();
        TransactionPartsMut {
            version,
            inputs,
            outputs,
            lock_time,
            metadata,
            merkle_path,
        }
    }

    /// A transaction of the six parts, no cache. A struct literal does not
    /// compile, the fields being private:
    ///
    /// ```compile_fail,E0560
    /// use bsv_rs::transaction::Transaction;
    /// let tx = Transaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, ..Default::default() };
    /// ```
    pub fn from_parts(parts: TransactionParts) -> Self {
        Self {
            fields: Fields::new(parts.version, parts.inputs, parts.outputs, parts.lock_time),
            metadata: parts.metadata,
            merkle_path: parts.merkle_path,
        }
    }

    /// The six fields, moved out: `Transaction::from_parts(tx.into_parts())`
    /// is `tx` in every field, its merkle path and metadata included.
    ///
    /// ```
    /// use bsv_rs::transaction::{Transaction, TransactionParts};
    /// let mut tx = Transaction::new();
    /// tx.set_lock_time(9);
    /// let TransactionParts { version, lock_time, .. } = tx.into_parts();
    /// assert_eq!((version, lock_time), (1, 9));
    /// ```
    pub fn into_parts(mut self) -> TransactionParts {
        // `Transaction` implements `Drop`, so its fields are taken, not
        // moved: an empty `Fields` is left, and the emptied value then
        // drops with nothing to walk. The taken value is consumed, so no
        // cache outlives the take.
        let (version, inputs, outputs, lock_time) =
            std::mem::replace(&mut self.fields, Fields::new(1, Vec::new(), Vec::new(), 0))
                .into_four();
        TransactionParts {
            version,
            inputs,
            outputs,
            lock_time,
            metadata: std::mem::take(&mut self.metadata),
            merkle_path: self.merkle_path.take(),
        }
    }

    /// One transaction read from `bin` (a byte after it refused), with `bin`
    /// as its cached serialization and `hex`, when given, as its cached hex:
    /// the readers' fill, `from_binary`'s and `from_hex`'s. The bytes cannot
    /// differ from the fields: they are exactly the transaction just read
    /// from them (#840).
    pub(super) fn read_exact(bin: Vec<u8>, hex: Option<String>) -> Result<Self> {
        let tx = Self::from_whole(&bin, TRAILING_DATA)?;
        // Filled on a value no one else holds yet, through `&self`.
        let (_, raw_bytes_cache, hex_cache) = tx.fields.caches();
        let _ = raw_bytes_cache.set(bin);
        if let Some(hex) = hex {
            let _ = hex_cache.set(hex);
        }
        Ok(tx)
    }

    /// The serialization, cached: `to_binary`'s fill, from the fields alone.
    pub(super) fn serialized_bytes(&self) -> &[u8] {
        self.fields
            .caches()
            .1
            .get_or_init(|| self.build_serialized_bytes())
    }

    /// The hex, cached: `to_hex`'s fill, from the serialization alone.
    pub(super) fn serialized_hex(&self) -> &str {
        self.fields
            .caches()
            .2
            .get_or_init(|| to_hex(self.serialized_bytes()))
    }

    /// The hash, cached: `hash`'s fill, from the serialization alone.
    pub(super) fn serialized_hash(&self) -> [u8; 32] {
        *self
            .fields
            .caches()
            .0
            .get_or_init(|| sha256d(self.serialized_bytes()))
    }

    /// Calls `f` with the cached serialization, or `None` when none is
    /// cached, without copying it: the bytes [`to_binary`](Self::to_binary)
    /// returns while the cache holds. For the BEEF writers' check (#621's
    /// fold): `from_binary` and `from_hex` cache the bytes they read, which
    /// are exactly one transaction since #840 (until then the whole buffer
    /// they read a prefix of), `to_binary` its own serialization, `Clone` a
    /// copy.
    pub(crate) fn with_cached_bytes<R>(&self, f: impl FnOnce(Option<&[u8]>) -> R) -> R {
        f(self.fields.caches().1.get().map(Vec::as_slice))
    }

    /// This transaction with `bytes` as its cached serialization, whatever
    /// they hold: the state `from_binary` of a buffer longer than one
    /// transaction left until #840, which no public door builds since, and a
    /// stale cache under edited fields (#621's fold: its differential, the
    /// `to_writer` pin and `fuzz_beef_parser`'s hand states). Built only for
    /// the crate's own tests and under the `internal-test-doors` feature,
    /// which this repository's fuzz crate turns on and which is no part of
    /// the API (#869's fold: under `cfg(fuzzing)` until then, which
    /// cargo-fuzz sets for every crate of a build, a dependent's included).
    #[cfg(any(test, feature = "internal-test-doors"))]
    #[doc(hidden)]
    pub fn with_cached_bytes_for_test(mut self, bytes: Vec<u8>) -> Self {
        // The cached hash and hex kept as they were (#869's sixth fold:
        // emptied through `write` with the bytes, then put back).
        let (hash, _, hex) = self.fields.caches();
        let (hash, hex) = (hash.get().copied(), hex.get().cloned());
        self.fields.write();
        let (hash_cache, raw_bytes_cache, hex_cache) = self.fields.caches();
        let _ = raw_bytes_cache.set(bytes);
        if let Some(hash) = hash {
            let _ = hash_cache.set(hash);
        }
        if let Some(hex) = hex {
            let _ = hex_cache.set(hex);
        }
        self
    }

    /// Hashes, deepest first, every linked source whose id this transaction's
    /// serialization reads THROUGH the source ([`OutpointTxid::Source`]: an
    /// input with no `source_txid`, the shape `add_input_from_tx` builds, or
    /// one whose text does not parse), so reading an id
    /// never recurses more than one level: a chain built that way used to
    /// recurse once per link through `id()` (0.3.35, bsv-stack-lean #57). The
    /// reference does the same for an input with no `sourceTXID` before it
    /// serializes (`@bsv/sdk` `Transaction.materializeSourceTXIDs`,
    /// `ts-stack@edf6e03` `Transaction.ts:217-224,254`).
    fn hash_sources_without_txids(&self) {
        fn unhashed(input: &TransactionInput) -> Option<&Transaction> {
            input.source_transaction.as_ref()?;
            match outpoint_txid(input) {
                OutpointTxid::Source(source) if source.fields.caches().0.get().is_none() => {
                    Some(source)
                }
                _ => None,
            }
        }
        if self.inputs().iter().all(|input| unhashed(input).is_none()) {
            return;
        }
        // Every reachable source to hash, each after the one that links it,
        // so the reversed list hashes a source before anything that reads it.
        let mut order: Vec<&Transaction> = Vec::new();
        let mut stack: Vec<&Transaction> = Vec::from([self]);
        while let Some(tx) = stack.pop() {
            for source in tx.inputs().iter().filter_map(unhashed) {
                order.push(source);
                stack.push(source);
            }
        }
        for source in order.into_iter().rev() {
            source.hash();
        }
    }

    /// Builds the serialized bytes for this transaction.
    fn build_serialized_bytes(&self) -> Vec<u8> {
        self.hash_sources_without_txids();
        let mut writer = Writer::new();
        writer.write_u32_le(self.version());
        writer.write_var_int(self.inputs().len() as u64);
        for input in self.inputs() {
            writer.write_bytes(&outpoint_txid_bytes(input));
            writer.write_u32_le(input.source_output_index);
            if let Some(ref script) = input.unlocking_script {
                let script_bytes = script.to_binary();
                writer.write_var_int(script_bytes.len() as u64);
                writer.write_bytes(&script_bytes);
            } else {
                writer.write_var_int(0);
            }
            writer.write_u32_le(input.sequence);
        }
        writer.write_var_int(self.outputs().len() as u64);
        for output in self.outputs() {
            writer.write_u64_le(output.satoshis.unwrap_or(0));
            let script = output.locking_script.to_binary();
            writer.write_var_int(script.len() as u64);
            writer.write_bytes(&script);
        }
        writer.write_u32_le(self.lock_time());
        writer.into_bytes()
    }

    /// The copy of this transaction a BEEF stores: every field but the
    /// ancestry, the caches copied, each input the serializer reads through
    /// its source ([`OutpointTxid::Source`]) named by that source's id, the
    /// same bytes (#869's second fold; the sealed module's
    /// `Fields::copy_named` since the sixth).
    pub(in crate::transaction) fn clone_for_beef(&self) -> Transaction {
        let copy = Transaction {
            fields: self.fields.copy_named(),
            metadata: self.metadata.clone(),
            merkle_path: self.merkle_path.clone(),
        };
        debug_assert!(copy
            .inputs()
            .iter()
            .zip(self.inputs())
            .all(|(c, o)| outpoint_txid_bytes(c) == outpoint_txid_bytes(o)));
        copy
    }

    /// Links `source` to input `index` (or unlinks it, with `None`) and
    /// returns the source it held: the crate's linking door (#869's second
    /// fold), `Fields::replace_source`: the caches kept exactly under
    /// [`OutpointTxid::Named`], where no byte can move, else emptied.
    ///
    /// # Panics
    ///
    /// When `index` is not an input's, as `inputs_mut()[index]` does.
    pub(in crate::transaction) fn replace_source(
        &mut self,
        index: usize,
        source: Option<Box<Transaction>>,
    ) -> Option<Box<Transaction>> {
        self.fields.replace_source(index, source)
    }
}

/// What the serializer writes as an input's outpoint txid, by the one rule
/// every path that copies a cache shares (#869's second fold): the input's
/// `source_txid` when it is hex of exactly 32 bytes (`Named`, the bytes
/// reversed into internal order), else the linked source's hash
/// (`Source`), else 32 zero bytes (`Zero`). The rule is the serializer's
/// as it stood (`get_source_txid_bytes`, then the source's `hash()`, then
/// zeros); no byte it writes moved.
pub(in crate::transaction) enum OutpointTxid<'a> {
    /// `source_txid` is 64 hex digits: its bytes, whatever the source.
    Named(&'a str),
    /// `source_txid` is absent or not 64 hex digits, and a source is
    /// linked: its hash.
    Source(&'a Transaction),
    /// Neither: 32 zero bytes.
    Zero,
}

/// The arm of [`OutpointTxid`] an input is in.
pub(in crate::transaction) fn outpoint_txid(input: &TransactionInput) -> OutpointTxid<'_> {
    match (
        input
            .source_txid
            .as_deref()
            .filter(|t| sealed::names_32_bytes(t)),
        input.source_transaction.as_deref(),
    ) {
        (Some(text), _) => OutpointTxid::Named(text),
        (None, Some(source)) => OutpointTxid::Source(source),
        (None, None) => OutpointTxid::Zero,
    }
}

/// The outpoint txid bytes the serializer writes for `input`.
pub(in crate::transaction) fn outpoint_txid_bytes(input: &TransactionInput) -> [u8; 32] {
    match outpoint_txid(input) {
        OutpointTxid::Named(text) => {
            let mut out = [0u8; 32];
            // 64 hex digits always decode to 32 bytes.
            if hex::decode_to_slice(text, &mut out).is_err() {
                return [0; 32];
            }
            out.reverse();
            out
        }
        OutpointTxid::Source(source) => source.hash(),
        OutpointTxid::Zero => [0; 32],
    }
}

/// The txid an input's outpoint names, as the BEEF graph keys it (#869's
/// third fold): the text when it is 64 hex digits, as given; else the linked
/// source's id; else the text as given, if any (what `get_source_txid` read
/// before the fold, so only a text that does not parse over a linked source
/// moves: it named the text, which no entry and no written byte carries).
pub(in crate::transaction) fn outpoint_txid_name(input: &TransactionInput) -> Option<String> {
    if input.source_transaction.is_none() {
        // `Named` or `Zero`: the text either way, so no scan (the read path's
        // entries link nothing).
        return input.source_txid.clone();
    }
    match outpoint_txid(input) {
        OutpointTxid::Named(text) => Some(text.to_string()),
        OutpointTxid::Source(source) => Some(source.id()),
        OutpointTxid::Zero => input.source_txid.clone(),
    }
}

#[cfg(test)]
#[path = "link_source_869_tests.rs"]
mod link_source_869_tests;

/// The derive's output, field for field; each input prints its linked source
/// as its txid (`TransactionInput`'s `Debug`), so the output is the
/// transaction, not its history.
impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (version, inputs, outputs, lock_time) = self.fields.read();
        let (cached_hash, raw_bytes_cache, hex_cache) = self.fields.caches();
        f.debug_struct("Transaction")
            .field("version", &version)
            .field("inputs", &inputs)
            .field("outputs", &outputs)
            .field("lock_time", &lock_time)
            .field("metadata", &self.metadata)
            .field("merkle_path", &self.merkle_path)
            .field("cached_hash", cached_hash)
            .field("raw_bytes_cache", raw_bytes_cache)
            .field("hex_cache", hex_cache)
            .finish()
    }
}

impl Clone for Transaction {
    /// A deep copy, ancestry included, as the derived `Clone` made: every
    /// linked `source_transaction` is copied, and every input's
    /// `unlocking_script_template` is left `None` (templates hold closures).
    /// The ancestry is copied depth first with an explicit stack, so a deep
    /// chain costs heap, not stack. Each copy's caches are copied from its
    /// original, which held the same link at the same input, so linking the
    /// copied source back moves no byte.
    // Since #869's sixth fold each copy is built after its sources' copies
    // by `Fields::copy_relinked`, which copies the caches exactly when each
    // copied source's cached hash is its original's.
    #[allow(clippy::expect_used)] // #134: the loop pops only what it pushed and returns at the root; Clone has no Result
    fn clone(&self) -> Self {
        /// One transaction being copied, and the copies of its inputs'
        /// sources so far, one per input looked at.
        struct Frame<'a> {
            original: &'a Transaction,
            sources: Vec<Option<Box<Transaction>>>,
        }

        fn frame(original: &Transaction) -> Frame<'_> {
            Frame {
                original,
                sources: Vec::with_capacity(original.inputs().len()),
            }
        }

        let mut stack = Vec::from([frame(self)]);
        loop {
            let top = stack.last_mut().expect("the stack is not empty");
            let original = top.original;
            if let Some(input) = original.inputs().get(top.sources.len()) {
                match input.source_transaction.as_deref() {
                    Some(source) => stack.push(frame(source)),
                    None => top.sources.push(None),
                }
                continue;
            }
            let Frame { original, sources } = stack.pop().expect("the stack is not empty");
            let done = Transaction {
                fields: original.fields.copy_relinked(sources),
                metadata: original.metadata.clone(),
                merkle_path: original.merkle_path.clone(),
            };
            match stack.last_mut() {
                Some(parent) => parent.sources.push(Some(Box::new(done))),
                None => return done,
            }
        }
    }
}
