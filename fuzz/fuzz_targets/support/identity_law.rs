//! #843's IDENTITY law as a fuzz invariant (#869's fold, the strength read):
//! after a parse that succeeds, a short sequence of edits through the doors,
//! chosen by the input's bytes, and after each one `id()` is the display hex
//! of `sha256d` of the fields' serialization, written here from the four
//! accessors alone (no cache of the crate read, no `to_binary`), and a fresh
//! parse of `to_binary()` has the same id. Shared by `fuzz_transaction_parser`
//! and `fuzz_beef_parser` (`#[path]`).

use std::collections::HashMap;

use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, Transaction, TransactionInput, TransactionOutput, TransactionParts,
};

/// Edits per input, at most.
const EDITS: usize = 6;

fn var_int(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// The input's outpoint txid when its `source_txid` is hex of exactly 32
/// bytes (internal order), the serializer's `Named` arm.
fn named(input: &TransactionInput) -> Option<[u8; 32]> {
    let mut b: [u8; 32] = from_hex(input.source_txid.as_deref()?)
        .ok()?
        .try_into()
        .ok()?;
    b.reverse();
    Some(b)
}

/// The fields' bytes, by the serializer's rule (#869's second fold): an
/// input's outpoint txid its `source_txid` when that parses to 32 bytes,
/// else the linked source's own fields' hash, else zeros. Iterative: every
/// source the bytes read through is hashed first, deepest first, on an
/// explicit stack (a fuzzed chain can be deep), memoized by address.
pub fn fields_bytes(tx: &Transaction) -> Vec<u8> {
    let key = |t: &Transaction| t as *const Transaction as usize;
    // Each transaction after the one that reads it; hashed in reverse.
    let mut order: Vec<&Transaction> = Vec::new();
    let mut stack: Vec<&Transaction> = through(tx);
    while let Some(t) = stack.pop() {
        order.push(t);
        stack.extend(through(t));
    }
    let mut hashes: HashMap<usize, [u8; 32]> = HashMap::new();
    for t in order.into_iter().rev() {
        if !hashes.contains_key(&key(t)) {
            let bytes = one_level(t, &hashes);
            hashes.insert(key(t), sha256d(&bytes));
        }
    }
    one_level(tx, &hashes)
}

/// The sources `t`'s bytes read through (an input whose `source_txid` does
/// not parse to 32 bytes).
fn through(t: &Transaction) -> Vec<&Transaction> {
    t.inputs()
        .iter()
        .filter(|input| named(input).is_none())
        .filter_map(|input| input.source_transaction.as_deref())
        .collect()
}

/// One transaction's bytes, its read-through sources' hashes given.
fn one_level(tx: &Transaction, hashes: &HashMap<usize, [u8; 32]>) -> Vec<u8> {
    let mut out = tx.version().to_le_bytes().to_vec();
    var_int(&mut out, tx.inputs().len() as u64);
    for input in tx.inputs() {
        let wire = match (named(input), input.source_transaction.as_deref()) {
            (Some(b), _) => b,
            (None, Some(source)) => hashes[&(source as *const Transaction as usize)],
            (None, None) => [0; 32],
        };
        out.extend_from_slice(&wire);
        out.extend_from_slice(&input.source_output_index.to_le_bytes());
        let script = input
            .unlocking_script
            .as_ref()
            .map(|s| s.to_binary())
            .unwrap_or_default();
        var_int(&mut out, script.len() as u64);
        out.extend_from_slice(&script);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    var_int(&mut out, tx.outputs().len() as u64);
    for output in tx.outputs() {
        out.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
        let script = output.locking_script.to_binary();
        var_int(&mut out, script.len() as u64);
        out.extend_from_slice(&script);
    }
    out.extend_from_slice(&tx.lock_time().to_le_bytes());
    out
}

fn display(hash: [u8; 32]) -> String {
    let mut h = hash;
    h.reverse();
    to_hex(&h)
}

/// The law at one point.
pub fn law(tx: &Transaction, at: &str) {
    let id = tx.id();
    assert_eq!(
        id,
        display(sha256d(&fields_bytes(tx))),
        "{at}: id() is the hash of the fields (#843)"
    );
    if let Ok(fresh) = Transaction::from_binary(&tx.to_binary()) {
        assert_eq!(
            fresh.id(),
            id,
            "{at}: a fresh parse of to_binary() has the same id"
        );
    }
}

/// The law on `tx` and on every transaction linked below it, at any depth
/// (an explicit stack).
pub fn law_reach(tx: &Transaction, at: &str) {
    let mut stack = vec![tx];
    while let Some(t) = stack.pop() {
        law(t, at);
        stack.extend(
            t.inputs()
                .iter()
                .filter_map(|input| input.source_transaction.as_deref()),
        );
    }
}

/// The law over every transaction a BEEF stores (#869's second fold, the
/// cold re-read's FIX): each held entry, each linked again through
/// `find_atomic_transaction` (the linking door) and that linked transaction
/// merged back through `merge_transaction` (every ancestor a stored copy),
/// then the same of the BEEF merged into an empty BEEF and into itself.
#[allow(dead_code)] // `fuzz_beef_parser`'s alone; the module is shared.
pub fn beef_copies_keep_the_law(beef: &Beef) {
    fn entries(beef: &Beef, at: &str) {
        for entry in &beef.txs {
            if let Some(tx) = entry.tx() {
                law_reach(tx, at);
                let id = entry.txid();
                if let Some(signing) = beef.find_transaction_for_signing(&id) {
                    assert_eq!(signing.id(), id, "{at}: the id for signing (#869)");
                }
                if let Some(linked) = beef.find_atomic_transaction(&id) {
                    assert_eq!(linked.id(), id, "{at}: the id linked (#869)");
                    law_reach(&linked, at);
                    // Merged back: every ancestor stored as a copy.
                    merged_hands_back_what_it_took(&linked, "a linked entry merged back");
                    let mut back = Beef::new();
                    back.merge_transaction(linked);
                    for copy in back.txs.iter().filter_map(|e| e.tx()) {
                        law_reach(copy, "a linked entry merged back");
                    }
                }
            }
        }
    }
    entries(beef, "a parsed BEEF's entries");
    let mut empty = Beef::new();
    if empty.merge_beef(beef).is_ok() {
        entries(&empty, "merged into an empty BEEF");
    }
    let mut itself = beef.clone();
    if itself.merge_beef(beef).is_ok() {
        entries(&itself, "merged into itself");
    }
}

/// `tx` merged by `merge_transaction` is handed back by
/// `find_atomic_transaction` and `find_transaction_for_signing` of its id
/// under that id, each input that carried a source linked to a source of the
/// same id at every depth both reach (#869's third fold: the linker keyed its
/// stubs by the txid text, so two inputs sharing one that does not parse were
/// handed one source). An explicit stack: a chain read from bytes is deep.
pub fn merged_hands_back_what_it_took(tx: &Transaction, at: &str) {
    let id = tx.id();
    let mut beef = Beef::new();
    beef.merge_transaction(tx.clone());
    let signing = beef.find_transaction_for_signing(&id).expect("merged");
    assert_eq!(
        signing.id(),
        id,
        "{at}: find_transaction_for_signing's id (#869)"
    );
    let linked = beef.find_atomic_transaction(&id).expect("merged");
    assert_eq!(linked.id(), id, "{at}: find_atomic_transaction's id (#869)");
    let mut stack = vec![(tx, &linked)];
    while let Some((g, l)) = stack.pop() {
        for (gi, li) in g.inputs().iter().zip(l.inputs()) {
            if let (Some(gs), Some(ls)) = (
                gi.source_transaction.as_deref(),
                li.source_transaction.as_deref(),
            ) {
                assert_eq!(ls.id(), gs.id(), "{at}: a linked source's id (#869)");
                stack.push((gs, ls));
            }
        }
    }
}

/// The input's bytes, cycled.
struct Bytes<'a> {
    data: &'a [u8],
    at: usize,
}

impl Bytes<'_> {
    fn next(&mut self) -> u8 {
        let b = self
            .data
            .get(self.at % self.data.len().max(1))
            .copied()
            .unwrap_or(0);
        self.at += 1;
        b
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.next(), self.next(), self.next(), self.next()])
    }
}

/// One edit through a door, chosen by `op`; its name for the log.
fn edit(tx: &mut Transaction, op: u8, b: &mut Bytes<'_>) -> &'static str {
    let room = tx.inputs().len() < 64 && tx.outputs().len() < 64;
    match op % 14 {
        0 => {
            tx.set_version(b.u32());
            "set_version"
        }
        1 => {
            tx.set_lock_time(b.u32());
            "set_lock_time"
        }
        2 if room => {
            let txid = to_hex(&[b.next(); 32]);
            tx.inputs_mut().push(TransactionInput::new(txid, b.u32()));
            "inputs_mut().push"
        }
        3 if room => {
            let script = LockingScript::from_binary(&[0x51 + (b.next() % 16)]).unwrap_or_default();
            tx.outputs_mut()
                .push(TransactionOutput::new(u64::from(b.u32()), script));
            "outputs_mut().push"
        }
        4 if !tx.inputs().is_empty() => {
            let i = usize::from(b.next()) % tx.inputs().len();
            tx.inputs_mut()[i].sequence = b.u32();
            "inputs_mut()[i].sequence"
        }
        5 if !tx.outputs().is_empty() => {
            let i = usize::from(b.next()) % tx.outputs().len();
            tx.outputs_mut()[i].satoshis = Some(u64::from(b.u32()));
            "outputs_mut()[i].satoshis"
        }
        6 if tx.inputs().len() > 1 => {
            tx.inputs_mut().pop();
            "inputs_mut().pop"
        }
        7 => {
            let flip = b.u32();
            let parts = tx.parts_mut();
            *parts.lock_time = parts.inputs.len() as u32 ^ flip;
            "parts_mut"
        }
        8 => {
            let TransactionParts {
                version,
                inputs,
                outputs,
                lock_time,
                metadata,
                merkle_path,
            } = std::mem::take(tx).into_parts();
            *tx = Transaction::from_parts(TransactionParts {
                version: lock_time,
                inputs,
                outputs,
                lock_time: version,
                metadata,
                merkle_path,
            });
            "into_parts/from_parts"
        }
        9 => {
            *tx = tx.clone();
            "clone"
        }
        10 => {
            let linked = tx
                .inputs()
                .iter()
                .position(|input| input.source_transaction.is_some());
            if let Some(i) = linked {
                let lock = b.u32();
                if let Some(source) = tx.inputs_mut()[i].source_transaction.as_mut() {
                    source.set_lock_time(lock);
                }
            }
            "a linked source's set_lock_time"
        }
        12 if !tx.inputs().is_empty() => {
            // A txid text the serializer cannot read (#869's second fold):
            // the outpoint is then the linked source's hash, or zeros.
            let i = usize::from(b.next()) % tx.inputs().len();
            let text = match b.next() % 3 {
                0 => "zz".repeat(32),
                1 => String::new(),
                _ => "ab".repeat(31),
            };
            tx.inputs_mut()[i].source_txid = Some(text);
            "inputs_mut()[i].source_txid odd"
        }
        13 if room && !tx.inputs().is_empty() => {
            // One text on every input, each keeping its source (#869's third
            // fold): a text that does not parse, or one that parses. When an
            // input is linked, a second input linked to a copy of its source
            // under another lock time first, so two inputs share the text
            // over two different sources (the linker keyed its stubs by the
            // text and handed the second the first one's source).
            let linked = tx
                .inputs()
                .iter()
                .find_map(|input| input.source_transaction.clone());
            if let Some(source) = linked {
                let mut other = *source;
                other.set_lock_time(other.lock_time() ^ (b.u32() | 1));
                let mut input = TransactionInput::new(String::new(), 0);
                input.source_transaction = Some(Box::new(other));
                tx.inputs_mut().push(input);
            }
            let text = match b.next() % 3 {
                0 => "zz".to_string(),
                1 => String::new(),
                _ => to_hex(&[b.next(); 32]),
            };
            for input in tx.inputs_mut().iter_mut() {
                input.source_txid = Some(text.clone());
            }
            "every input's source_txid one text"
        }
        11 => {
            let keep = b.next();
            let mut n = 0u32;
            tx.outputs_mut().retain(|_| {
                n += 1;
                keep >> (n % 8) & 1 == 1
            });
            "outputs_mut().retain"
        }
        _ => "no edit",
    }
}

/// The law on `tx` as read, then after each of up to [`EDITS`] edits the
/// input's bytes choose (the caches read before each edit, so a door is
/// judged on a value whose caches are full).
pub fn edits_keep_the_law(mut tx: Transaction, data: &[u8]) {
    law_reach(&tx, "as read");
    let mut b = Bytes { data, at: 0 };
    let count = usize::from(b.next()) % (EDITS + 1);
    let mut log = Vec::new();
    for _ in 0..count {
        let _ = (tx.id(), tx.to_hex());
        log.push(edit(&mut tx, b.next(), &mut b));
        law_reach(&tx, &format!("after {log:?}"));
    }
    merged_hands_back_what_it_took(&tx, &format!("merged after {log:?}"));
}
