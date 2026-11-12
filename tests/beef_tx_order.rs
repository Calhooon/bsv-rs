//! A transaction's BEEF ends with that transaction (BRC-62's order: each
//! entry's sources above it, the subject last), so a reader that takes the
//! last entry (`Transaction::from_beef` with no txid, the reference's own
//! reader contract, `#fromAnyBeef`'s target = `txid ?? atomicTxid ??
//! lastTx.txid`) reads the transaction the writer wrote, not an ancestor
//! beside it.
//!
//! Through 0.8.7 the transaction doors (`to_beef`, `to_beef_v1`) sorted the
//! collected ancestry into `Beef::to_binary`'s dependency order, which holds
//! a proven entry after every entry whose closure rests on a missing source:
//! a graph holding both — one branch proven, one branch resting on an input
//! whose source transaction is absent — wrote the subject before the proven
//! entry, and the no-txid read returned the other transaction (every
//! published version since `0.2.0`, the crate's first release; a graph with
//! no proven entry was never misread). The reference's transaction door never sorts
//! (`ts-stack@edf6e03` `Transaction.ts:1787-1839`, its
//! `writeSerializedBEEF` walking its LIFO stack and writing what it
//! collects): since 0.8.8 these doors write the collected order, the
//! subject last, byte-equal to the reference's `toBEEF` (the reference's
//! door writes the V1 word; this crate's `to_beef` writes the same bytes
//! under the V2 word).
//!
//! A BEEF a caller assembles by hand keeps the documented dependency sort —
//! as the reference's `Beef.toBinary` still sorts it (`Beef.ts:360-373`)
//! — and the order every version before 0.8.8 wrote still reads. The
//! reference's bytes and that sorted order are pinned by
//! `tests/vectors/beef_tx_order.json`, recorded by
//! `tests/support/beef_tx_order.mjs` at `ts-stack@edf6e03`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::{HashMap, HashSet};

use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    ATOMIC_BEEF, BEEF_V1, BEEF_V2,
};

/// The xorshift harness of the sweep that measured the reach (the same seed
/// and draw order, so the graphs here are of the population it counted).
struct R(u64);
impl R {
    fn n(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn b(&mut self, k: u64) -> u64 {
        self.n() % k
    }
}

/// A txid no entry of the shapes holds: the absent source of a root's input.
fn absent_source(salt: u8) -> String {
    format!("{salt:02x}{}", "5e".repeat(31))
}

/// A root of the shapes: one input whose source transaction is absent (a
/// partial graph), one output, proven by a merkle path when `proven`.
fn root(proven: bool, salt: u8) -> Transaction {
    let mut t = Transaction::new();
    t.version = 1;
    t.lock_time = salt as u32;
    let mut input = TransactionInput::new(absent_source(salt), (salt % 4) as u32);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    t.inputs.push(input);
    t.outputs.push(TransactionOutput::new(
        1000 + salt as u64,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    if proven {
        let id = t.id();
        t.merkle_path = Some(
            MerklePath::new(
                800_000 + salt as u32,
                vec![vec![MerklePathLeaf::new_txid(0, id)]],
            )
            .unwrap(),
        );
    }
    t
}

/// An input spending `src`'s output `idx`, as the walk collects it.
fn link(src: &Transaction, idx: u32) -> TransactionInput {
    let mut i = TransactionInput::with_source_transaction(src.clone(), idx);
    i.source_txid = Some(src.id());
    i.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    i.sequence = 0xffffffff;
    i
}

/// A mid of the shapes: one input per root, one output.
fn mid(roots: &[Transaction], salt: u64) -> Transaction {
    let mut t = Transaction::new();
    t.version = 1;
    t.lock_time = salt as u32;
    for src in roots {
        t.inputs.push(link(src, 0));
    }
    t.outputs.push(TransactionOutput::new(
        500 + salt,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    t
}

/// The subject of the shapes: one input per mid, one output.
fn subject(mids: &[Transaction]) -> Transaction {
    let mut t = Transaction::new();
    t.version = 2;
    t.lock_time = 0x4243;
    for src in mids {
        t.inputs.push(link(src, 0));
    }
    t.outputs.push(TransactionOutput::new(
        250,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    t
}

/// The finding's shape: one proven branch and one branch resting on a missing
/// source, the subject spending both. Until 0.8.8 the dependency sort
/// wrote the subject before the proven root.
fn beside_proven() -> Transaction {
    let root_p = root(true, 1);
    let root_m = root(false, 2);
    let mid_p = mid(&[root_p], 10);
    let mid_m = mid(&[root_m], 20);
    subject(&[mid_p, mid_m])
}

/// A proven root, a mid, the subject: the collected order and the dependency
/// order are the same bytes (an honest graph the fix leaves untouched).
fn chain_proven() -> Transaction {
    let r = root(true, 3);
    let m = mid(&[r], 30);
    subject(&[m])
}

/// The same chain over an unproven root (a partial graph).
fn chain_missing() -> Transaction {
    let r = root(false, 4);
    let m = mid(&[r], 40);
    subject(&[m])
}

/// One proven root spent by two mids, the subject spending both (a diamond).
fn diamond_proven() -> Transaction {
    let r = root(true, 5);
    let m1 = mid(std::slice::from_ref(&r), 50);
    let m2 = mid(std::slice::from_ref(&r), 60);
    subject(&[m1, m2])
}

/// The witnesses by name, as this crate's writers build them.
fn witnesses() -> Vec<(&'static str, Transaction)> {
    vec![
        ("beside_proven", beside_proven()),
        ("chain_proven", chain_proven()),
        ("chain_missing", chain_missing()),
        ("diamond_proven", diamond_proven()),
    ]
}

/// Every transaction of the subject's ancestry, each entry's sources above
/// it, the subject last (the walk `to_beef` collects), each txid once.
fn ancestry(subject: &Transaction) -> Vec<Transaction> {
    fn walk(tx: &Transaction, seen: &mut HashSet<String>, out: &mut Vec<Transaction>) {
        if !seen.insert(tx.id()) {
            return;
        }
        for input in tx.inputs.iter().rev() {
            if let Some(src) = input.source_transaction.as_deref() {
                walk(src, seen, out);
            }
        }
        out.push(tx.clone());
    }
    let mut out = Vec::new();
    walk(subject, &mut HashSet::new(), &mut out);
    out
}

/// The same graph assembled by hand, a caller's Beef under the V1 word (the
/// reference's `toBEEF` writes V1; the V1 word keeps the bytes comparable):
/// the BUMPs merged, the entries pushed in the collected order, written by
/// [`Beef::to_binary`], which sorts a BEEF a caller assembles — the
/// dependency order every version before 0.8.8 also wrote at the
/// transaction doors.
fn assembled_by_hand(subject: &Transaction) -> Vec<u8> {
    let entries = ancestry(subject);
    let mut beef = Beef::with_version(BEEF_V1);
    let mut bump_of: HashMap<String, usize> = HashMap::new();
    for tx in &entries {
        if let Some(path) = &tx.merkle_path {
            bump_of.insert(tx.id(), beef.merge_bump(path.clone()));
        }
    }
    for tx in &entries {
        beef.txs
            .push(BeefTx::from_tx(tx.clone(), bump_of.get(&tx.id()).copied()));
    }
    beef.to_binary()
}

/// The dependency order of the entries a door wrote, as the Beef-level sort
/// still computes it: parse the bytes, sort, write (the parsed BEEF's own
/// order is the held one, so the sort is what moves).
fn sorted_bytes(held: &[u8]) -> Vec<u8> {
    let mut beef = Beef::from_binary(held).unwrap();
    let _ = beef.sort_txs();
    beef.to_binary()
}

/// The witnesses' recorded answers, `tests/vectors/beef_tx_order.json`.
fn recorded() -> HashMap<String, serde_json::Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/beef_tx_order.json"
    );
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    file["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| (w["name"].as_str().unwrap().to_string(), w.clone()))
        .collect()
}

/// A BEEF beside a proven ancestor ends with the subject, so a no-txid read
/// returns it: the finding's shape through both transaction doors, each read
/// the readers make. Until 0.8.8 the sorted bytes wrote the proven root
/// after the subject and the no-txid read returned the mid that spends it.
#[test]
fn a_beef_beside_a_proven_ancestor_ends_with_the_subject() {
    let tx = beside_proven();
    let id = tx.id();
    for bytes in [tx.to_beef(true).unwrap(), tx.to_beef_v1(true).unwrap()] {
        assert_eq!(
            Transaction::from_beef(&bytes, None).unwrap().id(),
            id,
            "the no-txid read takes the last entry: the subject"
        );
        assert_eq!(
            Transaction::from_beef(&bytes, Some(&id)).unwrap().id(),
            id,
            "the named read"
        );
        assert_eq!(
            Beef::from_binary(&bytes)
                .unwrap()
                .txs
                .last()
                .unwrap()
                .txid(),
            id,
            "the subject is written last"
        );
    }
}

/// The reference writes the same bytes: this crate's `to_beef_v1` is
/// byte-equal to the reference's `toBEEF` on every witness, `to_beef` the
/// same entries in the same order under the V2 word and its per-entry
/// format bytes, and the reference's own bytes read back the subject
/// through this crate's readers. `BEEF_TX_ORDER_PRINT=1` prints the
/// witnesses (`<name> <v1 hex> <subject txid>`), the input of
/// `tests/support/beef_tx_order.mjs`.
#[test]
fn the_reference_writes_the_same_bytes_on_every_witness() {
    let print = std::env::var("BEEF_TX_ORDER_PRINT").is_ok();
    let recorded = if print { HashMap::new() } else { recorded() };
    assert_eq!(
        recorded.len(),
        if print { 0 } else { witnesses().len() },
        "one record per witness"
    );
    for (name, tx) in witnesses() {
        let id = tx.id();
        let v1 = tx.to_beef_v1(true).unwrap();
        if print {
            println!("{name} {} {id}", to_hex(&v1));
            continue;
        }
        let w = &recorded[name];
        let reference = w["reference_tx_door_hex"].as_str().unwrap();
        assert_eq!(
            to_hex(&v1),
            w["hex"].as_str().unwrap(),
            "{name}: this crate's v1 bytes are the recorded ones"
        );
        assert_eq!(
            to_hex(&v1),
            reference,
            "{name}: the reference's toBEEF writes the same bytes"
        );
        assert_eq!(
            Transaction::from_beef(&from_hex(reference).unwrap(), None)
                .unwrap()
                .id(),
            id,
            "{name}: the reference's bytes read back the subject"
        );
        let v2 = tx.to_beef(true).unwrap();
        assert_eq!(
            Beef::from_binary(&v2)
                .unwrap()
                .txs
                .iter()
                .map(|t| t.txid().to_string())
                .collect::<Vec<_>>(),
            Beef::from_binary(&v1)
                .unwrap()
                .txs
                .iter()
                .map(|t| t.txid().to_string())
                .collect::<Vec<_>>(),
            "{name}: to_beef writes the same entries in the same order under the V2 word"
        );
        assert_eq!(
            Transaction::from_beef(&v2, None).unwrap().id(),
            id,
            "{name}: the v2 no-txid read"
        );
        assert_eq!(
            Beef::from_binary(&v1).unwrap().verify_valid(true).valid,
            recorded[name]["reference_valid"].as_bool().unwrap(),
            "{name}: the reference's verdict on this crate's bytes"
        );
    }
}

/// A BEEF a caller assembles by hand keeps the documented dependency sort,
/// as the reference's `Beef.toBinary` still sorts it: the hand-assembled
/// graph's bytes are the reference's sorted ones, and where the subject's
/// closure rests on a missing source beside a proven entry the sorted order
/// writes the subject before the proven root — the no-txid read of those
/// bytes takes the last entry, not the subject, as every version before
/// 0.8.8 read what the transaction doors wrote.
#[test]
fn a_caller_assembled_beef_keeps_the_documented_dependency_sort() {
    let recorded = recorded();
    for (name, tx) in witnesses() {
        let id = tx.id();
        let sorted = assembled_by_hand(&tx);
        assert_eq!(
            to_hex(&sorted),
            recorded[name]["reference_beef_sorted_hex"]
                .as_str()
                .unwrap(),
            "{name}: the assembled door writes the reference's dependency order"
        );
        let last = Transaction::from_beef(&sorted, None).unwrap().id();
        if name == "beside_proven" {
            assert_ne!(last, id, "{name}: the sorted order is not the subject's");
        } else {
            assert_eq!(
                last, id,
                "{name}: an honest graph's order keeps the subject"
            );
        }
        assert_eq!(
            Transaction::from_beef(&sorted, Some(&id)).unwrap().id(),
            id,
            "{name}: the named read of the sorted bytes"
        );
    }
}

/// What every version before 0.8.8 wrote at the transaction doors still
/// reads: the dependency order of the same entries, read by both readers
/// and judged by the same verdict — the named read takes the subject, the
/// no-txid read takes the last entry the order wrote.
#[test]
fn what_a_version_before_0_8_8_wrote_still_reads() {
    let recorded = recorded();
    for (name, tx) in witnesses() {
        let id = tx.id();
        let held = tx.to_beef(true).unwrap();
        let sorted = sorted_bytes(&held);
        assert_eq!(
            Transaction::from_beef(&sorted, Some(&id)).unwrap().id(),
            id,
            "{name}: the named read of the old order"
        );
        let last = Transaction::from_beef(&sorted, None).unwrap().id();
        if name == "beside_proven" {
            assert_ne!(last, id, "{name}: the old order's no-txid read, unchanged");
        } else {
            assert_eq!(last, id, "{name}: an honest graph's old order");
        }
        assert_eq!(
            Beef::from_binary(&sorted).unwrap().verify_valid(true).valid,
            recorded[name]["reference_valid"].as_bool().unwrap(),
            "{name}: the old order carries the same verdict"
        );
    }
}

/// A merged BEEF keeps the documented dependency sort: `merge_beef` into a
/// fresh BEEF, then `to_binary`, writes the dependency order of the same
/// entries (the reference's `mergeBeef` merges the held order and its
/// `toBinary` sorts what it holds).
#[test]
fn a_merged_beef_keeps_the_documented_dependency_sort() {
    for (name, tx) in witnesses() {
        let id = tx.id();
        let held = tx.to_beef(true).unwrap();
        let mut target = Beef::new();
        target.merge_beef(&Beef::from_binary(&held).unwrap());
        let merged = target.to_binary();
        assert_eq!(
            Beef::from_binary(&merged)
                .unwrap()
                .txs
                .iter()
                .map(BeefTx::txid)
                .collect::<Vec<_>>(),
            Beef::from_binary(&sorted_bytes(&held))
                .unwrap()
                .txs
                .iter()
                .map(BeefTx::txid)
                .collect::<Vec<_>>(),
            "{name}: the merged door writes the dependency order"
        );
        let last = Transaction::from_beef(&merged, None).unwrap().id();
        if name == "beside_proven" {
            assert_ne!(last, id, "{name}: the merged order is not the subject's");
        } else {
            assert_eq!(last, id, "{name}: an honest graph's merged order");
        }
    }
}

/// The atomic doors take the subject beside a proven ancestor: the atomic
/// word names it, so the reader that honors it has never been misled, at any
/// version; since 0.8.8 the transaction door's closure ends with the
/// subject (the sorted closure, the subject moved last), so the no-txid read
/// of its bytes takes it too (a no-txid `from_beef` of the bytes misread
/// before `0.3.20`, which is when the reader began honoring the word).
#[test]
fn the_atomic_doors_take_the_subject_beside_a_proven_ancestor() {
    let tx = beside_proven();
    let id = tx.id();
    let atomic = tx.to_atomic_beef(true).unwrap();
    assert_eq!(
        Transaction::from_atomic_beef(&atomic).unwrap().id(),
        id,
        "the atomic word names the subject"
    );
    assert_eq!(
        Transaction::from_beef(&atomic, None).unwrap().id(),
        id,
        "the no-txid read of atomic bytes takes the atomic word's subject"
    );
}

/// A random script of the sweep's population (`n` bytes after `OP_1`).
fn generated_script(r: &mut R) -> Vec<u8> {
    let n = r.b(6) as usize;
    let mut v = vec![0x51];
    for _ in 0..n {
        v.push(0x51 + r.b(16) as u8);
    }
    v
}

/// A random output of the sweep's population.
fn generated_output(r: &mut R) -> TransactionOutput {
    TransactionOutput::new(
        1 + r.b(100_000),
        LockingScript::from_binary(&generated_script(r)).unwrap(),
    )
}

/// A generated root of the sweep's population, its draw order the sweep's:
/// one absent-source input (a random txid and output), one or more outputs,
/// proven with odds 1/2 under MODE 1 (never under MODE 0).
fn generated_root(r: &mut R, mode: u32) -> Transaction {
    let mut t = Transaction::new();
    let mut txid = String::new();
    for _ in 0..32 {
        txid.push_str(&format!("{:02x}", r.b(256)));
    }
    let mut input = TransactionInput::new(txid, r.b(4) as u32);
    input.unlocking_script = Some(UnlockingScript::from_binary(&generated_script(r)).unwrap());
    t.inputs.push(input);
    for _ in 0..1 + r.b(3) {
        t.outputs.push(generated_output(r));
    }
    if mode == 1 && r.b(2) == 0 {
        let id = t.id();
        t.merkle_path = Some(
            MerklePath::new(
                800_000 + r.b(1000) as u32,
                vec![vec![MerklePathLeaf::new_txid(0, id)]],
            )
            .unwrap(),
        );
    }
    t
}

/// A generated link of the sweep's population: an input spending a random
/// output of `src`, a one-byte unlock, a random sequence.
fn generated_link(r: &mut R, src: &Transaction) -> TransactionInput {
    let mut i = TransactionInput::with_source_transaction(
        src.clone(),
        r.b(src.outputs.len() as u64) as u32,
    );
    i.source_txid = Some(src.id());
    i.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    i.sequence = if r.b(2) == 0 {
        0xffffffff
    } else {
        r.b(1 << 32) as u32
    };
    i
}

/// A generated mid of the sweep's population: one to three roots, outputs.
fn generated_mid(r: &mut R, mode: u32) -> Transaction {
    let mut t = Transaction::new();
    for _ in 0..1 + r.b(2) {
        let s = generated_root(r, mode);
        t.inputs.push(generated_link(r, &s));
    }
    for _ in 0..1 + r.b(3) {
        t.outputs.push(generated_output(r));
    }
    t
}

/// A generated subject of the sweep's population: one to four mids, outputs
/// (the sweep's draw order, seed `0x869f_01d4`).
fn generated_subject(r: &mut R, mode: u32) -> Transaction {
    let mut c = Transaction::new();
    c.version = 1 + r.b(2) as u32;
    c.lock_time = r.b(500_000) as u32;
    for _ in 0..1 + r.b(3) {
        let m = generated_mid(r, mode);
        c.inputs.push(generated_link(r, &m));
    }
    for _ in 0..1 + r.b(3) {
        c.outputs.push(generated_output(r));
    }
    c
}

/// A generated single-root tree of the differential's population: one root
/// (proven on even graphs), one to four mids each spending one or two
/// outputs of the root or an earlier mid, the subject spending one to three
/// outputs of any of them (seed `0xd1ff_c0de_2026`).
fn generated_tree(r: &mut R, i: u64) -> Transaction {
    let mut root = Transaction::new();
    let mut input = TransactionInput::new(format!("{i:02x}{}", "7a".repeat(31)), r.b(4) as u32);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    root.inputs.push(input);
    for o in 0..1 + r.b(3) as usize {
        root.outputs.push(TransactionOutput::new(
            1000 + o as u64,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
    }
    if i.is_multiple_of(2) {
        let id = root.id();
        root.merkle_path = Some(
            MerklePath::new(
                800_000 + (i % 1000) as u32,
                vec![vec![MerklePathLeaf::new_txid(0, id)]],
            )
            .unwrap(),
        );
    }
    let mut nodes = vec![root];
    let mut pool: Vec<(usize, u32)> = (0..nodes[0].outputs.len()).map(|o| (0, o as u32)).collect();
    for _ in 0..1 + r.b(4) {
        let mut mid = Transaction::new();
        for _ in 0..1 + r.b(2) {
            let (ni, oi) = pool[r.b(pool.len() as u64) as usize];
            mid.inputs.push(link(&nodes[ni], oi));
        }
        for o in 0..1 + r.b(3) as usize {
            mid.outputs.push(TransactionOutput::new(
                500 + o as u64,
                LockingScript::from_binary(&[0x51]).unwrap(),
            ));
        }
        let at = nodes.len();
        pool.extend((0..mid.outputs.len()).map(|o| (at, o as u32)));
        nodes.push(mid);
    }
    let mut subject = Transaction::new();
    subject.version = 1 + r.b(2) as u32;
    subject.lock_time = r.b(500_000) as u32;
    for _ in 0..1 + r.b(3) {
        let (ni, oi) = pool[r.b(pool.len() as u64) as usize];
        subject.inputs.push(link(&nodes[ni], oi));
    }
    for o in 0..1 + r.b(3) as usize {
        subject.outputs.push(TransactionOutput::new(
            250 + o as u64,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
    }
    subject
}

/// The counts of a property corpus: how many graphs the dependency sort
/// would write differently than the collected order (`divergent`), how many
/// of those move the subject off the wire's last entry (`misordered`), and
/// how many it leaves byte-equal (`stable`).
#[derive(Default)]
struct Corpus {
    divergent: usize,
    misordered: usize,
    stable: usize,
}

/// One graph through every door: both transaction doors end with the subject
/// (the no-txid read returns it, the named read returns it, the parsed last
/// entry is it), and the atomic word names it.
fn one_graph_holds_the_invariant(tx: &Transaction, corpus: &mut Corpus) {
    let id = tx.id();
    for bytes in [tx.to_beef(true).unwrap(), tx.to_beef_v1(true).unwrap()] {
        assert_eq!(
            Transaction::from_beef(&bytes, None).unwrap().id(),
            id,
            "the no-txid read takes the subject"
        );
        assert_eq!(
            Transaction::from_beef(&bytes, Some(&id)).unwrap().id(),
            id,
            "the named read takes the subject"
        );
        assert_eq!(
            Beef::from_binary(&bytes)
                .unwrap()
                .txs
                .last()
                .unwrap()
                .txid(),
            id,
            "the subject is written last"
        );
    }
    let atomic = tx.to_atomic_beef(true).unwrap();
    assert_eq!(
        Transaction::from_atomic_beef(&atomic).unwrap().id(),
        id,
        "the atomic door takes the subject"
    );
    let held = tx.to_beef(true).unwrap();
    let sorted = sorted_bytes(&held);
    if sorted != held {
        corpus.divergent += 1;
        if Transaction::from_beef(&sorted, None).unwrap().id() != id {
            corpus.misordered += 1;
        }
    } else {
        corpus.stable += 1;
    }
}

/// Generated graphs of the finding's population — a root proven with odds
/// 1/2 beside a root resting on a missing source — end with the subject at
/// every door. Until 0.8.8 the sort wrote the subject before a proven
/// ancestor in most of this corpus (the sweep that measured the reach:
/// 1,259 of 2,000 misread at this seed on 0.8.7); the floors hold the
/// corpus to that population, so the property is never vacuous.
#[test]
fn generated_graphs_beside_proven_ancestors_end_with_the_subject() {
    let mut r = R(0x869f_01d4);
    let mut corpus = Corpus::default();
    for _ in 0..200 {
        one_graph_holds_the_invariant(&generated_subject(&mut r, 1), &mut corpus);
    }
    println!(
        "mode 1: divergent {}, misordered {}, stable {}",
        corpus.divergent, corpus.misordered, corpus.stable
    );
    assert!(
        corpus.misordered >= 60,
        "the corpus holds the finding's shape (measured {})",
        corpus.misordered
    );
    assert!(
        corpus.divergent >= 60,
        "the corpus holds graphs the sort writes differently (measured {})",
        corpus.divergent
    );
    assert!(
        corpus.stable >= 5,
        "the corpus holds honest graphs the sort leaves alone (measured {})",
        corpus.stable
    );
}

/// Generated graphs of missing roots only (no proven entry) end with the
/// subject at every door, and the dependency order does too: such a graph
/// was never misread, at any version (the sweep's 0 of 2,000), and the fix
/// leaves its reads alone. The bytes may still differ from the collected
/// order (the sort gathers the missing roots first), the floors hold that
/// the corpus holds both classes.
#[test]
fn generated_graphs_of_missing_roots_end_with_the_subject() {
    let mut r = R(0x869f_01d4);
    let mut corpus = Corpus::default();
    for _ in 0..200 {
        one_graph_holds_the_invariant(&generated_subject(&mut r, 0), &mut corpus);
    }
    println!(
        "mode 0: divergent {}, misordered {}, stable {}",
        corpus.divergent, corpus.misordered, corpus.stable
    );
    assert_eq!(
        corpus.misordered, 0,
        "a graph with no proven entry was never misread (measured {} divergent)",
        corpus.divergent
    );
    assert!(
        corpus.divergent >= 60,
        "the corpus holds graphs the sort writes differently (measured {})",
        corpus.divergent
    );
    assert!(
        corpus.stable >= 5,
        "the corpus holds honest graphs the sort leaves alone (measured {})",
        corpus.stable
    );
}

/// The fix leaves an honest single-root tree alone: its collected order is
/// its dependency order (the root first, the mids as the walk collected
/// them, the subject last), so both doors write the bytes every version
/// before 0.8.8 wrote for such a tree, and every read still takes the
/// subject. A differential over 20,000 of these trees (this seed, `i` from
/// 0 to 19,999, half proven roots) found the fix's bytes and reads equal to
/// the base's by one digest.
#[test]
fn generated_single_root_trees_write_the_dependency_order() {
    let mut r = R(0xd1ff_c0de_2026);
    for i in 0..200 {
        let tx = generated_tree(&mut r, i);
        let id = tx.id();
        for bytes in [tx.to_beef(true).unwrap(), tx.to_beef_v1(true).unwrap()] {
            assert_eq!(
                bytes,
                sorted_bytes(&bytes),
                "graph {i}: the collected order is the dependency order"
            );
            assert_eq!(
                Transaction::from_beef(&bytes, None).unwrap().id(),
                id,
                "the no-txid read takes the subject"
            );
        }
    }
}

/// The plain doors write their own version words: `to_beef` the V2 word,
/// `to_beef_v1` the V1 word, the atomic door the Atomic BEEF word (a
/// helper that assembled the closure under the wrong word — or a door that
/// reaches the wrong helper — is red here; the words, not the entries, are
/// what a reader dispatches on).
#[test]
fn the_plain_doors_write_their_version_words() {
    let tx = beside_proven();
    let v2 = tx.to_beef(true).unwrap();
    let v1 = tx.to_beef_v1(true).unwrap();
    let atomic = tx.to_atomic_beef(true).unwrap();
    assert_eq!(
        u32::from_le_bytes(v2[0..4].try_into().unwrap()),
        BEEF_V2,
        "to_beef writes the V2 word"
    );
    assert_eq!(
        u32::from_le_bytes(v1[0..4].try_into().unwrap()),
        BEEF_V1,
        "to_beef_v1 writes the V1 word"
    );
    assert_eq!(
        u32::from_le_bytes(atomic[0..4].try_into().unwrap()),
        ATOMIC_BEEF,
        "to_atomic_beef writes the Atomic BEEF word"
    );
    assert_ne!(
        u32::from_le_bytes(v1[0..4].try_into().unwrap()),
        BEEF_V2,
        "the two plain doors are apart in their words alone"
    );
}

/// The atomic door's bytes on the finding's shape, pinned: the closure in
/// the dependency sort with the subject moved last — each entry's sources
/// above it, the subject last (where the closure's sort alone writes the
/// subject mid-list on this shape).
#[test]
fn the_atomic_bytes_of_the_finding_shape_are_pinned() {
    let tx = beside_proven();
    let atomic = tx.to_atomic_beef(true).unwrap();
    if std::env::var("BEEF_TX_ORDER_PRINT").is_ok() {
        println!("atomic_beside_proven {}", to_hex(&atomic));
    }
    assert_eq!(
        to_hex(&atomic),
        "01010101634f04c4ed505d66cee7dd91087eafe49d1fbcd5f4e3b01f39a320f3355592060200beef01fe01350c00010100021c603b733b4c156f5463165531c16c7b432b0025210664dc668f8c2242f0fba3050001000000015e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e02020000000151ffffffff01ea03000000000000015102000000000100000001ecdc695f30bbe1cafa53ee6904445fadbd9e3c7cc45481ed757eeed0c21e4287000000000151ffffffff010802000000000000015114000000010001000000015e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e01010000000151ffffffff01e9030000000000000151010000000001000000011c603b733b4c156f5463165531c16c7b432b0025210664dc668f8c2242f0fba3000000000151ffffffff01fe0100000000000001510a000000000200000002535e83c497247e3c72a92b77bc3fd4a2dd4ae3288818d5e506bd7f06ed2b880a000000000151ffffffff454e4cf286fe5d8016ae0039904cbb7370f7c25c8df72e7cdb1e9d8076b0c486000000000151ffffffff01fa00000000000000015143420000",
        "the atomic door ends its closure with the subject on the finding's shape"
    );
    // The closure ends with the subject, and the entries read back.
    let beef = Beef::from_binary(&atomic).unwrap();
    assert_eq!(
        beef.txs.last().unwrap().txid(),
        tx.id(),
        "the closure's last entry is the subject"
    );
    assert!(
        beef.txs.len() >= 4,
        "the finding's shape holds both branches in the closure"
    );
}

/// The atomic closure of `subject` as the Beef-level door sorts it, for the
/// same graph assembled by hand: the closure's entry txids in written order.
fn beef_level_atomic_order(subject: &Transaction) -> Vec<String> {
    let entries = ancestry(subject);
    let mut beef = Beef::with_version(BEEF_V2);
    let mut bump_of: HashMap<String, usize> = HashMap::new();
    for tx in &entries {
        if let Some(path) = &tx.merkle_path {
            bump_of.insert(tx.id(), beef.merge_bump(path.clone()));
        }
    }
    for tx in &entries {
        beef.txs
            .push(BeefTx::from_tx(tx.clone(), bump_of.get(&tx.id()).copied()));
    }
    let atomic = beef.to_binary_atomic(&subject.id()).unwrap();
    let closure = Beef::from_binary(&atomic).unwrap();
    closure.txs.iter().map(|t| t.txid()).collect()
}

/// The transaction door's atomic order on one graph, checked: its closure is
/// the Beef-level door's sort of the same graph with the subject moved last,
/// and its BUMPs and entries those of the Beef-level door. Answers whether
/// the closure's collected order differs from that one (the cell's reach).
fn atomic_door_order_holds(name: &str, tx: &Transaction) -> bool {
    let id = tx.id();
    let atomic = tx.to_atomic_beef(true).unwrap();
    let written: Vec<String> = Beef::from_binary(&atomic)
        .unwrap()
        .txs
        .iter()
        .map(|t| t.txid())
        .collect();
    let mut expected: Vec<String> = beef_level_atomic_order(tx)
        .into_iter()
        .filter(|t| t != &id)
        .collect();
    expected.push(id.clone());
    assert_eq!(
        written, expected,
        "{name}: the atomic door writes the sorted closure, the subject moved last"
    );
    let collected: Vec<String> = ancestry(tx)
        .iter()
        .map(|t| t.id())
        .filter(|t| written.contains(t))
        .collect();
    collected != written
}

/// Two proven branches, fully linked: an honest graph whose collected order
/// is not the dependency order (the walk interleaves the branches; the sort
/// writes both proven roots first).
fn two_proven_branches() -> Transaction {
    let root_a = root(true, 8);
    let root_b = root(true, 9);
    let mid_a = mid(&[root_a], 90);
    let mid_b = mid(&[root_b], 100);
    subject(&[mid_a, mid_b])
}

/// The atomic door's order on every shape: the sorted closure, the subject
/// moved last — never the collected order where the two differ, so an
/// honest graph of two proven branches keeps the bytes the atomic door wrote
/// before 0.8.8, and never the sort alone, so the subject is the last entry.
/// The cell counts the graphs on which the collected order would write
/// otherwise, so it cannot go vacuous.
#[test]
fn the_atomic_door_writes_the_sorted_closure_with_the_subject_last() {
    let mut differ = 0;
    for (name, tx) in witnesses() {
        differ += usize::from(atomic_door_order_holds(name, &tx));
    }
    let two = atomic_door_order_holds("two_proven_branches", &two_proven_branches());
    assert!(
        two,
        "two proven branches: the collected order is not the written one"
    );
    differ += usize::from(two);
    for mode in [0, 1] {
        let mut r = R(0x869f_01d4);
        for _ in 0..200 {
            differ += usize::from(atomic_door_order_holds(
                "generated",
                &generated_subject(&mut r, mode),
            ));
        }
    }
    let mut r = R(0xd1ff_c0de_2026);
    for i in 0..200 {
        differ += usize::from(atomic_door_order_holds("tree", &generated_tree(&mut r, i)));
    }
    println!("atomic: the collected order differs on {differ}");
    assert_eq!(differ, 280, "the graphs whose collected closure differs");
}

/// `Beef::to_writer` writes a BEEF it is given in the order it holds, never
/// sorted (the held order every door assembles): the same graph hand-built
/// in the collected order, written through `to_writer`, is byte-equal to
/// the transaction door's held bytes — the door's `to_binary` on a held
/// BEEF and `to_writer` walk the same entries.
#[test]
fn a_held_beef_written_by_to_writer_keeps_the_collected_order() {
    for (name, tx) in witnesses() {
        let entries = ancestry(&tx);
        let mut beef = Beef::with_version(BEEF_V2);
        let mut bump_of: HashMap<String, usize> = HashMap::new();
        for t in &entries {
            if let Some(path) = &t.merkle_path {
                bump_of.insert(t.id(), beef.merge_bump(path.clone()));
            }
        }
        for t in &entries {
            beef.txs
                .push(BeefTx::from_tx(t.clone(), bump_of.get(&t.id()).copied()));
        }
        let mut writer = bsv_rs::primitives::Writer::new();
        beef.to_writer(&mut writer);
        assert_eq!(
            writer.into_bytes(),
            tx.to_beef(true).unwrap(),
            "{name}: to_writer writes the collected order, as the door's held bytes"
        );
    }
}

/// The committed fuzz seed for the shape, replayed through the no-txid read:
/// the seed is a BEEF of the finding's population written by the transaction
/// door, so a read that names no txid takes the subject back. The cell keeps
/// the seed's shape recurring — a seed removed or emptied is red here — the
/// companion of the fuzz target's round-trip check, which a mutant that
/// swaps the read for the named one leaves green.
#[test]
fn the_committed_fuzz_seed_reads_the_subject() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/corpus/fuzz_beef_parser/tx-door-order"
    );
    let bytes = std::fs::read(path).expect("the seed is committed");
    let tx = Transaction::from_beef(&bytes, None).expect("the seed is a BEEF of the shape");
    let id = tx.id();
    assert_eq!(
        Beef::from_binary(&bytes)
            .unwrap()
            .txs
            .last()
            .unwrap()
            .txid(),
        id,
        "the seed's last entry is the subject the door wrote"
    );
    for round in [
        tx.to_beef(true).unwrap(),
        tx.to_beef_v1(true).unwrap(),
        tx.to_atomic_beef(true).unwrap(),
    ] {
        assert_eq!(
            Transaction::from_beef(&round, None).unwrap().id(),
            id,
            "every door re-serializes the seed's subject and reads it back"
        );
    }
}

/// Two proven roots under one BUMP (a level-0 path of two leaves): a shape
/// no cell had built, where the door's BUMP-combine path returns both roots
/// one index and the atomic closure's renumbering shares it between them.
/// Every door reads the subject back; the atomic closure holds the one BUMP
/// and both roots naming it.
#[test]
fn two_proven_roots_under_one_bump_read_through_every_door() {
    let mut root_a = root(true, 6);
    let mut root_b = root(true, 7);
    let shared = MerklePath::new(
        800_007,
        vec![vec![
            MerklePathLeaf::new_txid(0, root_a.id()),
            MerklePathLeaf::new_txid(1, root_b.id()),
        ]],
    )
    .unwrap();
    root_a.merkle_path = Some(shared.clone());
    root_b.merkle_path = Some(shared);
    let mid_a = mid(&[root_a.clone()], 70);
    let mid_b = mid(&[root_b.clone()], 80);
    let tx = subject(&[mid_a, mid_b]);
    let id = tx.id();
    for bytes in [
        tx.to_beef(true).unwrap(),
        tx.to_beef_v1(true).unwrap(),
        tx.to_atomic_beef(true).unwrap(),
    ] {
        assert_eq!(
            Transaction::from_beef(&bytes, None).unwrap().id(),
            id,
            "the no-txid read takes the subject of a two-root BUMP"
        );
    }
    let atomic = tx.to_atomic_beef(true).unwrap();
    let beef = Beef::from_binary(&atomic).unwrap();
    assert_eq!(
        beef.bumps.len(),
        1,
        "the two roots share the one renumbered BUMP"
    );
    let index_of = |wanted: &String| {
        beef.txs
            .iter()
            .find(|t| &t.txid() == wanted)
            .unwrap()
            .bump_index()
    };
    assert_eq!(
        index_of(&root_a.id()),
        index_of(&root_b.id()),
        "both roots name the one BUMP"
    );
    assert!(
        index_of(&root_a.id()).is_some(),
        "the shared BUMP is carried, not dropped"
    );
}

/// The property corpora hold the measured counts (the 817 sweeps' form): the
/// two property cells hold floors, this cell re-derives the corpora and
/// holds the exact counts, so a generator degraded below a floor stays red
/// here with the floors gone.
#[test]
fn the_property_corpora_hold_the_measured_counts() {
    let mut r = R(0x869f_01d4);
    let mut one = Corpus::default();
    for _ in 0..200 {
        one_graph_holds_the_invariant(&generated_subject(&mut r, 1), &mut one);
    }
    let mut r = R(0x869f_01d4);
    let mut zero = Corpus::default();
    for _ in 0..200 {
        one_graph_holds_the_invariant(&generated_subject(&mut r, 0), &mut zero);
    }
    assert_eq!(
        (one.divergent, one.misordered, one.stable),
        (156, 128, 44),
        "mode 1: the finding's population, the sweep's counts"
    );
    assert_eq!(
        (zero.divergent, zero.misordered, zero.stable),
        (134, 0, 66),
        "mode 0: missing roots only, never misread"
    );
}
