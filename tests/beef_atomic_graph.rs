//! The atomic BEEF rule on the subject's graph (0.8.1, BRC-95).
//!
//! BRC-95 defines the rule on the dependency graph: the subject is a
//! transaction of the BEEF, every other transaction is in its graph, and
//! nothing else is present. It says nothing about order. The TypeScript
//! writer (`@bsv/sdk` 2.1.4 `Beef.sortTxs` / `partitionTxs`) puts every
//! proven transaction first in encounter order and the unproven ones after,
//! in dependency order, so a raw unproven ancestor can follow its proven
//! descendant; the Go writer puts dependencies first and the subject last.
//! Until 0.8.0 both readers of this crate marked a parent only when it was
//! read before its child and refused the TypeScript shape (the bsv-dd x402
//! refund, P0-65). Here one atomic BEEF is written in every order the BRC-62
//! clause allows (an unproven transaction after the transactions it spends)
//! and both readers, the streaming one with and without its spend checks and
//! the whole one, give one verdict on each.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::{HashMap, HashSet};

use bsv_rs::primitives::{from_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::{
    verify_stream, verify_stream_structure, Hash32, HeadersFn, Kind, Reason, Verdict,
};
use bsv_rs::transaction::{
    resume, Beef, Cursor, MerklePath, Progress, StreamVerifier, Transaction, TransactionInput,
    TransactionOutput, ATOMIC_BEEF, BEEF_V1,
};

/// A transaction of the graph: its name, its raw bytes, its txid (display
/// hex), and its BUMP's index when it is proven.
#[derive(Clone)]
struct Node {
    name: &'static str,
    raw: Vec<u8>,
    txid: String,
    bump: Option<usize>,
    /// The names of the transactions of the graph its inputs spend.
    spends: Vec<&'static str>,
}

/// A transaction with an `OP_TRUE` output per amount, spending `inputs`
/// (txid, vout) with empty unlocking scripts.
fn tx(inputs: &[(&str, u32)], amounts: &[u64]) -> Transaction {
    let mut t = Transaction::new();
    for (txid, vout) in inputs {
        let mut input = TransactionInput::new(txid.to_string(), *vout);
        input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
        t.inputs.push(input);
    }
    for amount in amounts {
        t.outputs.push(TransactionOutput::new(
            *amount,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
    }
    t
}

fn internal(txid: &str) -> Hash32 {
    let mut h: Hash32 = from_hex(txid).unwrap().try_into().unwrap();
    h.reverse();
    h
}

/// The graph, subject `S`:
///
/// ```text
/// Z (proven) ──0──> A (raw) ──0──> P (proven) ──0──> S (raw, the subject)
///   └──────────1──────────> C (raw) ─────────0────────┘
/// V (proven) ──0──> W (proven) ─────────0─────────────┘
/// ```
///
/// `A` is a raw unproven ancestor of the proven `P`, and nothing else
/// spends it (the bsv-dd shape); `V` and `W` are a proven parent and a
/// proven child; `Z`, `V` and `A` are spent by no input of `S`, so they may
/// sit after it.
struct Graph {
    nodes: Vec<Node>,
    bumps: Vec<MerklePath>,
}

impl Graph {
    fn build() -> Self {
        let mut nodes = Vec::new();
        let mut bumps = Vec::new();
        let mut add = |name, t: Transaction, proven: bool, spends: Vec<&'static str>| {
            let txid = t.id();
            let bump = proven.then(|| {
                // A block of one transaction: the lone leaf at offset 0, one
                // block height per proven transaction.
                bumps.push(MerklePath::from_coinbase_txid(
                    &txid,
                    900_000 + bumps.len() as u32,
                ));
                bumps.len() - 1
            });
            nodes.push(Node {
                name,
                raw: t.to_binary(),
                txid: txid.clone(),
                bump,
                spends,
            });
            txid
        };
        let z = add(
            "Z",
            tx(&[(&"2a".repeat(32), 0)], &[1_000, 500, 5]),
            true,
            vec![],
        );
        let v = add("V", tx(&[(&"2b".repeat(32), 0)], &[1_000]), true, vec![]);
        let a = add("A", tx(&[(&z, 0)], &[400]), false, vec!["Z"]);
        let p = add("P", tx(&[(&a, 0)], &[350]), true, vec!["A"]);
        let w = add("W", tx(&[(&v, 0)], &[900]), true, vec!["V"]);
        let c = add("C", tx(&[(&z, 1)], &[300]), false, vec!["Z"]);
        add(
            "S",
            tx(&[(&p, 0), (&c, 0), (&w, 0)], &[1_000]),
            false,
            vec!["P", "C", "W"],
        );
        Self { nodes, bumps }
    }

    fn node(&self, name: &str) -> &Node {
        self.nodes.iter().find(|n| n.name == name).unwrap()
    }

    fn subject(&self) -> Hash32 {
        internal(&self.node("S").txid)
    }

    /// The headers: each BUMP's root at its height.
    fn roots(&self) -> HashMap<u64, Hash32> {
        self.bumps
            .iter()
            .map(|b| {
                (
                    u64::from(b.block_height),
                    internal(&b.compute_root(None).unwrap()),
                )
            })
            .collect()
    }
}

/// An entry of a written BEEF: a node, or a txid-only entry.
#[derive(Clone)]
enum Entry<'a> {
    Raw(&'a Node),
    TxidOnly(String),
}

/// An atomic BEEF V1 (V2 when it holds a txid-only entry) naming `subject`,
/// with `entries` in the order given and no sort.
fn write(subject: &Hash32, bumps: &[MerklePath], entries: &[Entry]) -> Vec<u8> {
    let v2 = entries.iter().any(|e| matches!(e, Entry::TxidOnly(_)));
    let mut w = Writer::new();
    w.write_u32_le(ATOMIC_BEEF);
    w.write_bytes(subject);
    w.write_u32_le(if v2 {
        bsv_rs::transaction::BEEF_V2
    } else {
        BEEF_V1
    });
    w.write_var_int(bumps.len() as u64);
    for bump in bumps {
        w.write_bytes(&bump.to_binary());
    }
    w.write_var_int(entries.len() as u64);
    for entry in entries {
        match entry {
            Entry::Raw(node) => {
                if v2 {
                    w.write_u8(if node.bump.is_some() { 1 } else { 0 });
                    if let Some(i) = node.bump {
                        w.write_var_int(i as u64);
                    }
                    w.write_bytes(&node.raw);
                } else {
                    w.write_bytes(&node.raw);
                    match node.bump {
                        Some(i) => {
                            w.write_u8(1);
                            w.write_var_int(i as u64);
                        }
                        None => {
                            w.write_u8(0);
                        }
                    }
                }
            }
            Entry::TxidOnly(txid) => {
                w.write_u8(2);
                w.write_bytes(&internal(txid));
            }
        }
    }
    w.into_bytes()
}

/// The verdicts of the readers: the stream's (structure only), the stream's
/// (with its spend checks), the whole path's `verify_structure` and its
/// `verify_valid`. Ok(()) or the kind.
fn verdicts(bytes: &[u8], roots: &HashMap<u64, Hash32>) -> [Result<(), Kind>; 4] {
    let stream = |v: Verdict| match v {
        Verdict::Valid { .. } => Ok(()),
        Verdict::Invalid { kind, .. } => Err(kind),
        other => panic!("a verdict on the bytes expected, got {other:?}"),
    };
    let structure = stream(verify_stream_structure(bytes, roots, None).unwrap());
    let full = stream(verify_stream(bytes, roots, None).unwrap());
    let mut beef = Beef::from_binary(bytes).unwrap();
    let whole = beef.verify_structure().map(|_| ());
    let mut beef = Beef::from_binary(bytes).unwrap();
    let valid = if beef.verify_valid(false).valid {
        Ok(())
    } else {
        whole
    };
    [structure, full, whole, valid]
}

/// Every order of `items`.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, first.clone());
            all.push(tail);
        }
    }
    all
}

/// The BRC-62 clause: a transaction without a BUMP follows every
/// transaction of the BEEF it spends.
fn brc62_order(order: &[&Node]) -> bool {
    let mut seen: HashSet<&str> = HashSet::new();
    order.iter().all(|n| {
        let ok = n.bump.is_some() || n.spends.iter().all(|s| seen.contains(s));
        seen.insert(n.name);
        ok
    })
}

fn orders(graph: &Graph) -> Vec<Vec<&Node>> {
    let nodes: Vec<&Node> = graph.nodes.iter().collect();
    permutations(&nodes)
        .into_iter()
        .filter(|o| brc62_order(o))
        .collect()
}

fn names(order: &[&Node]) -> String {
    order.iter().map(|n| n.name).collect::<Vec<_>>().join(",")
}

fn raw<'a>(order: &[&'a Node]) -> Vec<Entry<'a>> {
    order.iter().map(|n| Entry::Raw(n)).collect()
}

#[test]
fn an_atomic_beef_is_accepted_by_both_readers_in_every_order_its_dependencies_allow() {
    let graph = Graph::build();
    let roots = graph.roots();
    let orders = orders(&graph);
    // 7 transactions, 3 of them unproven with their spends before them
    // (Z < A, Z < C, and C, P, W < S): 364 orders.
    assert_eq!(orders.len(), 364);
    let shapes: HashSet<String> = orders.iter().map(|o| names(o)).collect();
    // The TypeScript partition order (proven first in encounter order, then
    // unproven in dependency order): the raw unproven `A` follows its proven
    // descendant `P`.
    assert!(shapes.contains("Z,V,P,W,A,C,S"));
    // The Go order (dependencies first, the subject last).
    assert!(shapes.contains("Z,A,P,V,W,C,S"));
    // The subject not last: a raw unproven ancestor after it, or a proven
    // one.
    assert!(shapes.contains("Z,C,P,V,W,S,A"));
    assert!(shapes.contains("Z,A,P,C,W,S,V"));
    for order in &orders {
        let bytes = write(&graph.subject(), &graph.bumps, &raw(order));
        assert_eq!(
            verdicts(&bytes, &roots),
            [Ok(()), Ok(()), Ok(()), Ok(())],
            "order {}",
            names(order)
        );
    }
}

#[test]
fn a_raw_unproven_ancestor_after_its_proven_descendant_is_accepted() {
    // The bsv-dd x402 refund's shape (P0-65), alone: the TypeScript writer's
    // order, refused `UnrelatedTransaction` by both readers until 0.8.0.
    let graph = Graph::build();
    let order: Vec<&Node> = ["Z", "V", "P", "W", "A", "C", "S"]
        .iter()
        .map(|n| graph.node(n))
        .collect();
    let bytes = write(&graph.subject(), &graph.bumps, &raw(&order));
    assert_eq!(
        verify_stream(bytes.as_slice(), graph.roots(), None).unwrap(),
        Verdict::Valid {
            subject: Some(graph.subject()),
            roots: graph
                .bumps
                .iter()
                .map(|b| {
                    (
                        u64::from(b.block_height),
                        internal(&b.compute_root(None).unwrap()),
                    )
                })
                .collect()
        }
    );
    let tx = Transaction::from_atomic_beef(&bytes).unwrap();
    assert_eq!(tx.id(), graph.node("S").txid);
}

#[test]
fn a_cursor_carries_the_txids_named_before_they_were_read() {
    // The stream counts a spend by a transaction read before its parent
    // (BSC3): a cursor between the proven `P` and its raw ancestor `A` holds
    // `A` as named, and the resumed reading accepts, at every `k`.
    let graph = Graph::build();
    let roots = graph.roots();
    let order: Vec<&Node> = ["Z", "V", "P", "W", "A", "C", "S"]
        .iter()
        .map(|n| graph.node(n))
        .collect();
    let bytes = write(&graph.subject(), &graph.bumps, &raw(&order));
    // The BUMPs, then the seven transactions.
    let elements = graph.bumps.len() as u64 + order.len() as u64;
    for scripts in [false, true] {
        let whole = if scripts {
            verify_stream(bytes.as_slice(), &roots, None).unwrap()
        } else {
            verify_stream_structure(bytes.as_slice(), &roots, None).unwrap()
        };
        assert!(whole.is_valid(), "{whole:?}");
        for k in 0..=elements {
            let mut reader = if scripts {
                StreamVerifier::new(bytes.as_slice(), &roots, None)
            } else {
                StreamVerifier::structure_only(bytes.as_slice(), &roots, None)
            };
            for _ in 0..k {
                assert!(matches!(reader.step().unwrap(), Progress::Stepped));
            }
            let stored = reader.cursor().to_binary();
            assert_eq!(&stored[..4], b"BSC3");
            let cursor = Cursor::from_binary(&stored).unwrap();
            assert_eq!(cursor.to_binary(), stored);
            let rest = &bytes[cursor.offset() as usize..];
            assert_eq!(
                resume(cursor, rest, &roots).unwrap(),
                whole,
                "scripts {scripts}, k = {k}"
            );
        }
    }
}

#[test]
fn an_unrelated_entry_is_refused_by_both_readers_in_every_order() {
    // The mirror: one entry outside the subject's graph, raw proven, raw
    // unproven (spending `Z`), or txid-only (proven by its own BUMP), at every
    // position the clause allows.
    let graph = Graph::build();
    let mut bumps = graph.bumps.clone();
    let proven_stranger = tx(&[(&"2c".repeat(32), 0)], &[5]);
    bumps.push(MerklePath::from_coinbase_txid(
        &proven_stranger.id(),
        950_000,
    ));
    let proven_stranger = Node {
        name: "X",
        raw: proven_stranger.to_binary(),
        txid: proven_stranger.id(),
        bump: Some(bumps.len() - 1),
        spends: vec![],
    };
    let z = graph.node("Z").txid.clone();
    let unproven_stranger = tx(&[(&z, 2)], &[5]);
    let unproven_stranger = Node {
        name: "Y",
        raw: unproven_stranger.to_binary(),
        txid: unproven_stranger.id(),
        bump: None,
        spends: vec!["Z"],
    };
    let stub = tx(&[(&"2d".repeat(32), 0)], &[5]).id();
    bumps.push(MerklePath::from_coinbase_txid(&stub, 960_000));
    let roots: HashMap<u64, Hash32> = bumps
        .iter()
        .map(|b| {
            (
                u64::from(b.block_height),
                internal(&b.compute_root(None).unwrap()),
            )
        })
        .collect();

    let mut checked = 0;
    for (k, order) in orders(&graph).iter().enumerate() {
        for position in 0..=order.len() {
            // The three strangers in turn, so every order meets each (the unproven
            // one spends `Z`'s third output, which nothing else spends).
            let mut entries = raw(order);
            let stranger = match (k + position) % 3 {
                0 => Entry::Raw(&proven_stranger),
                1 => {
                    let z_at = order.iter().position(|n| n.name == "Z").unwrap();
                    if position <= z_at {
                        continue; // it spends `Z`: after it, or not at all
                    }
                    Entry::Raw(&unproven_stranger)
                }
                _ => Entry::TxidOnly(stub.clone()),
            };
            entries.insert(position, stranger);
            let bytes = write(&graph.subject(), &bumps, &entries);
            let [structure, full, whole, valid] = verdicts(&bytes, &roots);
            let refused = Err(Kind::UnrelatedTransaction);
            assert_eq!(
                (structure, full, whole, valid),
                (refused, refused, refused, refused),
                "order {}, a stranger at {position}",
                names(order)
            );
            checked += 1;
        }
    }
    assert!(checked > 1_000, "{checked}");
}

#[test]
fn a_subject_the_beef_does_not_carry_raw_is_missing_in_every_order() {
    let graph = Graph::build();
    let roots = graph.roots();
    let stranger = internal(&tx(&[(&"2e".repeat(32), 0)], &[1]).id());
    for order in orders(&graph) {
        let bytes = write(&stranger, &graph.bumps, &raw(&order));
        assert_eq!(
            verdicts(&bytes, &roots),
            [Err(Kind::SubjectMissing); 4],
            "order {}",
            names(&order)
        );
        // The stream names the prefix's 32 bytes.
        match verify_stream_structure(bytes.as_slice(), &roots, None).unwrap() {
            Verdict::Invalid { offset, reason, .. } => {
                assert_eq!(
                    (offset, reason),
                    (4, Reason::SubjectMissing { subject: stranger })
                )
            }
            other => panic!("{other:?}"),
        }
    }
    // A subject present only as a txid-only entry is no raw transaction of
    // the BEEF: missing too.
    let p = graph.node("P");
    let order: Vec<Entry> = vec![
        Entry::Raw(graph.node("Z")),
        Entry::Raw(graph.node("A")),
        Entry::TxidOnly(p.txid.clone()),
    ];
    let bytes = write(&internal(&p.txid), &graph.bumps, &order);
    assert_eq!(verdicts(&bytes, &roots), [Err(Kind::SubjectMissing); 4]);
}

#[test]
fn what_this_crates_writer_writes_its_own_two_readers_accept() {
    // `to_binary_atomic` writes the subject's BRC-95 closure (0.8.1): from
    // `S`, the inputs of raw entries, stopping at each proof. `P`, `W` and
    // `Z` are proven, so `A` (behind `P`) and `V` (behind `W`) are not
    // written; the order is the reference's sort, the subject last. Merged
    // in each of the 364 orders, the bytes are one BEEF, accepted by both
    // readers and by the TypeScript 3 rule.
    let graph = Graph::build();
    let roots = graph.roots();
    let subject = graph.node("S").txid.clone();
    for order in &orders(&graph) {
        let mut beef = Beef::new();
        for bump in &graph.bumps {
            beef.merge_bump(bump.clone());
        }
        for node in order {
            beef.merge_raw_tx(node.raw.clone(), node.bump);
        }
        let bytes = beef.to_binary_atomic(&subject).unwrap();
        let written = Beef::from_binary(&bytes).unwrap();
        let txids: HashSet<String> = written.txs.iter().map(|t| t.txid()).collect();
        let expected: HashSet<String> = ["S", "P", "C", "Z", "W"]
            .iter()
            .map(|n| graph.node(n).txid.clone())
            .collect();
        assert_eq!(txids, expected, "merged {}", names(order));
        assert_eq!(written.txs.last().unwrap().txid(), subject);
        assert_eq!(written.bumps.len(), 3);
        assert_eq!(
            verdicts(&bytes, &roots),
            [Ok(()), Ok(()), Ok(()), Ok(())],
            "merged {}",
            names(order)
        );
        assert!(ts3_accepts(&bytes), "merged {}", names(order));
        let tx = Transaction::from_atomic_beef(&bytes).unwrap();
        assert_eq!(tx.id(), subject);
    }
}

/// The `@bsv/sdk` 3 rule, modelled (ts-stack `4d0ea63` `Beef.ts:420-434`,
/// `isAtomic` `:482-491`): from the subject, follow the inputs of each raw
/// entry a BUMP index does not prove (a BUMP whose level 0 carries its txid)
/// and of no txid-only entry; atomic when that closure is every entry.
fn ts3_accepts(bytes: &[u8]) -> bool {
    let beef = Beef::from_binary(bytes).unwrap();
    let Some(subject) = beef.atomic_txid.clone() else {
        return false;
    };
    let at: HashMap<String, usize> = beef
        .txs
        .iter()
        .enumerate()
        .map(|(i, t)| (t.txid(), i))
        .collect();
    if at.len() != beef.txs.len() {
        return false;
    }
    let Some(&root) = at.get(&subject) else {
        return false;
    };
    let mut included = HashSet::new();
    let mut stack = vec![root];
    while let Some(i) = stack.pop() {
        if !included.insert(i) {
            continue;
        }
        let entry = &beef.txs[i];
        let proven = entry
            .bump_index()
            .and_then(|b| beef.bumps.get(b))
            .is_some_and(|b| b.contains(&entry.txid()));
        if proven || entry.is_txid_only() {
            continue;
        }
        let t = match entry.tx() {
            Some(t) => t.clone(),
            None => Transaction::from_binary(entry.raw_tx().unwrap()).unwrap(),
        };
        for input in &t.inputs {
            if let Some(&j) = at.get(&input.get_source_txid().unwrap()) {
                stack.push(j);
            }
        }
    }
    included.len() == beef.txs.len()
}

#[test]
fn the_atomic_writer_emits_the_brc95_closure_and_drops_the_rest() {
    // A Beef holding the graph (a proven parent `V` and child `W`, the raw
    // unproven `A` behind the proven `P`) and an unrelated branch (`X`
    // proven, `Y` spending it). The atomic BEEF of `S` is its closure: `A`
    // and `V` behind a proof, `X` and `Y` absent, their BUMPs dropped and
    // the rest renumbered. The non-atomic writer keeps every entry.
    let graph = Graph::build();
    let x = tx(&[(&"2f".repeat(32), 0)], &[50]);
    let y = tx(&[(&x.id(), 0)], &[40]);
    let mut bumps = graph.bumps.clone();
    bumps.insert(0, MerklePath::from_coinbase_txid(&x.id(), 990_000));
    let mut roots = graph.roots();
    roots.insert(990_000, internal(&bumps[0].compute_root(None).unwrap()));

    let mut beef = Beef::new();
    for bump in &bumps {
        beef.merge_bump(bump.clone());
    }
    beef.merge_raw_tx(x.to_binary(), Some(0));
    beef.merge_raw_tx(y.to_binary(), None);
    for node in &graph.nodes {
        beef.merge_raw_tx(node.raw.clone(), node.bump.map(|b| b + 1));
    }
    let all = beef.clone().to_binary();
    let subject = graph.node("S").txid.clone();
    let bytes = beef.to_binary_atomic(&subject).unwrap();

    let written = Beef::from_binary(&bytes).unwrap();
    let txids: Vec<String> = written.txs.iter().map(|t| t.txid()).collect();
    for absent in [
        x.id(),
        y.id(),
        graph.node("A").txid.clone(),
        graph.node("V").txid.clone(),
    ] {
        assert!(!txids.contains(&absent), "{absent} written");
    }
    assert_eq!(txids.len(), 5);
    assert_eq!(txids.last(), Some(&subject));
    // The BUMPs of `P`, `Z`, `W`, renumbered from 0; each proves its entry.
    assert_eq!(written.bumps.len(), 3);
    for entry in &written.txs {
        if let Some(b) = entry.bump_index() {
            assert!(written.bumps[b].contains(&entry.txid()));
        }
    }
    assert_eq!(verdicts(&bytes, &roots), [Ok(()), Ok(()), Ok(()), Ok(())]);
    assert!(ts3_accepts(&bytes));
    // The writer's BEEF held whole is refused as atomic by TS 3 (`A`, `V`
    // behind proofs; `X`, `Y` unrelated) and by this crate (`X`, `Y`).
    let mut whole = bytes[..36].to_vec();
    whole.extend_from_slice(&all);
    assert!(!ts3_accepts(&whole));
    assert_eq!(
        verdicts(&whole, &roots),
        [Err(Kind::UnrelatedTransaction); 4]
    );
    // The non-atomic writer is unchanged: all nine.
    assert_eq!(Beef::from_binary(&all).unwrap().txs.len(), 9);
}

#[test]
fn every_accepted_vector_round_trips_through_the_atomic_writer() {
    // The staged BRC-95 vectors: each the readers accept, read and written
    // again by `to_binary_atomic`, is accepted by both readers and by the
    // TypeScript 3 rule; the two TS 3 refuses come back as their closure.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/transaction/vectors/atomic-beef.json");
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut accepted = 0;
    for vector in file["vectors"].as_array().unwrap() {
        if vector["expected"]["valid"] != serde_json::Value::Bool(true) {
            continue;
        }
        let id = vector["id"].as_str().unwrap();
        let bytes = from_hex(vector["input"]["beef_hex"].as_str().unwrap()).unwrap();
        let roots: HashMap<u64, Hash32> = vector["input"]["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(h, r)| (h.parse().unwrap(), internal(r.as_str().unwrap())))
            .collect();
        let subject = vector["expected"]["subject_txid"].as_str().unwrap();
        let mut beef = Beef::from_binary(&bytes).unwrap();
        let again = beef.to_binary_atomic(subject).unwrap();
        assert_eq!(
            verdicts(&again, &roots),
            [Ok(()), Ok(()), Ok(()), Ok(())],
            "{id}"
        );
        assert!(ts3_accepts(&again), "{id}");
        assert_eq!(
            ts3_accepts(&bytes),
            vector["parity_class"].as_str() != Some("intended"),
            "{id}: the TS 3 model's verdict on the vector"
        );
        let written = Beef::from_binary(&again).unwrap();
        assert_eq!(written.txs.last().unwrap().txid(), subject, "{id}");
        accepted += 1;
    }
    assert_eq!(accepted, 4);
}

/// The Lean's W4 bytes (`bsv-stack-lean corpus/beef-of-any-size`, copied
/// under `tests/vectors/beef_of_any_size/`), every one still refused, the
/// readers agreeing. Under the graph rule `wrong_subject`, its twin and
/// `example_atomic_parent` name a subject that is a raw transaction of the
/// BEEF, so the refusal is the transaction outside its graph, their last
/// (`UnrelatedTransaction` at its offset), where the positional rule of
/// 0.8.0 named the subject (`SubjectMissing` at 4). `unrelated` and its twin
/// keep their offsets and kinds.
#[test]
fn the_leans_w4_bytes_are_refused_under_the_graph_rule() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/beef_of_any_size");
    let any = HeadersFn(|_: u64, _: &Hash32| true);
    // (row, offset, the transaction named: the Lean's datum, or the last;
    // whether the spend checks reach the atomic rule: the rows without
    // `OP_TRUE` outputs are a refused spend first, as at 0.8.0).
    let rows: [(&str, u64, Option<&str>, bool); 5] = [
        ("wrong_subject", 278, None, false),
        (
            "unrelated",
            278,
            Some("9209de30a4024b7c109dca915336a1922a257bb00fca4a8b25855010f8bccfee"),
            false,
        ),
        ("example_atomic_parent", 521, None, true),
        ("wrong_subject_true", 282, None, true),
        (
            "unrelated_true",
            282,
            Some("1cba38b3d4e6245a36b947290c99641f428a011faf876dd099e05c6d9a1d93a1"),
            true,
        ),
    ];
    for (name, offset, named, scripted) in rows {
        let bytes = std::fs::read(dir.join(format!("{name}.bin"))).unwrap();
        let beef = Beef::from_binary(&bytes).unwrap();
        let txid = internal(named.unwrap_or(&beef.txs.last().unwrap().txid()));
        let expected = Verdict::Invalid {
            offset,
            kind: Kind::UnrelatedTransaction,
            reason: Reason::UnrelatedTransaction { txid },
        };
        assert_eq!(
            verify_stream_structure(bytes.as_slice(), &any, None).unwrap(),
            expected,
            "{name}"
        );
        let full = verify_stream(bytes.as_slice(), &any, None).unwrap();
        if scripted {
            assert_eq!(full, expected, "{name}");
        } else {
            assert!(
                matches!(full, Verdict::SpendRefused { .. }),
                "{name}: {full:?}"
            );
        }
        assert_eq!(
            Beef::from_binary(&bytes).unwrap().verify_structure(),
            Err(Kind::UnrelatedTransaction),
            "{name}"
        );
    }
}

/// A proven transaction of `inputs` inputs whose parents the BEEF does not
/// carry, alone in a BEEF with its BUMP: the bytes, with `subject` as an
/// atomic prefix or none, and the headers.
fn proven_with_inputs(inputs: usize, atomic: bool) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let parents: Vec<(String, u32)> = (0..inputs)
        .map(|i| (format!("{:064x}", i + 1), 0))
        .collect();
    let parents: Vec<(&str, u32)> = parents.iter().map(|(t, v)| (t.as_str(), *v)).collect();
    let t = tx(&parents, &[1]);
    let bump = MerklePath::from_coinbase_txid(&t.id(), 970_000);
    let node = Node {
        name: "M",
        raw: t.to_binary(),
        txid: t.id(),
        bump: Some(0),
        spends: vec![],
    };
    let roots = HashMap::from([(970_000u64, internal(&bump.compute_root(None).unwrap()))]);
    let bytes = write(&internal(&node.txid), &[bump], &[Entry::Raw(&node)]);
    // Without the prefix: the plain BEEF behind its 36 bytes.
    let bytes = if atomic { bytes } else { bytes[36..].to_vec() };
    (bytes, roots)
}

#[test]
fn the_txids_named_ahead_are_kept_only_under_a_subject() {
    // A proven transaction's parents are outside the BEEF as a rule, so
    // without a subject nothing reads what its inputs name: the cursor after
    // it holds its three entries (BUMP, level-0 txid, transaction) in both
    // modes, at any input count. Under a subject (the prefix's, or the
    // caller's) each input whose parent is unread is one more entry, 32 bytes
    // of the cursor, and `entries` counts it.
    const INPUTS: usize = 10_000;
    for scripts in [false, true] {
        for (atomic, named) in [(false, false), (true, false), (false, true)] {
            let (bytes, roots) = proven_with_inputs(INPUTS, atomic);
            let subject = named.then(|| {
                let beef = Beef::from_binary(&bytes).unwrap();
                internal(&beef.txs[0].txid())
            });
            let mut reader = if scripts {
                StreamVerifier::new(bytes.as_slice(), &roots, subject)
            } else {
                StreamVerifier::structure_only(bytes.as_slice(), &roots, subject)
            };
            // The BUMP, then the transaction.
            for _ in 0..2 {
                assert!(matches!(reader.step().unwrap(), Progress::Stepped));
            }
            let cursor = reader.cursor();
            let size = cursor.to_binary().len();
            println!("scripts {scripts}, prefix {atomic}, caller's subject {named}: {size} B");
            if atomic || named {
                assert_eq!(cursor.index().entries(), 3 + INPUTS as u64);
                assert!(size > 32 * INPUTS, "{size} B");
            } else {
                assert_eq!(cursor.index().entries(), 3);
                assert!(size < 1_024, "{size} B");
            }
            let stored = cursor.to_binary();
            let cursor = Cursor::from_binary(&stored).unwrap();
            assert_eq!(cursor.to_binary(), stored);
            assert!(matches!(reader.step().unwrap(), Progress::Verdict(_)));
        }
    }
}

/// The TS partition order's bytes and its transactions in order. The txids
/// named ahead after `k` elements: the outside parents of `Z` and `V` once
/// each is read, and `A` from the step that reads `P` to the one that reads
/// `A`.
fn ts_order(graph: &Graph) -> (Vec<u8>, Vec<&Node>) {
    let order: Vec<&Node> = ["Z", "V", "P", "W", "A", "C", "S"]
        .iter()
        .map(|n| graph.node(n))
        .collect();
    (write(&graph.subject(), &graph.bumps, &raw(&order)), order)
}

#[test]
fn a_bsc2_cursor_reads_as_bsc3_with_nothing_named_ahead() {
    // 0.8.0's cursor (BSC2) is BSC3 without the list. It reads with an
    // empty list: equal to BSC3's where nothing was named ahead, and where
    // something was, the resumed reading refuses (a spend read before the
    // cursor is not counted), as 0.8.0 refused the whole: it never accepts
    // more than BSC3 does.
    let graph = Graph::build();
    let roots = graph.roots();
    let (bytes, order) = ts_order(&graph);
    let bumps = graph.bumps.len() as u64;
    let whole = verify_stream(bytes.as_slice(), &roots, None).unwrap();
    assert!(whole.is_valid());
    for k in 0..=bumps + order.len() as u64 {
        let mut reader = StreamVerifier::new(bytes.as_slice(), &roots, None);
        for _ in 0..k {
            assert!(matches!(reader.step().unwrap(), Progress::Stepped));
        }
        let stored = reader.cursor().to_binary();
        // Between two elements, with every output kept: the list, then the
        // `wanted` byte, 0 (no pending transaction follows).
        let read = |name: &str| (bumps..k).any(|i| order[(i - bumps) as usize].name == name);
        let a_ahead = read("P") && !read("A");
        let named = usize::from(read("Z")) + usize::from(read("V")) + usize::from(a_ahead);
        let tail = 1 + 1 + 32 * named;
        assert_eq!(stored[stored.len() - tail], named as u8, "k = {k}");
        let mut bsc2 = b"BSC2".to_vec();
        bsc2.extend_from_slice(&stored[4..stored.len() - tail]);
        bsc2.push(0);
        let cursor = Cursor::from_binary(&bsc2).unwrap();
        let rest = &bytes[cursor.offset() as usize..];
        if named == 0 {
            assert_eq!(cursor, Cursor::from_binary(&stored).unwrap(), "k = {k}");
        }
        if !a_ahead {
            assert_eq!(resume(cursor, rest, &roots).unwrap(), whole, "k = {k}");
        } else {
            match resume(cursor, rest, &roots).unwrap() {
                Verdict::Invalid { kind, .. } => {
                    assert_eq!(kind, Kind::UnrelatedTransaction, "k = {k}")
                }
                other => panic!("k = {k}: {other:?}"),
            }
        }
    }
}

#[test]
fn a_cursor_whose_named_list_is_not_strictly_ascending_is_refused() {
    let graph = Graph::build();
    let roots = graph.roots();
    let (bytes, _) = ts_order(&graph);
    // After the BUMPs, `Z`, `V` and `P`: the outside parents of `Z` and `V`,
    // and `A`, are named ahead.
    let mut reader = StreamVerifier::new(bytes.as_slice(), &roots, None);
    for _ in 0..graph.bumps.len() + 3 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let stored = reader.cursor().to_binary();
    let at = stored.len() - 1 - 3 * 32 - 1;
    assert_eq!(stored[at], 3);
    let a = stored[at + 1..at + 33].to_vec();
    // The one txid twice: a list that does not ascend strictly.
    let mut twice = stored[..at].to_vec();
    twice.push(2);
    twice.extend_from_slice(&a);
    twice.extend_from_slice(&a);
    twice.push(0);
    let err = Cursor::from_binary(&twice).unwrap_err().to_string();
    assert!(err.contains("out of order"), "{err}");
    // A smaller txid after it: descending.
    let mut down = stored[..at].to_vec();
    down.push(2);
    down.extend_from_slice(&a);
    down.extend_from_slice(&[0u8; 32]);
    down.push(0);
    let err = Cursor::from_binary(&down).unwrap_err().to_string();
    assert!(err.contains("out of order"), "{err}");
    // The stored one reads.
    assert!(Cursor::from_binary(&stored).is_ok());
}
