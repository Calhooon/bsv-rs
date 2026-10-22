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
    // `to_binary_atomic` sorts as the TypeScript writer does (`sort_txs`:
    // proven first in encounter order, then unproven in dependency order):
    // the proven `P` is written before its raw unproven ancestor `A`, the
    // proven parent `V` and child `W` before the unproven. Until 0.8.0 the
    // crate's own readers refused what its writer wrote. Merged in each of
    // the 364 orders.
    let graph = Graph::build();
    let roots = graph.roots();
    let mut subject_not_last = 0;
    let orders = orders(&graph);
    for order in &orders {
        let mut beef = Beef::new();
        for bump in &graph.bumps {
            beef.merge_bump(bump.clone());
        }
        // Merged in this order, the subject's place included; the bump
        // indexes are the merge's (each BUMP is its own block).
        for node in order {
            beef.merge_raw_tx(node.raw.clone(), node.bump);
        }
        let subject = graph.node("S").txid.clone();
        let bytes = beef.to_binary_atomic(&subject).unwrap();
        let written: Vec<String> = Beef::from_binary(&bytes)
            .unwrap()
            .txs
            .iter()
            .map(|t| t.txid())
            .collect();
        let at = |name: &str| {
            written
                .iter()
                .position(|t| *t == graph.node(name).txid)
                .unwrap()
        };
        assert!(at("P") < at("A"), "the proven descendant first");
        // The sort is the reference's repeated scan in merge order: `A`,
        // which `S` does not spend, is written after it when merged after
        // it. The positional rule refused that too (`SubjectMissing`).
        if at("S") != written.len() - 1 {
            assert_eq!(at("A"), written.len() - 1);
            subject_not_last += 1;
        }
        assert_eq!(
            verdicts(&bytes, &roots),
            [Ok(()), Ok(()), Ok(()), Ok(())],
            "merged {}",
            names(order)
        );
        let tx = Transaction::from_atomic_beef(&bytes).unwrap();
        assert_eq!(tx.id(), subject);
    }
    assert!(subject_not_last > 0 && subject_not_last < orders.len());
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
