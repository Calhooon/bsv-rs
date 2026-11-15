//! #843b: a `Beef`'s index and every entry's BUMP position are always those
//! of its rows, as a seeded property over every public `&mut` door.
//!
//! The compiler holds the write door (`src/transaction/beef/rows.rs`: no
//! code outside its `sealed` module can change a row but through a function
//! that does the index's and the marks' part). This file holds what a run
//! can: on BEEFs built by merges and BEEFs read from bytes (a txid twice, an
//! index naming no BUMP, a child ahead of its parent among them), after
//! EVERY step through a public `&mut` door of `Beef` (and a write of its two
//! public fields):
//!
//! 1. `find_txid` of each row's txid is the LAST row holding it, of a txid
//!    no row holds `None`, and the same from a `Txid` parsed out of that
//!    txid's upper-case text;
//! 2. each row's `txid()`, `id()` and `input_txids()` are those of the bytes
//!    it writes (the hash of the bytes; the distinct txids the bytes' inputs
//!    name, none for an entry naming a BUMP);
//! 3. a BUMP moves only where a door says so: `retain_bumps` re-points every
//!    entry by the positions it kept (an independent re-statement of its
//!    rule), `trim_known_proven` leaves every surviving entry naming the
//!    BUMP it named, and every other door leaves the BUMPs held where they
//!    were, appending alone;
//! 4. a clone answers every lookup as its original;
//! 5. the rows written (`to_writer`, as held) read back as the same rows,
//!    and `to_binary` then `from_binary` as the rows the sort left.
//!
//! The reach is counted and asserted with a floor per door, state and
//! outcome, and the list of doors is held against the source: a public
//! `fn` of `Beef` taking `&mut self` that is not on [`DOORS`] fails
//! `every_public_mut_door_of_beef_is_exercised_843b`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use std::collections::{BTreeMap, HashMap, HashSet};

use bsv_rs::primitives::Writer;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    Txid, BEEF_V1, BEEF_V2,
};

const SEED: u64 = 0x0843_b000_5eed_0001;
/// Sequences in the run, and the steps of each.
const SEQUENCES: usize = 700;
const STEPS: usize = 28;
/// The transactions a sequence draws from.
const POOL: usize = 9;

/// Every public `&mut self` door of `Beef`, by name: the list the property
/// exercises, held against the source below and against the rustdoc JSON of
/// the lane's record (`docs/lanes/fix-843b.md`).
const DOORS: &[&str] = &[
    "edit_bump",
    "edit_tx",
    "is_valid",
    "make_txid_only",
    "merge_beef",
    "merge_bump",
    "merge_raw_tx",
    "merge_transaction",
    "merge_txid_only",
    "retain_bumps",
    "retain_txs",
    "set_bump_index",
    "sort_txs",
    "to_binary",
    "to_binary_atomic",
    "to_hex",
    "to_log_string",
    "trim_known_proven",
    "verify_structure",
    "verify_valid",
];

/// splitmix64: a seeded sequence, the same on every host.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

/// The transactions of a sequence: `txs[k]` spends earlier members (or an
/// outpoint outside the pool), each in a block of its own height.
struct Pool {
    txs: Vec<Transaction>,
}

impl Pool {
    fn new(rng: &mut Rng) -> Self {
        let mut txs: Vec<Transaction> = Vec::new();
        for k in 0..POOL {
            let mut tx = Transaction::new();
            let inputs = 1 + rng.below(2);
            for i in 0..inputs {
                let source = if k == 0 || rng.chance(3) {
                    format!("{:02x}", 0xa0 + k).repeat(32).parse().unwrap()
                } else {
                    txs[rng.below(k)].txid()
                };
                let mut input = TransactionInput::new(source, i as u32);
                input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
                tx.inputs_mut().push(input);
            }
            tx.outputs_mut().push(TransactionOutput::new(
                1_000 + k as u64,
                LockingScript::from_binary(&[0x51]).unwrap(),
            ));
            tx.set_lock_time(rng.below(1 << 20) as u32);
            txs.push(tx);
        }
        Self { txs }
    }

    fn txid(&self, k: usize) -> Txid {
        self.txs[k].txid()
    }

    /// The block height of `txs[k]`'s BUMP: one block a transaction, so a
    /// BUMP is known by its height wherever it moves.
    fn height(k: usize) -> u32 {
        1_000 + k as u32
    }

    /// A BUMP proving `txs[k]`: its txid at offset 0 beside a sibling.
    fn bump(&self, k: usize) -> MerklePath {
        MerklePath::new(
            Self::height(k),
            vec![vec![
                MerklePathLeaf::new_txid(0, self.txs[k].id()),
                MerklePathLeaf::new(1, format!("{:02x}", 0x10 + k).repeat(32)),
            ]],
        )
        .unwrap()
    }
}

/// What a run reached.
#[derive(Debug, Default)]
struct Counts {
    steps: usize,
    by_door: BTreeMap<&'static str, usize>,
    outcomes: BTreeMap<&'static str, usize>,
    read_from_bytes: usize,
    built_by_merges: usize,
    twins_checked: usize,
    dangling_checked: usize,
    txid_only_checked: usize,
    upper_case_lookups: usize,
    absent_lookups: usize,
    rows_checked: usize,
    written_as_held: usize,
    sorted_round_trips: usize,
    marks_checked: usize,
}

impl Counts {
    fn door(&mut self, name: &'static str) {
        *self.by_door.entry(name).or_default() += 1;
    }
    fn outcome(&mut self, name: &'static str) {
        *self.outcomes.entry(name).or_default() += 1;
    }
}

/// A frame of `bumps` and `entries` as given, by this crate's own writers.
fn frame(version: u32, bumps: &[MerklePath], entries: &[BeefTx]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32_le(version);
    w.write_var_int(bumps.len() as u64);
    for bump in bumps {
        bump.to_writer(&mut w).unwrap();
    }
    w.write_var_int(entries.len() as u64);
    for entry in entries {
        entry.to_writer(&mut w, version).unwrap();
    }
    w.into_bytes()
}

/// A BEEF read from bytes holding rows no merge builds: any order, a txid
/// twice (raw and raw, raw and txid-only), an index naming no BUMP or a
/// BUMP that does not hold the txid.
fn read_from_bytes(pool: &Pool, rng: &mut Rng) -> Option<Beef> {
    let mut bumps = Vec::new();
    for k in 0..POOL {
        if rng.chance(3) {
            bumps.push(pool.bump(k));
        }
    }
    let mut entries = Vec::new();
    let count = 1 + rng.below(7);
    for _ in 0..count {
        let k = rng.below(POOL);
        let entry = match rng.below(5) {
            0 => BeefTx::from_txid(pool.txid(k)),
            1 => BeefTx::from_raw_tx(pool.txs[k].to_binary(), Some(9 + rng.below(3))).unwrap(),
            2 if !bumps.is_empty() => {
                BeefTx::from_raw_tx(pool.txs[k].to_binary(), Some(rng.below(bumps.len()))).unwrap()
            }
            _ => BeefTx::from_raw_tx(pool.txs[k].to_binary(), None).unwrap(),
        };
        if rng.chance(4) {
            entries.push(entry.clone());
        }
        entries.push(entry);
    }
    Beef::from_binary(&frame(BEEF_V2, &bumps, &entries)).ok()
}

/// One row as the checks compare it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Row {
    txid: Txid,
    txid_only: bool,
    bump_index: Option<usize>,
    bytes: Option<Vec<u8>>,
}

fn rows(beef: &Beef) -> Vec<Row> {
    beef.txs()
        .iter()
        .map(|t| Row {
            txid: t.txid(),
            txid_only: t.is_txid_only(),
            bump_index: t.bump_index(),
            bytes: t.raw_tx_or_compute(),
        })
        .collect()
}

/// The rows as a frame carries them: a txid-only entry's frame is its txid
/// alone (format byte `02`), so the read holds no BUMP index for it.
fn framed(beef: &Beef) -> Vec<Row> {
    let mut rows = rows(beef);
    for row in rows.iter_mut().filter(|r| r.txid_only) {
        row.bump_index = None;
    }
    rows
}

fn heights(beef: &Beef) -> Vec<u32> {
    beef.bumps().iter().map(|b| b.block_height).collect()
}

/// The height of the BUMP each row names, `None` for a row naming none or
/// an index past the BUMPs.
fn named(beef: &Beef) -> Vec<Option<u32>> {
    beef.txs()
        .iter()
        .map(|t| {
            t.bump_index()
                .and_then(|i| beef.bumps().get(i))
                .map(|b| b.block_height)
        })
        .collect()
}

/// The distinct txids `bytes`' inputs name, in input order.
fn inputs_of(bytes: &[u8]) -> Vec<Txid> {
    let tx = Transaction::from_binary(bytes).unwrap();
    let mut seen = HashSet::new();
    tx.inputs()
        .iter()
        .filter_map(|i| i.source_txid)
        .filter(|t| seen.insert(*t))
        .collect()
}

/// Checks 1, 2, 4 and 5 on `beef` as it stands.
fn check(beef: &Beef, pool: &Pool, absent: Txid, at: &str, counts: &mut Counts) {
    let copy = beef.clone();
    let mut last: HashMap<Txid, usize> = HashMap::new();
    for (i, row) in beef.txs().iter().enumerate() {
        last.insert(row.txid(), i);
    }
    if last.len() < beef.txs().len() {
        counts.twins_checked += 1;
    }
    for (i, row) in beef.txs().iter().enumerate() {
        counts.rows_checked += 1;
        let txid = row.txid();
        let want = last[&txid];
        // 1. The last row holding the txid, by a lower-case and an
        //    upper-case text's `Txid` alike, and by a clone.
        let found = beef
            .find_txid(txid)
            .unwrap_or_else(|| panic!("{at}: row {i} not found"));
        assert!(
            std::ptr::eq(found, &beef.txs()[want]),
            "{at}: row {i}: find_txid is not the last row holding {txid}"
        );
        let upper: Txid = txid.to_string().to_uppercase().parse().unwrap();
        assert!(
            std::ptr::eq(beef.find_txid(upper).unwrap(), &beef.txs()[want]),
            "{at}: row {i}: the upper-case text"
        );
        counts.upper_case_lookups += 1;
        let copied = copy.find_txid(txid).unwrap();
        assert!(
            std::ptr::eq(copied, &copy.txs()[want]),
            "{at}: row {i}: a clone's lookup"
        );
        // 2. The row's identity and input list are its written bytes'.
        assert_eq!(row.id(), txid.to_string(), "{at}: row {i}: id()");
        match row.raw_tx_or_compute() {
            Some(bytes) => {
                let parsed = Transaction::from_binary(&bytes)
                    .unwrap_or_else(|e| panic!("{at}: row {i}: its bytes: {e}"));
                assert_eq!(
                    parsed.txid(),
                    txid,
                    "{at}: row {i}: txid() is its bytes' hash"
                );
                let want_inputs = if row.bump_index().is_some() {
                    Vec::new()
                } else {
                    inputs_of(&bytes)
                };
                assert_eq!(
                    row.input_txids(),
                    want_inputs,
                    "{at}: row {i}: input_txids()"
                );
                assert!(!row.is_txid_only(), "{at}: row {i}");
            }
            None => {
                counts.txid_only_checked += 1;
                assert!(row.is_txid_only(), "{at}: row {i}: no bytes, a txid alone");
                assert!(row.input_txids().is_empty(), "{at}: row {i}");
            }
        }
        if row.bump_index().is_some_and(|b| b >= beef.bumps().len()) {
            counts.dangling_checked += 1;
        }
    }
    // A txid no row holds, the pool's and one outside it.
    for txid in (0..POOL).map(|k| pool.txid(k)).chain([absent]) {
        if !last.contains_key(&txid) {
            counts.absent_lookups += 1;
            assert!(beef.find_txid(txid).is_none(), "{at}: an absent txid found");
            assert!(copy.find_txid(txid).is_none(), "{at}: a clone, absent");
            let upper: Txid = txid.to_string().to_uppercase().parse().unwrap();
            assert!(beef.find_txid(upper).is_none(), "{at}: absent, upper case");
        }
    }
    // 4. A clone holds the same rows.
    assert_eq!(rows(&copy), rows(beef), "{at}: a clone's rows");
    let paths = |b: &Beef| -> Vec<_> {
        b.bumps()
            .iter()
            .map(|bump| (bump.block_height, bump.path.clone()))
            .collect()
    };
    assert_eq!(paths(&copy), paths(beef), "{at}: a clone's BUMPs");

    // 5. The rows as held, written and read back.
    let mut writer = Writer::new();
    if beef.to_writer(&mut writer).is_ok() {
        if let Ok(back) = Beef::from_binary(&writer.into_bytes()) {
            assert_eq!(
                framed(&back),
                framed(beef),
                "{at}: to_writer then from_binary"
            );
            assert_eq!(heights(&back), heights(beef), "{at}: the BUMPs read back");
            counts.written_as_held += 1;
        }
    }
    let mut sorted = beef.clone();
    if let Ok(bytes) = sorted.to_binary() {
        if let Ok(back) = Beef::from_binary(&bytes) {
            assert_eq!(
                framed(&back),
                framed(&sorted),
                "{at}: to_binary then from_binary"
            );
            counts.sorted_round_trips += 1;
        }
    }
}

/// Row `i`'s BUMP position after `retain_bumps(keep)`, stated apart from
/// the door: a kept BUMP's new position, none for a dropped one, an index
/// past the BUMPs as it was.
fn re_pointed(before: Option<usize>, kept: &[bool]) -> Option<usize> {
    let old = before?;
    match kept.get(old) {
        Some(true) => Some(kept[..old].iter().filter(|k| **k).count()),
        Some(false) => None,
        None => Some(old),
    }
}

/// One step through a door chosen by `rng`, with check 3 for that door.
#[allow(clippy::too_many_lines)]
fn step(beef: &mut Beef, pool: &Pool, rng: &mut Rng, at: &str, counts: &mut Counts) {
    let before_rows = rows(beef);
    let before_named = named(beef);
    let before_heights = heights(beef);
    let k = rng.below(POOL);
    let txid = if !beef.txs().is_empty() && !rng.chance(4) {
        beef.txs()[rng.below(beef.txs().len())].txid()
    } else {
        pool.txid(k)
    };
    // Whether the door may move a BUMP's position (check 3).
    let mut moves_bumps = false;
    // Whether the door sets both marks (check 6).
    let mut marks = false;
    // Every door, and a write of each of the two public fields.
    let pick = rng.below(DOORS.len() + 2);
    let door = match DOORS.get(pick) {
        Some(door) => *door,
        None if pick == DOORS.len() => "version",
        None => "atomic_txid",
    };
    counts.door(door);
    match door {
        "merge_bump" => {
            let held = beef.bumps().len();
            let index = beef.merge_bump(pool.bump(k));
            assert_eq!(beef.bumps()[index].block_height, Pool::height(k), "{at}");
            counts.outcome(if beef.bumps().len() > held {
                "merge_bump appended"
            } else {
                "merge_bump combined"
            });
        }
        "merge_txid_only" => {
            let held = beef.txs().len();
            let entry = beef.merge_txid_only(txid);
            assert_eq!(entry.txid(), txid, "{at}");
            counts.outcome(if beef.txs().len() > held {
                "merge_txid_only appended"
            } else {
                "merge_txid_only kept the entry held"
            });
        }
        "make_txid_only" => match beef.make_txid_only(txid) {
            Some(entry) => {
                assert!(entry.is_txid_only() && entry.txid() == txid, "{at}");
                counts.outcome("make_txid_only made one");
            }
            None => counts.outcome("make_txid_only of a txid not held"),
        },
        "merge_raw_tx" => {
            if rng.chance(6) {
                let rows_before = rows(beef);
                assert!(beef.merge_raw_tx(vec![0xde, 0xad], None).is_err(), "{at}");
                assert_eq!(rows(beef), rows_before, "{at}: untouched on Err");
                counts.outcome("merge_raw_tx refused bytes that are no transaction");
            } else {
                let index = match rng.below(3) {
                    0 => None,
                    1 => Some(rng.below(beef.bumps().len() + 1)),
                    _ => Some(9 + rng.below(3)),
                };
                let held = beef.txs().len();
                let entry = beef.merge_raw_tx(pool.txs[k].to_binary(), index).unwrap();
                assert_eq!(entry.txid(), pool.txid(k), "{at}");
                if index.is_some() {
                    assert_eq!(entry.bump_index(), index, "{at}: stored as given");
                }
                counts.outcome(if beef.txs().len() > held {
                    "merge_raw_tx appended"
                } else {
                    "merge_raw_tx replaced in place"
                });
            }
        }
        "merge_transaction" => {
            let mut tx = pool.txs[k].clone();
            if rng.chance(2) {
                tx.merkle_path = Some(pool.bump(k));
                counts.outcome("merge_transaction with a path");
            }
            if rng.chance(2) {
                // Link every input whose source the pool holds.
                for i in 0..tx.inputs().len() {
                    let source = tx.inputs()[i].source_txid;
                    if let Some(parent) = pool.txs.iter().find(|p| Some(p.txid()) == source) {
                        tx.inputs_mut()[i].source_transaction = Some(Box::new(parent.clone()));
                    }
                }
                counts.outcome("merge_transaction with linked sources");
            }
            let entry = beef.merge_transaction(tx);
            assert_eq!(entry.txid(), pool.txid(k), "{at}");
        }
        "merge_beef" => {
            let mut other = match read_from_bytes(pool, rng) {
                Some(read) if rng.chance(2) => read,
                _ => {
                    let mut other = Beef::new();
                    for _ in 0..1 + rng.below(4) {
                        let j = rng.below(POOL);
                        match rng.below(3) {
                            0 => {
                                other.merge_bump(pool.bump(j));
                            }
                            1 => {
                                other.merge_txid_only(pool.txid(j));
                            }
                            _ => {
                                other.merge_raw_tx(pool.txs[j].to_binary(), None).unwrap();
                            }
                        }
                    }
                    other
                }
            };
            if rng.chance(5) {
                other.version = BEEF_V1;
            }
            let source_rows = rows(&other);
            match beef.merge_beef(&other) {
                Ok(()) => counts.outcome("merge_beef merged"),
                Err(_) => {
                    assert_eq!(rows(beef), before_rows, "{at}: untouched on Err");
                    assert_eq!(heights(beef), before_heights, "{at}: untouched on Err");
                    counts.outcome("merge_beef refused its source");
                }
            }
            assert_eq!(rows(&other), source_rows, "{at}: the source is unchanged");
        }
        "edit_tx" => {
            let lock_time = rng.below(1 << 20) as u32;
            let moves = rng.chance(2);
            let edited = beef.edit_tx(txid, |tx| {
                if moves {
                    tx.set_lock_time(lock_time);
                } else {
                    tx.metadata.insert("note".into(), lock_time.into());
                }
                tx.txid()
            });
            match edited {
                Ok(new) if new != txid => {
                    assert!(
                        beef.find_txid(new).is_some(),
                        "{at}: the edit is found at once"
                    );
                    counts.outcome("edit_tx moved the txid");
                }
                Ok(_) => {
                    assert_eq!(rows(beef), before_rows, "{at}: an edit that moves no byte");
                    counts.outcome("edit_tx moved nothing");
                }
                Err(_) => {
                    assert_eq!(rows(beef), before_rows, "{at}: untouched on Err");
                    counts.outcome("edit_tx refused");
                }
            }
        }
        "retain_txs" => {
            marks = true;
            let salt = rng.next();
            let keep = |entry: &BeefTx| {
                let b = entry.txid().as_wire_bytes()[0] as u64;
                !(b ^ salt).is_multiple_of(4)
            };
            let want: Vec<Row> = beef
                .txs()
                .iter()
                .zip(&before_rows)
                .filter(|(entry, _)| keep(entry))
                .map(|(_, row)| row.clone())
                .collect();
            beef.retain_txs(keep);
            assert_eq!(rows(beef), want, "{at}: the kept rows in their order");
            counts.outcome(if want.len() < before_rows.len() {
                "retain_txs dropped a row"
            } else {
                "retain_txs kept every row"
            });
        }
        "retain_bumps" => {
            moves_bumps = true;
            marks = true;
            let salt = rng.next();
            let kept: Vec<bool> = (0..beef.bumps().len())
                .map(|i| !(i as u64 ^ salt).is_multiple_of(3))
                .collect();
            let mut asked = Vec::new();
            beef.retain_bumps(|i, bump| {
                asked.push((i, bump.block_height));
                kept[i]
            });
            let want_asked: Vec<(usize, u32)> =
                before_heights.iter().copied().enumerate().collect();
            assert_eq!(asked, want_asked, "{at}: each BUMP asked once, in order");
            let want_heights: Vec<u32> = before_heights
                .iter()
                .zip(&kept)
                .filter(|(_, k)| **k)
                .map(|(h, _)| *h)
                .collect();
            assert_eq!(heights(beef), want_heights, "{at}: the BUMPs kept");
            let want_index: Vec<Option<usize>> = before_rows
                .iter()
                .map(|row| re_pointed(row.bump_index, &kept))
                .collect();
            let after: Vec<Option<usize>> = beef.txs().iter().map(BeefTx::bump_index).collect();
            assert_eq!(after, want_index, "{at}: every entry re-pointed");
            // Said again by the BUMP itself: a row that named a BUMP names
            // the same one, or none where it was dropped.
            for (i, (was, is)) in before_named.iter().zip(named(beef)).enumerate() {
                if let Some(height) = was {
                    assert!(
                        is == Some(*height) || beef.txs()[i].bump_index().is_none(),
                        "{at}: row {i} named the BUMP at {height} and names {is:?}"
                    );
                }
            }
            if kept.iter().any(|k| !k) {
                counts.outcome("retain_bumps dropped a BUMP");
                let moved = before_rows
                    .iter()
                    .zip(&after)
                    .any(|(row, now)| row.bump_index != *now && now.is_some());
                if moved {
                    counts.outcome("retain_bumps moved an entry's index");
                }
                let orphaned = before_rows
                    .iter()
                    .zip(&after)
                    .any(|(row, now)| row.bump_index.is_some() && now.is_none());
                if orphaned {
                    counts.outcome("retain_bumps left an entry naming none");
                }
            }
        }
        "edit_bump" => {
            let index = rng.below(beef.bumps().len() + 2);
            let edited = beef.edit_bump(index, |bump| {
                // A flag of the sibling leaf: the root does not move.
                if let Some(leaf) = bump.path[0].last_mut() {
                    leaf.txid = !leaf.txid;
                }
                bump.block_height
            });
            match edited {
                Ok(height) => {
                    marks = true;
                    assert_eq!(height, before_heights[index], "{at}");
                    counts.outcome("edit_bump edited");
                }
                Err(_) => {
                    assert!(index >= before_heights.len(), "{at}");
                    assert_eq!(beef.bumps().len(), before_heights.len(), "{at}");
                    counts.outcome("edit_bump of an index naming no BUMP");
                }
            }
        }
        "set_bump_index" => {
            let index = match rng.below(3) {
                0 => None,
                1 => Some(rng.below(beef.bumps().len() + 1)),
                _ => Some(9 + rng.below(3)),
            };
            match beef.set_bump_index(txid, index) {
                Ok(()) => {
                    let entry = beef.find_txid(txid).unwrap();
                    assert_eq!(entry.bump_index(), index, "{at}: stored as given");
                    marks = true;
                    counts.outcome("set_bump_index set");
                }
                Err(_) => {
                    assert_eq!(rows(beef), before_rows, "{at}: untouched on Err");
                    counts.outcome("set_bump_index of a txid not held");
                }
            }
        }
        "trim_known_proven" => {
            moves_bumps = true;
            beef.trim_known_proven();
            // The surviving rows are the rows before, in order, less the
            // trimmed ones; each names the BUMP it named.
            let after_rows = rows(beef);
            let after_named = named(beef);
            let mut from = 0;
            for (i, row) in after_rows.iter().enumerate() {
                let found = (from..before_rows.len())
                    .find(|j| {
                        before_rows[*j].txid == row.txid
                            && before_rows[*j].bytes == row.bytes
                            && before_named[*j] == after_named[i]
                    })
                    .unwrap_or_else(|| panic!("{at}: row {i} after the trim is no row before it"));
                from = found + 1;
            }
            counts.outcome(if after_rows.len() < before_rows.len() {
                "trim_known_proven trimmed"
            } else {
                "trim_known_proven kept every row"
            });
        }
        "sort_txs" => {
            let sorted = beef.sort_txs();
            let held: HashSet<Txid> = beef.txs().iter().map(BeefTx::txid).collect();
            for txid in sorted.valid.iter().chain(&sorted.not_valid) {
                assert!(held.contains(txid), "{at}: the sort names a txid not held");
            }
            counts.outcome("sort_txs");
        }
        "is_valid" => {
            let valid = beef.is_valid(false);
            counts.outcome(if valid {
                "is_valid true"
            } else {
                "is_valid false"
            });
        }
        "verify_valid" => {
            let _ = beef.verify_valid(false);
        }
        "verify_structure" => {
            counts.outcome(match beef.verify_structure() {
                Ok(_) => "verify_structure Ok",
                Err(_) => "verify_structure Err",
            });
        }
        "to_log_string" => {
            assert!(beef.to_log_string().starts_with("BEEF with "), "{at}");
        }
        "to_binary" => {
            counts.outcome(match beef.to_binary() {
                Ok(_) => "to_binary Ok",
                Err(_) => "to_binary refused",
            });
        }
        "to_hex" => {
            let _ = beef.to_hex();
        }
        "to_binary_atomic" => match beef.to_binary_atomic(txid) {
            Ok(bytes) => {
                let read = Beef::from_binary(&bytes)
                    .unwrap_or_else(|e| panic!("{at}: the atomic bytes do not read: {e}"));
                assert_eq!(
                    read.atomic_txid,
                    Some(txid),
                    "{at}: the prefix names the subject"
                );
                assert!(
                    read.find_txid(txid).is_some(),
                    "{at}: the closure holds its subject"
                );
                counts.outcome("to_binary_atomic wrote a closure");
            }
            Err(_) => counts.outcome("to_binary_atomic refused"),
        },
        "version" => {
            beef.version = if beef.version == BEEF_V2 {
                BEEF_V1
            } else {
                BEEF_V2
            };
        }
        "atomic_txid" => {
            beef.atomic_txid = if rng.chance(3) { None } else { Some(txid) };
        }
        other => panic!("no step for the door {other}"),
    }
    // 3. No other door moves a BUMP: those held stand where they stood.
    if !moves_bumps {
        let after = heights(beef);
        assert!(
            after.len() >= before_heights.len()
                && after[..before_heights.len()] == before_heights[..],
            "{at}: {door} moved a BUMP: {before_heights:?} to {after:?}"
        );
    }
    // 6. The marks, read by what they decide: after a door that changes a
    // row the BEEF is marked for a sort and not as read.
    if marks {
        marked(beef, &format!("{at}: {door}"), counts);
    }
}

/// The two marks after a door that sets both, read through the doors they
/// decide (they are private to the rows): `to_binary` sorts before it writes, so the
/// bytes are those of a copy sorted by hand and then written; and
/// `merge_beef` walks the source sorted, not as held, so a target takes its
/// entries in the order the sorted copy gives them.
fn marked(beef: &Beef, at: &str, counts: &mut Counts) {
    let mut sorted = beef.clone();
    sorted.sort_txs();
    let mut copy = beef.clone();
    assert_eq!(
        copy.to_binary().ok(),
        sorted.to_binary().ok(),
        "{at}: marked for a sort, so written as its sorted copy is"
    );
    let merged = |source: &Beef| -> Option<Vec<Txid>> {
        let mut target = Beef::new();
        target.merge_beef(source).ok()?;
        Some(target.txs().iter().map(BeefTx::txid).collect())
    };
    assert_eq!(
        merged(beef),
        merged(&sorted),
        "{at}: not as read, so merged in its sorted order"
    );
    counts.marks_checked += 1;
}

#[test]
fn the_index_and_every_bump_position_are_the_rows_after_every_door_843b() {
    let mut rng = Rng(SEED);
    let mut counts = Counts::default();
    let absent: Txid = "8430000000000000000000000000000000000000000000000000000000000b43"
        .parse()
        .unwrap();
    for sequence in 0..SEQUENCES {
        let pool = Pool::new(&mut rng);
        let mut beef = match read_from_bytes(&pool, &mut rng) {
            Some(read) if sequence % 2 == 0 => {
                counts.read_from_bytes += 1;
                read
            }
            _ => {
                counts.built_by_merges += 1;
                Beef::new()
            }
        };
        check(
            &beef,
            &pool,
            absent,
            &format!("sequence {sequence}, as built"),
            &mut counts,
        );
        for n in 0..STEPS {
            let at = format!("seed {SEED:#x}, sequence {sequence}, step {n}");
            step(&mut beef, &pool, &mut rng, &at, &mut counts);
            counts.steps += 1;
            check(&beef, &pool, absent, &at, &mut counts);
        }
    }
    reach_floors(&counts);
}

/// The reach, asserted: every door, state and outcome the property claims
/// to cover was reached at least this often (each floor under what the run
/// counts, so a generator that stops reaching a cell fails here).
fn reach_floors(c: &Counts) {
    let mut short = Vec::new();
    let mut floor = |name: &str, n: usize, floor: usize| {
        if n < floor {
            short.push(format!("{name}: {n} < {floor}"));
        }
    };
    floor("steps", c.steps, SEQUENCES * STEPS);
    for door in DOORS.iter().chain(&["version", "atomic_txid"]) {
        floor(
            door,
            c.by_door.get(door).copied().unwrap_or(0),
            FLOOR_PER_DOOR,
        );
    }
    for (outcome, least) in OUTCOME_FLOORS {
        floor(
            outcome,
            c.outcomes.get(outcome).copied().unwrap_or(0),
            *least,
        );
    }
    floor("read from bytes", c.read_from_bytes, SEQUENCES / 2);
    floor("built by merges", c.built_by_merges, SEQUENCES / 2);
    floor("states holding a txid twice", c.twins_checked, 3_300);
    floor(
        "rows naming no BUMP by an index past them",
        c.dangling_checked,
        5_800,
    );
    floor("txid-only rows", c.txid_only_checked, 10_000);
    floor("upper-case lookups", c.upper_case_lookups, 42_000);
    floor("absent lookups", c.absent_lookups, 78_000);
    floor("rows checked", c.rows_checked, 42_000);
    floor("written as held and read back", c.written_as_held, 9_000);
    floor("sorted, written and read back", c.sorted_round_trips, 9_000);
    floor("states whose marks were read", c.marks_checked, 1_500);
    assert!(
        short.is_empty(),
        "seed {SEED:#x}: the property's reach fell below its floor: {short:?}\n{c:#?}"
    );
    // The census, for the lane's record (`--nocapture`).
    println!("seed {SEED:#x}, {SEQUENCES} sequences of {STEPS} steps: {c:#?}");
}

/// The least a door is called.
const FLOOR_PER_DOOR: usize = 500;

/// The least each outcome is reached.
const OUTCOME_FLOORS: &[(&str, usize)] = &[
    ("merge_bump appended", 370),
    ("merge_bump combined", 110),
    ("merge_txid_only appended", 120),
    ("merge_txid_only kept the entry held", 360),
    ("make_txid_only made one", 350),
    ("make_txid_only of a txid not held", 130),
    ("merge_raw_tx appended", 270),
    ("merge_raw_tx replaced in place", 135),
    ("merge_raw_tx refused bytes that are no transaction", 75),
    ("merge_transaction with a path", 260),
    ("merge_transaction with linked sources", 250),
    ("merge_beef merged", 460),
    ("merge_beef refused its source", 45),
    ("edit_tx moved the txid", 130),
    ("edit_tx moved nothing", 130),
    ("edit_tx refused", 240),
    ("retain_txs dropped a row", 235),
    ("retain_txs kept every row", 240),
    ("retain_bumps dropped a BUMP", 275),
    ("retain_bumps moved an entry's index", 100),
    ("retain_bumps left an entry naming none", 150),
    ("edit_bump edited", 230),
    ("edit_bump of an index naming no BUMP", 280),
    ("set_bump_index set", 340),
    ("set_bump_index of a txid not held", 120),
    ("trim_known_proven trimmed", 115),
    ("trim_known_proven kept every row", 380),
    ("is_valid true", 65),
    ("is_valid false", 420),
    ("verify_structure Ok", 70),
    ("verify_structure Err", 420),
    ("to_binary Ok", 400),
    ("to_binary refused", 80),
    ("to_binary_atomic wrote a closure", 325),
    ("to_binary_atomic refused", 140),
];

/// Every `pub fn` of `Beef` that takes `&mut self`, read from the source:
/// the files that hold an `impl Beef`, each signature from `pub fn` to its
/// receiver. The list the property exercises is exactly these, so a door
/// added is a door the property must take before this passes.
#[test]
fn every_public_mut_door_of_beef_is_exercised_843b() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/transaction");
    let mut files = vec![
        root.join("beef.rs"),
        root.join("beef_writable.rs"),
        root.join("beef_atomic.rs"),
    ];
    for entry in std::fs::read_dir(root.join("beef")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            files.push(path);
        }
    }
    let mut found: Vec<String> = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        // The unit tests at a file's end declare no `pub fn`.
        let mut rest = text.as_str();
        while let Some(at) = rest.find("pub fn ") {
            rest = &rest[at + "pub fn ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let Some(open) = rest.find('(') else {
                continue;
            };
            let receiver = rest[open + 1..].trim_start();
            if receiver.starts_with("&mut self") {
                found.push(name);
            }
        }
    }
    found.sort();
    found.dedup();
    assert_eq!(
        found, DOORS,
        "the public `&mut self` doors of `Beef` in the source are not the listed ones"
    );
}

/// A transaction spending `11..11`:`vout`.
fn spending(vout: u32) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("11".repeat(32).parse().unwrap(), vout);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    tx.inputs_mut().push(input);
    tx.outputs_mut().push(TransactionOutput::new(
        1_000,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    tx
}

/// The named case. Until #843b `merge_txid_only` took a `String` nothing
/// checked and held it as given: a text that is not 64 hex digits was found
/// again by `find_txid` and refused only when the BEEF was written or
/// merged as a source (`Invalid txid-only entry txid: expected 64 hex
/// digits, got N`, `Invalid hex string`, the empty text ahead of
/// everything), and a txid in upper case was a second entry beside the same
/// transaction merged raw, both written. The door takes a `Txid`: none of
/// the texts is one, and the upper-case text and its lower-case twin are
/// one entry, found at every door.
#[test]
fn no_merge_txid_only_holds_a_text_that_is_no_txid_843b() {
    let texts = [
        "abcd".to_string(),
        "ab".repeat(31),
        "a".repeat(63),
        "ab".repeat(33),
        "zz".repeat(32),
        String::new(),
        format!(" {} ", "ab".repeat(31)),
    ];
    for text in &texts {
        assert_eq!(
            Txid::from_hex(text),
            Err(bsv_rs::Error::TransactionError(
                "txid must be a 32-byte hexadecimal transaction ID.".to_string()
            )),
            "{text:?} is no txid, so no door of the BEEF takes it"
        );
        assert!(text.parse::<Txid>().is_err(), "{text:?}");
    }

    // The upper-case text and its lower-case twin: one `Txid`, one entry.
    let tx = spending(0);
    let (lower, upper) = (tx.id(), tx.id().to_uppercase());
    let named: Txid = upper.parse().unwrap();
    assert_eq!(named, tx.txid());
    let mut beef = Beef::new();
    assert!(beef.merge_txid_only(named).is_txid_only());
    beef.merge_raw_tx(tx.to_binary(), None).unwrap();
    assert_eq!(beef.txs().len(), 1, "one entry, where the base held two");
    assert!(
        !beef.txs()[0].is_txid_only(),
        "the transaction in the txid's place"
    );
    let mut control = Beef::new();
    control.merge_txid_only(lower.parse().unwrap());
    control.merge_raw_tx(tx.to_binary(), None).unwrap();
    let bytes = beef.to_binary().unwrap();
    assert_eq!(bytes, control.to_binary().unwrap(), "the lower-case bytes");
    assert_eq!(Beef::from_binary(&bytes).unwrap().txs().len(), 1);

    // Every door finds the entry by the upper-case text's `Txid`.
    let mut beef = Beef::new();
    beef.merge_bump(MerklePath::from_coinbase_txid(&lower, 100));
    beef.merge_raw_tx(tx.to_binary(), None).unwrap();
    assert_eq!(beef.find_txid(named).map(BeefTx::id), Some(lower.clone()));
    assert!(beef.find_bump(named).is_some());
    assert!(beef.find_transaction_for_signing(named).is_some());
    assert!(beef.find_atomic_transaction(named).is_some());
    assert_eq!(beef.edit_tx(named, |tx| tx.lock_time()), Ok(0));
    let atomic = beef.to_binary_atomic(named).unwrap();
    assert_eq!(
        Beef::from_binary(&atomic).unwrap().atomic_txid,
        Some(tx.txid())
    );
    let whole = beef.to_binary().unwrap();
    assert_eq!(
        Transaction::from_beef(&whole, Some(named)).map(|t| t.id()),
        Ok(lower.clone())
    );
    assert_eq!(
        beef.merge_txid_only(named).id(),
        lower,
        "the held entry, kept"
    );
    assert_eq!(
        beef.txs().len(),
        1,
        "no second entry for the upper-case text"
    );
    assert!(beef.make_txid_only(named).is_some());
    assert!(beef.txs()[0].is_txid_only());

    // A txid-only entry writes its 32 bytes in wire order, whatever the
    // case its text came in.
    let mut only = Beef::new();
    only.merge_txid_only(named);
    let written = only.to_binary().unwrap();
    assert_eq!(written.len(), 4 + 1 + 1 + 1 + 32);
    assert_eq!(&written[7..], tx.txid().as_wire_bytes());
}

/// Stated, not closed (#843b): `MerklePath` compares a leaf's hash as the
/// text held, and is unchanged by this cut. A BUMP built by hand whose
/// level-0 hash is in upper case was found by the upper-case text until the
/// doors took a `Txid`, and is found by no `Txid`, whose text is lower case:
/// no entry is given its index, by either merge door.
#[test]
fn a_bump_leaf_in_upper_case_is_found_by_no_txid_stated_843b() {
    let tx = spending(1);
    let upper = tx.id().to_uppercase();
    let bump = MerklePath::new(
        100,
        vec![vec![
            MerklePathLeaf::new_txid(0, upper.clone()),
            MerklePathLeaf::new(1, "22".repeat(32)),
        ]],
    )
    .unwrap();
    assert!(bump.contains(&upper) && !bump.contains(&tx.id()));
    let mut beef = Beef::new();
    beef.merge_bump(bump);
    assert!(beef.find_bump(tx.txid()).is_none());
    assert!(beef.find_bump(upper.parse().unwrap()).is_none());
    let raw = beef.merge_raw_tx(tx.to_binary(), None).unwrap();
    assert_eq!(raw.bump_index(), None);
    let mut other = Beef::new();
    other.merge_bump(beef.bumps()[0].clone());
    assert_eq!(
        other.merge_txid_only(upper.parse().unwrap()).bump_index(),
        None
    );
}

/// `set_bump_index` on a BEEF read from bytes marks it: `merge_beef` of it
/// walks the entries sorted, as an edited BEEF is walked, where the same
/// edit through `find_txid_mut` left it "as read" (#764's residue) and the
/// child was merged ahead of its parent.
#[test]
fn set_bump_index_marks_a_beef_read_from_bytes_843b() {
    let parent = spending(2);
    let mut child = Transaction::new();
    let mut input = TransactionInput::new(parent.txid(), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    child.inputs_mut().push(input);
    child.outputs_mut().push(TransactionOutput::new(
        900,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    let bump = MerklePath::new(
        100,
        vec![vec![
            MerklePathLeaf::new_txid(0, parent.id()),
            MerklePathLeaf::new(1, "22".repeat(32)),
        ]],
    )
    .unwrap();
    // The unproven child written ahead of its proven parent.
    let bytes = frame(
        BEEF_V2,
        &[bump],
        &[
            BeefTx::from_raw_tx(child.to_binary(), None).unwrap(),
            BeefTx::from_raw_tx(parent.to_binary(), Some(0)).unwrap(),
        ],
    );
    let merged = |source: &Beef| -> Vec<Txid> {
        let mut target = Beef::new();
        target.merge_beef(source).unwrap();
        target.txs().iter().map(BeefTx::txid).collect()
    };
    let read = Beef::from_binary(&bytes).unwrap();
    assert_eq!(merged(&read), [child.txid(), parent.txid()], "as read");
    let mut edited = Beef::from_binary(&bytes).unwrap();
    edited.set_bump_index(parent.txid(), Some(0)).unwrap();
    assert_eq!(merged(&edited), [parent.txid(), child.txid()], "sorted");
    assert_eq!(
        edited.set_bump_index("77".repeat(32).parse().unwrap(), None),
        Err(bsv_rs::Error::BeefError(format!(
            "{} does not exist in this Beef",
            "77".repeat(32)
        )))
    );
}

/// A trim keeps the parse of a proven entry held raw, as it always has: the
/// entry's transaction is not parsed when it is merged with a BUMP index
/// (`tx()` none), `trim_known_proven` reads its inputs from the bytes and
/// keeps what it read, and after it the lookups that hand a transaction
/// back answer for the entry. Found by the lane's differential of the base
/// against the tip (the tip as built before that run read the inputs through `&self`
/// and kept nothing, so both lookups answered `None` after a trim); the
/// bytes, the txid, the order and the marks are the same either way.
#[test]
fn a_trim_keeps_the_parse_of_a_proven_entry_held_raw_843b() {
    let proven = spending(4);
    let mut beef = Beef::new();
    let bump = beef.merge_bump(
        MerklePath::new(
            100,
            vec![vec![
                MerklePathLeaf::new_txid(0, proven.id()),
                MerklePathLeaf::new(1, "22".repeat(32)),
            ]],
        )
        .unwrap(),
    );
    beef.merge_raw_tx(proven.to_binary(), Some(bump)).unwrap();
    let written = beef.to_binary().unwrap();
    assert!(beef.find_txid(proven.txid()).unwrap().tx().is_none());
    assert!(beef.find_atomic_transaction(proven.txid()).is_none());
    assert!(beef.find_transaction_for_signing(proven.txid()).is_none());

    beef.trim_known_proven();
    let entry = beef.find_txid(proven.txid()).unwrap();
    assert_eq!(entry.tx().map(Transaction::txid), Some(proven.txid()));
    assert_eq!(
        entry.raw_tx(),
        Some(&proven.to_binary()[..]),
        "its bytes kept"
    );
    assert_eq!(entry.bump_index(), Some(bump));
    let linked = beef.find_atomic_transaction(proven.txid()).unwrap();
    assert_eq!(linked.txid(), proven.txid());
    assert!(linked.merkle_path.is_some(), "with the BEEF's BUMP");
    assert_eq!(
        beef.find_transaction_for_signing(proven.txid())
            .map(|tx| tx.txid()),
        Some(proven.txid())
    );
    assert_eq!(beef.to_binary().unwrap(), written, "no byte moves");
}

/// A txid-only entry's frame is its txid's 32 bytes in wire order, at both
/// doors that read or write one alone: `BeefTx::to_writer` writes the format
/// byte `02` and the bytes `as_wire_bytes` gives (the display text
/// reversed), and `BeefTx::from_reader` reads them back as the same `Txid`.
/// With either conversion in the display order the entry reads back as the
/// reversed id.
#[test]
fn a_txid_only_entry_is_framed_in_wire_order_by_its_own_reader_and_writer_843b() {
    let text: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
    let txid: Txid = text.parse().unwrap();
    let entry = BeefTx::from_txid(txid);
    let mut writer = Writer::new();
    entry.to_writer(&mut writer, BEEF_V2).unwrap();
    let bytes = writer.into_bytes();
    let mut want = vec![2u8];
    want.extend((0u8..32).rev());
    assert_eq!(bytes, want, "02 and the text's bytes reversed");
    let read = BeefTx::from_reader(&mut bsv_rs::primitives::Reader::new(&bytes), BEEF_V2).unwrap();
    assert!(read.is_txid_only());
    assert_eq!(read.txid(), txid);
    assert_eq!(read.id(), text);
}
