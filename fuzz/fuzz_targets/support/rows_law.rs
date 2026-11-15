//! #843b's law on a BEEF under edits the input chooses: after every public
//! `&mut` door, the index and every entry's BUMP position are those of the
//! rows held.
//!
//! `fuzz_beef_parser` runs it on every BEEF it parses. The doors and their
//! arguments come from the input's bytes; after each one:
//!
//! - `find_txid` of each row's txid is the LAST row holding it, by the
//!   lower-case and the upper-case text's `Txid` alike, and by a clone;
//! - each row's `txid()` is the hash of the bytes it writes, its `id()` that
//!   txid's text and its `input_txids()` the distinct txids those bytes'
//!   inputs name (none for a row naming a BUMP);
//! - `retain_bumps` re-points every entry by the positions it kept, stated
//!   here apart from the door, and no other door but `trim_known_proven`
//!   moves a BUMP;
//! - the rows as held, written by `to_writer`, read back as the same rows
//!   (a txid-only entry's BUMP position aside: its frame carries none).

use std::collections::{HashMap, HashSet};

use bsv_rs::primitives::Writer;
use bsv_rs::transaction::{Beef, BeefTx, Transaction, Txid};

/// One row as the law compares it: its txid, whether it is a txid alone,
/// the BUMP position it names and the bytes it writes.
type Row = (Txid, bool, Option<usize>, Option<Vec<u8>>);

fn rows(beef: &Beef) -> Vec<Row> {
    beef.txs()
        .iter()
        .map(|t| {
            (
                t.txid(),
                t.is_txid_only(),
                t.bump_index(),
                t.raw_tx_or_compute(),
            )
        })
        .collect()
}

/// The rows as a frame carries them: a txid-only entry's frame is its txid
/// alone (format byte `02`), so the read holds no BUMP position for it.
fn framed(beef: &Beef) -> Vec<Row> {
    let mut rows = rows(beef);
    for row in rows.iter_mut().filter(|r| r.1) {
        row.2 = None;
    }
    rows
}

fn heights(beef: &Beef) -> Vec<u32> {
    beef.bumps().iter().map(|b| b.block_height).collect()
}

/// The law on `beef` as it stands.
fn law(beef: &Beef, at: &str) {
    let copy = beef.clone();
    let mut last: HashMap<Txid, usize> = HashMap::new();
    for (i, row) in beef.txs().iter().enumerate() {
        last.insert(row.txid(), i);
    }
    for (i, row) in beef.txs().iter().enumerate() {
        let txid = row.txid();
        let want = &beef.txs()[last[&txid]];
        let found = beef.find_txid(txid);
        assert!(
            found.is_some_and(|f| std::ptr::eq(f, want)),
            "{at}: row {i}: find_txid is not the last row holding its txid (#843b)"
        );
        let upper: Txid = txid
            .to_string()
            .to_uppercase()
            .parse()
            .expect("64 hex digits in upper case are a txid");
        assert!(
            beef.find_txid(upper).is_some_and(|f| std::ptr::eq(f, want)),
            "{at}: row {i}: the upper-case text names another row (#843b)"
        );
        assert!(
            copy.find_txid(txid)
                .is_some_and(|f| std::ptr::eq(f, &copy.txs()[last[&txid]])),
            "{at}: row {i}: a clone's lookup (#843b)"
        );
        assert_eq!(row.id(), txid.to_string(), "{at}: row {i}: id() (#843b)");
        match row.raw_tx_or_compute() {
            Some(bytes) => {
                let parsed = Transaction::from_binary(&bytes)
                    .expect("a held entry's bytes are one transaction");
                assert_eq!(
                    parsed.txid(),
                    txid,
                    "{at}: row {i}: txid() is not its bytes' hash (#843b)"
                );
                let mut seen = HashSet::new();
                let named: Vec<Txid> = if row.bump_index().is_some() {
                    Vec::new()
                } else {
                    parsed
                        .inputs()
                        .iter()
                        .filter_map(|input| input.source_txid)
                        .filter(|t| seen.insert(*t))
                        .collect()
                };
                assert_eq!(
                    row.input_txids(),
                    named,
                    "{at}: row {i}: input_txids() (#843b)"
                );
            }
            None => assert!(row.is_txid_only(), "{at}: row {i}: no bytes (#843b)"),
        }
    }
    assert_eq!(rows(&copy), rows(beef), "{at}: a clone's rows (#843b)");
    // An edit can leave rows the writer writes and the reader refuses (a
    // BUMP an edit emptied of its proof, for one); the target asserts the
    // round trip of every BEEF as parsed elsewhere (#817).
    let mut writer = Writer::new();
    if beef.to_writer(&mut writer).is_ok() {
        if let Ok(back) = Beef::from_binary(&writer.into_bytes()) {
            assert_eq!(
                framed(&back),
                framed(beef),
                "{at}: written and read back (#843b)"
            );
            assert_eq!(heights(&back), heights(beef), "{at}: the BUMPs read back");
        }
    }
}

/// Up to eight steps through the public `&mut` doors, each chosen by the
/// input's bytes, the law after each.
#[allow(dead_code)] // `fuzz_beef_parser`'s alone; the module is shared.
pub fn edits_keep_the_rows_law(beef: &Beef, data: &[u8]) {
    let pick = |i: usize| data.get(i).copied().unwrap_or(0) as usize;
    let mut beef = beef.clone();
    law(&beef, "a parsed BEEF");
    for n in 0..1 + pick(0) % 8 {
        let (door, arg) = (pick(1 + 2 * n) % 11, pick(2 + 2 * n));
        let held = beef.txs().len();
        let txid = (held > 0).then(|| beef.txs()[arg % held].txid());
        let before = heights(&beef);
        let mut moves_bumps = false;
        match door {
            0 => beef.retain_txs(|e| usize::from(e.txid().as_wire_bytes()[0]) % 3 != arg % 3),
            1 => {
                moves_bumps = true;
                let kept: Vec<bool> = (0..beef.bumps().len())
                    .map(|i| (i + arg) % 3 != 0)
                    .collect();
                // Each entry's position after the door, stated apart from it.
                let want: Vec<Option<usize>> = beef
                    .txs()
                    .iter()
                    .map(|t| {
                        let old = t.bump_index()?;
                        match kept.get(old) {
                            Some(true) => Some(kept[..old].iter().filter(|k| **k).count()),
                            Some(false) => None,
                            None => Some(old),
                        }
                    })
                    .collect();
                beef.retain_bumps(|i, _| kept[i]);
                let after: Vec<Option<usize>> = beef.txs().iter().map(BeefTx::bump_index).collect();
                assert_eq!(after, want, "retain_bumps re-points every entry (#843b)");
                let kept_heights: Vec<u32> = before
                    .iter()
                    .zip(&kept)
                    .filter(|(_, k)| **k)
                    .map(|(h, _)| *h)
                    .collect();
                assert_eq!(heights(&beef), kept_heights, "the BUMPs kept (#843b)");
            }
            2 => {
                if let Some(txid) = txid {
                    let index = match arg % 3 {
                        0 => None,
                        1 => Some(arg % (beef.bumps().len() + 1)),
                        _ => Some(arg),
                    };
                    beef.set_bump_index(txid, index)
                        .expect("a held txid takes an index (#843b)");
                    assert_eq!(
                        beef.find_txid(txid).and_then(BeefTx::bump_index),
                        index,
                        "stored as given (#843b)"
                    );
                }
            }
            3 => {
                if let Some(txid) = txid {
                    let turn = 1 + arg as u32;
                    if let Ok(new) = beef.edit_tx(txid, |tx| {
                        tx.set_lock_time(tx.lock_time() ^ turn);
                        tx.txid()
                    }) {
                        assert!(
                            beef.find_txid(new).is_some(),
                            "an edit is found at once (#843b)"
                        );
                    }
                }
            }
            4 => {
                let index = arg % (beef.bumps().len() + 1);
                let _ = beef.edit_bump(index, |bump| {
                    if let Some(leaf) = bump.path.first_mut().and_then(|l| l.last_mut()) {
                        leaf.txid = !leaf.txid;
                    }
                });
            }
            5 => {
                if let Some(txid) = txid {
                    beef.make_txid_only(txid);
                }
            }
            6 => {
                let raw = txid
                    .and_then(|t| beef.find_txid(t))
                    .and_then(BeefTx::raw_tx_or_compute);
                if let Some(raw) = raw {
                    let index = (arg % 2 == 0).then_some(arg % 4);
                    beef.merge_raw_tx(raw, index)
                        .expect("a held entry's bytes are one transaction");
                }
            }
            7 => {
                beef.sort_txs();
            }
            8 => {
                moves_bumps = true;
                beef.trim_known_proven();
            }
            9 => {
                if let Some(txid) = txid {
                    beef.merge_txid_only(txid);
                }
            }
            _ => {
                // A txid from the input's bytes, in wire order.
                let mut wire = [0u8; 32];
                for (i, byte) in wire.iter_mut().enumerate() {
                    *byte = pick(3 + n + i) as u8;
                }
                let txid = Txid::from_wire_bytes(wire);
                assert_eq!(beef.merge_txid_only(txid).txid(), txid, "(#843b)");
            }
        }
        if !moves_bumps {
            let after = heights(&beef);
            assert!(
                after.len() >= before.len() && after[..before.len()] == before[..],
                "door {door} moved a BUMP (#843b)"
            );
        }
        law(&beef, "after a door");
    }
}
