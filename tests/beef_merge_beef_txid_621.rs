//! #621: `Beef::merge_beef` stores each source raw entry under the txid the
//! entry holds, where it went through `merge_raw_tx` and hashed the bytes a
//! second time. Nothing observable moves: on every BEEF the tree holds that
//! `Beef::from_binary` reads (the seeds of `beef_two_readers_agree.rs`),
//! merged into an empty `Beef` and into one already holding a txid-only
//! entry and a raw entry of the source, the bytes written, each entry's
//! BUMP index, the entries' order and `find_txid` equal the per-entry merge
//! through the public `merge_bump` then `merge_raw_tx(raw, None)` for each
//! entry the target does not hold raw (the reference's conditions since
//! #621's fold). Green on the base and the tip (the no-change evidence: no
//! case of the 260 moves with the fold); the RED witnesses are the unit
//! tests `src/transaction/beef/merge_entry_621_tests.rs` and the held-entry
//! cases of `tests/beef_merge_beef_held_621.rs`.
//!
//! #817's pin: on those targets the held raw entry and the source's are the
//! same bytes under the same index, so the differential stayed green with the
//! held-entry rule's return removed (`src/transaction/beef/merge_entry.rs`,
//! `holds_a_transaction`). Two more targets hold an entry that differs
//! observably from the source's: a raw entry under a BUMP of the target's own
//! at index 0 where the source's BUMP holding the txid lands later (a rescan
//! names the later), and a parsed entry `merge_transaction` stored with its
//! source link (a replacement holds the bytes alone). On every BEEF of the
//! tree that offers the shape the index and the link are kept, and the bytes
//! and entries equal the per-entry model's.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::transaction::{Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction};

#[path = "support/beef_chain.rs"]
mod beef_chain;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn beef_hex(s: &str) -> Option<Vec<u8>> {
    let lower = s.to_ascii_lowercase();
    let opens = ["0100beef", "0200beef", "01010101"]
        .iter()
        .any(|p| lower.starts_with(p));
    if opens && lower.len().is_multiple_of(2) {
        from_hex(&lower).ok()
    } else {
        None
    }
}

fn hex_in_json(value: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
    match value {
        serde_json::Value::String(s) => out.extend(beef_hex(s)),
        serde_json::Value::Array(items) => items.iter().for_each(|v| hex_in_json(v, out)),
        serde_json::Value::Object(map) => map.values().for_each(|v| hex_in_json(v, out)),
        _ => {}
    }
}

fn json_beefs(dir: &Path, seeds: &mut Vec<(String, Vec<u8>)>) {
    let mut paths = Vec::new();
    files(dir, &mut paths);
    for path in paths {
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let mut found = Vec::new();
        hex_in_json(&value, &mut found);
        for (i, bytes) in found.into_iter().enumerate() {
            seeds.push((format!("{}#{i}", path.display()), bytes));
        }
    }
}

fn bin_files(dir: &Path, seeds: &mut Vec<(String, Vec<u8>)>) {
    let mut paths = Vec::new();
    files(dir, &mut paths);
    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "md" || ext == "txt" {
            continue;
        }
        seeds.push((path.display().to_string(), std::fs::read(&path).unwrap()));
    }
}

/// Every BEEF the tree holds that `Beef::from_binary` reads, by bytes once.
fn sources() -> Vec<(String, Beef)> {
    let root = crate_dir();
    let mut seeds = Vec::new();
    json_beefs(&root.join("tests/fixtures"), &mut seeds);
    json_beefs(&root.join("tests/vectors"), &mut seeds);
    json_beefs(&root.join("tests/transaction/vectors"), &mut seeds);
    bin_files(&root.join("tests/vectors/beef_of_any_size"), &mut seeds);
    bin_files(&root.join("fuzz/corpus/fuzz_beef_parser"), &mut seeds);
    let mut chain = Vec::new();
    beef_chain::ChainSource::new(40)
        .read_to_end(&mut chain)
        .unwrap();
    seeds.push(("deep chain of 40".into(), chain));
    let mut seen = BTreeSet::new();
    seeds.retain(|(_, bytes)| seen.insert(bytes.clone()));
    seeds
        .into_iter()
        .filter_map(|(name, bytes)| Beef::from_binary(&bytes).ok().map(|b| (name, b)))
        .collect()
}

/// The per-entry merge by the public doors under the reference's conditions
/// (`#mergeBeefTxEntry`, `Beef.ts:950-967`): each BUMP through `merge_bump`,
/// each entry one by one, a raw entry the target does not hold raw through
/// `merge_raw_tx(raw, None)` (the hash of its bytes). Until #621's fold the
/// raw entry went through `merge_raw_tx` whatever the target held; on these
/// 260 BEEFs the two models write the same (green on `abbda405` and the tip).
fn merge_entry_by_entry(target: &mut Beef, source: &Beef) {
    for bump in source.bumps() {
        target.merge_bump(bump.clone());
    }
    for tx in source.txs() {
        if tx.is_txid_only() {
            target.merge_txid_only(tx.txid());
        } else if let Some(raw) = tx.raw_tx() {
            let held = target
                .find_txid(tx.txid())
                .is_some_and(|e| !e.is_txid_only());
            if !held {
                target
                    .merge_raw_tx(raw.to_vec(), None)
                    .expect("the bytes are one transaction");
            }
        } else {
            panic!("a BEEF read from bytes holds bytes or a txid");
        }
    }
}

/// What a reader of the merged BEEF sees.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    bytes: Vec<u8>,
    entries: Vec<(String, Option<usize>, bool)>,
    found: Vec<bool>,
}

fn seen(mut beef: Beef, txids: &[String]) -> Seen {
    let bytes = beef.to_binary().expect("the BEEF is writable");
    let entries = beef
        .txs()
        .iter()
        .map(|t| (t.id(), t.bump_index(), t.is_txid_only()))
        .collect();
    let found = txids
        .iter()
        .map(|t| beef.find_txid(t.parse().unwrap()).is_some())
        .collect();
    Seen {
        bytes,
        entries,
        found,
    }
}

/// A target already holding a txid-only entry and a raw entry of the source
/// (the two leading raw entries), or `None` with fewer than two.
fn prefilled(source: &Beef) -> Option<Beef> {
    let mut raws = source
        .txs()
        .iter()
        .filter_map(|t| t.raw_tx().map(|r| (t.txid(), r)));
    let (leading, _) = raws.next()?;
    let (_, second) = raws.next()?;
    let mut target = Beef::new();
    target.merge_txid_only(leading);
    target
        .merge_raw_tx(second.to_vec(), None)
        .expect("the bytes are one transaction");
    Some(target)
}

#[test]
fn merge_beef_writes_the_bytes_the_per_entry_merge_writes_621() {
    let sources = sources();
    assert!(sources.len() > 50, "the tree's BEEFs: {}", sources.len());
    let mut prefilled_count = 0;
    for (name, source) in &sources {
        let txids: Vec<String> = source.txs().iter().map(BeefTx::id).collect();

        let mut merged = Beef::new();
        merged
            .merge_beef(source)
            .expect("the source BEEF writes and reads back");
        let mut by_entry = Beef::new();
        merge_entry_by_entry(&mut by_entry, source);
        assert_eq!(
            seen(merged, &txids),
            seen(by_entry, &txids),
            "{name}: into an empty BEEF"
        );

        if let (Some(mut merged), Some(mut by_entry)) = (prefilled(source), prefilled(source)) {
            prefilled_count += 1;
            merged
                .merge_beef(source)
                .expect("the source BEEF writes and reads back");
            merge_entry_by_entry(&mut by_entry, source);
            assert_eq!(
                seen(merged, &txids),
                seen(by_entry, &txids),
                "{name}: into a held BEEF"
            );
        }
    }
    eprintln!(
        "{} BEEFs merged, {prefilled_count} into a held BEEF too",
        sources.len()
    );
    assert!(prefilled_count > 0);
}

/// A source entry merged from raw bytes is filed by `merge_beef` under the
/// hash of those bytes.
///
/// Replaces `a_source_entry_built_from_raw_bytes_without_a_txid_merges_under_its_hash_621`,
/// which pushed `BeefTx::from_raw_tx(raw, None)`, an entry holding no txid,
/// onto the public `txs`. No public door puts such an entry in a `Beef`
/// since #843b (the push does not compile: `src/transaction/beef/rows.rs`'
/// `compile_fail` doc tests); `merge_raw_tx` is the door for raw bytes and
/// files the entry under their hash where it enters, which `merge_beef`
/// keeps.
#[test]
fn a_source_entry_merged_from_raw_bytes_merges_under_its_hash_843b() {
    let (_, chain) = sources()
        .into_iter()
        .find(|(name, _)| name == "deep chain of 40")
        .unwrap();
    let raw = chain.txs()[1].raw_tx().unwrap().to_vec();
    let mut hash = sha256d(&raw);
    hash.reverse();
    let txid = to_hex(&hash);

    let mut source = Beef::new();
    source
        .merge_raw_tx(raw.clone(), None)
        .expect("the bytes are one transaction");
    let mut merged = Beef::new();
    merged
        .merge_beef(&source)
        .expect("the source BEEF writes and reads back");
    assert_eq!(
        merged.find_txid(txid.parse().unwrap()).unwrap().raw_tx(),
        Some(raw.as_slice())
    );
    assert_eq!(merged.txs().len(), 1);
}

/// A source entry edited through `edit_tx` is re-keyed at once and merges
/// under its new txid, its bytes the edited transaction's.
///
/// Replaces `a_source_entry_mutated_through_tx_mut_merges_under_its_new_txid_621`:
/// `BeefTx::tx_mut` and `Beef::find_txid_mut` do not compile since #843b
/// (`src/transaction/beef/rows.rs`' `compile_fail` doc tests). Through
/// `tx_mut` the entry dropped its bytes and waited for `merge_beef`'s scan
/// to re-key it; through `edit_tx` an entry held raw stays raw, re-written,
/// and the source is found by the new txid before any merge.
#[test]
fn a_source_entry_edited_through_edit_tx_merges_under_its_new_txid_843b() {
    let (_, mut source) = sources()
        .into_iter()
        .find(|(name, _)| name == "deep chain of 40")
        .unwrap();
    let old = source.txs()[2].txid();
    let new = source
        .edit_tx(old, |tx| {
            tx.set_lock_time(7);
            tx.txid()
        })
        .unwrap();
    assert_ne!(old, new);
    assert!(source.find_txid(new).is_some(), "re-keyed at once");
    assert!(source.find_txid(old).is_none());

    let mut merged = Beef::new();
    merged
        .merge_beef(&source)
        .expect("the source BEEF writes and reads back");
    assert!(merged.find_txid(new).is_some());
    assert!(merged.find_txid(old).is_none());
    assert_eq!(merged.find_txid(new).unwrap().tx().unwrap().lock_time(), 7);
}

/// #817: a target holding a raw entry of the source under a BUMP of its own
/// at index 0 (the txid alone in a block one above the source's highest, so
/// no BUMP of the source combines into it), where a BUMP of the source holds
/// the txid at level 0 too: after the merge that BUMP sits at index 1 or
/// later, the index a rescan of the entry would name. `None` where the source
/// proves no raw entry. The target and the entry's txid.
fn held_under_its_own_bump(source: &Beef) -> Option<(Beef, String)> {
    let (txid, raw) = source.txs().iter().find_map(|t| {
        let raw = t.raw_tx()?;
        let txid = t.txid();
        let bump = source.bumps().get(t.bump_index()?)?;
        bump.path
            .first()?
            .iter()
            .any(|leaf| leaf.hash.as_deref().is_some_and(|hash| txid == hash))
            .then(|| (txid, raw.to_vec()))
    })?;
    let height = source.bumps().iter().map(|b| b.block_height).max()?;
    let own = MerklePath::new(
        height.checked_add(1)?,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .ok()?;
    let mut target = Beef::new();
    assert_eq!(target.merge_bump(own), 0);
    let held = target
        .merge_raw_tx(raw, None)
        .expect("the bytes are one transaction");
    assert_eq!(
        held.bump_index(),
        Some(0),
        "the target's own BUMP proves it"
    );
    Some((target, txid.to_string()))
}

/// #817: a target holding a raw child of the source as `merge_transaction`
/// stores it, parsed and linked to its parent (a raw entry of the source
/// too), or `None` where no raw entry of the source spends another. The
/// target, the child's txid and the linked input's position.
fn held_with_its_source_link(source: &Beef) -> Option<(Beef, String, usize)> {
    source.txs().iter().find_map(|t| {
        let mut child = Transaction::from_binary(t.raw_tx()?).ok()?;
        let (at, parent) = child.inputs().iter().enumerate().find_map(|(at, input)| {
            let named = input.source_txid.map(|t| t.to_string())?;
            let parent = source.find_txid(named.parse().unwrap())?;
            Some((at, Transaction::from_binary(parent.raw_tx()?).ok()?))
        })?;
        child.inputs_mut()[at].source_transaction = Some(Box::new(parent));
        let txid = child.id();
        let mut target = Beef::new();
        target.merge_transaction(child);
        Some((target, txid, at))
    })
}

/// True when the entry under `txid` is held parsed with its input `at`
/// linked to a source transaction.
fn linked(beef: &Beef, txid: &str, at: usize) -> bool {
    beef.find_txid(txid.parse().unwrap())
        .and_then(BeefTx::tx)
        .and_then(|tx| tx.inputs().get(at))
        .is_some_and(|input| input.source_transaction.is_some())
}

/// #817, the bucket's line on this differential: an entry the target holds
/// raw is left as it is by `merge_beef` (the reference's
/// `#mergeBeefTxEntry`, `Beef.ts:950-967` at `ts-stack@edf6e03`; its recorded
/// cell is `beef_merge_beef_held_621.rs`'s `held_raw_keeps_its_bump_index`),
/// told here on every BEEF of the tree that proves a raw entry: the index 0
/// of the target's own BUMP kept where the source's BUMP holding the txid
/// lands later, the index a rescan would name.
#[test]
fn a_held_raw_entry_keeps_the_index_of_its_own_bump_on_every_beef_817() {
    let sources = sources();
    let mut indexed = 0;
    for (name, source) in &sources {
        let txids: Vec<String> = source.txs().iter().map(BeefTx::id).collect();
        let (Some((mut merged, txid)), Some((mut by_entry, _))) = (
            held_under_its_own_bump(source),
            held_under_its_own_bump(source),
        ) else {
            continue;
        };
        indexed += 1;
        merged
            .merge_beef(source)
            .expect("the source BEEF writes and reads back");
        let later = merged.bumps().iter().skip(1).any(|b| {
            b.path
                .first()
                .is_some_and(|l| l.iter().any(|leaf| leaf.hash.as_deref() == Some(&txid)))
        });
        assert!(later, "{name}: a later BUMP holds the held txid");
        assert_eq!(
            merged
                .find_txid(txid.parse().unwrap())
                .unwrap()
                .bump_index(),
            Some(0),
            "{name}: the held raw entry keeps the index it was held under"
        );
        merge_entry_by_entry(&mut by_entry, source);
        assert_eq!(
            seen(merged, &txids),
            seen(by_entry, &txids),
            "{name}: into a BEEF holding the entry under its own BUMP"
        );
    }
    eprintln!(
        "{} BEEFs, {indexed} merged into a BEEF holding an entry under its own BUMP",
        sources.len()
    );
    assert!(indexed >= 10, "held under an own BUMP: {indexed}");
}

/// #817, the same line: an entry the target holds parsed, as
/// `merge_transaction` stored it with its source link, is left as it is by
/// `merge_beef` (the recorded cell `held_parsed_entry_keeps_its_links`), told
/// here on every BEEF of the tree where a raw entry spends another: the link
/// kept, where a replacement would hold the source's bytes alone.
#[test]
fn a_held_parsed_entry_keeps_its_source_link_on_every_beef_817() {
    let sources = sources();
    let mut with_links = 0;
    for (name, source) in &sources {
        let txids: Vec<String> = source.txs().iter().map(BeefTx::id).collect();
        let (Some((mut merged, txid, at)), Some((mut by_entry, _, _))) = (
            held_with_its_source_link(source),
            held_with_its_source_link(source),
        ) else {
            continue;
        };
        with_links += 1;
        assert!(linked(&merged, &txid, at), "{name}: held with its link");
        merged
            .merge_beef(source)
            .expect("the source BEEF writes and reads back");
        assert!(
            linked(&merged, &txid, at),
            "{name}: the held parsed entry keeps its source link"
        );
        merge_entry_by_entry(&mut by_entry, source);
        assert!(linked(&by_entry, &txid, at), "{name}: the model's too");
        assert_eq!(
            seen(merged, &txids),
            seen(by_entry, &txids),
            "{name}: into a BEEF holding the entry with its link"
        );
    }
    eprintln!(
        "{} BEEFs, {with_links} merged into a BEEF holding an entry with its source link",
        sources.len()
    );
    assert!(with_links >= 10, "held with a source link: {with_links}");
}
