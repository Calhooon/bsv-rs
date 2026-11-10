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
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::transaction::{Beef, BeefTx};

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
    for bump in &source.bumps {
        target.merge_bump(bump.clone());
    }
    for tx in &source.txs {
        if tx.is_txid_only() {
            target.merge_txid_only(tx.txid());
        } else if let Some(raw) = tx.raw_tx() {
            let held = target
                .find_txid(&tx.txid())
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
        .txs
        .iter()
        .map(|t| (t.txid(), t.bump_index(), t.is_txid_only()))
        .collect();
    let found = txids.iter().map(|t| beef.find_txid(t).is_some()).collect();
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
        .txs
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
        let txids: Vec<String> = source.txs.iter().map(BeefTx::txid).collect();

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

/// The source entry built by the public constructor holds no txid: the merge
/// files it under its bytes' hash.
#[test]
fn a_source_entry_built_from_raw_bytes_without_a_txid_merges_under_its_hash_621() {
    let (_, chain) = sources()
        .into_iter()
        .find(|(name, _)| name == "deep chain of 40")
        .unwrap();
    let raw = chain.txs[1].raw_tx().unwrap().to_vec();
    let mut hash = sha256d(&raw);
    hash.reverse();
    let txid = to_hex(&hash);

    let mut source = Beef::new();
    source
        .txs
        .push(BeefTx::from_raw_tx(raw.clone(), None).expect("the bytes are one transaction"));
    let mut merged = Beef::new();
    merged
        .merge_beef(&source)
        .expect("the source BEEF writes and reads back");
    assert_eq!(
        merged.find_txid(&txid).unwrap().raw_tx(),
        Some(raw.as_slice())
    );
    assert_eq!(merged.txs.len(), 1);
}

/// An entry mutated through `tx_mut` has dropped its bytes and merges on the
/// parsed branch under its new txid, unchanged by #621.
#[test]
#[allow(deprecated)] // pins the deprecated `tx_mut` path: an entry that dropped its bytes
fn a_source_entry_mutated_through_tx_mut_merges_under_its_new_txid_621() {
    let (_, mut source) = sources()
        .into_iter()
        .find(|(name, _)| name == "deep chain of 40")
        .unwrap();
    let old = source.txs[2].txid();
    let tx = source.find_txid_mut(&old).unwrap().tx_mut().unwrap();
    tx.lock_time = 7;
    let new = tx.id();
    assert_ne!(old, new);

    let mut merged = Beef::new();
    merged
        .merge_beef(&source)
        .expect("the source BEEF writes and reads back");
    assert!(merged.find_txid(&new).is_some());
    assert!(merged.find_txid(&old).is_none());
    assert_eq!(merged.find_txid(&new).unwrap().tx().unwrap().lock_time, 7);
}
