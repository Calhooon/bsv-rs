//! The two entry points of the BEEF reader, on every BEEF input the tree has
//! (bsv-rs#86): `Beef::from_binary` then `Beef::verify_structure` (the whole
//! path, `verify_valid` without the roots' check) and
//! `verify_stream_structure` (the streaming reader, the Lean's validity).
//! Each input is read by both, and every disagreement is recorded: accepted
//! by one and refused by the other, the kinds, the offsets where both name
//! one, the roots of an accepted BEEF.
//!
//! The inputs: the hex BEEFs of the fixtures and vectors under `tests/`
//! (`tests/fixtures`, `tests/vectors`, `tests/transaction/vectors`), the
//! `beef_of_any_size` vectors, the fuzz seed corpus of `fuzz_beef_parser`,
//! the ts-stack corpus when `BSV_CONFORMANCE_DIR` is set, a deep chain, and
//! from each of those the hand-built derivations the tests build (each
//! prefix of a short input, three single-byte changes at each byte, the
//! transactions in reverse order).
//!
//! The headers carry the root of the leading BUMP at each height, the one
//! root a chain carries there, at the heights a chain reaches (the in-memory
//! height is a `u32`); the whole path reads the same rule from the BEEF
//! alone (two BUMPs at one height with different roots are
//! `RootNotCarried`, and so is a BUMP above a `u32` height). The whole path's verdict on a BEEF it holds in memory
//! names no offset; an offset is compared where both name one.
//!
//! No difference is stated. A transaction written ahead of the parent it
//! spends is refused by both, `InputNamesNoElement` (BRC-62's dependency
//! order, the charter's validity clause): through 0.9.0 the whole
//! path sorted ahead of judging, as `@bsv/sdk`'s `Beef.verifyValid` does
//! (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts:1065`), and
//! accepted what the stream refused.
//!
//! `BEEF_TWO_READERS_TABLE=<path>` writes the table of disagreements there.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use bsv_rs::primitives::{from_hex, Writer};
use bsv_rs::transaction::{verify_stream_structure, Beef, BeefStream, Element, Kind, Verdict};

#[path = "support/beef_chain.rs"]
mod beef_chain;

use beef_chain::Hash32;

/// What one entry point said of one input.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// Accepted, with the roots by height (display hex).
    Valid(BTreeSet<(u64, String)>),
    /// Refused: the kind when one is named, the offset when one is named,
    /// and the text.
    Refused {
        kind: Option<Kind>,
        offset: Option<u64>,
        text: String,
    },
}

impl Answer {
    fn short(&self) -> String {
        match self {
            Answer::Valid(roots) => format!("valid ({} roots)", roots.len()),
            Answer::Refused { kind, offset, text } => {
                let kind = kind.map_or_else(|| format!("no kind: {text}"), |k| format!("{k:?}"));
                match offset {
                    Some(o) => format!("{kind} at {o}"),
                    None => kind,
                }
            }
        }
    }
}

/// The kind and the offset of a refusal in the reader's words, `invalid
/// BEEF at byte N: Reason`.
fn refusal_in_words(text: &str) -> Option<(u64, Kind)> {
    let rest = &text[text.find("invalid BEEF at byte ")? + "invalid BEEF at byte ".len()..];
    let (offset, reason) = rest.split_once(": ")?;
    let name: String = reason
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    let kind = Kind::ALL.into_iter().find(|k| format!("{k:?}") == name)?;
    Some((offset.parse().ok()?, kind))
}

fn display(hash: &Hash32) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    bsv_rs::primitives::to_hex(&bytes)
}

/// The whole path: parse, then the structure.
fn whole(bytes: &[u8]) -> Answer {
    let mut beef = match Beef::from_binary(bytes) {
        Ok(beef) => beef,
        Err(e) => {
            let text = e.to_string();
            let named = refusal_in_words(&text);
            return Answer::Refused {
                kind: named.map(|(_, k)| k),
                offset: named.map(|(o, _)| o),
                text,
            };
        }
    };
    match beef.verify_structure() {
        Ok(roots) => Answer::Valid(roots.into_iter().map(|(h, r)| (h as u64, r)).collect()),
        Err(kind) => Answer::Refused {
            kind: Some(kind),
            offset: None,
            text: format!("{kind:?}"),
        },
    }
}

/// The root of the leading BUMP at each height, as the stream cuts them, at
/// the heights a chain reaches (the in-memory height is a `u32`).
fn leading_roots(bytes: &[u8]) -> HashMap<u64, Hash32> {
    let mut roots = HashMap::new();
    for element in BeefStream::new(bytes) {
        match element {
            // A chain's heights: the in-memory height is a `u32`.
            Ok(Element::Bump(bump)) if u32::try_from(bump.block_height).is_ok() => {
                roots.entry(bump.block_height).or_insert(bump.root);
            }
            Ok(Element::Bump(_)) => {}
            _ => break,
        }
    }
    roots
}

/// The streaming reader on the BEEF's structure.
fn stream(bytes: &[u8]) -> Answer {
    let headers = leading_roots(bytes);
    match verify_stream_structure(bytes, &headers, None).expect("a slice never fails to read") {
        Verdict::Valid { roots, .. } => {
            Answer::Valid(roots.iter().map(|(h, r)| (*h, display(r))).collect())
        }
        Verdict::Invalid {
            offset,
            kind,
            reason,
        } => Answer::Refused {
            kind: Some(kind),
            offset: Some(offset),
            text: format!("{reason:?}"),
        },
        other => Answer::Refused {
            kind: None,
            offset: None,
            text: format!("{other:?}"),
        },
    }
}

/// How two answers differ, if they do.
fn disagreement(whole: &Answer, stream: &Answer) -> Option<&'static str> {
    match (whole, stream) {
        (Answer::Valid(a), Answer::Valid(b)) => (a != b).then_some("roots"),
        (Answer::Valid(_), Answer::Refused { .. }) => Some("whole accepts, stream refuses"),
        (Answer::Refused { .. }, Answer::Valid(_)) => Some("whole refuses, stream accepts"),
        (
            Answer::Refused {
                kind: ka,
                offset: oa,
                ..
            },
            Answer::Refused {
                kind: kb,
                offset: ob,
                ..
            },
        ) => {
            if ka.is_none() {
                Some("whole names no kind")
            } else if ka != kb {
                Some("kinds")
            } else if oa.is_some() && oa != ob {
                Some("offsets")
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The inputs
// ---------------------------------------------------------------------------

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

/// A string of hex that opens as a BEEF does.
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

fn json_beefs(dir: &Path, label: &str, seeds: &mut Vec<(String, Vec<u8>)>) {
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
        // The seed's name reads the same on every OS: the whole-suite run on
        // Windows (#146) looked for `fixtures/beef/v1.json#0` and found a
        // backslash.
        let name = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        for (i, bytes) in found.into_iter().enumerate() {
            seeds.push((format!("{label}/{name}#{i}"), bytes));
        }
    }
}

fn bin_files(dir: &Path, label: &str, seeds: &mut Vec<(String, Vec<u8>)>) {
    let mut paths = Vec::new();
    files(dir, &mut paths);
    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "md" || ext == "txt" {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        seeds.push((format!("{label}/{name}"), std::fs::read(&path).unwrap()));
    }
}

/// The seeds: every BEEF the tree holds, deduplicated by bytes.
fn seeds() -> Vec<(String, Vec<u8>)> {
    let root = crate_dir();
    let mut seeds = Vec::new();
    json_beefs(&root.join("tests/fixtures"), "fixtures", &mut seeds);
    json_beefs(&root.join("tests/vectors"), "vectors", &mut seeds);
    json_beefs(
        &root.join("tests/transaction/vectors"),
        "transaction/vectors",
        &mut seeds,
    );
    bin_files(
        &root.join("tests/vectors/beef_of_any_size"),
        "beef_of_any_size",
        &mut seeds,
    );
    bin_files(
        &root.join("fuzz/corpus/fuzz_beef_parser"),
        "fuzz",
        &mut seeds,
    );
    if let Ok(dir) = std::env::var("BSV_CONFORMANCE_DIR") {
        json_beefs(&PathBuf::from(dir).join("vectors"), "ts-stack", &mut seeds);
    }
    let mut chain = Vec::new();
    beef_chain::ChainSource::new(40)
        .read_to_end(&mut chain)
        .unwrap();
    seeds.push(("deep chain of 40".into(), chain));
    seeds.push(("a BUMP at height 2^32".into(), above_u32_height()));

    let mut seen = BTreeSet::new();
    seeds.retain(|(_, bytes)| seen.insert(bytes.clone()));
    seeds
}

/// The funding transaction of the deep chain under a BUMP at height 2^32,
/// its root the txid: valid but for a height no chain reaches.
fn above_u32_height() -> Vec<u8> {
    let mut bytes = 0xEFBE_0002u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend(beef_chain::varint(1 << 32));
    bytes.extend_from_slice(&[1, 1, 0, 2]);
    bytes.extend_from_slice(&beef_chain::funding_root());
    bytes.extend_from_slice(&[1, 1, 0]);
    bytes.extend(beef_chain::funding());
    bytes
}

/// Through 0.9.0 the whole path cut a BUMP's height to its low 32 bits
/// (`as u32`) and keyed the root at height 0 here; the stream reads the
/// height whole. The in-memory height is a `u32`, so the parse refuses the
/// BUMP as the stream refuses it under a chain's headers.
#[test]
fn a_bump_above_a_u32_height_is_refused_not_cut_to_its_low_bits() {
    let bytes = above_u32_height();
    assert_eq!(
        Beef::from_binary(&bytes).unwrap_err().to_string(),
        format!(
            "BEEF error: invalid BEEF at byte 5: RootNotCarried {{ height: 4294967296, root: {:?} }}",
            beef_chain::funding_root()
        )
    );
    assert_eq!(disagreement(&whole(&bytes), &stream(&bytes)), None);
}

/// The BEEF's transactions written in reverse order, when the whole path
/// reads it: an unproven transaction ahead of the parent it spends.
fn reversed(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut beef = Beef::from_binary(bytes).ok()?;
    if beef.txs.len() < 2 {
        return None;
    }
    beef.txs.reverse();
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    Some(writer.into_bytes())
}

/// The seeds and what the tests build from them.
fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut inputs = Vec::new();
    for (name, bytes) in seeds() {
        if let Some(r) = reversed(&bytes) {
            inputs.push((format!("{name} reversed"), r));
        }
        if bytes.len() <= 2_048 {
            for len in 0..bytes.len() {
                inputs.push((format!("{name} cut at {len}"), bytes[..len].to_vec()));
            }
            for at in 0..bytes.len() {
                for (what, change) in [("0x00", 0u8), ("0xff", 0xff)] {
                    if bytes[at] != change {
                        let mut b = bytes.clone();
                        b[at] = change;
                        inputs.push((format!("{name} byte {at} = {what}"), b));
                    }
                }
                let mut b = bytes.clone();
                b[at] ^= 0x01;
                inputs.push((format!("{name} byte {at} ^ 0x01"), b));
            }
            let mut b = bytes.clone();
            b.push(0);
            inputs.push((format!("{name} and a byte"), b));
        }
        inputs.push((name, bytes));
    }
    inputs
}

#[test]
fn the_whole_path_and_the_stream_agree_on_every_beef_the_tree_holds() {
    let inputs = inputs();
    let mut table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut count = 0usize;
    for (name, bytes) in &inputs {
        let w = whole(bytes);
        let s = stream(bytes);
        if let Some(class) = disagreement(&w, &s) {
            count += 1;
            let key = format!(
                "{class} | whole {} | stream {}",
                short_kind(&w),
                short_kind(&s)
            );
            table.entry(key).or_default().push(format!(
                "{name}: whole {}; stream {}",
                w.short(),
                s.short()
            ));
        }
    }
    let mut report = format!(
        "{} inputs read by both entry points, {} disagreements in {} classes\n",
        inputs.len(),
        count,
        table.len()
    );
    for (class, rows) in &table {
        report.push_str(&format!("\n{class}: {} inputs\n", rows.len()));
        for row in rows.iter().take(5) {
            report.push_str(&format!("  {row}\n"));
        }
    }
    println!("{report}");
    if let Ok(path) = std::env::var("BEEF_TWO_READERS_TABLE") {
        let mut full = report.clone();
        for (class, rows) in &table {
            full.push_str(&format!("\n== {class}\n"));
            for row in rows {
                full.push_str(&format!("{row}\n"));
            }
        }
        std::fs::write(path, full).unwrap();
    }
    assert_eq!(count, 0, "the two readers disagree:\n{report}");
}

/// The reversed v1 fixture: its unproven transaction written ahead of the
/// parent it spends. Through 0.9.0 the whole path sorted ahead of
/// judging and accepted it; the stream refused it. Both refuse it now, the
/// stream at the input's previous txid.
#[test]
fn a_transaction_written_ahead_of_its_parent_is_refused_on_the_whole_path() {
    let (_, v1) = seeds()
        .into_iter()
        .find(|(name, _)| name == "fixtures/beef/v1.json#0")
        .expect("the v1 fixture");
    let bytes = reversed(&v1).expect("two transactions");
    let mut beef = Beef::from_binary(&bytes).expect("the frame parses");
    assert_eq!(beef.verify_structure(), Err(Kind::InputNamesNoElement));
    assert!(!beef.verify_valid(false).valid);
    let Answer::Refused {
        kind: Some(Kind::InputNamesNoElement),
        offset: Some(_),
        ..
    } = stream(&bytes)
    else {
        panic!("the stream refuses the input: {:?}", stream(&bytes));
    };
    assert_eq!(disagreement(&whole(&bytes), &stream(&bytes)), None);
}

/// The class of an answer for the table: valid, or the kind refused.
fn short_kind(a: &Answer) -> String {
    match a {
        Answer::Valid(_) => "valid".into(),
        Answer::Refused { kind: Some(k), .. } => format!("{k:?}"),
        Answer::Refused { text, .. } => {
            // The text without its numbers, so one error class is one row.
            let t: String = text.chars().filter(|c| !c.is_ascii_digit()).collect();
            format!("\"{t}\"")
        }
    }
}

// ---------------------------------------------------------------------------
// A repeated leaf offset (bsv-rs#86, the keeper's reading)
// ---------------------------------------------------------------------------

/// One leaf of a hand-built BUMP: its offset, its flag, its hash (none for
/// flag `01`).
type HandLeaf = (u64, u8, Hash32);

/// A V1 BEEF of one BUMP with `levels` at the chain's height and the
/// funding transaction under it, and the stream offset of each leaf's offset
/// varint, by level.
fn bump_beef(levels: &[Vec<HandLeaf>]) -> (Vec<u8>, Vec<Vec<u64>>) {
    let mut bytes = 0xEFBE_0001u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend(beef_chain::varint(beef_chain::HEIGHT));
    bytes.push(levels.len() as u8);
    let mut at = Vec::new();
    for level in levels {
        bytes.extend(beef_chain::varint(level.len() as u64));
        let mut here = Vec::new();
        for (offset, flag, hash) in level {
            here.push(bytes.len() as u64);
            bytes.extend(beef_chain::varint(*offset));
            bytes.push(*flag);
            if *flag != 1 {
                bytes.extend_from_slice(hash);
            }
        }
        at.push(here);
    }
    bytes.push(1);
    bytes.extend(beef_chain::funding());
    bytes.extend_from_slice(&[1, 0]);
    (bytes, at)
}

const SIBLING: Hash32 = [0x5a; 32];
const OTHER: Hash32 = [0xa5; 32];

/// Both paths refuse `bytes` as `DuplicateOffset { level, offset }` at
/// `at`, the second leaf's offset varint (its own kind by the owner's word
/// of 2026-10-25, bsv-rs#86 and #167; the branch that brought the refusal
/// named it `MismatchedNode`, the walk's kind for a node the level below
/// contradicts).
fn refused_at_the_second_leaf(bytes: &[u8], level: u8, offset: u64, at: u64) {
    let text = Beef::from_binary(bytes)
        .expect_err("the parse refuses")
        .to_string();
    assert_eq!(
        text,
        format!("BEEF error: invalid BEEF at byte {at}: DuplicateOffset {{ level: {level}, offset: {offset} }}")
    );
    assert_eq!(
        stream(bytes),
        Answer::Refused {
            kind: Some(Kind::DuplicateOffset),
            offset: Some(at),
            text: format!("DuplicateOffset {{ level: {level}, offset: {offset} }}"),
        }
    );
    assert_eq!(disagreement(&whole(bytes), &stream(bytes)), None);
}

/// The BUMP the repeats are built on is valid on both paths.
#[test]
fn the_bump_the_repeats_are_built_on_is_valid_on_both_paths() {
    let txid = beef_chain::funding_root();
    let (one, _) = bump_beef(&[vec![(0, 2, txid), (1, 0, SIBLING)]]);
    let (two, _) = bump_beef(&[vec![(0, 2, txid), (1, 0, SIBLING)], vec![(1, 0, OTHER)]]);
    for bytes in [one, two] {
        assert!(
            matches!(whole(&bytes), Answer::Valid(_)),
            "{:?}",
            whole(&bytes)
        );
        assert_eq!(disagreement(&whole(&bytes), &stream(&bytes)), None);
    }
}

/// Level 0 carries the txid's sibling twice, the same hash: through the
/// lane's draft both paths read the earlier leaf and accepted it (0.9.0's
/// whole reader refused it, `Duplicate offset`; so does the reference,
/// `MerklePath.ts:221`).
#[test]
fn a_level_0_leaf_repeated_with_the_same_hash_is_refused_on_both_paths() {
    let txid = beef_chain::funding_root();
    let (bytes, at) = bump_beef(&[vec![(0, 2, txid), (1, 0, SIBLING), (1, 0, SIBLING)]]);
    refused_at_the_second_leaf(&bytes, 0, 1, at[0][2]);
}

/// Level 0 carries a node at the sibling's offset twice, different: a
/// flag-`01` leaf after the hash (through the lane's draft the earlier leaf
/// stood and the BEEF was accepted), and a second hash (refused before, as a
/// path node the level contradicts, at the same byte).
#[test]
fn a_level_0_leaf_repeated_with_a_different_node_is_refused_on_both_paths() {
    let txid = beef_chain::funding_root();
    let (bytes, at) = bump_beef(&[vec![(0, 2, txid), (1, 0, SIBLING), (1, 1, [0; 32])]]);
    refused_at_the_second_leaf(&bytes, 0, 1, at[0][2]);
    let (bytes, at) = bump_beef(&[vec![(0, 2, txid), (1, 0, SIBLING), (1, 0, OTHER)]]);
    refused_at_the_second_leaf(&bytes, 0, 1, at[0][2]);
}

/// Level 1 carries the path's sibling twice, the second different: through
/// the lane's draft the earlier leaf stood and the root was its.
#[test]
fn a_higher_level_leaf_repeated_is_refused_on_both_paths() {
    let txid = beef_chain::funding_root();
    let (bytes, at) = bump_beef(&[
        vec![(0, 2, txid), (1, 0, SIBLING)],
        vec![(1, 0, OTHER), (1, 0, SIBLING)],
    ]);
    refused_at_the_second_leaf(&bytes, 1, 1, at[1][1]);
    let (bytes, at) = bump_beef(&[
        vec![(0, 2, txid), (1, 0, SIBLING)],
        vec![(1, 0, OTHER), (1, 0, OTHER)],
    ]);
    refused_at_the_second_leaf(&bytes, 1, 1, at[1][1]);
}

/// A BUMP held in memory with a second leaf at an offset: `verify_structure`
/// refuses it in `merkle_path_root`'s pre-pass ahead of the walk, the kind
/// the decoder names on the wire (`DuplicateOffset`).
#[test]
fn a_repeated_leaf_offset_in_a_bump_held_in_memory_is_refused_by_verify_structure() {
    let txid = beef_chain::funding_root();
    let (bytes, _) = bump_beef(&[vec![(0, 2, txid), (1, 0, SIBLING)], vec![(1, 0, OTHER)]]);
    let mut beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    let leaf = beef.bumps[0].path[1][0].clone();
    let mut changed = leaf.clone();
    changed.hash = Some(display(&SIBLING));
    beef.bumps[0].path[1].push(changed);
    assert_eq!(beef.verify_structure(), Err(Kind::DuplicateOffset));
    beef.bumps[0].path[1][1] = leaf;
    assert_eq!(beef.verify_structure(), Err(Kind::DuplicateOffset));
}
