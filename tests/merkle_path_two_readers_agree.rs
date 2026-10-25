//! The two readers of a BUMP, on every BUMP the tree has (bsv-rs#167):
//! `MerklePath::from_reader` (the standalone reader, with `from_binary` and
//! `from_hex` on the same bytes) and the BEEF reader's BUMP decoder, reached
//! by wrapping the bytes as a one-BUMP BEEF (`0100BEEF`, one BUMP): the
//! stream's first element names the BUMP's extent or its refusal, and
//! `Beef::from_binary` on the BUMP with no transaction after it gives the
//! in-memory form. Every disagreement is recorded: accepted by one and
//! refused by the other, the kinds, the offsets (the BEEF's less the five
//! bytes of its header), the bytes the BUMP took, the height, the levels,
//! the root.
//!
//! The inputs: the BUMPs of the fixtures, vectors and ts-stack corpus (a
//! string under a key naming a BUMP, the merkle path fixtures' hex, and the
//! BUMPs of every BEEF there, cut out by the stream), the fuzz seed corpora
//! of `fuzz_merkle_path` (whole) and `fuzz_beef_parser` (their BUMPs), the
//! lone-leaf and cost tests' hand-built BUMPs, flags 3 and 4 (the harness
//! rows `bump-027` and `bump-028`), and from each of those each prefix of a
//! short one, three single-byte changes at each byte and a byte appended.
//!
//! No difference is stated. Through 0.9.0 the standalone reader read a leaf
//! flag by its bits, accepted an offset outside its level, a carried node
//! that disagrees with the one its children make, a level 0 with no hash, a
//! height above a `u32` (cut to its low bits), and named its refusals in
//! words of its own; it is the stream's decoder since (#167).
//!
//! `MERKLE_PATH_TWO_READERS_TABLE=<path>` writes the table of disagreements there.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bsv_rs::primitives::{from_hex, to_hex, Reader};
use bsv_rs::transaction::{Beef, BeefStream, Element, Kind, MerklePath, MerklePathLeaf};

/// The BEEF header the BUMP is wrapped in: the V1 word and a count of one.
const HEADER: [u8; 5] = [0x01, 0x00, 0xbe, 0xef, 0x01];

/// What one reader said of one input.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// Accepted: the bytes the BUMP took, its height, its levels, and the
    /// root from each hash of level 0.
    Valid {
        used: usize,
        height: u32,
        path: Vec<Vec<MerklePathLeaf>>,
        roots: BTreeSet<Option<String>>,
    },
    /// Refused: the kind and the offset when the text names them, and the text.
    Refused {
        kind: Option<Kind>,
        offset: Option<u64>,
        text: String,
    },
}

/// The kind and the offset of a refusal in the stream's words, `invalid
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

fn refused(text: String, less: u64) -> Answer {
    let named = refusal_in_words(&text);
    Answer::Refused {
        kind: named.map(|(_, k)| k),
        offset: named.map(|(o, _)| o - less),
        text,
    }
}

fn valid(path: &MerklePath, used: usize, roots: BTreeSet<Option<String>>) -> Answer {
    Answer::Valid {
        used,
        height: path.block_height,
        path: path.path.clone(),
        roots,
    }
}

/// `compute_root` from each hash of level 0.
fn roots_of(path: &MerklePath) -> BTreeSet<Option<String>> {
    path.path[0]
        .iter()
        .filter_map(|l| l.hash.as_deref())
        .map(|txid| path.compute_root(Some(txid)).ok())
        .collect()
}

/// The standalone reader.
fn standalone(bytes: &[u8]) -> Answer {
    let mut reader = Reader::new(bytes);
    match MerklePath::from_reader(&mut reader) {
        Ok(path) => valid(&path, reader.position(), roots_of(&path)),
        Err(e) => refused(e.to_string(), 0),
    }
}

/// The BEEF reader's BUMP decoder, on the bytes wrapped as a one-BUMP BEEF.
fn beef_reader(bytes: &[u8]) -> Answer {
    let mut wrapped = HEADER.to_vec();
    wrapped.extend_from_slice(bytes);
    let bump = match BeefStream::new(wrapped.as_slice()).next() {
        Some(Ok(Element::Bump(bump))) => bump,
        Some(Ok(other)) => panic!("a BEEF of one BUMP leads with it: {other:?}"),
        Some(Err(e)) => return refused(e.to_string(), HEADER.len() as u64),
        None => panic!("a BEEF of one BUMP yields it or a refusal"),
    };
    let used = bump.wire_len as usize;
    let mut whole = HEADER.to_vec();
    whole.extend_from_slice(&bytes[..used]);
    whole.push(0);
    match Beef::from_binary(&whole) {
        Ok(beef) => {
            // One root, the walk's, from every hash of level 0.
            let mut root = bump.root;
            root.reverse();
            let roots = BTreeSet::from([Some(to_hex(&root))]);
            valid(&beef.bumps[0], used, roots)
        }
        Err(e) => refused(e.to_string(), HEADER.len() as u64),
    }
}

/// How two answers differ, if they do.
fn disagreement(alone: &Answer, beef: &Answer) -> Option<String> {
    match (alone, beef) {
        (
            Answer::Valid {
                used: ua,
                height: ha,
                path: pa,
                roots: ra,
            },
            Answer::Valid {
                used: ub,
                height: hb,
                path: pb,
                roots: rb,
            },
        ) => {
            if ua != ub {
                Some("both accept: the bytes taken".into())
            } else if ha != hb {
                Some("both accept: the height".into())
            } else if pa != pb {
                Some("both accept: the levels".into())
            } else if ra != rb {
                Some("both accept: the roots".into())
            } else {
                None
            }
        }
        (Answer::Valid { .. }, Answer::Refused { kind, .. }) => {
            Some(format!("standalone accepts, BEEF refuses {kind:?}"))
        }
        (Answer::Refused { text, .. }, Answer::Valid { .. }) => Some(format!(
            "standalone refuses `{}`, BEEF accepts",
            numbers_out(text)
        )),
        (
            Answer::Refused {
                kind: ka,
                offset: oa,
                text,
            },
            Answer::Refused {
                kind: kb,
                offset: ob,
                ..
            },
        ) => {
            if ka.is_none() {
                Some(format!(
                    "both refuse: standalone `{}` names no kind, BEEF {kb:?}",
                    numbers_out(text)
                ))
            } else if ka != kb {
                Some(format!("both refuse: kinds {ka:?} and {kb:?}"))
            } else if oa != ob {
                Some(format!("both refuse {ka:?}: offsets"))
            } else {
                None
            }
        }
    }
}

/// A text with its numbers and hashes as `N`, to class it.
fn numbers_out(text: &str) -> String {
    let mut out = String::new();
    let mut in_number = false;
    for c in text.chars() {
        if c.is_ascii_hexdigit() && (in_number || c.is_ascii_digit()) {
            if !in_number {
                out.push('N');
            }
            in_number = true;
        } else {
            in_number = false;
            out.push(c);
        }
    }
    out
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

/// The BUMPs of a BEEF, cut out by the stream until it stops.
fn bumps_of_beef(bytes: &[u8], out: &mut Vec<Vec<u8>>) {
    for element in BeefStream::new(bytes) {
        match element {
            Ok(Element::Bump(bump)) => {
                let (at, len) = (bump.offset as usize, bump.wire_len as usize);
                out.push(bytes[at..at + len].to_vec());
            }
            _ => break,
        }
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let lower = s.to_ascii_lowercase();
    if lower.is_empty() || !lower.len().is_multiple_of(2) {
        return None;
    }
    from_hex(&lower).ok()
}

/// The BUMPs in a JSON value: a hex string under a key naming a BUMP (or
/// any hex string, `all_hex`), and the BUMPs of a BEEF in hex.
fn bumps_in_json(value: &serde_json::Value, key: &str, all_hex: bool, out: &mut Vec<Vec<u8>>) {
    match value {
        serde_json::Value::String(s) => {
            let Some(bytes) = hex_bytes(s) else {
                return;
            };
            let opens_as_beef = [
                &[0x01, 0x00, 0xbe, 0xef][..],
                &[0x02, 0x00, 0xbe, 0xef],
                &[0x01, 0x01, 0x01, 0x01],
            ]
            .iter()
            .any(|p| bytes.starts_with(p));
            if opens_as_beef {
                bumps_of_beef(&bytes, out);
            } else if all_hex || key.to_ascii_lowercase().contains("bump") {
                out.push(bytes);
            }
        }
        serde_json::Value::Array(items) => items
            .iter()
            .for_each(|v| bumps_in_json(v, key, all_hex, out)),
        serde_json::Value::Object(map) => map
            .iter()
            .for_each(|(k, v)| bumps_in_json(v, k, all_hex, out)),
        _ => {}
    }
}

fn json_bumps(dir: &Path, label: &str, seeds: &mut Vec<(String, Vec<u8>)>) {
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
        // The seed's name reads the same on every OS (#146).
        let name = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        let all_hex = name.starts_with("merkle_path/");
        let mut found = Vec::new();
        bumps_in_json(&value, "", all_hex, &mut found);
        for (i, bytes) in found.into_iter().enumerate() {
            seeds.push((format!("{label}/{name}#{i}"), bytes));
        }
    }
}

/// The hex string literals of the Rust vector constants
/// (`tests/transaction/vectors`): a BUMP, or the BUMPs of a BEEF.
fn rs_bumps(dir: &Path, label: &str, seeds: &mut Vec<(String, Vec<u8>)>) {
    let mut paths = Vec::new();
    files(dir, &mut paths);
    for path in paths {
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut found = Vec::new();
        for literal in text.split('"').skip(1).step_by(2) {
            if literal.len() >= 8 && literal.chars().all(|c| c.is_ascii_hexdigit()) {
                let value = serde_json::Value::String(literal.to_string());
                bumps_in_json(&value, "bump", false, &mut found);
            }
        }
        for (i, bytes) in found.into_iter().enumerate() {
            seeds.push((format!("{label}/{name}#{i}"), bytes));
        }
    }
}

fn bin_files(dir: &Path, label: &str, beefs: bool, seeds: &mut Vec<(String, Vec<u8>)>) {
    let mut paths = Vec::new();
    files(dir, &mut paths);
    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "md" || ext == "txt" {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let bytes = std::fs::read(&path).unwrap();
        if beefs {
            let mut found = Vec::new();
            bumps_of_beef(&bytes, &mut found);
            for (i, bump) in found.into_iter().enumerate() {
                seeds.push((format!("{label}/{name}#{i}"), bump));
            }
        } else {
            seeds.push((format!("{label}/{name}"), bytes));
        }
    }
}

const TXID: &str = "f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f";

/// The lone-leaf test's BUMPs (`tests/merkle_path_lone_leaf.rs`): the txid
/// alone at each offset class.
fn lone_leaves(seeds: &mut Vec<(String, Vec<u8>)>) {
    for offset in [
        0,
        1,
        2,
        3,
        252,
        253,
        65535,
        65536,
        u32::MAX as u64,
        u64::MAX,
    ] {
        let path = MerklePath {
            block_height: 800_005,
            path: vec![vec![MerklePathLeaf::new_txid(offset, TXID.into())]],
        };
        seeds.push((format!("lone leaf at {offset}"), path.to_binary()));
    }
}

fn leaf_hash(i: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&i.to_le_bytes());
    h[31] = 0x5a;
    h
}

/// The cost test's BUMP of a tree height (`tests/merkle_path_cost.rs`).
fn bump_of_height(height: u8, stored: u8) -> Vec<u8> {
    let mut bytes = vec![0x01, height];
    for level in 0..height {
        if level == 0 {
            bytes.push(if stored > 0 { 2 } else { 1 });
            bytes.extend_from_slice(&[0x00, 0x02]);
            bytes.extend_from_slice(&leaf_hash(0));
            if stored > 0 {
                bytes.extend_from_slice(&[0x01, 0x00]);
                bytes.extend_from_slice(&leaf_hash(1));
            }
        } else if level < stored {
            bytes.extend_from_slice(&[0x01, 0x01, 0x00]);
            bytes.extend_from_slice(&leaf_hash(u64::from(level) + 1));
        } else {
            bytes.push(0);
        }
    }
    bytes
}

/// A flat BUMP of `2^k` leaves, every one a txid, as the cost test's flat
/// probe (one level of leaves, the levels above empty).
fn flat(k: u32) -> Vec<u8> {
    let mut bytes = vec![0x01, k as u8];
    bytes.extend(bsv_rs::primitives::to_var_int(1 << k));
    for i in 0..(1u64 << k) {
        bytes.extend(bsv_rs::primitives::to_var_int(i));
        bytes.push(2);
        bytes.extend_from_slice(&leaf_hash(i));
    }
    bytes.extend(std::iter::repeat_n(0, k as usize - 1));
    bytes
}

/// A BUMP of two levels: a txid at 0, its sibling at 1 carried with
/// `flag`, the level above empty (flags 3 and 4 are the harness rows
/// `bump-027` and `bump-028`).
fn with_sibling_flag(flag: u8) -> Vec<u8> {
    let mut bytes = vec![0x01, 0x01, 0x02, 0x00, 0x02];
    bytes.extend_from_slice(&leaf_hash(0));
    bytes.extend_from_slice(&[0x01, flag]);
    if flag & 1 == 0 {
        bytes.extend_from_slice(&leaf_hash(1));
    }
    bytes
}

/// A BUMP of four levels and two paths (txids at 4 and 8) whose level 2
/// carries a duplicate at offset 0, the left sibling of the first path's
/// node, and level 3 nothing: the second path computes level 3's offset 0
/// from that duplicate and the first path's node. The BEEF reader reads the
/// duplicate as the working hash paired with itself wherever the walk meets
/// it; through 0.9.0 the standalone reader (the reference's
/// `findOrComputeLeaf`, `ts-stack@edf6e03 MerklePath.ts`) hashed an empty
/// left hash there and refused `Mismatched roots`.
fn even_offset_duplicate() -> Vec<u8> {
    let leaf = |offset: u8, flag: u8, hash: Option<u64>| {
        let mut b = vec![offset, flag];
        if let Some(h) = hash {
            b.extend_from_slice(&leaf_hash(h));
        }
        b
    };
    let mut bytes = vec![0x01, 0x04];
    bytes.push(4);
    for (offset, flag, hash) in [(4, 2, 4), (5, 0, 5), (8, 2, 8), (9, 0, 9)] {
        bytes.extend(leaf(offset, flag, Some(hash)));
    }
    bytes.push(2);
    bytes.extend(leaf(3, 0, Some(13)));
    bytes.extend(leaf(5, 0, Some(15)));
    bytes.push(2);
    bytes.extend(leaf(0, 1, None));
    bytes.extend(leaf(3, 0, Some(23)));
    bytes.push(0);
    bytes
}

fn hand_built(seeds: &mut Vec<(String, Vec<u8>)>) {
    lone_leaves(seeds);
    for (height, stored) in [(0, 0), (1, 1), (2, 2), (64, 64), (65, 0), (255, 0)] {
        seeds.push((
            format!("tree height {height}, {stored} stored"),
            bump_of_height(height, stored),
        ));
    }
    for k in [1, 2, 4] {
        seeds.push((format!("flat of 2^{k}"), flat(k)));
    }
    for flag in 0..=4 {
        seeds.push((format!("sibling flag {flag}"), with_sibling_flag(flag)));
    }
    seeds.push((
        "an even-offset duplicate, a computed node's left child".into(),
        even_offset_duplicate(),
    ));
    // A lone leaf at height 2^32: through 0.9.0 the standalone reader cut
    // the height to its low 32 bits.
    let mut above = bsv_rs::primitives::to_var_int(1 << 32);
    above.extend_from_slice(&[0x01, 0x01, 0x00, 0x02]);
    above.extend_from_slice(&leaf_hash(0));
    seeds.push(("a lone leaf at height 2^32".into(), above));
}

/// The seeds: every BUMP the tree holds, deduplicated by bytes.
fn seeds() -> Vec<(String, Vec<u8>)> {
    let root = crate_dir();
    let mut seeds = Vec::new();
    json_bumps(&root.join("tests/fixtures"), "fixtures", &mut seeds);
    json_bumps(&root.join("tests/vectors"), "vectors", &mut seeds);
    json_bumps(
        &root.join("tests/transaction/vectors"),
        "transaction/vectors",
        &mut seeds,
    );
    rs_bumps(
        &root.join("tests/transaction/vectors"),
        "transaction/vectors",
        &mut seeds,
    );
    bin_files(
        &root.join("tests/vectors/beef_of_any_size"),
        "beef_of_any_size",
        true,
        &mut seeds,
    );
    bin_files(
        &root.join("fuzz/corpus/fuzz_merkle_path"),
        "fuzz_merkle_path",
        false,
        &mut seeds,
    );
    bin_files(
        &root.join("fuzz/corpus/fuzz_beef_parser"),
        "fuzz_beef_parser",
        true,
        &mut seeds,
    );
    if let Ok(dir) = std::env::var("BSV_CONFORMANCE_DIR") {
        json_bumps(&PathBuf::from(dir).join("vectors"), "ts-stack", &mut seeds);
    }
    hand_built(&mut seeds);

    let mut seen = BTreeSet::new();
    seeds.retain(|(_, bytes)| seen.insert(bytes.clone()));
    seeds
}

/// The seeds and what the test builds from them.
fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut inputs = Vec::new();
    for (name, bytes) in seeds() {
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
fn an_even_offset_duplicate_reads_as_the_beef_reader_reads_it() {
    let bytes = even_offset_duplicate();
    let path = MerklePath::from_binary(&bytes).expect("the BEEF reader accepts it");
    assert_eq!(standalone(&bytes), beef_reader(&bytes));
    let txids = path.txids();
    assert_eq!(txids.len(), 2);
    let root = path.compute_root(Some(&txids[0])).unwrap();
    assert_eq!(path.compute_root(Some(&txids[1])).unwrap(), root);
}

#[test]
fn the_standalone_reader_and_the_beef_reader_agree_on_every_bump_the_tree_holds() {
    let inputs = inputs();
    let mut table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut count = 0usize;
    let mut accepted = 0usize;
    for (name, bytes) in &inputs {
        let alone = standalone(bytes);
        // The three standalone entry points are one reader.
        let binary = MerklePath::from_binary(bytes).map(|p| p.to_binary());
        let hex = MerklePath::from_hex(&to_hex(bytes)).map(|p| p.to_binary());
        assert_eq!(binary, hex, "{name}: from_binary and from_hex");
        assert_eq!(
            binary.is_ok(),
            matches!(alone, Answer::Valid { .. }),
            "{name}"
        );
        let beef = beef_reader(bytes);
        accepted += usize::from(matches!(beef, Answer::Valid { .. }));
        if let Some(class) = disagreement(&alone, &beef) {
            count += 1;
            table
                .entry(class)
                .or_default()
                .push(format!("{name}: {alone:?} / {beef:?}"));
        }
    }
    let mut report = format!(
        "{} inputs ({} accepted by the BEEF reader), {} disagreements in {} classes\n",
        inputs.len(),
        accepted,
        count,
        table.len()
    );
    for (class, rows) in &table {
        report.push_str(&format!("{} x {}\n", rows.len(), class));
        for row in rows.iter().take(3) {
            let row: String = row.chars().take(400).collect();
            report.push_str(&format!("    {row}\n"));
        }
    }
    println!("{report}");
    if let Ok(path) = std::env::var("MERKLE_PATH_TWO_READERS_TABLE") {
        std::fs::write(path, &report).unwrap();
    }
    assert!(accepted > 0, "the inputs hold a valid BUMP");
    assert_eq!(count, 0, "the two readers disagree:\n{report}");
}
