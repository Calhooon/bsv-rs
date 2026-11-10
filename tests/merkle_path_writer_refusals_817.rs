//! #817: `MerklePath`'s writers (`to_binary`, `to_hex`, `to_writer`) return
//! `Result` and refuse a path their bytes cannot carry faithfully: bytes that
//! would not frame, or would read back as another path. Every other state,
//! valid or not, is written as the reference writes it (`ts-stack@edf6e03`
//! `MerklePath.ts:271-293`); validity is the readers' and `verify`'s. Where the
//! reference refuses (a hash that is not hex, `Invalid hex string`), its words;
//! where it writes bytes no reader reads back as written, this crate refuses
//! in its own words, a stated row. The constructors and `compute_root` refuse
//! a hash that is not hex where the reference's `hashPair` throws (`:30-32`).
//!
//! The reference's side is recorded in
//! `tests/vectors/merkle_path_writer_refusals_817.json` by
//! `tests/support/merkle_path_writer_refusals_817.mjs` (Node 22, the bundle
//! at the pin), each cell a path held through the public fields.

#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::path::Path;

use bsv_rs::primitives::{from_hex, to_hex, Writer};
use bsv_rs::transaction::{Beef, MerklePath, MerklePathLeaf};
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/merkle_path_writer_refusals_817.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the vector is JSON")
}

fn cell(name: &str) -> Value {
    vector()["cells"]
        .as_array()
        .expect("cells")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no cell {name}"))
        .clone()
}

/// The cell's path held as a caller holds one: through the public fields.
fn held(cell: &Value) -> MerklePath {
    let path = cell["path"]
        .as_array()
        .expect("path")
        .iter()
        .map(|level| {
            level
                .as_array()
                .expect("level")
                .iter()
                .map(|leaf| MerklePathLeaf {
                    offset: leaf["offset"].as_u64().expect("offset"),
                    hash: leaf["hash"].as_str().map(str::to_string),
                    txid: leaf["txid"].as_bool().unwrap_or(false),
                    duplicate: leaf["duplicate"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .collect();
    MerklePath {
        block_height: vector()["block_height"].as_u64().expect("height") as u32,
        path,
    }
}

/// The three doors agree, and a refusal leaves the caller's writer as it was.
fn written(name: &str) -> Result<String, Error> {
    let path = held(&cell(name));
    let hex = path.to_hex();
    let binary = path.to_binary().map(|b| to_hex(&b));
    assert_eq!(hex, binary, "{name}: to_hex and to_binary agree");
    let mut writer = Writer::new();
    writer.write_bytes(&[0xaa, 0xbb]);
    let into = path.to_writer(&mut writer);
    match (&hex, into) {
        (Ok(hex), Ok(())) => {
            assert_eq!(to_hex(&writer.as_bytes()[2..]), *hex, "{name}: to_writer");
        }
        (Err(e), Err(f)) => {
            assert_eq!(*e, f, "{name}: to_writer refuses alike");
            assert_eq!(writer.as_bytes(), &[0xaa, 0xbb], "{name}: writer untouched");
        }
        (h, w) => panic!("{name}: to_hex {h:?}, to_writer {w:?}"),
    }
    hex
}

fn refused(name: &str) -> String {
    match written(name) {
        Err(Error::MerklePathError(words)) => words,
        other => panic!("{name}: expected a MerklePathError, got {other:?}"),
    }
}

/// The reference's `toHex` of the cell: `Ok(hex)` or `Err(words)`.
fn reference_write(name: &str) -> Result<String, String> {
    let c = cell(name);
    let w = &c["write"];
    assert_eq!(
        w, &c["to_binary"],
        "{name}: the reference's two doors agree"
    );
    if w["accepted"].as_bool().expect("accepted") {
        Ok(w["result"].as_str().expect("hex").to_string())
    } else {
        Err(w["refusal"].as_str().expect("words").to_string())
    }
}

// ---- refused: the reference refuses too, in its words ----

#[test]
fn a_non_hex_leaf_hash_is_refused_by_the_writer_817() {
    assert_eq!(refused("non_hex_leaf_hash"), "Invalid hex string");
    assert_eq!(
        reference_write("non_hex_leaf_hash"),
        Err("Invalid hex string".into())
    );
    // `from_coinbase_txid` reaches the state: it checks nothing.
    let coinbase = MerklePath::from_coinbase_txid(&"zz".repeat(32), 1);
    assert_eq!(
        coinbase.to_hex(),
        Err(Error::MerklePathError("Invalid hex string".into()))
    );
}

#[test]
fn a_non_hex_hash_of_another_length_is_refused_as_not_hex_first_817() {
    // The reference's `assertValidHex` runs before any length is read.
    assert_eq!(refused("non_hex_short_hash"), "Invalid hex string");
    assert_eq!(
        reference_write("non_hex_short_hash"),
        Err("Invalid hex string".into())
    );
}

// ---- refused: the reference writes bytes no reader reads back (stated) ----

#[test]
fn a_hashless_leaf_not_flagged_duplicate_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("hashless_leaf"),
        "Missing hash at height 0, offset 1"
    );
    // The reference writes the flag byte and nothing after it.
    let theirs = reference_write("hashless_leaf").expect("the reference writes it");
    assert!(theirs.ends_with("0100"), "{theirs}");
}

#[test]
fn a_hash_of_63_hex_digits_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("hash_of_63_digits"),
        "Invalid hash at height 0, offset 0: expected 64 hex digits, got 63"
    );
    // The reference pads it with a leading zero: 32 bytes that read back as
    // another text, `0` and the 63 digits.
    let theirs = reference_write("hash_of_63_digits").expect("the reference writes it");
    let back = MerklePath::from_hex(&theirs).expect("its bytes read");
    let h = cell("hash_of_63_digits")["path"][0][0]["hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(back.path[0][0].hash, Some(format!("0{h}")));
}

#[test]
fn a_hash_of_62_hex_digits_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("hash_of_62_digits"),
        "Invalid hash at height 0, offset 0: expected 64 hex digits, got 62"
    );
    let theirs = reference_write("hash_of_62_digits").expect("the reference writes it");
    assert!(
        MerklePath::from_hex(&theirs).is_err(),
        "31 bytes do not frame"
    );
}

#[test]
fn a_hash_of_66_hex_digits_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("hash_of_66_digits"),
        "Invalid hash at height 0, offset 0: expected 64 hex digits, got 66"
    );
    let theirs = reference_write("hash_of_66_digits").expect("the reference writes it");
    assert!(
        MerklePath::from_hex(&theirs).is_err(),
        "33 bytes do not frame"
    );
}

#[test]
fn an_empty_hash_text_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("empty_hash"),
        "Invalid hash at height 0, offset 0: expected 64 hex digits, got 0"
    );
    assert_eq!(
        reference_write("empty_hash"),
        Ok("fe00350c0001010002".into())
    );
}

#[test]
fn a_path_of_256_levels_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("levels_256"),
        "Invalid tree height: 256, over the 255 levels a BUMP's tree height byte writes"
    );
    // The reference cuts the height to its low byte, `00`.
    let theirs = reference_write("levels_256").expect("the reference writes it");
    assert!(theirs.starts_with("fe00350c0000"), "{}", &theirs[..12]);
}

#[test]
fn a_duplicate_leaf_carrying_a_hash_is_refused_by_the_writer_817() {
    assert_eq!(
        refused("duplicate_carrying_a_hash"),
        "Duplicate leaf at height 0, offset 1 carries a hash, which a BUMP's duplicate flag cannot write"
    );
    // The reference writes the flag alone: the hash is gone on the read.
    let theirs = reference_write("duplicate_carrying_a_hash").expect("the reference writes it");
    assert!(theirs.ends_with("0101"), "{theirs}");
}

// ---- written though invalid: the format carries the state ----

fn written_as_the_reference(name: &str) -> String {
    let ours = written(name).unwrap_or_else(|e| panic!("{name}: refused {e}"));
    assert_eq!(Ok(ours.clone()), reference_write(name), "{name}");
    ours
}

#[test]
fn a_path_of_no_levels_is_written_817() {
    assert_eq!(written_as_the_reference("zero_levels"), "fe00350c0000");
    // No reader accepts it (#649's `TreeHeightZero`).
    assert!(MerklePath::from_hex("fe00350c0000").is_err());
}

#[test]
fn a_path_of_65_levels_is_written_817() {
    let hex = written_as_the_reference("levels_65");
    assert!(hex.starts_with("fe00350c0041"));
    assert!(
        MerklePath::from_hex(&hex).is_err(),
        "over BRC-74's 64 levels"
    );
}

#[test]
fn a_path_of_255_levels_is_written_817() {
    let hex = written_as_the_reference("levels_255");
    assert!(hex.starts_with("fe00350c00ff"));
}

#[test]
fn an_empty_level_0_is_written_817() {
    assert_eq!(written_as_the_reference("empty_level_0"), "fe00350c000100");
}

#[test]
fn a_repeated_offset_is_written_817() {
    let hex = written_as_the_reference("duplicate_offsets");
    assert!(MerklePath::from_hex(&hex).is_err(), "DuplicateOffset");
}

#[test]
fn an_illegal_offset_and_a_mismatched_root_are_written_817() {
    written_as_the_reference("illegal_offset_and_mismatched_root");
}

#[test]
fn a_duplicate_flagged_txid_is_refused_by_the_writer_817() {
    // The fold (the rule read, cell (a)): the reference writes `03` and reads
    // it back as a plain duplicate, the txid flag lost (`MerklePath.ts:133-140`);
    // this crate's reader refuses the flag. The same ground as a duplicate
    // carrying a hash: a stated row.
    assert_eq!(
        refused("duplicate_flagged_txid"),
        "Duplicate leaf at height 0, offset 1 is flagged txid, which a BUMP's duplicate flag cannot write"
    );
    let theirs = reference_write("duplicate_flagged_txid").expect("the reference writes it");
    assert!(theirs.ends_with("0103"), "{theirs}");
    assert!(MerklePath::from_hex(&theirs).is_err());
}

// ---- the fold: a non-hex hash beside another refused state ----

/// The reference's writer throws at a non-hex hash wherever it sits, so its
/// words come first whatever other state the path holds (the reads of
/// 2026-11-09: the cold read's c1, c3, c4, the strength read's three).
#[test]
fn a_non_hex_hash_after_256_levels_is_refused_in_the_reference_words_817() {
    assert_eq!(
        reference_write("levels_256_with_non_hex_leaf"),
        Err("Invalid hex string".into())
    );
    assert_eq!(
        refused("levels_256_with_non_hex_leaf"),
        "Invalid hex string"
    );
}

#[test]
fn a_non_hex_hash_after_a_hashless_leaf_is_refused_in_the_reference_words_817() {
    for name in [
        "hashless_leaf_then_non_hex",
        "hashless_leaf_at_1_then_non_hex_above",
    ] {
        assert_eq!(
            reference_write(name),
            Err("Invalid hex string".into()),
            "{name}"
        );
        assert_eq!(refused(name), "Invalid hex string", "{name}");
    }
}

#[test]
fn a_non_hex_hash_after_a_62_digit_hash_is_refused_in_the_reference_words_817() {
    assert_eq!(
        reference_write("hash_of_62_digits_then_non_hex"),
        Err("Invalid hex string".into())
    );
    assert_eq!(
        refused("hash_of_62_digits_then_non_hex"),
        "Invalid hex string"
    );
}

#[test]
fn a_duplicate_carrying_a_non_hex_hash_is_refused_as_a_duplicate_carrying_a_hash_817() {
    // The reference writes the duplicate's flag alone, its hash unread
    // (`MerklePath.ts:288`): no throw, so the stated row's words here.
    let theirs =
        reference_write("duplicate_carrying_a_non_hex_hash").expect("the reference writes it");
    assert!(theirs.ends_with("0101"), "{theirs}");
    assert_eq!(
        refused("duplicate_carrying_a_non_hex_hash"),
        "Duplicate leaf at height 0, offset 1 carries a hash, which a BUMP's duplicate flag cannot write"
    );
}

#[test]
fn a_computed_node_pairing_a_non_hex_hash_is_refused_at_every_door_817() {
    // Level 1's node at offset 1 is computed from level 0's 2 and 3, one of
    // them not hex: the reference's `hashPair` throws there (`:30-32`).
    constructed("computed_node_pairing_non_hex");
    assert_eq!(
        door("computed_node_pairing_non_hex", "compute_root"),
        Err("Invalid hex string".into())
    );
    assert_eq!(
        refused("computed_node_pairing_non_hex"),
        "Invalid hex string"
    );
}

#[test]
fn an_upper_case_hash_is_written_and_reads_back_lower_case_817() {
    let hex = written_as_the_reference("upper_case_hash");
    let back = MerklePath::from_hex(&hex).expect("reads");
    let held = held(&cell("upper_case_hash"));
    assert_eq!(
        back.path[0][0].hash,
        held.path[0][0].hash.as_ref().map(|h| h.to_lowercase())
    );
}

#[test]
fn leaves_out_of_offset_order_are_written_as_held_817() {
    let hex = written_as_the_reference("leaves_out_of_offset_order");
    let back = MerklePath::from_hex(&hex).expect("reads");
    assert_eq!(back.path[0][0].offset, 0, "the reader sorts");
}

#[test]
fn a_txid_flag_above_level_0_is_written_817() {
    written_as_the_reference("txid_flag_above_level_0");
}

#[test]
fn a_lone_leaf_at_offset_1_is_written_817() {
    let hex = written_as_the_reference("lone_leaf_at_offset_1");
    assert!(MerklePath::from_hex(&hex).is_err(), "MissingSibling");
}

#[test]
fn a_leaf_not_flagged_txid_is_written_00_where_the_reference_writes_02_817() {
    // Stated: the reference flags a txid when its member is present, `false`
    // included (`MerklePath.ts:284-286`), so its `{ txid: false }` reads back
    // as a txid; this crate's `false` is written `00`.
    let ours = written("explicit_txid_false").expect("written");
    let theirs = reference_write("explicit_txid_false").expect("written");
    assert_eq!(&ours[..18], "fe00350c0001010000");
    assert_eq!(&theirs[..18], "fe00350c0001010002");
    assert_eq!(ours[18..], theirs[18..]);
}

// ---- the constructors and compute_root ----

fn door(name: &str, which: &str) -> Result<(), String> {
    let d = &cell(name)[which];
    if d["accepted"].as_bool().expect("accepted") {
        Ok(())
    } else {
        Err(d["refusal"].as_str().expect("words").to_string())
    }
}

fn ours<T>(r: bsv_rs::Result<T>) -> Result<(), String> {
    r.map(|_| ()).map_err(|e| match e {
        Error::MerklePathError(w) => w,
        other => panic!("not a MerklePathError: {other:?}"),
    })
}

fn constructed(name: &str) {
    let path = held(&cell(name));
    assert_eq!(
        ours(MerklePath::new(path.block_height, path.path.clone())),
        door(name, "checked"),
        "{name}: new"
    );
    assert_eq!(
        ours(MerklePath::new_unchecked(
            path.block_height,
            path.path.clone()
        )),
        door(name, "unchecked"),
        "{name}: new_unchecked"
    );
    assert_eq!(
        ours(path.compute_root(None)),
        door(name, "compute_root"),
        "{name}: compute_root"
    );
}

#[test]
fn a_non_hex_sibling_hash_is_refused_by_the_constructor_817() {
    constructed("constructor_non_hex_sibling");
    assert_eq!(
        door("constructor_non_hex_sibling", "checked"),
        Err("Invalid hex string".into())
    );
}

#[test]
fn a_non_hex_txid_is_refused_by_the_constructor_817() {
    constructed("constructor_non_hex_txid");
}

#[test]
fn a_non_hex_hash_no_walk_reads_is_not_refused_by_the_constructor_817() {
    // Neither side reads it (the unchecked constructor); the writer refuses it.
    constructed("constructor_non_hex_hash_no_walk_reads");
    assert_eq!(
        refused("constructor_non_hex_hash_no_walk_reads"),
        "Invalid hex string"
    );
}

#[test]
fn a_lone_non_hex_leaf_is_returned_unread_by_the_constructor_817() {
    // As the reference's: a one-leaf path's root is its txid, unread.
    let path = held(&cell("non_hex_leaf_hash"));
    assert!(MerklePath::new(path.block_height, path.path.clone()).is_ok());
    assert_eq!(door("non_hex_leaf_hash", "checked"), Ok(()));
}

// ---- the recording, cell by cell ----

/// The cells where this crate refuses and the reference writes bytes no
/// reader reads back as written: the stated rows.
const REFUSED_HERE_WRITTEN_THERE: [&str; 10] = [
    "hashless_leaf",
    "hash_of_63_digits",
    "hash_of_62_digits",
    "hash_of_66_digits",
    "empty_hash",
    "levels_256",
    "duplicate_carrying_a_hash",
    "duplicate_flagged_txid",
    "duplicate_carrying_a_non_hex_hash",
    "explicit_txid_false", // written by both, other bytes (the reference's flag)
];

#[test]
fn every_recorded_cell_is_written_or_refused_as_the_reference_save_the_stated_rows_817() {
    let v = vector();
    assert_eq!(v["node"], "v22.18.0");
    let cells = v["cells"].as_array().expect("cells");
    assert_eq!(cells.len(), 30);
    let mut stated = 0;
    for c in cells {
        let name = c["name"].as_str().unwrap();
        let ours = written(name).map_err(|e| match e {
            Error::MerklePathError(w) => w,
            other => panic!("{other:?}"),
        });
        let theirs = reference_write(name);
        if REFUSED_HERE_WRITTEN_THERE.contains(&name) {
            assert!(theirs.is_ok(), "{name}: the reference writes it");
            assert_ne!(ours, theirs, "{name}: stated");
            stated += 1;
        } else {
            assert_eq!(ours, theirs, "{name}");
        }
    }
    assert_eq!(stated, REFUSED_HERE_WRITTEN_THERE.len());
}

// ---- the sweep: every merkle path the tree's vectors hold ----

fn hex_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if s.len() >= 8 && s.len() % 2 == 0 => {
            if s.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.push(s.clone());
            }
        }
        Value::Array(a) => a.iter().for_each(|x| hex_strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| hex_strings(x, out)),
        _ => {}
    }
}

fn rust_literals(text: &str, out: &mut Vec<String>) {
    for piece in text.split('"').skip(1).step_by(2) {
        if piece.len() >= 8 && piece.len() % 2 == 0 && piece.bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.push(piece.to_string());
        }
    }
}

fn paths_of(bytes: &[u8], out: &mut Vec<MerklePath>) {
    if let Ok(path) = MerklePath::from_binary(bytes) {
        out.push(path);
        return;
    }
    let magic = bytes.get(..4);
    let beefish = matches!(
        magic,
        Some([0x01, 0x00, 0xbe, 0xef])
            | Some([0x02, 0x00, 0xbe, 0xef])
            | Some([0x01, 0x01, 0x01, 0x01])
    );
    if beefish {
        if let Ok(beef) = Beef::from_binary(bytes) {
            out.extend(beef.bumps);
        }
    }
}

fn files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("dir") {
        let p = entry.expect("entry").path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn every_merkle_path_the_vectors_hold_writes_and_reads_back_equal_817() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut all = Vec::new();
    files(&root.join("vectors"), &mut all);
    files(&root.join("transaction/vectors"), &mut all);
    all.sort();
    let mut paths = Vec::new();
    for file in &all {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mut texts = Vec::new();
        match ext {
            "json" => {
                let text = std::fs::read_to_string(file).expect("read");
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    hex_strings(&v, &mut texts);
                }
            }
            "jsonl" => {
                let text = std::fs::read_to_string(file).expect("read");
                for line in text.lines() {
                    if let Ok(v) = serde_json::from_str::<Value>(line) {
                        hex_strings(&v, &mut texts);
                    }
                }
            }
            "rs" => rust_literals(&std::fs::read_to_string(file).expect("read"), &mut texts),
            "bin" => paths_of(&std::fs::read(file).expect("read"), &mut paths),
            _ => {}
        }
        for t in texts {
            paths_of(&from_hex(&t).expect("hex"), &mut paths);
        }
    }
    for (i, path) in paths.iter().enumerate() {
        let bytes = path
            .to_binary()
            .unwrap_or_else(|e| panic!("path {i} refused: {e}"));
        let back = MerklePath::from_binary(&bytes).expect("its own bytes read");
        assert_eq!(back.block_height, path.block_height, "path {i}");
        assert_eq!(back.path, path.path, "path {i}");
        assert_eq!(back.to_binary().expect("again"), bytes, "path {i}");
    }
    println!(
        "{} merkle paths swept from {} files",
        paths.len(),
        all.len()
    );
    assert!(paths.len() > 100, "the sweep found {} paths", paths.len());
}
