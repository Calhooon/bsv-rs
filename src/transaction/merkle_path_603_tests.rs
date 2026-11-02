#![cfg(test)]
//! #603's witnesses for the constructor's offset and height rules, `combine`
//! and `trim`, inside the Merkle surface's mutation selection. No entry of the
//! sibling's corpora reaches these (the readers build a path through the
//! stream, never through `new`; `bsv-script-lean@387dab35`, all nine corpora
//! of `harness/run --corpus all` and `corpus/wire`'s 150 rows unmoved under
//! each of the 25 survivors, `bump.jsonl` the bytes it had at `5a4c0b0a`), so
//! every expectation is a recording of the reference (`ts-stack@edf6e03`
//! `MerklePath.ts`, Node v22.18.0) over BUMPs copied by their ids from the
//! sibling's `corpus/wire/bump.jsonl` and the conformance corpus's
//! `vectors/sdk/transactions/merkle-path.json`, or a row of those corpora:
//! `tests/vectors/merkle_path_603.json`, written by
//! `tests/support/merkle_path_603.mjs`, never by hand. Where this crate reads
//! a path otherwise than the reference, the rule it follows is cited and the
//! reference's recorded verdict asserted beside it.

use super::merkle_path::{MerklePath, MerklePathLeaf};
use crate::Result;
use serde_json::Value;

fn recorded() -> Value {
    serde_json::from_str(include_str!("../../tests/vectors/merkle_path_603.json")).unwrap()
}

fn family<'a>(v: &'a Value, name: &str) -> &'a [Value] {
    v[name].as_array().unwrap()
}

fn entry<'a>(v: &'a Value, name: &str, id: &str) -> &'a Value {
    family(v, name).iter().find(|e| e["id"] == id).unwrap()
}

/// A path as the reference holds it: a leaf is a client txid only when its
/// `txid` is `true` (`MerklePath.ts:137`), a duplicate when `duplicate` is.
fn levels(path: &Value) -> Vec<Vec<MerklePathLeaf>> {
    path.as_array()
        .unwrap()
        .iter()
        .map(|level| {
            level
                .as_array()
                .unwrap()
                .iter()
                .map(|leaf| MerklePathLeaf {
                    offset: leaf["offset"].as_u64().unwrap(),
                    hash: leaf["hash"].as_str().map(str::to_string),
                    txid: leaf["txid"] == true,
                    duplicate: leaf["duplicate"] == true,
                })
                .collect()
        })
        .collect()
}

fn height(e: &Value) -> u32 {
    u32::try_from(e["block_height"].as_u64().unwrap()).unwrap()
}

/// Every root the reference computed from a hash of level 0, computed here.
fn assert_roots(mp: &MerklePath, roots: &Value, id: &str) {
    let roots = roots.as_object().unwrap();
    assert!(!roots.is_empty(), "{id}: no root recorded");
    for (hash, root) in roots {
        assert_eq!(
            mp.compute_root(Some(hash)).unwrap(),
            root.as_str().unwrap(),
            "{id}: the root from {hash}"
        );
    }
}

fn refusal(result: Result<MerklePath>) -> String {
    match result {
        Err(crate::Error::MerklePathError(words)) => words,
        Err(other) => panic!("not a merkle path refusal: {other}"),
        Ok(mp) => panic!("accepted: {}", mp.to_hex()),
    }
}

/// The rows themselves (not a shape derived from one), `construct`.
fn rows(v: &Value) -> impl Iterator<Item = &Value> {
    family(v, "construct").iter().filter(|e| {
        let d = e["derivation"].as_str().unwrap();
        d == "the row as the reference reads it"
            || d == "the vector's BUMP as the reference reads it"
    })
}

/// The legal offsets (`MerklePath.ts:220-235`: a level above 0 lists only the
/// sibling of a level-0 hash's ancestor) and the root check (`:242-261`, the
/// sibling's `Bump.root`, `lean/BsvChain/Views/Wire/BUMP.lean:382-393`: every
/// level-0 word climbs to one root): each BUMP of `corpus/wire/bump.jsonl`
/// the reference reads, and `mp-parse-001` and `mp-combine-001`, held by
/// `new` and `new_unchecked` to the reference's roots. `bump-031`'s height is
/// above a `u32`, which the in-memory path cannot hold (the stream refuses it,
/// `RootNotCarried`; bsv-rs#86).
#[test]
fn legal_offsets_admit_every_path_the_reference_admits_wire_bump_rows_and_mp_parse_combine_001() {
    let v = recorded();
    let mut held = Vec::new();
    let mut skipped = Vec::new();
    for e in rows(&v) {
        let id = e["id"].as_str().unwrap();
        assert_eq!(e["legal"]["accepted"], true, "{id}");
        if e["block_height"].as_u64().unwrap() > u64::from(u32::MAX) {
            skipped.push(id);
            continue;
        }
        let path = levels(&e["path"]);
        let mp = MerklePath::new(height(e), path.clone())
            .unwrap_or_else(|err| panic!("{id}: new refuses {err}"));
        assert_roots(&mp, &e["legal"]["roots"], id);
        let mp = MerklePath::new_unchecked(height(e), path)
            .unwrap_or_else(|err| panic!("{id}: new_unchecked refuses {err}"));
        assert_roots(&mp, &e["unchecked"]["roots"], id);
        held.push(id);
    }
    assert_eq!(skipped, ["bump-031"]);
    assert_eq!(held.len(), 33, "{held:?}");
    for id in [
        "bump-007",
        "bump-024",
        "bump-026",
        "mp-parse-001",
        "mp-combine-001",
    ] {
        assert!(held.contains(&id), "{id}");
    }
}

/// A level-0 duplicate is no hash and names no legal offset; it is not judged
/// by the offset rule either (`MerklePath.ts:224-231`: level 0's leaves are
/// read, never checked). `bump-007`, block 100,002's last transaction (offset
/// 8, the duplicate at 9, and at levels 1 and 2), as WhatsOnChain serves it.
#[test]
fn a_level_0_duplicate_takes_no_part_in_the_offset_rule_wire_bump_007() {
    let v = recorded();
    let e = entry(&v, "construct", "bump-007");
    let path = levels(&e["path"]);
    assert!(path[0].iter().any(|l| l.duplicate && l.offset == 9));
    let mp = MerklePath::new(height(e), path.clone()).unwrap();
    assert_roots(&mp, &e["legal"]["roots"], "bump-007");
    let mp = MerklePath::new_unchecked(height(e), path).unwrap();
    assert_roots(&mp, &e["unchecked"]["roots"], "bump-007");
}

/// A leaf above level 0 at an offset no level-0 hash climbs through is refused
/// with legal offsets only, and read without them (`MerklePath.ts:230-235`;
/// `legalOffsetsOnly` false, `MerklePath::new_unchecked`), the roots
/// unchanged. Three shapes, each a row of `corpus/wire/bump.jsonl` with one
/// leaf added (`bump-008` at level 1, `bump-014` at level 5, `bump-018` at its
/// top level, 11). The reference's words go on to list the legal offsets
/// (`, with legal offsets: 1`); this crate's stop at the height.
#[test]
fn an_offset_off_every_path_is_refused_by_legal_offsets_alone_wire_bump_008_014_018() {
    let v = recorded();
    for id in [
        "bump-008-off-path-level-1",
        "bump-014-off-path-level-5",
        "bump-018-off-path-level-11",
    ] {
        let e = entry(&v, "construct", id);
        let path = levels(&e["path"]);
        let theirs = e["legal"]["refusal"].as_str().unwrap();
        let (words, _) = theirs.split_once(", with legal offsets").unwrap();
        assert_eq!(
            refusal(MerklePath::new(height(e), path.clone())),
            words,
            "{id}"
        );
        assert_eq!(e["unchecked"]["accepted"], true, "{id}");
        let mp = MerklePath::new_unchecked(height(e), path)
            .unwrap_or_else(|err| panic!("{id}: new_unchecked refuses {err}"));
        assert_roots(&mp, &e["unchecked"]["roots"], id);
    }
}

/// The tree height's bound, BRC-74's "max 64" (`transactions/0074.md:51`;
/// the sibling's `bumpMaxTreeHeight`, `BUMP.lean:66`, its decoder refusing a
/// height above it, `:113`, a well-formed BUMP at most 64 levels, `:139`):
/// `bump-001`'s txid with the duplicate marker as its sibling at each of 54
/// and 64 levels held to the root the reference's walk climbs to, and
/// `bump-029` (`bump-008`'s levels with empty levels appended to 65, the row's
/// own bytes) refused. The reference bounds a path at 54 levels
/// (`MerklePath.ts:198-199`): it holds the 54 and refuses the 64, a stated
/// difference; the 64-level root is its walk's, one level at a time.
#[test]
fn the_tree_height_bound_is_64_levels_bump_lean_66_wire_bump_001_029() {
    let v = recorded();
    let folds = &v["duplicate_fold_roots"];
    let coinbase = entry(&v, "construct", "bump-001")["path"][0][0]["hash"]
        .as_str()
        .unwrap()
        .to_string();

    let e = entry(&v, "construct", "bump-001-duplicates-54-levels");
    let mp = MerklePath::new(height(e), levels(&e["path"])).unwrap();
    assert_eq!(mp.path.len(), 54);
    assert_roots(&mp, &e["legal"]["roots"], "54 levels");
    assert_eq!(e["legal"]["root"], folds["54"]);

    let e = entry(&v, "construct", "bump-001-duplicates-64-levels");
    let theirs = "Merkle Path must contain between 1 and 54 levels";
    assert_eq!(e["legal"]["refusal"], theirs);
    assert_eq!(e["unchecked"]["refusal"], theirs);
    for mp in [
        MerklePath::new(height(e), levels(&e["path"])).unwrap(),
        MerklePath::new_unchecked(height(e), levels(&e["path"])).unwrap(),
    ] {
        assert_eq!(mp.path.len(), 64);
        assert_eq!(
            mp.compute_root(Some(&coinbase)).unwrap(),
            folds["64"].as_str().unwrap()
        );
    }

    let e = entry(&v, "construct", "bump-029");
    let path = levels(&e["path"]);
    assert_eq!(path.len(), 65);
    assert_eq!(e["from_hex"]["refusal"], theirs);
    let words = "Invalid tree height: 65, over the maximum height 64";
    assert_eq!(refusal(MerklePath::new(height(e), path.clone())), words);
    assert_eq!(refusal(MerklePath::new_unchecked(height(e), path)), words);
}

/// `combine` (`MerklePath.ts:508-537`): the union of two paths of one block
/// and one root, each level's leaves once, a client txid kept as one, then
/// `trim` (`:544-594`: every node the client txids compute dropped). Every
/// ordered pair of two mainnet rows of one block in `corpus/wire/bump.jsonl`
/// (blocks 100,000, 500,000, 900,000 and 971,000; 74 pairs), combined here to
/// the reference's bytes and roots.
#[test]
fn combine_of_two_paths_of_one_block_is_the_references_compound_wire_bump_pairs() {
    let v = recorded();
    let mut pairs = 0;
    for e in family(&v, "combine")
        .iter()
        .filter(|e| e["a_hex"].is_string())
    {
        let id = e["id"].as_str().unwrap();
        let mut mp = MerklePath::from_hex(e["a_hex"].as_str().unwrap()).unwrap();
        let other = MerklePath::from_hex(e["b_hex"].as_str().unwrap()).unwrap();
        mp.combine(&other)
            .unwrap_or_else(|err| panic!("{id}: combine refuses {err}"));
        assert_eq!(mp.to_hex(), e["result_hex"].as_str().unwrap(), "{id}");
        assert_roots(&mp, &e["result"]["roots"], id);
        pairs += 1;
    }
    assert_eq!(pairs, 74);
}

/// `combine` of a path with fewer levels than the other's: `bump-005`'s level
/// 1 as one level (its hash at offset 0 and the node the reference computes at
/// offset 1), the same root, combined with `bump-005` takes the other's levels
/// and, trimmed, is `bump-005` byte for byte, the row as the reference reads
/// and writes it (its levels in ascending offset order). The reference
/// combines over `this`'s levels alone (`MerklePath.ts:520`), so its result
/// has one level and climbs to another root (recorded); this crate does not
/// follow it, a stated difference (the root `CLAUDE.md`'s divergence list).
#[test]
fn combine_extends_a_shorter_path_to_the_others_levels_wire_bump_005() {
    let v = recorded();
    let e = entry(&v, "combine", "bump-005-under-its-level-1");
    let root = e["b_root"].as_str().unwrap();
    let mut mp = MerklePath::new(100_000, levels(&e["a_path"])).unwrap();
    assert_eq!(mp.compute_root(None).unwrap(), root);
    let other = MerklePath::from_hex(e["b_hex"].as_str().unwrap()).unwrap();
    mp.combine(&other).unwrap();
    assert_eq!(mp.to_hex(), e["b_sorted_hex"].as_str().unwrap());
    assert_eq!(mp.compute_root(None).unwrap(), root);
    assert_eq!(e["result_path"].as_array().unwrap().len(), 1);
    assert_ne!(e["result"]["root"], root);
}

/// `trim` (`MerklePath.ts:544-594`): a level-0 leaf that is no client txid is
/// dropped with its sibling when that is none either (`:580-585`), and above
/// level 0 every node the client txids compute (`:589-593`). The compound rows
/// of `corpus/wire/bump.jsonl` (`bump-023` to `bump-026`, two paths of one
/// block merged by leaf union) and each with one client txid's flag cleared,
/// trimmed here to the reference's bytes.
#[test]
fn trim_drops_a_level_0_pair_with_no_client_txid_wire_bump_023_to_026() {
    let v = recorded();
    let mut trimmed = Vec::new();
    for e in family(&v, "trim") {
        let id = e["id"].as_str().unwrap();
        let mut mp = MerklePath::from_hex(e["hex"].as_str().unwrap())
            .unwrap_or_else(|err| panic!("{id}: from_hex refuses {err}"));
        mp.trim();
        assert_eq!(mp.to_hex(), e["result_hex"].as_str().unwrap(), "{id}");
        trimmed.push(id);
    }
    assert_eq!(trimmed.len(), 10);
    assert!(trimmed.contains(&"bump-024-unflagged-2"));
}
