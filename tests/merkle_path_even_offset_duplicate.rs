//! A duplicate-flagged leaf at an even offset is read as the reference
//! reads it (bsv-rs#167, the re-read of 2026-10-26): where it is the working
//! hash's sibling the working hash is paired with itself (`ts-stack@edf6e03`
//! `MerklePath.ts:60`), and the computed root against the header decides;
//! where a walk needs a node the BUMP does not carry and computing it meets
//! the duplicate on the left, the reference's walk gives up (`cachedFindLeaf`
//! `:628-631`, `nextCachedHash` `:58`, `Missing hash for index N at height
//! N`) and this crate refuses `LeftDuplicateBelow` at that node.
//!
//! The shapes and the reference's verdicts are
//! `tests/vectors/merkle_path_even_offset_duplicate_167.json`, written by
//! `tests/support/even_offset_duplicate_167.mjs` against `@bsv/sdk` at
//! `ts-stack@edf6e03` under Node v22.18.0. Each shape's bytes are this
//! crate's writer's (`MerklePath::to_binary`), equal to the reference's;
//! each is read by the three readers (a BUMP read alone, the stream, the
//! whole BEEF), held in memory (`MerklePath::new`, `new_unchecked`,
//! `Beef::verify_structure`) and verified against a header carrying the
//! reference's root. A reason is compared by its words, so this file reads
//! the same on a tree without the kind.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::BTreeMap;

use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::transaction::{
    verify_stream_structure, Beef, BeefStream, Element, Headers, MerklePath, MerklePathLeaf,
    Verdict,
};
use serde::Deserialize;

const VECTORS: &str = "tests/vectors/merkle_path_even_offset_duplicate_167.json";

#[derive(Deserialize)]
struct Vectors {
    reference: String,
    node: String,
    shapes: Vec<Shape>,
}

#[derive(Deserialize)]
struct Shape {
    name: String,
    block_height: u32,
    path: Vec<Vec<JsonLeaf>>,
    hex: String,
    verdict: RefVerdict,
    unchecked: RefVerdict,
}

#[derive(Deserialize)]
struct JsonLeaf {
    offset: u64,
    hash: Option<String>,
    #[serde(default)]
    txid: bool,
    #[serde(default)]
    duplicate: bool,
}

#[derive(Deserialize)]
struct RefVerdict {
    accepted: bool,
    root: Option<String>,
    #[serde(default)]
    roots: BTreeMap<String, String>,
    refusal: Option<String>,
}

fn vectors() -> Vectors {
    let data = std::fs::read_to_string(VECTORS).expect("read the #167 vectors");
    serde_json::from_str(&data).expect("parse the #167 vectors")
}

/// This crate's reason for each shape the reference refuses, in its words.
fn refused_here(name: &str) -> &'static str {
    match name {
        "two-txids-the-left-duplicate-node-carried-wrong" => {
            "MismatchedNode { level: 1, offset: 0 }"
        }
        "two-txids-a-node-computed-from-the-left-duplicate" => {
            "LeftDuplicateBelow { level: 1, offset: 0 }"
        }
        "two-paths-level-3-computed-from-the-left-duplicate" => {
            "LeftDuplicateBelow { level: 3, offset: 0 }"
        }
        "two-paths-a-right-child-computed-from-the-left-duplicate" => {
            "LeftDuplicateBelow { level: 2, offset: 0 }"
        }
        "a-duplicate-at-the-path-nodes-own-offset" => "MismatchedNode { level: 1, offset: 0 }",
        other => panic!("no refusal stated for {other}"),
    }
}

fn path_of(shape: &Shape) -> Vec<Vec<MerklePathLeaf>> {
    shape
        .path
        .iter()
        .map(|level| {
            level
                .iter()
                .map(|l| MerklePathLeaf {
                    offset: l.offset,
                    hash: l.hash.clone(),
                    txid: l.txid,
                    duplicate: l.duplicate,
                })
                .collect()
        })
        .collect()
}

/// The shape as a V2 BEEF of one BUMP and no transaction.
fn beef_of(bump: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x02, 0x00, 0xbe, 0xef, 0x01];
    bytes.extend_from_slice(bump);
    bytes.push(0);
    bytes
}

/// A header chain carrying one root at one height (wire order).
struct OneRoot(u64, [u8; 32]);

impl Headers for OneRoot {
    fn carries(&self, height: u64, root: &[u8; 32]) -> bool {
        height == self.0 && *root == self.1
    }
}

fn wire(display: &str) -> [u8; 32] {
    let mut h: [u8; 32] = from_hex(display).unwrap().try_into().unwrap();
    h.reverse();
    h
}

/// What this crate's readers say of one shape: the root from every hash of
/// level 0, or the reason in its words.
fn readers(shape: &Shape) -> Result<BTreeMap<String, String>, String> {
    let bytes = from_hex(&shape.hex).unwrap();
    let path = path_of(shape);
    let hashes: Vec<String> = path[0].iter().filter_map(|l| l.hash.clone()).collect();

    // A BUMP read alone.
    let alone = MerklePath::from_binary(&bytes);
    // The stream's leading element.
    let streamed = match BeefStream::new(beef_of(&bytes).as_slice()).next() {
        Some(Ok(Element::Bump(bump))) => Ok(bump.root),
        Some(Err(e)) => Err(e.to_string()),
        other => panic!(
            "{}: a BEEF of one BUMP leads with it: {other:?}",
            shape.name
        ),
    };
    // The whole BEEF, and a BUMP held in memory.
    let mut whole = Beef::from_binary(&beef_of(&bytes));
    let mut held = Beef::new();
    held.bumps.push(MerklePath {
        block_height: shape.block_height,
        path: path.clone(),
    });
    let held = held.verify_structure();

    match alone {
        Ok(read) => {
            let mut roots = BTreeMap::new();
            for h in &hashes {
                roots.insert(h.clone(), read.compute_root(Some(h)).unwrap());
            }
            let root = roots.values().next().unwrap().clone();
            assert!(
                roots.values().all(|r| *r == root),
                "{}: one root",
                shape.name
            );
            let mut streamed = streamed.expect("the stream accepts what the BUMP alone does");
            streamed.reverse();
            assert_eq!(to_hex(&streamed), root, "{}: the stream's root", shape.name);
            let whole = whole
                .as_mut()
                .expect("the whole BEEF parses")
                .verify_structure()
                .expect("the whole BEEF accepts what the BUMP alone does");
            assert_eq!(
                whole.get(&shape.block_height),
                Some(&root),
                "{}",
                shape.name
            );
            let held = held.expect("a BUMP held in memory is accepted");
            assert_eq!(held.get(&shape.block_height), Some(&root), "{}", shape.name);
            // The header carrying the root decides.
            let verdict = verify_stream_structure(
                beef_of(&bytes).as_slice(),
                OneRoot(shape.block_height.into(), wire(&root)),
                None,
            )
            .unwrap();
            assert!(
                matches!(verdict, Verdict::Valid { .. }),
                "{}: {verdict:?}",
                shape.name
            );
            Ok(roots)
        }
        Err(e) => {
            let text = e.to_string();
            let (_, reason) = text
                .split_once(": invalid BUMP at byte ")
                .and_then(|(_, rest)| rest.split_once(": "))
                .unwrap_or_else(|| panic!("{}: {text}", shape.name));
            let reason = reason.to_string();
            let streamed = streamed.expect_err("the stream refuses what the BUMP alone does");
            assert!(streamed.ends_with(&reason), "{}: {streamed}", shape.name);
            let whole = match whole {
                Err(e) => e.to_string(),
                Ok(_) => panic!(
                    "{}: the whole BEEF parses what the stream refuses",
                    shape.name
                ),
            };
            assert!(whole.ends_with(&reason), "{}: {whole}", shape.name);
            let kind = reason.split_whitespace().next().unwrap().to_string();
            assert_eq!(format!("{:?}", held.unwrap_err()), kind, "{}", shape.name);
            Err(reason)
        }
    }
}

/// `MerklePath::new` and `new_unchecked` (the reference's constructor with
/// `legalOffsetsOnly` true and false) against the reference's verdicts.
fn built_in_memory(shape: &Shape) {
    let path = path_of(shape);
    for (what, built, reference) in [
        (
            "new",
            MerklePath::new(shape.block_height, path.clone()),
            &shape.verdict,
        ),
        (
            "new_unchecked",
            MerklePath::new_unchecked(shape.block_height, path.clone()),
            &shape.unchecked,
        ),
    ] {
        match built {
            Ok(built) => {
                assert!(reference.accepted, "{}: {what} accepts", shape.name);
                for (txid, root) in &reference.roots {
                    assert_eq!(
                        &built.compute_root(Some(txid)).unwrap(),
                        root,
                        "{}",
                        shape.name
                    );
                }
            }
            Err(e) => assert!(!reference.accepted, "{}: {what} refuses {e}", shape.name),
        }
    }
}

/// The bytes are this crate's writer's and the reference's.
#[test]
fn each_shape_is_the_bytes_this_crates_writer_and_the_reference_write() {
    let v = vectors();
    assert_eq!(
        v.reference,
        "ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts"
    );
    assert_eq!(v.node, "v22.18.0");
    assert_eq!(v.shapes.len(), 9);
    for shape in &v.shapes {
        let written = MerklePath {
            block_height: shape.block_height,
            path: path_of(shape),
        }
        .to_hex();
        assert_eq!(written, shape.hex, "{}", shape.name);
    }
}

/// Every reader gives the reference's root where the reference computes
/// one, and refuses where it refuses: a duplicate at an even offset met as
/// the working hash's sibling pairs it with itself (at levels 0, 1 and 2,
/// and beside a second txid whose path finds the node over it carried); a
/// node computed from it, as a left child or under a right child, is
/// `LeftDuplicateBelow` at the node the walk needed. Through 0.9.0-beta.1, until the
/// re-read of 2026-10-26, every shape was refused `BadFlag { byte: 1 }` at the flag.
#[test]
fn an_even_offset_duplicate_reads_as_the_reference_reads_it() {
    let v = vectors();
    let mut accepted = 0;
    for shape in &v.shapes {
        built_in_memory(shape);
        match (readers(shape), &shape.verdict) {
            (Ok(roots), r) if r.accepted => {
                assert_eq!(&roots, &r.roots, "{}: the reference's roots", shape.name);
                assert!(roots.values().all(|x| Some(x) == r.root.as_ref()));
                accepted += 1;
            }
            (Err(reason), r) if !r.accepted => {
                assert!(r.refusal.is_some(), "{}", shape.name);
                assert_eq!(reason, refused_here(&shape.name), "{}", shape.name);
            }
            (here, r) => panic!(
                "{}: here {here:?}, the reference {}",
                shape.name,
                r.refusal.as_deref().unwrap_or("accepts")
            ),
        }
    }
    assert_eq!(accepted, 4);
}
