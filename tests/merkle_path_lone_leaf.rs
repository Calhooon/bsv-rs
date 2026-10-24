//! L2-offset0: owned vectors in bsv-stack-lean/conformance/merkle-path-lone-leaf.json.
#![cfg(feature = "transaction")]

use bsv_rs::primitives::{from_hex, Reader};
use bsv_rs::transaction::{
    verify_stream_structure, Beef, Kind, MerklePath, MerklePathLeaf, Reason, Verdict,
};
use bsv_rs::Error;
use std::collections::HashMap;

const LONE: &str =
    "fe05350c00010100027f99c4e42e06eca54293b05cb7a67be42778ae046c04fc5b68122bedcadbeef5";
const LONE_AT_ONE: &str =
    "fe05350c00010101027f99c4e42e06eca54293b05cb7a67be42778ae046c04fc5b68122bedcadbeef5";
const BEEF_LONE: &str = "0100beef01fe05350c00010100027f99c4e42e06eca54293b05cb7a67be42778ae046c04fc5b68122bedcadbeef50101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01010000000000000000000000000100";
const BEEF_LONE_AT_ONE: &str = "0100beef01fe05350c00010101027f99c4e42e06eca54293b05cb7a67be42778ae046c04fc5b68122bedcadbeef500";
const TXID: &str = "f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f";

fn missing(offset: u64) -> Error {
    Error::MerklePathError(format!(
        "MissingSibling {{ level: 0, offset: {} }}",
        offset ^ 1
    ))
}

fn in_memory(offset: u64) -> MerklePath {
    MerklePath {
        block_height: 800_005,
        path: vec![vec![MerklePathLeaf::new_txid(offset, TXID.into())]],
    }
}

#[test]
fn lone_parsers_accept_offset_zero() {
    let bytes = from_hex(LONE).unwrap();
    for path in [
        MerklePath::from_binary(&bytes),
        MerklePath::from_hex(LONE),
        MerklePath::from_reader(&mut Reader::new(&bytes)),
    ] {
        let path = path.unwrap();
        assert_eq!(path.to_hex(), LONE);
        assert_eq!(path.compute_root(None).unwrap(), TXID);
    }
    assert_eq!(MerklePath::from_coinbase_txid(TXID, 800_005).to_hex(), LONE);
}

#[test]
fn lone_at_one_parsers_refuse_missing_sibling() {
    let bytes = from_hex(LONE_AT_ONE).unwrap();
    for result in [
        MerklePath::from_binary(&bytes),
        MerklePath::from_hex(LONE_AT_ONE),
        MerklePath::from_reader(&mut Reader::new(&bytes)),
        MerklePath::new(800_005, in_memory(1).path),
        MerklePath::new_unchecked(800_005, in_memory(1).path),
    ] {
        assert_eq!(result.unwrap_err(), missing(1));
    }
}

#[test]
fn lone_compute_root_accepts_offset_zero() {
    for txid in [None, Some(TXID)] {
        assert_eq!(in_memory(0).compute_root(txid).unwrap(), TXID);
    }
}

#[test]
fn lone_compute_root_refuses_every_nonzero_offset_class() {
    for offset in [1, 2, 3, 252, 253, 65535, 65536, u32::MAX as u64, u64::MAX] {
        for txid in [None, Some(TXID)] {
            assert_eq!(
                in_memory(offset).compute_root(txid).unwrap_err(),
                missing(offset)
            );
        }
        let bytes = in_memory(offset).to_binary();
        assert_eq!(
            MerklePath::from_binary(&bytes).unwrap_err(),
            missing(offset)
        );
    }
}

#[test]
fn combine_valid_paths_preserves_lone_offset_zero_and_refuses_forgery() {
    let parsed = MerklePath::from_hex(LONE).unwrap();
    let built = MerklePath::from_coinbase_txid(TXID, 800_005);
    for (mut left, right) in [(parsed.clone(), built.clone()), (built, parsed.clone())] {
        left.combine(&right).unwrap();
        assert_eq!(left.to_hex(), LONE);
        assert_eq!(left.compute_root(None).unwrap(), TXID);
        assert_eq!(
            MerklePath::from_binary(&left.to_binary()).unwrap().to_hex(),
            left.to_hex()
        );
    }
    // Neither argument order may merge the old reference's same-root forgery.
    for (mut left, right) in [(parsed.clone(), in_memory(1)), (in_memory(1), parsed)] {
        let before = left.clone();
        assert_eq!(left.combine(&right).unwrap_err(), missing(1));
        assert_eq!(left.to_hex(), before.to_hex());
    }
    // Valid two-leaf paths stay a pair, even when their txid flags differ.
    let mut left = MerklePath::new(
        800_005,
        vec![vec![
            MerklePathLeaf::new_txid(0, TXID.into()),
            MerklePathLeaf::new(1, "11".repeat(32)),
        ]],
    )
    .unwrap();
    let mut right = left.clone();
    right.path[0][0].txid = false;
    right.path[0][1].txid = true;
    let root = left.compute_root(None).unwrap();
    left.combine(&right).unwrap();
    assert_eq!(left.path[0].len(), 2);
    assert_eq!(left.compute_root(None).unwrap(), root);
}

#[test]
fn beef_and_merkle_path_agree_on_both_owned_bodies() {
    let mut wire_hash = from_hex(TXID).unwrap();
    wire_hash.reverse();
    let headers = HashMap::from([(800_005u64, <[u8; 32]>::try_from(wire_hash).unwrap())]);
    for (body, bump, accepted) in [
        (BEEF_LONE, LONE, true),
        (BEEF_LONE_AT_ONE, LONE_AT_ONE, false),
    ] {
        let bytes = from_hex(body).unwrap();
        assert_eq!(&bytes[5..46], from_hex(bump).unwrap());
        let stream = verify_stream_structure(bytes.as_slice(), &headers, None).unwrap();
        let mut whole = Beef::new();
        whole.bumps.push(in_memory(if accepted { 0 } else { 1 }));
        if accepted {
            assert!(stream.is_valid());
            for roots in [
                whole.verify_structure().unwrap(),
                Beef::from_binary(&bytes)
                    .unwrap()
                    .verify_structure()
                    .unwrap(),
            ] {
                assert_eq!(roots.get(&800_005).unwrap(), TXID);
            }
            assert_eq!(
                MerklePath::from_hex(bump)
                    .unwrap()
                    .compute_root(None)
                    .unwrap(),
                TXID
            );
        } else {
            assert!(matches!(
                stream,
                Verdict::Invalid {
                    kind: Kind::MissingSibling,
                    reason: Reason::MissingSibling {
                        level: 0,
                        offset: 0
                    },
                    ..
                }
            ));
            assert_eq!(whole.verify_structure(), Err(Kind::MissingSibling));
            // The parse is the stream's decoder (#86): its refusal, in its
            // words, at the leaf's offset varint.
            assert_eq!(
                Beef::from_binary(&bytes).unwrap_err(),
                Error::BeefError(
                    "invalid BEEF at byte 12: MissingSibling { level: 0, offset: 0 }".to_string()
                )
            );
            assert_eq!(MerklePath::from_hex(bump).unwrap_err(), missing(1));
        }
    }
}
