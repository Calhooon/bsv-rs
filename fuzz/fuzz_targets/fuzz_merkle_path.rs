#![no_main]
//! `MerklePath` (BRC-74 BUMP) on arbitrary bytes: the binary and hex parsers,
//! then every walk a parsed path offers (each leaf's root, `combine` with
//! itself, `trim`, `contains`). The assertion is that each returns; the
//! target also checks a round trip: a parsed path's bytes parse again, to the
//! same bytes and the same root for each txid; and that the standalone reader
//! is the BEEF reader's BUMP decoder (bsv-rs#167;
//! `tests/merkle_path_two_readers_agree.rs`): the bytes wrapped as a
//! one-BUMP BEEF are accepted when the parse accepts them, to the same bytes
//! taken, levels and root, and refused otherwise with the same refusal, its
//! offset the BEEF's less the five bytes of its header.
use bsv_rs::primitives::{to_hex, Reader};
use bsv_rs::transaction::{Beef, BeefStream, Element, MerklePath};
use libfuzzer_sys::fuzz_target;

/// The BEEF header the BUMP is wrapped in: the V1 word and a count of one.
const HEADER: [u8; 5] = [0x01, 0x00, 0xbe, 0xef, 0x01];

/// A refusal's text with its offset moved back by `less` bytes.
fn moved(text: &str, less: u64) -> String {
    const AT: &str = "invalid BEEF at byte ";
    let Some(i) = text.find(AT) else {
        return text.to_string();
    };
    let rest = &text[i + AT.len()..];
    let Some((offset, reason)) = rest.split_once(": ") else {
        return text.to_string();
    };
    let offset: u64 = offset.parse().expect("an offset");
    format!("{AT}{}: {reason}", offset - less)
}

fn both_readers_agree(data: &[u8]) {
    let mut reader = Reader::new(data);
    let alone = MerklePath::from_reader(&mut reader);
    let mut wrapped = HEADER.to_vec();
    wrapped.extend_from_slice(data);
    let bump = match BeefStream::new(wrapped.as_slice()).next() {
        Some(Ok(Element::Bump(bump))) => bump,
        Some(Err(e)) => {
            let text = alone
                .expect_err("the BEEF reader refuses the BUMP")
                .to_string();
            assert_eq!(
                text.split_once("error: ").map(|(_, t)| t),
                Some(moved(&e.to_string(), HEADER.len() as u64).as_str())
            );
            return;
        }
        other => panic!("a BEEF of one BUMP leads with it: {other:?}"),
    };
    let used = bump.wire_len as usize;
    let mut whole = HEADER.to_vec();
    whole.extend_from_slice(&data[..used]);
    whole.push(0);
    match (alone, Beef::from_binary(&whole)) {
        (Ok(path), Ok(beef)) => {
            assert_eq!(reader.position(), used, "the bytes taken");
            assert_eq!(path.block_height, beef.bumps[0].block_height);
            assert_eq!(path.path, beef.bumps[0].path, "the levels");
            let mut root = bump.root;
            root.reverse();
            let root = to_hex(&root);
            for leaf in &path.path[0] {
                if let Some(txid) = &leaf.hash {
                    assert_eq!(path.compute_root(Some(txid)).ok().as_ref(), Some(&root));
                }
            }
        }
        (Err(a), Err(b)) => assert_eq!(
            a.to_string()
                .split_once("error: ")
                .map(|(_, t)| t.to_string()),
            b.to_string()
                .split_once("error: ")
                .map(|(_, t)| moved(t, HEADER.len() as u64))
        ),
        (a, b) => panic!("the readers disagree: {a:?} / {b:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = MerklePath::from_hex(text);
    }
    both_readers_agree(data);
    let Ok(path) = MerklePath::from_binary(data) else {
        return;
    };

    let bytes = path.to_binary();
    let again = MerklePath::from_binary(&bytes).expect("a path's own bytes parse");
    assert_eq!(again.to_binary(), bytes, "the bytes are not a fixed point");
    assert_eq!(
        MerklePath::from_hex(&path.to_hex())
            .map(|p| p.to_binary())
            .ok(),
        Some(bytes)
    );

    let txids = path.txids();
    let _ = path.compute_root(None);
    for txid in &txids {
        let root = path.compute_root(Some(txid));
        assert_eq!(
            root.as_ref().ok(),
            again.compute_root(Some(txid)).as_ref().ok()
        );
        assert!(path.contains(txid));
    }
    let _ = path.compute_root(Some("00"));
    let _ = path.compute_root(Some(&"ab".repeat(32)));

    let mut combined = path.clone();
    let _ = combined.combine(&again);
    let _ = combined.to_binary();
    let mut trimmed = path.clone();
    trimmed.trim();
    let _ = trimmed.to_binary();
    if let [txid, ..] = &txids[..] {
        let mut marked = path.clone();
        let _ = marked.contains_and_mark(txid);
        let _ = marked.compute_root(Some(txid));
    }
});
