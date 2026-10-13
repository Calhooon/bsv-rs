//! Canonical reading: bitcoin-sv@6504a3af src/serialize.h:315-340,
//! through bsv-script-lean@50d437b lean/BsvScript/Tx.lean:45-57.
#![cfg(feature = "primitives")]

use bsv_rs::primitives::Reader;
#[cfg(feature = "transaction")]
use bsv_rs::primitives::Writer;

#[test]
fn node_noncanonical_encodings_are_refused() {
    // Transcribed from bitcoin-sv@6504a3af src/test/serialize_tests.cpp:359-399.
    for raw in [
        "fd0000",
        "fdfc00",
        "fe00000000",
        "feffff0000",
        "ff0000000000000000",
        "ffffffff0100000000",
    ] {
        let bytes = hex::decode(raw).unwrap();
        assert!(
            Reader::new(&bytes).read_var_int().is_err(),
            "accepted {raw}"
        );
    }
    assert_eq!(Reader::new(&[0xfd, 0xfd, 0]).read_var_int(), Ok(253));
}

#[test]
#[cfg(feature = "transaction")]
fn transaction_noncanonical_input_count_is_refused() {
    // The design probe's witness: serialize.h:320-323 rejects fd0100.
    let mut writer = Writer::new();
    writer
        .write_u32_le(1)
        .write_var_int(1)
        .write_bytes(&[0; 32]);
    writer.write_u32_le(u32::MAX).write_var_bytes(&[0x51]);
    writer.write_u32_le(u32::MAX).write_var_int(1);
    writer.write_u64_le(0).write_var_bytes(&[]).write_u32_le(0);
    let mut bytes = writer.into_bytes();
    assert!(bsv_rs::transaction::Transaction::from_binary(&bytes).is_ok());
    bytes.splice(4..5, [0xfd, 1, 0]);
    assert!(bsv_rs::transaction::Transaction::from_binary(&bytes).is_err());
}

#[test]
#[cfg(feature = "transaction")]
fn beef_noncanonical_count_is_refused() {
    use bsv_rs::transaction::Beef;
    let mut writer = Writer::new();
    writer
        .write_u32_le(0xefbe0002)
        .write_var_int(0)
        .write_var_int(0);
    let mut bytes = writer.into_bytes();
    assert!(Beef::from_binary(&bytes).is_ok());
    bytes.splice(4..5, [0xfd, 0, 0]);
    assert!(Beef::from_binary(&bytes).is_err());
}

#[test]
#[cfg(feature = "transaction")]
fn streaming_beef_noncanonical_count_is_refused() {
    use bsv_rs::transaction::beef_stream::{BeefDecoder, Step};
    let bytes = hex::decode("0200beeffd000000").unwrap();
    let mut decoder = BeefDecoder::new();
    let mut input = bytes.as_slice();
    loop {
        match decoder.next(&mut input) {
            Err(_) => break,
            Ok(Step::Done | Step::NeedMore) => panic!("accepted noncanonical count"),
            Ok(_) => {}
        }
    }
}

#[test]
#[cfg(feature = "transaction")]
fn bump_noncanonical_height_is_refused() {
    use bsv_rs::transaction::{MerklePath, MerklePathLeaf};
    let bump =
        MerklePath::new(1, vec![vec![MerklePathLeaf::new_txid(0, "01".repeat(32))]]).unwrap();
    let mut bytes = bump.to_binary();
    assert!(MerklePath::from_binary(&bytes).is_ok());
    bytes.splice(0..1, [0xfd, 1, 0]);
    assert!(MerklePath::from_binary(&bytes).is_err());
}

#[test]
#[cfg(feature = "transaction")]
fn streaming_noncanonical_refusal_survives_every_chunk_boundary() {
    use bsv_rs::transaction::beef_stream::{BeefDecoder, Step};
    use bsv_rs::transaction::Reason;
    // serialize.h:320-335 at bitcoin-sv@6504a3af, each width in a BEEF count.
    for encoded in ["fd0000", "fe00000000", "ff0000000000000000"] {
        let mut writer = Writer::new();
        writer
            .write_u32_le(0xefbe0002)
            .write_bytes(&hex::decode(encoded).unwrap())
            .write_var_int(0);
        let bytes = writer.into_bytes();
        for split in 0..=bytes.len() {
            let mut decoder = BeefDecoder::new();
            let mut error = None;
            for chunk in [&bytes[..split], &bytes[split..]] {
                let mut input = chunk;
                loop {
                    match decoder.next(&mut input) {
                        Ok(Step::NeedMore) => break,
                        Ok(Step::Element(_)) => {}
                        Ok(Step::Done) => panic!("accepted noncanonical count"),
                        Err(refusal) => {
                            error = Some(refusal);
                            break;
                        }
                    }
                }
                if error.is_some() {
                    break;
                }
            }
            let refusal = error.expect("noncanonical refusal");
            assert_eq!(refusal.offset, 4);
            assert_eq!(refusal.reason, Reason::BadVarint);
        }
    }
}
