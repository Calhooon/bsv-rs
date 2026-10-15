//! Node vectors at bitcoin-sv@6504a3af, through bsv-script-lean@50d437b
//! lean/BsvChain/{Header,Pow,Merkle}.lean, issues #63, #64 and #65.
#![cfg(feature = "block")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::block::*;
use bsv_rs::primitives::{sha256, Hash32, Reader, Writer, U256};
use bsv_rs::Error;

#[path = "chain_vectors/compact.rs"]
mod compact;

const GENESIS: &str = concat!(
    "010000000000000000000000000000000000000000000000000000000000000000000000",
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
    "29ab5f49ffff001d1dac2b7c"
);

#[test]
fn node_compact_tables_and_limits() {
    for (bits, negative, overflow, hex) in compact::SET_COMPACT {
        assert_eq!(
            CompactTarget::from_bits(bits),
            CompactTarget {
                target: U256::from_hex(hex).unwrap(),
                negative,
                overflow,
            },
            "{bits:#010x}"
        );
    }
    for (bits, encoded, signed, negative, overflow) in compact::GET_COMPACT {
        let target = CompactTarget::from_bits(bits);
        assert_eq!((target.negative, target.overflow), (negative, overflow));
        if !overflow {
            assert_eq!(target.target.to_compact_signed(signed), encoded);
        }
        assert_eq!(
            target.is_valid(),
            !negative && !overflow && !target.target.is_zero()
        );
    }
    // bitcoin-sv@6504a3af src/test/arith_uint256_tests.cpp:640-642.
    assert_eq!(U256::from_u64(0x80).to_compact(), 0x02008000);
    assert_eq!(U256::ZERO.to_compact_signed(true), 0);
    // bitcoin-sv@6504a3af src/chainparams.cpp:1047-1048,1214,1343-1344,1471-1472.
    for limit in [POW_LIMIT_MAIN, POW_LIMIT_TEST, POW_LIMIT_STN] {
        assert_eq!(limit.to_compact(), 0x1d00ffff);
        assert_eq!(limit, U256::MAX.shr(32));
    }
    assert_eq!(POW_LIMIT_REGTEST, U256::MAX.shr(1));
    assert_eq!(POW_LIMIT_REGTEST.to_compact(), 0x207fffff);
    // Exponent/mantissa boundaries from arith_uint256.cpp:197-199.
    for (bits, overflow) in [
        (0x220000ff, false),
        (0x22000100, true),
        (0x2100ffff, false),
        (0x21010000, true),
        (0x23000001, true),
        (0xff000000, false),
    ] {
        assert_eq!(CompactTarget::from_bits(bits).overflow, overflow);
    }
}

#[test]
fn node_pow_refusals_and_equality() {
    // bitcoin-sv@6504a3af src/pow.cpp:159-167. Zero precedes overflow.
    let rows = [
        (0x1d80ffff, PowError::BitsNegative { bits: 0x1d80ffff }),
        (0x00123456, PowError::BitsZero { bits: 0x00123456 }),
        (0x01803456, PowError::BitsZero { bits: 0x01803456 }),
        (0xff123456, PowError::BitsZero { bits: 0xff123456 }),
        (0x407fffff, PowError::BitsZero { bits: 0x407fffff }),
        (0x21123456, PowError::BitsOverflow { bits: 0x21123456 }),
        (0x1d01ffff, PowError::BitsAboveLimit { bits: 0x1d01ffff }),
    ];
    for (bits, error) in rows {
        assert_eq!(error.reject_reason(), "high-hash");
        assert_eq!(
            check_proof_of_work(&[0; 32], bits, &POW_LIMIT_MAIN),
            Err(error)
        );
    }
    let target = CompactTarget::from_bits(0x1d00ffff).target;
    assert_eq!(
        check_proof_of_work(&target.to_le_bytes(), 0x1d00ffff, &POW_LIMIT_MAIN),
        Ok(())
    );
    assert_eq!(
        check_proof_of_work(
            &target.wrapping_add(U256::ONE).to_le_bytes(),
            0x1d00ffff,
            &POW_LIMIT_MAIN
        ),
        Err(PowError::HighHash { bits: 0x1d00ffff })
    );
    let mut header = BlockHeader::from_hex(GENESIS).unwrap();
    assert_eq!(header.check_proof_of_work(&POW_LIMIT_MAIN), Ok(()));
    header.nonce ^= 1;
    assert_eq!(
        header.check_proof_of_work(&POW_LIMIT_MAIN),
        Err(PowError::HighHash { bits: header.bits })
    );
}

#[test]
fn node_genesis_header_and_exact_frame() {
    // bitcoin-sv@6504a3af src/chainparams.cpp:1094-1102, block.h:23-65;
    // ts-stack@edf6e03 wallet-toolbox/src/services/chaintracker/chaintracks/
    // util/blockHeaderUtilities.ts:718-730; sibling Header.lean:24-67.
    let header = BlockHeader::from_hex(GENESIS).unwrap();
    assert_eq!(header.to_hex(), GENESIS);
    assert_eq!(
        header.id(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    assert_eq!(
        header.merkle_root_hex(),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    );
    assert_eq!(header.prev_id(), "0".repeat(64));
    assert_eq!(
        (header.version, header.time, header.bits, header.nonce),
        (1, 1231006505, 0x1d00ffff, 2083236893)
    );
    assert_eq!(header.hash_number().to_le_bytes(), header.hash());
    assert_eq!(header.hash_number().to_hex(), header.id());
    for size in [0, 79, 81, 160] {
        assert_eq!(
            BlockHeader::from_binary(&vec![0; size]),
            Err(Error::InvalidDataLength {
                expected: 80,
                actual: size
            })
        );
    }
    for size in 0..80 {
        assert!(matches!(
            BlockHeader::from_reader(&mut Reader::new(&vec![0; size])),
            Err(Error::ReaderUnderflow { .. })
        ));
    }
    let mut writer = Writer::new();
    header.to_writer(&mut writer);
    writer.write_u8(42);
    let mut reader = Reader::new(writer.as_bytes());
    assert_eq!(BlockHeader::from_reader(&mut reader).unwrap(), header);
    assert_eq!(reader.read_u8().unwrap(), 42);
    let mut bytes = header.to_binary();
    bytes[..4].fill(255);
    let signed = BlockHeader::from_binary(&bytes).unwrap();
    assert_eq!(signed.version, -1);
    assert_eq!(signed.to_binary(), bytes);
    assert!(BlockHeader::from_hex("xyz").is_err());
}

#[test]
fn teranode_header_runs_link_work_and_pow() {
    // Header/hash/pow/work rules: bitcoin-sv@6504a3af block.h:23-65,
    // block.cpp:16-18, pow.cpp:150-171, block_index.cpp:114-127.
    // Fixtures: Teranode@4edb60a4 via chaintracks@db4008d src/testdata/README.md:1-23.
    // The terminal 504031 hash is also chainparams.cpp:1155 at the node pin.
    let rows: &[(&[u8], usize, &str, &str, &str)] = &[
        (
            include_bytes!("data/chain_headers/main_501984_504031.bin"),
            2048,
            "48999616d05872e958709c1ac964022d0979394e348a0a1013d87b6a3b40ca35",
            "feb2c8ddd3f7dbc3a200",
            "0000000000000000011ebf65b60d0a3de80b8175be709d653b4c1a1beeb6ab9c",
        ),
        (
            include_bytes!("data/chain_headers/main_886001_888000.bin"),
            2000,
            "106deacffa0eba0db49f814f1c3672222a81f792e514bf343478dcf055385bd9",
            "767c6646e2b78099887f",
            "000000000000000004026d10802cf1132fc67cc7a0c340eb4686869edaf48f38",
        ),
        (
            include_bytes!("data/chain_headers/test_0_547.bin"),
            548,
            "8a6ba287b6a64cff223c4ffadccce85f8af292ad2a13b1427f20534083f9100e",
            "22402240224",
            "00000000a52cae0fc21fd9fec071c2dc1990077f9c8e2b885c1de9c8be407e56",
        ),
    ];
    for &(data, count, sha, work, tip) in rows {
        assert_eq!(hex::encode(sha256(data)), sha);
        assert_eq!(data.len(), count * HEADER_SIZE);
        let mut prev = None;
        let mut sum = ChainWork::ZERO;
        for frame in data.as_chunks::<HEADER_SIZE>().0 {
            let frame: &[u8] = frame;
            let header = BlockHeader::from_binary(frame).unwrap();
            assert_eq!(header.to_binary(), frame);
            if let Some(hash) = prev {
                assert_eq!(header.prev_hash, hash);
            }
            assert_eq!(header.check_proof_of_work(&POW_LIMIT_MAIN), Ok(()));
            assert_eq!(header.target().target.to_compact(), header.bits);
            sum = sum.wrapping_add(header.work());
            prev = Some(header.hash());
        }
        assert_eq!(sum, ChainWork::from_hex(work).unwrap());
        assert_eq!(U256::from_le_bytes(prev.unwrap()).to_hex(), tip);
        println!(
            "headers={count}; links={}; work={work}; tip={tip}",
            count - 1
        );
    }
}

#[test]
fn node_block_proof_and_wrapping_chain_work() {
    // bitcoin-sv@6504a3af src/block_index.cpp:114-127 and block_index.h:663-664.
    assert_eq!(
        ChainWork::from_bits(0x1d00ffff),
        ChainWork::from_hex("100010001").unwrap()
    );
    for bits in [0x01803456, 0x1d80ffff, 0xff123456, 0] {
        assert_eq!(ChainWork::from_bits(bits), ChainWork::ZERO);
    }
    let max = ChainWork::from_be_bytes([255; 32]);
    let one = ChainWork::from_hex("1").unwrap();
    assert_eq!(max.wrapping_add(one), ChainWork::ZERO);
    assert_eq!(one.checked_sub(max), None);
    assert_eq!(max.checked_sub(max), Some(ChainWork::ZERO));
    assert_eq!(max.checked_sub(one).unwrap().wrapping_add(one), max);
    assert!(
        ChainWork::from_hex("10000000000000000").unwrap()
            > ChainWork::from_hex("ffffffffffffffff").unwrap()
    );
    for value in [max, one, ChainWork::ZERO, ChainWork::from_bits(0x207fffff)] {
        assert_eq!(value.to_hex().len(), 64);
        assert_eq!(ChainWork::from_hex(&value.to_hex()).unwrap(), value);
        assert_eq!(ChainWork::from_be_bytes(value.to_be_bytes()), value);
        assert_eq!(value.as_u256().to_hex(), value.to_hex());
    }
    for bad in [
        "".to_string(),
        "f".repeat(65),
        "0x01".into(),
        "+1".into(),
        "-1".into(),
        " 1".into(),
        "1 ".into(),
        "1g".into(),
        "é".into(),
    ] {
        assert!(ChainWork::from_hex(&bad).is_err(), "{bad:?}");
        assert!(U256::from_hex(&bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        ChainWork::from_hex("ABC").unwrap(),
        ChainWork::from_hex("abc").unwrap()
    );
}

#[test]
fn u256_arithmetic_against_independent_big_integer_oracle() {
    use num_bigint::BigUint;
    let modulus = BigUint::from(1u8) << 256usize;
    let mask = &modulus - 1u8;
    let big = |value: U256| BigUint::from_bytes_le(&value.to_le_bytes());
    let mut values = vec![U256::ZERO, U256::ONE, U256::MAX];
    for bit in [1, 63, 64, 65, 127, 128, 191, 192, 255] {
        values.push(U256::ONE.shl(bit));
        values.push(U256::ONE.shl(bit).wrapping_sub(U256::ONE));
    }
    for n in 0u32..256 {
        values.push(U256::from_le_bytes(sha256(&n.to_le_bytes())));
    }
    for (i, &a) in values.iter().enumerate() {
        let b = values[(i * 73 + 7) % values.len()];
        let (aa, bb) = (big(a), big(b));
        assert_eq!(a.cmp(&b), aa.cmp(&bb));
        assert_eq!(a.bits() as u64, aa.bits());
        assert_eq!(U256::from_be_bytes(a.to_be_bytes()), a);
        assert_eq!(U256::from_hex(&a.to_hex()).unwrap(), a);
        assert_eq!(big(a.not()), &mask ^ &aa);
        assert_eq!(big(a.wrapping_add(b)), (&aa + &bb) % &modulus);
        assert_eq!(big(a.wrapping_sub(b)), (&aa + &modulus - &bb) % &modulus);
        assert_eq!(big(a.wrapping_neg()), (&modulus - &aa) % &modulus);
        for factor in [0, 1, u32::MAX as u64, u64::MAX] {
            assert_eq!(big(a.wrapping_mul_u64(factor)), (&aa * factor) % &modulus);
        }
        for divisor in [U256::ZERO, U256::ONE, b, U256::MAX] {
            assert_eq!(
                a.checked_div(divisor).map(big),
                if divisor.is_zero() {
                    None
                } else {
                    Some(&aa / big(divisor))
                }
            );
        }
        for shift in [
            0,
            1,
            63,
            64,
            65,
            127,
            128,
            191,
            192,
            255,
            256,
            257,
            u32::MAX,
        ] {
            let left = if shift >= 256 {
                BigUint::from(0u8)
            } else {
                (&aa << shift as usize) % &modulus
            };
            let right = if shift >= 256 {
                BigUint::from(0u8)
            } else {
                &aa >> shift as usize
            };
            assert_eq!(big(a.shl(shift)), left);
            assert_eq!(big(a.shr(shift)), right);
            assert_eq!(a << shift, a.shl(shift));
            assert_eq!(a >> shift, a.shr(shift));
        }
        assert_eq!(!a, a.not());
    }
}

#[test]
fn merkle_empty_single_and_zero_sentinel_collision() {
    assert_eq!(
        merkle_root(&[]),
        MerkleRoot {
            root: [0; 32],
            mutated: false
        }
    );
    assert_eq!(
        merkle_root(&[[1; 32]]),
        MerkleRoot {
            root: [1; 32],
            mutated: false
        }
    );
    // bitcoin-sv@6504a3af src/test/merkle_tests.cpp:304-316.
    let leaves: Vec<Hash32> = [0x11, 0x22, 0, 0]
        .map(|n| U256::from_u64(n).to_le_bytes())
        .to_vec();
    let expected = merkle_parent(
        &merkle_parent(&leaves[0], &leaves[1]),
        &merkle_parent(&[0; 32], &[0; 32]),
    );
    assert_eq!(
        merkle_root(&leaves),
        MerkleRoot {
            root: expected,
            mutated: true
        }
    );
    assert!(merkle_root(&[[1; 32], [2; 32], [1; 32], [2; 32]]).mutated);
    assert!(!merkle_root(&[[1; 32], [2; 32], [3; 32]]).mutated);
}

#[cfg(feature = "transaction")]
mod merkle_paths {
    use super::*;
    use bsv_rs::transaction::{MerklePath, MerklePathLeaf, Transaction};

    fn transaction(locktime: u32) -> Transaction {
        // bitcoin-sv@6504a3af src/primitives/transaction.cpp:61-62,
        // transaction.h:261: CMutableTransaction, version 2, empty vin/vout.
        let mut writer = Writer::new();
        writer
            .write_u32_le(2)
            .write_var_int(0)
            .write_var_int(0)
            .write_u32_le(locktime);
        Transaction::from_binary(writer.as_bytes()).unwrap()
    }

    fn display(hash: &Hash32) -> String {
        U256::from_le_bytes(*hash).to_hex()
    }

    fn path_for(leaves: &[Hash32], index: usize) -> MerklePath {
        let mut rows = Vec::new();
        let mut level = leaves.to_vec();
        let mut at = index;
        while level.len() > 1 {
            let sibling = at ^ 1;
            let mut row = Vec::new();
            if rows.is_empty() {
                row.push(MerklePathLeaf::new_txid(at as u64, display(&level[at])));
            }
            if sibling < level.len() {
                row.push(MerklePathLeaf::new(
                    sibling as u64,
                    display(&level[sibling]),
                ));
            } else {
                row.push(MerklePathLeaf::new_duplicate(sibling as u64));
            }
            row.sort_by_key(|leaf| leaf.offset);
            rows.push(row);
            level = level
                .chunks(2)
                .map(|pair| merkle_parent(&pair[0], pair.get(1).unwrap_or(&pair[0])))
                .collect();
            at >>= 1;
        }
        MerklePath::new(1, rows).unwrap()
    }

    #[test]
    fn node_merkle_property_and_all_bump_paths() {
        // bitcoin-sv@6504a3af src/test/merkle_tests.cpp:88-195,
        // through sibling@50d437b lean/BsvChain/Merkle.lean:19-52 (#63, #65).
        let (mut cases, mut paths) = (0, 0);
        for count in 0..=16usize {
            let txs: Vec<_> = (0..count as u32).map(transaction).collect();
            let leaves: Vec<_> = txs.iter().map(|tx| tx.hash()).collect();
            let root = merkle_root(&leaves);
            assert!(!root.mutated);
            assert_eq!(block_merkle_root(&txs), root);
            assert_eq!(root.root == [0; 32], count == 0);
            for mutations in 0..=3 {
                let mut mutated = leaves.clone();
                let mut stop = false;
                for _ in 0..mutations {
                    let zeros = if mutated.is_empty() {
                        0
                    } else {
                        mutated.len().trailing_zeros()
                    };
                    let duplicate = 1usize << zeros;
                    if duplicate >= mutated.len() {
                        stop = true;
                        break;
                    }
                    mutated.extend_from_within(mutated.len() - duplicate..);
                }
                if stop {
                    break;
                }
                assert_eq!(
                    merkle_root(&mutated),
                    MerkleRoot {
                        root: root.root,
                        mutated: mutations > 0
                    }
                );
                cases += 1;
            }
            if count >= 2 {
                for (index, leaf) in leaves.iter().enumerate() {
                    let path = path_for(&leaves, index);
                    assert_eq!(
                        path.compute_root(Some(&display(leaf))).unwrap(),
                        display(&root.root)
                    );
                    let parsed = MerklePath::from_binary(&path.to_binary()).unwrap();
                    assert_eq!(
                        parsed.compute_root(Some(&display(leaf))).unwrap(),
                        display(&root.root)
                    );
                    paths += 1;
                }
            }
        }
        assert_eq!((cases, paths), (34, 135));
        println!("merkle mutation cases={cases}; BUMP paths={paths}");
    }

    #[test]
    fn cve_2012_2459_six_into_eight_root_and_mutation() {
        // bitcoin-sv@6504a3af src/consensus/merkle.cpp:18-50.
        let six: Vec<_> = (1..=6).map(|n| transaction(n).hash()).collect();
        let mut eight = six.clone();
        eight.extend_from_slice(&six[4..]);
        let a = merkle_root(&six);
        let b = merkle_root(&eight);
        assert_eq!(a.root, b.root);
        assert!(!a.mutated);
        assert!(b.mutated);
        assert_eq!(
            display(&a.root),
            "3bca610c3418509bf63660f88c2400a3d14dc36d18dc93930572291d5d72c502"
        );
    }
}
