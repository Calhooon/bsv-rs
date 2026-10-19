//! The difficulty rule, `GetNextWorkRequired` at bitcoin-sv v1.2.3
//! (`6504a3aff65ba97c0f6c80962b033e35ecbfed4b`), on the node's own tables in
//! `src/test/pow_tests.cpp`, carried over from chaintracks-cloudflare@74cc110
//! `src/consensus.rs` with their citations, and on a real testnet run.
//!
//! The node builds block indexes with times and bits and no proof of work
//! (`GetBlockIndex`, pow_tests.cpp:125-138), and so do these (a slice of
//! `HeaderLink`s).
#![cfg(feature = "block")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::cmp::Ordering;

use bsv_rs::block::*;
use bsv_rs::primitives::{sha256, U256};

// The node's names for the calls the vectors read, so each reads as the
// node's test does.
fn set_compact(bits: u32) -> U256 {
    CompactTarget::from_bits(bits).target
}
fn get_compact(a: &U256) -> u32 {
    a.to_compact()
}

fn link(height: u32, time: u32, bits: u32) -> HeaderLink {
    HeaderLink { height, time, bits }
}

#[test]
fn the_chain_params_are_the_node_values() {
    let main = ChainParams::main();
    assert_eq!(
        main.pow_limit.to_hex(),
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    assert_eq!(ChainParams::test().pow_limit, main.pow_limit);
    assert_eq!(
        ChainParams::regtest().pow_limit.to_hex(),
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    assert_eq!(main.pow_limit_bits(), 0x1d00ffff);
    assert_eq!(ChainParams::regtest().pow_limit_bits(), 0x207fffff);
    for p in [
        ChainParams::main(),
        ChainParams::test(),
        ChainParams::regtest(),
    ] {
        assert_eq!(
            (p.pow_target_spacing, p.pow_target_timespan),
            (600, 1_209_600)
        );
        assert_eq!(p.difficulty_adjustment_interval(), 2016);
    }
    assert_eq!(
        (
            main.daa_height,
            main.allow_min_difficulty_blocks,
            main.no_retargeting
        ),
        (504_031, false, false)
    );
    let test = ChainParams::test();
    assert_eq!(
        (
            test.daa_height,
            test.allow_min_difficulty_blocks,
            test.no_retargeting
        ),
        (1_188_697, true, false)
    );
    let regtest = ChainParams::regtest();
    assert_eq!(
        (
            regtest.daa_height,
            regtest.allow_min_difficulty_blocks,
            regtest.no_retargeting
        ),
        (0, true, true)
    );
}

/// `get_next_work` (pow_tests.cpp:30-43), `get_next_work_pow_limit`
/// (:46-59), `get_next_work_lower_limit_actual` (:62-75),
/// `get_next_work_upper_limit_actual` (:78-91).
#[test]
fn calculate_next_work_required_matches_the_node_vectors() {
    let main = ChainParams::main();
    let rows: &[(u32, u32, u32, i64, u32)] = &[
        (32255, 1262152739, 0x1d00ffff, 1261130161, 0x1d00d86a),
        (2015, 1233061996, 0x1d00ffff, 1231006505, 0x1d00ffff),
        (68543, 1279297671, 0x1c05a3f4, 1279008237, 0x1c0168fd),
        (46367, 1269211443, 0x1c387f6f, 1263163443, 0x1d00e1fd),
    ];
    for &(height, time, bits, first_time, expected) in rows {
        assert_eq!(
            calculate_next_work_required(&main, link(height, time, bits), first_time),
            expected,
            "block {height}"
        );
    }
}

/// A chain built the way the node's tests build theirs: a first block at
/// `time0`, then each block `interval` seconds after the last.
struct Chain {
    links: Vec<HeaderLink>,
    time: u32,
}

impl Chain {
    fn new(time0: u32, bits: u32) -> Self {
        Chain {
            links: vec![link(0, time0, bits)],
            time: time0,
        }
    }
    fn add(&mut self, interval: i64, bits: u32) {
        self.time = (self.time as i64 + interval) as u32;
        let height = self.links.len() as u32;
        self.links.push(link(height, self.time, bits));
    }
    fn tip(&self) -> u32 {
        self.links.len() as u32 - 1
    }
    /// `GetNextWorkRequired(blocks.Tip(), &blkHeaderDummy)`: the dummy
    /// header's time is 0 (only the minimum-difficulty rule reads it).
    fn next_work(&self, params: &ChainParams) -> u32 {
        next_work_required(params, &self.links[..], self.tip(), 0).unwrap()
    }
    fn next_cash_work(&self, params: &ChainParams) -> u32 {
        next_cash_work_required(params, &self.links[..], self.tip(), 0).unwrap()
    }
}

/// `retargeting_test` (pow_tests.cpp:140-249): the emergency adjustment on
/// mainnet's parameters, below the DAA height.
#[test]
fn the_emergency_adjustment_matches_retargeting_test() {
    let main = ChainParams::main();
    let pow_limit = main.pow_limit;
    let mut current = pow_limit.shr(1);
    let initial_bits = get_compact(&current);
    let mut c = Chain::new(1269211443, initial_bits);
    for _ in 1..100 {
        c.add(main.pow_target_spacing, initial_bits);
    }
    for _ in 100..110 {
        c.add(2 * 3600, initial_bits);
        assert_eq!(c.next_work(&main), initial_bits);
    }
    let step = |current: &mut U256| {
        *current = set_compact(get_compact(current));
        *current = current.wrapping_add(current.shr(2));
    };
    c.add(2 * 3600, initial_bits);
    step(&mut current);
    assert_eq!(c.next_work(&main), get_compact(&current));
    c.add(2 * 3600, get_compact(&current));
    step(&mut current);
    assert_eq!(c.next_work(&main), get_compact(&current));
    c.add(2 * 3600, get_compact(&current));
    step(&mut current);
    assert_eq!(c.next_work(&main), get_compact(&current));
    c.add(2 * 3600, get_compact(&current));
    step(&mut current);
    assert_ne!(get_compact(&pow_limit), get_compact(&current));
    assert_eq!(c.next_work(&main), get_compact(&pow_limit));
    c.add(2 * 3600, get_compact(&current));
    assert_ne!(get_compact(&pow_limit), get_compact(&current));
    assert_eq!(c.next_work(&main), get_compact(&pow_limit));
}

/// `cash_difficulty_test` (pow_tests.cpp:251-496): the DAA, every value and
/// every bound the node checks.
#[test]
fn the_daa_matches_cash_difficulty_test() {
    let main = ChainParams::main();
    let pow_limit = main.pow_limit;
    let pow_limit_bits = get_compact(&pow_limit);
    let initial_bits = get_compact(&pow_limit.shr(4));
    let mut c = Chain::new(1269211443, initial_bits);
    for _ in 1..2050 {
        c.add(600, initial_bits);
    }
    let mut bits = next_cash_work_required(&main, &c.links[..], 2049, 0).unwrap();
    for _ in 0..10 {
        c.add(600, bits);
        assert_eq!(c.next_cash_work(&main), bits);
    }
    c.add(6000, bits);
    assert_eq!(c.next_cash_work(&main), bits);
    c.add(2 * 600 - 6000, bits);
    assert_eq!(c.next_cash_work(&main), bits);
    for _ in 0..20 {
        c.add(600, bits);
        assert_eq!(c.next_cash_work(&main), bits);
    }
    c.add(550, bits);
    assert_eq!(c.next_cash_work(&main), bits);
    for _ in 0..10 {
        c.add(550, bits);
        let next = c.next_cash_work(&main);
        let (cur, nxt) = (set_compact(bits), set_compact(next));
        assert_eq!(nxt.cmp(&cur), Ordering::Less);
        assert_eq!(cur.wrapping_sub(nxt).cmp(&cur.shr(10)), Ordering::Less);
        bits = next;
    }
    assert_eq!(bits, 0x1c0fe7b1);
    for _ in 0..20 {
        c.add(10, bits);
        let next = c.next_cash_work(&main);
        let (cur, nxt) = (set_compact(bits), set_compact(next));
        assert_eq!(nxt.cmp(&cur), Ordering::Less);
        assert_eq!(cur.wrapping_sub(nxt).cmp(&cur.shr(4)), Ordering::Less);
        bits = next;
    }
    assert_eq!(bits, 0x1c0db19f);
    c.add(6000, bits);
    bits = c.next_cash_work(&main);
    assert_eq!(bits, 0x1c0d9222);
    for _ in 0..93 {
        c.add(6000, bits);
        let next = c.next_cash_work(&main);
        let (cur, nxt) = (set_compact(bits), set_compact(next));
        assert_ne!(nxt.cmp(&pow_limit), Ordering::Greater);
        assert_eq!(nxt.cmp(&cur), Ordering::Greater);
        assert_eq!(nxt.wrapping_sub(cur).cmp(&cur.shr(3)), Ordering::Less);
        bits = next;
    }
    assert_eq!(bits, 0x1c2f13b9);
    c.add(6000, bits);
    bits = c.next_cash_work(&main);
    assert_eq!(bits, 0x1c2ee9bf);
    for _ in 0..192 {
        c.add(6000, bits);
        let next = c.next_cash_work(&main);
        let (cur, nxt) = (set_compact(bits), set_compact(next));
        assert_ne!(nxt.cmp(&pow_limit), Ordering::Greater);
        assert_eq!(nxt.cmp(&cur), Ordering::Greater);
        assert_eq!(nxt.wrapping_sub(cur).cmp(&cur.shr(3)), Ordering::Less);
        bits = next;
    }
    assert_eq!(bits, 0x1d00ffff);
    for _ in 0..5 {
        c.add(6000, bits);
        let next = c.next_cash_work(&main);
        assert_eq!(next, pow_limit_bits);
        bits = next;
    }
}

/// Regtest never retargets (pow.cpp:106-109); testnet's 20-minute rule
/// answers the limit (pow.cpp:44-51, 264-271).
#[test]
fn regtest_keeps_the_parents_bits_and_testnet_grants_the_limit_after_20_minutes() {
    let regtest = ChainParams::regtest();
    let w = [link(7, 1000, 0x2000ffff)];
    assert_eq!(
        next_work_required(&regtest, &w[..], 7, 1_000_000),
        Ok(0x2000ffff)
    );
    let test = ChainParams::test();
    let w = [link(1_600_000, 1000, 0x1a33c833)];
    assert_eq!(
        next_work_required(&test, &w[..], 1_600_000, 1000 + 1201),
        Ok(0x1d00ffff)
    );
    // 20 minutes exactly is not more than 20 minutes: the DAA answers, and it
    // needs the headers this chain does not hold.
    assert_eq!(
        next_work_required(&test, &w[..], 1_600_000, 1000 + 1200),
        Err(DifficultyError::MissingAncestor { height: 1_599_998 })
    );
}

/// Testnet below the DAA: the walk back to the last header not mined under
/// the minimum-difficulty rule (pow.cpp:53-61), stopping at an interval
/// boundary and at the genesis.
#[test]
fn testnet_walks_back_past_minimum_difficulty_headers() {
    let test = ChainParams::test();
    let limit = test.pow_limit_bits();
    let w = [
        link(4030, 0, limit),
        link(4031, 0, 0x1c0fffff),
        link(4032, 0, limit),
        link(4033, 0, limit),
        link(4034, 0, limit),
    ];
    // 4032 is a boundary: the walk stops there and answers its bits.
    assert_eq!(next_work_required(&test, &w[..], 4034, 600), Ok(limit));
    let w = [
        link(4033, 0, 0x1c0fffff),
        link(4034, 0, limit),
        link(4035, 0, limit),
    ];
    assert_eq!(next_work_required(&test, &w[..], 4035, 600), Ok(0x1c0fffff));
    let w = [link(0, 0, limit), link(1, 0, limit)];
    assert_eq!(next_work_required(&test, &w[..], 1, 600), Ok(limit));
}

/// `GetMedianTimePast` (block_index.h:720-737) and the `SetChainWork` sums
/// (block_index.h:661-666) read only what the host holds.
#[test]
fn median_time_past_and_chain_work_read_the_held_ancestors() {
    let chain: Vec<_> = (0..12)
        .map(|h| {
            link(
                h,
                [5, 1, 9, 3, 7, 2, 8, 4, 6, 0, 10, 11][h as usize],
                0x207fffff,
            )
        })
        .collect();
    assert_eq!(median_time_past(&chain[..], 0), Ok(5));
    assert_eq!(median_time_past(&chain[..], 10), Ok(5));
    assert_eq!(median_time_past(&chain[..], 11), Ok(6));
    assert_eq!(
        median_time_past(&chain[1..], 10),
        Err(DifficultyError::MissingAncestor { height: 0 })
    );
    let proof = ChainWork::from_bits(0x207fffff);
    assert_eq!(
        chain_work_between(&chain[..], 3, 5),
        Ok(proof.wrapping_add(proof))
    );
    assert_eq!(chain_work_between(&chain[..], 5, 5), Ok(ChainWork::ZERO));
    assert_eq!(
        chain_work_between(&chain[..], 3, 12),
        Err(DifficultyError::MissingAncestor { height: 12 })
    );
}

/// The node asserts where the rule has no answer; this crate refuses without
/// a panic, including on parameters a host set.
#[test]
fn the_rule_refuses_where_the_node_asserts() {
    let main = ChainParams::main();
    let short = [link(5, 0, 0x1c0fffff)];
    assert_eq!(
        next_work_required(&main, &short[..], 5, 0),
        Err(DifficultyError::ChainTooShort { prev_height: 5 })
    );
    let mut daa = ChainParams::main();
    daa.daa_height = 0;
    assert_eq!(
        next_work_required(&daa, &short[..], 5, 0),
        Err(DifficultyError::ChainTooShort { prev_height: 5 })
    );
    let mut broken = ChainParams::main();
    broken.pow_target_spacing = 0;
    assert_eq!(broken.difficulty_adjustment_interval(), 0);
    assert_eq!(
        next_work_required(&broken, &short[..], 5, 0),
        Err(DifficultyError::InvalidParams)
    );
    let _ = broken.window_depth(5);
    broken.pow_target_timespan = -1;
    broken.pow_target_spacing = 600;
    let _ = calculate_next_work_required(&broken, short[0], 0);
    // 147 headers with bits that carry no work: the node's division throws
    let zero: Vec<_> = (0..2017).map(|h| link(h, h * 600, 0)).collect();
    let mut daa = ChainParams::main();
    daa.daa_height = 0;
    assert!(matches!(
        next_work_required(&daa, &zero[..], 2016, 0),
        Err(DifficultyError::ZeroWork { .. })
    ));
}

#[test]
fn the_window_depth_covers_what_each_regime_reads() {
    assert_eq!(ChainParams::regtest().window_depth(965_000), 1);
    assert_eq!(ChainParams::main().window_depth(886_000), 147);
    assert_eq!(ChainParams::main().window_depth(478_000), 17);
    assert_eq!(
        ChainParams::main().window_depth(479_807),
        2016,
        "479808 is a boundary"
    );
    assert_eq!(
        ChainParams::test().window_depth(1_000),
        1001,
        "the walk back, never past genesis"
    );
}

/// Real testnet headers 1602530..=1602710, Teranode v0.16.0 (`4edb60a4`)
/// `test/testnet_headers_1602530_1602710.bin` (WhatsOnChain's, per its
/// README), copied through chaintracks-cloudflare@74cc110 `src/testdata/`.
const TESTNET_1602530: &[u8] = include_bytes!("chain_vectors/test_1602530_1602710.bin");

/// A testnet header on top of the real 1602682, mined for chaintracks'
/// suite (never broadcast): the minimum difficulty only 600 s after its
/// parent, so testnet's rule refuses its bits (pow.cpp:264-271).
const WITNESS_1602683: &str = "00000020d826db8f95129f488573cf1f8fba9b3716c5a9acb5f4a3934b2e00000000000023eb40b70a23238a5a970b93ed6ba28190ac210d8f90215f719feeabc515cb6f06bff865ffff001dd1abae12";

/// Every header from 1602677 (the first with 147 ancestors in the run) to
/// 1602710 carries the bits the DAA answers: 34 headers, 8 of them late
/// enough for the minimum difficulty.
#[test]
fn real_testnet_daa_headers_carry_the_rules_bits() {
    assert_eq!(
        hex::encode(sha256(TESTNET_1602530)),
        "bb0f4db69dd334354cc4a59912e94549dffe1437ad16f373c525f85959f776c1"
    );
    let headers: Vec<BlockHeader> = TESTNET_1602530
        .chunks(HEADER_SIZE)
        .map(|c| BlockHeader::from_binary(c).unwrap())
        .collect();
    assert_eq!(headers.len(), 181);
    let links: Vec<_> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| link(1_602_530 + i as u32, h.time, h.bits))
        .collect();
    for pair in headers.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash(), "hash-linked");
    }
    let test = ChainParams::test();
    let (mut checked, mut late) = (0, 0);
    for l in &links[147..] {
        let parent = &links[(l.height - 1 - 1_602_530) as usize];
        assert_eq!(
            next_work_required(&test, &links[..], l.height - 1, l.time),
            Ok(l.bits),
            "height {}",
            l.height
        );
        checked += 1;
        if l.bits == 0x1d00ffff && l.time > parent.time + 1200 {
            late += 1;
        }
    }
    assert_eq!((checked, late), (34, 8));

    let witness = BlockHeader::from_hex(WITNESS_1602683).unwrap();
    assert_eq!(witness.prev_hash, headers[152].hash());
    assert_eq!(witness.bits, 0x1d00ffff);
    assert!(check_proof_of_work(&witness.hash(), witness.bits, &test.pow_limit).is_ok());
    let expected = next_work_required(&test, &links[..], 1_602_682, witness.time).unwrap();
    assert_ne!(expected, witness.bits, "bad-diffbits");
    assert_eq!(
        next_work_required(&test, &links[..], 1_602_682, links[153].time),
        Ok(0x1d00ffff),
        "the real 1602683 earned the minimum difficulty"
    );
}
