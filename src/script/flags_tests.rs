//! `flags.rs`'s unit tests, moved beside it for the file's line ceiling (#843d9); the module is still `tests`.
#![cfg(test)]

use super::*;

/// The words a post-Chronicle mainnet node derives today, as `uint32_t`:
/// the block word `0x3D462F` and the standard word `0x3D47FF`. Bits:
/// P2SH 0, STRICTENC 1, DERSIG 2, LOW_S 3, SIGPUSHONLY 5, CLTV 9, CSV 10,
/// NULLFAIL 14, SIGHASH_FORKID 16, GENESIS 18, UTXO_AFTER_GENESIS 19,
/// CHRONICLE 20, UTXO_AFTER_CHRONICLE 21; the standard word adds
/// NULLDUMMY 4, MINIMALDATA 6, DISCOURAGE_UPGRADABLE_NOPS 7, CLEANSTACK 8.
#[test]
fn the_post_chronicle_block_and_standard_words_have_the_reference_values() {
    assert_eq!(
        ScriptFlags::block(ProtocolEra::PostChronicle).bits(),
        0x3D462F
    );
    assert_eq!(
        ScriptFlags::standard(ProtocolEra::PostChronicle).bits(),
        0x3D47FF
    );
}

#[test]
fn the_post_genesis_words_drop_the_two_chronicle_bits_and_nothing_else() {
    let block = ScriptFlags::block(ProtocolEra::PostGenesis);
    let chronicle = ScriptFlags::block(ProtocolEra::PostChronicle);
    assert_eq!(
        chronicle.without(block),
        ScriptFlags::CHRONICLE | ScriptFlags::UTXO_AFTER_CHRONICLE
    );
    assert_eq!(block.without(chronicle), ScriptFlags::NONE);
    let standard = ScriptFlags::standard(ProtocolEra::PostGenesis);
    assert_eq!(
        ScriptFlags::standard(ProtocolEra::PostChronicle).without(standard),
        ScriptFlags::CHRONICLE | ScriptFlags::UTXO_AFTER_CHRONICLE
    );
}

/// `policy.h:178-190`: the block word never carries a standard-only flag
/// (the reference's comment: blocks violating them must be accepted).
#[test]
fn the_block_word_never_carries_a_standard_only_flag() {
    for era in [ProtocolEra::PostGenesis, ProtocolEra::PostChronicle] {
        let block = ScriptFlags::block(era);
        for bit in [
            ScriptFlags::NULLDUMMY,
            ScriptFlags::MINIMALDATA,
            ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS,
            ScriptFlags::CLEANSTACK,
        ] {
            assert!(
                !block.contains(bit),
                "{era:?}: {bit:?} is in the block word"
            );
        }
        assert_eq!(
            ScriptFlags::standard(era).without(block),
            ScriptFlags::NULLDUMMY
                | ScriptFlags::MINIMALDATA
                | ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS
                | ScriptFlags::CLEANSTACK
        );
    }
}

/// `interpreter.cpp:46-49`, the four `static_assert`s.
#[test]
fn the_version_gate_matches_the_references_static_asserts() {
    let none = ScriptFlags::NONE;
    let chronicle = ScriptFlags::CHRONICLE;
    assert!(none.enforce_non_malleability(1));
    assert!(none.enforce_non_malleability(2));
    assert!(chronicle.enforce_non_malleability(1));
    assert!(!chronicle.enforce_non_malleability(2));
    // A negative version is not malleable either (`version > 1`).
    assert!(chronicle.enforce_non_malleability(-1));
    assert!(chronicle.enforce_non_malleability(0));
}

/// `interpreter.cpp:2321-2334`.
#[test]
fn push_only_is_required_pre_chronicle_at_every_version_and_post_chronicle_at_version_1() {
    let genesis = ScriptFlags::block(ProtocolEra::PostGenesis);
    assert!(genesis.requires_push_only(1));
    assert!(genesis.requires_push_only(2));
    let chronicle = ScriptFlags::block(ProtocolEra::PostChronicle);
    assert!(chronicle.requires_push_only(1));
    assert!(!chronicle.requires_push_only(2));
    assert!(!chronicle
        .without(ScriptFlags::SIGPUSHONLY)
        .requires_push_only(1));
}

#[test]
fn the_gates_of_the_block_word_follow_the_version_at_chronicle() {
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let v1 = word.gates(1);
    assert!(v1.low_s && v1.null_fail && v1.push_only);
    assert!(!v1.minimal && !v1.clean_stack && !v1.null_dummy && !v1.minimal_if);
    assert!(!v1.discourage_upgradable_nops && !v1.compressed_pubkey);
    let v2 = word.gates(2);
    assert_eq!(
        v2,
        Gates {
            push_only: false,
            minimal: false,
            low_s: false,
            clean_stack: false,
            null_dummy: false,
            null_fail: false,
            minimal_if: false,
            discourage_upgradable_nops: false,
            compressed_pubkey: false,
            utxo_after_chronicle: true,
        }
    );
    assert!(
        !ScriptFlags::block(ProtocolEra::PostGenesis)
            .gates(2)
            .utxo_after_chronicle
    );
    let standard_v1 = ScriptFlags::standard(ProtocolEra::PostChronicle).gates(1);
    assert!(standard_v1.minimal && standard_v1.clean_stack && standard_v1.null_dummy);
    assert!(standard_v1.discourage_upgradable_nops);
    let standard_v2 = ScriptFlags::standard(ProtocolEra::PostChronicle).gates(2);
    assert!(
        standard_v2.discourage_upgradable_nops,
        "not a malleability rule: no version gate"
    );
    assert!(!standard_v2.minimal && !standard_v2.clean_stack && !standard_v2.null_dummy);
}

#[test]
fn the_gates_of_the_standard_word_before_chronicle_ignore_the_version() {
    let word = ScriptFlags::standard(ProtocolEra::PostGenesis);
    assert_eq!(word.gates(1), word.gates(2));
    assert!(word.gates(2).minimal && word.gates(2).null_fail && word.gates(2).push_only);
}

#[test]
fn names_round_trip_through_the_references_table() {
    let word = ScriptFlags::standard(ProtocolEra::PostChronicle);
    let names = word.names();
    assert_eq!(
        ScriptFlags::from_names(names.iter().copied()).unwrap(),
        word
    );
    assert_eq!(
        ScriptFlags::from_names(" NULLFAIL , SIGHASH_FORKID,NONE".split(',')).unwrap(),
        ScriptFlags::NULLFAIL | ScriptFlags::SIGHASH_FORKID
    );
    assert_eq!(
        ScriptFlags::from_names(["NULLFAIL", "BIP16"]).unwrap_err(),
        ScriptFlagsError::UnknownName("BIP16".into())
    );
    assert_eq!(word.to_string(), names.join(","));
    assert_eq!(ScriptFlags::NONE.to_string(), "NONE");
}

#[test]
fn from_bits_refuses_a_bit_the_crate_does_not_know() {
    assert_eq!(
        ScriptFlags::from_bits(0x3D462F).unwrap(),
        ScriptFlags::block(ProtocolEra::PostChronicle)
    );
    assert_eq!(
        ScriptFlags::from_bits(1 << 11).unwrap_err(),
        ScriptFlagsError::UnknownBits(1 << 11)
    );
    assert_eq!(
        ScriptFlags::from_bits(0x3D462F | (1 << 22)).unwrap_err(),
        ScriptFlagsError::UnknownBits(1 << 22)
    );
}

#[test]
fn check_refuses_what_the_interpreter_cannot_honor_and_what_the_reference_refuses() {
    assert!(ScriptFlags::block(ProtocolEra::PostGenesis).check().is_ok());
    assert!(ScriptFlags::standard(ProtocolEra::PostChronicle)
        .check()
        .is_ok());
    let block = ScriptFlags::block(ProtocolEra::PostChronicle);
    assert!(block.without(ScriptFlags::SIGHASH_FORKID).check().is_err());
    assert!(block.without(ScriptFlags::GENESIS).check().is_err());
    assert!(block
        .without(ScriptFlags::UTXO_AFTER_GENESIS)
        .check()
        .is_err());
    assert!((ScriptFlags::SIGHASH_FORKID
        | ScriptFlags::GENESIS
        | ScriptFlags::UTXO_AFTER_CHRONICLE)
        .check()
        .is_err());
    assert!((block | ScriptFlags::CLEANSTACK)
        .without(ScriptFlags::P2SH)
        .check()
        .is_err());
    assert!((block | ScriptFlags::CLEANSTACK).check().is_ok());
}

#[test]
fn the_mainnet_eras_switch_at_the_activation_heights() {
    assert_eq!(ProtocolEra::mainnet(620_537), None);
    assert_eq!(
        ProtocolEra::mainnet(620_538),
        Some(ProtocolEra::PostGenesis)
    );
    assert_eq!(
        ProtocolEra::mainnet(943_815),
        Some(ProtocolEra::PostGenesis)
    );
    assert_eq!(
        ProtocolEra::mainnet(943_816),
        Some(ProtocolEra::PostChronicle)
    );
    assert_eq!(
        ProtocolEra::at_height(20_000, 10_000, 15_000),
        Some(ProtocolEra::PostChronicle)
    );
    assert_eq!(
        ProtocolEra::at_height(12_000, 10_000, 15_000),
        Some(ProtocolEra::PostGenesis)
    );
}
