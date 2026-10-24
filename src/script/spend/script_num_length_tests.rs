use super::*;
use crate::primitives::to_hex;
use crate::script::flags::ProtocolEra;

const PUBKEY: &str = "035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7";

/// A minimal push of `n` as a script number (always under 76 bytes here).
fn push_num(lock: &mut Vec<u8>, n: u64) {
    let bytes = ScriptNum::to_bytes(&BigNumber::from_u64(n));
    lock.push(bytes.len() as u8);
    lock.extend_from_slice(&bytes);
}

/// `OP_1 <n> OP_NUM2BIN OP_1ADD OP_DROP OP_1`: OP_1ADD reads an n-byte
/// number (the value 1, padded).
fn read_n_bytes(n: u64) -> Vec<u8> {
    let mut lock = vec![OP_1];
    push_num(&mut lock, n);
    lock.extend_from_slice(&[OP_NUM2BIN, OP_1ADD, OP_DROP, OP_1]);
    lock
}

/// `OP_1 <n> OP_NUM2BIN <0x40> OP_CAT OP_DUP OP_MUL OP_DROP OP_1`: two
/// (n + 1)-byte operands whose product is about 2(n + 1) bytes long.
fn square_of_n_plus_one_bytes(n: u64) -> Vec<u8> {
    let mut lock = vec![OP_1];
    push_num(&mut lock, n);
    lock.extend_from_slice(&[
        OP_NUM2BIN, 0x01, 0x40, OP_CAT, OP_DUP, OP_MUL, OP_DROP, OP_1,
    ]);
    lock
}

/// `OP_1 <n> OP_NUM2BIN <0x40> OP_CAT OP_BIN2NUM OP_DROP OP_1`: OP_BIN2NUM's
/// result is (n + 1) bytes long and minimal.
fn bin2num_of_n_plus_one_bytes(n: u64) -> Vec<u8> {
    let mut lock = vec![OP_1];
    push_num(&mut lock, n);
    lock.extend_from_slice(&[OP_NUM2BIN, 0x01, 0x40, OP_CAT, OP_BIN2NUM, OP_DROP, OP_1]);
    lock
}

/// `OP_0 OP_0 <pubkey> <count as `len` bytes> OP_CHECKMULTISIG`: zero
/// signatures of one key, the key count encoded non-minimally.
fn checkmultisig_with_a_count_of(len: u8) -> Vec<u8> {
    let mut lock = vec![OP_0, OP_0, 0x21];
    lock.extend_from_slice(&crate::primitives::from_hex(PUBKEY).unwrap());
    lock.push(len);
    lock.push(0x01);
    lock.extend_from_slice(&vec![0u8; len as usize - 1]);
    lock.push(OP_CHECKMULTISIG);
    lock
}

fn spend(lock: &[u8], version: i32) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(&to_hex(lock)).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&[]).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: Some(200_000_000),
        work_limit: None,
    })
}

fn block() -> ScriptFlags {
    ScriptFlags::block(ProtocolEra::PostChronicle)
}

fn standard() -> ScriptFlags {
    ScriptFlags::standard(ProtocolEra::PostChronicle)
}

/// The verdict as a string: `Ok(true)`, or the refusal's message.
fn run(
    lock: &[u8],
    version: i32,
    word: Option<ScriptFlags>,
    utxo_after_chronicle: Option<bool>,
    policy: Option<usize>,
) -> String {
    let mut s = spend(lock, version);
    if let Some(w) = word {
        s.set_flags(w);
    }
    if let Some(after) = utxo_after_chronicle {
        s.set_utxo_after_chronicle(after);
    }
    if let Some(bytes) = policy {
        s.set_script_num_length_policy(bytes);
    }
    match s.validate() {
        Ok(v) => format!("Ok({v})"),
        Err(e) => e.message,
    }
}

fn overflow(len: usize, max: usize) -> String {
    format!("Script number overflow: {len} bytes, the limit is {max} bytes.")
}

#[test]
fn the_word_and_the_coins_era_decide_the_limit() {
    assert!(!block().is_mempool_word());
    assert!(standard().is_mempool_word());
    assert_eq!(block().max_script_num_length(false, 10_000), 750_000);
    assert_eq!(block().max_script_num_length(true, 10_000), 32_000_000);
    assert_eq!(standard().max_script_num_length(false, 10_000), 10_000);
    assert_eq!(standard().max_script_num_length(true, 10_000), 10_000);
    assert_eq!(standard().max_script_num_length(false, 0), 750_000);
    assert_eq!(standard().max_script_num_length(true, 0), 32_000_000);

    let lock = read_n_bytes(1);
    assert_eq!(spend(&lock, 2).max_script_num_length(), None);
    let mut s = spend(&lock, 2);
    s.set_flags(block());
    assert_eq!(s.max_script_num_length(), Some(32_000_000));
    s.set_utxo_after_chronicle(false);
    assert_eq!(s.max_script_num_length(), Some(750_000));
    s.set_flags(standard());
    assert_eq!(s.max_script_num_length(), Some(10_000));
    s.set_script_num_length_policy(0);
    assert_eq!(s.max_script_num_length(), Some(32_000_000));
}

/// A coin created after Genesis, before Chronicle, on the block path:
/// 750,000 bytes read, 750,001 refused (`consensus.h:64`).
#[test]
fn a_coin_created_after_genesis_reads_750_000_bytes_and_refuses_750_001_under_the_block_word() {
    assert_eq!(
        run(&read_n_bytes(750_000), 2, Some(block()), Some(false), None),
        "Ok(true)"
    );
    assert_eq!(
        run(&read_n_bytes(750_001), 2, Some(block()), Some(false), None),
        overflow(750_001, 750_000)
    );
}

/// A coin created after Chronicle, on the block path: 32,000,000 bytes
/// read, 32,000,001 refused (`consensus.h:66`).
#[test]
fn a_coin_created_after_chronicle_reads_32_000_000_bytes_and_refuses_32_000_001() {
    assert_eq!(
        run(
            &read_n_bytes(32_000_000),
            2,
            Some(block()),
            Some(true),
            None
        ),
        "Ok(true)"
    );
    assert_eq!(
        run(
            &read_n_bytes(32_000_001),
            2,
            Some(block()),
            Some(true),
            None
        ),
        overflow(32_000_001, 32_000_000)
    );
}

/// The mempool path: the policy default of 10,000 bytes whatever the
/// coin's era (`policy.h:156`); a policy of 0 selects the consensus limit.
#[test]
fn the_standard_word_applies_the_policy_default_in_both_eras_and_zero_selects_the_consensus_limit()
{
    for after in [false, true] {
        assert_eq!(
            run(
                &read_n_bytes(10_000),
                2,
                Some(standard()),
                Some(after),
                None
            ),
            "Ok(true)"
        );
        assert_eq!(
            run(
                &read_n_bytes(10_001),
                2,
                Some(standard()),
                Some(after),
                None
            ),
            overflow(10_001, 10_000)
        );
    }
    assert_eq!(
        run(
            &read_n_bytes(750_000),
            2,
            Some(standard()),
            Some(false),
            Some(0)
        ),
        "Ok(true)"
    );
    assert_eq!(
        run(
            &read_n_bytes(750_001),
            2,
            Some(standard()),
            Some(false),
            Some(0)
        ),
        overflow(750_001, 750_000)
    );
    assert_eq!(
        run(
            &read_n_bytes(20_000),
            2,
            Some(standard()),
            Some(false),
            Some(20_000)
        ),
        "Ok(true)"
    );
    assert_eq!(
        run(
            &read_n_bytes(20_001),
            2,
            Some(standard()),
            Some(false),
            Some(20_000)
        ),
        overflow(20_001, 20_000)
    );
}

/// The length test precedes the minimal-encoding test
/// (`script_num.cpp:62` before `:67`): at version 1 under the standard
/// word a padded number of 10,000 bytes is a minimal-encoding refusal,
/// one of 10,001 bytes an overflow.
#[test]
fn the_length_test_precedes_the_minimal_encoding_test() {
    assert_eq!(
        run(
            &read_n_bytes(10_000),
            1,
            Some(standard()),
            Some(false),
            None
        ),
        "Invalid script number: script execution error: Non-minimally encoded script number"
    );
    assert_eq!(
        run(
            &read_n_bytes(10_001),
            1,
            Some(standard()),
            Some(false),
            None
        ),
        overflow(10_001, 10_000)
    );
}

/// A product longer than the limit is refused before it is pushed
/// (`script_num.cpp:214`); one within it is pushed.
#[test]
fn a_product_longer_than_the_limit_is_refused_before_it_is_pushed() {
    assert_eq!(
        run(
            &square_of_n_plus_one_bytes(369_999),
            2,
            Some(block()),
            Some(false),
            None
        ),
        "Ok(true)"
    );
    let refused = run(
        &square_of_n_plus_one_bytes(379_999),
        2,
        Some(block()),
        Some(false),
        None,
    );
    assert!(
        refused.starts_with("Script number overflow: 7")
            && refused.ends_with("the limit is 750000 bytes."),
        "{refused}"
    );
}

/// `OP_BIN2NUM`'s result beyond the limit is refused as the reference
/// refuses it (`interpreter.cpp:1789-1790`).
#[test]
fn bin2num_refuses_a_result_longer_than_the_limit() {
    assert_eq!(
        run(
            &bin2num_of_n_plus_one_bytes(9_999),
            2,
            Some(standard()),
            Some(false),
            None
        ),
        "Ok(true)"
    );
    assert_eq!(
        run(
            &bin2num_of_n_plus_one_bytes(10_000),
            2,
            Some(standard()),
            Some(false),
            None
        ),
        "OP_BIN2NUM requires that the resulting number is valid."
    );
}

/// `OP_CHECKMULTISIG`'s counts are 4-byte numbers under a word
/// (`interpreter.cpp:1519-1525`); the default mode reads them as the
/// TypeScript SDK does.
#[test]
fn a_five_byte_checkmultisig_count_is_an_overflow_under_a_word() {
    assert_eq!(
        run(
            &checkmultisig_with_a_count_of(4),
            2,
            Some(block()),
            Some(false),
            None
        ),
        "Ok(true)"
    );
    assert_eq!(
        run(
            &checkmultisig_with_a_count_of(5),
            2,
            Some(block()),
            Some(false),
            None
        ),
        overflow(5, 4)
    );
    assert_eq!(
        run(&checkmultisig_with_a_count_of(5), 2, None, None, None),
        "Ok(true)"
    );
}

/// The default mode is the TypeScript SDK's: a number of any length.
#[test]
fn the_default_mode_reads_a_number_of_any_length() {
    assert_eq!(
        run(&read_n_bytes(1_048_577), 2, None, None, None),
        "Ok(true)"
    );
}

/// Under a word the numeric left shift's result is sized before it is
/// computed: the magnitude's bits plus the count, one byte for each 8 bits
/// and one for the sign's room, which is the serialized length of the
/// shifted number, whatever its sign (Calhooon/bsv-rs#30).
#[test]
fn a_left_shifts_exact_length_is_its_serialized_length() {
    for x in [
        1i64,
        2,
        127,
        128,
        255,
        256,
        32_767,
        32_768,
        -1,
        -127,
        -128,
        -255,
        i64::MAX,
        i64::MIN + 1,
    ] {
        let x = BigNumber::from_i64(x);
        for n in 0..40u64 {
            let bits = x.bit_length() as u64 + n;
            assert_eq!(
                (bits / 8 + 1) as usize,
                ScriptNum::to_bytes(&x.shl_bits(n)).len(),
                "{} << {n}",
                x.to_dec_string()
            );
        }
    }
}
