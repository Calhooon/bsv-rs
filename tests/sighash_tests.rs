//! Integration tests for sighash computation with 499 test vectors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash, compute_sighash_for_signing, parse_transaction, SighashCache, SighashParams,
};
use serde::Deserialize;

/// Test vector for sighash computation.
#[derive(Deserialize, Debug)]
struct SighashVector {
    raw_tx: String,
    script: String,
    input_index: usize,
    hash_type: i32,
    expected_hash: String,
}

fn load_sighash_vectors() -> Vec<SighashVector> {
    let data = include_str!("vectors/sighash.json");
    serde_json::from_str(data).expect("Failed to parse sighash vectors")
}

#[test]
fn test_sighash_vectors() {
    let vectors = load_sighash_vectors();
    let total = vectors.len();

    println!("Running {} sighash test vectors...", total);

    let mut passed = 0;
    let mut failed = 0;
    let mut first_failures: Vec<String> = Vec::new();

    for (i, v) in vectors.iter().enumerate() {
        // Parse the raw transaction
        let raw_tx = match hex::decode(&v.raw_tx) {
            Ok(bytes) => bytes,
            Err(e) => {
                failed += 1;
                if first_failures.len() < 5 {
                    first_failures.push(format!("Vector {}: Failed to decode raw_tx: {}", i, e));
                }
                continue;
            }
        };

        let tx = match parse_transaction(&raw_tx) {
            Ok(tx) => tx,
            Err(e) => {
                failed += 1;
                if first_failures.len() < 5 {
                    first_failures.push(format!("Vector {}: Failed to parse tx: {}", i, e));
                }
                continue;
            }
        };

        // Parse the subscript
        let subscript = match hex::decode(&v.script) {
            Ok(bytes) => bytes,
            Err(e) => {
                failed += 1;
                if first_failures.len() < 5 {
                    first_failures.push(format!("Vector {}: Failed to decode script: {}", i, e));
                }
                continue;
            }
        };

        // Validate input index
        if v.input_index >= tx.inputs.len() {
            failed += 1;
            if first_failures.len() < 5 {
                first_failures.push(format!(
                    "Vector {}: Input index {} out of range (tx has {} inputs)",
                    i,
                    v.input_index,
                    tx.inputs.len()
                ));
            }
            continue;
        }

        // Convert hash_type from signed to unsigned
        // The hash_type can be negative when the high bit is set
        let scope = v.hash_type as u32;

        // Compute sighash
        // Note: Test vectors use satoshis = 0 (pre-BIP-143 style or unknown value)
        let sighash = compute_sighash(&SighashParams {
            version: tx.version,
            inputs: &tx.inputs,
            outputs: &tx.outputs,
            locktime: tx.locktime,
            input_index: v.input_index,
            subscript: &subscript,
            satoshis: 0, // Test vectors use 0
            scope,
        });

        let computed_hex = hex::encode(sighash);
        let expected_hex = v.expected_hash.to_lowercase();

        if computed_hex == expected_hex {
            passed += 1;
        } else {
            failed += 1;
            if first_failures.len() < 5 {
                first_failures.push(format!(
                    "Vector {}: hash_type=0x{:08x}, computed={}, expected={}",
                    i, scope, computed_hex, expected_hex
                ));
            }
        }
    }

    println!(
        "Results: {} passed, {} failed out of {}",
        passed, failed, total
    );

    if !first_failures.is_empty() {
        println!("\nFirst {} failures:", first_failures.len());
        for failure in &first_failures {
            println!("  {}", failure);
        }
    }

    assert_eq!(
        failed, 0,
        "Sighash test failures: {} out of {} vectors failed",
        failed, total
    );
}

#[test]
fn test_sighash_first_vector_detailed() {
    // Test the first vector in detail for debugging
    let vectors = load_sighash_vectors();
    let v = &vectors[0];

    println!("Testing first vector:");
    println!("  raw_tx: {}...", &v.raw_tx[..60.min(v.raw_tx.len())]);
    println!("  script: {}", v.script);
    println!("  input_index: {}", v.input_index);
    println!(
        "  hash_type: {} (0x{:08x})",
        v.hash_type, v.hash_type as u32
    );
    println!("  expected_hash: {}", v.expected_hash);

    let raw_tx = hex::decode(&v.raw_tx).expect("Failed to decode raw_tx");
    let tx = parse_transaction(&raw_tx).expect("Failed to parse tx");

    println!("\nParsed transaction:");
    println!("  version: {}", tx.version);
    println!("  inputs: {}", tx.inputs.len());
    println!("  outputs: {}", tx.outputs.len());
    println!("  locktime: {}", tx.locktime);

    for (i, input) in tx.inputs.iter().enumerate() {
        let mut txid_display = input.txid;
        txid_display.reverse();
        println!(
            "  Input {}: txid={}..., vout={}, seq=0x{:08x}",
            i,
            hex::encode(&txid_display[..8]),
            input.output_index,
            input.sequence
        );
    }

    let subscript = hex::decode(&v.script).expect("Failed to decode script");
    let scope = v.hash_type as u32;

    let sighash = compute_sighash(&SighashParams {
        version: tx.version,
        inputs: &tx.inputs,
        outputs: &tx.outputs,
        locktime: tx.locktime,
        input_index: v.input_index,
        subscript: &subscript,
        satoshis: 0,
        scope,
    });

    let computed_hex = hex::encode(sighash);
    println!("\nComputed sighash: {}", computed_hex);
    println!("Expected sighash: {}", v.expected_hash);

    assert_eq!(
        computed_hex,
        v.expected_hash.to_lowercase(),
        "First vector sighash mismatch"
    );
}

#[test]
fn test_parse_all_vectors_transactions() {
    // First, verify we can parse all 499 transactions
    let vectors = load_sighash_vectors();
    let total = vectors.len();

    println!("Parsing {} transactions...", total);

    let mut parse_failures = 0;
    for (i, v) in vectors.iter().enumerate() {
        let raw_tx = match hex::decode(&v.raw_tx) {
            Ok(bytes) => bytes,
            Err(e) => {
                parse_failures += 1;
                println!("Vector {}: hex decode failed: {}", i, e);
                continue;
            }
        };

        if let Err(e) = parse_transaction(&raw_tx) {
            parse_failures += 1;
            println!("Vector {}: parse failed: {}", i, e);
        }
    }

    assert_eq!(
        parse_failures, 0,
        "Failed to parse {} out of {} transactions",
        parse_failures, total
    );
    println!("All {} transactions parsed successfully!", total);
}

/// The midstate-reuse `SighashCache` must be byte-identical to the free
/// functions on every cross-SDK vector — and not only at the vector's own
/// input index: one shared cache is run across EVERY input of each vector's
/// transaction (with the vector's scope and subscript), so cached midstates
/// are actually reused and compared against fresh per-call computation. The
/// vector's own input is additionally checked against `expected_hash`.
#[test]
fn test_sighash_cache_matches_vectors_and_free_functions() {
    let vectors = load_sighash_vectors();
    let mut checked_inputs = 0usize;

    for (i, v) in vectors.iter().enumerate() {
        let raw_tx = hex::decode(&v.raw_tx).expect("raw_tx hex");
        let tx = match parse_transaction(&raw_tx) {
            Ok(tx) => tx,
            Err(_) => continue,
        };
        let subscript = hex::decode(&v.script).expect("script hex");
        let scope = v.hash_type as u32;
        if v.input_index >= tx.inputs.len() {
            continue;
        }

        let mut cache = SighashCache::new(&tx);
        for input_index in 0..tx.inputs.len() {
            let params = SighashParams {
                version: tx.version,
                inputs: &tx.inputs,
                outputs: &tx.outputs,
                locktime: tx.locktime,
                input_index,
                subscript: &subscript,
                satoshis: 0, // test vectors use 0
                scope,
            };
            let cached_display = cache
                .sighash(input_index, &subscript, 0, scope)
                .expect("in-range index");
            assert_eq!(
                cached_display,
                compute_sighash(&params),
                "vector {} input {}: cache vs compute_sighash",
                i,
                input_index
            );
            assert_eq!(
                cache
                    .sighash_for_signing(input_index, &subscript, 0, scope)
                    .expect("in-range index"),
                compute_sighash_for_signing(&params),
                "vector {} input {}: cache vs compute_sighash_for_signing",
                i,
                input_index
            );
            if input_index == v.input_index {
                assert_eq!(
                    hex::encode(cached_display),
                    v.expected_hash.to_lowercase(),
                    "vector {}: cache vs expected_hash",
                    i
                );
            }
            checked_inputs += 1;
        }
    }

    println!(
        "SighashCache checked {} inputs across {} vectors",
        checked_inputs,
        vectors.len()
    );
    assert!(checked_inputs >= vectors.len(), "coverage sanity");
}

/// The default signing path (`SigningContext::compute_sighash`, which every
/// template's `unlock` and `Transaction::sign` reach) against the node's
/// digest dispatch. bitcoin-sv v1.2.3 `src/script/interpreter.cpp:2112-2124`
/// (`SignatureHash`): BIP143 only when the hash type carries FORKID and not
/// CHRONICLE (0x20, `sighashtype.h`), the original digest otherwise;
/// `:2086-2100` (`SignatureHashOriginal`): the constant `one` when SINGLE
/// names an output the transaction does not have. Until 0.7.0 the context
/// computed BIP143 for every hash type.
mod the_default_signing_digest {
    use bsv_rs::primitives::bsv::sighash::{
        compute_sighash_dispatched_for_signing, compute_sighash_for_signing, parse_transaction,
        SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_CHRONICLE,
        SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
    };
    use bsv_rs::primitives::bsv::TransactionSignature;
    use bsv_rs::primitives::ec::PrivateKey;
    use bsv_rs::script::{
        LockingScript, ProtocolEra, Script, ScriptFlags, SigningContext, Spend, SpendParams,
        UnlockingScript,
    };

    /// `uint256S("0…01")` in the internal order a verifier consumes
    /// (`interpreter.cpp:2089`).
    pub const ONE: [u8; 32] = {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    };

    /// A transaction of `n_in` inputs and `n_out` outputs, every field
    /// distinct, every input carrying a script (the original digest empties
    /// the unsigned ones, `interpreter.cpp:1905-1915`, BIP143 never reads them).
    pub fn raw_tx(version: i32, n_in: usize, n_out: usize, seed: u8) -> Vec<u8> {
        let mut t = version.to_le_bytes().to_vec();
        t.push(n_in as u8);
        for i in 0..n_in {
            t.extend((0..32u8).map(|b| seed.wrapping_mul(31) ^ b.wrapping_add(7 * i as u8)));
            t.extend((i as u32 + u32::from(seed)).to_le_bytes());
            t.extend([2, 0x01, 0x10 + i as u8]);
            t.extend((0xffff_fff0u32 - i as u32).to_le_bytes());
        }
        t.push(n_out as u8);
        for o in 0..n_out {
            t.extend((1_000 + 17 * o as u64 + u64::from(seed)).to_le_bytes());
            t.extend([3, 0x00, 0x6a, 0x51 + o as u8]);
        }
        t.extend(u32::from(seed).to_le_bytes());
        t
    }

    pub fn params<'a>(
        tx: &'a bsv_rs::primitives::bsv::sighash::RawTransaction,
        input_index: usize,
        subscript: &'a [u8],
        satoshis: u64,
        scope: u32,
    ) -> SighashParams<'a> {
        SighashParams {
            version: tx.version,
            inputs: &tx.inputs,
            outputs: &tx.outputs,
            locktime: tx.locktime,
            input_index,
            subscript,
            satoshis,
            scope,
        }
    }

    /// Every hash type the property ranges over: {ALL, NONE, SINGLE} x
    /// {with, without ANYONECANPAY} x {FORKID, FORKID|CHRONICLE, no FORKID}.
    fn scopes() -> Vec<u32> {
        let mut out = Vec::new();
        for base in [SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE] {
            for acp in [0, SIGHASH_ANYONECANPAY] {
                for fork in [SIGHASH_FORKID, SIGHASH_FORKID | SIGHASH_CHRONICLE, 0] {
                    out.push(base | acp | fork);
                }
            }
        }
        out
    }

    /// The locks signed over: a P2PKH, and one with an `OP_CODESEPARATOR`
    /// (the original digest drops it from the scriptCode,
    /// `interpreter.cpp:1864-1892`; BIP143 keeps it).
    fn locks() -> Vec<Script> {
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend([0x5a; 20]);
        p2pkh.extend([0x88, 0xac]);
        let mut separated = vec![0x51, 0xab];
        separated.extend(&p2pkh);
        vec![
            Script::from_binary(&p2pkh).unwrap(),
            Script::from_binary(&separated).unwrap(),
        ]
    }

    #[test]
    fn the_default_signing_digest_is_the_dispatchers_for_every_hash_type() {
        let mut checked = 0usize;
        let mut single_beyond_outputs = 0usize;
        let mut wrong = Vec::new();
        for seed in 0..6u8 {
            for version in [1, 2] {
                // (3, 2) and (4, 1) put a SINGLE input beyond the outputs
                for (n_in, n_out) in [(3, 2), (1, 1), (4, 1), (2, 3)] {
                    let raw = raw_tx(version, n_in, n_out, seed);
                    let tx = parse_transaction(&raw).unwrap();
                    for lock in locks() {
                        let code = lock.to_binary();
                        for input_index in 0..n_in {
                            for scope in scopes() {
                                let satoshis = 5_000 + u64::from(seed);
                                let got = SigningContext::new(&raw, input_index, satoshis, &lock)
                                    .compute_sighash(scope)
                                    .unwrap();
                                let want = compute_sighash_dispatched_for_signing(&params(
                                    &tx,
                                    input_index,
                                    &code,
                                    satoshis,
                                    scope,
                                ));
                                if got != want {
                                    wrong.push((seed, version, n_in, n_out, input_index, scope));
                                }
                                if scope & 0x1f == SIGHASH_SINGLE && input_index >= n_out {
                                    single_beyond_outputs += 1;
                                }
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(single_beyond_outputs > 0, "the sentinel case is covered");
        assert!(
            wrong.is_empty(),
            "{} of {} default digests differ from the dispatcher's; the first (seed, version, \
             inputs, outputs, input, scope): {:?}",
            wrong.len(),
            checked,
            wrong.first()
        );
    }

    /// The templates sign FORKID types without CHRONICLE: their digest is the
    /// BIP143 one, unchanged by the dispatch.
    #[test]
    fn the_forkid_digest_of_the_templates_is_unchanged() {
        let raw = raw_tx(1, 3, 2, 9);
        let tx = parse_transaction(&raw).unwrap();
        for lock in locks() {
            let code = lock.to_binary();
            for input_index in 0..3 {
                for scope in scopes().into_iter().filter(|s| s & 0x60 == SIGHASH_FORKID) {
                    assert_eq!(
                        SigningContext::new(&raw, input_index, 77, &lock)
                            .compute_sighash(scope)
                            .unwrap(),
                        compute_sighash_for_signing(&params(&tx, input_index, &code, 77, scope)),
                        "input {input_index} scope {scope:#04x}"
                    );
                }
            }
        }
    }

    /// `SignatureHashOriginal`, `interpreter.cpp:2095-2100`: SINGLE with the
    /// input index at or beyond the outputs signs the constant `one`
    /// (`:2089`), reached for a type without FORKID or with CHRONICLE
    /// (`:2118-2123`). Under BIP143 (FORKID alone) the same input hashes a
    /// preimage with a zero hashOutputs and is never `one`.
    #[test]
    fn a_single_beyond_the_outputs_under_the_original_digest_signs_the_constant_one() {
        let raw = raw_tx(2, 3, 2, 4);
        let lock = &locks()[0];
        for input_index in [2usize] {
            for scope in [0x03, 0x83, 0x63, 0xe3] {
                assert_eq!(
                    SigningContext::new(&raw, input_index, 1, lock)
                        .compute_sighash(scope)
                        .unwrap(),
                    ONE,
                    "input {input_index} scope {scope:#04x}"
                );
            }
            for scope in [0x43, 0xc3] {
                assert_ne!(
                    SigningContext::new(&raw, input_index, 1, lock)
                        .compute_sighash(scope)
                        .unwrap(),
                    ONE,
                    "scope {scope:#04x} is BIP143"
                );
            }
        }
        // in range, the original digest is a hash, not the sentinel
        assert_ne!(
            SigningContext::new(&raw, 1, 1, lock)
                .compute_sighash(0x03)
                .unwrap(),
            ONE
        );
    }

    /// An input the transaction does not have is an error; until 0.7.0 the
    /// context panicked in the preimage builder.
    #[test]
    fn a_signing_context_naming_an_absent_input_is_an_error_not_a_panic() {
        let raw = raw_tx(1, 1, 1, 0);
        let lock = &locks()[0];
        for scope in [0x41, 0x61, 0x01, 0x03] {
            let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                SigningContext::new(&raw, 1, 1, lock).compute_sighash(scope)
            }));
            assert!(
                matches!(got, Ok(Err(_))),
                "scope {scope:#04x}: an Err, not a panic or a digest"
            );
        }
    }

    pub fn key(byte: u8) -> PrivateKey {
        let mut scalar = [0u8; 32];
        scalar[31] = byte;
        scalar[0] = 0x2b;
        PrivateKey::from_bytes(&scalar).unwrap()
    }

    pub fn checksig_push(key: &PrivateKey, digest: &[u8; 32], scope: u32) -> Vec<u8> {
        TransactionSignature::new(key.sign(digest).unwrap(), scope).to_checksig_format()
    }

    /// Input 0 of `raw` spending `lock` with `unlock`, run as a node of the
    /// Chronicle era runs it on a block, the coin created after Chronicle.
    pub fn node_verdict(
        raw: &[u8],
        satoshis: u64,
        lock: &Script,
        unlock: &Script,
    ) -> Result<bool, String> {
        let tx = parse_transaction(raw).unwrap();
        let input = &tx.inputs[0];
        let mut spend = Spend::new(SpendParams {
            source_txid: input.txid,
            source_output_index: input.output_index,
            source_satoshis: satoshis,
            locking_script: LockingScript::from_binary(&lock.to_binary()).unwrap(),
            transaction_version: tx.version,
            other_inputs: Vec::<TxInput>::new(),
            outputs: tx
                .outputs
                .iter()
                .map(|o| TxOutput {
                    satoshis: o.satoshis,
                    script: o.script.clone(),
                })
                .collect(),
            input_index: 0,
            unlocking_script: UnlockingScript::from_binary(&unlock.to_binary()).unwrap(),
            input_sequence: input.sequence,
            lock_time: tx.locktime,
            memory_limit: None,
            work_limit: None,
        });
        spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        spend.set_utxo_after_chronicle(true);
        spend.validate().map_err(|e| e.message)
    }

    /// A P2PK spend signed through the context with ALL|FORKID|CHRONICLE
    /// (0x61): the node verifies it against the original digest
    /// (`interpreter.cpp:2118-2123`), so the context must sign that one.
    #[test]
    fn a_chronicle_hash_type_signed_through_the_context_verifies_under_the_node_word() {
        let raw = raw_tx(2, 1, 1, 3);
        let k = key(1);
        let mut lock = Script::new();
        lock.write_bin(&k.public_key().to_compressed())
            .write_opcode(0xac);
        for scope in [0x41u32, 0x61, 0xc1, 0xe1, 0x42, 0x62, 0x43, 0x63] {
            let digest = SigningContext::new(&raw, 0, 900, &lock)
                .compute_sighash(scope)
                .unwrap();
            let mut unlock = Script::new();
            unlock.write_bin(&checksig_push(&k, &digest, scope));
            assert_eq!(
                node_verdict(&raw, 900, &lock, &unlock),
                Ok(true),
                "scope {scope:#04x}"
            );
        }
    }
}

/// The scriptCode of a CHECKSIG executing inside a post-Chronicle unlocking
/// script: bitcoin-sv v1.2.3 `src/script/interpreter.cpp:1471-1481` signs the
/// script from the last executed `OP_CODESEPARATOR` (`:1447`) to the end of
/// the unlocking script, followed by `checksigData`, the scriptPubKey
/// `VerifyScript` passes (`:2336-2342`). The shape: a lock
/// `<utxoPub> OP_CHECKSIG` and an unlock
/// `<utxoSig> <sig> OP_CODESEPARATOR <pub> OP_CHECKSIGVERIFY`.
mod the_chronicle_script_code {
    use super::the_default_signing_digest::{checksig_push, key, node_verdict, raw_tx};
    use bsv_rs::primitives::from_hex;
    use bsv_rs::script::{chronicle_unlocking_script_code, Script, SigningContext};

    /// The generator and twice it, compressed: any 33 bytes serve, the helper
    /// reads no key.
    const PUB: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const UTXO_PUB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn script(hex: &str) -> Script {
        Script::from_binary(&from_hex(hex).unwrap()).unwrap()
    }

    #[test]
    fn the_chronicle_script_code_is_the_unlock_after_its_last_separator_then_the_lock() {
        let lock = script(&format!("21{UTXO_PUB}ac"));
        // two 71-byte placeholder signatures, the separator, `<pub> OP_CHECKSIGVERIFY`
        let placeholder = format!("47{}", "00".repeat(71));
        let unlock = script(&format!("{placeholder}{placeholder}ab21{PUB}ad"));
        assert_eq!(
            chronicle_unlocking_script_code(&unlock, &lock).to_hex(),
            format!("21{PUB}ad21{UTXO_PUB}ac")
        );
    }

    /// A separator is an opcode the node's parser reads (`script.h:164-195`):
    /// a `0xab` inside push data is data, and none past a truncated push is
    /// reached; with no separator the whole unlocking script is signed.
    #[test]
    fn the_chronicle_script_code_reads_separators_as_the_parser_reads_them() {
        let lock = script("51");
        for (unlock, code) in [
            ("03ababab" /* push of three 0xab */, "03ababab51"),
            ("03abababab52", "5251"),
            ("ab52ab53", "5351"),
            ("", "51"),
            // PUSHDATA1 of 5 with one byte left: the walk stops at it
            ("ab524c05ab", "524c05ab51"),
        ] {
            assert_eq!(
                chronicle_unlocking_script_code(&script(unlock), &lock).to_hex(),
                code,
                "unlock {unlock}"
            );
        }
    }

    /// The whole shape signed through the context and run under the node's
    /// Chronicle block word: valid with the helper's scriptCode for
    /// ALL|FORKID and ALL|FORKID|CHRONICLE, refused with the default (the
    /// locking script alone), which is what the context signed before the
    /// override existed.
    #[test]
    fn a_check_in_the_unlocking_script_signed_over_the_helpers_script_code_verifies() {
        let raw = raw_tx(2, 1, 1, 8);
        let (utxo_key, check_key) = (key(2), key(3));
        let mut lock = Script::new();
        lock.write_bin(&utxo_key.public_key().to_compressed())
            .write_opcode(0xac);
        let mut check = Script::new();
        check
            .write_bin(&check_key.public_key().to_compressed())
            .write_opcode(0xad);
        let unlock_with = |utxo_sig: &[u8], sig: &[u8]| {
            let mut s = Script::new();
            s.write_bin(utxo_sig).write_bin(sig).write_opcode(0xab);
            let mut bytes = s.to_binary();
            bytes.extend(check.to_binary());
            Script::from_binary(&bytes).unwrap()
        };
        let code = chronicle_unlocking_script_code(&unlock_with(&[0; 71], &[0; 71]), &lock);
        for scope in [0x41u32, 0x61] {
            let utxo_digest = SigningContext::new(&raw, 0, 700, &lock)
                .compute_sighash(0x41)
                .unwrap();
            let utxo_sig = checksig_push(&utxo_key, &utxo_digest, 0x41);
            let signed = SigningContext::new(&raw, 0, 700, &lock)
                .with_script_code(&code)
                .compute_sighash(scope)
                .unwrap();
            let unlock = unlock_with(&utxo_sig, &checksig_push(&check_key, &signed, scope));
            assert_eq!(
                node_verdict(&raw, 700, &lock, &unlock),
                Ok(true),
                "scope {scope:#04x}, the helper's scriptCode"
            );
            let default = SigningContext::new(&raw, 0, 700, &lock)
                .compute_sighash(scope)
                .unwrap();
            let unlock = unlock_with(&utxo_sig, &checksig_push(&check_key, &default, scope));
            assert_ne!(
                node_verdict(&raw, 700, &lock, &unlock),
                Ok(true),
                "scope {scope:#04x}, the locking script alone"
            );
        }
    }
}
