//! Integration tests for sighash computation with 499 test vectors.

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
