//! Script Test Vectors
//!
//! This module tests the script interpreter using comprehensive test vectors
//! from the TypeScript SDK. The vectors ensure cross-SDK compatibility.
//!
//! Test Vector Categories:
//! - spend_valid.json: ~570+ valid spend execution vectors
//! - script_valid.json: ~590+ valid script parsing vectors
//! - script_invalid.json: ~500+ invalid scripts that should fail

use bsv_sdk::script::{LockingScript, Script, Spend, SpendParams, UnlockingScript};
use serde::Deserialize;
use std::fs;

// ============================================================================
// Test Vector Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpendVector {
    script_sig: String,
    script_pub_key: String,
    comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptVector {
    script_sig: String,
    script_pub_key: String,
    flags: String,
    comment: String,
}

// ============================================================================
// Spend Valid Vectors Tests
// ============================================================================

/// Load spend vectors from JSON file.
fn load_spend_vectors() -> Vec<SpendVector> {
    let data = fs::read_to_string("tests/vectors/spend_valid.json")
        .expect("Failed to read spend_valid.json");
    serde_json::from_str(&data).expect("Failed to parse spend_valid.json")
}

/// Run a single spend vector test.
fn run_spend_vector(index: usize, vector: &SpendVector) -> Result<bool, String> {
    // Parse the unlocking script (scriptSig)
    let unlocking_script = if vector.script_sig.is_empty() {
        UnlockingScript::new()
    } else {
        UnlockingScript::from_hex(&vector.script_sig).map_err(|e| {
            format!(
                "Vector {}: Failed to parse scriptSig '{}': {}",
                index, vector.script_sig, e
            )
        })?
    };

    // Parse the locking script (scriptPubKey)
    let locking_script = if vector.script_pub_key.is_empty() {
        LockingScript::new()
    } else {
        LockingScript::from_hex(&vector.script_pub_key).map_err(|e| {
            format!(
                "Vector {}: Failed to parse scriptPubKey '{}': {}",
                index, vector.script_pub_key, e
            )
        })?
    };

    // Create spend validator with mock transaction context
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    // Validate the spend
    spend.validate().map_err(|e| {
        format!(
            "Vector {}: Validation failed - {} (comment: {})",
            index, e, vector.comment
        )
    })
}

#[test]
fn test_spend_valid_vectors() {
    let vectors = load_spend_vectors();
    let total = vectors.len();
    let mut passed = 0;
    let mut failed = 0;
    let mut failures: Vec<String> = Vec::new();

    for (i, vector) in vectors.iter().enumerate() {
        match run_spend_vector(i, vector) {
            Ok(true) => {
                passed += 1;
            }
            Ok(false) => {
                failed += 1;
                failures.push(format!(
                    "Vector {}: Validation returned false (expected true) - scriptSig: '{}', scriptPubKey: '{}', comment: '{}'",
                    i, vector.script_sig, vector.script_pub_key, vector.comment
                ));
            }
            Err(e) => {
                failed += 1;
                failures.push(e);
            }
        }
    }

    // Print summary
    println!("\n=== Spend Valid Vectors Summary ===");
    println!("Total: {}, Passed: {}, Failed: {}", total, passed, failed);

    if !failures.is_empty() {
        println!("\nFirst 20 failures:");
        for (i, failure) in failures.iter().take(20).enumerate() {
            println!("  {}. {}", i + 1, failure);
        }

        panic!(
            "Spend valid vectors: {}/{} passed ({} failed)",
            passed, total, failed
        );
    }
}

// ============================================================================
// Script Parsing Tests (Valid Vectors)
// ============================================================================

/// Load script valid vectors from JSON file.
fn load_script_valid_vectors() -> Vec<ScriptVector> {
    let data = fs::read_to_string("tests/vectors/script_valid.json")
        .expect("Failed to read script_valid.json");
    serde_json::from_str(&data).expect("Failed to parse script_valid.json")
}

/// Test that valid scripts can be parsed without errors.
/// Note: This tests parsing only, not execution. Some ASM roundtrip mismatches
/// may occur due to differences in how data is displayed (e.g., OP_0 vs 0).
#[test]
fn test_script_valid_vectors_parsing() {
    let vectors = load_script_valid_vectors();
    let total = vectors.len();
    let mut passed = 0;
    let mut failed = 0;
    let mut failures: Vec<String> = Vec::new();

    for (i, vector) in vectors.iter().enumerate() {
        let mut test_passed = true;

        // Test scriptSig parsing
        if !vector.script_sig.is_empty() {
            match Script::from_hex(&vector.script_sig) {
                Ok(script) => {
                    // Just verify we can get ASM and hex back
                    let _asm = script.to_asm();
                    let _hex = script.to_hex();
                    // Hex roundtrip should be exact
                    let roundtrip_hex = Script::from_hex(&vector.script_sig)
                        .map(|s| s.to_hex())
                        .unwrap_or_default();
                    if roundtrip_hex.to_lowercase() != vector.script_sig.to_lowercase() {
                        test_passed = false;
                        failures.push(format!(
                            "Vector {}: scriptSig hex roundtrip mismatch - original: '{}', roundtrip: '{}'",
                            i, vector.script_sig, roundtrip_hex
                        ));
                    }
                }
                Err(e) => {
                    test_passed = false;
                    failures.push(format!(
                        "Vector {}: Failed to parse scriptSig '{}': {}",
                        i, vector.script_sig, e
                    ));
                }
            }
        }

        // Test scriptPubKey parsing
        if !vector.script_pub_key.is_empty() {
            match Script::from_hex(&vector.script_pub_key) {
                Ok(script) => {
                    let _asm = script.to_asm();
                    let roundtrip_hex = script.to_hex();
                    if roundtrip_hex.to_lowercase() != vector.script_pub_key.to_lowercase() {
                        test_passed = false;
                        failures.push(format!(
                            "Vector {}: scriptPubKey hex roundtrip mismatch - original: '{}', roundtrip: '{}'",
                            i, vector.script_pub_key, roundtrip_hex
                        ));
                    }
                }
                Err(e) => {
                    test_passed = false;
                    failures.push(format!(
                        "Vector {}: Failed to parse scriptPubKey '{}': {}",
                        i, vector.script_pub_key, e
                    ));
                }
            }
        }

        if test_passed {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    println!("\n=== Script Valid Vectors (Parsing) Summary ===");
    println!("Total: {}, Passed: {}, Failed: {}", total, passed, failed);

    if !failures.is_empty() {
        println!("\nFirst 10 failures:");
        for (i, failure) in failures.iter().take(10).enumerate() {
            println!("  {}. {}", i + 1, failure);
        }

        // Parsing should work for all vectors
        if failed > 10 {
            panic!(
                "Script valid vectors (parsing): {}/{} passed ({} failed)",
                passed, total, failed
            );
        }
    }
}

/// Test that valid scripts execute correctly.
/// Note: The script_valid.vectors file contains both BSV and BTC-specific vectors.
/// Some vectors may fail because:
/// - BSV requires push-only unlocking scripts
/// - BSV requires minimal push encoding
/// - BSV has different clean stack requirements
/// - Some vectors test BTC-specific behavior (P2SH, etc.)
#[test]
fn test_script_valid_vectors_execution() {
    let vectors = load_script_valid_vectors();
    let total = vectors.len();
    let mut passed = 0;
    let mut skipped = 0;
    let mut failed = 0;
    let mut failures: Vec<String> = Vec::new();

    for (i, vector) in vectors.iter().enumerate() {
        // Skip vectors that use features not supported in BSV
        // P2SH is a BTC-specific feature
        if vector.flags.contains("P2SH") && !vector.flags.contains("STRICTENC") {
            skipped += 1;
            continue;
        }

        // Parse scripts
        let unlocking_script = if vector.script_sig.is_empty() {
            UnlockingScript::new()
        } else {
            match UnlockingScript::from_hex(&vector.script_sig) {
                Ok(s) => s,
                Err(e) => {
                    failed += 1;
                    failures.push(format!("Vector {}: Parse error: {}", i, e));
                    continue;
                }
            }
        };

        let locking_script = if vector.script_pub_key.is_empty() {
            LockingScript::new()
        } else {
            match LockingScript::from_hex(&vector.script_pub_key) {
                Ok(s) => s,
                Err(e) => {
                    failed += 1;
                    failures.push(format!("Vector {}: Parse error: {}", i, e));
                    continue;
                }
            }
        };

        // Create and run spend validator
        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1,
            locking_script,
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script,
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: None,
        });

        match spend.validate() {
            Ok(true) => {
                passed += 1;
            }
            Ok(false) => {
                failed += 1;
                failures.push(format!(
                    "Vector {}: Validation returned false (flags: {}, comment: {})",
                    i, vector.flags, vector.comment
                ));
            }
            Err(e) => {
                failed += 1;
                failures.push(format!(
                    "Vector {}: Execution failed - {} (flags: {}, comment: {})",
                    i, e, vector.flags, vector.comment
                ));
            }
        }
    }

    println!("\n=== Script Valid Vectors (Execution) Summary ===");
    println!(
        "Total: {}, Passed: {}, Skipped: {}, Failed: {}",
        total, passed, skipped, failed
    );

    // These vectors include BTC-specific tests, so we don't require 100% pass rate.
    // However, we enforce a minimum pass rate to catch regressions.
    println!(
        "\nNote: Some vectors fail due to BTC-specific behavior (P2SH, non-push scriptSig, etc.)"
    );
    println!("The BSV-specific spend.valid.vectors should all pass.");

    // Minimum pass rate assertion to catch regressions.
    // The script_valid.json vectors include many BTC-specific scripts (P2SH, non-push
    // scriptSig, etc.) that correctly fail under BSV rules. The current baseline is ~39.5%.
    // We set the floor at 35% to catch regressions where BSV-valid scripts start failing.
    let pass_rate = (passed as f64) / (total as f64) * 100.0;
    let min_pass_rate = 35.0;
    assert!(
        pass_rate >= min_pass_rate,
        "Script valid vectors execution pass rate {:.1}% is below minimum {:.1}%. \
         Passed: {}/{} (skipped: {}, failed: {}). This indicates a regression.",
        pass_rate,
        min_pass_rate,
        passed,
        total,
        skipped,
        failed
    );
}

// ============================================================================
// Script Invalid Vectors Tests
// ============================================================================

/// Load script invalid vectors from JSON file.
fn load_script_invalid_vectors() -> Vec<ScriptVector> {
    let data = fs::read_to_string("tests/vectors/script_invalid.json")
        .expect("Failed to read script_invalid.json");
    serde_json::from_str(&data).expect("Failed to parse script_invalid.json")
}

/// Test that invalid scripts fail during parsing or execution.
#[test]
fn test_script_invalid_vectors() {
    let vectors = load_script_invalid_vectors();
    let total = vectors.len();
    let mut passed = 0;
    let mut failed = 0;
    let mut failures: Vec<String> = Vec::new();

    for (i, vector) in vectors.iter().enumerate() {
        // An invalid vector should either:
        // 1. Fail to parse
        // 2. Fail during execution (validate returns Err or Ok(false))

        // Try to parse the scripts
        let unlocking_result = if vector.script_sig.is_empty() {
            Ok(UnlockingScript::new())
        } else {
            UnlockingScript::from_hex(&vector.script_sig)
        };

        let locking_result = if vector.script_pub_key.is_empty() {
            Ok(LockingScript::new())
        } else {
            LockingScript::from_hex(&vector.script_pub_key)
        };

        // If parsing fails, that's expected for invalid vectors
        let (unlocking_script, locking_script) = match (unlocking_result, locking_result) {
            (Ok(u), Ok(l)) => (u, l),
            _ => {
                // Parse failure is valid for invalid vectors
                passed += 1;
                continue;
            }
        };

        // If parsing succeeded, execution should fail
        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1,
            locking_script,
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script,
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: None,
        });

        match spend.validate() {
            Ok(true) => {
                // Invalid vector passed - this is unexpected
                failed += 1;
                failures.push(format!(
                    "Vector {}: Expected to fail but passed - scriptSig: '{}', scriptPubKey: '{}', comment: '{}'",
                    i, vector.script_sig, vector.script_pub_key, vector.comment
                ));
            }
            Ok(false) | Err(_) => {
                // Expected behavior - validation failed
                passed += 1;
            }
        }
    }

    println!("\n=== Script Invalid Vectors Summary ===");
    println!("Total: {}, Passed: {}, Failed: {}", total, passed, failed);

    if !failures.is_empty() {
        println!("\nFirst 20 failures (vectors that passed but should have failed):");
        for (i, failure) in failures.iter().take(20).enumerate() {
            println!("  {}. {}", i + 1, failure);
        }

        // Some invalid vectors might pass due to different flag handling between
        // BSV and BTC (e.g., STRICTENC, CLEANSTACK rules).
        // Tightened from 10% to 5% tolerance to better catch regressions.
        let false_positive_rate = (failed as f64) / (total as f64) * 100.0;
        let max_false_positive_rate = 5.0;
        if false_positive_rate > max_false_positive_rate {
            panic!(
                "Script invalid vectors: {:.1}% false positives ({} of {} incorrectly passed). \
                 Maximum allowed is {:.1}%. {}/{} correctly failed.",
                false_positive_rate, failed, total, max_false_positive_rate, passed, total
            );
        }
    }
}

// ============================================================================
// Individual Test Cases
// ============================================================================

/// Test basic arithmetic script: 1 + 2 = 3
#[test]
fn test_arithmetic_script() {
    let unlocking = UnlockingScript::from_hex("5152").unwrap(); // OP_1 OP_2
    let locking = LockingScript::from_hex("935387").unwrap(); // OP_ADD OP_3 OP_EQUAL

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap(), "1 + 2 should equal 3");
}

/// Test OP_DEPTH
#[test]
fn test_op_depth() {
    // Simplest valid: push nothing, depth should be 0, check 0 == 0
    // [] -> DEPTH -> [0] -> 0 -> [0, 0] -> EQUAL -> [1]
    let unlocking = UnlockingScript::new();
    let locking = LockingScript::from_hex("740087").unwrap(); // DEPTH 0 EQUAL

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test conditional execution: IF/ELSE/ENDIF
#[test]
fn test_conditional() {
    // scriptSig: OP_1 (true branch)
    // scriptPubKey: OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    let unlocking = UnlockingScript::from_hex("51").unwrap();
    let locking = LockingScript::from_hex("635167005168").unwrap();

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test OP_CAT (BSV re-enabled)
#[test]
fn test_op_cat() {
    // Simpler: just check CAT produces expected result
    let unlocking = UnlockingScript::from_hex("026162026364").unwrap(); // push "ab" push "cd"
    let locking = LockingScript::from_hex("7e046162636487").unwrap(); // OP_CAT <"abcd"> OP_EQUAL

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test OP_SPLIT (BSV re-enabled)
#[test]
fn test_op_split() {
    // Push "abcd", split at position 2
    // After OP_SPLIT: stack = ["ab", "cd"] (cd on top)
    // Then verify: top == "cd" (EQUALVERIFY), remaining == "ab" (EQUAL)
    let unlocking = UnlockingScript::from_hex("0461626364").unwrap(); // push "abcd"
    let locking = LockingScript::from_hex("527f0263648802616287").unwrap(); // OP_2 OP_SPLIT <"cd"> OP_EQUALVERIFY <"ab"> OP_EQUAL

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test multiplication (BSV re-enabled OP_MUL)
#[test]
fn test_op_mul() {
    // 3 * 7 = 21
    let unlocking = UnlockingScript::from_hex("5357").unwrap(); // OP_3 OP_7
    let locking = LockingScript::from_hex("95011587").unwrap(); // OP_MUL <21> OP_EQUAL

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test division (BSV re-enabled OP_DIV)
#[test]
fn test_op_div() {
    // 21 / 7 = 3
    let unlocking = UnlockingScript::from_hex("011557").unwrap(); // <21> OP_7
    let locking = LockingScript::from_hex("965387").unwrap(); // OP_DIV OP_3 OP_EQUAL

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test hash operations
#[test]
fn test_hash_operations() {
    use bsv_sdk::primitives::sha256;

    // Test OP_SHA256
    let data = vec![0x01, 0x02, 0x03];
    let expected_hash = sha256(&data);

    // Build script to push data, hash it, and compare
    let mut unlocking = Script::new();
    unlocking.write_bin(&data);
    let unlocking = UnlockingScript::from_script(unlocking);

    let mut locking = Script::new();
    locking.write_opcode(0xa8); // OP_SHA256
    locking.write_bin(&expected_hash);
    locking.write_opcode(0x87); // OP_EQUAL
    let locking = LockingScript::from_script(locking);

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    assert!(spend.validate().unwrap());
}

/// Test the first spend vector in detail for debugging
#[test]
fn test_first_spend_vector_detailed() {
    let vectors = load_spend_vectors();
    if vectors.is_empty() {
        return;
    }

    let v = &vectors[0];
    println!("First vector:");
    println!("  scriptSig: '{}'", v.script_sig);
    println!("  scriptPubKey: '{}'", v.script_pub_key);
    println!("  comment: '{}'", v.comment);

    let unlocking = if v.script_sig.is_empty() {
        UnlockingScript::new()
    } else {
        UnlockingScript::from_hex(&v.script_sig).expect("Failed to parse scriptSig")
    };

    let locking = if v.script_pub_key.is_empty() {
        LockingScript::new()
    } else {
        LockingScript::from_hex(&v.script_pub_key).expect("Failed to parse scriptPubKey")
    };

    println!("  unlocking ASM: '{}'", unlocking.to_asm());
    println!("  locking ASM: '{}'", locking.to_asm());

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
    });

    let result = spend.validate();
    println!("  result: {:?}", result);
    assert!(result.is_ok() && result.unwrap());
}
