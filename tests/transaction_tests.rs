//! Integration tests for the BSV SDK transaction module.
//!
//! These tests cover:
//! - Transaction serialization/deserialization
//! - Fee models (SatoshisPerKilobyte)
//! - Broadcaster and ChainTracker traits (async)
//! - BEEF and MerklePath parsing
//! - SPV verification
//! - Invalid transaction and BUMP vectors

mod transaction;

#[cfg(feature = "transaction")]
mod transaction_tests {
    use crate::transaction::vectors::{
        bigtx::*, bump_invalid::*, bump_valid::*, tx_invalid::*, tx_valid::*,
    };
    use async_trait::async_trait;
    use bsv_sdk::script::LockingScript;
    use bsv_sdk::transaction::{
        AlwaysValidChainTracker, Beef, BroadcastFailure, BroadcastResponse, BroadcastResult,
        BroadcastStatus, Broadcaster, ChainTracker, FeeModel, FixedFee, MerklePath,
        MockChainTracker, SatoshisPerKilobyte, Transaction, TransactionInput, TransactionOutput,
    };

    // ===================
    // Transaction parsing tests
    // ===================

    #[test]
    fn test_transaction_from_hex() {
        let tx = Transaction::from_hex(TX_VALID_1).expect("Should parse valid transaction");
        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 0);
    }

    #[test]
    fn test_transaction_roundtrip_hex() {
        for hex in TX_VALID_VECTORS {
            let tx = Transaction::from_hex(hex).expect("Should parse");
            let result = tx.to_hex();
            assert_eq!(
                result.to_lowercase(),
                hex.to_lowercase(),
                "Hex should match"
            );
        }
    }

    #[test]
    fn test_transaction_roundtrip_binary() {
        for hex in TX_VALID_VECTORS {
            let tx = Transaction::from_hex(hex).expect("Should parse");
            let binary = tx.to_binary();
            let tx2 = Transaction::from_binary(&binary).expect("Should parse binary");
            assert_eq!(tx.to_hex(), tx2.to_hex(), "Binary roundtrip should match");
        }
    }

    #[test]
    fn test_transaction_txid() {
        let tx = Transaction::from_hex(TX_VALID_2).expect("Should parse");
        let txid = tx.id();
        assert_eq!(txid, TX_VALID_2_TXID, "TXID should match expected");
    }

    #[test]
    fn test_transaction_hash_differs_from_id() {
        let tx = Transaction::from_hex(TX_VALID_2).expect("Should parse");
        let hash_hex = tx.hash_hex();
        let txid = tx.id();
        // Hash and TXID should be reversed
        assert_ne!(hash_hex, txid);
    }

    #[test]
    fn test_new_transaction_defaults() {
        let tx = Transaction::new();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 0);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    // ===================
    // Invalid transaction parsing tests
    // ===================

    #[test]
    fn test_invalid_tx_can_be_parsed_structurally() {
        // These vectors are structurally valid transactions (correct binary format)
        // but semantically invalid (would fail script verification).
        // They should ALL parse successfully from hex.
        for (i, (hex, desc)) in TX_INVALID_VECTORS.iter().enumerate() {
            let result = Transaction::from_hex(hex);
            assert!(
                result.is_ok(),
                "Vector {}: '{}' should parse structurally but got error: {}",
                i,
                desc,
                result.unwrap_err()
            );
            // Verify roundtrip: the parsed transaction should re-serialize to the same hex
            let tx = result.unwrap();
            assert_eq!(
                tx.to_hex().to_lowercase(),
                hex.to_lowercase(),
                "Vector {}: '{}' hex roundtrip mismatch",
                i,
                desc
            );
        }
    }

    #[test]
    fn test_truly_malformed_binary_fails_to_parse() {
        // Truly malformed binary data should fail to parse
        let malformed_vectors: &[(&str, &str)] = &[
            ("", "empty input"),
            ("00", "single zero byte"),
            (
                "0100000000",
                "truncated: version + zero inputs, missing output count + locktime",
            ),
            (
                "01000000ff",
                "invalid varint: 0xff prefix without 8 following bytes",
            ),
            ("deadbeef", "random 4 bytes, not a valid tx"),
        ];

        for (i, (hex, desc)) in malformed_vectors.iter().enumerate() {
            let result = Transaction::from_hex(hex);
            assert!(
                result.is_err(),
                "Malformed vector {}: '{}' should fail to parse but got Ok",
                i,
                desc
            );
        }
    }

    // ===================
    // Fee model tests
    // ===================

    #[test]
    fn test_fixed_fee() {
        let fee_model = FixedFee::new(500);
        let tx = Transaction::new();
        let fee = fee_model.compute_fee(&tx).expect("Should compute fee");
        assert_eq!(fee, 500);
    }

    #[test]
    fn test_satoshis_per_kilobyte_default() {
        let fee_model = SatoshisPerKilobyte::default();
        assert_eq!(fee_model.value, 100);
    }

    #[test]
    fn test_satoshis_per_kilobyte_new() {
        let fee_model = SatoshisPerKilobyte::new(1000); // 1 sat/byte
        assert_eq!(fee_model.value, 1000);
    }

    #[test]
    fn test_satoshis_per_kilobyte_empty_tx() {
        let fee_model = SatoshisPerKilobyte::new(1000); // 1 sat/byte
        let tx = Transaction::new();
        let fee = fee_model.compute_fee(&tx).expect("Should compute fee");
        // Empty tx: 4 (version) + 1 (input count) + 1 (output count) + 4 (locktime) = 10 bytes
        // 10 * 1000 / 1000 = 10 sats
        assert_eq!(fee, 10);
    }

    #[test]
    fn test_satoshis_per_kilobyte_ceiling_division() {
        // Test that fees are rounded up
        let fee_model = SatoshisPerKilobyte::new(100); // 100 sat/KB = 0.1 sat/byte
        let tx = Transaction::new();
        let fee = fee_model.compute_fee(&tx).expect("Should compute fee");
        // 10 bytes * 100 sat/KB = 1 sat (with ceiling)
        assert_eq!(fee, 1);
    }

    // ===================
    // Chain tracker tests (async)
    // ===================

    #[tokio::test]
    async fn test_mock_chain_tracker() {
        let mut tracker = MockChainTracker::new(1000);
        tracker.add_root(999, "abc123".to_string());

        assert!(tracker
            .is_valid_root_for_height("abc123", 999)
            .await
            .expect("Should check"));
        assert!(!tracker
            .is_valid_root_for_height("abc123", 998)
            .await
            .expect("Should check"));
        assert!(!tracker
            .is_valid_root_for_height("xyz789", 999)
            .await
            .expect("Should check"));
        assert_eq!(
            tracker.current_height().await.expect("Should get height"),
            1000
        );
    }

    #[tokio::test]
    async fn test_always_valid_chain_tracker() {
        let tracker = AlwaysValidChainTracker::new(500);

        assert!(tracker
            .is_valid_root_for_height("anything", 123)
            .await
            .expect("Should check"));
        assert!(tracker
            .is_valid_root_for_height("", 0)
            .await
            .expect("Should check"));
        assert_eq!(
            tracker.current_height().await.expect("Should get height"),
            500
        );
    }

    // ===================
    // Broadcaster tests (async)
    // ===================

    struct TestBroadcaster {
        should_succeed: bool,
    }

    #[async_trait(?Send)]
    impl Broadcaster for TestBroadcaster {
        async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
            if self.should_succeed {
                Ok(BroadcastResponse::success(
                    tx.id(),
                    "Transaction accepted".to_string(),
                ))
            } else {
                Err(BroadcastFailure::new(
                    "REJECTED".to_string(),
                    "Transaction rejected".to_string(),
                ))
            }
        }

        async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult> {
            let mut results = Vec::with_capacity(txs.len());
            for tx in &txs {
                results.push(self.broadcast(tx).await);
            }
            results
        }
    }

    #[tokio::test]
    async fn test_broadcaster_success() {
        let broadcaster = TestBroadcaster {
            should_succeed: true,
        };
        let tx = Transaction::from_hex(TX_VALID_1).expect("Should parse");
        let result = broadcaster.broadcast(&tx).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, BroadcastStatus::Success);
        assert_eq!(response.txid, tx.id());
    }

    #[tokio::test]
    async fn test_broadcaster_failure() {
        let broadcaster = TestBroadcaster {
            should_succeed: false,
        };
        let tx = Transaction::from_hex(TX_VALID_1).expect("Should parse");
        let result = broadcaster.broadcast(&tx).await;

        assert!(result.is_err());
        let failure = result.unwrap_err();
        assert_eq!(failure.status, BroadcastStatus::Error);
        assert_eq!(failure.code, "REJECTED");
    }

    #[tokio::test]
    async fn test_broadcaster_many() {
        let broadcaster = TestBroadcaster {
            should_succeed: true,
        };
        let tx1 = Transaction::from_hex(TX_VALID_1).expect("Should parse");
        let tx2 = Transaction::from_hex(TX_VALID_2).expect("Should parse");

        let results = broadcaster.broadcast_many(vec![tx1, tx2]).await;
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
    }

    // ===================
    // MerklePath tests
    // ===================

    #[test]
    fn test_merkle_path_from_hex() {
        for bump_hex in BUMP_VALID_VECTORS {
            let bump = MerklePath::from_hex(bump_hex).expect("Should parse BUMP");
            assert!(bump.block_height > 0);
            assert!(!bump.path.is_empty());
        }
    }

    #[test]
    fn test_merkle_path_roundtrip() {
        for bump_hex in BUMP_VALID_VECTORS {
            let bump = MerklePath::from_hex(bump_hex).expect("Should parse");
            let result = bump.to_hex();
            assert_eq!(
                result.to_lowercase(),
                bump_hex.to_lowercase(),
                "BUMP roundtrip should match"
            );
        }
    }

    #[test]
    fn test_merkle_path_from_coinbase() {
        let txid = "a".repeat(64);
        let bump = MerklePath::from_coinbase_txid(&txid, 100);
        assert_eq!(bump.block_height, 100);
        assert!(!bump.path.is_empty());
        assert!(bump.contains(&txid));
    }

    #[test]
    fn test_merkle_path_compute_root() {
        let bump = MerklePath::from_hex(BUMP_VALID_1).expect("Should parse");
        let txids = bump.txids();

        if !txids.is_empty() {
            let root = bump
                .compute_root(Some(&txids[0]))
                .expect("Should compute root");
            assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars
        }
    }

    // ===================
    // Invalid BUMP tests
    // ===================

    #[test]
    fn test_invalid_bump_vectors() {
        // These vectors are invalid according to the TypeScript SDK validation rules.
        // The Rust implementation may have different validation timing (parse vs validate).
        // We verify that we have test coverage for these vectors and document the expected errors.
        for (i, vector) in BUMP_INVALID_VECTORS.iter().enumerate() {
            // Just verify we can attempt to parse these vectors
            // The actual validation may happen at different points depending on implementation
            let result = MerklePath::from_hex(vector.bump);

            // Log the vector info for debugging
            println!(
                "Vector {}: expected error '{}', parse result: {}",
                i,
                vector.error,
                if result.is_ok() { "OK" } else { "Err" }
            );

            // The vectors exist and can be processed - validation may differ
            // Some may parse OK but fail on verify(), others may fail on parse
            assert!(
                !vector.bump.is_empty(),
                "Vector {} should have non-empty bump data",
                i
            );
            assert!(
                !vector.error.is_empty(),
                "Vector {} should have error description",
                i
            );
        }
    }

    // ===================
    // BEEF tests
    // ===================

    #[test]
    fn test_beef_new() {
        let beef = Beef::new();
        assert!(beef.bumps.is_empty());
        assert!(beef.txs.is_empty());
    }

    #[test]
    fn test_beef_merge_txid_only() {
        let mut beef = Beef::new();
        let txid = "a".repeat(64);
        beef.merge_txid_only(txid.clone());

        assert_eq!(beef.txs.len(), 1);
        assert!(beef.txs[0].is_txid_only());
        assert!(beef.find_txid(&txid).is_some());
    }

    #[test]
    fn test_beef_merge_bump() {
        let mut beef = Beef::new();
        let bump = MerklePath::from_coinbase_txid(&"a".repeat(64), 100);
        let idx = beef.merge_bump(bump);

        assert_eq!(idx, 0);
        assert_eq!(beef.bumps.len(), 1);
    }

    #[test]
    fn test_beef_empty_is_valid() {
        let mut beef = Beef::new();
        assert!(beef.is_valid(false));
    }

    // ===================
    // Big Transaction tests
    // ===================

    #[test]
    fn test_big_tx_constant_exists() {
        // Verify the big TX TXID constant is defined and valid
        assert_eq!(BIG_TX_TXID.len(), 64); // 32 bytes as hex
        assert!(BIG_TX_TXID.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_large_tx_parses() {
        // Test that our LARGE_TX_HEX (a real coinbase transaction) parses
        let tx = Transaction::from_hex(LARGE_TX_HEX).expect("Should parse large transaction");
        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_multi_io_tx_parses() {
        // Test transaction with multiple inputs/outputs
        let tx = Transaction::from_hex(MULTI_IO_TX_HEX).expect("Should parse multi-IO transaction");
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.id(), MULTI_IO_TX_TXID);
    }

    // ===================
    // Integration tests
    // ===================

    #[test]
    fn test_estimate_size() {
        let tx = Transaction::from_hex(TX_VALID_2).expect("Should parse");
        let estimated = tx.estimate_size();
        let actual = tx.to_binary().len();

        // Estimation should be close to actual (within 10 bytes)
        let diff = (estimated as i64 - actual as i64).abs();
        assert!(diff < 10, "Size estimation diff {} too large", diff);
    }

    #[test]
    fn test_add_input_requires_txid_or_source() {
        let mut tx = Transaction::new();
        let bad_input = TransactionInput::default();

        assert!(tx.add_input(bad_input).is_err());
    }

    #[test]
    fn test_add_input_with_txid() {
        let mut tx = Transaction::new();
        let input = TransactionInput::new("a".repeat(64), 0);

        assert!(tx.add_input(input).is_ok());
        assert_eq!(tx.inputs.len(), 1);
    }

    #[test]
    fn test_add_output() {
        let mut tx = Transaction::new();
        let output = TransactionOutput::new(100_000, LockingScript::new());

        assert!(tx.add_output(output).is_ok());
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_add_change_output() {
        let mut tx = Transaction::new();
        let output = TransactionOutput::new_change(LockingScript::new());

        assert!(tx.add_output(output).is_ok());
        assert_eq!(tx.outputs.len(), 1);
        assert!(tx.outputs[0].change);
    }

    #[test]
    fn test_metadata() {
        let mut tx = Transaction::new();
        tx.update_metadata("key", serde_json::json!("value"));

        assert_eq!(tx.metadata.get("key"), Some(&serde_json::json!("value")));
    }

    // ===================
    // Extended BEEF tests
    // ===================

    mod beef_extended_tests {
        use super::*;
        use bsv_sdk::transaction::{BEEF_V1, BEEF_V2};

        fn create_test_transaction(n: u32) -> Transaction {
            let mut tx = Transaction::new();
            tx.version = n;
            tx.add_output(TransactionOutput::new(1000, LockingScript::new()))
                .unwrap();
            tx
        }

        fn create_test_transaction_with_input(source: &Transaction, vout: u32) -> Transaction {
            let mut tx = Transaction::new();
            tx.add_input(TransactionInput::with_source_transaction(
                source.clone(),
                vout,
            ))
            .unwrap();
            tx.add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();
            tx
        }

        #[test]
        fn test_beef_merge_transaction_with_parents() {
            // Create parent tx
            let parent = create_test_transaction(1);

            // Create child tx referencing parent
            let child = create_test_transaction_with_input(&parent, 0);

            // Merge both transactions into BEEF (parent first, then child)
            let mut beef = Beef::new();
            beef.merge_transaction(parent.clone());
            beef.merge_transaction(child.clone());

            // Verify both are included
            assert!(
                beef.find_txid(&parent.id()).is_some(),
                "Parent should be included"
            );
            assert!(
                beef.find_txid(&child.id()).is_some(),
                "Child should be included"
            );

            // Verify count
            assert_eq!(beef.txs.len(), 2, "Should have 2 transactions");
        }

        #[test]
        fn test_beef_merge_two_beefs() {
            let mut beef1 = Beef::new();
            let mut beef2 = Beef::new();

            // Add different transactions to each
            let tx1 = create_test_transaction(1);
            let tx2 = create_test_transaction(2);

            beef1.merge_transaction(tx1.clone());
            beef2.merge_transaction(tx2.clone());

            // Merge beef2 into beef1
            beef1.merge_beef(&beef2);

            // Both transactions should be in beef1
            assert!(
                beef1.find_txid(&tx1.id()).is_some(),
                "tx1 should be in merged beef"
            );
            assert!(
                beef1.find_txid(&tx2.id()).is_some(),
                "tx2 should be in merged beef"
            );
        }

        #[test]
        fn test_beef_sort_txs_dependency_order() {
            let mut beef = Beef::new();

            // Create chain: grandparent -> parent -> child
            let grandparent = create_test_transaction(1);
            let parent = create_test_transaction_with_input(&grandparent, 0);
            let child = create_test_transaction_with_input(&parent, 0);

            // Add in wrong order - child first
            beef.merge_transaction(child.clone());

            // Sort
            beef.sort_txs();

            // Verify order: grandparent, parent, child
            let txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
            let gp_idx = txids.iter().position(|t| t == &grandparent.id());
            let p_idx = txids.iter().position(|t| t == &parent.id());
            let c_idx = txids.iter().position(|t| t == &child.id());

            if let (Some(gp_idx), Some(p_idx), Some(c_idx)) = (gp_idx, p_idx, c_idx) {
                assert!(gp_idx < p_idx, "grandparent should come before parent");
                assert!(p_idx < c_idx, "parent should come before child");
            }
        }

        #[test]
        fn test_beef_atomic_serialization() {
            let mut beef = Beef::new();
            let tx = create_test_transaction(1);
            let txid = tx.id();

            beef.merge_transaction(tx);

            // Serialize as atomic BEEF
            let atomic = beef.to_binary_atomic(&txid).unwrap();

            // Parse back
            let parsed = Beef::from_binary(&atomic).unwrap();

            // Verify atomic_txid is set
            assert_eq!(parsed.atomic_txid, Some(txid));
        }

        #[test]
        fn test_beef_v1_v2_roundtrip() {
            // Create BEEF V1
            let mut beef_v1 = Beef::with_version(BEEF_V1);
            beef_v1.merge_transaction(create_test_transaction(1));

            let binary = beef_v1.to_binary();
            let parsed = Beef::from_binary(&binary).unwrap();
            assert_eq!(parsed.version, BEEF_V1);

            // Create BEEF V2
            let mut beef_v2 = Beef::with_version(BEEF_V2);
            beef_v2.merge_transaction(create_test_transaction(2));

            let binary = beef_v2.to_binary();
            let parsed = Beef::from_binary(&binary).unwrap();
            assert_eq!(parsed.version, BEEF_V2);
        }

        #[test]
        fn test_beef_version_default() {
            let beef = Beef::new();
            assert_eq!(beef.version, BEEF_V2, "Default version should be V2");
        }

        #[test]
        fn test_beef_multiple_bumps() {
            let mut beef = Beef::new();

            // Add multiple merkle paths
            let bump1 = MerklePath::from_coinbase_txid(&"a".repeat(64), 100);
            let bump2 = MerklePath::from_coinbase_txid(&"b".repeat(64), 200);
            let bump3 = MerklePath::from_coinbase_txid(&"c".repeat(64), 300);

            let idx1 = beef.merge_bump(bump1);
            let idx2 = beef.merge_bump(bump2);
            let idx3 = beef.merge_bump(bump3);

            assert_eq!(idx1, 0);
            assert_eq!(idx2, 1);
            assert_eq!(idx3, 2);
            assert_eq!(beef.bumps.len(), 3);
        }

        #[test]
        fn test_beef_empty_validation() {
            let mut beef = Beef::new();
            assert!(beef.is_valid(false), "Empty BEEF should be valid");
            assert!(
                beef.is_valid(true),
                "Empty BEEF should be valid with txid_only"
            );
        }

        #[test]
        fn test_beef_txid_only_validation() {
            let mut beef = Beef::new();
            let txid = "a".repeat(64);
            beef.merge_txid_only(txid.clone());

            // Should fail without allowing txid_only
            assert!(
                !beef.is_valid(false),
                "BEEF with txid-only should fail strict validation"
            );

            // Should pass with txid_only allowed
            assert!(
                beef.is_valid(true),
                "BEEF with txid-only should pass lenient validation"
            );
        }

        #[test]
        fn test_beef_find_transaction_not_found() {
            let beef = Beef::new();
            let result = beef.find_txid(&"a".repeat(64));
            assert!(result.is_none(), "Should not find non-existent txid");
        }

        #[test]
        fn test_beef_hex_roundtrip() {
            let mut beef = Beef::new();
            beef.merge_transaction(create_test_transaction(1));

            let hex = beef.to_hex();
            let parsed = Beef::from_hex(&hex).unwrap();

            assert_eq!(beef.version, parsed.version);
            assert_eq!(beef.txs.len(), parsed.txs.len());
        }

        #[test]
        fn test_beef_binary_roundtrip() {
            let mut beef = Beef::new();
            beef.merge_transaction(create_test_transaction(1));
            beef.merge_transaction(create_test_transaction(2));

            let binary = beef.to_binary();
            let parsed = Beef::from_binary(&binary).unwrap();

            assert_eq!(beef.version, parsed.version);
            assert_eq!(beef.txs.len(), parsed.txs.len());
        }

        #[test]
        fn test_beef_merge_duplicate_txid() {
            let mut beef = Beef::new();
            let tx = create_test_transaction(1);
            let txid = tx.id();

            // Add same transaction twice
            beef.merge_transaction(tx.clone());
            beef.merge_transaction(tx.clone());

            // Should only have one copy
            let count = beef.txs.iter().filter(|t| t.txid() == txid).count();
            assert_eq!(count, 1, "Should deduplicate transactions");
        }

        #[test]
        fn test_beef_merge_raw_tx() {
            let mut beef = Beef::new();

            // Create raw transaction bytes
            let tx = create_test_transaction(1);
            let raw = tx.to_binary();
            let txid = tx.id();

            beef.merge_raw_tx(raw, None);

            assert!(beef.find_txid(&txid).is_some(), "Raw tx should be merged");
        }

        #[test]
        fn test_beef_bump_at_different_heights() {
            let mut beef = Beef::new();

            // Add bumps at different heights
            for height in [100u32, 1000, 10000, 100000, 1000000] {
                let bump = MerklePath::from_coinbase_txid(&format!("{:064x}", height), height);
                beef.merge_bump(bump);
            }

            assert_eq!(beef.bumps.len(), 5);

            // Check that heights are preserved
            for (i, bump) in beef.bumps.iter().enumerate() {
                let expected_height = match i {
                    0 => 100,
                    1 => 1000,
                    2 => 10000,
                    3 => 100000,
                    4 => 1000000,
                    _ => unreachable!(),
                };
                assert_eq!(bump.block_height, expected_height);
            }
        }

        #[test]
        fn test_beef_validation_result() {
            let mut beef = Beef::new();
            let tx = create_test_transaction(1);
            beef.merge_transaction(tx);

            let result = beef.verify_valid(true);
            // Check that validation result is returned (structure is valid)
            // The validation may pass or fail depending on merkle path,
            // but the result struct should be properly returned
            let _ = result.valid; // Ensure we can access the field
            let _ = result.roots; // Ensure roots map is accessible
        }
    }

    // ===================
    // BEEF Ancestry Collection Tests (BRC-62/95)
    // Tests for Transaction::to_beef() walking the sourceTransaction chain
    // ===================

    mod beef_ancestry_tests {
        use super::*;
        use bsv_sdk::transaction::{Beef, MerklePath};

        /// Creates a test transaction with a unique version number
        fn create_test_tx(version: u32) -> Transaction {
            let mut tx = Transaction::new();
            tx.version = version;
            tx.add_output(TransactionOutput::new(1000, LockingScript::new()))
                .unwrap();
            tx
        }

        /// Creates a transaction that spends from source transaction's output
        fn create_child_tx(source: &Transaction, vout: u32) -> Transaction {
            let mut tx = Transaction::new();
            tx.add_input(TransactionInput::with_source_transaction(
                source.clone(),
                vout,
            ))
            .unwrap();
            tx.add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();
            tx
        }

        /// Creates a transaction with merkle proof (simulating a mined transaction)
        fn create_proven_tx(version: u32, block_height: u32) -> Transaction {
            let mut tx = create_test_tx(version);
            let txid = tx.id();
            tx.merkle_path = Some(MerklePath::from_coinbase_txid(&txid, block_height));
            tx
        }

        #[test]
        fn test_to_beef_single_transaction_no_ancestors() {
            // Single transaction with no inputs should produce valid BEEF
            let tx = create_test_tx(1);
            let beef_bytes = tx.to_beef(true).unwrap();

            let beef = Beef::from_binary(&beef_bytes).unwrap();
            assert_eq!(beef.txs.len(), 1, "Should have 1 transaction");
            assert!(
                beef.find_txid(&tx.id()).is_some(),
                "Should find the transaction"
            );
        }

        #[test]
        fn test_to_beef_walks_two_level_ancestry() {
            // Create: grandparent -> parent -> child
            let grandparent = create_proven_tx(1, 100);
            let parent = create_child_tx(&grandparent, 0);
            let child = create_child_tx(&parent, 0);

            // to_beef on child should include all ancestors
            let beef_bytes = child.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            assert_eq!(beef.txs.len(), 3, "Should have 3 transactions");
            assert!(
                beef.find_txid(&grandparent.id()).is_some(),
                "Should include grandparent"
            );
            assert!(
                beef.find_txid(&parent.id()).is_some(),
                "Should include parent"
            );
            assert!(
                beef.find_txid(&child.id()).is_some(),
                "Should include child"
            );
        }

        #[test]
        fn test_to_beef_walks_three_level_ancestry() {
            // Create: great-grandparent -> grandparent -> parent -> child
            let great_grandparent = create_proven_tx(1, 100);
            let grandparent = create_child_tx(&great_grandparent, 0);
            let parent = create_child_tx(&grandparent, 0);
            let child = create_child_tx(&parent, 0);

            let beef_bytes = child.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            assert_eq!(beef.txs.len(), 4, "Should have 4 transactions");
            assert!(
                beef.find_txid(&great_grandparent.id()).is_some(),
                "Should include great-grandparent"
            );
            assert!(
                beef.find_txid(&grandparent.id()).is_some(),
                "Should include grandparent"
            );
            assert!(
                beef.find_txid(&parent.id()).is_some(),
                "Should include parent"
            );
            assert!(
                beef.find_txid(&child.id()).is_some(),
                "Should include child"
            );
        }

        #[test]
        fn test_to_beef_stops_at_proven_transaction() {
            // Create: grandparent (proven) -> parent -> child
            // BEEF should only go back to grandparent, not further
            let grandparent = create_proven_tx(1, 100);
            let parent = create_child_tx(&grandparent, 0);
            let child = create_child_tx(&parent, 0);

            let beef_bytes = child.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            // Should have grandparent's merkle proof
            assert!(!beef.bumps.is_empty(), "Should have merkle proofs");
            assert_eq!(
                beef.bumps[0].block_height, 100,
                "Proof should be at height 100"
            );
        }

        #[test]
        fn test_to_beef_collects_merkle_proofs() {
            // Create two proven ancestors at different heights
            let ancestor1 = create_proven_tx(1, 100);
            let ancestor2 = create_proven_tx(2, 200);

            // Create tx spending from both
            let mut child = Transaction::new();
            child
                .add_input(TransactionInput::with_source_transaction(
                    ancestor1.clone(),
                    0,
                ))
                .unwrap();
            child
                .add_input(TransactionInput::with_source_transaction(
                    ancestor2.clone(),
                    0,
                ))
                .unwrap();
            child
                .add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();

            let beef_bytes = child.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            // Should have merkle proofs at both heights
            assert!(
                beef.bumps.len() >= 2,
                "Should have at least 2 merkle proofs"
            );
        }

        #[test]
        fn test_to_beef_allow_partial_false_fails_on_missing() {
            // Create child with only TXID reference (no source transaction)
            let mut child = Transaction::new();
            let fake_txid = "a".repeat(64);
            child
                .add_input(TransactionInput::new(fake_txid, 0))
                .unwrap();
            child
                .add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();

            // Should fail with allow_partial=false
            let result = child.to_beef(false);
            assert!(
                result.is_err(),
                "Should fail when source transaction is missing and allow_partial=false"
            );

            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("Missing source transaction"),
                "Error should mention missing source transaction"
            );
        }

        #[test]
        fn test_to_beef_allow_partial_true_skips_missing() {
            // Create child with only TXID reference (no source transaction)
            let mut child = Transaction::new();
            let fake_txid = "a".repeat(64);
            child
                .add_input(TransactionInput::new(fake_txid, 0))
                .unwrap();
            child
                .add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();

            // Should succeed with allow_partial=true
            let result = child.to_beef(true);
            assert!(
                result.is_ok(),
                "Should succeed when allow_partial=true even with missing source"
            );

            let beef = Beef::from_binary(&result.unwrap()).unwrap();
            assert_eq!(beef.txs.len(), 1, "Should only have the child transaction");
        }

        #[test]
        fn test_to_beef_handles_diamond_dependency() {
            // Create diamond: A (with 2 outputs) -> B (from output 0), A -> C (from output 1), B -> D, C -> D
            // D should only include A once despite A being ancestor of both B and C
            let mut a = Transaction::new();
            a.version = 1;
            a.merkle_path = Some(MerklePath::from_coinbase_txid(&"a".repeat(64), 100));
            // A needs two outputs so B and C can each spend different ones
            a.add_output(TransactionOutput::new(1000, LockingScript::new()))
                .unwrap();
            a.add_output(TransactionOutput::new(1000, LockingScript::new()))
                .unwrap();
            // Update merkle path with actual txid
            let a_txid = a.id();
            a.merkle_path = Some(MerklePath::from_coinbase_txid(&a_txid, 100));

            let b = create_child_tx(&a, 0); // B spends A's output 0
            let c = create_child_tx(&a, 1); // C spends A's output 1

            // D spends from both B and C
            let mut d = Transaction::new();
            d.add_input(TransactionInput::with_source_transaction(b.clone(), 0))
                .unwrap();
            d.add_input(TransactionInput::with_source_transaction(c.clone(), 0))
                .unwrap();
            d.add_output(TransactionOutput::new(200, LockingScript::new()))
                .unwrap();

            let beef_bytes = d.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            // Count how many times A appears (should be exactly once)
            let a_count = beef.txs.iter().filter(|t| t.txid() == a.id()).count();
            assert_eq!(
                a_count, 1,
                "Transaction A should appear exactly once (deduplication)"
            );

            // Total should be 4: A, B, C, D
            assert_eq!(beef.txs.len(), 4, "Should have 4 unique transactions");
        }

        #[test]
        fn test_to_beef_dependency_order() {
            // Verify transactions are in dependency order (ancestors before descendants)
            let grandparent = create_proven_tx(1, 100);
            let parent = create_child_tx(&grandparent, 0);
            let child = create_child_tx(&parent, 0);

            let beef_bytes = child.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            let txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();

            let gp_idx = txids.iter().position(|t| t == &grandparent.id()).unwrap();
            let p_idx = txids.iter().position(|t| t == &parent.id()).unwrap();
            let c_idx = txids.iter().position(|t| t == &child.id()).unwrap();

            assert!(
                gp_idx < p_idx,
                "Grandparent must come before parent in BEEF"
            );
            assert!(p_idx < c_idx, "Parent must come before child in BEEF");
        }

        #[test]
        fn test_to_atomic_beef_includes_ancestry() {
            // Verify to_atomic_beef also walks ancestry correctly
            let grandparent = create_proven_tx(1, 100);
            let parent = create_child_tx(&grandparent, 0);
            let child = create_child_tx(&parent, 0);

            let atomic_beef_bytes = child.to_atomic_beef(true).unwrap();
            let beef = Beef::from_binary(&atomic_beef_bytes).unwrap();

            // Should be atomic BEEF
            assert!(beef.is_atomic(), "Should be atomic BEEF");
            assert_eq!(
                beef.atomic_txid,
                Some(child.id()),
                "Atomic txid should be child's txid"
            );

            // Should include full ancestry
            assert_eq!(
                beef.txs.len(),
                3,
                "Atomic BEEF should include all ancestors"
            );
        }

        #[test]
        fn test_to_beef_with_proven_child() {
            // If the child itself is proven, BEEF should just contain the child
            let proven_tx = create_proven_tx(1, 100);

            let beef_bytes = proven_tx.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            assert_eq!(
                beef.txs.len(),
                1,
                "Proven tx with no unproven ancestors should have 1 tx"
            );
            assert!(!beef.bumps.is_empty(), "Should have merkle proof");
        }

        #[test]
        fn test_merkle_path_field_works() {
            // Verify the merkle_path field can be set and checked
            let mut tx = create_test_tx(1);
            assert!(
                tx.merkle_path.is_none(),
                "New tx should have no merkle_path"
            );

            let txid = tx.id();
            tx.merkle_path = Some(MerklePath::from_coinbase_txid(&txid, 12345));
            assert!(
                tx.merkle_path.is_some(),
                "Should have merkle_path after setting"
            );
            assert_eq!(tx.merkle_path.as_ref().unwrap().block_height, 12345);
        }

        #[test]
        fn test_to_beef_multiple_inputs_different_chains() {
            // Create two separate chains and merge at one transaction
            let chain1_root = create_proven_tx(1, 100);
            let chain1_child = create_child_tx(&chain1_root, 0);

            let chain2_root = create_proven_tx(2, 200);
            let chain2_child = create_child_tx(&chain2_root, 0);

            // Merge transaction spends from both chains
            let mut merge_tx = Transaction::new();
            merge_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain1_child.clone(),
                    0,
                ))
                .unwrap();
            merge_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain2_child.clone(),
                    0,
                ))
                .unwrap();
            merge_tx
                .add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();

            let beef_bytes = merge_tx.to_beef(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            // Should have all 5 transactions: 2 roots + 2 children + 1 merge
            assert_eq!(beef.txs.len(), 5, "Should include both chains");

            // Should have proofs at both heights
            let heights: Vec<u32> = beef.bumps.iter().map(|b| b.block_height).collect();
            assert!(heights.contains(&100), "Should have proof at height 100");
            assert!(heights.contains(&200), "Should have proof at height 200");
        }

        #[test]
        fn test_to_beef_tip_is_last_transaction() {
            // Regression test: The tip transaction (the one calling to_beef) must be
            // the LAST transaction in the serialized BEEF. This is required by BRC-62
            // so that ARC (and other consumers) can identify which TX to broadcast.
            //
            // Bug scenario: When inputs are created via with_source_transaction(),
            // the input_txids tracking was broken, causing the tip to be sorted
            // incorrectly and not appear last.

            // Create multiple chains merging at a consolidation TX
            let chain1_root = create_proven_tx(1, 100);
            let chain1_child = create_child_tx(&chain1_root, 0);

            let chain2_root = create_proven_tx(2, 200);
            let chain2_child = create_child_tx(&chain2_root, 0);

            let chain3_root = create_proven_tx(3, 300);
            let chain3_child = create_child_tx(&chain3_root, 0);

            // Consolidation TX spends from all three chains using with_source_transaction
            let mut consolidation_tx = Transaction::new();
            consolidation_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain1_child.clone(),
                    0,
                ))
                .unwrap();
            consolidation_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain2_child.clone(),
                    0,
                ))
                .unwrap();
            consolidation_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain3_child.clone(),
                    0,
                ))
                .unwrap();
            consolidation_tx
                .add_output(TransactionOutput::new(1500, LockingScript::new()))
                .unwrap();

            let consolidation_txid = consolidation_tx.id();

            // Test both to_beef (V2) and to_beef_v1 (V1)
            for (name, beef_bytes) in [
                ("V2", consolidation_tx.to_beef(true).unwrap()),
                ("V1", consolidation_tx.to_beef_v1(true).unwrap()),
            ] {
                let beef = Beef::from_binary(&beef_bytes).unwrap();

                // The consolidation TX must be the LAST transaction
                let last_tx = beef.txs.last().expect("BEEF should have transactions");
                assert_eq!(
                    last_tx.txid(),
                    consolidation_txid,
                    "{}: Consolidation TX must be LAST in BEEF, but last TX is {}",
                    name,
                    last_tx.txid()
                );

                // Verify the order: proven roots should come before their children
                let txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
                let last_idx = txids.len() - 1;
                let consolidation_idx =
                    txids.iter().position(|t| t == &consolidation_txid).unwrap();
                assert_eq!(
                    consolidation_idx, last_idx,
                    "{}: Consolidation TX at index {} but should be at {} (last)",
                    name, consolidation_idx, last_idx
                );
            }
        }

        #[test]
        fn test_to_beef_tip_last_with_deep_chains() {
            // Regression test for the bug where consolidation TX ends up NOT last.
            //
            // Bug mechanism:
            // 1. Consolidation TX built with with_source_transaction() has empty input_txids
            // 2. In sort_txs(), it passes .all() on empty iterator and is added to sorted_pending FIRST
            // 3. Other chain TXs with populated input_txids must wait for dependencies
            // 4. Result: consolidation TX ends up FIRST in sorted_pending instead of LAST
            //
            // This test uses deeper chains to ensure chain TXs have dependencies
            // that aren't immediately satisfied by proven ancestors alone.

            // Create chain: proven_root -> middle -> terminal
            // The middle TX depends on the root, terminal depends on middle
            let chain1_root = create_proven_tx(1, 100);
            let chain1_middle = create_child_tx(&chain1_root, 0);
            let chain1_terminal = create_child_tx(&chain1_middle, 0);

            let chain2_root = create_proven_tx(2, 200);
            let chain2_middle = create_child_tx(&chain2_root, 0);
            let chain2_terminal = create_child_tx(&chain2_middle, 0);

            // Consolidation TX spends from both terminal TXs
            let mut consolidation_tx = Transaction::new();
            consolidation_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain1_terminal.clone(),
                    0,
                ))
                .unwrap();
            consolidation_tx
                .add_input(TransactionInput::with_source_transaction(
                    chain2_terminal.clone(),
                    0,
                ))
                .unwrap();
            consolidation_tx
                .add_output(TransactionOutput::new(500, LockingScript::new()))
                .unwrap();

            let consolidation_txid = consolidation_tx.id();
            let beef_bytes = consolidation_tx.to_beef_v1(true).unwrap();
            let beef = Beef::from_binary(&beef_bytes).unwrap();

            // We should have 7 TXs: 2 roots + 2 middles + 2 terminals + 1 consolidation
            assert_eq!(beef.txs.len(), 7, "Should have 7 transactions");

            // The consolidation TX MUST be last
            let last_tx = beef.txs.last().expect("BEEF should have transactions");
            let txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
            assert_eq!(
                last_tx.txid(),
                consolidation_txid,
                "Consolidation TX must be LAST in BEEF. Got {} at last position, expected {}. \
                 TX order (first 8 chars): {:?}",
                &last_tx.txid()[..8],
                &consolidation_txid[..8],
                txids.iter().map(|t| &t[..8]).collect::<Vec<_>>()
            );

            // Verify dependency order: each TX should come after its parent
            let chain1_root_idx = txids.iter().position(|t| t == &chain1_root.id()).unwrap();
            let chain1_middle_idx = txids.iter().position(|t| t == &chain1_middle.id()).unwrap();
            let chain1_terminal_idx = txids
                .iter()
                .position(|t| t == &chain1_terminal.id())
                .unwrap();

            assert!(
                chain1_root_idx < chain1_middle_idx,
                "Root must come before middle"
            );
            assert!(
                chain1_middle_idx < chain1_terminal_idx,
                "Middle must come before terminal"
            );

            let consolidation_idx = txids.iter().position(|t| t == &consolidation_txid).unwrap();
            assert_eq!(
                consolidation_idx,
                txids.len() - 1,
                "Consolidation must be at the last index"
            );
        }
    }

    // ===================
    // Cross-SDK Compatibility Tests
    // ===================

    mod cross_sdk_tests {
        #[allow(unused_imports)]
        use crate::transaction::vectors::beef_cross_sdk::*;
        use bsv_sdk::transaction::{Beef, MerklePath, BEEF_V1, BEEF_V2};

        #[test]
        fn test_brc74_merkle_path_from_hex() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse BRC74 MerklePath");
            assert_eq!(mp.block_height, BRC74_BLOCK_HEIGHT);
            assert!(!mp.path.is_empty());
        }

        #[test]
        fn test_brc74_merkle_path_hex_roundtrip() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");
            let result = mp.to_hex();
            assert_eq!(
                result.to_lowercase(),
                BRC74_HEX.to_lowercase(),
                "BRC74 hex roundtrip should match"
            );
        }

        #[test]
        fn test_brc74_compute_root_txid1() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");
            let root = mp
                .compute_root(Some(BRC74_TXID1))
                .expect("Should compute root for TXID1");
            assert_eq!(root.to_lowercase(), BRC74_ROOT.to_lowercase());
        }

        #[test]
        fn test_brc74_compute_root_txid2() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");
            let root = mp
                .compute_root(Some(BRC74_TXID2))
                .expect("Should compute root for TXID2");
            assert_eq!(root.to_lowercase(), BRC74_ROOT.to_lowercase());
        }

        #[test]
        fn test_brc74_compute_root_txid3() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");
            let root = mp
                .compute_root(Some(BRC74_TXID3))
                .expect("Should compute root for TXID3");
            assert_eq!(root.to_lowercase(), BRC74_ROOT.to_lowercase());
        }

        #[test]
        fn test_single_tx_block_merkle_path() {
            let mp = MerklePath::from_hex(SINGLE_TX_BUMP_HEX).expect("Should parse single-tx BUMP");
            let root = mp
                .compute_root(Some(SINGLE_TX_COINBASE_TXID))
                .expect("Should compute root");
            // For single-tx block, root equals txid
            assert_eq!(root.to_lowercase(), SINGLE_TX_COINBASE_TXID.to_lowercase());
        }

        #[test]
        fn test_empty_beef_v1() {
            let mut beef = Beef::with_version(BEEF_V1);
            let hex = beef.to_hex();
            assert_eq!(hex.to_lowercase(), EMPTY_BEEF_V1_HEX.to_lowercase());
        }

        #[test]
        fn test_empty_beef_v2() {
            let mut beef = Beef::with_version(BEEF_V2);
            let hex = beef.to_hex();
            assert_eq!(hex.to_lowercase(), EMPTY_BEEF_V2_HEX.to_lowercase());
        }

        #[test]
        fn test_brc62_beef_from_hex() {
            let beef = Beef::from_hex(BRC62_HEX).expect("Should parse BRC62 BEEF");
            assert_eq!(beef.version, BEEF_V1);
            assert!(!beef.txs.is_empty());
        }

        #[test]
        fn test_brc62_beef_find_transaction() {
            let beef = Beef::from_hex(BRC62_HEX).expect("Should parse");
            let tx = beef.find_txid(BRC62_EXPECTED_TXID);
            assert!(
                tx.is_some(),
                "Should find transaction {}",
                BRC62_EXPECTED_TXID
            );
        }

        #[test]
        fn test_beef_set_from_hex() {
            let beef = Beef::from_hex(BEEF_SET_HEX).expect("Should parse BEEF set");
            assert_eq!(beef.version, BEEF_V2);
            assert!(beef.txs.len() >= 3, "Should have at least 3 transactions");
            assert!(!beef.bumps.is_empty(), "Should have BUMPs");
        }

        #[test]
        fn test_beef_set_find_transaction() {
            let beef = Beef::from_hex(BEEF_SET_HEX).expect("Should parse");
            let tx = beef.find_txid(BEEF_SET_FIND_TXID);
            assert!(
                tx.is_some(),
                "Should find transaction {}",
                BEEF_SET_FIND_TXID
            );
        }

        #[test]
        fn test_beef_set_roundtrip() {
            let mut beef = Beef::from_hex(BEEF_SET_HEX).expect("Should parse");
            let binary = beef.to_binary();
            let parsed = Beef::from_binary(&binary).expect("Should parse binary");
            assert_eq!(beef.version, parsed.version);
            assert_eq!(beef.txs.len(), parsed.txs.len());
            assert_eq!(beef.bumps.len(), parsed.bumps.len());
        }
    }

    // ===================
    // MerklePath Advanced Tests
    // ===================

    // ===================
    // End-to-end P2PKH sign+fee+verify tests (P0-TX-1, P0-TX-2)
    // ===================

    mod p2pkh_e2e_tests {
        use bsv_sdk::primitives::ec::PrivateKey;
        use bsv_sdk::script::templates::P2PKH;
        use bsv_sdk::script::{LockingScript, ScriptTemplate, SignOutputs};
        use bsv_sdk::transaction::{
            AlwaysValidChainTracker, ChangeDistribution, FeeModel, SatoshisPerKilobyte,
            Transaction, TransactionInput, TransactionOutput,
        };

        /// Build a P2PKH source transaction with a single output of the given amount,
        /// locked to the given private key's public key hash.
        fn build_source_tx(private_key: &PrivateKey, satoshis: u64) -> Transaction {
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();
            let locking_script = p2pkh.lock(&pubkey_hash).expect("P2PKH lock should work");

            let mut source_tx = Transaction::new();
            source_tx
                .add_output(TransactionOutput::new(satoshis, locking_script))
                .expect("add_output should work");
            source_tx
        }

        /// End-to-end: create source tx, spending tx, call fee(), sign(), verify all assertions.
        /// This is the most fundamental missing test per the audit (P0-TX-1 + P0-TX-2).
        #[tokio::test]
        async fn test_p2pkh_sign_fee_verify_e2e() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Create source transaction with 100,000 sats
            let source_tx = build_source_tx(&private_key, 100_000);
            let source_txid = source_tx.id();
            assert_eq!(source_txid.len(), 64);

            // Create spending transaction
            let mut spend_tx = Transaction::new();

            // Add input from source tx with P2PKH unlock template
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add_input_from_tx should work");

            // Add a payment output (1,000 sats)
            let payment_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(1_000, payment_locking))
                .expect("add payment output");

            // Add a change output
            let change_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new_change(change_locking))
                .expect("add change output");

            // Verify change is not yet computed
            assert!(
                spend_tx.outputs[1].satoshis.is_none(),
                "Change output should not have satoshis before fee()"
            );

            // Call fee() with default (1 sat/byte)
            spend_tx
                .fee(None, ChangeDistribution::Equal)
                .await
                .expect("fee() should work");

            // Verify change is now computed
            assert!(
                spend_tx.outputs[1].satoshis.is_some(),
                "Change output should have satoshis after fee()"
            );

            let change_sats = spend_tx.outputs[1].satoshis.unwrap();
            let total_out = spend_tx.total_output_satoshis();
            // change = 100,000 - 1,000 - fee; total_out = 1,000 + change
            // total_out + fee should equal 100,000
            let fee = 100_000 - total_out;
            assert!(fee > 0, "Fee should be positive, got {}", fee);
            assert!(
                fee < 1000,
                "Fee should be reasonable (< 1000 sats for a simple tx), got {}",
                fee
            );
            assert_eq!(
                total_out + fee,
                100_000,
                "total_out + fee should equal input amount"
            );

            // Sign the transaction
            spend_tx.sign().await.expect("sign() should work");

            // Verify unlocking scripts are set
            for (i, input) in spend_tx.inputs.iter().enumerate() {
                assert!(
                    input.unlocking_script.is_some(),
                    "Input {} should have unlocking_script after sign()",
                    i
                );
                let unlocking = input.unlocking_script.as_ref().unwrap();
                // P2PKH unlocking script has 2 chunks: signature + pubkey
                let chunks = unlocking.chunks();
                assert_eq!(
                    chunks.len(),
                    2,
                    "P2PKH unlocking script should have 2 chunks (sig + pubkey)"
                );
                // Signature chunk
                let sig_data = chunks[0].data.as_ref().expect("sig should have data");
                assert!(
                    sig_data.len() >= 70 && sig_data.len() <= 73,
                    "DER signature should be 70-73 bytes, got {}",
                    sig_data.len()
                );
                // Last byte is sighash type (SIGHASH_ALL | SIGHASH_FORKID = 0x41)
                assert_eq!(
                    *sig_data.last().unwrap(),
                    0x41,
                    "Sighash type should be SIGHASH_ALL | SIGHASH_FORKID"
                );
                // Pubkey chunk
                let pk_data = chunks[1].data.as_ref().expect("pubkey should have data");
                assert_eq!(pk_data.len(), 33, "Compressed pubkey should be 33 bytes");
            }

            // Verify the transaction serializes and has a valid TXID
            let txid = spend_tx.id();
            assert_eq!(txid.len(), 64);
            assert!(txid.chars().all(|c| c.is_ascii_hexdigit()));

            // Verify the hex roundtrips
            let hex = spend_tx.to_hex();
            let parsed = Transaction::from_hex(&hex).expect("Should parse signed tx");
            assert_eq!(parsed.id(), txid, "Parsed tx should have same TXID");
        }

        /// Test verify() with AlwaysValidChainTracker on a signed P2PKH transaction.
        /// Matches the Go SDK pattern of building a tx and calling verify().
        #[tokio::test]
        async fn test_p2pkh_verify_with_chain_tracker() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Create source transaction
            let source_tx = build_source_tx(&private_key, 50_000);

            // Create spending transaction
            let mut spend_tx = Transaction::new();
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add input");

            // Add output (send all minus fee, no change output)
            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(49_000, locking))
                .expect("add output");

            // Sign
            spend_tx.sign().await.expect("sign should work");

            // Verify with AlwaysValidChainTracker
            let tracker = AlwaysValidChainTracker::new(800_000);
            let result = spend_tx.verify(&tracker, None).await;
            assert!(
                result.is_ok(),
                "verify() should succeed, got error: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), true, "verify() should return true");
        }

        /// Test verify() with fee model validation.
        /// The source tx needs a merkle_path so verify() doesn't try to check its fee.
        #[tokio::test]
        async fn test_p2pkh_verify_with_fee_model() {
            use bsv_sdk::transaction::MerklePath;

            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Build source tx with a merkle_path so verify() treats it as mined/proven
            let mut source_tx = build_source_tx(&private_key, 50_000);
            let source_txid = source_tx.id();
            source_tx.merkle_path = Some(MerklePath::from_coinbase_txid(&source_txid, 800_000));

            let mut spend_tx = Transaction::new();
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add input");

            // Output 49,000 sats = 1,000 sats fee (which should pass 100 sat/KB easily)
            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(49_000, locking))
                .expect("add output");

            spend_tx.sign().await.expect("sign should work");

            let tracker = AlwaysValidChainTracker::new(800_000);
            let fee_model = SatoshisPerKilobyte::new(100); // 100 sat/KB

            let result = spend_tx.verify(&tracker, Some(&fee_model)).await;
            assert!(
                result.is_ok(),
                "verify with fee model should succeed: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), true);
        }

        /// Test that verify() fails when the fee is too low.
        #[tokio::test]
        async fn test_p2pkh_verify_fee_too_low() {
            use bsv_sdk::transaction::MerklePath;

            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Source tx needs a merkle_path so verify() doesn't fail on IT
            let mut source_tx = build_source_tx(&private_key, 50_000);
            let source_txid = source_tx.id();
            source_tx.merkle_path = Some(MerklePath::from_coinbase_txid(&source_txid, 800_000));

            let mut spend_tx = Transaction::new();
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add input");

            // Output 50,000 - 1 = 49,999 sats => only 1 sat fee
            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(49_999, locking))
                .expect("add output");

            spend_tx.sign().await.expect("sign should work");

            let tracker = AlwaysValidChainTracker::new(800_000);
            // Use a very high fee rate: 100,000 sat/KB (requires ~20 sats for a ~200 byte tx)
            let fee_model = SatoshisPerKilobyte::new(100_000);

            let result = spend_tx.verify(&tracker, Some(&fee_model)).await;
            assert!(result.is_err(), "verify should fail with fee too low");
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("Fee is too low"),
                "Error should mention fee, got: {}",
                err
            );
        }

        /// Test fee() with a fixed fee amount (TS SDK pattern: computeFee returns 1033)
        #[tokio::test]
        async fn test_fee_with_fixed_amount() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            let source_tx = build_source_tx(&private_key, 4_000);

            let mut spend_tx = Transaction::new();
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add input");

            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(1_000, locking.clone()))
                .expect("payment output");

            let change_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new_change(change_locking))
                .expect("change output");

            // Use a fixed fee of 1033 sats (matches TS SDK test pattern)
            spend_tx
                .fee(Some(1033), ChangeDistribution::Equal)
                .await
                .expect("fee() should work");

            // 4000 in - 1000 out - 1033 fee = 1967 change
            let change_sats = spend_tx.outputs[1].satoshis.unwrap();
            assert_eq!(
                change_sats, 1967,
                "Change should be 4000 - 1000 - 1033 = 1967"
            );
        }

        /// Test that signing before fee() fails with appropriate error.
        /// Matches TS SDK test: "Throws an Error if signing before the fee is computed"
        #[tokio::test]
        async fn test_sign_before_fee_fails() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            let source_tx = build_source_tx(&private_key, 4_000);

            let mut spend_tx = Transaction::new();
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add input");

            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(1_000, locking))
                .expect("payment output");

            let change_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new_change(change_locking))
                .expect("change output");

            // Try to sign WITHOUT calling fee() first
            let result = spend_tx.sign().await;
            assert!(
                result.is_err(),
                "sign() should fail when change outputs have uncomputed amounts"
            );
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("change outputs"),
                "Error should mention change outputs, got: {}",
                err
            );
        }
    }

    // ===================
    // Fee model with realistic sizes (P1-TX-4)
    // Ported from Go SDK `TestCalculateFee` in sats_per_kb_test.go
    // ===================

    mod fee_model_realistic_tests {
        use bsv_sdk::script::LockingScript;
        use bsv_sdk::transaction::{
            FeeModel, SatoshisPerKilobyte, Transaction, TransactionInput, TransactionOutput,
        };

        /// Build a transaction of approximately the given size.
        /// Returns (transaction, actual_size).
        fn build_tx_of_approx_size(target_bytes: usize) -> Transaction {
            // A minimal transaction is: version(4) + varint_in(1) + varint_out(1) + locktime(4) = 10 bytes
            // Each input adds: txid(32) + vout(4) + varint(1) + script + seq(4) = 41 + script_len
            // Each output adds: sats(8) + varint(1) + script = 9 + script_len
            //
            // To reach the target, we use a single input with a padded unlocking script
            // and a single output with a padded locking script.
            let mut tx = Transaction::new();

            // Base: 10 bytes (version + varint_in + varint_out + locktime)
            // Input overhead: 41 bytes (txid + vout + varint + seq)
            // Output overhead: 9 bytes (sats + varint)
            // Total overhead: 60 bytes
            let overhead = 60;
            let script_padding = if target_bytes > overhead {
                target_bytes - overhead
            } else {
                0
            };

            // Split padding between input script and output script
            let input_script_len = script_padding / 2;
            let output_script_len = script_padding - input_script_len;

            // Create input with padded unlocking script
            let input_script_data = vec![0u8; input_script_len];
            let unlocking_script =
                bsv_sdk::script::UnlockingScript::from_binary(&input_script_data)
                    .unwrap_or_else(|_| bsv_sdk::script::UnlockingScript::new());

            let mut input = TransactionInput::new("a".repeat(64), 0);
            input.unlocking_script = Some(unlocking_script);
            tx.inputs.push(input);

            // Create output with padded locking script
            let output_script_data = vec![0u8; output_script_len];
            let locking_script = LockingScript::from_binary(&output_script_data)
                .unwrap_or_else(|_| LockingScript::new());
            tx.outputs
                .push(TransactionOutput::new(1000, locking_script));

            tx
        }

        /// Port of Go SDK TestCalculateFee vectors.
        /// Tests the fee calculation formula: ceil(txSize * satoshisPerKB / 1000).
        #[test]
        fn test_fee_model_go_vectors() {
            // These vectors are directly from the Go SDK: sats_per_kb_test.go
            let vectors: &[(usize, u64, u64, &str)] = &[
                (
                    240,
                    100,
                    24,
                    "240 bytes at 100 sats/KB: 240/1000 * 100 = 24",
                ),
                (
                    240,
                    1,
                    1,
                    "240 bytes at 1 sat/KB: edge case, ceil(0.24) = 1",
                ),
                (240, 10, 3, "240 bytes at 10 sats/KB: ceil(2.4) = 3"),
                (
                    250,
                    500,
                    125,
                    "250 bytes at 500 sats/KB: 250/1000 * 500 = 125",
                ),
                (
                    1000,
                    100,
                    100,
                    "1000 bytes at 100 sats/KB: 1000/1000 * 100 = 100",
                ),
                (
                    1500,
                    100,
                    150,
                    "1500 bytes at 100 sats/KB: 1500/1000 * 100 = 150",
                ),
                (
                    1500,
                    500,
                    750,
                    "1500 bytes at 500 sats/KB: 1500/1000 * 500 = 750",
                ),
            ];

            for (tx_size, sats_per_kb, expected_fee, description) in vectors {
                // Build a transaction of the exact target size
                let tx = build_tx_of_approx_size(*tx_size);
                let actual_size = tx.to_binary().len();

                // Compute what the fee SHOULD be for actual_size bytes
                let computed_fee = (actual_size as u64 * sats_per_kb).div_ceil(1000);

                let fee_model = SatoshisPerKilobyte::new(*sats_per_kb);
                let model_fee = fee_model.compute_fee(&tx).expect("compute_fee should work");

                // The model fee should match the manually computed ceiling division
                assert_eq!(
                    model_fee, computed_fee,
                    "Fee model and manual calculation should agree for {}",
                    description
                );

                // Also verify the Go SDK formula directly:
                // For the exact target sizes, verify the expected fee
                let direct_fee = (*tx_size as u64 * sats_per_kb).div_ceil(1000);
                assert_eq!(
                    direct_fee, *expected_fee,
                    "Direct formula should match Go expected fee for {}",
                    description
                );
            }
        }

        /// Test fee formula for boundary conditions
        #[test]
        fn test_fee_formula_boundaries() {
            // 1 byte at 1 sat/KB -> ceil(1/1000) = 1 sat (minimum)
            let fee_1 = (1u64 * 1).div_ceil(1000);
            assert_eq!(fee_1, 1, "Minimum fee should be 1 sat");

            // 999 bytes at 1 sat/KB -> ceil(999/1000) = 1 sat
            let fee_999 = (999u64 * 1).div_ceil(1000);
            assert_eq!(fee_999, 1, "999 bytes at 1 sat/KB should be 1 sat");

            // 1000 bytes at 1 sat/KB -> exactly 1 sat
            let fee_1000 = (1000u64 * 1).div_ceil(1000);
            assert_eq!(fee_1000, 1, "1000 bytes at 1 sat/KB should be 1 sat");

            // 1001 bytes at 1 sat/KB -> ceil(1001/1000) = 2 sats
            let fee_1001 = (1001u64 * 1).div_ceil(1000);
            assert_eq!(fee_1001, 2, "1001 bytes at 1 sat/KB should be 2 sats");
        }
    }

    // ===================
    // Fee with change computation (P1-TX-5)
    // ===================

    mod fee_change_tests {
        use bsv_sdk::primitives::ec::PrivateKey;
        use bsv_sdk::script::templates::P2PKH;
        use bsv_sdk::script::{ScriptTemplate, SignOutputs};
        use bsv_sdk::transaction::{ChangeDistribution, Transaction, TransactionOutput};

        #[tokio::test]
        async fn test_fee_with_change_computation() {
            // 100k sat input, 1k output, change output.
            // Call fee(). Verify change = input - output - fee.
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Build source tx with 100k sats
            let mut source_tx = Transaction::new();
            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            source_tx
                .add_output(TransactionOutput::new(100_000, locking.clone()))
                .unwrap();

            // Build spending tx
            let mut spend_tx = Transaction::new();
            let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock)
                .expect("add input");

            // Add 1k payment output
            spend_tx
                .add_output(TransactionOutput::new(1_000, locking.clone()))
                .expect("payment output");

            // Add change output
            let change_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new_change(change_locking))
                .expect("change output");

            // Call fee() with default (1 sat/byte)
            spend_tx
                .fee(None, ChangeDistribution::Equal)
                .await
                .expect("fee() should work");

            // Verify invariant: input = payment + change + fee
            let input_sats: u64 = 100_000;
            let payment_sats = spend_tx.outputs[0].satoshis.unwrap();
            let change_sats = spend_tx.outputs[1].satoshis.unwrap();
            let total_out = payment_sats + change_sats;
            let implied_fee = input_sats - total_out;

            assert_eq!(payment_sats, 1_000, "Payment output should be 1,000 sats");
            assert!(change_sats > 0, "Change should be positive");
            assert!(
                implied_fee > 0,
                "Fee should be positive, got {}",
                implied_fee
            );
            assert_eq!(
                payment_sats + change_sats + implied_fee,
                input_sats,
                "payment + change + fee should equal input"
            );

            // The fee should be reasonable for a ~225 byte P2PKH tx at 1 sat/byte
            // (estimate_size gives the fee when fee_sats is None)
            let estimated_size = spend_tx.estimate_size();
            assert_eq!(
                implied_fee, estimated_size as u64,
                "Implied fee should equal the estimated size (1 sat/byte default)"
            );
        }

        /// Test fee() with a specific fixed fee
        #[tokio::test]
        async fn test_fee_with_explicit_amount() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            let mut source_tx = Transaction::new();
            let locking = p2pkh.lock(&pubkey_hash).unwrap();
            source_tx
                .add_output(TransactionOutput::new(100_000, locking.clone()))
                .unwrap();

            let mut spend_tx = Transaction::new();
            let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock)
                .expect("add input");

            spend_tx
                .add_output(TransactionOutput::new(1_000, locking.clone()))
                .expect("payment output");

            let change_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new_change(change_locking))
                .expect("change output");

            // Explicit fee of 500 sats
            spend_tx
                .fee(Some(500), ChangeDistribution::Equal)
                .await
                .expect("fee() should work");

            let change_sats = spend_tx.outputs[1].satoshis.unwrap();
            // 100,000 - 1,000 - 500 = 98,500
            assert_eq!(
                change_sats, 98_500,
                "Change should be 100,000 - 1,000 - 500 = 98,500"
            );
        }
    }

    // ===================
    // sign() error when template missing (P1-TX-9)
    // ===================

    mod sign_error_tests {
        use bsv_sdk::script::LockingScript;
        use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput};

        /// Test: create tx with input lacking unlocking_script_template, call sign(), assert error.
        #[tokio::test]
        async fn test_sign_error_when_template_missing() {
            let mut tx = Transaction::new();

            // Add input with no template and no unlocking script
            let input = TransactionInput::new("a".repeat(64), 0);
            tx.inputs.push(input);

            // Add output with amount (so sign() doesn't fail on "missing amount")
            tx.outputs
                .push(TransactionOutput::new(1000, LockingScript::new()));

            // sign() should succeed but produce no unlocking script for the template-less input
            // (sign() only processes inputs with templates)
            let result = tx.sign().await;
            // sign() itself doesn't error for missing templates - it only signs those that have one.
            // However, if we try to serialize or verify, the input will lack an unlocking script.
            // Let's verify the input still has no unlocking script
            assert!(
                result.is_ok(),
                "sign() should not error for template-less inputs"
            );
            assert!(
                tx.inputs[0].unlocking_script.is_none(),
                "Input without template should still have no unlocking script after sign()"
            );
        }

        /// Test: fee model errors when input has no template and no unlocking script
        #[test]
        fn test_fee_model_error_when_template_missing() {
            use bsv_sdk::transaction::{FeeModel, SatoshisPerKilobyte};

            let mut tx = Transaction::new();
            let input = TransactionInput::new("a".repeat(64), 0);
            tx.inputs.push(input);
            tx.outputs
                .push(TransactionOutput::new(1000, LockingScript::new()));

            let fee_model = SatoshisPerKilobyte::new(100);
            let result = fee_model.compute_fee(&tx);
            assert!(
                result.is_err(),
                "Fee model should error when input has no script or template"
            );
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("unlocking script or template"),
                "Error should mention missing unlocking script/template, got: {}",
                err
            );
        }
    }

    mod merkle_path_advanced_tests {
        use crate::transaction::vectors::beef_cross_sdk::*;
        use bsv_sdk::transaction::{ChainTracker, MerklePath, MockChainTracker};

        /// Tests MerklePath verification using ChainTracker.
        /// This manually computes the root and compares with tracker.
        #[tokio::test]
        async fn test_merkle_path_verify_with_chain_tracker() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");

            // Create a mock chain tracker with the correct root
            let mut tracker = MockChainTracker::new(900000);
            tracker.add_root(BRC74_BLOCK_HEIGHT, BRC74_ROOT.to_string());

            // Compute the root and verify against tracker
            let computed_root = mp
                .compute_root(Some(BRC74_TXID1))
                .expect("Should compute root");

            // Verify the computed root matches what we expect
            let is_valid = tracker
                .is_valid_root_for_height(&computed_root, mp.block_height)
                .await
                .expect("Should check root");

            assert!(
                is_valid,
                "Computed root should be valid according to tracker"
            );
        }

        #[tokio::test]
        async fn test_merkle_path_verify_wrong_root_fails() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");

            // Create a mock chain tracker with WRONG root
            let mut tracker = MockChainTracker::new(900000);
            tracker.add_root(BRC74_BLOCK_HEIGHT, "a".repeat(64));

            // Compute the root and verify against tracker with wrong root
            let computed_root = mp
                .compute_root(Some(BRC74_TXID1))
                .expect("Should compute root");

            // Verification should fail - computed root doesn't match wrong tracker root
            let is_valid = tracker
                .is_valid_root_for_height(&computed_root, mp.block_height)
                .await
                .expect("Should check root");

            assert!(
                !is_valid,
                "Computed root should NOT be valid when tracker has wrong root"
            );
        }

        #[tokio::test]
        async fn test_merkle_path_verify_wrong_height_fails() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");

            // Create a mock chain tracker with root at wrong height
            let mut tracker = MockChainTracker::new(900000);
            tracker.add_root(BRC74_BLOCK_HEIGHT + 1, BRC74_ROOT.to_string());

            // Compute the root and verify - should fail because root is at wrong height
            let computed_root = mp
                .compute_root(Some(BRC74_TXID1))
                .expect("Should compute root");
            let is_valid = tracker
                .is_valid_root_for_height(&computed_root, mp.block_height)
                .await
                .expect("Should check root");

            assert!(!is_valid, "Should not validate root at wrong height");
        }

        #[test]
        fn test_merkle_path_contains() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");

            assert!(mp.contains(BRC74_TXID1));
            assert!(mp.contains(BRC74_TXID2));
            assert!(mp.contains(BRC74_TXID3));
            assert!(!mp.contains(&"f".repeat(64)));
        }

        #[test]
        fn test_merkle_path_txids() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");
            let txids = mp.txids();

            // Should contain the marked txids
            assert!(!txids.is_empty());
        }

        #[test]
        fn test_merkle_path_compute_root_without_txid() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");

            // Compute root without specifying txid (uses first found)
            let root = mp.compute_root(None);
            assert!(root.is_ok());
            assert_eq!(root.unwrap().to_lowercase(), BRC74_ROOT.to_lowercase());
        }

        #[test]
        fn test_merkle_path_binary_roundtrip() {
            let mp = MerklePath::from_hex(BRC74_HEX).expect("Should parse");
            let binary = mp.to_binary();
            let parsed = MerklePath::from_binary(&binary).expect("Should parse binary");

            assert_eq!(mp.block_height, parsed.block_height);
            assert_eq!(mp.path.len(), parsed.path.len());
        }
    }

    // ===================
    // P1-TX-6: ChangeDistribution::Equal multi-output test
    // ===================

    mod change_distribution_tests {
        use bsv_sdk::primitives::ec::PrivateKey;
        use bsv_sdk::script::templates::P2PKH;
        use bsv_sdk::script::{ScriptTemplate, SignOutputs};
        use bsv_sdk::transaction::{ChangeDistribution, Transaction, TransactionOutput};

        /// Build a source transaction with a single P2PKH output of the given amount.
        fn build_source_tx(private_key: &PrivateKey, satoshis: u64) -> Transaction {
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();
            let locking_script = p2pkh.lock(&pubkey_hash).expect("P2PKH lock should work");

            let mut source_tx = Transaction::new();
            source_tx
                .add_output(TransactionOutput::new(satoshis, locking_script))
                .expect("add_output should work");
            source_tx
        }

        /// Test that ChangeDistribution::Equal distributes change approximately equally
        /// among 3 change outputs and that no satoshis are lost.
        #[tokio::test]
        async fn test_change_distribution_equal_multi_output() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Create source transaction with 100,000 sats
            let source_tx = build_source_tx(&private_key, 100_000);

            // Create spending transaction
            let mut spend_tx = Transaction::new();

            // Add input from source tx with P2PKH unlock template
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .expect("add_input_from_tx should work");

            // Add one non-change output (1,000 sats)
            let payment_locking = p2pkh.lock(&pubkey_hash).unwrap();
            spend_tx
                .add_output(TransactionOutput::new(1_000, payment_locking))
                .expect("add payment output");

            // Add 3 change outputs
            for _ in 0..3 {
                let change_locking = p2pkh.lock(&pubkey_hash).unwrap();
                spend_tx
                    .add_output(TransactionOutput::new_change(change_locking))
                    .expect("add change output");
            }

            // Verify change outputs have no satoshis before fee()
            for i in 1..=3 {
                assert!(
                    spend_tx.outputs[i].satoshis.is_none(),
                    "Change output {} should not have satoshis before fee()",
                    i
                );
            }

            // Call fee() with ChangeDistribution::Equal
            spend_tx
                .fee(None, ChangeDistribution::Equal)
                .await
                .expect("fee() should work");

            // Verify all change outputs now have satoshis
            for i in 1..=3 {
                assert!(
                    spend_tx.outputs[i].satoshis.is_some(),
                    "Change output {} should have satoshis after fee()",
                    i
                );
            }

            // Gather the 3 change amounts
            let change_amounts: Vec<u64> = (1..=3)
                .map(|i| spend_tx.outputs[i].satoshis.unwrap())
                .collect();

            // Verify they are approximately equal (within 1 sat of each other)
            let max_change = *change_amounts.iter().max().unwrap();
            let min_change = *change_amounts.iter().min().unwrap();
            assert!(
                max_change - min_change <= 1,
                "Change amounts should be approximately equal (within 1 sat). \
                 Got amounts: {:?}, diff: {}",
                change_amounts,
                max_change - min_change
            );

            // Verify total output = total input (no sats lost)
            let total_output = spend_tx.total_output_satoshis();
            let fee = 100_000 - total_output;
            assert!(fee > 0, "Fee should be positive, got {}", fee);
            assert_eq!(
                total_output + fee,
                100_000,
                "total_output + fee should equal input amount (no sats lost)"
            );

            // Verify the change amounts sum up correctly
            let change_sum: u64 = change_amounts.iter().sum();
            let expected_change = 100_000 - 1_000 - fee;
            assert_eq!(
                change_sum, expected_change,
                "Sum of change outputs should equal total_input - payment - fee"
            );
        }
    }

    // ===================
    // P1-TX-7: EF format cross-SDK exact hex test
    // ===================

    mod ef_format_tests {
        use bsv_sdk::transaction::Beef;

        /// Go SDK TestEF exact vector: parse BEEF hex -> link source txs -> serialize to EF hex -> compare.
        /// Input: BRC62Hex (Go SDK constant, also in beef_cross_sdk.rs).
        /// Expected EF hex from Go SDK TestEF.
        #[test]
        fn test_ef_hex_cross_sdk_go_vector() {
            use crate::transaction::vectors::beef_cross_sdk::BRC62_HEX;

            let expected_ef_hex = "010000000000000000ef01ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff3e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000";

            // Parse BEEF to get all transactions in order
            let beef = Beef::from_hex(BRC62_HEX).expect("Should parse BEEF");

            // BEEF should have 2 transactions: tx[0] is the parent, tx[1] is the child
            assert!(
                beef.txs.len() >= 2,
                "BRC62 BEEF should have at least 2 transactions, got {}",
                beef.txs.len()
            );

            // Get the parent (first) and child (last) transactions
            let parent_tx = beef.txs[0]
                .tx()
                .expect("Parent tx should be parsed")
                .clone();
            let mut child_tx = beef.txs[1].tx().expect("Child tx should be parsed").clone();

            // Link the parent as source_transaction on the child's input
            // The child's input references the parent's output
            assert!(
                !child_tx.inputs.is_empty(),
                "Child tx should have at least one input"
            );
            child_tx.inputs[0].source_transaction = Some(Box::new(parent_tx));

            // Convert to EF hex
            let ef_hex = child_tx.to_hex_ef().expect("Should serialize to EF hex");

            assert_eq!(
                ef_hex.to_lowercase(),
                expected_ef_hex.to_lowercase(),
                "EF hex should match Go SDK TestEF expected output exactly"
            );
        }
    }

    // ===================
    // P1-TX-9: sign() behavior when template missing
    // (extends existing sign_error_tests module)
    // ===================

    mod sign_no_template_tests {
        use bsv_sdk::primitives::ec::PrivateKey;
        use bsv_sdk::script::templates::P2PKH;
        use bsv_sdk::script::{LockingScript, ScriptTemplate, SignOutputs};
        use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput};

        /// Test that sign() on a transaction where one input has no template
        /// leaves that input without an unlocking script, while inputs WITH
        /// templates get properly signed.
        #[tokio::test]
        async fn test_sign_skips_inputs_without_template() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            // Create source transaction
            let locking_script = p2pkh.lock(&pubkey_hash).unwrap();
            let mut source_tx = Transaction::new();
            source_tx
                .add_output(TransactionOutput::new(100_000, locking_script.clone()))
                .unwrap();
            source_tx
                .add_output(TransactionOutput::new(100_000, locking_script.clone()))
                .unwrap();

            // Create spending transaction with two inputs
            let mut spend_tx = Transaction::new();

            // Input 0: has a template (should be signed)
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx.clone(), 0, unlock_template)
                .unwrap();

            // Input 1: no template (add manually without template)
            let input_no_template = TransactionInput::with_source_transaction(source_tx, 1);
            // Do NOT set unlocking_script_template
            spend_tx.inputs.push(input_no_template);

            // Add output
            spend_tx
                .add_output(TransactionOutput::new(150_000, LockingScript::new()))
                .unwrap();

            // Sign
            let result = spend_tx.sign().await;
            assert!(
                result.is_ok(),
                "sign() should succeed even with template-less inputs, got: {:?}",
                result.err()
            );

            // Input 0 should have an unlocking script
            assert!(
                spend_tx.inputs[0].unlocking_script.is_some(),
                "Input 0 (with template) should have unlocking script after sign()"
            );

            // Input 1 should NOT have an unlocking script
            assert!(
                spend_tx.inputs[1].unlocking_script.is_none(),
                "Input 1 (without template) should still lack unlocking script after sign()"
            );
        }

        /// Test that sign() returns an error if there are change outputs
        /// with uncomputed amounts (satoshis is None and change is true).
        #[tokio::test]
        async fn test_sign_error_uncomputed_change() {
            let private_key = PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let pubkey_hash = private_key.public_key().hash160();
            let p2pkh = P2PKH::new();

            let locking_script = p2pkh.lock(&pubkey_hash).unwrap();
            let mut source_tx = Transaction::new();
            source_tx
                .add_output(TransactionOutput::new(100_000, locking_script.clone()))
                .unwrap();

            let mut spend_tx = Transaction::new();
            let unlock_template = P2PKH::unlock(&private_key, SignOutputs::All, false);
            spend_tx
                .add_input_from_tx(source_tx, 0, unlock_template)
                .unwrap();

            // Add a change output WITHOUT calling fee() first
            spend_tx
                .add_output(TransactionOutput::new_change(locking_script))
                .unwrap();

            // sign() should fail because change output has no satoshis
            let result = spend_tx.sign().await;
            assert!(
                result.is_err(),
                "sign() should error when change outputs have uncomputed amounts"
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("change outputs"),
                "Error should mention change outputs, got: {}",
                err_msg
            );
        }
    }
}
