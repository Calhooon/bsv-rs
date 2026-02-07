//! Transaction JSON Serialization.
//!
//! Provides JSON serialization and deserialization for Transaction, TransactionInput,
//! and TransactionOutput, matching the Go SDK's JSON format for cross-SDK compatibility.
//!
//! The JSON format uses the following field names:
//! - Transaction: `txid`, `hex`, `inputs`, `outputs`, `version`, `lockTime`
//! - Input: `unlockingScript`, `txid`, `vout`, `sequence`
//! - Output: `satoshis`, `lockingScript`

use serde::{Deserialize, Serialize};

use super::input::TransactionInput;
use super::output::TransactionOutput;
use super::transaction::Transaction;
use crate::script::{LockingScript, UnlockingScript};
use crate::Result;

/// JSON representation of a Transaction, matching Go SDK's txJSON struct.
#[derive(Serialize, Deserialize)]
struct TxJson {
    txid: String,
    hex: String,
    inputs: Vec<InputJson>,
    outputs: Vec<OutputJson>,
    version: u32,
    #[serde(rename = "lockTime")]
    lock_time: u32,
}

/// JSON representation of a TransactionInput, matching Go SDK's inputJSON struct.
#[derive(Serialize, Deserialize)]
struct InputJson {
    #[serde(rename = "unlockingScript")]
    unlocking_script: String,
    txid: String,
    vout: u32,
    sequence: u32,
}

/// JSON representation of a TransactionOutput, matching Go SDK's outputJSON struct.
#[derive(Serialize, Deserialize)]
struct OutputJson {
    satoshis: u64,
    #[serde(rename = "lockingScript")]
    locking_script: String,
}

/// Intermediate JSON structure for deserialization that accepts optional fields.
/// This allows parsing JSON with only a `hex` field (no inputs/outputs).
#[derive(Deserialize)]
struct TxJsonOptional {
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    inputs: Option<Vec<InputJson>>,
    #[serde(default)]
    outputs: Option<Vec<OutputJson>>,
    #[serde(default)]
    version: Option<u32>,
    #[serde(rename = "lockTime", default)]
    lock_time: Option<u32>,
}

impl Transaction {
    /// Serializes this transaction to a JSON string.
    ///
    /// The JSON format matches the Go SDK's MarshalJSON output, including:
    /// - `txid`: The transaction ID (hex, reversed hash)
    /// - `hex`: The full serialized transaction as hex
    /// - `inputs`: Array of input objects with `unlockingScript`, `txid`, `vout`, `sequence`
    /// - `outputs`: Array of output objects with `satoshis`, `lockingScript`
    /// - `version`: The transaction version number
    /// - `lockTime`: The lock time
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_sdk::transaction::Transaction;
    ///
    /// let tx = Transaction::from_hex("0100000001...")?;
    /// let json = tx.to_json()?;
    /// println!("{}", json);
    /// ```
    pub fn to_json(&self) -> Result<String> {
        let tx_json = self.to_tx_json();
        serde_json::to_string(&tx_json).map_err(|e| {
            crate::Error::TransactionError(format!("JSON serialization failed: {}", e))
        })
    }

    /// Serializes this transaction to a pretty-printed JSON string.
    ///
    /// Same as `to_json()` but with indented formatting for readability.
    pub fn to_json_pretty(&self) -> Result<String> {
        let tx_json = self.to_tx_json();
        serde_json::to_string_pretty(&tx_json).map_err(|e| {
            crate::Error::TransactionError(format!("JSON serialization failed: {}", e))
        })
    }

    /// Deserializes a transaction from a JSON string.
    ///
    /// If the JSON contains a `hex` field, the transaction is parsed from the hex
    /// representation (matching Go SDK behavior). Otherwise, the transaction is
    /// reconstructed from the individual fields.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_sdk::transaction::Transaction;
    ///
    /// let json = r#"{"hex": "0100000001...", "version": 1, "lockTime": 0, ...}"#;
    /// let tx = Transaction::from_json(json)?;
    /// ```
    pub fn from_json(json: &str) -> Result<Transaction> {
        let parsed: TxJsonOptional = serde_json::from_str(json).map_err(|e| {
            crate::Error::TransactionError(format!("JSON deserialization failed: {}", e))
        })?;

        // If hex is present, reconstruct from hex (matching Go SDK behavior)
        if let Some(ref hex) = parsed.hex {
            if !hex.is_empty() {
                return Transaction::from_hex(hex);
            }
        }

        // Otherwise, build from individual fields
        let version = parsed.version.unwrap_or(1);
        let lock_time = parsed.lock_time.unwrap_or(0);

        let inputs = match parsed.inputs {
            Some(input_jsons) => {
                let mut inputs = Vec::with_capacity(input_jsons.len());
                for ij in input_jsons {
                    inputs.push(input_from_json(&ij)?);
                }
                inputs
            }
            None => Vec::new(),
        };

        let outputs = match parsed.outputs {
            Some(output_jsons) => {
                let mut outputs = Vec::with_capacity(output_jsons.len());
                for oj in output_jsons {
                    outputs.push(output_from_json(&oj)?);
                }
                outputs
            }
            None => Vec::new(),
        };

        Ok(Transaction::with_params(version, inputs, outputs, lock_time))
    }

    /// Builds the internal TxJson representation for serialization.
    fn to_tx_json(&self) -> TxJson {
        let inputs: Vec<InputJson> = self
            .inputs
            .iter()
            .map(|input| {
                let txid = input
                    .get_source_txid()
                    .unwrap_or_else(|_| "0".repeat(64));
                let unlocking_script = input
                    .unlocking_script
                    .as_ref()
                    .map(|s| s.to_hex())
                    .unwrap_or_default();
                InputJson {
                    unlocking_script,
                    txid,
                    vout: input.source_output_index,
                    sequence: input.sequence,
                }
            })
            .collect();

        let outputs: Vec<OutputJson> = self
            .outputs
            .iter()
            .map(|output| OutputJson {
                satoshis: output.satoshis.unwrap_or(0),
                locking_script: output.locking_script.to_hex(),
            })
            .collect();

        TxJson {
            txid: self.id(),
            hex: self.to_hex(),
            inputs,
            outputs,
            version: self.version,
            lock_time: self.lock_time,
        }
    }
}

/// Converts a JSON input representation to a TransactionInput.
fn input_from_json(ij: &InputJson) -> Result<TransactionInput> {
    let unlocking_script = if ij.unlocking_script.is_empty() {
        None
    } else {
        Some(UnlockingScript::from_hex(&ij.unlocking_script)?)
    };

    Ok(TransactionInput {
        source_transaction: None,
        source_txid: Some(ij.txid.clone()),
        source_output_index: ij.vout,
        unlocking_script,
        unlocking_script_template: None,
        sequence: ij.sequence,
    })
}

/// Converts a JSON output representation to a TransactionOutput.
fn output_from_json(oj: &OutputJson) -> Result<TransactionOutput> {
    let locking_script = if oj.locking_script.is_empty() {
        LockingScript::new()
    } else {
        LockingScript::from_hex(&oj.locking_script)?
    };

    Ok(TransactionOutput {
        satoshis: Some(oj.satoshis),
        locking_script,
        change: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known transaction hex from Go SDK test
    const GO_SDK_TX_HEX: &str = "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a2010000006a4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000";

    // Expected JSON from Go SDK test (TestTx_MarshallJSON)
    const GO_SDK_EXPECTED_JSON: &str = r#"{"txid":"aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d","hex":"0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a2010000006a4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000","inputs":[{"unlockingScript":"4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8","txid":"a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab","vout":1,"sequence":4294967295}],"outputs":[{"satoshis":0,"lockingScript":"006a0548656c6c6f"},{"satoshis":895,"lockingScript":"76a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac"}],"version":1,"lockTime":0}"#;

    #[test]
    fn test_tx_json_roundtrip() {
        // Parse from hex, serialize to JSON, deserialize, verify hex matches
        let tx = Transaction::from_hex(GO_SDK_TX_HEX).unwrap();
        let json = tx.to_json().unwrap();
        let tx2 = Transaction::from_json(&json).unwrap();

        assert_eq!(tx.to_hex(), tx2.to_hex());
        assert_eq!(tx.id(), tx2.id());
        assert_eq!(tx.version, tx2.version);
        assert_eq!(tx.lock_time, tx2.lock_time);
        assert_eq!(tx.inputs.len(), tx2.inputs.len());
        assert_eq!(tx.outputs.len(), tx2.outputs.len());
    }

    #[test]
    fn test_tx_json_serialize_known_tx() {
        // Serialize a known transaction and verify JSON fields match Go SDK
        let tx = Transaction::from_hex(GO_SDK_TX_HEX).unwrap();
        let json = tx.to_json().unwrap();

        assert_eq!(json, GO_SDK_EXPECTED_JSON);
    }

    #[test]
    fn test_tx_json_deserialize_known_json() {
        // Deserialize from Go SDK expected JSON and verify fields
        let tx = Transaction::from_json(GO_SDK_EXPECTED_JSON).unwrap();

        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(
            tx.id(),
            "aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d"
        );
        assert_eq!(tx.to_hex(), GO_SDK_TX_HEX);
    }

    #[test]
    fn test_tx_json_empty_transaction() {
        // Empty transaction should serialize and deserialize
        let tx = Transaction::new();
        let json = tx.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["lockTime"], 0);
        assert!(parsed["inputs"].as_array().unwrap().is_empty());
        assert!(parsed["outputs"].as_array().unwrap().is_empty());
        assert!(parsed["txid"].as_str().unwrap().len() == 64);
        assert!(!parsed["hex"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_tx_json_multiple_inputs_outputs() {
        // Create a transaction with multiple inputs and outputs
        let mut tx = Transaction::new();

        // Add inputs directly (bypassing validation for test)
        tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5".to_string(),
            ),
            source_output_index: 0,
            unlocking_script: Some(UnlockingScript::from_hex("00").unwrap()),
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        });

        tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab".to_string(),
            ),
            source_output_index: 2,
            unlocking_script: Some(UnlockingScript::from_hex("5151").unwrap()),
            unlocking_script_template: None,
            sequence: 0xFFFFFFFE,
        });

        tx.outputs.push(TransactionOutput::new(
            50000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));

        tx.outputs.push(TransactionOutput::new(
            0,
            LockingScript::from_hex("006a0548656c6c6f").unwrap(),
        ));

        let json = tx.to_json().unwrap();
        let tx2 = Transaction::from_json(&json).unwrap();

        assert_eq!(tx.to_hex(), tx2.to_hex());
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);

        // Verify JSON structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let inputs = parsed["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["vout"], 0);
        assert_eq!(inputs[1]["vout"], 2);
        assert_eq!(inputs[1]["sequence"], 0xFFFFFFFEu32);

        let outputs = parsed["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0]["satoshis"], 50000);
        assert_eq!(outputs[1]["satoshis"], 0);
    }

    #[test]
    fn test_tx_json_from_hex_only() {
        // Go SDK supports deserializing from JSON with only a hex field
        let json = format!(r#"{{"hex":"{}"}}"#, GO_SDK_TX_HEX);
        let tx = Transaction::from_json(&json).unwrap();

        assert_eq!(tx.to_hex(), GO_SDK_TX_HEX);
        assert_eq!(
            tx.id(),
            "aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d"
        );
    }

    #[test]
    fn test_tx_json_from_fields_no_hex() {
        // Deserialize from JSON without a hex field (use individual fields)
        let json = r#"{
            "version": 1,
            "lockTime": 0,
            "inputs": [
                {
                    "unlockingScript": "00",
                    "txid": "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5",
                    "vout": 0,
                    "sequence": 4294967295
                }
            ],
            "outputs": [
                {
                    "satoshis": 1000,
                    "lockingScript": "76a914000000000000000000000000000000000000000088ac"
                }
            ]
        }"#;

        let tx = Transaction::from_json(json).unwrap();

        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(
            tx.inputs[0].source_txid.as_deref().unwrap(),
            "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5"
        );
        assert_eq!(tx.inputs[0].source_output_index, 0);
        assert_eq!(tx.inputs[0].sequence, 0xFFFFFFFF);
        assert_eq!(tx.outputs[0].satoshis, Some(1000));
    }

    #[test]
    fn test_tx_json_pretty_format() {
        let tx = Transaction::from_hex(GO_SDK_TX_HEX).unwrap();
        let pretty = tx.to_json_pretty().unwrap();

        // Pretty format should contain newlines and indentation
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("  "));

        // Should still round-trip correctly
        let tx2 = Transaction::from_json(&pretty).unwrap();
        assert_eq!(tx.to_hex(), tx2.to_hex());
    }

    #[test]
    fn test_tx_json_field_names_match_go_sdk() {
        // Verify exact field names match Go SDK
        let tx = Transaction::from_hex(GO_SDK_TX_HEX).unwrap();
        let json = tx.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Top-level fields
        assert!(parsed.get("txid").is_some(), "missing 'txid' field");
        assert!(parsed.get("hex").is_some(), "missing 'hex' field");
        assert!(parsed.get("inputs").is_some(), "missing 'inputs' field");
        assert!(parsed.get("outputs").is_some(), "missing 'outputs' field");
        assert!(parsed.get("version").is_some(), "missing 'version' field");
        assert!(parsed.get("lockTime").is_some(), "missing 'lockTime' field");

        // Input fields
        let input = &parsed["inputs"][0];
        assert!(
            input.get("unlockingScript").is_some(),
            "missing input 'unlockingScript' field"
        );
        assert!(input.get("txid").is_some(), "missing input 'txid' field");
        assert!(input.get("vout").is_some(), "missing input 'vout' field");
        assert!(
            input.get("sequence").is_some(),
            "missing input 'sequence' field"
        );

        // Output fields
        let output = &parsed["outputs"][0];
        assert!(
            output.get("satoshis").is_some(),
            "missing output 'satoshis' field"
        );
        assert!(
            output.get("lockingScript").is_some(),
            "missing output 'lockingScript' field"
        );
    }

    #[test]
    fn test_tx_json_invalid_json() {
        let result = Transaction::from_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_tx_json_invalid_hex() {
        let json = r#"{"hex":"not_valid_hex"}"#;
        let result = Transaction::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_tx_json_go_sdk_multi_input_vector() {
        // This is the multi-input test case from Go SDK's TestTx_MarshallJSON
        let multi_input_hex = "0100000003d5da6f960610cc65153521fd16dbe96b499143ac8d03222c13a9b97ce2dd8e3c000000006b48304502210081214df575da1e9378f1d5a29dfd6811e93466a7222fb010b7c50dd2d44d7f2e0220399bb396336d2e294049e7db009926b1b30018ac834ee0cbca20b9d99f488038412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffffd5da6f960610cc65153521fd16dbe96b499143ac8d03222c13a9b97ce2dd8e3c0200000069463043021f7059426d6aeb7d74275e52819a309b2bf903bd18b2b4d942d0e8e037681df702203f851f8a45aabfefdca5822f457609600f5d12a173adc09c6e7e2d4fdff7620a412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffffd5da6f960610cc65153521fd16dbe96b499143ac8d03222c13a9b97ce2dd8e3c720000006b483045022100e7b3837f2818fe00a05293e0f90e9005d59b0c5c8890f22bd31c36190a9b55e9022027de4b77b78139ea21b9fd30876a447bbf29662bd19d7914028c607bccd772e4412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffff01e8030000000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000";

        let tx = Transaction::from_hex(multi_input_hex).unwrap();
        let json = tx.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify the transaction structure matches Go SDK expectations
        assert_eq!(
            parsed["txid"].as_str().unwrap(),
            "41741af6fb64839c69f2385987eb3770c55c42eb6f7900fa2af9d667c42ceb20"
        );
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["lockTime"], 0);

        let inputs = parsed["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 3);

        // Verify each input's source txid and vout
        assert_eq!(
            inputs[0]["txid"].as_str().unwrap(),
            "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5"
        );
        assert_eq!(inputs[0]["vout"], 0);
        assert_eq!(inputs[0]["sequence"], 4294967295u64);

        assert_eq!(
            inputs[1]["txid"].as_str().unwrap(),
            "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5"
        );
        assert_eq!(inputs[1]["vout"], 2);

        assert_eq!(
            inputs[2]["txid"].as_str().unwrap(),
            "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5"
        );
        assert_eq!(inputs[2]["vout"], 114);

        let outputs = parsed["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["satoshis"], 1000);

        // Round-trip verification
        let tx2 = Transaction::from_json(&json).unwrap();
        assert_eq!(tx.to_hex(), tx2.to_hex());
    }
}
