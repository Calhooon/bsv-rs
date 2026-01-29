//! Client-side WalletWire message transceiver.
//!
//! The [`WalletWireTransceiver`] serializes wallet method calls into binary messages
//! and deserializes the responses.

use super::encoding::{WireReader, WireWriter};
use super::{WalletCall, WalletWire};
use crate::primitives::{from_base64, from_hex, to_base64, to_hex};
use crate::wallet::types::Network;
use crate::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AcquisitionProtocol,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetPublicKeyArgs, GetPublicKeyResult, InternalizeActionArgs,
    InternalizeActionResult, KeyringRevealer, ListActionsArgs, ListActionsResult,
    ListCertificatesArgs, ListCertificatesResult, ListOutputsArgs, ListOutputsResult,
    ProveCertificateArgs, ProveCertificateResult, RelinquishCertificateArgs,
    RelinquishCertificateResult, RelinquishOutputArgs, RelinquishOutputResult, SignActionArgs,
    SignActionResult, SignableTransaction, TrustSelf, VerifyHmacArgs, VerifyHmacResult,
    VerifySignatureArgs, VerifySignatureResult, WalletCertificate,
};
use crate::Error;

/// Client-side wallet wire protocol implementation.
///
/// The transceiver serializes wallet method calls into binary messages,
/// transmits them over the wire, and deserializes the responses.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::wallet::wire::{WalletWire, WalletWireTransceiver};
/// use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};
///
/// // Create transceiver with some wire transport
/// let wire = MyWireTransport::new();
/// let transceiver = WalletWireTransceiver::new(wire);
///
/// // Make wallet calls
/// let result = transceiver.get_public_key(GetPublicKeyArgs {
///     protocol_id: Protocol::new(SecurityLevel::App, "my app"),
///     key_id: "key-1".to_string(),
///     counterparty: None,
///     for_self: Some(true),
/// }, "originator").await?;
/// ```
pub struct WalletWireTransceiver<T: WalletWire> {
    wire: T,
}

impl<T: WalletWire> WalletWireTransceiver<T> {
    /// Creates a new transceiver with the given wire transport.
    pub fn new(wire: T) -> Self {
        Self { wire }
    }

    /// Returns a reference to the underlying wire transport.
    pub fn wire(&self) -> &T {
        &self.wire
    }

    /// Transmits a message and handles the response.
    async fn transmit(
        &self,
        call: WalletCall,
        originator: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut writer = WireWriter::new();

        // Write call code
        writer.write_u8(call.as_u8());

        // Write originator
        let originator_bytes = originator.as_bytes();
        writer.write_u8(originator_bytes.len() as u8);
        writer.write_bytes(originator_bytes);

        // Write parameters
        writer.write_bytes(params);

        // Transmit
        let response = self.wire.transmit_to_wallet(writer.as_bytes()).await?;

        // Parse response
        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8()?;

        if error_byte == 0 {
            // Success - return remaining bytes
            Ok(reader.read_remaining().to_vec())
        } else {
            // Error
            let message = reader.read_string()?;
            // Skip stack trace
            let _stack_len = reader.read_signed_var_int()?;

            Err(Error::WalletError(format!(
                "wallet error (code {}): {}",
                error_byte, message
            )))
        }
    }

    // =========================================================================
    // Wallet interface methods
    // =========================================================================

    /// Gets a public key from the wallet.
    pub async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: &str,
    ) -> Result<GetPublicKeyResult, Error> {
        let mut writer = WireWriter::new();

        // Identity key flag
        writer.write_optional_bool(Some(args.identity_key));

        // Protocol ID (optional)
        writer.write_optional_protocol_id(args.protocol_id.as_ref());

        // Key ID (optional)
        writer.write_optional_string(args.key_id.as_deref());

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // for_self
        writer.write_optional_bool(args.for_self);

        let response = self
            .transmit(WalletCall::GetPublicKey, originator, writer.as_bytes())
            .await?;

        // Parse response - 33 bytes compressed public key
        let mut reader = WireReader::new(&response);
        let pubkey_bytes = reader.read_bytes(33)?;
        let public_key = crate::primitives::to_hex(pubkey_bytes);

        Ok(GetPublicKeyResult { public_key })
    }

    /// Encrypts data using the wallet's derived key.
    pub async fn encrypt(
        &self,
        args: EncryptArgs,
        originator: &str,
    ) -> Result<EncryptResult, Error> {
        let mut writer = WireWriter::new();

        // Protocol ID
        writer.write_protocol_id(&args.protocol_id);

        // Key ID
        writer.write_string(&args.key_id);

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // Plaintext
        writer.write_var_int(args.plaintext.len() as u64);
        writer.write_bytes(&args.plaintext);

        let response = self
            .transmit(WalletCall::Encrypt, originator, writer.as_bytes())
            .await?;

        // Parse response
        let mut reader = WireReader::new(&response);
        let ciphertext_len = reader.read_var_int()? as usize;
        let ciphertext = reader.read_bytes(ciphertext_len)?.to_vec();

        Ok(EncryptResult { ciphertext })
    }

    /// Decrypts data using the wallet's derived key.
    pub async fn decrypt(
        &self,
        args: DecryptArgs,
        originator: &str,
    ) -> Result<DecryptResult, Error> {
        let mut writer = WireWriter::new();

        // Protocol ID
        writer.write_protocol_id(&args.protocol_id);

        // Key ID
        writer.write_string(&args.key_id);

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // Ciphertext
        writer.write_var_int(args.ciphertext.len() as u64);
        writer.write_bytes(&args.ciphertext);

        let response = self
            .transmit(WalletCall::Decrypt, originator, writer.as_bytes())
            .await?;

        // Parse response
        let mut reader = WireReader::new(&response);
        let plaintext_len = reader.read_var_int()? as usize;
        let plaintext = reader.read_bytes(plaintext_len)?.to_vec();

        Ok(DecryptResult { plaintext })
    }

    /// Creates an HMAC using the wallet's derived key.
    pub async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: &str,
    ) -> Result<CreateHmacResult, Error> {
        let mut writer = WireWriter::new();

        // Protocol ID
        writer.write_protocol_id(&args.protocol_id);

        // Key ID
        writer.write_string(&args.key_id);

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // Data
        writer.write_var_int(args.data.len() as u64);
        writer.write_bytes(&args.data);

        let response = self
            .transmit(WalletCall::CreateHmac, originator, writer.as_bytes())
            .await?;

        // Parse response - HMAC is always 32 bytes
        let mut reader = WireReader::new(&response);
        let hmac_len = reader.read_var_int()? as usize;
        if hmac_len != 32 {
            return Err(Error::WalletError(format!(
                "invalid HMAC length: expected 32, got {}",
                hmac_len
            )));
        }
        let hmac_bytes = reader.read_bytes(32)?;
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(hmac_bytes);

        Ok(CreateHmacResult { hmac })
    }

    /// Verifies an HMAC using the wallet's derived key.
    pub async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: &str,
    ) -> Result<VerifyHmacResult, Error> {
        let mut writer = WireWriter::new();

        // Protocol ID
        writer.write_protocol_id(&args.protocol_id);

        // Key ID
        writer.write_string(&args.key_id);

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // Data
        writer.write_var_int(args.data.len() as u64);
        writer.write_bytes(&args.data);

        // HMAC
        writer.write_var_int(args.hmac.len() as u64);
        writer.write_bytes(&args.hmac);

        let response = self
            .transmit(WalletCall::VerifyHmac, originator, writer.as_bytes())
            .await?;

        // Parse response
        let mut reader = WireReader::new(&response);
        let valid = reader.read_optional_bool()?.unwrap_or(false);

        Ok(VerifyHmacResult { valid })
    }

    /// Creates a signature using the wallet's derived key.
    pub async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: &str,
    ) -> Result<CreateSignatureResult, Error> {
        let mut writer = WireWriter::new();

        // Protocol ID
        writer.write_protocol_id(&args.protocol_id);

        // Key ID
        writer.write_string(&args.key_id);

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // Data
        writer.write_optional_bytes(args.data.as_deref());

        // Hash to directly sign
        writer.write_optional_bytes(args.hash_to_directly_sign.as_ref().map(|h| &h[..]));

        let response = self
            .transmit(WalletCall::CreateSignature, originator, writer.as_bytes())
            .await?;

        // Parse response - DER-encoded signature
        let mut reader = WireReader::new(&response);
        let sig_len = reader.read_var_int()? as usize;
        let signature = reader.read_bytes(sig_len)?.to_vec();

        Ok(CreateSignatureResult { signature })
    }

    /// Verifies a signature using the wallet's derived key.
    pub async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: &str,
    ) -> Result<VerifySignatureResult, Error> {
        let mut writer = WireWriter::new();

        // Protocol ID
        writer.write_protocol_id(&args.protocol_id);

        // Key ID
        writer.write_string(&args.key_id);

        // Counterparty
        writer.write_counterparty(args.counterparty.as_ref());

        // for_self
        writer.write_optional_bool(args.for_self);

        // Data
        writer.write_optional_bytes(args.data.as_deref());

        // Hash to directly verify
        writer.write_optional_bytes(args.hash_to_directly_verify.as_ref().map(|h| &h[..]));

        // Signature (already DER-encoded)
        writer.write_var_int(args.signature.len() as u64);
        writer.write_bytes(&args.signature);

        let response = self
            .transmit(WalletCall::VerifySignature, originator, writer.as_bytes())
            .await?;

        // Parse response
        let mut reader = WireReader::new(&response);
        let valid = reader.read_optional_bool()?.unwrap_or(false);

        Ok(VerifySignatureResult { valid })
    }

    /// Checks if the wallet is authenticated.
    pub async fn is_authenticated(&self, originator: &str) -> Result<bool, Error> {
        let response = self
            .transmit(WalletCall::IsAuthenticated, originator, &[])
            .await?;

        let mut reader = WireReader::new(&response);
        Ok(reader.read_optional_bool()?.unwrap_or(false))
    }

    /// Gets the current block height.
    pub async fn get_height(&self, originator: &str) -> Result<u64, Error> {
        let response = self
            .transmit(WalletCall::GetHeight, originator, &[])
            .await?;

        let mut reader = WireReader::new(&response);
        reader.read_var_int()
    }

    /// Gets the network the wallet is connected to.
    pub async fn get_network(&self, originator: &str) -> Result<Network, Error> {
        let response = self
            .transmit(WalletCall::GetNetwork, originator, &[])
            .await?;

        let mut reader = WireReader::new(&response);
        let network_str = reader.read_string()?;

        match network_str.as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            _ => Err(Error::WalletError(format!(
                "unknown network: {}",
                network_str
            ))),
        }
    }

    /// Gets the wallet version.
    pub async fn get_version(&self, originator: &str) -> Result<String, Error> {
        let response = self
            .transmit(WalletCall::GetVersion, originator, &[])
            .await?;

        let mut reader = WireReader::new(&response);
        reader.read_string()
    }

    // =========================================================================
    // Action methods
    // =========================================================================

    /// Creates a new transaction action.
    pub async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: &str,
    ) -> Result<CreateActionResult, Error> {
        let mut writer = WireWriter::new();

        // Description
        writer.write_string(&args.description);

        // Input BEEF
        writer.write_optional_bytes(args.input_beef.as_deref());

        // Inputs
        if let Some(inputs) = &args.inputs {
            writer.write_signed_var_int(inputs.len() as i64);
            for input in inputs {
                // Outpoint
                writer.write_outpoint(&input.outpoint);

                // Unlocking script (or length)
                if let Some(unlocking_script) = &input.unlocking_script {
                    writer.write_signed_var_int(unlocking_script.len() as i64);
                    writer.write_bytes(unlocking_script);
                } else {
                    writer.write_signed_var_int(-1);
                    writer.write_signed_var_int(input.unlocking_script_length.unwrap_or(0) as i64);
                }

                // Input description
                writer.write_string(&input.input_description);

                // Sequence number
                writer.write_optional_var_int(input.sequence_number.map(|v| v as u64));
            }
        } else {
            writer.write_signed_var_int(-1);
        }

        // Outputs
        if let Some(outputs) = &args.outputs {
            writer.write_signed_var_int(outputs.len() as i64);
            for output in outputs {
                // Locking script
                writer.write_var_int(output.locking_script.len() as u64);
                writer.write_bytes(&output.locking_script);

                // Satoshis
                writer.write_var_int(output.satoshis);

                // Output description
                writer.write_string(&output.output_description);

                // Basket
                writer.write_optional_string(output.basket.as_deref());

                // Custom instructions
                writer.write_optional_string(output.custom_instructions.as_deref());

                // Tags
                writer.write_optional_string_array(output.tags.as_deref());
            }
        } else {
            writer.write_signed_var_int(-1);
        }

        // Lock time
        writer.write_optional_var_int(args.lock_time.map(|v| v as u64));

        // Version
        writer.write_optional_var_int(args.version.map(|v| v as u64));

        // Labels
        writer.write_optional_string_array(args.labels.as_deref());

        // Options
        if let Some(options) = &args.options {
            writer.write_i8(1); // Options present

            writer.write_optional_bool(options.sign_and_process);
            writer.write_optional_bool(options.accept_delayed_broadcast);

            // Trust self
            if options.trust_self == Some(TrustSelf::Known) {
                writer.write_i8(1);
            } else {
                writer.write_i8(-1);
            }

            // Known txids
            if let Some(txids) = &options.known_txids {
                writer.write_signed_var_int(txids.len() as i64);
                for txid in txids {
                    writer.write_bytes(txid);
                }
            } else {
                writer.write_signed_var_int(-1);
            }

            writer.write_optional_bool(options.return_txid_only);
            writer.write_optional_bool(options.no_send);

            // No send change
            if let Some(outpoints) = &options.no_send_change {
                writer.write_signed_var_int(outpoints.len() as i64);
                for outpoint in outpoints {
                    writer.write_outpoint(outpoint);
                }
            } else {
                writer.write_signed_var_int(-1);
            }

            // Send with
            if let Some(txids) = &options.send_with {
                writer.write_signed_var_int(txids.len() as i64);
                for txid in txids {
                    writer.write_bytes(txid);
                }
            } else {
                writer.write_signed_var_int(-1);
            }

            writer.write_optional_bool(options.randomize_outputs);
        } else {
            writer.write_i8(0); // Options not present
        }

        let response = self
            .transmit(WalletCall::CreateAction, originator, writer.as_bytes())
            .await?;

        let mut reader = WireReader::new(&response);

        // Parse txid
        let txid_flag = reader.read_i8()?;
        let txid = if txid_flag == 1 {
            let bytes = reader.read_bytes(32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        } else {
            None
        };

        // Parse tx
        let tx_flag = reader.read_i8()?;
        let tx = if tx_flag == 1 {
            let len = reader.read_var_int()? as usize;
            Some(reader.read_bytes(len)?.to_vec())
        } else {
            None
        };

        // Parse no_send_change
        let no_send_change_len = reader.read_signed_var_int()?;
        let no_send_change = if no_send_change_len >= 0 {
            let mut outpoints = Vec::with_capacity(no_send_change_len as usize);
            for _ in 0..no_send_change_len {
                outpoints.push(reader.read_outpoint()?);
            }
            Some(outpoints)
        } else {
            None
        };

        // Parse send_with_results
        let send_with_results = reader.read_send_with_result_array()?;

        // Parse signable_transaction
        let signable_flag = reader.read_i8()?;
        let signable_transaction = if signable_flag == 1 {
            let tx_len = reader.read_var_int()? as usize;
            let tx_bytes = reader.read_bytes(tx_len)?.to_vec();
            let ref_len = reader.read_var_int()? as usize;
            let reference = reader.read_bytes(ref_len)?.to_vec();
            Some(SignableTransaction {
                tx: tx_bytes,
                reference,
            })
        } else {
            None
        };

        Ok(CreateActionResult {
            txid,
            tx,
            no_send_change,
            send_with_results,
            signable_transaction,
            input_type: None,
            inputs: None,
            reference_number: None,
        })
    }

    /// Signs a previously created transaction.
    pub async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: &str,
    ) -> Result<SignActionResult, Error> {
        let mut writer = WireWriter::new();

        // Spends map
        writer.write_sign_action_spends(&args.spends);

        // Reference (base64 string -> bytes)
        let reference_bytes = from_base64(&args.reference)
            .map_err(|e| Error::WalletError(format!("invalid reference base64: {}", e)))?;
        writer.write_var_int(reference_bytes.len() as u64);
        writer.write_bytes(&reference_bytes);

        // Options
        if let Some(options) = &args.options {
            writer.write_i8(1);
            writer.write_optional_bool(options.accept_delayed_broadcast);
            writer.write_optional_bool(options.return_txid_only);
            writer.write_optional_bool(options.no_send);

            if let Some(txids) = &options.send_with {
                writer.write_signed_var_int(txids.len() as i64);
                for txid in txids {
                    writer.write_bytes(txid);
                }
            } else {
                writer.write_signed_var_int(-1);
            }
        } else {
            writer.write_i8(0);
        }

        let response = self
            .transmit(WalletCall::SignAction, originator, writer.as_bytes())
            .await?;

        let mut reader = WireReader::new(&response);

        // Parse txid
        let txid_flag = reader.read_i8()?;
        let txid = if txid_flag == 1 {
            let bytes = reader.read_bytes(32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        } else {
            None
        };

        // Parse tx
        let tx_flag = reader.read_i8()?;
        let tx = if tx_flag == 1 {
            let len = reader.read_var_int()? as usize;
            Some(reader.read_bytes(len)?.to_vec())
        } else {
            None
        };

        // Parse send_with_results
        let send_with_results = reader.read_send_with_result_array()?;

        Ok(SignActionResult {
            txid,
            tx,
            send_with_results,
        })
    }

    /// Aborts an in-progress action.
    pub async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: &str,
    ) -> Result<AbortActionResult, Error> {
        let reference_bytes = from_base64(&args.reference)
            .map_err(|e| Error::WalletError(format!("invalid reference base64: {}", e)))?;

        self.transmit(WalletCall::AbortAction, originator, &reference_bytes)
            .await?;

        Ok(AbortActionResult { aborted: true })
    }

    /// Lists wallet actions (transactions).
    pub async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: &str,
    ) -> Result<ListActionsResult, Error> {
        let mut writer = WireWriter::new();

        // Labels
        writer.write_string_array(&args.labels);

        // Label query mode
        writer.write_optional_query_mode(args.label_query_mode);

        // Include options
        writer.write_optional_bool(args.include_labels);
        writer.write_optional_bool(args.include_inputs);
        writer.write_optional_bool(args.include_input_source_locking_scripts);
        writer.write_optional_bool(args.include_input_unlocking_scripts);
        writer.write_optional_bool(args.include_outputs);
        writer.write_optional_bool(args.include_output_locking_scripts);

        // Limit and offset
        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));

        // Seek permission
        writer.write_optional_bool(args.seek_permission);

        let response = self
            .transmit(WalletCall::ListActions, originator, writer.as_bytes())
            .await?;

        let mut reader = WireReader::new(&response);

        let total_actions = reader.read_var_int()? as u32;
        let mut actions = Vec::with_capacity(total_actions as usize);

        for _ in 0..total_actions {
            actions.push(reader.read_wallet_action()?);
        }

        Ok(ListActionsResult {
            total_actions,
            actions,
        })
    }

    /// Internalizes an external transaction.
    pub async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: &str,
    ) -> Result<InternalizeActionResult, Error> {
        let mut writer = WireWriter::new();

        // Transaction
        writer.write_var_int(args.tx.len() as u64);
        writer.write_bytes(&args.tx);

        // Outputs
        writer.write_var_int(args.outputs.len() as u64);
        for output in &args.outputs {
            writer.write_var_int(output.output_index as u64);

            if output.protocol == "wallet payment" {
                writer.write_u8(1);
                if let Some(payment) = &output.payment_remittance {
                    let sender_key_bytes = from_hex(&payment.sender_identity_key)?;
                    writer.write_bytes(&sender_key_bytes);
                    let prefix_bytes = from_base64(&payment.derivation_prefix).map_err(|e| {
                        Error::WalletError(format!("invalid derivation_prefix: {}", e))
                    })?;
                    writer.write_var_int(prefix_bytes.len() as u64);
                    writer.write_bytes(&prefix_bytes);
                    let suffix_bytes = from_base64(&payment.derivation_suffix).map_err(|e| {
                        Error::WalletError(format!("invalid derivation_suffix: {}", e))
                    })?;
                    writer.write_var_int(suffix_bytes.len() as u64);
                    writer.write_bytes(&suffix_bytes);
                } else {
                    return Err(Error::WalletError(
                        "payment_remittance required for wallet payment".to_string(),
                    ));
                }
            } else {
                writer.write_u8(2); // basket insertion
                if let Some(insertion) = &output.insertion_remittance {
                    writer.write_string(&insertion.basket);
                    writer.write_optional_string(insertion.custom_instructions.as_deref());
                    let tags = insertion.tags.as_deref().unwrap_or(&[]);
                    writer.write_string_array(tags);
                } else {
                    writer.write_string("");
                    writer.write_signed_var_int(-1);
                    writer.write_signed_var_int(0);
                }
            }
        }

        // Labels
        writer.write_optional_string_array(args.labels.as_deref());

        // Description
        writer.write_string(&args.description);

        // Seek permission
        writer.write_optional_bool(args.seek_permission);

        self.transmit(WalletCall::InternalizeAction, originator, writer.as_bytes())
            .await?;

        Ok(InternalizeActionResult { accepted: true })
    }

    // =========================================================================
    // Output methods
    // =========================================================================

    /// Lists wallet outputs.
    pub async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: &str,
    ) -> Result<ListOutputsResult, Error> {
        let mut writer = WireWriter::new();

        // Basket
        writer.write_string(&args.basket);

        // Tags
        let tags = args.tags.as_deref().unwrap_or(&[]);
        writer.write_string_array(tags);

        // Tag query mode (encoded differently in TypeScript: all=1, any=2)
        if args.tag_query_mode == Some(crate::wallet::QueryMode::All) {
            writer.write_i8(1);
        } else if args.tag_query_mode == Some(crate::wallet::QueryMode::Any) {
            writer.write_i8(2);
        } else {
            writer.write_i8(-1);
        }

        // Include mode (encoded differently: locking scripts=1, entire transactions=2)
        if args.include == Some(crate::wallet::OutputInclude::LockingScripts) {
            writer.write_i8(1);
        } else if args.include == Some(crate::wallet::OutputInclude::EntireTransactions) {
            writer.write_i8(2);
        } else {
            writer.write_i8(-1);
        }

        writer.write_optional_bool(args.include_custom_instructions);
        writer.write_optional_bool(args.include_tags);
        writer.write_optional_bool(args.include_labels);

        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));
        writer.write_optional_bool(args.seek_permission);

        let response = self
            .transmit(WalletCall::ListOutputs, originator, writer.as_bytes())
            .await?;

        let mut reader = WireReader::new(&response);

        let total_outputs = reader.read_var_int()? as u32;
        let beef_len = reader.read_signed_var_int()?;
        let beef = if beef_len >= 0 {
            Some(reader.read_bytes(beef_len as usize)?.to_vec())
        } else {
            None
        };

        let mut outputs = Vec::with_capacity(total_outputs as usize);
        for _ in 0..total_outputs {
            outputs.push(reader.read_wallet_output()?);
        }

        Ok(ListOutputsResult {
            total_outputs,
            beef,
            outputs,
        })
    }

    /// Relinquishes an output from a basket.
    pub async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: &str,
    ) -> Result<RelinquishOutputResult, Error> {
        let mut writer = WireWriter::new();

        writer.write_string(&args.basket);
        writer.write_outpoint(&args.output);

        self.transmit(WalletCall::RelinquishOutput, originator, writer.as_bytes())
            .await?;

        Ok(RelinquishOutputResult { relinquished: true })
    }

    // =========================================================================
    // Certificate methods
    // =========================================================================

    /// Acquires a certificate.
    pub async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: &str,
    ) -> Result<WalletCertificate, Error> {
        let mut writer = WireWriter::new();

        // Type (base64 -> bytes)
        let type_bytes = from_base64(&args.certificate_type)
            .map_err(|e| Error::WalletError(format!("invalid certificate_type base64: {}", e)))?;
        writer.write_bytes(&type_bytes);

        // Certifier (hex -> bytes)
        let certifier_bytes = from_hex(&args.certifier)?;
        writer.write_bytes(&certifier_bytes);

        // Fields
        writer.write_string_map(&args.fields);

        // Privileged params
        writer.write_optional_bool(args.privileged);
        if let Some(reason) = &args.privileged_reason {
            let reason_bytes = reason.as_bytes();
            writer.write_i8(reason_bytes.len() as i8);
            writer.write_bytes(reason_bytes);
        } else {
            writer.write_i8(-1);
        }

        // Acquisition protocol
        writer.write_u8(match args.acquisition_protocol {
            AcquisitionProtocol::Direct => 1,
            AcquisitionProtocol::Issuance => 2,
        });

        if args.acquisition_protocol == AcquisitionProtocol::Direct {
            // Serial number
            if let Some(serial) = &args.serial_number {
                let serial_bytes = from_base64(serial).map_err(|e| {
                    Error::WalletError(format!("invalid serial_number base64: {}", e))
                })?;
                writer.write_bytes(&serial_bytes);
            } else {
                return Err(Error::WalletError(
                    "serial_number required for direct acquisition".to_string(),
                ));
            }

            // Revocation outpoint
            if let Some(outpoint) = &args.revocation_outpoint {
                writer.write_outpoint_string(outpoint)?;
            } else {
                // Empty outpoint
                writer.write_bytes(&[0u8; 32]);
                writer.write_var_int(0);
            }

            // Signature
            if let Some(sig) = &args.signature {
                let sig_bytes = from_hex(sig)?;
                writer.write_var_int(sig_bytes.len() as u64);
                writer.write_bytes(&sig_bytes);
            } else {
                return Err(Error::WalletError(
                    "signature required for direct acquisition".to_string(),
                ));
            }

            // Keyring revealer
            if let Some(revealer) = &args.keyring_revealer {
                match revealer {
                    KeyringRevealer::Certifier => {
                        writer.write_u8(11);
                    }
                    KeyringRevealer::PublicKey(pk) => {
                        writer.write_bytes(&pk.to_compressed());
                    }
                }
            } else {
                writer.write_u8(11); // Default to certifier
            }

            // Keyring for subject
            if let Some(keyring) = &args.keyring_for_subject {
                writer.write_signed_var_int(keyring.len() as i64);
                for (key, value) in keyring {
                    writer.write_string(key);
                    let value_bytes = from_base64(value).map_err(|e| {
                        Error::WalletError(format!("invalid keyring value base64: {}", e))
                    })?;
                    writer.write_var_int(value_bytes.len() as u64);
                    writer.write_bytes(&value_bytes);
                }
            } else {
                writer.write_signed_var_int(0);
            }
        } else {
            // Issuance - certifier URL
            if let Some(url) = &args.certifier_url {
                writer.write_string(url);
            } else {
                return Err(Error::WalletError(
                    "certifier_url required for issuance acquisition".to_string(),
                ));
            }
        }

        let response = self
            .transmit(
                WalletCall::AcquireCertificate,
                originator,
                writer.as_bytes(),
            )
            .await?;

        // Parse certificate from binary
        self.parse_certificate_from_binary(&response)
    }

    /// Lists certificates.
    pub async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: &str,
    ) -> Result<ListCertificatesResult, Error> {
        let mut writer = WireWriter::new();

        // Certifiers
        writer.write_signed_var_int(args.certifiers.len() as i64);
        for certifier in &args.certifiers {
            let bytes = from_hex(certifier)?;
            writer.write_bytes(&bytes);
        }

        // Types
        writer.write_signed_var_int(args.types.len() as i64);
        for cert_type in &args.types {
            let bytes = from_base64(cert_type).map_err(|e| {
                Error::WalletError(format!("invalid certificate type base64: {}", e))
            })?;
            writer.write_bytes(&bytes);
        }

        // Limit and offset
        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));

        // Privileged params
        writer.write_optional_bool(args.privileged);
        if let Some(reason) = &args.privileged_reason {
            let reason_bytes = reason.as_bytes();
            writer.write_i8(reason_bytes.len() as i8);
            writer.write_bytes(reason_bytes);
        } else {
            writer.write_i8(-1);
        }

        let response = self
            .transmit(WalletCall::ListCertificates, originator, writer.as_bytes())
            .await?;

        let mut reader = WireReader::new(&response);

        let total_certificates = reader.read_var_int()? as u32;
        let mut certificates = Vec::with_capacity(total_certificates as usize);

        for _ in 0..total_certificates {
            let cert_len = reader.read_var_int()? as usize;
            let cert_bytes = reader.read_bytes(cert_len)?;
            let certificate = self.parse_certificate_from_binary(cert_bytes)?;

            // Keyring
            let keyring = if reader.read_i8()? == 1 {
                let num_fields = reader.read_var_int()? as usize;
                let mut keyring = std::collections::HashMap::with_capacity(num_fields);
                for _ in 0..num_fields {
                    let key = reader.read_string()?;
                    let value_len = reader.read_var_int()? as usize;
                    let value_bytes = reader.read_bytes(value_len)?;
                    keyring.insert(key, to_base64(value_bytes));
                }
                Some(keyring)
            } else {
                None
            };

            // Verifier
            let verifier_len = reader.read_var_int()? as usize;
            let verifier = if verifier_len > 0 {
                Some(
                    String::from_utf8(reader.read_bytes(verifier_len)?.to_vec())
                        .map_err(|_| Error::WalletError("invalid verifier UTF-8".to_string()))?,
                )
            } else {
                None
            };

            certificates.push(crate::wallet::CertificateResult {
                certificate,
                keyring,
                verifier,
            });
        }

        Ok(ListCertificatesResult {
            total_certificates,
            certificates,
        })
    }

    /// Proves a certificate.
    pub async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: &str,
    ) -> Result<ProveCertificateResult, Error> {
        let mut writer = WireWriter::new();

        // Certificate type
        let type_bytes = from_base64(&args.certificate.certificate_type)
            .map_err(|e| Error::WalletError(format!("invalid certificate_type base64: {}", e)))?;
        writer.write_bytes(&type_bytes);

        // Subject
        let subject_bytes = from_hex(&args.certificate.subject)?;
        writer.write_bytes(&subject_bytes);

        // Serial number
        let serial_bytes = from_base64(&args.certificate.serial_number)
            .map_err(|e| Error::WalletError(format!("invalid serial_number base64: {}", e)))?;
        writer.write_bytes(&serial_bytes);

        // Certifier
        let certifier_bytes = from_hex(&args.certificate.certifier)?;
        writer.write_bytes(&certifier_bytes);

        // Revocation outpoint
        writer.write_outpoint_string(&args.certificate.revocation_outpoint)?;

        // Signature
        let sig_bytes = from_hex(&args.certificate.signature)?;
        writer.write_var_int(sig_bytes.len() as u64);
        writer.write_bytes(&sig_bytes);

        // Fields
        writer.write_string_map(&args.certificate.fields);

        // Fields to reveal
        writer.write_string_array(&args.fields_to_reveal);

        // Verifier
        let verifier_bytes = from_hex(&args.verifier)?;
        writer.write_bytes(&verifier_bytes);

        // Privileged params
        writer.write_optional_bool(args.privileged);
        if let Some(reason) = &args.privileged_reason {
            let reason_bytes = reason.as_bytes();
            writer.write_i8(reason_bytes.len() as i8);
            writer.write_bytes(reason_bytes);
        } else {
            writer.write_i8(-1);
        }

        let response = self
            .transmit(WalletCall::ProveCertificate, originator, writer.as_bytes())
            .await?;

        let mut reader = WireReader::new(&response);

        let num_fields = reader.read_var_int()? as usize;
        let mut keyring_for_verifier = std::collections::HashMap::with_capacity(num_fields);
        for _ in 0..num_fields {
            let key = reader.read_string()?;
            let value_len = reader.read_var_int()? as usize;
            let value_bytes = reader.read_bytes(value_len)?;
            keyring_for_verifier.insert(key, to_base64(value_bytes));
        }

        Ok(ProveCertificateResult {
            keyring_for_verifier,
            certificate: None,
            verifier: None,
        })
    }

    /// Relinquishes a certificate.
    pub async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: &str,
    ) -> Result<RelinquishCertificateResult, Error> {
        let mut writer = WireWriter::new();

        // Type
        let type_bytes = from_base64(&args.certificate_type)
            .map_err(|e| Error::WalletError(format!("invalid certificate_type base64: {}", e)))?;
        writer.write_bytes(&type_bytes);

        // Serial number
        let serial_bytes = from_base64(&args.serial_number)
            .map_err(|e| Error::WalletError(format!("invalid serial_number base64: {}", e)))?;
        writer.write_bytes(&serial_bytes);

        // Certifier
        let certifier_bytes = from_hex(&args.certifier)?;
        writer.write_bytes(&certifier_bytes);

        self.transmit(
            WalletCall::RelinquishCertificate,
            originator,
            writer.as_bytes(),
        )
        .await?;

        Ok(RelinquishCertificateResult { relinquished: true })
    }

    // =========================================================================
    // Discovery methods
    // =========================================================================

    /// Discovers certificates by identity key.
    pub async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: &str,
    ) -> Result<DiscoverCertificatesResult, Error> {
        let mut writer = WireWriter::new();

        // Identity key
        let key_bytes = from_hex(&args.identity_key)?;
        writer.write_bytes(&key_bytes);

        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));
        writer.write_optional_bool(args.seek_permission);

        let response = self
            .transmit(
                WalletCall::DiscoverByIdentityKey,
                originator,
                writer.as_bytes(),
            )
            .await?;

        self.parse_discovery_result(&response)
    }

    /// Discovers certificates by attributes.
    pub async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: &str,
    ) -> Result<DiscoverCertificatesResult, Error> {
        let mut writer = WireWriter::new();

        // Attributes
        writer.write_signed_var_int(args.attributes.len() as i64);
        for (key, value) in &args.attributes {
            writer.write_string(key);
            writer.write_string(value);
        }

        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));
        writer.write_optional_bool(args.seek_permission);

        let response = self
            .transmit(
                WalletCall::DiscoverByAttributes,
                originator,
                writer.as_bytes(),
            )
            .await?;

        self.parse_discovery_result(&response)
    }

    // =========================================================================
    // Chain methods
    // =========================================================================

    /// Gets a block header for a given height.
    pub async fn get_header(
        &self,
        args: GetHeaderArgs,
        originator: &str,
    ) -> Result<GetHeaderResult, Error> {
        let mut writer = WireWriter::new();
        writer.write_var_int(args.height as u64);

        let response = self
            .transmit(
                WalletCall::GetHeaderForHeight,
                originator,
                writer.as_bytes(),
            )
            .await?;

        Ok(GetHeaderResult {
            header: to_hex(&response),
        })
    }

    /// Waits for authentication.
    pub async fn wait_for_authentication(&self, originator: &str) -> Result<bool, Error> {
        self.transmit(WalletCall::WaitForAuthentication, originator, &[])
            .await?;
        Ok(true)
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// Parses a certificate from binary format.
    fn parse_certificate_from_binary(&self, data: &[u8]) -> Result<WalletCertificate, Error> {
        let mut reader = WireReader::new(data);

        // Type (32 bytes)
        let type_bytes = reader.read_bytes(32)?;
        let certificate_type = to_base64(type_bytes);

        // Subject (33 bytes)
        let subject_bytes = reader.read_bytes(33)?;
        let subject = to_hex(subject_bytes);

        // Serial number (32 bytes)
        let serial_bytes = reader.read_bytes(32)?;
        let serial_number = to_base64(serial_bytes);

        // Certifier (33 bytes)
        let certifier_bytes = reader.read_bytes(33)?;
        let certifier = to_hex(certifier_bytes);

        // Revocation outpoint
        let revocation_outpoint = reader.read_outpoint_string()?;

        // Signature
        let sig_len = reader.read_var_int()? as usize;
        let sig_bytes = reader.read_bytes(sig_len)?;
        let signature = to_hex(sig_bytes);

        // Fields
        let fields = reader.read_string_map()?;

        Ok(WalletCertificate {
            certificate_type,
            subject,
            serial_number,
            certifier,
            revocation_outpoint,
            signature,
            fields,
        })
    }

    /// Parses a discovery result.
    fn parse_discovery_result(&self, data: &[u8]) -> Result<DiscoverCertificatesResult, Error> {
        let mut reader = WireReader::new(data);

        let total_certificates = reader.read_var_int()? as u32;
        let mut certificates = Vec::with_capacity(total_certificates as usize);

        for _ in 0..total_certificates {
            let cert_len = reader.read_var_int()? as usize;
            let cert_bytes = reader.read_bytes(cert_len)?;
            let certificate = self.parse_certificate_from_binary(cert_bytes)?;

            // Certifier info
            let name = reader.read_string()?;
            let icon_url = reader.read_optional_string()?;
            let description = reader.read_optional_string()?;
            let trust = reader.read_u8()?;

            let certifier_info = crate::wallet::IdentityCertifier {
                name,
                icon_url,
                description,
                trust,
            };

            // Publicly revealed keyring
            let num_public = reader.read_var_int()? as usize;
            let publicly_revealed_keyring = if num_public > 0 {
                let mut keyring = std::collections::HashMap::with_capacity(num_public);
                for _ in 0..num_public {
                    let key = reader.read_string()?;
                    let value_len = reader.read_var_int()? as usize;
                    let value_bytes = reader.read_bytes(value_len)?;
                    keyring.insert(key, to_base64(value_bytes));
                }
                Some(keyring)
            } else {
                None
            };

            // Decrypted fields
            let num_decrypted = reader.read_var_int()? as usize;
            let decrypted_fields = if num_decrypted > 0 {
                let mut fields = std::collections::HashMap::with_capacity(num_decrypted);
                for _ in 0..num_decrypted {
                    let key = reader.read_string()?;
                    let value = reader.read_string()?;
                    fields.insert(key, value);
                }
                Some(fields)
            } else {
                None
            };

            certificates.push(crate::wallet::IdentityCertificate {
                certificate,
                certifier_info: Some(certifier_info),
                publicly_revealed_keyring,
                decrypted_fields,
            });
        }

        Ok(DiscoverCertificatesResult {
            total_certificates,
            certificates,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;
    use crate::wallet::types::{Counterparty, Protocol};
    use crate::wallet::wire::WalletWireProcessor;
    use crate::wallet::{ProtoWallet, SecurityLevel};
    use std::sync::Arc;

    /// Test wire that loops back through the processor.
    struct LoopbackWire {
        processor: Arc<WalletWireProcessor<ProtoWallet>>,
    }

    #[async_trait::async_trait]
    impl WalletWire for LoopbackWire {
        async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            self.processor.process_message(message).await
        }
    }

    fn create_loopback() -> WalletWireTransceiver<LoopbackWire> {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = Arc::new(WalletWireProcessor::new(wallet));
        let wire = LoopbackWire { processor };
        WalletWireTransceiver::new(wire)
    }

    #[tokio::test]
    async fn test_roundtrip_get_public_key() {
        let transceiver = create_loopback();

        let result = transceiver
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol::new(SecurityLevel::App, "my test app")),
                    key_id: Some("test-key".to_string()),
                    counterparty: Some(Counterparty::Self_),
                    for_self: Some(true),
                },
                "test.example.com",
            )
            .await
            .unwrap();

        // Verify we got a valid hex-encoded public key
        assert_eq!(result.public_key.len(), 66); // 33 bytes = 66 hex chars
        assert!(result.public_key.starts_with("02") || result.public_key.starts_with("03"));
    }

    #[tokio::test]
    async fn test_roundtrip_encrypt_decrypt() {
        let transceiver = create_loopback();
        let plaintext = b"Hello, BSV!".to_vec();

        // Encrypt
        let encrypt_result = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "encryption test"),
                    key_id: "enc-key".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        // Decrypt
        let decrypt_result = transceiver
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypt_result.ciphertext,
                    protocol_id: Protocol::new(SecurityLevel::App, "encryption test"),
                    key_id: "enc-key".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        assert_eq!(decrypt_result.plaintext, plaintext);
    }

    #[tokio::test]
    async fn test_roundtrip_hmac() {
        let transceiver = create_loopback();
        let data = b"data to authenticate".to_vec();

        // Create HMAC
        let hmac_result = transceiver
            .create_hmac(
                CreateHmacArgs {
                    data: data.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "hmac test"),
                    key_id: "hmac-key".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        // Verify HMAC
        let verify_result = transceiver
            .verify_hmac(
                VerifyHmacArgs {
                    data,
                    hmac: hmac_result.hmac,
                    protocol_id: Protocol::new(SecurityLevel::App, "hmac test"),
                    key_id: "hmac-key".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        assert!(verify_result.valid);
    }

    #[tokio::test]
    async fn test_roundtrip_signature() {
        let transceiver = create_loopback();
        let data = b"data to sign".to_vec();

        // Create signature
        let sig_result = transceiver
            .create_signature(
                CreateSignatureArgs {
                    data: Some(data.clone()),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol::new(SecurityLevel::App, "signature test"),
                    key_id: "sig-key".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        // Verify signature
        let verify_result = transceiver
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(data),
                    hash_to_directly_verify: None,
                    signature: sig_result.signature,
                    protocol_id: Protocol::new(SecurityLevel::App, "signature test"),
                    key_id: "sig-key".to_string(),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                },
                "test",
            )
            .await
            .unwrap();

        assert!(verify_result.valid);
    }

    #[tokio::test]
    async fn test_roundtrip_is_authenticated() {
        let transceiver = create_loopback();
        let result = transceiver.is_authenticated("test").await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_roundtrip_get_network() {
        let transceiver = create_loopback();
        let result = transceiver.get_network("test").await.unwrap();
        assert_eq!(result, Network::Mainnet);
    }

    #[tokio::test]
    async fn test_roundtrip_get_version() {
        let transceiver = create_loopback();
        let result = transceiver.get_version("test").await.unwrap();
        assert!(!result.is_empty());
    }
}
