//! Server-side WalletWire message processor.
//!
//! The [`WalletWireProcessor`] deserializes incoming binary messages, dispatches
//! them to the appropriate wallet methods, and serializes the responses.

use super::encoding::{WireReader, WireWriter};
use super::WalletCall;
use crate::primitives::{from_hex, PublicKey};
use crate::wallet::types::Network;
use crate::wallet::{
    CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs, ProtoWallet,
    RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs, VerifyHmacArgs,
    VerifySignatureArgs,
};
use crate::Error;

/// Server-side processor for WalletWire messages.
///
/// This processor handles incoming binary messages from clients, deserializes the
/// parameters, invokes the appropriate wallet method, and serializes the response.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::wallet::wire::WalletWireProcessor;
/// use bsv_sdk::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let processor = WalletWireProcessor::new(wallet);
///
/// // Process incoming message
/// let response = processor.process_message(&request_bytes).await?;
/// ```
pub struct WalletWireProcessor {
    wallet: ProtoWallet,
    network: Network,
    version: String,
}

impl WalletWireProcessor {
    /// Creates a new processor with the given wallet.
    pub fn new(wallet: ProtoWallet) -> Self {
        Self {
            wallet,
            network: Network::Mainnet,
            version: "0.1.0".to_string(),
        }
    }

    /// Creates a new processor with custom network and version.
    pub fn with_config(wallet: ProtoWallet, network: Network, version: impl Into<String>) -> Self {
        Self {
            wallet,
            network,
            version: version.into(),
        }
    }

    /// Processes an incoming binary message and returns the response.
    ///
    /// The message format is:
    /// - Call code (1 byte)
    /// - Originator length (1 byte)
    /// - Originator string (N bytes)
    /// - Serialized parameters (variable)
    ///
    /// The response format is:
    /// - Error byte (0 = success, non-zero = error code)
    /// - Result data or error message
    pub async fn process_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let result = self.process_message_inner(message).await;
        self.encode_response(result)
    }

    /// Internal message processing that can return errors.
    async fn process_message_inner(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut reader = WireReader::new(message);

        // Read call code
        let call_code = reader.read_u8()?;
        let call = WalletCall::try_from(call_code)?;

        // Read originator
        let originator_len = reader.read_u8()? as usize;
        let originator_bytes = reader.read_bytes(originator_len)?;
        let _originator = String::from_utf8(originator_bytes.to_vec())
            .map_err(|_| Error::WalletError("invalid originator UTF-8".to_string()))?;

        // Dispatch based on call type
        match call {
            WalletCall::GetPublicKey => self.handle_get_public_key(&mut reader).await,
            WalletCall::Encrypt => self.handle_encrypt(&mut reader).await,
            WalletCall::Decrypt => self.handle_decrypt(&mut reader).await,
            WalletCall::CreateHmac => self.handle_create_hmac(&mut reader).await,
            WalletCall::VerifyHmac => self.handle_verify_hmac(&mut reader).await,
            WalletCall::CreateSignature => self.handle_create_signature(&mut reader).await,
            WalletCall::VerifySignature => self.handle_verify_signature(&mut reader).await,
            WalletCall::RevealCounterpartyKeyLinkage => {
                self.handle_reveal_counterparty_key_linkage(&mut reader)
                    .await
            }
            WalletCall::RevealSpecificKeyLinkage => {
                self.handle_reveal_specific_key_linkage(&mut reader).await
            }
            WalletCall::IsAuthenticated => self.handle_is_authenticated().await,
            WalletCall::GetHeight => self.handle_get_height().await,
            WalletCall::GetNetwork => self.handle_get_network().await,
            WalletCall::GetVersion => self.handle_get_version().await,
            // Transaction-related calls require full wallet implementation
            WalletCall::CreateAction => Err(Error::WalletError(
                "createAction not yet implemented".to_string(),
            )),
            WalletCall::SignAction => Err(Error::WalletError(
                "signAction not yet implemented".to_string(),
            )),
            WalletCall::AbortAction => Err(Error::WalletError(
                "abortAction not yet implemented".to_string(),
            )),
            WalletCall::ListActions => Err(Error::WalletError(
                "listActions not yet implemented".to_string(),
            )),
            WalletCall::InternalizeAction => Err(Error::WalletError(
                "internalizeAction not yet implemented".to_string(),
            )),
            WalletCall::ListOutputs => Err(Error::WalletError(
                "listOutputs not yet implemented".to_string(),
            )),
            WalletCall::RelinquishOutput => Err(Error::WalletError(
                "relinquishOutput not yet implemented".to_string(),
            )),
            WalletCall::AcquireCertificate => Err(Error::WalletError(
                "acquireCertificate not yet implemented".to_string(),
            )),
            WalletCall::ListCertificates => Err(Error::WalletError(
                "listCertificates not yet implemented".to_string(),
            )),
            WalletCall::ProveCertificate => Err(Error::WalletError(
                "proveCertificate not yet implemented".to_string(),
            )),
            WalletCall::RelinquishCertificate => Err(Error::WalletError(
                "relinquishCertificate not yet implemented".to_string(),
            )),
            WalletCall::DiscoverByIdentityKey => Err(Error::WalletError(
                "discoverByIdentityKey not yet implemented".to_string(),
            )),
            WalletCall::DiscoverByAttributes => Err(Error::WalletError(
                "discoverByAttributes not yet implemented".to_string(),
            )),
            WalletCall::WaitForAuthentication => Err(Error::WalletError(
                "waitForAuthentication not yet implemented".to_string(),
            )),
            WalletCall::GetHeaderForHeight => Err(Error::WalletError(
                "getHeaderForHeight not yet implemented".to_string(),
            )),
        }
    }

    /// Encodes a response (success or error) into wire format.
    fn encode_response(&self, result: Result<Vec<u8>, Error>) -> Result<Vec<u8>, Error> {
        let mut writer = WireWriter::new();

        match result {
            Ok(response_bytes) => {
                writer.write_u8(0); // Success
                writer.write_bytes(&response_bytes);
            }
            Err(e) => {
                // Map error to code
                let code = self.error_to_code(&e);
                writer.write_u8(code);

                // Write error message
                let message = e.to_string();
                writer.write_string(&message);

                // Write empty stack trace
                writer.write_signed_var_int(0);
            }
        }

        Ok(writer.into_bytes())
    }

    /// Maps an error to a wire protocol error code.
    fn error_to_code(&self, error: &Error) -> u8 {
        match error {
            Error::WalletError(msg) if msg.contains("invalid parameter") => 6,
            Error::WalletError(msg) if msg.contains("insufficient funds") => 7,
            Error::InvalidSignature(_) => 1,
            _ => 1, // Generic error
        }
    }

    // =========================================================================
    // Handler implementations
    // =========================================================================

    async fn handle_get_public_key(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments (matching transceiver serialization order)
        let identity_key = reader.read_optional_bool()?.unwrap_or(false);
        let protocol_id = reader.read_optional_protocol_id()?;
        let key_id = reader.read_optional_string()?;
        let counterparty = reader.read_counterparty()?;
        let for_self = reader.read_optional_bool()?;

        // Call wallet method
        let args = GetPublicKeyArgs {
            identity_key,
            protocol_id,
            key_id,
            counterparty,
            for_self,
        };
        let result = self.wallet.get_public_key(args)?;

        // Serialize response - result.public_key is a hex string
        let mut writer = WireWriter::new();
        let pubkey_bytes = from_hex(&result.public_key)?;
        writer.write_bytes(&pubkey_bytes);
        Ok(writer.into_bytes())
    }

    async fn handle_encrypt(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;
        let counterparty = reader.read_counterparty()?;
        let plaintext_len = reader.read_var_int()? as usize;
        let plaintext = reader.read_bytes(plaintext_len)?.to_vec();

        // Call wallet method
        let args = EncryptArgs {
            plaintext,
            protocol_id,
            key_id,
            counterparty,
        };
        let result = self.wallet.encrypt(args)?;

        // Serialize response
        let mut writer = WireWriter::new();
        writer.write_var_int(result.ciphertext.len() as u64);
        writer.write_bytes(&result.ciphertext);
        Ok(writer.into_bytes())
    }

    async fn handle_decrypt(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;
        let counterparty = reader.read_counterparty()?;
        let ciphertext_len = reader.read_var_int()? as usize;
        let ciphertext = reader.read_bytes(ciphertext_len)?.to_vec();

        // Call wallet method
        let args = DecryptArgs {
            ciphertext,
            protocol_id,
            key_id,
            counterparty,
        };
        let result = self.wallet.decrypt(args)?;

        // Serialize response
        let mut writer = WireWriter::new();
        writer.write_var_int(result.plaintext.len() as u64);
        writer.write_bytes(&result.plaintext);
        Ok(writer.into_bytes())
    }

    async fn handle_create_hmac(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;
        let counterparty = reader.read_counterparty()?;
        let data_len = reader.read_var_int()? as usize;
        let data = reader.read_bytes(data_len)?.to_vec();

        // Call wallet method
        let args = CreateHmacArgs {
            data,
            protocol_id,
            key_id,
            counterparty,
        };
        let result = self.wallet.create_hmac(args)?;

        // Serialize response - hmac is [u8; 32]
        let mut writer = WireWriter::new();
        writer.write_var_int(32);
        writer.write_bytes(&result.hmac);
        Ok(writer.into_bytes())
    }

    async fn handle_verify_hmac(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;
        let counterparty = reader.read_counterparty()?;
        let data_len = reader.read_var_int()? as usize;
        let data = reader.read_bytes(data_len)?.to_vec();
        let hmac_len = reader.read_var_int()? as usize;
        let hmac_bytes = reader.read_bytes(hmac_len)?;

        // Convert to [u8; 32]
        if hmac_bytes.len() != 32 {
            return Err(Error::WalletError(format!(
                "invalid HMAC length: expected 32, got {}",
                hmac_bytes.len()
            )));
        }
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(hmac_bytes);

        // Call wallet method
        let args = VerifyHmacArgs {
            data,
            hmac,
            protocol_id,
            key_id,
            counterparty,
        };
        let result = self.wallet.verify_hmac(args)?;

        // Serialize response
        let mut writer = WireWriter::new();
        writer.write_optional_bool(Some(result.valid));
        Ok(writer.into_bytes())
    }

    async fn handle_create_signature(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;
        let counterparty = reader.read_counterparty()?;

        // Read data or hash
        let data = reader.read_optional_bytes()?;
        let hash_to_directly_sign = reader.read_optional_bytes()?.and_then(|b| {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            } else {
                None
            }
        });

        // Call wallet method
        let args = CreateSignatureArgs {
            data,
            hash_to_directly_sign,
            protocol_id,
            key_id,
            counterparty,
        };
        let result = self.wallet.create_signature(args)?;

        // Serialize response - signature is Vec<u8> (DER encoded)
        let mut writer = WireWriter::new();
        writer.write_var_int(result.signature.len() as u64);
        writer.write_bytes(&result.signature);
        Ok(writer.into_bytes())
    }

    async fn handle_verify_signature(&self, reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
        // Read arguments
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;
        let counterparty = reader.read_counterparty()?;
        let for_self = reader.read_optional_bool()?;

        // Read data or hash
        let data = reader.read_optional_bytes()?;
        let hash_to_directly_verify = reader.read_optional_bytes()?.and_then(|b| {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            } else {
                None
            }
        });

        // Read signature (DER encoded)
        let sig_len = reader.read_var_int()? as usize;
        let signature = reader.read_bytes(sig_len)?.to_vec();

        // Call wallet method
        let args = VerifySignatureArgs {
            data,
            hash_to_directly_verify,
            signature,
            protocol_id,
            key_id,
            counterparty,
            for_self,
        };
        let result = self.wallet.verify_signature(args)?;

        // Serialize response
        let mut writer = WireWriter::new();
        writer.write_optional_bool(Some(result.valid));
        Ok(writer.into_bytes())
    }

    async fn handle_reveal_counterparty_key_linkage(
        &self,
        reader: &mut WireReader<'_>,
    ) -> Result<Vec<u8>, Error> {
        // Read arguments
        let counterparty_bytes = reader.read_bytes(33)?;
        let counterparty = PublicKey::from_bytes(counterparty_bytes)?;
        let verifier_bytes = reader.read_bytes(33)?;
        let verifier = PublicKey::from_bytes(verifier_bytes)?;

        // Call wallet method
        let args = RevealCounterpartyKeyLinkageArgs {
            counterparty,
            verifier,
        };
        let result = self.wallet.reveal_counterparty_key_linkage(args)?;

        // Serialize response - prover, verifier, counterparty are hex strings
        let mut writer = WireWriter::new();
        writer.write_var_int(result.encrypted_linkage.len() as u64);
        writer.write_bytes(&result.encrypted_linkage);
        writer.write_var_int(result.encrypted_linkage_proof.len() as u64);
        writer.write_bytes(&result.encrypted_linkage_proof);

        // Convert hex strings to bytes for public keys
        let prover_bytes = from_hex(&result.prover)?;
        let verifier_bytes = from_hex(&result.verifier)?;
        let counterparty_bytes = from_hex(&result.counterparty)?;

        writer.write_bytes(&prover_bytes);
        writer.write_bytes(&verifier_bytes);
        writer.write_bytes(&counterparty_bytes);
        writer.write_string(&result.revelation_time);
        Ok(writer.into_bytes())
    }

    async fn handle_reveal_specific_key_linkage(
        &self,
        reader: &mut WireReader<'_>,
    ) -> Result<Vec<u8>, Error> {
        // Read arguments
        let counterparty = reader
            .read_counterparty()?
            .ok_or_else(|| Error::WalletError("counterparty is required".to_string()))?;
        let verifier_bytes = reader.read_bytes(33)?;
        let verifier = PublicKey::from_bytes(verifier_bytes)?;
        let protocol_id = reader.read_protocol_id()?;
        let key_id = reader.read_string()?;

        // Call wallet method
        let args = RevealSpecificKeyLinkageArgs {
            counterparty,
            verifier,
            protocol_id,
            key_id,
        };
        let result = self.wallet.reveal_specific_key_linkage(args)?;

        // Serialize response
        let mut writer = WireWriter::new();
        writer.write_var_int(result.encrypted_linkage.len() as u64);
        writer.write_bytes(&result.encrypted_linkage);
        writer.write_var_int(result.encrypted_linkage_proof.len() as u64);
        writer.write_bytes(&result.encrypted_linkage_proof);

        // Convert hex strings to bytes for public keys
        let prover_bytes = from_hex(&result.prover)?;
        let verifier_bytes = from_hex(&result.verifier)?;
        let counterparty_bytes = from_hex(&result.counterparty)
            .unwrap_or_else(|_| result.counterparty.as_bytes().to_vec());

        writer.write_bytes(&prover_bytes);
        writer.write_bytes(&verifier_bytes);
        writer.write_bytes(&counterparty_bytes);
        writer.write_protocol_id(&result.protocol_id);
        writer.write_string(&result.key_id);
        writer.write_u8(result.proof_type);
        Ok(writer.into_bytes())
    }

    async fn handle_is_authenticated(&self) -> Result<Vec<u8>, Error> {
        // ProtoWallet is always authenticated
        let mut writer = WireWriter::new();
        writer.write_optional_bool(Some(true));
        Ok(writer.into_bytes())
    }

    async fn handle_get_height(&self) -> Result<Vec<u8>, Error> {
        // Return a placeholder height (ProtoWallet doesn't track chain state)
        let mut writer = WireWriter::new();
        writer.write_var_int(0);
        Ok(writer.into_bytes())
    }

    async fn handle_get_network(&self) -> Result<Vec<u8>, Error> {
        let mut writer = WireWriter::new();
        writer.write_string(self.network.as_str());
        Ok(writer.into_bytes())
    }

    async fn handle_get_version(&self) -> Result<Vec<u8>, Error> {
        let mut writer = WireWriter::new();
        writer.write_string(&self.version);
        Ok(writer.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;
    use crate::wallet::SecurityLevel;

    fn create_test_processor() -> WalletWireProcessor {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        WalletWireProcessor::new(wallet)
    }

    fn create_get_public_key_request(originator: &str) -> Vec<u8> {
        let mut writer = WireWriter::new();

        // Call code
        writer.write_u8(WalletCall::GetPublicKey.as_u8());

        // Originator
        let orig_bytes = originator.as_bytes();
        writer.write_u8(orig_bytes.len() as u8);
        writer.write_bytes(orig_bytes);

        // identity_key (false - derive from protocol/key_id)
        writer.write_i8(0);

        // Protocol ID
        writer.write_u8(SecurityLevel::App.as_u8());
        writer.write_string("my test app");

        // Key ID
        writer.write_optional_string(Some("test-key-1"));

        // Counterparty (self)
        writer.write_u8(11);

        // for_self
        writer.write_i8(1);

        writer.into_bytes()
    }

    #[tokio::test]
    async fn test_process_get_public_key() {
        let processor = create_test_processor();
        let request = create_get_public_key_request("test.example.com");

        let response = processor.process_message(&request).await.unwrap();

        // Check response
        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(error_byte, 0, "expected success");

        // Read public key (33 bytes compressed)
        let pubkey_bytes = reader.read_bytes(33).unwrap();
        assert_eq!(pubkey_bytes.len(), 33);
        assert!(pubkey_bytes[0] == 0x02 || pubkey_bytes[0] == 0x03);
    }

    #[tokio::test]
    async fn test_process_get_network() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = WalletWireProcessor::with_config(wallet, Network::Testnet, "1.0.0");

        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::GetNetwork.as_u8());
        writer.write_u8(0); // Empty originator
        let request = writer.into_bytes();

        let response = processor.process_message(&request).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(error_byte, 0);

        let network = reader.read_string().unwrap();
        assert_eq!(network, "testnet");
    }

    #[tokio::test]
    async fn test_process_get_version() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = WalletWireProcessor::with_config(wallet, Network::Mainnet, "2.0.0-beta");

        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::GetVersion.as_u8());
        writer.write_u8(0);
        let request = writer.into_bytes();

        let response = processor.process_message(&request).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(error_byte, 0);

        let version = reader.read_string().unwrap();
        assert_eq!(version, "2.0.0-beta");
    }

    #[tokio::test]
    async fn test_process_invalid_call_code() {
        let processor = create_test_processor();

        let mut writer = WireWriter::new();
        writer.write_u8(99); // Invalid call code
        writer.write_u8(0);
        let request = writer.into_bytes();

        let response = processor.process_message(&request).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_ne!(error_byte, 0, "expected error");
    }

    #[tokio::test]
    async fn test_process_is_authenticated() {
        let processor = create_test_processor();

        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::IsAuthenticated.as_u8());
        writer.write_u8(0);
        let request = writer.into_bytes();

        let response = processor.process_message(&request).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(error_byte, 0);

        let authenticated = reader.read_optional_bool().unwrap();
        assert_eq!(authenticated, Some(true));
    }
}
