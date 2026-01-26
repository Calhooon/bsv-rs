//! Client-side WalletWire message transceiver.
//!
//! The [`WalletWireTransceiver`] serializes wallet method calls into binary messages
//! and deserializes the responses.

use super::encoding::{WireReader, WireWriter};
use super::{WalletCall, WalletWire};
use crate::wallet::types::Network;
use crate::wallet::{
    CreateHmacArgs, CreateHmacResult, CreateSignatureArgs, CreateSignatureResult, DecryptArgs,
    DecryptResult, EncryptArgs, EncryptResult, GetPublicKeyArgs, GetPublicKeyResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult,
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
        processor: Arc<WalletWireProcessor>,
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
