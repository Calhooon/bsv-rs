//! Server-side WalletWire message processor.
//!
//! The [`WalletWireProcessor`] deserializes incoming binary messages, dispatches
//! them to the appropriate wallet methods, and serializes the responses.
//!
//! # Generic Over WalletInterface
//!
//! The processor is generic over any type implementing [`WalletInterface`],
//! allowing it to work with different wallet implementations:
//! - `ProtoWallet`: Crypto-only operations
//! - Custom full wallet: All 28 methods
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::wallet::wire::WalletWireProcessor;
//! use bsv_rs::wallet::ProtoWallet;
//!
//! let wallet = ProtoWallet::new(None);
//! let processor = WalletWireProcessor::new(wallet);
//!
//! // Process incoming message
//! let response = processor.process_message(&request_bytes).await?;
//! ```

use super::encoding::{WireReader, WireWriter};
use super::requests::{
    read_reveal_counterparty_key_linkage_args, read_reveal_specific_key_linkage_args,
};
use super::results::{
    write_create_hmac_result, write_create_signature_result, write_decrypt_result,
    write_encrypt_result, write_reveal_counterparty_key_linkage_result,
    write_reveal_specific_key_linkage_result, write_verify_hmac_result,
    write_verify_signature_result, write_wait_for_authentication_result,
};
use super::WalletCall;
use crate::primitives::from_hex;
use crate::wallet::interface::WalletInterface;
use crate::wallet::types::Network;
use crate::wallet::{CreateHmacArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs};
use crate::Error;
use std::marker::PhantomData;

/// `walletErrors.unknownError` (`WalletError.ts:72` at `ts-stack@edf6e03`).
const UNKNOWN_ERROR: u8 = 1;

/// `MAX_WIRE_ERROR_MESSAGE_BYTES` (`WalletWireProcessor.ts:25`).
const MAX_WIRE_ERROR_MESSAGE_BYTES: usize = 4096;

/// The words of the reference's replacement (`WalletWireProcessor.ts:2417`
/// at `ts-stack@edf6e03`): every wallet error that is not an explicit one is
/// framed as `new WalletError('Wallet operation failed', unknownError)`.
const WALLET_OPERATION_FAILED: &str = "Wallet operation failed";

/// The code of an explicit wallet error, 2 to 8 (`WalletWireProcessor.ts:2405-2416`:
/// a `WalletError`, or a `WERR_` error, whose `code` lies in unsupportedAction
/// to abortRefused). This crate's `Error` carries no wallet code (#137), so no
/// error is explicit today; a coded variant, when one exists, answers here and
/// keeps its words and its code on the wire.
fn explicit_wallet_code(_error: &Error) -> Option<u8> {
    None
}

/// The words an error frame carries: the reference writes `error.message`
/// (`WalletWireProcessor.ts:2387`), never this crate's `Display` prefix. A
/// `WalletError` is its own words (the replacement's constant, a stub's
/// refusal); every other variant, the processor's own reading of the request,
/// is this crate's own sentence, written as its `Display` reads.
fn wire_message(error: &Error) -> String {
    match error {
        Error::WalletError(words) => words.clone(),
        other => other.to_string(),
    }
}

/// Server-side processor for WalletWire messages.
///
/// This processor handles incoming binary messages from clients, deserializes the
/// parameters, invokes the appropriate wallet method, and serializes the response.
///
/// The processor is generic over `W: WalletInterface`, allowing it to work with
/// any wallet implementation. When using `ProtoWallet`, only crypto operations
/// are supported. A full wallet implementation would support all 28 methods.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::wire::WalletWireProcessor;
/// use bsv_rs::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let processor = WalletWireProcessor::new(wallet);
///
/// // Process incoming message
/// let response = processor.process_message(&request_bytes).await?;
/// ```
pub struct WalletWireProcessor<W: WalletInterface> {
    wallet: W,
    network: Network,
    version: String,
    _marker: PhantomData<W>,
}

impl<W: WalletInterface> WalletWireProcessor<W> {
    /// Creates a new processor with the given wallet.
    pub fn new(wallet: W) -> Self {
        Self {
            wallet,
            network: Network::Mainnet,
            version: "0.1.0".to_string(),
            _marker: PhantomData,
        }
    }

    /// Creates a new processor with custom network and version.
    pub fn with_config(wallet: W, network: Network, version: impl Into<String>) -> Self {
        Self {
            wallet,
            network,
            version: version.into(),
            _marker: PhantomData,
        }
    }

    /// Returns a reference to the underlying wallet.
    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    /// Returns the configured network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the configured version string.
    pub fn version(&self) -> &str {
        &self.version
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
        let originator = String::from_utf8(originator_bytes.to_vec())
            .map_err(|_| Error::WalletError("invalid originator UTF-8".to_string()))?;

        // Dispatch based on call type
        match call {
            // Key Operations
            WalletCall::GetPublicKey => self.handle_get_public_key(&mut reader, &originator).await,
            WalletCall::Encrypt => self.handle_encrypt(&mut reader, &originator).await,
            WalletCall::Decrypt => self.handle_decrypt(&mut reader, &originator).await,
            WalletCall::CreateHmac => self.handle_create_hmac(&mut reader, &originator).await,
            WalletCall::VerifyHmac => self.handle_verify_hmac(&mut reader, &originator).await,
            WalletCall::CreateSignature => {
                self.handle_create_signature(&mut reader, &originator).await
            }
            WalletCall::VerifySignature => {
                self.handle_verify_signature(&mut reader, &originator).await
            }
            WalletCall::RevealCounterpartyKeyLinkage => {
                self.handle_reveal_counterparty_key_linkage(&mut reader, &originator)
                    .await
            }
            WalletCall::RevealSpecificKeyLinkage => {
                self.handle_reveal_specific_key_linkage(&mut reader, &originator)
                    .await
            }

            // Chain/Status Operations
            WalletCall::IsAuthenticated => self.handle_is_authenticated(&originator).await,
            WalletCall::GetHeight => self.handle_get_height(&originator).await,
            WalletCall::GetNetwork => self.handle_get_network(&originator).await,
            WalletCall::GetVersion => self.handle_get_version(&originator).await,
            WalletCall::WaitForAuthentication => {
                self.handle_wait_for_authentication(&originator).await
            }
            WalletCall::GetHeaderForHeight => {
                self.handle_get_header_for_height(&mut reader, &originator)
                    .await
            }

            // Action Operations - delegated to wallet
            WalletCall::CreateAction => self.handle_create_action(&mut reader, &originator).await,
            WalletCall::SignAction => self.handle_sign_action(&mut reader, &originator).await,
            WalletCall::AbortAction => self.handle_abort_action(&mut reader, &originator).await,
            WalletCall::ListActions => self.handle_list_actions(&mut reader, &originator).await,
            WalletCall::InternalizeAction => {
                self.handle_internalize_action(&mut reader, &originator)
                    .await
            }

            // Output Operations - delegated to wallet
            WalletCall::ListOutputs => self.handle_list_outputs(&mut reader, &originator).await,
            WalletCall::RelinquishOutput => {
                self.handle_relinquish_output(&mut reader, &originator)
                    .await
            }

            // Certificate Operations - delegated to wallet
            WalletCall::AcquireCertificate => {
                self.handle_acquire_certificate(&mut reader, &originator)
                    .await
            }
            WalletCall::ListCertificates => {
                self.handle_list_certificates(&mut reader, &originator)
                    .await
            }
            WalletCall::ProveCertificate => {
                self.handle_prove_certificate(&mut reader, &originator)
                    .await
            }
            WalletCall::RelinquishCertificate => {
                self.handle_relinquish_certificate(&mut reader, &originator)
                    .await
            }

            // Discovery Operations - delegated to wallet
            WalletCall::DiscoverByIdentityKey => {
                self.handle_discover_by_identity_key(&mut reader, &originator)
                    .await
            }
            WalletCall::DiscoverByAttributes => {
                self.handle_discover_by_attributes(&mut reader, &originator)
                    .await
            }
        }
    }

    /// The reference's `#invokeWallet` (`WalletWireProcessor.ts:2402-2418` at
    /// `ts-stack@edf6e03`, bsv-rs#202): a wallet's explicit error keeps its
    /// words and code; every other error the wallet returns is replaced by
    /// `Wallet operation failed`, so a wallet's words (which can carry paths
    /// or internal state) never reach the wire. The processor's own errors
    /// (its reading of the request, a false verdict, a stub) are raised
    /// outside this call and framed in their own words, as the reference's
    /// throws outside the wrapper are.
    async fn invoke_wallet<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        operation
            .await
            .map_err(|error| match explicit_wallet_code(&error) {
                Some(_) => error,
                None => Error::WalletError(WALLET_OPERATION_FAILED.to_string()),
            })
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
                // The reference's outer catch (`WalletWireProcessor.ts:2370-2396`
                // at `ts-stack@edf6e03`, bsv-rs#202): the error's own code when
                // it lies in 2 to 8, else unknownError (1); this crate's `Error`
                // carries no code (#137), so every frame is 1 today. The message
                // is the error's own words, cut at 4096 bytes; the stack an
                // empty string.
                writer.write_u8(explicit_wallet_code(&e).unwrap_or(UNKNOWN_ERROR));
                let message = wire_message(&e);
                let bytes = message.as_bytes();
                let bytes = &bytes[..bytes.len().min(MAX_WIRE_ERROR_MESSAGE_BYTES)];
                writer.write_var_int(bytes.len() as u64);
                writer.write_bytes(bytes);
                writer.write_var_int(0);
            }
        }

        Ok(writer.into_bytes())
    }

    // =========================================================================
    // Key Operation Handlers
    // =========================================================================

    async fn handle_get_public_key(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
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
        let result = self
            .invoke_wallet(self.wallet.get_public_key(args, originator))
            .await?;

        // Serialize response - result.public_key is a hex string
        let mut writer = WireWriter::new();
        let pubkey_bytes = from_hex(&result.public_key)?;
        writer.write_bytes(&pubkey_bytes);
        Ok(writer.into_bytes())
    }

    async fn handle_encrypt(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
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
        let result = self
            .invoke_wallet(self.wallet.encrypt(args, originator))
            .await?;

        Ok(write_encrypt_result(&result))
    }

    async fn handle_decrypt(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
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
        let result = self
            .invoke_wallet(self.wallet.decrypt(args, originator))
            .await?;

        Ok(write_decrypt_result(&result))
    }

    async fn handle_create_hmac(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
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
        let result = self
            .invoke_wallet(self.wallet.create_hmac(args, originator))
            .await?;

        Ok(write_create_hmac_result(&result))
    }

    async fn handle_verify_hmac(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
        let args = super::requests::read_verify_hmac_args(reader)?;
        let result = self
            .invoke_wallet(self.wallet.verify_hmac(args, originator))
            .await?;

        write_verify_hmac_result(&result)
    }

    async fn handle_create_signature(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
        let args = super::requests::read_create_signature_args(reader)?;
        let result = self
            .invoke_wallet(self.wallet.create_signature(args, originator))
            .await?;

        Ok(write_create_signature_result(&result))
    }

    async fn handle_verify_signature(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
        let args = super::requests::read_verify_signature_args(reader)?;
        let result = self
            .invoke_wallet(self.wallet.verify_signature(args, originator))
            .await?;

        write_verify_signature_result(&result)
    }

    async fn handle_reveal_counterparty_key_linkage(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
        let args = read_reveal_counterparty_key_linkage_args(reader)?;
        let result = self
            .invoke_wallet(
                self.wallet
                    .reveal_counterparty_key_linkage(args, originator),
            )
            .await?;

        Ok(write_reveal_counterparty_key_linkage_result(&result))
    }

    async fn handle_reveal_specific_key_linkage(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
        let args = read_reveal_specific_key_linkage_args(reader)?;
        let result = self
            .invoke_wallet(self.wallet.reveal_specific_key_linkage(args, originator))
            .await?;

        Ok(write_reveal_specific_key_linkage_result(&result))
    }

    // =========================================================================
    // Chain/Status Operation Handlers
    // =========================================================================

    async fn handle_is_authenticated(&self, originator: &str) -> Result<Vec<u8>, Error> {
        let result = self
            .invoke_wallet(self.wallet.is_authenticated(originator))
            .await?;
        let mut writer = WireWriter::new();
        writer.write_optional_bool(Some(result.authenticated));
        Ok(writer.into_bytes())
    }

    async fn handle_wait_for_authentication(&self, originator: &str) -> Result<Vec<u8>, Error> {
        let result = self
            .invoke_wallet(self.wallet.wait_for_authentication(originator))
            .await?;
        write_wait_for_authentication_result(&result)
    }

    async fn handle_get_height(&self, originator: &str) -> Result<Vec<u8>, Error> {
        let result = self
            .invoke_wallet(self.wallet.get_height(originator))
            .await?;
        let mut writer = WireWriter::new();
        writer.write_var_int(result.height as u64);
        Ok(writer.into_bytes())
    }

    async fn handle_get_header_for_height(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Result<Vec<u8>, Error> {
        // Read height argument
        let height = reader.read_var_int_u32("height")?;

        let args = crate::wallet::GetHeaderArgs { height };
        let result = self
            .invoke_wallet(self.wallet.get_header_for_height(args, originator))
            .await?;

        // The 80 bytes raw, no length prefix (`WalletWireProcessor.ts:1687-1690`
        // at `ts-stack@edf6e03`; BRC-100 `0100.md:2478` at `5119a9b`), another
        // length refused (`WalletResultValidation.ts:2297`, bsv-rs#183)
        super::header_result(&result.header)
    }

    async fn handle_get_network(&self, _originator: &str) -> Result<Vec<u8>, Error> {
        // Go uses single byte: 0x00=mainnet, 0x01=testnet (not length-prefixed string)
        let mut writer = WireWriter::new();
        let code = match self.network {
            Network::Mainnet => 0u8,
            Network::Testnet => 1u8,
        };
        writer.write_u8(code);
        Ok(writer.into_bytes())
    }

    async fn handle_get_version(&self, _originator: &str) -> Result<Vec<u8>, Error> {
        // Go writes raw UTF-8 bytes with NO length prefix
        let mut writer = WireWriter::new();
        writer.write_bytes(self.version.as_bytes());
        Ok(writer.into_bytes())
    }

    // =========================================================================
    // Action Operation Handlers
    // NOTE: These require a full wallet implementation. When args parsing
    // is implemented in encoding.rs, these can be updated to call the wallet.
    // For now, they return early errors since ProtoWallet doesn't support them.
    // =========================================================================

    async fn handle_create_action(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "createAction requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_sign_action(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "signAction requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_abort_action(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "abortAction requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_list_actions(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "listActions requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_internalize_action(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "internalizeAction requires a full wallet implementation".to_string(),
        ))
    }

    // =========================================================================
    // Output Operation Handlers
    // =========================================================================

    async fn handle_list_outputs(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "listOutputs requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_relinquish_output(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "relinquishOutput requires a full wallet implementation".to_string(),
        ))
    }

    // =========================================================================
    // Certificate Operation Handlers
    // =========================================================================

    async fn handle_acquire_certificate(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "acquireCertificate requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_list_certificates(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "listCertificates requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_prove_certificate(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "proveCertificate requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_relinquish_certificate(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "relinquishCertificate requires a full wallet implementation".to_string(),
        ))
    }

    // =========================================================================
    // Discovery Operation Handlers
    // =========================================================================

    async fn handle_discover_by_identity_key(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "discoverByIdentityKey requires a full wallet implementation".to_string(),
        ))
    }

    async fn handle_discover_by_attributes(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::WalletError(
            "discoverByAttributes requires a full wallet implementation".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;
    use crate::wallet::{ProtoWallet, SecurityLevel};

    /// The frame `encode_response` writes for an error: since #202's division
    /// a wallet's words never reach it, so the cut is pinned on the writer.
    fn error_frame(error: Error) -> Vec<u8> {
        create_test_processor().encode_response(Err(error)).unwrap()
    }

    /// #202: a message past 4096 bytes is cut at 4096 (`:2388-2391`), its
    /// length `fd 00 10`.
    #[test]
    fn a_message_past_4096_bytes_is_cut_at_4096() {
        let long = "a".repeat(5000);
        let frame = error_frame(Error::WalletError(long.clone()));
        let mut expected = vec![1, 0xfd, 0x00, 0x10];
        expected.extend(&long.as_bytes()[..4096]);
        expected.push(0);
        assert_eq!(frame, expected);
    }

    /// #202: the cut is at the byte, as the reference's `subarray` cuts it,
    /// even inside a character: `é` at bytes 4095-4096 leaves `c3` last.
    #[test]
    fn the_cut_is_at_the_byte_inside_a_character() {
        let long = format!("{}é", "a".repeat(4095));
        let frame = error_frame(Error::WalletError(long.clone()));
        assert_eq!(frame.len(), 4 + 4096 + 1);
        assert_eq!(&frame[4..frame.len() - 1], &long.as_bytes()[..4096]);
        assert_eq!(frame[frame.len() - 2..], [0xc3, 0]);
    }

    /// #202: the stack field is an empty string, a varint 0 and nothing after
    /// it (`:2395-2396`): an empty message is framed `01 00 00`.
    #[test]
    fn the_stack_field_is_a_varint_zero() {
        assert_eq!(error_frame(Error::WalletError(String::new())), [1, 0, 0]);
    }

    /// #202: the processor's own error that is not a `WalletError` is its
    /// `Display`, with no wallet replacement (`:2387`).
    #[test]
    fn a_processor_error_is_framed_as_its_display() {
        let frame = error_frame(Error::InvalidHex("zz".into()));
        let words = b"invalid hex string: zz";
        let mut expected = vec![1, words.len() as u8];
        expected.extend(words);
        expected.push(0);
        assert_eq!(frame, expected);
    }

    fn create_test_processor() -> WalletWireProcessor<ProtoWallet> {
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

        // Go wire format: single byte (0x00=mainnet, 0x01=testnet)
        let network_byte = reader.read_u8().unwrap();
        assert_eq!(network_byte, 0x01); // testnet
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

        // Go wire format: raw UTF-8 bytes (no length prefix)
        let version = std::str::from_utf8(reader.read_remaining()).unwrap();
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

    #[tokio::test]
    async fn test_process_create_action_not_supported() {
        let processor = create_test_processor();

        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::CreateAction.as_u8());
        writer.write_u8(0);
        // Write minimal args (will fail at wallet level)
        writer.write_string("test description"); // description
        writer.write_var_int(u64::MAX); // no inputBEEF
        writer.write_var_int(u64::MAX); // no inputs
        writer.write_var_int(u64::MAX); // no outputs
        writer.write_var_int(u64::MAX); // no lockTime
        writer.write_var_int(u64::MAX); // no version
        writer.write_var_int(u64::MAX); // no labels
        writer.write_i8(-1); // no options
        let request = writer.into_bytes();

        let response = processor.process_message(&request).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        // Should return error because ProtoWallet doesn't support createAction
        assert_ne!(error_byte, 0, "expected error from ProtoWallet");
    }
}
