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
    assert_request_consumed, read_create_hmac_args, read_create_signature_args, read_decrypt_args,
    read_encrypt_args, read_get_public_key_args, read_reveal_counterparty_key_linkage_args,
    read_reveal_specific_key_linkage_args, read_verify_hmac_args, read_verify_signature_args,
};
use super::results::{
    write_abort_action_result, write_create_hmac_result, write_create_signature_result,
    write_decrypt_result, write_encrypt_result, write_reveal_counterparty_key_linkage_result,
    write_reveal_specific_key_linkage_result, write_verify_hmac_result,
    write_verify_signature_result, write_wait_for_authentication_result,
};
use super::validation::{self, explicit_wallet_code, Refusal};
use super::WalletCall;
use crate::primitives::to_base64;
use crate::wallet::interface::WalletInterface;
use crate::wallet::types::Network;
use crate::wallet::AbortActionArgs;
use crate::Error;
use std::marker::PhantomData;

/// `MAX_WIRE_ERROR_MESSAGE_BYTES` (`WalletWireProcessor.ts:25`).
const MAX_WIRE_ERROR_MESSAGE_BYTES: usize = 4096;

/// The words of the reference's replacement (`WalletWireProcessor.ts:2417`
/// at `ts-stack@edf6e03`): every wallet error that is not an explicit one is
/// framed as `new WalletError('Wallet operation failed', unknownError)`.
const WALLET_OPERATION_FAILED: &str = "Wallet operation failed";

/// A call's answer: its result's bytes, or the processor's refusal.
type Answer = Result<Vec<u8>, Refusal>;

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
    _marker: PhantomData<W>,
}

impl<W: WalletInterface> WalletWireProcessor<W> {
    /// Creates a new processor with the given wallet.
    pub fn new(wallet: W) -> Self {
        Self {
            wallet,
            _marker: PhantomData,
        }
    }

    /// Returns a reference to the underlying wallet.
    pub fn wallet(&self) -> &W {
        &self.wallet
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
    async fn process_message_inner(&self, message: &[u8]) -> Answer {
        let mut reader = WireReader::new(message);

        // Read call code
        let call_code = reader.read_u8()?;
        let call = WalletCall::try_from(call_code)?;

        // Read originator
        let originator_len = reader.read_u8()? as usize;
        let originator_bytes = reader.read_bytes(originator_len)?;
        let originator = String::from_utf8(originator_bytes.to_vec())
            .map_err(|_| Error::WalletError("invalid originator UTF-8".to_string()))?;

        // The calls with no parameters read none (`#assertRequestConsumed`,
        // `WalletWireProcessor.ts:1610-1719`); every other call this
        // processor reads asserts after its last field (#193)
        if matches!(
            call,
            WalletCall::IsAuthenticated
                | WalletCall::WaitForAuthentication
                | WalletCall::GetHeight
                | WalletCall::GetNetwork
                | WalletCall::GetVersion
        ) {
            assert_request_consumed(&reader, call.method_name())?;
        }

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
    /// throws outside the wrapper are. With the `tracing` feature the words
    /// the frame drops go to one `warn` event here, with the call's name
    /// (bsv-rs#212), with the class too for a refusal whose class has no SDK
    /// code, and a refusal kept with its code to one `warn` event with the
    /// call's name and its class (#137); the wire is the same with the
    /// feature on or off.
    async fn invoke_wallet<T>(
        &self,
        call: WalletCall,
        operation: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        #[cfg(not(feature = "tracing"))]
        let _ = call;
        operation
            .await
            .map_err(|error| match explicit_wallet_code(&error) {
                Some(_) => {
                    #[cfg(feature = "tracing")]
                    if let Error::WalletRefusal { class, .. } = &error {
                        tracing::warn!(
                            call = call.method_name(),
                            class = class.name(),
                            "wallet refusal framed with its code"
                        );
                    }
                    error
                }
                None => {
                    #[cfg(feature = "tracing")]
                    match &error {
                        Error::WalletRefusal { class, message } => tracing::warn!(
                            call = call.method_name(),
                            class = class.name(),
                            error = %message,
                            "wallet error framed as Wallet operation failed"
                        ),
                        _ => tracing::warn!(
                            call = call.method_name(),
                            error = %error,
                            "wallet error framed as Wallet operation failed"
                        ),
                    }
                    Error::WalletError(WALLET_OPERATION_FAILED.to_string())
                }
            })
    }

    /// Encodes a response (success or error) into wire format.
    fn encode_response(&self, result: Answer) -> Result<Vec<u8>, Error> {
        let mut writer = WireWriter::new();

        match result {
            Ok(response_bytes) => {
                writer.write_u8(0); // Success
                writer.write_bytes(&response_bytes);
            }
            Err(e) => {
                // The reference's outer catch (`WalletWireProcessor.ts:2370-2396`
                // at `ts-stack@edf6e03`, bsv-rs#202): the refusal's code (6 for
                // an argument the reference's validator refuses, #216; a
                // wallet refusal's class, #137; else 1) and its words,
                // cut at 4096 bytes; the stack an empty string.
                writer.write_u8(e.code);
                let bytes = e.words.as_bytes();
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

    async fn handle_get_public_key(&self, reader: &mut WireReader<'_>, originator: &str) -> Answer {
        let args = read_get_public_key_args(reader)?;
        assert_request_consumed(reader, "getPublicKey")?;
        validation::get_public_key_args(&args)?;
        let result = self
            .invoke_wallet(
                WalletCall::GetPublicKey,
                self.wallet.get_public_key(args, originator),
            )
            .await?;

        // The key's 33 bytes, a result the reference refuses refused (#216)
        validation::public_key_result(&result.public_key)
    }

    async fn handle_encrypt(&self, reader: &mut WireReader<'_>, originator: &str) -> Answer {
        let args = read_encrypt_args(reader)?;
        assert_request_consumed(reader, "encrypt")?;
        validation::encrypt_args(&args)?;
        let result = self
            .invoke_wallet(WalletCall::Encrypt, self.wallet.encrypt(args, originator))
            .await?;

        validation::bytes_result(&result.ciphertext, "encrypt", "ciphertext")?;
        Ok(write_encrypt_result(&result))
    }

    async fn handle_decrypt(&self, reader: &mut WireReader<'_>, originator: &str) -> Answer {
        let args = read_decrypt_args(reader)?;
        assert_request_consumed(reader, "decrypt")?;
        validation::decrypt_args(&args)?;
        let result = self
            .invoke_wallet(WalletCall::Decrypt, self.wallet.decrypt(args, originator))
            .await?;

        validation::bytes_result(&result.plaintext, "decrypt", "plaintext")?;
        Ok(write_decrypt_result(&result))
    }

    async fn handle_create_hmac(&self, reader: &mut WireReader<'_>, originator: &str) -> Answer {
        let args = read_create_hmac_args(reader)?;
        assert_request_consumed(reader, "createHmac")?;
        validation::create_hmac_args(&args)?;
        let result = self
            .invoke_wallet(
                WalletCall::CreateHmac,
                self.wallet.create_hmac(args, originator),
            )
            .await?;

        Ok(write_create_hmac_result(&result))
    }

    async fn handle_verify_hmac(&self, reader: &mut WireReader<'_>, originator: &str) -> Answer {
        let args = read_verify_hmac_args(reader)?;
        assert_request_consumed(reader, "verifyHmac")?;
        validation::verify_hmac_args(&args)?;
        let result = self
            .invoke_wallet(
                WalletCall::VerifyHmac,
                self.wallet.verify_hmac(args, originator),
            )
            .await?;

        Ok(write_verify_hmac_result(&result)?)
    }

    async fn handle_create_signature(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Answer {
        let args = read_create_signature_args(reader)?;
        assert_request_consumed(reader, "createSignature")?;
        validation::create_signature_args(&args)?;
        let result = self
            .invoke_wallet(
                WalletCall::CreateSignature,
                self.wallet.create_signature(args, originator),
            )
            .await?;
        validation::signature_result(&result.signature)?;

        Ok(write_create_signature_result(&result))
    }

    async fn handle_verify_signature(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Answer {
        let args = read_verify_signature_args(reader)?;
        assert_request_consumed(reader, "verifySignature")?;
        validation::verify_signature_args(&args)?;
        let result = self
            .invoke_wallet(
                WalletCall::VerifySignature,
                self.wallet.verify_signature(args, originator),
            )
            .await?;

        Ok(write_verify_signature_result(&result)?)
    }

    async fn handle_reveal_counterparty_key_linkage(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Answer {
        let request = read_reveal_counterparty_key_linkage_args(reader)?;
        assert_request_consumed(reader, "revealCounterpartyKeyLinkage")?;
        let args = validation::reveal_counterparty_args(request)?;
        let request = args.clone();
        let result = self
            .invoke_wallet(
                WalletCall::RevealCounterpartyKeyLinkage,
                self.wallet
                    .reveal_counterparty_key_linkage(args, originator),
            )
            .await?;
        validation::reveal_counterparty_result(&request, &result)?;

        Ok(write_reveal_counterparty_key_linkage_result(&result))
    }

    async fn handle_reveal_specific_key_linkage(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Answer {
        let request = read_reveal_specific_key_linkage_args(reader)?;
        assert_request_consumed(reader, "revealSpecificKeyLinkage")?;
        let args = validation::reveal_specific_args(request)?;
        let request = args.clone();
        let result = self
            .invoke_wallet(
                WalletCall::RevealSpecificKeyLinkage,
                self.wallet.reveal_specific_key_linkage(args, originator),
            )
            .await?;
        validation::reveal_specific_result(&request, &result)?;

        Ok(write_reveal_specific_key_linkage_result(&result))
    }

    // =========================================================================
    // Chain/Status Operation Handlers
    // =========================================================================

    async fn handle_is_authenticated(&self, originator: &str) -> Answer {
        let result = self
            .invoke_wallet(
                WalletCall::IsAuthenticated,
                self.wallet.is_authenticated(originator),
            )
            .await?;
        let mut writer = WireWriter::new();
        writer.write_optional_bool(Some(result.authenticated));
        Ok(writer.into_bytes())
    }

    async fn handle_wait_for_authentication(&self, originator: &str) -> Answer {
        let result = self
            .invoke_wallet(
                WalletCall::WaitForAuthentication,
                self.wallet.wait_for_authentication(originator),
            )
            .await?;
        Ok(write_wait_for_authentication_result(&result)?)
    }

    async fn handle_get_height(&self, originator: &str) -> Answer {
        let result = self
            .invoke_wallet(WalletCall::GetHeight, self.wallet.get_height(originator))
            .await?;
        let mut writer = WireWriter::new();
        writer.write_var_int(validation::height_result(result.height)?.into());
        Ok(writer.into_bytes())
    }

    async fn handle_get_header_for_height(
        &self,
        reader: &mut WireReader<'_>,
        originator: &str,
    ) -> Answer {
        let height = validation::read_header_height(reader)?;
        assert_request_consumed(reader, "getHeaderForHeight")?;

        let args = crate::wallet::GetHeaderArgs { height };
        let result = self
            .invoke_wallet(
                WalletCall::GetHeaderForHeight,
                self.wallet.get_header_for_height(args, originator),
            )
            .await?;

        // The 80 bytes raw, no length prefix (`WalletWireProcessor.ts:1687-1690`
        // at `ts-stack@edf6e03`; BRC-100 `0100.md:2478` at `5119a9b`), another
        // length refused (`WalletResultValidation.ts:2297`, bsv-rs#183)
        Ok(super::header_result(&result.header)?)
    }

    async fn handle_get_network(&self, originator: &str) -> Answer {
        // The wallet's answer forwarded (`WalletWireProcessor.ts:1701-1705` at
        // `ts-stack@edf6e03`, bsv-rs#222), one byte: 0 mainnet, 1 testnet
        // (`:1710`); the result's rule is the `Network` type's
        let result = self
            .invoke_wallet(WalletCall::GetNetwork, self.wallet.get_network(originator))
            .await?;
        Ok(vec![u8::from(result.network == Network::Testnet)])
    }

    async fn handle_get_version(&self, originator: &str) -> Answer {
        // The wallet's answer forwarded (`:1721-1725`), 7 to 30 UTF-8 bytes
        // (`WalletResultValidation.ts:2304-2306`), written with no length
        // prefix (`:1730`)
        let result = self
            .invoke_wallet(WalletCall::GetVersion, self.wallet.get_version(originator))
            .await?;
        validation::version_result(&result.version)?;
        Ok(result.version.into_bytes())
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
    ) -> Answer {
        Err(
            Error::WalletError("createAction requires a full wallet implementation".to_string())
                .into(),
        )
    }

    async fn handle_sign_action(&self, _reader: &mut WireReader<'_>, _originator: &str) -> Answer {
        Err(
            Error::WalletError("signAction requires a full wallet implementation".to_string())
                .into(),
        )
    }

    async fn handle_abort_action(&self, reader: &mut WireReader<'_>, originator: &str) -> Answer {
        // The rest of the request as base64 (`WalletWireProcessor.ts:785-790`; #206)
        let reference = to_base64(reader.read_remaining());
        validation::abort_action_args(&reference)?;
        let args = AbortActionArgs { reference };
        let call = self.wallet.abort_action(args, originator);
        let result = self.invoke_wallet(WalletCall::AbortAction, call).await?;
        write_abort_action_result(&result)
    }

    async fn handle_list_actions(&self, _reader: &mut WireReader<'_>, _originator: &str) -> Answer {
        Err(
            Error::WalletError("listActions requires a full wallet implementation".to_string())
                .into(),
        )
    }

    async fn handle_internalize_action(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "internalizeAction requires a full wallet implementation".to_string(),
        )
        .into())
    }

    // =========================================================================
    // Output Operation Handlers
    // =========================================================================

    async fn handle_list_outputs(&self, _reader: &mut WireReader<'_>, _originator: &str) -> Answer {
        Err(
            Error::WalletError("listOutputs requires a full wallet implementation".to_string())
                .into(),
        )
    }

    async fn handle_relinquish_output(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "relinquishOutput requires a full wallet implementation".to_string(),
        )
        .into())
    }

    // =========================================================================
    // Certificate Operation Handlers
    // =========================================================================

    async fn handle_acquire_certificate(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "acquireCertificate requires a full wallet implementation".to_string(),
        )
        .into())
    }

    async fn handle_list_certificates(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "listCertificates requires a full wallet implementation".to_string(),
        )
        .into())
    }

    async fn handle_prove_certificate(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "proveCertificate requires a full wallet implementation".to_string(),
        )
        .into())
    }

    async fn handle_relinquish_certificate(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "relinquishCertificate requires a full wallet implementation".to_string(),
        )
        .into())
    }

    // =========================================================================
    // Discovery Operation Handlers
    // =========================================================================

    async fn handle_discover_by_identity_key(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "discoverByIdentityKey requires a full wallet implementation".to_string(),
        )
        .into())
    }

    async fn handle_discover_by_attributes(
        &self,
        _reader: &mut WireReader<'_>,
        _originator: &str,
    ) -> Answer {
        Err(Error::WalletError(
            "discoverByAttributes requires a full wallet implementation".to_string(),
        )
        .into())
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
        create_test_processor()
            .encode_response(Err(error.into()))
            .unwrap()
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

        // The privileged flag and reason, absent (#193)
        writer.write_i8(-1);
        writer.write_i8(-1);

        // for_self
        writer.write_i8(1);

        // seekPermission, absent (#193)
        writer.write_i8(-1);

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
        // The wallet's answer, ProtoWallet's mainnet (#222)
        let processor = create_test_processor();

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
        assert_eq!(network_byte, 0x00); // mainnet
    }

    #[tokio::test]
    async fn test_process_get_version() {
        // The wallet's answer, ProtoWallet's bsv-rs-<version> (#222)
        let processor = create_test_processor();

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
        assert_eq!(version, concat!("bsv-rs-", env!("CARGO_PKG_VERSION")));
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
