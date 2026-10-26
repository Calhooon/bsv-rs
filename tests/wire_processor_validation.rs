//! The processor validates a request's arguments ahead of the wallet call and
//! the wallet's result after it, in the reference's rules and words
//! (bsv-rs#216, the keeper's ruling): `validateWalletArgs` at each call
//! (`ts-stack@edf6e03` `WalletWireProcessor.ts:1407`, `:1434`, `:1461`,
//! `:1488`, `:1516`, `:1550`, `:1593`, `:1751`, `:1801`; the rules in
//! `validationHelpers.ts`) and `validateWalletResult` through
//! `#invokeValidatedWallet` (`:2421-2431`; the checks in
//! `WalletResultValidation.ts:2179-2306`). An argument refused is
//! `WERR_INVALID_PARAMETER`, code 6, `The <parameter> parameter must be
//! <mustBe>`, and the wallet is never called; a result refused is a plain
//! `Error`, code 1, `Invalid <call> result <field>: expected <expectation>`.
//! Each expected frame is the reference's bytes, assembled by hand: the code,
//! the words' varint length, the words, the empty stack `00`.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireWriter};
use bsv_rs::wallet::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ============================================================================
// The wallet: a ProtoWallet whose answers a test can replace
// ============================================================================

/// The fields a test replaces in the wallet's answer.
#[derive(Default)]
struct Answers {
    public_key: Option<String>,
    signature: Option<Vec<u8>>,
    height: Option<u32>,
    revelation_time: Option<String>,
    verifier: Option<PublicKey>,
    counterparty: Option<PublicKey>,
    key_id: Option<String>,
    protocol: Option<Protocol>,
    network: Option<Network>,
    version: Option<String>,
}

/// A ProtoWallet that counts the calls it receives and answers with the
/// replacements a test sets.
struct Wallet {
    inner: ProtoWallet,
    calls: AtomicUsize,
    answers: Mutex<Answers>,
}

impl Wallet {
    fn new(answers: Answers) -> Self {
        Self {
            inner: ProtoWallet::new(Some(PrivateKey::from_bytes(&[7; 32]).unwrap())),
            calls: AtomicUsize::new(0),
            answers: Mutex::new(answers),
        }
    }

    fn called(&self) -> bsv_rs::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Wallet {
            $(async fn $method(&self, _: $args, _: &str) -> bsv_rs::Result<$result> {
                unreachable!()
            })*

            async fn get_public_key(
                &self,
                args: GetPublicKeyArgs,
                o: &str,
            ) -> bsv_rs::Result<GetPublicKeyResult> {
                self.called()?;
                let mut result = WalletInterface::get_public_key(&self.inner, args, o).await?;
                if let Some(key) = self.answers.lock().unwrap().public_key.clone() {
                    result.public_key = key;
                }
                Ok(result)
            }
            async fn encrypt(&self, args: EncryptArgs, o: &str) -> bsv_rs::Result<EncryptResult> {
                self.called()?;
                WalletInterface::encrypt(&self.inner, args, o).await
            }
            async fn decrypt(&self, args: DecryptArgs, o: &str) -> bsv_rs::Result<DecryptResult> {
                self.called()?;
                WalletInterface::decrypt(&self.inner, args, o).await
            }
            async fn create_hmac(
                &self,
                args: CreateHmacArgs,
                o: &str,
            ) -> bsv_rs::Result<CreateHmacResult> {
                self.called()?;
                WalletInterface::create_hmac(&self.inner, args, o).await
            }
            async fn verify_hmac(
                &self,
                args: VerifyHmacArgs,
                o: &str,
            ) -> bsv_rs::Result<VerifyHmacResult> {
                self.called()?;
                WalletInterface::verify_hmac(&self.inner, args, o).await
            }
            async fn create_signature(
                &self,
                args: CreateSignatureArgs,
                o: &str,
            ) -> bsv_rs::Result<CreateSignatureResult> {
                self.called()?;
                let mut result = WalletInterface::create_signature(&self.inner, args, o).await?;
                if let Some(signature) = self.answers.lock().unwrap().signature.clone() {
                    result.signature = signature;
                }
                Ok(result)
            }
            async fn verify_signature(
                &self,
                args: VerifySignatureArgs,
                o: &str,
            ) -> bsv_rs::Result<VerifySignatureResult> {
                self.called()?;
                WalletInterface::verify_signature(&self.inner, args, o).await
            }
            async fn reveal_counterparty_key_linkage(
                &self,
                args: WalletRevealCounterpartyArgs,
                o: &str,
            ) -> bsv_rs::Result<RevealCounterpartyKeyLinkageResult> {
                self.called()?;
                let mut result =
                    WalletInterface::reveal_counterparty_key_linkage(&self.inner, args, o).await?;
                let answers = self.answers.lock().unwrap();
                if let Some(time) = answers.revelation_time.clone() {
                    result.revelation_time = time;
                }
                if let Some(key) = answers.verifier.clone() {
                    result.linkage.verifier = key;
                }
                if let Some(key) = answers.counterparty.clone() {
                    result.linkage.counterparty = key;
                }
                Ok(result)
            }
            async fn reveal_specific_key_linkage(
                &self,
                args: WalletRevealSpecificArgs,
                o: &str,
            ) -> bsv_rs::Result<RevealSpecificKeyLinkageResult> {
                self.called()?;
                let mut result =
                    WalletInterface::reveal_specific_key_linkage(&self.inner, args, o).await?;
                let answers = self.answers.lock().unwrap();
                if let Some(key) = answers.verifier.clone() {
                    result.linkage.verifier = key;
                }
                if let Some(key) = answers.counterparty.clone() {
                    result.linkage.counterparty = key;
                }
                if let Some(key_id) = answers.key_id.clone() {
                    result.key_id = key_id;
                }
                if let Some(protocol) = answers.protocol.clone() {
                    result.protocol = protocol;
                }
                Ok(result)
            }
            async fn is_authenticated(&self, _: &str) -> bsv_rs::Result<AuthenticatedResult> {
                self.called()?;
                Ok(AuthenticatedResult { authenticated: true })
            }
            async fn wait_for_authentication(&self, _: &str) -> bsv_rs::Result<AuthenticatedResult> {
                self.called()?;
                Ok(AuthenticatedResult { authenticated: true })
            }
            async fn get_height(&self, _: &str) -> bsv_rs::Result<GetHeightResult> {
                self.called()?;
                let height = self.answers.lock().unwrap().height.unwrap_or(800_000);
                Ok(GetHeightResult { height })
            }
            async fn get_header_for_height(
                &self,
                _: GetHeaderArgs,
                _: &str,
            ) -> bsv_rs::Result<GetHeaderResult> {
                self.called()?;
                Ok(GetHeaderResult { header: "00".repeat(80) })
            }
            async fn get_network(&self, o: &str) -> bsv_rs::Result<GetNetworkResult> {
                self.called()?;
                let mut result = WalletInterface::get_network(&self.inner, o).await?;
                if let Some(network) = self.answers.lock().unwrap().network {
                    result.network = network;
                }
                Ok(result)
            }
            async fn get_version(&self, o: &str) -> bsv_rs::Result<GetVersionResult> {
                self.called()?;
                let mut result = WalletInterface::get_version(&self.inner, o).await?;
                if let Some(version) = self.answers.lock().unwrap().version.clone() {
                    result.version = version;
                }
                Ok(result)
            }
        }
    };
}

wallet! {
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
}

// ============================================================================
// The frames
// ============================================================================

/// The reference's error frame: the code, the words behind their varint
/// length, the empty stack.
fn refusal(code: u8, words: &str) -> Vec<u8> {
    let mut frame = vec![code];
    let mut writer = WireWriter::new();
    writer.write_var_int(words.len() as u64);
    frame.extend(writer.into_bytes());
    frame.extend(words.as_bytes());
    frame.push(0);
    frame
}

/// A `WERR_INVALID_PARAMETER` frame, code 6.
fn invalid(parameter: &str, must_be: &str) -> Vec<u8> {
    refusal(6, &format!("The {parameter} parameter must be {must_be}"))
}

/// A result refused, code 1.
fn invalid_result(call: &str, field: &str, expected: &str) -> Vec<u8> {
    refusal(
        1,
        &format!("Invalid {call} result {field}: expected {expected}"),
    )
}

/// The key-related parameters (`#decodeKeyRelatedParams`,
/// `WalletWireProcessor.ts:2564-2583`).
#[derive(Clone)]
struct Key {
    level: u8,
    protocol: String,
    key_id: String,
    /// `11` self; a 33-byte key otherwise.
    counterparty: Vec<u8>,
    privileged: i8,
    reason: Option<String>,
}

impl Default for Key {
    fn default() -> Self {
        Self {
            level: 1,
            protocol: "testing wire".into(),
            key_id: "1".into(),
            counterparty: vec![11],
            privileged: -1,
            reason: None,
        }
    }
}

fn privileged(writer: &mut WireWriter, flag: i8, reason: &Option<String>) {
    writer.write_i8(flag);
    match reason {
        None => {
            writer.write_i8(-1);
        }
        Some(reason) => {
            writer.write_i8(reason.len() as i8);
            writer.write_bytes(reason.as_bytes());
        }
    }
}

impl Key {
    fn write(&self, writer: &mut WireWriter) {
        writer.write_u8(self.level);
        writer.write_var_int(self.protocol.len() as u64);
        writer.write_bytes(self.protocol.as_bytes());
        writer.write_var_int(self.key_id.len() as u64);
        writer.write_bytes(self.key_id.as_bytes());
        writer.write_bytes(&self.counterparty);
        privileged(writer, self.privileged, &self.reason);
    }
}

fn head(call: WalletCall) -> WireWriter {
    let mut writer = WireWriter::new();
    writer.write_u8(call.as_u8());
    writer.write_u8(4);
    writer.write_bytes(b"test");
    writer
}

fn bytes(writer: &mut WireWriter, bytes: &[u8]) {
    writer.write_var_int(bytes.len() as u64);
    writer.write_bytes(bytes);
}

/// encrypt, decrypt, createHmac: the key, the bytes, seekPermission absent.
fn key_bytes_request(call: WalletCall, key: &Key, data: &[u8]) -> Vec<u8> {
    let mut writer = head(call);
    key.write(&mut writer);
    bytes(&mut writer, data);
    writer.write_i8(-1);
    writer.into_bytes()
}

fn verify_hmac_request(key: &Key) -> Vec<u8> {
    let mut writer = head(WalletCall::VerifyHmac);
    key.write(&mut writer);
    writer.write_bytes(&[0; 32]);
    bytes(&mut writer, b"data");
    writer.write_i8(-1);
    writer.into_bytes()
}

fn create_signature_request(key: &Key) -> Vec<u8> {
    let mut writer = head(WalletCall::CreateSignature);
    key.write(&mut writer);
    writer.write_u8(1);
    bytes(&mut writer, b"data");
    writer.write_i8(-1);
    writer.into_bytes()
}

fn verify_signature_request(key: &Key, signature: &[u8]) -> Vec<u8> {
    let mut writer = head(WalletCall::VerifySignature);
    key.write(&mut writer);
    writer.write_i8(-1);
    bytes(&mut writer, signature);
    writer.write_u8(1);
    bytes(&mut writer, b"data");
    writer.write_i8(-1);
    writer.into_bytes()
}

fn get_public_key_request(key: &Key) -> Vec<u8> {
    let mut writer = head(WalletCall::GetPublicKey);
    writer.write_i8(0);
    key.write(&mut writer);
    writer.write_i8(-1);
    writer.write_i8(-1);
    writer.into_bytes()
}

fn identity_key_request(flag: i8, reason: &Option<String>) -> Vec<u8> {
    let mut writer = head(WalletCall::GetPublicKey);
    writer.write_i8(1);
    privileged(&mut writer, flag, reason);
    writer.write_i8(-1);
    writer.into_bytes()
}

fn verifier() -> PublicKey {
    PrivateKey::from_bytes(&[9; 32]).unwrap().public_key()
}

fn counterparty_key() -> PublicKey {
    PrivateKey::from_bytes(&[5; 32]).unwrap().public_key()
}

fn reveal_counterparty_request(flag: i8, reason: &Option<String>) -> Vec<u8> {
    let mut writer = head(WalletCall::RevealCounterpartyKeyLinkage);
    privileged(&mut writer, flag, reason);
    writer.write_bytes(&counterparty_key().to_compressed());
    writer.write_bytes(&verifier().to_compressed());
    writer.into_bytes()
}

fn reveal_specific_request(key: &Key) -> Vec<u8> {
    let mut writer = head(WalletCall::RevealSpecificKeyLinkage);
    key.write(&mut writer);
    writer.write_bytes(&verifier().to_compressed());
    writer.into_bytes()
}

fn header_request(height: u64) -> Vec<u8> {
    let mut writer = head(WalletCall::GetHeaderForHeight);
    writer.write_var_int(height);
    writer.into_bytes()
}

fn bare_request(call: WalletCall) -> Vec<u8> {
    head(call).into_bytes()
}

/// The processor's answer and the number of wallet calls it made.
async fn answer_with(answers: Answers, request: &[u8]) -> (Vec<u8>, usize) {
    let processor = WalletWireProcessor::new(Wallet::new(answers));
    let answer = processor.process_message(request).await.unwrap();
    (answer, processor.wallet().calls.load(Ordering::SeqCst))
}

async fn answer(request: &[u8]) -> (Vec<u8>, usize) {
    answer_with(Answers::default(), request).await
}

/// The processor refuses the request with `frame` and never calls the wallet.
async fn refused(request: &[u8], frame: &[u8]) {
    let (answer, calls) = answer(request).await;
    assert_eq!(answer, frame, "{:?}", String::from_utf8_lossy(&answer));
    assert_eq!(calls, 0, "the wallet is not called");
}

/// Every request a key-related rule reaches, built over `key`.
fn every_key_request(key: &Key) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("getPublicKey", get_public_key_request(key)),
        (
            "encrypt",
            key_bytes_request(WalletCall::Encrypt, key, b"data"),
        ),
        (
            "decrypt",
            key_bytes_request(WalletCall::Decrypt, key, b"data"),
        ),
        (
            "createHmac",
            key_bytes_request(WalletCall::CreateHmac, key, b"data"),
        ),
        ("verifyHmac", verify_hmac_request(key)),
        ("createSignature", create_signature_request(key)),
        (
            "verifySignature",
            verify_signature_request(key, &valid_signature()),
        ),
        ("revealSpecificKeyLinkage", reveal_specific_request(key)),
    ]
}

/// A canonical DER signature: r = 1, s = 1.
fn valid_signature() -> Vec<u8> {
    vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
}

// ============================================================================
// The arguments
// ============================================================================

/// `validateProtocol` (`validationHelpers.ts:198-205`) through
/// `validateStringLength` (`:348-356`): the protocol name 5 to 400 bytes, on
/// each of the eight calls that carry one.
#[tokio::test]
async fn a_protocol_name_outside_5_to_400_bytes_is_refused_with_code_6() {
    for (name, must_be) in [
        ("abcd".to_string(), "at least 5 length."),
        ("a".repeat(401), "no more than 400 length."),
    ] {
        let key = Key {
            protocol: name,
            ..Key::default()
        };
        for (call, request) in every_key_request(&key) {
            let (answer, calls) = answer(&request).await;
            assert_eq!(answer, invalid("protocolID[1]", must_be), "{call}");
            assert_eq!(calls, 0, "{call}");
        }
    }
}

/// `validateEncryptionArgs` (`:224-230`) and
/// `validateRevealSpecificKeyLinkageArgs` (`:1743-1750`): the key ID 1 to 800
/// bytes.
#[tokio::test]
async fn a_key_id_outside_1_to_800_bytes_is_refused_with_code_6() {
    for (key_id, must_be) in [
        (String::new(), "at least 1 length."),
        ("k".repeat(801), "no more than 800 length."),
    ] {
        let key = Key {
            key_id,
            ..Key::default()
        };
        for (call, request) in every_key_request(&key) {
            let (answer, calls) = answer(&request).await;
            assert_eq!(answer, invalid("keyID", must_be), "{call}");
            assert_eq!(calls, 0, "{call}");
        }
    }
}

/// The reference checks the protocol ahead of the key ID (`:226-227`).
#[tokio::test]
async fn the_protocol_is_judged_ahead_of_the_key_id() {
    let key = Key {
        protocol: "abc".into(),
        key_id: String::new(),
        ..Key::default()
    };
    refused(
        &key_bytes_request(WalletCall::Encrypt, &key, b"x"),
        &invalid("protocolID[1]", "at least 5 length."),
    )
    .await;
}

/// `validatePrivilege` (`:207-222`): a reason outside 5 to 50 bytes, on every
/// call that carries the privileged pair.
#[tokio::test]
async fn a_privileged_reason_outside_5_to_50_bytes_is_refused_with_code_6() {
    for (reason, must_be) in [
        ("four".to_string(), "at least 5 length."),
        ("r".repeat(51), "no more than 50 length."),
    ] {
        let key = Key {
            privileged: 1,
            reason: Some(reason.clone()),
            ..Key::default()
        };
        let mut requests = every_key_request(&key);
        requests.push((
            "getPublicKey identityKey",
            identity_key_request(1, &Some(reason.clone())),
        ));
        requests.push((
            "revealCounterpartyKeyLinkage",
            reveal_counterparty_request(1, &Some(reason.clone())),
        ));
        for (call, request) in requests {
            let (answer, calls) = answer(&request).await;
            assert_eq!(answer, invalid("privilegedReason", must_be), "{call}");
            assert_eq!(calls, 0, "{call}");
        }
    }
}

/// `validatePrivilege` (`:217-219`): `privileged` true with no reason.
#[tokio::test]
async fn privileged_without_a_reason_is_refused_with_code_6() {
    let key = Key {
        privileged: 1,
        ..Key::default()
    };
    let mut requests = every_key_request(&key);
    requests.push(("getPublicKey identityKey", identity_key_request(1, &None)));
    requests.push((
        "revealCounterpartyKeyLinkage",
        reveal_counterparty_request(1, &None),
    ));
    for (call, request) in requests {
        let (answer, calls) = answer(&request).await;
        assert_eq!(
            answer,
            invalid("privilegedReason", "a value when 'privileged' is true"),
            "{call}"
        );
        assert_eq!(calls, 0, "{call}");
    }
}

/// `validateVerifySignatureArgs` (`:1795-1804`): the signature at most 72
/// bytes, then canonical DER (`isCanonicalDERSignature`,
/// `Secp256k1Validation.ts:33-53`).
#[tokio::test]
async fn a_signature_past_72_bytes_or_not_canonical_der_is_refused_with_code_6() {
    let key = Key::default();
    refused(
        &verify_signature_request(&key, &[0x30; 73]),
        &invalid("signature", "at most 72 bytes"),
    )
    .await;
    let n =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    let mut s_at_order = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
    s_at_order.extend(&n);
    for bad in [
        vec![],
        // r = 0
        vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
        // r negative
        vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
        // r with a needless leading zero
        vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
        // the sequence's length one short
        vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        // a byte after s
        vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
        // s at the group order
        s_at_order,
    ] {
        refused(
            &verify_signature_request(&key, &bad),
            &invalid("signature", "a canonical DER-encoded ECDSA signature"),
        )
        .await;
    }
}

/// `#requireInteger(height, 'getHeaderForHeight height', 1, 0xffffffff)`
/// (`WalletWireProcessor.ts:1670-1675`, `:138-148`): a plain `Error`, code 1,
/// ahead of the trailing-data check.
#[tokio::test]
async fn a_header_height_outside_1_to_u32_max_is_refused_in_the_reference_words() {
    for height in [0u64, u32::MAX as u64 + 1] {
        refused(
            &header_request(height),
            &refusal(
                1,
                &format!(
                    "Invalid getHeaderForHeight height: expected an integer from 1 to 4294967295, received {height}"
                ),
            ),
        )
        .await;
    }
    let mut trailing = header_request(0);
    trailing.push(0);
    refused(
        &trailing,
        &refusal(
            1,
            "Invalid getHeaderForHeight height: expected an integer from 1 to 4294967295, received 0",
        ),
    )
    .await;
}

/// The bounds themselves pass: a protocol of 5 and 400 bytes, key IDs of 1
/// and 800, reasons of 5 and 50, a 72-byte signature's length rule, the
/// heights 1 and `u32::MAX`; each reaches the wallet once.
#[tokio::test]
async fn valid_arguments_at_the_bounds_reach_the_wallet() {
    for key in [
        Key {
            protocol: "a".repeat(400),
            key_id: "k".repeat(800),
            privileged: 1,
            reason: Some("r".repeat(50)),
            ..Key::default()
        },
        Key {
            protocol: "abcde".into(),
            key_id: "k".into(),
            privileged: 0,
            reason: Some("fives".into()),
            ..Key::default()
        },
    ] {
        for (call, request) in every_key_request(&key) {
            if matches!(call, "decrypt" | "verifyHmac" | "verifySignature") {
                // A ciphertext that does not open and a false verdict are the
                // wallet's answers: the wallet was called
                let (_, calls) = answer(&request).await;
                assert_eq!(calls, 1, "{call}");
                continue;
            }
            let (answer, calls) = answer(&request).await;
            assert_eq!(
                answer[0],
                0,
                "{call}: {:?}",
                String::from_utf8_lossy(&answer)
            );
            assert_eq!(calls, 1, "{call}");
        }
    }
    for request in [
        identity_key_request(1, &Some("fives".into())),
        reveal_counterparty_request(1, &Some("fives".into())),
        header_request(1),
        header_request(u32::MAX as u64),
        bare_request(WalletCall::GetHeight),
        bare_request(WalletCall::IsAuthenticated),
        bare_request(WalletCall::WaitForAuthentication),
    ] {
        let (answer, calls) = answer(&request).await;
        assert_eq!(answer[0], 0, "{:?}", String::from_utf8_lossy(&answer));
        assert_eq!(calls, 1);
    }
}

/// Four 33-byte keys that are no compressed point (`isValidCompressedPublicKey`,
/// `Secp256k1Validation.ts:15-22`): an `04` prefix, a `00` prefix, x = 5 (no
/// y; 5^3 + 7 is not a square modulo p), x = p + 1 (at or above the prime).
fn non_points() -> Vec<[u8; 33]> {
    let good = verifier().to_compressed();
    let mut prefixed = [0u8; 33];
    prefixed.copy_from_slice(&good);
    prefixed[0] = 0x04;
    let mut zero = prefixed;
    zero[0] = 0x00;
    let mut off_curve = [0u8; 33];
    off_curve[0] = 0x02;
    off_curve[32] = 5;
    let mut above_p = [0xffu8; 33];
    above_p[0] = 0x02;
    above_p[25..].copy_from_slice(&[0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30]);
    vec![prefixed, zero, off_curve, above_p]
}

fn reveal_counterparty_keys(counterparty: &[u8], verifier: &[u8]) -> Vec<u8> {
    let mut writer = head(WalletCall::RevealCounterpartyKeyLinkage);
    privileged(&mut writer, -1, &None);
    writer.write_bytes(counterparty);
    writer.write_bytes(verifier);
    writer.into_bytes()
}

fn reveal_specific_verifier(key: &Key, verifier: &[u8]) -> Vec<u8> {
    let mut writer = head(WalletCall::RevealSpecificKeyLinkage);
    key.write(&mut writer);
    writer.write_bytes(verifier);
    writer.into_bytes()
}

/// `validateRevealCounterpartyKeyLinkageArgs` (`validationHelpers.ts:1734-1741`)
/// over the keys the reference reads raw (`WalletWireProcessor.ts:1742-1747`):
/// `validatePublicKey` (`:182-188`) refuses a key that is no point, code 6,
/// the counterparty ahead of the verifier, both ahead of the privilege; the
/// wallet is never called (#226; until then the reader refused it, code 1).
#[tokio::test]
async fn a_counterparty_linkage_key_that_is_no_point_is_refused_with_code_6() {
    let good = verifier().to_compressed();
    let must_be = "a valid compressed secp256k1 public key";
    for bad in non_points() {
        refused(
            &reveal_counterparty_keys(&bad, &good),
            &invalid("counterparty", must_be),
        )
        .await;
        refused(
            &reveal_counterparty_keys(&good, &bad),
            &invalid("verifier", must_be),
        )
        .await;
        refused(
            &reveal_counterparty_keys(&bad, &bad),
            &invalid("counterparty", must_be),
        )
        .await;
        let mut writer = head(WalletCall::RevealCounterpartyKeyLinkage);
        privileged(&mut writer, 1, &None);
        writer.write_bytes(&good);
        writer.write_bytes(&bad);
        refused(&writer.into_bytes(), &invalid("verifier", must_be)).await;
    }
}

/// `validateRevealSpecificKeyLinkageArgs` (`validationHelpers.ts:1743-1750`)
/// over the verifier the reference reads raw (`WalletWireProcessor.ts:1796`):
/// a verifier that is no point is refused, code 6, ahead of the protocol, the
/// key ID and the privilege (#226).
#[tokio::test]
async fn a_specific_linkage_verifier_that_is_no_point_is_refused_with_code_6() {
    let short_protocol = Key {
        protocol: "abcd".into(),
        ..Key::default()
    };
    for bad in non_points() {
        for key in [Key::default(), short_protocol.clone()] {
            refused(
                &reveal_specific_verifier(&key, &bad),
                &invalid("verifier", "a valid compressed secp256k1 public key"),
            )
            .await;
        }
    }
}

/// revealSpecificKeyLinkage's counterparty flag 0 is absent
/// (`#decodeCounterparty`, `WalletWireProcessor.ts:2456-2457`), and
/// `validateCounterparty` (`validationHelpers.ts:190-193`) hands it to
/// `validateHexString` (`:523`): `The counterparty parameter must be a
/// hexadecimal string`, code 6, ahead of the verifier and the protocol (#226;
/// until then the reader refused it, `counterparty is required`, code 1).
#[tokio::test]
async fn a_specific_linkage_with_no_counterparty_is_refused_with_code_6() {
    let frame = invalid("counterparty", "a hexadecimal string");
    let absent = Key {
        counterparty: vec![0],
        ..Key::default()
    };
    refused(&reveal_specific_request(&absent), &frame).await;
    refused(&reveal_specific_verifier(&absent, &non_points()[2]), &frame).await;
    let short_protocol = Key {
        protocol: "abcd".into(),
        ..absent
    };
    refused(&reveal_specific_request(&short_protocol), &frame).await;
}

/// The keys that are points reach the wallet: `02` and `03` prefixes, and
/// an absent counterparty is refused only on revealSpecificKeyLinkage.
#[tokio::test]
async fn linkage_keys_that_are_points_reach_the_wallet() {
    let counterparty = counterparty_key().to_compressed();
    let verifier = verifier().to_compressed();
    let (reached, calls) = answer(&reveal_counterparty_keys(&counterparty, &verifier)).await;
    assert_eq!(reached[0], 0, "{:?}", String::from_utf8_lossy(&reached));
    assert_eq!(calls, 1);
    for counterparty in [vec![11], vec![12], counterparty.to_vec()] {
        let key = Key {
            counterparty,
            ..Key::default()
        };
        let (reached, calls) = answer(&reveal_specific_request(&key)).await;
        assert_eq!(reached[0], 0, "{:?}", String::from_utf8_lossy(&reached));
        assert_eq!(calls, 1);
    }
}

/// `#decodeProtocolID` (`WalletWireProcessor.ts:2440-2443`): a security level
/// other than 0, 1, 2 is refused by the reader in the reference's words, a
/// plain `Error`, code 1, on each of the eight calls that carry one (#226).
#[tokio::test]
async fn a_security_level_outside_0_to_2_is_refused_in_the_reference_words() {
    for level in [3u8, 255] {
        let key = Key {
            level,
            ..Key::default()
        };
        let frame = refusal(
            1,
            &format!("Invalid security level: expected 0, 1, or 2, received {level}"),
        );
        for (call, request) in every_key_request(&key) {
            let (answer, calls) = answer(&request).await;
            assert_eq!(
                answer,
                frame,
                "{call}: {:?}",
                String::from_utf8_lossy(&answer)
            );
            assert_eq!(calls, 0, "{call}: the wallet is not called");
        }
    }
}

/// The twelve calls this processor refuses as needing a full wallet keep
/// their words and code 1: no validation runs ahead of them. abortAction left
/// them for the wallet (bsv-rs#206).
#[tokio::test]
async fn the_twelve_stubs_are_untouched() {
    for call in [
        WalletCall::CreateAction,
        WalletCall::SignAction,
        WalletCall::ListActions,
        WalletCall::InternalizeAction,
        WalletCall::ListOutputs,
        WalletCall::RelinquishOutput,
        WalletCall::AcquireCertificate,
        WalletCall::ListCertificates,
        WalletCall::ProveCertificate,
        WalletCall::RelinquishCertificate,
        WalletCall::DiscoverByIdentityKey,
        WalletCall::DiscoverByAttributes,
    ] {
        let (answer, calls) = answer(&bare_request(call)).await;
        let words = format!(
            "{} requires a full wallet implementation",
            call.method_name()
        );
        assert_eq!(answer, refusal(1, &words), "{call}");
        assert_eq!(calls, 0);
    }
}

// ============================================================================
// The results
// ============================================================================

/// The processor answers `frame` after calling the wallet once.
async fn result_refused(answers: Answers, request: &[u8], frame: &[u8]) {
    let (answer, calls) = answer_with(answers, request).await;
    assert_eq!(answer, frame, "{:?}", String::from_utf8_lossy(&answer));
    assert_eq!(calls, 1, "the wallet answered");
}

/// getPublicKey's key (`WalletResultValidation.ts:2207-2209`, `publicKey`
/// `:928-933`, `hex` `:917-926`).
#[tokio::test]
async fn a_public_key_result_the_reference_refuses_is_refused_with_code_1() {
    let request = get_public_key_request(&Key::default());
    let x_at_p = format!("02{}", "ff".repeat(24) + "fffffffe" + "fffffc2f");
    for (key, expected) in [
        ("0".to_string(), "an even-length hex string"),
        ("zz".to_string(), "an even-length hex string"),
        ("02".repeat(32), "33 hexadecimal bytes"),
        (
            format!("04{}", "11".repeat(32)),
            "a valid compressed secp256k1 public key",
        ),
        (x_at_p, "a valid compressed secp256k1 public key"),
    ] {
        let answers = Answers {
            public_key: Some(key.clone()),
            ..Answers::default()
        };
        result_refused(
            answers,
            &request,
            &invalid_result("getPublicKey", "publicKey", expected),
        )
        .await;
    }
    // Upper-case hex is the reference's too (`/^(?:[0-9a-fA-F]{2})*$/`)
    let key = verifier().to_hex().to_uppercase();
    let answers = Answers {
        public_key: Some(key),
        ..Answers::default()
    };
    let (answer, _) = answer_with(answers, &request).await;
    assert_eq!(answer[1..], verifier().to_compressed());
}

/// createSignature's signature (`:2219-2225`).
#[tokio::test]
async fn a_signature_result_past_72_bytes_or_not_canonical_is_refused_with_code_1() {
    let request = create_signature_request(&Key::default());
    for (signature, expected) in [
        (vec![0x30; 73], "at most 72 bytes"),
        (vec![], "a canonical DER-encoded ECDSA signature"),
        (
            vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
            "a canonical DER-encoded ECDSA signature",
        ),
    ] {
        let answers = Answers {
            signature: Some(signature),
            ..Answers::default()
        };
        result_refused(
            answers,
            &request,
            &invalid_result("createSignature", "signature", expected),
        )
        .await;
    }
}

/// getHeight's height (`:2293-2295`, `rangedInteger` `:946-961`).
#[tokio::test]
async fn a_height_result_of_0_is_refused_with_code_1() {
    let answers = Answers {
        height: Some(0),
        ..Answers::default()
    };
    result_refused(
        answers,
        &bare_request(WalletCall::GetHeight),
        &invalid_result("getHeight", "height", "an integer from 1 to 4294967295"),
    )
    .await;
}

/// revealCounterpartyKeyLinkage's result (`:2226-2241`, `isoTimestamp`
/// `:992-999`): the time, then the requested verifier and counterparty.
#[tokio::test]
async fn a_counterparty_linkage_result_the_reference_refuses_is_refused_with_code_1() {
    const CALL: &str = "revealCounterpartyKeyLinkage";
    let request = reveal_counterparty_request(-1, &None);
    for (time, expected) in [
        (String::new(), "1\u{2013}64 UTF-8 bytes"),
        (
            "2024-01-01T00:00:00.000Z".repeat(3),
            "1\u{2013}64 UTF-8 bytes",
        ),
        ("yesterday".into(), "an ISO timestamp with a timezone"),
        (
            "2024-01-01T00:00:00".into(),
            "an ISO timestamp with a timezone",
        ),
        ("2024-13-01T00:00:00Z".into(), "a valid ISO timestamp"),
        ("2024-01-01T25:00Z".into(), "a valid ISO timestamp"),
    ] {
        let answers = Answers {
            revelation_time: Some(time),
            ..Answers::default()
        };
        result_refused(
            answers,
            &request,
            &invalid_result(CALL, "revelationTime", expected),
        )
        .await;
    }
    let answers = Answers {
        verifier: Some(counterparty_key()),
        ..Answers::default()
    };
    result_refused(
        answers,
        &request,
        &invalid_result(CALL, "verifier", "the requested verifier"),
    )
    .await;
    let answers = Answers {
        counterparty: Some(verifier()),
        ..Answers::default()
    };
    result_refused(
        answers,
        &request,
        &invalid_result(CALL, "counterparty", "the requested counterparty"),
    )
    .await;
}

/// revealSpecificKeyLinkage's result (`:2242-2281`): the verifier, the
/// counterparty for self, anyone and a key, the protocol, the key ID.
#[tokio::test]
async fn a_specific_linkage_result_the_reference_refuses_is_refused_with_code_1() {
    const CALL: &str = "revealSpecificKeyLinkage";
    let key = Key::default();
    let other = Key {
        counterparty: counterparty_key().to_compressed().to_vec(),
        ..Key::default()
    };
    let anyone = Key {
        counterparty: vec![12],
        ..Key::default()
    };
    let cases = [
        (
            &key,
            Answers {
                verifier: Some(counterparty_key()),
                ..Answers::default()
            },
            ("verifier", "the requested verifier"),
        ),
        (
            &key,
            Answers {
                counterparty: Some(verifier()),
                ..Answers::default()
            },
            (
                "counterparty",
                "the prover's identity key for counterparty self",
            ),
        ),
        (
            &anyone,
            Answers {
                counterparty: Some(verifier()),
                ..Answers::default()
            },
            ("counterparty", "the canonical anyone public key"),
        ),
        (
            &other,
            Answers {
                counterparty: Some(verifier()),
                ..Answers::default()
            },
            ("counterparty", "the requested counterparty"),
        ),
        (
            &key,
            Answers {
                protocol: Some(Protocol::new(SecurityLevel::Silent, "testing wire")),
                ..Answers::default()
            },
            ("protocolID", "the requested protocol"),
        ),
        (
            &key,
            Answers {
                key_id: Some("2".into()),
                ..Answers::default()
            },
            ("keyID", "the requested key ID"),
        ),
        (
            &key,
            Answers {
                key_id: Some(String::new()),
                ..Answers::default()
            },
            ("keyID", "1\u{2013}800 UTF-8 bytes"),
        ),
        (
            &key,
            Answers {
                protocol: Some(Protocol::new(SecurityLevel::App, "abcd")),
                ..Answers::default()
            },
            ("protocolID[1]", "5\u{2013}400 UTF-8 bytes"),
        ),
    ];
    for (key, answers, (field, expected)) in cases {
        result_refused(
            answers,
            &reveal_specific_request(key),
            &invalid_result(CALL, field, expected),
        )
        .await;
    }
}

/// The crate's ProtoWallet answers both linkages in the shape the reference's
/// result checks accept, for self, anyone and a key: the anyone key is
/// `PrivateKey(1)`'s, as the reference's ProtoWallet answers
/// (`ProtoWallet.ts:235-240`).
#[tokio::test]
async fn the_proto_wallet_linkages_pass_the_result_checks() {
    for counterparty in [
        vec![11],
        vec![12],
        counterparty_key().to_compressed().to_vec(),
    ] {
        let key = Key {
            counterparty,
            ..Key::default()
        };
        let (answer, calls) = answer(&reveal_specific_request(&key)).await;
        assert_eq!(answer[0], 0, "{:?}", String::from_utf8_lossy(&answer));
        assert_eq!(calls, 1);
    }
    let (answer, _) = answer(&reveal_counterparty_request(-1, &None)).await;
    assert_eq!(answer[0], 0, "{:?}", String::from_utf8_lossy(&answer));
}

// ============================================================================
// getNetwork and getVersion: the wallet's answers forwarded (bsv-rs#222)
// ============================================================================

/// The reference's processor calls `this.wallet.getNetwork({}, originator)`
/// and `this.wallet.getVersion({}, originator)` (`WalletWireProcessor.ts:1701-1705`,
/// `:1721-1725` at `ts-stack@edf6e03`) and writes the network as one byte, 0
/// for mainnet (`:1710`), and the version's UTF-8 bytes with no length
/// (`:1730`): the wallet's answers, never the processor's own.
#[tokio::test]
async fn get_network_and_get_version_forward_the_wallets_answers_byte_for_byte() {
    for (network, byte) in [(Network::Mainnet, 0u8), (Network::Testnet, 1)] {
        let answers = Answers {
            network: Some(network),
            ..Answers::default()
        };
        let (answer, calls) = answer_with(answers, &bare_request(WalletCall::GetNetwork)).await;
        assert_eq!(answer, [0, byte], "{network:?}");
        assert_eq!(calls, 1, "the wallet answered");
    }
    for version in ["vendor-1.0.0", "wallet-7.8.9-rc.1+\u{e9}t\u{e9}"] {
        let answers = Answers {
            version: Some(version.to_string()),
            ..Answers::default()
        };
        let (answer, calls) = answer_with(answers, &bare_request(WalletCall::GetVersion)).await;
        assert_eq!(answer[0], 0, "{:?}", String::from_utf8_lossy(&answer));
        assert_eq!(&answer[1..], version.as_bytes());
        assert_eq!(calls, 1, "the wallet answered");
    }
}

/// getVersion's version (`WalletResultValidation.ts:2304-2306`, `string`
/// `:908-915`): 7 to 30 UTF-8 bytes, the refusal in the reference's words
/// with its en dash; the bounds themselves pass.
#[tokio::test]
async fn a_version_result_outside_7_to_30_bytes_is_refused_with_code_1() {
    let refused_frame = invalid_result("getVersion", "version", "7\u{2013}30 UTF-8 bytes");
    for version in ["0.1.0".to_string(), "v1.0.0".to_string(), "v".repeat(31)] {
        let answers = Answers {
            version: Some(version.clone()),
            ..Answers::default()
        };
        result_refused(
            answers,
            &bare_request(WalletCall::GetVersion),
            &refused_frame,
        )
        .await;
    }
    // Bytes, not characters: six two-byte characters are 12 bytes
    for version in ["v1.0.00".to_string(), "v".repeat(30), "\u{e9}".repeat(6)] {
        let answers = Answers {
            version: Some(version.clone()),
            ..Answers::default()
        };
        let (answer, _) = answer_with(answers, &bare_request(WalletCall::GetVersion)).await;
        assert_eq!(answer[0], 0, "{version:?}");
    }
}

/// getNetwork's network (`WalletResultValidation.ts:2299-2303`): mainnet or
/// testnet, else `Invalid getNetwork result network: expected mainnet or
/// testnet`. A wallet here answers a `Network`, which has the two values and
/// no third, so the processor has no network to refuse; the reference's rule
/// is the type's, and a third read from JSON (the HTTP substrate's answer) is
/// refused where it is read.
#[test]
fn a_network_outside_mainnet_and_testnet_is_no_network_result() {
    for network in ["regtest", "Mainnet", "", "stn"] {
        let read: Result<GetNetworkResult, _> =
            serde_json::from_value(serde_json::json!({ "network": network }));
        assert!(
            read.is_err(),
            "{network:?} read as {:?}",
            read.unwrap().network
        );
    }
    for (network, value) in [("mainnet", Network::Mainnet), ("testnet", Network::Testnet)] {
        let read: GetNetworkResult =
            serde_json::from_value(serde_json::json!({ "network": network })).unwrap();
        assert_eq!(read.network, value);
    }
}

/// `ProtoWallet` answers mainnet and `bsv-rs-<version>`, BRC-100's
/// vendor-1.0.0 shape (`wallet/0100.md:2517` at `5119a9b`), and both pass
/// the reference's result checks through a processor built with `new`.
#[tokio::test]
async fn the_proto_wallet_network_and_version_pass_the_result_checks() {
    let (network, calls) = answer(&bare_request(WalletCall::GetNetwork)).await;
    assert_eq!(network, [0, 0]);
    assert_eq!(calls, 1);
    let (frame, calls) = answer(&bare_request(WalletCall::GetVersion)).await;
    let version = concat!("bsv-rs-", env!("CARGO_PKG_VERSION"));
    assert_eq!(frame[0], 0, "{:?}", String::from_utf8_lossy(&frame));
    assert_eq!(&frame[1..], version.as_bytes());
    assert!((7..=30).contains(&version.len()));
    assert_eq!(calls, 1);
}
