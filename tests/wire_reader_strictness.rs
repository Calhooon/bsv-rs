//! The wallet wire's readers refuse what the reference's readers refuse, and
//! the writer makes no frame the reference's reader refuses (bsv-rs#183).
//!
//! The reference is `ts-stack@edf6e03`: `Certificate.fromBinary`
//! (`packages/sdk/src/auth/certificates/Certificate.ts:329-408`), the
//! transceiver's listCertificates, discovery and getHeaderForHeight readers
//! (`packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1500-1550`,
//! `:1682-1760`, `:1903`) and the processor's result check
//! (`WalletWireProcessor.ts:1681-1685`, `validateWalletResult`,
//! `WalletResultValidation.ts:2296-2297`). Every frame is hand-assembled to
//! those lines, a valid one mutated at the byte under test.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::to_base64;
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::collections::HashMap;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// r = 1, s = 1: the shortest DER `Signature.fromDER` reads.
const SIGNATURE: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

/// Answers every call with the success byte and `body`.
struct CannedWire {
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl WalletWire for CannedWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        let mut answer = vec![0u8];
        answer.extend_from_slice(&self.body);
        Ok(answer)
    }
}

fn client(body: Vec<u8>) -> WalletWireTransceiver<CannedWire> {
    WalletWireTransceiver::new(CannedWire { body })
}

fn var_int(out: &mut Vec<u8>, n: u64) {
    let mut w = WireWriter::new();
    w.write_var_int(n);
    out.extend_from_slice(w.as_bytes());
}

fn var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    var_int(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn key(hex_key: &str) -> Vec<u8> {
    hex::decode(hex_key).unwrap()
}

/// A 33-byte key `02 || x` with x = 5, which no point on secp256k1 has
/// (5^3 + 7 is not a square modulo p).
fn off_curve() -> Vec<u8> {
    let mut k = vec![0x02];
    k.extend_from_slice(&[0; 31]);
    k.push(5);
    k
}

/// `Certificate.toBinary`'s parts (`Certificate.ts:229-321`), each mutable.
struct Parts {
    subject: Vec<u8>,
    certifier: Vec<u8>,
    /// The field count's varint and the fields, as written.
    fields: Vec<u8>,
    signature: Vec<u8>,
}

impl Parts {
    fn valid() -> Self {
        Self {
            subject: key(G),
            certifier: key(TWO_G),
            fields: fields(&[(b"name", b"Fixture"), (b"role", b"reader")]),
            signature: SIGNATURE.to_vec(),
        }
    }

    /// type(32), serialNumber(32), subject(33), certifier(33), the outpoint
    /// (txid 32 + varint), the fields, the signature as the bytes remaining
    /// (`Certificate.ts:333-397`).
    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0x11; 32];
        out.extend_from_slice(&[0x22; 32]);
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(&self.certifier);
        out.extend_from_slice(&[0x33; 32]);
        out.push(1);
        out.extend_from_slice(&self.fields);
        out.extend_from_slice(&self.signature);
        out
    }
}

fn fields(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    var_int(&mut out, entries.len() as u64);
    for (name, value) in entries {
        var_bytes(&mut out, name);
        var_bytes(&mut out, value);
    }
    out
}

fn message(error: Error) -> String {
    match error {
        Error::WalletError(m) => m,
        other => panic!("expected a WalletError, got {other:?}"),
    }
}

fn read_certificate(bytes: &[u8]) -> Result<WalletCertificate, Error> {
    WireReader::new(bytes).read_wallet_certificate()
}

/// A listCertificates result of one certificate (`WalletWireTransceiver.ts:1500-1544`):
/// total, the certificate's length and bytes, the keyring flag and entries,
/// the verifier's length and bytes.
fn list_frame(certificate: &[u8], keyring: &[u8], verifier: &[u8]) -> Vec<u8> {
    let mut out = vec![1];
    var_bytes(&mut out, certificate);
    out.extend_from_slice(keyring);
    var_bytes(&mut out, verifier);
    out
}

fn no_keyring() -> Vec<u8> {
    vec![0]
}

async fn list(frame: Vec<u8>) -> Result<ListCertificatesResult, Error> {
    let args = ListCertificatesArgs {
        certifiers: vec![],
        types: vec![],
        limit: None,
        offset: None,
        privileged: None,
        privileged_reason: None,
    };
    client(frame)
        .list_certificates(args, "fixtures.invalid")
        .await
}

/// A discovery result of one entry (`WalletWireTransceiver.ts:1700-1752`):
/// the certificate, three strings, the trust byte, the public keyring, the
/// decrypted fields.
fn discovery_frame(certificate: &[u8], trust: u8, keyring: &[u8], decrypted: &[u8]) -> Vec<u8> {
    let mut out = vec![1];
    var_bytes(&mut out, certificate);
    var_bytes(&mut out, b"Fixture Certifier");
    var_bytes(&mut out, b"https://certifier.invalid/icon");
    var_bytes(&mut out, b"fixture only");
    out.push(trust);
    out.extend_from_slice(keyring);
    out.extend_from_slice(decrypted);
    out
}

async fn discover(frame: Vec<u8>) -> Result<DiscoverCertificatesResult, Error> {
    let args = DiscoverByIdentityKeyArgs {
        identity_key: G.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    };
    client(frame)
        .discover_by_identity_key(args, "fixtures.invalid")
        .await
}

/// The certificate read by both readers: `WireReader::read_wallet_certificate`
/// and the transceiver's, inside a listCertificates and a discovery frame.
async fn every_reader(certificate: &[u8]) -> [Result<(), String>; 3] {
    let direct = read_certificate(certificate).map(drop).map_err(message);
    let listed = list(list_frame(certificate, &no_keyring(), &[]))
        .await
        .map(drop)
        .map_err(message);
    let discovered = discover(discovery_frame(certificate, 5, &[0], &[0]))
        .await
        .map(drop)
        .map_err(message);
    [direct, listed, discovered]
}

async fn refused_by_every_reader(certificate: &[u8], words: &str) {
    for read in every_reader(certificate).await {
        let error = read.expect_err("refused");
        assert!(error.contains(words), "{error:?} lacks {words:?}");
    }
}

#[tokio::test]
async fn the_valid_certificate_is_read_by_every_reader() {
    for read in every_reader(&Parts::valid().bytes()).await {
        read.unwrap();
    }
    let read = read_certificate(&Parts::valid().bytes()).unwrap();
    assert_eq!(read.subject, G);
    assert_eq!(read.certifier, TWO_G);
    assert_eq!(read.signature, "3006020101020101");
    assert_eq!(read.fields.len(), 2);
}

// ---------------------------------------------------------------------------
// 1. getHeaderForHeight: exactly 80 bytes after the error byte
// ---------------------------------------------------------------------------

/// `WalletWireTransceiver.ts:1903`, `#requireResponseLength(header, 80, ...)`
/// (`:2027-2031`): "Wallet Wire getHeaderForHeight response has an invalid
/// length".
#[tokio::test]
async fn a_header_that_is_not_80_bytes_is_refused() {
    for length in [0, 79, 81] {
        let error = client(vec![1; length])
            .get_header(GetHeaderArgs { height: 1 }, "fixtures.invalid")
            .await
            .unwrap_err();
        assert_eq!(
            message(error),
            "Wallet Wire getHeaderForHeight response has an invalid length"
        );
    }
    let read = client(vec![1; 80])
        .get_header(GetHeaderArgs { height: 1 }, "fixtures.invalid")
        .await
        .unwrap();
    assert_eq!(read.header, "01".repeat(80));
}

/// Answers `get_header_for_height` with its header; every other method is
/// unreachable from these tests.
struct HeaderWallet(String);

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! header_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for HeaderWallet {
            $(async fn $method(&self, _: $args, _: &str) -> bsv_rs::Result<$result> {
                unreachable!()
            })*

            async fn is_authenticated(&self, _: &str) -> bsv_rs::Result<AuthenticatedResult> {
                unreachable!()
            }
            async fn wait_for_authentication(&self, _: &str) -> bsv_rs::Result<AuthenticatedResult> {
                unreachable!()
            }
            async fn get_height(&self, _: &str) -> bsv_rs::Result<GetHeightResult> {
                unreachable!()
            }
            async fn get_header_for_height(
                &self,
                _: GetHeaderArgs,
                _: &str,
            ) -> bsv_rs::Result<GetHeaderResult> {
                Ok(GetHeaderResult { header: self.0.clone() })
            }
            async fn get_network(&self, _: &str) -> bsv_rs::Result<GetNetworkResult> {
                unreachable!()
            }
            async fn get_version(&self, _: &str) -> bsv_rs::Result<GetVersionResult> {
                unreachable!()
            }
        }
    };
}

header_wallet! {
        (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
        (encrypt, EncryptArgs, EncryptResult),
        (decrypt, DecryptArgs, DecryptResult),
        (create_hmac, CreateHmacArgs, CreateHmacResult),
        (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
        (create_signature, CreateSignatureArgs, CreateSignatureResult),
        (verify_signature, VerifySignatureArgs, VerifySignatureResult),
        (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
        (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
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

async fn processor_answer(header: String, request: &[u8]) -> Vec<u8> {
    WalletWireProcessor::new(HeaderWallet(header))
        .process_message(request)
        .await
        .unwrap()
}

/// The processor writes the wallet's header only when it is 80 bytes: the
/// reference's `#invokeValidatedWallet` (`WalletWireProcessor.ts:1681-1685`)
/// runs `validateWalletResult`, whose `hex(result.header, call, 'header', 80)`
/// (`WalletResultValidation.ts:2296-2297`) refuses another length with
/// "Invalid getHeaderForHeight result header: expected 80 hexadecimal bytes"
/// (`:917-926`, `invalid` `:510-512`). The refusal is an error frame.
#[tokio::test]
async fn the_processor_refuses_a_wallets_header_that_is_not_80_bytes() {
    let request = [WalletCall::GetHeaderForHeight.as_u8(), 0, 1];
    for length in [79, 81] {
        let answer = processor_answer("01".repeat(length), &request).await;
        assert_ne!(answer[0], 0, "an error frame");
        let mut reader = WireReader::new(&answer[1..]);
        let words = reader.read_string().unwrap();
        assert!(
            words.contains(
                "Invalid getHeaderForHeight result header: expected 80 hexadecimal bytes"
            ),
            "{words:?}"
        );
    }
    let answer = processor_answer("01".repeat(80), &request).await;
    assert_eq!(answer.len(), 81);
    assert_eq!(answer[0], 0);
}

// ---------------------------------------------------------------------------
// 2. The certificate frame (`Certificate.fromBinary`)
// ---------------------------------------------------------------------------

/// `Certificate.ts:342`, `:347`: `assertCompressedPublicKey` runs
/// `PublicKey.fromDER` on the 33 bytes (`:135-142`), which decompresses
/// (`Point.fromDER`, `Point.ts:322-323`): a prefix other than 02 or 03 and an
/// x with no point are both refused, "Invalid certificate subject: expected a
/// compressed secp256k1 public key".
#[tokio::test]
async fn a_certificate_subject_or_certifier_that_is_not_a_compressed_key_is_refused() {
    let mut prefixed = key(G);
    prefixed[0] = 0x04;
    for bad in [prefixed, off_curve()] {
        let mut parts = Parts::valid();
        parts.subject = bad.clone();
        refused_by_every_reader(
            &parts.bytes(),
            "Invalid certificate subject: expected a compressed secp256k1 public key",
        )
        .await;
        let mut parts = Parts::valid();
        parts.certifier = bad;
        refused_by_every_reader(
            &parts.bytes(),
            "Invalid certificate certifier: expected a compressed secp256k1 public key",
        )
        .await;
    }
}

/// `Certificate.ts:357-363`: the field count is `readVarIntNumStrict(false)`,
/// at most `MAX_CERTIFICATE_FIELDS` (100,000, `:26`) and at most a third of
/// the bytes remaining, each refused before a field is read; nine 0xFF are a
/// count past `Number.MAX_SAFE_INTEGER`, refused by the strict reader
/// (`readVarIntNumStrict.ts`: "number too large to retain precision"), never
/// an empty map.
#[tokio::test]
async fn a_certificate_field_count_past_the_maximum_or_the_bytes_is_refused() {
    let mut parts = Parts::valid();
    parts.fields = vec![0xfe, 0xa1, 0x86, 0x01, 0x00]; // 100,001
    refused_by_every_reader(
        &parts.bytes(),
        "Certificate field count exceeds the maximum of 100000",
    )
    .await;

    // One field ("a" = "b", 4 bytes) and the signature (8 bytes): 12 bytes
    // remain after the count, so 4 is the most a count may say.
    let mut parts = Parts::valid();
    parts.fields = fields(&[(b"a", b"b")]);
    parts.fields[0] = 5;
    refused_by_every_reader(
        &parts.bytes(),
        "Certificate field count exceeds the available data",
    )
    .await;

    let mut parts = Parts::valid();
    parts.fields = vec![0xff; 9];
    refused_by_every_reader(&parts.bytes(), "number too large to retain precision").await;
}

/// `Certificate.ts:367-370`: a field name of 1 to 50 bytes; `:373`
/// `assertCertificateFieldName` (`:116-125`) refuses an unsafe record key
/// (`SafeRecord.ts`: `__proto__`, `constructor`, `prototype`).
#[tokio::test]
async fn a_certificate_field_name_outside_1_to_50_bytes_or_unsafe_is_refused() {
    let long = [b'n'; 51];
    for (name, words) in [
        (
            &b""[..],
            "Invalid certificate field name length: received 0",
        ),
        (
            &long[..],
            "Invalid certificate field name length: received 51",
        ),
        (b"__proto__", "Unsafe certificate field name: __proto__"),
        (b"constructor", "Unsafe certificate field name: constructor"),
    ] {
        let mut parts = Parts::valid();
        parts.fields = fields(&[(name, b"v")]);
        refused_by_every_reader(&parts.bytes(), words).await;
    }
    let mut parts = Parts::valid();
    parts.fields = fields(&[(&[b'n'; 50], b"v")]);
    read_certificate(&parts.bytes()).unwrap();
}

/// `Certificate.ts:374`: "Duplicate certificate field name".
#[tokio::test]
async fn a_repeated_certificate_field_name_is_refused() {
    let mut parts = Parts::valid();
    parts.fields = fields(&[(b"name", b"one"), (b"name", b"two")]);
    refused_by_every_reader(&parts.bytes(), "Duplicate certificate field name: name").await;
}

/// `Certificate.ts:378-382`: a field value of at most
/// `MAX_CERTIFICATE_FIELD_VALUE_BYTES` (1 MiB, `:27`).
#[test]
fn a_certificate_field_value_past_a_mebibyte_is_refused() {
    let mut parts = Parts::valid();
    parts.fields = fields(&[(b"name", &vec![b'v'; 1024 * 1024 + 1])]);
    let error = message(read_certificate(&parts.bytes()).unwrap_err());
    assert!(
        error.contains("Certificate field name exceeds the maximum of 1048576 bytes"),
        "{error:?}"
    );
    parts.fields = fields(&[(b"name", &vec![b'v'; 1024 * 1024])]);
    read_certificate(&parts.bytes()).unwrap();
}

/// `Certificate.ts:390-397`: the bytes remaining are at most 72
/// (`MAX_CERTIFICATE_SIGNATURE_BYTES`, `:28`) and `Signature.fromDER` parses
/// them (`Signature.ts:44-97`); the writer's `:310` parses them too.
#[tokio::test]
async fn a_certificate_signature_that_is_not_der_is_refused() {
    for (signature, words) in [
        (
            vec![0xdd; 73],
            "Certificate signature exceeds the DER size limit",
        ),
        (vec![0xdd; 72], "Signature DER must start with 0x30"),
        // The sequence's length one short of the bytes.
        (
            vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            "Signature DER invalid",
        ),
        // A long-form length.
        (
            vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            "Invalid DER entity length",
        ),
        // S's length past the end.
        (
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01],
            "Signature DER invalid",
        ),
        (
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01],
            "Invalid R-length in signature DER",
        ),
        // A zero byte before a byte whose high bit is clear.
        (
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
            "Invalid R-value in signature DER",
        ),
        (
            vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01],
            "Invalid S-value in signature DER",
        ),
    ] {
        let mut parts = Parts::valid();
        parts.signature = signature;
        refused_by_every_reader(&parts.bytes(), words).await;
    }
}

/// `Certificate.ts:396-397`: the signature is kept as `sig.toString('hex')`,
/// the DER `Signature.toDER` writes (`Signature.ts:201-250`), so an R whose
/// high bit is set and has no zero byte before it is read and kept padded; no
/// signature (no bytes remain) is no signature.
#[test]
fn a_der_signature_is_kept_as_the_reference_re_encodes_it() {
    let mut parts = Parts::valid();
    parts.signature = vec![0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01];
    let read = read_certificate(&parts.bytes()).unwrap();
    assert_eq!(read.signature, "300702020081020101");

    // An S of zero is the one value `toDER` leaves empty (`Signature.ts:237-239`,
    // the trailing `while` loop); a zero R never reaches `toDER`: `fromDER`
    // refuses a lone `00` as an invalid R-value.
    parts.signature = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00];
    assert_eq!(
        read_certificate(&parts.bytes()).unwrap().signature,
        "30050201010200"
    );
    parts.signature = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
    let error = message(read_certificate(&parts.bytes()).unwrap_err());
    assert!(
        error.contains("Invalid R-value in signature DER"),
        "{error:?}"
    );

    parts.signature = vec![];
    assert_eq!(read_certificate(&parts.bytes()).unwrap().signature, "");
}

// ---------------------------------------------------------------------------
// 3. listCertificates: the keyring flag, the keyring, the verifier
// ---------------------------------------------------------------------------

/// `WalletWireTransceiver.ts:1533-1542`: the verifier's length is 0 or 33,
/// and the 33 bytes are a compressed key (`#readCompressedPublicKey`,
/// `:2004-2008`, `PublicKey.fromDER`).
#[tokio::test]
async fn a_list_certificates_verifier_that_is_not_a_compressed_key_is_refused() {
    let cert = Parts::valid().bytes();
    for bad in [vec![0x02; 32], [key(G), vec![0]].concat()] {
        let error = message(
            list(list_frame(&cert, &no_keyring(), &bad))
                .await
                .unwrap_err(),
        );
        assert!(
            error.contains("listCertificates verifier length: expected 33 bytes"),
            "{error:?}"
        );
    }
    let error = message(
        list(list_frame(&cert, &no_keyring(), &off_curve()))
            .await
            .unwrap_err(),
    );
    assert!(
        error.contains(
            "Invalid listCertificates verifier: expected a compressed secp256k1 public key"
        ),
        "{error:?}"
    );
    let read = list(list_frame(&cert, &no_keyring(), &key(G)))
        .await
        .unwrap();
    assert_eq!(read.certificates[0].verifier.as_deref(), Some(G));
    let read = list(list_frame(&cert, &no_keyring(), &[])).await.unwrap();
    assert_eq!(read.certificates[0].verifier, None);
}

/// `WalletWireTransceiver.ts:1513`, `#readBooleanFlag` (`:1971-1977`): the
/// keyring's present flag is 0 or 1.
#[tokio::test]
async fn a_list_certificates_keyring_flag_other_than_0_or_1_is_refused() {
    let cert = Parts::valid().bytes();
    for flag in [2u8, 0xff] {
        let error = message(list(list_frame(&cert, &[flag], &[])).await.unwrap_err());
        assert!(
            error.contains(&format!(
                "Invalid listCertificates keyring present flag: expected 0 or 1, received {}",
                flag as i8
            )),
            "{error:?}"
        );
    }
}

/// A record's entries (`#readRecordKey`, `:1979-1990`; `#setUniqueWireRecordEntry`,
/// `:1992-2002`): a count, then varint-length keys of 1 to 50 bytes, never an
/// unsafe one, never repeated.
fn record(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    fields(entries)
}

/// `WalletWireTransceiver.ts:1514-1530`: the keyring's count, its keys' bounds
/// and their uniqueness.
#[tokio::test]
async fn a_list_certificates_keyring_key_out_of_bounds_or_repeated_is_refused() {
    let cert = Parts::valid().bytes();
    let keyring = |entries: &[(&[u8], &[u8])]| [vec![1], record(entries)].concat();
    let long = [b'k'; 51];
    for (entries, words) in [
        (
            vec![(&b""[..], &b"v"[..])],
            "Invalid listCertificates keyring key length: expected 1\u{2013}50 bytes, received 0",
        ),
        (
            vec![(&long[..], &b"v"[..])],
            "Invalid listCertificates keyring key length: expected 1\u{2013}50 bytes, received 51",
        ),
        (
            vec![(&b"prototype"[..], &b"v"[..])],
            "Unsafe listCertificates keyring key: prototype",
        ),
        (
            vec![(&b"name"[..], &b"1"[..]), (&b"name"[..], &b"2"[..])],
            "Duplicate listCertificates keyring key: name",
        ),
    ] {
        let error = message(
            list(list_frame(&cert, &keyring(&entries), &[]))
                .await
                .unwrap_err(),
        );
        assert!(error.contains(words), "{error:?} lacks {words:?}");
    }
    let mut nil = vec![1];
    nil.extend_from_slice(&[0xff; 9]);
    let error = message(list(list_frame(&cert, &nil, &[])).await.unwrap_err());
    assert!(
        error.contains("number too large to retain precision"),
        "{error:?}"
    );

    let read = list(list_frame(&cert, &keyring(&[(b"name", b"key")]), &[]))
        .await
        .unwrap();
    let expected: HashMap<String, String> = [("name".to_string(), to_base64(b"key"))].into();
    assert_eq!(read.certificates[0].keyring.as_ref(), Some(&expected));
}

// ---------------------------------------------------------------------------
// 4. Discovery: the trust byte, the keyring and decrypted-field counts
// ---------------------------------------------------------------------------

/// `WalletWireTransceiver.ts:1710`: `#requireInteger(readUInt8(), 'discovery
/// trust', 1, 10)` (`:2018-2025`).
#[tokio::test]
async fn a_discovery_trust_outside_1_to_10_is_refused() {
    let cert = Parts::valid().bytes();
    for trust in [0u8, 11, 0xff] {
        let error = message(
            discover(discovery_frame(&cert, trust, &[0], &[0]))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            error,
            format!("Invalid discovery trust: expected an integer from 1 to 10, received {trust}")
        );
    }
    for trust in [1u8, 10] {
        let read = discover(discovery_frame(&cert, trust, &[0], &[0]))
            .await
            .unwrap();
        assert_eq!(
            read.certificates[0].certifier_info.as_ref().unwrap().trust,
            trust
        );
    }
}

/// `WalletWireTransceiver.ts:1712-1717`, `:1730-1735`: each count is
/// `readVarIntNumStrict(false)` and `#requireResponseCollectionLength`
/// (`:1955-1969`): nine 0xFF are refused by the strict reader, a count past
/// the bytes remaining before an entry is read. No NIL sentinel.
#[tokio::test]
async fn a_nil_sentinel_or_overlong_discovery_count_is_refused() {
    let cert = Parts::valid().bytes();
    let nil = [0xff; 9];
    for (keyring, decrypted) in [(&nil[..], &[0u8][..]), (&[0u8][..], &nil[..])] {
        let error = message(
            discover(discovery_frame(&cert, 5, keyring, decrypted))
                .await
                .unwrap_err(),
        );
        assert!(
            error.contains("number too large to retain precision"),
            "{error:?}"
        );
    }
    let error = message(
        discover(discovery_frame(&cert, 5, &[2], &[0]))
            .await
            .unwrap_err(),
    );
    assert_eq!(
        error,
        "Wallet Wire discovery public keyring count exceeds the remaining response data"
    );
    let error = message(
        discover(discovery_frame(&cert, 5, &[0], &[2]))
            .await
            .unwrap_err(),
    );
    assert_eq!(
        error,
        "Wallet Wire discovery decrypted fields count exceeds the remaining response data"
    );
}

/// `WalletWireTransceiver.ts:1718-1752`: the keys of both maps are record
/// keys, bounded and unique.
#[tokio::test]
async fn a_discovery_record_key_out_of_bounds_or_repeated_is_refused() {
    let cert = Parts::valid().bytes();
    let repeated = record(&[(b"name", b"1"), (b"name", b"2")]);
    let empty_key = record(&[(b"", b"1")]);
    for (keyring, decrypted, words) in [
        (
            &repeated[..],
            &[0u8][..],
            "Duplicate discovery public keyring key: name",
        ),
        (
            &[0u8][..],
            &repeated[..],
            "Duplicate discovery decrypted fields key: name",
        ),
        (
            &empty_key[..],
            &[0u8][..],
            "Invalid discovery public keyring key length: expected 1\u{2013}50 bytes, received 0",
        ),
        (
            &[0u8][..],
            &empty_key[..],
            "Invalid discovery decrypted fields key length: expected 1\u{2013}50 bytes, received 0",
        ),
    ] {
        let error = message(
            discover(discovery_frame(&cert, 5, keyring, decrypted))
                .await
                .unwrap_err(),
        );
        assert_eq!(error, words);
    }
    let read = discover(discovery_frame(
        &cert,
        5,
        &record(&[(b"name", b"key")]),
        &record(&[(b"name", b"Fixture")]),
    ))
    .await
    .unwrap();
    let entry = &read.certificates[0];
    let keyring: HashMap<String, String> = [("name".to_string(), to_base64(b"key"))].into();
    let decrypted: HashMap<String, String> = [("name".to_string(), "Fixture".to_string())].into();
    assert_eq!(entry.publicly_revealed_keyring.as_ref(), Some(&keyring));
    assert_eq!(entry.decrypted_fields.as_ref(), Some(&decrypted));
}

/// `WireReader::read_identity_certificate` reads one discovery entry, the
/// writer's layout, and refuses a repeated key in either map as the
/// transceiver does, in its words (`#setUniqueWireRecordEntry`, `:1992-2002`);
/// it kept the later value until #192.
#[tokio::test]
async fn an_identity_certificate_with_a_repeated_record_key_is_refused_as_discovery_refuses_it() {
    let cert = Parts::valid().bytes();
    let repeated = record(&[(b"name", b"1"), (b"name", b"2")]);
    for (keyring, decrypted, words) in [
        (
            &repeated[..],
            &[0u8][..],
            "Duplicate discovery public keyring key: name",
        ),
        (
            &[0u8][..],
            &repeated[..],
            "Duplicate discovery decrypted fields key: name",
        ),
    ] {
        let frame = discovery_frame(&cert, 5, keyring, decrypted);
        let read = WireReader::new(&frame[1..]).read_identity_certificate();
        assert_eq!(read.map(drop), Err(Error::WalletError(words.into())));
        assert_eq!(
            discover(frame).await.map(drop),
            Err(Error::WalletError(words.into()))
        );
    }
}

/// `WireReader::read_identity_certificate` reads each map as the transceiver
/// reads it, through one helper (bsv-rs#236): the count `readVarIntNumStrict`
/// and `#requireResponseCollectionLength` (`WalletWireTransceiver.ts:1711-1716`,
/// `:1955-1969`), each key `#readRecordKey` (`:1979-1990`): 1 to 50 bytes, not
/// `__proto__`, `constructor` or `prototype` (`SafeRecord.ts:2-4`). Until #236
/// it read a key of any length or name and a count past the bytes as far as the
/// bytes went. A count that stops short of its entries is refused at the count;
/// one that runs long leaves an entry the next count's reading meets, the
/// decrypted-field key length here `n` (110).
#[tokio::test]
async fn an_identity_certificate_refuses_the_record_keys_and_counts_discovery_refuses() {
    let cert = Parts::valid().bytes();
    let long = [b'k'; 51];
    let one = |key: &[u8]| record(&[(key, b"v")]);
    let mut short = Vec::new();
    var_int(&mut short, 200);
    short.extend_from_slice(&record(&[(b"name", b"1")])[1..]);
    let mut over_max = Vec::new();
    var_int(&mut over_max, 100_001);
    let mut long_run = vec![1];
    long_run.extend_from_slice(&record(&[(b"name", b"1"), (b"nick", b"2")])[1..]);
    let empty = vec![0u8];
    for (keyring, decrypted, words) in [
        (
            one(b""),
            empty.clone(),
            "Invalid discovery public keyring key length: expected 1\u{2013}50 bytes, received 0",
        ),
        (
            one(&long),
            empty.clone(),
            "Invalid discovery public keyring key length: expected 1\u{2013}50 bytes, received 51",
        ),
        (
            empty.clone(),
            one(&long),
            "Invalid discovery decrypted fields key length: expected 1\u{2013}50 bytes, received 51",
        ),
        (
            one(b"__proto__"),
            empty.clone(),
            "Unsafe discovery public keyring key: __proto__",
        ),
        (
            empty.clone(),
            one(b"constructor"),
            "Unsafe discovery decrypted fields key: constructor",
        ),
        (
            short,
            empty.clone(),
            "Wallet Wire discovery public keyring count exceeds the remaining response data",
        ),
        (
            over_max,
            empty.clone(),
            "Wallet Wire discovery public keyring exceeds the maximum collection size of 100000",
        ),
        (
            empty.clone(),
            vec![0xff; 9],
            "number too large to retain precision - use readVarIntBn",
        ),
        (
            long_run,
            empty.clone(),
            "Invalid discovery decrypted fields key length: expected 1\u{2013}50 bytes, received 110",
        ),
    ] {
        let frame = discovery_frame(&cert, 5, &keyring, &decrypted);
        let read = WireReader::new(&frame[1..]).read_identity_certificate();
        assert_eq!(read.map(drop), Err(Error::WalletError(words.into())), "{words}");
        assert_eq!(
            discover(frame).await.map(drop),
            Err(Error::WalletError(words.into())),
            "{words}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. The writer: no frame the reference's reader refuses
// ---------------------------------------------------------------------------

fn identity_certificate(info: Option<IdentityCertifier>) -> IdentityCertificate {
    let cert = read_certificate(&Parts::valid().bytes()).unwrap();
    IdentityCertificate {
        certificate: cert,
        certifier_info: info,
        publicly_revealed_keyring: None,
        decrypted_fields: None,
    }
}

fn certifier(trust: u8) -> IdentityCertifier {
    IdentityCertifier {
        name: "Fixture Certifier".into(),
        icon_url: None,
        description: None,
        trust,
    }
}

/// The reference's writer writes the trust byte unchecked
/// (`WalletWireProcessor.ts:2520`) and its reader refuses one outside 1 to 10
/// (`WalletWireTransceiver.ts:1710`); this writer refuses the certificate
/// before a byte is written.
#[test]
fn an_identity_certificate_with_a_trust_outside_1_to_10_is_refused_before_a_byte() {
    for trust in [0u8, 11, 0xff] {
        let mut w = WireWriter::new();
        let error = message(
            w.write_identity_certificate(&identity_certificate(Some(certifier(trust))))
                .err()
                .expect("refused"),
        );
        assert_eq!(
            error,
            format!("Invalid discovery trust: expected an integer from 1 to 10, received {trust}")
        );
        assert!(w.is_empty(), "no byte written");
    }
    for trust in [1u8, 10] {
        let mut w = WireWriter::new();
        w.write_identity_certificate(&identity_certificate(Some(certifier(trust))))
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// 6. The processor's reads
// ---------------------------------------------------------------------------

/// The processor reads revealCounterpartyKeyLinkage's two keys as 33 raw
/// bytes after the privileged flag and reason, as the reference does
/// (`WalletWireProcessor.ts:1739-1747`), and `validateWalletArgs` refuses a
/// key that is not a point (`validationHelpers.ts:1734-1738`): the
/// reference's frame, code 6, before the wallet is called (the header
/// wallet's other methods are unreachable). Until #226 this crate's reader
/// refused it, code 1, in its own words.
#[tokio::test]
async fn the_processor_refuses_a_linkage_key_that_is_not_a_compressed_point() {
    let words = b"The counterparty parameter must be a valid compressed secp256k1 public key";
    let mut frame = vec![6, words.len() as u8];
    frame.extend_from_slice(words);
    frame.push(0);
    let mut prefixed = key(G);
    prefixed[0] = 0x04;
    for bad in [prefixed, off_curve()] {
        // The absent privileged flag and reason, then the keys (#191).
        let mut request = vec![
            WalletCall::RevealCounterpartyKeyLinkage.as_u8(),
            0,
            0xff,
            0xff,
        ];
        request.extend_from_slice(&bad);
        request.extend_from_slice(&key(G));
        let answer = processor_answer(String::new(), &request).await;
        assert_eq!(answer, frame, "{:?}", String::from_utf8_lossy(&answer));
    }
}

// ---------------------------------------------------------------------------
// 6. A wire length past the bytes, on every target (bsv-rs#192)
// ---------------------------------------------------------------------------

/// A varint length of `2^32 + 3` before three bytes. On wasm32 `as usize`
/// kept its low 32 bits, 3, and read the three bytes as the value (`Ok("abc")`,
/// measured under wasm-bindgen-test-runner before the fix); the length is now
/// compared with the bytes remaining before it is narrowed, so every target
/// refuses it with the same error (CLAUDE.md rule 5).
#[test]
fn a_wire_length_past_u32_is_refused_on_every_target_not_cut_to_its_low_bits() {
    let length = (1u64 << 32) + 3;
    let mut bytes = Vec::new();
    var_int(&mut bytes, length);
    bytes.extend_from_slice(b"abc");
    let refused = Err(Error::ReaderUnderflow {
        needed: usize::try_from(length).unwrap_or(usize::MAX),
        available: 3,
    });
    assert_eq!(WireReader::new(&bytes).read_string(), refused);
    assert_eq!(
        WireReader::new(&bytes).read_optional_string(),
        refused.clone().map(Some)
    );
    assert_eq!(
        WireReader::new(&bytes).read_optional_bytes(),
        refused.clone().map(|_: String| None)
    );
    // The same length as a discovery keyring value, in the writer's layout.
    let frame = discovery_frame(&Parts::valid().bytes(), 5, &[1, 4], &[]);
    let entry = [&frame[1..], b"name", &bytes].concat();
    assert_eq!(
        WireReader::new(&entry)
            .read_identity_certificate()
            .map(drop),
        refused.map(drop)
    );
}

/// A page of `entries` copies of one valid entry behind the declared `total`:
/// the one frame's total byte replaced, its entry repeated.
fn page(one: &[u8], total: u64, entries: usize) -> Vec<u8> {
    let mut out = Vec::new();
    var_int(&mut out, total);
    for _ in 0..entries {
        out.extend_from_slice(&one[1..]);
    }
    out
}

fn list_page(total: u64, entries: usize) -> Vec<u8> {
    let one = list_frame(&Parts::valid().bytes(), &no_keyring(), &[]);
    page(&one, total, entries)
}

fn discovery_page(total: u64, entries: usize) -> Vec<u8> {
    let one = discovery_frame(&Parts::valid().bytes(), 5, &[0], &[0]);
    page(&one, total, entries)
}

/// A refusal's words, or the typed error's form for one that is not a
/// `WalletError`.
fn words(error: Error) -> String {
    match error {
        Error::WalletError(m) => m,
        other => format!("{other:?}"),
    }
}

/// listCertificates and both discovery calls with a requested `limit`.
async fn every_page_reader(
    list_frame: Vec<u8>,
    discovery_frame: Vec<u8>,
    limit: Option<u32>,
) -> [Result<(u32, usize), String>; 3] {
    let listed = client(list_frame)
        .list_certificates(
            ListCertificatesArgs {
                certifiers: vec![],
                types: vec![],
                limit,
                offset: None,
                privileged: None,
                privileged_reason: None,
            },
            "fixtures.invalid",
        )
        .await
        .map(|r| (r.total_certificates, r.certificates.len()))
        .map_err(words);
    let by_key = client(discovery_frame.clone())
        .discover_by_identity_key(
            DiscoverByIdentityKeyArgs {
                identity_key: G.to_string(),
                limit,
                offset: None,
                seek_permission: None,
            },
            "fixtures.invalid",
        )
        .await
        .map(|r| (r.total_certificates, r.certificates.len()))
        .map_err(words);
    let by_attributes = client(discovery_frame)
        .discover_by_attributes(
            DiscoverByAttributesArgs {
                attributes: HashMap::from([("name".to_string(), "x".to_string())]),
                limit,
                offset: None,
                seek_permission: None,
            },
            "fixtures.invalid",
        )
        .await
        .map(|r| (r.total_certificates, r.certificates.len()))
        .map_err(words);
    [listed, by_key, by_attributes]
}

/// `WalletWireTransceiver.ts:1508` (listCertificates) and `:1699`
/// (discovery): the entries are read `while (!resultReader.eof())`, so a byte
/// after the last entry is read as the start of another and refused by the
/// entry's reader (bsv-rs#190). A one-byte `00` is an entry whose certificate
/// is empty, its type's 32 bytes missing.
#[tokio::test]
async fn a_byte_after_the_last_certificates_entry_is_refused() {
    let mut listed = list_page(1, 1);
    listed.push(0);
    let mut discovered = discovery_page(1, 1);
    discovered.push(0);
    for read in every_page_reader(listed, discovered, None).await {
        assert_eq!(
            read,
            Err(format!(
                "{:?}",
                Error::ReaderUnderflow {
                    needed: 32,
                    available: 0
                }
            ))
        );
    }
}

/// `WalletWireTransceiver.ts:1550`, `:1759` and `#assertPageCount`
/// (`:1940-1946`): a page holding more entries than the declared total is
/// refused, where the entries were read to the total and the rest dropped
/// (bsv-rs#190).
#[tokio::test]
async fn a_certificates_page_past_its_declared_total_is_refused() {
    let reads = every_page_reader(list_page(1, 2), discovery_page(1, 2), None).await;
    let calls = ["listCertificates", "discover", "discover"];
    for (read, call) in reads.into_iter().zip(calls) {
        assert_eq!(
            read,
            Err(format!(
                "Wallet Wire {call} response returned 2 records but declared a total of 1"
            ))
        );
    }
}

/// `totalCertificates` is the total of every page (the processor writes
/// `certificatesPage.total` ahead of the page's records,
/// `WalletWireProcessor.ts:2052-2053`, `:2486-2487`), so a total above the
/// entries is read as given, where the reader asked for `total` entries
/// (bsv-rs#190).
#[tokio::test]
async fn a_certificates_total_above_the_page_is_read() {
    let reads = every_page_reader(list_page(25, 2), discovery_page(25, 2), None).await;
    for read in reads {
        assert_eq!(read, Ok((25, 2)));
    }
    let reads = every_page_reader(list_page(7, 0), discovery_page(7, 0), None).await;
    for read in reads {
        assert_eq!(read, Ok((7, 0)));
    }
}

/// `#requirePageCapacity` (`WalletWireTransceiver.ts:1948-1953`), called
/// before each entry (`:1509`, `:1700`): a page past the requested limit, or
/// past 10 when none was requested (`requestedLimit ?? 10`), is refused; a
/// page at the limit is read (bsv-rs#190).
#[tokio::test]
async fn a_certificates_page_past_the_requested_limit_is_refused() {
    let calls = ["listCertificates", "discover", "discover"];
    for (limit, maximum) in [(Some(3), 3usize), (None, 10)] {
        let at =
            every_page_reader(list_page(50, maximum), discovery_page(50, maximum), limit).await;
        for read in at {
            assert_eq!(read, Ok((50, maximum)));
        }
        let past = every_page_reader(
            list_page(50, maximum + 1),
            discovery_page(50, maximum + 1),
            limit,
        )
        .await;
        for (read, call) in past.into_iter().zip(calls) {
            assert_eq!(
                read,
                Err(format!(
                    "Wallet Wire {call} response exceeds the requested page limit of {maximum}"
                ))
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 7. A listActions satoshis value in the reference's bound (bsv-rs#236)
// ---------------------------------------------------------------------------

fn action(satoshis: i64) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_wallet_action(&WalletAction {
        txid: [0x11; 32],
        satoshis,
        status: ActionStatus::Completed,
        is_outgoing: false,
        description: "fixture".into(),
        labels: None,
        version: 1,
        lock_time: 0,
        inputs: None,
        outputs: None,
    });
    w.as_bytes().to_vec()
}

/// `#readActionSatoshis` (`WalletWireTransceiver.ts:400-416`): a negative net
/// amount `0xff` and a signed int64 with its high bit set, any other value
/// `readVarIntNumStrict(false)` (refused past `2^53 - 1`), and the value
/// `#requireInteger(value, 'listActions satoshis', -21e14, 21e14)` (`:2018-2025`).
/// Until #236 `read_wallet_action` cast the varint `as i64`: the negatives the
/// same, no bound.
#[test]
fn a_list_actions_satoshis_value_outside_the_reference_bound_is_refused() {
    let bound = |value: i64| {
        format!(
            "Invalid listActions satoshis: expected an integer from -2100000000000000 to 2100000000000000, received {value}"
        )
    };
    for satoshis in [0, -25_000, 2_100_000_000_000_000, -2_100_000_000_000_000] {
        let read = WireReader::new(&action(satoshis)).read_wallet_action();
        assert_eq!(read.map(|a| a.satoshis), Ok(satoshis));
    }
    for satoshis in [2_100_000_000_000_001, -2_100_000_000_000_001] {
        let read = WireReader::new(&action(satoshis)).read_wallet_action();
        assert_eq!(read.map(drop), Err(Error::WalletError(bound(satoshis))));
    }
    // A negative below `-(2^53 - 1)` never reaches the bound in the reference:
    // `readInt64LEBn().toNumber()` throws at `BigNumber.ts:625-630` (the review's fold).
    for satoshis in [i64::MIN, -(1 << 53)] {
        let read = WireReader::new(&action(satoshis)).read_wallet_action();
        assert_eq!(
            read.map(drop),
            Err(Error::WalletError(
                "Number can only safely store up to 53 bits".into()
            ))
        );
    }
    // Past `2^53 - 1` without the sign bit: the strict reader's words.
    let read = WireReader::new(&action(1 << 60)).read_wallet_action();
    assert_eq!(
        read.map(drop),
        Err(Error::WalletError(
            "number too large to retain precision - use readVarIntBn".into()
        ))
    );
}
