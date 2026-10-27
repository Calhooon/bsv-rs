//! getHeaderForHeight's result is the error byte then the header's 80 raw
//! bytes, as the reference writes it (bsv-rs#178): the processor writes no
//! length prefix and the transceiver reads the header's own bytes.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;

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

fn vector(name: &str) -> (serde_json::Value, Vec<u8>) {
    let path = format!(
        "{}/tests/vectors/wallet_wire/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let wire = hex::decode(v["wire"].as_str().unwrap()).unwrap();
    assert_eq!(wire[0], 0, "a success frame");
    (v["json"].clone(), wire)
}

/// The genesis header, the shared vector's.
fn genesis() -> (String, Vec<u8>) {
    let (json, wire) = vector("getHeaderForHeight-simple-result.json");
    (json["header"].as_str().unwrap().to_string(), wire)
}

/// Answers `get_header_for_height` with the genesis header; every other
/// method is unreachable from these tests.
struct HeaderWallet;

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! header_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for HeaderWallet {
            $(async fn $method(&self, _: $args, _: Option<&str>) -> bsv_rs::Result<$result> {
                unreachable!()
            })*

            async fn is_authenticated(&self, _: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                unreachable!()
            }
            async fn wait_for_authentication(&self, _: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                unreachable!()
            }
            async fn get_height(&self, _: Option<&str>) -> bsv_rs::Result<GetHeightResult> {
                unreachable!()
            }
            async fn get_header_for_height(
                &self,
                _: GetHeaderArgs,
                _: Option<&str>,
            ) -> bsv_rs::Result<GetHeaderResult> {
                Ok(GetHeaderResult { header: genesis().0 })
            }
            async fn get_network(&self, _: Option<&str>) -> bsv_rs::Result<GetNetworkResult> {
                unreachable!()
            }
            async fn get_version(&self, _: Option<&str>) -> bsv_rs::Result<GetVersionResult> {
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

/// The client's wire into a processor answering with the genesis header.
struct ProcessorWire(WalletWireProcessor<HeaderWallet>);

#[async_trait::async_trait]
impl WalletWire for ProcessorWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.process_message(message).await
    }
}

/// [call: u8][originator: u8 len + bytes][height: varint]
fn get_header_request() -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(WalletCall::GetHeaderForHeight.as_u8());
    writer.write_u8(0);
    writer.write_var_int(1);
    writer.into_bytes()
}

/// The processor writes the error byte then the 80 raw bytes, as the reference
/// does (`WalletWireProcessor.ts:1687-1690`; BRC-100 `0100.md:2478` at
/// `5119a9b`, "Byte Array (80 bytes)"): no length prefix.
#[tokio::test]
async fn a_header_frame_is_the_error_byte_then_the_80_raw_bytes() {
    let (_, reference) = genesis();
    assert_eq!(reference.len(), 81);
    let answer = WalletWireProcessor::new(HeaderWallet)
        .process_message(&get_header_request())
        .await
        .unwrap();
    assert_eq!(answer, reference);
    let mut reader = WireReader::new(&answer);
    assert_eq!(reader.read_u8().unwrap(), 0);
    assert_eq!(reader.read_remaining().len(), 80);
}

/// The transceiver reads the processor's frame and the reference's bytes to
/// the header's own 80 bytes, the version byte leading
/// (`WalletWireTransceiver.ts:1903`, `#requireResponseLength(header, 80)`).
#[tokio::test]
async fn a_header_for_height_reaches_the_client_as_its_80_bytes() {
    let (header, reference) = genesis();
    let looped = WalletWireTransceiver::new(ProcessorWire(WalletWireProcessor::new(HeaderWallet)))
        .get_header(GetHeaderArgs { height: 1 }, Some("fixtures.invalid"))
        .await
        .unwrap();
    let canned = client(reference[1..].to_vec())
        .get_header(GetHeaderArgs { height: 1 }, Some("fixtures.invalid"))
        .await
        .unwrap();
    for read in [looped, canned] {
        assert_eq!(read.header, header);
        assert_eq!(read.header.len(), 160);
        assert!(read.header.starts_with("01000000"));
    }
}
