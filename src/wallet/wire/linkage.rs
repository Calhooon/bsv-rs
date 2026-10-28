//! The transceiver's two linkage calls, revealCounterpartyKeyLinkage (9) and
//! revealSpecificKeyLinkage (10), as the reference's `WalletWireTransceiver`
//! writes and reads them (`ts-stack@edf6e03` `WalletWireTransceiver.ts:790-924`;
//! bsv-rs#406). The arguments are judged by the processor's `validateWalletArgs`
//! rules before a byte is sent and the result by its `validateWalletResult`
//! rules bound to the request (`validation.rs`), as the reference's
//! transceiver judges both.

use super::encoding::{WireReader, WireWriter};
use super::requests::{RevealCounterpartyRequest, RevealSpecificRequest};
use super::validation::{self, Refusal};
use super::{WalletCall, WalletWire, WalletWireTransceiver};
use crate::primitives::PublicKey;
use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::types::Protocol;
use crate::wallet::{
    KeyLinkageResult, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
    SecurityLevel,
};
use crate::{Error, WalletRefusalClass};

const COUNTERPARTY: &str = "revealCounterpartyKeyLinkage";
const SPECIFIC: &str = "revealSpecificKeyLinkage";

/// A check's refusal as the reference's transceiver throws it: an argument a
/// `WERR_INVALID_PARAMETER` (code 6, its class), a result a plain `Error` in
/// its words.
fn thrown(refusal: Refusal) -> Error {
    match WalletRefusalClass::from_code(refusal.code) {
        Some(class) => Error::WalletRefusal {
            class,
            message: refusal.words,
        },
        None => Error::WalletError(refusal.words),
    }
}

/// `#readCompressedPublicKey` (`WalletWireTransceiver.ts:2004-2008`): 33
/// bytes that are a compressed point.
fn read_key(reader: &mut WireReader<'_>, what: &str) -> Result<PublicKey, Error> {
    let bytes = reader.read_bytes(33)?;
    super::require_compressed_key(bytes, what)?;
    PublicKey::from_bytes(bytes)
}

/// The bytes behind a `readVarIntNumStrict(false)` length.
fn read_bytes(reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
    let length = reader.read_var_int_num_strict()?;
    Ok(reader.read_bytes(length)?.to_vec())
}

/// `toUTF8Strict` of the bytes behind a strict length.
fn read_text(reader: &mut WireReader<'_>, call: &str, field: &str) -> Result<String, Error> {
    String::from_utf8(read_bytes(reader)?)
        .map_err(|_| Error::WalletError(format!("Invalid {call} {field}: expected UTF-8")))
}

/// The three keys, in the reference's order and words.
fn read_keys(reader: &mut WireReader<'_>, call: &str) -> Result<[PublicKey; 3], Error> {
    Ok([
        read_key(reader, &format!("{call} prover"))?,
        read_key(reader, &format!("{call} verifier"))?,
        read_key(reader, &format!("{call} counterparty"))?,
    ])
}

/// The encrypted linkage and its proof, behind the three keys.
fn read_linkage(
    reader: &mut WireReader<'_>,
    [prover, verifier, counterparty]: [PublicKey; 3],
) -> Result<KeyLinkageResult, Error> {
    Ok(KeyLinkageResult {
        encrypted_linkage: read_bytes(reader)?,
        encrypted_linkage_proof: read_bytes(reader)?,
        prover,
        verifier,
        counterparty,
    })
}

/// `#readSecurityLevel` (`WalletWireTransceiver.ts:2010-2016`).
fn read_security_level(reader: &mut WireReader<'_>) -> Result<SecurityLevel, Error> {
    let level = reader.read_u8()?;
    SecurityLevel::from_u8(level)
        .ok_or_else(|| Error::WalletError(format!("Invalid {SPECIFIC} security level: {level}")))
}

/// `#assertResponseConsumed` (`WalletWireTransceiver.ts:1936-1938`).
fn assert_consumed(reader: &WireReader<'_>, call: &str) -> Result<(), Error> {
    if !reader.is_empty() {
        return Err(Error::WalletError(format!(
            "Wallet Wire {call} response contains trailing data"
        )));
    }
    Ok(())
}

impl<T: WalletWire> WalletWireTransceiver<T> {
    /// Reveals the linkage between this wallet's identity key and a
    /// counterparty's to a verifier (call 9): the privileged flag and reason,
    /// the counterparty's key, the verifier's key; the result the three keys,
    /// the revelation time, the encrypted linkage and its proof
    /// (`WalletWireTransceiver.ts:790-849` at `ts-stack@edf6e03`; #406).
    pub async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, Error> {
        let args = validation::reveal_counterparty_args(RevealCounterpartyRequest {
            counterparty: args.counterparty.to_compressed(),
            verifier: args.verifier.to_compressed(),
            privileged: args.privileged,
            privileged_reason: args.privileged_reason,
        })
        .map_err(thrown)?;

        let mut writer = WireWriter::new();
        super::write_privileged_params(
            &mut writer,
            args.privileged,
            args.privileged_reason.as_deref(),
        )?;
        writer.write_bytes(&args.counterparty.to_compressed());
        writer.write_bytes(&args.verifier.to_compressed());

        let response = self
            .transmit(
                WalletCall::RevealCounterpartyKeyLinkage,
                originator,
                writer.as_bytes(),
            )
            .await?;

        let mut reader = WireReader::new(&response);
        let keys = read_keys(&mut reader, COUNTERPARTY)?;
        let revelation_time = read_text(&mut reader, COUNTERPARTY, "revelationTime")?;
        let linkage = read_linkage(&mut reader, keys)?;
        assert_consumed(&reader, COUNTERPARTY)?;
        let result = RevealCounterpartyKeyLinkageResult {
            linkage,
            revelation_time,
        };
        validation::reveal_counterparty_result(&args, &result).map_err(thrown)?;
        Ok(result)
    }

    /// Reveals the linkage of one derived key to a verifier (call 10): the
    /// key-related parameters (protocol, key ID, counterparty, the privileged
    /// flag and reason), then the verifier's key; the result the three keys,
    /// the protocol, the key ID, the encrypted linkage and its proof and the
    /// proof type (`WalletWireTransceiver.ts:851-924` at `ts-stack@edf6e03`;
    /// #406).
    pub async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, Error> {
        let args = validation::reveal_specific_args(RevealSpecificRequest {
            counterparty: Some(args.counterparty),
            verifier: args.verifier.to_compressed(),
            protocol_id: args.protocol_id,
            key_id: args.key_id,
            privileged: args.privileged,
            privileged_reason: args.privileged_reason,
        })
        .map_err(thrown)?;

        let mut writer = WireWriter::new();
        super::write_key_related_params(
            &mut writer,
            &args.protocol_id,
            &args.key_id,
            Some(&args.counterparty),
            args.privileged,
            args.privileged_reason.as_deref(),
        )?;
        writer.write_bytes(&args.verifier.to_compressed());

        let response = self
            .transmit(
                WalletCall::RevealSpecificKeyLinkage,
                originator,
                writer.as_bytes(),
            )
            .await?;

        let mut reader = WireReader::new(&response);
        let keys = read_keys(&mut reader, SPECIFIC)?;
        let level = read_security_level(&mut reader)?;
        let protocol_name = read_text(&mut reader, SPECIFIC, "protocolID[1]")?;
        let key_id = read_text(&mut reader, SPECIFIC, "keyID")?;
        let linkage = read_linkage(&mut reader, keys)?;
        let proof_type = reader.read_u8()?;
        assert_consumed(&reader, SPECIFIC)?;
        let result = RevealSpecificKeyLinkageResult {
            linkage,
            protocol: Protocol::new(level, protocol_name),
            key_id,
            proof_type,
        };
        validation::reveal_specific_result(&args, &result).map_err(thrown)?;
        Ok(result)
    }
}
