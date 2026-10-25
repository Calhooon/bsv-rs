//! The processor's writers of a call's result, one per call, where a call's
//! frame needs more than the handler's few lines.

use super::encoding::WireWriter;
use crate::wallet::{
    KeyLinkageResult, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
};

/// Writes the prover, the verifier and the counterparty, 33 bytes each: the
/// three keys open both linkage results.
fn write_linkage_keys(writer: &mut WireWriter, linkage: &KeyLinkageResult) {
    writer.write_bytes(&linkage.prover.to_compressed());
    writer.write_bytes(&linkage.verifier.to_compressed());
    writer.write_bytes(&linkage.counterparty.to_compressed());
}

/// Writes encryptedLinkage and encryptedLinkageProof, each behind its varint
/// length.
fn write_linkage_bytes(writer: &mut WireWriter, linkage: &KeyLinkageResult) {
    writer.write_var_int(linkage.encrypted_linkage.len() as u64);
    writer.write_bytes(&linkage.encrypted_linkage);
    writer.write_var_int(linkage.encrypted_linkage_proof.len() as u64);
    writer.write_bytes(&linkage.encrypted_linkage_proof);
}

/// Writes revealCounterpartyKeyLinkage's result in the reference's order
/// (`ts-stack@edf6e03` `WalletWireProcessor.ts:1761-1781`, read at
/// `WalletWireTransceiver.ts:818-836`; go-sdk@2ca481c
/// `wallet/serializer/reveal_counterparty_key_linkage.go:68-89`; BRC-100
/// `wallet/0100.md:2052-2057` at `5119a9b`): the three keys, revelationTime
/// behind its length, then encryptedLinkage and encryptedLinkageProof (#194).
pub(super) fn write_reveal_counterparty_key_linkage_result(
    result: &RevealCounterpartyKeyLinkageResult,
) -> Vec<u8> {
    let mut writer = WireWriter::new();
    write_linkage_keys(&mut writer, &result.linkage);
    writer.write_string(&result.revelation_time);
    write_linkage_bytes(&mut writer, &result.linkage);
    writer.into_bytes()
}

/// Writes revealSpecificKeyLinkage's result in the reference's order
/// (`WalletWireProcessor.ts:1811-1841`, read at `WalletWireTransceiver.ts:890-908`;
/// go-sdk `reveal_specific_key_linkage.go:73-92`; BRC-100 `:2088-2095` at
/// `5119a9b`): the three keys, the security level and the protocol string
/// behind its length, keyID behind its length, encryptedLinkage,
/// encryptedLinkageProof, then proofType as one byte (#194).
pub(super) fn write_reveal_specific_key_linkage_result(
    result: &RevealSpecificKeyLinkageResult,
) -> Vec<u8> {
    let mut writer = WireWriter::new();
    write_linkage_keys(&mut writer, &result.linkage);
    writer.write_protocol_id(&result.protocol);
    writer.write_string(&result.key_id);
    write_linkage_bytes(&mut writer, &result.linkage);
    writer.write_u8(result.proof_type);
    writer.into_bytes()
}
