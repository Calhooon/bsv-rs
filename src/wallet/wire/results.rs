//! The processor's writers of a call's result, one per call, where a call's
//! frame needs more than the handler's few lines.

use super::encoding::WireWriter;
use crate::wallet::types::{
    KeyLinkageResult, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
};

/// Writes encryptedLinkage and encryptedLinkageProof, each behind its varint
/// length, then the prover, the verifier and the counterparty, 33 bytes each.
fn write_linkage(writer: &mut WireWriter, linkage: &KeyLinkageResult) {
    writer.write_var_int(linkage.encrypted_linkage.len() as u64);
    writer.write_bytes(&linkage.encrypted_linkage);
    writer.write_var_int(linkage.encrypted_linkage_proof.len() as u64);
    writer.write_bytes(&linkage.encrypted_linkage_proof);
    writer.write_bytes(&linkage.prover.to_compressed());
    writer.write_bytes(&linkage.verifier.to_compressed());
    writer.write_bytes(&linkage.counterparty.to_compressed());
}

/// Writes revealCounterpartyKeyLinkage's result: the linkage, then
/// revelationTime behind its length.
pub(super) fn write_reveal_counterparty_key_linkage_result(
    result: &RevealCounterpartyKeyLinkageResult,
) -> Vec<u8> {
    let mut writer = WireWriter::new();
    write_linkage(&mut writer, &result.linkage);
    writer.write_string(&result.revelation_time);
    writer.into_bytes()
}

/// Writes revealSpecificKeyLinkage's result: the linkage, the protocol, keyID
/// behind its length, then proofType as one byte.
pub(super) fn write_reveal_specific_key_linkage_result(
    result: &RevealSpecificKeyLinkageResult,
) -> Vec<u8> {
    let mut writer = WireWriter::new();
    write_linkage(&mut writer, &result.linkage);
    writer.write_protocol_id(&result.protocol);
    writer.write_string(&result.key_id);
    writer.write_u8(result.proof_type);
    writer.into_bytes()
}
