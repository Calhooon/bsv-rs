//! The processor's writers of a call's result, one per call, where a call's
//! frame needs more than the handler's few lines.

use super::encoding::WireWriter;
use crate::wallet::{
    AuthenticatedResult, CreateHmacResult, CreateSignatureResult, DecryptResult, EncryptResult,
    KeyLinkageResult, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
    VerifyHmacResult, VerifySignatureResult,
};
use crate::Error;

// The four byte-array results are the bytes alone to the end of the frame, no
// length ahead of them (`ts-stack@edf6e03` `WalletWireProcessor.ts:1443-1444`,
// `:1470-1471`, `:1495-1496`, `:1559-1560`, read as the rest of the frame at
// `WalletWireTransceiver.ts:953-957`, `:988`, `:1019-1021`, `:1092-1100`;
// go-sdk@2ca481c `wallet/serializer/{encrypt,decrypt,create_hmac,create_signature}.go`;
// BRC-100 `wallet/0100.md:2117`, `:2139`, `:2161`, `:2204` at `5119a9b`; #197).

/// Writes encrypt's result: the ciphertext alone.
pub(super) fn write_encrypt_result(result: &EncryptResult) -> Vec<u8> {
    result.ciphertext.clone()
}

/// Writes decrypt's result: the plaintext alone.
pub(super) fn write_decrypt_result(result: &DecryptResult) -> Vec<u8> {
    result.plaintext.clone()
}

/// Writes createHmac's result: the 32 HMAC bytes alone.
pub(super) fn write_create_hmac_result(result: &CreateHmacResult) -> Vec<u8> {
    result.hmac.to_vec()
}

/// Writes createSignature's result: the DER signature alone.
pub(super) fn write_create_signature_result(result: &CreateSignatureResult) -> Vec<u8> {
    result.signature.clone()
}

// The three verdicts are the error byte and nothing after it: the reference
// answers a verdict other than true with an error frame (`WalletWireProcessor.ts:1520-1525`,
// `:1597-1602`, `:1636-1643`), its transceiver reads an empty result as true and
// refuses a byte after the error byte (`WalletWireTransceiver.ts:1053-1055`,
// `:1147-1149`, `:1870-1872`, `#requireEmptyResponse` `:2033-2035`). go-sdk
// writes nothing for a true or a false verdict and reads any result as true
// (`wallet/serializer/verify_hmac.go:71-77`, `verify_signature.go:102-110`,
// `authenticated.go:36-44`); BRC-100 "Nothing extra" (`wallet/0100.md:2180`,
// `:2226` at `5119a9b`; #197).

/// Writes verifyHmac's result: nothing, or the reference's refusal of a false verdict.
pub(super) fn write_verify_hmac_result(result: &VerifyHmacResult) -> Result<Vec<u8>, Error> {
    verdict(result.valid, "HMAC is not valid")
}

/// Writes verifySignature's result: nothing, or the reference's refusal of a false verdict.
pub(super) fn write_verify_signature_result(
    result: &VerifySignatureResult,
) -> Result<Vec<u8>, Error> {
    verdict(result.valid, "Signature is not valid")
}

/// Writes waitForAuthentication's result: nothing, or the reference's refusal
/// of a false verdict.
pub(super) fn write_wait_for_authentication_result(
    result: &AuthenticatedResult,
) -> Result<Vec<u8>, Error> {
    verdict(
        result.authenticated,
        "Wallet did not affirmatively authenticate",
    )
}

fn verdict(affirmed: bool, refusal: &str) -> Result<Vec<u8>, Error> {
    if !affirmed {
        return Err(Error::WalletError(refusal.to_string()));
    }
    Ok(Vec::new())
}

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
