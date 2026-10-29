//! Wallet requests made by PushDrop unlockers (TS PushDrop.ts:234-258).
use super::{Counterparty, CreateSignatureArgs, Protocol, WalletInterface};
use crate::primitives::bsv::sighash::{build_sighash_preimage, SighashParams};
use crate::primitives::{bsv::TransactionSignature, sha256, Signature};
use crate::Result;

/// Send SHA256(preimage) as data: the wallet performs the other SHA256.
pub(crate) async fn sign<W: WalletInterface + ?Sized>(
    wallet: &W,
    params: &SighashParams<'_>,
    protocol_id: Protocol,
    key_id: String,
    counterparty: Counterparty,
    originator: Option<&str>,
) -> Result<Vec<u8>> {
    let signature = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(sha256(&build_sighash_preimage(params)).to_vec()),
                protocol_id,
                key_id,
                counterparty: Some(counterparty),
                ..Default::default()
            },
            originator,
        )
        .await?;
    let signature = Signature::from_der(&signature.signature)?;
    let checksig = TransactionSignature::new(signature, params.scope).to_checksig_format();
    let mut script = Vec::with_capacity(checksig.len() + 1);
    script.push(checksig.len() as u8);
    script.extend(checksig);
    Ok(script)
}
