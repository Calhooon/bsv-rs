//! Per-outpoint PushDrop signers for the stores' owned action boundary (#343).
use super::bound::{complete_action, complete_with_signers};
use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::transaction::{Beef, Transaction};
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionResult, Outpoint, Protocol,
    SignActionSpend, WalletInterface,
};
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub(super) struct SigningProtocol {
    pub(super) protocol: Protocol,
    pub(super) key_id: String,
    pub(super) counterparty: Counterparty,
}

pub(super) enum InputSigner {
    Bytes(Vec<u8>),
    Token(SigningProtocol),
}

pub(super) async fn complete_token_action<W: WalletInterface>(
    wallet: &W,
    args: CreateActionArgs,
    protocol: SigningProtocol,
    originator: Option<&str>,
) -> Result<CreateActionResult> {
    if args.inputs.iter().flatten().next().is_none() {
        return complete_action(wallet, args, originator).await;
    }
    let signers = args
        .inputs
        .iter()
        .flatten()
        .map(|input| (input.outpoint.clone(), InputSigner::Token(protocol.clone())))
        .collect();
    complete_with_signers(wallet, args, signers, originator).await
}

pub(super) fn inputs(
    outpoints: impl IntoIterator<Item = String>,
    description: &str,
) -> Result<Vec<CreateActionInput>> {
    let mut seen = HashSet::new();
    let mut inputs = Vec::new();
    for outpoint in outpoints {
        let outpoint = Outpoint::from_string(&outpoint)?;
        if seen.insert(outpoint.clone()) {
            inputs.push(CreateActionInput {
                outpoint,
                input_description: description.into(),
                unlocking_script: None,
                unlocking_script_length: Some(74),
                sequence_number: None,
            });
        }
    }
    Ok(inputs)
}

pub(super) fn merge_beef<'a>(beefs: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<u8>> {
    let mut merged = Beef::new();
    for bytes in beefs {
        merged.merge_beef(&Beef::from_binary(bytes)?);
    }
    Ok(merged.to_binary())
}

pub(super) async fn sign_bound_inputs<W: WalletInterface>(
    wallet: &W,
    tx: &Transaction,
    bound: HashMap<u32, &InputSigner>,
    originator: Option<&str>,
) -> Result<HashMap<u32, SignActionSpend>> {
    let mut spends = HashMap::new();
    let mut bound: Vec<_> = bound.into_iter().collect();
    bound.sort_unstable_by_key(|(index, _)| *index);
    for (index, signer) in bound {
        let unlocking_script = match signer {
            InputSigner::Bytes(bytes) => bytes.clone(),
            InputSigner::Token(protocol) => {
                protocol
                    .sign(wallet, tx, index as usize, originator)
                    .await?
            }
        };
        spends.insert(
            index,
            SignActionSpend {
                unlocking_script,
                sequence_number: None,
            },
        );
    }
    Ok(spends)
}

impl SigningProtocol {
    async fn sign<W: WalletInterface>(
        &self,
        wallet: &W,
        tx: &Transaction,
        index: usize,
        originator: Option<&str>,
    ) -> Result<Vec<u8>> {
        let input = &tx.inputs[index];
        let source = input
            .source_transaction
            .as_ref()
            .and_then(|tx| tx.outputs.get(input.source_output_index as usize))
            .ok_or_else(|| {
                Error::KvStoreError(
                    "Wallet signable transaction omitted an input source output".into(),
                )
            })?;
        let parsed = parse_transaction(&tx.to_binary())?;
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        crate::wallet::pushdrop::sign(
            wallet,
            &SighashParams {
                version: parsed.version,
                inputs: &parsed.inputs,
                outputs: &parsed.outputs,
                locktime: parsed.locktime,
                input_index: index,
                subscript: &source.locking_script.to_binary(),
                satoshis: source.satoshis.unwrap_or_default(),
                scope,
            },
            self.protocol.clone(),
            self.key_id.clone(),
            self.counterparty.clone(),
            originator,
        )
        .await
    }
}
