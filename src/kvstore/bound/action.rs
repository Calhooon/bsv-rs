//! Shared owned-data create/sign boundary. Rust has no replaceable JS intrinsics
//! or data-property getters: owned typed arguments/results provide that isolation.
use super::bound_sign_options;
use super::checks::{bind_requested, refusal, same_template};
use crate::kvstore::token_spends::{sign_bound_inputs, InputSigner};
use crate::primitives::to_base64;
use crate::transaction::Transaction;
use crate::wallet::{
    AbortActionArgs, CreateActionArgs, CreateActionResult, Outpoint, SignActionArgs,
    SignActionResult, SignActionSpend, WalletInterface,
};
use crate::Result;
use std::collections::HashMap;

pub(crate) async fn complete_action<W: WalletInterface>(
    wallet: &W,
    args: CreateActionArgs,
    originator: Option<&str>,
) -> Result<(CreateActionResult, Transaction)> {
    let signers = args
        .inputs
        .iter()
        .flatten()
        .filter(|input| input.unlocking_script.is_none())
        .map(|input| (input.outpoint.clone(), InputSigner::Bytes(Vec::new())))
        .collect();
    complete_with_signers(wallet, args, signers, originator).await
}

pub(in crate::kvstore) async fn complete_with_signers<W: WalletInterface>(
    wallet: &W,
    mut args: CreateActionArgs,
    signers: HashMap<Outpoint, InputSigner>,
    originator: Option<&str>,
) -> Result<(CreateActionResult, Transaction)> {
    let options = args.options.get_or_insert_with(Default::default);
    options.sign_and_process = Some(false);
    options.return_txid_only = Some(false);
    let result = wallet.create_action(args.clone(), originator).await?;
    let signable = result
        .signable_transaction
        .as_ref()
        .ok_or_else(|| refusal("Wallet signable transaction must be a plain data object"))?;
    let reference = to_base64(&signable.reference);
    if reference.is_empty() || reference.len() > 4096 {
        return Err(refusal("Wallet signable transaction reference is invalid"));
    }
    let completed = sign_and_check(
        wallet,
        &args,
        &signers,
        &signable.tx,
        &reference,
        originator,
    )
    .await;
    if completed.is_err() {
        let _ = wallet
            .abort_action(AbortActionArgs { reference }, originator)
            .await;
    }
    completed
}

async fn sign_and_check<W: WalletInterface>(
    wallet: &W,
    args: &CreateActionArgs,
    signers: &HashMap<Outpoint, InputSigner>,
    bytes: &[u8],
    reference: &str,
    originator: Option<&str>,
) -> Result<(CreateActionResult, Transaction)> {
    let partial = parse(bytes, "Wallet signable transaction")?;
    let indexes = bind_requested(args, &partial)?;
    let bound = bind_signers(args, &indexes, signers)?;
    let spends = sign_bound_inputs(wallet, &partial, bound, originator).await?;
    let signed = wallet
        .sign_action(
            SignActionArgs {
                reference: reference.to_owned(),
                spends: spends.clone(),
                options: Some(bound_sign_options(args.options.as_ref())),
            },
            originator,
        )
        .await?;
    let tx = validate_signed(&partial, args, &indexes, &spends, &signed)?;
    let id = Outpoint::from_string(&format!("{}.0", tx.id()))?.txid;
    Ok((
        CreateActionResult {
            txid: Some(id),
            tx: signed.tx,
            ..Default::default()
        },
        tx,
    ))
}

fn parse(bytes: &[u8], label: &str) -> Result<Transaction> {
    if bytes.is_empty() {
        return Err(refusal(format!(
            "{label} must be a bounded non-empty byte array"
        )));
    }
    if bytes.len() > 256 * 1024 * 1024 {
        return Err(refusal(format!("{label} exceeds the byte limit")));
    }
    Transaction::from_atomic_beef(bytes)
}

fn bind_signers<'a>(
    args: &CreateActionArgs,
    indexes: &[usize],
    signers: &'a HashMap<Outpoint, InputSigner>,
) -> Result<HashMap<u32, &'a InputSigner>> {
    let mut spends = HashMap::new();
    for (index, requested) in args.inputs.iter().flatten().enumerate() {
        if requested.unlocking_script.is_some() {
            continue;
        }
        let script = signers
            .get(&requested.outpoint)
            .filter(|_| requested.unlocking_script_length.is_some())
            .ok_or_else(|| refusal(format!("Requested input {index} has no authorized signer")))?;
        spends.insert(spend_index(indexes[index])?, script);
    }
    if spends.len() != signers.len() {
        return Err(refusal(
            "An input signer does not match a requested signable input",
        ));
    }
    Ok(spends)
}

fn spend_index(index: usize) -> Result<u32> {
    u32::try_from(index).map_err(|_| refusal("Wallet transaction input is malformed"))
}

fn validate_signed(
    partial: &Transaction,
    args: &CreateActionArgs,
    indexes: &[usize],
    spends: &HashMap<u32, SignActionSpend>,
    result: &SignActionResult,
) -> Result<Transaction> {
    let signed = parse(
        result.tx.as_deref().unwrap_or_default(),
        "Wallet signed transaction",
    )?;
    same_template(partial, &signed)?;
    for (index, requested) in args.inputs.iter().flatten().enumerate() {
        let input_index = indexes[index];
        let key = spend_index(input_index)?;
        let expected = requested
            .unlocking_script
            .as_ref()
            .or_else(|| spends.get(&key).map(|s| &s.unlocking_script));
        let actual = signed.inputs[input_index]
            .unlocking_script
            .as_ref()
            .map(crate::script::UnlockingScript::to_binary);
        if actual.as_ref() != expected {
            return Err(refusal(
                "Wallet signed transaction substituted an authorized unlocking script",
            ));
        }
    }
    if let Some(id) = result.txid {
        if crate::primitives::to_hex(&id) != signed.id() {
            return Err(refusal(
                "Wallet signed transaction ID does not match its transaction data",
            ));
        }
    }
    Ok(signed)
}

#[cfg(test)]
#[path = "action_tests.rs"]
mod tests;
