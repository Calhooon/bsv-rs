//! The whole-transaction SPV walk, with an optional chain-derived script word.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::block::ChainParams;
use crate::primitives::bsv::sighash::{TxInput, TxOutput, TxSighashCache};
use crate::script::{LockingScript, Spend, TxSpendParams, UnlockingScript};
use crate::{Error, Result};

use super::transaction::refuse_no_transaction;
use super::{ChainTracker, FeeModel, Transaction, TransactionOutput};

impl Transaction {
    /// SPV verification with the node's standard word derived per input from
    /// `chain`, the tracker's tip + 1 and the source's BUMP height. With no tip,
    /// the latest era in `chain` applies. An unproven source takes the spend's
    /// era; unsupported chain facts return [`Error::TransactionNotJudged`].
    ///
    /// The graph, proof, value, fee and resource behavior is [`Self::verify`]'s.
    /// Proven transactions still use their verified proof without executing
    /// their scripts. The original method retains SDK default evaluation.
    ///
    /// # Errors
    /// Propagates tracker and proof failures, unavailable source data and fee
    /// errors. Script failures are transaction errors; unsupported chain facts
    /// are [`Error::TransactionNotJudged`], and a local resource limit remains
    /// [`Error::ScriptEvaluationDeclined`].
    pub async fn verify_with_chain_params(
        &self,
        chain_tracker: &dyn ChainTracker,
        fee_model: Option<&dyn FeeModel>,
        memory_limit: Option<usize>,
        chain: &ChainParams,
    ) -> Result<bool> {
        verify(self, chain_tracker, fee_model, memory_limit, Some(chain)).await
    }
}

struct Evaluation<'a> {
    chain: Option<&'a ChainParams>,
    tip_height: Option<u32>,
    memory_limit: Option<usize>,
    fee_model: Option<&'a dyn FeeModel>,
}

struct Source<'a> {
    txid: String,
    output: &'a TransactionOutput,
    height: Option<u32>,
}

pub(super) async fn verify(
    root: &Transaction,
    tracker: &dyn ChainTracker,
    fee_model: Option<&dyn FeeModel>,
    memory_limit: Option<usize>,
    chain: Option<&ChainParams>,
) -> Result<bool> {
    let evaluation = Evaluation {
        chain,
        tip_height: if chain.is_some() {
            tracker.mining_tip().await?.map(|t| t.height)
        } else {
            None
        },
        memory_limit,
        fee_model,
    };
    let by_txid = root.reachable_by_txid();
    let mut verified = HashSet::new();
    let mut queue = vec![root.id()];
    while let Some(txid) = queue.pop() {
        if !verified.insert(txid.clone()) {
            continue;
        }
        let Some(tx) = by_txid.get(&txid).copied() else {
            continue;
        };
        refuse_no_transaction(tx, &txid)?;
        if proven(tx, &txid, tracker).await? {
            continue;
        }
        if !evaluation.unproven(tx, &by_txid, &verified, &mut queue)? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn proven(tx: &Transaction, txid: &str, tracker: &dyn ChainTracker) -> Result<bool> {
    let Some(path) = &tx.merkle_path else {
        return Ok(false);
    };
    let root = path.compute_root(Some(txid))?;
    if tracker
        .is_valid_root_for_height(&root, path.block_height)
        .await?
    {
        Ok(true)
    } else {
        Err(Error::TransactionError(format!(
            "Invalid merkle path for transaction {txid}"
        )))
    }
}

fn overflow() -> Error {
    Error::TransactionError("Input satoshis overflow".to_string())
}

fn sources<'a>(
    tx: &Transaction,
    by_txid: &HashMap<String, &'a Transaction>,
) -> Result<(Vec<Source<'a>>, u64)> {
    let mut sources = Vec::with_capacity(tx.inputs.len());
    let mut total = 0u64;
    for (vin, input) in tx.inputs.iter().enumerate() {
        let missing = || Error::TransactionError(format!("Input {vin} has no source transaction"));
        let txid = input.get_source_txid().map_err(|_| missing())?;
        let source = by_txid.get(&txid).copied().ok_or_else(missing)?;
        refuse_no_transaction(source, &txid)?;
        let output = source
            .outputs
            .get(input.source_output_index as usize)
            .ok_or_else(|| {
                Error::TransactionError(format!("Input {vin} source output index out of bounds"))
            })?;
        total = total
            .checked_add(output.satoshis.unwrap_or(0))
            .ok_or_else(overflow)?;
        sources.push(Source {
            txid,
            output,
            height: source.merkle_path.as_ref().map(|p| p.block_height),
        });
    }
    Ok((sources, total))
}

impl Evaluation<'_> {
    fn unproven(
        &self,
        tx: &Transaction,
        by_txid: &HashMap<String, &Transaction>,
        verified: &HashSet<String>,
        queue: &mut Vec<String>,
    ) -> Result<bool> {
        let (sources, input_total) = sources(tx, by_txid)?;
        let output_total = tx.outputs.iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.satoshis.unwrap_or(0))
                .ok_or_else(overflow)
        })?;
        if let Some(model) = self.fee_model {
            if input_total.saturating_sub(output_total) < model.compute_fee(tx)? {
                return Err(Error::TransactionError("Fee is too low".to_string()));
            }
        }
        let shared = shared_sighash(tx)?;
        for (vin, source) in sources.into_iter().enumerate() {
            self.input(tx, vin, &source, shared.clone())?;
            if !verified.contains(&source.txid) {
                queue.push(source.txid);
            }
        }
        Ok(output_total <= input_total)
    }

    fn input(
        &self,
        tx: &Transaction,
        vin: usize,
        source: &Source<'_>,
        shared: Arc<TxSighashCache>,
    ) -> Result<()> {
        let flags = self
            .chain
            .map(|chain| {
                super::verification_flags::verification_flags(chain, self.tip_height, source.height)
                    .map_err(|cause| Error::TransactionNotJudged {
                        txid: tx.id(),
                        input_index: vin,
                        cause,
                    })
            })
            .transpose()?;
        let unlocking = tx.inputs[vin].unlocking_script.as_ref().ok_or_else(|| {
            Error::TransactionError(format!("Input {vin} is missing unlocking script"))
        })?;
        let mut spend = Spend::with_transaction(TxSpendParams {
            transaction: shared,
            input_index: vin,
            source_satoshis: source.output.satoshis.unwrap_or(0),
            locking_script: LockingScript::from_binary(&source.output.locking_script.to_binary())?,
            unlocking_script: UnlockingScript::from_binary(&unlocking.to_binary())?,
            memory_limit: self.memory_limit,
            work_limit: None,
        })?;
        if let Some(flags) = flags {
            spend.set_flags(flags);
        }
        spend
            .validate()
            .map_err(|e| super::verify_refusal::script_refusal(vin, e))?;
        Ok(())
    }
}

fn shared_sighash(tx: &Transaction) -> Result<Arc<TxSighashCache>> {
    let outputs = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis.unwrap_or(0),
            script: o.locking_script.to_binary(),
        })
        .collect();
    let inputs = tx
        .inputs
        .iter()
        .map(|i| {
            Ok(TxInput {
                txid: i.get_source_txid_bytes()?,
                output_index: i.source_output_index,
                script: i
                    .unlocking_script
                    .as_ref()
                    .map(|s| s.to_binary())
                    .unwrap_or_default(),
                sequence: i.sequence,
            })
        })
        .collect::<Result<_>>()?;
    Ok(Arc::new(TxSighashCache::new(
        tx.version as i32,
        inputs,
        outputs,
        tx.lock_time,
    )))
}
