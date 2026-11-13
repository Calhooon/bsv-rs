//! The whole-transaction SPV walk, with an optional chain-derived script word.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::block::ChainParams;
use crate::primitives::bsv::sighash::TxSighashCache;
use crate::{Error, Result};

use super::amount::{add_amount, require_satoshi_amount};
use super::source_link::source_named_otherwise;
use super::spending::{judge_input, sighash_of, InputRules};
use super::transaction::refuse_no_transaction;
use super::{ChainTracker, FeeModel, Transaction, TransactionOutput, WorkBudget};

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
    /// are [`Error::TransactionNotJudged`], and a local memory limit remains
    /// [`Error::ScriptEvaluationDeclined`].
    pub async fn verify_with_chain_params(
        &self,
        chain_tracker: &dyn ChainTracker,
        fee_model: Option<&dyn FeeModel>,
        memory_limit: Option<usize>,
        chain: &ChainParams,
    ) -> Result<bool> {
        self.verify_with_chain_params_and_work_budget(
            chain_tracker,
            fee_model,
            memory_limit,
            None,
            chain,
        )
        .await
    }

    /// SPV verification with an optional local work budget per input.
    ///
    /// Uses SDK default evaluation, as [`Self::verify`], with `work_limit` in
    /// [`crate::script::SpendParams::work_limit`] units: reached opcodes plus
    /// bytes hashed, charged before the work. `None` is the default and keeps
    /// the reference's unbounded behavior; the reference's `verify` has no
    /// work bound. This is a door's policy, not a clock or consensus rule:
    /// it cannot interrupt an arithmetic opcode already running.
    ///
    /// # Errors
    /// As [`Self::verify`]. Work exhaustion returns
    /// [`Error::TransactionNotJudged`] with
    /// [`crate::script::NotJudgedCause::WorkBudgetExceeded`], naming the input,
    /// budget and work already charged. Memory declines keep their class.
    pub async fn verify_with_work_budget(
        &self,
        chain_tracker: &dyn ChainTracker,
        fee_model: Option<&dyn FeeModel>,
        memory_limit: Option<usize>,
        work_limit: Option<u64>,
    ) -> Result<bool> {
        verify(
            self,
            chain_tracker,
            fee_model,
            memory_limit,
            WorkBudget::NONE.with_per_input(work_limit),
            None,
        )
        .await
    }

    /// Chain-parameter SPV verification with an optional local work budget per input.
    ///
    /// The word selection is [`Self::verify_with_chain_params`]'s; the budget,
    /// default `None`, accounting and resource refusal are
    /// [`Self::verify_with_work_budget`]'s. The reference's `verify` has no
    /// work bound; callers set this local policy at each service door.
    ///
    /// # Errors
    /// As [`Self::verify_with_chain_params`], with work exhaustion returned as
    /// [`Error::TransactionNotJudged`] carrying
    /// [`crate::script::NotJudgedCause::WorkBudgetExceeded`].
    pub async fn verify_with_chain_params_and_work_budget(
        &self,
        chain_tracker: &dyn ChainTracker,
        fee_model: Option<&dyn FeeModel>,
        memory_limit: Option<usize>,
        work_limit: Option<u64>,
        chain: &ChainParams,
    ) -> Result<bool> {
        verify(
            self,
            chain_tracker,
            fee_model,
            memory_limit,
            WorkBudget::NONE.with_per_input(work_limit),
            Some(chain),
        )
        .await
    }

    /// SPV verification with per-input and per-transaction local work bounds.
    ///
    /// The defaults and accounting are [`Self::verify_with_work_budget`]'s.
    /// Each unproven transaction gets a fresh total, charged after each input
    /// in verification order. A proof does not execute or charge its scripts.
    ///
    /// # Errors
    /// As [`Self::verify_with_work_budget`]. Crossing `work.per_transaction`
    /// returns [`Error::TransactionNotJudged`] with
    /// [`crate::script::NotJudgedCause::TransactionWorkBudgetExceeded`], naming
    /// the crossing input, the limit and the total including that input.
    pub async fn verify_with_work_budgets(
        &self,
        chain_tracker: &dyn ChainTracker,
        fee_model: Option<&dyn FeeModel>,
        memory_limit: Option<usize>,
        work: WorkBudget,
    ) -> Result<bool> {
        verify(self, chain_tracker, fee_model, memory_limit, work, None).await
    }

    /// Chain-parameter verification with both local work bounds.
    ///
    /// The word selection is [`Self::verify_with_chain_params`]'s; accounting
    /// and per-transaction totals are [`Self::verify_with_work_budgets`]'s.
    ///
    /// # Errors
    /// As [`Self::verify_with_chain_params_and_work_budget`], with
    /// [`crate::script::NotJudgedCause::TransactionWorkBudgetExceeded`] when
    /// the transaction total crosses its bound.
    pub async fn verify_with_chain_params_and_work_budgets(
        &self,
        chain_tracker: &dyn ChainTracker,
        fee_model: Option<&dyn FeeModel>,
        memory_limit: Option<usize>,
        work: WorkBudget,
        chain: &ChainParams,
    ) -> Result<bool> {
        verify(
            self,
            chain_tracker,
            fee_model,
            memory_limit,
            work,
            Some(chain),
        )
        .await
    }
}

struct Evaluation<'a> {
    chain: Option<&'a ChainParams>,
    tip_height: Option<u32>,
    memory_limit: Option<usize>,
    work: WorkBudget,
    fee_model: Option<&'a dyn FeeModel>,
}

struct Source<'a> {
    txid: String,
    output: &'a TransactionOutput,
    satoshis: u64,
    height: Option<u32>,
}

pub(super) async fn verify(
    root: &Transaction,
    tracker: &dyn ChainTracker,
    fee_model: Option<&dyn FeeModel>,
    memory_limit: Option<usize>,
    work: WorkBudget,
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
        work,
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
    // The reference's `MerklePath.verify` (`MerklePath.ts:476-500`, #734): an
    // offset-0 proof under 100 blocks deep is not proven.
    if path.verify(txid, tracker).await? {
        Ok(true)
    } else {
        Err(Error::TransactionError(format!(
            "Invalid merkle path for transaction {txid}"
        )))
    }
}

/// An input's source amount, refused when absent or past 21e14 and summed
/// into the input total, refused past 21e14, as the reference's
/// `#verifyTransactionInputs` reads it (`requireSatoshiAmount` and
/// `addSatoshiAmount`, `ts-stack@edf6e03` `Transaction.ts:1414-1418`); an
/// absent amount was read as 0 and the total bounded by `u64` until #848's
/// fold.
fn source_amount(output: &TransactionOutput, vin: usize, total: &mut u64) -> Result<u64> {
    let satoshis = require_satoshi_amount(output.satoshis, &format!("Input {vin} source amount"))?;
    *total = add_amount(*total, satoshis, "Transaction input total")?;
    Ok(satoshis)
}

/// The output total, each amount refused when absent or past 21e14 and the
/// total past 21e14, read before any input as the reference's
/// `#validateUnminedTransactionStructure` reads it (`#totalVerifiedOutputs`,
/// `Transaction.ts:1367`, `:1464-1474`); an absent amount was read as 0 and
/// the outputs read after the inputs until #848's fold.
fn output_total(tx: &Transaction) -> Result<u64> {
    tx.outputs()
        .iter()
        .enumerate()
        .try_fold(0u64, |total, (index, output)| {
            let amount =
                require_satoshi_amount(output.satoshis, &format!("Output {index} amount"))?;
            add_amount(total, amount, "Transaction output total")
        })
}

fn sources<'a>(
    tx: &Transaction,
    by_txid: &HashMap<String, &'a Transaction>,
) -> Result<(Vec<Source<'a>>, u64)> {
    let mut sources = Vec::with_capacity(tx.inputs().len());
    let mut total = 0u64;
    for (vin, input) in tx.inputs().iter().enumerate() {
        let missing = || Error::TransactionError(format!("Input {vin} has no source transaction"));
        let out_of_bounds =
            || Error::TransactionError(format!("Input {vin} source output index out of bounds"));
        // An input that links no source (#848's fold): refused in the
        // reference's words (`Transaction.ts:1396-1400`), whether or not the
        // txid it names is another input's source; until the fold it was
        // judged against that source when one was reachable.
        if input.source_transaction.is_none() {
            return Err(Error::TransactionError(format!(
                "Verification failed because the input at index {vin} of transaction {} is \
                 missing an associated source transaction. This source transaction is required \
                 for transaction verification because there is no merkle proof for the \
                 transaction spending a UTXO it contains.",
                tx.id()
            )));
        }
        // A linked source under another txid (#848): refused where the
        // reference refuses it (`Transaction.ts:1410-1432`), after the linked
        // source's output is found and its amount checked and summed,
        // whatever the source holds (no exemption for a descriptor without
        // inputs) and whether or not the named txid is another reachable
        // transaction's.
        if let Some(linked) = source_named_otherwise(input) {
            let output = linked
                .outputs()
                .get(input.source_output_index as usize)
                .ok_or_else(out_of_bounds)?;
            source_amount(output, vin, &mut total)?;
            return Err(Error::TransactionError(format!(
                "Verification failed because input {vin} of transaction {} does not reference \
                 its supplied source transaction.",
                tx.id()
            )));
        }
        // The walk is by txid; a text in upper case names the same 32 bytes
        // (the serializer's reading, the reference's `requireTXID`).
        let txid = input
            .get_source_txid()
            .map_err(|_| missing())?
            .to_ascii_lowercase();
        let source = by_txid.get(&txid).copied().ok_or_else(missing)?;
        refuse_no_transaction(source, &txid)?;
        let output = source
            .outputs()
            .get(input.source_output_index as usize)
            .ok_or_else(out_of_bounds)?;
        let satoshis = source_amount(output, vin, &mut total)?;
        sources.push(Source {
            txid,
            output,
            satoshis,
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
        let output_total = output_total(tx)?;
        let (sources, input_total) = sources(tx, by_txid)?;
        if let Some(model) = self.fee_model {
            if input_total.saturating_sub(output_total) < model.compute_fee(tx)? {
                return Err(Error::TransactionError("Fee is too low".to_string()));
            }
        }
        let shared = sighash_of(tx)?;
        let mut work_spent = 0;
        for (vin, source) in sources.into_iter().enumerate() {
            let work = self.input(tx, vin, &source, shared.clone())?;
            self.work
                .charge(&mut work_spent, vin as u32, work)
                .map_err(|cause| Error::TransactionNotJudged {
                    txid: tx.id(),
                    input_index: vin,
                    cause,
                })?;
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
    ) -> Result<u64> {
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
        let unlocking = tx.inputs()[vin].unlocking_script.as_ref().ok_or_else(|| {
            Error::TransactionError(format!("Input {vin} is missing unlocking script"))
        })?;
        let rules = InputRules::for_verifier(flags, self.memory_limit, self.work.input_limit());
        let judged = judge_input(
            &shared,
            vin,
            &source.output.locking_script.to_binary(),
            &unlocking.to_binary(),
            source.satoshis,
            &rules,
        );
        match judged.result {
            Ok(verified) => Ok(verified.work_spent),
            Err(refusal) => {
                let error = refusal.before_evaluation()?;
                Err(super::verify_refusal::script_refusal(&tx.id(), vin, error))
            }
        }
    }
}
