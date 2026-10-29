//! Script checks shared by in-order and deferred transactions. The index
//! retains only the requested outputs; one sighash cache serves all inputs.

use std::sync::Arc;

use crate::primitives::bsv::sighash::{TxInput, TxOutput, TxSighashCache};
use crate::script::{LockingScript, Spend, TxSpendParams, UnlockingScript};

use super::deferred::HeldInput;
use super::{
    BeefIndex, ChainTip, Evaluation, Hash32, MiningCheck, Retained, SpendRefusal, Stop, TxFields,
    MAX_MONEY,
};

struct InputCheck<'a, T> {
    txid: &'a Hash32,
    body: &'a T,
    evaluation: &'a Evaluation,
    tip: Option<ChainTip>,
}

impl BeefIndex {
    #[allow(clippy::too_many_arguments)] // The existing fold's resumption and mining context.
    pub(super) fn check_spends_of<T: TxFields>(
        &self,
        offset: u64,
        txid: &Hash32,
        body: &T,
        from: u32,
        spent: &mut dyn FnMut() -> bool,
        evaluation: &Evaluation,
        tip: Option<ChainTip>,
    ) -> Result<Option<u32>, Stop> {
        let check = InputCheck {
            txid,
            body,
            evaluation,
            tip,
        };
        let (sources, input_total) = check.sources(self)?;
        let output_total: u64 = (0..body.output_count()).map(|v| body.output(v).1).sum();
        // check_transaction bounded every output prefix before this check.
        debug_assert!(output_total <= MAX_MONEY);
        let shared = shared_sighash(body);
        for (vin, source) in sources.into_iter().enumerate().skip(from as usize) {
            if vin > from as usize && spent() {
                return Ok(Some(vin as u32));
            }
            check.execute(self, vin, source, shared.clone())?;
        }
        if output_total > input_total {
            return Err(check.refuse(offset, None, SpendRefusal::CreatesValue));
        }
        Ok(None)
    }
}

impl<T: TxFields> InputCheck<'_, T> {
    fn refuse(&self, offset: u64, input: Option<u32>, why: SpendRefusal) -> Stop {
        Stop::Spend {
            offset,
            txid: *self.txid,
            input,
            why,
        }
    }

    fn sources<'a>(&self, index: &'a BeefIndex) -> Result<(Vec<&'a Retained>, u64), Stop> {
        let mut sources = Vec::with_capacity(self.body.input_count());
        let mut total = 0;
        for vin in 0..self.body.input_count() {
            let input = self.body.input(vin);
            let refuse = |why| self.refuse(input.at, Some(vin as u32), why);
            let parent = index.txs.get(&input.prev).ok_or_else(|| {
                super::Refusal::new(
                    input.at,
                    super::Reason::InputNamesNoElement { txid: input.prev },
                )
            })?;
            if !parent.raw {
                return Err(refuse(SpendRefusal::ParentIsTxidOnly));
            }
            let source = parent
                .outputs
                .as_ref()
                .and_then(|o| o.get(input.vout as usize))
                .and_then(Option::as_ref)
                .ok_or_else(|| refuse(SpendRefusal::OutputNotAvailable { vout: input.vout }))?;
            if let Some(height) = parent.coinbase_height {
                self.check_maturity(&input, vin, height)?;
            }
            if source.satoshis > MAX_MONEY || source.satoshis > MAX_MONEY - total {
                return Err(refuse(SpendRefusal::InputValueOutOfRange));
            }
            total += source.satoshis;
            sources.push(source);
        }
        Ok((sources, total))
    }

    fn check_maturity(&self, input: &HeldInput, vin: usize, height: u64) -> Result<(), Stop> {
        // sibling BLOCK-CONSENSUS.md:68; node consensus/consensus.h:75.
        let context = self.tip.ok_or(Stop::Unverifiable {
            offset: input.at,
            txid: *self.txid,
            input: Some(vin as u32),
            check: MiningCheck::CoinbaseMaturity,
        })?;
        if (u64::from(context.height) + 1)
            .checked_sub(height)
            .is_none_or(|depth| depth < 100)
        {
            return Err(self.refuse(
                input.at,
                Some(vin as u32),
                SpendRefusal::PrematureCoinbase { height },
            ));
        }
        Ok(())
    }

    fn execute(
        &self,
        index: &BeefIndex,
        vin: usize,
        source: &Retained,
        shared: Arc<TxSighashCache>,
    ) -> Result<(), Stop> {
        let input = self.body.input(vin);
        let refuse = |why| self.refuse(input.at, Some(vin as u32), why);
        let script_error = |e: String| refuse(SpendRefusal::Script(e));
        let source_height = index
            .proven
            .get(&input.prev)
            .and_then(|i| index.bumps.get(*i as usize))
            .map(|b| b.0);
        let flags = self
            .evaluation
            .flags(self.tip, source_height)
            .map_err(|cause| {
                refuse(SpendRefusal::NotJudged {
                    input: vin as u32,
                    cause,
                })
            })?;
        let locking_script =
            LockingScript::from_binary(&source.script).map_err(|e| script_error(e.to_string()))?;
        let unlocking_script = UnlockingScript::from_binary(self.body.unlocking(vin))
            .map_err(|e| script_error(e.to_string()))?;
        let mut spend = Spend::with_transaction(TxSpendParams {
            transaction: shared,
            input_index: vin,
            source_satoshis: source.satoshis,
            locking_script,
            unlocking_script,
            memory_limit: self.evaluation.memory,
            work_limit: self.evaluation.work,
        })
        .map_err(|e| script_error(e.to_string()))?;
        if let Some(flags) = flags {
            spend.set_flags(flags);
        }
        match spend.validate() {
            Ok(true) => Ok(()),
            Ok(false) => Err(script_error("the script did not succeed".to_string())),
            Err(e) => Err(match e.resource_limit {
                Some(limit) => refuse(SpendRefusal::Resource(limit)),
                None => script_error(e.message),
            }),
        }
    }
}

fn shared_sighash(body: &impl TxFields) -> Arc<TxSighashCache> {
    let outputs = (0..body.output_count())
        .map(|vout| {
            let (_, satoshis, script) = body.output(vout);
            TxOutput {
                satoshis,
                script: script.to_vec(),
            }
        })
        .collect();
    let inputs = (0..body.input_count())
        .map(|i| {
            let input = body.input(i);
            TxInput {
                txid: input.prev,
                output_index: input.vout,
                script: Vec::new(),
                sequence: input.sequence,
            }
        })
        .collect();
    Arc::new(TxSighashCache::new(
        body.version() as i32,
        inputs,
        outputs,
        body.lock_time(),
    ))
}
