//! The caller's two LOCAL budgets for an unproven transaction's scripts
//! (bsv-rs#1043, the stable line's port of beta's #373): the work bound per
//! input (`set_work_limit`) and the memory budget per input's stacks
//! (`set_memory_limit`).
//!
//! Neither is reader state: both are absent from the [`Cursor`](super::Cursor)
//! and are set again after `resume`, a decoded cursor's included. A budget
//! spent is a decline, [`Verdict::SpendRefused`](super::Verdict::SpendRefused)
//! with [`SpendRefusal::Resource`](super::SpendRefusal::Resource), never an
//! invalid script; the structure-only reader runs no script and spends none.

use std::io::Read;

use super::{AsyncStreamVerifier, Headers, StreamVerifier};

/// The budgets every input of the reading runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Budget {
    /// As `TxSpendParams::work_limit`.
    pub(super) work: Option<u64>,
    /// As `TxSpendParams::memory_limit`: `None` is the default mode's
    /// 32,000,000 bytes per stack on this line.
    pub(super) memory: Option<usize>,
}

impl Budget {
    /// Neither budget set: the readers' default, the answers of 0.8.11.
    pub(super) const NONE: Budget = Budget {
        work: None,
        memory: None,
    };
}

impl<R: Read, H: Headers> StreamVerifier<R, H> {
    /// Sets the LOCAL work bound per input, before its scripts run. A
    /// resource decline is `SpendRefusal::Resource`, naming the input, work
    /// spent and budget. `None` is the default. This configuration is not
    /// cursor state: reapply it after `resume`, including a decoded cursor.
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.budget.work = limit;
    }

    /// Sets the LOCAL memory budget per input, in bytes per stack, before its
    /// scripts run. `Some(n)` stops an input whose stack would pass `n`
    /// bytes; the resource decline is
    /// `SpendRefusal::Resource`, naming the input, the bytes asked and the
    /// budget, never a verdict on the script. `None`, the default, is this
    /// line's default-mode budget of 32,000,000 bytes per stack, the figure
    /// every reading used before this setter (on the 0.9 line `None` is
    /// uncapped). This configuration is not cursor state: reapply it after
    /// `resume`, including a decoded cursor.
    pub fn set_memory_limit(&mut self, limit: Option<usize>) {
        self.budget.memory = limit;
    }
}

impl AsyncStreamVerifier {
    /// Sets the LOCAL work bound per input, before its scripts run. A
    /// resource decline is `SpendRefusal::Resource`, naming the input, work
    /// spent and budget. `None` is the default. This configuration is not
    /// cursor state: reapply it after `resume`, including a decoded cursor.
    pub fn set_work_limit(&mut self, limit: Option<u64>) {
        self.budget.work = limit;
    }

    /// Sets the LOCAL memory budget per input, in bytes per stack, before its
    /// scripts run. `Some(n)` stops an input whose stack would pass `n`
    /// bytes; the resource decline is
    /// `SpendRefusal::Resource`, naming the input, the bytes asked and the
    /// budget, never a verdict on the script. `None`, the default, is this
    /// line's default-mode budget of 32,000,000 bytes per stack, the figure
    /// every reading used before this setter (on the 0.9 line `None` is
    /// uncapped). This configuration is not cursor state: reapply it after
    /// `resume`, including a decoded cursor.
    ///
    /// The reader built as a payment check builds it, both budgets set:
    ///
    /// ```
    /// use bsv_rs::script::{LockingScript, Script, ScriptResource, UnlockingScript};
    /// use bsv_rs::transaction::beef_stream::{AsyncByteSource, SpendRefusal};
    /// use bsv_rs::transaction::{
    ///     AsyncStreamVerifier, MerklePath, MockChainTracker, Transaction, TransactionInput,
    ///     TransactionOutput, Verdict,
    /// };
    ///
    /// struct Body(Option<Vec<u8>>);
    /// impl AsyncByteSource for Body {
    ///     async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
    ///         Ok(self.0.take())
    ///     }
    /// }
    ///
    /// // A proven parent locked by `OP_DUP OP_2DROP OP_1`, and a spend of it
    /// // pushing 600 bytes: the duplicate needs 1,200 on the stack.
    /// let mut parent = Transaction::new();
    /// let mut phantom = TransactionInput::new("aa".repeat(32), 0);
    /// phantom.set_unlocking_script(UnlockingScript::new());
    /// parent.add_input(phantom).unwrap();
    /// let lock = LockingScript::from_binary(&[0x76, 0x6d, 0x51]).unwrap();
    /// parent.add_output(TransactionOutput::new(1_000, lock)).unwrap();
    /// parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 800_000));
    /// let mut tracker = MockChainTracker::new(800_000);
    /// tracker.add_root(800_000, parent.id());
    ///
    /// let mut push = Script::new();
    /// push.write_bin(&[0x5a; 600]);
    /// let mut input = TransactionInput::with_source_transaction(parent, 0);
    /// input.set_unlocking_script(UnlockingScript::from_binary(&push.to_binary()).unwrap());
    /// let paid = LockingScript::from_binary(&[0x51]).unwrap();
    /// let output = TransactionOutput::new(900, paid);
    /// let payment = Transaction::with_params(2, vec![input], vec![output], 0);
    /// let beef = payment.to_beef(false).unwrap();
    ///
    /// let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    /// let verdict = runtime.block_on(async {
    ///     let mut reader = AsyncStreamVerifier::new(None);
    ///     reader.set_work_limit(Some(1_000_000));
    ///     reader.set_memory_limit(Some(1_000));
    ///     reader.run(&mut Body(Some(beef)), &tracker).await.unwrap()
    /// });
    /// match verdict {
    ///     Verdict::SpendRefused { input: Some(0), why: SpendRefusal::Resource(limit), .. } => {
    ///         assert_eq!(limit.resource, ScriptResource::Stack);
    ///         assert_eq!((limit.limit, limit.attempted), (1_000, 1_200));
    ///     }
    ///     other => panic!("expected the memory budget's decline: {other:?}"),
    /// }
    /// ```
    pub fn set_memory_limit(&mut self, limit: Option<usize>) {
        self.budget.memory = limit;
    }
}
