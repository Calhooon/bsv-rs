//! Owned, writer-built transactions for the pre-existing kvstore mock wallets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::sdk;
use sdk::script::{LockingScript, UnlockingScript};
use sdk::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use sdk::wallet::{
    CreateActionArgs, CreateActionResult, Outpoint, SignActionArgs, SignActionResult,
    SignableTransaction,
};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default, Debug)]
pub struct Actions(Mutex<(HashMap<String, Transaction>, Option<Transaction>)>);

impl Actions {
    #[allow(dead_code)] // Used by the integration wallet, not the unit wallet.
    pub fn pending_id(&self) -> [u8; 32] {
        Outpoint::from_string(&format!(
            "{}.0",
            self.0.lock().unwrap().1.as_ref().unwrap().id()
        ))
        .unwrap()
        .txid
    }

    #[allow(dead_code)] // Used by the integration wallet, not the unit wallet.
    pub fn beef(&self, txids: impl Iterator<Item = String>) -> Vec<u8> {
        let state = self.0.lock().unwrap();
        let mut beef = Beef::new();
        for id in txids {
            beef.merge_transaction(state.0[&id].clone());
        }
        beef.to_binary()
    }

    pub fn create(&self, args: &CreateActionArgs) -> CreateActionResult {
        let mut state = self.0.lock().unwrap();
        let mut tx = Transaction::new();
        for input in args.inputs.iter().flatten() {
            let source = state
                .0
                .get(&sdk::primitives::to_hex(&input.outpoint.txid))
                .unwrap();
            let mut candidate =
                TransactionInput::with_source_transaction(source.clone(), input.outpoint.vout);
            candidate.unlocking_script = Some(UnlockingScript::new());
            tx.add_input(candidate).unwrap();
        }
        if tx.inputs.is_empty() {
            let mut funding = Transaction::new();
            funding
                .add_input(TransactionInput::new("11".repeat(32), 0))
                .unwrap();
            let value = args.outputs.iter().flatten().map(|o| o.satoshis).sum();
            funding
                .add_output(TransactionOutput::new(
                    value,
                    LockingScript::from_binary(&[0x51]).unwrap(),
                ))
                .unwrap();
            tx.add_input(TransactionInput::with_source_transaction(funding, 0))
                .unwrap();
        }
        for output in args.outputs.iter().flatten() {
            tx.add_output(TransactionOutput::new(
                output.satoshis,
                LockingScript::from_binary(&output.locking_script).unwrap(),
            ))
            .unwrap();
        }
        if tx.outputs.is_empty() {
            tx.add_output(TransactionOutput::new(
                0,
                LockingScript::from_binary(&[0x00, 0x6a]).unwrap(),
            ))
            .unwrap();
        }
        let id = Outpoint::from_string(&format!("{}.0", tx.id()))
            .unwrap()
            .txid;
        let bytes = tx.to_atomic_beef(true).unwrap();
        state.0.insert(tx.id(), tx.clone());
        state.1 = Some(tx);
        CreateActionResult {
            txid: Some(id),
            signable_transaction: Some(SignableTransaction {
                tx: bytes,
                reference: vec![0x52; 8],
            }),
            ..Default::default()
        }
    }

    pub fn sign(&self, args: SignActionArgs) -> SignActionResult {
        let mut state = self.0.lock().unwrap();
        let mut tx = state.1.take().unwrap();
        for (index, spend) in args.spends {
            tx.inputs[index as usize].unlocking_script =
                Some(UnlockingScript::from_binary(&spend.unlocking_script).unwrap());
        }
        tx.invalidate_caches();
        state.0.insert(tx.id(), tx.clone());
        let id = Outpoint::from_string(&format!("{}.0", tx.id()))
            .unwrap()
            .txid;
        SignActionResult {
            txid: Some(id),
            tx: Some(tx.to_atomic_beef(true).unwrap()),
            send_with_results: None,
        }
    }
}
