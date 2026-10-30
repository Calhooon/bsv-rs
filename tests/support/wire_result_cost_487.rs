//! Deterministic large, conforming wire answer, built by the public writers.
#![allow(clippy::unwrap_used)] // Fixed writer inputs in test fixtures (#134).

use async_trait::async_trait;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{MerklePath, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::wire::{WalletWire, WireWriter};
use bsv_rs::wallet::CreateActionArgs;
use bsv_rs::Error;

pub struct Fixed(pub Vec<u8>);

#[async_trait]
impl WalletWire for Fixed {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

pub fn fixture(mib: usize, bind_output: bool) -> (CreateActionArgs, Vec<u8>) {
    let mut parent = Transaction::new();
    let mut input = TransactionInput::new("11".repeat(32), 0);
    input.unlocking_script = Some(UnlockingScript::new());
    parent.add_input(input).unwrap();
    parent
        .add_output(TransactionOutput::new(
            2_000_000,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ))
        .unwrap();
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 800_000));
    let length = mib * 1024 * 1024;
    let mut script = vec![0, 0x6a, 0x4e];
    script.extend_from_slice(&(length as u32).to_le_bytes());
    script.resize(length + 7, 0xab);
    let mut child = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    child.add_input(input).unwrap();
    child
        .add_output(TransactionOutput::new(
            1000,
            LockingScript::from_binary(&script).unwrap(),
        ))
        .unwrap();
    let beef = child.to_atomic_beef(true).unwrap();
    let id: [u8; 32] = hex::decode(child.id()).unwrap().try_into().unwrap();
    let mut writer = WireWriter::new();
    writer.write_u8(0);
    writer.write_i8(1);
    writer.write_bytes(&id);
    writer.write_i8(1);
    writer.write_var_int(beef.len() as u64);
    writer.write_bytes(&beef);
    writer.write_var_int(u64::MAX); // noSendChange absent
    writer.write_var_int(u64::MAX); // sendWithResults absent
    writer.write_i8(0); // signableTransaction absent
    let mut args = serde_json::json!({"description": "large wire answer"});
    if bind_output {
        args["outputs"] = serde_json::json!([{
            "lockingScript": hex::encode(script), "satoshis": 1000,
            "outputDescription": "large wire output",
        }]);
    }
    (serde_json::from_value(args).unwrap(), writer.into_bytes())
}
