//! R404-H1 / bsv-stack-lean #75 B: one input must stop inside its script.
//! Phantom outpoints and a deterministic throwaway key; nothing broadcast.
#![cfg(feature = "transaction")]
use bsv_rs::primitives::bsv::sighash::{compute_sighash_dispatched_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID, SIGHASH_CHRONICLE};
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::{PrivateKey, Writer};
use bsv_rs::script::{Spend, SpendParams, Script, LockingScript, UnlockingScript};
use std::time::Instant;

// Red-only compatibility shim: 0.4.4 has no work budget. Removed with the fix.
trait MissingBudget { fn set_work_limit(&mut self, limit: Option<u64>); }
impl MissingBudget for Spend { fn set_work_limit(&mut self, _: Option<u64>) {} }

fn witness(n: usize, scope: u32) -> (Spend, usize, usize) {
    let key = PrivateKey::from_hex("2a").unwrap();
    let mut lock = Script::new();
    for _ in 0..n {
        lock.write_opcode(0x76).write_bin(&key.public_key().to_compressed()).write_opcode(0xad);
    }
    lock.write_opcode(0x75).write_opcode(0x51);
    let locking = lock.to_binary();
    let inputs = vec![TxInput { txid: [0xaa;32], output_index: 0, script: vec![], sequence: u32::MAX }];
    // The serialized subject is 1 MB plus its ~73-byte unlocking script.
    let outputs = vec![TxOutput { satoshis: 100, script: vec![0;1_000_000 - 64] }];
    let params = SighashParams { version: 2, inputs: &inputs, outputs: &outputs, locktime: 0, input_index: 0, subscript: &locking, satoshis: 1000, scope };
    let digest = compute_sighash_dispatched_for_signing(&params);
    let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope).to_checksig_format();
    let mut unlock = Script::new();
    unlock.write_bin(&sig);
    let mut raw = Writer::new();
    raw.write_i32_le(2).write_var_int(1).write_bytes(&[0xaa;32]).write_u32_le(0).write_var_bytes(&unlock.to_binary()).write_u32_le(u32::MAX).write_var_int(1).write_u64_le(100).write_var_bytes(&outputs[0].script).write_u32_le(0);
    let size = raw.len();
    let spend = Spend::new(SpendParams { source_txid: [0xaa;32], source_output_index: 0, source_satoshis: 1000, locking_script: LockingScript::from_binary(&locking).unwrap(), transaction_version: 2, other_inputs: vec![], outputs, input_index: 0, unlocking_script: UnlockingScript::from_binary(&unlock.to_binary()).unwrap(), input_sequence: u32::MAX, lock_time: 0, memory_limit: None });
    (spend, size, locking.len())
}

#[test]
fn r404_h1_one_input_declines_inside_its_script() {
    let (mut spend, size, lock) = witness(10_000, SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE);
    spend.set_work_limit(Some(10_000_000));
    let start = Instant::now();
    let result = spend.validate();
    println!("R404-H1 n=10000 tx_bytes={size} locking_bytes={lock} budget=10000000 elapsed_ms={:.3} result={:?}", start.elapsed().as_secs_f64()*1000.0, result.as_ref().map_err(|e| &e.message));
    let error = result.expect_err("the evaluator must decline within this single input");
    assert!(error.is_resource_limit());
}

#[test]
#[ignore = "native wall-time measurement at 0.4.4 and after the fix"]
fn native_original_digest_measurements() {
    for n in [1_000, 10_000] {
        let (mut spend, size, lock) = witness(n, SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE);
        let start = Instant::now();
        assert!(spend.validate().unwrap());
        println!("BASELINE n={n} tx_bytes={size} locking_bytes={lock} elapsed_ms={:.3}", start.elapsed().as_secs_f64()*1000.0);
    }
}
