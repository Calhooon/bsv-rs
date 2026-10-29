//! R404-H1 / bsv-stack-lean #75 B: one input must stop inside its script.
//! Phantom outpoints and a deterministic throwaway key; nothing broadcast.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
use bsv_rs::primitives::bsv::sighash::{
    build_sighash_preimage_original, compute_sighash_dispatched_for_signing, SighashParams,
    TxInput, TxOutput, TxSighashCache, SIGHASH_ALL, SIGHASH_CHRONICLE, SIGHASH_FORKID,
};
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::{sha256d, PrivateKey, Writer};
use bsv_rs::script::{
    LockingScript, NotJudgedCause, Script, ScriptResource, Spend, SpendParams, TxSpendParams,
    UnlockingScript,
};
use bsv_rs::transaction::beef_stream::{StreamVerifier, Verdict};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

struct Fixture {
    transaction: Arc<TxSighashCache>,
    locking: LockingScript,
    unlocking: UnlockingScript,
    parent: Vec<u8>,
    raw: Vec<u8>,
    work: u64,
}
impl Fixture {
    fn spend(&self, work_limit: Option<u64>) -> Spend {
        Spend::with_transaction(TxSpendParams {
            transaction: self.transaction.clone(),
            input_index: 0,
            source_satoshis: 1000,
            locking_script: self.locking.clone(),
            unlocking_script: self.unlocking.clone(),
            memory_limit: None,
            work_limit,
        })
        .unwrap()
    }
    fn beef(&self) -> (Vec<u8>, HashMap<u64, [u8; 32]>) {
        let root = sha256d(&self.parent);
        let mut w = Writer::new();
        w.write_u32_le(0xefbe_0002)
            .write_var_int(1)
            .write_var_int(800_000)
            .write_bytes(&[1, 1, 0, 2])
            .write_bytes(&root)
            .write_var_int(2)
            .write_bytes(&[1, 0])
            .write_bytes(&self.parent)
            .write_u8(0)
            .write_bytes(&self.raw);
        (w.into_bytes(), HashMap::from([(800_000, root)]))
    }
}
fn witness(n: usize, scope: u32) -> Fixture {
    let key = PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap();
    let pubkey = key.public_key().to_compressed();
    let mut lock = Script::new();
    for _ in 0..n {
        lock.write_opcode(0x76)
            .write_bin(&pubkey)
            .write_opcode(0xad);
    }
    lock.write_opcode(0x75).write_opcode(0x51);
    let locking = lock.to_binary();
    let mut parent = Writer::new();
    parent
        .write_i32_le(2)
        .write_var_int(1)
        .write_bytes(&[0xaa; 32])
        .write_u32_le(0)
        .write_var_bytes(&[])
        .write_u32_le(u32::MAX)
        .write_var_int(1)
        .write_u64_le(1000)
        .write_var_bytes(&locking)
        .write_u32_le(0);
    let parent = parent.into_bytes();
    let prev = sha256d(&parent);
    let inputs = vec![TxInput {
        txid: prev,
        output_index: 0,
        script: vec![],
        sequence: u32::MAX,
    }];
    // The serialized subject is 1 MB plus its ~73-byte unlocking script.
    let outputs = vec![TxOutput {
        satoshis: 100,
        script: vec![0; 1_000_000 - 64],
    }];
    let params = SighashParams {
        version: 2,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
        input_index: 0,
        subscript: &locking,
        satoshis: 1000,
        scope,
    };
    let work =
        (build_sighash_preimage_original(&params).len() as u64 + 32) * n as u64 + 3 * n as u64 + 3;
    let digest = compute_sighash_dispatched_for_signing(&params);
    let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope).to_checksig_format();
    let mut unlock = Script::new();
    unlock.write_bin(&sig);
    let mut raw = Writer::new();
    raw.write_i32_le(2)
        .write_var_int(1)
        .write_bytes(&prev)
        .write_u32_le(0)
        .write_var_bytes(&unlock.to_binary())
        .write_u32_le(u32::MAX)
        .write_var_int(1)
        .write_u64_le(100)
        .write_var_bytes(&outputs[0].script)
        .write_u32_le(0);
    Fixture {
        transaction: Arc::new(TxSighashCache::new(2, inputs, outputs, 0)),
        locking: LockingScript::from_binary(&locking).unwrap(),
        unlocking: UnlockingScript::from_binary(&unlock.to_binary()).unwrap(),
        parent,
        raw: raw.into_bytes(),
        work,
    }
}

const ORIGINAL: u32 = SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE;
const BUDGET: u64 = 10_000_000;

#[test]
fn r404_h1_one_input_declines_inside_its_script() {
    let fixture = witness(10_000, ORIGINAL);
    let mut spend = fixture.spend(Some(BUDGET));
    let start = Instant::now();
    let error = spend.validate().expect_err("decline within this input");
    let resource = error.resource_limit.unwrap();
    println!(
        "R404-H1 n=10000 tx_bytes={} locking_bytes={} elapsed_ms={:.3} resource={resource:?}",
        fixture.raw.len(),
        fixture.locking.to_binary().len(),
        start.elapsed().as_secs_f64() * 1000.0
    );
    assert_eq!(resource.resource, ScriptResource::Work);
    assert_eq!(resource.limit, BUDGET);
    assert_eq!(resource.work_spent, Some(spend.work_spent()));
    assert!(spend.work_spent() <= BUDGET);
    assert!(resource.attempted > BUDGET);
    // Re-entering a declined evaluation cannot skip the refused hash.
    assert_eq!(spend.step().unwrap_err().resource_limit, Some(resource));
}

#[test]
fn original_digest_at_and_above_its_work_keeps_the_verdict() {
    let fixture = witness(16, ORIGINAL);
    assert!(fixture.spend(None).validate().unwrap());
    let mut bounded = fixture.spend(Some(fixture.work));
    assert!(bounded.validate().unwrap());
    assert_eq!(bounded.work_spent(), fixture.work);
    assert!(fixture.spend(Some(fixture.work + 1)).validate().unwrap());
    let error = fixture
        .spend(Some(fixture.work - 1))
        .validate()
        .unwrap_err();
    assert_eq!(error.resource_limit.unwrap().resource, ScriptResource::Work);
    // A wrong digest remains invalid under None and a generous budget.
    let wrong = Fixture {
        transaction: Arc::new(TxSighashCache::new(
            2,
            fixture.transaction.inputs().to_vec(),
            fixture.transaction.outputs().to_vec(),
            1,
        )),
        ..fixture
    };
    for limit in [None, Some(wrong.work + 1)] {
        let error = wrong.spend(limit).validate().unwrap_err();
        assert!(!error.is_resource_limit());
    }
}

fn simple(lock: Script, unlock: Script, limit: Option<u64>) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0xaa; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: limit,
    })
}

#[test]
fn hash_bytes_are_reserved_before_the_hash_and_zero_before_an_opcode() {
    for (op, second) in [(0xa6, 0), (0xa7, 0), (0xa8, 0), (0xa9, 32), (0xaa, 32)] {
        let mut unlock = Script::new();
        unlock.write_bin(&[7; 64]);
        let mut lock = Script::new();
        lock.write_opcode(op);
        let total = 2 + 64 + second;
        let mut exact = simple(lock.clone(), unlock.clone(), Some(total));
        assert!(exact.validate().unwrap());
        assert_eq!(exact.work_spent(), total);
        let mut low = simple(lock.clone(), unlock.clone(), Some(total - 1));
        let error = low.validate().unwrap_err().resource_limit.unwrap();
        assert_eq!(error.work_spent, Some(2));
        assert_eq!(error.attempted, total);
        let mut zero = simple(lock, unlock, Some(0));
        assert_eq!(
            zero.step().unwrap_err().resource_limit.unwrap().work_spent,
            Some(0)
        );
        exact.reset();
        assert_eq!(exact.work_spent(), 0);
        assert!(exact.validate().unwrap());
    }
    // A skipped HASH256 does not hash, but visited branch opcodes cost units.
    let lock = Script::from_asm("0 OP_IF OP_HASH256 OP_ENDIF OP_1").unwrap();
    let mut spend = simple(lock, Script::new(), Some(5));
    assert!(spend.validate().unwrap());
    assert_eq!(spend.work_spent(), 5);
}

#[test]
fn checks_inside_one_multisig_propagate_a_work_decline() {
    let key = PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap();
    let wrong = PrivateKey::from_hex(&format!("{:064x}", 43)).unwrap();
    let mut lock = Script::new();
    lock.write_opcode(0x51)
        .write_bin(&key.public_key().to_compressed())
        .write_bin(&wrong.public_key().to_compressed())
        .write_opcode(0x52)
        .write_opcode(0xae);
    let input = TxInput {
        txid: [0xaa; 32],
        output_index: 0,
        script: vec![],
        sequence: u32::MAX,
    };
    let tx = Arc::new(TxSighashCache::new(2, vec![input], vec![], 0));
    let digest = tx.sighash_dispatched_for_signing(0, &lock.to_binary(), 1000, ORIGINAL);
    let sig = TransactionSignature::new(key.sign(&digest).unwrap(), ORIGINAL).to_checksig_format();
    let mut unlock = Script::new();
    unlock.write_opcode(0).write_bin(&sig);
    let bytes = build_sighash_preimage_original(&SighashParams {
        version: 2,
        inputs: tx.inputs(),
        outputs: tx.outputs(),
        locktime: 0,
        input_index: 0,
        subscript: &lock.to_binary(),
        satoshis: 1000,
        scope: ORIGINAL,
    })
    .len() as u64
        + 32;
    // Seven opcodes, one failed check (wrong key), then the correct key.
    let total = 7 + 2 * bytes;
    let mut low = simple(lock.clone(), unlock.clone(), Some(total - 1));
    let resource = low.validate().unwrap_err().resource_limit.unwrap();
    assert_eq!(resource.resource, ScriptResource::Work);
    assert_eq!(resource.work_spent, Some(7 + bytes));
    assert_eq!(resource.attempted, total);
    assert!(simple(lock, unlock, Some(total)).validate().unwrap());
}

#[test]
fn stream_names_the_decline_at_input_zero_and_preserves_its_cursor() {
    let fixture = witness(10_000, ORIGINAL);
    let (beef, headers) = fixture.beef();
    let mut reader = StreamVerifier::new(beef.as_slice(), headers, None);
    reader.set_work_limit(Some(BUDGET));
    let start = Instant::now();
    let verdict = reader.run().unwrap();
    println!(
        "STREAM R404-H1 elapsed_ms={:.3} {verdict:?}",
        start.elapsed().as_secs_f64() * 1000.0
    );
    match verdict {
        Verdict::NotJudged {
            input: 0,
            cause:
                NotJudgedCause::WorkBudgetExceeded {
                    input: 0,
                    budget,
                    work_done,
                },
            ..
        } => {
            assert_eq!(budget, BUDGET);
            assert!(work_done <= BUDGET);
        }
        other => panic!("expected a named local decline: {other:?}"),
    }
    // Exact same bytes, ample budget: the script and proof both succeed.
    let control = witness(16, ORIGINAL);
    let (beef, headers) = control.beef();
    let mut reader = StreamVerifier::new(beef.as_slice(), headers.clone(), None);
    reader.set_work_limit(Some(control.work));
    reader.step().unwrap();
    reader.step().unwrap();
    let cursor = reader.cursor();
    let encoded = cursor.to_binary();
    let decoded = bsv_rs::transaction::Cursor::from_binary(&encoded).unwrap();
    assert_eq!(decoded.to_binary(), encoded);
    let mut resumed = StreamVerifier::resume(decoded, &beef[cursor.offset() as usize..], headers);
    resumed.set_work_limit(Some(control.work));
    assert!(resumed.run().unwrap().is_valid());
}

#[test]
#[ignore = "native full-work control, run explicitly in release"]
fn native_original_digest_measurements() {
    for n in [1_000, 10_000] {
        let fixture = witness(n, ORIGINAL);
        let mut spend = fixture.spend(Some(fixture.work + 1));
        let start = Instant::now();
        assert!(spend.validate().unwrap());
        assert_eq!(spend.work_spent(), fixture.work);
        println!(
            "CONTROL n={n} tx_bytes={} locking_bytes={} work={} elapsed_ms={:.3} ms_per_unit={:.9}",
            fixture.raw.len(),
            fixture.locking.to_binary().len(),
            fixture.work,
            start.elapsed().as_secs_f64() * 1000.0,
            start.elapsed().as_secs_f64() * 1000.0 / fixture.work as f64
        );
    }
}

#[test]
fn forkid_charges_missing_midstates_once_and_fixed_preimages_each_check() {
    let fixture = witness(4, SIGHASH_ALL | SIGHASH_FORKID);
    let script = fixture.locking.to_binary();
    // ALL, one input: prevouts 36 + sequence 4 + output 8/5/script,
    // with the 32-byte second hash of each; four BIP-143 preimages.
    let preimage = 156 + 1 + script.len() as u64 + 32;
    let expected = 15
        + 4 * preimage
        + 36
        + 32
        + 4
        + 32
        + 8
        + 5
        + fixture.transaction.outputs()[0].script.len() as u64
        + 32;
    let mut spend = fixture.spend(Some(expected));
    assert!(spend.validate().unwrap());
    assert_eq!(spend.work_spent(), expected);
    // Same Arc: every ALL midstate is now covered; only the preimages cost.
    let mut warm = fixture.spend(Some(15 + 4 * preimage));
    assert!(warm.validate().unwrap());
    assert_eq!(warm.work_spent(), 15 + 4 * preimage);
}

struct Chunk(Option<Vec<u8>>);
impl bsv_rs::transaction::beef_stream::AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}
#[tokio::test]
async fn asynchronous_reader_names_the_same_resource_decline() {
    use bsv_rs::transaction::{AsyncStreamVerifier, MockChainTracker};
    let fixture = witness(16, ORIGINAL);
    let (beef, headers) = fixture.beef();
    let mut tracker = MockChainTracker::new(800_000);
    for (height, mut hash) in headers {
        hash.reverse();
        tracker.add_root(height as u32, bsv_rs::primitives::to_hex(&hash));
    }
    let mut reader = AsyncStreamVerifier::new(None);
    reader.set_work_limit(Some(10_000));
    let verdict = reader.run(&mut Chunk(Some(beef)), &tracker).await.unwrap();
    assert!(
        matches!(verdict, Verdict::NotJudged { input: 0, cause: NotJudgedCause::WorkBudgetExceeded { input: 0, budget: 10_000, work_done }, .. } if work_done <= 10_000)
    );
}

#[tokio::test]
async fn whole_transaction_charges_the_existing_signature_work_378() {
    use bsv_rs::transaction::{MerklePath, MockChainTracker, Transaction};
    use bsv_rs::Error;

    let fixture = witness(16, ORIGINAL);
    let mut parent = Transaction::from_binary(&fixture.parent).unwrap();
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 800_000));
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, parent.id());
    let mut tx = Transaction::from_binary(&fixture.raw).unwrap();
    tx.inputs[0].source_transaction = Some(Box::new(parent));
    let mut spend = fixture.spend(Some(10_000));
    let limit = spend.validate().unwrap_err().resource_limit.unwrap();
    assert_eq!(
        tx.verify_with_work_budget(&tracker, None, None, Some(10_000))
            .await,
        Err(Error::TransactionNotJudged {
            txid: tx.id(),
            input_index: 0,
            cause: NotJudgedCause::WorkBudgetExceeded {
                input: 0,
                budget: 10_000,
                work_done: limit.work_spent.unwrap(),
            },
        })
    );
    for budget in [None, Some(fixture.work), Some(fixture.work + 1)] {
        assert!(tx
            .verify_with_work_budget(&tracker, None, None, budget)
            .await
            .unwrap());
    }
}
