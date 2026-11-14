//! The door that verifies one input of a transaction held as bytes (#855):
//! `SpendingTransaction::from_bytes(..).verify_input(..)` and the one-shot
//! `verify_input(..)` in the node's argument order.
//!
//! (a) the door equals a `Spend::new` built by hand, verdict, words and
//! resource fields, on every spend of `vectors/spend_valid.json`,
//! `script_valid.json` and `script_invalid.json`, at versions 1 and 2, in the
//! default mode and under `ScriptFlags::block(era)` and `standard(era)` of
//! both eras, and again under a memory and a work budget; (b) the door
//! equals `Transaction::verify`'s class for every input of every vector
//! transaction whose sources the vectors carry (each BEEF under `tests/`)
//! and of signed P2PKH spends this crate's writer builds, in the default
//! mode and under the chain parameters' word; (c) the prepared form equals
//! the one-shot; (d) each refusal before evaluation; (e) a decline is
//! `Declined`, never `Invalid`, and a larger budget judges the script; (f)
//! the default mode's overrides; (g) a word takes no override; (h) the
//! setters commute. `from_bytes` agrees with `Transaction::from_binary` on
//! every transaction the vectors hold and on their single-byte changes,
//! truncations and extensions, save a transaction whose only refusal there
//! is an output amount of 2^53 or more, which the door reads as the node
//! does and the default mode refuses in `from_binary`'s error (#874,
//! `verify_input_door_amount_874.rs`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code: a failed unwrap is the test failing.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use bsv_rs::block::ChainParams;
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptEvaluationError, ScriptFlags, ScriptFlagsError,
    ScriptResource, SignOutputs, Spend, SpendParams, UnlockingScript, Word,
};
use bsv_rs::transaction::{
    verify_input, Beef, DefaultMode, InputRefusal, InputRules, InputVerified, MerklePath,
    MockChainTracker, SpendingTransaction, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::Value;

// ============================================================================
// (a) The door against `Spend::new` built by hand
// ============================================================================

/// The modes of the equality runs: the default mode and the four words.
fn modes() -> Vec<Option<ScriptFlags>> {
    let mut modes = vec![None];
    for era in [ProtocolEra::PostGenesis, ProtocolEra::PostChronicle] {
        modes.push(Some(ScriptFlags::block(era)));
        modes.push(Some(ScriptFlags::standard(era)));
    }
    modes
}

/// The spending transaction `Spend::new` builds from its parameters: one
/// input of the zero outpoint, no output, lock time 0.
fn one_input_transaction(unlocking: &[u8], version: u32) -> Vec<u8> {
    let mut input = TransactionInput::new("00".repeat(32).parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_binary(unlocking).unwrap());
    Transaction::with_params(version, vec![input], vec![], 0).to_binary()
}

#[derive(Clone, Copy)]
struct Budget {
    memory: Option<usize>,
    work: Option<u64>,
}

const UNBOUNDED: Budget = Budget {
    memory: None,
    work: None,
};

fn rules(word: Option<ScriptFlags>, budget: Budget) -> InputRules {
    let mut rules = match word {
        Some(word) => InputRules::under(word).unwrap(),
        None => InputRules::reference_default(),
    };
    if let Some(bytes) = budget.memory {
        rules = rules.with_memory_limit(bytes);
    }
    if let Some(units) = budget.work {
        rules = rules.with_work_limit(units);
    }
    rules
}

fn by_hand(
    lock: &[u8],
    unlock: &[u8],
    version: u32,
    word: Option<ScriptFlags>,
    budget: Budget,
) -> (Result<bool, ScriptEvaluationError>, u64) {
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_binary(lock).unwrap(),
        transaction_version: version as i32,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(unlock).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: budget.memory,
        // The door counts the work whatever the rules bound: the hand-built
        // spend counts it under `u64::MAX` when the budget names none.
        work_limit: Some(budget.work.unwrap_or(u64::MAX)),
    });
    if let Some(word) = word {
        spend.set_flags(word);
    }
    let verdict = spend.validate();
    (verdict, spend.work_spent())
}

/// `None` when the door answers what the hand-built `Spend` answered; else
/// the difference in words.
fn differs(
    hand: &(Result<bool, ScriptEvaluationError>, u64),
    door: &Result<InputVerified, InputRefusal>,
) -> Option<String> {
    let agree = match (&hand.0, door) {
        (Ok(true), Ok(verified)) => verified.work_spent == hand.1,
        (Err(e), Err(InputRefusal::Declined(d))) if e.is_resource_limit() => {
            format!("{e:?}") == format!("{d:?}")
        }
        (Err(e), Err(InputRefusal::Invalid(d))) if !e.is_resource_limit() => {
            format!("{e:?}") == format!("{d:?}")
        }
        _ => false,
    };
    (!agree).then(|| format!("by hand {hand:?}, door {door:?}"))
}

struct SpendCase {
    file: &'static str,
    index: usize,
    lock: Vec<u8>,
    unlock: Vec<u8>,
}

fn hex(text: &str) -> Option<Vec<u8>> {
    bsv_rs::primitives::from_hex(text).ok()
}

fn spend_cases() -> Vec<SpendCase> {
    let mut cases = Vec::new();
    for file in [
        "spend_valid.json",
        "script_valid.json",
        "script_invalid.json",
    ] {
        let text = fs::read_to_string(format!("tests/vectors/{file}")).unwrap();
        let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
        for (index, vector) in vectors.iter().enumerate() {
            let (Some(unlock), Some(lock)) = (
                hex(vector["scriptSig"].as_str().unwrap_or_default()),
                hex(vector["scriptPubKey"].as_str().unwrap_or_default()),
            ) else {
                continue;
            };
            cases.push(SpendCase {
                file,
                index,
                lock,
                unlock,
            });
        }
    }
    cases
}

fn compare_spends(budget: Budget) -> (usize, Vec<String>) {
    let mut runs = 0;
    let mut differences = Vec::new();
    for case in spend_cases() {
        for version in [1u32, 2] {
            let bytes = one_input_transaction(&case.unlock, version);
            let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
            for word in modes() {
                let rules = rules(word, budget);
                let hand = by_hand(&case.lock, &case.unlock, version, word, budget);
                let door = prepared.verify_input(0, &case.lock, 1, &rules);
                let once = verify_input(&case.lock, 1, &bytes, 0, &rules);
                runs += 1;
                if let Some(why) = differs(&hand, &door) {
                    differences.push(format!(
                        "{} #{} v{version} {word:?}: {why}",
                        case.file, case.index
                    ));
                }
                if once != door {
                    differences.push(format!(
                        "{} #{} v{version} {word:?}: one-shot {once:?}, prepared {door:?}",
                        case.file, case.index
                    ));
                }
            }
        }
    }
    (runs, differences)
}

#[test]
fn the_door_equals_a_spend_built_by_hand_on_every_vector_spend_855() {
    let (runs, differences) = compare_spends(UNBOUNDED);
    eprintln!("spends judged through the door and by hand: {runs}");
    assert_eq!(runs, 14_880, "the vectors moved: {runs} runs");
    assert!(
        differences.is_empty(),
        "{} of {runs} differ:\n{}",
        differences.len(),
        differences[..differences.len().min(20)].join("\n")
    );
}

#[test]
fn the_door_equals_a_spend_built_by_hand_under_a_budget_855() {
    let tight = Budget {
        memory: Some(48),
        work: Some(12),
    };
    let (runs, differences) = compare_spends(tight);
    eprintln!("spends judged under a budget: {runs}");
    assert!(
        differences.is_empty(),
        "{} of {runs} differ:\n{}",
        differences.len(),
        differences[..differences.len().min(20)].join("\n")
    );
}

// ============================================================================
// (b) The door against `Transaction::verify`
// ============================================================================

const TIP: u32 = 900_000;

/// A transaction whose every input links a source proven by a lone-leaf
/// path at its own height (each deep below the tip), so that
/// `Transaction::verify` judges this transaction's inputs alone.
struct Linked {
    name: String,
    tx: Transaction,
    tracker: MockChainTracker,
}

fn link(name: String, tx: &Transaction, parents: &HashMap<String, Transaction>) -> Option<Linked> {
    if tx.inputs().is_empty() || tx.outputs().is_empty() {
        return None;
    }
    let mut tracker = MockChainTracker::new(TIP);
    let mut linked = tx.clone();
    for (vin, input) in tx.inputs().iter().enumerate() {
        let txid = input.get_source_txid().ok()?;
        let mut parent = parents.get(&txid)?.clone();
        if parent.inputs().is_empty()
            || parent.outputs().len() <= input.source_output_index as usize
        {
            return None;
        }
        let height = 800_000 + vin as u32;
        tracker.add_root(height, txid.clone());
        parent.merkle_path = Some(MerklePath::from_coinbase_txid(&txid, height));
        linked.inputs_mut()[vin].source_transaction = Some(Box::new(parent));
    }
    Some(Linked {
        name,
        tx: linked,
        tracker,
    })
}

fn beef_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            beef_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "bin") {
            out.push(path);
        }
    }
}

fn vector_transactions() -> Vec<Linked> {
    let mut files = Vec::new();
    beef_files(Path::new("tests"), &mut files);
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let Ok(beef) = Beef::from_binary(&fs::read(&file).unwrap()) else {
            continue;
        };
        let held: HashMap<String, Transaction> = beef
            .txs
            .iter()
            .filter_map(|entry| entry.tx().map(|tx| (tx.id(), tx.clone())))
            .collect();
        for entry in beef.txs.iter().filter(|e| e.bump_index().is_none()) {
            if let Some(tx) = entry.tx() {
                let name = format!("{} {}", file.display(), tx.id());
                out.extend(link(name, tx, &held));
            }
        }
    }
    out
}

/// Signed P2PKH spends of 1, 3 and 10 inputs, each as signed and with input
/// 1's signature broken (where it has one).
fn signed_spends() -> Vec<Linked> {
    let key = PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let address = key.public_key().to_address();
    let mut out = Vec::new();
    for inputs in [1usize, 3, 10] {
        let mut parents = HashMap::new();
        let mut spend = Transaction::new();
        for n in 0..inputs {
            let mut funding = Transaction::new();
            let mut mined =
                TransactionInput::new((format!("{:02x}", n + 1).repeat(32)).parse().unwrap(), 0);
            mined.unlocking_script = Some(UnlockingScript::new());
            funding.add_input(mined).unwrap();
            funding
                .add_output(TransactionOutput::new(
                    10_000,
                    P2PKH::lock_from_address(&address).unwrap(),
                ))
                .unwrap();
            let mut input = TransactionInput::with_source_transaction(funding.clone(), 0);
            input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
            spend.add_input(input).unwrap();
            parents.insert(funding.id(), funding);
        }
        spend.add_p2pkh_output(&address, Some(9_000)).unwrap();
        futures::executor::block_on(spend.sign()).unwrap();
        let bare = Transaction::from_binary(&spend.to_binary()).unwrap();
        out.extend(link(format!("p2pkh x{inputs}"), &bare, &parents));
        if inputs > 1 {
            let mut broken = bare.to_binary();
            let sig = broken
                .windows(4)
                .enumerate()
                .filter(|(_, w)| w[0] == 0x30 && w[2] == 0x02)
                .nth(1)
                .map(|(at, _)| at)
                .unwrap();
            broken[sig + 10] ^= 0x55;
            let broken = Transaction::from_binary(&broken).unwrap();
            out.extend(link(format!("p2pkh x{inputs} broken"), &broken, &parents));
        }
    }
    out
}

/// What `Transaction::verify` must answer given the door's answer for each
/// input of the subject, in input order.
fn expected_verify(doors: &[Result<InputVerified, InputRefusal>]) -> Option<(usize, String)> {
    doors.iter().enumerate().find_map(|(vin, door)| match door {
        Ok(_) => None,
        Err(refusal) => Some((vin, refusal.to_string())),
    })
}

fn verify_words(case: &Linked, chain: Option<&ChainParams>) -> Result<bool, Error> {
    match chain {
        Some(chain) => futures::executor::block_on(case.tx.verify_with_chain_params(
            &case.tracker,
            None,
            None,
            chain,
        )),
        None => futures::executor::block_on(case.tx.verify(&case.tracker, None, None)),
    }
}

fn compare_verify(case: &Linked, chain: Option<&ChainParams>) -> Result<usize, String> {
    let prepared = SpendingTransaction::from_bytes(&case.tx.to_binary()).unwrap();
    let mut doors = Vec::new();
    for (vin, input) in case.tx.inputs().iter().enumerate() {
        let parent = input.source_transaction.as_ref().unwrap();
        let output = &parent.outputs()[input.source_output_index as usize];
        let rules = match chain {
            Some(chain) => {
                let source = parent.merkle_path.as_ref().map(|p| p.block_height);
                let word = chain
                    .word_for_input(Word::Standard, Some(TIP + 1), source)
                    .unwrap();
                InputRules::under(word).unwrap()
            }
            None => InputRules::reference_default(),
        };
        doors.push(prepared.verify_input(
            vin,
            &output.locking_script.to_binary(),
            output.satoshis.unwrap_or(0),
            &rules,
        ));
    }
    let verified = verify_words(case, chain);
    let agree = match (expected_verify(&doors), &verified) {
        (None, Ok(_)) => true,
        (Some((vin, words)), Err(Error::TransactionError(text))) => {
            *text == format!("Script validation failed for input {vin}: {words}")
        }
        _ => false,
    };
    if agree {
        Ok(doors.len())
    } else {
        Err(format!(
            "{}: verify {verified:?}, doors {doors:?}",
            case.name
        ))
    }
}

#[test]
fn the_door_equals_transaction_verify_on_every_input_whose_source_the_vectors_carry_855() {
    let cases: Vec<Linked> = vector_transactions()
        .into_iter()
        .chain(signed_spends())
        .collect();
    let chain = ChainParams::mainnet();
    let (mut inputs, mut differences) = (0, Vec::new());
    for case in &cases {
        for chain in [None, Some(&chain)] {
            match compare_verify(case, chain) {
                Ok(n) => inputs += n,
                Err(why) => differences.push(why),
            }
        }
    }
    eprintln!(
        "transactions: {}, inputs judged by the door and by verify: {inputs}",
        cases.len()
    );
    assert!(cases.len() >= 10, "too few transactions: {}", cases.len());
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

// ============================================================================
// from_bytes agrees with Transaction::from_binary
// ============================================================================

fn vector_transaction_bytes() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vector_transactions()
        .iter()
        .map(|case| case.tx.to_binary())
        .chain(signed_spends().iter().map(|case| case.tx.to_binary()))
        .collect();
    let text = fs::read_to_string("tests/vectors/sighash.json").unwrap();
    let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
    out.extend(
        vectors
            .iter()
            .filter_map(|v| hex(v["raw_tx"].as_str().unwrap_or_default())),
    );
    out
}

/// `bytes` with every output amount of 2^53 or more replaced by 0: what
/// `from_binary` reads when the amount was its only refusal.
fn amounts_made_safe(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let Ok(offsets) = Transaction::parse_script_offsets(bytes) else {
        return out;
    };
    for script in offsets.outputs {
        let varint = match script.length {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        };
        let at = script.offset - varint - 8;
        let amount = u64::from_le_bytes(out[at..at + 8].try_into().unwrap());
        if amount >= 1 << 53 {
            out[at..at + 8].copy_from_slice(&[0; 8]);
        }
    }
    out
}

fn agrees(bytes: &[u8]) -> bool {
    match (
        Transaction::from_binary(bytes),
        SpendingTransaction::from_bytes(bytes),
    ) {
        (Ok(tx), Ok(prepared)) => tx.inputs().len() == prepared.input_count(),
        (Err(a), Err(b)) => a == b,
        // Read by the door alone (#874): `from_binary`'s only refusal the
        // amount, which the default mode answers in its error at any index.
        (Err(a), Ok(prepared)) => {
            a == Error::TransactionError("Number can only safely store up to 53 bits".into())
                && Transaction::from_binary(&amounts_made_safe(bytes)).is_ok()
                && [0, prepared.input_count()].iter().all(|&index| {
                    prepared.verify_input(index, &[0x51], 1, &InputRules::default())
                        == Err(InputRefusal::Transaction(a.clone()))
                })
        }
        (Ok(_), Err(_)) => false,
    }
}

#[test]
fn from_bytes_reads_exactly_what_from_binary_reads_855() {
    let transactions = vector_transaction_bytes();
    let mut checked = 0;
    let mut disagreements = Vec::new();
    for (n, bytes) in transactions.iter().enumerate() {
        let mut inputs: Vec<Vec<u8>> = vec![bytes.clone(), vec![]];
        let mutate = n < 64 || bytes.len() <= 512;
        if mutate {
            for at in 0..bytes.len() {
                let mut changed = bytes.clone();
                changed[at] ^= 0x01;
                inputs.push(changed);
                let mut changed = bytes.clone();
                changed[at] = 0xff;
                inputs.push(changed);
                inputs.push(bytes[..at].to_vec());
            }
            for extra in [0x00u8, 0xff] {
                let mut extended = bytes.clone();
                extended.push(extra);
                inputs.push(extended);
            }
        }
        for input in inputs {
            checked += 1;
            if !agrees(&input) {
                disagreements.push(bsv_rs::primitives::to_hex(&input));
            }
        }
    }
    eprintln!(
        "transactions: {}, inputs read by both: {checked}",
        transactions.len()
    );
    assert!(disagreements.is_empty(), "{disagreements:?}");
}

// ============================================================================
// (d) Refusals before evaluation
// ============================================================================

const ALWAYS: &[u8] = &[0x51]; // OP_1

#[test]
fn an_index_at_or_past_the_inputs_is_refused_before_evaluation_855() {
    let bytes = one_input_transaction(&[0x51], 2);
    let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
    assert_eq!(prepared.input_count(), 1);
    for index in [1usize, 2, usize::MAX] {
        let refusal = prepared
            .verify_input(index, ALWAYS, 1, &InputRules::default())
            .unwrap_err();
        assert_eq!(refusal, InputRefusal::InputIndex { index, inputs: 1 });
        assert_eq!(
            refusal.to_string(),
            format!("input index {index} out of range (transaction has 1 inputs)")
        );
        assert!(refusal.evaluation().is_none());
        assert_eq!(
            verify_input(ALWAYS, 1, &bytes, index, &InputRules::default()),
            Err(refusal)
        );
    }
}

#[test]
fn bytes_that_are_not_exactly_one_transaction_are_refused_in_the_readers_words_855() {
    let bytes = one_input_transaction(&[0x51], 2);
    let mut trailing = bytes.clone();
    trailing.push(0);
    for input in [trailing, bytes[..bytes.len() - 1].to_vec(), vec![]] {
        let reader = Transaction::from_binary(&input).unwrap_err();
        assert_eq!(SpendingTransaction::from_bytes(&input).unwrap_err(), reader);
        // An index past the inputs as well: the bytes are refused first.
        let once = verify_input(ALWAYS, 1, &input, 5, &InputRules::default()).unwrap_err();
        assert_eq!(once, InputRefusal::Transaction(reader.clone()));
        assert_eq!(once.to_string(), reader.to_string());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        SpendingTransaction::from_bytes(&trailing)
            .unwrap_err()
            .to_string(),
        "transaction error: Serialized transaction contains trailing data"
    );
}

#[test]
fn an_unknown_bit_and_a_word_the_interpreter_cannot_honor_are_refused_when_the_rules_are_built_855()
{
    assert_eq!(
        ScriptFlags::from_bits(1 << 31).unwrap_err(),
        ScriptFlagsError::UnknownBits(1 << 31)
    );
    let block = ScriptFlags::block(ProtocolEra::PostChronicle);
    for missing in [
        ScriptFlags::SIGHASH_FORKID,
        ScriptFlags::GENESIS,
        ScriptFlags::UTXO_AFTER_GENESIS,
    ] {
        let word = block.without(missing);
        let refused = InputRules::under(word).unwrap_err();
        assert_eq!(refused, word.check().unwrap_err());
        assert!(matches!(refused, ScriptFlagsError::NotApplicable(_)));
    }
    assert!(InputRules::under(ScriptFlags::from_bits(0).unwrap()).is_err());
    let rules = InputRules::under(block).unwrap();
    assert_eq!(rules.word(), Some(block));
    assert_eq!(rules.default_mode(), None);
}

// ============================================================================
// (e) A decline is Declined, never Invalid
// ============================================================================

#[test]
fn a_memory_and_a_work_decline_are_declined_and_a_larger_budget_judges_855() {
    // 200 bytes pushed, dropped, then OP_1: valid in every mode.
    let mut unlock = vec![0x4c, 200];
    unlock.extend([0xab; 200]);
    let lock = [0x75, 0x61, 0x61, 0x61, 0x61, 0x51]; // OP_DROP OP_NOP x4 OP_1
    let bytes = one_input_transaction(&unlock, 2);
    let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
    for word in modes() {
        let base = rules(word, UNBOUNDED);
        let memory = prepared
            .verify_input(0, &lock, 1, &base.with_memory_limit(100))
            .unwrap_err();
        assert!(matches!(memory, InputRefusal::Declined(_)), "{memory:?}");
        assert!(matches!(
            memory.resource_limit().unwrap().resource,
            ScriptResource::Stack
        ));
        let work = prepared
            .verify_input(0, &lock, 1, &base.with_work_limit(3))
            .unwrap_err();
        assert!(matches!(work, InputRefusal::Declined(_)), "{work:?}");
        assert_eq!(
            work.resource_limit().unwrap().resource,
            ScriptResource::Work
        );
        assert_eq!(work.to_string(), work.evaluation().unwrap().message);
        let judged = prepared
            .verify_input(
                0,
                &lock,
                1,
                &base.with_memory_limit(1 << 20).with_work_limit(1_000),
            )
            .unwrap();
        assert_eq!(judged.work_spent, 7);
    }
}

// ============================================================================
// (f) The default mode's overrides
// ============================================================================

fn judged(unlock: &[u8], lock: &[u8], version: u32, rules: &InputRules) -> Result<u64, String> {
    verify_input(lock, 1, &one_input_transaction(unlock, version), 0, rules)
        .map(|v| v.work_spent)
        .map_err(|e| match e {
            InputRefusal::Invalid(e) => e.message,
            other => panic!("not a verdict: {other:?}"),
        })
}

const PUSH_ONLY: &str = "Unlocking scripts can only contain push operations, and no other opcodes.";

#[test]
fn the_push_only_override_holds_at_every_version_855() {
    let (unlock, lock) = ([0x51, 0x75, 0x51], [0x61]); // OP_1 OP_DROP OP_1 | OP_NOP
    let default = InputRules::reference_default();
    let on = InputRules::reference_default_with(DefaultMode::new().with_require_push_only(true));
    let off = InputRules::reference_default_with(DefaultMode::new().with_require_push_only(false));
    assert_eq!(
        judged(&unlock, &lock, 1, &default),
        Err(PUSH_ONLY.to_string())
    );
    assert!(judged(&unlock, &lock, 2, &default).is_ok());
    assert_eq!(judged(&unlock, &lock, 2, &on), Err(PUSH_ONLY.to_string()));
    assert!(judged(&unlock, &lock, 1, &off).is_ok());
}

#[test]
fn the_minimal_override_holds_at_every_version_855() {
    let (unlock, lock) = ([0x01, 0x05], [0x55, 0x87]); // <05> | OP_5 OP_EQUAL
    let default = InputRules::reference_default();
    let on = InputRules::reference_default_with(DefaultMode::new().with_require_minimal(true));
    let off = InputRules::reference_default_with(DefaultMode::new().with_require_minimal(false));
    let v1 = judged(&unlock, &lock, 1, &default).unwrap_err();
    assert!(judged(&unlock, &lock, 2, &default).is_ok());
    assert_eq!(judged(&unlock, &lock, 2, &on).unwrap_err(), v1);
    assert!(judged(&unlock, &lock, 1, &off).is_ok());
}

#[test]
fn the_chronicle_opcodes_override_disables_them_855() {
    let (unlock, lock) = ([0x52], [0x8d, 0x54, 0x87]); // OP_2 | OP_2MUL OP_4 OP_EQUAL
    let default = InputRules::reference_default();
    let before =
        InputRules::reference_default_with(DefaultMode::new().with_utxo_after_chronicle(false));
    assert!(judged(&unlock, &lock, 1, &default).is_ok());
    assert!(judged(&unlock, &lock, 1, &before).is_err());
}

// ============================================================================
// (g) A word takes no override; (h) the setters commute
// ============================================================================

#[test]
fn a_word_carries_no_default_mode_and_the_default_mode_no_word_855() {
    let block = ScriptFlags::block(ProtocolEra::PostChronicle);
    let word = InputRules::under(block).unwrap();
    assert_eq!((word.word(), word.default_mode()), (Some(block), None));
    let mode = DefaultMode::new().with_require_push_only(true);
    let default = InputRules::reference_default_with(mode);
    assert_eq!((default.word(), default.default_mode()), (None, Some(mode)));
    assert_eq!(InputRules::default(), InputRules::reference_default());
    assert_eq!(
        InputRules::reference_default().default_mode(),
        Some(DefaultMode::new())
    );
    // The overrides are on `DefaultMode` alone, and only
    // `reference_default_with` takes one: the `compile_fail` doc test on
    // `DefaultMode` pins that `under(word)?.with_require_push_only(..)` does
    // not compile.
}

#[test]
fn the_setters_commute_855() {
    type Setter = fn(DefaultMode) -> DefaultMode;
    let setters: [Setter; 3] = [
        |m| m.with_require_push_only(true),
        |m| m.with_require_minimal(false),
        |m| m.with_utxo_after_chronicle(false),
    ];
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let built: Vec<DefaultMode> = orders
        .iter()
        .map(|order| order.iter().fold(DefaultMode::new(), |m, &i| setters[i](m)))
        .collect();
    assert!(built.windows(2).all(|w| w[0] == w[1]), "{built:?}");
    let mode = built[0];
    assert_eq!(
        (
            mode.require_push_only(),
            mode.require_minimal(),
            mode.utxo_after_chronicle()
        ),
        (Some(true), Some(false), Some(false))
    );
    for base in [
        InputRules::reference_default_with(mode),
        InputRules::under(ScriptFlags::standard(ProtocolEra::PostGenesis)).unwrap(),
    ] {
        let a = base.with_memory_limit(64).with_work_limit(9);
        let b = base.with_work_limit(9).with_memory_limit(64);
        assert_eq!(a, b);
        assert_eq!((a.memory_limit(), a.work_limit()), (Some(64), Some(9)));
        let bytes = one_input_transaction(&[0x51, 0x75, 0x51], 2);
        assert_eq!(
            verify_input(&[0x61], 1, &bytes, 0, &a),
            verify_input(&[0x61], 1, &bytes, 0, &b)
        );
    }
}

#[test]
fn a_prepared_transaction_is_shared_across_threads_855() {
    let bytes = one_input_transaction(&[0x51], 2);
    let prepared = std::sync::Arc::new(SpendingTransaction::from_bytes(&bytes).unwrap());
    let rules = InputRules::reference_default();
    let answers: Vec<_> = (0..4)
        .map(|_| {
            let prepared = prepared.clone();
            std::thread::spawn(move || prepared.verify_input(0, &[0x61], 1, &rules))
        })
        .map(|h| h.join().unwrap())
        .collect();
    let alone = prepared.verify_input(0, &[0x61], 1, &rules).unwrap();
    assert!(
        answers.iter().all(|a| a.as_ref() == Ok(&alone)),
        "{answers:?}"
    );
    assert!(format!("{prepared:?}").contains("inputs: 1"));
}
