//! The fold of the one-input door (#855, the three reads of PR #857):
//! (1) `InputVerified::work_spent` is always the work spent, with or without
//! a work limit (the rule read's FIX): a valid input reports at least 1, the
//! count with no limit equals the count under `u64::MAX` on every vector
//! spend and on signed P2PKH spends, a decline carries its count; (2) the
//! node's own figures (`NodeFigures`, taken only by `InputRules::under_with`)
//! judge as a hand-built `Spend` with the same setters does, on every vector
//! spend and on a script crossing each bound, a verdict past the figure, a
//! decline below it, the consensus figure 0 judging a stack past
//! 100,000,000 bytes under an unbounded local budget (the strength read's
//! row); (3) `InputRefusal`'s hand-written equality tells refusals apart by
//! the index, the input count, the message, the resource fields, the arm and
//! the reader's error (the strength read's second row).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code: a failed unwrap is the test failing.

use std::fs;

use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{
    ExecutionContext, LockingScript, ProtocolEra, ScriptEvaluationError, ScriptFlags,
    ScriptResource, ScriptResourceLimit, SignOutputs, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::transaction::{
    verify_input, InputRefusal, InputRules, InputVerified, NodeFigures, SpendingTransaction,
    Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::Value;

fn one_input_transaction(unlocking: &[u8], version: u32) -> Vec<u8> {
    let mut input = TransactionInput::new("00".repeat(32).parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_binary(unlocking).unwrap());
    Transaction::with_params(version, vec![input], vec![], 0).to_binary()
}

fn hex(text: &str) -> Option<Vec<u8>> {
    bsv_rs::primitives::from_hex(text).ok()
}

/// Every (unlocking, locking) pair of the three script vector files.
fn spend_cases() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut cases = Vec::new();
    for file in [
        "spend_valid.json",
        "script_valid.json",
        "script_invalid.json",
    ] {
        let text = fs::read_to_string(format!("tests/vectors/{file}")).unwrap();
        let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
        for (index, vector) in vectors.iter().enumerate() {
            if let (Some(unlock), Some(lock)) = (
                hex(vector["scriptSig"].as_str().unwrap_or_default()),
                hex(vector["scriptPubKey"].as_str().unwrap_or_default()),
            ) {
                cases.push((format!("{file} #{index}"), unlock, lock));
            }
        }
    }
    cases
}

fn modes() -> Vec<Option<ScriptFlags>> {
    let mut modes = vec![None];
    for era in [ProtocolEra::PostGenesis, ProtocolEra::PostChronicle] {
        modes.push(Some(ScriptFlags::block(era)));
        modes.push(Some(ScriptFlags::standard(era)));
    }
    modes
}

// ============================================================================
// (1) work_spent is always the work spent
// ============================================================================

#[test]
fn a_valid_input_reports_its_work_with_no_limit_set_855() {
    // OP_1 then OP_NOP: two opcodes reached.
    let bytes = one_input_transaction(&[0x51], 2);
    for word in modes() {
        let rules = match word {
            Some(word) => InputRules::under(word).unwrap(),
            None => InputRules::reference_default(),
        };
        assert_eq!(rules.work_limit(), None);
        let verified = verify_input(&[0x61], 1, &bytes, 0, &rules).unwrap();
        assert_eq!(verified.work_spent, 2, "{word:?}");
    }
}

#[test]
fn the_count_with_no_limit_equals_the_count_under_u64_max_on_every_vector_spend_855() {
    let mut valid = 0;
    let mut differences = Vec::new();
    for (name, unlock, lock) in spend_cases() {
        for version in [1u32, 2] {
            let prepared =
                SpendingTransaction::from_bytes(&one_input_transaction(&unlock, version)).unwrap();
            for word in modes() {
                let plain = match word {
                    Some(word) => InputRules::under(word).unwrap(),
                    None => InputRules::reference_default(),
                };
                let open = prepared.verify_input(0, &lock, 1, &plain);
                let bounded = prepared.verify_input(0, &lock, 1, &plain.with_work_limit(u64::MAX));
                if open != bounded {
                    differences.push(format!(
                        "{name} v{version} {word:?}: {open:?} / {bounded:?}"
                    ));
                }
                if let Ok(verified) = open {
                    valid += 1;
                    if verified.work_spent == 0 {
                        differences.push(format!("{name} v{version} {word:?}: valid, no work"));
                    }
                }
            }
        }
    }
    assert!(valid > 1_000, "too few valid spends: {valid}");
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

/// A two-input P2PKH spend this crate's writer signs: the bytes, the lock.
fn signed_p2pkh() -> (Vec<u8>, Vec<u8>) {
    let key = PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let lock = P2PKH::lock_from_address(&key.public_key().to_address()).unwrap();
    let mut coin = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32).parse().unwrap(), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    coin.add_input(mined).unwrap();
    for _ in 0..2 {
        coin.add_output(TransactionOutput::new(5_000, lock.clone()))
            .unwrap();
    }
    let mut spend = Transaction::new();
    for vout in 0..2 {
        let mut input = TransactionInput::with_source_transaction(coin.clone(), vout);
        input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
        spend.add_input(input).unwrap();
    }
    spend
        .add_output(TransactionOutput::new(9_900, lock.clone()))
        .unwrap();
    futures::executor::block_on(spend.sign()).unwrap();
    (spend.to_binary(), lock.to_binary())
}

#[test]
fn a_signature_checks_hashed_bytes_are_counted_without_a_limit_855() {
    let (bytes, lock) = signed_p2pkh();
    for word in modes() {
        let plain = match word {
            Some(word) => InputRules::under(word).unwrap(),
            None => InputRules::reference_default(),
        };
        for index in 0..2 {
            // A fresh preparation each: the midstates are hashed once per
            // prepared transaction, charged to the input whose check
            // computes them.
            let fresh = || SpendingTransaction::from_bytes(&bytes).unwrap();
            let open = fresh().verify_input(index, &lock, 5_000, &plain).unwrap();
            let bounded = fresh()
                .verify_input(index, &lock, 5_000, &plain.with_work_limit(u64::MAX))
                .unwrap();
            assert_eq!(open, bounded, "{word:?} input {index}");
            // Seven opcodes, the HASH160's operand and the sighash preimage:
            // well past the opcodes alone.
            assert!(open.work_spent > 100, "{word:?}: {}", open.work_spent);
        }
        // On one preparation the second input reuses the midstates the first
        // computed: it is charged less than it is alone.
        let shared = SpendingTransaction::from_bytes(&bytes).unwrap();
        let first = shared.verify_input(0, &lock, 5_000, &plain).unwrap();
        let second = shared.verify_input(1, &lock, 5_000, &plain).unwrap();
        let alone = SpendingTransaction::from_bytes(&bytes)
            .unwrap()
            .verify_input(1, &lock, 5_000, &plain)
            .unwrap();
        assert!(first.work_spent > second.work_spent, "{word:?}");
        assert!(alone.work_spent > second.work_spent, "{word:?}");
    }
}

#[test]
fn a_work_decline_carries_its_count_855() {
    let mut unlock = vec![0x4c, 200];
    unlock.extend([0xab; 200]);
    let lock = [0x75, 0x61, 0x61, 0x61, 0x61, 0x51];
    let bytes = one_input_transaction(&unlock, 2);
    let refusal = verify_input(
        &lock,
        1,
        &bytes,
        0,
        &InputRules::reference_default().with_work_limit(3),
    )
    .unwrap_err();
    let limit = refusal.resource_limit().unwrap();
    assert_eq!(limit.resource, ScriptResource::Work);
    assert_eq!(
        (limit.limit, limit.attempted, limit.work_spent),
        (3, 4, Some(3))
    );
    let full = verify_input(&lock, 1, &bytes, 0, &InputRules::reference_default()).unwrap();
    assert_eq!(full.work_spent, 7);
}

// ============================================================================
// (2) The node's figures through the door
// ============================================================================

#[allow(clippy::result_large_err)] // `Spend::validate`'s own answer, returned as it is.
fn by_hand(
    lock: &[u8],
    unlock: &[u8],
    version: u32,
    word: ScriptFlags,
    figures: NodeFigures,
    memory_limit: Option<usize>,
) -> Result<bool, ScriptEvaluationError> {
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
        memory_limit,
        work_limit: None,
    });
    spend.set_flags(word);
    spend.set_stack_memory_policy(figures.stack_memory_policy());
    spend.set_stack_memory_consensus(figures.stack_memory_consensus());
    spend.set_script_num_length_policy(figures.script_num_length_policy());
    spend.validate()
}

/// `None` when the door answers the hand-built verdict; the work is not
/// compared (the hand-built spend counts none without a budget).
fn differs(
    hand: &Result<bool, ScriptEvaluationError>,
    door: &Result<InputVerified, InputRefusal>,
) -> Option<String> {
    let agree = match (hand, door) {
        (Ok(true), Ok(_)) => true,
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

fn figure_sets() -> Vec<NodeFigures> {
    vec![
        NodeFigures::new(),
        NodeFigures::new()
            .with_stack_memory_policy(100)
            .with_stack_memory_consensus(90)
            .with_script_num_length_policy(2),
        NodeFigures::new()
            .with_stack_memory_policy(0)
            .with_stack_memory_consensus(0)
            .with_script_num_length_policy(0),
    ]
}

#[test]
fn the_figures_through_the_door_equal_a_spend_built_by_hand_on_every_vector_spend_855() {
    let mut runs = 0;
    let mut differences = Vec::new();
    for (name, unlock, lock) in spend_cases() {
        for version in [1u32, 2] {
            let prepared =
                SpendingTransaction::from_bytes(&one_input_transaction(&unlock, version)).unwrap();
            for word in modes().into_iter().flatten() {
                for figures in figure_sets() {
                    let rules = InputRules::under_with(word, figures).unwrap();
                    let hand = by_hand(&lock, &unlock, version, word, figures, None);
                    let door = prepared.verify_input(0, &lock, 1, &rules);
                    runs += 1;
                    if let Some(why) = differs(&hand, &door) {
                        differences.push(format!("{name} v{version} {word:?} {figures:?}: {why}"));
                    }
                }
            }
        }
    }
    assert_eq!(runs, 35_712, "the vectors moved: {runs} runs");
    assert!(
        differences.is_empty(),
        "{} of {runs} differ:\n{}",
        differences.len(),
        differences[..differences.len().min(20)].join("\n")
    );
}

/// One case: the door and the hand-built spend under the same word, figures
/// and local budget, the door's answer returned.
fn judge(
    unlock: &[u8],
    lock: &[u8],
    word: ScriptFlags,
    figures: NodeFigures,
    memory_limit: Option<usize>,
) -> Result<InputVerified, InputRefusal> {
    let mut rules = InputRules::under_with(word, figures).unwrap();
    if let Some(bytes) = memory_limit {
        rules = rules.with_memory_limit(bytes);
    }
    let door = verify_input(lock, 1, &one_input_transaction(unlock, 2), 0, &rules);
    let hand = by_hand(lock, unlock, 2, word, figures, memory_limit);
    assert_eq!(differs(&hand, &door), None);
    door
}

fn verdict(answer: &Result<InputVerified, InputRefusal>) -> &str {
    match answer {
        Err(InputRefusal::Invalid(error)) => &error.message,
        other => panic!("expected a verdict, got {other:?}"),
    }
}

fn declined(answer: &Result<InputVerified, InputRefusal>) -> bool {
    matches!(answer, Err(InputRefusal::Declined(_)))
}

/// 600 bytes pushed, dropped, then OP_1: the node's count 632 bytes.
fn six_hundred() -> (Vec<u8>, Vec<u8>) {
    let mut unlock = vec![0x4d, 0x58, 0x02];
    unlock.extend([0xab; 600]);
    (unlock, vec![0x75, 0x51])
}

#[test]
fn the_stack_memory_policy_is_a_verdict_past_it_and_the_local_budget_declines_below_it_855() {
    let (unlock, lock) = six_hundred();
    let word = ScriptFlags::standard(ProtocolEra::PostChronicle);
    let policy = |bytes| NodeFigures::new().with_stack_memory_policy(bytes);
    assert_eq!(
        verdict(&judge(&unlock, &lock, word, policy(500), Some(2_000))),
        "Stack size limit exceeded: 632 bytes, the stack memory policy is 500 bytes."
    );
    assert!(declined(&judge(
        &unlock,
        &lock,
        word,
        policy(1_000),
        Some(400)
    )));
    assert!(judge(&unlock, &lock, word, policy(1_000), Some(2_000)).is_ok());
    // 0 selects no policy verdict: the local budget alone.
    assert!(declined(&judge(&unlock, &lock, word, policy(0), Some(400))));
    assert!(judge(&unlock, &lock, word, policy(0), None).is_ok());
    // `under` is the node's default policy, 100,000,000 bytes.
    assert_eq!(
        InputRules::under(word).unwrap(),
        InputRules::under_with(word, NodeFigures::new()).unwrap()
    );
    // A block word ignores the policy.
    let block = ScriptFlags::block(ProtocolEra::PostChronicle);
    assert!(judge(&unlock, &lock, block, policy(500), None).is_ok());
}

#[test]
fn the_consensus_figure_is_a_verdict_past_it_and_the_local_budget_declines_below_it_855() {
    let (unlock, lock) = six_hundred();
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let consensus = |bytes| NodeFigures::new().with_stack_memory_consensus(bytes);
    assert_eq!(
        verdict(&judge(&unlock, &lock, word, consensus(500), Some(2_000))),
        "Stack size limit exceeded: 632 bytes, the stack memory consensus limit is 500 bytes."
    );
    assert!(declined(&judge(
        &unlock,
        &lock,
        word,
        consensus(1_000),
        Some(400)
    )));
    assert!(judge(&unlock, &lock, word, consensus(1_000), Some(2_000)).is_ok());
    // The mempool word ignores the consensus figure.
    let standard = ScriptFlags::standard(ProtocolEra::PostChronicle);
    assert!(judge(&unlock, &lock, standard, consensus(500), None).is_ok());
}

#[test]
fn a_stack_past_100_000_000_bytes_is_judged_by_a_node_run_with_a_consensus_figure_of_0_855() {
    // OP_1 <100,000,001> in the unlocking script; OP_NUM2BIN OP_DROP OP_1:
    // an element of 100,000,001 bytes, the node's count 100,000,033.
    let unlock = [0x51, 0x04, 0x01, 0xe1, 0xf5, 0x05];
    let lock = [0x80, 0x75, 0x51];
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    // The node's defaults: the local budget of 100,000,000 bytes declines.
    let defaults = judge(&unlock, &lock, word, NodeFigures::new(), None);
    assert!(declined(&defaults), "{defaults:?}");
    // A node run with 0 judges it: valid.
    let zero = NodeFigures::new().with_stack_memory_consensus(0);
    assert!(judge(&unlock, &lock, word, zero, Some(usize::MAX)).is_ok());
    // A node run with 150,000,000 judges it valid; with 50,000,000 invalid.
    let above = NodeFigures::new().with_stack_memory_consensus(150_000_000);
    assert!(judge(&unlock, &lock, word, above, Some(usize::MAX)).is_ok());
    let below = NodeFigures::new().with_stack_memory_consensus(50_000_000);
    assert_eq!(
        verdict(&judge(&unlock, &lock, word, below, Some(usize::MAX))),
        "Stack size limit exceeded: 100000033 bytes, the stack memory consensus limit is 50000000 bytes."
    );
}

#[test]
fn the_script_number_length_policy_bounds_an_operand_on_the_mempool_path_855() {
    // A 5-byte number, OP_1ADD, OP_DROP, OP_1.
    let unlock = [0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    let lock = [0x8b, 0x75, 0x51];
    let word = ScriptFlags::standard(ProtocolEra::PostChronicle);
    let length = |bytes| NodeFigures::new().with_script_num_length_policy(bytes);
    let refused = judge(&unlock, &lock, word, length(4), None);
    assert!(verdict(&refused).contains("overflow"), "{refused:?}");
    assert!(judge(&unlock, &lock, word, length(5), None).is_ok());
    assert!(judge(&unlock, &lock, word, length(0), None).is_ok());
    assert!(judge(&unlock, &lock, word, NodeFigures::new(), None).is_ok());
    // A block word ignores it.
    let block = ScriptFlags::block(ProtocolEra::PostChronicle);
    assert!(judge(&unlock, &lock, block, length(4), None).is_ok());
}

#[test]
fn the_figures_setters_commute_and_a_word_carries_them_855() {
    type Setter = fn(NodeFigures) -> NodeFigures;
    let setters: [Setter; 3] = [
        |f| f.with_stack_memory_policy(1),
        |f| f.with_stack_memory_consensus(2),
        |f| f.with_script_num_length_policy(3),
    ];
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let built: Vec<NodeFigures> = orders
        .iter()
        .map(|order| order.iter().fold(NodeFigures::new(), |f, &i| setters[i](f)))
        .collect();
    assert!(built.windows(2).all(|w| w[0] == w[1]), "{built:?}");
    let figures = built[0];
    assert_eq!(
        (
            figures.stack_memory_policy(),
            figures.stack_memory_consensus(),
            figures.script_num_length_policy()
        ),
        (1, 2, 3)
    );
    assert_eq!(NodeFigures::default(), NodeFigures::new());
    assert_eq!(
        (
            NodeFigures::new().stack_memory_policy(),
            NodeFigures::new().stack_memory_consensus(),
            NodeFigures::new().script_num_length_policy()
        ),
        (100_000_000, 0, 10_000)
    );
    let word = ScriptFlags::block(ProtocolEra::PostGenesis);
    let rules = InputRules::under_with(word, figures).unwrap();
    assert_eq!(
        (rules.word(), rules.node_figures()),
        (Some(word), Some(figures))
    );
    assert_eq!(rules.default_mode(), None);
    assert_eq!(InputRules::reference_default().node_figures(), None);
    assert_ne!(rules, InputRules::under(word).unwrap());
    // A word the interpreter cannot honor is refused whatever the figures.
    assert_eq!(
        InputRules::under_with(ScriptFlags::from_bits(0).unwrap(), figures).unwrap_err(),
        ScriptFlags::from_bits(0).unwrap().check().unwrap_err()
    );
}

// ============================================================================
// (3) InputRefusal's equality tells refusals apart
// ============================================================================

fn evaluation(message: &str, limit: Option<ScriptResourceLimit>) -> Box<ScriptEvaluationError> {
    let error = ScriptEvaluationError::new(
        message,
        String::new(),
        0,
        ExecutionContext::LockingScript,
        3,
        vec![vec![1]],
        Vec::new(),
        Vec::new(),
        1,
        0,
    );
    Box::new(match limit {
        Some(limit) => error.with_resource_limit(limit),
        None => error,
    })
}

const WORK: ScriptResourceLimit = ScriptResourceLimit {
    resource: ScriptResource::Work,
    limit: 3,
    attempted: 4,
    work_spent: Some(3),
};

#[test]
fn refusals_that_differ_compare_unequal_855() {
    let index = |index, inputs| InputRefusal::InputIndex { index, inputs };
    assert_eq!(index(2, 1), index(2, 1));
    assert_ne!(index(2, 1), index(3, 1), "the index");
    assert_ne!(index(2, 1), index(2, 2), "the input count");

    let invalid = |message| InputRefusal::Invalid(evaluation(message, None));
    assert_eq!(invalid("a"), invalid("a"));
    assert_ne!(invalid("a"), invalid("b"), "the message");

    let declined = |limit| InputRefusal::Declined(evaluation("w", Some(limit)));
    assert_eq!(declined(WORK), declined(WORK));
    assert_ne!(
        declined(WORK),
        declined(ScriptResourceLimit { limit: 4, ..WORK })
    );
    assert_ne!(
        declined(WORK),
        declined(ScriptResourceLimit {
            attempted: 5,
            ..WORK
        })
    );
    assert_ne!(
        declined(WORK),
        declined(ScriptResourceLimit {
            work_spent: Some(2),
            ..WORK
        })
    );
    assert_ne!(
        declined(WORK),
        declined(ScriptResourceLimit {
            resource: ScriptResource::Stack,
            ..WORK
        })
    );

    // One error, two arms.
    let same = evaluation("w", Some(WORK));
    assert_ne!(
        InputRefusal::Invalid(same.clone()),
        InputRefusal::Declined(same),
        "the arm"
    );

    let reader = |text: &str| InputRefusal::Transaction(Error::TransactionError(text.into()));
    assert_eq!(reader("x"), reader("x"));
    assert_ne!(reader("x"), reader("y"), "the reader's error");
    assert_ne!(index(0, 0), invalid("a"));
    assert_ne!(reader("x"), index(0, 0));
}

// ============================================================================
// (3, the second fold) Every field the equality compares, pinned by a row
// ============================================================================
//
// `InputRefusal`'s `PartialEq` (`src/transaction/spending.rs`) compares the
// arm, the reader's error, the index and the input count, and through
// `same_evaluation`'s exhaustive destructure every field of
// `ScriptEvaluationError`; `resource_limit` by `ScriptResourceLimit`'s derived
// equality, whose four fields have rows of their own. One row per field: two
// refusals differing in that field alone compare unequal, and two built alike
// equal. The rows are checked against the destructure in the source (a field
// added there without a row fails `every_compared_field_has_a_row_855`), and
// `evaluation_fields` destructures `ScriptEvaluationError` exhaustively here,
// so a field added to the type fails this file's build until it has a row.

/// The base every evaluation row changes one field of: every field set to a
/// value no row's change produces.
fn base_evaluation() -> ScriptEvaluationError {
    ScriptEvaluationError::new(
        "w",
        "aa".repeat(32),
        1,
        ExecutionContext::LockingScript,
        3,
        vec![vec![1]],
        vec![vec![2]],
        vec![true],
        1,
        2,
    )
    .with_resource_limit(WORK)
}

type EvaluationChange = fn(&mut ScriptEvaluationError);

/// One change per field of `ScriptEvaluationError`, by its name. The
/// destructure names every field, so a field added to the type does not
/// compile here until a row for it is written.
fn evaluation_fields() -> Vec<(&'static str, EvaluationChange)> {
    let ScriptEvaluationError {
        message: _,
        source_txid: _,
        source_output_index: _,
        context: _,
        program_counter: _,
        stack: _,
        alt_stack: _,
        if_stack: _,
        stack_mem: _,
        alt_stack_mem: _,
        resource_limit: _,
    } = base_evaluation();
    vec![
        ("message", |e| e.message = "x".into()),
        ("source_txid", |e| e.source_txid = "bb".repeat(32)),
        ("source_output_index", |e| e.source_output_index = 2),
        ("context", |e| e.context = ExecutionContext::UnlockingScript),
        ("program_counter", |e| e.program_counter = 4),
        ("stack", |e| e.stack = vec![vec![9]]),
        ("alt_stack", |e| e.alt_stack = vec![vec![9]]),
        ("if_stack", |e| e.if_stack = vec![false]),
        ("stack_mem", |e| e.stack_mem = 9),
        ("alt_stack_mem", |e| e.alt_stack_mem = 9),
        ("resource_limit", |e| e.resource_limit = None),
    ]
}

/// The nested fields of `resource_limit`, compared by the derived equality.
fn resource_fields() -> Vec<(&'static str, EvaluationChange)> {
    let ScriptResourceLimit {
        resource: _,
        limit: _,
        attempted: _,
        work_spent: _,
    } = WORK;
    vec![
        ("resource_limit.resource", |e| {
            e.resource_limit = Some(ScriptResourceLimit {
                resource: ScriptResource::Stack,
                ..WORK
            })
        }),
        ("resource_limit.limit", |e| {
            e.resource_limit = Some(ScriptResourceLimit { limit: 4, ..WORK })
        }),
        ("resource_limit.attempted", |e| {
            e.resource_limit = Some(ScriptResourceLimit {
                attempted: 5,
                ..WORK
            })
        }),
        ("resource_limit.work_spent", |e| {
            e.resource_limit = Some(ScriptResourceLimit {
                work_spent: Some(2),
                ..WORK
            })
        }),
    ]
}

/// A row: its field's name, the base refusal and the refusal differing from
/// it in that field alone; each built twice so "built alike" is two values.
struct Row {
    field: &'static str,
    base: fn() -> InputRefusal,
    changed: Box<dyn Fn() -> InputRefusal>,
}

/// The refusal-level rows (the arm, the reader's error, the index and the
/// input count) and each evaluation row under both evaluation arms.
fn rows() -> Vec<Row> {
    fn invalid() -> InputRefusal {
        InputRefusal::Invalid(Box::new(base_evaluation()))
    }
    fn declined() -> InputRefusal {
        InputRefusal::Declined(Box::new(base_evaluation()))
    }
    fn reader() -> InputRefusal {
        InputRefusal::Transaction(Error::TransactionError("x".into()))
    }
    fn index() -> InputRefusal {
        InputRefusal::InputIndex {
            index: 2,
            inputs: 1,
        }
    }
    let mut rows = vec![
        Row {
            field: "arm",
            base: invalid,
            changed: Box::new(declined),
        },
        Row {
            field: "Transaction.0",
            base: reader,
            changed: Box::new(|| InputRefusal::Transaction(Error::TransactionError("y".into()))),
        },
        Row {
            field: "InputIndex.index",
            base: index,
            changed: Box::new(|| InputRefusal::InputIndex {
                index: 3,
                inputs: 1,
            }),
        },
        Row {
            field: "InputIndex.inputs",
            base: index,
            changed: Box::new(|| InputRefusal::InputIndex {
                index: 2,
                inputs: 2,
            }),
        },
    ];
    for (field, change) in evaluation_fields().into_iter().chain(resource_fields()) {
        for (base, arm) in [
            (
                invalid as fn() -> InputRefusal,
                InputRefusal::Invalid as fn(_) -> _,
            ),
            (declined, InputRefusal::Declined),
        ] {
            rows.push(Row {
                field,
                base,
                changed: Box::new(move || {
                    let mut error = base_evaluation();
                    change(&mut error);
                    arm(Box::new(error))
                }),
            });
        }
    }
    rows
}

/// The fields `same_evaluation`'s destructure names in the source, in order.
fn destructured_fields() -> Vec<String> {
    let source = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/transaction/spending.rs"
    ))
    .expect("the door's source");
    let start = source
        .find("fn same_evaluation(")
        .expect("same_evaluation in the source");
    let body = &source[start..];
    let open = body
        .find("let ScriptEvaluationError {")
        .expect("the destructure");
    let close = body[open..].find("} = a;").expect("the destructure's end") + open;
    body[open + "let ScriptEvaluationError {".len()..close]
        .split(',')
        .map(|field| field.trim().to_string())
        .filter(|field| !field.is_empty())
        .collect()
}

#[test]
fn every_compared_field_has_a_row_855() {
    let destructured = destructured_fields();
    let named: Vec<&str> = evaluation_fields().into_iter().map(|(f, _)| f).collect();
    assert_eq!(
        destructured, named,
        "same_evaluation's destructure and this file's evaluation rows"
    );
    // Each destructured field is compared in the source, `*f == b.f`.
    let source = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/transaction/spending.rs"
    ))
    .unwrap();
    for field in &destructured {
        assert!(
            source.contains(&format!("*{field} == b.{field}")),
            "same_evaluation compares {field}"
        );
    }
    // The table: four refusal-level rows, each evaluation field and each
    // nested resource field under both evaluation arms.
    assert_eq!(destructured.len(), 11);
    assert_eq!(rows().len(), 4 + 2 * (11 + 4));
}

#[test]
fn every_field_alone_tells_two_refusals_apart_855() {
    let mut red = Vec::new();
    for row in rows() {
        if (row.base)() != (row.base)() || (row.changed)() != (row.changed)() {
            red.push(format!("{}: two built alike compare unequal", row.field));
        }
        if (row.base)() == (row.changed)() || (row.changed)() == (row.base)() {
            red.push(format!(
                "{}: differing in it alone compare equal",
                row.field
            ));
        }
    }
    assert!(red.is_empty(), "fields the equality misses: {red:#?}");
}
