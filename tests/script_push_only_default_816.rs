//! #816: the default mode's push-only rule, the reference's default's.
//!
//! Without a flag word this crate requires a push-only unlocking script at a
//! version of 1 or below alone (`src/script/spend/mod.rs`, `Spend::new`'s
//! `require_push_only`, the check at the head of `Spend::validate`), as the
//! reference's default mode does (`ts-stack@edf6e03` `Spend.ts:319-321`,
//! `#isRelaxed()` is `transactionVersion > 1` on the number `readUInt32LE`
//! reads; `:365-369`, `#shouldEnforceSigPushOnly()` is `!this.#isRelaxed()`
//! without flags; the check at `:2059-2063`), and as the node does under
//! Chronicle at a non-malleable version (bitcoin-sv v1.2.2
//! `interpreter.cpp:2321-2334`: `(IsGenesis && !IsChronicle) || (IsChronicle
//! && !IsMalleableTxnVersion)`). Until the owner's word of 2026-11-09 23:5xZ
//! ("yeah relax it") this crate refused at every version; the stated lane's
//! divergent cells (`<sig> OP_DUP OP_DROP` and `OP_1 OP_DROP <sig>` at
//! version 2, refused by `Spend`, `Transaction::verify` and the streaming
//! reader) now agree with the recording.
//!
//! These tests pin both sides against
//! `vectors/script_push_only_default_816.json` (`support/script_push_only_default_816.mjs`,
//! Node v22.18.0): the 24-case grid and the default mode's version edges
//! (0 strict; 2^31 and 2^32 - 1 relaxed, the version read unsigned).
//!
//! The issue's comment of 2026-11-10 (two paths of the relaxed rule with no
//! test) is closed by the last three tests: the two-pass and asynchronous
//! stream readers on the same BEEFs, and an unproven ancestor that is not the
//! subject, judged through `judge_input` at
//! `src/transaction/beef_stream/spends.rs` by the three stream doors and by
//! `Transaction::verify`. They pin landed behaviour: their RED is the tip
//! with `&& !relaxed_by_default(transaction_version)` removed from
//! `Spend::new` (`docs/lanes/fix-816.md`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::transaction::beef_stream::{
    verify_stream, verify_stream_async, verify_stream_two_pass, AsyncByteSource, SpendRefusal,
    Verdict,
};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde::Deserialize;

/// This crate's words for the refusal: the reference's sentence.
const REFUSAL: &str = "Unlocking scripts can only contain push operations, and no other opcodes.";

#[derive(Deserialize)]
struct Recording {
    reference: String,
    node: String,
    cases: Vec<Case>,
    version_edges: Vec<Case>,
}

#[derive(Clone, Deserialize)]
struct Case {
    mode: String,
    /// The reference's number: the four bytes read unsigned.
    version: u32,
    unlock_name: String,
    unlock: String,
    lock: String,
    push_only: bool,
    valid: Option<bool>,
    error: Option<String>,
}

impl Case {
    /// The reference's verdict: `Ok(true)` or its error words, the
    /// `Script evaluation error: ` prefix removed.
    fn reference(&self) -> Result<bool, String> {
        match (&self.valid, &self.error) {
            (Some(v), None) => Ok(*v),
            (None, Some(e)) => Err(e
                .strip_prefix("Script evaluation error: ")
                .unwrap()
                .to_string()),
            _ => panic!("a case with no answer"),
        }
    }
}

fn recording() -> Recording {
    let r: Recording =
        serde_json::from_str(include_str!("vectors/script_push_only_default_816.json")).unwrap();
    assert_eq!(
        r.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(r.node, "v22.18.0");
    assert_eq!(r.cases.len(), 24);
    assert_eq!(r.version_edges.len(), 9);
    r
}

fn cases(mode: &str) -> Vec<Case> {
    let c: Vec<_> = recording()
        .cases
        .into_iter()
        .filter(|c| c.mode == mode)
        .collect();
    assert_eq!(c.len(), 6, "{mode}");
    c
}

/// Every default-mode cell: the grid's versions 1 and 2 and the edges.
fn default_cells() -> Vec<Case> {
    let mut c = cases("default");
    c.extend(recording().version_edges);
    assert!(c.iter().all(|c| c.mode == "default"));
    c
}

fn spend(c: &Case) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_hex(&c.lock).unwrap(),
        // The parameter's bits are the wire's four bytes.
        transaction_version: c.version as i32,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex(&c.unlock).unwrap(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    })
}

fn verdict(mut s: Spend) -> Result<bool, String> {
    s.validate().map_err(|e| {
        assert!(!e.is_resource_limit());
        e.message
    })
}

/// The reference's default relaxes the rule above version 1 (unsigned).
fn relaxed(c: &Case) -> bool {
    c.version > 1
}

#[test]
fn the_recording_is_the_grid_816() {
    let r = recording();
    for c in r.cases.iter().chain(&r.version_edges) {
        assert_eq!(
            UnlockingScript::from_hex(&c.unlock).unwrap().is_push_only(),
            c.push_only,
            "{}",
            c.unlock_name
        );
    }
    // The reference's default runs both non-push-only scripts above version
    // 1, the version read unsigned, and refuses them at 0 and 1.
    let ran: Vec<_> = default_cells()
        .iter()
        .filter(|c| c.reference() == Ok(true) && !c.push_only)
        .map(|c| (c.version, c.unlock_name.clone()))
        .collect();
    let mut expected = vec![];
    for v in [2u32, 2_147_483_648, 4_294_967_295] {
        expected.push((v, "op1-drop-then-push".to_string()));
        expected.push((v, "push-dup-drop".to_string()));
    }
    let mut ran_sorted = ran.clone();
    ran_sorted.sort();
    expected.sort();
    assert_eq!(ran_sorted, expected);
}

/// The default mode, cell by cell, is the reference's default: the push-only
/// script valid at every version; a non-push-only script refused at versions
/// 0 and 1 in the reference's words and run above 1 (2, 2^31, 2^32 - 1).
/// Until #816's relaxing (the owner's word of 2026-11-09 23:5xZ) the cells
/// above 1 were refused here.
#[test]
fn the_default_mode_judges_push_only_as_the_reference_default_816() {
    for c in default_cells() {
        let here = verdict(spend(&c));
        let label = format!("v{} {}", c.version, c.unlock_name);
        assert_eq!(here, c.reference(), "{label}");
        let expected = if c.push_only || relaxed(&c) {
            Ok(true)
        } else {
            Err(REFUSAL.to_string())
        };
        assert_eq!(here, expected, "{label}");
    }
}

/// The switch overrides the derived rule both ways: `true` gives the old
/// refusal above version 1 (this crate's rule until #816's relaxing), `false`
/// runs a non-push-only script at versions 0 and 1.
#[test]
fn the_switch_overrides_the_default_reading_both_ways_816() {
    for c in default_cells().iter().filter(|c| !c.push_only) {
        let label = format!("v{} {}", c.version, c.unlock_name);
        let mut on = spend(c);
        on.set_require_push_only(true);
        assert_eq!(verdict(on), Err(REFUSAL.to_string()), "{label}");
        let mut off = spend(c);
        off.set_require_push_only(false);
        assert_eq!(verdict(off), Ok(true), "{label}");
    }
}

/// Under the node's words: before Chronicle (`SIGPUSHONLY` with `GENESIS`)
/// push-only at both versions; under Chronicle at version 1 alone. Each cell
/// is the reference's under its explicit flags of the same reading
/// (`SIGPUSHONLY` alone, `SIGPUSHONLY,CHRONICLE`).
#[test]
fn the_words_require_push_only_as_the_node_does_816() {
    for (era, mode) in [
        (ProtocolEra::PostGenesis, "SIGPUSHONLY"),
        (ProtocolEra::PostChronicle, "SIGPUSHONLY,CHRONICLE"),
    ] {
        for (word, name) in [
            (ScriptFlags::block(era), "block"),
            (ScriptFlags::standard(era), "standard"),
        ] {
            assert!(word.contains(ScriptFlags::SIGPUSHONLY));
            for c in cases(mode) {
                let mut s = spend(&c);
                s.set_flags(word);
                let here = verdict(s);
                let label = format!("{name}({era:?}) v{} {}", c.version, c.unlock_name);
                assert_eq!(here, c.reference(), "{label}");
                let runs = c.push_only || (era == ProtocolEra::PostChronicle && c.version > 1);
                let expected = if runs {
                    Ok(true)
                } else {
                    Err(REFUSAL.to_string())
                };
                assert_eq!(here, expected, "{label}");
            }
        }
    }
}

/// The reference's explicit flags without `SIGPUSHONLY` run every cell; no
/// word of this crate lacks the bit (the node's `per_input` carries it), so
/// the recording stands as the reference's alone.
#[test]
fn the_reference_without_sigpushonly_runs_every_cell_816() {
    for c in cases("CHRONICLE") {
        assert_eq!(c.reference(), Ok(true), "v{} {}", c.version, c.unlock_name);
    }
}

/// A proven parent whose output 0 is locked by the grid's lock, and a child
/// at `version` spending it with `unlock`.
fn parent_and_child(version: u32, unlock: &str) -> (Transaction, Transaction, MockChainTracker) {
    let lock = cases("default")[0].lock.clone();
    let mut parent = Transaction::new();
    parent
        .add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    parent.inputs_mut()[0].set_unlocking_script(UnlockingScript::from_hex("51").unwrap());
    parent
        .add_output(TransactionOutput::new(
            1000,
            LockingScript::from_hex(&lock).unwrap(),
        ))
        .unwrap();
    let path = MerklePath::from_coinbase_txid(&parent.id(), 800_000);
    let root = path.compute_root(Some(&parent.id())).unwrap();
    parent.merkle_path = Some(path);
    // Past the offset-0 depth rule (#734).
    let mut tracker = MockChainTracker::new(900_000);
    tracker.add_root(800_000, root);
    let mut child = Transaction::new();
    child.set_version(version);
    let mut input = TransactionInput::with_source_transaction(parent.clone(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex(unlock).unwrap());
    child.add_input(input).unwrap();
    child
        .add_output(TransactionOutput::new(
            900,
            LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
    (parent, child, tracker)
}

/// `Transaction::verify` (the default mode, the overlay engine's submit
/// door) on every default-mode cell over a proven parent: the reference's
/// default verdict, so a non-push-only script runs above version 1 (refused
/// there until #816's relaxing) and is refused at versions 0 and 1.
#[tokio::test]
async fn transaction_verify_judges_push_only_as_the_reference_default_816() {
    for c in default_cells() {
        let (_, child, tracker) = parent_and_child(c.version, &c.unlock);
        let got = child.verify(&tracker, None, None).await;
        let label = format!("v{} {}", c.version, c.unlock_name);
        if c.reference() == Ok(true) {
            assert_eq!(got, Ok(true), "{label}");
        } else {
            assert_eq!(
                got,
                Err(Error::TransactionError(format!(
                    "Script validation failed for input 0: {REFUSAL}"
                ))),
                "{label}"
            );
        }
    }
}

/// The streaming reader on the same BEEFs: valid where the reference's
/// default runs the spend (a non-push-only script above version 1 included,
/// `SpendRefused` until #816's relaxing), `SpendRefused` in this crate's words
/// at versions 0 and 1.
#[test]
fn the_stream_judges_push_only_as_the_reference_default_816() {
    for c in default_cells() {
        let (_, child, tracker) = parent_and_child(c.version, &c.unlock);
        let bytes = child.to_beef_v1(false).unwrap();
        let v = verify_stream(bytes.as_slice(), &tracker, None).unwrap();
        let label = format!("v{} {}", c.version, c.unlock_name);
        if c.reference() == Ok(true) {
            assert!(matches!(v, Verdict::Valid { .. }), "{label}: {v:?}");
        } else {
            match v {
                Verdict::SpendRefused {
                    input: Some(0),
                    why: SpendRefusal::Script(words),
                    ..
                } => assert!(words.contains(REFUSAL), "{label}: {words}"),
                other => panic!("{label}: {other:?}"),
            }
        }
    }
}

/// The stream doors' verdict on a cell: valid where the reference's default
/// runs the spend, `SpendRefused` at input 0 of `refused` in `REFUSAL`'s
/// words otherwise.
fn assert_stream_verdict(label: &str, c: &Case, v: Verdict, refused: &Transaction) {
    if c.reference() == Ok(true) {
        assert!(matches!(v, Verdict::Valid { .. }), "{label}: {v:?}");
        return;
    }
    assert!(!c.push_only && !relaxed(c), "{label}");
    match v {
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Script(words),
            ..
        } => {
            assert_eq!(txid, refused.hash(), "{label}: the transaction named");
            assert!(words.contains(REFUSAL), "{label}: {words}");
        }
        other => panic!("{label}: {other:?}"),
    }
}

/// The asynchronous reader's source: the bytes in chunks of `size`.
struct Chunks {
    bytes: Vec<u8>,
    at: usize,
    size: usize,
}

impl AsyncByteSource for Chunks {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let end = (self.at + self.size).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

async fn verify_async(bytes: &[u8], tracker: &MockChainTracker, size: usize) -> Verdict {
    let mut source = Chunks {
        bytes: bytes.to_vec(),
        at: 0,
        size,
    };
    verify_stream_async(&mut source, tracker, None)
        .await
        .unwrap()
}

/// The two-pass reader (`verify_stream_two_pass`, a seekable source) on the
/// BEEFs of `the_stream_judges_push_only_as_the_reference_default_816`: the
/// same verdicts, a non-push-only script run above version 1 and refused at
/// versions 0 and 1 (#816's comment of 2026-11-10: no test reached it).
#[test]
fn the_two_pass_stream_judges_push_only_as_the_reference_default_816() {
    for c in default_cells() {
        let (_, child, tracker) = parent_and_child(c.version, &c.unlock);
        let bytes = child.to_beef_v1(false).unwrap();
        let v = verify_stream_two_pass(std::io::Cursor::new(&bytes), &tracker, None).unwrap();
        let label = format!("two-pass v{} {}", c.version, c.unlock_name);
        assert_stream_verdict(&label, &c, v, &child);
    }
}

/// The asynchronous reader (`verify_stream_async`) on the same bytes and
/// tracker, in chunks of 1, 7 and 4096 bytes: the same verdicts.
#[tokio::test]
async fn the_async_stream_judges_push_only_as_the_reference_default_816() {
    for c in default_cells() {
        let (_, child, tracker) = parent_and_child(c.version, &c.unlock);
        let bytes = child.to_beef_v1(false).unwrap();
        for size in [1, 7, 4096] {
            let v = verify_async(&bytes, &tracker, size).await;
            let label = format!("async({size}) v{} {}", c.version, c.unlock_name);
            assert_stream_verdict(&label, &c, v, &child);
        }
    }
}

/// A proven grandparent, an UNPROVEN parent at `version` spending it with
/// `unlock`, and a version-1 subject spending the parent with the grid's
/// push-only unlocking script: the cell's script sits in an ancestor that is
/// not the subject.
fn unproven_ancestor(version: u32, unlock: &str) -> (Transaction, Transaction, MockChainTracker) {
    let (_, mut parent, tracker) = parent_and_child(version, unlock);
    let grid = cases("default");
    let push_only = grid.iter().find(|c| c.push_only).unwrap();
    parent.outputs_mut()[0] =
        TransactionOutput::new(900, LockingScript::from_hex(&push_only.lock).unwrap());
    assert!(parent.merkle_path.is_none());
    let mut subject = Transaction::new();
    assert_eq!(subject.version(), 1);
    let mut input = TransactionInput::with_source_transaction(parent.clone(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex(&push_only.unlock).unwrap());
    subject.add_input(input).unwrap();
    subject
        .add_output(TransactionOutput::new(
            800,
            LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
    (parent, subject, tracker)
}

/// An unproven ancestor that is not the subject is judged by the same rule
/// (`judge_input` at `src/transaction/beef_stream/spends.rs`, and
/// `Transaction::verify`'s descent): valid where the reference's default
/// runs the cell, a version-2 (or 2^31, 2^32 - 1) script that is not
/// push-only included; refused at the PARENT's input 0 in `REFUSAL`'s words
/// at versions 0 and 1, the subject's own version 1 and push-only script
/// deciding nothing. The BEEF is this crate's writer's, read by the three
/// stream doors.
#[tokio::test]
async fn an_unproven_ancestor_is_judged_push_only_as_the_reference_default_816() {
    for c in default_cells() {
        let (parent, subject, tracker) = unproven_ancestor(c.version, &c.unlock);
        let label = format!("ancestor v{} {}", c.version, c.unlock_name);
        let bytes = subject.to_beef_v1(false).unwrap();

        let v = verify_stream(bytes.as_slice(), &tracker, None).unwrap();
        assert_stream_verdict(&format!("stream {label}"), &c, v, &parent);
        let v = verify_stream_two_pass(std::io::Cursor::new(&bytes), &tracker, None).unwrap();
        assert_stream_verdict(&format!("two-pass {label}"), &c, v, &parent);
        for size in [1, 4096] {
            let v = verify_async(&bytes, &tracker, size).await;
            assert_stream_verdict(&format!("async({size}) {label}"), &c, v, &parent);
        }

        let got = subject.verify(&tracker, None, None).await;
        if c.reference() == Ok(true) {
            assert_eq!(got, Ok(true), "{label}");
        } else {
            assert_eq!(
                got,
                Err(Error::TransactionError(format!(
                    "Script validation failed for input 0: {REFUSAL}"
                ))),
                "{label}"
            );
        }
    }
}
