//! `src/script/script.rs`'s truncated-push index (`truncated_push_index`,
//! read through `Script::truncated_push` and `Spend`), shard D of #603: the
//! 27 mutants the widened oracle left (run 41327640129,
//! `docs/census/mutants-2026-11-01.md`), killed here on the sibling
//! `bsv-script-lean`'s recorded vectors (at `5dc337e1`), each copied by its
//! corpus and id with its recorded verdict, and on its rules.
//!
//! The rules:
//!
//! * `push.truncated`: the node's parser refuses a push whose declared size
//!   runs past the end: `GetOp2` returns false for a cut length word or cut
//!   data (bitcoin-sv v1.2.3 `6504a3a` `src/script/script.h:165-200`, the
//!   length words at `:179-191`, the data at `:192-193`), and the
//!   interpreter fails with `SCRIPT_ERR_BAD_OPCODE` where its walk reaches it,
//!   executed or not (`interpreter.cpp:450-451`); this crate's rule since
//!   0.3.27 (bsv-rs#12). The sibling's `getOpTail`
//!   (`lean/BsvScript/Machine.lean:29-50`): below `OP_PUSHDATA1` the size is
//!   the opcode (`:32`), else 1, 2 or 4 little-endian length bytes, `a + 256 *
//!   b` and `a + 256 * (b + 256 * (c + 256 * d))` (`:33-44`); a cut length or
//!   a body shorter than the size is `none` (`:36,40,44,49`), which the loop
//!   reports as `badOpcode` at that instruction (`:384-386`).
//! * `flow.return`: a top-level `OP_RETURN` after Genesis ends the script
//!   (`Machine.lean:342-344`, `.done` when no conditional is open; the node's
//!   `interpreter.cpp:856-861`), so the bytes after it are never parsed; a
//!   nested one sets the non-top-level mark and the walk goes on parsing
//!   (`:344`, `:387`). Whether an `OP_RETURN` is top level is the static scope
//!   of `GetSigOpCount`'s walk, the one `truncated_push_index` follows:
//!   `OP_IF`, `OP_NOTIF`, `OP_VERIF`, `OP_VERNOTIF` open a scope and
//!   `OP_ENDIF` closes one (`lean/BsvScript/SigOps.lean:62-69`, a top-level
//!   `OP_RETURN` ending the walk at `:85`; the node's `script.cpp:45-58`).
//!
//! Eighteen of the 27 fall to recorded vectors (the sibling's `flow`,
//! `arith`, `road`, `cpp/cscript_tests`, `cpp/bn_op_tests` corpora and its
//! `sighash/bsv-rs-0.7.0.jsonl` subscripts): the whole corpus run through the
//! harness and every script of it through `truncated_push` on each mutant,
//! the vector being an entry whose answer moved. Four (788:60, 789:34,
//! 791:58 `+` and `/`) moved no entry of the whole corpus; their scripts are
//! built from the scope rule above, the expected index read off it, no
//! recorder's (`a_scope_..._scope_rule`). Five are candidates for equivalence
//! and are not tested here (the changelog's entry names them).
//!
//! Three mutants (784:13 `*=`, 800:17 `-=`, 826:17 `-=`) stop the walk from
//! advancing: `walk_within_a_deadline` runs every index and spend on a
//! thread and fails the test when no answer arrives within ten seconds, so a
//! loop that never ends is a failure of this test, never a timeout counted as
//! caught. Under `cargo mutants` the three still read TIMEOUT: the library's
//! own `script::spend` unit tests run first and hang on them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxInput, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

const TRUNCATED: &str = "A push declares more bytes than the script holds";

/// A spend of the sibling's corpus: the entry's id, its transaction, the
/// script and satoshis of the coin it spends (one input each).
#[derive(Clone, Copy)]
struct Entry {
    id: &'static str,
    tx_hex: &'static str,
    prevout_script_hex: &'static str,
    satoshis: u64,
}

/// The entry under the post-Chronicle block word (every entry here is spent
/// at 967,896 from a coin created after Chronicle, `params.consensus` true:
/// the harness's `engine::word_for`), within the deadline.
fn validate(e: &Entry) -> Result<bool, String> {
    let e = *e;
    walk_within_a_deadline(e.id, move || spend(&e))
}

fn spend(e: &Entry) -> Result<bool, String> {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).expect("a parseable transaction");
    assert_eq!(tx.inputs.len(), 1, "{}: one input", e.id);
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: e.satoshis,
        locking_script: LockingScript::from_hex(e.prevout_script_hex).unwrap(),
        transaction_version: tx.version,
        other_inputs: Vec::<TxInput>::new(),
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    spend.validate().map_err(|err| err.message)
}

/// The recorded verdict: `spec@cb7e46e` and `sv-node@v1.2.3` agree on every
/// entry here (`Ok` valid; `Err` the words of this crate's refusal).
fn assert_verdict(e: &Entry, want: Result<(), &str>) {
    let got = validate(e);
    match want {
        Ok(()) => assert_eq!(got, Ok(true), "{}: recorded valid", e.id),
        Err(fragment) => {
            let msg = got.expect_err(&format!("{}: recorded invalid", e.id));
            assert!(msg.contains(fragment), "{}: {msg:?}", e.id);
        }
    }
}

/// `Script::truncated_push` on the script `hex`, within the deadline.
fn index(hex: &str) -> Option<usize> {
    let script = Script::from_hex(hex).unwrap();
    walk_within_a_deadline(hex, move || script.truncated_push())
}

/// The unlocking script of an entry, as hex.
fn script_sig(e: &Entry) -> String {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).unwrap();
    bsv_rs::primitives::to_hex(&tx.inputs[0].script)
}

/// Runs `f` on its own thread and fails when it has not answered within ten
/// seconds: a walk that does not advance is a failure here, never a hang
/// (every index and spend of this file goes through it, so no test waits on a
/// walk that never ends).
fn walk_within_a_deadline<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(v) => v,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what}: the walk did not end within ten seconds")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: the walk panicked"),
    }
}

// arith/cases.jsonl:1, family bitwise/and: lock `00840087` (OP_0 OP_AND OP_0
// OP_EQUAL) under scriptSig `00`; spec@cb7e46e and sv-node@v1.2.3 valid.
const ARITH_00001: Entry = Entry {
    id: "arith-00001",
    tx_hex: "020000000100cdba52719119ebe5ed530a3dbd386ed23d52687cd638136ecf16c4df4c0f5b000000000100ffffffff010100000000000000015100000000",
    prevout_script_hex: "00840087",
    satoshis: 1000,
};

// arith/cases.jsonl:3, family bitwise/and: lock `01f684016087`, two direct
// pushes of one byte; spec@cb7e46e and sv-node@v1.2.3 valid.
const ARITH_00003: Entry = Entry {
    id: "arith-00003",
    tx_hex: "02000000010cd53348a34f5962be634cb83611eb77356252c372fec14dc6d4d2e893a1a01d00000000020161ffffffff010100000000000000015100000000",
    prevout_script_hex: "01f684016087",
    satoshis: 1000,
};

/// 784:13 (`pos += 1` to `*=`), 800:17 (`pos += 1` after the PUSHDATA1 length
/// to `-=`) and 826:17 (`pos += n` to `-=`): each walk stays at or returns to
/// an earlier byte and never ends. Every byte of a complete script is
/// consumed once (`getOpTail` returns the bytes consumed, `p + n`,
/// `Machine.lean:49`; the walk drops them, `:387`), so the walk ends.
#[test]
fn push_truncated_the_walk_ends_arith_bitwise_and_arith_00001_arith_00003_cpp_bn_op_00003() {
    for e in [ARITH_00001, ARITH_00003] {
        assert_eq!(index(e.prevout_script_hex), None, "{}", e.id);
        assert_verdict(&e, Ok(()));
    }
    // cpp/bn_op_tests.jsonl:3 (src/test/bn_op_tests.cpp:103, bint_unary_ops):
    // the script `4c008b`, a PUSHDATA1 of nothing then OP_1ADD, which the
    // node's EvalScript runs to "ok" under SCRIPT_UTXO_AFTER_GENESIS
    // (sv-node-unit@v1.2.2): its every push complete.
    assert_eq!(index("4c008b"), None);
}

/// 788:15, 788:30, 788:48, 788:66 (`==` to `!=` at `OP_IF`, `OP_NOTIF`,
/// `OP_VERIF`, `OP_VERNOTIF`): every other opcode opens a scope, so `OP_1`
/// puts the `OP_RETURN` after it inside one and the walk reads its data.
/// flow/flow.jsonl:1085, family flow/return-junk: lock `516a4c` (OP_1
/// OP_RETURN and a PUSHDATA1 with no length byte after it); spec@cb7e46e and
/// sv-node@v1.2.3 valid: the top-level `OP_RETURN` ends the script
/// (`Machine.lean:342-344`, `SigOps.lean:85`), its tail never parsed.
#[test]
fn flow_return_top_level_ends_the_parse_flow_return_junk_flow_01085() {
    let e = Entry {
        id: "flow-01085",
        tx_hex: "0200000001ee5189d10b56cbb359b7dbc2ff1264d52b2a07b2619dd7c570d8ea793635844a0000000000ffffffff010100000000000000015100000000",
        prevout_script_hex: "516a4c",
        satoshis: 1000,
    };
    assert_eq!(index(e.prevout_script_hex), None);
    assert_verdict(&e, Ok(()));
}

/// 788:42 (`OP_IF || OP_NOTIF || OP_VERIF` to `OP_IF || OP_NOTIF && OP_VERIF`:
/// `OP_NOTIF` and `OP_VERIF` open no scope) and 790:22 (`== OP_ENDIF` to `!=`:
/// every other opcode closes one): the `OP_RETURN` inside the `OP_NOTIF` reads
/// as top level and the cut push after it goes unseen.
/// sighash/bsv-rs-0.7.0.jsonl:495 (digest `2a9ee8b2…150f`, input 0): the
/// subscript `ffd7646f6a13b1a079c39025`, `0xff 0xd7 OP_NOTIF OP_3DUP
/// OP_RETURN` then a push of 19 bytes with 6 left: the `OP_NOTIF` opens a
/// scope (`SigOps.lean:65-67`), the `OP_RETURN` is nested and the walk goes
/// on (`Machine.lean:344`) to the cut push at index 5 (`:49`).
#[test]
fn flow_return_nested_keeps_the_parse_sighash_bsv_rs_0_7_0_line_495() {
    assert_eq!(index("ffd7646f6a13b1a079c39025"), Some(5));
}

/// 800:17 (`pos += 1` after the PUSHDATA1 length to `*=`): the length byte is
/// read again as an opcode. flow/flow.jsonl:1031, family
/// flags/v1/minimaldata/push-in-lock: lock `4c0121` + `6351675168`, a
/// PUSHDATA1 of one byte `0x21` (`Machine.lean:33-36`, one length byte
/// consumed) then `OP_IF OP_1 OP_ELSE OP_1 OP_ENDIF`; spec@cb7e46e and
/// sv-node@v1.2.3 valid. The mutant reads `0x21` as a push of 33 and refuses.
#[test]
fn push_pushdata1_length_consumed_flags_v1_minimaldata_push_in_lock_flow_01031() {
    let e = Entry {
        id: "flow-01031",
        tx_hex: "020000000157e400ef035a5ec00441508909c3a304b7720c1efe07c9a699e18ec66f24ff2b0000000000ffffffff010100000000000000015100000000",
        prevout_script_hex: "4c01216351675168",
        satoshis: 1000,
    };
    assert_eq!(index(e.prevout_script_hex), None);
    assert_verdict(&e, Ok(()));
}

/// 806:41 (`|` to `&`) and 806:70 (`<<` to `>>`): PUSHDATA2's size is `a + 256
/// * b` (`Machine.lean:39`).
/// * cpp/cscript_tests.jsonl:9 (src/test/cscript_tests.cpp, GetOp2): `4d0001`,
///   a size of 256 with no data, on which the node's `GetOp2` returns false
///   (sv-node-unit@v1.2.2); both mutants read a size of 0.
/// * flow/flow.jsonl:1045, family flags/v1/minimaldata/pushdata2-for-76: lock
///   `4d4c00` + 76 bytes + `6351675168`; spec@cb7e46e and sv-node@v1.2.3
///   valid. `&` reads a size of 0 and the data as opcodes, and refuses.
#[test]
fn push_pushdata2_little_endian_cpp_cscript_getop2_cpp_cscript_00009_flow_01045() {
    assert_eq!(index("4d0001"), Some(0));
    let e = Entry {
        id: "flow-01045",
        tx_hex: "0200000001783ac3b80eb5c6a86f96553e02ef0f7378a52dea41c95d6dc77517c8aba1a55e0000000000ffffffff010100000000000000015100000000",
        prevout_script_hex: "4d4c00202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6351675168",
        satoshis: 1000,
    };
    assert_eq!(index(e.prevout_script_hex), None);
    assert_verdict(&e, Ok(()));
}

/// 810:20 (`pos + 4` to `pos * 4`): PUSHDATA4 with fewer than four length
/// bytes is cut (`Machine.lean:42-44`); the mutant's bound lets the read run
/// past the end.
/// * cpp/cscript_tests.jsonl:13 (GetOp2): `4e000001`, three length bytes, on
///   which the node's `GetOp2` returns false (sv-node-unit@v1.2.2).
/// * flow/flow.jsonl:753, family flow/truncated-push: scriptSig `4e010000`
///   under lock `51`; spec@cb7e46e and sv-node@v1.2.3 invalid,
///   `SCRIPT_ERR_BAD_OPCODE`.
#[test]
fn push_pushdata4_length_cut_cpp_cscript_getop2_cpp_cscript_00013_flow_truncated_push_flow_00753() {
    assert_eq!(index("4e000001"), Some(0));
    let e = Entry {
        id: "flow-00753",
        tx_hex: "0200000001e5e6ac81cc3f2a53a3738b1c71cb058a118459013cb3b242dff1f10edbadca6e00000000044e010000ffffffff010100000000000000015100000000",
        prevout_script_hex: "51",
        satoshis: 1000,
    };
    assert_eq!(script_sig(&e), "4e010000");
    assert_eq!(index("4e010000"), Some(0));
    assert_verdict(&e, Err(TRUNCATED));
}

/// 814:46, 815:46, 816:46 (`<<` to `>>`) and 815:17, 816:17 (`|` to `&`):
/// PUSHDATA4's size is `a + 256 * (b + 256 * (c + 256 * d))`
/// (`Machine.lean:43`), every one of its four bytes read.
/// * flow/flow.jsonl:1049, family flags/v1/minimaldata/pushdata4-for-256:
///   lock `4e00010000` + 256 bytes + `6351675168` (its second byte 1, a size
///   of 256); spec@cb7e46e and sv-node@v1.2.3 valid (814:46, 815:17).
/// * road/road.jsonl:9157, family mutation/unlock: scriptSig `4e00008000` +
///   9 bytes (its third byte 0x80, a size of 8,388,608) under lock `965187`;
///   spec@cb7e46e invalid `SCRIPT_ERR_BAD_OPCODE`, sv-node@v1.2.3 refusing
///   the block (`blk-bad-inputs`) (815:46, 815:17, 816:17).
/// * cpp/cscript_tests.jsonl:14 (GetOp2): `4e00000001` (its fourth byte 1, a
///   size of 16,777,216) with no data, on which the node's `GetOp2` returns
///   false (sv-node-unit@v1.2.2) (816:46, 816:17).
#[test]
fn push_pushdata4_little_endian_flow_01049_road_mutation_unlock_road_seed_009157_cpp_cscript_00014()
{
    let flow_01049 = Entry {
        id: "flow-01049",
        tx_hex: "02000000013a9ce86b89b1e9260994cadb1be2487d89eb13966c854aad6363475e132beab10000000000ffffffff010100000000000000015100000000",
        prevout_script_hex: "4e000100002122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206351675168",
        satoshis: 1000,
    };
    assert_eq!(index(flow_01049.prevout_script_hex), None);
    assert_verdict(&flow_01049, Ok(()));

    let road_seed_009157 = Entry {
        id: "road-seed-009157",
        tx_hex: "02000000010b5e42987ffd54643e08b0a2be55fbb6e8f4375bae03fa4358ec54cb7f76fc67000000000e4e000080000886fe05d09e17cf38ffffffff010100000000000000015100000000",
        prevout_script_hex: "965187",
        satoshis: 1000,
    };
    let sig = script_sig(&road_seed_009157);
    assert_eq!(sig, "4e000080000886fe05d09e17cf38");
    assert_eq!(index(&sig), Some(0));
    assert_verdict(&road_seed_009157, Err(TRUNCATED));

    assert_eq!(index("4e00000001"), Some(0));
}

/// 788:60 (`OP_NOTIF || OP_VERIF || OP_VERNOTIF` to `OP_NOTIF || OP_VERIF &&
/// OP_VERNOTIF`: `OP_VERIF` and `OP_VERNOTIF` open no scope), 789:34 (an
/// opening `+= 1` to `-= 1`), 791:58 (`OP_ENDIF`'s `- 1` to `+ 1` and `/ 1`).
/// No entry of the sibling's whole corpus moved under any of the four; the
/// scripts are the scope rule's own cases (`SigOps.lean:65-69`: `OP_VERIF`
/// and `OP_VERNOTIF` open a scope, as `OP_IF` and `OP_NOTIF` do, and
/// `OP_ENDIF` closes one), each followed by an `OP_RETURN` and a direct push
/// of one byte with none left (`Machine.lean:32,49`):
/// * `65 6a 01`, `66 6a 01`: the `OP_RETURN` inside an `OP_VERIF`,
///   `OP_VERNOTIF` is nested, the cut push at index 2 (788:60);
/// * `63 63 68 6a 01`: two opened, one closed, the `OP_RETURN` nested, the
///   cut push at 4 (789:34);
/// * `63 68 6a 01`: opened and closed, the `OP_RETURN` top level, its tail
///   unread (791:58, both).
///
/// A spend makes 789:34's difference a verdict: under scriptSig `OP_1 OP_1
/// OP_1`, lock `63 63 68 6a 68 02 aa` runs both branches, the nested
/// `OP_RETURN` stops execution and the walk reaches the cut push at index 5,
/// `SCRIPT_ERR_BAD_OPCODE` (`Machine.lean:384-386`); read as top level it
/// would end valid with `1` on the stack.
#[test]
fn a_scope_opened_by_each_conditional_and_closed_by_endif_scope_rule() {
    assert_eq!(index("656a01"), Some(2));
    assert_eq!(index("666a01"), Some(2));
    assert_eq!(index("6363686a01"), Some(4));
    assert_eq!(index("63686a01"), None);

    let tx = "0200000001ee5189d10b56cbb359b7dbc2ff1264d52b2a07b2619dd7c570d8ea793635844a0000000003515151ffffffff010100000000000000015100000000";
    let e = Entry {
        id: "the scope rule, 63 63 68 6a 68 02 aa",
        tx_hex: tx,
        prevout_script_hex: "6363686a6802aa",
        satoshis: 1000,
    };
    assert_eq!(index(e.prevout_script_hex), Some(5));
    assert_verdict(&e, Err(TRUNCATED));
}
