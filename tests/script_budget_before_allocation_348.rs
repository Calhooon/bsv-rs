//! The interpreter's memory under a caller's budget, on the two inputs the
//! nightly fuzz job found in `fuzz_script_spend` at `5f3fa1ab` (run
//! 40474836749): bsv-rs#348 held 4,815,906 bytes live and bsv-rs#349 made one
//! allocation of 3,978,066 bytes under `memory_limit: Some(1_048_576)`. The
//! node's count was never crossed by either: the bytes were ones the budget
//! does not see. A number pushed by an arithmetic opcode held twice the bytes
//! it was charged (`ScriptNum::to_bytes` grew its buffer for the sign byte),
//! the number's decode and encode copied it twice more (a negated and an
//! absolute copy) while the popped operands were still held, and
//! `OP_NUM2BIN`'s refusal of an 825,905-byte size wrote that size in decimal
//! into its text (about five times the number's bytes in scratch).
//!
//! Each input is evaluated as the fuzz target evaluates it, with a counting
//! allocator armed on this thread alone, and held to the target's two
//! bounds: one allocation at most `2 * MEMORY_LIMIT + slack`, the live peak
//! at most `4 * MEMORY_LIMIT + slack`, `slack = 256 * input + 64 KiB`.
//! A reservation, the interpreter's step probe (`arithmetic_room.rs`'s
//! `reserve`: `try_reserve_exact` of a step's room, given back at once,
//! bsv-rs#374), is left out as the target leaves it out (bsv-rs#331): its
//! sites are out of the single-site read, and the live bound adds the largest
//! one, since dhat's peak cannot leave out a reservation held at that moment.
//! The #348 input is also held to one site under the budget itself, which
//! the target's live bound no longer separates from the base: that bound
//! carries six budgets for an arithmetic opcode's working set since #348.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
use bsv_rs::primitives::bsv::sighash::TxOutput;
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptEvaluationError, ScriptFlags, Spend, SpendParams,
    UnlockingScript,
};
use std::sync::{Mutex, MutexGuard};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// The one dhat profiler of this process: a test takes it before it creates
/// a profiler (a second one panics).
static PROFILER: Mutex<()> = Mutex::new(());

/// Waits for the profiler; a poisoned lock still serializes the next test.
fn serial() -> MutexGuard<'static, ()> {
    PROFILER.lock().unwrap_or_else(|e| e.into_inner())
}

/// The fuzz target's local memory budget.
const MEMORY_LIMIT: usize = 1 << 20;
/// The fuzz target's work budget.
const WORK_LIMIT: u64 = 50_000;

/// bsv-rs#348 (`crash-01e75c4ffed76db3bc7f55c7a83bccef523d2772`, 449 bytes):
/// mode 6 (the block word, post-Chronicle, version 2), an `OP_3DUP` and
/// `OP_MUL` chain whose products reach 685 KB.
const ISSUE_348: &[&str] = &[
    "06026300000061aa54556f6f6f6f0b000000000000006f756f6f6f6f6f6f6f6f6f0602637200000095959595956f9595",
    "53959595956f9595546f2f6f6f6f6f6f6f6fef6f6f6f9595959595959595951a0195959595959595959595159595956f",
    "956f06959595959595959595959595959595616f6f6f6f6f6f6f6f6f6f6f6f6f6f0602630000009595959595546f6f6f",
    "6f6f959595959595959595959595616f6f6f6f6f6f6f6f6f0602630000009595959595959595959595959595954c4c4c",
    "4c4c0000000000000000a4a070ace4fc746e6e6e6e0a0a0a0a0a0a0000012f6e906e6e6e6e6e6e6e6e6e5b5b007fa400",
    "009393939393939393939393939395959595959595959595959595959595959595959595616f6f6f6f6f6f6f6f6f6f6f",
    "6f6f6f06026300000095959595956f918b2f6f6f6fb06f6f0602630000009595959595546f6f6f6f6f6f6f6f6f6f6f95",
    "956f6e6e6e5b5b007fa4000093933d93939393939393939393959595959595959595959595959595959595959595956f",
    "959595959595951a01959595959595959595951595959595959595959595959595959595959595959595959595959595",
    "ebebebebebebeb95959495959595959595",
];

/// bsv-rs#349 (`crash-53ee39e8a744bb4bc824ceb7dea3622d6d1c43be`, 525 bytes):
/// mode 6, an `OP_MUL` chain to an 825,905-byte number, then `OP_NUM2BIN`
/// with it as the size.
const ISSUE_349: &[&str] = &[
    "06026300000061aa54556f6f6f6f6f756f6f6f6f6f6f6f6f5a06fd950000009595959595959595959595959595959595",
    "95959595956f6f6f6f6f6f239595616f6f6f6f6f55aa5400000008000001e66f6f6f6f6f6f236f6f6f6f6f6f6f6f6f6f",
    "6f6f6f313031303130313031303130333133303331333033313330333133303331333033316f6f6f6f6f6f9595959595",
    "95800095959595959595959595959595959595959595959595616f6f9595959595953331333033316f6f6f6f6f959595",
    "959595959595959595959595959595959595959595616f6f6f6f6f55aa543f6f6f6f6f6f6f6f6f6f6f6f6f6f95959595",
    "959595959595959595959595959595956f6f6f6f6f6f239595616f6f6f6f6f55aa5400000008000001e66f6f6f6f6f6f",
    "236f6f6f6f6f6f6f6f6f6f6f6f6f31303130313031303130313033313330333133303331333033313330333133303331",
    "6f6f6f6f6f6f959595959595800095959595959595959595959595959595959595959595616f6f959595959595800095",
    "959595959595959595959595959595959595959595616f6f6f6f6f55aa546f6f6f000095959595959595959595959595",
    "9595954195959595616f6f6f6f01000501210001000001210000146f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f",
    "6f6f6f6f6f6f6f6f6f6f6f6f908b2f6f6f06026300000061aa54556f6f6f6f6f6f6f6f6f6f6f6f6f6f6f060263",
];

/// What one evaluation allocated, as dhat counts the blocks allocated while
/// it ran: the peak of their live bytes (the fuzz target's peak, with any
/// reservation held at that moment), the most bytes live at once from any one
/// allocation site but a reservation's, which no single request exceeds (the
/// target's largest request is at most this), and the largest reservation.
struct Measured {
    verdict: Result<bool, ScriptEvaluationError>,
    largest_site: usize,
    largest_reservation: usize,
    peak: usize,
}

/// The frame of the interpreter's step probe: an allocation under it is a
/// reservation, given back before the allocator's next call.
const RESERVATION_FRAME: &str = "arithmetic_room::reserve";

/// Runs `unlocking` then `locking` as the fuzz target does, under `word`
/// and the target's two budgets, under a dhat profiler.
fn measure(word: ScriptFlags, version: i32, unlocking: &[u8], locking: &[u8]) -> Measured {
    let _serial = serial();
    let mut spend = Spend::new(SpendParams {
        source_txid: [0x11; 32],
        source_output_index: 0,
        source_satoshis: 1_000,
        locking_script: LockingScript::from_binary(locking).unwrap(),
        transaction_version: version,
        other_inputs: Vec::new(),
        outputs: vec![TxOutput {
            satoshis: 900,
            script: vec![0x51],
        }],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(unlocking).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: Some(MEMORY_LIMIT),
        work_limit: Some(WORK_LIMIT),
    });
    spend.set_flags(word);
    let file = std::env::temp_dir().join(format!(
        "bsv-rs-348-dhat-{}-{}.json",
        std::process::id(),
        unlocking.len() + locking.len()
    ));
    let profiler = dhat::Profiler::builder().file_name(&file).build();
    let verdict = spend.validate();
    drop(spend);
    let peak = dhat::HeapStats::get().max_bytes;
    drop(profiler);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    std::fs::remove_file(&file).unwrap();
    let frames = json["ftbl"].as_array().unwrap();
    let (mut largest_site, mut largest_reservation) = (0, 0);
    for pp in json["pps"].as_array().unwrap() {
        let reservation = pp["fs"].as_array().unwrap().iter().any(|f| {
            frames[f.as_u64().unwrap() as usize]
                .as_str()
                .unwrap()
                .contains(RESERVATION_FRAME)
        });
        let site = if reservation {
            &mut largest_reservation
        } else {
            &mut largest_site
        };
        *site = (*site).max(pp["mb"].as_u64().unwrap() as usize);
    }
    Measured {
        verdict,
        largest_site,
        largest_reservation,
        peak,
    }
}

/// A fuzz input split as the target splits it: byte 0 the word, the era and
/// the version, bytes 1 and 2 the unlocking script's length.
fn measure_fuzz_input(hex: &[&str]) -> (Measured, usize) {
    let data = from_hex(&hex.concat()).unwrap();
    let [mode, low, high, rest @ ..] = &data[..] else {
        panic!("a fuzz input has three header bytes");
    };
    let era = if mode & 2 == 0 {
        ProtocolEra::PostGenesis
    } else {
        ProtocolEra::PostChronicle
    };
    let word = if mode & 1 == 0 {
        ScriptFlags::block(era)
    } else {
        ScriptFlags::standard(era)
    };
    let version = if mode & 4 == 0 { 1 } else { 2 };
    let split = (u16::from_le_bytes([*low, *high]) as usize).min(rest.len());
    let (unlocking, locking) = rest.split_at(split);
    (
        measure(word, version, unlocking, locking),
        unlocking.len() + locking.len(),
    )
}

/// The fuzz target's two bounds on an input of `input` script bytes, a
/// reservation out of both: the live bound holds with the largest
/// reservation added whenever the target's read holds.
fn assert_within_the_fuzz_bounds(measured: &Measured, input: usize) {
    let slack = 256 * input + (64 << 10);
    assert!(
        measured.largest_site <= 2 * MEMORY_LIMIT + slack,
        "{} bytes live from one site under a budget of {MEMORY_LIMIT}",
        measured.largest_site
    );
    assert!(
        measured.peak <= 4 * MEMORY_LIMIT + slack + measured.largest_reservation,
        "{} bytes live under a budget of {MEMORY_LIMIT}, a reservation of {} among them",
        measured.peak,
        measured.largest_reservation
    );
}

#[test]
fn issue_348_a_multiplication_chain_stays_within_the_budgets_bounds() {
    let (measured, input) = measure_fuzz_input(ISSUE_348);
    assert_eq!(input, 446);
    let err = measured.verdict.as_ref().unwrap_err();
    // The node's count is never crossed: the chain runs to the undefined
    // opcode 0xeb, a verdict, not a decline.
    assert_eq!(err.message, "Invalid opcode 235 (pc=197).");
    assert_eq!(err.resource_limit, None);
    assert_within_the_fuzz_bounds(&measured, input);
    // Before #348 one site held 2,061,735 bytes (an encoder's buffer doubled
    // for the sign byte), within the target's single-request bound and its
    // live bound of ten budgets: a site under the budget itself is what
    // separates the fix (695,285 bytes after it, the error's stack snapshot).
    assert!(
        measured.largest_site < MEMORY_LIMIT,
        "{} bytes live from one site under a budget of {MEMORY_LIMIT}",
        measured.largest_site
    );
}

#[test]
fn issue_349_num2bin_refuses_a_huge_size_without_writing_it_in_decimal() {
    let (measured, input) = measure_fuzz_input(ISSUE_349);
    assert_eq!(input, 522);
    let err = measured.verdict.as_ref().unwrap_err();
    // SCRIPT_ERR_PUSH_SIZE (`interpreter.cpp:1747-1749`), its size named by
    // its length: the decimal text alone was a 3,978,066-byte allocation.
    assert_eq!(
        err.message,
        "OP_NUM2BIN requires a size from 0 to 2147483647, found a 825905-byte number."
    );
    assert_eq!(err.resource_limit, None);
    assert_within_the_fuzz_bounds(&measured, input);
    assert!(
        measured.largest_site < MEMORY_LIMIT,
        "{} bytes live from one site",
        measured.largest_site
    );
}

/// `<n bytes> OP_DUP OP_MUL OP_DROP OP_1`: a 100,000-byte magnitude whose high
/// bit is set takes a sign byte. Before #348 the encoder grew its buffer for
/// that byte by doubling it (a 200,000-byte request) and the element pushed
/// held twice the bytes the budget charged.
#[test]
fn a_pushed_product_holds_the_bytes_it_is_charged() {
    let mut operand = vec![0xff; 50_000];
    operand.push(0x00);
    let mut unlocking = vec![0x4e];
    unlocking.extend_from_slice(&(operand.len() as u32).to_le_bytes());
    unlocking.extend_from_slice(&operand);
    let locking = [0x76, 0x95, 0x75, 0x51];
    let measured = measure(
        ScriptFlags::block(ProtocolEra::PostChronicle),
        2,
        &unlocking,
        &locking,
    );
    assert!(measured.verdict.unwrap());
    // The product's own digits (num-bigint's 100,000 bytes and its word's
    // rounding) are the largest; the encoder's buffer is 100,001 bytes.
    assert!(
        measured.largest_site < 150_000,
        "{} bytes live from one site for a 100,001-byte product",
        measured.largest_site
    );
}

/// A number named in a refusal's text: in decimal up to 64 bytes of
/// magnitude, by its length above.
#[test]
fn a_refusals_number_is_named_by_its_length_above_sixty_four_bytes() {
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let size_text = |size: &[u8]| {
        let mut unlocking = vec![0x51, 0x4c, size.len() as u8];
        unlocking.extend_from_slice(size);
        let measured = measure(word, 2, &unlocking, &[0x80]);
        measured.verdict.unwrap_err().message
    };
    let mut at_64 = vec![0x00; 63];
    at_64.push(0x01);
    assert_eq!(
        size_text(&at_64),
        format!(
            "OP_NUM2BIN requires a size from 0 to 2147483647, found {}.",
            bsv_rs::primitives::BigNumber::from_bytes_le(&at_64).to_dec_string()
        )
    );
    let mut at_65 = vec![0x00; 64];
    at_65.push(0x01);
    assert_eq!(
        size_text(&at_65),
        "OP_NUM2BIN requires a size from 0 to 2147483647, found a 65-byte number."
    );
}
