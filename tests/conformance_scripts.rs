//! Cross-language conformance vectors: script evaluation, sighash, whole-tx.
//!
//! Reads the shared conformance corpus maintained in the `ts-stack` repository
//! (`conformance/vectors/sdk/scripts/evaluation.json` plus the script-domain
//! regression files) and drives the bsv-rs `Spend` interpreter, sighash
//! builder, and `Script` API against the pinned consensus data.
//!
//! Corpus location: `$BSV_CONFORMANCE_DIR`, defaulting to
//! `../ts-stack/conformance` relative to the crate root. If the corpus is not
//! present the tests SKIP (print + pass) so CI without the sibling checkout
//! stays green. When the corpus IS present, every vector is either executed
//! or counted against an enumerated `unsupported` allowlist with a reason —
//! never silently dropped. Per-class unsupported counts and the total vector
//! count are pinned so corpus or harness drift is detected.
//!
//! IMPORTANT CONTEXT — why an unsupported allowlist exists at all:
//! bsv-rs's `Spend` interpreter is a port of the ts-sdk *default* evaluation
//! mode: it has NO verify-flags parameter. It unconditionally enforces
//! MINIMALDATA (minimal pushes + minimally-encoded numbers), LOW_S, NULLDUMMY,
//! SIGPUSHONLY (push-only unlocking scripts), CLEANSTACK, strict DER/pubkey
//! encodings, and SIGHASH_FORKID-required, while running the post-genesis BSV
//! opcode set (OP_MUL/OP_CAT/OP_LSHIFT... enabled; only OP_2MUL/OP_2DIV/
//! OP_VER/OP_VERIF/OP_VERNOTIF disabled; no pre-genesis size/count limits; no
//! P2SH redeem-script evaluation; OP_CHECKLOCKTIMEVERIFY/OP_CHECKSEQUENCEVERIFY
//! are NOPs). The node fixtures, in contrast, are parameterized by node verify
//! flags (P2SH, STRICTENC, UTXO_AFTER_GENESIS, ...). Vectors whose expected
//! outcome depends on a flag configuration bsv-rs cannot express are counted
//! per-class below, with the class totals pinned.
#![cfg(feature = "transaction")]

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

use bsv_rs::primitives::bsv::sighash::{parse_transaction, SighashCache, TxOutput};
use bsv_rs::primitives::sha256d;
use bsv_rs::script::{op, LockingScript, Script, ScriptChunk, Spend, SpendParams, UnlockingScript};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};

// ============================================================================
// Corpus location (shared convention with conformance_beef.rs)
// ============================================================================

/// Locates the conformance corpus, or returns None (SKIP) if absent.
fn corpus_dir() -> Option<PathBuf> {
    let dir = match std::env::var("BSV_CONFORMANCE_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ts-stack/conformance"),
    };
    if dir.join("META.json").is_file() {
        Some(dir)
    } else {
        eprintln!(
            "SKIP: conformance corpus not found at {} (set BSV_CONFORMANCE_DIR or check out \
             ts-stack next to bsv-rs); conformance tests pass vacuously",
            dir.display()
        );
        None
    }
}

fn load_json(path: &PathBuf) -> Value {
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

// ============================================================================
// Small JSON helpers
// ============================================================================

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn n(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn b(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn from_hex(hex: &str) -> Vec<u8> {
    bsv_rs::primitives::from_hex(hex).unwrap_or_else(|e| panic!("bad hex '{}': {}", hex, e))
}

fn to_hex(bytes: &[u8]) -> String {
    bsv_rs::primitives::to_hex(bytes)
}

// ============================================================================
// Result accounting
// ============================================================================

#[derive(Default)]
struct Summary {
    run: usize,
    passed: usize,
    /// class -> (reason, vector ids)
    unsupported: BTreeMap<&'static str, Vec<String>>,
    skipped: Vec<String>,
    known_failures_hit: Vec<String>,
    /// Unexplained mismatches — these FAIL the test.
    failures: Vec<String>,
    /// Vector ids whose execution PANICKED inside bsv-rs (robustness bugs:
    /// the SDK should return Err, never panic, on malformed input). Panics
    /// are converted to "spend invalid" for conformance comparison (the TS
    /// SDK throws→invalid on the same inputs) but tracked and pinned here so
    /// the robustness gap stays visible.
    panics: Vec<String>,
}

impl Summary {
    fn unsupported_total(&self) -> usize {
        self.unsupported.values().map(Vec::len).sum()
    }

    fn print(&self, name: &str) {
        println!("=== {} summary ===", name);
        println!(
            "total={} run={} passed={} unsupported={} skipped={} known_failures={} failures={} panics={}",
            self.run + self.unsupported_total() + self.skipped.len(),
            self.run,
            self.passed,
            self.unsupported_total(),
            self.skipped.len(),
            self.known_failures_hit.len(),
            self.failures.len(),
            self.panics.len()
        );
        for (class, ids) in &self.unsupported {
            println!("  unsupported[{}] = {}", class, ids.len());
        }
        for f in &self.known_failures_hit {
            println!("  KNOWN FAILURE (SDK divergence, tracked): {}", f);
        }
        if !self.panics.is_empty() {
            println!(
                "  PANICS (bsv-rs robustness bugs — SDK panicked instead of Err): {} vectors, e.g. {:?}",
                self.panics.len(),
                &self.panics[..self.panics.len().min(5)]
            );
        }
        for f in self.failures.iter().take(25) {
            println!("  FAILURE: {}", f);
        }
    }
}

/// Runs `f`, converting a panic inside bsv-rs into `None` (recorded by the
/// caller). The panic hook is silenced by the callers around bulk loops.
fn catch<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}

/// Silences the panic hook for the duration of a bulk vector loop (thousands
/// of malformed-input panics would otherwise flood the output). Returns the
/// previous hook, which the caller MUST restore before asserting.
fn silence_panics() -> Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    prev
}

// ============================================================================
// sdk.scripts.evaluation — node-script fixtures
// ============================================================================

/// Builds the crediting transaction exactly like the TS conformance runner
/// (`buildCreditingTransaction`): version 1, one coinbase-style input
/// (zero txid, vout 0xffffffff, unlocking script OP_0 OP_0, sequence
/// 0xffffffff), one output carrying the locking script and amount, locktime 0.
fn crediting_txid(locking_script: &LockingScript, amount: u64) -> [u8; 32] {
    let mut input = TransactionInput::new(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        0xffff_ffff,
    );
    input.unlocking_script = Some(UnlockingScript::from_chunks(vec![
        ScriptChunk { op: op::OP_0, data: None },
        ScriptChunk { op: op::OP_0, data: None },
    ]));
    input.sequence = 0xffff_ffff;
    let output = TransactionOutput {
        satoshis: Some(amount),
        locking_script: locking_script.clone(),
        change: false,
    };
    Transaction::with_params(1, vec![input], vec![output], 0).hash()
}

/// Executes one node-script fixture through the bsv-rs Spend interpreter,
/// mirroring the TS runner's spending-transaction context.
///
/// Returns `Ok(valid)` or `Err(message)` — a rejection with the interpreter's
/// error message, used for precise attribution when classifying mismatches
/// (the TS runner treats evaluation exceptions as `valid=false`).
fn run_node_script(input: &Value) -> Result<bool, String> {
    let locking = LockingScript::from_hex(s(input, "script_pubkey_hex"))
        .map_err(|e| format!("locking script parse: {}", e))?;
    let sig_hex = s(input, "script_sig_hex");
    let unlocking = if sig_hex.is_empty() {
        UnlockingScript::new()
    } else {
        UnlockingScript::from_hex(sig_hex)
            .map_err(|e| format!("unlocking script parse: {}", e))?
    };
    let amount = n(input, "amount_satoshis") as u64;
    let source_txid = crediting_txid(&locking, amount);

    let mut spend = Spend::new(SpendParams {
        source_txid,
        source_output_index: 0,
        source_satoshis: amount,
        locking_script: locking,
        transaction_version: n(input, "tx_version") as i32,
        other_inputs: vec![],
        outputs: vec![TxOutput { satoshis: amount, script: vec![] }],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
    });
    spend.validate().map_err(|e| e.message)
}

/// Enumerated unsupported classes for node-script/node-transaction fixtures.
///
/// A mismatch (bsv-rs result != expected) is only tolerated when it is
/// attributable to a verify-flag capability bsv-rs's flagless interpreter
/// cannot express. Anything else is a hard failure (or a pinned KNOWN_FAILURE).
///
/// got=true / expected=false → bsv-rs is missing a flag-ON enforcement:
///   classified via the fixture's expected node result code.
/// got=false / expected=true → bsv-rs enforces an always-ON restriction that
///   the fixture's flag set turns off:
///   classified via the absence of the corresponding flag.
fn classify_node_mismatch(ctx: &MismatchContext<'_>) -> Option<&'static str> {
    let has = |f: &str| ctx.flags.iter().any(|x| x == f);
    if !ctx.expected_valid {
        // bsv-rs accepted a spend the node fixture rejects under these flags.
        // Attribution uses the fixture's expected node result code (and the
        // P2SH shape of the locking script, since P2SH failures surface under
        // many result codes).
        if has("P2SH") && ctx.locking_is_p2sh {
            // The fixture expects the redeem script to be evaluated; bsv-rs
            // (post-genesis rules) treats P2SH as a plain hash puzzle.
            return Some("no P2SH redeem-script evaluation in bsv-rs (post-genesis rules)");
        }
        match ctx.result_code {
            // Pre-genesis limits (script/number/push/stack/op-count sizes) —
            // bsv-rs runs BSV unlimited semantics.
            "SCRIPTNUM_OVERFLOW" | "OPERAND_SIZE" | "SCRIPT_SIZE" | "PUSH_SIZE"
            | "STACK_SIZE" | "OP_COUNT" | "PUBKEY_COUNT" | "SIG_COUNT" => {
                Some("pre-genesis limits (bsv-rs runs post-genesis/unlimited rules)")
            }
            // Opcodes valid post-genesis but rejected by the fixture's
            // pre-genesis flag set (OP_MUL, OP_CAT, OP_SPLIT, OP_INVERT, ...),
            // or Chronicle-era opcode remapping bsv-rs does not implement.
            "BAD_OPCODE" | "DISABLED_OPCODE" => {
                Some("flag-dependent opcode set (pre-genesis/Chronicle) not expressible in bsv-rs")
            }
            "INVALID_STACK_OPERATION" if has("UTXO_AFTER_CHRONICLE") => {
                Some("UTXO_AFTER_CHRONICLE opcode semantics not implemented in bsv-rs")
            }
            "DISCOURAGE_UPGRADABLE_NOPS" => Some("no DISCOURAGE_UPGRADABLE_NOPS flag in bsv-rs"),
            "MINIMALIF" => Some("no MINIMALIF flag in bsv-rs"),
            "NULLFAIL" => Some("no NULLFAIL flag in bsv-rs"),
            // OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY are NOPs in
            // bsv-rs (post-genesis), so locktime fixtures cannot reject.
            "UNSATISFIED_LOCKTIME" | "NEGATIVE_LOCKTIME" => {
                Some("no CLTV/CSV enforcement in bsv-rs (post-genesis NOPs)")
            }
            // Pre-genesis: an executed OP_RETURN fails the script. bsv-rs
            // implements the post-genesis skip-to-end semantics only.
            "OP_RETURN" => {
                Some("pre-genesis OP_RETURN semantics (bsv-rs implements post-genesis skip)")
            }
            // Flag-dependent conditional structure rules (e.g. the
            // post-genesis multiple-ELSE ban). bsv-rs implements the ts-sdk
            // default (relaxed) ELSE/ENDIF handling.
            "UNBALANCED_CONDITIONAL" => {
                Some("flag-dependent ELSE/ENDIF structure rules not expressible in bsv-rs")
            }
            // STRICTENC without SIGHASH_FORKID: a signature CARRYING the
            // FORKID bit must be rejected. bsv-rs always requires FORKID.
            "ILLEGAL_FORKID" => {
                Some("bsv-rs always requires SIGHASH_FORKID (cannot reject FORKID-bit sigs)")
            }
            // node-transaction fixtures carry no result code; attribute via
            // flags.
            "" if has("CHECKLOCKTIMEVERIFY") || has("CHECKSEQUENCEVERIFY") => {
                Some("no CLTV/CSV enforcement in bsv-rs (post-genesis NOPs)")
            }
            _ => None,
        }
    } else {
        // bsv-rs rejected a spend the node fixture accepts: attribute via the
        // interpreter's own error message — an always-ON bsv-rs restriction
        // that the fixture's flag set disables.
        let msg = ctx.error_message;
        if has("P2SH") && ctx.locking_is_p2sh {
            // Fixture validity depends on evaluating the redeem script (e.g.
            // P2SH + CLEANSTACK, where the node checks the stack AFTER the
            // redeem evaluation); bsv-rs treats P2SH as a plain hash puzzle.
            return Some("no P2SH redeem-script evaluation in bsv-rs (post-genesis rules)");
        }
        if msg.starts_with("Invalid opcode") && has("UTXO_AFTER_GENESIS") {
            // Post-genesis, OP_VERIF/OP_VERNOTIF in an UNEXECUTED branch are
            // tolerated; bsv-rs implements the pre-genesis/default rule that
            // rejects them anywhere.
            return Some("flag-dependent opcode set (pre-genesis/Chronicle) not expressible in bsv-rs");
        }
        if msg.contains("currently disabled") && has("UTXO_AFTER_CHRONICLE") {
            // Chronicle re-enables OP_VER/OP_2MUL/OP_2DIV; bsv-rs keeps them
            // disabled unconditionally.
            return Some("UTXO_AFTER_CHRONICLE opcode semantics not implemented in bsv-rs");
        }
        if msg.contains("can only contain push operations") && !has("SIGPUSHONLY") {
            return Some("bsv-rs always enforces SIGPUSHONLY (push-only unlocking scripts)");
        }
        if (msg.contains("not minimally-encoded") || msg.contains("Invalid script number"))
            && !has("MINIMALDATA")
        {
            return Some("bsv-rs always enforces MINIMALDATA (no off switch)");
        }
        if msg.contains("clean stack") && !has("CLEANSTACK") {
            return Some("bsv-rs always enforces CLEANSTACK (no off switch)");
        }
        if msg.contains("SIGHASH_FORKID") && !has("SIGHASH_FORKID") {
            return Some("bsv-rs always requires SIGHASH_FORKID (legacy-signature fixtures)");
        }
        if msg.contains("low S") && !has("LOW_S") {
            return Some("bsv-rs always enforces LOW_S (no off switch)");
        }
        if msg.contains("dummy") && !has("NULLDUMMY") {
            return Some("bsv-rs always enforces NULLDUMMY (no off switch)");
        }
        if (msg.contains("signature format is invalid") || msg.contains("public key"))
            && !has("STRICTENC")
            && !has("DERSIG")
        {
            return Some("bsv-rs always enforces strict DER/pubkey encodings (no off switch)");
        }
        None
    }
}

/// Context for classifying a conformance mismatch.
struct MismatchContext<'a> {
    flags: &'a [String],
    expected_valid: bool,
    /// The fixture's expected node result code ("" for node-transaction).
    result_code: &'a str,
    /// bsv-rs's own rejection message ("" when bsv-rs accepted).
    error_message: &'a str,
    /// Whether the locking script under test is the canonical P2SH pattern.
    locking_is_p2sh: bool,
}

/// Canonical P2SH pattern: OP_HASH160 <20 bytes> OP_EQUAL.
fn is_p2sh_hex(script_pubkey_hex: &str) -> bool {
    script_pubkey_hex.len() == 46
        && script_pubkey_hex.starts_with("a914")
        && script_pubkey_hex.ends_with("87")
}

/// KNOWN SDK DIVERGENCES for `sdk.scripts.evaluation` — real behavior
/// differences between bsv-rs and the pinned consensus vectors that are NOT
/// attributable to the missing verify-flags API. Each entry is a genuine
/// bsv-rs bug that should be fixed upstream; the list is asserted exactly
/// (a new failure fails the test, and once a bug is fixed its entry goes
/// stale and must be removed).
///
/// *** BUG 1 (15 vectors): bsv-rs OP_CHECKMULTISIG validates the DER/pubkey
/// encoding of EVERY signature and public key up front
/// (src/script/spend.rs::op_checkmultisig), while the node and ts-sdk only
/// check encodings for (sig, key) pairs actually evaluated — empty sigs and
/// keys skipped after an early exit are never encoding-checked. Fixtures with
/// e.g. 20 empty sigs against garbage pubkeys wrapped in NOT are consensus-
/// VALID but bsv-rs rejects them ("OP_CHECKMULTISIG requires correct
/// encoding..."). ***
///
/// *** BUG 2 (script-012) — FIXED 2026-07-08: Script::from_binary([0x4c])
/// (truncated OP_PUSHDATA1) used to PANIC; it now parses to an empty-data
/// chunk like ts-sdk. ***
const EVALUATION_KNOWN_FAILURES: &[(&str, &str)] = &[
    // (script-012 FIXED 2026-07-08: truncated OP_PUSHDATA1 now parses to an
    // empty-data chunk like ts-sdk — src/script/script.rs pushdata arm.)
    // BUG 1 — eager OP_CHECKMULTISIG encoding validation (see above):
    ("node.script.bitcoin-sv.0698", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.0699", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.1433", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.1535", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.1536", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.1537", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.1539", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.bitcoin-sv.1541", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.0666", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.0667", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.1384", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.1486", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.1487", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.1488", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.1490", "eager CHECKMULTISIG encoding check (BUG 1)"),
    ("node.script.teranode.1492", "eager CHECKMULTISIG encoding check (BUG 1)"),
];

#[test]
fn conformance_scripts_evaluation() {
    let Some(dir) = corpus_dir() else { return };
    let file = load_json(&dir.join("vectors/sdk/scripts/evaluation.json"));
    let vectors = file["vectors"].as_array().expect("vectors array");
    assert_eq!(
        vectors.len(),
        5116,
        "evaluation.json vector count changed — review new vectors and update the pins"
    );

    let mut summary = Summary::default();
    let debug = std::env::var("BSV_CONFORMANCE_DEBUG").is_ok();
    let mut debug_lines: Vec<String> = Vec::new();

    let prev_hook = silence_panics();
    for vector in vectors {
        let id = s(vector, "id").to_string();
        // Corpus-directed skips, mirroring the reference TS runner:
        //   skip: true                    → explicitly deprecated/skipped
        //   parity_class: intended/…      → documented gap, not required
        //     (e.g. the "full-transaction-consensus" tx_invalid fixtures that
        //     no standalone script interpreter can reject)
        let parity = s(vector, "parity_class");
        if b(vector, "skip") || (!parity.is_empty() && parity != "required") {
            summary.skipped.push(id);
            continue;
        }
        let input = &vector["input"];
        let expected = &vector["expected"];

        let outcome = match s(input, "fixture_type") {
            "node-script" => eval_node_script_vector(&id, input, expected, &mut summary),
            "node-sighash" => eval_node_sighash_vector(&id, input, expected, &mut summary),
            "node-transaction" => eval_node_transaction_vector(&id, input, expected, &mut summary),
            _ => eval_misc_vector(&id, input, expected, &mut summary),
        };
        if debug {
            if let Some(line) = outcome {
                debug_lines.push(line);
            }
        }
    }

    std::panic::set_hook(prev_hook);

    if debug && !debug_lines.is_empty() {
        let out = std::env::var("BSV_CONFORMANCE_DEBUG").unwrap();
        std::fs::write(&out, debug_lines.join("\n")).ok();
        eprintln!("wrote {} debug lines to {}", debug_lines.len(), out);
    }

    finish_evaluation(summary);
}

/// Applies mismatch classification for node-script; returns a debug line on
/// mismatch.
fn eval_node_script_vector(
    id: &str,
    input: &Value,
    expected: &Value,
    summary: &mut Summary,
) -> Option<String> {
    let expected_valid = b(expected, "valid");
    let (got, error_message) = match catch(|| run_node_script(input)) {
        Some(Ok(v)) => (v, String::new()),
        Some(Err(msg)) => (false, msg),
        None => {
            // bsv-rs panicked on this input (robustness bug, tracked in the
            // summary + pinned). Conformance-wise a panic is a rejection.
            summary.panics.push(id.to_string());
            (false, "panicked inside bsv-rs".to_string())
        }
    };
    if got == expected_valid {
        summary.run += 1;
        summary.passed += 1;
        return None;
    }
    let flags: Vec<String> = input["flags"]
        .as_array()
        .map(|a| a.iter().map(|f| f.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let result_code = s(expected, "result");
    record_mismatch(
        id,
        &MismatchContext {
            flags: &flags,
            expected_valid,
            result_code,
            error_message: &error_message,
            locking_is_p2sh: is_p2sh_hex(s(input, "script_pubkey_hex")),
        },
        got,
        summary,
    );
    Some(format!(
        "{}\tflags={}\texpected={}\tgot={}\tresult={}\terr={}\tsig={}\tpubkey={}",
        id,
        s(input, "flags_csv"),
        expected_valid,
        got,
        result_code,
        error_message,
        s(input, "script_sig_hex"),
        s(input, "script_pubkey_hex"),
    ))
}

/// Shared mismatch recording: unsupported class, known failure, or failure.
fn record_mismatch(id: &str, ctx: &MismatchContext<'_>, got: bool, summary: &mut Summary) {
    if let Some(class) = classify_node_mismatch(ctx) {
        summary.unsupported.entry(class).or_default().push(id.to_string());
    } else if let Some((_, detail)) =
        EVALUATION_KNOWN_FAILURES.iter().find(|(k, _)| *k == id)
    {
        summary.run += 1;
        summary.known_failures_hit.push(format!(
            "{}: expected valid={}, got {} — {}",
            id, ctx.expected_valid, got, detail
        ));
    } else {
        summary.run += 1;
        summary.failures.push(format!(
            "{}: expected valid={} (result={}, flags={:?}), bsv-rs got {} (err='{}')",
            id, ctx.expected_valid, ctx.result_code, ctx.flags, got, ctx.error_message
        ));
    }
}

// ============================================================================
// sdk.scripts.evaluation — node-sighash fixtures
// ============================================================================

/// Executes one node-sighash fixture.
///
/// The fixture's `regular_hash` is the TS `TransactionSignature.format()`
/// output: BIP-143 (FORKID) preimage when the scope has SIGHASH_FORKID set and
/// the Chronicle bit is not honored, otherwise the original (legacy/OTDA)
/// digest algorithm. The fixture's `original_hash` is always OTDA.
///
/// bsv-rs implements ONLY the BIP-143/FORKID preimage
/// (`build_sighash_preimage`); it has no legacy-sighash API. So:
///   - regular_hash with an effective-FORKID scope → executed and compared.
///   - regular_hash with an effective-OTDA scope   → unsupported (counted).
///   - original_hash                                → unsupported (counted via
///     the same vector: a vector is counted "run" only when its regular hash
///     is executable; the missing original_hash check is reported once as a
///     suite-level gap, see `finish_evaluation`).
fn eval_node_sighash_vector(
    id: &str,
    input: &Value,
    expected: &Value,
    summary: &mut Summary,
) -> Option<String> {
    const SIGHASH_CHRONICLE: u32 = 0x20;
    const SIGHASH_FORKID: u32 = 0x40;

    let scope = n(input, "hash_type") as u32;
    let ignore_chronicle = input["sources"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some("teranode")))
        .unwrap_or(false);
    let has_forkid = scope & SIGHASH_FORKID != 0;
    let has_chronicle = !ignore_chronicle && (scope & SIGHASH_CHRONICLE != 0);

    if !has_forkid || has_chronicle {
        // TS format() falls back to the original transaction digest algorithm
        // (OTDA) here; bsv-rs has no legacy sighash implementation.
        summary
            .unsupported
            .entry("legacy/OTDA sighash not implemented in bsv-rs")
            .or_default()
            .push(id.to_string());
        return None;
    }

    let computed = catch(|| -> Result<String, String> {
        let raw_tx = from_hex(s(input, "tx_hex"));
        let tx = parse_transaction(&raw_tx).map_err(|e| format!("tx parse failed: {}", e))?;
        let subscript = from_hex(s(input, "script_hex"));
        // The census sighash path runs through the midstate-reuse cache API —
        // the same code path `build_sighash_preimage` wraps — so the 5,116
        // vectors pin the cache implementation directly.
        let mut sighash_cache = SighashCache::new(&tx);
        let preimage = sighash_cache
            .preimage(
                n(input, "input_index") as usize,
                &subscript,
                0, // fixture context: no amount (matches the TS runner)
                scope,
            )
            .map_err(|e| format!("sighash preimage failed: {}", e))?;
        let mut digest = sha256d(&preimage);
        digest.reverse(); // display order, as in the fixture
        Ok(to_hex(&digest))
    });
    let got = match computed {
        Some(Ok(hex)) => hex,
        Some(Err(e)) => {
            summary.run += 1;
            summary.failures.push(format!("{}: {}", id, e));
            return None;
        }
        None => {
            summary.run += 1;
            summary.panics.push(id.to_string());
            summary.failures.push(format!("{}: panicked computing sighash", id));
            return None;
        }
    };
    let want = s(expected, "regular_hash");

    summary.run += 1;
    if got == want {
        summary.passed += 1;
        None
    } else {
        summary.failures.push(format!(
            "{}: FORKID sighash mismatch: expected {}, got {}",
            id, want, got
        ));
        Some(format!("{}\tsighash expected={} got={}", id, want, got))
    }
}

// ============================================================================
// sdk.scripts.evaluation — node-transaction fixtures
// ============================================================================

/// Executes one node-transaction fixture: parse the tx, round-trip it, then
/// validate every input against its prevout. The fixtures carry node flag
/// sets; bsv-rs has no flags, so each flag set produces the same evaluation —
/// we still honor the fixture contract (valid: all inputs validate; invalid:
/// at least one input rejects).
fn eval_node_transaction_vector(
    id: &str,
    input: &Value,
    expected: &Value,
    summary: &mut Summary,
) -> Option<String> {
    let expected_valid = b(expected, "valid");
    let tx_hex = s(input, "tx_hex");

    let parsed = match catch(|| Transaction::from_hex(tx_hex)) {
        Some(p) => p,
        None => {
            summary.panics.push(id.to_string());
            Err(bsv_rs::Error::TransactionError("panicked".into()))
        }
    };
    // NOTE: `Transaction::from_hex` caches the raw bytes, so `tx.to_hex()`
    // always echoes the input. Re-serialize from the parsed fields instead so
    // a lenient parse of a malformed tx cannot round-trip vacuously.
    let reserialized = |t: &Transaction| {
        Transaction::with_params(t.version, t.inputs.clone(), t.outputs.clone(), t.lock_time)
            .to_hex()
    };
    let tx = match parsed {
        Ok(t) if reserialized(&t) == tx_hex => t,
        // Parse failure or non-canonical round-trip counts as a rejection.
        _ => {
            if expected_valid {
                summary.run += 1;
                summary
                    .failures
                    .push(format!("{}: expected-valid tx failed to parse/round-trip", id));
            } else {
                summary.run += 1;
                summary.passed += 1;
            }
            return None;
        }
    };

    let empty = vec![];
    let prevouts = input["prevouts"].as_array().unwrap_or(&empty);
    let mut rejected = 0usize;
    let mut first_error = String::new();
    let mut any_p2sh_prevout = false;

    for (vin, txin) in tx.inputs.iter().enumerate() {
        let prevout = prevouts.iter().find(|p| {
            Some(s(p, "txid")) == txin.source_txid.as_deref()
                && (n(p, "vout") as u32) == txin.source_output_index
        });
        let Some(prevout) = prevout else {
            rejected += 1;
            if first_error.is_empty() {
                first_error = format!("missing prevout fixture for input {}", vin);
            }
            continue;
        };
        any_p2sh_prevout |= is_p2sh_hex(s(prevout, "script_pubkey_hex"));
        match catch(|| validate_tx_input(&tx, vin, prevout)) {
            Some(Ok(())) => {}
            Some(Err(msg)) => {
                rejected += 1;
                if first_error.is_empty() {
                    first_error = msg;
                }
            }
            None => {
                summary.panics.push(format!("{} (input {})", id, vin));
                rejected += 1;
                if first_error.is_empty() {
                    first_error = "panicked inside bsv-rs".to_string();
                }
            }
        }
    }

    let flags: Vec<String> = input["flag_strings"]
        .as_array()
        .map(|a| {
            a.iter()
                .flat_map(|fs| fs.as_str().unwrap_or("").split(','))
                .filter(|f| !f.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let got_valid = rejected == 0;
    if got_valid == expected_valid {
        summary.run += 1;
        summary.passed += 1;
        return None;
    }
    record_mismatch(
        id,
        &MismatchContext {
            flags: &flags,
            expected_valid,
            result_code: "", // node-transaction fixtures carry no result code
            error_message: &first_error,
            locking_is_p2sh: any_p2sh_prevout,
        },
        got_valid,
        summary,
    );
    Some(format!(
        "{}\tflags={:?}\texpected={}\tgot={}\terr={}\ttx={}",
        id, flags, expected_valid, got_valid, first_error, tx_hex
    ))
}

/// Validates a single input of a parsed transaction against a prevout fixture
/// using the Spend interpreter (mirrors `Transaction::verify` wiring).
/// Err carries the interpreter's rejection message for classification.
fn validate_tx_input(tx: &Transaction, vin: usize, prevout: &Value) -> Result<(), String> {
    use bsv_rs::primitives::bsv::sighash::TxInput;

    let txin = &tx.inputs[vin];
    let locking = LockingScript::from_hex(s(prevout, "script_pubkey_hex"))
        .map_err(|e| format!("prevout script parse: {}", e))?;
    let unlocking = txin
        .unlocking_script
        .clone()
        .ok_or_else(|| "missing unlocking script".to_string())?;

    let other_inputs: Vec<TxInput> = tx
        .inputs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != vin)
        .map(|(_, inp)| TxInput {
            txid: inp.get_source_txid_bytes().unwrap_or([0u8; 32]),
            output_index: inp.source_output_index,
            script: inp
                .unlocking_script
                .as_ref()
                .map(|u| u.to_binary())
                .unwrap_or_default(),
            sequence: inp.sequence,
        })
        .collect();
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis.unwrap_or(0),
            script: o.locking_script.to_binary(),
        })
        .collect();

    let mut spend = Spend::new(SpendParams {
        source_txid: txin.get_source_txid_bytes().map_err(|e| e.to_string())?,
        source_output_index: txin.source_output_index,
        source_satoshis: n(prevout, "amount_satoshis") as u64,
        locking_script: locking,
        transaction_version: tx.version as i32,
        other_inputs,
        outputs,
        input_index: vin,
        unlocking_script: unlocking,
        input_sequence: txin.sequence,
        lock_time: tx.lock_time,
        memory_limit: None,
    });
    match spend.validate() {
        Ok(_) => Ok(()),
        Err(e) => Err(e.message),
    }
}

// ============================================================================
// sdk.scripts.evaluation — misc Script API vectors (script-001 .. script-033)
// ============================================================================

/// Executes the non-node vectors (Script parse/encode/mutate + a handful of
/// Spend evaluations). Unknown shapes are hard failures, not silent drops.
fn eval_misc_vector(
    id: &str,
    input: &Value,
    expected: &Value,
    summary: &mut Summary,
) -> Option<String> {
    let outcome = match catch(|| run_misc_vector(input, expected)) {
        Some(o) => o,
        None => {
            summary.panics.push(id.to_string());
            MiscOutcome::Fail("panicked inside bsv-rs".to_string())
        }
    };
    match outcome {
        MiscOutcome::Unsupported(class) => {
            summary.unsupported.entry(class).or_default().push(id.to_string());
            None
        }
        MiscOutcome::Pass => {
            summary.run += 1;
            summary.passed += 1;
            None
        }
        MiscOutcome::Fail(msg) => {
            summary.run += 1;
            if let Some((_, detail)) = EVALUATION_KNOWN_FAILURES.iter().find(|(k, _)| *k == id) {
                summary.known_failures_hit.push(format!("{}: {} — {}", id, msg, detail));
            } else {
                summary.failures.push(format!("{}: {}", id, msg));
            }
            Some(format!("{}\t{}", id, "misc failure"))
        }
    }
}

enum MiscOutcome {
    Pass,
    Fail(String),
    Unsupported(&'static str),
}

fn check(cond: bool, msg: String) -> MiscOutcome {
    if cond {
        MiscOutcome::Pass
    } else {
        MiscOutcome::Fail(msg)
    }
}

fn run_misc_vector(input: &Value, expected: &Value) -> MiscOutcome {
    // Spend-evaluation pairs (flags or isRelaxed shapes).
    if input.get("script_pubkey_hex").is_some() {
        if b(input, "isRelaxed") {
            // bsv-rs has no relaxed/Chronicle evaluation mode.
            return MiscOutcome::Unsupported("no isRelaxed evaluation mode in bsv-rs");
        }
        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: match LockingScript::from_hex(s(input, "script_pubkey_hex")) {
                Ok(l) => l,
                Err(e) => return MiscOutcome::Fail(format!("pubkey parse: {}", e)),
            },
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: {
                let sig = s(input, "script_sig_hex");
                if sig.is_empty() {
                    UnlockingScript::new()
                } else {
                    match UnlockingScript::from_hex(sig) {
                        Ok(u) => u,
                        Err(e) => return MiscOutcome::Fail(format!("sig parse: {}", e)),
                    }
                }
            },
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
        });
        let got = spend.validate().unwrap_or(false);
        let want = b(expected, "valid");
        return check(got == want, format!("expected valid={}, got {}", want, got));
    }

    // Script.fromHex parse vectors.
    if let Some(hex) = input.get("hex").and_then(Value::as_str) {
        let parsed = Script::from_hex(hex);
        if b(expected, "throws") {
            return check(parsed.is_err(), format!("expected parse error for '{}'", hex));
        }
        let script = match parsed {
            Ok(p) => p,
            Err(e) => return MiscOutcome::Fail(format!("parse '{}': {}", hex, e)),
        };
        return verify_chunk_expectations(&script, expected);
    }

    // Script.fromBinary parse vectors.
    if let Some(bin) = input.get("binary").and_then(Value::as_array) {
        let bytes: Vec<u8> = bin.iter().map(|x| x.as_u64().unwrap_or(0) as u8).collect();
        let script = match Script::from_binary(&bytes) {
            Ok(p) => p,
            Err(e) => return MiscOutcome::Fail(format!("from_binary: {}", e)),
        };
        return verify_chunk_expectations(&script, expected);
    }

    // P2PKH locking script construction.
    if s(input, "type") == "P2PKH_lock" {
        let hash = from_hex(s(input, "pubkey_hash_hex"));
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&[0x88, 0xac]);
        let script = match Script::from_binary(&bytes) {
            Ok(p) => p,
            Err(e) => return MiscOutcome::Fail(format!("from_binary: {}", e)),
        };
        let asm = script.to_asm();
        if script.to_hex() != s(expected, "hex") {
            return MiscOutcome::Fail(format!("hex: got {}", script.to_hex()));
        }
        if bytes.len() as i64 != n(expected, "byte_length") {
            return MiscOutcome::Fail(format!("byte_length: got {}", bytes.len()));
        }
        return check(
            asm.starts_with(s(expected, "asm_prefix")) && asm.ends_with(s(expected, "asm_suffix")),
            format!("asm affixes: got '{}'", asm),
        );
    }

    // writeBin encoding vectors (data_fill_byte / findAndDelete use fill bytes).
    if input.get("data_length_bytes").is_some() && s(input, "operation") != "findAndDelete" {
        let len = n(input, "data_length_bytes") as usize;
        let fill = parse_fill_byte(s(input, "data_fill_byte"));
        let mut script = Script::new();
        script.write_bin(&vec![fill; len]);
        let got = script.chunks()[0].op as i64;
        return check(
            got == n(expected, "chunk_0_op"),
            format!("chunk_0_op: expected {}, got {}", n(expected, "chunk_0_op"), got),
        );
    }

    // Named operations.
    match s(input, "operation") {
        "writeBn" => {
            let mut script = Script::new();
            script.write_number(n(input, "value"));
            let got = script.chunks()[0].op as i64;
            return check(
                got == n(expected, "chunk_0_op"),
                format!("writeBn({}): chunk op {}", n(input, "value"), got),
            );
        }
        "writeBn_range" => {
            let values = input["values"].as_array().cloned().unwrap_or_default();
            let opcodes = expected["opcodes"].as_array().cloned().unwrap_or_default();
            for (value, opcode) in values.iter().zip(opcodes.iter()) {
                let mut script = Script::new();
                script.write_number(value.as_i64().unwrap_or(0));
                if script.chunks()[0].op as i64 != opcode.as_i64().unwrap_or(-1) {
                    return MiscOutcome::Fail(format!(
                        "writeBn({}): expected op {}, got {}",
                        value,
                        opcode,
                        script.chunks()[0].op
                    ));
                }
            }
            return MiscOutcome::Pass;
        }
        "findAndDelete" => {
            // Build: [PUSHDATA1 data] [OP_1] [PUSHDATA1 data], delete the push.
            let len = n(input, "data_length_bytes") as usize;
            let fill = parse_fill_byte(s(input, "fill_byte"));
            let data = vec![fill; len];
            let mut target = Script::new();
            target.write_bin(&data);
            let mut source = Script::new();
            source.write_bin(&data);
            if b(input, "source_has_trailing_op1") {
                source.write_opcode(op::OP_1);
            }
            source.write_bin(&data);
            source.find_and_delete(&target);
            let chunks = source.chunks();
            if chunks.len() as i64 != n(expected, "remaining_chunks_count") {
                return MiscOutcome::Fail(format!("remaining chunks: {}", chunks.len()));
            }
            return check(
                chunks[0].op as i64 == n(expected, "remaining_chunk_0_op"),
                format!("remaining chunk op: {}", chunks[0].op),
            );
        }
        _ => {}
    }

    // ASM manipulation vectors.
    if let Some(asm) = input.get("script_asm").and_then(Value::as_str) {
        let mut script = match Script::from_asm(asm) {
            Ok(p) => p,
            Err(e) => return MiscOutcome::Fail(format!("from_asm: {}", e)),
        };
        if let Some(append) = input.get("append_asm").and_then(Value::as_str) {
            let other = match Script::from_asm(append) {
                Ok(p) => p,
                Err(e) => return MiscOutcome::Fail(format!("from_asm append: {}", e)),
            };
            script.write_script(&other);
            let got = script.to_asm();
            return check(
                got == s(expected, "result_asm"),
                format!("result_asm: got '{}'", got),
            );
        }
        if input.get("index").is_some() {
            let index = n(input, "index") as usize;
            let new_op = n(input, "new_op") as u8;
            script.set_chunk_opcode(index, new_op);
            let key = format!("chunk_{}_op", index);
            let want = expected.get(&key).and_then(Value::as_i64).unwrap_or(-1);
            return check(
                script.chunks()[index].op as i64 == want,
                format!("chunk op after set: {}", script.chunks()[index].op),
            );
        }
    }

    MiscOutcome::Fail("unrecognized misc vector shape".to_string())
}

fn verify_chunk_expectations(script: &Script, expected: &Value) -> MiscOutcome {
    let chunks = script.chunks();
    if let Some(count) = expected.get("chunks_count").and_then(Value::as_i64) {
        if chunks.len() as i64 != count {
            return MiscOutcome::Fail(format!("chunks_count: got {}", chunks.len()));
        }
    }
    if let Some(op0) = expected.get("chunk_0_op").and_then(Value::as_i64) {
        if chunks.is_empty() || chunks[0].op as i64 != op0 {
            return MiscOutcome::Fail(format!("chunk_0_op: got {:?}", chunks.first().map(|c| c.op)));
        }
    }
    if let Some(data0) = expected.get("chunk_0_data").and_then(Value::as_array) {
        let want: Vec<u8> = data0.iter().map(|x| x.as_u64().unwrap_or(0) as u8).collect();
        let got = chunks.first().and_then(|c| c.data.clone()).unwrap_or_default();
        if got != want {
            return MiscOutcome::Fail(format!("chunk_0_data: got {:?}", got));
        }
    }
    if let Some(round) = expected.get("hex_roundtrip").and_then(Value::as_str) {
        if script.to_hex() != round {
            return MiscOutcome::Fail(format!("hex_roundtrip: got {}", script.to_hex()));
        }
    }
    MiscOutcome::Pass
}

fn parse_fill_byte(text: &str) -> u8 {
    let trimmed = text.trim_start_matches("0x");
    u8::from_str_radix(trimmed, 16).unwrap_or(0)
}

// ============================================================================
// Pinned expectations for the evaluation suite
// ============================================================================

/// Asserts summary integrity for `sdk.scripts.evaluation`.
///
/// The per-class unsupported counts are PINNED: if the corpus or bsv-rs
/// changes behavior, these assertions fire and force a human review. This is
/// the "enumerated allowlist" — silent drops are impossible because
/// run + unsupported + skipped must equal the (also pinned) total.
fn finish_evaluation(summary: Summary) {
    summary.print("sdk.scripts.evaluation");

    // Every mismatch must be classified, known, or fail loudly.
    assert!(
        summary.failures.is_empty(),
        "unexplained conformance failures:\n{}",
        summary.failures.join("\n")
    );

    // KNOWN_FAILURES must be hit exactly (a fixed bug must be removed here).
    assert_eq!(
        summary.known_failures_hit.len(),
        EVALUATION_KNOWN_FAILURES.len(),
        "KNOWN_FAILURES drift: hit={:?}, pinned={:?}",
        summary.known_failures_hit,
        EVALUATION_KNOWN_FAILURES
    );

    // Pinned unsupported classes (populated from the audited first run).
    let pins: BTreeMap<&str, usize> = EVALUATION_UNSUPPORTED_PINS.iter().cloned().collect();
    let counts: BTreeMap<&str, usize> = summary
        .unsupported
        .iter()
        .map(|(k, v)| (*k, v.len()))
        .collect();
    assert_eq!(
        counts, pins,
        "unsupported-class drift — audit the new/removed vectors before repinning"
    );

    // No silent drops: every vector is accounted for.
    assert_eq!(
        summary.run + summary.unsupported_total() + summary.skipped.len(),
        5116,
        "vector accounting mismatch"
    );
    // 2 × skip:true + 35 × vector-level parity_class:"intended" (the
    // full-transaction-consensus tx_invalid fixtures the reference TS runner
    // also skips).
    assert_eq!(summary.skipped.len(), 37, "corpus-skipped vectors");
    assert_eq!(summary.passed + summary.known_failures_hit.len(), summary.run);
    // Robustness-bug panics (see EVALUATION_KNOWN_FAILURES BUG 2). A new
    // panic anywhere in the corpus fails here even if its valid/invalid
    // outcome happens to match.
    assert!(
        summary.panics.is_empty(),
        "bsv-rs panicked on vectors: {:?}",
        summary.panics
    );
}

/// Pinned per-class unsupported counts for sdk.scripts.evaluation.
/// Audited empirically against corpus stats (5,116 vectors, META.json
/// last_updated 2026-05-19) — see classify_node_mismatch for what each class
/// means. THESE ARE NOT FAILURES — they are enumerated capability gaps of
/// bsv-rs's flagless, always-strict, post-genesis interpreter and its
/// FORKID-only sighash. Any drift (corpus update, SDK behavior change) fails
/// the assert and forces a re-audit.
const EVALUATION_UNSUPPORTED_PINS: &[(&str, usize)] = &[
    ("UTXO_AFTER_CHRONICLE opcode semantics not implemented in bsv-rs", 5),
    // 2026-07-09 repin (225 -> 195): Spend now mirrors ts-sdk's version-based
    // relaxed mode (tx version > 1 disables CLEANSTACK/LOW_S/MINIMALDATA).
    // 30 version-2 fixtures that previously died at the always-on clean-stack
    // check now execute; 27 pass conformantly (moved to `run`) and 3 progress
    // to the CLTV/CSV gap below (5 -> 8). Zero new mismatches.
    ("bsv-rs always enforces CLEANSTACK (no off switch)", 195),
    ("bsv-rs always enforces LOW_S (no off switch)", 9),
    ("bsv-rs always enforces MINIMALDATA (no off switch)", 181),
    ("bsv-rs always enforces NULLDUMMY (no off switch)", 4),
    ("bsv-rs always enforces SIGPUSHONLY (push-only unlocking scripts)", 319),
    ("bsv-rs always enforces strict DER/pubkey encodings (no off switch)", 54),
    ("bsv-rs always requires SIGHASH_FORKID (cannot reject FORKID-bit sigs)", 6),
    ("bsv-rs always requires SIGHASH_FORKID (legacy-signature fixtures)", 36),
    ("flag-dependent ELSE/ENDIF structure rules not expressible in bsv-rs", 30),
    ("flag-dependent opcode set (pre-genesis/Chronicle) not expressible in bsv-rs", 12),
    // NOTE: this is HALF the sighash corpus. The fixture's `regular_hash`
    // uses the original (legacy) digest algorithm whenever the FORKID bit is
    // absent (or the Chronicle bit applies), and `original_hash` is ALWAYS
    // legacy. bsv-rs has no legacy-sighash API at all
    // (`build_sighash_preimage` is BIP-143-only), so the 756 executed
    // sighash vectors cover the FORKID `regular_hash` side only.
    ("legacy/OTDA sighash not implemented in bsv-rs", 1244),
    ("no CLTV/CSV enforcement in bsv-rs (post-genesis NOPs)", 8),
    ("no DISCOURAGE_UPGRADABLE_NOPS flag in bsv-rs", 20),
    ("no MINIMALIF flag in bsv-rs", 6),
    ("no P2SH redeem-script evaluation in bsv-rs (post-genesis rules)", 72),
    ("no isRelaxed evaluation mode in bsv-rs", 3),
    ("pre-genesis OP_RETURN semantics (bsv-rs implements post-genesis skip)", 34),
    ("pre-genesis limits (bsv-rs runs post-genesis/unlimited rules)", 14),
];

// ============================================================================
// Script-domain regression vectors
// ============================================================================

/// Builds a minimally-encoded push chunk for `bytes` (OP_0 / OP_1..16 /
/// OP_1NEGATE / direct push), as required by the always-on MINIMALDATA rule.
fn minimal_push(bytes: &[u8]) -> ScriptChunk {
    if bytes.is_empty() {
        return ScriptChunk { op: op::OP_0, data: None };
    }
    if bytes.len() == 1 {
        if (1..=16).contains(&bytes[0]) {
            return ScriptChunk { op: op::OP_1 + bytes[0] - 1, data: None };
        }
        if bytes[0] == 0x81 {
            return ScriptChunk { op: op::OP_1NEGATE, data: None };
        }
    }
    ScriptChunk { op: bytes.len() as u8, data: Some(bytes.to_vec()) }
}

/// Evaluates `<value> <shift> OP_LSHIFT/OP_RSHIFT <expected> OP_EQUAL` through
/// the real Spend interpreter, so the regression exercises bsv-rs's actual
/// opcode implementation (not a harness reimplementation).
fn shift_via_interpreter(value: &[u8], shift_bits: i64, shift_op: u8, want: &[u8]) -> bool {
    let unlocking = UnlockingScript::from_chunks(vec![minimal_push(value)]);
    let shift_num = {
        let mut script = Script::new();
        script.write_number(shift_bits);
        script.chunks()[0].clone()
    };
    let locking = LockingScript::from_script(Script::from_chunks(vec![
        shift_num,
        ScriptChunk { op: shift_op, data: None },
        minimal_push(want),
        ScriptChunk { op: op::OP_EQUAL, data: None },
    ]));
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
    });
    spend.validate().unwrap_or(false)
}

/// KNOWN SDK BUGS hit by the script regression corpus — REAL bsv-rs failures,
/// isolated here (NOT papered over) and asserted to not grow. Fixing the SDK
/// makes the corresponding entry stale, which also fails until it is removed.
///
/// *** BUG (ts-sdk#493 class): bsv-rs OP_LSHIFT does not truncate the result
/// to the input byte length. `Spend` shifts via
/// `BigNumber::mul(1<<n)` + `to_bytes_be(buf.len())`, and `to_bytes_be`
/// PANICS ("BigNumber requires N bytes, but only M requested") whenever the
/// shifted value overflows the original width, instead of dropping the high
/// bits like the node and the fixed ts-sdk/go-sdk do. src/script/spend.rs
/// (OP_LSHIFT arm) + src/primitives/bignum.rs::to_bytes_be. ***
const REGRESSION_KNOWN_FAILURES: &[(&str, &str)] = &[
    // (lshift-truncation.0001/.0003 FIXED 2026-07-08: OP_LSHIFT/OP_RSHIFT are
    // now width-preserving bitwise byte shifts — no BigNumber, no panic, no
    // 63-bit clamp. src/script/spend.rs.)
    // *** BUG (ASM parity): ScriptChunk::to_asm renders OP_0 as "0" (and
    // OP_1NEGATE as "-1"), while ts-sdk renders "OP_0"/"OP_1NEGATE". Scripts
    // round-tripped through ASM across the two SDKs disagree.
    // src/script/chunk.rs::to_asm. ***
    (
        "regression.script.writebin-empty.0001",
        "writeBin([]).toASM() must be 'OP_0'; bsv-rs renders '0' (ts-sdk ASM parity bug)",
    ),
];

#[test]
fn conformance_scripts_regressions() {
    let Some(dir) = corpus_dir() else { return };
    let mut summary = Summary::default();
    let prev_hook = silence_panics();

    // script-lshift-truncation + script-shift-endianness: OP_LSHIFT/OP_RSHIFT
    // byte-order and truncation semantics through the interpreter.
    for file in ["script-lshift-truncation.json", "script-shift-endianness.json"] {
        let json = load_json(&dir.join("vectors/regressions").join(file));
        for vector in json["vectors"].as_array().expect("vectors") {
            let id = s(vector, "id");
            let input = &vector["input"];
            let expected = &vector["expected"];
            let shift_op = match s(input, "operation") {
                "op_lshift" => op::OP_LSHIFT,
                "op_rshift" => op::OP_RSHIFT,
                other => panic!("{}: unknown shift op {}", id, other),
            };
            let value = from_hex(s(input, "value_hex"));
            let want = from_hex(s(expected, "result_hex"));
            assert_eq!(
                want.len() as i64,
                n(expected, "result_length_bytes"),
                "{}: corpus self-consistency",
                id
            );
            summary.run += 1;
            let shift_bits = n(input, "shift_bits");
            let result = catch(|| shift_via_interpreter(&value, shift_bits, shift_op, &want));
            if result.is_none() {
                summary.panics.push(id.to_string());
            }
            match result {
                Some(true) => summary.passed += 1,
                got => {
                    let detail = format!(
                        "{}: {} value={} shift={} expected {} — bsv-rs {}",
                        id,
                        s(input, "operation"),
                        s(input, "value_hex"),
                        shift_bits,
                        s(expected, "result_hex"),
                        if got.is_none() { "PANICKED (BigNumber::to_bytes_be overflow)" } else { "produced a different result" }
                    );
                    if REGRESSION_KNOWN_FAILURES.iter().any(|(k, _)| *k == id) {
                        summary.known_failures_hit.push(detail);
                    } else {
                        summary.failures.push(detail);
                    }
                }
            }
        }
    }

    // script-writebin-empty: writeBin([]) must encode OP_0.
    let json = load_json(&dir.join("vectors/regressions/script-writebin-empty.json"));
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        let input = &vector["input"];
        let expected = &vector["expected"];
        let data = from_hex(s(input, "data_hex"));
        let mut script = Script::new();
        script.write_bin(&data);
        summary.run += 1;
        let ok = match s(input, "operation") {
            "script_writeBin_toASM" => script.to_asm() == s(expected, "asm"),
            "script_writeBin_toHex" => script.to_hex() == s(expected, "hex"),
            other => panic!("{}: unknown operation {}", id, other),
        };
        if ok {
            summary.passed += 1;
        } else {
            let detail = format!(
                "{}: writeBin asm='{}' hex='{}'",
                id,
                script.to_asm(),
                script.to_hex()
            );
            if REGRESSION_KNOWN_FAILURES.iter().any(|(k, _)| *k == id) {
                summary.known_failures_hit.push(detail);
            } else {
                summary.failures.push(detail);
            }
        }
    }

    // script-fromasm-numeric-token: hex-looking ASM tokens are data pushes.
    let json = load_json(&dir.join("vectors/regressions/script-fromasm-numeric-token.json"));
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        assert_eq!(s(&vector["input"], "operation"), "fromASM_toHex", "{}", id);
        let asm = s(&vector["input"], "asm");
        summary.run += 1;
        match Script::from_asm(asm) {
            Ok(script) if script.to_hex() == s(&vector["expected"], "hex") => summary.passed += 1,
            Ok(script) => summary.failures.push(format!(
                "{}: fromASM('{}') expected {}, got {}",
                id,
                asm,
                s(&vector["expected"], "hex"),
                script.to_hex()
            )),
            Err(e) => summary
                .failures
                .push(format!("{}: fromASM('{}') failed: {}", id, asm, e)),
        }
    }

    std::panic::set_hook(prev_hook);
    summary.print("script regressions");
    assert!(
        summary.failures.is_empty(),
        "script regression failures:\n{}",
        summary.failures.join("\n")
    );
    assert_eq!(summary.run, 11, "regression vector count changed — review");
    assert_eq!(
        summary.known_failures_hit.len(),
        REGRESSION_KNOWN_FAILURES.len(),
        "KNOWN_FAILURES drift (fixed bug? new bug?): {:?}",
        summary.known_failures_hit
    );
    assert_eq!(summary.passed + summary.known_failures_hit.len(), summary.run);
}
