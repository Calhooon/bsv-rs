//! Cross-language conformance vectors: MerklePath/BUMP, transaction
//! serialization, BEEF, and the transactions-domain regression corpus.
//!
//! Reads the shared conformance corpus maintained in the `ts-stack`
//! repository:
//!   - vectors/sdk/transactions/merkle-path.json     (BRC-74 BUMP)
//!   - vectors/sdk/transactions/serialization.json   (tx / EF / BEEF)
//!   - vectors/regressions/merkle-path-odd-node.json (go-sdk#298)
//!   - vectors/regressions/beef-v2-txid-panic.json   (go-sdk#306)
//!   - vectors/regressions/beef-isvalid-hydration.json (go-sdk#167)
//!   - vectors/regressions/tx-sequence-zero-sighash.json (ts-sdk#371)
//!   - vectors/regressions/fee-model-mismatch.json   (go-sdk#267)
//!
//! Corpus location: `$BSV_CONFORMANCE_DIR`, defaulting to
//! `../ts-stack/conformance` relative to the crate root. Missing corpus →
//! SKIP (pass with an eprintln). Present corpus → every vector is executed or
//! explicitly counted as unsupported with a reason; totals are pinned.
#![cfg(feature = "transaction")]

use serde_json::Value;
use std::path::PathBuf;

use bsv_rs::primitives::bsv::sighash::{build_sighash_preimage, SighashParams, TxInput};
use bsv_rs::primitives::sha256d;
use bsv_rs::script::{LockingScript, Script, UnlockingScript};
use bsv_rs::transaction::{
    Beef, FeeModel, MerklePath, SatoshisPerKilobyte, Transaction, TransactionInput,
    TransactionOutput, SIGHASH_ALL, SIGHASH_FORKID,
};

// ============================================================================
// Corpus location (shared convention with conformance_scripts.rs)
// ============================================================================

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

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn n(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn from_hex(hex: &str) -> Vec<u8> {
    bsv_rs::primitives::from_hex(hex).unwrap_or_else(|e| panic!("bad hex '{}': {}", hex, e))
}

fn to_hex(bytes: &[u8]) -> String {
    bsv_rs::primitives::to_hex(bytes)
}

/// Test outcome collector: failures accumulate and fail at the end so a
/// single mismatch cannot hide the rest of the report.
#[derive(Default)]
struct Suite {
    run: usize,
    passed: usize,
    unsupported: Vec<(String, &'static str)>,
    skipped: Vec<String>,
    known_failures_hit: Vec<String>,
    failures: Vec<String>,
}

impl Suite {
    fn check(&mut self, id: &str, cond: bool, detail: String) {
        self.run += 1;
        if cond {
            self.passed += 1;
        } else {
            self.failures.push(format!("{}: {}", id, detail));
        }
    }

    fn unsupported(&mut self, id: &str, reason: &'static str) {
        self.unsupported.push((id.to_string(), reason));
    }

    fn finish(self, name: &str, expect_run: usize, expect_unsupported: usize, expect_known: usize) {
        println!("=== {} summary ===", name);
        println!(
            "total={} run={} passed={} unsupported={} skipped={} known_failures={} failures={}",
            self.run + self.unsupported.len() + self.skipped.len(),
            self.run,
            self.passed,
            self.unsupported.len(),
            self.skipped.len(),
            self.known_failures_hit.len(),
            self.failures.len()
        );
        for (id, reason) in &self.unsupported {
            println!("  unsupported: {} — {}", id, reason);
        }
        for id in &self.skipped {
            println!("  skipped (corpus-directed): {}", id);
        }
        for f in &self.known_failures_hit {
            println!("  KNOWN FAILURE (SDK divergence, tracked): {}", f);
        }
        for f in &self.failures {
            println!("  FAILURE: {}", f);
        }
        assert!(self.failures.is_empty(), "{} failures:\n{}", name, self.failures.join("\n"));
        assert_eq!(self.run, expect_run, "{}: executed-vector count drift", name);
        assert_eq!(
            self.unsupported.len(),
            expect_unsupported,
            "{}: unsupported allowlist drift",
            name
        );
        assert_eq!(
            self.known_failures_hit.len(),
            expect_known,
            "{}: KNOWN_FAILURES drift (fixed bug? new bug?): {:?}",
            name,
            self.known_failures_hit
        );
        assert_eq!(self.passed + self.known_failures_hit.len(), self.run);
    }
}

/// Computes a merkle root from display-order txids with the Bitcoin
/// odd-count duplicate rule, using the SDK's sha256d. Mirrors the reference
/// runner's `computeMerkleRootFromDisplayTxids` for full-block fixtures
/// (bsv-rs has no full-block tree builder API).
fn merkle_root_from_display_txids(txids: &[&str]) -> String {
    assert!(!txids.is_empty());
    let mut level: Vec<Vec<u8>> = txids
        .iter()
        .map(|t| {
            let mut b = from_hex(t);
            b.reverse();
            b
        })
        .collect();
    while level.len() > 1 {
        if level.len() % 2 != 0 {
            level.push(level.last().unwrap().clone());
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut cat = pair[0].clone();
                cat.extend_from_slice(&pair[1]);
                sha256d(&cat).to_vec()
            })
            .collect();
    }
    let mut root = level.remove(0);
    root.reverse();
    to_hex(&root)
}

// ============================================================================
// sdk.transactions.merklepath (merkle-path.json, 16 vectors)
// ============================================================================

/// KNOWN SDK DIVERGENCES in the merkle-path suite — real bsv-rs gaps,
/// isolated (NOT papered over) and asserted to not grow.
///
/// *** BUG (parity with ts-sdk MerklePath.computeRoot): for a compound BUMP
/// whose txids all sit at level 0 with offsets implying a taller tree
/// (mp-compound-001: 4 txids, offsets 0..3, one stored level), ts-sdk derives
/// the effective tree height from the maximum level-0 offset
/// (`Math.max(path.length, 32 - clz32(maxOffset))`) and computes missing
/// upper levels. bsv-rs `MerklePath::compute_root` only climbs
/// `self.path.len()` levels, so the four txids yield two different "roots"
/// and `MerklePath::from_hex` rejects the whole BUMP with "Mismatched roots".
/// src/transaction/merkle_path.rs (compute_root / validation). ***
const MP_KNOWN_FAILURES: &[(&str, &str)] = &[(
    "mp-compound-001",
    "single-level compound BUMP: bsv-rs lacks ts-sdk's effective-tree-height derivation; \
     from_hex fails with 'Mismatched roots'",
)];

#[test]
fn conformance_merkle_path() {
    let Some(dir) = corpus_dir() else { return };
    let file = load_json(&dir.join("vectors/sdk/transactions/merkle-path.json"));
    let vectors = file["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 16, "merkle-path.json vector count changed — review");

    let mut suite = Suite::default();
    for vector in vectors {
        let id = s(vector, "id");
        let input = &vector["input"];
        let expected = &vector["expected"];
        match id {
            "mp-parse-001" => {
                let mp = MerklePath::from_hex(s(input, "bump_hex")).expect(id);
                suite.check(
                    id,
                    mp.block_height as i64 == n(expected, "block_height")
                        && mp.path.len() as i64 == n(expected, "path_levels")
                        && mp.path[0].len() as i64 == n(expected, "path_level0_length"),
                    format!(
                        "height={} levels={} level0={}",
                        mp.block_height,
                        mp.path.len(),
                        mp.path[0].len()
                    ),
                );
            }
            "mp-serialize-001" => {
                let mp = MerklePath::from_hex(s(input, "bump_hex")).expect(id);
                let got = mp.to_hex();
                suite.check(id, got == s(expected, "toHex"), format!("to_hex={}", got));
            }
            "mp-computeroot-001" | "mp-computeroot-002" | "mp-computeroot-003"
            | "mp-single-tx-001" => {
                let mp = MerklePath::from_hex(s(input, "bump_hex")).expect(id);
                let root = mp.compute_root(Some(s(input, "txid"))).expect(id);
                let height_ok = !expected.get("block_height").is_some()
                    || mp.block_height as i64 == n(expected, "block_height");
                suite.check(
                    id,
                    root == s(expected, "merkle_root") && height_ok,
                    format!("root={} height={}", root, mp.block_height),
                );
            }
            "mp-compound-001" => {
                let mut ok = true;
                let mut detail = String::new();
                match MerklePath::from_hex(s(input, "bump_hex")) {
                    Ok(mp) => {
                        ok &= mp.to_hex() == s(expected, "serialized_bump_hex");
                        let txids: Vec<&str> = input["txids_at_level_0"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|t| t.as_str().unwrap())
                            .collect();
                        for (i, txid) in txids.iter().enumerate() {
                            let want = s(expected, &format!("merkle_root_for_tx{}", i));
                            match mp.compute_root(Some(txid)) {
                                Ok(root) if root == want => {}
                                Ok(root) => {
                                    ok = false;
                                    detail = format!("tx{} root={} want={}", i, root, want);
                                }
                                Err(e) => {
                                    ok = false;
                                    detail = format!("tx{} compute_root err: {}", i, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        ok = false;
                        detail = format!("from_hex err: {}", e);
                    }
                }
                suite.run += 1;
                if ok {
                    suite.passed += 1;
                } else if let Some((_, known)) =
                    MP_KNOWN_FAILURES.iter().find(|(k, _)| *k == id)
                {
                    suite.known_failures_hit.push(format!("{}: {} — {}", id, detail, known));
                } else {
                    suite.failures.push(format!("{}: {}", id, detail));
                }
            }
            "mp-coinbase-001" => {
                let mp = MerklePath::from_coinbase_txid(
                    s(input, "txid"),
                    n(input, "height") as u32,
                );
                let root = mp.compute_root(Some(s(input, "txid"))).expect(id);
                suite.check(
                    id,
                    mp.to_hex() == s(expected, "bump_hex")
                        && mp.block_height as i64 == n(expected, "block_height")
                        && root == s(expected, "merkle_root"),
                    format!("hex={} height={} root={}", mp.to_hex(), mp.block_height, root),
                );
            }
            "mp-block125632-001" | "mp-extract-001" => {
                // Full-block root computation. bsv-rs has no full-block tree
                // builder; fold with the SDK's sha256d exactly like the
                // reference runner's computeMerkleRootFromDisplayTxids.
                let key = if id == "mp-extract-001" { "full_block_txids" } else { "txids" };
                let txids: Vec<&str> = input[key]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| t.as_str().unwrap())
                    .collect();
                let root = merkle_root_from_display_txids(&txids);
                // mp-extract-001's `extracted_smaller_than_full` mirrors the
                // reference runner: a proof for one txid is smaller than the
                // full block list (trivially true for >=2 txids).
                suite.check(
                    id,
                    root == s(expected, "merkle_root") && txids.len() >= 2,
                    format!("root={}", root),
                );
            }
            "mp-block125632-002" => {
                suite.unsupported(
                    id,
                    "not executable: fixture supplies a partial proof shape the reference TS \
                     runner also no-ops (and its proof_level1_hash is 65 hex chars — malformed)",
                );
            }
            "mp-block125632-003" => {
                suite.unsupported(
                    id,
                    "not executable: input carries only txid+height (no proof data); the \
                     reference TS runner also no-ops this shape",
                );
            }
            "mp-combine-001" => {
                let mut mp = MerklePath::from_hex(s(input, "combined_bump_hex")).expect(id);
                let mut ok = mp.to_hex() == s(expected, "serialized_bump_hex");
                let mut detail = format!("to_hex={}", mp.to_hex());
                for key in ["txid_tx2", "txid_tx5", "txid_tx8"] {
                    match mp.compute_root(Some(s(input, key))) {
                        Ok(root) if root == s(expected, "merkle_root") => {}
                        Ok(root) => {
                            ok = false;
                            detail = format!("{} root={}", key, root);
                        }
                        Err(e) => {
                            ok = false;
                            detail = format!("{} err={}", key, e);
                        }
                    }
                }
                // combine() round-trip: combining with itself must not change
                // the serialized form.
                let clone = mp.clone();
                if mp.combine(&clone).is_ok() && mp.to_hex() != s(expected, "serialized_bump_hex")
                {
                    ok = false;
                    detail = format!("post-combine to_hex={}", mp.to_hex());
                }
                suite.check(id, ok, detail);
            }
            "mp-findleaf-001" => {
                // leaf1.duplicate=true overrides leaf1.hash: parent =
                // hash256(leaf0 || leaf0), display-reversed.
                let leaf0 = from_hex(s(input, "leaf0_hash"));
                let mut cat = leaf0.clone();
                cat.extend_from_slice(&leaf0);
                let mut parent = sha256d(&cat).to_vec();
                parent.reverse();
                suite.check(
                    id,
                    to_hex(&parent) == s(expected, "computed_hash"),
                    format!("parent={}", to_hex(&parent)),
                );
            }
            "mp-extract-002" | "mp-extract-003" => {
                suite.unsupported(
                    id,
                    "no MerklePath::extract() API in bsv-rs (the reference TS runner also \
                     no-ops these error-case shapes)",
                );
            }
            other => panic!("unrecognized merkle-path vector id '{}' — new corpus vector?", other),
        }
    }
    // 12 executed (1 of them a pinned KNOWN failure) + 4 enumerated-
    // unsupported = 16 total, all accounted for.
    suite.finish("sdk.transactions.merklepath", 12, 4, MP_KNOWN_FAILURES.len());
}

// ============================================================================
// sdk.transactions.serialization (serialization.json, 15 vectors)
// ============================================================================

/// Re-serializes from parsed fields — `Transaction::from_hex` caches raw
/// bytes, so `tx.to_hex()` echoes the input and cannot catch lenient parses.
fn reserialize(tx: &Transaction) -> String {
    Transaction::with_params(tx.version, tx.inputs.clone(), tx.outputs.clone(), tx.lock_time)
        .to_hex()
}

#[test]
fn conformance_serialization() {
    let Some(dir) = corpus_dir() else { return };
    let file = load_json(&dir.join("vectors/sdk/transactions/serialization.json"));
    let vectors = file["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 15, "serialization.json vector count changed — review");

    let mut suite = Suite::default();
    for vector in vectors {
        let id = s(vector, "id");
        let input = &vector["input"];
        let expected = &vector["expected"];
        match id {
            "tx-001" | "tx-002" => {
                let tx = Transaction::from_hex(s(input, "raw_hex")).expect(id);
                let mut ok = tx.version as i64 == n(expected, "version")
                    && tx.inputs.len() as i64 == n(expected, "inputs_count")
                    && tx.outputs.len() as i64 == n(expected, "outputs_count")
                    && tx.lock_time as i64 == n(expected, "locktime")
                    && reserialize(&tx) == s(expected, "raw_hex_roundtrip");
                if !s(expected, "txid").is_empty() {
                    ok &= tx.id() == s(expected, "txid");
                }
                suite.check(
                    id,
                    ok,
                    format!("version={} txid={} roundtrip={}", tx.version, tx.id(), reserialize(&tx)),
                );
            }
            "tx-003" => {
                let mut beef = Beef::from_binary(&from_hex(s(input, "beef_hex"))).expect(id);
                let root = beef.bumps[0].compute_root(None).expect(id);
                // Also require overall structural validity of the parsed BEEF.
                let valid = beef.is_valid(false);
                suite.check(
                    id,
                    root == s(expected, "merkle_root") && valid,
                    format!("root={} valid={}", root, valid),
                );
            }
            "tx-004" => {
                let tx = Transaction::from_hex_ef(s(input, "ef_hex")).expect(id);
                suite.check(
                    id,
                    tx.inputs.len() as i64 == n(expected, "inputs_count")
                        && tx.outputs.len() as i64 == n(expected, "outputs_count"),
                    format!("inputs={} outputs={}", tx.inputs.len(), tx.outputs.len()),
                );
            }
            "tx-005" => {
                let tx = Transaction::new();
                suite.check(
                    id,
                    tx.version as i64 == n(expected, "version")
                        && tx.inputs.is_empty()
                        && tx.outputs.is_empty()
                        && tx.lock_time as i64 == n(expected, "locktime"),
                    format!("version={} locktime={}", tx.version, tx.lock_time),
                );
            }
            "tx-006" => {
                // Non-atomic BEEF V1 into from_atomic_beef must error.
                // (Assert throws-ness only — never error-string parity.)
                let result = Transaction::from_atomic_beef(&from_hex(s(input, "beef_hex")));
                suite.check(id, result.is_err(), "expected Err for non-atomic BEEF".to_string());
            }
            "tx-007" | "tx-009" | "tx-010" => {
                suite.unsupported(
                    id,
                    "TS runtime-validation fixture (addInput/addOutput with missing/negative \
                     fields) — unrepresentable in bsv-rs's typed API (Option<String> txid is \
                     checked at spend/serialize time; satoshis is u64)",
                );
            }
            "tx-008" => {
                let input_default = TransactionInput::new(
                    s(input, "source_txid").to_string(),
                    n(input, "source_output_index") as u32,
                );
                suite.check(
                    id,
                    input_default.sequence as i64 == n(expected, "sequence"),
                    format!("sequence={}", input_default.sequence),
                );
            }
            "tx-011" => {
                let hash_hex = Transaction::new().hash_hex();
                suite.check(
                    id,
                    hash_hex.len() as i64 == n(expected, "hash_length_chars"),
                    format!("len={}", hash_hex.len()),
                );
            }
            "tx-012" => {
                let hash = Transaction::new().hash();
                suite.check(
                    id,
                    hash.len() as i64 == n(expected, "id_length_bytes"),
                    format!("len={}", hash.len()),
                );
            }
            "tx-013" => {
                let mp = MerklePath::from_hex(s(input, "bump_hex")).expect(id);
                suite.check(
                    id,
                    mp.block_height as i64 == n(expected, "block_height")
                        && mp.path[0].len() as i64 == n(expected, "path_leaf_count"),
                    format!("height={} leaves={}", mp.block_height, mp.path[0].len()),
                );
            }
            "tx-014" => {
                let mut tx = Transaction::new();
                tx.inputs.push(TransactionInput::new(
                    s(input, "source_txid").to_string(),
                    n(input, "source_output_index") as u32,
                ));
                suite.check(
                    id,
                    tx.get_fee().is_err(),
                    "expected Err from get_fee without source data".to_string(),
                );
            }
            "tx-015" => {
                let raw = from_hex(s(input, "raw_hex"));
                let offsets = Transaction::parse_script_offsets(&raw).expect(id);
                suite.check(
                    id,
                    offsets.inputs.len() as i64 == n(expected, "inputs_count")
                        && offsets.outputs.len() as i64 == n(expected, "outputs_count"),
                    format!("inputs={} outputs={}", offsets.inputs.len(), offsets.outputs.len()),
                );
            }
            other => {
                panic!("unrecognized serialization vector id '{}' — new corpus vector?", other)
            }
        }
    }
    // 12 executed + 3 enumerated-unsupported = 15 total.
    suite.finish("sdk.transactions.serialization", 12, 3, 0);
}

// ============================================================================
// Transactions-domain regression vectors
// ============================================================================

/// KNOWN SDK DIVERGENCES hit by the transactions regression corpus — real
/// bsv-rs bugs, isolated (NOT papered over) and asserted to not grow.
///
/// *** BUG (go-sdk#267 class): bsv-rs `SatoshisPerKilobyte::compute_fee` uses
/// CEILING division (`(size * rate).div_ceil(1000)`,
/// src/transaction/fee_models/sats_per_kb.rs) but the BSV node fee formula is
/// FLOOR with a minimum of 1 sat for nonzero size at a positive rate. For a
/// 1001-byte tx at 1 sat/kB the node expects 1 sat; bsv-rs computes 2. This
/// OVERPAYS fees (never underpays): every 1..999 excess byte range rounds up
/// a full satoshi. ***
const TX_REGRESSION_KNOWN_FAILURES: &[(&str, &str)] = &[(
    "regression.transactions.fee-model-mismatch.0001",
    "floor(1001*1/1000)=1 expected; bsv-rs div_ceil gives 2 (node formula is floor, min 1)",
)];

/// Builds a transaction whose `SatoshisPerKilobyte::estimate_size` is exactly
/// `target` bytes: 1 input with an L-byte unlocking script + 1 output with a
/// 1-byte locking script. Layout: 4 (version) + 1 (n_in) + 40 + varint(L) + L
/// + 1 (n_out) + 8 + 1 + 1 + 4 (locktime) = 60 + varint(L) + L.
fn tx_of_estimated_size(target: usize) -> Transaction {
    assert!(target > 63 + 253, "calibration assumes a 3-byte varint script length");
    let script_len = target - 60 - 3; // 3-byte varint for 253 <= L < 65536
    let mut input = TransactionInput::new(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        0,
    );
    input.unlocking_script = Some(UnlockingScript::from_script(
        Script::from_binary(&vec![0u8; script_len]).expect("OP_0 filler script"),
    ));
    let output = TransactionOutput {
        satoshis: Some(1),
        locking_script: LockingScript::from_script(
            Script::from_binary(&[0u8]).expect("1-byte script"),
        ),
        change: false,
    };
    let tx = Transaction::with_params(1, vec![input], vec![output], 0);
    // Self-check the calibration: at 1000 sat/kB, ceil(size*1000/1000) == size.
    let probe = SatoshisPerKilobyte::new(1000).compute_fee(&tx).expect("probe fee");
    assert_eq!(probe as usize, target, "size calibration drift");
    tx
}

#[test]
fn conformance_transactions_regressions() {
    let Some(dir) = corpus_dir() else { return };
    let regressions = dir.join("vectors/regressions");
    let mut suite = Suite::default();

    // ── merkle-path-odd-node (go-sdk#298): duplicate-node propagation. ──────
    // The 5 vectors pin every parent on the 5-leaf tree's path, including the
    // KEY case (0004): the level-1 odd node paired with itself. If bsv-rs's
    // duplicate propagation were wrong these hashes would not chain to the
    // pinned root in 0005.
    let json = load_json(&regressions.join("merkle-path-odd-node.json"));
    let mut parents: Vec<(String, String)> = Vec::new(); // (id, parent_hex)
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        let input = &vector["input"];
        assert_eq!(s(input, "operation"), "merkle_tree_parent", "{}", id);
        let mut cat = from_hex(s(input, "left_hex"));
        cat.extend_from_slice(&from_hex(s(input, "right_hex")));
        let parent = to_hex(&sha256d(&cat));
        let want = s(&vector["expected"], "parent_hex");
        suite.check(id, parent == want, format!("parent={} want={}", parent, want));
        parents.push((id.to_string(), parent));
    }
    // End-to-end: the same 5-leaf tree via MerklePath::compute_root must
    // reproduce the vector 0005 root. Leaves are literal (non-reversed)
    // bytes, so feed compute_root the display form (reversed) of leaf 3.
    {
        let leaves: Vec<String> = (1u8..=5)
            .map(|i| {
                let mut leaf = vec![0u8; 32];
                leaf[31] = i;
                leaf.reverse(); // display order for the fold helper
                to_hex(&leaf)
            })
            .collect();
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let root_display = merkle_root_from_display_txids(&leaf_refs);
        let mut root = from_hex(&root_display);
        root.reverse(); // vectors pin the literal (non-reversed) root bytes
        let want = &parents.last().expect("0005 present").1;
        suite.check(
            "regression.merkle-path.odd-node (5-leaf end-to-end)",
            to_hex(&root) == *want,
            format!("root={} want={}", to_hex(&root), want),
        );
    }

    // ── beef-v2-txid-panic (go-sdk#306). ────────────────────────────────────
    let json = load_json(&regressions.join("beef-v2-txid-panic.json"));
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        // 0002 is parity_class "intended" with a documented go-sdk skip
        // reason; the reference runner skips intended vectors.
        if s(vector, "parity_class") != "required" {
            suite.skipped.push(id.to_string());
            continue;
        }
        let input = &vector["input"];
        let expected = &vector["expected"];
        let parsed = Beef::from_binary(&from_hex(s(input, "beef_hex")));
        let want_parse = expected["parse_succeeds"].as_bool().unwrap_or(false);
        let want_txid = expected["txid_non_null"].as_bool().unwrap_or(false);
        match parsed {
            Ok(beef) => suite.check(
                id,
                want_parse && (!beef.txs.is_empty()) == want_txid,
                format!("parsed, txs={}", beef.txs.len()),
            ),
            Err(e) => suite.check(id, !want_parse, format!("parse err: {}", e)),
        }
    }

    // ── beef-isvalid-hydration (go-sdk#167). ────────────────────────────────
    let json = load_json(&regressions.join("beef-isvalid-hydration.json"));
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        let input = &vector["input"];
        let expected = &vector["expected"];
        let bytes = from_hex(s(input, "beef_hex"));
        match s(input, "operation") {
            "NewBeefFromBytes_IsValid" => {
                let mut beef = Beef::from_binary(&bytes).expect(id);
                let valid = beef.is_valid(true);
                suite.check(
                    id,
                    valid == expected["is_valid"].as_bool().unwrap(),
                    format!("is_valid={}", valid),
                );
            }
            "NewTransactionFromBEEFHex_TxID" => {
                // Full parse-and-extract path: the newest tx must come out
                // with a real txid.
                let beef = Beef::from_binary(&bytes).expect(id);
                let has_tx = !beef.txs.is_empty();
                let tx = Transaction::from_beef(&bytes, None);
                let txid_ok = tx.map(|t| t.id().len() == 64).unwrap_or(false);
                suite.check(
                    id,
                    (has_tx && txid_ok) == expected["txid_non_null"].as_bool().unwrap(),
                    format!("has_tx={} txid_ok={}", has_tx, txid_ok),
                );
            }
            other => panic!("{}: unknown operation {}", id, other),
        }
    }

    // ── tx-sequence-zero-sighash (ts-sdk#371). ──────────────────────────────
    let json = load_json(&regressions.join("tx-sequence-zero-sighash.json"));
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        let input = &vector["input"];
        let expected = &vector["expected"];
        match s(input, "operation") {
            "sighash_preimage" => {
                // BIP-143 preimage with one input carrying the fixture's
                // sequence; the nSequence field sits at a fixed offset:
                // 4 (version) + 32 + 32 (hashes) + 36 (outpoint) +
                // 1 (varint empty subscript) + 8 (value) = 113.
                let seq = n(input, "input_sequence") as u32;
                let inputs = [TxInput {
                    txid: [0u8; 32],
                    output_index: 0,
                    script: vec![],
                    sequence: seq,
                }];
                let preimage = build_sighash_preimage(&SighashParams {
                    version: n(input, "version") as i32,
                    inputs: &inputs,
                    outputs: &[],
                    locktime: n(input, "lock_time") as u32,
                    input_index: 0,
                    subscript: &[],
                    satoshis: 0,
                    scope: SIGHASH_ALL | SIGHASH_FORKID,
                });
                let got = to_hex(&preimage[113..117]);
                suite.check(
                    id,
                    got == s(expected, "preimage_sequence_field_hex"),
                    format!("sequence field={}", got),
                );
            }
            "serialise_input_sequence" => {
                // Serialized layout with 1 input, 0 outputs: the 4 sequence
                // bytes precede the output count + locktime (last 5 bytes).
                let mut txin = TransactionInput::new(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    0,
                );
                txin.unlocking_script = Some(UnlockingScript::new());
                txin.sequence = n(input, "input_sequence") as u32;
                let bytes = Transaction::with_params(1, vec![txin], vec![], 0).to_binary();
                let seq_field = &bytes[bytes.len() - 9..bytes.len() - 5];
                suite.check(
                    id,
                    to_hex(seq_field) == s(expected, "serialised_sequence_hex"),
                    format!("serialized sequence={}", to_hex(seq_field)),
                );
            }
            other => panic!("{}: unknown operation {}", id, other),
        }
    }

    // ── fee-model-mismatch (go-sdk#267). ────────────────────────────────────
    let json = load_json(&regressions.join("fee-model-mismatch.json"));
    for vector in json["vectors"].as_array().expect("vectors") {
        let id = s(vector, "id");
        let input = &vector["input"];
        assert_eq!(s(input, "operation"), "compute_fee", "{}", id);
        let tx = tx_of_estimated_size(n(input, "size_bytes") as usize);
        let fee = SatoshisPerKilobyte::new(n(input, "satoshis_per_kb") as u64)
            .compute_fee(&tx)
            .expect(id);
        let want = n(&vector["expected"], "fee_satoshis") as u64;
        suite.run += 1;
        if fee == want {
            suite.passed += 1;
        } else {
            let detail = format!(
                "{}: size={} rate={} expected fee {} sat, bsv-rs computed {}",
                id,
                n(input, "size_bytes"),
                n(input, "satoshis_per_kb"),
                want,
                fee
            );
            if TX_REGRESSION_KNOWN_FAILURES.iter().any(|(k, _)| *k == id) {
                suite.known_failures_hit.push(detail);
            } else {
                suite.failures.push(detail);
            }
        }
    }

    // 5 odd-node + 1 end-to-end + 1 beef-v2 (1 skipped) + 2 hydration +
    // 3 sequence-zero + 3 fee = 15 executed.
    assert_eq!(suite.skipped.len(), 1, "corpus-directed skips (parity_class intended)");
    suite.finish("transactions regressions", 15, 0, TX_REGRESSION_KNOWN_FAILURES.len());
}
