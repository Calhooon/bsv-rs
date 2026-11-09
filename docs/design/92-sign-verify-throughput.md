# Design: #92, signing and verification throughput

Read at beta `e228c61a`. `[X]` read at the line; `[D]` told, derived, proposed. No cargo ran: every figure is a record's, every effect `[D]` until measured. Pins: ts-stack `edf6e03`, bitcoin-sv `v1.2.2`, BRCs `5119a9b`, bsv-stack-lean `13e1fa5d748b`; k256 0.14.0, ecdsa 0.17.0 (`tools/ratchet/library.Cargo.lock:626-628,1281-1283`) `[X]`.

## 1. The exit test and the scoreboard row

Issue #92 `[X]`: "Bench sign and verify at 100 inputs; a cached key deriver exists; add batch verification for a transaction's inputs and measure; derivation caches keyed safely (no key material in logs or errors). **Exit test.** The bench improves by a measured factor; the vectors pass. **Stack alignment.** BRC-42, 43 unchanged."

Rows moved `[X]`: `docs/NORTH-STAR.md:26` ("Signing and verification | Multi-input signing and batch verification", "not yet measured") and epic #101's "sign and verify | 100 inputs, batch verification measured". The queue row (`:214`) names #76, #77, #81 (all CLOSED) and "BRC derivation and crypto/API approval before changes"; no matrix item under it.

At target with recorded evidence `[D]`:

- Command: `cargo run --locked --manifest-path tools/bench-compare/Cargo.toml` (`benches/README.md`); in CI `gh workflow run bench.yml --ref beta`.
- Record ("delta" below): two `run.json` on one machine key (base, landed), the factor per id as p50 over p50 with p99 beside it, in the lane's record; then a baseline record (`-f bench_baseline_record=true`) so `benches/baseline.json` holds the gain under the 5 percent p99 gate; the `scoreboard` job fills the cell.
- "The vectors pass": `tests/ec_tests.rs` (BRC-42 `:42-134`; RFC 6979 `:315-419`; the DER pins `:954,:979`), `tests/vectors/sighash.json`, the `vectors` job; under `src/script/` or `src/transaction/`, the sibling's `harness/run --impl bsv-rs --corpus seed` identical before and after ("harness" below).

## 2. Today on beta

**Benches and gate** `[X]`. `benches/transaction_sign_verify.rs:63,70`: `sign_100_p2pkh`, `verify_100_p2pkh`, 100 P2PKH inputs locked to ONE key (`:25-35`). `tools/bench-compare/src/main.rs:68-82` requires both ids (`:391-395`).

**Numbers** `[X]`: p50, microseconds (the two batches whole), the Linux entry (EPYC 7763 / 4 cores, at `4b1c4688`) of `benches/baseline.json`; the macOS entry (M1 Max, at `67559f9d`) has the same ids:

| id | p50 |
|---|---|
| `sign_100_p2pkh` | 10,685 (macOS 14,929) |
| `verify_100_p2pkh` | 10,142 (macOS 9,261) |
| `Signing/PrivateKey::sign (secp256k1)` | 69.4 |
| `Key Generation/PrivateKey::public_key` | 29.9 |
| `Template Sign/P2PKH::sign_with_sighash` | 100.6 |
| `Verification/PublicKey::verify (secp256k1)` | 80.5 |
| `Key Derivation/PrivateKey::derive_child` | 61.7 |
| `Key Derivation/PublicKey::derive_child` | 122.6 |
| `Sighash/sighash x50`: `SighashCache` / `from_raw per input` | 15.0 / 179.0 |

Per input: signing 106.9, verifying 101.4.

**The code paths** `[X]`:

- `PrivateKey::sign` (`src/primitives/ec/private_key.rs:196-218`) builds `SigningKey::from(&self.inner)` per call (`:197`); ecdsa computes the public key inside that conversion (`ecdsa-0.17.0/src/signing.rs:479-490`). The signature is `sign_prehashed_rfc6979(&secret_scalar, prehash, b"")` through the recoverable `sign_prehash` the crate calls (`recovery.rs:277-278,204-205`, `hazmat.rs:102`): no public key read.
- `PrivateKey::public_key` (`:156-159`) multiplies the base point per call; `P2PKH::unlock` calls it per input (`src/script/templates/p2pkh.rs:170`).
- `Transaction::sign` (`src/transaction/transaction.rs:1410-1474`) makes per input a `SigningContext` (`:1462`) whose `compute_sighash` re-parses the transaction (`src/script/template.rs:133-134`): quadratic. `SigningContext` is a public struct of public fields (`:75`).
- `Transaction::verify`'s unproven step (`Evaluation::unproven`, `src/transaction/verify.rs:263-297`) shares one `TxSighashCache` per transaction (`:281`), runs the inputs in order, charges the work budget after each (`:284-291`) and re-parses both scripts from their bytes per input (`:324-325`).
- The interpreter's check (`src/script/spend/crypto.rs:394-432`): `signature_key` parses the pushed key (`key_point.rs:47-52`, one decompression); `PublicKey::verify` (`crypto.rs:431`, `public_key.rs:120-121`) calls `ecdsa::verify`, which re-encodes the point and parses it again (`src/primitives/ec/ecdsa.rs:71`).
- `PublicKey::derive_child` computes `GENERATOR * scalar` (`src/primitives/ec/public_key.rs:268`; again `:338`), the generic `lincomb` (`k256-0.14.0/src/arithmetic/mul.rs:236-238`), not the table path `mul_by_generator` (`mul.rs:180`).
- `CachedKeyDeriver` (`src/wallet/cached_key_deriver.rs:142-147`): keys of method, level, protocol, key ID, the counterparty's public hex (or `self`, `anyone`) and `forSelf` (`:187-209`), nothing private; eviction a full scan (`:112-127`). Results only: a new key ID for a known counterparty repeats the ECDH (`src/wallet/key_deriver.rs:192-201`, `private_key.rs:320-331`).

**The references** `[X]`, beyond the lines section 6 cites: `Transaction.sign` gives each input's template a fresh snapshot and a fresh `{ hashOutputsSingle }` cache (`Transaction.ts:207-215,939,994-1011`), where its verify keeps one per transaction (`:1398`); the node queues script checks (`validation.cpp:2691-2713`) and caches signatures (`script/sigcache.cpp:26`); BRC-42 asks that shared secrets and derived keys stay protected (`0042.md:59,:65`) and is silent on caching.

**Not on record:** these numbers at `e228c61a`; what the 20.9 microseconds per verified input beyond `PublicKey::verify` are; one decompression's cost; 100 DISTINCT keys; the wallet path (derive and sign 100 key IDs); a cache hit's cost; any wasm32 timing; whether `Spend` is `Send`; a mutation floor on any file below (`docs/ratchets.json`'s 29 floors are on other files `[X]`).

## 3. The gap

1. Each signed input computes the public key twice and uses it once: about 60 of 106.9 microseconds `[D]`.
2. Signing re-parses the transaction per input; verifying decompresses each key twice.
3. No batch verification, and no ruled meaning for it: ECDSA carries only `r`, so no algebraic batch `[D]`; the reference's is an external verifier hook, the node's a check queue.
4. The deriver caches results, not the shared secret; no batch derivation; no test pins "no key material in logs or errors".
5. The bench has one key and no wallet path; no target factor is named.

## 4. The design, ranked

Effects are `[D]` arithmetic on the table above. Each step keeps the public shape and every fixture, verdict and error text unless its row says so, and is one lane, one PR, one concern (S1 and S2 share one file and one lane).

| # | Change | Effect | Proof | Risk |
|---|---|---|---|---|
| S0 | Measure, no `src/` change: both machine keys at the tip; profile `verify_100_p2pkh`; new ids for 100 distinct keys, the wallet path, a cache hit, a new key ID for a known counterparty (`benches/`, `bench-compare`'s `main.rs:68-82`); a baseline record | Numbers for clauses 2 and 4; no one-key bias | `run.json`; bench-compare's tests | 0.10 |
| S1 | `PrivateKey::sign` calls `ecdsa::hazmat::sign_prehashed_rfc6979` on the secret scalar with `&[]`, the body `sign_prehash` runs today; no `SigningKey` built (`private_key.rs:197-203`) | One base-point multiplication less per signature: 69.4 to about 40 | signatures byte identical (`ec_tests.rs:315-419,954,979`, the wire and auth fixtures); delta | 0.15 (#125's pin is the tripwire) |
| S2 | `PrivateKey` memoizes its public key in a `OnceLock` filled on demand (`private_key.rs:30-32,156-159`); construction cost unchanged, so `PrivateKey::random` and `from_wif` stay inside the gate | With S1, 106.9 to about 47 per input: a factor near 2.2 on `sign_100_p2pkh` | S1's pins; a test that a clone and a derived child each answer their own key; delta | 0.10 |
| V1 | `ecdsa::verify` builds its `VerifyingKey` from the held point (`ecdsa.rs:71`); `derive_child` and `from_scalar_mul_generator` take `mul_by_generator` (`public_key.rs:268,338`) | One decompression less per verify (size not on record); `PublicKey::derive_child` 122.6 to about 92 | BRC-42 vectors, the #498 and #660 key vectors; harness; delta | 0.10 |
| S3 | Signing shares one `TxSighashCache`, as verify does here and in the reference: built once in `Transaction::sign`, carried by `SigningContext` (`template.rs:75-170`, `transaction.rs:1433-1466`) | Removes the quadratic parse: about 3.6 per input at 50 inputs by the `Sighash` row, growing with the count | RED `signing_n_inputs_parses_the_transaction_once` (a test-only counter); `sighash.json`; harness; delta | 0.25 (public shape, Q92.4) |
| V2 | The verify loop's overhead as S0's profile attributes it: scripts parsed once (`verify.rs:324-325`), the parsed key handed to the check | Up to 20.9 per input sits outside ECDSA, unattributed today | harness; `transaction_work_budget_378/519` unchanged; delta | 0.30 |
| D1 | `CachedKeyDeriver` caches the shared secret per counterparty, keyed by the counterparty's 33 bytes, never a private key; O(1) eviction; a test (a pin if green today) that no `Debug`, `Display` or `Error` of the deriver or `ProtoWallet` carries key material | A new key ID for a known counterparty: 61.7 to about 1 | RED `a_second_key_id_for_one_counterparty_computes_no_second_ecdh`; BRC-42 vectors; an eviction-order pin; delta | 0.25 (Q92.5) |
| D2 | `derive_private_keys` on `KeyDeriverApi`, a default body, grouped by counterparty (Q92.6) | The wallet's 100-input signing without a warm cache | equal to 100 single calls; delta | 0.20 (Q92.6) |
| B1 | Batch verification as Q92.1 rules: an additive native-only method running a transaction's inputs on scoped threads and folding the results in input order, so the verdict, the refusing input, its words and the `WorkBudget` cause equal the sequential path's; wasm32 compiles the sequential body | Up to the core count on `verify_100_*`; the row's batch, measured | RED differential `batch_and_sequential_agree_on_every_vector` (corpus and witness sets, a refusal at each index); harness; a batch id | 0.45 |

Fact-check (2026-11-09): the reference's signing builds a snapshot and a cache per input (`Transaction.ts:1006,1011`), only its verify shares one (`:1398`); S3's effect (`template.rs:133-134`) stands.

Rejected: an algebraic ECDSA batch (no equation without `R`); a process-wide signature cache as the node's (hidden state, a host's to own); a backend change (Q92.7).

## 5. The slicing

| Lane | Steps | Files | Waits on |
|---|---|---|---|
| L0 | S0 | `benches/`, `tools/bench-compare/` | nothing |
| L1 | S1+S2 | `src/primitives/ec/private_key.rs` | L0's base run |
| L2 | V1 | `src/primitives/ec/ecdsa.rs`, `public_key.rs` | L0; beside L1 |
| L3 | S3 | `src/script/template.rs`, `src/transaction/transaction.rs` | Q92.4 |
| L4 | V2 | `src/transaction/verify.rs`, `src/script/spend/crypto.rs`, `key_point.rs` | L0's profile, L2 |
| L5 | D1 | `src/wallet/cached_key_deriver.rs` | Q92.5; beside L1 to L4 |
| L6 | D2 | `src/wallet/key_deriver.rs`, `cached_key_deriver.rs` | Q92.6, L5 |
| L7 | B1 | `src/transaction/verify.rs`, a new `verify_batch.rs` | Q92.1 to Q92.3, L4 |
| L8 | the row | `benches/baseline.json`, the `NORTH-STAR.md` cell | all |

Gates: every lane the full gate, the wasm32 slice, its delta; L2, L3, L4, L7 the harness; L3, L6 the semver check; L4, L7 an adversarial read; L0, L8 the captain's baseline record.

Shared files: `benches/baseline.json` and `main.rs:68-82` (L0, L8, and the designs #90, #91, #93 if they add ids `[D]`: one baseline record per landing train); `verify.rs` (L4, L7); `cached_key_deriver.rs` (L5, L6); `CHANGELOG.md` and the module `CLAUDE.md` files (all).

Collisions `[D]` (the issues' bodies, the checkpoint): #90 owns `src/script/spend/`; L4 touches `crypto.rs:394-432` and `key_point.rs:47`, so it lands before or after #90, never beside it. #91 shares `TxSighashCache` through `beef_stream/spends.rs`; B1 leaves the stream alone. #93: the bench files. #96: no new dependency, no thread on wasm32. #99: semver checks judge S3 and D2. Other siblings: no shared source file. The blocking set: #782 is under `src/script/templates/`, which no step edits; #734 reads `MerklePath::verify` and `Transaction::verify` (its body); the other seven are identity and overlay: `CHANGELOG.md` alone. #603 adds tests under `src/script/` and `src/transaction/`: L3, L4, L7 rebase over it.

Fact-check (2026-11-09): #734 (OPEN) may land in `verify.rs`, beside L4 and L7.

## 6. The owner's questions

**Q92.1 What "batch verification" is.** (a) B1: in-crate parallel inputs, additive, native only; (b) port the reference's `verifier` hook with `verifyScriptsBatch` (`Transaction.ts:1694-1699,1476-1487`); (c) neither. Reference: sequential, the hook optional. Recommendation: (a): the row asks for a batch measured; (b) measures someone else's verifier. Cost: (a) none to a caller that does not call it, nothing for the Workers; (b) a new public trait; (c) the row's second half unmet.

**Q92.2 Threads inside a crate that starts no runtime.** (a) `std::thread::scope` off wasm32, the caller's count, no pool, no dependency; (b) the caller passes an executor; (c) `rayon`. No reference line. Recommendation: (a). Cost: (c) a dependency in every native dependent's graph; (b) a wider API for the toolbox and the CLI.

**Q92.3 The resource semantic on a refusal.** Sequential stops at the refusing input; a batch has run later ones. (a) Accept, bounded by `per_input` times the inputs; (b) no batch without a `per_input` bound; (c) chunks of the thread count, stopping between them. No reference line. Recommendation: (c): a door's budget is local policy (#378, #519). Cost: none to a caller of `verify`.

**Q92.4 `SigningContext`'s shape for S3.** Public fields, not `#[non_exhaustive]` (`template.rs:75`), so the cache is a new field: (a) add it in the 0.9.0 break window (migration: build with `SigningContext::new`), as 0.7.0 added `script_code`; (b) keep the shape, signing stays quadratic; (c) a second context type. Reference: the signing cache is per input, `hashOutputsSingle` alone (`Transaction.ts:207-215,1011`). Recommendation: (a). Cost: a dependent building the struct by literal changes one line; which do, not on record.

**Q92.5 Caching the shared secret.** (a) On by default under `max_size`, as the reference (`CachedKeyDeriver.ts:51-57`; its cache key holds `priv.toString()`, not followed here); (b) opt-in through a new `CacheConfig` field (one public field today, `cached_key_deriver.rs:51-54`: a break); (c) not cached. BRC-42 asks that it stay confidential (`0042.md:59`); the cache already holds derived private keys. Recommendation: (a), zeroized on eviction. Cost: no shape change; memory bounded by `max_size`.

**Q92.6 `derive_private_keys` on `KeyDeriverApi`.** (a) A trait method with a default body; (b) inherent only; (c) none. Reference: one shared secret per counterparty (`KeyDeriver.ts:207-240`, `CachedKeyDeriver.ts:153`). Recommendation: (a). Cost: additive; an outside implementor inherits the default.

**Q92.7 The backend.** (a) k256 stays; (b) libsecp256k1 on native. Reference: ts-stack's own arithmetic (`ECDSA.ts:150,211`). Recommendation: (a): (b) costs every dependent a C toolchain, the Workers a second path, #125's pin a new derivation.

**Q92.8 The factor that reads "at target".** Named in no record or reference. (a) Any recorded factor above 1; (b) a named floor. Recommendation: (b): `sign_100_p2pkh` p50 at or below half the Linux baseline entry; `verify_100_p2pkh` sequential and batch each with its factor recorded. Cost: none to a dependent.

## 7. Stack alignment

BRC-42 and BRC-43 unchanged: the derivation (`0042.md:43-48,52-55`) and the invoice number (`0043.md:19-31`) computed as today, pinned by `tests/vectors/brc42_private.json` and `brc42_public.json`. The wallet charter's `sign(t)` door (bsv-stack-lean's `docs/charters/wallet.md:50` at the pin) is untouched; no matrix row or charter line names signing throughput (a grep of both `[X]`; `lean/` not read).

T1: the costs removed grow with our inputs, never the chain. T2: no verdict moves (B1's differential). T3: one multiplication where two ran. T4: no rule changes; a budget stays local policy. T5: no new trust, no new dependency. T6: each step returns a replayable run.

## 8. Not in this design

P-256, Schnorr, AES and HMAC paths: no consumer asks. The stream's spends: #91's. The interpreter beyond the signature check: #90's. A host's signature cache or verifier pool: the toolbox's. The `BdkVerifierInterface` port, if Q92.1 answers (b): a parity row. The hosted harness: #97.
