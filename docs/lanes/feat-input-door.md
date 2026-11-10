# Lane feat-input-door: the one-input door (#855)

Started at `842e5cc4` (`origin/beta`, no reset needed). One commit on
`lane/feat-input-door`, not pushed. The design is the three reads of
2026-11-10 (`design-door-api`, `design-door-callers`, `design-door-parity`);
this record holds what the lane settled, the two callers' code against the
door, and the numbers.

## What was built

`src/transaction/spending.rs`, re-exported from `bsv_rs::transaction`:

```rust
pub struct SpendingTransaction { /* Arc<TxSighashCache> */ }   // Clone, Debug, Send + Sync
impl SpendingTransaction {
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self>;
    pub fn input_count(&self) -> usize;
    pub fn verify_input(&self, input_index: usize, locking_script: &[u8], source_satoshis: u64,
                        rules: &InputRules) -> Result<InputVerified, InputRefusal>;
}
pub fn verify_input(locking_script: &[u8], source_satoshis: u64, spending_tx: &[u8],
                    input_index: usize, rules: &InputRules) -> Result<InputVerified, InputRefusal>;

pub struct DefaultMode { /* private */ }                      // Copy, Default, Eq, Hash
impl DefaultMode {
    pub const fn new() -> Self;
    pub const fn with_require_push_only(self, require: bool) -> Self;
    pub const fn with_require_minimal(self, require: bool) -> Self;
    pub const fn with_utxo_after_chronicle(self, after: bool) -> Self;
    pub const fn require_push_only(&self) -> Option<bool>;     // and the other two getters
}
pub struct InputRules { /* private: mode, memory_limit, work_limit */ }   // Copy, Eq, Hash; Default = reference_default()
impl InputRules {
    pub const fn reference_default() -> Self;
    pub const fn reference_default_with(mode: DefaultMode) -> Self;
    pub fn under(word: ScriptFlags) -> Result<Self, ScriptFlagsError>;      // word.check()
    pub const fn with_memory_limit(self, bytes: usize) -> Self;
    pub const fn with_work_limit(self, units: u64) -> Self;
    pub const fn word(&self) -> Option<ScriptFlags>;
    pub const fn default_mode(&self) -> Option<DefaultMode>;
    pub const fn memory_limit(&self) -> Option<usize>;
    pub const fn work_limit(&self) -> Option<u64>;
}
#[non_exhaustive] pub struct InputVerified { pub work_spent: u64 }
#[non_exhaustive] pub enum InputRefusal {
    Transaction(crate::Error),
    InputIndex { index: usize, inputs: usize },
    Invalid(Box<ScriptEvaluationError>),
    Declined(Box<ScriptEvaluationError>),
}   // std::error::Error, PartialEq + Eq (manual), evaluation(), resource_limit()
```

The core: `pub(crate) fn judge_input(&Arc<TxSighashCache>, input_index,
locking_script, unlocking_script, source_satoshis, &InputRules) -> Judged`
(the result and the work charged either way), the only construction of a
`Spend` for an input outside `src/script/` (`tests/arch_one_input_core.rs`).
`Transaction::verify` (`verify.rs`, `Evaluation::input`) and the streaming
reader (`beef_stream/spends.rs`, `InputCheck::execute`) call it with
`InputRules::for_verifier(word, memory, work)`, which leaves their word for
`Spend::validate` to check so its refusal keeps their words; each maps the
answer back through its own code (`InputRefusal::before_evaluation`, then
`script_refusal` or `execution_result`).

## The cells that were the lane's

- Names: `from_bytes`, `input_count`, `verify_input`, `reference_default`,
  `reference_default_with`, `under`, `with_memory_limit`, `with_work_limit`,
  `word`, `default_mode`, `memory_limit`, `work_limit`; the overrides on
  `DefaultMode` (`with_require_push_only`, `with_require_minimal`,
  `with_utxo_after_chronicle`, the last needed by the corpus's door runner,
  whose `Spend` runner sets it).
- A word with an override is inexpressible BY TYPE: the overrides live on
  `DefaultMode`, which only `reference_default_with` takes, and `InputRules`
  has no override setter; a `compile_fail` doc test on `DefaultMode` pins
  `InputRules::under(word)?.with_require_push_only(true)` not compiling.
- `InputRefusal` implements `std::error::Error` (thiserror); it converts into
  no `crate::Error` variant: the crate's mapping is `Transaction::verify`'s,
  with the txid and the input, and a generic `From` would fold a decline into
  a verdict's variant.
- `PartialEq`/`Eq`: derived on `DefaultMode`, `InputRules`, `InputVerified`;
  on `InputRefusal` by hand, every field of `ScriptEvaluationError` compared
  through an exhaustive destructure (a field added there fails to compile),
  `ScriptEvaluationError` unchanged.
- The two `&[u8]` of the one-shot: a rustdoc paragraph, no newtypes. A swap
  reads the locking script as the transaction, which the strict reader
  refuses save for a script built to be exactly one transaction, and the
  node's call has the same order (its own `NOLINT(bugprone-easily-swappable-
  parameters)`, `bitcoinconsensus.cpp:82`); newtypes would be two more frozen
  types for a hazard the reader already catches.
- `InputVerified::work_spent` is always the work spent (the fold, below):
  the door counts under `u64::MAX` when the rules carry no work limit; the
  production paths pass their own rules, unchanged. Until the fold it was
  counted only under a work limit.

## The two callers against the door

A scratch crate (`/Volumes/Lanes/out/bsv-rs/feat-input-door/callers`, a path
dependency on this tree, its own target dir) compiles both callers' per-input
code against the door, and their code as it stands (`Spend` by hand) beside
it, and runs both over the sibling's corpus (bsv-script-lean@1c051eae
`corpus/**/*.jsonl`, 29,102 cases, 29,263 inputs; the cold read's count).

### The oracle harness (`harness/src/engine.rs:282-366`)

```rust
pub fn run_input(
    tx: &RawTx,
    prevouts: &[Prevout],
    i: usize,
    mode: Mode,
    cfg: &EngineConfig,
) -> Verdict {
    let prev = &prevouts[i];
    let bytes = if mode == Mode::V1Strict {
        RawTx { version: 1, ..tx.clone() }.encode()
    } else {
        tx.encode()
    };
    let rules = match (cfg.flags, mode) {
        (Some(_), Mode::V2MinimalOnly) => {
            return Verdict::NotApplicable("a word takes no minimal override".into())
        }
        (Some(word), _) => match InputRules::under(word) {
            Ok(rules) => rules,
            Err(e) => return Verdict::NotApplicable(e.to_string()),
        },
        (None, mode) => {
            let mut default = DefaultMode::new().with_require_push_only(cfg.require_push_only);
            if mode == Mode::V2MinimalOnly {
                default = default.with_require_minimal(true);
            }
            InputRules::reference_default_with(default)
        }
    };
    let rules = match cfg.memory_limit {
        Some(bytes) => rules.with_memory_limit(bytes),
        None => rules,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        verify_input(&prev.script, prev.satoshis, &bytes, i, &rules)
    }));
    match result {
        Ok(Ok(_)) => Verdict::Accept,
        Ok(Err(InputRefusal::Declined(e))) => {
            let r = e.resource_limit.expect("a decline carries its budget");
            Verdict::Resource(format!(
                "{} limit {} attempted {}",
                r.resource, r.limit, r.attempted
            ))
        }
        Ok(Err(InputRefusal::Invalid(e))) => Verdict::ErrorV(e.message),
        Ok(Err(other)) => Verdict::Unparseable(other.to_string()),
        Err(p) => Verdict::Panic(panic_message(p)),
    }
}
```

It no longer hand-builds the other inputs, the outputs, the two scripts or
the `Spend`; it needs nothing from `Spend`. Over the corpus (5
configurations: the default mode with push-only, the post-Chronicle standard
and block words, the post-Genesis block word, the post-Chronicle block word
without GENESIS; 3 modes): 438,945 input runs, 263,367 equal, every other in two classes the
door makes on purpose: 58,526 a word `check` refuses, `ErrorV("Invalid
verification flags: ..")` before (a refused word read as a verdict on the
script, the misclassification `design-door-callers` found), `NotApplicable`
after; 117,052 `V2MinimalOnly` under a word, which sets `require_minimal`
after `set_flags` (`engine.rs:346-348`, the override at `:347`): a word with an override, no node's
word; for every run a node can make it is expressible as the word with
`MINIMALDATA` added (the cold read's measure, a row below). No other difference.

### The overlay engine (`crates/overlay-engine/src/script_door.rs:690-797`, at `2efad2f0`)

Read `SpendingTransaction::from_bytes(raw)` once per unproven transaction,
where `Layout::of(raw)` is read (`:584`), and replace the span from the
digest view to the verdict with:

```rust
pub fn door_rules(memory_limit: usize) -> InputRules {
    InputRules::reference_default_with(DefaultMode::new().with_require_push_only(true))
        .with_memory_limit(memory_limit)
}

pub fn judge(
    prepared: &SpendingTransaction,
    vin: usize,
    locking_bytes: &[u8],
    source_sats: u64,
    rules: &InputRules,
) -> Result<(), Answer> {
    match prepared.verify_input(vin, locking_bytes, source_sats, rules) {
        Ok(_) => Ok(()),
        // The door's own limit tripping inside the interpreter: over budget,
        // never refused (the arm, not a field, says which).
        Err(InputRefusal::Declined(e)) => Err(Answer::Over(format!("input {vin}: {}", e.message))),
        Err(InputRefusal::Invalid(e)) => Err(Answer::Refused(e.message)),
        // An index past the inputs cannot come from the walk (it iterates
        // the layout's inputs); kept as a fault, never a verdict.
        Err(other) => Err(Answer::Fault(format!("input {vin}: {other}"))),
    }
}
```

(`Answer::Refused` is its `ScriptVerificationFailed`, `Answer::Over` its
`over(..)` with `trace.interpreter_tripped = true`, `Answer::Fault` its
`fault(..)`.) It no longer hand-builds the digest view, the two lists or the
two scripts, and no longer reads `is_resource_limit()`: the arm says which.
It still needs nothing from `Spend`; its static pre-pass and census stay
(walk policy). Over the corpus with a 1 MiB budget: 29,263 inputs, all equal
to its code as it stands.

### What each caller's own framing accepts that the strict reader refuses

Nothing on the corpus: each corpus transaction and every single-byte change
(`^ 0x01`, `0xff`, `0xfd`), truncation and one-byte extension of those of 4,096
bytes or fewer (11,582,032 inputs) is accepted or refused alike by the
harness's `RawTx::decode` (`harness/src/txraw.rs:139-180`: canonical
CompactSize, `MAX_SIZE`, no trailing byte), the engine's `Layout::of`
(`script_door.rs:376-409`: bsv-rs's canonical varint reader, no trailing byte)
and `Transaction::from_binary`. Not a proof over every input: a shape no
mutation of the corpus reaches is not covered.

## Rows for the captain

- What I would deprecate in the break program (#843): `TxSpendParams` and
  `Spend::with_transaction` (the door is their caller's shape; the core can
  build its `Spend` through a crate-private constructor); `SpendValidation`
  (`src/script/transaction.rs`, a per-input door with no implementer in
  `src/`, an `Ok(false)` in its contract, no decline arm); `SpendParams` made
  `#[non_exhaustive]` with a constructor, `Spend` kept for stepping and
  debugging, its rustdoc pointing at the door.
- The harness's `Mode::V2MinimalOnly` under a word (`engine.rs:346-348`, the override at `:347`) is a
  word with an override, which the door takes by decision for no word; for
  every run a node can make it is expressible as the word with `MINIMALDATA`
  added, `InputRules::under(word.union(ScriptFlags::MINIMALDATA))`. The cold read's measure (2026-11-10, its
  REPORT): `InputRules::under(word.union(ScriptFlags::MINIMALDATA))`, a node's
  word, answers what the override answers on 83,855 of the 87,789 such runs
  under a word `check` honors (every run under the post-Genesis block word,
  every run at a version of 1 or below); the 3,934 left are post-Chronicle
  words at version 2, where the node's own gate relaxes MINIMALDATA
  (`EnforceNonMalleability`, bitcoin-sv v1.2.2 `interpreter.cpp:40-44`), so
  the override there is the configuration no node runs, and the door is right.
- The harness passes the prevout's outpoint where the door uses the input's
  own (`engine.rs:325-326`): equal on every corpus case; a case whose prevout
  named another outpoint would move its digest.
- `fuzz/corpus-gen`'s full run panics at the beta tip in `wallet_corpora`
  (`src/main.rs:394`, a `tests/vectors/wallet_wire/*.json` file without
  `wire`), older than this lane; `--door-only` writes this lane's seeds alone.

## Cost

Release, five runs each after a warm-up, base and tip interleaved twice
(`/Volumes/Lanes/out/bsv-rs/feat-input-door/bench.log`): `Transaction::verify`
of 1, 10 and 1,000 P2PKH inputs 0.034-0.036 / 0.305-0.326 / 30.4-33.0 ms on the
base, 0.034 / 0.311-0.317 / 30.5-32.4 ms on the tip; the streaming reader on
the largest vector BEEF (713 bytes) 0.037 / 0.034-0.036 ms, on a 1,000-input
BEEF 32.0-32.2 / 30.2-32.0 ms; the door's prepared form on 1,000 inputs
30.0-30.8 ms against 158-173 ms for a `Spend::new` per input.

## The fold (the three reads of `458914f1`, 2026-11-10)

The reads: cold MERGE 0.9 (one core, 0 of 6,515 runs differing from the base,
no cost; `be7ccada`: the node header's line ranges at v1.2.2, the corpus's
29,102 cases, the `V2MinimalOnly` row's measure); rule FIX 0.8 on one cell,
`work_spent`'s meaning, every other cell "freeze" (`841fe8d1`: the fuzz target
count before #855, a sentence break in `tests/CLAUDE.md`); strength ACCEPT
0.82 with two rows (the node's stack-memory figures; `InputRefusal`'s
equality unpinned). Both docs commits taken in that order; they touch no
common line. The captain's line: this is public API that 0.9.0 freezes, so
both rows are folded here.

- **`work_spent` is always the work spent.** `SpendingTransaction::verify_input`
  hands the core `work_limit: Some(rules.work_limit.unwrap_or(u64::MAX))`;
  `for_verifier`, `Transaction::verify` and the stream are unchanged. The
  field's rustdoc names the unit (one per opcode reached, one per byte
  hashed) and that a preparation hashes its BIP143 midstates once, charged to
  the input whose check computes them (found by the fold's own test: on one
  preparation a P2PKH input is charged 496 when it computes the midstates and
  286 after). The price, measured before building it (release, five
  interleaved rounds over a prepared 1,000-input P2PKH transaction, the
  default mode without a limit against `with_work_limit(u64::MAX)`, the
  door's new path): 32.24-32.71 ms against 32.25-32.85 ms, within the noise
  (`/Volumes/Lanes/out/bsv-rs/feat-input-door-fold/cost-measure.log`). The
  README example drops its `with_work_limit(u64::MAX)`.
- **The node's figures through the door.** `NodeFigures` (private fields,
  `new()` the node's defaults and `Default`, `with_stack_memory_policy`,
  `with_stack_memory_consensus`, `with_script_num_length_policy`, getters),
  taken only by `InputRules::under_with(word, figures)`; `under(word)` is
  `under_with(word, NodeFigures::new())`; `InputRules::node_figures()`. A
  `compile_fail` doc test: no default-mode constructor takes figures. The
  third figure, the script-number length policy, is `Spend`'s third public
  node setter, found by the class's machine below. No `#[non_exhaustive]`:
  the fields are private, as `DefaultMode`'s.
- **The machine for the class.** `tests/arch_door_says_what_spend_says_855.rs`
  reads every public `set_*` of `src/script/spend/` and every public field of
  `SpendParams` and holds each to a counterpart (`COUNTERPARTS`, read in its
  type's `impl` block in `spending.rs`) or an `ALLOWED` reason (the fields
  the bytes or the door's arguments carry); a stale entry or a missing
  counterpart is refused too.
- **`InputRefusal`'s equality pinned.** Unequal by the index, the input
  count, the message, each resource field, the arm (`Invalid` against
  `Declined` with one error) and the reader's error.

RED (`/Volumes/Lanes/out/bsv-rs/feat-input-door-fold/red-base-458914f1.log`,
`red-planted-tip.log`): on `458914f1` with the tests overlaid, the new file
compile-RED (E0432 `NodeFigures`, E0599 `under_with`), the arch test 2 of 2
(`NodeFigures::with_stack_memory_policy ... is not declared`, three lines),
`the_door_equals_a_spend_built_by_hand_on_every_vector_spend_855` RED (the
door's 0 against the counted hand-built spend). On a scratch copy of the tip,
each plant RED and reverted: the count dropped (4 tests, `left: 0, right: 2`);
the index, the input count, the message, the resource limit, the reader's
error dropped from the equality and `Invalid` equal to `Declined` (each
`refusals_that_differ_compare_unequal_855`); the consensus figure not applied
(3 tests); a `pub fn set_planted_knob` on `Spend` (`` `Spend`'s
`set_planted_knob` has no counterpart on the door and no allowance ``).

Rows outside the subject, not folded: what the break program deprecates
(`TxSpendParams`, `Spend::with_transaction`, `SpendValidation`; after-cut);
`fuzz/corpus-gen`'s older panic.

## The second fold (the cold and rule re-reads of `d520315e`, 2026-11-10)

The cold re-read found the equality claim wider than its test: six of the
fifteen comparisons were pinned, so dropping `program_counter` (or eight
others) passed every test. Two docs commits taken first (`346e895d`,
picked from `2d201bed`: the node's configuration refusals beside
`NodeFigures`; `75b278f8`, picked from `b081a386`: `work_spent`'s sum
order-free when judged one after another), then:

- **`InputRefusal`'s equality pinned for every field.** The impl compares 15
  fields: the arm, the reader's error, the index, the input count, and the
  eleven of `ScriptEvaluationError` (`message`, `source_txid`,
  `source_output_index`, `context`, `program_counter`, `stack`, `alt_stack`,
  `if_stack`, `stack_mem`, `alt_stack_mem`, `resource_limit`), the last by
  `ScriptResourceLimit`'s derived equality, whose four fields (`resource`,
  `limit`, `attempted`, `work_spent`) have rows too. The table
  (`every_field_alone_tells_two_refusals_apart_855`) has 34 rows: the four
  refusal-level fields and each of the fifteen evaluation fields under both
  arms; `every_compared_field_has_a_row_855` holds the eleven rows equal to
  `same_evaluation`'s destructure in the source, each compared there, and the
  rows' builder destructures `ScriptEvaluationError` exhaustively, so a field
  added to the type does not compile until it has a row. On a scratch copy
  of the tip each of the 15 comparisons dropped in turn turns the table RED
  naming that field alone (`resource_limit` with its four nested rows)
  (`/Volumes/Lanes/out/bsv-rs/feat-input-door-fold2/plants.log`).
- **The two modes' values cannot be swapped, by type.** Two `compile_fail`
  doc tests beside `NodeFigures`'s: `reference_default_with(NodeFigures::new())`
  and `under_with(word, DefaultMode::new())`, each E0308. Stable rustdoc does
  not enforce a `compile_fail` code (the four tests stay green with every
  code changed to E0599), so each snippet's code was read from a direct build
  in the scratch tree (`compile_fail_codes.log`: E0308, E0308, and the two
  older snippets' E0599).

Row, not folded: `ScriptFlagsError` is not `#[non_exhaustive]`, so
`under_with` could not later refuse a pair of figures without a break; that
attribute is the API break's (#843).
