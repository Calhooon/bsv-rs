# #803: PushDrop's wallet-aware unlock, `PushDrop::unlock_with_wallet`

Base `cb950611` (`origin/beta`'s tip at the lane's start and at its gate).
The issue carries no comment: no decision and no wait recorded on it.

## The site, side by side

| | Reference (`ts-stack@edf6e03` `packages/sdk/src/script/templates/PushDrop.ts`, `SignatureUtils.ts`) | This crate at `cb950611` | Tip |
|---|---|---|---|
| the door | `new PushDrop(wallet, originator).unlock(protocolID, keyID, counterparty, signOutputs = 'all', anyoneCanPay = false, sourceSatoshis?, lockingScript?)`, `PushDrop.ts:217-229`, returning `{ sign, estimateLength }` | none public: `wallet::pushdrop::sign` is `pub(crate)`, compiled under `kvstore`, `identity` or `registry`, four callers | `PushDrop::unlock_with_wallet(wallet, originator, protocol_id, key_id, counterparty, sign_outputs, anyone_can_pay) -> PushDropWalletUnlock<'_, W>`, under `wallet` |
| the scope | `computeSignatureScope`, `SignatureUtils.ts:44-68`: FORKID with ALL, NONE or SINGLE, ANYONECANPAY or-ed in | `compute_sighash_scope`, the same bytes | `compute_sighash_scope` |
| the source | `resolveSourceDetails`, `SignatureUtils.ts:74-184`: the two optional arguments or the input's linked source, a disagreement refused | the callers' own | the `SigningContext`'s amount and script (or its named scriptCode) |
| the refusals before the wallet | an input index outside the inputs (`:89-91`), an amount past 21e14 (`:16-21`), and the linked-source checks | none | the index and the amount, in the reference's words; unparsable bytes in the parser's |
| the request | `createSignature({ data: sha256(preimage), protocolID, keyID, counterparty }, originator)`, `PushDrop.ts:245-254` | the signer's, the same | the signer's, once |
| the answer | `Signature.fromDER`, `toChecksigFormat`, one push, `:255-258` | `Signature::from_der`, `to_checksig_format`, one push | the same |
| the estimate | 73, `:260` | (`PushDrop::estimate_unlocking_length` 73) | 73 |

Go (`go-sdk@2ca481c` `transaction/template/pushdrop/pushdrop.go:199-277`):
an `Unlocker` with `Sign(tx, inputIndex)` and `EstimateLength() 73`; it asks
the wallet with `HashToDirectlySign` (the double hash) and wraps a wallet
error.

## The premise, checked on the tip

The plan's lines, each read at `cb950611`:

| Cited | Holds |
|---|---|
| `src/wallet/mod.rs:120`, `pub(crate) mod pushdrop;` | yes (line 120, under a `cfg(any(kvstore, identity, registry))` at 119) |
| `src/wallet/pushdrop.rs:8`, `pub(crate) async fn sign`, the preimage hashed and handed to `create_signature` at `:16-20` | yes (the call at `:16-27`) |
| `src/script/templates/pushdrop_wallet.rs:61`, `PushDrop::lock_with_wallet` | yes |
| `PushDrop.ts:205-262`, the scope at `:231` | yes (`unlock(` at `:217`, its doc comment from `:205`) |
| `estimateLength` 73 at `:227`, `:260` | yes (`:227` the type, `:260` the value) |
| the door returns the crate's `ScriptTemplateUnlock` whose sign closure calls the signer | **no**: `ScriptTemplateUnlock`'s closure is `Fn(&SigningContext) -> Result<UnlockingScript> + Send + Sync + 'static` (`src/script/template.rs:253-275`), synchronous, and the signer is `async` (a wallet call). The crate starts no runtime and wasm32 cannot block, so the closure cannot await it. The door returns a type of its own with an `async` `sign` |
| the parameters `source_satoshis`, `locking_script` | not taken: every template of this crate reads them from the `SigningContext`, which always names one of each |

## The decision

A template type of its own, `PushDropWalletUnlock<'a, W>`, with the
reference's two members (`sign`, `estimate_length`), built by the associated
function the issue names, the wallet and the originator leading as at
`lock_with_wallet`. Nothing existing changes shape. The signer stays
crate-private and is now compiled under `wallet`; the door is its fifth
caller (`tests/arch_listed_spend_binds_its_input.rs`).

Where the reference's door does something this crate does not follow, each
is stated (the root `CLAUDE.md` row, the changelog's parity note): the
synchronous `ScriptTemplateUnlock` is not the return type; the linked-source
checks of `resolveSourceDetails` have no twin (#848's row); a named
scriptCode is signed; a wallet's high-S answer is written low-S (found by the
recording: `Signature::to_der` writes the low-S form, at this door and at the
four sites sharing the signer, older than this lane; the signer was not
changed).

## The recording

```text
W=/Volumes/Lanes/out/bsv-rs/fix-803-unlock/ref
git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
(cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk803.mjs")
~/.nvm/versions/node/v22.18.0/bin/node tests/support/pushdrop_wallet_unlock_803.mjs \
  "$W/sdk803.mjs" > tests/vectors/pushdrop_wallet_unlock_803.json
```

Two runs byte-identical (`cmp`), SHA-256
`6f71d42cb86cda75bbca5149995ea24c8c8cc49279473a6a7f8299cf8fd70794`. 23 cases
(the three scopes with and without anyone-can-pay at each of three inputs;
counterparty `anyone` and a key; an originator; version 2; an amount of
21e14), 3 refusals (an index past the inputs, an amount past 21e14, a wallet
that throws), 4 wallet answers (not DER, empty, a byte after, the high-S
twin). The recorder was written before the door and re-run twice before the
vector was committed: once to lock the spent outputs with `forSelf` true
(with `false` the `anyone` and key counterparties lock to a key the wallet
does not sign for, so the recorded scripts did not spend the recorded locks:
the recorder's fixture, not a finding), once for the `source` line's
citations. One probe outside the vector
(`/Volumes/Lanes/out/bsv-rs/fix-803-unlock/highs_probe.mjs`): the
reference's default `Spend` on the recorded `answer_high_s` script at version
1 answers `The signature format is invalid.`

## RED

Before the door (`red-compile.log`): the test file against `cb950611`'s
sources,

```text
error[E0599]: no associated function or constant named `unlock_with_wallet` found for struct `PushDrop` in the current scope
```

(five sites, no other error). On the tip, a scratch copy under the lane's
out folder with a target dir of its own, seven planted faults, each watched
RED and reverted (`red-plant-A.log` to `-G.log`; 11 tests):

| Fault | RED |
|---|---|
| A: anyone-can-pay dropped from the scope | 4 failed: the bytes, the scope byte, the wallet's `data`, `Debug` |
| B: the amount signed as 0 | 6 failed: the bytes, `data`, the recorded spends, the mint-and-spend, the answers, the named scriptCode |
| C: the amount check removed | 1 failed: the amount refusal |
| D: the index check loosened | 1 failed: the index refusal |
| E: the originator unsent | 1 failed: the wallet's arguments |
| F: a named scriptCode unread | 1 failed: the named scriptCode |
| G: the key ID fixed at `1` | 1 failed: the mint-and-spend under key ID `7` |

The callers guard with beta's list (`red-arch-callers.log`):
`src/script/templates/pushdrop_wallet_unlock.rs calls wallet::pushdrop::sign
and is not in CALLERS`. The scratch tree and its target dir were removed.

## The gate

`CARGO_BUILD_JOBS=4`, one cargo at a time, each in the foreground, target
`/Volumes/Lanes/targets/fix-803-unlock` (removed at the end).

| Command | Result |
|---|---|
| `cargo fmt --all -- --check`; `--manifest-path fuzz/Cargo.toml`; `--manifest-path fuzz/corpus-gen/Cargo.toml` | clean, all three |
| `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings` | clean |
| the same on the slices `script`, `transaction`, `wallet`, `auth,wallet,transaction,overlay,socketio,wasm`, `wallet,auth,transaction,wasm` | clean |
| `cargo check --all-targets --all-features` | clean |
| the wasm32 slice (`auth,wallet,transaction,overlay,socketio,wasm`) | builds |
| the new test, three runs (one `--test-threads=1`) and once under `--no-default-features --features wallet` | 11 passed each |
| `cargo test --features "full,http" --lib script`; `--lib wallet` | 288 passed, 4 ignored; 207 passed |
| `--test 'script_*' --test 'pushdrop_*' --test fixtures_replay --test readme_examples` (51 binaries) | 354 passed, 0 failed, 11 ignored |
| the 40 other binaries that use the counting wallet (`contacts_*`, `identity_*`, `kvstore_*`, `registry_*`, `wallet_*`) | 299 passed, 0 failed, 4 ignored |
| `--test 'arch_*'` (36 binaries) | 188 passed, 0 failed, 1 ignored |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`; `cargo test --doc --all-features`; `cargo build --examples --all-features` | clean; 382 passed, 129 ignored; builds |
| `cargo +1.95.0 semver-checks check-release --baseline-rev origin/beta --all-features --release-type minor` (0.51.0) | 202 checks pass, 58 skip, no update required |
| `tools/ratchet/run --check --against origin/beta` | all 7 counters, oversized-file limits and mutation floors pass |
| `python3 .github/scripts/mutants_entries.py`; `rows_from_sources.py --check`; `test_rows_from_sources.py` | PASS, 28 entries; 0 refusals; 10 tests OK |
| `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` | no leaks |

Not run: the whole suite (`--tests`), the conformance corpus files, the fuzz
targets (no parser touched), a Linux cell.

## The shape (as folded: three design reads and three reads of 2026-11-14)

```rust
impl PushDrop {
    pub fn unlock_with_wallet<'a, W: WalletInterface + ?Sized>(
        wallet: &'a W,
        originator: Option<&'a str>,
        protocol_id: Protocol,
        key_id: &str,
        counterparty: Counterparty,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> PushDropWalletUnlock<'a, W>;
}

pub struct PushDropWalletUnlock<'a, W: WalletInterface + ?Sized> { /* private */ }

impl<W: WalletInterface + ?Sized> PushDropWalletUnlock<'_, W> {
    // native and wasm32 alike
    pub fn sign(
        &self,
        context: SigningContext<'_>,
    ) -> impl Future<Output = Result<UnlockingScript>> + Send + '_;
    pub fn estimate_length(&self) -> usize; // 73
}
// Debug by hand: the scope and the estimate alone.
```

At `c4eb5756` `sign` was `pub async fn sign(&self, context: &SigningContext<'_>)
-> Result<UnlockingScript>`. The callers' read compiled the three forms a
dependent would write and none was `Send`; the fold takes the context by
value, reads it into owned data (`Read::of`: the parsed transaction, the
index, the amount, the scriptCode's bytes) and returns an `async move` block
that awaits the one signer over that data.

| Choice | Taken | Not taken | Why |
|---|---|---|---|
| the return type | a new `PushDropWalletUnlock`, `sign` returning a future | `ScriptTemplateUnlock` (the plan's premise) | its closure is synchronous; awaiting a wallet inside it needs a blocking executor, which the crate does not start and wasm32 does not have |
| | | one `async fn unlock_with_wallet(.., context) -> Result<UnlockingScript>`, no template | the reference returns a template with two members; the estimate is asked before the signature (fee sizing) |
| | | an async closure field or a new async variant on `ScriptTemplateUnlock`, so `Transaction::sign` drives it | a change of an existing public type's shape and of `Transaction::sign` (sync); rule 9, a question for the captain |
| sync or async | a future from `sign` | sync | `WalletInterface::create_signature` is async |
| the context (the fold) | by value, `context: SigningContext<'_>`, read before the future starts | `&SigningContext<'_>` in an `async fn` (as built at `c4eb5756`) | a context borrows a `Script`, which is not `Sync`; kept across the await it made the future not `Send`, so the door did not compile under `#[async_trait]`'s default or in a multi-threaded handler (the callers' read, by a compile; `red-send-as-built.log`) |
| | | `&SigningContext<'_>` in a plain `fn` that reads it before the future | `Send` only when the caller scopes the context away from the await; `t.sign(&ctx).await` still fails (the callers' read's mirror) |
| what the caller owns across the await (the second fold) | said in `sign`'s rustdoc, with a compiled `no_run` example whose future is checked `Send`: each locking script OWNED across the await (parsed or cloned inside the loop, or moved out of an owned list), the context built in the call | a `compile_fail` doc test of the borrowed form | the door's future is `Send`, but a caller that holds a `&LockingScript` or `&Script` across the await (a loop over a borrowed `&[(usize, LockingScript)]`), or keeps a `SigningContext` alive past it (a clone given to `sign`), has a future of its own that is not `Send`: a `Script` is `Send` and not `Sync`. Four caller shapes compiled by the second fold (`caller-shape-{a,b,c,d}.rs` and `.log` in its folder): owned parsed in the loop, `Send`; a borrowed list, 4 errors (`future cannot be sent between threads safely`); a cloned context kept, 4 errors; an owned list moved through the loop, `Send`. A `compile_fail` block on stable names no error number, so it would pass for any reason: one sentence instead |
| the future's bound (the fold) | `impl Future<Output = Result<UnlockingScript>> + Send + '_`, on every target | a conditional bound (`Send` on native alone) or an alias | `WalletInterface` is `#[async_trait]` with no `?Send` and `Send + Sync` supertraits, so its futures are `Send` on wasm32 too; the crate's `?Send` traits are the broadcasters and facilitators, which hold a `Transaction`; the wasm32 slice builds with the bound |
| what the future borrows (the fold) | the template (`'_`: the wallet, the originator, the protocol, key ID and counterparty read at the await) | `+ 'a`, the wallet's lifetime alone, the template's fields cloned before the future | the narrower promise; widening `'_` to `'a` later is no break, the reverse is |
| when a refusal is answered (the fold) | at the await: the bytes are parsed and the two refusals judged when `sign` is called, the `Err` held in the future | `fn sign(..) -> Result<impl Future>` | one place for a caller to read an error, as the `async fn` had it |
| the wallet | borrowed, `&'a W`, `W: ?Sized` | owned `W`, or `Arc<W>` | `lock_with_wallet`'s form; a `&dyn WalletInterface` works; the cost is the lifetime: the template cannot be stored in a `TransactionInput` or sent to a task that outlives the wallet borrow |
| where `originator` sits | second, after the wallet, `Option<&'a str>` | last (the trait methods' place); owned `Option<String>` | the reference's constructor order `(wallet, originator)` and `lock_with_wallet`'s |
| `protocol_id`, `counterparty` | owned `Protocol`, `Counterparty` (cloned per `sign`) | borrowed | `lock_with_wallet`'s form; the template signs any number of inputs |
| `key_id` | `&str`, held as `String` | `String`, `impl Into<String>` | `lock_with_wallet`'s form |
| `sign_outputs`, `anyone_can_pay` | required, `SignOutputs` and `bool` | defaults (`'all'`, `false`) through a builder | the raw `PushDrop::unlock`'s form; the enum makes the reference's `signOutputs must be "all", "none", or "single"` refusal unreachable |
| the source amount and script | the `SigningContext`'s | two `Option` parameters as the reference's `sourceSatoshis?`, `lockingScript?` | the context always names both, so the reference's "explicit against linked" comparison has nothing to compare; two more parameters would be a second place to say the same thing |
| the scriptCode | `context.script_code` honoured | the locking script alone, as the reference | every template's `sign` here reads it through `compute_sighash`; ignoring it at one template would be a silent difference inside the crate |
| the error type | `crate::Result`; the two refusals `Error::TransactionError` in the reference's words | `Error::CryptoError` (what `SigningContext::compute_sighash` uses for the index, in its own words); a new variant | the words are the reference's `SignatureUtils` sentences; `TransactionError` is the family #848 and #871 put such sentences in; no new variant on the 80 |
| a high-S answer | written low-S (the signer's `to_der`) | pushed as answered, as the reference | the signer is shared by four sites; changing it moves their bytes for such a wallet, outside this issue; stated |
| `Debug` | by hand, scope and estimate | derived | `W` need not be `Debug`; no key ID, counterparty or originator printed |
| the feature | `wallet` | `transaction`; the sites' features | the lock door's; `WalletInterface` lives there |

### Additive later (the design reads' rows; none is a break)

| Row | From | What it adds |
|---|---|---|
| a form taking a `&Transaction` | callers, item 6 | the amount and script from the input's linked source; today a caller holding Atomic BEEF does `from_atomic_beef(..)?.to_binary()` and builds the context |
| a `'static` constructor | api, item 1 | an `Arc` wallet and an owned originator, the private field a borrowed-or-shared enum; for a template stored in a map or a task |
| an async unlock trait and a `Transaction::sign_async` | api, item 8; parity, row 4 | the trait implemented for this type, the templates passed as arguments |
| defaults for `sign_outputs` and `anyone_can_pay` | parity | a builder or a second constructor |
| the struct-level `WalletInterface` bound dropped; `Clone`; `#[must_use]` | api, items 2 and 10 | removing a bound and adding an impl or an attribute |
| a `Send` check of `lock_with_wallet`'s future | callers | a test; not run by this lane |
| a public ts-stack issue: `PushDrop.unlock` pushes a high-S answer | parity, row 3 | the keeper's filing; the answer is the caller's own wallet's, no peer reaches it |
| the overlay's re-pin from `=0.7.2`; the toolbox's intake row | callers | the dependents' own lanes |

Done by the fold from the same lists: the future is `Send`, with its test
(api item 6, callers item 1); the constructor's example is a compiled
`no_run` doc test (api's last row); the two recorded cases (parity rows 1
and 2).

## The fold

Rebased from `c4eb5756` onto `origin/beta` (`228d4f34`, then `1acd0854`):
`CHANGELOG.md` and the root `CLAUDE.md` conflicted and keep both sides
(beta's reworded #782 row, this lane's #803 row after it).

| Item | What | RED |
|---|---|---|
| 1, the shape | `sign` by value, its future `Send`; `the_future_sign_returns_is_send_in_each_caller_form_803` (the context built in the call, bound then given, the future made in a scope of its own, an `#[async_trait]` method over an `Arc<dyn WalletInterface>`; each run to the recorded script) | a scratch copy with the door's file as built and the test's calls given `&`: compile-RED, 16 errors (`red-send-as-built.log`), each `E0277` (`RefCell<..>` cannot be shared between threads safely, within `Script`) or `future cannot be sent between threads safely`; no other error |
| 2, the vacuous test | `high_s` writes the twin's DER by hand and asserts it is not low-S (the cold read's patch); until then it went through `Signature::to_der`, which writes low-S | a plant in `src/wallet/pushdrop.rs` pushing the wallet's answer as given: 1 of 14 failed, `a_wallet_answer_no_der_is_refused_and_a_high_s_one_is_written_low_803`, `left` the recorded `answer_high_s` script byte for byte, 74 bytes (`red-high-s-plant.log`) |
| 3, the Go clause | go-sdk writes a high-S answer low-S too (`Signature.Serialize`, `primitives/ec/signature.go:77-82`, called at `pushdrop.go:228`) and holds `UnlockOptions.SourceSatoshis` and `LockingScript` (`:272-273`) that `Sign` (`:199-236`) never reads; read at `2ca481c` by `git show` | none (words) |
| 3, two recorded cases | the vector's group `fold`, by the recorder at the pin (Node v22.18.0, the bundle rebuilt from `edf6e03`), two runs byte-identical (`cmp`), SHA-256 `455dd6fed8e29c099a672ae79162ccfc84dd0ad8c094c1a3e4193100435ca200`; `diff` against the committed vector: lines appended after `answers` alone, so the 23 cases, 3 refusals and 4 answers are byte for byte. Both faults at once: the reference names the index. An R of 33 bytes: the reference pushes it (a 73-byte push), this crate refuses it (`Integer component too large`), stated | the two checks swapped in `Read::of`: 1 of 14 failed, `both_faults_at_once_are_refused_for_the_index_before_the_amount_803`, `left: "sourceSatoshis must be a valid number of satoshis"` (`red-order-plant.log`). The R case pins a stated difference and was green on arrival |

The logs are under `/Volumes/Lanes/out/bsv-rs/fix-803-unlock-fold/`; the
scratch tree and its target dir were removed.

### The fold's gate

`CARGO_BUILD_JOBS=4`, then 2 (the host's swap use above half), one cargo at
a time, target `/Volumes/Lanes/targets/fix-803-unlock-fold` (removed at the
end).

| Command | Result |
|---|---|
| `cargo fmt --all -- --check`; `--manifest-path fuzz/Cargo.toml`; `--manifest-path fuzz/corpus-gen/Cargo.toml` | clean, all three |
| `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`; the same on `--no-default-features --features wallet` | clean; clean |
| `cargo check --all-targets --all-features` | clean |
| the wasm32 slice (`auth,wallet,transaction,overlay,socketio,wasm`) | builds, the `Send` bound unconditional |
| the test file under `full,http`, three runs (one `--test-threads=1`), and under `--no-default-features --features wallet` | 14 passed each |
| `cargo test --features "full,http" --lib script`; `--lib wallet` | 288 passed, 4 ignored; 207 passed |
| `cargo test --doc --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` | 383 passed, 128 ignored (the constructor's example compiled); clean |
| `--test 'arch_*'` (37 binaries) | 195 passed, 0 failed, 1 ignored |
| `--test fixtures_replay`; `--test readme_examples` | 1 passed; 1 passed |
| `cargo +1.95.0 semver-checks check-release --baseline-rev origin/beta --all-features --release-type minor` (0.51.0) | 202 checks pass, 58 skip, no update required |
| `tools/ratchet/run --check --against origin/beta` | all 7 counters, oversized-file limits and mutation floors pass |
| `python3 .github/scripts/mutants_entries.py`; `rows_from_sources.py --check` | PASS, 28 entries; 0 refusals |
| `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` | no leaks |

Not run: the whole suite (`--tests`), the other binaries that use the
counting wallet (its file is unchanged by the fold), the conformance corpus
files, the fuzz targets (no parser touched), a Linux cell.

## The second fold

Lane fix-803-unlock-fold2, the re-read's three small items. Rebased from
`8de2717d` onto `origin/beta` (`b31fa910`, then `f3aa5ff3`, which moved
during the gate), no conflict.

| Item | What | RED |
|---|---|---|
| 1, a second high-S sample | `a_high_s_answer_as_long_as_its_low_s_form_is_written_low_803` against the vector's group `fold2` (one case, `answer_high_s_of_equal_der_length`): the wallet's R over an S of 2^255 - 1, its DER written by hand on both sides. The recorder at the pin (the bundle rebuilt from `edf6e03`, Node v22.18.0), two runs byte-identical (`cmp`), SHA-256 `e9e6b2a5fd00ac71f11bbbd4bf9b1c5e9d03a565287a2a257399ab3cc509f4fe`; `diff` against the committed vector: lines appended after `fold` alone, so the 23 cases, 3 refusals, 4 answers and the fold's 2 are byte for byte. The reference pushes the answer as given (a 72-byte push, the script 73 bytes); the door writes `n - s` (`7fff..fe baaedce6 af48a03b bfd25e8c d0364142`, 32 bytes) in its place, the same length | a scratch copy with the re-read's plant in `src/wallet/pushdrop.rs` (the answer pushed as given when it is as long as its low-S form): 1 of 15 failed, the new test, `left` the recorded script byte for byte (`red-equal-length-plant.log`); the 14 others green under it, the earlier high-S sample among them |
| 2, what a caller owns | `sign`'s rustdoc, section "What the caller owns across the await", with a `no_run` example in the caller's shape whose future is checked `Send`; the row in the shape table above; the toolbox's intake draft's note 1 | none (words and a compiled example); the four caller shapes compiled once each, two `Send` and two refused (`caller-shape-{a,b,c,d}.log`) |
| 3, the records | the root row (it named `sign(&SigningContext)`, the shape before the fold; now `sign(SigningContext)`, with the caller's caveat and the equal-length case), the CHANGELOG's paragraph, the rows of `tests/CLAUDE.md`, `src/script/CLAUDE.md` and `src/script/templates/CLAUDE.md` | none |

The sample's bound, stated: the re-read wrote that the two DERs are of one
length when the low-S S starts with a zero byte, about 1 answer in 256. The
arithmetic gives another answer. A high S is above n / 2, and n / 2 is just
under 2^255, so a high S has its top bit set and takes 33 DER bytes unless it
lies between n / 2 and 2^255, a range about 2^127 wide (1 answer in 2^128);
a low S is under 2^255 and takes 32 bytes or fewer. So the lengths are equal
only for a high S in that range, whose twin `n - s` is 32 bytes too, and a
low S that starts with a zero byte makes the difference two bytes or more,
not none. No signature of the wallet's lands there by chance, so the sample's
S is chosen (2^255 - 1) over the wallet's own R: the signature verifies under
no key, and the door, which asks no verification, is judged on the bytes it
writes. The plant is the re-read's as worded (a comparison of lengths); a
plant keyed on another property of the answer is another sample's, and so is
one keyed on the call: both high-S samples sign input 0 under `0x41`, so a
signer that pushes the answer as given only under anyone-can-pay (the scope's
`0x80` bit) passes all 15 (the cold read of the second fold, run).

The logs are under `/Volumes/Lanes/out/bsv-rs/fix-803-unlock-fold2/`; the
scratch tree and its target dir were removed.

### The second fold's gate

`CARGO_BUILD_JOBS=4`, one cargo at a time, target
`/Volumes/Lanes/targets/fix-803-unlock-fold2` (removed at the end); run on
the tip rebased onto `f3aa5ff3`.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check`; `--manifest-path fuzz/Cargo.toml`; `--manifest-path fuzz/corpus-gen/Cargo.toml` | clean, all three |
| `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`; the same on `--no-default-features --features wallet` | clean; clean |
| the wasm32 slice (`auth,wallet,transaction,overlay,socketio,wasm`) | builds |
| the test file under `full,http`, three runs (one `--test-threads=1`), and under `--no-default-features --features wallet` | 15 passed each |
| `cargo test --doc --all-features pushdrop_wallet_unlock` | 2 passed (the constructor's example and `sign`'s, both compiled) |
| `--test 'arch_*'` (37 binaries) | 195 passed, 0 failed, 1 ignored |
| `--test fixtures_replay` | 1 passed |
| `cargo +1.95.0 semver-checks check-release --baseline-rev origin/beta --all-features --release-type minor` (0.51.0) | 202 checks pass, 58 skip, no update required |
| `tools/ratchet/run --check --against origin/beta` | all 7 counters, oversized-file limits and mutation floors pass |
| `python3 .github/scripts/mutants_entries.py`; `rows_from_sources.py --check` | PASS, 28 entries; 0 refusals |
| `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` | no leaks |

Not run: the whole suite (`--tests`), the whole doc suite, `cargo doc`, the
conformance corpus files, the fuzz targets (no parser touched), a Linux cell.
