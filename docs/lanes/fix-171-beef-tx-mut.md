# Lane: fix-171-beef-tx-mut. `BeefTx::tx_mut` leaves `input_txids` stale; one entry, one reading (#171)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 2, 7, 9), `src/transaction/CLAUDE.md`, `tests/CLAUDE.md`, `benches/CLAUDE.md` and issue #171 (`gh issue view 171 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The finding

`BeefTx` caches `input_txids` (`src/transaction/beef_tx.rs`); only the constructors and `set_bump_index` write it. `tx_mut` hands out the parsed transaction mutably and does not refresh the cache, so after a caller rewrites an input's `source_txid`, `sort_txs` (`beef.rs`) and `verify_structure` read the old list while `to_binary_atomic`'s closure reads the new transaction, and `write_tx_data` emits the raw bytes the entry was read with. A mutated entry is three different things. `tests/beef_cycle.rs`'s in-memory fixture sets the cache by hand today because of this.

## The work (no public method is removed: that is the owner's word and NOT yours; choose between the issue's other two)

1. Read the one in-crate caller (`beef.rs`, `tx_mut`'s read-only use) and grep the on-disk dependents (`~/bsv/bsv-overlay-cloudflare`, `~/bsv/rust-message-box`, `~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`; NEVER `~/bsv/bsv-low`) for `tx_mut`; report each.
2. Either (a) `tx_mut` returns a guard whose `Drop` recomputes `input_txids` and the raw bytes (`write_tx_data` then emits the mutated transaction's serialization, so the wire sees what the readers see; say what happens to a pinned `bump_index` and to `raw`), or (b) the cache goes and every reader derives the inputs from the transaction on each read, with the cost measured on `benches/` BEEF benches before and after (a regression over 10 percent is a finding to report, not to hide). Say which you chose and why in the changelog entry. If (a), the guard's type is a new public type: name it, keep it minimal (`Deref`/`DerefMut` to `Transaction`), and say so; if that reads to you as a public shape change beyond the owner's standing word for 0.9.0 additions, STOP and report rather than invent.
3. Rule 2: a RED-before test: mutate an input through `tx_mut`, then `sort_txs`, `verify_structure` and the atomic writer all read the new input and the written bytes carry it. `tests/beef_cycle.rs`'s by-hand cache setting goes if the fix makes it needless (say so).
4. Docs: the changelog entry; `src/transaction/CLAUDE.md`'s row for `beef_tx.rs`.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --test beef_stream --test beef_cycle --test beef_tests` (the BEEF test files by name: `ls tests/ | grep -i beef`, each `--test`); `cargo test --lib transaction::beef --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-171-beef-tx-mut` (fresh; never re-record a baseline). The conformance files with `BSV_CONFORMANCE_DIR=$HOME/bsv/ts-stack/conformance`: `cargo test --features full --test conformance_beef` (its pinned totals must hold).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#171)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the callers found; the option taken and why; any public type added (name, signature); the RED proof and the green run (every gate command with its result line); the bench numbers if (b); anything you could not do and why.
