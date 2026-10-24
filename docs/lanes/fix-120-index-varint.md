# Lane fix-120-index-varint: a varint output index above u32::MAX is refused, never cast (#120)

**Repository.** `bsv-rs`, your worktree on a branch from `origin/beta`. `docs/lanes/README.md` binds you. Two hours.

**Read in this order.** #120 and the keeper's ruling in its comment (refuse; a typed refusal naming the field; the boundary tests). `CLAUDE.md` rules 1, 2, 5. The five sites: `src/auth/certificates/certificate.rs:187` (the revocation outpoint's index), `src/wallet/wire/encoding.rs:197, 439, 603, 641` (outpoints and output indexes in the wire frames). `src/error.rs` for the error to return: the wire reader's existing error for a malformed field if it has one (read how `encoding.rs` refuses a bad count or an over-long string and use the same variant and wording shape), else `ReaderUnderflow` is wrong (nothing is short) and a variant that names the field is right; say which and why. `tests/wire_method_roundtrip_tests.rs`, `tests/wallet_wire_cross_sdk_tests.rs` and the 54 message files under `tests/vectors/wallet_wire/` (every valid index must still read; never edit a vector). BRC-100 at the line's pin (`git -C ~/bsv/brcs show ed1b015:wallet/0100.md`) for the frames that carry an index.

**The work.**
1. One helper on the wire reader (and the certificate reader, or shared if they share a reader) that reads a varint and refuses a value above `u32::MAX` with the typed error naming the field; the five sites call it. No `as u32` on a varint remains in `src/auth/` or `src/wallet/wire/` (grep and show).
2. Tests RED on a scratch copy without the fix, GREEN after, named for the finding, one per site: `u32::MAX` accepted and read back exactly, `u32::MAX + 1` refused with the typed error naming the field; built by this crate's own writer where a writer exists, else by hand-assembled bytes cited to the frame's BRC-100 table.
3. Every existing wire test and vector green (`cargo test --features "full,http,websocket" --test wire_method_roundtrip_tests --test wallet_wire_cross_sdk_tests` and the full suite).
4. `CHANGELOG.md` under `[Unreleased]`: a `### Fixed` entry in the house's voice, with the keeper's reading in one clause and the TypeScript reader's unbounded number noted as the reference's own gap.

**Bounds.** No change to any valid wire byte or to any BRC-100 shape; no change outside the five sites, the helper, the error variant if new, tests and the changelog. `Cargo.toml` untouched. The harness run is not needed (nothing under `script/` or `transaction/`), say so. Lanes never push; do not open the PR.

**Report.** `REPORT: STATUS done|blocked`, the base and tip commits, the sites, the RED and GREEN tails per test, the grep showing no cast remains, the commands and their tails, the six tests each choice passes. Write the full REPORT before your turn ends: never leave the gate in the background and stop.
