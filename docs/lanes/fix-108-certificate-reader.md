# Lane fix-108-certificate-reader: a length that wraps the reader's bounds check (#108)

**Repository.** `bsv-rs`, your worktree on a branch from `origin/beta`. `docs/lanes/README.md` binds you. Two hours.

**Read in this order.** #108 (the input, the panic's tail, the likely fix). `CLAUDE.md` rules 2 and 5 (a fix lands with a test that was RED before it; nothing panics on input; `primitives::bounded_capacity`; index with `get`). `src/auth/certificates/certificate.rs` (`BinaryReader`, `read_bytes` at `:350-357`, every other `read_*` on it, `Certificate::from_binary`, `MasterCertificate`/`VerifiableCertificate` binary paths), `src/primitives/encoding.rs` and the transaction reader for how this crate's other readers bound a length (`bounded_capacity`, `remaining`). `tests/auth_cross_sdk_tests.rs` and `tests/vectors/auth_certificate.json` (the certificate vectors; never edit a vector). `src/error.rs` for the error the refusal returns (`ReaderUnderflow` or the auth reader's own; say which and why).

**The work.**
1. The reader refuses before it allocates or slices: every length is compared to the bytes remaining with no sum that can wrap (`n > self.remaining()`, or checked arithmetic), every pre-allocation bounded by the bytes remaining, every slice through `get`. Audit every `read_*` of that reader and every other reader under `src/auth/` (messages, nonces, the Socket.IO and HTTP transports' decoders) for the same shape; fix each site found, named in the report.
2. The regression test, named for the finding (`a_certificate_length_that_wraps_the_bounds_check_is_refused` or like it), feeding the 189-byte input from #108 (as a Rust constant in the test, cited to the issue) and a minimal constructed input (a length field of `usize::MAX - k`), asserting `Err` and no panic; plus one test per sibling site you fix. Watch each RED on a scratch copy with the fix removed, GREEN after; the tails of both runs in the report.
3. `fuzz_auth_messages`'s crash inputs under `/Volumes/Lanes/out/bsv-rs/oracle-fuzz/run-10min/` (the 535 of this class): replay them through the fixed reader with the fuzz target or a test loop; zero panics, the count in the report.
4. `CHANGELOG.md` under `[Unreleased]`: a `### Fixed` line in the house's voice (what was wrong, which test pins it, found by #82's fuzz lane).

**Bounds.** No change to any wire format or verdict: a valid certificate still parses to the same struct (the vectors prove it). Nothing under `src/` outside the auth readers. `Cargo.toml` untouched. The harness run is not needed (nothing under `script/` or `transaction/`), say so.

**Report.** `REPORT: STATUS done|blocked`, the base and tip commits, the sites fixed, the RED and GREEN tails per test, the crash-replay count, the commands and their tails, the six tests each choice passes. Write the full REPORT before your turn ends: never leave the gate in the background and stop.
