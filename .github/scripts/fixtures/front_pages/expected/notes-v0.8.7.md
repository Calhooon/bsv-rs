A security patch on the stable line. To upgrade: `cargo update -p bsv-rs` (a `"0.8"` requirement takes it).

## Changes

- Fixed: Thing::read refuses bytes after the thing, as the reference does (#901)
- Changed: The gate runs the page script's tests on every pull request (#902).
- Changed: The reconciler names each gap (#903).

The section carries 1 cross-SDK parity note(s); the changelog at the tag has them.

## Migration

- (#901) Migration. A caller that passed bytes after the thing now gets an `Err`. No public type or signature changes.

## Advisories

- Fixes [GHSA-aaaa-bbbb-cccc](https://github.com/example/bsv-rs/security/advisories/GHSA-aaaa-bbbb-cccc) (medium, CVSS 5.3): bsv-rs: Thing::read kept bytes after the thing. Its other affected range(s): `>= 0.9.0-beta.1, <= 0.9.0-beta.1` (no patched version yet).

## Measured at this tag

- The ts-stack corpus (`tests/conformance_scripts.rs`, every vector run or counted under a named reason): `total=5116 run=4121 passed=4110 unsupported=958 skipped=37 known_failures=11 failures=0 panics=0`.
- The test suite, Linux stable: 1,860 passed, 0 failed, 135 ignored or skipped (the sum of 2 `test result:` line(s)).
- The script oracle (bsv-script-lean, a Lean specification of bitcoin-sv's script interpreter): not run on this line (no `CI / sibling` job in this run).
- wasm32 slices that passed: combined, relay.
- Dependents built against this tree: 2 (bsv-tracker, bsv-wallet-toolbox-rs).
- The run: https://github.com/example/bsv-rs/actions/runs/7

[Changelog at v0.8.7](https://github.com/Calhooon/bsv-rs/blob/v0.8.7/CHANGELOG.md) · [crates.io](https://crates.io/crates/bsv-rs/0.8.7) · [docs.rs](https://docs.rs/bsv-rs/0.8.7)
