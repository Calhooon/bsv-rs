# Kill lane: `src/script/spend/key_point.rs` (#681)

Base: `origin/beta` at `2a3b9e77371f1552c42892a7de93129c94313910` (the worktree opened at
`efe12e63`, main's tip; reset to `origin/beta`). The node is the reference for this file
(`~/bsv/bitcoin-sv` read at `879fc8b` by `git show`); the TypeScript clone is absent on this
host, so no TS citation is made.

## Why the survivors stood

The #660 pins (`tests/pubkey_encoding_660.rs`, `tests/pubkey_point_shapes_660_adv.rs`) assert
exactly what the `||` and `true` mutants break (a non-point under `<key> OP_CHECKSIG OP_NOT`
valid), but the nightly's script surface runs `--lib` and `tests/script_*.rs` plus five named
targets (`.github/scripts/nightly_mutants.py`, `SURFACES["script"]`, `mutation_args`), and
neither `pubkey_*` file is in that selection. The kills are library tests, so the oracle
reaches them.

## Before and after

Measured with the nightly's own arguments (`mutation_args("script", ..., [key_point.rs])`,
`--locked` dropped as no lockfile is committed), `--jobs 1 --no-config` (the fold's row with the
configuration, so its entry applies), in a scratch copy with its own target dir:

| Run | Caught | Missed | Timeout | Unviable | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline (base tree), reproduces #681 | 1 | 3 | 0 | 1 | 25.00% |
| Final (#681) | 3 | 1 | 0 | 1 | 75.00% |
| Fold (#684), the entry applied | 3 | 0 | 0 | 1 | 100.00% |

## Kills (`src/script/spend/key_point_tests.rs`)

| Mutant | Test | RED | GREEN |
| --- | --- | --- | --- |
| `key_point.rs:37:45` `&&` to `\|\|` in `check_public_key_point` | `a_key_that_is_no_point_passes_the_encoding_check_and_checks_false_in_every_mode_681` | `02\|\|0`, default v1, CHECKSIG: an `Err` at the encoding check where the tip is valid | tip: valid in every mode |
| `key_point.rs:27:9` `reads_the_reference_point` to `true` | the same test, and `an_x_past_the_field_prime_is_no_signature_key_in_every_mode_681` | the former as above; the latter at `signature_key(03\|\|p+1)` returning `Some` | tip: `None` in every mode |

The `||` mutant is the two conditions each alone: with the switch `false`, `||` leaves the
reference's `fromDER` reading as the whole condition, which the non-point test refuses to
see at the encoding check. The `true` mutant has no input on which the tip's switch reads
otherwise (it is the constant `false`); its kill is the input on which the two readings
differ: a key the reference's reading accepts and the node refuses (`03||p+1`, x reduced to
1, a point, at `signature_key`), and a key the reference's reading refuses at the encoding
check (`02||0`). The node: `IsCompressedOrUncompressedPubKey`
(`src/script/interpreter.cpp:132-152`) behind `CheckPubKeyEncoding` (`:312-317`), reached at
`:1465` and `:1611`; `CPubKey::Verify`'s `secp256k1_ec_pubkey_parse` (`src/pubkey.cpp:183-194`).

`a_wrong_length_or_prefix_is_refused_as_the_scripts_error_in_every_mode_681` (a 33-byte `04`,
a 65-byte `02`, a 32-byte key, both sites, every mode, an `Err` with `resource_limit: None`)
is the issue's reading; it kills none of this file's mutants, since those keys are refused in
`crypto.rs`'s `check_public_key_encoding` before `check_public_key_point` is called.

## Declared equivalent (the #684 fold)

- `check_public_key_point` to `Ok(())`, at `key_point.rs:39:9` since the fold (`37:9` above,
  before its two-line rustdoc note; the kills' mutants moved with it, `&&` to `||` to
  `39:45`). The body is `if self.reads_the_reference_point() && <..> { return Err(..) } Ok(())`
  and `reads_the_reference_point` returns the literal `false` (`key_point.rs:26-28`), the
  node's reading in every mode (#660), so `&&` short-circuits and the body is `Ok(())` on every
  input, `from_reference_der` never evaluated (no side effect lost).
- Three reads, 2026-11-03, on `4a54f025`: the rule read (DECLARE, 0.96), the adversarial read
  (EQUIVALENT, 0.97), the design read (DECLARE, 0.85); the switch kept as the stated
  divergence's fold path.
- The entry, `.cargo/mutants.toml`, with its comment block:
  `'^src/script/spend/key_point\.rs:39:9: replace Spend::check_public_key_point -> Result<\(\), ScriptEvaluationError> with Ok\(\(\)\)$'`.
  `.github/scripts/mutants_entries.py` (#663): `PASS mutants-entries: 28 entries, each one
  listed mutant (8 files, 1307 mutants listed)`. The entry is removed when the switch reads a
  flag or a feature (the rustdoc's fold to `self.flags.is_none()`), where the kills above cover
  the mutant in the default mode.
- The file's score with the entry: 3 caught of 3 viable, 100%. Measured with the
  configuration (so the entry applies) and the nightly's arguments (`mutation_args("script",
  ..., [key_point.rs])`, `--locked` dropped), `--jobs 1`, in a scratch copy with its own
  target dir, as two round-robin shards: 4 of 5 listed mutants tested, 3 caught (`27:9`,
  `39:45`, `48:9` to `None`), 0 missed, 0 timeout, 1 unviable (`48:9` to
  `Some(Default::default())`), the declared `39:9` excluded.

## Timeouts

None.
