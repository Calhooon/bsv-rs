# Kill lane: `src/script/templates/multisig.rs` (#681)

Base: `origin/beta` at `2a3b9e77371f1552c42892a7de93129c94313910` (the worktree opened at
`efe12e63`, main's tip; reset to `origin/beta` before any edit). The node is read at
`879fc8b` (`git show 879fc8b:<path>`); the TypeScript SDK has no Multisig template
(`tests/p2pk_hybrid_625.rs`'s module docs), and its clone is absent on this host, so its
citation is left out.

## The measure

`cargo mutants --jobs 1` with the nightly's script-surface selection
(`nightly_mutants.py`'s `mutation_args("script", ...)`, `--file src/script/templates/multisig.rs`,
`--no-config`), in a scratch copy with its own target dir, six round-robin shards run one after
another (each under four minutes). The surface's selection, not the lane prompt's plain
`-- --features "full,http"` (every test target: past the ten-minute rule per shard), is what the
nightly runs; it does not include `tests/p2pk_hybrid_625.rs`, which is why the #625 survivors stood.

| Run | Caught | Missed | Timeout | Unviable | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| Issue #681 (run 41579707627) | 33 | 13 | 0 | 1 | 71.74% |
| Baseline at the base | 33 | 13 | 0 | 1 | 71.74% |
| Final at the tip | 45 | 1 | 0 | 1 | 97.83% |

The baseline reproduces the issue's counts and the same 13 survivors.

## The kills

Every test is in the file's own `#[cfg(test)]` module (the file is 593 lines, under the 800
bound; the lib tests are in the nightly's selection). Each was RED with its mutant applied by hand
in the scratch copy and GREEN on the tip.

| Mutant | Killed by |
| --- | --- |
| `114:19` `\|\|` to `&&` (`lock_from_keys`, the key count) | `a_key_count_of_257_is_refused_not_written_as_a_count_of_one` |
| `238:14` `>` to `==` (`lock`, the key count) | `a_key_count_of_257_is_refused_not_written_as_a_count_of_one`, `sixteen_of_sixteen_writes_op_16_twice_and_seventeen_keys_are_refused`, `a_threshold_equal_to_the_key_count_is_written_and_one_above_is_refused` |
| `238:14` `>` to `>=` | `sixteen_of_sixteen_writes_op_16_twice_and_seventeen_keys_are_refused`, `a_threshold_equal_to_the_key_count_is_written_and_one_above_is_refused` |
| `241:38` `>` to `==` (`lock`, m against n) | `a_threshold_equal_to_the_key_count_is_written_and_one_above_is_refused`, `a_one_of_one_and_a_two_of_three_lock_write_the_nodes_cscript_bytes`, `sixteen_of_sixteen_...` |
| `241:38` `>` to `>=` | the same three |
| `266:27` `-` to `/`, `266:27` `-` to `+`, `266:31` `-` to `+` (`n - 1 - j`) | `the_last_key_retagged_in_a_one_of_two_is_refused_as_every_spend_reaches_it` |
| `266:31` `-` to `/` | `the_last_key_retagged_...`, `a_retagged_key_with_enough_keys_after_it_is_avoidable_and_written` |
| `267:22` `<` to `>` (`after < m`) | `the_last_key_retagged_...` |
| `267:22` `<` to `==` | `the_last_key_retagged_...`, `a_retagged_key_with_enough_keys_...` |
| `267:22` `<` to `<=` | `a_retagged_key_with_enough_keys_after_it_is_avoidable_and_written` |

The split (the keeper's crate-contract pin ruling, 2026-11-02): twelve kills, two on the node's
rule and ten crate-contract pins, counted apart for this file. The node's two are `241:38` `==` and
`>=`, the 1 <= m <= n reading (`standard.cpp:135`) in the form `standard.cpp:315-324` writes. The
ten pin the template's own documented bounds, which no sibling rule of the node fixes (the node's
key bound is 20 before Genesis and `UINT32_MAX` after, not sixteen; the node writes any lock and
fails its spend, where `lock` refuses one every spend fails): `114:19` and `238:14` `==` and `>=`
on the 16-key bound (`multisig.rs:103`, "Must have 1-16 keys"), and the seven of `266:27`,
`266:31` and `267:22` on #625's reachability refusal (`multisig.rs:224-229`). Each test that makes
one of the ten carries the line "crate-contract pin, no sibling rule, stated: `multisig.rs:<line>`"
(`sixteen_of_sixteen_...`, `a_key_count_of_257_...` and the `n = 16` cell of
`a_threshold_equal_to_the_key_count_...` at `:103`; `the_last_key_retagged_...` and
`a_retagged_key_with_enough_keys_...` at `:224-229`); the pins are re-cited if a sibling rule of
the node lands for either bound. `a_one_of_one_and_a_two_of_three_...` keeps its node citation.
The one survivor is the candidate `108:19` below, the error message its only difference.

The sources: the node's form `CScript() << m << keys << n << OP_CHECKMULTISIG`
(`src/script/standard.cpp:315-324`), a count of 1 to 16 as `OP_1`..`OP_16`
(`src/script/script.cpp:224-229`), 1 <= m <= n (`standard.cpp:135`), the key bound 20 before
Genesis and `UINT32_MAX` after (`src/consensus/consensus.h:50,55`; `interpreter.cpp:1531-1532`).
The template's own bound is 16 keys (the small-integer counts): a crate-contract pin, labeled in
the tests by `lock_from_keys`'s rustdoc ("Must have 1-16 keys, and threshold <= N"). The #625
tests are labeled by `lock`'s rustdoc (refused "when the n - 1 - j keys after it cannot meet
the threshold") and cite the walk at `interpreter.cpp:1588-1611` and `CheckPubKeyEncoding`
(`:312-315`). Every assertion is on the verdict and the error variant, none on the words.

The 257-key test answers the lane prompt's reading of `lock_from_keys`'s two `&&` survivors:
they are not an empty key list and a wrong key length (a `PublicKey` is always 33 bytes
compressed) but the threshold check (`108`) and the key-count check (`114`). Without `114`'s
`||` a count of 257 reaches `small_int_to_opcode(n as u8)`, `257 as u8` is 1, and the lock is
written as `OP_1 <257 keys> OP_1 OP_CHECKMULTISIG`; `lock`'s `238:14` `==` does the same.

## The candidate

`108:19`, `||` to `&&` in `Multisig::lock_from_keys` (`m == 0 || m > 16`). With `&&` the
condition is false for every `u8`. A threshold of 0 then passes `114` (on n alone) and `120`
(`0 > n` is false) and is refused by `small_int_to_opcode(0)` as `Error::CryptoError`; a
threshold of 17 to 255 is refused at `120` as `Error::CryptoError`, since `114` has bounded n to
16 or refused it as `CryptoError` already. Every input gives the same verdict and the same error
variant on both forms; only the message differs, and a kill on message text does not count. Its
share of the floor: 1 of 46 viable, 2.17 points (97.83% with it standing, 100% if declared). No
`exclude_re` entry is written by this lane.

## The timeouts

None at the base, none at the tip.
