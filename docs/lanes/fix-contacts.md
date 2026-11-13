# Lane fix-contacts (#904, and #907's line 1)

Started from `43ee8c85` (`origin/beta`'s tip at the start, checked by `git fetch` and `git rev-parse`). The reference is `ts-stack@edf6e03` `packages/sdk/src/identity/ContactsManager.ts` (`CM` below), bundled with bun as the #326 recorder's header says and run under Node v22.18.0.

## The sites side by side

| step | reference (`CM`) | base (`43ee8c85`) | tip |
|---|---|---|---|
| the source for the authentication | `#readListedSource`, `Transaction.fromBEEF(BEEF, txid)` (`:633-659`) | the BEEF's entry under the txid (`contacts_actions.rs:93-118`) | `listed_source`: `#readListedSource` whole, its answer `ListedSource` |
| the source for the spend | the same reading again (`:784`, `:948`) | `beef.txs.first()` at the listed index (`:416-427`) | the same `ListedSource` |
| the input signed | `#findBoundInput` (`:666-697`, `:819`, `:987`) | `input_index: 0` (`:441`) | `find_bound_input` (`contacts_spend.rs`) |
| the spend key | `{ [inputIndex]: .. }` (`:835`, `:1002`) | `0` (`:389`) | the bound index |
| after signAction | `tx` required, template, input unmoved, signature kept, output present (`:839-851`, `:1006-1015`) | `tx` or `txid` taken as done (`:273-275`, `:363-367`) | `check_signed` |
| on failure past createAction | `#abortPartialAction` (`:738-745`) | nothing | `spend_listed` aborts by reference, the failure returned |
| `saveContact`'s wallet errors | through (`:536-546`, `:882`) | HMAC, listing, createAction swallowed (`contacts.rs:119-157`) | through |
| the cache | after the chain (`:566`, `:912`, `:919`) | written whatever happened; removal emptied it before any wallet call | after the chain |
| `removeContact` of an uncached key | asks the wallet | `ContactNotFound` | asks the wallet |
| the listing's failure | throws (`:353-368`) | `Ok(vec![])` (`contacts_cache.rs:46-52`) | through |
| the requests | `Add Contact`, `Update Contact`, `Delete Contact`, `Spend previous contact output`, `Spend contact output to delete`, `Contact: <name>`, `Updated Contact: <name>`, `outputs: []`, no label, `{ acceptDelayedBroadcast: false, randomizeOutputs: false }` | the name or key added to the descriptions, other input descriptions, the key's ten characters, `contacts` label, `signAndProcess`, `noSend: true` on the spends | the reference's |

The class (rule 11): the other three callers of `wallet::pushdrop::sign` read by outpoint. `src/identity/revoke.rs` signs the authenticated transaction's output at the one input at the outpoint (`input_outpoint`, `:462`); `src/registry/unlock.rs` finds the input by outpoint and signs over the record's listed script and satoshis (#548's residue, the record not read from its BEEF); `src/kvstore/token_spends.rs` finds the input by outpoint and signs over the signable transaction's linked source (#343's row). Not run at their doors with item 1's two-entry listing in this lane (see the REPORT); the machine over all four is `tests/arch_listed_spend_binds_its_input.rs`.

## The runs on the base (item 1)

`tests/contacts_listed_spend.rs` on the base (`base_listed.log`; a probe copy priming the cache by an update for the removals, `base_remove_probe.log`, deleted after the run):

- token at C's output 0 after its parent P (P's output 0 the token's lock at 1000 satoshis): the update's and the removal's unlocking script refused against C:0 (`OP_CHECKSIG requires failing signatures to be empty.`) and valid against P:0 (`Some(Ok(true))`), the output signed.
- token at C's output 1, P of one output: `IdentityError("Unable to update contact")`, no signAction.
- the contact's input at index 1: the spend keyed `[0]`.
- an uncached removal: `ContactNotFound`.

The reference on the same listings (`tests/vectors/contacts_listed_spend.json`): every case `ok`, the spend keyed `0`, `0` and `1`, its removal's unlocking scripts this crate's tip's byte for byte. Row 2: every cell of the brief's items 3 and 4 recorded beside its run (`contacts_wallet_failures.rs`); the update's failed createAction was already returned on the base (a control, green on both).

## The RED names

On a scratch copy of `43ee8c85` (`git archive`, the three test files, the double and the vector overlaid; target `/Volumes/Lanes/targets/fix-contacts-red`, removed after the run): `contacts_listed_spend` 7 of 7, `contacts_wallet_failures` 12 of 13 (`an_update_whose_create_action_fails_returns_the_wallets_error_contacts` the control), `arch_listed_spend_binds_its_input` 1 of 2 (`every_caller_of_the_pushdrop_signer_is_listed_and_binds_by_outpoint`, naming the literal index, the literal key and `txs.first()`; the probe-text test green). All green on the tip.

## The tests moved off the swallow

`src/identity/contacts_tests.rs` (an in-file `Answering` double), `tests/identity_tests.rs`' contacts module, `tests/identity_spend_witness.rs` (the two contact tests stop at the mock's signAction in the reference's words), `tests/contacts_signaction_326.rs` (and it reads #326's `create_action_options`, `abort_action`, `stopped`), `tests/identity_contact_abbreviated_key_559.rs`, `identity_contact_badges_552.rs`, `identity_contact_badges_558.rs`, `identity_contact_shape_552.rs`, `identity_contacts_envelope_544.rs`, `identity_contacts_protocol_542.rs`, `identity_from_identity_abbreviated_key_568.rs` (over `Counting::answering_contacts`, the txid-only signAction answer removed).

## The gate

Run in a private target (`/Volumes/Lanes/targets/fix-contacts-tip`, removed before the REPORT): the shared target served a stale library from another build mid-lane. The counts are in the REPORT.

## The fold (lane fix-contacts-fold, PR #929 after its three reads)

The picks: the rule read's `e9049469`, the strength read's `1c2ad8af` and the cold read's `6d9fac26`, then a rebase onto `origin/beta` `4dc92be3` and again onto `ad43c269` (#886, no vector; the figures below held there, the whole suite green). The rule and cold commits rewrote one rustdoc (`remove_contact`'s errors); the cold read's wording is kept, as it names the decrypt beside createAction and signAction (all three under the wrapper in `remove_listed`, the code at `contacts_actions.rs:320-329`) and matches its module row in `src/identity/CLAUDE.md`; the line range `:908-918` is the loop that holds the `try`.

The census (the cold read's FIX): the new vector holds nine distinct BEEFs no other vector holds (three listings, V1, no BUMP; six Atomic signable transactions over V1, three entries each, no BUMP), each read by `Beef::from_binary` and none valid under `verify_valid` (nothing proven), which the sweeps do not ask. Three pinned totals moved, each read off its failing assertion's `left` on the rebased tip: `prepass_621_tests.rs` `read` 363 to 372, its split `(2467, 3704, 1789, 252)` to `(2566, 3758, 1789, 252)` (6,324 = 17 x 372); `beef_v1_txid_only_writer_817.rs` `SWEPT` `(363, 126)` to `(372, 135)`; `beef_writer_refusals_817.rs` `6 * 363` to `6 * 372` (2,232). The cold read named the pre-pass census; the two sweeps read the same seeds and were not named there.

### Rows left (the strength read's survivors, after-cut)

Pinned by the fold: `find_bound_input`'s `[index]` as `[index, ..]` (`contacts_spend.rs:63`) and the signable's output check dropped (`contacts_actions.rs:414`), by `an_update_whose_signable_transaction_is_not_the_requested_one_is_aborted_unsigned_contacts`. Left, each needing a new double mode or input rather than one assertion:

- `contacts_spend.rs:83-91`: the per-input outpoint and sequence check in `assert_template` (no sign mode moves an input's outpoint or sequence; `sequence` is a create mode, which moves the signable, not the signed).
- `contacts_spend.rs:112`: `!= 1` as `== 0` in `require_contact_output` (needs a signable with the contact output twice; no create mode writes one).
- `contacts_spend.rs:18`: the 16 MiB BEEF bound moved by one (needs a listing BEEF of 16 MiB plus one byte).
- `contacts_cache.rs:52`: the 1000-entry listing bound dropped (needs a listing of 1001 outputs).
- `contacts_actions.rs:252`: the created transaction's output check dropped (the double always writes the outputs it was asked for).
- The arch scan's `use`-import gap (`tests/arch_listed_spend_binds_its_input.rs` finds callers by the text `pushdrop::sign(`).
- From the rule read: the arch test's header says each door's sources are "returned in reverse", true of the stores' test alone; the full contacts listing sends `tags: None` where the reference sends `tags: []` (older than #904).

## The second fold (lane fix-contacts-fold2, PR #929 after the scoped re-read of the fold)

Item 1, the assertion that could never fail: `contacts_wallet_failures.rs:287` asked that the calls not contain `"signAction"`; the double records `"sign_action"`. The siblings by a run: every string literal in `tests/contacts_*.rs` and `tests/identity_*.rs` that is a `WalletInterface` method name in either case was listed and read (71 lines). 48 occurrences name a call the double records, in six files (`contacts_wallet_failures.rs` 19, `identity_reveal_verifies_307.rs` 8, `identity_reveal_create_action_315.rs` 1, `identity_reveal_rest_310.rs` 5, `identity_wallet_calls_318.rs` 7, `identity_revocation_checks_327.rs` 8); 47 named a recorded name, one did not (`"signAction"` at `:287`). The rest are the reference's camelCase names compared with a recording, or a vector's keys (`case["sign_action"]`), not the double's names. The form taken: a macro, `wallet_call!(<method>)` in `tests/support/identity_reveal_wallet.rs`, the method's identifier, checked by the compiler against `WalletInterface` (`W::<method>` for a `W: WalletInterface`); the double records every name through it and the 48 occurrences are written through it, so a wrong name is E0599, not a test that passes (true of a name no trait in scope answers; `from` compiled through `From::from`, the third fold's finding 1, below). An enum of calls would have changed the `calls()` type for the 43 files that include the double; the macro keeps it.

The REDs, on a scratch copy of the tip (removed after the runs): `find_bound_input`'s `[index]` as `[index, ..]` with the update test's error assertion removed: RED at `:287` (the assertion, which rustfmt split; the panic names its `assert!` at `:295`) (`duplicate_input`; the re-read's `vacuous.log` shows the old string passing under the same plant); `wallet_call!(signAction)` at `:287`: `error[E0599]: no associated function or constant named signAction`.

Item 2, the removal's refusal: the recorder (`contacts_listed_reference.mjs`) gains a `bind` state that writes the signable transaction as this crate's counting wallet's `create_mode` does (the contact's input twice; its output index moved to 1), and two cases at the end of `cases`, `remove_duplicate_input` and `remove_missing_input`, each kept as its calls, signAction, aborts and outcome alone so the vector holds no new BEEF (the census figures unmoved: 372, (372, 135), 2,232). The reference refuses both before signAction (`Unable to authenticate or remove a contact output`, cause `Contact transaction does not spend the exact contact outpoint once`) and aborts by its reference. Two runs under Node v22.18.0 byte-identical; the 17 earlier cases byte-identical. `a_removal_whose_signable_transaction_does_not_spend_the_contact_once_is_aborted_unsigned_contacts`: this crate's error the wrapper alone (the stated residue), no `sign_action` call, the call list the recording's, one abort by its reference. RED with the plant P1 (the removal path's `find_bound_input` taken as `unwrap_or(0)` when there is no lock): `duplicate_input: [.., "create_action", "create_signature", "sign_action", "abort_action"]` at the `sign_action` assertion.


## The third fold (lane fix-contacts-fold3, PR #929 after the re-read of its second fold)

Picked the re-read's `63b3d540` (two RED line numbers), rebased onto `origin/beta` `f549192a` (0.8.9's security release and its sync; one CHANGELOG conflict, both sides kept) again onto `b6972335` (#843d23, which landed during the lane; no conflict) and onto `a1e01fbf` (#848, #818b, #914 and #843d7, four more that landed; no conflict, the gate re-run there). No vector of either beta moved a census figure: the three census files pass with the second fold's figures (372, `(372, 135)`, 2,232).

Finding 1, the macro: `W::$method` resolved through any trait in scope, so `wallet_call!(from)` compiled (`From::from`) and an assertion through it could not fail. The macro is now `tests/support/wallet_call.rs`, `<W as bsv_rs::wallet::WalletInterface>::$method`, included by the double; `from` and `signAction` are E0576 (rustc 1.98.1, a probe compiled in the test binary). Held by three doc tests on `WalletCallMacroDocTests`, a `cfg(all(doctest, feature = "wallet"))` item of `src/lib.rs` that includes the same file (no item of the crate's API): `sign_action` and `create_signature` compile, `from` and `signAction` do not. RED: with the macro put back to `W::$method`, the `from` block compiles and its doc test fails (`doc-macro-red.log`). Rustdoc on stable checks that a `compile_fail` block fails, not its error code (the `signAction` block passed under the old form, where the code is E0599).

Finding 2, the update signs before it refuses: three cells added to the recorder after the removal's two, `update_duplicate_input`, `update_missing_input` and `update_output` (a `bind` of `output` writing the signable's leading output at 0 satoshis, as the double's `create_mode` `output` does), kept as the removal's are; the reference refuses each after createAction with no createSignature and aborts (`:819-820` before `:821-830`). The update test now compares the call list with the recording less its cold `listOutputs` (`:529-531`, the stated residue) and asks that no `create_signature` follow the last `create_action` (the lock's own createSignature comes before it, so a list without the name could not be asked). RED with the update signing (input 0) before `find_bound_input`: at `:307`, `duplicate_input: [.., "create_action", "create_signature", "abort_action"]`.

Finding 3, a removal that fails at its spend dropped the cached contact: `a_removal_that_fails_at_its_spend_keeps_the_cached_contact_contacts` caches the contact by an add over an empty listing, lists the token, and fails the removal three ways past the listing (signAction with no transaction, createAction failing, signAction failing): the contact stays cached; the same wallet signing, the removal `Ok` and the contact gone (`:908-919`). RED with the cache entry dropped before the loop: at `:420`, `sign_no_tx: a failed spend dropped the cached contact`.

The recording: 27 cases (19 before), the 19 earlier byte-identical, two runs under Node v22.18.0 byte-identical (`rec3.json`, `rec4.json`); no new BEEF.

### The sweep (item 4)

`cargo mutants` 27.1.0, `-f src/identity/contacts_actions.rs`, `--jobs 1`, `--baseline skip` (the tip green by the gate's runs), nine shards each under ten minutes, against the 17 test files that reach the manager (`arch_listed_spend_binds_its_input`, `contacts_listed_spend`, `contacts_signaction_326`, `contacts_wallet_failures`, the eleven `identity_contact*`, `identity_from_identity_abbreviated_key_568`, `identity_spend_witness`, `identity_tests`, `pushdrop_lock_key_order_816`, `script_pushdrop_key_bytes_545`; the lib's `contacts_tests.rs` not in the run). 55 mutants: 9 unviable, 31 caught, 15 missed on the tests after findings 2 and 3. Six of the 15 (`find_existing`'s `> 100` as `==` and `>=`, the no-match guard as `true`, the different-identity arm deleted; `remove_contact`'s `> 100` as `==` and `>=`) are caught by `the_lookups_bounds_and_another_identitys_token_are_the_references_contacts` against five new recorded cells (`update_other_identity`, `update_listing_100`, `update_listing_101`, `remove_listing_100`, `remove_listing_101`, kept as their call count, signAction count and outcome), each confirmed on a re-run (`mut-re.log`). Of the 15, only `:11` is a line this pull request wrote; the rest are older than #904. Final: 55 made, 37 caught, 9 unviable, 9 not caught.

### Rows left (the third fold's sweep)

- `contacts_actions.rs:11:42`, `(1 << 53) - 1` as `+ 1` or `/ 1` (2^53 + 1, 2^53): equivalent at every door. The bound is read by `listed_source` on an output `Transaction::from_beef` gave it, and `Beef::from_binary` refuses an amount above `MAX_MONEY` (21e14, below both) before it (`ValueOutOfRange`, the #844 row), so no source of 2^53 - 1 to 2^53 + 1 satoshis reaches the comparison.
- `contacts_actions.rs:427:36`, `SIGHASH_ALL | SIGHASH_FORKID` as `^`: equivalent; the bits are disjoint (0x01, 0x40), as the excluded `template.rs:210:36` entry states.
- `contacts_actions.rs:63:28`, the plaintext bound `>` as `==` or `>=`: out of scope (older than #904); a record `validateContact` admits stays below 64 KiB of JSON (metadata at most 32 KiB, every field bounded), so the bound needs a record built past the validator.
- `contacts_actions.rs:75:21`, the encrypt's `counterparty: Some(Self_)` deleted: out of scope (older than #904); the ProtoWallet and BRC-100 default an absent counterparty to self, so the verdict holds, but the request differs on a JSON wire; the double records no encrypt arguments, and a recording of them is a later lane's.
- `contacts_actions.rs:82:34` and `:82:54`, the ciphertext bounds (`||` as `&&`, `>` as `==` or `>=`): out of scope (older than #904); each needs a wallet answering an empty, a 66,560-byte or a 66,561-byte ciphertext, a double mode no test has.

## The fourth fold (lane fix-contacts-fold4, PR #929 after the re-read of its third fold)

Picked the re-read's `1d48c688` (the call-name sentence scoped), rebased onto `origin/beta` `b36bca93` (the third fold's base; no move, no conflict). No census figure moved: the vector's new cells hold no BEEF.

The re-read's two FIXes, each a plant on a line this pull request wrote that passed every test: `contacts_actions.rs:332` with `remove` as `clear` (a removal dropping every cached contact), and `:412-415` with the update's two checks of the signable transaction swapped. Both are pinned below, and each one's kind is swept.

### Item 1's kind: every cache write this pull request touches, held with two entries

Each test holds Bob and Carol (the scalars 3 and 4) and tells "this entry" from "every entry". Plants run in a scratch copy of the tip, each alone, against `tests/contacts_wallet_failures.rs` (logs `plant-*.log` in the lane's out folder).

| The write | The test | The plant | RED |
|---|---|---|---|
| `contacts_actions.rs:332`, the removal's entry dropped after the spend, kept on a failure | `a_removal_that_fails_at_its_spend_keeps_the_cached_contact_contacts` (Carol added; after each failure both cached, after the spend Bob gone, Carol kept, one entry) | P1: `remove(identity_key)` as `clear()` | `:463`, `sign_no_tx: the removal of one contact dropped another` |
| `contacts.rs:154`, the add's entry written after the chain (create, update, failure) | `the_cache_writes_touch_their_own_entry_alone_with_two_contacts_cached_contacts` (two adds, a failed add of Dave, Bob's update over his listed token) | P5: `contacts.clear()` before the insert | `:680` (two entries after the adds) and `:430` in the removal test (`left: 1`, `right: 2`) |
| `contacts_cache.rs:29-41`, a forced refresh whose listing fails | the same test, against the recorded `refresh_fails_after_two_saves` | P6: the cache kept on the failure (the tip before this fold) | `:754`, `a failed forced refresh kept the cache`, `left: 2`, `right: 0` |
| `contacts_cache.rs:39`, the cache marked not loaded when a forced refresh's listing fails (the fifth fold) | `a_failed_forced_refresh_over_a_loaded_cache_leaves_it_to_list_again_904` (a successful forced refresh loads the cache, two adds, a failed forced refresh, then a plain read), against the same recorded cell | plant A: the line deleted | `:814`, `left: ["list_outputs"]`, `right: ["list_outputs", "list_outputs"]` |

The third row is a finding of the sweep, not a plant: the reference's forced refresh drops its cache before it loads (`getContacts`, `ContactsManager.ts:321`, `#invalidate` `:343-347`), so one whose listing fails leaves it cold; the tip kept both entries (#904 had made the failure the caller's error and left the cache; before #904 the failure refreshed to none). Recorded (`refresh_fails_after_two_saves`: two saves, the forced refresh `listOutputs failed`, the plain read after it asking the wallet again, `["listOutputs", "listOutputs"]`) and conformed: `list_contacts_with_refresh(true)` drops the cache when its load fails (not before the load: `decode_cached_contact` reads each contact's saved-at time from the cache during it).

### Item 2's kind: every pair of refusals the update and the removal order, the two-fault cell recorded and pinned

Eleven cells added at the end of `cases` (27 to 38, then `refresh_fails_after_two_saves`, 39), each kept as its calls, signAction, aborts and outcome alone (no BEEF); the 27 earlier cases byte-identical; two runs under Node v22.18.0 byte-identical (`rec1.json`, `rec2.json`). The recorder's `bind` takes two faults and its signAction three (`signFaults`), as the double's `create_mode` and `sign_mode` do, joined by `+`. Pinned by `two_faults_at_once_are_refused_in_the_references_order_contacts`.

| The pair | The reference's answer | The cell | The plant that turns it RED |
|---|---|---|---|
| update: the bound input (twice) and the contact output | `Contact transaction does not spend the exact contact outpoint once` | `update_duplicate_input_and_output` | P2, `:412-415` swapped: `:889`, `left: ... does not contain the exact requested output` |
| update: the bound input (absent) and the contact output | the same | `update_missing_input_and_output` | P2 |
| update: the bound input (twice) and a signed fault | the bound input's words, no signAction | `update_duplicate_input_and_signed_version` | P8, the signable's checks after signAction (the input taken as 0 until then): each of the five cross cells RED alone (`plant-P8-cell-*.log`: the three update cells at the error, `left: ... substituted the authorized transaction template`; the two removal cells at the call list, `sign_action` called); the whole test RED at `:895` on its first cell, the earlier tests at `:317` and `:508` |
| update: the bound input (absent) and a signed fault | the same | `update_missing_input_and_signed_version` | P8 |
| update: the contact output and a signed fault | `Contact transaction does not contain the exact requested output`, no signAction | `update_output_and_signed_version` | P8 |
| update: the template's header and its outputs | `Signed contact transaction substituted the authorized transaction template` | `update_signed_version_and_output` | P3, `assert_template`'s header after its outputs: `:889`, `left: ... substituted an authorized output` |
| update: the template and the signature | the same | `update_signed_version_and_script` | P4, `check_signed`'s signature before the template: `:889`, `left: ... omitted or substituted the authorized signature` |
| update: the template's outputs and the signature | `Signed contact transaction substituted an authorized output` | `update_signed_output_and_script` | P4 |
| removal: the bound input (twice) and a signed fault | the wrapper, cause the bound input's words; no signAction | `remove_duplicate_input_and_signed_version` | P8 (the call list) |
| removal: the bound input (absent) and a signed fault | the same | `remove_missing_input_and_signed_version` | P8 |
| removal: the template and the signature | the wrapper, cause the template's words | `remove_signed_version_and_script` | none of its own: this crate's error carries the wrapper alone (the stated residue) and the call list is the same in either order; `check_signed` is shared with the update, whose cell is RED under P4 |

One signed fault stands for the three beside a signable fault: a signed fault lives in signAction's answer, which a signable fault never reaches. The removal's one output is the zero-satoshi `OP_FALSE OP_RETURN` both doubles write, so `signed_output` moves nothing there (recorded once and seen: its cell answered the signature's words) and its removal pairs are the version and the script alone. Pairs not recorded, each unreachable: the moved input (`contacts_spend.rs:161-163`) and the signed transaction's contact output (`:168-170`) come after `assert_template`, which compares every input's outpoint and every output, so neither refuses where the template passed, in the reference as here (`:847-851`); the signable parse and a failed signAction exclude every other fault; the two bound-input faults are one refusal.

### Item 3

`tests/arch_non_exhaustive_pins_819.rs` reads the doc suite's log by name: `OTHER_DOC_TESTS` adds `src/lib.rs - WalletCallMacroDocTests`, two `compile fail ... ok` lines and one plain line required, so an `ignore` on either of the macro's `compile_fail` blocks fails CI's step after the doc step. Green on the doc suite's log of the tip (375 passed; `the_doc_suite_ran_every_pinned_block_819` reads the three lines at 195, 205, 214); RED on that log with the line-205 block shown as rustdoc prints an ignored block (`... ignored`): `src/lib.rs - WalletCallMacroDocTests: 1 compile fail ... ok lines in the doc suite, where 2 must run`. The RED is an edited log, not a rustdoc run with the attribute planted.

### The bound

The fourth fold's sentence, replaced by the seventh fold's (its item 4, below): these tests hold, against the reference's recorded answers, what the update and the removal sign, send, refuse (alone and in pairs) and cache, with up to two contacts cached; they do not hold a scenario with three or more faults, a cache of three or more contacts, or the thirteen lines listed here:

1. `contacts_actions.rs:11`, the 2^53 source bound (equivalent: every BEEF reader refuses a larger amount ahead of it).
2. `contacts_actions.rs:63`, the plaintext bound (older than #904).
3. `contacts_actions.rs:75`, the encrypt's counterparty (older than #904).
4. `contacts_actions.rs:82`, the ciphertext bounds (older than #904).
5. `contacts_actions.rs:252`, the created transaction's output check (the double writes the outputs asked).
6. `contacts_actions.rs:427`, `SIGHASH_ALL | SIGHASH_FORKID` as `^` (equivalent: disjoint bits).
7. `contacts_spend.rs:18`, the 16 MiB BEEF bound.
8. `contacts_spend.rs:83-91`, `assert_template`'s per-input outpoint and sequence check (no sign mode moves an input).
9. `contacts_spend.rs:112`, `!= 1` as `== 0` (no create mode writes the contact output twice).
10. `contacts_spend.rs:161-163`, the moved input after the template (unreachable).
11. `contacts_spend.rs:168-170`, the signed transaction's contact output after the template (unreachable).
12. `contacts_cache.rs:36`, the forced-refresh guard: P7, the cache dropped on any failed load (`if true`), passes every test (19 of 19, `plant-P7-refresh-clears-always.log`); a plain load fails only while the cache is not initialized, and this crate's adds leave it so where the reference's cold save loads the basket first (`:529-531`, the stated residue), so the cell has no reference twin.
13. `contacts_cache.rs:67`, the 1000-entry listing bound (a listing of 1001 outputs): held by the replay since the seventh fold (its `pad` steps; the tool's two `:67` mutants caught).

### Rows left

- The removal's template-and-signature order (`remove_signed_version_and_script`) is held through the update's cell alone (the shared `check_signed`); a removal-only reorder would not be seen, and would change nothing a caller reads.
- The previous folds' rows stand (the arch scan's `use`-import gap; the arch test's header wording; `tags: None` against `tags: []`).

Each plant ran in a scratch copy of the tip (`git ls-files` synced into the lane's out folder, target `/Volumes/Lanes/targets/fix-contacts-fold4-scratch`), against `tests/contacts_wallet_failures.rs` alone: P1, P2, P3, P4, P6 1 of 19 RED, P5 2 of 19, P8 3 of 19, P7 0 of 19 (`plants-final.txt`). P1 and P2 are the re-read's plants, which its logs show passing every contacts and identity test before this fold.

## The fifth fold (lane fix-contacts-fold5, PR #929 after the re-read of its fourth fold)

Rebased onto `origin/beta` `b93f81bd` (from `b36bca93`; no conflict, no census figure moved: the fold adds no vector cell).

The re-read's one FIX, plant A: `cache.initialized = false;` (`contacts_cache.rs:39`) deleted passed every test, since the fourth fold's test reads the flag where this crate's adds had left it unloaded already. Pinned by the re-read's witness, taken unchanged in what it asserts as `a_failed_forced_refresh_over_a_loaded_cache_leaves_it_to_list_again_904`: RED under plant A at `:814` (`left: ["list_outputs"]`, `right: ["list_outputs", "list_outputs"]`; `plantA.log`), green on the tip.

### The kind: one mutation of each line of `contacts_cache.rs` this pull request added or changed

Each mutant ran alone in a scratch copy of the tip (`git ls-files` synced into the lane's out folder, target `/Volumes/Lanes/targets/fix-contacts-fold5-scratch`, both removed after), against `contacts_wallet_failures`, `contacts_listed_spend`, `contacts_signaction_326` and `--lib identity` (logs `mut-*.log`). Eleven mutants: one unviable, seven caught, three not caught, each already in the bound.

| Line | The mutant | Result |
|---|---|---|
| `:33-43` | the `match` as `?` (the failure branch gone; P6) | caught: `the_cache_writes_touch_their_own_entry_alone_with_two_contacts_cached_contacts`, `..._904` |
| `:36` | `if force_refresh` as `if !force_refresh` | caught: the same two |
| `:36` | `if true` (P7) | not caught: the bound's row 12 |
| `:37` | the write lock's line deleted | unviable (E0423) |
| `:38` | `cache.contacts.clear();` deleted | caught: `the_cache_writes_touch_their_own_entry_alone_with_two_contacts_cached_contacts` |
| `:39` | `cache.initialized = false;` deleted (plant A) | caught: `..._904` |
| `:41` | `return Err(error)` as `return Ok(Vec::new())` | caught: `a_refresh_whose_listing_fails_returns_the_wallets_error_contacts` and the two above |
| `:66` | the listing's `?` as the old swallow (`Ok(vec![])` on a failure) | caught: the same three |
| `:67` | `> 1000` as `<= 1000` | caught: the two cache tests |
| `:67` | the bound dropped (`false &&`) | not caught: the bound's row 13 |
| `:69` | the words' `1000` as `1001` | not caught: the bound's row 13 |

### Rows left

- `contacts_cache.rs:67` and `:69`, the 1000-entry listing bound and its words: not equivalent; they are the bound's row 13 (a listing of 1001 outputs, which no recorded cell holds), left there, as the brief keeps the bound.
- `contacts_cache.rs:36` as `if true` (P7): the bound's row 12, unchanged (20 of 20 pass).

## The sixth fold (lane fix-contacts-fold6, PR #929 after the re-read of its fifth fold)

Three re-reads in a row each found one hand change to `contacts_cache.rs` that every test passed. This fold takes the fifth re-read's witness and replaces the hand sweep by the mutation tool's, then the three hand changes the re-reads used, at every site of the file.

### The re-read's plant

`a_failed_forced_refresh_over_a_loaded_empty_cache_leaves_it_to_list_again_904`, the re-read's witness unchanged in what it asserts (rustfmt's layout alone), in `tests/contacts_wallet_failures.rs`. On a scratch copy of the tip (target `/Volumes/Lanes/targets/fix-contacts-fold6-scratch`): RED under plant R2 (`:36` as `if force_refresh && !self.cache.read().await.contacts.is_empty()`) at `:837`, `a failed forced refresh left an empty cache loaded`, 1 of 21; RED under plant A (`:39` deleted) at `:837` beside the fifth fold's test at `:814` (`left: [String("list_outputs")]`), 2 of 21; green on the tip.

### The tool

`cargo mutants` 27.1.0 (the version `ci.yml` and `nightly.yml` pin), `--in-place` on the scratch copy (one job by construction), `--file src/identity/contacts_cache.rs --features full,http --baseline skip --timeout 240 --build-timeout 400`, `--no-shuffle --sharding round-robin --shard K/8` for K in 0 to 7 (each under four minutes), `--cargo-arg=--lib` and `--cargo-arg=--test=<f>` for every `tests/contacts_*.rs` and `tests/identity_*.rs` (43 files): the lib's unit tests whole and every contacts and identity file, 2,096 tests passing on the tip, about 45 s a run. The tip's baseline was green by the same set (`cargo test --features full,http --lib` and the 43, 2,096 passed, 8 ignored).

| | Count | Mutants |
|---|---:|---|
| made | 29 | |
| caught | 17, then 18 | every `-> Result` and `-> bool`/`usize` replacement that compiles, `20:12` `!` deleted, `67:33` and `94:24` `>` as `<`, `138:21` and `141:21` `\|\|` as `&&`, `166:64` `==` as `!=`, `clear_cache` as `()`; after this fold also `94:56` `+` as `-` |
| unviable | 6 | the six `Ok(vec![Default::default()])` and `Ok(Some(Default::default()))` (`Contact` has no `Default`) |
| timed out | 0 | |
| missed | 6, then 5 | below |

| Missed | What became of it |
|---|---|
| `94:56` `+` as `-` (the bound 64,512) | a test: `a_listed_contact_token_past_64512_bytes_inside_the_script_bound_is_read_904` (a token of about 65,160 bytes, Bob's record padded with JSON whitespace to 65,000, encrypted and locked by the wallet as `#encryptAndLock` does, read back), RED at `:958` (`the listed token was dropped`, `left: 0`); caught on the tool's re-run |
| `94:56` `+` as `*`, `94:24` `>` as `>=`, `94:24` `>` as `==` | equivalent, a row below |
| `67:33` `>` as `>=`, `67:33` `>` as `==` | the bound's row 13 (a listing of 1000 or 1001 outputs) |

### The hand pattern

Each `if`, `match` arm, early return and assignment of the file, by the three changes the last three re-reads used: the statement deleted (an `if` with its body); the condition narrowed by one more clause, twice, `&& E` and `&& !E` with E the loaded cache empty (`self.cache.read().await.contacts.is_empty()`, `cache.contacts.is_empty()` where the guard is in scope; R2 is the second at `:36`), and at `:74` also the push kept only while nothing is pushed yet; the condition widened to `true` (a `let`-`else` skip: taken always). Each ran on the scratch copy against the 17 files that name a contact (the three `contacts_*`, `identity_contact*`, `identity_door_args_818b`, `identity_evidence_736`, `identity_from_identity_abbreviated_key_568`, `identity_wallet_calls_318`, `identity_tests`, `identity_spend_witness`) with the lib's tests whole, and every one not caught there again against the tool's 43 (`tools/plants.py` and `plants.log` in the lane's out folder). 55 plants: 7 unviable (the four `let`-`else` returns deleted, by construction, not built: an `else` must diverge; the two `match` arms deleted; `:41`'s `return Err(error)` deleted, the arm's type no longer a `Vec`), 48 built. On the tip's test file before this fold (`HEAD`'s, `plants-prefold.log` for the ten whose catching tests were all new), 24 caught and 24 not caught; with this fold's six tests, 37 caught and 11 not caught, each a row of the bound or equivalent (below). The 13 that moved: R2 (`:36` `&& !E`), by the re-read's witness, and 12 by the five new tests.

| Site | Deleted | `&& E` | `&& !E` | `true` |
|---|---|---|---|---|
| `:20` the plain read's guard | new test | new test | new test | caught |
| `:22` `cache.initialized` | new test | new test | new test | caught |
| `:23` the cached return | new test (not caught before; run on `HEAD`'s file) | | | |
| `:36` the failed refresh's guard | caught | caught | caught (R2, the re-read's witness) | row 12 |
| `:41` `return Err` | unviable | | | |
| `:34`, `:35` the two arms | unviable | | | |
| `:38` clear, `:39` not loaded (plant A) | caught | | | |
| `:48` the clear before the rewrite | new test | | | |
| `:50` the insert, `:54` loaded | caught | | | |
| `:67` the listing bound (and `:68`'s return) | row 13 | row 13 | row 13 | caught |
| `:74` the read contact kept | caught | new test | caught | (first only: new test) |
| `:75` the push | caught | | | |
| `:91`, `:97`, `:100`, `:103` the decode's skips | unviable | | | caught |
| `:94` the script bound (and `:95`'s return) | equivalent | equivalent | equivalent | caught |
| `:106` the cached saved-at time read (as 0) | new test | | | |
| `:137` the search's filter | caught | caught | equivalent | caught |
| `:166` the tag's filter | caught | caught | equivalent | caught |
| `:182` the clear, `:183` not loaded | caught, new test | | | |

The new tests, each RED on the tip before this fold by the plants it names (the logs `plant-<id>.log`, the same scratch copy, the tests synced): `a_plain_read_over_a_loaded_cache_answers_it_without_the_wallet_904` (the reference's `getContacts` without `forceRefresh` returns `#knownEmpty`'s `[]` or the cached contacts before any load, `ContactsManager.ts:321-328`; a forced refresh loads one contact and, apart, an empty basket, then a plain read answers it and asks nothing): `:20` deleted, `&& E`, `&& !E`, `:22` the same three, `:23` deleted, each `the plain read over a loaded cache asked the wallet`; `a_forced_refresh_reads_every_listed_contact_and_keeps_none_the_listing_lacks_904` (two tokens listed, Bob's and Carol's, read over a cold and over a loaded cache; then an empty listing leaving none cached; `:321`, `:343-347`, `:353-368`, `:507-513`): `:74` `&& E` and first only, `:48` deleted; `a_forced_refresh_keeps_a_cached_contacts_saved_at_time_904` (an add with `added_at` 1,700,000,000,000, then a forced refresh listing its token; this crate's member, #544): `:106` as 0, and `:74` `&& E`; `clear_cache_leaves_the_next_plain_read_to_list_again_904`: `:183` deleted. Each reads the reference at the pin; none is recorded. `tests/contacts_wallet_failures.rs` holds 26 tests (20 before this fold): green three times, the third single-threaded.

### Rows left (the sixth fold)

- `contacts_cache.rs:94` (and `:95`'s return), the listed script's bound, deleted, narrowed (`&& E`, `&& !E`), or as the tool's `+` as `*`, `>` as `>=`, `>` as `==`: equivalent. Every script past the bound (68,608 bytes, the reference's `MAX_CONTACT_CIPHERTEXT_BYTES * 2 + 4096` hex digits, `ContactsManager.ts:487-492`) is refused by `authenticate_contact` before its wallet's `getPublicKey`: the canonical envelope (`token_envelope.rs:24-34`) is five chunks, a 33-byte key, the ciphertext bounded at 66,560 bytes, the signature at 80, so at most 66,683 bytes; `read_key_id` and the script's parse ahead of it ask no wallet. The answer (`Ok(None)`) and the wallet's calls are the same on every input; only the work before the refusal differs. Older than #904 (#544's line).
- `contacts_cache.rs:137` and `:166`, the two filters narrowed by `&& !cache.contacts.is_empty()`: equivalent. The closure runs on an element of `cache.contacts` alone, so the clause holds wherever it is read. Older than #904.
- `contacts_cache.rs:67` (and `:68`'s return), deleted or narrowed, and the tool's `>` as `>=` and `==`: the bound's row 13, unchanged.
- `contacts_cache.rs:36` as `true`: the bound's row 12, unchanged.

The bound sentence is unchanged: every hand change and mutant left is a row it lists or equivalent. Before this fold it was not true of the file: thirteen hand changes inside it (R2, and twelve on the plain read's cache, the forced refresh over a loaded cache, two listed contacts, the saved-at time and `clear_cache`) passed every test.

## The seventh fold (lane fix-contacts-fold7, PR #929 after the sixth re-read)

Opened from `origin/lane/fix-contacts` at `efbe17b4`; `origin/beta` at `5f441217`, the rebase a no-op (no census figure moved); the sixth re-read's documents commit `da26ebe6` cherry-picked before this fold's work. No `src/` change.

### Item 1: the sixth re-read's three tests

Taken as written into `tests/contacts_wallet_failures.rs` (29 tests), each RED on a scratch copy of the tip under its plant (target `/Volumes/Lanes/targets/fix-contacts-fold7-scratch`, removed after):

| Test | Plant | RED |
|---|---|---|
| `a_forced_refresh_keeps_each_of_two_cached_contacts_saved_at_time_904` | K2, `contacts_cache.rs:111` the saved-at time read as `.values().next()` | `:1272`, `Carol Example: the saved-at time`, `left: 1700000000000`, `right: 1800000000000` |
| `a_plain_read_over_two_cached_contacts_answers_both_904` | K8, `:23` the cached read as `.take(1)` | `:1298`, `the plain read's answer`, one contact where the load answered two |
| `a_cold_plain_read_caches_what_it_loaded_904` | K10, `:45` the cache written only by a forced refresh | `:1313`, `a cold plain read left the cache unloaded` |

### Item 2: the differential replay

Six re-reads in a row each found changes to the cache that every test passed, and the last of them found three of ten after a mutation tool's sweep. They were changes of meaning, which no operator-level tool makes. This fold replaces the next hand sweep with the reference itself: the same sequence of calls is made on both implementations, and every observable answer is compared.

- **The recorder.** `tests/support/contacts_replay_reference.mjs`, a mode of the #326 recorder (`signaction_reference_326.mjs --contacts-replay`): the same bun bundle of `ts-stack@edf6e03`, run under Node v22.18.0, with the SDK's SHA-256 counter stream reset before every sequence. Two runs are byte-identical and equal to the committed vector.
- **The generator.** It lives in the recorder and draws from its own SHA-256 counter stream, `bsv-rs#904 fold7 <n>`, apart from the SDK's stream. It writes 320 sequences of 4 to 16 steps (3,155 steps) over three contacts, the scalars 3, 4 and 5.
  - **The operations.** Each step is one public call of the manager that touches the cache: a plain read, a forced read, a read by identity key, a save, an update, a removal or a clear (the reference's clear is a new manager over the same wallet). Rarely a step is the wallet's alone, `pad`: the basket filled with outputs that are no contact's, to 999, 1000 or 1001 entries.
  - **The faults.** A step carries zero to two wallet faults (1,627 with none, 738 with one, 790 with two), each named by its call, its turn within the step and a mode. A second fault is drawn from the call of the one already drawn half the time, so two modes of one call apply together. The calls are `createHmac`, `listOutputs`, `getPublicKey`, `verifySignature`, `decrypt`, `encrypt`, `createSignature`, `createAction`, `signAction` and `abortAction`. The modes are `throw`, `no_tx`, the bound modes `duplicate_input`, `missing_input` and `output`, and the signed modes `signed_version`, `signed_output` and `signed_script`, which are the faults the pull request's tests already inject.
  - **Retries.** After a failed step, half the time the next step is the same call again without its faults, as a caller's retry.
  - **The cache model.** The generator reads a model of the reference's cache, written from its code and checked against the reference at every step: a warm plain read must ask the wallet nothing, and a warm save must not load the basket. The model decides what may be drawn. A save, an update and a read by key are drawn only over a warm cache, and an update only of a cached contact. A removal names a cached contact three times in four.
- **The directed sequences.** Thirteen sequences (77 steps), one for each survivor below, plus the listing's bound and three contacts. They are written out as steps; their answers are the reference's, run.
- **The wallet.** The ProtoWallet of the scalar 9 over a basket it keeps, the same on both sides: `basketWallet` in the recorder and `tests/support/contacts_replay_wallet.rs` in Rust.
  - **A listing** answers the basket in the order its entries were added, filtered by a tag when one is asked. With `entire transactions` it answers the entries' transactions merged into one BEEF; with `locking scripts`, their scripts. It answers every entry whatever the limit, as a wallet that does not honour the limit would.
  - **A create without inputs** commits its outputs at once.
  - **A create with inputs** answers a signable transaction spending the outpoints asked, sourced from the input BEEF. It commits at signAction: the spent entries are dropped and the new contact outputs are added after the rest.
  - **An abort** drops the pending action.
- **The replay.** `tests/contacts_replay.rs`, two tests:
  - `the_cache_replays_every_recorded_sequence_as_the_reference_answers_904` runs every sequence, each in a local task of its own so that a panic is named with its sequence. After every step it compares the outcome (an error's words), the contacts answered (key, name and saved-at time, in the reference's order), the wallet's calls in order, and the arguments the pull request pins (listOutputs' basket, include, tags, limit and custom-instructions flag; createAction's descriptions, inputs, outputs, labels and options; signAction's spend keys, reference and options; abortAction's reference). It fails naming the sequence, the step and the difference.
  - `the_corpus_reaches_every_operation_fault_and_three_contacts_904` holds the corpus to what this record says it is.
  - **Time.** About 6 s, alone or with `--test-threads=1`.
- **Readings the replay states.** It normalized these three and nothing else; since the eighth fold the two below the first (the order is compared since then, the section at the end):
  - **Order.** A plain read answered from a warm cache is compared as a set (the finding below; retired by the eighth fold).
  - **Concurrency.** The reference's load decrypts its outputs concurrently (`Promise.allSettled`, `ContactsManager.ts:480-513`), so a run of `getPublicKey`, `verifySignature` and `decrypt` is compared by the count of each name, never by the interleaving.
  - **`added_at`.** It has no reference twin (`:171-198`). Its expected value is the recorder's statement of this crate's rule: the time of the latest save while the cache held the contact, else 0.
- **Clock.** None: the reference reads no clock (no `Date` in `ContactsManager.ts` at the pin), so time does not advance between steps.

### Item 3: the proof that it ends the rounds

Each plant ran alone on the scratch copy, against `--test contacts_replay` alone, so none of the directed tests of folds 2 to 7 ran (logs `replay-<plant>.log`, the plants in `tools/plants.json`, both in the lane's out folder).

**The survivors of the six re-reads.** Every surviving change any of them found:

| Re-read | Place | What changed | The replay alone (generated sequences that differ, directed) |
|---|---|---|---|
| fold | `contacts_actions.rs:412` (P1) | the removal's bound input taken as 0 when there is no lock | caught (12, 1) |
| fold | `tests/contacts_wallet_failures.rs:287` | an assertion on `"signAction"`, a name the double never records | not a change of behaviour: a test's own defect (no code moved), mended by the second fold |
| fold2 | `tests/support/identity_reveal_wallet.rs:42` | `wallet_call!(from)` compiled through `From::from` | not a change of behaviour: the test machinery's (no code moved), mended by the third fold |
| fold2 | `contacts_actions.rs:412` | the update signing before it refuses | caught (30, 2) |
| fold2 | `contacts_actions.rs:332` moved above `:318` | the removal dropping the cached contact before its spend | caught (10, 2) |
| fold3 | `contacts_actions.rs:332` | `remove` as `clear` | caught (16, 2) |
| fold3 | `contacts_actions.rs:412-415` | the update's two signable checks swapped | caught (1, 1): not caught until the generator applied two modes of one call together (it applied one alone); extended, not a directed sequence alone |
| fold4 | `contacts_cache.rs:39` (plant A) | the failed forced refresh's `initialized = false` deleted | caught (4, 3) |
| fold5 | `contacts_cache.rs:36` (R2) | the guard narrowed to a non-empty cache | caught (2, 1) |
| fold6b | `contacts_cache.rs:111` (K2) | the saved-at time read from the cache's leading entry | caught (27, 4), by the `added_at` column |
| fold6b | `contacts_cache.rs:23` (K8) | the cached read cut to one contact | caught (46, 5) |
| fold6b | `contacts_cache.rs:45` (K10) | the cache written by a forced refresh alone | caught (104, 4) |
| fold6b | `contacts_cache.rs:65` (K4) | the load's limit 100 | caught (318, 13), by listOutputs' arguments |
| fold6b | `contacts_cache.rs:65` (K5) | the load asking `entire transactions` | caught (318, 13), by listOutputs' arguments |
| fold6b | `contacts_cache.rs:166` (K13) | `get_contacts_by_tag`'s match case-sensitive | not caught: `get_contacts_by_tag` is this crate's own helper (the reference has none, nor any call of its manager that reads its tags), so no sequence of the reference's calls can show it; a change of behaviour of a door with no reference twin, a row (below), the re-read right to call it one |

Survivors caught by the replay alone: 12 of 12, of the 13 code survivors (K13 excepted, with its reason); the two that were no code change are not counted.

**The tool.** `cargo mutants` 27.1.0, `--in-place` on the scratch copy, `--file src/identity/contacts_cache.rs --features full,http --baseline skip`, eight round-robin shards (each under four minutes), against `--lib` and every `tests/contacts_*.rs` and `tests/identity_*.rs` (44 files, `contacts_replay` among them):

| | The sixth fold | This fold |
|---|---:|---:|
| made | 29 | 29 |
| caught | 18 | 20 |
| unviable | 6 | 6 |
| missed | 5 | 3 |

The two that moved are `67:33` `>` as `>=` and as `==`, the bound's row 13, caught by the `pad` steps (a listing of 1000 and of 1001 entries). Before the extension the same run gave the sixth fold's 18 and 5. The three left are `94:56` `+` as `*` and `94:24` `>` as `>=` and as `==`, equivalent (the sixth fold's row: every script past the bound is refused before any wallet call). The two `:67` mutants were also run as plants against the replay alone: caught (18, 1) and (34, 1).

**Twenty changes of meaning of this fold's own**, of the kinds the readers made, each caught by the replay alone (generated sequences that differ, directed):

| | Change | Kind | Caught |
|---|---|---|---|
| M01 | the load keeps its leading two contacts | an entry dropped | (17, 1) |
| M02 | a cached read of two answers its leading contact twice | an entry duplicated | (46, 5) |
| M03 | with two cached, a save cached under the least key | the wrong entry updated | (30, 1) |
| M04 | a save keeps the cached entry's old time | a time from another save | (55, 0) |
| M05 | the load reads the latest time in the cache | a time from another entry | (28, 4) |
| M06 | an update is not cached | a write skipped on one path | (59, 0) |
| M07 | a removal with nothing spent leaves the cache | a write skipped on one path | (2, 0): not caught until the generator's retry rule and its removal of a cached contact (the path is a removal that fails after its spend committed, then retried); extended, no directed sequence |
| M08 | a load answers its contacts reversed | an order changed | (33, 4) |
| M09 | the load sorts by name, descending | an order changed | (21, 4) |
| M10 | a failed forced refresh answers no contacts | an error swallowed | (58, 3) |
| M11 | the removal's wrapper reworded | an error reworded | (61, 2) |
| M12 | a failed create cached as saved | an error swallowed | (52, 0) |
| M13 | a failed cold plain read answers none and loads the cache | an error swallowed | (34, 1) |
| M14 | `clear_cache` keeps the contacts | a write skipped | (28, 3), by `added_at` |
| M15 | a load merges into the cache | an entry kept | (14, 1) |
| M16 | a read by key falls back to another contact | the wrong entry answered | (28, 0) |
| M17 | an update cached before the chain | a write moved | (25, 1) |
| M18 | the load drops a contact with no cached time | an entry dropped | (46, 5) |
| M19 | the removal drops a key that never matches | the wrong entry removed | (23, 2) |
| M20 | a forced refresh leaves the cache marked not loaded | a write skipped | (122, 7) |

20 of 20. The bound's row 12 (`:36` as `if true`), run as a plant: not caught, as the row says (a plain load fails only over a cold cache, which holds nothing here).

### Item 4: the bound

These tests and the differential replay (`tests/contacts_replay.rs`, against `tests/vectors/contacts_replay.json`: 320 sequences of 4 to 16 steps, 3,155 steps, generated from the seed `bsv-rs#904 fold7` by `tests/support/contacts_replay_reference.mjs`, and 13 directed sequences, every step run on the reference) hold, against the reference's recorded answers, what the cache answers and keeps and what the update and the removal sign, send, refuse (alone and in pairs) and cache, with up to three contacts cached and up to two faults in a step. They do not hold:

- a step with three or more faults;
- a cache of four or more contacts;
- the replay's stated readings: a warm plain read's order, compared as a set (until the eighth fold); the load's concurrent reads, compared by count; a save, an update or a read by key over a cold cache, which the generator does not make;
- this crate's search helpers (`search_contacts`, `get_contacts_by_tag`), which have no reference twin;
- the twelve lines listed under "The bound" above (row 13 is held by the replay since this fold).

This sentence replaces the fourth fold's at `CHANGELOG.md`, in `tests/CLAUDE.md`'s rows and in `tests/contacts_wallet_failures.rs`' header.

### Item 5: what the replay shows about the code

One difference on the tip, older than #904, stated and not mended (a public order, a choice for the design reads of root rule 13):

- **What differs.** A plain read over a warm cache of two or more contacts answers in a `HashMap`'s order, which changes from run to run: `contacts.rs:44`, `ContactsCache::contacts`. The reference answers its cache array's order: the load's order, a new contact appended, an updated one in place (`ContactsManager.ts:326-328`, `:532-534`).
- **Measured.** With the cached reads compared in order, 27 and then 24 of the 333 sequences differ on two runs of the same binary. The earliest is sequence 34, step 6: this crate `[Carol v3, Dave v5]`, the reference `[Dave v5, Carol v3]`.
- **Not a security matter.** It is this crate's own order, not another side's handling of a peer's input.

Nothing else differs on the tip.

### Rows left (the seventh fold)

- `contacts_cache.rs:166`, `get_contacts_by_tag`'s case-insensitive match (K13): this crate's helper, with no reference twin; its behaviour is pinned by no recorded cell.
- The warm cached read's order (item 5): mended by the eighth fold.
- The previous folds' rows stand.

## The eighth fold (`lane/fix-contacts-fold8`)

The captain's ruling on the seventh fold's item 5: a fault to mend in this pull request, not a divergence to state (an answer whose order changes from run to run cannot be stated as anything; root rule 1).

### Item 1: the RED

`tests/contacts_replay.rs` compares every answer in order: the `order: cache` steps (a plain read over a warm cache, a read by key) are no longer sorted by key before the comparison, and the header's first stated reading is gone. On the code before the mend (the commit `test(#904): the replay compares the order of cached answers`, RED alone) the replay fails on two runs of the same binary: 28 and then 25 of 333 sequences, every difference a plain read's answer order (`red-1.log`, `red-2.log` in the lane's out folder). The corpus is unchanged: the reference's answers were always recorded in order.

### Item 2: the mend

`ContactsCache` (`src/identity/contacts.rs`) holds the contacts in a `Vec` in the reference's array order, read at the pin (`ContactsManager.ts` at `ts-stack@edf6e03`, the same at `4d0ea63`):

| Event | The reference | Here |
|---|---|---|
| a load (a plain read over a cold cache, a forced refresh) | the array the decrypt answers, in the listing's order (`:376`, `:507-513`) | `ContactsCache::load`, the listing's order |
| a save of a new key | `contacts.push` (`:534`) | `save`, appended |
| a save of a cached key | `contacts[findIndex(...)] = contact`, the first entry of the key, in place (`:532-533`) | `save`, the first entry replaced in place |
| a removal | `contacts.filter(c => c.identityKey !== key)` (`:934`) | `remove`, every entry of the key, the others in order |
| a plain read | the cached array (`:326-328`) | `ordered`, the `Vec` |
| a read by key | the cached array filtered by the key (`:390`), every entry | `get`, the first entry (stated: two entries of one key need a basket holding two outputs of it, a state no sequence of the replay reaches; `get_contact` answers an `Option`, a public shape) |

A map from each key to its first position keeps a lookup at one hash at the manager's bound of 1,000 contacts; a load and a removal rebuild it in one pass, as the reference rewrites its array there. `search_contacts` and `get_contacts_by_tag` iterate the `Vec`. No public type changed shape (`ContactsCache` is private; every public signature is as it was), so the semver check was not run; no dependency added.

### Item 3: green

- The replay with order compared: 333 of 333 on three runs (`green-1.log` to `green-3.log`).
- `cargo mutants` 27.1.0, `--in-place` on a scratch copy, `--file src/identity/contacts_cache.rs --features full,http --baseline skip`, eight round-robin shards, against `--lib` and the 44 `tests/contacts_*.rs` and `tests/identity_*.rs`:

| | The seventh fold | This fold |
|---|---:|---:|
| made | 29 | 29 |
| caught | 20 | 20 |
| unviable | 6 | 6 |
| missed | 3 | 3 |

The three missed are the same equivalent bound mutants, now at `:87` (`+` as `*`, `>` as `>=` and as `==`). The cache's own code moved to `contacts.rs`; its ten mutants (`--re ContactsCache`, two shards): 8 caught, 2 unviable, 0 missed. The same run reached four field deletions in `create_identity_tag` (older than #904): 3 caught, `counterparty` deleted missed (not this fold's line; a row for a later read).

- Ten changes of order of this fold's own, each run against the replay alone (`plants/` in the lane's out folder):

| | Change | Sequences that differ |
|---|---|---:|
| O1 | a new contact prepended | 44 |
| O2 | an update moved to the end | 8 |
| O3 | an update moved to the front | 11 |
| O4 | a removal by `swap_remove` | 1 |
| O5 | a removal followed by a rotation | 3 |
| O6 | a load sorted by key | 8 |
| O7 | a load reversed | 12 |
| O8 | a plain read sorted by name | 29 |
| O9 | a plain read reversed | 51 |
| O10 | a new contact inserted at the second place | 9 |

10 of 10. O4 is caught by one sequence alone: thin, a residual.

### Item 4: the other answers

Answers read, 15: the manager's `list_contacts`, `list_contacts_with_refresh`, `get_contact`, `search_contacts`, `get_contacts_by_tag`, `cached_count`; the identity client's `get_contacts`, `get_contact`, `resolve_by_identity_key` with contacts, `resolve_by_attributes` with contacts (the contacts map); and the module's five other maps and sets (`client_trust.rs`'s seen set, `reveal.rs`'s requested set, `evidence.rs`'s visited and spent sets, `revoke.rs`'s one-entry spends map). Those that iterated a map where the reference has an order: five (the manager's two lists, its two searches, the client's `get_contacts`), all through `ContactsCache`, mended by item 2; the searches have no reference twin and the replay holds the two lists alone. The rest are lookups or membership: `resolve_by_attributes`' contacts map keeps the later of two entries of a key, as the reference's `new Map(contacts.map(...))` does (`IdentityClient.ts:627-630`, `:1028`); one row: a read by key over a cache holding two entries of a key (the table above).

The stable line: `origin/main` (`f569499a`) has the same iteration, `contacts.rs:30` a `HashMap<String, Contact>` read through `values()` at `:764`, `:776`, `:914`, `:944` (a row for the captain).

