# Lane fix-843-structs: the 57 all-public structs no ruling covered are each ruled (#843)

Base `c9c74c7d` (`origin/lane/fix-843d9-rebase`, pull request #1014 carried onto beta `4c5454be`). One commit, nothing pushed. A break of the 0.9.0 cut.

## What the lane was given

`tests/arch_non_exhaustive_843d.rs` held 57 all-public structs as `Unruled` (`UNRULED_LEN`): no class held them and no ruling named them. The captain's rulings of 2026-11-17 (on three design reads and three audits of the whole public surface; issue #843's comment of that day) decide them:

- (a) a struct is OPEN (`#[non_exhaustive]`, a `new(<required>)` and a `with_<field>` per optional field, pinned as #819's pins are) when it is a context or parameter block, a configuration, or a result this crate produces; it is LITERAL ON PURPOSE when its fields are a wire or byte format, when it is a value type, or when a caller must build it to call a public door;
- (b) twenty named OPEN, (c) the named LITERAL ones, (d) rule (a) for a struct the three reads class differently and (b) and (c) do not name;
- (e) `wallet::Certificate` removed, (f) the identity module's `IdentityCertificate` and `CertifierInfo` unified into the wallet's, (g) `Network` and `Protocol` declared twice on purpose and said so, (h) seven left for other lanes.

## The table

Literal sites are `git grep` counts of `Name {` (a tuple struct's `Name(`) at the base, declarations and comments set aside: an upper bound, since a same-named type of another module or of a dependent's own counts too. "This crate" is `tests/`, `benches/`, `examples/`, `fuzz/` and `README.md`; the dependents are the trees checked out on this host on 2026-11-17, read only in files that name `bsv_rs` (toolbox `420f2e03`, which requires `=0.9.0-beta.8`; overlay `2c626f7c`, `0.8.11`; messagebox `537bae3`, `=0.7.0`; relay `419bf18`, `=0.4.5`; middleware-rs `57a0b8b`, `0.3`; chaintracks `74cc110`, `=0.6.0`; the CLI and middleware-cloudflare hold no `.rs` file naming `bsv_rs`).

| # | Struct | Class | What decides it; its door | This crate | Dependents |
|---|---|---|---|---:|---|
| 1 | `Response` (`auth/clients/response.rs`) | OPEN | (b), named: a result this crate produces; `Response::new(status, headers, body)` | 1 | toolbox 1 |
| 2 | `HttpRequest` (`auth/transports/http.rs`) | LITERAL | (c), named: the BRC-104 request frame, a caller builds it | 19 | toolbox 5, middleware-rs 2 |
| 3 | `HttpResponse` (`auth/transports/http.rs`) | LITERAL | (c), named: the BRC-104 response frame, a caller builds it | 10 | toolbox 2 |
| 4 | `AppEvent` (`auth/transports/socketio/mod.rs`) | OPEN | (b), named: a result this crate produces; `AppEvent::new(sender, event_name, data)`; declared in `socketio/app_event.rs` since | 1 | 0 |
| 5 | `HeaderLink` (`block/difficulty.rs`) | LITERAL | (c), named: a block value | 1 | 0 |
| 6 | `BlockHeader` (`block/header.rs`) | LITERAL | (c), named: a block value (the 80-byte header) | 0 | toolbox 32, chaintracks 5 |
| 7 | `MerkleRoot` (`block/merkle.rs`) | LITERAL | (c), named: a block value | 4 | 0 |
| 8 | `CompactTarget` (`block/target.rs`) | LITERAL | (c), named: a block value | 1 | 0 |
| 9 | `IdentityResolutionResult` (`identity/types.rs`) | OPEN | (b), named: a result this crate produces; `IdentityResolutionResult::new(identity, certificates)` | 0 | 0 |
| 10 | `CertifierInfo` (`identity/types.rs`) | UNIFIED | (f): gone, `identity::IdentityCertifier` is the wallet's type re-exported | 2 | 0 |
| 11 | `BroadcastSuccess` (`identity/types.rs`) | NOT THIS LANE | (h): waits for the one broadcast answer type | 6 | 0 |
| 12 | `KVStoreContext` (`kvstore/interpreter.rs`) | OPEN | (b), named: a context block; gains `controller`; `KVStoreContext::new(key, protocol_id, controller)` | 0 | 0 |
| 13 | `KVStoreFields` (`kvstore/interpreter.rs`) | LITERAL | (d) by rule (a): its fields are the token's fields by position (a wire format) | 8 | 0 |
| 14 | `RankChangeEvent` (`overlay/host_reputation_tracker.rs`) | OPEN | (b), named: a result this crate produces; `RankChangeEvent::new(host, old_rank, new_rank, reason)`; declared in `rank_change_receiver.rs` since | 0 | 0 |
| 15 | `OverlayAdminTokenData` (`overlay/overlay_admin_token_template.rs`) | LITERAL | (d) by rule (a): its fields are the advertisement token's four data fields (a wire format) | 0 | 0 |
| 16 | `OutputListItem` (`overlay/types.rs`) | OPEN | (b), named: a record that grew (`txid`, #735); `OutputListItem::new(beef, output_index)`, `with_context`, `with_txid` | 49 | toolbox 5, overlay 5 |
| 17 | `HostResponse` (`overlay/types.rs`) | OPEN | (b), named: a result this crate produces; `HostResponse::success(host, steak)`, `failure(host, error)` (an `ASSIGNED` row) | 0 | 0 |
| 18 | `ServiceMetadata` (`overlay/types.rs`) | LITERAL | (c), named: a dependent builds 62 by literal | 1 | overlay 62 |
| 19 | `SchnorrProof` (`primitives/bsv/schnorr.rs`) | LITERAL | (d) by rule (a): a value type (R, S', z); a verifier builds it for `verify_proof` | 0 | 0 |
| 20 | `TxInput` (`primitives/bsv/sighash.rs`) | LITERAL | (c), named: a serialized input; callers build it for `SighashParams` | 20 | toolbox 2, overlay 5, messagebox 2, relay 2 |
| 21 | `TxOutput` (`primitives/bsv/sighash.rs`) | LITERAL | (c), named: a serialized output; callers build it for `SighashParams` | 40 | toolbox 2, overlay 5, messagebox 2, relay 2 |
| 22 | `RawTransaction` (`primitives/bsv/sighash.rs`) | LITERAL | (c), named: a serialized transaction | 0 | 0 |
| 23 | `RegisterDefinitionResult` (`registry/types.rs`) | NOT THIS LANE | (h): waits for the one broadcast answer type | 2 | 0 |
| 24 | `BroadcastSuccess` (`registry/types.rs`) | NOT THIS LANE | (h): waits for the one broadcast answer type | 6 | 0 |
| 25 | `RevokeDefinitionResult` (`registry/types.rs`) | NOT THIS LANE | (h): waits for the one broadcast answer type | 2 | 0 |
| 26 | `UpdateDefinitionResult` (`registry/types.rs`) | NOT THIS LANE | (h): waits for the one broadcast answer type | 2 | 0 |
| 27 | `ScriptResourceLimit` (`script/evaluation_error.rs`) | OPEN | (b), named: a record that grew (`work_spent`); `ScriptResourceLimit::new(resource, limit, attempted)`, `with_work_spent` (both `const`) | 18 | toolbox 1 |
| 28 | `SigningContext` (`script/template.rs`) | OPEN | (b), named: a context block that grew (`script_code`); `SigningContext::new(..)`, `with_script_code` (as before) | 0 | 0 |
| 29 | `Multisig` (`script/templates/multisig.rs`) | LITERAL | (d) by rule (a): a value type, the template is its threshold | 0 | 0 |
| 30 | `SimpleUtxo` (`script/transaction.rs`) | NOT THIS LANE | (h): another lane's (`script::transaction`) | 1 | 0 |
| 31 | `UploadMetadata` (`storage/types.rs`) | OPEN | (d) by rule (a): a result this crate produces from a server's JSON, no reference record, no literal site; `UploadMetadata::new(uhrp_url, expiry_time)` | 0 | 0 |
| 32 | `SortResult` (`transaction/beef.rs`) | OPEN | (b), named: a result this crate produces; `SortResult::new()` and five `with_` setters | 0 | 0 |
| 33 | `BeefValidationResult` (`transaction/beef.rs`) | OPEN | (b), named: a result this crate produces; `BeefValidationResult::new(valid, roots)` | 0 | 0 |
| 34 | `Refusal` (`transaction/beef_stream.rs`) | OPEN | (b), named; `Refusal::new(offset, reason)` (public since) | 0 | overlay 1 |
| 35 | `Leaf` (`transaction/beef_stream.rs`) | LITERAL | (c), named: a caller builds it for the public `fold_bump` | 0 | 0 |
| 36 | `Bump` (`transaction/beef_stream.rs`) | LITERAL | (c), named: a caller builds it for the public `fold_bump` | 0 | 0 |
| 37 | `InputRef` (`transaction/beef_stream.rs`) | LITERAL | (c), named: a caller builds it for the public `fold` | 0 | 0 |
| 38 | `OutputRef` (`transaction/beef_stream.rs`) | LITERAL | (c), named: a caller builds it for the public `fold` | 0 | 0 |
| 39 | `TxBody` (`transaction/beef_stream.rs`) | LITERAL | (c), named: a caller builds it for the public `fold` | 0 | 0 |
| 40 | `ChainTip` (`transaction/beef_stream.rs`) | OPEN | (b), named: a context block; `genesis_height` removed; `ChainTip::new(height, median_time_past)`, `with_csv_height`, `with_next_block_time` (all `const`); declared in `beef_stream/tip.rs` since | 9 | toolbox 5 |
| 41 | `HeadersFn` (`transaction/beef_stream.rs`) | LITERAL | (c), named: a callback newtype | 7 | 0 |
| 42 | `AlwaysValidChainTracker` (`transaction/chain_tracker.rs`) | OPEN | (d) by rule (a): a configuration (a configured double; its sibling mock grew a field, #218); `AlwaysValidChainTracker::new(height)` (as before) | 0 | 0 |
| 43 | `Utxo` (`transaction/input.rs`) | NOT THIS LANE | (h): another lane's (its `txid` is typed with the id doors) | 2 | 0 |
| 44 | `ScriptOffsets` (`transaction/transaction.rs`) | LITERAL | (d) by rule (a): a value type, the reference's `parseScriptOffsets` answer | 0 | 0 |
| 45 | `ScriptOffset` (`transaction/transaction.rs`) | LITERAL | (d) by rule (a): a value type (index, offset, length) | 0 | 0 |
| 46 | `TransactionParts` (`transaction/transaction/fields.rs`) | LITERAL | (d) by rule (a): a caller builds it to call `Transaction::from_parts` | 6 | 0 |
| 47 | `TransactionPartsMut` (`transaction/transaction/fields.rs`) | LITERAL | (d) by rule (a): a transaction's six fields lent at once, the same six as `TransactionParts` | 0 | 0 |
| 48 | `ReviewActionsRefusal` (`wallet/review_actions.rs`) | OPEN | (b), named: a record that grew (four members, #339); `new`, `with_members` (as before) and five `with_` setters | 0 | 0 |
| 49 | `Protocol` (`wallet/types.rs`) | LITERAL | (g): a value type (the `WalletProtocol` pair); declared beside `overlay::Protocol` on purpose | 1 | toolbox 6, overlay 6 |
| 50 | `Outpoint` (`wallet/types.rs`) | LITERAL | (c), named: a value type | 2 | toolbox 29, overlay 33 |
| 51 | `Certificate` (`wallet/types.rs`) | REMOVED | (e): no user; `auth::Certificate::to_wallet_certificate` returns `WalletCertificate` | 1 | toolbox 6 |
| 52 | `CreateActionInputRaw` (`wallet/validation.rs`) | OPEN | (b), named: a validation input; `new(outpoint, input_description)` and three `with_` setters; declared in `validation/raw.rs` since | 1 | 0 |
| 53 | `CreateActionOutputRaw` (`wallet/validation.rs`) | OPEN | (b), named: a validation input; `new(locking_script, satoshis, output_description)` and three `with_` setters | 1 | 0 |
| 54 | `CreateActionOptionsRaw` (`wallet/validation.rs`) | OPEN | (b), named: a validation input; gains `trust_self`; `new()` and nine `with_` setters | 0 | 0 |
| 55 | `CreateActionArgsRaw` (`wallet/validation.rs`) | OPEN | (b), named: a validation input; `new(description)` and seven `with_` setters | 1 | 0 |
| 56 | `SignActionSpendRaw` (`wallet/validation.rs`) | OPEN | (b), named: a validation input; `new(unlocking_script)`, `with_sequence_number` | 0 | 0 |
| 57 | `ValidSignActionSpend` (`wallet/validation.rs`) | LITERAL | (d) by rule (a): a value type, the validated form of the reference's `SignActionSpend` | 0 | 0 |

Not one of the 57, opened by the same ruling (b):

| | Struct | Class | What decides it; its door | This crate | Dependents |
|---|---|---|---|---:|---|
| + | `ScriptEvaluationError` (`script/evaluation_error.rs`) | OPEN | (b), named (a `Record` row until now, not one of the 57): a record that grew (`resource_limit`, 0.3.23); `ScriptEvaluationError::new(..)`, `with_resource_limit` (as before) | 3 | 0 |

Totals over the 57: 21 OPEN, 27 LITERAL, 1 REMOVED, 1 UNIFIED, 7 NOT THIS LANE. With `ScriptEvaluationError`, 22 structs take `#[non_exhaustive]` in this commit (13 to 35 attributed; 220 to 217 all-public structs under `src/`, the removed `wallet::Certificate`, the unified `CertifierInfo` and the identity module's own `IdentityCertificate`, now crate-private, leaving the scan).

## Rule (d), one line each

The three reads agree on none of these eleven by name in the reports this host holds (the api and parity reads class every one literal but `ValidSignActionSpend`, which the api read left to an additive door; the callers read opens the configurations and the results among them), so rule (a) decides:

- `KVStoreFields`: LITERAL. Its fields are the token's fields by position (protocol 0, key 1, value 2, controller 3, tags 4, the signature last) and its locking key: a wire format.
- `OverlayAdminTokenData`: LITERAL. Its fields are the advertisement token's four data fields, as the reference's `decodeAdvertisement` returns them: a wire format.
- `SchnorrProof`: LITERAL. A value: the proof's three members, which a verifier builds from received bytes to call `verify_proof`.
- `Multisig`: LITERAL. A value: the template is its threshold, as the `Record` rows `RPuzzle` and `PushDrop` are their members.
- `ScriptOffsets`, `ScriptOffset`: LITERAL. Values: the reference's `parseScriptOffsets` answer is its two lists of (index, offset, length).
- `TransactionParts`: LITERAL. A caller builds it to call `Transaction::from_parts`. `TransactionPartsMut`: LITERAL, the same six fields lent at once.
- `ValidSignActionSpend`: LITERAL. A value: the validated form of the reference's `SignActionSpend`, beside the `ValidCreateAction*` `Record` rows.
- `UploadMetadata`: OPEN. A result this crate produces from a storage server's JSON answer; the reference types that answer nowhere (`listUploads` returns its server's objects), no caller builds one (0 literal sites), and a JSON record gains members as `OutputListItem` did.
- `AlwaysValidChainTracker`: OPEN. A configuration: a double configured by its height (its sibling `MockChainTracker` gained its tip field with #218); `new(height)` stood already.

## Read before you rely on it: what moved besides shapes

1. **`ChainTip::genesis_height` is removed, and with it GHSA-h4m7-c6p8-725m's way out for a test chain.** The field was deprecated by #451 (`0.9.0-beta.4`) with the promise that at its removal "the default stream path judges by mainnet's heights as the reference does: a caller on another chain supplies its `ChainParams`". After #451, the fix of GHSA-h4m7-c6p8-725m made the default doors that prove a coin's height judge a coin below the tip's `genesis_height` by the rules of its era, and named the tip's field as the way out for a test chain (a regtest whose coins are proven below 620,538). Three sites read the field: the streaming fold's P2SH-output refusal (`beef_stream.rs`), the reader's `before_genesis` (`beef_stream/spends.rs`) and the whole-transaction verifier's `genesis_height` (`verify.rs`, which asked the tracker's `mining_tip` once for it). All three now take mainnet's 620,538 when no chain parameters are given, and the verifier no longer asks the tip for it. On mainnet nothing moves. On a test chain the default doors judge every coin proven below 620,538 by the older rules as well (they only add refusals), with a tip or without one, and the way out is the chain's parameters at a door that takes them (`verify_with_chain_params*`, `StreamVerifier::with_chain_params`, `AsyncStreamVerifier::with_chain_params`, `verify_stream_two_pass_with_chain_params`), which judge under the chain's word and decline a coin from before the chain's own Genesis. The toolbox's production tip (`src/services/mod.rs:151-156` at `420f2e03`) names `chain.genesis_height` today.
2. **`KVStoreContext` carries the controller and the interpreter matches it**, as the reference's does (`kvStoreInterpreter.ts:6-10,39-46`): `new(key, protocol_id, controller)`; a context of another controller reads no value; `cache_key()` holds all three members. The global store's history walk hands the entry's controller, as the reference hands its historian. A `None` context still reads any token (this crate's own door; stated).
3. **`IdentityClient::parse_identity` takes the wallet's record**, and `auth::Certificate::to_wallet_certificate` returns `WalletCertificate` (text members), `wallet::Certificate` being gone.
4. **`CreateActionOptionsRaw` gains `trust_self`** (text, absent or `known`, refused otherwise in the reference's words) and `ValidCreateActionOptions` carries it as `Option<TrustSelf>`: a field added to a `Record` row built by literal (one migration line).
5. **`assert_no_drop!` reads its name as a type** (`$name:ty`), so a struct generic over a lifetime is pinned at `'static` (`SigningContext<'static>`): an identifier with type arguments could name no lifetime. One arm still; `MACRO_FILE_DIGEST` moved with it.

## RED before the change (root rule 2)

Scratch copies under `/Volumes/Lanes/tmp/` with their own target dir, never a checkout of a dirty tree; removed after.

| What | On | Result |
|---|---|---|
| `tests/arch_non_exhaustive_843d.rs` overlaid | a copy of `c9c74c7d` | 2 of 9 failed: `every_all_public_struct_is_attributed_or_listed_843d8a` naming exactly the 22 structs to open and the three that go (`CertifierInfo`, the identity module's `IdentityCertificate`, `wallet::Certificate`); `the_scan_reads_every_form_by_name_843d8a`, 220 where 217 |
| the 22 `compile_fail` pins and `assert_no_drop!` | a copy of the tip less the 22 `#[non_exhaustive]` lines | `cargo test --doc --all-features`: 477 passed, 22 failed, the 22 pinned blocks by name (each literal builds without the attribute) |
| `tests/open_structs_843.rs` | a copy of `c9c74c7d` | does not compile (E0599: no `new` on `ChainTip`, `SortResult`, `ScriptResourceLimit`, `OutputListItem`, `CreateActionOptionsRaw`, no `with_message`; E0609: no `trust_self`; E0308) |
| `tests/kvstore_context_controller_843.rs` | a copy of `c9c74c7d` | does not compile (E0061, `new` takes two arguments; E0609, no `controller`) |
| the same file | a copy of the tip with the controller taken out of the interpreter's match | 2 of 2 failed, `left: Some("one")`, `right: None` |
| `the_history_walk_keeps_to_the_entrys_controller_843` (unit) | the same copy, the controller taken out of the walk | failed, `left: ["theirs", "old", "new"]`, `right: ["old", "new"]` |
| `tests/identity_parse_identity_843.rs` | a copy of `c9c74c7d` | does not compile (E0308, the door took the identity module's record; E0425, no `identity::IdentityCertifier`) |
| `ChainTip`'s existing tests | carried to `ChainTip::new` | eight integration files and two unit modules; assertions unchanged but where the removed field was the subject (the next section) |

## Tests whose subject was the removed thing

Said here because "no assertion changed" cannot hold for them:

- `tests/pre_genesis_coin_rules.rs`: `a_test_chain_names_its_genesis_height_by_its_tip_h4m7` asserted that a tip naming Genesis at 1 or 800 made a low coin's spend valid at the default doors (and 801 refused it). The tip names nothing now. Restated as `a_test_chain_names_its_genesis_height_by_its_chain_parameters_h4m7`: refused at the seven default doors with mainnet's tip and with none (kept), and at the six doors that take chain parameters valid with Genesis at 1 or 800, not judged with Genesis at 801. `a_child_held_for_its_parent_is_judged_by_its_coins_era_h4m7` keeps its refusals (a tip, no tip) and shows the way out on the held path with the 521-byte push under parameters naming Genesis at 1 at the three readers that take them, where it showed every refused cell valid under a tip naming Genesis at 1 (under a word those cells are judged by the node's rules, not the default mode's, so "every cell valid" is not the claim any more).
- `tests/beef_stream.rs` `mining_row3d_p2sh_before_genesis`: the regtest tips 9,998 and 9,999 under the tip's Genesis at 10,000 become mainnet's 620,536 and 620,537; the two assertions stand.
- `tests/beef_not_judged_452.rs`: the helper's "obsolete Genesis" argument is gone; `chain_params_alone_decide_when_the_tip_disagrees_451` keeps its cells and its name (older records cite it), the tip no longer able to disagree.
- Removed with their types: `a_wallet_certificate_subject_or_certifier_in_a_lenient_form_is_refused_498`; the `wallet::Certificate` cell of `tests/wallet_certificate_field_order_385.rs`; `test_certifier_info_default` three times (`tests/identity_tests.rs`, `src/identity/types_tests.rs`, `src/identity/client.rs`).
- `tests/auth_integration_tests.rs`: four conversion tests assert text where they asserted keys, bytes and options.
- `tests/verify_input_door_fold_855.rs`: its two exhaustive destructures (one row per field, held by the build) cannot be written outside the crate any more; the rows are held by `same_evaluation`'s destructure in the source and by `declared_resource_fields`, a read of `ScriptResourceLimit`'s declaration.

## What the reads said that this lane did not follow

- The parity read's `ChainTip::new(height, median_time_past, csv_height)`: the captain's ruling is `new(height, median_time_past)` plus setters; `new` takes mainnet's CSV height, as the default path takes mainnet's Genesis.
- The parity read's "a produced-only result gets an `ASSIGNED` row": rule (a) asks a constructor, so each result has one (a test double builds it); `HostResponse` alone is an `ASSIGNED` row, its `success` and `failure` being its two valid states.
- The parity read's opening of both `BroadcastSuccess`, the registry's three results and `ServiceMetadata`, and its literal `Refusal`: (h), (c) and (b) decide otherwise. Its `wallet::Certificate` deprecated after the cut: (e) removes it.
- The api read's "the `*Raw` family additive after the cut" and its literal `SortResult`, `BeefValidationResult`, `ReviewActionsRefusal`, `OutputListItem`, `ScriptResourceLimit`: (b) opens them.
- The callers read's open `Multisig`, `Utxo` and `SimpleUtxo` and its literal raw arguments: (d), (h) and (b).
- The audits' open stream element records (`Bump`, `TxBody`, `Leaf`, `InputRef`, `OutputRef`; item 4 of the rulings as posted on #843 lists them too): the brief's (c) and the posted item 3 (#1033) keep them literal, and this lane follows those.
- The skeptic audit's additive controller door for `KVStoreContext`: (b) puts the controller in the cut.

## The dependents, counted, not changed

By `git grep` on the trees checked out on this host (none compiled: each pins a release whose tree differs from this base for other reasons too, the toolbox `=0.9.0-beta.8`, the overlay `0.8.11`):

| Repository | Lines that stop compiling | The fix per kind of site |
|---|---|---|
| `bsv-wallet-toolbox-rs` `420f2e03` | `ChainTip` literals, 10 at most (`benches/common/mod.rs:54`, `examples/a8_census.rs:71`, `src/services/mod.rs:153`, `src/storage/sqlx/beef_verification/live_word.rs:659,710,726`, `own_word_tests.rs:21`, `script_pin_tests/network_words.rs:59,81`, `tests/fixtures/storage/seed.rs:58`); `OutputListItem` literals, 5 (`src/wallet/discovery_evidence_tests.rs:126,132`, `lookup_decode_tests.rs:22`, `lookup_evidence_tests.rs:65`, `lookup_fixture.rs:181`); `ScriptResourceLimit` literal, 1 (`live_word.rs:522`); `to_wallet_certificate`, 1 (`src/wallet/lookup_fixture.rs:81`, whose readers take text now) | `ChainTip::new(height, median_time_past)` with `.with_csv_height(..)`, `.with_next_block_time(..)`; the Genesis height dropped, and where a tip named a chain's own (`src/services/mod.rs:151-156` names `chain.genesis_height` in production) the chain's `ChainParams` at the door; `OutputListItem::new(beef, output_index)`; `ScriptResourceLimit::new(resource, limit, attempted)`; the wallet record's text members |
| `bsv-overlay-cloudflare` `2c626f7c` | `OutputListItem` literals, 4 (`crates/overlay-engine/src/engine.rs:4058,9186,9216`, `crates/overlay-integration-tests/tests/wire_compat.rs:338`); `Refusal` literal, 1 (`crates/overlay-engine/src/beef_limits.rs:247`) | `OutputListItem::new(beef, output_index)` with `.with_context(..)`, `.with_txid(..)`; `Refusal::new(offset, reason)` |
| `bsv-messagebox-cloudflare-public`, `rust-message-box`, `bsv-middleware-rs`, `chaintracks-cloudflare`, `bsv-wallet-cli`, `bsv-middleware-cloudflare` | 0 | none (no site of an opened or removed item; the last two hold no `.rs` file naming `bsv_rs`) |

No dependent names `KVStoreContext`, `KVStoreInterpreter`, `identity::CertifierInfo`, `identity::IdentityCertificate`, `wallet::Certificate`, `parse_identity` or a raw action record.

## Found on the way, not this lane's

- `GlobalKVStore`'s query reads its subject with `Transaction::from_beef_subject` (no ancestry linked, #749's fold2), and its history walk follows `source_transaction` links, so with `with_history(true)` the walk reaches the subject alone at that door. Read in the code, not run. The controller match of the walk is pinned at the function for that reason.
- `IdentityClient::parse_identity` ports none of the display validation the reference runs at its head, and shows a short subject whole: stated in the root list with this change, older than it.

## The gate (on the commit's tree; this host's cargo 1.100.0, CI's stable this week; the ratchet on its pinned 1.95.0)

| Gate | Result |
|---|---|
| Rustfmt, the lint job's three lines (`cargo fmt --all -- --check`, `--manifest-path fuzz/Cargo.toml`, `--manifest-path fuzz/corpus-gen/Cargo.toml`) | pass, pass, pass |
| Clippy, the whole step: `--all-targets --all-features -- -D warnings`, then the twelve slices | pass; 12 of 12 pass |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` | pass |
| Unit (`cargo test --lib --all-features`) | 1,892 passed, 0 failed, 4 ignored |
| Integration (`--features "full,http,websocket"`, 435 binaries in two halves of 217 and 218) | 4,334 passed (1,952 and 2,382), 0 failed, 35 ignored |
| `memory_profiling` (`--all-features`, each test in a process of its own) | 16 passed, 0 failed |
| `wire_tracing_sink`, `wire_error_frames`, `fixtures_replay` (`--all-features`) | 20 passed, 0 failed |
| Doc tests (`cargo test --doc --all-features`) | 499 passed, 0 failed, 125 ignored |
| The doc pins (`the_doc_suite_ran_every_pinned_block_819` on that log) | 1 passed: 77 pinned types, each block ran |
| Sum over the test job's steps | 6,762 passed, 0 failed, 164 ignored |
| `fixtures_replay` and `front_page` (`--features "full,http"`) | 12 passed |
| wasm32 (`--no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`) | builds |
| Ratchet (`tools/ratchet/run --check --against c9c74c7d`, its own target dir) | all 7 counters, oversized-file limits and mutation floors pass: pedantic warnings 2,643 (2,650 on the base), duplicate windows 6,891 (6,895), 27 files over 800 lines (27) |
| `cargo semver-checks check-release --baseline-rev c9c74c7d --all-features --release-type minor` (0.51.0) | 202 checks, 196 pass, 6 fail, each the break meant: `struct_marked_non_exhaustive` (the 22), `struct_pub_field_missing` (`ChainTip::genesis_height`), `method_parameter_count_changed` (`KVStoreContext::new`), `struct_missing` (`identity::CertifierInfo`, `wallet::Certificate`), `inherent_method_missing` (the identity record's four helpers), `constructible_struct_adds_field` (`ValidCreateActionOptions::trust_self`) |
| Rows: `rows_from_sources.py --check`; `test_rows_from_sources.py` | 0 refusals; 10 tests OK |
| The fuzz crate (`cargo check --manifest-path fuzz/Cargo.toml`) | compiles (its one `to_wallet_certificate` call discards the answer) |

Not run here: a Linux or Windows cell (CI's, after the landing), `cargo fuzz run` (no parser changed), the nightly's mutants.

## Files shared with the open pull requests

By `gh pr diff <n> --name-only` against this lane's 122 changed paths: #915, 5 (documents only: the root and three module `CLAUDE.md`, `CHANGELOG.md`); #1014, 19 (this lane's base: the two censuses, `arch_no_foreign_type_843d23.rs`, `src/util/non_exhaustive.rs`, `src/identity/types.rs`, `src/overlay/types.rs`, `src/script/evaluation_error.rs`, `src/transaction/beef_stream.rs`, `src/wallet/types.rs`); #1005, 46 (the two censuses and the test files holding `OutputListItem` literals); #974 and #1009, 41 each (`src/transaction/beef.rs`, `beef_stream/not_judged_tests.rs` and the same test files); #1008, 51 (`src/auth/certificates/certificate.rs`, `src/wallet/mod.rs`, `review_actions.rs`, `types.rs`, `validation.rs`, `src/transaction/beef.rs` and the same test files). The test-file overlaps are one line each where a literal became a constructor call.
