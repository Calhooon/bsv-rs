# Lane fix-der-strict (#842, BLOCKS-CUT)

Started from beta `2c464e81` (`origin/beta`'s tip on 2026-11-10). Reference
`ts-stack@edf6e03` (`packages/sdk`), Go `go-sdk@2ca481c`, the node
`bitcoin-sv` `v1.2.2`. Logs under `/Volumes/Lanes/out/bsv-rs/fix-der-strict/`.

## The reader as built

`src/primitives/ec/signature_der.rs`, `read(der) -> Result<DerIntegers, &'static str>`,
crate-visible: the reference's `Signature.fromDER` (`Signature.ts:44-97`) in its
order and words, every byte by `get`:

| Check, in order | The reference | The words |
|---|---|---|
| byte 0 is `0x30` (empty input included) | `:60-62` | `Signature DER must start with 0x30` |
| byte 1 short form | `getLength`, `:45-52` | `Invalid DER entity length` |
| byte 1 + 2 equals the input's length (byte 1 absent: `NaN`) | `:64-66` | `Signature DER invalid` |
| byte 2 is `0x02` | `:67-69` | `Signature DER invalid` |
| R's length short form; absent (`NaN` position) | `:70`, `:73-75` | `Invalid DER entity length`; `Signature DER invalid` |
| the byte after R is `0x02` | `:73-75` | `Signature DER invalid` |
| S's length short form; absent | `:76-78` | `Invalid DER entity length`; `Invalid R-length in signature DER` |
| S ends the input | `:76-78` | `Invalid R-length in signature DER` |
| R: a zero byte only before a high bit, then dropped (a lone `00` refused) | `:80-86` | `Invalid R-value in signature DER` |
| S: the same | `:87-93` | `Invalid S-value in signature DER` |

`Signature::from_der` reads through it and then, this crate's one cell, refuses
an integer longer than 32 bytes as `Integer component too large` (stated).
`TransactionSignature::from_checksig_format` splits the last byte off and reads
the rest through `from_der`, the empty input the blank signature, as
`fromChecksigFormat` (`TransactionSignature.ts:460-472`).

**`reference_der`** (`src/wallet/wire/mod.rs`, #305) carried a full second copy
of the same checks with its re-encoding. It now calls `signature_der::read` and
keeps only the reference's `toDER` re-encoding (R written through `toArray`, a
zero R `00`; a zero S empty). One implementation of the checks, so the wire,
the certificate and `Signature::from_der` cannot drift. It did not become
`from_der`'s body because its job is the re-encoding the wire and the
certificate need (the bytes `fromBinary` keeps), which `from_der` has no use
for; `from_der` calls the shared reader instead of `reference_der` so that
`primitives` does not depend on `wallet`.

## The survey

Shapes: (1) bytes after the sequence, (2) a sequence length other than its
contents', (3) a long-form length, (4) an unneeded leading zero, (5) an integer
past 32 bytes, (6) an input under 8 bytes. "Base" is `2c464e81`, "after" this
lane's tip; "ref" the twin at its pin.

| Caller | Bytes from | Twin at the pin | Base | After | Twin |
|---|---|---|---|---|---|
| `Signature::from_der` (`primitives/ec/signature.rs`) | any | `Signature.fromDER` (`Signature.ts:44-97`) | (1) (2) accepted; (3) refused in other words; (4) accepted for one zero, two refused; (5) refused; (6) refused `DER too short` | (1)-(4) refused in the reference's words; (5) refused (stated); (6) read as the reference reads it (`300402000200` = (0, 0)) | (1)-(4) refused; (5) a `BigNumber`; (6) its checks |
| `TransactionSignature::from_checksig_format` (`primitives/bsv/tx_signature.rs:97`) | a script's push, a template's own output | `TransactionSignature.fromChecksigFormat` (`TransactionSignature.ts:460-472`) | as `from_der`; one byte `Checksig format too short` | as `from_der`; one byte `Signature DER must start with 0x30` | as `fromDER`; one byte the same words |
| `Spend::check_signature_encoding` (`script/spend/signature_encoding.rs:22`) and `verify_signature` (`script/spend/crypto.rs:401`) | a peer's unlocking script | under a word the node (`CheckSignatureEncoding`, `interpreter.cpp:265-280`, STRICTENC forced by FORKID at `:2315-2318`); default the reference's `Spend` (`Spend.ts:606-629`) | all six refused before the reader by BIP 66 (`The signature format is invalid.`) | unchanged | the node `SCRIPT_ERR_SIG_DER`; the reference the same words |
| templates `multisig.rs:388`, `p2pk.rs:215`, `p2pkh.rs:353`, `pushdrop.rs:632` | this crate's own signer's checksig bytes | none (the reference's templates write, never re-read) | this crate's writer only | unchanged (the round trip test, 2,000 signatures) | n/a |
| `messages::verify` (`messages/signed.rs:234`) | a peer's signed message | `SignedMessage.verify` (`SignedMessage.ts:65-105`) | (1) (2) and an S padded once verified `true` | refused in `fromDER`'s words; (5) `Err` (stated) | refused, (5) `false` |
| `compat::bsm::verify_message_der` (`compat/bsm.rs:314`) | a caller's DER | `fromDER` then `BSM.verify` (`BSM.ts:71-74`; the reference's BSM takes a parsed signature) | as above, `true` | refused | refused, (5) `false` |
| `ProtoWallet::verify_signature` (`wallet/proto_wallet.rs:344`) | a caller's argument | `ProtoWallet.verifySignature` (`ProtoWallet.ts:358-394`), its `isCanonicalDERSignature` check before the reader (`validationHelpers.ts:1795-1801`) | all refused at the argument check (`is_canonical_der_signature`) | unchanged | the same words |
| `wallet::pushdrop::sign` (`wallet/pushdrop.rs:28`) | the wallet's `createSignature` answer | `PushDrop.unlock` (`PushDrop.ts:255`, `Signature.fromDER`) | a wallet answering (1)-(4) was read | refused in `fromDER`'s words, as the reference | refused |
| `Certificate::verify` (`auth/certificates/certificate.rs:476`) | a peer's certificate | `Certificate.verify` (`Certificate.ts:425-440`) | behind `bounds::der_signature` (`reference_der`, #305): unchanged | unchanged | `false` |
| `auth::validate_certificate_encoding` (`auth/utils/validation.rs:265`) | a certificate held | none (this crate's helper; nearest `Certificate.toBinary`'s `fromDER`, `Certificate.ts:310`) | (1) (2) and one padded zero accepted | refused (`Signature is not valid DER encoding`) | `toBinary` refuses |
| overlay admin token (`overlay/admin_token_validation.rs:258`) | an advertisement on chain | `decodeAndVerifyOverlayAdvertisement` (`OverlayAdminTokenTemplate.ts:199-222`) | behind the canonical check (`reference_der` equality at `:222`): unchanged | unchanged | refused |
| UHRP advertisement (`storage/advertisement.rs:128`) and the wire's certificate signature (`wallet/wire/mod.rs:420`, `certificate_signature_der`) | an advertisement on chain; a certificate on the wallet wire | `decodeAndVerifyUHRPAdvertisement` (`UHRPAdvertisementValidation.ts`); `Certificate.fromBinary`'s `fromDER` (`Certificate.ts:390-397`) | `reference_der`'s own copy of the checks (#305) | unchanged: the same checks now read through `signature_der::read` (the rule read of PR #846 compared the removed copy with `read` branch by branch) | refused |
| `P256Signature::from_der` (`primitives/p256.rs:455`) | a caller's DER | none: `Secp256r1.ts` has no DER reader | RustCrypto `der`, strict: every shape refused (`invalid DER signature: signature error`, probed) | unchanged | n/a |

Go at `2ca481c`, one line each: `ParseDERSignature` (`primitives/ec/signature.go:304`,
`parseSig` `:177-295`) cuts the input to the sequence's length (bytes after it
ignored), reads length bytes as numbers, refuses an unneeded zero, refuses R or
S outside 1 to n - 1; `ParseSignature` (`:297`) the same without the padding
rule; `FromDER` (`:47-54`) is `encoding/asn1.Unmarshal`, the rest after the
sequence ignored. `message/signed.go:102` reads through `FromDER`,
`compat/bsm/verify.go:62` through `ParseDERSignature`.

## The interpreter's witness table

`tests/script_signature_der_842.rs`; each shape on this crate's signer's
signature over the input's digest, `<sig> <key> OP_CHECKSIG` and the same under
`OP_NOT`, versions 1 and 2. Words: "the format" is `The signature format is
invalid.`.

| Word | Shapes (1)-(4), (6): today | The node | After |
|---|---|---|---|
| default (no word) | the format | (the reference's default: the format, `isChecksigFormatHelper`) | the format |
| `block(PostGenesis)`, `standard(PostGenesis)` | the format | `SCRIPT_ERR_SIG_DER` | the format |
| `block(PostChronicle)`, `standard(PostChronicle)` | the format | `SCRIPT_ERR_SIG_DER` | the format |
| `block(era)` less DERSIG, STRICTENC, LOW_S | the format | `SCRIPT_ERR_SIG_DER` (STRICTENC forced back by FORKID) | the format |

As built before the reads, this lane held that no private lax reader was
needed. The reads showed otherwise: an R or S that is a single `00` byte passes
BIP 66 and the reference's reader refuses it, so under a word the strict reader
moved a verdict away from the node. The fold (below) ports the node's lax parse
for the interpreter under a word.

Shape (5), stated, older than #842 (`an_integer_past_32_bytes_is_refused_in_every_mode_stated_842`):

| Word | Today and after | The node | The reference's default |
|---|---|---|---|
| default v1 | the format | n/a | R long: valid under `OP_NOT`; S long: the format (low-S) |
| default v2 | the format | n/a | valid under `OP_NOT` |
| words with NULLFAIL enforced (v1; post-Genesis at v2) | the format | NULLFAIL's error | n/a |
| `block(PostChronicle)` / `standard(PostChronicle)` at v2 | the format | valid under `OP_NOT` (lax parse: the all-zero signature, `pubkey.cpp:146-173`) | n/a |

A verdict apart from the node under a supported word; not fixed here (the fix
is the interpreter's reading of such an integer, a reader this lane did not
build). Reported.

## The differential

Harness: `/Volumes/Lanes/out/bsv-rs/fix-der-strict/harness/` (`gen.mjs`,
`main.rs`, `ref.mjs` copied from the #305 harness; `gen_842.mjs` adds the six
shapes at every byte position of four signatures: suffixes of 1, 2 and 33
bytes, each length byte plus and minus one and two, each length in three long
forms with the sequence adjusted and not, zeros before R and S, truncation at
every position; `ref_842.mjs` calls `Signature.fromDER`; the scratch crate
`crate/` calls `Signature::from_der`). 11,393 inputs (9,878 distinct).

| Tree | Differing lines |
|---|---|
| base `2c464e81` | 8,133 (1,012 inputs accepted that the reference refuses, 357 refused that it reads, the rest the words) |
| tip | 347, every one an R or S past 32 bytes (the stated cell) |

## The recording and the RED

`tests/vectors/signature_der_842.json`, 42 cells, two runs byte-identical.
`tests/signature_der_842.rs` on a scratch copy of the base with its own target:

```
test a_der_signature_followed_by_bytes_is_refused_842 ... FAILED
test an_input_under_eight_bytes_and_a_lone_byte_are_read_as_the_reference_reads_them_842 ... FAILED
test a_sequence_length_other_than_its_contents_is_refused_842 ... FAILED
test an_unneeded_leading_zero_is_refused_842 ... FAILED
test every_reader_cell_is_the_reference_save_the_stated_one_842 ... FAILED
test a_long_form_length_is_refused_in_the_reference_words_842 ... FAILED
test a_bsm_signature_with_bytes_after_it_does_not_verify_842 ... FAILED
test a_proto_wallet_refuses_every_shape_at_its_argument_check_as_the_reference_does_842 ... ok
test a_signed_message_with_bytes_after_its_signature_does_not_verify_842 ... FAILED
test the_three_signatures_are_this_crates_signers_and_the_shapes_its_builders_842 ... ok
test every_signature_this_crate_writes_reads_back_equal_842 ... ok
  left: "true"
 right: "ERR:Signature DER invalid"   (the signed message and the BSM signature)
test result: FAILED. 3 passed; 8 failed
```

`tests/script_signature_der_842.rs`: 6 of 6 green on the base and on the tip.

## The sweep

Every integration file under `tests/` (344; `memory_profiling` aside) under
`full,http`: one failure, `tests/ec_tests.rs`'
`test_malformed_der_trailing_data_accepted`, which pinned the acceptance #842
reverses (its comment named go-sdk's trimming); renamed
`test_malformed_der_trailing_data_refused_842`, asserting the reference's words
and that `from_checksig_format` reads the byte as the scope. No other test failed. A scan of every hex run in `tests/vectors/` for a DER
sequence (`30 LL 02`, LL from 4 to 72; 2,057 candidates, each at its exact length
and with one byte after it) through the base and the tip reader: 16 exact-length
DERs the base read are refused now, all in vectors whose doors already refuse
them as the reference does and whose tests stay green (`auth_certificate_signature_der_305.json` 2,
`auth_certificate_verify_false_299.json` 1, `http_json_result_values_408.json` 2,
`script_valid.json`/`script_invalid.json` 5, judged at BIP 66 before the reader,
`signature_der_842.json` 6); the 981 others are checksig forms (a DER and its
hash type byte), read by `from_checksig_format`. No vector is edited. No source, test or
dependent matches on the old words (`DER too short`, `Expected sequence tag`,
`DER length mismatch`, `Expected integer tag`, `length overflow`, `Checksig
format too short`); `CHANGELOG.md` keeps them in its history.

## The dependents

Calls of `Signature::from_der`, `from_checksig_format`, `verify_message_der`,
`messages::verify` and `verify_signature`, each sibling grepped by its own path:

| Path | Count | Production sites |
|---|---|---|
| `~/bsv/bsv-wallet-toolbox-rs/src` | 2 | `storage/client/auth.rs:386`, `wallet/wallet.rs:992` (`ProtoWallet::verify_signature`: a canonical check before the reader, no move) |
| `~/bsv/bsv-wallet-cli/src` | 1 | `server/handlers.rs:738` (the wallet's `verify_signature`) |
| `~/bsv/bsv-overlay-cloudflare/crates` | 13 (7 production) | `overlay-discovery/src/validation.rs:356`, `result/validity.rs:117`, `uhrp/topic_manager.rs:249`, `potparty/validity.rs:334` (`ProtoWallet::verify_signature`); `pot/spend_signers.rs:180` (`Signature::from_der` on a spending transaction's pushes, part of a raw transaction whose txid is taken); `potparty/validity.rs:283` (`canonical_der`: `from_der` then `to_der` equality and low S, the marker signature's bytes keyed; its own guard already refused every reshaped form) |
| `~/bsv/rust-message-box/src` | 2 (1 production) | `engineio/auth.rs:319` (`verify_signature`) |
| `~/bsv/bsv-middleware-rs` | 1 | `src/auth.rs:134` (`verify_signature`) |
| `~/bsv/chaintracks-cloudflare` | 0 | none |

None matches on the old error words.

## Notes for the captain

- `fuzz/corpus-gen` did not compile on beta (#817 made `Beef::to_binary` and
  `MerklePath::to_binary` return `Result`; `fuzz/corpus-gen/src/main.rs:240`,
  `:274`): fixed here with `.unwrap()`. It then panics at
  `fuzz/corpus-gen/src/main.rs:393` (`value["wire"]` absent in a wallet-wire
  vector file), older than this lane and not fixed; the `fuzz_signature_der`
  seeds were written by running `signature_corpus` alone.
- `messages::verify` has no 174-byte upper bound where `SignedMessage.verify`
  refuses past `MAX_SIGNED_MESSAGE_BYTES` (`MessageValidation.ts:11-25`); older
  than #842, outside its cells.

## The fold (lane fix-der-strict-fold, 2026-11-10)

The three reads of 2026-11-09 on `4b3fe10d`: the cold read FIX, the rule read
ACCEPT (its docs commit `257265db`, the survey's two missing `reference_der`
callers, cherry-picked), the strength read FIX. The cold and strength reads
named no commit. Both FIX reads found that this PR moved a consensus verdict
away from the node: a lone `00` R or S passes BIP 66, and the node's lax parse
reads it as zero, so `<sig> <key> OP_CHECKSIG OP_NOT` is valid under the three
post-Chronicle words at version 2. The strict reader refused it. The cell this
lane stated (an R or S past 32 bytes, #847) is the same mechanism.

**What was folded.**

- **One reading in the interpreter.** `src/script/spend/der_lax.rs` ports
  `ecdsa_signature_parse_der_lax` (bitcoin-sv v1.2.2 `pubkey.cpp:32-175`)
  whole, every branch cited, every byte by `get`.
- **One reader at both sites.** `src/script/spend/signature_read.rs` gives the
  signature to the encoding check and to `verify_signature` alike: under a word
  the lax parse, without one the reference's `fromDER`. All four signature
  opcodes reach it through the two shared sites.
- **#14's order exception.** `signature_overflows_the_order` is removed: under
  a word the lax parse's overflow is the same reading. In the default mode the
  reference's predicate is kept, with #14's exception for 32-byte values.
- **The default mode.** It is conformed to a recording of the reference's
  `Spend` (`tests/vectors/script_signature_der_842.json`, 64 spend cells, two
  runs byte-identical under Node v22.18.0). 14 cells moved against the base,
  stated in the CHANGELOG.
- **The writer.** `Signature::to_der` writes a zero S `02 00`, as the
  reference's `toDER` does.
- **The length edges.** `0x7f` and `0x80` cells at the sequence, at R and at S
  (7 recorded) kill the two `length()` survivors.
- **The witness pin.** `tests/script_signature_der_842.rs` is rewritten (5
  tests). Its stated pin is replaced by witnesses against the node and the
  base.

**RED** (logs in `/Volumes/Lanes/out/bsv-rs/fix-der-strict-fold/`):

```
4b3fe10d + the fold's tests (red_tip_4b3fe10d.txt):
test a_lone_zero_r_or_s_is_a_failed_check_under_a_word_as_the_node_reads_it_842 ... FAILED   (120 cells)
test an_integer_past_32_bytes_is_a_failed_check_under_a_word_as_the_node_reads_it_847 ... FAILED   (120 cells)
test the_default_mode_answers_as_the_reference_recorded_842_847 ... FAILED   (6 cells)
r_lone_zero CheckSig post-genesis 0xd462f v1: got Err("The signature format is invalid."), node Err("OP_CHECKSIG requires failing signatures to be empty."), base Err("OP_CHECKSIG requires failing signatures to be empty.")
test a_zero_s_is_written_as_the_reference_writes_it_and_reads_back_842 ... FAILED
  left: "3006020105020100"
 right: "30050201050200"
2c464e81 + the fold's tests (red_base_2c464e81.txt):
test an_integer_past_32_bytes_is_a_failed_check_under_a_word_as_the_node_reads_it_847 ... FAILED   (120 cells)
test the_default_mode_answers_as_the_reference_recorded_842_847 ... FAILED   (14 cells)
test a_lone_zero_r_or_s_is_a_failed_check_under_a_word_as_the_node_reads_it_842 ... ok
length() mutants planted in a scratch copy of 4b3fe10d (red_length_mutants.txt):
*b <= 0x80: left: "Signature DER invalid", right: "Invalid DER entity length"
*b < 0x7f:  left: "Invalid DER entity length", right: "Signature DER invalid"
```

**The oracles.**

- **The Lean harness.** bsv-script-lean@5dc337e1's `harness/run --impl bsv-rs
  --corpus all`, in a scratch copy linked to the fold, gives 8 GREEN and 1 RED.
  The RED is crypto's one recorded-verdict disagreement, `crypto-00079` (#657's
  CHECKMULTISIG words), the base's one. `crypto-00035` and `crypto-00077`
  agree again.
- **gobdk and sv-node.** Neither runs on this host: no Go toolchain, no
  `bitcoind`, no VM. Their setup stops are `oracle_gobdk.txt` and
  `oracle_svnode.txt`.

**The differential.** It was rebuilt in the fold's own folder, because the #305
harness is another lane's: 6,843 inputs. The base differs on 4,559 lines;
`4b3fe10d` and the fold differ on 15 each, every one the stated cell.
`differential/README.md` holds the method. The scoped cold re-read's count on
the 11,039-input set the cold reads used (9,562 distinct): 347 differing lines
on the fold, every one the stated cell; 7,779 on beta `7df16cf6`.

**Rows outside the subject, not taken:**

- `messages::verify`'s length-bound words (after-cut).
- `fuzz/corpus-gen/src/main.rs:393`.
