# Changelog

All notable changes to `bsv-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed: the KVStore reader accepts the reference writer's untagged token (#344)

The public token reader now distinguishes exactly five fields (no tags,
signature at index 4) from six (tags at index 4, signature at index 5).
Previously `extract_fields` also treated the five-field token's signature as
its tags, concatenating the signature into its own signed message and
rejecting every untagged token. A present tag field is parsed as a JSON array
of at most 32 strings; each must occupy 1 to 256 UTF-8 bytes and be unique.
The checks run in the reference's order: array/count, then each tag's
length/type before its uniqueness. Invalid tags are skipped by the store
and interpreter, as the reference skips them, with the validator's exact
`KVStore tags must be a bounded array`, `KVStore tag has an invalid length`
and `KVStore tags must be unique` words pinned in the unit test.

Reading the actual reference token also requires its signature derivation:
the JSON wallet protocol and the token's key as key ID, with its locking key
bound to that controller. The reader now recognizes that form and verifies
it on both the global lookup and history paths. The store's string
configuration `kvstore` matches that same App namespace `[1,"kvstore"]`, so
the reference token reads through the default store configuration. The
writer and the store implementations are unchanged; their older raw-protocol
tokens retain their existing verification path. An explicit empty tag array remains a present,
signed field; an absent field never includes the signature in the message.

`tests/support/signaction_reference_326.mjs --kvstore-tags` extends the #326
recorder. Its 18 cases in `tests/vectors/kvstore_tags_344.json` were recorded
twice identically under Node v22.18.0 from `ts-stack@edf6e03` built from the
clone's commit. Accepted tokens come from `GlobalKVStore.set`; the malformed
tag and explicit-empty witnesses come from the reference's signed
`PushDrop.lock`, since the store refuses to write malformed tags.
`tests/kvstore_untagged_token_344.rs` pins field separation, reading the
writer's untagged token through an injected, offline-only resolver, all
accepted boundaries, signing an explicit empty array, and rejecting the
malformed tokens. The five tests are RED on base `bf97cc74` in a scratch
copy with its own target directory. The unit
`malformed_reference_token_tags_use_the_reference_words_and_order` checks
the nine validator refusals, including competing failures, against the
recorded words. Two older `kvstore_integration_tests` expectations now refuse
empty and zero-byte tag fields: the reference writer encodes both as `00`
and its reader skips both as invalid JSON (recorded too). These are not an
absent tag field or the valid JSON array `[]`. Both corrected expectations
are also RED on the same scratch base.

### Notes: cross-SDK parity (#344)

Under the owner's ruling (c), the tag rule follows
`ts-stack@edf6e03` `packages/sdk/src/kvstore/kvStoreTokenValidation.ts:58-74`
and `:88-118`: exactly five or six fields, tags only in the six-field form,
the signature always last, and all preceding fields signed. The interpreter
names both layouts at `kvStoreInterpreter.ts:15-18`, authenticates at `:37`,
then filters and returns the value at `:39-47`, skipping failures at `:48-50`.
The global writer omits the tags field for absent or empty tags
(`GlobalKVStore.ts:279-304`); its reader authenticates at `:627` and skips a
refusal at `:657-659`. Untagged means no payload tags, not an invalid token;
an explicit `[]` is also accepted. The local store's tag is different: its
wallet output is tagged with the key (`LocalKVStore.ts:175-188`), while its
token contains only value and signature (`:278-298`), authenticated before
optional decryption (`:340-368`).

The older `ts-sdk@9e3ede6b` interpreter also accepts exactly five/six fields
(`src/kvstore/kvStoreInterpreter.ts:34-46`); its global reader calls
`verifySignature` on the last field, then treats unparseable tags as absent
(`GlobalKVStore.ts:456-498`), unlike the current reference's strict tag
checks. `go-sdk@2ca481c` has only the local store: wallet lookup by `[key]`
(`kvstore/local_kv_store.go:174-188`), value in field 0 (`:131-156`), its
writer's value-only payload (`:265-278`); no public five/six-field reader.

This closes #326's untagged-token finding. Other existing differences remain:
this crate's writer uses a raw protocol name and the fixed `kvstore-token`
key ID, its reader continues to accept that older form, and its public
context has no controller selector. The rest of the reference's canonical
PushDrop, protocol/value/controller bounds, overlay selector/active-state checks and
local-token authentication are outside this tag fix; it does not claim full
reader parity. The #326 signAction/previous-token findings remain separate.

## [0.9.0-beta.3] - 2026-10-28

The 0.9.0 line's third prerelease (RELEASING.md point 14), cut from `beta` at the owner's word through the keeper (the brief's 19.7: bsv-rs 0.9.0-beta.3, then the toolbox's 0.14.0-beta.3 carrying its re-pin, then the CLI's one pin PR) at the tip after #429 landed (a53a9492), so the canaries re-pin the interpreter's default-mode changes of #397 and #429 once. The pin set the canaries waited on: #385 and #394 (the ordered maps), #373 (the streaming reader's memory budget), #335 and #404 (`WalletClient` as a `WalletInterface` under the `wallet` feature, its methods on `&self`: the one API break of this prerelease, named in #404's entry), #415 and #420 (`ProtoWallet`'s argument validators in the reference's words), #406 (the wire transceiver's two linkage calls), #416 (the HTTP auth transport's bounds) and #417 (the script engine's version-1 words). Every entry below was cold-reviewed on a model other than its lane's and landed through the sequencer; the fixtures' diff since beta.2 is in the announcement.
### Fixed: HTTP JSON result lengths, DER signatures, containers and signed certificates follow the reference (#408)

The keeper's 2026-10-28 ruling (c), parity on beta.3: the reference client's
`validateWalletResult` bounds are this port's bounds. #365 normalized byte
fields only after a typed read failed. A typed success could therefore hide
a present `null` in an `Option`, return a non-DER signature, or accept a
malformed or oversized wallet certificate. HMAC length was checked, but in
this crate's words rather than the reference's.

`http_json/result_values.rs` now checks the raw response before that typed
read. Its modules borrow field slices; normal byte arrays avoid a `Value`
tree, and #365's historical numeric-key objects and integral floats still
work. The new checks are:

- HMAC exactly 32 bytes; signature at most 72 bytes and strict minimal DER,
  with both scalars nonzero and below the curve order (high S is allowed).
- Every result is an object; every result byte, record and array site
  rejects `null` in the reference's words. Optional arrays distinguish
  absence from null and admit at most 100,000 entries. A signable transaction
  is an object, is exclusive of tx/txid and belongs only to createAction.
- Every wallet certificate returned by acquisition, listing, either
  discovery call or proof has canonical 32-byte base64 identifiers,
  compressed keys, the reference's revocation outpoint, 1–50-byte field names
  and string values, a canonical DER signature and encoded length at most
  16 MiB, including compact-size prefixes. These are structure checks;
  the reference does not verify the signature here either.

The complete dispatch inventory, with each reference line and before/after
behavior, is in `src/wallet/substrates/CLAUDE.md` under “Result-check
inventory (#408)”. This is the explicitly permitted four-class split:
remaining scalar bounds, affirmative verdicts, request/filter bindings,
transaction/BEEF checks, global graph budgets and unsafe-key checks
are assigned to a second lane. Their behavior is unchanged. No public
type or signature changes.

`tests/wallet_http_json_result_values_408.rs` pins the four classes against
387 bodies written by `tests/support/http_json_result_values_408.mjs` from
the unmodified `ts-stack@edf6e03` SDK, bundled from that commit and run
under Node 22.18.0. Of these, 56 are accepted and 331 refused. The 16 MiB
certificate boundary (one byte below, exact, one above) and the 100,000
array boundary use recorded expansion recipes instead of huge fixtures.
The HMAC, signature, container and certificate regression tests all fail
on scratch base `3eb965cb` with its own target directory (322 of 387 bodies
differ; no setup failures), then pass here.
#365's independent 110 byte-field cases remain pinned.
The permission-request unit test now returns two valid DER signatures; the
nonce safety test expects the new HMAC words. The transport architecture
guard explicitly allows the two schema selectors (call name and output
member name); neither classifies error text.
The fixture writer was run in a scratch copy: only
`tests/fixtures/http_json/createAction.json` (the full result carries both a
signable and a completed transaction) and `http_json/errors.json` (the short
HMAC's words) changed. Their inputs and the fixture census are unchanged.

Operator-visible rows for the toolbox (`Error::WalletError` keeps its
`wallet error: ` Display prefix):

| Trigger | Old words / behavior | New words / behavior |
|---|---|---|
| HMAC length N ≠32 | `invalid HMAC length: expected 32, got N` | `Invalid createHmac result hmac: expected 32 bytes` |
| Signature longer than 72 bytes | Accepted | `Invalid createSignature result signature: expected at most 72 bytes` |
| Noncanonical signature | Accepted | `Invalid createSignature result signature: expected a canonical DER-encoded ECDSA signature` |
| Null optional tx / BEEF | Absent | `Invalid <call> result <field>: expected an array of bytes` |
| Null/scalar signableTransaction | Absent / serde words | `Invalid createAction result signableTransaction: expected an object` |
| Null optional array | Absent | `Invalid <call> result <field>: expected an array` |
| Array above 100,000 entries | Accepted | `Invalid <call> result <field>: expected at most 100000 entries` |
| Signable transaction beside txid/tx | Accepted | `Invalid createAction result signableTransaction: expected exclusive of txid and tx` |
| signAction carrying signableTransaction | Ignored | `Invalid signAction result signableTransaction: expected an absent field` |
| Non-object nested record | Absent / serde words | `Invalid <call> result <field>: expected an object` |
| Specific-linkage protocolID of the wrong shape/length | Serde words | `Invalid revealSpecificKeyLinkage result protocolID: expected a [securityLevel, protocolName] tuple` |
| Non-object entire response | Accepted positional arrays / serde words | `Invalid HTTPWalletJSON <call> response: expected an object` |
| Malformed / oversized certificate | Accepted / serde words | `Invalid <call> result <certificate path>: expected a canonical signed wallet certificate` |

### Notes: cross-SDK parity (#408)

The four classes follow `WalletResultValidation.ts:868–906`, `:971–976`,
`:1247–1273`, `:1477–1537`, `:1919–1938`, `:2216–2225` and the HTTP wrapper's
own `HTTPWalletJSON.ts:330–331` words. A non-object nested certificate uses
`expected an object` outside the certificate catch. A scalar malformed
alongside a container can still be refused in a different order until the
second lane ports the pending scalar checks. The reference's global unsafe
record-key check remains assigned to that lane as well.

Go at `2ca481c` (`wallet/substrates/http_wallet_json.go:204–213`, `:226–235`,
`:248–267`) reads each successful response with `json.Unmarshal`, including
its types' custom readers; it has no separate `validateWalletResult` pass.
Its HMAC reader already requires 32 bytes, in its own words
(`wallet/encoding_json.go:796–811`). Its signature reader uses
`ec.ParseSignature` (`wallet/encoding.go:141–153`), which checks scalar range
but uses the BER path: padding is not enforced and bytes beyond the declared
sequence are trimmed (`primitives/ec/signature.go:177–305`). Its certificate
reader skips an empty signature and otherwise uses that same parser, with
no 16 MiB encoded-size bound (`wallet/encoding_json.go:195–211`). `BytesList`
is read through `[]uint8` (`wallet/encoding.go:24–31`), which also accepts
base64 and reads null as a nil slice (the HMAC length check then refuses it).
The outstanding differences are enumerated in the module inventory; this
change makes no claim of complete JSON result parity.
### Fixed: certificate requests verify the parsed object's JSON.stringify preimage (#426)

A received certificate request now verifies the complete `requestedCertificates`
object re-serialized as the reference's `JSON.stringify`, including properties
outside the typed certificate set. Previously `AuthMessage::signing_data` used
its retained raw JSON bytes under #280's precedent. That accepted a signature
the reference refused on whitespace or redundant escapes, and refused the
reference's valid signature over the parsed object. Neither SDK's normal
writer emits those alternate encodings; third-party clients can send them.

The new `auth/requested_certificates_json.rs` parser preserves insertion order
with `IndexMap`, moves array-index property names ahead in numeric order, and
keeps the last duplicate property's value in its first position. It emits
compact separators. Node 22.18.0 measures the short escapes for backspace,
tab, newline, form feed and carriage return; lowercase `\u00xx` for the other
C0 controls; `\"` and `\\`; lowercase `\uXXXX` for lone UTF-16 surrogates.
Slashes, HTML punctuation, Unicode, U+2028/U+2029 and valid surrogate pairs
are unescaped. Numbers read as doubles and print with ECMAScript formatting
(`ryu-js`), including negative zero as `0`, the fixed/exponent thresholds,
and rounding beyond the safe-integer range. The original text stays available
on `AuthMessage`; only the request's signature preimage changes. The shared
`signing_data` path covers HTTP and JSON-message transports. CertificateResponse
keeps its existing #280 behavior.

This is #400's byte-compared body: parse it in order, never through a sorted
`serde_json::Value`. The typed set alone loses extra properties and cannot be
the signature preimage. No public fields or method signatures change.

`tests/support/auth_http_certificate_request_416.mjs` extends the #416 recorder,
running both archived reference SDKs under Node 22.18.0 without a socket. The
regenerated `tests/vectors/auth_http_certificate_request_416.json` adds eight
pairs signed over the raw and stringified forms: whitespace, reordered keys,
an escaped string, all 32 controls plus otherwise unescaped characters, lone
surrogates, numeric property names, duplicate keys, and fourteen number forms.
Callback objects are recorded as JSON text to preserve lone surrogates.
Two independent recordings match byte for byte. `tests/auth_peer_http_certificate_request_416.rs`
asserts the real Peer's verdict equals both recorded references and checks its
preimage bytes and callback delivery. On base `edfc442d`, eleven tests fail and
four pass; all fifteen pass with this fix.

The four #422 pins are the record of the state before this lane, not changed
reference observations. For the toolbox's table:

| Condition / pin | Before #426 (Rust / reference) | After #426 (Rust / reference) |
| H3: whitespace header, raw signature | Accept / refuse | Refuse / refuse |
| H3b: whitespace header, stringified signature | Refuse / accept | Accept / accept |
| H5: escaped key, raw signature | Accept / refuse | Refuse / refuse |
| H5b: escaped key, stringified signature | Refuse / accept | Accept / accept |
| Reordered keys, signed in received order | Accept / accept | Accept / accept |
| Extra property, signed with that property | Accept / accept | Accept / accept |

Rust refusals in this table are `WalletError("Signature is not valid")`;
no certificate-request or general-message callback is delivered.

### Notes: cross-SDK parity (#426)

Under the owner's ruling (c) and the keeper's 2026-10-28 12:1xZ word,
this follows `ts-stack@edf6e03`
`packages/sdk/src/auth/Peer.ts:1068`: the verifier uses
`JSON.stringify(message.requestedCertificates)` as its preimage. `SimplifiedFetchTransport.ts:238-249`
parses the header with `JSON.parse`, and `:349` carries that object into the
message. The older `ts-sdk@9e3ede6b` records the same certificate-handler
verdicts. The newer full HTTP intake still refuses its missing `initialNonce`;
the recorder retains that observation separately and invokes its unchanged
certificate handler, as #416 did. This change resolves the preimage divergence,
not that separate intake difference or existing typed-schema limitations.

Go at `2ca481c`, `auth/peer.go:829`, also re-serializes before verifying with
`json.Marshal(message.RequestedCertificates)` (its writer at `:1109`). Its
typed set drops unknown properties, sorts map keys and uses Go's JSON string
escaping; it is not a byte oracle for JavaScript's insertion-ordered object.
The reference writers use `JSON.stringify` (`auth-express-middleware/src/index.ts:943,1015`)
and Rust's header writer uses `serde_json::to_string` (`http.rs:581`). #422's
H3/H3b/H5/H5b verdicts remain historical evidence of the old behavior above.

### Fixed: inherent specific-key linkage returns counterparty keys, as the trait does (#427)

`ProtoWallet::reveal_specific_key_linkage` now returns the counterparty's
compressed public-key hex: the wallet's identity key for `Self_`, the public
key of private scalar 1 for `Anyone`, and the supplied key for `Other`.
Previously the inherent method returned the strings `self` and `anyone`,
disagreeing with both the current reference and its own `WalletInterface`
adapter. The adapter now reads the inherent result's counterparty instead
of resolving the request again, as the counterparty-linkage adapter does.
Public types and the trait's result are unchanged.

The wire wrapper's unreachable second missing-counterparty refusal is
removed. The shared `crypto::reveal_specific_args` returns the required
counterparty with its checked verifier; its first refusal retains code 6,
`The counterparty parameter must be a hexadecimal string`, before checking
the verifier, protocol, key ID or privilege.

`tests/support/wallet_proto_args_415.mjs --specific-linkage` extends #420's
recorder and records the actual ProtoWallets built from both pinned commits
under Node v22.18.0. `tests/vectors/wallet_specific_linkage_427.json` holds
three current-reference results and three older-reference observations;
two recordings match byte for byte. `tests/wallet_specific_linkage_427.rs`
checks all three counterparty forms through both entry points, including
the decrypted linkage and proof length. On a scratch copy of base
`3eb965cb99f288da089d47749ae8f7e0532eb1d5`, the self and anyone tests are
RED (the aliases versus recorded keys), and the explicit-key test passes.
The existing self-linkage unit test now expects the identity key as well.
The #420 replay helper now reads the returned keys instead of reconstructing
them from the request, which previously concealed this mismatch.

`a_missing_specific_linkage_counterparty_is_refused_before_all_other_arguments`
in `tests/wire_processor_validation.rs` pins the first refusal's complete
frame and that the wallet is not called, with all later arguments invalid.
It passes before and after removing the dead check; the existing absent-key
and invalid-verifier ordering tests remain in place.

Rows for the toolbox's operator-visible table (key 42 is the recorded prover):

| Condition | Old result or words | New result or words |
|---|---|---|
| Inherent specific linkage with `Self_` | `self` | `02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af` (the prover's identity key) |
| Inherent specific linkage with `Anyone` | `anyone` | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| Inherent specific linkage with `Other` | Supplied compressed key hex | Unchanged |
| Wire specific linkage without a counterparty | `The counterparty parameter must be a hexadecimal string` (InvalidParameter, code 6) | Unchanged |

### Notes: cross-SDK parity (#427)

Under the owner's ruling (c), the result follows `ts-stack@edf6e03`
`packages/sdk/src/wallet/ProtoWallet.ts:235-250`: `self` becomes the identity
key, `anyone` becomes `new PrivateKey(1).toPublicKey().toString()`, and an
explicit key is returned as supplied. Its counterparty-linkage result also
returns the supplied key (`:208-217`). The older `ts-sdk@9e3ede6b`
`src/wallet/ProtoWallet.ts:161-171` returns `args.counterparty` unchanged,
including the two aliases; that difference is retained in the recording.
Go at `2ca481c` resolves the same three forms to public keys
(`wallet/proto_wallet_reveal.go:120-123,169-177,195-214`). Rust's typed
public keys serialize compressed; #420's existing input-encoding and
type-enforced limitations still apply. No current-reference result-form
divergence remains for the three representable counterparty variants.
### Fixed: the default mode accepts signatures without the fork-ID bit over the original digest (#429)

Without an explicit flag word, a `0x01` signature at transaction version 1
or 2 now verifies over the original transaction digest, as both TypeScript
references do. A signature over the wrong digest still fails CHECKSIG; the
recorded BIP143-signed control answers `The top stack element must be truthy
after script evaluation.` Previously an unconditional check rejected both
with `The signature must use SIGHASH_FORKID.` before verification. The
existing digest dispatcher already selected the original algorithm for a
signature lacking the bit; the encoding gate prevented it from being used.
No public API or signing behavior changes. The version-1 DER-wrapper words
and order fixed by #417, and every explicit-word refusal, stay unchanged.

`tests/script_forkid_gate_429.rs` pins the version-1 acceptance, wrong-digest
words, both version-2 verdicts, and the node's refusal under a word at both
versions, with and without an explicit STRICTENC bit. Its three default tests
are RED on `ff08faa3` in the old fork-ID words. The extended
`tests/support/script_signature_words_417.mjs` records twelve cases from each
unmodified pin under Node v22.18.0, with both original and BIP143 digests,
in `script_forkid_gate_429{,_ts_sdk}.json`. The original nine #417 recordings
reproduce byte for byte; their tests and the existing witness files have no
diff. The fix gates only the missing-fork-ID refusal in
`src/script/spend/signature_encoding.rs`.

The census re-judges 66 rows against both references (identical default
verdicts), recorded by `tests/support/script_forkid_census_429.mjs` in
`tests/vectors/script_forkid_census_429.json`. The new test in
`tests/support/conformance_forkid_gate_429.rs` replays every verdict against
the shared corpus, including every newly passing allowlisted row, the six
removed known failures, the newly exposed NULLFAIL cases, and #417's fourteen
low-S/undefined-type rows plus #397's Chronicle row. With
`BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance`:

| Evaluation census | Before | After |
|---|---:|---:|
| Total | 5,116 | 5,116 |
| Run / passed | 2,851 / 2,834 | 2,876 / 2,865 |
| Unsupported | 2,228 | 2,203 |
| Skipped / known failures | 37 / 17 | 37 / 11 |
| Unexplained failures / panics | 0 / 0 | 0 / 0 |

The regression census stays 11 total, 10 passed and one known failure.
The separate historical `script_invalid.json` census moves from 420 refused
and 12 accepted to 418 refused and 14 accepted (432 rows). Rows 408 and 409,
BIP66 example 8 with and without DERSIG in the fixture, now reach a failed
CHECKMULTISIG followed by NOT. Both reference defaults accept the same bytes
under Node 22 (`script_invalid_forkid_429.json`, the #417 recorder's
`--script-invalid-forkid` mode). `script_invalid_allowlist.rs` names the two
new accepted rows and replays them against the unchanged source fixture;
that regression is also RED on `ff08faa3`. The fixture's flags are not passed
by this default-mode census. No node-word expectation or shared vector is
rewritten.

The moved rows below use `b` = `node.script.bitcoin-sv`, `t` =
`node.script.teranode`, `tx` = `node.tx-valid.shared`; every number is the
four-digit suffix of the recorded ID.

| Previous attribution → new result | Rows | Reason |
| Legacy-signature → pass (19) | b:1370/1372/1374/1403/1464/1465/1466; t:1321/1323/1325/1354/1415/1416/1417; tx:0025/0051/0057/0082/0174 | The original-digest signature can reach verification |
| DER/public-key → pass (8) | b:1381/1432/1455; t:1332/1383/1406; tx:0067/0070 | CHECKMULTISIG's encoding wrapper previously hid the fork-ID refusal |
| Known eager-CHECKMULTISIG failure → pass (6) | b:0698/0699/1433; t:0666/0667/1384 | These six failures were the fork-ID gate; removed from the known-failure list |
| Legacy-signature → DER/public-key (5) | b:1426/1430; t:1377/1381; tx:0064 | Four unknown-format keys and one empty key are reached |
| Legacy-signature → CLEANSTACK (4) | b:1456; t:1407; tx:0027/0062 | Verification succeeds but leaves extra stack entries |
| Legacy-signature → LOW_S (2) | tx:0055/0097 | A later high-S signature is reached |
| DER/public-key → NULLDUMMY (4) | b:1443/1445; t:1394/1396 | The signature now verifies before the dummy is checked |
| Pass → NULLFAIL capability gap (2) | b:1405; t:1356 | The default allows a failing nonempty signature followed by NOT; the fixture's NULLFAIL word refuses it |

Thus legacy-signature 35 becomes five undefined-hash-type cases, renamed for
the actual remaining restriction; DER/public-key 54 → 47, CLEANSTACK 194 →
198, LOW_S 9 → 11, NULLDUMMY 4 → 8, and NULLFAIL 0 → 2. The six ILLEGAL_FORKID
rows retain their count under the accurate name “the default mode permits
SIGHASH_FORKID (fixture forbids the bit)”. `tx:0093` still belongs to the
P2SH class (72), although its first refusal moves from fork ID to CLEANSTACK.
Every other class is unchanged. These are capability attributions, not
relaxations of the node word.

### Notes: cross-SDK parity (#429)

`ts-stack@edf6e03` `Spend.ts:595-604` returns from the fork-ID helper unless
explicit flags carry STRICTENC; its callers are the encoding check at
`:617`, CHECKSIG at `:1669` and CHECKMULTISIG at `:1809`. Default verification
passes `sighashForkIdEnabled: true` (`:720-740`), but
`TransactionSignature.ts:429-440` selects the original algorithm when the
signature itself lacks FORKID. `ts-sdk@9e3ede6b` has the same default result
(`Spend.ts:458-468`, `:571-593`; `TransactionSignature.ts:319-329`); its fork-ID check runs for *any* explicit
word. Both default recordings accept the original digest and refuse BIP143
for the same `0x01` signature form at versions 1 and 2.

Under a word the node remains the authority: bitcoin-sv v1.2.2 at `879fc8b`
adds STRICTENC whenever SIGHASH_FORKID is enabled
(`interpreter.cpp:2315-2318`), then `CheckSignatureEncoding` refuses the
missing bit with `SCRIPT_ERR_MUST_USE_FORKID` (`:291-306`). Its sighash
selector (`:2112-2123`) would choose the original digest without the bit,
but the encoding refusal prevents that call under this word. Rust retains
`The signature must use SIGHASH_FORKID.` there. The references expose their
DER wrapper instead when their gate runs; edf6e03 even skips it if the word
omits explicit STRICTENC, unlike 9e3ede6b and the node. Neither discrepancy
changes Rust's explicit-word behavior.

The three DER-off empty-word rows recorded for #417 remain separate from
the default mode (DER is always on there):

| Empty-word row at version 1 | ts-stack edf6e03 | ts-sdk 9e3ede6b | Node at 879fc8b | Rust before and after |
|---|---|---|---|---|
| `der-off-chronicle`, `0x61` | Valid, original digest | Valid, original digest | Valid, original digest | Refuses the unsupported empty word |
| `der-off-forkid-present`, `0x41`, signed over original | Valid, original digest | Refused, BIP143 digest | Valid, original digest | Refuses the unsupported empty word |
| `der-off-forkid-absent`, `0x01` | Valid, original digest | Valid, original digest | Valid, original digest | Refuses the unsupported empty word |

These are replays of the same bytes, not signatures regenerated for each
SDK. Unlike edf6e03, 9e3ede6b's digest dispatch ignores the word's disabled
fork ID (`TransactionSignature.ts:319-329`), so the original-signed `0x41`
control reaches its truthy-top refusal. This existing difference does not
affect a `0x01` signature, which selects the original digest in both.

The census's empty-word b:1435/1437/1441, t:1386/1392 also keep their
default DER-wrapper refusal for undefined hash types; t:1388 keeps its
version-1 Chronicle refusal. Both references accept all six with the actual
empty word. Rust still refuses that word before execution. #429 adds no
DER-off API and does not change those existing findings.

The default accepts a pre-fork form no BSV wallet produces because the reference's default does, and the node refuses it, so a door on a live chain passes the word. `Transaction::verify` (`src/transaction/transaction.rs:1821`) and the streaming reader take no word, so they accept a `0x01` signature over the original digest now, as the reference's `Transaction.verify` and `Beef.verifyValid` do; a door that wants the node's verdict runs `Spend::set_flags` per input.

### Changed: the default mode runs all ten Chronicle opcodes at every version, gates the Chronicle hash type by version, and uses the reference's non-minimal-number words (#397)

The keeper's words of 2026-10-28 05:1xZ and 07:1xZ, under the owner's ruling
(c), read at `ts-stack@edf6e03`: without a word all ten Chronicle opcodes
run at every version, the number-length bound is absent (the V8 read bound
still applies), and the Chronicle hash type requires version > 1; under a
word the opcode and number-length gates use `UTXO_AFTER_CHRONICLE`, while
the hash-type gate independently uses `CHRONICLE`. These are three separate
rules, not one era switch. `#scriptNumMaxSize` returns `undefined` without
flags (`Spend.ts:393-401`); the default's number bound is not version-based.

The first commit (`8928fd74`) split `chronicle_opcodes` from the coin's era
and ran `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM` and `OP_RSHIFTNUM`
at every version. This fold puts the other five on that same opcode gate:
`#skipUnavailablePreChronicleOpcode` returns before **all** its refusals
without flags (`:827-858`), and `#enforceChronicleOnlyOpcode` is word-only
(`:792-803`). Before this fold the default refused these five at version 1;
now it executes the reference's semantics:

- `OP_VER` pushes exactly four little-endian version bytes (`:982-991`),
  including two's-complement negative versions. A missing JS version
  bitwise-coerces to four zero bytes; the Rust API requires a version, with
  explicit zero producing those same bytes.
- `OP_VERIF` and `OP_VERNOTIF` pop an element and compare its bytes only if
  its length is exactly four (`:1141-1159`); a numeric one does not match
  four-byte version 1. A mismatch selects the false branch (`VERNOTIF`
  inverts it), not an opcode error. An empty stack uses the reference's
  `OP_VERIF and OP_VERNOTIF require at least one item on the stack when they
  are used!`; a skipped conditional still adds its nesting level.
- `OP_2MUL` multiplies a script number by two and `OP_2DIV` divides toward
  zero (`:1494-1536`). Arbitrary minimal bytes are numbers; non-minimal
  encodings at version 1 use `non-minimally encoded script number`.

The default formerly admitted `SIGHASH_CHRONICLE` at every version. It now
requires version > 1 (`:338-341`, `:586-591`) and at version 1 refuses in
the reference's visible words, `The signature format is invalid.`
(`Script evaluation error: The signature format is invalid.` as the
first line of the error's `Display`, the reference's own prefix,
`ScriptEvaluationError.ts:38`). The gate at `:586-591` throws `The
signature hash type is invalid before Chronicle.` inside the `try` of
`#checkSignatureEncoding` (`:614-622`), and its `catch` (`:622-625`)
rethrows the DER wrapper's words, the default mode always enforcing DER
(`:376-386`; `ts-sdk@9e3ede6` the same, the gate at `Spend.ts:450-456`,
the catch at `:473-476`); the inner words, the keeper's first reading,
reach no caller there and none here. `hash_type.rs` holds the check; the
original-digest dispatch of #22 is unchanged. `set_utxo_after_chronicle`
overrides the opcodes and a word's number length, not the transaction
version or the separate `CHRONICLE` bit. Under a word every gate and refusal
stays as before; `script_sighash_dispatch_witness.rs` and
`script_flags_witnesses.rs` are unchanged and green.

The first commit also changed the default's non-minimal-number refusal
from `Invalid script number: script execution error: Non-minimally encoded
script number` to `non-minimally encoded script number` (`BigNumber.ts:1684`,
`Spend.ts:547`); under a word the reader's existing words are kept.
`script_chronicle_gate_397.rs` pins the first five opcodes, the setter, the
word's number length and the non-minimal words; its former version-1
`OP_2MUL` refusal is replaced by this fold's execution tests.

`tests/support/script_chronicle_default_397.mjs` records 73 opcode outcomes
and four signed CHECKSIG outcomes from the unmodified reference built from
`edf6e03`, under Node 22.18.0. The generated JSON is never hand-edited.
`script_chronicle_default_397.rs` pins their bytes, comparison outcomes,
arithmetic, nesting, hash digests and the word gates. On a scratch copy of
`8928fd74` with a separate target directory: **6 failed, 2 passed** (all
five default opcode tests and the version-1 hash gate RED; version-2
hash/digest and explicit-word tests GREEN). The first commit's tests were
RED 2 of 7 on `7257d73d` (opcode gate, non-minimal words).

The conformance census retains its totals: evaluation 5,116 = 2,851 run
(2,834 passed, 17 known failures) + 2,228 unsupported + 37 skipped; zero
failures or panics. One class moves: `node.script.teranode.1388` (no flags,
version 1, scope `0x21`) was already refused for missing FORKID, and is now
refused earlier by the Chronicle gate. The exact-entry allowlist in
`tests/support/conformance_script_allowlist.rs` names that reason: the
legacy-signature class **36 to 35**, the new Chronicle-version class **1**.
Script regressions remain 11 (10 passed, 1 known); BEEF/transaction census
pins are unchanged. Shared `spend_valid` known divergences remain **22**
after this fold (20 to 22 in the first commit): vectors 80 and 311 assert
NOPs for `0xb3`-`0xb7`, whereas the reference's default executes `OP_SUBSTR`
and refuses their missing operands. Their reference source carries
`P2SH,STRICTENC`, a word with the UTXO bit off; the shared file lacks that
column. No shared vector is edited.

The historical `script_invalid` tally improves from 419/432 to 420/432:
row 18 now runs `OP_VER` and is accepted, while rows 19 and 21 now keep
VERIF/VERNOTIF's skipped nesting and reject the unbalanced conditional.
The remaining 12 accepted rows are enumerated with reasons in
`tests/support/script_invalid_allowlist.rs`, replacing the 5% tolerance.
All three changed verdicts are recorded from the reference too.

Migration: callers relying on default NOPs or refusals for these ten
opcodes select the appropriate `ScriptFlags` word or explicitly name the
coin's era; version-1 Chronicle signatures must use a word enabling
`CHRONICLE`, or be signed with a legal hash type.

The version gate reaches BEEF verification and `Transaction::verify` (the
fourth fold, CI's Test Suite on PR #413): both run the default mode, so a
version-1 transaction with a CHRONICLE-bit signature is now refused there,
as the reference's `Transaction.verify` refuses it (`Spend` built with
`transactionVersion: tx.version` and no flags, `Transaction.ts:1441-1455`;
`Beef.verifyValid` runs no script and still reads such a BEEF as valid).
The stream answers `SpendRefused` at the input with `Script("The
signature format is invalid.")`, `Transaction::verify` `Script validation
failed for input N: The signature format is invalid.`. A downstream that
executes scripts through `Transaction::verify` or the streaming reader
(neither takes a word; the keeper's grep of the overlay engine at its main
found no such call) and relied on the old acceptance sends version-2
transactions or runs `Spend` under a word carrying `CHRONICLE`. `tests/beef_order_held.rs`'s
signed family (bsv-rs#22's dispatch to the original digest, under
ALL|CHRONICLE|FORKID and NONE|CHRONICLE|FORKID) moves its spenders to
version 2, where the dispatch is still what the signatures are made over
and every reader verifies it; the new
`a_chronicle_bit_signature_in_a_version_1_family_is_refused_at_its_input_in_the_reference_words`
keeps the family at version 1 and pins the refusal at `C`'s input 2 on the
stream in both orders and on `Transaction::verify` (RED on `bfdd4e7f`,
where the family was valid). The reference's answers on the same bytes,
under Node 22.18.0 from `edf6e03` built with bun: `verifyValid` true at
both versions, `Transaction.verify('scripts only')` of `C` and of `G`
`Script evaluation error: The signature format is invalid.` at version 1
and `true` at version 2. No other test in the whole suite moved.

### Notes: cross-SDK parity (#397)

The keeper's cross-SDK filing is ts-stack #1437, extended by the keeper for
all five opcodes and the hash-type gate. This crate follows the reference's
default opcode execution. Go gates the ten opcodes and the hash type on the
coin's era, but with no epoch option it takes the coin as created after
Chronicle (`go-sdk@2ca481c` `script/interpreter/thread.go:370-374`, the
`CHRONICLE` flag added at `:504-506`), so its default runs all ten and
admits `SIGHASH_CHRONICLE` at version 1 (`:807-812`), where this crate and
the reference refuse it.

The version-1 refusal's words are the reference's visible ones, byte for
byte with the Node 22 recording (`Script evaluation error: The signature
format is invalid.`): the second fold took the gate's inner words at
`Spend.ts:591`, which the wrapper at `:622-625` never lets out; the third
fold answers the wrapper's words, by the captain's reading of rule 1, and
no words difference remains.

### Fixed: ProtoWallet validates signature and HMAC arguments before cryptography (#415)

`create_signature`, `verify_signature`, `create_hmac` and `verify_hmac` now
run the reference's argument checks, in order, before hashing, deriving keys
or parsing a signature. They previously ran only the key deriver's checks:
malformed DER exposed parser errors, both data and a direct hash silently
selected the hash, privilege fields were ignored, and oversized data was
hashed. Refusals now use `Error::WalletRefusal` with class `InvalidParameter`,
the sibling validators' representation of `WERR_INVALID_PARAMETER` (code 6).
No public type changes; valid cryptographic results and genuine signature
or HMAC misses retain their behavior.

The common checks and canonical DER predicate live in
`src/wallet/validation/crypto.rs`, shared with the wire processor. Its old
checks covered the same typed fields except data/hash exclusivity, already
enforced by its decoder's data-type flag. The direct ProtoWallet API needed
that check as well. The full inventory of all nine reference-guarded methods,
before and after this lane, is in `src/wallet/CLAUDE.md`; getPublicKey,
encrypt/decrypt and the two linkage methods are follow-up work for the captain.

`tests/wallet_proto_args_415.rs` has one test for each of the twelve reachable
refusal texts, an ordering test, and valid-boundary/crypto-miss replays. The
Node v22.18.0 recorder `tests/support/wallet_proto_args_415.mjs` calls the
actual ProtoWallet built from `ts-stack@edf6e03`: 202 cases, 117 replayable
here and 85 documenting JS states excluded by Rust's types. The twelve
refusal tests and ordering test fail on the base (the old words or
success; `326b0836` when recorded, `1b64374f` after the rebase); the
success/miss test passes. The #407 Peer pins, landed at `1b64374f`, and their
two-reference recorder were re-run: the malformed-signature test is red on
the base and green here, with no listener called on either start path.
No current-reference DER-word divergence remains; #415 removes the old #407
divergence row after conforming the wallet's argument refusal.

Downstream migration, old -> new (new `Display` is the message alone):

```text
invalid signature: DER too short
invalid signature: Expected sequence tag 0x30
invalid signature: Expected integer tag 0x02 for R
invalid signature: Expected integer tag 0x02 for S
invalid signature: DER length mismatch / R length overflow / S length missing / S length overflow
  -> The signature parameter must be a canonical DER-encoded ECDSA signature
signature >72 bytes, previously parser error or crypto miss
  -> The signature parameter must be at most 72 bytes
wallet error: data or hashToDirectlySign must be provided; both inputs previously accepted
  -> The data, hashToDirectlySign parameter must be exactly one value
wallet error: data or hashToDirectlyVerify must be provided; both inputs previously accepted
  -> The data, hashToDirectlyVerify parameter must be exactly one value
### Fixed: ProtoWallet's remaining five argument validators share the wire's checks (#420)

`get_public_key`, `encrypt`, `decrypt`, `reveal_counterparty_key_linkage`
and `reveal_specific_key_linkage` now run the reference's argument checks
before returning the identity key, deriving a secret or doing cryptography.
Previously the identity branch bypassed checks, encryption and decryption
relied on the key deriver, and the linkage trait adapters discarded privilege
fields. The five validators moved from `wire/validation.rs` into the shared
`validation/crypto.rs`, beside #415's four validators. The wire wrappers
convert errors and construct typed arguments; their existing wire refusal
texts are unchanged. All nine methods' inventory is closed in
`src/wallet/CLAUDE.md`, with the type-enforced cases stated.

The reference's order (`ts-stack@edf6e03`, `validationHelpers.ts:1717-1762`):

- `validateGetPublicKeyArgs`: record, identityKey true/absent, forSelf
  boolean; on the identity branch each supplied protocol, key ID and
  counterparty, then privilege; otherwise the common encryption checks.
- `validateWalletEncryptArgs` / `validateWalletDecryptArgs`: record, common
  encryption checks, then plaintext / ciphertext byte array, at most
  268435456 bytes.
- `validateRevealCounterpartyKeyLinkageArgs`: record, counterparty public
  key, verifier public key, privilege without seekPermission.
- `validateRevealSpecificKeyLinkageArgs`: record, required counterparty,
  verifier public key, protocol, key ID, privilege without seekPermission.

Common encryption checks are protocol name 5..400 raw UTF-8 bytes, key ID
1..800 bytes, optional counterparty, then privilege. A counterparty given as hex that is not a key is refused when the `Counterparty` is built (`src/wallet/types.rs:321`), before any call exists, so a call with both a bad protocol and a bad hex counterparty is refused for the counterparty here where the reference names the protocol. A present privileged
reason needs 5..50 UTF-8 bytes, even without privilege; privileged=true needs
a reason. Key checks trim as JavaScript does, require even hex, then exactly
66 characters, then a compressed secp256k1 point. `Counterparty::from_hex`
checks that encoding before parsing; a valid uncompressed key used to lose
its 130-character encoding and be accepted. It now fails in the reference's
words. The shared point check also judges the wire's raw linkage keys.

The inherent linkage arguments contain no privilege fields; their typed
checks run there, and the trait adapters validate their additional privilege
fields first. Specific linkage derives its internal encryption key directly,
as the reference does, so a valid 400-byte public protocol can still produce
a 430-byte revelation protocol. The public encryption validator is not
reapplied to that internal protocol. No public type changes. The trait
implementation and unit tests moved into `proto_wallet/` to keep the core
below 800 lines; the moved proof test was split without changing assertions.

`tests/wallet_proto_args_420.rs` pins sixteen reachable refusal texts,
ordering, identity-branch checks, both linkage entry points, and valid
boundaries including the 430-byte internal protocol. Its 257 cases come
from the actual reference ProtoWallet under Node v22.18.0, through
`tests/support/wallet_proto_args_415.mjs --remaining` and its #420 extension:
148 replayable and 109 explicitly excluded by the typed API, both counts
pinned. Entropy and time are fixed for reproducible recording; a second
recording matches byte for byte. The original #415 corpus remains 117/85.
The existing `fuzz_wire_protocol` target also exercises encoded-counterparty
intake, seeded from this recording in the lane's external corpus.
All sixteen refusal tests, the ordering test and the inherent-linkage test
are RED on `6daf5afb` in a scratch copy with a separate target directory
(18 failed, one valid-boundary test passed), then all 19 pass after the fix.

Old Display text or behavior -> new Display text (each new refusal is a
`WalletRefusal` of class `InvalidParameter`, code 6; the wire already used
these words):

protocol validation error: protocol name must be at least 5 characters
  -> The protocolID[1] parameter must be at least 5 length.
protocol validation error: protocol name must be 400 characters or less
  -> The protocolID[1] parameter must be no more than 400 length.
wallet error: protocolID is required when identityKey is false
  -> The protocolID parameter must be a [securityLevel, protocolName] tuple
# Absent key:
wallet error: keyID is required when identityKey is false
  -> The keyID parameter must be a string
# Empty key:
wallet error: keyID is required when identityKey is false
protocol validation error: key ID must be at least 1 character
  -> The keyID parameter must be at least 1 length.
protocol validation error: key ID must be 800 characters or less
  -> The keyID parameter must be no more than 800 length.
privileged reason missing/short/long, previously ignored
  -> The privilegedReason parameter must be a value when 'privileged' is true
  -> The privilegedReason parameter must be at least 5 length.
  -> The privilegedReason parameter must be no more than 50 length.
data >268435456 bytes, previously processed
  -> The data parameter must be at most 268435456 bytes
```

Rows for the toolbox's operator-visible table:

| Condition | New operator-visible words | Class |
|---|---|---|
| Malformed general-answer signature / direct verifySignature DER | `The signature parameter must be a canonical DER-encoded ECDSA signature` | InvalidParameter, code 6 |
| Signature over 72 bytes | `The signature parameter must be at most 72 bytes` | InvalidParameter, code 6 |
| Missing or conflicting signature data/hash | `The data, hashToDirectlySign parameter must be exactly one value` / `The data, hashToDirectlyVerify parameter must be exactly one value` | InvalidParameter, code 6 |
| Invalid protocol/key/reason/data bounds | The field-specific validator words in the migration block above | InvalidParameter, code 6 |
| Canonical signature made by another key | `wallet error: Signature is not valid` | Unchanged WalletError |

### Notes: cross-SDK parity (#415)

The authority is `ts-stack@edf6e03` `ProtoWallet.ts:283-396`,
`validationHelpers.ts:146-230,1752-1804`, and
`Secp256k1Validation.ts:33-53`. Checks are: a plain argument record; protocol
tuple and its level/name; key ID; optional counterparty; privilege flag,
optional reason, required reason when privileged, seekPermission; then data
or exactly one data/hash for signatures; then signature length/canonical DER
and forSelf, or HMAC length. Byte and string lengths are inclusive; strings
are measured in UTF-8 before key-deriver normalization. Canonical DER allows
high-S but requires both scalars in 1..n-1. Structs, enums, parsed keys, byte
vectors, fixed 32-byte arrays and booleans enforce the corresponding JS type
checks here. Their exact reference errors are recorded in the vector.

One input-encoding bound is a stated divergence for #420 to conform: an
uncompressed counterparty key (130 hex characters) is refused by the reference
with `The counterparty parameter must be no more than 66 length.`, but parses
to a `PublicKey` and is accepted here. The type holds a curve point, not its
input encoding; it does not enforce the reference's compressed-key length.

The older `ts-sdk@9e3ede6b` ProtoWallet has no argument validators
(`ProtoWallet.ts:267-302` calls its DER parser directly); the #407
witness, unchanged, still returns `Signature DER must start with 0x30` there.
Go at `2ca481c` likewise has no equivalent validator: `wallet/proto_wallet.go`
rejects verification when both data/hash byte slices have zero length, checks
a nil parsed signature, prefers a present hash, then derives and verifies. Its HMAC is `[32]byte`, and its
signature is already `*ec.Signature`. The key deriver validates key ID and
normalized protocol later, in its own words (`key_deriver.go:214-253`);
privilege and frame-byte bounds are not checked. Its linkage methods only
check nil keys. These are stated reference-version differences, not reasons
to retain the missing current-reference checks.
### Fixed: `WalletClient` is a `WalletInterface` and its core needs only `wallet` (#404)

#335 added `with_substrate`, but the entire client still required `http`.
A Worker with `wallet,auth,transaction,overlay,socketio,wasm` could not wrap
its in-process wallet, and a client could not be passed to `Peer`, another
client or any other consumer of `WalletInterface`.

The core (`WalletClient`, `SubstrateType`, `with_substrate` and all 28 calls,
including both linkage calls) is now under `wallet`. Only the HTTP JSON and
wire variants, imports, construction and discovery need `http`.
`SubstrateType` remains `Copy + Eq`: `JsonApi`, `Cicada` and `SecureJsonApi`
are absent at compile time without `http`, rather than accepting an unusable
transport and failing later. `Auto` remains available; without `http` its
first call reports no available substrate. `with_substrate` always works
without discovery. With `http`, the variants, default URLs and probe order
(secure JSON, JSON, wire) are unchanged. Both wire linkage calls go through
the transceiver since #406.

`src/wallet/client/interface.rs` implements all 28 trait methods using the
same `forward!` macro as the inherent API. Both surfaces keep the client's
configured originator, including `None` and `Some("")` (#329), even when a
trait caller supplies another; a nested client applies its own configured
originator. The trait returns its status records and names the header call
`get_header_for_height`; the inherent names and result types stay available.
The inherent methods now borrow `&self`, matching the reference's operations
and the trait's receivers. A `OnceLock` holds the resolved substrate through
interior mutability; a runtime-independent futures mutex serializes HTTP
discovery. No lock is held across subsequent wallet calls and no dependency
is added. `src/wallet/client/http.rs` holds the HTTP construction and probes;
the client file shrinks, and no new function exceeds 60 lines.

Pinned by `tests/wallet_client_instance_335.rs` under `wallet` alone and
`tests/wallet_client_interface_404.rs`: all 28 calls through an instance,
all 28 through a client wrapping another client (absent, empty and named
originators), the trait's status answers, validation before dispatch and
unchanged refusals. On base `94b74c03`, the wallet-only instance test is RED
with 11 missing-client/type errors; with `wallet,http` the trait test is RED
with four missing-`WalletInterface` implementation errors.
`tests/wallet_client_shared_404.rs` calls through both `&WalletClient` and
`Arc<WalletClient>` and pins the replies and configured originator; both
calls are compile errors on the base's mutable receivers. No test probes
`Auto` or the default URLs. The standard wasm32 feature slice now exports
`WalletClient` and can wrap a wallet without enabling native HTTP.

The requested minor-release check against `94b74c03` passes: cargo-semver-checks
0.51.0 reports 202 checks passed, 58 skipped, and no semver update required.
Its default feature heuristic includes `http`, so the three cfg-gated names
are present on both sides; without `http` the base exported no client at all.
The explicit `wallet`-only comparison also passes all 202 checks (58 skipped).
The checker does not lint the receiver change.

Rebased over #406 at `d510bc36`: the wire arm holds its transceiver
directly, and the fixture-backed client test lives under the HTTP module,
using the shared connection fields. The obsolete unsent-linkage test is
removed, so no test calls a default wallet port. The unreconciled rebase
fails to compile without `http`; this fold is kept as one compiling commit.

API break (beta line): `WalletClient`'s methods take `&self`
(the reference's and the trait's receivers).

- A method-path reference such as `.map(WalletClient::get_version)` becomes `.map(|client| client.get_version())`.
- A `let mut client` binding may drop `mut`.

Wasm Workers gain the client under `wallet`, without enabling `http`.

### Notes: cross-SDK parity (#404)

The reference defines `class WalletClient implements WalletInterface`
(`ts-stack@edf6e03`, `packages/sdk/src/wallet/WalletClient.ts:82-110`;
`ts-sdk@9e3ede6b`, `src/wallet/WalletClient.ts:67`). Its constructor accepts
`'auto' | 'Cicada' | 'XDM' | 'window.CWI' | 'json-api' | 'react-native' |
'secure-json-api' | WalletInterface`: the HTTP, wire, browser and React
Native substrates are imports it resolves, not requirements of its core.
Rust keeps separate `new` and `with_substrate` constructors so the named
selector stays `Copy + Eq`, and has no browser or React Native substrate.
After construction, the reference only assigns `this.substrate` in
`connectToSubstrate` (`:121-198`); its wallet methods read the substrate and
originator. The shared receivers here preserve that shape, with the one-time
resolution held in `OnceLock` rather than a public `&mut self` requirement.
The #335 differences remain: only internalizeAction's arguments are
validated here, and the configured originator is preserved rather than
normalized; the reference validates every request and result. Go at
`2ca481c` has no multi-substrate client; callers hold a `wallet.Interface`
or construct a concrete substrate.
accepted short / long / missing privileged reason
accepted oversized plaintext
  -> The plaintext parameter must be at most 268435456 bytes
decryption failed
  -> The ciphertext parameter must be at most 268435456 bytes
invalid hex string: Odd number of digits
  -> The counterparty parameter must be even length, not 1.
invalid hex string: Invalid character 'z' at position 0
  -> The counterparty parameter must be hexadecimal string.
invalid public key: Invalid public key encoding: elliptic curve point encoding error
  -> The counterparty parameter must be at least 66 length.
accepted uncompressed counterparty (or parser error for malformed long hex)
  -> The counterparty parameter must be no more than 66 length.
invalid public key: Point not on curve
  -> The counterparty parameter must be a valid compressed secp256k1 public key

### Notes: cross-SDK parity (#420)

The five validators and every reachable refusal follow `ts-stack@edf6e03`
(`ProtoWallet.ts:159-280`, `validationHelpers.ts:146-230,348-356,522-535,1717-1762`).
`ts-sdk@9e3ede6b` has none of those five validator calls; its ProtoWallet
relies on derivation/parsing and ignores privilege. Go at `2ca481c`
(`wallet/proto_wallet.go:63-177`, `proto_wallet_reveal.go:14-161`) likewise
has no equivalent argument-validation layer; its linkage methods check
required public keys and otherwise derive/encrypt. This follows the newer
reference under the owner's ruling (c), as #415 did.

Typed structs already enforce record shape, booleans, tuples, security
levels, byte elements and parsed public keys. `identity_key: false` denotes
an absent flag here and cannot separately represent the reference's
explicitly false flag. The mandatory counterparty in counterparty linkage
and both verifiers are `PublicKey` points; they have no original encoding
to reject after construction. A generic `PublicKey` still accepts an
uncompressed encoding and serializes the resulting point compressed; raw
encoded counterparty intake now applies the bound before that information
is lost. Each excluded recording states its reason. Later cipher misses
(empty or wrong-key ciphertext) reach cryptography on both sides; their
error texts are outside this argument-validation change.
### Fixed: the default's version-1 signature refusals use the reference's visible words and check order (#417)

At transaction version 1, an undefined signature hash type (the recorded
`0x44`) and a high-S signature now answer `The signature format is invalid.`
in the default mode. The hash type is checked before low-S, including when
both fail. Previously this crate exposed the inner reason and checked low-S
first; the reference catches that reason and replaces it with its DER
wrapper's text. The version-1 Chronicle refusal from #397 keeps its words.
The rules live in the new `src/script/spend/signature_encoding.rs`; no public
API changes. Under an explicit word the node's low-S-before-hash-type order
and distinct messages are unchanged.

Downstream migration (the first `Display` line, byte for byte):

| Version-1 default refusal | Old text | New text |
| Undefined hash type `0x44` | `Script evaluation error: The signature's hash type (0x44) has no defined base type.` | `Script evaluation error: The signature format is invalid.` |
| High-S | `Script evaluation error: The signature must have a low S value.` | `Script evaluation error: The signature format is invalid.` |
| Undefined `0x44` and high-S together | `Script evaluation error: The signature must have a low S value.` | `Script evaluation error: The signature format is invalid.` |

`tests/script_signature_words_417.rs` replays nine vectors from
`tests/vectors/script_signature_words_417.json`, recorded under Node v22.18.0
from the unmodified clone's `ts-stack@edf6e03` build by
`tests/support/script_signature_words_417.mjs`. The three refusal tests are
RED on `e5aa0a36` in the old words above and green here; the valid version-1
control and version-2 high-S control keep their verdicts. The recorder
observes the public `hasLowS` predicate: never called for an undefined hash
type, even with high-S too; called once for high-S alone. A unit test pins
the inner order before the wrapper erases that distinction. The explicit
block/standard word checks and the existing
`script_undefined_hashtype_witness.rs` and `script_low_s_order_witness.rs`
pass on both revisions; those two files have no diff. The existing low-S
boundary unit test's two version-1 default messages change with this fix.

The census pins hold: evaluation 5,116 total, 2,851 run, 2,834 passed,
2,228 unsupported, 37 skipped, 17 known failures, no unexplained failures
or panics; regressions 11 total, 10 passed and one known failure.
`tests/support/conformance_signature_words_417.rs` keeps fourteen named
vectors in their existing classes after the wrapper hides their reasons:
nine low-S rows (`bitcoin-sv.1424`, `teranode.1375`, and `tx-valid.shared`
0023/0053/0073/0074/0076/0078/0080), five undefined legacy-type rows
(`bitcoin-sv` 1435/1437/1441 and `teranode` 1386/1392). The low-S class
stays 9, the legacy-signature class 35, and the DER/public-key class 54;
without this attribution the generic text would misclassify all fourteen
as DER. No vector's verdict or allowlist total changes.

This correction covers the default strict set (version <= 1): #23's
version-2 undefined hash-type message remains the old text, although the
TypeScript catch also wraps it there. The order-overflow exception from #14 remains in both
modes: `r` or `s` at or above the curve order passes low-S and then fails
verification, following the node's lax parser; the TypeScript predicate
instead judges S directly. Neither existing witness is repinned.

### Notes: cross-SDK parity (#417)

The authority is `ts-stack@edf6e03` `Spend.ts:609-629`: empty signatures
return true; the DER-shape check runs before the try; parsing, hash-type
definedness and Chronicle legality (`:577-592`), fork-ID (`:594-603`), then
low-S (`:618-621`) run inside it. The catch (`:622-626`) exposes only
`The signature format is invalid.` when `enforceDer` is true. Without a
word it is always true (`#shouldEnforceDerSignatures`, `:376-386`), including
the relaxed version-2 mode; low-S is enabled by default at version 1
(`:350-353`). The default fork-ID helper is a no-op. Before #429, without a word this
crate refused a signature lacking the fork-ID bit outside the wrapper
with `The signature must use SIGHASH_FORKID.`, where both pins accept it
(`0x01` at version 1): a divergence older than this change, stated now in
`CLAUDE.md`'s list at the time; the #429 entry corrects that default-mode divergence.

`ts-sdk@9e3ede6b` `Spend.ts:435-489` has the same visible words and order
for all three version-1 refusals (replayed from the same bytes under Node
22). Its fork-ID checks run for any explicit word, whereas edf6e03 requires
STRICTENC. Go at `2ca481c` has no wrapping catch: CHECKSIG checks the hash
type before DER/low-S (`script/interpreter/operations.go:2110-2113`),
returning `invalid hash type 0x44` or
`signature is not canonical due to unnecessarily high S value`
(`thread.go:768-819,842-1018`). Bitcoin-SV v1.2.2 (`879fc8b`)
`interpreter.cpp:265-310` checks DER, low-S, then hash-type definedness,
illegal fork ID, illegal Chronicle, and missing fork ID; under a word this
crate retains that existing low-S-before-hash-type behavior and its node
diagnostics. Both failures together therefore retain the low-S sentence
under a word and use the generic wrapper in the version-1 default.

The DER-off cell is unreachable without a word in either TypeScript
revision and has no separate switch in this crate. In TypeScript it
requires an explicit word lacking DERSIG, STRICTENC, LOW_S and
SIGHASH_FORKID. With the empty word at version 1, edf6e03 skips the hash-type
and fork-ID checks; 9e3ede6b can throw for the fork-ID bit and swallow it
because `enforceDer` is false. The recorded answers are:

| Vector, version 1, empty word | edf6e03 | This crate (base and fixed) |
| `der-off-chronicle`, scope `0x61` | Valid | Refuses the word before encoding |
| `der-off-forkid-present`, scope `0x41`, signed with fork ID disabled | Valid | Refuses the word before encoding |
| `der-off-forkid-absent`, scope `0x01` | Valid | Refuses the word before encoding |

All three Rust refusals are `Script evaluation error: Invalid verification
flags: SIGHASH_FORKID is not set: this interpreter computes the BIP-143
sighash only.` (`ScriptFlags::check`, before signature checking). bitcoin-sv v1.2.2
accepts all three as well: with none of DERSIG, LOW_S or STRICTENC set,
`CheckSignatureEncoding` (`interpreter.cpp:265-310` at 879fc8b) runs no
check and `SignatureHash` (`:2118`) takes the original digest, which the
three vectors are signed over; this crate's refusal names SIGHASH_FORKID,
and the empty word also lacks GENESIS and UTXO_AFTER_GENESIS (the documented
limit of `src/script/flags.rs:483-506`). The older
TypeScript accepts the Chronicle and absent-bit vectors too; it rejects
the same present-bit bytes with a false top because its formatter/verifier
does not honor `sighashForkIdEnabled: false` for that digest. Its own
present-bit signature is accepted; the recorder can replay the saved
inputs against either build. No DER-off behavior or flag support is changed
by this fix.

### Added: the wire transceiver makes revealCounterpartyKeyLinkage and revealSpecificKeyLinkage as the reference's does; the client's existing linkage arms route to it (#406)

The finding (#404's second item, split out by the keeper on 2026-10-28
under the owner's ruling (c)): the processor has read both linkage calls
(call codes 9 and 10) since #191 and written both answers since #194, but
`WalletWireTransceiver` had neither method; #335 added both calls to
`WalletClient`, but its wire arms refused them, so a client over the wire
substrate could not reveal a linkage; the
fixtures recorded the two calls through a test-side shim of the low-level
codec (`docs/FIXTURES.md` F2).

`WalletWireTransceiver::reveal_counterparty_key_linkage` and
`reveal_specific_key_linkage` (`src/wallet/wire/linkage.rs`) write the
reference's request and read its answer (`ts-stack@edf6e03`
`WalletWireTransceiver.ts:790-924`; the same bytes as ts-sdk@9e3ede6b
`:1139-1251`):

- revealCounterpartyKeyLinkage: the privileged flag (`i8`, -1 absent), the
  reason's length (`i8`, -1 absent) and its UTF-8 bytes
  (`#encodePrivilegedParams`, `:1448-1462`), the counterparty's 33 bytes,
  the verifier's 33 bytes (`:809-811`); the answer the prover, verifier and
  counterparty, 33 bytes each, the revelation time, the encrypted linkage
  and its proof, each behind a `readVarIntNumStrict(false)` length
  (`:817-836`).
- revealSpecificKeyLinkage: the key-related parameters (the security level
  byte, the protocol name and the key ID behind their lengths, the
  counterparty: `11` self, `12` anyone, else its 33 bytes, then the
  privileged pair; `#encodeKeyRelatedParams`, `:1351-1376`), the verifier's
  33 bytes (`:874-883`); the answer the three keys, the security level
  byte, the protocol name, the key ID, the encrypted linkage, its proof and
  the proof type byte (`:889-908`).

As the reference's transceiver does, the arguments are judged before a
byte is sent (`validateWalletArgs`: the privileged reason 5 to 50 bytes and
required when privileged, the protocol name 5 to 400 bytes, the key ID 1 to
800; `WalletRefusal` of class `InvalidParameter` in its words, nothing
sent) and the answer after it is read: each key a compressed point
(`#readCompressedPublicKey`, `:2004-2008`), the level 0 to 2 (`Invalid
revealSpecificKeyLinkage security level: N`, `:2010-2016`), no byte after
the last field (`Wallet Wire <call> response contains trailing data`,
`:1936-1938`), then `validateWalletResult` bound to the request (the
requested verifier and counterparty, the prover for `self`, the anyone key
for `anyone`, the protocol and key ID, the revelation time an ISO
timestamp; `WalletResultValidation.ts:2226-2281`), the processor's own
checks of #216 and #226 reused (`validation.rs`), the result refusals
`WalletError` in the reference's words. `WalletClient`'s existing
`reveal_counterparty_key_linkage` and `reveal_specific_key_linkage` arms
are routed to the transceiver through `forward!` (`src/wallet/client.rs`),
which also forwards them to the JSON substrate or the caller's instance
as before. The duplicate `client/linkage.rs` and the obsolete `wire_lacks`
refusal are removed in the fold over #335.

The fixtures moved nowhere: `tests/support/fixtures/` now calls the two
methods where its shim stood, and the 323 wire entries replay unchanged
(the shim wrote the reference's bytes since #191).

Pinned by `tests/wire_linkage_calls_406.rs` (7 tests) against
`tests/vectors/wallet_wire/linkage_calls_406.json` (6 cases, 8 refusals),
recorded by `tests/support/wire_linkage_calls_406.mjs` from the reference's
transceiver over a transport handing each frame to the reference's
processor, whose wallet answers fixed values bound to the request
(`ts-stack@edf6e03`, Node v22.18.0): the transceiver writes each request
frame byte for byte and reads each answer to the reference's result; the
processor reads each request to the args the reference's wallet saw and
writes each answer byte for byte; `WalletClient`'s wire type
(`WalletWireTransceiver<HttpWalletWire>`, on an in-process wiremock) carries
both calls; the eight changed answers refused as the reference refuses
them; a four-byte privileged reason refused unsent; a `ProtoWallet`
answering both across the wire; Go's two args and result vectors written
and read. On the base (`485848ba`) the file does not compile (`E0599`, no
method `reveal_counterparty_key_linkage` or `reveal_specific_key_linkage`
on `WalletWireTransceiver`, five sites); its processor test alone passes
there. This RED remains the pre-fix `485848ba` transceiver replay; the
fold over #335 changes neither that replay nor its vectors. A unit test,
`the_clients_wire_arms_send_both_linkage_calls_406`, injects an HTTP wire
on an in-process wiremock into `WalletClient`'s actual `ConnectedSubstrate::WireApi` path
and checks both calls' recorded request bodies, originator and results;
no default URL or port is used.

Semver: additive, two public methods on `WalletWireTransceiver`; the
existing `WalletClient` methods now make both calls over the wire.

### Notes: cross-SDK parity (#406)

The bytes are the reference's both ways; ts-stack@edf6e03 and
ts-sdk@9e3ede6b write and read the six recorded frames identically. Where
the two references differ this crate follows edf6e03, as its transceiver
does elsewhere: 9e3ede6b's transceiver validates neither the arguments nor
the answer (no point check, no level check, no trailing-data check, no
binding to the request) and returns all eight answers edf6e03 refuses. One
refusal is in other words: a malformed prover in the answer is refused
here as `Invalid revealCounterpartyKeyLinkage prover: expected a compressed
secp256k1 public key` (the wire's `require_compressed_key`). For a `05`
prefix the reference's `PublicKey.fromDER` throws `Unknown point format`.
For the x > p case (`x = p + 1`), `fromDER` accepts the point and the
reference's result validator throws `Invalid revealCounterpartyKeyLinkage
result prover: expected a valid compressed secp256k1 public key` (confirmed
under Node v22.18.0); this crate keeps its refusal above, so the words
still differ. go-sdk@2ca481c's transceiver writes the same
bytes for a reason of 1 to 252 bytes (`wallet/substrates/wallet_wire_transceiver.go:146-168`,
`wallet/serializer/reveal_counterparty_key_linkage.go:11-29`,
`reveal_specific_key_linkage.go:11-35`: the reason a varint-length string,
where the reference writes an `i8` length; an empty reason is written as
absent, `serializer.go:177-190`), reads the answer to its end
(`CheckComplete`) with each key through `ec.PublicKeyFromBytes`, reads the
security level unbounded (`serializer.go:165-174`), and checks nothing
against the request; its two vectors are this transceiver's bytes both
ways.
### Fixed: `HttpWalletJson` reads every success-path byte field as the reference's `HTTPWalletJSON` does, the historical object form included (#365)

The reference runs `normalizeBRC100WalletByteFields` over every answer's
body before `validateWalletResult` reads it (`ts-stack@edf6e03`
`packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:322-341`): each own
member named in `walletByteFieldNames`, at any depth
(`packages/sdk/src/wallet/BRC100ByteEncoding.ts:5-23`, `:164-190`), read
by `normalizeBRC100ByteArray` (`:81-86`): an array of byte numbers, or
the historical object form `JSON.stringify(new Uint8Array(..))` wrote
(keys `"0"` to `"n-1"`), each value `isByte` (`Number.isInteger` from 0
to 255, `:32-34`, so `1.0` and `-0` too). Since #339 this crate read
createAction's and signAction's top-level `tx` so; the other byte fields a
success answer carries were read as plain arrays of integers, so a body
the reference reads was refused, and one it refuses was refused in
`serde_json`'s words. The #339 fold's re-review found it (filed as #365).
The fields, per call, as `validateWalletResult` reads them
(`packages/sdk/src/wallet/WalletResultValidation.ts`):

| Call | Field | Reference's site | Byte reader before | After |
|---|---|---|---|---|
| createAction | `tx` | `validateActionResult`, `:1247-1248` | yes (#339) | yes |
| createAction | `signableTransaction.tx` | `:1266-1272` | no | yes |
| signAction | `tx` | `:1247-1248` | yes (#339) | yes |
| encrypt | `ciphertext` | `:2210-2212` | no | yes |
| decrypt | `plaintext` | `:2213-2215` | no | yes |
| createHmac | `hmac` | `:2216-2218` | no | yes |
| createSignature | `signature` | `:2219-2225` | no | yes |
| revealCounterpartyKeyLinkage | `encryptedLinkage`, `encryptedLinkageProof` | `validateKeyLinkage`, `:2163-2173` | no | yes |
| revealSpecificKeyLinkage | `encryptedLinkage`, `encryptedLinkageProof` | `:2163-2173` | no | yes |
| listOutputs | `BEEF` | `validateListOutputs`, `:2082` | no | yes |

The certificate results carry no byte field (a certificate's `signature`
is hex text, which the walk leaves; the keyrings are base64 text, outside
`walletByteFieldNames`), nor do the other calls' results.

One reader for all of them: `src/wallet/substrates/http_json/byte_fields.rs`
holds #339's `byte_array` (moved from `review_actions.rs`, which reads the
code-5 body's `tx` and `competingBeef` through it as before), the
reference's walk (`normalize`: every member of the seventeen names at any
depth, one it does not read walked into, as `visitBRC100WalletByteField`
does) and the fields above (`refusal`: the first in the reference's order
that is no array of bytes after the walk, present or, for the required
ones, absent, refused `Error::WalletError` in `bytes`' words, `Invalid
<call> result <field>: expected an array of bytes`, `:868-906`; the
signable transaction's `tx` required when `signableTransaction` is an
object, as `actionBeefTransaction(signable.tx, ..)` requires it,
`:1271-1272`, where this crate gave `serde_json`'s ``missing field `tx` ``).
`answer::success` reads every call's answer as #339's second fold read the
two action calls': the typed reading first, at the cost it costs, the
`Value` tree built only for an answer the typed reading refuses, then the
walk, the refusal, and the typed reading of the tree; an answer neither
takes is refused in `serde_json`'s words as before. A body that is no JSON
is refused in `serde_json`'s words on every call now (not the reference's:
its `JSON.parse` throws a `SyntaxError` in its runtime's words), where the
calls other than createAction and signAction gave reqwest's (`error
decoding response body`): one recorded fixture moves, in its own commit (F22,
`http_json/errors.json`'s `malformed_json`).

Pinned by `tests/wallet_http_json_success_bytes_365.rs` against
`tests/vectors/http_json_success_bytes_365.json` (110 bodies, the
reference's `HTTPWalletJSON` under Node v22.18.0, written by
`tests/support/http_json_success_bytes_365.mjs`, the body's text recorded
as served so `1.0` and `-0` cross as written, the BEEF and action requests
#339's): each of the twelve fields as an array, in the object form and
with every byte `1.0`, read to the reference's bytes; with its first byte
`256`, `-1` or `1.5` in the array and in the object form, refused in the
reference's words; ciphertext's object form with the integer text `-0`
read as the byte 0, as `isByte` reads it (the #339 re-review's unpinned
case, `the_integer_text_minus_zero_in_the_object_form_is_the_byte_zero`);
a `signableTransaction` object without its `tx` refused in `bytes`' words
(`a_signable_transaction_without_its_tx_is_refused_in_the_references_words`,
the cold review's required change). 2 of 3 tests and 93 of the first 109
bodies red on `5f8fc526` (the 21 forms the reference reads refused, the
72 refusals in `serde_json`'s words), the 16 that agree the twelve arrays
and #339's four action `tx` forms; the fold's body, the 110th, and 2 of
the 4 tests red on `e0fe1b33` (``missing field `tx` ``); green after. The walk
and the refusal are unit-tested in `byte_fields.rs`. #339's
`{"tx": "x"}` pin moves to `bytes`' words
(`a_success_answer_neither_reading_takes_is_refused_in_serdes_or_the_references_words`,
renamed from `..._in_serdes_words`). No public shape moves; no migration.

### Notes: cross-SDK parity (#365)

At the #365 landing the typed reading still answered first, so an answer
it took and the reference refused was read here: `validateWalletResult`'s
other checks and refusal words were not ported (createHmac's 32-byte
refusal used the post-read check's own words, createSignature's 72
bytes and canonical DER, `:2217-2225`; an action `tx` and a listOutputs
`BEEF` of `null`, which the typed `Option` reads as absent where the
reference refuses it, `:1247-1248`, `:2082`; the BEEF
checks of listOutputs and the signable transaction). #408 above supersedes
the HMAC/signature/null behavior; the BEEF checks remain pending. Where a byte field
and another member are both malformed, the byte field is named here, where
the reference names whichever it checks first (the linkages' keys before
their bytes, `:2167-2170`). go-sdk@2ca481c's JSON substrate decodes each
result with `json.Unmarshal` (`wallet/substrates/http_wallet_json.go:77-79`,
`:187-189`), its byte fields `BytesList` read as `[]uint8`
(`wallet/encoding.go:24-31`), which `encoding/json` also reads from a
base64 string (`"AQID"` is `[1 2 3]`, a text the reference refuses), and
normalizes nothing.

### Fixed: the HTTP auth transport's handshake, JSON, certificate-header and redirect refusals use the reference's words (#410)

The four changes cover three operator-visible refusals whose words differed
from `SimplifiedFetchTransport` at `ts-stack@edf6e03`, found by the toolbox's
#315 review, and one silently accepted header: a non-2xx
handshake used `Auth endpoint returned ...`, malformed handshake JSON used
`Failed to parse auth response: ...`, and a redirect used `redirect refused:
...`; a malformed `x-bsv-auth-requested-certificates` header was discarded.
Downstreams match these texts. The owner's ruling (c) requires the
reference's words, including its status description, URL, header message
and body preview.

The handshake now shares #354's status/preview formatter, passing the
reference's empty missing-header list: `response lacked required BSV auth
headers`, even if some or all headers are present. The HTTP status is read
before the body and still selects #87's fault class. Malformed JSON uses Node
22's unwrapped syntax diagnostic; an iterative scanner runs only after
serde refuses, with pending states proportional to input depth, no fixed
depth cutoff, and a 20-UTF-16-unit context,
and constructs no JSON value. A malformed `x-bsv-auth-requested-certificates`
header uses the reference's separate wrapper and syntax cause; previously
this crate silently dropped it. The header is parsed on every general
response, not only one labelled `certificateRequest`, as in the reference.
Redirect refusals on both paths use Node 22's outer fetch wrapper, and still
never replay a request with the default client.

Pinned by `tests/auth_transport_refusal_words_410.rs` (12 tests): six tests RED on a
scratch copy of `7257d73dcc258643f64b63e296d9b3bc0bcfa624`, with its own
target directory (404, malformed body, malformed header, 307, fault classes,
and the syntax replay); the seventh pins the existing typed refusal of
well-formed non-auth JSON. Two more tests, at depth 127 and 200, are RED on
both that base and `aaa6b79f` (the latter 2 failed, 10 passed; the base
8 failed, 4 passed). Three tests pin the unchanged mappings described below.
`auth_transport_refusal_words_410.json` is the
unmodified output of `tests/support/auth_transport_refusal_words_410.mjs`
under Node 22.18.0 / undici 6.21.2, 75 cases per reference: six statuses, 57
JSON syntax errors (empty/truncated JSON, numbers, keys, escapes, Unicode
positions, context cuts, BOM, and four array/object cases at each of depths
127 and 200), six malformed headers (empty and Latin-1 values included),
two redirects, the valid JSON shape difference, and the three mappings below.
Both SDKs were bundled from their
clone's pinned commit. The recorder uses fake fetch and, for redirects,
Node's native fetch with a network-disabled MockAgent; no listening socket.
The Rust replay uses wiremock's ephemeral ports. The #320 and #87 tests now
assert the new texts; #354's general-response fixtures are unchanged.

Migration for callers matching the error payload (the existing
`authentication error: ` / `transport fault ...: ` display prefixes remain).
The four old/new pairs, on the recorded bodies `not found` and `not auth`,
are together here; `{url}` is the configured origin:

```text
404 old: Auth endpoint returned 404 Not Found: not found
404 new: Received HTTP 404 Not Found from {url}/.well-known/auth without valid BSV authentication (response lacked required BSV auth headers) - body preview: not found
200 old: Failed to parse auth response: expected ident at line 1 column 2 - body: not auth
200 new: Unexpected token 'o', "not auth" is not valid JSON
307 old: Network error while sending authenticated request to {url}/.well-known/auth: redirect refused: 307 Temporary Redirect
307 new: Network error while sending authenticated request to {url}/.well-known/auth: fetch failed
header old: accepted, malformed certificate-request header silently dropped
header new: Failed to parse x-bsv-auth-requested-certificates returned by {url}/sendMessage: not auth. Unexpected token 'o', "not auth" is not valid JSON

Line for the toolbox's `src/wallet/CLAUDE.md` matching table (that checkout
is not changed by this commit):

| bsv-rs #410 | `Auth endpoint returned ...` → `Received HTTP ... without valid BSV authentication (response lacked required BSV auth headers)` plus optional body preview; `Failed to parse auth response: ...` for malformed JSON → Node 22's unwrapped syntax error; `redirect refused: 307 Temporary Redirect` → `fetch failed` within the same URL wrapper; malformed certificate header → `Failed to parse x-bsv-auth-requested-certificates returned by {url}: {value}. {syntax cause}` |

### Notes: cross-SDK parity (#410)

The full paths were read at both pins. At `ts-stack@edf6e03`, the handshake
fetch sets `redirect: 'error'` (`SimplifiedFetchTransport.ts:115-173`), a
non-2xx calls `#createUnauthenticatedResponseError` with no missing-header
list (`:143-151`, `:464-494`), and the body uses unwrapped `JSON.parse`
(`:158-162`). The general fetch also refuses redirects (`:206-218`); the
certificate header's wrapper is separate (`:234-258`, `:496-510`). Node
22.18.0 measured the outer redirect text as `Network error while sending
authenticated request to {url}: fetch failed`, with causes `TypeError:
fetch failed` then `Error: unexpected redirect`. Rust matches the outer
payload byte for byte and keeps `AuthError` with no transport fault; it has
no equivalent JS stack/cause chain. A caller-supplied reqwest client that
follows redirects still follows before the transport can refuse (#320).

Node 22.18.0's `JSON.parse` accepts valid arrays and objects at depth 127,
128, 200, 1,000, 10,000 and 100,000. The actual reference transport also
delivers them. It delivers a 1,048,575-byte array at depth 524,287 and a
1,048,573-byte object at depth 174,762; the next depth with a scalar exceeds
its default 1 MiB handshake-body limit and is refused for size, not nesting.
`JSON.parse` itself also accepts empty arrays nested 524,288 and 1,000,000
deep (1 MiB and 2,000,000 bytes): no parser cutoff was reached. Rust's
diagnostic scanner therefore has no fixed nesting bound or recursive call
stack. Its pending states are bounded by input length. Rust still buffers
with `response.bytes()` without the reference's configurable body cap.

The saved review probe (`diff_flat.mjs`, 40,000 generated cases plus 48 depth
cases with each seed 3 and 99) now matches 80,087 of 80,096 inputs. All nine
remaining inputs are valid numbers outside finite double range:
`86e427`, `29E390`, `40e663`, `4e10382`, `5e624`, `2e8332`, `56e955`,
`44e360`, `7e515` (some with surrounding whitespace). V8 reads each as
`Infinity`; serde refuses it with `number out of range`. The saved corpus
reproduces 71 differences before this fold, not the review summary's 86;
62 depth-related differences are removed. The exact 86-input run was not
available for replay.

Three response mappings remain explicit divergences, pinned without changing
their existing behavior:

- The reference measures the UTF-8 certificate-header value against 262,144
  bytes (`:240-246`). A 262,145-byte valid empty requested set is refused as
  `Failed to parse x-bsv-auth-requested-certificates returned by {url}: [oversized]. header exceeds its byte limit`.
  Rust parses and delivers that set; it has no matching header-byte check.
  The older TypeScript pin also delivers it.
- The reference requires a nonempty, bounded, even-length hexadecimal
  signature (at most 2,048 characters, `:328-340`). A base64 `MAA=` is refused
  as `Failed to parse x-bsv-auth-signature returned by {url}: [invalid]. signature must be bounded even-length hexadecimal`.
  Rust tries hex then base64, delivering signature bytes `[48, 0]`; neither
  decoder succeeding leaves `None`, still delivered. The older TypeScript
  pin refuses `MAA=` with `Invalid hex string`.
- An exact `x-bsv-auth-message-type: certificateRequest` maps to
  `certificateRequest`, everything else to `general` (`:343-346`, both pins).
  Rust always delivers `MessageType::General` on this response path, even
  with that header. This is a type difference, with no refusal text.

`ts-sdk@9e3ede6b` agrees on status, body and header texts (`:55-93`,
`:163-170`, `:252-307`), but does not set a redirect option (`:58-64`,
`:141-145`): the recorded 307 follows and reaches its callback. This crate
follows the newer pin's refusal. Both references pass syntactically valid
JSON such as `{"ok":true}` to their callback, where this crate's typed
`AuthMessage` refuses it in its existing serde words. A syntactically valid
certificate header outside `RequestedCertificateSet`'s shape is refused
with the header wrapper and serde's cause; the reference only casts its
parsed value and passes it to the callback. Other typed shape and
lone-surrogate refusals remain serde's; only the diagnostic scanner's
artificial cutoff is removed. Node's syntax wording is runtime
specific, pinned here to 22.18.0. A lone surrogate left by a diagnostic's
context cut is recorded as U+FFFD, its UTF-8 wire representation, as in
#354. The existing non-ASCII HTTP reason-phrase difference of #354 remains.

The Go pin is `2ca481c5931b987a0c8f48bb341c70b7477b6b07`; its file is
`auth/transports/simplified_http_transport.go` (there is no
`auth/transports/http.go` at this pin). It wraps a non-2xx handshake in
`HTTP server failed to authenticate` (`ErrHTTPServerFailedToAuthenticate`)
and `request failed with status %d: %s`
(`:102-130`), malformed bodies in `failed to unmarshal authmessage from body
(%q): %w` (`:141-152`) and a bad certificate header in `invalid format of
requested certificates in response: %w` (`:220-227`). Its default
`http.Client{}` and supplied client use their own redirect policy
(`:31-44`, `:111`, `:175`); no `CheckRedirect` is installed. Those Go words
and policy are not the TypeScript reference's.
### Verified: a general message's wallet refusal precedes the Peer's own signature words (#407)

The proposed change in #407 would replace a `ProtoWallet`'s error with the
Peer's error. The premise was wrong: both pinned TypeScript references
already propagate `Signature is not valid` from `ProtoWallet.verifySignature`
for a signature made by another key. Neither `processGeneralMessage` nor
the incoming-message dispatcher catches that rejection. The Peer throws
`Invalid signature in generalMessage from <identityKey>` only when its
wallet **returns** `{ valid: false }`. Rust already preserves that distinction;
no runtime behavior or public API changes in this entry.

`tests/auth_peer_general_message_words_407.rs` pins both paths on `start`
and `start_server`, no listener called on either refusal, an honest message,
and an unrelated wallet error propagated unchanged. Its fixture is recorded
by `tests/support/auth_peer_general_message_words_407.mjs` from the actual
Peers in `ts-stack@edf6e03` and `ts-sdk@9e3ede6b`, built from those commits
and run under Node v22.18.0. The recorder runs an honest handshake before
each message and records both `ProtoWallet` and an explicitly adapting wallet
that returns `false` on a verification error. Rust reconstructs the messages
with its own nonce writer, as #353's witness does, because the nonce HMAC
inputs differ. These parity tests were green when #407 landed; #415 updates
the malformed-signature expectation to the current reference's code-6 refusal.
The two proposed Peer-error replacement expectations were red, not evidence
of a parity fix.

Downstream old / proposed new (replacement **not applied**): `wallet error: Signature is not valid` / `authentication error: Invalid signature in generalMessage from <identityKey>`.

Line for the toolbox's operator-visible table: `| Bad signature in a certifier's general answer (ProtoWallet) | wallet error: Signature is not valid | Unchanged; a wallet returning valid: false instead produces authentication error: Invalid signature in generalMessage from <identityKey>. |`

### Notes: cross-SDK parity

The Peer's own words interpolate the established session identity string
directly (`ts-stack` `Peer.ts:1286-1304`), the compressed public-key hex in
these witnesses (66 lowercase characters, no `0x`). The wallet call has no
catch (`:1292-1301`), and neither does its dispatcher (`:766-800`). Both
reference `ProtoWallet`s throw `Signature is not valid` with code
`ERR_INVALID_SIGNATURE`; they do not return `false` for a non-verifying
signature (`ts-stack` `ProtoWallet.ts:358-396`, `ts-sdk` `:267-302`).

Unparseable bytes are a different refusal, also propagated: `ts-stack`'s
wallet validation throws `The signature parameter must be a canonical
DER-encoded ECDSA signature` (code 6, `validationHelpers.ts:1795-1802`),
while `ts-sdk`'s parser throws `Signature DER must start with 0x30` for the
recorded bytes. At #407's landing Rust propagated its `InvalidSignature`
parser error, `invalid signature: Expected sequence tag 0x30`. #415 now
propagates the current reference's code-6 argument refusal, removing the old
#407 divergence row. It remains a thrown refusal, never a false verification
result. Go at `2ca481c`
parses first (`auth/peer.go:1013-1017`, `failed to parse signature`), then
classifies a wallet's `ErrInvalidSignature` or `Valid: false` as
`general message - invalid-signature` (`:414-435`, `:1036-1038`), wrapping
other wallet errors separately. Its classification is not the TypeScript
Peer's propagation rule.
### Fixed: the #348 test finds the step probe's reservation without debug info, so it holds under `--release`; the #382 dhat pin at a twelfth of its memory (#401)

The finding (#383's fold's re-review, at `5f8fc526`): under `cargo test
--release`, three of the four tests in
`tests/script_budget_before_allocation_348.rs` failed on beta (`a single
allocation site holds more than the allowed live bytes`: 4,117,104 bytes
for #348's input, 4,955,436 for #349's, 600,012 for the 100,001-byte
product) and passed in the debug profile. The test leaves the interpreter's
step probe out of its single-site read (`arithmetic_room.rs`, `reserve`:
`try_reserve_exact` of the step's room, given back at once, #374) by finding
the frame `arithmetic_room::reserve` in dhat's backtraces; a release build
inlines `reserve` into its callers and has no debug info to name an inlined
frame, so each reservation was read as a site (600,012 is the product's
step room, 6 times its operands).

`reserve` is now `#[inline(never)]`: the symbol table names its frame in
every profile, debug info or none, and the reservation is found by the same
name. The fuzz target keeps its own rule (an allocation freed before the
allocator's next call, nothing allocated, grown or freed in between, #331):
it counts in an allocator of its own, which the test cannot have (the
crate's `unsafe_code = "forbid"` reaches every target, and a `GlobalAlloc`
is an `unsafe impl`), and a backtrace per allocation is too slow for a
fuzzer. Two readings of one thing: the probe's allocation, and nothing else
under its frame. A build stripped of its symbols (`strip = "symbols"`, no
profile here sets it) names no frame: each of the three tests now asserts
it found a reservation, and says so in those words rather than as a bound.
The probe runs only at a step of 64 KiB or more, so the frame costs nothing
measurable.

Pinned: the file's four tests, green under `--release` and in the debug
profile; with the new test on the base's library (`reserve` inlined), three
of four red under `--release`, ``no allocation under
`arithmetic_room::reserve`: dhat's backtraces do not name the probe``, and
the same three red with symbols stripped
(`CARGO_PROFILE_RELEASE_STRIP=symbols`). CI runs the file in the debug
profile (`ci.yml`, `Run every integration test`, `cargo test --features
"full,http,websocket" --tests`), where it passed before the fix too; the
release profile is the lanes' and the re-reviews' gate.

The second finding (#382's fold's re-review): the #382 pin in
`tests/memory_profiling.rs`, `test_issue_382_a_minimal_splice_operand_is_not_decoded`,
built an 800,000,000-byte operand, and the file ran at 4,454,236,160 bytes
resident under `/usr/bin/time -l` (149 s). The proof does not need the
size: the guard is that a minimal splice operand past 8 bytes is not
decoded, and the decode is a second copy of the whole operand at any size.
At 64 MiB (67,108,864 bytes) the peak is 67,108,963 bytes with the guard
and 134,217,827 on a scratch copy of #396's head with `splice.rs`'s guard
removed (the test red there), the same factor of two as 800,000,099 against
1,600,000,099; the file now runs at 730,480,640 bytes resident (147 s, the
time the other eleven tests'). CI runs the file in the debug
profile, alone (`ci.yml`, `Run the memory profiling tests`, `cargo test
--test memory_profiling --all-features -- --test-threads=1`).
### Added: `WalletClient::with_substrate` takes a `WalletInterface` instance as the client's substrate, the reference's constructor's own alternative; the client carries the two linkage calls (#335)

The finding (the #323 fold re-review's note, 2026-10-27): `WalletClient::new`
builds its substrate itself from `SubstrateType` (`Auto`, the HTTP JSON and
wire substrates on their default URLs), so a caller holding a wallet (an
in-process one, a substrate built with its own URL or client) could not put
it behind the client, and no `WalletClient` test could run without reaching
the default ports. The reference's constructor takes the instance as the
same parameter as the names (`ts-stack@edf6e03`
`packages/sdk/src/wallet/WalletClient.ts:83-107`):

```ts
constructor(
  substrate: 'auto' | 'Cicada' | 'XDM' | 'window.CWI' | 'json-api'
    | 'react-native' | 'secure-json-api' | WalletInterface = 'auto',
  originator?: OriginatorDomainNameStringUnder250Bytes
)
```

and each call is `this.substrate.<call>(args, this.originator)`.

- `WalletClient::with_substrate(substrate: Arc<dyn WalletInterface>,
  originator: Option<String>) -> WalletClient`, beside `new`. A constructor,
  not a `SubstrateType::Custom(..)` variant: `SubstrateType` is `Copy`, `Eq`
  and exhaustive, and a variant holding a trait object would take all three
  away from every downstream that matches or copies it; the instance is the
  reference's parameter's other kind, not another name, and a second
  constructor is how this crate spells a parameter of two kinds (`new` and
  `with_client` on the substrates, #323). `Arc`, as `Peer` holds its wallet,
  so a caller keeps using the wallet it hands over (`Arc::from(boxed)` for a
  `Box`); `Send + Sync` come with the trait.
- Every call goes to the instance with the client's originator, the
  configured one or `None` (#329), exactly as to a named substrate:
  internalizeAction's arguments validated first as before (#117, #384), the
  status calls answered in the client's shapes (`get_height` the height,
  `get_version` the string, `is_authenticated` and `wait_for_authentication`
  the flag, `get_network` the `Network`), `get_header` reaching
  `get_header_for_height`. Nothing is probed: the instance is the connected
  substrate from construction, as the reference's `connectToSubstrate`
  returns at once for an object (`:121-124`); `substrate_type()` answers
  `Auto`, the reference's default parameter.
- `WalletClient::reveal_counterparty_key_linkage` and
  `reveal_specific_key_linkage`: the client carried 26 of the 28 calls; it
  carries all 28, as the reference's does. The JSON substrate and an
  instance forward them; since #406 the wire substrate forwards them too,
  through `WalletWireTransceiver`'s methods (`ts-stack@edf6e03`
  `WalletWireTransceiver.ts:790`, `:851`), with fixtures recorded both ways.
  #406 removes the earlier wire refusal and its test, which would now reach
  the default wallet URL.
- The forwarding is one macro over the three substrates (`client.rs` 745
  lines to 582, with the two calls); the instance's shape adapters are
  `src/wallet/client_instance.rs`.

The use: a downstream that already holds a wallet (the toolbox's and the
CLI's in-process wallets) hands it to the code that takes a `WalletClient`:

```rust,ignore
let mut client = WalletClient::with_substrate(Arc::new(wallet), Some("myapp.com".into()));
```

Pinned by `tests/wallet_client_instance_335.rs` (3 retained tests): the counting wallet of
#318 behind the client receives all 28 calls, in a table, each with the
client's originator, and each with `None` when none is set; a `ProtoWallet`'s
answers and refusals come back through the client unchanged. The original
four-test file was red on a scratch copy of `485848ba` (it did not compile:
`with_substrate` and the two linkage methods absent, 7 errors), and red
1 of 4 with the instance arm passing `None` for the originator; #406 removes
only the obsolete wire-refusal test. The `Auto` path and the named substrates
on their default URLs stay unpinned: a test of them reaches whatever
listens on 2121, 3321 and 3301, in the reference too (its `'auto'` probes
the named substrates on their defaults, `:126-196`).

Migration: none; additive (a constructor and two methods). The client stays
behind `http`, as it was; #404 moves the client core under `wallet` with the
HTTP substrates behind `http` (the keeper's word of 2026-10-28), and has the
client implement `WalletInterface` as the reference's does (`WalletClient.ts:82`).

### Notes: cross-SDK parity (#335)

The reference's client validates every call's arguments and its result
(`validateCreateActionArgs` and the rest, `validateWalletResult`,
`WalletClient.ts:111-118`, `:200-209` and each call after) and normalizes its originator at construction
(`validateOriginator`, `:97`) before handing it to the instance; this
crate's client validates internalizeAction's arguments alone and hands the
instance the originator as configured (the HTTP substrates validate theirs
at construction since #323), the same for an instance as for its own
substrates. `'XDM'`, `'window.CWI'` and `'react-native'` are browser and
React Native substrates with no counterpart here. go-sdk@2ca481c has no
multi-substrate client (its `wallet/README.md` names a
`wallet.NewWalletClient()` no Go file defines): a caller builds a substrate
(`substrates.NewHTTPWalletJSON(originator, baseURL, httpClient)`,
`NewHTTPWalletWire`) or holds any `wallet.Interface` and calls it with an
originator per call.
### Fixed: SimplifiedFetchTransport applies the reference's six response bounds and mappings (#416)

The #410 fold left three response mappings as documented divergences; its
re-review found the missing body, request-ID and signed-header checks too.
The keeper's 2026-10-28 word under ruling (c) calls for parity with
`ts-stack@edf6e03`, with no new owner word. Previously the transport could
deliver an oversized requested-certificate header, decode a base64 signature,
retype a certificate request as general, buffer an unbounded body, use its
own request ID when none was returned, and sign unbounded response headers.

The pinned `packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts`
now supplies all six rules:

| Rule and reference site | Accepted boundary and refusal |
|---|---|
| `x-bsv-auth-requested-certificates`, `:234-258` | At most 262,144 UTF-8 bytes; 262,145 refused before JSON parsing with `[oversized]. header exceeds its byte limit` in the header wrapper |
| `x-bsv-auth-signature`, `:328-340` | Nonempty even-length ASCII hexadecimal, at most 2,048 characters (1,024 decoded bytes), either case; otherwise `[invalid]. signature must be bounded even-length hexadecimal` in the header wrapper. This is a shape check, not DER validation. Missing or blank still uses #354's missing-header refusal |
| `x-bsv-auth-message-type`, `:343-346` | Exact `certificateRequest` stays `CertificateRequest`; every other value is `General` |
| Buffered bodies, `:23-25`, `:375-428` | Handshake default 1,048,576 bytes; authenticated application response default 16,777,216 bytes. Check Content-Length first, then every chunk before buffering it, on success and error responses. One byte over uses `Authenticated response from {url} exceeds {maximum} bytes`; invalid Content-Length uses `Invalid Content-Length returned by {url}` |
| `x-bsv-auth-request-id`, `:293-303` | Optional; when present, canonical standard padded base64 encoding exactly 32 bytes. Grammar failures use `Authenticated response request ID must be canonical base64`; wrong byte count or padding bits use `Authenticated response request ID must encode exactly 32 bytes`. No equality check against the outgoing ID; absent means no ID bytes in the payload |
| Signed response headers, `:261-289` | `x-bsv-*` except `x-bsv-auth*`, plus `authorization`: at most 512 distinct headers, name 1–1,024 UTF-8 bytes, value at most 32,768 UTF-8 bytes, sum of names and values at most 262,144 bytes. Individual overflow uses `Authenticated response contains an oversized signed header`; count or total overflow uses `Authenticated response signed headers exceed their limit` |

Repeated values join with `, ` before measurement, as fetch's Headers does;
wire values are Latin-1 interpreted as text, then counted and signed as UTF-8.
The reference's byte-sorted header walk determines the first refusal, and
its `localeCompare` order determines the signed payload (the existing ASCII
collation table covers HTTP names). The signature shape is checked before
the certificate header and payload checks, as in the reference.

The fold keeps the bounded certificate header as `requested_certificates_text`
before reading its typed `RequestedCertificateSet`. The Peer verifies the
carried text, so reordering its top-level properties or adding a property
outside the typed set no longer changes its signature preimage. The header
is parsed on every general reply, including a reply typed `General`.

`with_max_response_bytes` and `with_max_handshake_response_bytes` configure
the two body limits on either `new` or `with_client`. They accept positive
`usize` values up to JavaScript's maximum safe integer; zero and larger
values use the reference's `maxResponseBytes must be a positive safe integer`
and `maxHandshakeResponseBytes must be a positive safe integer`. Rust uses
builder methods instead of the reference constructor's options object;
negative and fractional values cannot be represented. The defaults are the
same even with a caller-supplied client. Returning a size error drops the
response and stops consuming its stream. The new work is in `http/body.rs`,
`http/response_bounds.rs` and `http/general.rs`; `http.rs` shrinks and
`transport_fault.rs` is unchanged.

Pinned by the six tests in `tests/auth_transport_bounds_416.rs`, one per
rule: `certificate_header_accepts_262144_utf8_bytes_and_refuses_one_more`,
`signatures_require_nonempty_even_hex_at_most_2048_characters`,
`certificate_request_response_keeps_its_type`,
`bodies_use_the_1_mib_handshake_and_16_mib_application_defaults`,
`optional_request_id_requires_canonical_base64_of_exactly_32_bytes`, and
`signed_headers_bound_names_values_count_and_total_utf8_bytes` (each prefixed
`issue_416_`). All six are RED on a scratch copy of base
`bfdd4e7fa5a5b17df5eff4a5ccb54d31c85b8d3f`, with its own Cargo target directory:
`0 passed; 6 failed`, with deliveries, decoded signatures and retyped
messages printed in the failures. The three #410 divergence tests now
assert the conforming outcomes and have names saying so.
`auth_peer_http_certificate_request_416.rs` adds three wiremock tests through
a signed handshake and `Peer::start`: the property-order and extra-property
headers reach the certificate-request listener (both RED on `96cd2988` as
`Signature is not valid`); a certificate request signed over the HTTP payload
is refused with that wallet error, never delivered as general (RED on
`bfdd4e7f`, which accepts it as `General`). All three are RED on `bfdd4e7f`.
`auth_transport_body_options_416.rs` adds the configurable-limit and invalid
option checks, including chunked responses without Content-Length.
The two signed-response pins in `transport_unsigned_response_354.rs` now
expect omission of an absent request ID too; their recorded headers and
bodies are unchanged. The architecture test's exact-line protocol-comparison
inventory follows the moved header checks and includes the message-type
comparison. No error-text classification is added.

`tests/vectors/auth_transport_bounds_416.json` is the unedited output of
`tests/support/auth_transport_bounds_416.mjs`: 66 cases per reference and
four option refusals at the newer pin, under Node 22.18.0, with fake fetch
and streaming bodies, never a listening socket. Both references were built
from their clone's pinned commit. Large values are recipes, not copied
blobs; successful deliveries pin message types, signature bytes and payload
SHA-256. The Rust replay uses wiremock, with HTTP/2 to exercise the SDK's
512-header bound. No HTTP/1 header-count limit is measured here.
The two fake-fetch Content-Length cases are retained in the vector and
tested against constructed Responses in `http/body_tests.rs`, isolating
the SDK guard from native HTTP framing, without I/O.

Migration for callers matching refusal payloads (the `authentication error: `
display prefix remains). All six old/new behaviors in one block for the
toolbox's matching table; `{url}` includes the response path:

certificate header old: 262,145-byte valid requested set delivered
certificate header new: Failed to parse x-bsv-auth-requested-certificates returned by {url}: [oversized]. header exceeds its byte limit
signature old: MAA= decoded to [48, 0]; undecodable forms delivered as None
signature new: Failed to parse x-bsv-auth-signature returned by {url}: [invalid]. signature must be bounded even-length hexadecimal
message type old: certificateRequest delivered as General
message type new: certificateRequest delivered as CertificateRequest
body old: response.bytes() buffered without a limit
body new: Authenticated response from {url} exceeds 1048576 bytes (handshake); exceeds 16777216 bytes (application)
request ID old: library base64 errors or Invalid request ID length; absent replaced by the outgoing ID
request ID new: Authenticated response request ID must be canonical base64; Authenticated response request ID must encode exactly 32 bytes; absent omitted
signed headers old: names, values, count and total unbounded; repeated/non-ASCII values not fetch's text
signed headers new: Authenticated response contains an oversized signed header; Authenticated response signed headers exceed their limit; fetch's joined UTF-8 text signed

### Notes: cross-SDK parity (#416)

`ts-sdk@9e3ede6b`'s `src/auth/transports/SimplifiedFetchTransport.ts` preserves
`certificateRequest` too, but has none of the certificate-header, body,
request-ID or signed-header limits. Its signature reader is hex-only but
unbounded and permits odd-length hex; `MAA=` uses `Invalid hex string`.
The recorder measures each of these older outcomes alongside the newer pin.

At `go-sdk@2ca481c`, `auth/transports/http.go` does not exist; the corresponding
code is `auth/transports/simplified_http_transport.go:125-237` and
`auth/authpayload/http.go:165-178,226-251,381-395`. Go uses unbounded
`io.ReadAll` for both paths, unbounded certificate JSON and `hex.DecodeString`
for the signature, and no signed-header size or count bounds. It rejects a
`certificateRequest` response with `unexpectedly received non-general message
type certificateRequest in response to general message`. It serializes the
outgoing request ID rather than checking the returned header. This change
follows the newer TypeScript reference, not Go. #410's typed JSON, JS
cause/stack, non-ASCII reason-phrase and caller-client redirect differences
remain; they are separate from these six rules.

The header's exact reference order is `headers.get` at
`SimplifiedFetchTransport.ts:238`, byte bound at `:240`, `JSON.parse` at
`:249`, assignment to the message at `:349`, then
`JSON.stringify(message.requestedCertificates)` at `Peer.ts:1068` for the
signature. The two compact headers above preserve their property order and
extra property through that path. For whitespace and redundant escapes the
two readers disagree in both directions. The #280 precedent keeps the signed
text's bytes as received here; the reference verifies the parsed object's
`JSON.stringify` form. The four cases are:

| Case | Received header | Signed preimage | This crate | Both references |
|---|---|---|---|---|
| H3 | JSON with whitespace | Raw header text | Verify | Refuse |
| H3b | JSON with whitespace | Stringified parsed object | Refuse | Verify |
| H5 | JSON with escaped `\u0074ypes` key | Raw header text | Verify | Refuse |
| H5b | JSON with escaped `\u0074ypes` key | Stringified parsed object | Refuse | Verify |

Neither writer emits these whitespace or redundant-escape header forms:
the reference's `ts-stack@edf6e03`
`packages/middleware/auth-express-middleware/src/index.ts:943,1015` uses
`JSON.stringify`, and this crate's `src/auth/transports/http.rs:582` uses
`serde_json::to_string`. Re-serialising on receipt as the reference does at
`packages/sdk/src/auth/Peer.ts:1068` remains an alternative open for the
keeper's word; this fold leaves the #280 choice and behavior unchanged.
`auth_http_certificate_request_416.json`, generated by
`tests/support/auth_http_certificate_request_416.mjs` under Node 22.18.0,
records both references' preimages and verdicts. The tests read the previously
unused whitespace case and all three added cases as four behavior pins;
no RED is expected for these unchanged verdicts. The two successful compact
headers and the wrong HTTP-payload preimage remain pinned too.

The newer reference's full Peer intake also refuses an HTTP certificate
request as `certificateRequest.initialNonce must be canonical base64.`:
its transport omits that member (`:340-352`), while
`AuthMessageValidation.ts:365` requires it. The recorder records that refusal
first, then calls the unmodified `processCertificateRequest` (`Peer.ts:1044-1118`)
to measure the path Rust implements; the older reference reaches its handler
through normal intake. This crate still implements the listener path, not
the reference's automatic certificate response or all of its intake/replay
checks. The Rust tests exercise its full HTTP-to-Peer path without an adapter.

### Changed: the auth and identity certificate maps and `resolve_by_attributes`'s attributes keep insertion order, the reference's `Record` order, one order through the crate after the wallet's (#394)

#385 moved the wallet types' certificate maps to insertion order and left
the auth and identity ones `HashMap`s, so a certificate crossing from
`auth::Certificate` to a wallet type took the signed order and the
validators here walked byte order. At the pin the reference's certificate
fields and keyrings are a JavaScript `Record` wherever they appear, which
keeps insertion order (`ts-stack@edf6e03`
`packages/sdk/src/auth/certificates/Certificate.ts:179`, `:203`, `:510`;
`VerifiableCertificate.ts:87`, `:110`; `packages/sdk/src/identity/IdentityClient.ts:667`
for the attributes `resolveByAttributes` matches contacts against). Its
`toBinary` checks each field's name and value in `Reflect.ownKeys` order
(`snapshotCertificateFields`, `Certificate.ts:44-84`) and sorts the names by
`localeCompare` only to write them (`:282`). The keeper's word (2026-10-28
04:1xZ) is #385's reading under the owner's ruling (c): no new owner word.

The maps are `indexmap::IndexMap<String, String>`, serde reading and writing
them in the text's order. `indexmap` was already under `wallet` since #385;
`auth` and `identity` get it through `wallet` and need nothing of their own,
and the wasm32 slice builds (`identity,wasm` too). By module:

- `auth` (6 maps, 10 walks): `Certificate.fields`, the binary reader's and
  the JSON form's maps, `MasterCertificate.master_keyring`,
  `VerifiableCertificate.keyring` and its decrypted cache. `to_binary`'s
  checks (`checked_field_names`) take each name's length and safety, then its
  value's 1 MiB, in the map's order, and sort only after, where they used to
  judge in the sorted order. `from_binary` keeps the frame's order. The
  master's snapshot (`snapshot_record`, `MasterCertificate.ts:31-61`), its
  constructor's two loops (`:195-233`), `create_keyring_for_verifier`'s two
  loops (`:348-365`) and `create_certificate_fields` (`Object.entries`,
  `:270`) walk the map, as does the verifier's `decrypt_fields`
  (`Reflect.ownKeys(keyring)`, `VerifiableCertificate.ts:160`). Each of those
  walked byte order before. `field_names` and `revealable_fields` give the
  map's order. `to_wallet_certificate` keeps the map's order, where #385 had
  it sort. `get_verifiable_certificates` holds the wallet's maps as given and
  no longer converts at the boundary.
- `identity` (5 maps, 4 walks): `IdentityQuery.attributes`, both of
  `IdentityCertificate`'s maps (`publicly_revealed_keyring`,
  `decrypted_fields`), the attributes parameter and the generic-identity
  reader's map. Both token parsers read the token's `fields` and `keyring` in
  the order of its JSON text (`token_maps.rs`, new: a `serde_json::Value`
  sorts its keys in this build). A member that is not an object reads as
  empty and a value that is not a string is skipped, as before.
  `decrypted_fields` follows the keyring.
- `kvstore`, `registry`: no map of certificate fields, keyrings or
  attributes. `registry::CertificateDefinitionData.fields`
  (`HashMap<String, CertificateFieldDescriptor>`) is a definition's field
  descriptors, not a certificate's values, and stays as it is.

The signer's preimage is unchanged: `localeCompare`'s order, the same
whatever order the fields come in (#246, #249). A certificate read from a
frame in another order keeps that frame's bytes (#249).

Pinned by `tests/auth_identity_certificate_field_order_394.rs` (13), on eight
names out of every sorted order:
- through `Certificate`'s JSON, `field_names`, `to_wallet_certificate` and
  the verifier;
- the binary form written in the signed order and read back in it;
- an issuer's frame in another order, read in that order and written back
  byte for byte;
- a `VerifiableCertificate`'s keyring through its JSON;
- issuance, the master's `decrypt_fields`, `create_keyring_for_verifier` (in
  the order of the names to reveal) and the verifier's `decrypt_fields`;
- the first bad name in insertion order refused by `to_binary` (a value over
  1 MiB; `prototype` before `__proto__`), by `MasterCertificate::new` (a
  missing keyring entry), by `create_keyring_for_verifier` (a non-canonical
  field), by the verifier's `decrypt_fields` (a bad keyring entry) and by
  `create_certificate_fields` (a plaintext over 64 KiB);
- a published token's fields and keyring in the order of its text, through
  `discover_certificates` over an injected facilitator;
- `IdentityQuery`'s attributes in its JSON.

The maps are built with `collect()` and `insert`, so the file compiles
against the old shape: red 13 of 13 on a scratch copy of `5f8fc526` with the
file added, each at its assertion (the sorted name named, a hash order read).
The golden fixtures did not move (`fixtures_replay` green, nothing
re-recorded), and neither did the #280 vector's texts
(`auth_signed_text_280` green, every recorded certificate's maps already in
the order the vector holds).

`resolve_by_attributes` sends its attributes in insertion order. The lookup
question's query is a `serde_json::Value` (`LookupQuestion::query`, a public
field), which sorts its keys in this build (no `preserve_order`).
`LookupQuestion` is unchanged: `bsv-overlay-cloudflare` re-exports it and
builds it with struct literals, so a field of any kind would break it. The
text travels beside the question instead. `resolve_by_attributes` serializes
its `IndexMap` once (the crate's `LookupResolver::query_ordered`, the `Value`
read back from that text) and the resolver hands the text to each host's
facilitator through `OverlayLookupFacilitator::lookup_ordered`, a new
provided method whose default ignores the text and calls `lookup`.
`HttpsOverlayLookupFacilitator` sends the text as the body's `query`.
`LookupResolver::query` passes no text, so its bodies are the `Value`'s, as
before. The body's members stay `query` then `service`, the order `json!`
gave them, where the reference writes `service` first (`LookupResolver.ts`
at edf6e03): a residual of #400's charter, not a reading of any parser. A
single attribute is still `{"any": value}`. A facilitator that keeps the
default `lookup_ordered`, or a wrapper that delegates to another's `lookup`,
sends the attributes sorted as before: a downstream facilitator overrides
`lookup_ordered` to keep the order (the overlay engine's and the relay's at
their re-pins). `query` moved, as
is, to `src/overlay/lookup_resolver/query.rs`: `lookup_resolver.rs` is over
the ratchet's 800-line bound and may not grow.

The keeper's word (2026-10-28 04:5xZ, under ruling (c)): "one order through the crate" is the data model, the map type wherever the
reference holds a `Record`, not a claim about every body's bytes. JSON key
order is a parity item only where the reference's bytes are hashed, signed or
compared whole, and this body is the one place found where the port's bytes
sit beside the reference's: the attributes in insertion order through
`JSON.stringify` (`IdentityClient.ts:667`). The reference's
`resolveByAttributes` itself sends no lookup; it asks its wallet's
`discoverByAttributes` (`:605-655`), whose arguments keep their order here
since #385. Every other body keeps its bytes: every other question goes
through `LookupResolver::query` or a facilitator's `lookup`, and its `Value`
writes what `json!` wrote. `preserve_order` crate-wide, the rest of the
`Value` bodies, is #400.

Pinned by `tests/identity_lookup_attribute_order_394.rs` (5), through a
wiremock lookup host: `zeta` then `alpha` sent in that order, byte for byte;
a single attribute still the `any` matcher; a question sent through `lookup`
sending the bytes `json!` of both members gives; `lookup_ordered` sending the
text it is given. An injected facilitator that keeps the default is asked
through `lookup` with the same `Value` as before. Red 1 of 3 on a scratch
copy of `6741a44a` (the two tests that name `lookup_ordered` left out): the
attributes arrived `alpha` first. The other two are green on both trees.

Public shape (no semver lint reads a field's or a parameter's type; the list
is complete):
- 6 fields: `Certificate.fields`, `MasterCertificate.master_keyring`,
  `VerifiableCertificate.keyring`, `IdentityQuery.attributes`,
  `IdentityCertificate.publicly_revealed_keyring` and `.decrypted_fields`.
- 12 signatures: `Certificate::with_fields`, `Certificate::set_fields`,
  `MasterCertificate::new`, `::create_certificate_fields` (its argument and
  both results), `::create_keyring_for_verifier` (both maps and its result),
  `::issue_for_subject`, `::decrypt_fields`, `VerifiableCertificate::new`,
  `::decrypt_fields`, `::get_decrypted_fields`, `IdentityQuery::by_attributes`,
  `IdentityClient::resolve_by_attributes`.
- 3 orders: `field_names`, `revealable_fields` and `to_wallet_certificate`
  now give the map's order.
- 1 addition: `OverlayLookupFacilitator::lookup_ordered`, a provided method
  (an implementor needs nothing new). `LookupQuestion` is unchanged. The JSON of the four types that carry these maps is written in insertion order where it was hash order: a consumer that compared those bodies byte for byte sees the change (#400 lists where that matters).

Migration: the same as #385's. Build an `IndexMap` where you built a
`HashMap` (`[(k, v)].into_iter().collect()` compiles unchanged;
`IndexMap::from([...])` for `HashMap::from([...])`). This crate does not
re-export `indexmap`, so a downstream that names the type adds
`indexmap = "2"` to its own manifest. `IndexMap`'s `==` ignores order. None
of the downstreams on this host (`bsv-overlay-cloudflare`, `rust-message-box`)
builds these maps. `bsv-middleware-cloudflare-public`, `rust-chaintracks`
and the LOW workers were not checked.

Semver: `cargo semver-checks --release-type minor --baseline-rev 5f8fc526
--all-features` passes 202 checks and names nothing. It has no lint for a
changed field or parameter type, so the pass is not evidence; this entry is.
A private field on `LookupQuestion` failed it
(`constructible_struct_adds_private_field`), which is why the text travels
beside the question.
Ratchet: every counter at or below `docs/ratchets.json` (`tools/ratchet/run
--check --against origin/beta`). `identity/client.rs`, over its bound, shrank
(the token's maps moved to `token_maps.rs`), and `overlay/lookup_resolver.rs`
went from 907 lines to 779 (`query` moved). Not re-recorded.

### Notes: cross-SDK parity (#394)

The integer-like residual is #385's: a JavaScript object walks a name like
`"7"` first, in ascending order, whatever its place, and `IndexMap` keeps it
where it was given. On a certificate with such a name, the first name a
bound refuses and a keyring's walk differ from the reference's. The signed
bytes do not, because both sides sort. go-sdk@2ca481c holds these maps as Go
maps (`auth/certificates/certificate.go:49`, `verifiable.go:23`,
`master.go:34`) and sorts the field names by bytes to sign
(`wallet/serializer/certificate.go:42-49`). Its JSON writes keys sorted
(`encoding/json`), so a certificate's JSON with unsorted fields that this
crate or the reference writes differs from Go's text. Go's readers require
no order.

The finding (the #323 fold re-review's note, 2026-10-27): `WalletClient::new`
builds its substrate itself from `SubstrateType` (`Auto`, the HTTP JSON and
wire substrates on their default URLs), so a caller holding a wallet (an
in-process one, a substrate built with its own URL or client) could not put
it behind the client, and no `WalletClient` test could run without reaching
the default ports. The reference's constructor takes the instance as the
same parameter as the names (`ts-stack@edf6e03`
`packages/sdk/src/wallet/WalletClient.ts:83-107`):

```ts
constructor(
  substrate: 'auto' | 'Cicada' | 'XDM' | 'window.CWI' | 'json-api'
    | 'react-native' | 'secure-json-api' | WalletInterface = 'auto',
  originator?: OriginatorDomainNameStringUnder250Bytes
)
```

and each call is `this.substrate.<call>(args, this.originator)`.

- `WalletClient::with_substrate(substrate: Arc<dyn WalletInterface>,
  originator: Option<String>) -> WalletClient`, beside `new`. A constructor,
  not a `SubstrateType::Custom(..)` variant: `SubstrateType` is `Copy`, `Eq`
  and exhaustive, and a variant holding a trait object would take all three
  away from every downstream that matches or copies it; the instance is the
  reference's parameter's other kind, not another name, and a second
  constructor is how this crate spells a parameter of two kinds (`new` and
  `with_client` on the substrates, #323). `Arc`, as `Peer` holds its wallet,
  so a caller keeps using the wallet it hands over (`Arc::from(boxed)` for a
  `Box`); `Send + Sync` come with the trait.
- Every call goes to the instance with the client's originator, the
  configured one or `None` (#329), exactly as to a named substrate:
  internalizeAction's arguments validated first as before (#117, #384), the
  status calls answered in the client's shapes (`get_height` the height,
  `get_version` the string, `is_authenticated` and `wait_for_authentication`
  the flag, `get_network` the `Network`), `get_header` reaching
  `get_header_for_height`. Nothing is probed: the instance is the connected
  substrate from construction, as the reference's `connectToSubstrate`
  returns at once for an object (`:121-124`); `substrate_type()` answers
  `Auto`, the reference's default parameter.
- `WalletClient::reveal_counterparty_key_linkage` and
  `reveal_specific_key_linkage`: the client carried 26 of the 28 calls; it
  carries all 28, as the reference's does. The JSON substrate and an
  instance forward them; the wire substrate refuses both before a byte is
  sent, `WalletError("<call> is not available over the wallet wire
  substrate")`: this crate's `WalletWireTransceiver` writes neither call
  (its processor reads both), where the reference's transceiver writes both
  (`ts-stack@edf6e03` `WalletWireTransceiver.ts:790`, `:851`; #406 ports
  them with fixtures recorded both ways).
- The forwarding is one macro over the three substrates (`client.rs` 745
  lines to 582, with the two calls); the instance's shape adapters are
  `src/wallet/client_instance.rs`.

The use: a downstream that already holds a wallet (the toolbox's and the
CLI's in-process wallets) hands it to the code that takes a `WalletClient`:

```rust,ignore
let mut client = WalletClient::with_substrate(Arc::new(wallet), Some("myapp.com".into()));
```

Pinned by `tests/wallet_client_instance_335.rs` (4): the counting wallet of
#318 behind the client receives all 28 calls, in a table, each with the
client's originator, and each with `None` when none is set; a `ProtoWallet`'s
answers and refusals come back through the client unchanged; the wire
substrate's two linkage refusals, unsent. Red on a scratch copy of
`485848ba` (the file does not compile: `with_substrate` and the two linkage
methods absent, 7 errors); red 1 of 4 on the tip with the instance arm
passing `None` for the originator. The `Auto` path and the named substrates
on their default URLs stay unpinned: a test of them reaches whatever
listens on 2121, 3321 and 3301, in the reference too (its `'auto'` probes
the named substrates on their defaults, `:126-196`).

Migration: none; additive (a constructor and two methods). The client stays
behind `http`, as it was; #404 moves the client core under `wallet` with the
HTTP substrates behind `http` (the keeper's word of 2026-10-28), and has the
client implement `WalletInterface` as the reference's does (`WalletClient.ts:82`).

### Notes: cross-SDK parity (#335)

The reference's client validates every call's arguments and its result
(`validateCreateActionArgs` and the rest, `validateWalletResult`,
`WalletClient.ts:111-118`, `:200-209` and each call after) and normalizes its originator at construction
(`validateOriginator`, `:97`) before handing it to the instance; this
crate's client validates internalizeAction's arguments alone and hands the
instance the originator as configured (the HTTP substrates validate theirs
at construction since #323), the same for an instance as for its own
substrates. `'XDM'`, `'window.CWI'` and `'react-native'` are browser and
React Native substrates with no counterpart here. go-sdk@2ca481c has no
multi-substrate client (its `wallet/README.md` names a
`wallet.NewWalletClient()` no Go file defines): a caller builds a substrate
(`substrates.NewHTTPWalletJSON(originator, baseURL, httpClient)`,
`NewHTTPWalletWire`) or holds any `wallet.Interface` and calls it with an
originator per call.
### Fixed: the #348 test finds the step probe's reservation without debug info, so it holds under `--release` (#401)
### Fixed: the #348 test finds the step probe's reservation without debug info, so it holds under `--release`; the #382 dhat pin at a twelfth of its memory (#401)

The finding (#383's fold's re-review, at `5f8fc526`): under `cargo test
--release`, three of the four tests in
`tests/script_budget_before_allocation_348.rs` failed on beta (`a single
allocation site holds more than the allowed live bytes`: 4,117,104 bytes
for #348's input, 4,955,436 for #349's, 600,012 for the 100,001-byte
product) and passed in the debug profile. The test leaves the interpreter's
step probe out of its single-site read (`arithmetic_room.rs`, `reserve`:
`try_reserve_exact` of the step's room, given back at once, #374) by finding
the frame `arithmetic_room::reserve` in dhat's backtraces; a release build
inlines `reserve` into its callers and has no debug info to name an inlined
frame, so each reservation was read as a site (600,012 is the product's
step room, 6 times its operands).

`reserve` is now `#[inline(never)]`: the symbol table names its frame in
every profile, debug info or none, and the reservation is found by the same
name. The fuzz target keeps its own rule (an allocation freed before the
allocator's next call, nothing allocated, grown or freed in between, #331):
it counts in an allocator of its own, which the test cannot have (the
crate's `unsafe_code = "forbid"` reaches every target, and a `GlobalAlloc`
is an `unsafe impl`), and a backtrace per allocation is too slow for a
fuzzer. Two readings of one thing: the probe's allocation, and nothing else
under its frame. A build stripped of its symbols (`strip = "symbols"`, no
profile here sets it) names no frame: each of the three tests now asserts
it found a reservation, and says so in those words rather than as a bound.
The probe runs only at a step of 64 KiB or more, so the frame costs nothing
measurable.

Pinned: the file's four tests, green under `--release` and in the debug
profile; with the new test on the base's library (`reserve` inlined), three
of four red under `--release`, ``no allocation under
`arithmetic_room::reserve`: dhat's backtraces do not name the probe``, and
the same three red with symbols stripped
(`CARGO_PROFILE_RELEASE_STRIP=symbols`). CI runs the file in the debug
profile (`ci.yml`, `Run every integration test`, `cargo test --features
"full,http,websocket" --tests`), where it passed before the fix too; the
release profile is the lanes' and the re-reviews' gate.

The second finding (#382's fold's re-review): the #382 pin in
`tests/memory_profiling.rs`, `test_issue_382_a_minimal_splice_operand_is_not_decoded`,
built an 800,000,000-byte operand, and the file ran at 4,454,236,160 bytes
resident under `/usr/bin/time -l` (149 s). The proof does not need the
size: the guard is that a minimal splice operand past 8 bytes is not
decoded, and the decode is a second copy of the whole operand at any size.
At 64 MiB (67,108,864 bytes) the peak is 67,108,963 bytes with the guard
and 134,217,827 on a scratch copy of #396's head with `splice.rs`'s guard
removed (the test red there), the same factor of two as 800,000,099 against
1,600,000,099; the file now runs at 730,480,640 bytes resident (147 s, the
time the other eleven tests'). CI runs the file in the debug
profile, alone (`ci.yml`, `Run the memory profiling tests`, `cargo test
--test memory_profiling --all-features -- --test-threads=1`).
### Verified: a general message's wallet refusal precedes the Peer's own signature words (#407)

The proposed change in #407 would replace a `ProtoWallet`'s error with the
Peer's error. The premise was wrong: both pinned TypeScript references
already propagate `Signature is not valid` from `ProtoWallet.verifySignature`
for a signature made by another key. Neither `processGeneralMessage` nor
the incoming-message dispatcher catches that rejection. The Peer throws
`Invalid signature in generalMessage from <identityKey>` only when its
wallet **returns** `{ valid: false }`. Rust already preserves that distinction;
no runtime behavior or public API changes in this entry.

`tests/auth_peer_general_message_words_407.rs` pins both paths on `start`
and `start_server`, no listener called on either refusal, an honest message,
and an unrelated wallet error propagated unchanged. Its fixture is recorded
by `tests/support/auth_peer_general_message_words_407.mjs` from the actual
Peers in `ts-stack@edf6e03` and `ts-sdk@9e3ede6b`, built from those commits
and run under Node v22.18.0. The recorder runs an honest handshake before
each message and records both `ProtoWallet` and an explicitly adapting wallet
that returns `false` on a verification error. Rust reconstructs the messages
with its own nonce writer, as #353's witness does, because the nonce HMAC
inputs differ. These parity tests are already green on the base; the two
proposed replacement expectations are red there, not evidence of a parity fix.

Downstream old / proposed new (replacement **not applied**): `wallet error: Signature is not valid` / `authentication error: Invalid signature in generalMessage from <identityKey>`.

Line for the toolbox's operator-visible table: `| Bad signature in a certifier's general answer (ProtoWallet) | wallet error: Signature is not valid | Unchanged; a wallet returning valid: false instead produces authentication error: Invalid signature in generalMessage from <identityKey>. |`

### Notes: cross-SDK parity

The Peer's own words interpolate the established session identity string
directly (`ts-stack` `Peer.ts:1286-1304`), the compressed public-key hex in
these witnesses (66 lowercase characters, no `0x`). The wallet call has no
catch (`:1292-1301`), and neither does its dispatcher (`:766-800`). Both
reference `ProtoWallet`s throw `Signature is not valid` with code
`ERR_INVALID_SIGNATURE`; they do not return `false` for a non-verifying
signature (`ts-stack` `ProtoWallet.ts:358-396`, `ts-sdk` `:267-302`).

Unparseable bytes are a different refusal, also propagated: `ts-stack`'s
wallet validation throws `The signature parameter must be a canonical
DER-encoded ECDSA signature` (code 6, `validationHelpers.ts:1795-1802`),
while `ts-sdk`'s parser throws `Signature DER must start with 0x30` for the
recorded bytes. Rust retains its existing `InvalidSignature` parser error,
`invalid signature: Expected sequence tag 0x30`; that wording difference is
recorded, not normalized into a false verification result. Go at `2ca481c`
parses first (`auth/peer.go:1013-1017`, `failed to parse signature`), then
classifies a wallet's `ErrInvalidSignature` or `Valid: false` as
`general message - invalid-signature` (`:414-435`, `:1036-1038`), wrapping
other wallet errors separately. Its classification is not the TypeScript
Peer's propagation rule.
### Fixed: the HTTP auth transport's handshake, JSON, certificate-header and redirect refusals use the reference's words (#410)

The four changes cover three operator-visible refusals whose words differed
from `SimplifiedFetchTransport` at `ts-stack@edf6e03`, found by the toolbox's
#315 review, and one silently accepted header: a non-2xx
handshake used `Auth endpoint returned ...`, malformed handshake JSON used
`Failed to parse auth response: ...`, and a redirect used `redirect refused:
...`; a malformed `x-bsv-auth-requested-certificates` header was discarded.
Downstreams match these texts. The owner's ruling (c) requires the
reference's words, including its status description, URL, header message
and body preview.

The handshake now shares #354's status/preview formatter, passing the
reference's empty missing-header list: `response lacked required BSV auth
headers`, even if some or all headers are present. The HTTP status is read
before the body and still selects #87's fault class. Malformed JSON uses Node
22's unwrapped syntax diagnostic; an iterative scanner runs only after
serde refuses, with pending states proportional to input depth, no fixed
depth cutoff, and a 20-UTF-16-unit context,
and constructs no JSON value. A malformed `x-bsv-auth-requested-certificates`
header uses the reference's separate wrapper and syntax cause; previously
this crate silently dropped it. The header is parsed on every general
response, not only one labelled `certificateRequest`, as in the reference.
Redirect refusals on both paths use Node 22's outer fetch wrapper, and still
never replay a request with the default client.

Pinned by `tests/auth_transport_refusal_words_410.rs` (12 tests): six tests RED on a
scratch copy of `7257d73dcc258643f64b63e296d9b3bc0bcfa624`, with its own
target directory (404, malformed body, malformed header, 307, fault classes,
and the syntax replay); the seventh pins the existing typed refusal of
well-formed non-auth JSON. Two more tests, at depth 127 and 200, are RED on
both that base and `aaa6b79f` (the latter 2 failed, 10 passed; the base
8 failed, 4 passed). Three tests now pin #416's conforming response mappings,
replacing the original divergence assertions.
`auth_transport_refusal_words_410.json` is the
unmodified output of `tests/support/auth_transport_refusal_words_410.mjs`
under Node 22.18.0 / undici 6.21.2, 75 cases per reference: six statuses, 57
JSON syntax errors (empty/truncated JSON, numbers, keys, escapes, Unicode
positions, context cuts, BOM, and four array/object cases at each of depths
127 and 200), six malformed headers (empty and Latin-1 values included),
two redirects, the valid JSON shape difference, and the three mappings below.
Both SDKs were bundled from their
clone's pinned commit. The recorder uses fake fetch and, for redirects,
Node's native fetch with a network-disabled MockAgent; no listening socket.
The Rust replay uses wiremock's ephemeral ports. The #320 and #87 tests now
assert the new texts; #354's general-response fixtures are unchanged.

Migration for callers matching the error payload (the existing
`authentication error: ` / `transport fault ...: ` display prefixes remain).
The four old/new pairs, on the recorded bodies `not found` and `not auth`,
are together here; `{url}` is the configured origin:

```text
404 old: Auth endpoint returned 404 Not Found: not found
404 new: Received HTTP 404 Not Found from {url}/.well-known/auth without valid BSV authentication (response lacked required BSV auth headers) - body preview: not found
200 old: Failed to parse auth response: expected ident at line 1 column 2 - body: not auth
200 new: Unexpected token 'o', "not auth" is not valid JSON
307 old: Network error while sending authenticated request to {url}/.well-known/auth: redirect refused: 307 Temporary Redirect
307 new: Network error while sending authenticated request to {url}/.well-known/auth: fetch failed
header old: accepted, malformed certificate-request header silently dropped
header new: Failed to parse x-bsv-auth-requested-certificates returned by {url}/sendMessage: not auth. Unexpected token 'o', "not auth" is not valid JSON
```

Line for the toolbox's `src/wallet/CLAUDE.md` matching table (that checkout
is not changed by this commit):

| bsv-rs #410 | `Auth endpoint returned ...` → `Received HTTP ... without valid BSV authentication (response lacked required BSV auth headers)` plus optional body preview; `Failed to parse auth response: ...` for malformed JSON → Node 22's unwrapped syntax error; `redirect refused: 307 Temporary Redirect` → `fetch failed` within the same URL wrapper; malformed certificate header → `Failed to parse x-bsv-auth-requested-certificates returned by {url}: {value}. {syntax cause}` |

### Notes: cross-SDK parity (#410)

The full paths were read at both pins. At `ts-stack@edf6e03`, the handshake
fetch sets `redirect: 'error'` (`SimplifiedFetchTransport.ts:115-173`), a
non-2xx calls `#createUnauthenticatedResponseError` with no missing-header
list (`:143-151`, `:464-494`), and the body uses unwrapped `JSON.parse`
(`:158-162`). The general fetch also refuses redirects (`:206-218`); the
certificate header's wrapper is separate (`:234-258`, `:496-510`). Node
22.18.0 measured the outer redirect text as `Network error while sending
authenticated request to {url}: fetch failed`, with causes `TypeError:
fetch failed` then `Error: unexpected redirect`. Rust matches the outer
payload byte for byte and keeps `AuthError` with no transport fault; it has
no equivalent JS stack/cause chain. A caller-supplied reqwest client that
follows redirects still follows before the transport can refuse (#320).

Node 22.18.0's `JSON.parse` accepts valid arrays and objects at depth 127,
128, 200, 1,000, 10,000 and 100,000. The actual reference transport also
delivers them. It delivers a 1,048,575-byte array at depth 524,287 and a
1,048,573-byte object at depth 174,762; the next depth with a scalar exceeds
its default 1 MiB handshake-body limit and is refused for size, not nesting.
`JSON.parse` itself also accepts empty arrays nested 524,288 and 1,000,000
deep (1 MiB and 2,000,000 bytes): no parser cutoff was reached. Rust's
diagnostic scanner therefore has no fixed nesting bound or recursive call
stack. Its pending states are bounded by input length. Since #416, Rust applies the same configurable 1 MiB handshake-body
default, including before the syntax scanner.

The saved review probe (`diff_flat.mjs`, 40,000 generated cases plus 48 depth
cases with each seed 3 and 99) now matches 80,087 of 80,096 inputs. All nine
remaining inputs are valid numbers outside finite double range:
`86e427`, `29E390`, `40e663`, `4e10382`, `5e624`, `2e8332`, `56e955`,
`44e360`, `7e515` (some with surrounding whitespace). V8 reads each as
`Infinity`; serde refuses it with `number out of range`. The saved corpus
reproduces 71 differences before this fold, not the review summary's 86;
62 depth-related differences are removed. The exact 86-input run was not
available for replay.

The three response mappings originally documented here are conforming since
#416: the 262,144-byte certificate-header bound, the bounded even-length
hex signature, and preservation of `certificateRequest`. The three tests
in `auth_transport_refusal_words_410.rs` now assert those outcomes against
the same recorded vectors. The older pin still accepts an oversized
certificate header and uses `Invalid hex string` for `MAA=`; both pins keep
`certificateRequest`. See #416 for the full bound set and migration block.

`ts-sdk@9e3ede6b` agrees on status, body and header texts (`:55-93`,
`:163-170`, `:252-307`), but does not set a redirect option (`:58-64`,
`:141-145`): the recorded 307 follows and reaches its callback. This crate
follows the newer pin's refusal. Both references pass syntactically valid
JSON such as `{"ok":true}` to their callback, where this crate's typed
`AuthMessage` refuses it in its existing serde words. A syntactically valid
certificate header outside `RequestedCertificateSet`'s shape is refused
with the header wrapper and serde's cause; the reference only casts its
parsed value and passes it to the callback. Other typed shape and
lone-surrogate refusals remain serde's; only the diagnostic scanner's
artificial cutoff is removed. Node's syntax wording is runtime
specific, pinned here to 22.18.0. A lone surrogate left by a diagnostic's
context cut is recorded as U+FFFD, its UTF-8 wire representation, as in
#354. The existing non-ASCII HTTP reason-phrase difference of #354 remains.

The Go pin is `2ca481c5931b987a0c8f48bb341c70b7477b6b07`; its file is
`auth/transports/simplified_http_transport.go` (there is no
`auth/transports/http.go` at this pin). It wraps a non-2xx handshake in
`HTTP server failed to authenticate` (`ErrHTTPServerFailedToAuthenticate`)
and `request failed with status %d: %s`
(`:102-130`), malformed bodies in `failed to unmarshal authmessage from body
(%q): %w` (`:141-152`) and a bad certificate header in `invalid format of
requested certificates in response: %w` (`:220-227`). Its default
`http.Client{}` and supplied client use their own redirect policy
(`:31-44`, `:111`, `:175`); no `CheckRedirect` is installed. Those Go words
and policy are not the TypeScript reference's.

### Fixed: the default mode refuses a numeric shift's count above `INT_MAX` as the reference does, a verdict before the value is read; the eight crash inputs confirmed closed (#383)

The finding (#331's fourth fold's cold re-review, at `bb80a525`): five
`fuzz_script_spend` crashes on beta independent of #331, the numeric shifts'
overflow refusal writing the count in decimal into its text (`splice.rs`,
then `:262-263` and `:275-276`), and no refusal of a shift count above
`INT_MAX` in the default mode, where the reference refuses one: `1 <2^31>
OP_RSHIFTNUM` was 0 here, a valid spend, and invalid in the reference.

The crash inputs, eight (the six kept under
`/Volumes/Lanes/out/bsv-rs/fix-331-fold5/fuzz/pre-existing/` and two of the
fifth fold's re-review, `27c51236…` and `e36fe93d…`), each run at `-runs=1`
through the target's counting allocator on `bb80a525`, `b744f4b6` (beta.2,
#331 landed) and `949f2782` (#348, #349 landed) under one bound, the base's
(a single request at most twice the 1 MiB budget, at most ten budgets live,
the input's term added, a reservation left out): none crashes on
`949f2782` or on the tip, and nothing in this change was needed for them.

- `e91f18e1…`, `ed740084…`, `e36fe93d…` (the shift's refusal) and
  `27c51236…` (`OP_NUM2BIN`'s): one request of 2,900,134, 2,525,294,
  2,525,296 and 2,382,952 bytes at `bb80a525` and at `b744f4b6`, the count's
  or the size's decimal text; 602,128, 524,304, 524,304 and 494,744 at
  `949f2782` (the operand itself, charged), closed by #349's `number_text`
  (`a shift by a 602113-byte number bits`).
- `44d4c72f…`, `4914d789…`, `d44dc981…` (`OP_NUM2BIN`'s refusal): 5,473,403,
  4,442,360 and 5,335,707 bytes live at `bb80a525`, past that target's live
  bound of four budgets, 5,141,890, 4,442,360 and 5,325,288 at `b744f4b6`;
  1,730,212, 1,022,688 and 1,484,734 at `949f2782`, closed by #349's
  `number_text` (the size's 1.2 to 1.6 MB of decimal gone), under four
  budgets too.
- `3c8497a5…`: 4,696,294 bytes live at `bb80a525`, past four budgets;
  4,068,812 at `b744f4b6` and since, under it, with the step probe's
  3,941,802-byte reservation (#374), which the target leaves out since #331:
  closed by #331.

All eight are in `fuzz/corpus/fuzz_script_spend/` under their sha1 (no
key-shaped bytes; `gitleaks` clean). The target runs under a word only, so
the default mode's change below is outside its reach.

The count: the reference reads it, refuses a negative one, then refuses one
above `INT_MAX` before it reads the value (`ts-stack@edf6e03`
`Spend.ts:1058-1060`, `1084-1086`: `OP_LSHIFTNUM shift count exceeds
INT_MAX.`, `OP_RSHIFTNUM shift count exceeds INT_MAX.`; run under Node
22.18.0 on counts of 2^31, 2^34, 2^64 and a 100-byte number, on values 1, 0
and -1). The default mode now does the same, in its words, a verdict and
never a decline (the owner's ruling (c)): no shift is sized, so a caller's
budget no longer declines `1 <2^31> OP_LSHIFTNUM` (a 268 MB result) and V8's
`Maximum BigInt size exceeded` is no longer this case's words; `1 <INT_MAX>
OP_RSHIFTNUM` stays valid and `1 <INT_MAX> OP_LSHIFTNUM` keeps the `BigInt`
words, as the reference. Under a word nothing moves: the node refuses the
count in `bint::operator<<=` and `operator>>=` (`big_int.cpp:359-369`,
`383-393` at v1.2.2, `879fc8b`), after the value's read
(`interpreter.cpp:716-719`, `752-755`) and a left shift's size test
(`script_num.cpp:305-308`), `SCRIPT_ERR_BIG_INT` (`interpreter.cpp:1819-1821`),
which this crate's word path already applied there
(`OP_RSHIFTNUM count (2147483648) does not fit an int.`).

Pinned by `tests/script_shift_count_int_max_383.rs` (seven tests, four red on
`949f2782`: the right shift by 2^31 valid, the left shift in the `BigInt`
words and its zero value valid, a decline under a budget, a 9-byte and a
100-byte count; the seventh, the cold review's, pins the order: a count
above `INT_MAX` on a 67,108,863-byte value, which the default mode cannot
read (`Invalid string length` with a count of 1), refused in the count's
words, red on the tip with the check moved after the value's read, where
the other six stay green), and three default-mode rows of
`tests/script_shift_count_witness.rs` that pinned the old reading moved to
the reference's (the witness, `1 OP_RSHIFTNUM 2147483648`, was `Ok(true)`;
`INT_MAX + 1` under a caller's 32,000,000 bytes a decline; the zero value's
two shifts `Ok(true)`), its word rows unchanged. Two pins of #331 met a count
above `INT_MAX` and move with it, the shift still refused before it
allocates: `tests/transaction_verify_budget_331.rs`'s left shift by 2^40
(the 1 GiB element bound uncapped, a decline under 32,000,000 bytes; now the
count's verdict under both) and the by-hand left shift by 2^33 + 8 in
`tests/script_default_mode_uncapped_331.rs`. The element bound stays at the
shift's site but is out of its reach in the default mode: a readable value
(536,870,888 bits) shifted by `INT_MAX` is 335 MB, below the 1 GiB bound, so
the bound (which runs before the shift's refusal at `splice.rs:332`) never
trips, and V8's `BigInt` cap refuses the result past 2^30 bits; the word
branch never reaches it. No test pins it (none can reach it); a comment at
`splice.rs:327` says so.
### Fixed: the default mode reads the splice operands as the reference does: a substring operand past 8 bytes by its first 8, every one clamped to the `int` range, and `OP_NUM2BIN`'s size refused in the reference's words (#382)

The #331 third fold's cold re-review noted that this crate read a splice
operand with a wider reader than the reference's. The reference's default
mode (`ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts`, no
`verifyFlags`; each outcome below its `Spend.validate()` under Node 22.18.0
on the bundle of that commit) reads the three substring opcodes' operands
with `#readSpliceOperand` (`:540-561`), not `#readScriptNumber`: no length
bound (`#scriptNumMaxSize()` is `undefined` without flags), the
minimal-encoding check when MINIMALDATA holds (version 1; `non-minimally
encoded script number`), an operand of at most 8 bytes read as a script
number, a longer one read as its first 8 bytes in two's complement
(`BigInt.asIntN(64, ..)`), the bytes after the eighth never read, and the
value clamped to `[-2^31, 2^31 - 1]`. This crate read every byte of a longer
operand as a sign-magnitude number (one past an `i64` as -1) and clamped
nothing, so a 9-byte operand was a verdict here where it is a reading
there, and the reverse:

| Script (version 2) | The reference | This crate before | After |
|---|---|---|---|
| `aabbcc <02 00×7 01> OP_LEFT <aabb> OP_EQUAL` | `ok true` | `OP_LEFT length (-1) must be in range [0, 3]` | `ok true` |
| `aabbcc <02 00×7 80> OP_LEFT <aabb> OP_EQUAL` | `ok true` | `OP_LEFT length (-2) ...` | `ok true` |
| `aabbcc <fe ff×7 01> OP_LEFT` | `OP_LEFT length (-2) ...` | `OP_LEFT length (-1) ...` | the reference's |
| `aabbcc <02 00×6 01> OP_LEFT` (8 bytes) | `OP_LEFT length (2147483647) ...` | `OP_LEFT length (72057594037927938) ...` | the reference's |
| `aabbcc <01 00×7 01> <01 00×7 01> OP_SUBSTR <bb> OP_EQUAL` | `ok true` | the range refusal at -1 | `ok true` |
| the 0.3.33 witness, `<04 00×7 80>` as `OP_SUBSTR`'s offset | `ok true` | the range refusal at -4 | `ok true` |

`OP_SPLIT`'s position is read whole by the reference (`#readScriptNumber`,
`:1913`), as here: a 9-byte and an 8-byte position are the same range
refusal on both sides, unchanged. `OP_NUM2BIN`'s size is read whole too
(`:1930`); its refusals are now the reference's words in its order
(`:1931-1950`): a negative size `It's not currently possible to push data
larger than Infinity bytes or negative size.` (its push size unbounded
without flags), a size above `INT32_MAX` `OP_NUM2BIN size exceeds the node
int32 push limit.`, then a size above a caller's budget the `element-size`
decline, where this crate gave its 1 GiB bound's sentence for all three and
checked the bound before the budget; the 1 GiB bound stays last, a refusal
the reference does not make (its `Array.from` of `2^31 - 1` elements aborts
the process, `FATAL ERROR: invalid table size Allocation failed`).
`OP_BIN2NUM` reads no number; unchanged, as the reference's.

Under a word nothing moves: the operands follow the node's checked `int64`
reading of 0.3.33 (bsv-rs#41, `int_serialization.h:61-118`), whose pins hold.

Pinned by `tests/script_splice_position_reader_382.rs` (16): per site the
longest operand the reference reads as a number (8 bytes) clamped, a 9-byte
one read by its first 8 bytes (two's complement, non-minimal without
MINIMALDATA, refused with it), a 100-byte operand whose later bytes are never
read, `OP_SPLIT`'s whole reading, `OP_NUM2BIN`'s three refusals, and the block
word's reading beside them. Red 13 of 16 on a scratch copy of `1791d2f8`
(every `issue_382_` test; the three guards green on both). Four default-mode
pins moved to the reference's outcomes: `script_int64_operand_witness.rs`
(the witness and the `OP_LEFT`/`OP_RIGHT` cases, each `ok true` in the
reference, until now read as -4 here; the test renamed
`the_witness_is_valid_in_the_default_mode`) and
`script_stack_memory_witness.rs` (the default mode's 2^31 and -1 sizes).
The conformance census holds (`BSV_CONFORMANCE_DIR`: 2,834 passed, 17 known
failures, 2,228 unsupported, as pinned).

The cold review's finding (PR #396): the minimal-encoding check of an
operand past 8 bytes decoded the whole operand (`ScriptNum::from_bytes`, a
`BigUint` of its bytes, with no #374 room check) where its comment said it
copied nothing. It is now judged from the operand's last two bytes
(`ScriptNum::is_minimally_encoded`), the decoder called only for the
refusal's words, so a minimal operand is read by its first 8 bytes alone.
Pinned by `tests/memory_profiling.rs`'s
`test_issue_382_a_minimal_splice_operand_is_not_decoded` (`dhat`): a
64 MiB (67,108,864-byte) minimal `OP_LEFT` length at version 1 peaks at
67,108,963 bytes (its one copy onto the stack), 134,217,827 on a scratch
copy without the guard (the operand was 800,000,000 bytes until #401,
800,000,099 and 1,600,000,099).

Migration: none in the API. A caller matching the default mode's
`OP_NUM2BIN` text for a size above `INT32_MAX` or below 0 reads the
reference's now.

### Notes: cross-SDK parity (#382)

The 0.3.33 row ("the default mode retains the TypeScript SDK's unrestricted
number reader") is corrected: the default mode reads the substring operands
as the reference's `#readSpliceOperand`. Under explicit flags the reference
uses the same reader (the era's length bound first), so a 10-byte operand is
its first 8 bytes there and `Script number overflow: operand does not fit
int64.` under this crate's word, the node's reading (`int_serialization.h`):
the reference against the node, not followed. Two differences this lane
found and did not change: a non-minimal operand under MINIMALDATA is refused
in this crate's reader's words at every number site (`Invalid script number:
script execution error: Non-minimally encoded script number`, the
reference's `non-minimally encoded script number`); and at version 1 the
reference's default mode runs `0xb3`-`0xb7` as the Chronicle opcodes (its
skip applies under explicit flags alone, `Spend.ts:827-848`), where this
crate's default runs them as `OP_NOP4`-`OP_NOP8` unless the coin is marked
post-Chronicle (`aabbcc <02 00×7 01> OP_LEFT <aabb> OP_EQUAL` at version 1:
`ok true` there, a refusal here). Both are #397, with the keeper's word (the opcode gate and the words follow the reference's default; the cross-SDK filing ts-stack #1437).
### Fixed: the default mode refuses a numeric shift's count above `INT_MAX` as the reference does, a verdict before the value is read; the eight crash inputs confirmed closed (#383)

The finding (#331's fourth fold's cold re-review, at `bb80a525`): five
`fuzz_script_spend` crashes on beta independent of #331, the numeric shifts'
overflow refusal writing the count in decimal into its text (`splice.rs`,
then `:262-263` and `:275-276`), and no refusal of a shift count above
`INT_MAX` in the default mode, where the reference refuses one: `1 <2^31>
OP_RSHIFTNUM` was 0 here, a valid spend, and invalid in the reference.

The crash inputs, eight (the six kept under
`/Volumes/Lanes/out/bsv-rs/fix-331-fold5/fuzz/pre-existing/` and two of the
fifth fold's re-review, `27c51236…` and `e36fe93d…`), each run at `-runs=1`
through the target's counting allocator on `bb80a525`, `b744f4b6` (beta.2,
#331 landed) and `949f2782` (#348, #349 landed) under one bound, the base's
(a single request at most twice the 1 MiB budget, at most ten budgets live,
the input's term added, a reservation left out): none crashes on
`949f2782` or on the tip, and nothing in this change was needed for them.

- `e91f18e1…`, `ed740084…`, `e36fe93d…` (the shift's refusal) and
  `27c51236…` (`OP_NUM2BIN`'s): one request of 2,900,134, 2,525,294,
  2,525,296 and 2,382,952 bytes at `bb80a525` and at `b744f4b6`, the count's
  or the size's decimal text; 602,128, 524,304, 524,304 and 494,744 at
  `949f2782` (the operand itself, charged), closed by #349's `number_text`
  (`a shift by a 602113-byte number bits`).
- `44d4c72f…`, `4914d789…`, `d44dc981…` (`OP_NUM2BIN`'s refusal): 5,473,403,
  4,442,360 and 5,335,707 bytes live at `bb80a525`, past that target's live
  bound of four budgets, 5,141,890, 4,442,360 and 5,325,288 at `b744f4b6`;
  1,730,212, 1,022,688 and 1,484,734 at `949f2782`, closed by #349's
  `number_text` (the size's 1.2 to 1.6 MB of decimal gone), under four
  budgets too.
- `3c8497a5…`: 4,696,294 bytes live at `bb80a525`, past four budgets;
  4,068,812 at `b744f4b6` and since, under it, with the step probe's
  3,941,802-byte reservation (#374), which the target leaves out since #331:
  closed by #331.

All eight are in `fuzz/corpus/fuzz_script_spend/` under their sha1 (no
key-shaped bytes; `gitleaks` clean). The target runs under a word only, so
the default mode's change below is outside its reach.

The count: the reference reads it, refuses a negative one, then refuses one
above `INT_MAX` before it reads the value (`ts-stack@edf6e03`
`Spend.ts:1058-1060`, `1084-1086`: `OP_LSHIFTNUM shift count exceeds
INT_MAX.`, `OP_RSHIFTNUM shift count exceeds INT_MAX.`; run under Node
22.18.0 on counts of 2^31, 2^34, 2^64 and a 100-byte number, on values 1, 0
and -1). The default mode now does the same, in its words, a verdict and
never a decline (the owner's ruling (c)): no shift is sized, so a caller's
budget no longer declines `1 <2^31> OP_LSHIFTNUM` (a 268 MB result) and V8's
`Maximum BigInt size exceeded` is no longer this case's words; `1 <INT_MAX>
OP_RSHIFTNUM` stays valid and `1 <INT_MAX> OP_LSHIFTNUM` keeps the `BigInt`
words, as the reference. Under a word nothing moves: the node refuses the
count in `bint::operator<<=` and `operator>>=` (`big_int.cpp:359-369`,
`383-393` at v1.2.2, `879fc8b`), after the value's read
(`interpreter.cpp:716-719`, `752-755`) and a left shift's size test
(`script_num.cpp:305-308`), `SCRIPT_ERR_BIG_INT` (`interpreter.cpp:1819-1821`),
which this crate's word path already applied there
(`OP_RSHIFTNUM count (2147483648) does not fit an int.`).

Pinned by `tests/script_shift_count_int_max_383.rs` (seven tests, four red on
`949f2782`: the right shift by 2^31 valid, the left shift in the `BigInt`
words and its zero value valid, a decline under a budget, a 9-byte and a
100-byte count; the seventh, the cold review's, pins the order: a count
above `INT_MAX` on a 67,108,863-byte value, which the default mode cannot
read (`Invalid string length` with a count of 1), refused in the count's
words, red on the tip with the check moved after the value's read, where
the other six stay green), and three default-mode rows of
`tests/script_shift_count_witness.rs` that pinned the old reading moved to
the reference's (the witness, `1 OP_RSHIFTNUM 2147483648`, was `Ok(true)`;
`INT_MAX + 1` under a caller's 32,000,000 bytes a decline; the zero value's
two shifts `Ok(true)`), its word rows unchanged. Two pins of #331 met a count
above `INT_MAX` and move with it, the shift still refused before it
allocates: `tests/transaction_verify_budget_331.rs`'s left shift by 2^40
(the 1 GiB element bound uncapped, a decline under 32,000,000 bytes; now the
count's verdict under both) and the by-hand left shift by 2^33 + 8 in
`tests/script_default_mode_uncapped_331.rs`. The element bound stays at the
shift's site but is out of its reach in the default mode: a readable value
(536,870,888 bits) shifted by `INT_MAX` is 335 MB, below the 1 GiB bound, so
the bound (which runs before the shift's refusal at `splice.rs:332`) never
trips, and V8's `BigInt` cap refuses the result past 2^30 bits; the word
branch never reaches it. No test pins it (none can reach it); a comment at
`splice.rs:327` says so.
### Changed: the wallet types' certificate field and keyring maps keep insertion order, the reference's `Object.keys` order, as `RequestedCertificateSet::types` does since #288 (#385)

The toolbox's #311 lane (toolbox PR #375, divergence row D12) found that of
several bad field names a direct acquire named the lowest-sorting one, where
the reference names the first given: the reference walks a certificate's
fields and a keyring in `Object.keys` order (`ts-stack@edf6e03`
`packages/sdk/src/wallet/validationHelpers.ts:1236`, `:1254`), its
`Record`s holding insertion order (`Wallet.interfaces.ts`), and this crate's
maps were `HashMap<String, String>`, which hold none whatever order the JSON
or the wire gave. The keeper's reading (2026-10-28 00:5xZ): an
insertion-ordered map is the reference's own field type in Rust, so under the
owner's ruling (c) and the keeper's reading of 2026-10-26 on #288 it needs
no new word.

The nine maps of `src/wallet/types.rs` are `indexmap::IndexMap<String,
String>`: `Certificate.fields`, `WalletCertificate.fields`,
`AcquireCertificateArgs.fields` and `.keyring_for_subject`,
`CertificateResult.keyring`, `ProveCertificateResult.keyring_for_verifier`,
`IdentityCertificate.publicly_revealed_keyring` and `.decrypted_fields`,
`DiscoverByAttributesArgs.attributes`. `indexmap` (2, `serde`) moves from
`auth` to `wallet`; `auth` has it through `wallet`, and the wasm32 slice
builds. Serde reads and writes them in the text's order. The walks:

- `wallet::validation` (1): `validate_certificate_fields` takes and returns
  the `IndexMap` and refuses the first bad name given.
- `wallet::wire` (9): `WireWriter::write_string_map` writes the map's order,
  the reference's `Object.entries` (`WalletWireTransceiver.ts:1389`,
  `:1583`, `:1815`; `WalletWireProcessor.ts:2542`), where it sorted keys as
  go-sdk does; `write_identity_certificate`'s public keyring the same
  (`#recordEntries`, `WalletWireProcessor.ts:2523`), where it sorted;
  `read_string_map`, `read_optional_string_map`, the strict record readers
  (`read_counted_wire_record`, the discovery maps, `read_certificate_fields`)
  and the transceiver's proveCertificate keyring read in the order the bytes
  arrive; acquireCertificate's `keyring_for_subject`, written in the
  `HashMap`'s iteration order before, is written in the map's
  (`WalletWireTransceiver.ts:1416`). The certificate frame keeps the signed
  order (`checked_field_names`, below); its bound checks (each name's length
  and safety, then its value's 1 MiB) walk the map's order, so of two bad
  names it refuses the first given, as the reference's
  `snapshotCertificateFields` walks `Reflect.ownKeys` before `toBinary`
  sorts (`Certificate.ts:56-83`, `:281-282`), where it judged them in the
  sorted order (the review's finding).
- `identity` (2): `publicly_reveal_attributes` judges and publishes the
  wallet's keyring in the wallet's key order (`IdentityClient.ts:485`,
  `:492-499`), where it used the order of the names asked, so of two values
  it refuses it names the wallet's first; the identity token's JSON writes
  the certificate's fields in the order held (`:502`), where it wrote them by
  name.
- `auth` (2): `Certificate::to_wallet_certificate` writes the fields in the
  signed order (`auth::Certificate.fields` stays a `HashMap`, below);
  `get_verifiable_certificates` converts at the boundary.
- `kvstore`, `registry`: none touches these maps (the local store's test
  wallet only names the argument types).

The signer is the one walk that does not follow the map, here as in the
reference: `Certificate.toBinary` sorts the names by `localeCompare`
(`Certificate.ts:282`) and signs and verifies that preimage, so the
signature is the same whatever order the fields were given in (the issue's
"signs in that order" is the validators' walk, not the signer's). This
crate's signer and `write_wallet_certificate` keep that order (#246, #249).

Pinned by `tests/wallet_certificate_field_order_385.rs` (9): 26 field names
over 50 bytes, longest first, refused at the first (76 bytes); a reveal whose
wallet answers two bad keyring values, `name` then `email`, for names asked
`email` then `name`, refused naming `keyringForVerifier.name`; the identity
token's JSON with the fields and keyring in their order (`name` first) and
the #307 vector's certifier signature verifying; twelve names given out of
order signed, the wallet's frame the sorted preimage `Certificate::to_binary`
signs (`alpha, bravo, ..., Kilo, Mike, name, role, x9, zeta`), verifying when
read back; each of the nine maps read from JSON text in its order and
written back in it; acquireCertificate's request writing the fields and
keyring in order; a proveCertificate keyring read in arrival order; a
discovery entry's maps written and read in order, the certificate's fields
crossing in the signed order; the wallet's certificate writer given a
51-byte name then a 52-byte one, which sorts first, refused naming the
51-byte one. The signer's order is pinned from the code's
reading (`Certificate.ts:282-284`) and the reference-recorded #249 vector
(`auth_certificate_field_order_249.json`), no new recording. The first
eight red 8 of 8 on a scratch copy of `1791d2f8` with the file added (three
runs); the signer test red there only at its map-order assertion, its
preimage half green without it. The writer's test red on a scratch copy of
`63d3e858` (the refusal named the 52-byte name), green after.
`tests/wire_identity_certificate_writer.rs` pinned the discovery maps in
go-sdk's sorted order as the reference's; its expected bytes are now the
reference's order. The golden fixtures (`tests/fixtures/{wire,http_json}`)
did not move: every recorded map of two or more keys is already in byte
order (`name`, `role`; the recorder wrote them through `serde_json::Value`,
which sorts keys in this build) and every certificate carries one field, so
insertion order reads them unchanged; `fixtures_replay` green, nothing
re-recorded.

Migration: a struct literal that built a `HashMap` builds an `IndexMap`
(`[(k, v)].into_iter().collect()` compiles unchanged, `IndexMap::from([...])`
for `HashMap::from([...])`); code that reads a map with the map API compiles
as it is and now gets order; `validate_certificate_fields`,
`WireReader::read_string_map`, `read_optional_string_map` and
`WireWriter::write_string_map` take or return the `IndexMap`. This crate
does not re-export `indexmap`: a downstream that names the type adds
`indexmap = "2"` to its own manifest, or builds the map with `collect()`
from pairs and names no type. `IndexMap`'s
`==` ignores order, as `HashMap`'s does. Downstreams that build these maps:
the toolbox (its re-pin flips D12) and any wallet over `WalletInterface`'s
certificate calls.

Semver: nine public field types and four public signatures change, under
the keeper's reading carried by (c). `cargo semver-checks --release-type
minor --baseline-rev 1791d2f8 --all-features` passes 202 checks and names
nothing: it has no lint for a changed field or parameter type, so the pass
is not evidence; the change is this entry's. Ratchet: every counter at or
below `docs/ratchets.json` (`tools/ratchet/run --check --against
origin/beta`), four files at their bound kept there (`types.rs` names
`indexmap::IndexMap` in place, one comment line each); not re-recorded.

### Notes: cross-SDK parity (#385)

A JavaScript object moves an integer-like key (`"1"`, `"42"`) ahead of the
others in ascending order, so the reference's `Object.keys` walks a field
named `"7"` first whatever its place; `IndexMap` keeps it where it was given.
`validateCertificateFields` refuses no integer-like name (1 to 50 bytes is
its rule), so on such a certificate the first name refused, the keyring's
judged and published order and the wire maps' bytes differ from the
reference's; on every other certificate they are the same. go-sdk@2ca481c
holds every map as `map[string]string` and orders none: its wire writer
sorts the keys (`WriteStringMap`, `util/writer.go:247-258`;
acquireCertificate's keyring, `wallet/serializer/acquire_certificate.go:67-71`) and its certificate frame
sorts the field names by bytes (`sort.Strings`,
`wallet/serializer/certificate.go:42-49`), so a frame with unsorted maps that
this crate or the reference writes differs from Go's bytes. Go's readers
require no order. The Go wire vectors carry maps already sorted and still
pass. `auth::Certificate`, `MasterCertificate`, `VerifiableCertificate` and
`identity::IdentityCertificate` keep `HashMap` fields and keyrings: their
signer sorts and their JSON is #268's (a follow-up decides whether they move
too); a wallet certificate converted from one takes the signed order. (#394,
above, moves them.)

### Fixed: internalizeAction judges an output's protocol and its one remittance before the remittances' fields, as the reference orders it (#384)

`wallet::validation::validate_internalize_action_args` read each output's
`insertionRemittance.customInstructions` without reading which remittances
the output carried, so a wallet payment that also carried an over-long
insertion remittance was refused in the customInstructions words, where the
reference refuses it for carrying the other remittance. The toolbox's #337
lane, which ported the reference's one-remittance check at its own
internalize door, found it (filed as #384). Each output is now judged in the
reference's `validateInternalizeOutput` order (`ts-stack@edf6e03`
`packages/sdk/src/wallet/validationHelpers.ts:966-984`):

1. the protocol (`:968-970`): neither `wallet payment` nor `basket
   insertion` is refused, `The protocol parameter must be 'basket
   insertion' or 'wallet payment'`;
2. the one remittance (`:971-977`): a wallet payment without a
   `paymentRemittance` or with an `insertionRemittance`, `The output
   remittance parameter must be only paymentRemittance for wallet
   payment`, and the twin, a basket insertion without an
   `insertionRemittance` or with a `paymentRemittance`, `The output
   remittance parameter must be only insertionRemittance for basket
   insertion`;
3. the remittances' fields (`:978-983`): the insertion's
   `customInstructions` at most 1,000 UTF-8 bytes in this crate's words as
   before (#117), `Invalid outputs[i].insertionRemittance.customInstructions:
   must be no more than 1000 bytes, got N`.

The first two are `Error::WalletRefusal` of class
`WalletRefusalClass::InvalidParameter` (`WERR_INVALID_PARAMETER`, code 6)
in the reference's words, which name no output index (`invalid`,
`:77-79`, and `WERR_INVALID_PARAMETER.ts:14`); output `i`'s checks all run
before output `i + 1`'s, as the reference's `map` runs them. Every door that
calls the validator answers so before it acts or sends: `ProtoWallet`,
`WalletClient`, `HttpWalletJson` and `WalletWireTransceiver` (whose writer's
own `payment_remittance required for wallet payment` is no longer reached,
and which no longer writes an empty insertion for a basket insertion without
one); the wire processor refuses internalizeAction as needing a full wallet
and calls no validator, its frame unchanged. No recorded fixture moves
(`fixtures_replay` green: every recorded output carries its own remittance
alone). Pinned by `tests/wallet_internalize_one_remittance_384.rs` (9
tests; 7 RED on the pre-fix tree, the two that pin the field checks still
reached green on both). No public shape changes; a caller whose output
carried both remittances, neither, or another protocol now gets the
refusal. The toolbox's door makes the same check (its #337): one verdict
across the two.

### Notes: cross-SDK parity (#384)

The reference's `validateInternalizeActionArgs` (`:1046-1074`) and the
remittance validators check more than this crate's validator does, and
little of it is ported here (the wire transceiver alone checks a payment
remittance's prefix and suffix as base64 and its sender key as hex when it
writes them, `transceiver.rs:825-833`): the output index a non-negative integer
(`:979`; a `u32` here by type), `derivationPrefix` and `derivationSuffix`
base64 and `senderIdentityKey` a public key (`validateWalletPayment`,
`:914-923`), the basket and the tags (`validateBasketInsertion`,
`:937-951`), `tx` an exactly framed Atomic BEEF, the description 5 to 2000
bytes, the labels, and at least one output (`:1050-1071`). go-sdk at
`2ca481c` has no internalizeAction argument validator: its writer refuses
an absent remittance in its own words (`payment remittance is required for
wallet payment protocol`, `wallet/serializer/internalize_action.go:29-30`;
`insertion remittance is required for basket insertion protocol`, `:38-39`)
and writes the protocol's remittance alone, dropping the other.

### Added: the streaming BEEF reader takes the caller's memory budget for its scripts, as `Transaction::verify` does since #331 (#373)

Since #331 `Transaction::verify` takes the caller's memory budget as the
reference's third parameter (`None` uncapped, `Some(n)` `n` bytes per
stack), while the streaming reader evaluated every unproven transaction's
inputs under `memory_limit: None` (`BeefIndex::check_spends_of`) and took no
budget from its caller: a door that reads untrusted BEEF could bound each
input's work (`set_work_limit`) and not its memory. The keeper's word
(2026-10-27 19:4xZ, under the owner's ruling (c)): "`verify_stream` takes
the same `memory_limit: Option<usize>` as `verify`, `None` uncapped, the
caller's budget per transaction; the streaming reader's own bound per
element is the charter's structural guarantee, not a cap on a script."

- `StreamVerifier::set_memory_limit(Option<usize>)` and
  `AsyncStreamVerifier::set_memory_limit(Option<usize>)`, beside
  `set_work_limit` and in its form: `None`, the default, uncapped, as
  `verify`'s `None`; `Some(n)` is `n` bytes per stack for every input the
  reading runs (a transaction read in order and one released from the held
  set alike), handed to `TxSpendParams::memory_limit` as given. An input
  past it is a decline, `Verdict::SpendRefused { offset, txid, input:
  Some(i), why: SpendRefusal::Resource(limit) }`: the transaction by its
  txid, the input, and the interpreter's `ScriptResourceLimit` (`Stack`,
  the budget, the bytes attempted), the stream's form of `verify`'s
  `Error::ScriptEvaluationDeclined { input_index, limit }`; never a verdict
  on the script, never an abort.
- Local configuration, as the work budget is: absent from the `Cursor`, set
  again after `StreamVerifier::resume` (a decoded cursor's included). The
  structure-only reader runs no script and spends none. The reader's own
  bound per element (the beef-of-any-size charter, NL-3) is untouched.
- `verify_stream`, `verify_stream_structure`, `verify_stream_two_pass`,
  `resume` and `verify_stream_async` keep their signatures: they take no
  work budget either, and a caller with a budget builds the reader
  (`StreamVerifier::new`, then `set_memory_limit`, then `run`). The two
  budgets travel as one value through the fold (`beef_stream/budget.rs`,
  where both setters now live).

Pinned by `tests/beef_stream_memory_budget_373.rs` (5): a version-2 spend
whose unlocking script pushes 600 bytes and whose locking script
duplicates them declines under `Some(1_000)` at 1,200 of 1,000 bytes,
naming the subject's txid and input 0, whether its script would be valid
or invalid, and is judged under `None` (valid, or the script's
`SpendRefusal::Script`) and under `Some(1_200)`; the structure-only reader
valid under `Some(1)`; a reader resumed before the subject declines with
the budget set after resumption and is uncapped without it; the
asynchronous reader the same decline. Red 3 of 5 on a scratch copy of
`b744f4b6` with the setter a no-op (the declines; the structure-only and
`None` tests pin what held).

Migration: none; additive. Consumers that pass one: the relay's submit door
(`rust-message-box@419bf18` `src/beef_door.rs:421-430` sets
`set_work_limit` after every construction, a resumed reader's included;
`set_memory_limit` goes beside it after its re-pin from `=0.4.5`) and the
watchtower.

Semver: two methods added; `cargo semver-checks` names nothing breaking.
Ratchet: `src/transaction/beef_stream.rs` shrinks from 3,605 lines to 3,597
(the two `set_work_limit` methods move to `beef_stream/budget.rs`); every
counter at or below `docs/ratchets.json` (`tools/ratchet/run --check
--against origin/beta`: duplicate windows 8,247 of 8,257, after the two
`AsyncStreamVerifier` setters were put memory first in `budget.rs:58-68`, the
natural order measuring 8,260); not re-recorded.

### Fixed: the interpreter holds no number's bytes twice and writes no huge number in an error's text, under a caller's memory budget (#348, #349)

The nightly fuzz job's two crashes in `fuzz_script_spend` (run 40474836749,
at `5f3fa1ab`), both under the block word after Chronicle with
`memory_limit: Some(1_048_576)`, neither past the node's count: the bytes were
ones the budget did not see. The figures are the fuzz target's counting
allocator's (a reservation left out, as the target leaves it out since #331)
and `dhat`'s, at `7029c7e` (the base the fix was made on), at `e813ce4`
(`beta` with #331) and at the tip.

- #348, 4,815,906 bytes live and 1,372,366 in the largest request at
  `7029c7e` (`dhat`: 2,061,735 bytes from one site, 4,129,299 at the peak):
  an `OP_3DUP` and `OP_MUL` chain to 686 KB products. `ScriptNum::to_bytes`
  grew the magnitude's buffer by doubling it for the sign byte (686,183 to
  1,372,366 bytes), so a pushed number held twice the bytes it was charged;
  it also took an absolute copy of the number first, `ScriptNum::from_bytes`
  a negated copy, and `op_binary_number` held both popped operands, both
  decoded numbers and the result through the encode. #331 (bsv-rs#374)
  landed first with the same cures: the decode reads the magnitude in place,
  the encoder writes into a buffer of exactly the encoding's length, and the
  operands' bytes leave as their numbers arrive; at `e813ce4` the input holds
  2,515,354 bytes live and 686,200 in the largest request, as at the tip
  (`dhat`: 695,285 bytes from one site, the error's stack snapshot). What this
  change adds over #331: `push_number` and `push_arithmetic_result` take the
  number and free it once encoded, before its bytes join the stack, so the
  number and its bytes are never both held through the push; on these two
  inputs that has no measured effect (the same figures at `e813ce4` and at
  the tip), the tests pinning #331's cure against a return.
- #349, one allocation of 3,978,066 bytes at `7029c7e` and at `e813ce4`
  (10,872,599 live there): `OP_NUM2BIN`'s refusal of a size above `INT32_MAX`
  (`SCRIPT_ERR_PUSH_SIZE`) wrote the size, an 825,905-byte number, in decimal
  into its text (`splice.rs`, num-bigint's radix conversion), as the shifts'
  two refusals of a huge count would. A number in an error's text is now
  written in decimal up to 64 bytes and as `a N-byte number` above
  (`found a 825905-byte number.`). The texts of the witnesses
  (`found 2147483648.`, `found -1.`,
  `OP_RSHIFTNUM count (2147483648) does not fit an int.`) are unchanged.
  825,920 bytes the largest request after, 3,919,917 live.

The arithmetic working set stays uncharged, in the keeper's word of
2026-10-27, 19:1xZ, under the owner's ruling (c): "the arithmetic working set
stays uncharged against the memory budget. The budget means what the node's
limitedstack.cpp and the reference's Spend.ts:1562-1573 make it mean, the
bytes of the stack's elements, and charging the working set would decline
scripts both of them judge valid, which is a divergence on the policy path;
parity is matching the reference's accounting exactly. The abort path is
guarded separately by #374's room check, so nothing is left unguarded; the
fuzz target's bound at ten budgets with its reason stated is a tolerance for
what the accounting leaves out by design, and its line says so." A product or
a quotient is computed in num-bigint 0.4.8's working memory, measured at 5.2
and 9.5 times the operands on operands of 2^16 to 2^24 bytes (the step probe
records 10.0 for a quotient, `arithmetic_room.rs:59`); a 68-byte script
squaring to a 1,015,808-byte dividend holds 7,667,840 bytes live in `OP_DIV`
under 1 MiB (`3093a215…`, at `e813ce4` and at the tip). The fuzz target's live
bound is now four budgets plus six for one arithmetic opcode's working set
(`ARITHMETIC_WORKING_SET`), a tolerance for what the accounting leaves out by
design; the single-request bound (twice the budget) holds as it was. Its side
effect: the live bound no longer catches #348's shape (4,815,906 bytes is
under ten budgets), so the test below holds that input to one site under the
budget itself.

Pinned by `tests/script_budget_before_allocation_348.rs`: each input as a
constant named for its issue, held by `dhat` (now a dev-dependency; the crate
forbids `unsafe`, so no allocator of its own) to the target's bounds when it
found them (one site at most twice the budget, at most four budgets live, the
input's term added; a reservation, the step probe's `try_reserve_exact`, out
of the site read and added to the live bound (the probe's frame read by name
from `dhat`'s backtraces, so the test needs debug info), since `dhat`'s peak cannot
leave one out), and #348's to one site under the budget; a 100,001-byte
product's encoding; the 64-byte edge of the number text. At `7029c7e` three
were red, then four with #348's site assertion (2,061,735 bytes from one
site, the encoder's doubled buffer); at `e813ce4` the two #349 tests are red
and #348's are green (#331's encoder); on the tip with the encoder's buffer
doubled again, #348's is red (1,380,138 bytes from one site). Both inputs are
in `fuzz/corpus/fuzz_script_spend/` under their sha1, with the 68-byte
`OP_DIV` script above (`3093a215…`), which the moved bound covers.

### Notes: cross-SDK parity (#348, #349)

The reference predicts an arithmetic result's length before computing it and
refuses it against the local budget (`ts-stack@edf6e03` `Spend.ts:1562-1573`:
the operands' byte lengths summed for `OP_MUL`, the longer plus one for
`OP_ADD` and `OP_SUB`, the longer otherwise). This crate does not port it: a
result is never longer than its operands' charge (a product's bytes are at
most the sum of the operands' minimal encodings, a sum's at most the longer
plus one, and both operands were charged), so under the node's count the
prediction never refuses before the push would, and the reference's
`OP_ADD` of a number and an empty operand refuses one byte early at the exact
budget, where this crate's push does not. Neither the reference nor the node
counts the big-number library's working memory (BN.js, OpenSSL's `BIGNUM`).
The reference's `OP_NUM2BIN` refusal writes no number
(`OP_NUM2BIN size exceeds the node int32 push limit.`, `:1942`); this crate's
words are its own.

## [0.9.0-beta.2] - 2026-10-28

The 0.9.0 line's second prerelease (RELEASING.md point 14), cut from `beta` at the owner's word once #329 and #331 landed (the keeper's rulings under the owner's ruling (c): `WalletInterface`'s `originator: Option<&str>`, `Transaction::verify`'s caller budget with `None` uncapped; #331 at e813ce4f), for the toolbox's 0.14.0-beta.2 and the CLI's beta line to build against; the entries below are 0.9.0's since 0.9.0-beta.1, unreleased on `main` until the minor merges at the phase exit.

### Changed: `Transaction::verify` takes the caller's memory budget as the reference's third parameter, and `Spend` and `verify` run uncapped without one, as the reference does (#331)

`Transaction::verify` evaluated every input under `memory_limit: None`, the
default mode's 32,000,000-byte local budget, and took no budget from its
caller, so a script whose stack passes 32,000,000 bytes, which the network
accepts, was a decline (#38's `ScriptEvaluationDeclined`). The reference's
`verify(chainTracker, feeModel, memoryLimit?, verifier?)` takes the budget
as its third parameter and hands it to `Spend` only when given
(`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts:1685-1697`,
`:1653-1664`), whose default is `Number.POSITIVE_INFINITY` with
`hasExplicitMemoryLimit` false (`packages/sdk/src/script/Spend.ts:295-296`):
without a caller's word it judges every script the network judges. The
keeper's ruling of 2026-10-27 (12:5xZ), under the owner's ruling (c),
carries the signature change on the 0.9.0 line; the keeper's ruling of
15:1xZ carries the same reading to `Spend`: "`SpendParams::memory_limit:
None` in the default mode is uncapped, as the reference's `Spend` has it
[...] A budget is the caller's `Some(n)`", the 32,000,000 figure "never a
library default", and `set_stack_memory_consensus` stays the block path's
word.

- `verify(chain_tracker, fee_model, memory_limit: Option<usize>)`: `None`
  is uncapped; `Some(n)` is the caller's local budget, `n` bytes on each
  stack, a decline above it `Error::ScriptEvaluationDeclined { input_index,
  limit }` as in #38. `verify` hands its parameter to `Spend` as given.
- `SpendParams::memory_limit: None` in the default mode is uncapped
  (`Spend::memory_limit()` reads `usize::MAX`; the constant
  `DEFAULT_MEMORY_LIMIT` is gone); `Some(n)` is `n` bytes per stack, as
  before. Under a word nothing moves: the node's count, `None` its 100,000,000
  bytes (`WORD_MEMORY_LIMIT`, the node's `-maxstackmemoryusagepolicy`
  default, `src/policy/policy.h:153`), the mempool path's policy a verdict
  at its figure, `set_stack_memory_consensus` the block path's verdict.
  The streaming BEEF reader runs each input under `None` and takes no
  memory budget, so it is uncapped too, its work bound
  (`set_work_limit`) as before.
- Uncapped, the allocator is the budget, and rule 5 forbids its abort (on
  `wasm32` an abort nobody catches). Every element the interpreter makes
  (a push, a copy by `OP_DUP` and its kin, `OP_CAT`, `OP_SPLIT`, the
  splices, `OP_NUM2BIN`, the byte shifts) is allocated with
  `try_reserve`, and so is each stack's growth: one the allocator refuses
  is a decline, `ScriptResource::Stack` with `limit` the bytes both stacks
  held and those the step holds off them (its popped operands: `OP_CAT`'s
  two, `OP_SPLIT`'s and the splices' data, a number being read or encoded;
  the re-review of the third fold: a step's operands were left out, and a
  decline beside 600 MiB of them said `exceeded 0 bytes`) and `attempted`
  those and the size asked (`Stack memory usage has exceeded N bytes`). `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR` work in
  place, allocating nothing. An error's copy of the stacks is made the same
  way, left empty if refused. A step no longer clones its chunk: the
  parsed scripts are shared (`Arc<[ScriptChunk]>`) and indexed in place,
  so an executed push is copied once, onto the stack, where each step's
  infallible clone of the push's bytes doubled its peak (the review's
  third note). The reference's allocation failure is a `RangeError` out of
  `verify`, neither of its two classes.
- The numbers: `BigNumber` (`num-bigint`) allocates infallibly, so its
  arithmetic is guarded before it runs (#374, closed by this branch; the
  keeper's word of 2026-10-27, 17:0xZ: "the fold that made None uncapped
  opened the abort path, and a change that opens an abort path lands with
  its guard; make the allocation fallible so OP_MUL near 1 GiB declines, on
  the branch before #331 lands. [...] A verdict is never loosened to go
  faster."). The default mode's 1 GiB element bound holds at a data push,
  `OP_CAT`, `OP_NUM2BIN` (whose bound under a word stays `INT32_MAX`) and
  the numeric left shift, whose result above it is refused before the
  shift allocates, `It's not currently possible to push data larger than
  1073741824 bytes.` (a shift of 1 by 2^40 bits asked for 2^37 bytes);
  the default mode's shift compares its size in `u64`, as the word branch
  does, where it truncated to `usize` (on `wasm32` a count past 2^35 bits
  wrapped below the budget). It now holds at every arithmetic result too,
  as a decline (`src/script/spend/arithmetic_room.rs`): before an operand
  is decoded its encoding is judged as the read judges it (the read's
  verdicts first, as the reference reads both operands first, the top one
  first, `bn2` before `bn1` (`Spend.ts:1560-1561`; the re-review of the third
  fold: this crate judged the deeper first, so of two bad operands it named
  the other; `OP_WITHIN` reads each operand as it pops it, `:1628-1630`)), then a
  result whose least possible length passes the bound is declined from the
  operands' bytes alone. Only `OP_MUL`'s result can pass its operands by
  more than a byte (at least `a + b - 1` bits for magnitudes of `a` and `b`
  bits: two operands near 1 GiB asked about 2 GiB, the abort the review's
  first note found); `OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB` and `OP_2MUL`
  pass their longest by one byte at most and the others not at all, so
  their exact length is judged after the arithmetic, no more than two bytes
  past the bound allocated. The decline is `ScriptResource::ElementSize`,
  `limit` 1073741824, `attempted` the length: `Script element allocation
  has exceeded 1073741824 bytes: OP_MUL needs at least N bytes for its
  result, from operands of A and B bytes.` (`needs N bytes` when judged
  after the arithmetic, `from an operand of A bytes` for a unary opcode).
  In every mode a step of 64 KiB or more asks the allocator first for the
  most it holds past its operands, `try_reserve_exact`, then released
  (the review of the guard's first form: it asked only for the result's
  size, and the step needs several times that, so a refusing allocator at
  a 4 GiB ceiling still aborted `OP_1 <2^29> OP_NUM2BIN OP_INVERT OP_DUP
  OP_ADD`, `OP_MUL` of two 300 MiB operands and `OP_1ADD` near 1 GiB after
  the probe had passed): the allocator's ceiling is the one bound nothing
  knows before the allocation, and num-bigint has no fallible form, so its
  refusal is a decline where the arithmetic's would be an abort. The room
  asked is a multiple of the operands' bytes (`STEP_PEAK_*`): 6 for
  `OP_MUL` (the product, both operands long, and num-bigint 0.4.8's Toom-3
  scratch, its six parts, four sums and five point products, a third the
  size at each level of its recursion; measured at most 5.12, where the
  shorter operand is just over half the longer), 12 for `OP_DIV` and
  `OP_MOD` (Burnikel-Ziegler pads the dividend to a power of two of
  digits, doubled once when its top block is not below the divisor, and
  recurses on copies of the blocks; measured at most 10.0, a dividend just
  past a power of two of digits over a divisor just past its 64-digit
  threshold, a seeded random search of 90 shapes reaching 9.93), 2 for
  every other arithmetic opcode (an operand's digits beside its bytes, the
  result in one operand's digits, its encoding beside them; measured
  1.0). The margins are 17, 20 and 100 percent over the worst measured,
  on a counting allocator whose reallocation holds both blocks. A number's
  read outside the arithmetic opcodes (`OP_WITHIN`, the splice operands,
  `OP_PICK`, `OP_ROLL`) asks for 1.5 times its bytes, a numeric shift for
  twice its result's, the same way, and every encoded number is allocated
  fallibly. The decline keeps its form, the step named where the result
  was: `Stack memory usage has exceeded H bytes: the allocator refused the
  N bytes OP_MUL's step may need, from operands of A and B bytes.`
  (`limit` the bytes the evaluation held when the allocator refused: both
  stacks and what the step holds off them, its operands, the number it is
  encoding; a read or a shift the bare `Stack memory usage has exceeded H
  bytes`). On the review's allocator refusing past 4 GiB (its harness, at
  the probe's commit, `d94a70b3` on `bb80a525`, `f92e2b4a` before the
  rebase; from the read limit's commit on all three are `Invalid string
  length` at the read, below): the
  sum of two 2^29-byte operands and `OP_1ADD` of 2^30 - 16 bytes are
  computed (`Ok(true)`, 1.3 s and 1.4 s, 2.1 GB resident), `OP_MUL` of two
  300 MiB operands is declined at 3,774,873,600 bytes; before this fold all
  three aborted (exit 134). On `wasm32` a granted probe grows the linear
  memory, which does not shrink, by up to the room asked; the pages are not
  touched. Under a word the element bound
  does not apply (an element after Genesis is bounded by the stack memory
  budget alone): the number length bounds each operand at its read (750,000
  bytes after Genesis, 32,000,000 after Chronicle, the policy's on the
  mempool path) and the node's overflow test follows the arithmetic
  (`script_num.cpp:164`, `194`, `214`), so a 2 GiB product does not arise
  on the block path; a node whose `BN_mul` cannot allocate answers
  `SCRIPT_ERR_BIG_INT` (`big_int.cpp:226-236`, `interpreter.cpp:1819-1822`
  at bitcoin-sv `6504a3a`), a verdict, where this crate declines. Under a
  caller's `Some(n)` the budget already bounded the allocation (the operands
  were charged when pushed, and a product is no longer than both together),
  but nothing declined before it: the operands were popped and multiplied,
  the push's charge after (`stack.rs`); the element bound now applies under
  a budget too, as at a push. The reference's
  `predictedLen` test (`Spend.ts:1562-1573`, the budget against the result's
  predicted length before the arithmetic) cannot fire under that count (the
  two operands it pops held at least as many bytes), so it is not ported.
  The step's own allocations are shrunk: `ScriptNum::from_bytes` reads the
  magnitude from the element in place, the sign bit cleared in the digits,
  where it copied the operand first; `ScriptNum::to_bytes` sizes its one
  allocation up front, the sign byte's room included, where pushing the
  sign byte onto a full vector doubled it, and the magnitude is no longer
  cloned to take its absolute value; an operand's bytes are released as
  its number arrives, and `+`, `-`, `OP_2MUL`'s `<< 1`, `OP_2DIV`'s `/ 2`,
  negation and `OP_ABS` work in one operand's digits, whose capacity holds
  the bit a sum may add. The peak of the heap per opcode on an n-byte
  operand (the review's dhat harness, `OP_1 <n> OP_NUM2BIN OP_INVERT`, then
  the opcode, `OP_DUP` before a binary one, the stack's copies included, n
  = 16 MiB): `OP_1ADD` 4n before, 2n after (3n with the probe's momentary
  reservation), `OP_ADD` 8n before, 3n after (6n), `OP_MUL` 14n before, 12n
  after (14n); the step's own past its operands, as a multiple of their
  bytes (operands of 4 MiB pushed as data, a counting allocator whose
  reallocation holds both blocks): `OP_1ADD`, `OP_1SUB`, `OP_2DIV`,
  `OP_NEGATE`, `OP_ABS` 3.0 before, 1.0 after; `OP_2MUL` 5.0 before, 1.0
  after; `OP_ADD` 3.5 before, 0.5 after; `OP_SUB`, the comparisons, `OP_MIN`,
  `OP_MAX` 2.0 before, 0.5 after; `OP_MUL` 5.52 before, 4.52 after on equal
  operands, 6.11 and 5.12 at its worst shape; `OP_DIV` 11.0 before, 10.0
  after at its worst shape. An operand's decoding stays infallible (num-bigint
  builds its digits with no fallible form), and is covered by the probe.
- The default mode reads a script number as the reference does (the
  keeper's word of 2026-10-27, 19:4xZ, under the owner's ruling (c): "a
  script number the reference cannot read is invalid there and so invalid
  here in that mode"): an operand whose magnitude passes 536,870,888 bits,
  a minimal encoding past 67,108,862 bytes, is invalid with the
  reference's words, `Invalid string length`, a verdict, never a decline,
  judged at every read after the minimal-encoding check, as the reference
  judges it (`src/script/spend/reference_read.rs`; the arithmetic guard's
  operand check too, so the verdict precedes any decline). The figure is
  V8's longest string at the reference's pin, not a BRC's rule: under
  Node v22.18.0 at `ts-stack@edf6e03` `#_finishInitialization` takes
  `toString(2)` of every magnitude it is given (`BigNumber.ts:450`) and
  `#readScriptNumber` rethrows the `RangeError`'s words
  (`Spend.ts:525-535`). The node's number length after Chronicle is
  32,000,000 bytes (#38's entry; `ScriptFlags::max_script_num_length`):
  the reference reads numbers the node refuses, and the default mode
  follows the reference; under a word nothing moves. With it the
  arithmetic's peak is bounded by construction for a minimal operand
  (`OP_MUL`'s room at most 6 times 134,217,724 bytes, 805,306,344), and the
  element bound at an arithmetic result is unreachable by operands the
  default mode reads (two give at most 2^30 - 48 bits, 134,217,722 bytes;
  kept, and modelled by the unit tests). A non-minimal operand (the default
  mode relaxes minimal encoding at version 2 and above) is read while its
  magnitude is within the figure, whatever its length: the reference's hex
  text (`fromSm`, `:1518-1527`) would refuse one past 268,435,443 bytes,
  but no script holds such an element there (a `number[]` of 2^27 entries
  is `RangeError: Invalid array length` under Node 22), so that bound is
  not followed; here the 1 GiB element bound and the step's probe bound it.
  The review's three scripts are now that verdict at their first read
  (`Err("Invalid string length")` on the review's allocator at 4 GiB, this
  tip).
- A result past the figure is invalid at its push in the same words (the
  keeper's word of 2026-10-27, 21:5xZ, under the owner's ruling (c), the
  symmetric reading: a script number the reference cannot encode is one it
  never judges valid): `OP_ADD`, `OP_SUB`, `OP_1ADD` and `OP_1SUB`, whose
  results the reference's `add` and `sub` set through
  `#_setValueFromSigned`, so through `toString(2)` (`BigNumber.ts:771-781`,
  `:912-924`), and `OP_LSHIFTNUM`, whose result it builds as `new
  BigNumber(value << bits)` (`Spend.ts:1066`). There each throws `RangeError:
  Invalid string length` past 536,870,888 bits, outside `#readScriptNumber`'s
  rethrow, uncaught out of its `validate` and `Transaction.verify`, neither
  of its two classes (the re-review ran it: an at-limit operand's `OP_DUP
  OP_ADD` in 4.5 s, its `OP_1ADD` in 3.5 s, `1 <536,870,888> OP_LSHIFTNUM`
  in 6 ms); here the push is a verdict with the same text, never an abort
  (`reference_read::result_refusal`, at `push_arithmetic_result` and the
  numeric left shift). The shift has a second figure: `value << bits` is a
  `BigInt` before any string is written, and V8 caps a `BigInt` at 2^30
  bits of magnitude (`BigInt::kMaxLengthBits`), so past 2^30 bits the
  reference's shift throws `RangeError: Maximum BigInt size exceeded`, the
  string never reached; from 536,870,889 to 2^30 bits the `BigInt` is built
  and its string throws `Invalid string length` (Node 22.18.0 at
  `edf6e03`: `1` and `-1` shifted by 2^30 - 1 bits, the string's words;
  `1` and `-1` by 2^30, `3` by 2^30 - 1 and `1` by INT_MAX, the `BigInt`'s,
  each in 1 to 37 ms). Here the shift answers each in its words, a verdict
  both, after a caller's budget's decline (`reference_read::shift_refusal`;
  `a_left_shift_past_2_pow_30_bits_is_invalid_with_the_bigint_words`, RED
  on 8eb1b2c8 with the string's words). No other opcode's result passes
  2^30 bits in one step: two readable operands' product is at most
  2^30 - 48 bits, a sum one past the longer operand. These are the opcodes
  whose result can cross the
  figure through the reference's `toString(2)`: `OP_MUL` and `OP_2MUL` can
  pass it, but `mul` sets its magnitude without a string (`:926-933`), so
  their result is pushed there and here (an at-limit `OP_2MUL` is `true`
  there; the result is invalid at its next read on both sides); `OP_DIV`,
  `OP_MOD`, `OP_2DIV`, `OP_RSHIFTNUM`, `OP_NEGATE`, `OP_ABS`, `OP_MIN`,
  `OP_MAX` and the comparisons give no magnitude past their operands'. A
  sum's bits are judged after the arithmetic (at most one past the longest
  operand's), the shift's before it allocates (the value's plus the count).
  The order, in the default mode: the element bound at the shift as before,
  then the caller's budget (`Some(n)`) on the result's push, its decline as
  #331 has it, then the verdict: a budget's refusal is never read as
  invalid (#38), and the verdict is the judgment of a step its budget
  admits. For `OP_ADD` and `OP_SUB` that is the reference's order
  (`#ensureStackMem(predictedLen)` at `Spend.ts:1573` before `add`); for
  `OP_1ADD`, `OP_1SUB` and `OP_LSHIFTNUM` the reference's throw precedes its
  push's budget (`:1510`, `:1066`, before `#pushStack`'s `#ensureStackMem`,
  `:448`). A budget that admitted a sum's operands admits its result (no
  longer than both together), so the order is observable at the shift
  alone. Under a word nothing moves: the node's number length bounds every
  operand and result (32,000,000 bytes after Chronicle, #38's entry; the
  result's test at `script_num.cpp:164`, `194`, `214`, `315-316`), so the
  node never holds such a number and refuses it as
  `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` first, in its words.

Pinned by `tests/transaction_verify_budget_331.rs` (#38's shape, 33 copies
of a 1,000,000-byte element: `Ok(true)` under `None`, the decline at
33,000,000 of 32,000,000 under `Some(32_000_000)`, `Ok(true)` under
`Some(40_000_000)`, an invalid script the same `TransactionError` under
both, the shift past the bound refused uncapped and declined under a
budget), `tests/script_default_mode_uncapped_331.rs` (4 tests, 1 ignored:
`Spend` in the default mode under `None`, the same shape `Ok(true)` and,
with an invalid tail, the script's verdict, never a decline; a
40,000,000-byte element `Ok(true)`; under `Some(32_000_000)` the 33rd copy
and the element declined as `None` declined them before; the ignored test,
run by hand, the shift of 1 by 2^33 + 8 bits refused by the element bound
alone, 0.01 s, where without the bound it is computed and valid, 63 s and
1.9 GB resident on the studio under lane load, 6.6 s and 3.2 GB on the
review's host), `test_an_executed_push_copies_its_bytes_once`
(`tests/memory_profiling.rs`, dhat: an 8,000,000-byte push evaluated at a
peak of 8,000,096 bytes, 16,000,096 with the clone) and
`an_allocation_the_allocator_refuses_is_a_decline_not_an_abort` (the
`spend` unit tests: an element of `isize::MAX + 1` bytes, which no script
reaches on a 64-bit host, is the decline at the 7 bytes held, where
`Vec::with_capacity` panicked), and for #374 the eleven unit tests of
`src/script/spend/arithmetic_room_tests.rs` (the bound and the allocator's
ceiling modelled at a small scale: two 600-byte operands under a bound of
1,000 declined at 1,200 before either is decoded, two of 500 bytes pushed at
1,000, `OP_1ADD` one byte past it declined at 1,001, a word not bounded, a
non-minimal operand's verdict first; the step's probe on results the old
probe granted: `OP_MUL` of two 40,000-byte operands declined at 480,000
under a ceiling of 100,000, `OP_DIV` and `OP_MOD` of 40,000 by 600 at
487,200, `OP_ADD` at 160,000 and `OP_1ADD` at 80,000 under 70,000, the four
computed under 1,000,000; `OP_WITHIN`'s read of three 50,000-byte operands
declined at 75,008, `OP_LSHIFTNUM` of 1 by 320,000 bits at 80,020) and
four ignored ones (the review's three scripts under the modelled ceiling
of 4 GiB less the operands held: computed, declined at 3,774,873,600 and
computed under the step's probe alone, now each invalid at its read; the
largest product the default mode reads, two operands of 67,108,862 bytes,
declined at 805,306,344 under a ceiling of 512 MiB; 0.45 s together in
release), the two unit tests of `src/script/spend/reference_read.rs` (the
figure on one 67,108,862-byte buffer: 536,870,888 bits read, a 536,870,889th
refused, a byte more refused; padding no bit),
`tests/script_reference_read_limit_331.rs` (10 tests, 8 ignored, by hand,
0.63 s and 1.01 GB resident in release under `--test-threads=1`: an operand
of 67,108,863 bytes invalid with the reference's words, one of 67,108,862
at 536,870,888 bits read (the negative one's `OP_1ADD`, `true` in the
reference), one bit more invalid, the node's overflow under a word; the
results: the at-limit `OP_1ADD`, `OP_DUP OP_ADD`, `OP_SUB` and the
negative's `OP_1SUB` invalid at the push, `OP_2MUL` pushed, `1
<536,870,888> OP_LSHIFTNUM` invalid before it allocates and `1
<536,870,887>` pushed, and under a budget of 67,108,870 bytes the shift's
push declined beside a 100-byte element, the verdict without it; red 2 of
the first 4 on the code before the read limit, and 4 of the 10 on the code
before the results' verdict: the increment, the sum, the shift and the
budget's order, the at-limit `OP_1ADD` `Ok(true)` there),
the unit test `a_result_past_v8s_longest_string_is_refused`
(`reference_read.rs`),
`test_each_arithmetic_steps_peak_is_within_the_room_its_guard_asks`
(`tests/memory_profiling.rs`, dhat: each step's peak of the heap past its
operands at most
its declared room and 4 KiB of the guard's bookkeeping, on `OP_MUL` of
262,144 by 131,098 bytes, `OP_DIV` and `OP_MOD` of 2,098,000 by 513,
`OP_ADD` of two 1 MiB operands and `OP_1ADD` of one; 4.7 s) and the
ignored `tests/script_arithmetic_result_bound_374.rs` (by hand: `OP_MUL` of
two operands of 2^29 + 1 bytes declined at 2^30 + 2, 0.69 s and 1.04 GB
resident, until the read limit, now invalid at the first read, 0.12 s;
with `dhat-profiling` a peak heap of 1,073,742,431 bytes, the operands and
no allocation of the product's size; without the guard still multiplying
after 60 s at a peak footprint of 5.4 GB, 3.7 GB resident). Red on the code before the guard: 3 of the 6
(the two acceptances and the encoding's verdict hold either way) and the
ignored test; on a copy of this tip with the result's probe in place of the
step's and no read or shift probe, 5 of the 11 (the six that pass either
way the bound's, the word's, the encoding's and the granted steps'); the
dhat test on the code before this fold, 3 of its 5 steps past their room
(`OP_MUL` 6.11, `OP_ADD` 3.0, `OP_1ADD` 3.0 times the operands; the
division's 11.0 under 12). Red on the code before, the parameter
unread and allocation infallible: 3 of the 5 in the first file (the 2
others, the 32,000,000 decline and the invalid script, hold either way) and
the unit test (`capacity overflow`); on the code before the fold of the
keeper's second ruling, 3 of the 4 in the second (the decline under
`Some(32_000_000)` holds either way) and the profile (16,000,096 bytes).
The default-mode rows that pinned the 32,000,000 decline under `None`
(`tests/script_stack_memory_witness.rs`, four; `tests/script_shift_count_witness.rs`,
two) pass `Some(32_000_000)`, the caller's budget, their figures
unchanged, and `Spend::memory_limit()` in the default mode reads
`usize::MAX`; `tests/transaction_verify_decline_38.rs` passes
`Some(32_000_000)`, the budget it pins; its 3 tests are otherwise
unchanged.

Migration: `tx.verify(&tracker, fee)` becomes `tx.verify(&tracker, fee,
None)` for the reference's uncapped default, or `Some(n)` to keep a budget
(`Some(32_000_000)` is the old one). A `Spend` caller in the default mode
that relied on the decline above 32,000,000 bytes passes
`memory_limit: Some(32_000_000)`. A door that verifies untrusted
transactions passes its own figure: uncapped, a script can hold up to
1 GiB per element and as many elements as its length allows. A memory
budget bounds memory, never time: an uncapped run is a longer one too (the
review measured `OP_MUL` of an n-byte number by itself at 20 s for 8 MB,
43 s for 16 MB and 125 s for 32 MB under load; the 16 MB case was reachable
under the old budget). Time is bounded by the work budget, one unit per
opcode reached and each byte hashed (`SpendParams::work_limit`,
`StreamVerifier::set_work_limit`), and by the script's length and the
element bound; `verify` takes no work budget, so a caller that wants a
time bound runs the inputs through `Spend` with `work_limit` or the
streaming reader with `set_work_limit`, or bounds the call from outside
(a deadline on its task). Downstreams, grepped at their tips:
`bsv-overlay-cloudflare@8c18730c`, the two `overlay-engine` tests
(`tests/script_verification.rs:785`, `:919`), add `None`; its production
walk is its own (`verify_spv_like_the_reference`), no call.
`bsv-wallet-cli@f4285bf`, `bsv-wallet-toolbox-rs@a3377ef`,
`rust-message-box@08418ec`: no `Transaction::verify` call; the relay's
`src/beef_door.rs` (419bf18 at its tip, `:420-428`) runs the streaming reader
(`StreamVerifier::new`, `structure_only`, `resume`) with `set_work_limit` and
no memory budget, so its scripts run uncapped after this change until the
stream takes `verify`'s parameter (#373, the keeper's shape; since #373,
Unreleased, it does: `StreamVerifier::set_memory_limit`, which the door can
set beside `set_work_limit` after its re-pin). LOW's
`low-spend` (`crates/low-spend/src/covenant.rs`) pins `=0.8.1` and takes the
parameter when its own captain re-pins.

Semver: a breaking change to a public method's signature (one parameter
added), carried by the ruling on the 0.9.0 line; `cargo semver-checks`
names it (`method_parameter_count_changed`). `SpendParams::memory_limit:
None`'s new reading is a behaviour change no lint sees.

### Notes: cross-SDK parity (#331)

The #38 note that `verify` kept 32,000,000 bytes where the reference
imposes no cap is closed: the parameter and its default are the
reference's. The divergence this entry first listed, `SpendParams::memory_limit:
None` keeping 32,000,000 bytes in the default mode where the reference's
`Spend` has defaulted to `Number.POSITIVE_INFINITY` since `ts-stack@30210fe`
(#349, 2026-07-25), is closed by the keeper's second ruling: both are
uncapped. Two differences stay, stated: the default mode's 1 GiB element
bound, which the reference's default does not have (its `#maxPushSize` is
unbounded outside explicit flags, `Spend.ts:405-409`), and the allocator's
refusal, a decline here and a `RangeError` there. An arithmetic step
(#374): the reference bounds none but by its engine. Under Node v22.18.0 at
`edf6e03` an operand fails at its read once its magnitude passes 536,870,888
bits, a minimal encoding longer than 67,108,862 bytes (V8's longest string:
`#_finishInitialization` takes `toString(2)` of every magnitude it is given,
`BigNumber.ts:450`, and throws `RangeError: Invalid string length`), which
`#readScriptNumber` rethrows as a script error (`Spend.ts:525-535`), a
verdict; a non-minimal operand longer than 268,435,444 bytes fails earlier,
at `fromSm`'s hex text (`:1520`, Node's `Cannot create a string longer than
0x1fffffe8 characters`). The 2^30-bit `RangeError: Maximum BigInt size
exceeded` this entry named before is unreachable through `OP_MUL`: two
readable operands give at most 2^30 - 48 bits, and `mul` sets the product's
magnitude without `toString(2)` (`:926-933`), so a 32 MiB by 32 MiB product
is pushed there and judged the same here, only slower (#378). Since the
keeper's word the default mode gives the reference's verdict, in its
words, on an operand past 536,870,888 bits, and since its second word
(21:5xZ) on a result past the figure where the reference builds it through
`toString(2)` (`OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`, `BigNumber.ts:771-781`;
`OP_LSHIFTNUM`, `Spend.ts:1066`). The reference's form there is an uncaught
`RangeError: Invalid string length` out of its `verify`, neither of its
classes, where this crate answers a verdict with the same text; the node
never holds such a number (its number length after Chronicle, 32,000,000
bytes, #38's entry, refuses it as `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`), so the
row is the reference's against the node; an `OP_MUL` or `OP_2MUL` result
past the figure is pushed on both sides (`mul`, `:926-933`), and under a
caller's budget a result's push is declined before its verdict where the
reference's `OP_1ADD`, `OP_1SUB` and `OP_LSHIFTNUM` throw before their
push's budget. Two differences stay, stated:
a non-minimal operand past 268,435,443 bytes, which the reference's hex
text would refuse, is read here while its magnitude is within the figure;
and an element of 2^27 bytes or more, which the reference cannot hold
(`RangeError: Invalid array length` for a `number[]` of 2^27 entries under
Node 22), is held here up to the 1 GiB element bound. The V8 figures were
measured with those lines' expressions under Node v22.18.0, the read through
the reference's `Spend` by #378. go-sdk@2ca481c's
`spv.Verify` takes no caller's budget and runs the interpreter at the relay
policy's 100,000,000 bytes (`interpreter.DefaultMaxStackMemory`,
`spv/verify.go:64-68`).

### Changed: a push runs exactly the required set; the measurements run on dispatch and before every tag, each in its own workflow with its own badge (the owner's word of 2026-10-27)

The owner's word at 20:1xZ, 2026-10-27, through the keeper: "sick of seeing
all these CI failures... why are none of them passing... they are all so
hardcore and slowing us down". The keeper's read: beta's last push run was red
on the Benchmark Regression Check alone, a job that judges the runner's load,
not the commit. The keeper's ruling, the balance: a push to `beta` or `main`
runs exactly the required set, the same contexts as a pull request to that
line, nothing more; every job that judges something other than the commit runs
on `workflow_dispatch` and once before a tag, each in its own workflow with its
own badge, never on the push run; the README badge points at the required-set
workflow on `main`; a cancelled run under the concurrency rule is never a red.
Nothing is lost: the measurements still run before every tag.

`ci.yml` keeps the required set (`Test Suite (ubuntu-latest, stable)`,
`Clippy`, `Rustfmt`, `vectors`, `deny`, `ratchet`, `fixtures`, `secrets`,
`wasm32 (combined)`, `main-in-beta` on beta, `dependents` on main, `semver` and
`beta-born` on a pull request), the context names unchanged. Two of the
required jobs read a pull request and cannot run on a push: `semver` (the
base's last tag) and `beta-born` (the PR's commits). The five other test cells
(macOS, Windows, the beta toolchain) run on a dispatch of `ci.yml` (the
nightly's `ci-full` on each line, the sync's) and on a tag's call. The
dependents jobs stay in `ci.yml`, since `dependents` is required on `main` and
a called workflow's job reports as `<caller> / <name>`; they leave beta's push
and run on a dispatch on either line and on every tag. The new workflows, each
with `workflow_dispatch` and `workflow_call`:

- `bench.yml`: `Benchmark Regression Check`, `Benchmarks Build` and the
  `scoreboard` (its `needs` now the two bench jobs; it reads artifacts, as
  before), with the `bench_baseline_record` input and the
  `BSV_SCRIPT_CORPUS_TOKEN` secret (`gh workflow run bench.yml --ref <branch>
  -f bench_baseline_record=true`).
- `msrv.yml`: `msrv`.
- `features.yml`: `features` (each feature alone) and the five wasm32 slices
  other than the required `wasm32 (combined)` (`wasm32 (watchtower)`,
  `(monitor)`, `(chaintracks)`, `(overlay)`, `(relay)`).
- `machete.yml`: `unused dependencies` (non-blocking, as before).
- `docs.yml`: `Documentation` (rustdoc) and `actionlint`, the checks of the text.

`release.yml` calls `ci.yml` and the five on every version tag, a prerelease's
included. The publish waits for `ci.yml`, `docs.yml`, `msrv.yml`,
`features.yml` and `machete.yml`, as it waited for those jobs inside `ci.yml`.
`bench.yml` runs beside the publish and does not hold it: a red there is the
runner's as often as the commit's, and it shows on the tag's run and the badge.
Before this change a tag's call skipped the regression check. `nightly.yml` is
unchanged: it is dispatch-only (the entry below) and not callable, so
`RELEASING.md` step 3 names its dispatch before a minor tag.

| Job (context) | Pull request | Push to `beta` | Push to `main` | Dispatch | Before a tag |
|---|---|---|---|---|---|
| `Test Suite (ubuntu-latest, stable)`, `Clippy`, `Rustfmt`, `vectors`, `deny`, `ratchet`, `fixtures`, `secrets`, `wasm32 (combined)` | yes | yes | yes | yes (`ci.yml`) | yes |
| the other five `Test Suite` cells | no | no | no | yes (`ci.yml`) | yes |
| `main-in-beta` | into `beta` | yes | no | on `sync/main-into-beta` | no |
| `semver`, `beta-born` | `semver` both; `beta-born` into `main` | no | no | no | no |
| `Plan pinned dependents`, `dependent (<id>)`, `dependents` | into `main` | no (was yes) | yes | yes (`ci.yml`) | yes |
| `Benchmark Regression Check` | no | no (was yes) | no | yes (`bench.yml`) | yes, not holding the publish (was skipped) |
| `Benchmarks Build`, `scoreboard` | no | no (was yes) | no (was yes) | yes (`bench.yml`) | yes, not holding the publish |
| `msrv` | no | no (was yes) | no (was yes) | yes (`msrv.yml`) | yes |
| `features`, the other five `wasm32 (...)` | no | no (was yes) | no (was yes) | yes (`features.yml`) | yes |
| `unused dependencies` | no | no (was yes) | no (was yes) | yes (`machete.yml`) | yes |
| `Documentation`, `actionlint` | no | no (was yes) | no (was yes) | yes (`docs.yml`) | yes |

The badges: README carries one per workflow, the required set's first. The
`CI` badge reads `ci.yml` with `?branch=main`, so a beta push in progress or
cancelled never shows there. The five measurement badges read their
workflow's latest run on the default branch. `ci.yml`'s concurrency group
stays per event and ref (`ci-<event>-<ref>`, without the record mark now that
the record input is `bench.yml`'s). A newer push cancels the run it
supersedes, and that cancelled run is never a red: the newer run judges the
same line.

`tests/arch_ci_pr_runs_the_required_set.rs` pins it. A push to each line runs
exactly its required set less `semver` and `beta-born`
(`a_push_to_beta_runs_exactly_betas_required_set`,
`a_push_to_main_runs_exactly_mains_required_set`, both RED on the previous
`ci.yml`, which named every leaving job, the Benchmark Regression Check among
them). A dispatch on each line and a tag's call run every job and the six test
cells. Each measurement workflow is triggered by dispatch and call alone, and
`release.yml` calls it (`the_measurements_run_on_dispatch_and_before_a_tag_never_on_a_push`).
Three edits are refused: the dependents back on beta's push, `semver` on a
push, an unrequired job on the push run. The evaluator reads `startsWith`.
Nothing under `src/` changes. `CLAUDE.md` (rule 7, the layout),
`RELEASING.md` (steps 2, 3, 5, 12, 14), `HANDOFF.md` ("The lines"),
`docs/NIGHTLY.md`, `docs/ARCHITECTURE.md`, `docs/ARCH-RULES.md`,
`docs/NORTH-STAR.md`, `docs/RATCHETS.md`, `benches/README.md` and
`benches/CLAUDE.md` say so.

### Fixed: `HttpWalletJson` reads a code-5 body's `reviewActionResults` as the reference's `HTTPWalletJSON` does, and `ReviewActionsRefusal` carries the reference's five members (#339)

`HttpWalletJson` read a wallet's code-5 body as `WalletRefusal { class:
ReviewActions, message }` and never read its `reviewActionResults`, so the
identity revocation's double-spend retry (#327, `src/identity/double_spend.rs`)
saw no evidence over the JSON substrate. The reference's `HTTPWalletJSON`
(`ts-stack@edf6e03` `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:117-241`,
`:330-341`) builds a `WERR_REVIEW_ACTIONS` from a 400 body with its results
validated, so its revocation over HTTP retries. Now a 400 body with an own
`isError`, code 5 and `reviewActionResults` is read as it reads it
(`src/wallet/substrates/http_json/review_actions.rs`), in its order and words:

| The reference | Now |
|---|---|
| `isError` true and a safe-integer code, else `Invalid wallet error envelope` (`:204-206`) | the same |
| `message` a string of at most 4096 UTF-8 bytes, else `Invalid wallet error message` (`:207`, `:117-122`) | the same |
| a call other than createAction or signAction: `Invalid <call> wallet error code` (`:210-212`) | the same |
| `sendWithResults` an array, else `Invalid wallet error sendWithResults` (`:213-215`) | the same |
| `txid`, `tx`, `noSendChange`, `sendWithResults` through `validateWalletResult` under the request with `returnTXIDOnly: true` (`:219-235`; `WalletResultValidation.ts:1242-1374`): `txid` 32 hex bytes, `tx` a BEEF whose transaction matches it, `noSendChange` canonical outpoints of that transaction (absent for signAction), each send result a txid and a supported status, unique and one of the action's or its `sendWith`; signAction's txid present; a createAction asking for a completed transaction answered with its txid, one deferring signing refused (a code-5 body has no signable transaction); an outcome | the same checks in its words (`Invalid <call> result <field>: expected <expectation>`) |
| `reviewActionResults` at most 1001 objects, each txid 64 hex digits, one of the action's (its txid or `sendWith`) and not repeated, a status of the four, competing txids and BEEF on a double spend alone, at most 1000 distinct txids not the reviewed one, a BEEF read whole (`Beef.fromBinaryStrict`) holding each (`:131-197`) | the same, each refusal `Invalid wallet error reviewActionResults[<i>]<member>` |
| `new WERR_REVIEW_ACTIONS(reviewActionResults, sendWithResults, txid, tx, noSendChange)`, its message the constant (`WERR_REVIEW_ACTIONS.ts:17-27`) | `Error::WalletReviewActions` with the five members and the constant |

`ReviewActionsRefusal` carries the reference's five members in its names:
`review_action_results` (as before), `send_with_results`
(`Vec<SendWithResult>`), `txid` (`Option<TxId>`), `tx` (`Option<Vec<u8>>`,
the atomic BEEF) and `no_send_change` (`Option<Vec<Outpoint>>`), beside
`message`; `ReviewActionsRefusal::with_members` is the reference's
constructor, `new` unchanged (the four new members empty). It is not
`#[non_exhaustive]`: the reference's class has carried these five since
it was written, and a wallet built on this crate constructs it.
`SendWithResult` derives `PartialEq` and `Eq` for it. `Error::WalletReviewActions`
is unchanged in shape. The binary wire is unchanged: the processor frames
the refusal with code 5 and its words and the transceiver reads back the
`ReviewActions` class, no member on the wire, as the reference's frame
carries none (`tests/wire_wallet_refusal_class.rs` unchanged and green).
`double_spend.rs` reads the evidence from the refusal whichever substrate
built it; only the JSON substrate can carry it.

Migration: a literal `ReviewActionsRefusal { message, review_action_results }`
adds `send_with_results: vec![]`, `txid: None`, `tx: None` and
`no_send_change: None` (or calls `ReviewActionsRefusal::new`); a pattern
with `..` is unaffected. No downstream builds one (`bsv-wallet-toolbox-rs`,
`bsv-wallet-cli`, `rust-message-box`, `bsv-overlay-cloudflare`,
`bsv-middleware-cloudflare-public`, `rust-chaintracks` grepped;
`bsv-wallet-cli` builds `SendWithResult` literally, which the derives do
not change). A caller that matched `WalletRefusal` of the `ReviewActions`
class from `HttpWalletJson`'s createAction or signAction gets
`WalletReviewActions` when the body carries results, or the reference's
refusal of a malformed member (`WalletError` with its words).

A 200 createAction or signAction answer's `tx` is read by the same byte
reader (`normalize_success_tx`, then the result's type): the reference's
`HTTPWalletJSON` runs `normalizeBRC100WalletByteFields` on the success
body as on the error body, before `validateWalletResult`
(`HTTPWalletJSON.ts:322-341`), so a `tx` in the historical object form or
with a byte written `1.0`, which this crate refused as `failed to parse
JSON response`, is its bytes (the re-review's finding). The answer is read
by its type first (`serde_json::from_slice`, what `response.json()` did)
and through the byte reader's `serde_json::Value` tree only when that
refuses it: the tree costs about 32 bytes a byte, so reading every answer
through it (the second fold) peaked at 68,630,175 bytes on a 1 MiB `tx` in
the array form, where the typed reading peaks at 8,075,422 (dhat, the
mock's copy and the client's of the 3.7 MB body counted; 1cdd149's reading
the same 8,075,422), and the object form, read through the tree,
154,148,388. An answer neither reading takes is refused in `serde_json`'s
words, where it was reqwest's `failed to parse JSON response: error
decoding response body` (1cdd149) for every one: a body that is not JSON
with the typed reading's, its place in the text (`failed to parse JSON
response: expected ident at line 1 column 2`), a JSON body the reading
after the byte reader refuses with that reading's, no place (`failed to
parse JSON response: invalid type: string "x", expected a sequence` for
`{"tx": "x"}`); the other calls keep reqwest's words, and a body cut on
the way stays `WalletTransport` (#87).

Pinned by `tests/wallet_http_json_review_actions_339.rs` (9 tests) on
`tests/vectors/wallet_http_json_review_actions_339.json`: 41 bodies, 39
code-5 bodies answered to signAction, createAction and listActions and two
200 answers (a createAction's `tx` in the object form, a signAction's with
every byte written as an integral float, `$BEEF_FLOAT`), each with the
reference's `HTTPWalletJSON` outcome (its `WERR_REVIEW_ACTIONS` members, or
the words it threw) at `ts-stack@edf6e03` under Node v22.18.0, recorded by
`tests/support/wallet_http_json_review_actions_339.mjs` (the competing
transaction and BEEF #327's), each served through wiremock here: 38 read
to the reference's outcome (the two answers as their `txid` and `tx`), 3 otherwise and enumerated with their reasons
(below); the five members on signAction (a double spend with its BEEF, two
send results) and on createAction (txid, BEEF, change outpoint); five
refusals named; a `tx` and a `competingBeef` in the historical object form
(`{"0": 1, "1": 0, ..}`, what `JSON.stringify(new Uint8Array(..))` wrote),
which the reference's `normalizeBRC100WalletByteFields` reads back as
bytes before it reads the error (`BRC100ByteEncoding.ts:52-71`, `:164-190`;
`HTTPWalletJSON.ts:326-328`): at least one key, the keys exactly `"0"` to
`"n-1"` whatever their order in the text (`Object.keys` lists integer keys
ascending), each value an integer from 0 to 255 (`isByte`, so `1.0` too),
an empty object refused (`a_byte_field_in_the_historical_object_form_is_read_as_its_bytes`,
and two unit tests in `review_actions.rs` for the rule's edges); a body
without results the `WalletRefusal` of before; a 400 body whose `code` is
absent, `"5"` or `5.5` the same (the parity note's fourth shape,
`a_review_body_whose_code_is_not_a_safe_integer_is_the_class_refusal`,
green before and after: it pins #137's reading); and
the revocation of #327's run `double_spend_then_accepted` with signAction
answered through the substrate under wiremock (a code-5 body with the
competing transaction, then the signed one; #327's recording wallet gains
`sign_via`): the reference's calls, broadcasts and both signAction bodies.
4 of the 5 red on a copy with the substrate's reading removed (the struct
kept so the file compiles; the fifth pins the old reading, green on both).
The object form, the cold review's finding, was red on the reader before
it (`Invalid createAction result tx: expected an array of bytes`,
`Invalid wallet error reviewActionResults[0].competingBeef`), and so was
the unit test of its acceptance; the unit test of its refusals is green on
both. The two 200 answers were red on the substrate before
`normalize_success_tx` (`failed to parse JSON response: error decoding
response body`, both) and are green after
(`a_success_tx_in_the_object_form_or_integral_floats_is_read_as_its_bytes`);
the recorder before them reproduces the 39-case vector byte for byte, and
the 41-case vector is identical on a rerun. The cost is pinned by
`tests/memory_profiling.rs`'s
`test_http_json_success_tx_in_the_array_form_costs_the_typed_reading`
(the peak under four times the body's text; red at the second fold,
68,630,175 bytes, green at 8,075,422), the words by
`a_success_answer_neither_reading_takes_is_refused_in_serdes_words` (red
at the second fold on the body that is not JSON, reqwest's words).

### Notes: cross-SDK parity (#339)

Three bodies are read otherwise than the reference reads them, enumerated
in the test, and a fourth shape is stated here: a code-5 body without `reviewActionResults` stays the class
refusal of #137 (`WalletRefusal`; the reference refuses it,
`Invalid wallet error sendWithResults` or `reviewActionResults`); a code-5
body at a status other than 400 is the class refusal at any status, as
#137 reads every class (the reference: `HTTPWalletJSON <call> failed with
HTTP status <n>`); a 400 body with an own `isError` whose `code` is
absent, not a number (`"5"`) or not an integer (`5.5`) is read by #137's
rule, its class by `name` (`WalletRefusal`, `ReviewActions` for a
`WERR_REVIEW_ACTIONS` name), where the reference answers the one sentence
`Invalid wallet error envelope` for each (`HTTPWalletJSON.ts:204-206`,
`Number.isSafeInteger`; the cold review ran the three): conforming the
words would refuse the toolbox's base `toJson` bodies too (`isError`,
`name`, `message`, no `code`: `WalletError.ts:143-150`; the reference
answers `Invalid wallet error envelope` to one at 400, the re-review ran
it), which #137 reads by their `name` by design (the four subclasses that
set a code, `WERR_INVALID_PARAMETER` 6, `WERR_INVALID_MERKLE_ROOT` 8,
`WERR_INSUFFICIENT_FUNDS` 7 and `WERR_REVIEW_ACTIONS` 5,
`WERR_errors.ts:110`, `:136`, `:225`, `:278`, pass the envelope there;
the toolbox's `asStatus` bodies carry no `isError` and never reach the
envelope's words: the reference answers them `HTTPWalletJSON <call>
failed with HTTP status 400`); and the checks `validateWalletResult` makes of a
returned `tx`'s transaction against the request
(`validateCreateActionTransaction`, `validateSignActionTransaction`,
`validateTransactionValueConservation`) are not ported, as the success
path makes none of them either: a `tx` is read as a BEEF and bound to
`txid`, its outputs, inputs and values not compared with the request.
`actionBeefTransaction`'s three readings (strict atomic, partial
atomic, plain) are this crate's one `Beef::from_binary`, the subject the
transaction of `txid`, else the atomic subject, else the last full one.
A byte written past the double range (`1e400`) fails the whole body's
parse here (`serde_json`, #285), so a code-5 body holding one is answered
`HTTP 400 for <call>: <body>`, where the reference reads `Infinity` and
refuses the member (`Invalid createAction result tx: expected an array of
bytes`): both refuse, in other words. On the success path only
createAction's and signAction's `tx` is normalized; the other byte fields
the reference's `normalizeBRC100WalletByteFields` cleans (`signature`,
`ciphertext`, `hmac` and the rest) are read here as plain arrays of
integers, a stated difference this change leaves as it was (#365; read as
the reference reads them since #365's entry above). A
success answer neither reading takes is refused in `serde_json`'s words
(above), where the reference throws its runtime's `SyntaxError` for a body
that is not JSON and `validateWalletResult`'s words for a member
(`Invalid createAction result tx: expected an array of bytes`,
`HTTPWalletJSON.ts:322-341`): both refuse, in other words.
go-sdk@2ca481c's JSON substrate reads no error body as a typed error
(`wallet/substrates/http_wallet_json.go:62-64`: `HTTP request failed with
status <n>: <body>`).
`bsv-wallet-toolbox-rs` answers no review body over HTTP (its storage's
`notDelayedResults`, `src/storage/traits.rs:289,337`, are its own types),
so there is nothing of its to compare.

### Fixed: `SimplifiedFetchTransport` refuses a general answer without valid BSV authentication, in the reference's words (#354)

A general message's answer whose auth headers were absent was read as
optional (`src/auth/transports/http.rs:755-756` at `1cdd149`: "Auth
headers on response are optional") and became an `AuthMessage` whose
sender was the client's own identity key (`:794-802`), with no signature;
`Peer::start`'s callback hands a General message to the listeners without
verifying it, so a caller saw an unsigned answer it could not tell from a
signed one. The reference refuses it before the body becomes a message
(`#validateResponseAuthentication`, `ts-stack@edf6e03`
`packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:220-232`,
called at `:365` after the body is read): an answer missing any of
`x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-signature`,
absent or white space alone (`value.trim().length === 0`, `:227`), is
thrown in `#createUnauthenticatedResponseError`'s words (`:464-494`):
`Received HTTP <status> <statusText> from <url> without valid BSV
authentication (missing headers: <names>)`, the missing names in that
order joined by `, `, then ` - body preview: <preview>` when the body is
not empty (`#getBodyPreview`, `:512-540`: the first 1,024 bytes as text
when the content type is textual or has a `charset=`, or more than 80
percent of them printable, `:542-574`, else `0x` and their hex,
`:576-579`; cut at 512 UTF-16 code units with `…`; ` (truncated)` past
1,024 bytes).

This crate now refuses the same answer in the same words, after the body
is read and before any message is built
(`src/auth/transports/http/unauthenticated.rs`), and takes the sender from the answer's
`x-bsv-auth-identity-key`, never the client's own key. The class, by
#87's and #73's rules (`status_fault`, `fault_or`): an unsigned 429, 502,
503 or 504 is not the named host's own voice but a gateway's or a
limiter's, so it is `Error::TransportFault` with the answer's status and
those words as its detail, a 429 or a 503 with `Retry-After`
`RateLimited` with the wait it asks, a 502, a 503 without it or a 504
`MayHaveBeenReceived`; any other status is the named host's answer,
`Error::AuthError`, `transport_fault()` `None`. A signed answer of any
status, a 503 included, is read as before. The reason phrase is the
status line's own: fetch's `statusText`, which hyper keeps in the
answer's extensions as `hyper::ext::ReasonPhrase` when it is not the
canonical one (`hyper` 1.12 `proto/h1/role.rs:1071-1076`, `:1176-1180`), read here
through `reqwest::Response::extensions`, the canonical one when the line
carries that one; `hyper` is now a direct dependency of the `http`
feature (the one reqwest builds on, no new crate in the tree). The
handshake path: the reference applies no header check to the
`/.well-known/auth` answer (`:136-173`; its body is a signed
`AuthMessage` the `Peer` verifies), so neither does this crate; its
non-2xx handshake answer is thrown in the same function's words with
`response lacked required BSV auth headers` (`:143-151`), where this
crate keeps `Auth endpoint returned {status}: {body}` and its fault
classes (#87; `transport_fault_auth` pins them): a stated difference,
below.

Migration: a caller that read an unsigned general answer (a server whose
error path answers without the auth middleware's headers, a 401 among
them) now gets the refusal from `Transport::send`, and through `Peer`
from `to_peer`; one that matched an unsigned 429, 502, 503 or 504 by its
status reads `transport_fault()`. The toolbox's `StorageClient`
(`bsv-wallet-toolbox-rs` beta at `a12ab5c`,
`src/storage/client/storage_client.rs:520-616`, pinning
`=0.9.0-beta.1`) matched an unsigned answer by its request ID and read
its status (`HTTP error {status}: {body}`); it now sees `Failed to send
request: Received HTTP ...` for a refusal and keeps the SDK's error for a
transport fault (`e.transport_fault().is_some()`, `:574`). Its main
at `3a8610f` pins `0.8.0` and does not reach 0.9 without a move.
`bsv-wallet-cli` (main `e7844c4`, beta `687f0b6`),
`bsv-overlay-cloudflare` (main `c51e161d`) and `rust-message-box` (main
`44a6320`) build no `SimplifiedFetchTransport`.

Pinned by `tests/transport_unsigned_response_354.rs` (8 tests, wiremock,
and a loopback listener that writes a case's own reason phrase, which
wiremock cannot) against `tests/vectors/transport_unsigned_response_354.json`,
the reference's transport driven against a local `node:http` server by
`tests/support/transport_unsigned_response_354.mjs` (`ts-stack@edf6e03`,
Node v22.18.0; 22 cases, 20 refusals): a 200 with a JSON body and no auth
headers refused in those words; a 200 with two of the three (the
signature, the identity key, a blank version) refused naming the one
missing; every refusal the reference recorded (a 401, 429, 502, 503 and
504, an empty body, binary bodies short and past 1,024 bytes, text past
1,024 bytes, a cut through a surrogate pair, a BOM and ill-formed UTF-8,
a custom and a blank reason phrase) equal here byte for byte but one
(`READ_OTHERWISE`, the parity note), nothing handed to the callback; an
unsigned 429 and 503 with `Retry-After` `RateLimited` with 7 and 3
seconds, a 502, a bare 503 and a 504 `MayHaveBeenReceived`, each in the
refusal's words with its status; a 200 and a 401 `AuthError`; the three
headers read as before, the sender the answer's key, a signed 503 handed
to the callback. On the tree with the fault classes removed 2 of the 8
are red, with the reason phrase removed 3, both removed 4.
The arch rule's `charset=` line (`tests/arch_no_string_errors.rs`,
`docs/ARCH-RULES.md` section 3): the reference's `#isTextualContent` reads
the answer's `Content-Type` for it to choose the preview's form, a header
value, no class decided by it, now an allowed line with its reason.

### Notes: cross-SDK parity (#354)

go-sdk@2ca481c's `SimplifiedHTTPTransport` refuses an answer without
`x-bsv-auth-version` in its own words (`server failed to authenticate:
missing version header in response`,
`auth/transports/simplified_http_transport.go:190-193`) and one without
`x-bsv-auth-identity-key` (`missing identity key header in response`,
`:205-208`), and reads an absent `x-bsv-auth-signature` as an empty
signature (`hex.DecodeString("")`, `:214-218`), the `Peer` refusing it
later; it names one header, not the list. This crate follows the
reference's words. Four residuals: an unsigned 429, 502, 503 or 504 is a
`TransportFault` here, by #87's rule, where the reference throws the
same plain `Error` for every status (it has no fault class); a reason
phrase with a byte above `0x7e` (obs-text) is read as none here, the
status alone, where fetch's `statusText` reads it as UTF-8 (`Caf\xe9` reads as
`Caf\u{fffd}` there): hyper's parser (httparse 1.10 `parse_reason`)
empties such a phrase, and reqwest exposes nothing else; a lone high
surrogate the reference's 512-unit cut leaves is U+FFFD here, the bytes
the reference's text has once written as UTF-8; and a non-2xx handshake
answer keeps `Auth endpoint returned {status}: {body}` and #87's fault
classes here, where the reference's `#sendAuthMessage` throws
`#createUnauthenticatedResponseError`'s words with `response lacked
required BSV auth headers` (`SimplifiedFetchTransport.ts:115-151`; the
follow-up is #366).

### Fixed: `Peer`'s client path verifies the initial response and general messages as the reference's `Peer` does: the nonce, the session, the pinned identity, the signature (#353)

`Peer::start` installed a callback of its own (`src/auth/peer.rs:194-338`
at `1cdd149`) that marked a session authenticated on any `initialResponse`
without a check (`:258-275`) and handed any general message to the
listeners without a session or a signature (`:298-307`); the verifying path,
`handle_incoming_message`, was installed by `start_server` only. A client on
`start` took its server's answers unproven: an initial response signed by
anyone, from any identity, naming any nonce, authenticated a session, and a
general message carrying anyone's key reached the listeners. Behind it,
`initiate_handshake` dropped the identity it was given (`_identity_key`,
`:704`); `process_initial_response_inner` checked the responder's nonce
against the responder's key, which no wallet but the responder's can
match, and continued on the failure ("Nonce verification is optional,
continue anyway", `:857-874`); `process_general_message` looked its session
up by the sender's key, verified no `yourNonce` and required no nonce
(`:986-1013`).

`start` now installs `handle_incoming_message` (`start_server` calls
`start`), the one path of both roles, as the reference's `Peer` has one
(`ts-stack@edf6e03` `packages/sdk/src/auth/Peer.ts:766-794`). An initial
response is checked in the reference's order and words
(`authenticateInitialResponse`, `:886-930`): its `yourNonce` one this
peer's wallet made (`Initial response nonce verification failed from peer:
<key>`), its session found by it (`Peer session not found for peer:
<key>`), the responder the identity the handshake was asked for
(`initialResponse identity does not match the requested peer identity.`),
its signature (`Unable to verify initial response signature for peer:
<key>`), its `initialNonce` present (`Initial response message nonce is
required.`); a refusal reaches the waiting handshake, whose session is
removed, as the reference removes it (`:658-664`). A general message
(`processGeneralMessage`, `:1270-1314`): its `yourNonce` (`Unable to verify
nonce for general message from: <key>`), its session found by it (`Session
not found for nonce: <nonce>`), the session's peer the sender (`Peer
identity is not established for general message.`, `general identity does
not match the authenticated session.`, `:745-759`), its signature (`Invalid
signature in generalMessage from <key>`), its nonce (`General message nonce
is required.`) and the session's (`Session nonce is required for general
messages`); the session is then marked authenticated and a listener's
error is the message's, as the reference's are (`:1315`, `:1329-1331`).
`initiate_handshake` pins the session to the identity key it is given and
refuses a string that is not one (`PublicKey::from_hex`'s error, before a
nonce is made). A wallet whose verify call refuses a miss
(`ProtoWallet`'s `Signature is not valid`) refuses in its own words before
the Peer's, on both sides.

Migration: a client on `start` that accepted unsigned or unproven answers
now refuses them: an initial response from another identity than the one
asked for, or not signed over the two nonces, fails the handshake; a
general message (over `SimplifiedFetchTransport`, an HTTP response) without
the server's signature, its nonce and the client's `yourNonce` is refused
and the request returns the error. A server that signs its responses, as
the reference's middleware does, is unaffected. A peer on `start` now
answers an initial request, as one on `start_server` did. `start_server`
keeps its signature. `get_authenticated_session`, `to_peer` and
`request_certificates` given a string that is not an identity key and
names no authenticated session now refuse it rather than handshaking with
whoever answers. The toolbox's storage client (`bsv-wallet-toolbox-rs`,
`src/storage/client/storage_client.rs:293-303`) runs on `start`, so its
server's answers are now proven. Its `verify_responses` (`:263`, `:313`,
`:347-348`) is the toolbox's field, not this crate's: set and never read
there, it meant nothing before this change and the `Peer` verifies
whatever it says after it; nothing in this crate is named by it, and its
removal is the toolbox's.

Pinned by `tests/auth_peer_client_verifies_353.rs` (8 tests; 10 with the drop below) on
`tests/vectors/auth_peer_client_verifies_353.json`, recorded by
`tests/support/auth_peer_client_verifies_353.mjs` at `ts-stack@edf6e03`
under Node v22.18.0: a reference client `Peer` (scalar 41) pinned to its
server (42) given an initial response forged at one field (a wrong
signature, mallory's (43) identity, a `yourNonce` not its own) and, after
an honest handshake, a general message forged at one field (a wrong
`yourNonce`, no nonce, mallory's signature, mallory's identity), each
verdict recorded with the client on a `ProtoWallet` and on a wallet
answering `{ valid: false }` where `ProtoWallet` throws. Here each case
runs over an in-process transport whose deliveries go through the callback
`start` installs: every forgery refused, the listener not called, no
session authenticated, in the reference's words save three stated below;
the honest response and message accepted; a handshake pinned to mallory
refused with its session gone; two peers both on `start` handshaking and
exchanging three messages each way. 5 of 8 red on the tree before the fix
(a scratch copy of `1cdd149` with the file added; the honest cases and the
vector's check pass on both). `auth_integration_tests.rs`'s TS-style
response and `auth_peer_e2e_tests.rs`'s session-less general message now
carry a nonce the receiving wallet made, the nonce being checked first.

The callback `start` installs owns a Peer over the same state, its
transport held weakly (`TransportHold::Callback`, upgraded for each send):
a Peer holding the transport strongly from inside the transport's own
callback is a cycle, and a Peer dropped after `start` (or an
`Arc<Peer>` after `start_server`, a cycle already at `1cdd149`) never
freed its transport, wallet, sessions or listeners, as the reference's
`Peer`, which holds no reference to itself, is freed. Pinned by
`a_dropped_peer_on_start_frees_its_transport_353` and
`a_dropped_peer_on_start_server_frees_its_transport_353` (the transport's
marker count back to 1 after the drop; both red on this branch before the
weak hold, `left: 2`). A signing server's acceptance over HTTP is pinned
by `tests/auth_peer_http_signing_server_353.rs` (3 tests, wiremock): a
server whose initial response and general response this crate's writer
and signer build (the payload `HttpResponse::to_payload` writes from the
request ID, status, `x-bsv-*` header and body, the reference client's
`SimplifiedFetchTransport.ts:289-323`, signed under
`<nonce> <clientSessionNonce>`) answers a client on `start` over
`SimplifiedFetchTransport`, the listener given the response; the same
server signing with another key is refused (a `ProtoWallet`'s
`Signature is not valid`), and not signing is refused.

### Notes: cross-SDK parity (#353)

The verdicts are the reference's; three words are not. The reference's
`verifyNonce` asks its wallet's `verifyHmac` (`verifyNonce.ts:44-53`),
which a `ProtoWallet` throws on (`HMAC is not valid`) before the Peer's
words; this crate's `verify_nonce` recomputes the HMAC with `create_hmac`
(it compares the 16 bytes a legacy 32-byte nonce keeps) and so reaches the
Peer's words on the initial response and the general message. The
reference's message snapshot refuses a general message without a nonce
(`general.nonce must be canonical base64.`, `snapshotAuthMessage`,
`Peer.ts:767`) before its Peer's `General message nonce is required.`;
this crate has no snapshot, and the Peer's check refuses it. Two of the
reference's checks are not here, each its own finding: the replay claim of
every message nonce (`#claimIncomingMessageNonce`, `:258-272`; Go's
`claimMessageNonce`), and the `yourNonce` and identity checks of a
certificate request and response (`:1044-1068`, `:1177-1200`), which here
still find their session by the sender's key and verify its signature.
A third is not here either: the reference awaits a session's pending
certificate validation before it hands a general message to its listeners
when the session requires certificates (`#waitForCertificateValidation`,
`Peer.ts:1318-1325`, a 30-second timeout resolved by the certificate
response's processing, `:286-329`); here the listeners are called at
once. It is not one guarded await: this crate has no pending-validation
registry, and `certificates_validated` is never set (the certificate
response's `get_session_mut` looks up by an identity key where the
manager keys by nonce), so the wait would time out every message of a
session that requires certificates; it goes with that finding, #364.

One refusal is in other words. An HTTP response without the auth
headers (`x-bsv-auth-version`, `x-bsv-auth-identity-key`,
`x-bsv-auth-signature`) is refused by the transport in the reference's
words since #354 (`Received HTTP <status> from <url> without valid BSV
authentication (missing headers: ...)`, `SimplifiedFetchTransport.ts:365`, the
call into `:220-232` and `:464-494`; pinned by `an_unsigned_server_response_is_refused_353`), where
#353 alone gave it the client's own key and the Peer refused it. An
initial response or a general message without `yourNonce` is read as the
empty nonce and refused by the nonce check (`Initial response nonce
verification failed`, `Unable to verify nonce for general message`), where
the reference's message snapshot refuses the absent member first
(`Peer.ts:767`).

Go's `Peer` (`go-sdk@2ca481c` `auth/peer.go`) verifies an initial
response's `yourNonce` against its own wallet (`ErrInvalidNonce`,
`:624-631`), finds the session by it (`ErrSessionNotFound`, `:633-636`),
verifies the signature over the two nonces (`initial response -
invalid-signature`) and claims the responder's nonce (`:675`), but does
not compare the responder with the identity `initiateHandshake` stored
(`:344`): it overwrites it with the message's (`:680`), so a Go client
pinned to one key accepts another's signed response. Its general message:
`yourNonce` (`:991-998`), the session by it (`:1003-1006`), the session
authenticated (`ErrNotAuthenticated`, `:1009-1011`, a check the reference
does not make and this crate no longer makes: the reference marks the
session authenticated after the signature), the signature over the payload
under `<nonce> <sessionNonce>`, the nonce required and claimed (`:1041`).
The comment this fix removes, that Go and TS let a failed nonce pass, was
wrong of both: each refuses it, and the nonce it checked here was the
responder's, which neither checks.

### Changed: the fuzz_http_json_responses harness names an originator (#356)

Since #323 `HttpWalletJson::with_client` returns `Result` and the substrate
refuses a call with no originator configured before any request, so the
target built with `with_client(client, None, ..)` did not compile and,
compiled, would have fuzzed nothing. The harness now passes the originator
`fuzz.invalid` and unwraps the constructor (its base URL is the harness's own
loopback). CI builds no fuzz target, so only `cargo fuzz` and the nightly saw
it.

### Fixed: the ARC default arch test reads a CRLF checkout as it reads LF (#367)

`no_live_policy_default_chooses_the_arc_policy_url`
(`tests/arch_arc_deprecated.rs`, #350) found each `impl Default` block's end
with `find("\n}\n")` on the raw text of `live_policy.rs`; a Windows checkout
holds it in CRLF, so the `expect("the impl's closing brace")` panicked on the
`Test Suite (windows-latest, stable)` and `(windows-latest, beta)` cells (run
40513515368; not in beta's required set, so no PR went red). The test now reads
through `arch_support::read`, which normalizes `\r\n` to `\n` before any
search, as `arch_ci_lines`, `arch_ci_pr_runs_the_required_set` and
`arch_secrets_scan_scope` already did for the workflows; `arch_support::sources()`,
the lexical rules' reader, normalizes the same way (their lexer already
tolerated a CR, so no verdict moves). Pinned by
`a_crlf_checkout_finds_the_impl_closing_brace_as_lf_does`, red without the
normalization. No other test under `tests/` searches raw file text for a
LF-only needle.

### Changed: `WalletInterface` takes `originator: Option<&str>`, the reference's optional, so an absent originator and an empty one are two values (#329)

`WalletInterface`'s 28 methods took `originator: &str`, so an absent
originator and `""` reached a wallet as one value, and a wallet behind the
trait could not give the reference's two verdicts: `validateOriginator`
accepts `undefined` and refuses `""` by its 1 to 250 length rule
(`ts-stack@edf6e03` `packages/sdk/src/wallet/validationHelpers.ts:1003-1006`).
The reference's interface carries `originator?:
OriginatorDomainNameStringUnder250Bytes` on all 28 methods
(`packages/sdk/src/wallet/Wallet.interfaces.ts`, 28 sites). The keeper's
ruling of 2026-10-27, under the owner's ruling (c) of 2026-10-26, carries
the change on the 0.9.0 line before the 0.9.0-beta.2 cut.

- The trait's 28 methods take `originator: Option<&str>`; `ProtoWallet`
  (which ignores it, as before) and `HttpWalletJson` implement it so, and
  `WalletWireTransceiver`'s 28 methods and the auth helpers that hand an
  originator to a wallet (`create_nonce`, `verify_nonce`,
  `validate_certificates`, `validate_certificate`,
  `get_verifiable_certificates`, `MasterCertificate`'s and
  `VerifiableCertificate`'s certificate methods) take the same type.
- A client passes `None` when it has no originator configured, the
  reference's `undefined`, and its configured one as given otherwise,
  `Some("")` included, never mapped to `None`: `WalletClient` (`""` before),
  `IdentityClient` (`""`, #318's absent originator, before),
  `ContactsManager` (`""` before), `LocalKVStore`
  and `GlobalKVStore` (`"kvstore"` before), `RegistryClient`
  (`"registry-client"` before) and `Peer` (`"unknown"` before), as the
  reference's `IdentityClient`, `ContactsManager`, `LocalKVStore`,
  `GlobalKVStore`, `RegistryClient` and `Peer` pass their constructor's
  `originator?` (`Peer.ts:145-152`, `ContactsManager.ts:288-290`,
  `LocalKVStore.ts:116-126`, `RegistryClient.ts:271-274`).
- The binary wire: the transceiver writes `None` (and `Some("")`) as the
  length-0 originator, as it wrote `""`, and the processor reads length 0
  back as `None`, a named originator as given (`""` before).
- The HTTP JSON substrate sends a call's non-empty `Some` as its
  `Originator` header, and for `None` (or `Some("")`, which no header
  carries apart from absence) its configured originator, else no header,
  as it did for `""`. The substrate's own rule (the configured originator
  required, both headers) is #323's.

Migration, one line per downstream (counted at their beta lines,
`bsv-wallet-toolbox-rs@0daecd0` and `bsv-wallet-cli@2f8e6cf`, both
pinning `=0.9.0-beta.1`, and `bsv-overlay-cloudflare@c51e161d`,
`rust-message-box@44a6320` at main):

- `bsv-wallet-toolbox-rs`: `originator: Option<&str>` at the two impls,
  `Wallet` (`src/wallet/wallet.rs:1755`) and the test `MockWallet`
  (`src/managers/permissions_manager.rs:1219`), 28 methods each; its
  `validate_originator` then reads `None` as absent and `Some("")` as the
  reference's refusal, and the interim `""`-as-absent reading of #329
  goes; `Some(originator)` (or `None`) at each call: 92 sites the compiler
  names in the library and its unit tests against this tree (56 of them
  the two impls' signatures; 29 other errors there are beta's own since
  0.9.0-beta.1 and appear against beta's tip too), its `tests/` and
  `benches/` not reached past the library (about 15 calls there by grep).
- `bsv-wallet-cli`: `Some(&originator)` at each wallet call, about 55
  calls by grep (26 in `src/server/handlers.rs`); it implements no trait.
- `bsv-overlay-cloudflare`: nothing; its wallet calls are `ProtoWallet`'s
  inherent methods and its `PeerOptions` already carry `Option<String>`.
- `rust-message-box`: `Some(..)` at its 5 `create_nonce` calls
  (`src/engineio/auth.rs`): four pass the constant `ORIGINATOR`
  (`:247`, `:563`, `:610`, `:670`) and one the literal
  `"bsv-auth-cloudflare"` (`:787`), when it moves from `=0.6.0`.
- A `PeerOptions`, kvstore, registry, identity or contacts configuration
  that relied on the old default originator (`"unknown"`, `"kvstore"`,
  `"registry-client"`, `"identity-client"`) now sends none; configure it
  to keep sending one.

The change is a major: every implementer and every caller of the trait
changes. `cargo semver-checks` does not name it (`--release-type minor
--baseline-rev b09a81a`: 202 checks pass, "no semver update required"; it
has no lint for a changed parameter type), so this sentence is the record;
the keeper's ruling under (c) carries it on the 0.9.0 line.

Pinned by `tests/wallet_originator_option_329.rs` (12 tests): `None`
written on the binary wire as the length-0 originator and read back by the
processor as `None` (and a frame of length 0 written by hand); a named
originator round-tripped byte for byte; `Some("")` written as length 0 and
read back as `None`; `Some("")` reaching an in-process wallet as
`Some("")`; the JSON substrate refusing a call with no originator configured
before any request (#323's rule, in the reference's words) and sending the
configured one as both headers for `None`; the identity
client (`""` configured reaching the wallet as `Some("")`), the contacts
manager, the local and global kvstores (the overlay a facilitator that
cannot succeed), the registry client and `Peer` passing `None` with none
configured and `Some` when configured, each through a recording wallet.
On beta's tip (`b09a81a`) the file does not compile (62 errors: the trait takes no
`Option`); on this tree with the behaviour reverted (the processor's
length 0 read as `Some("")`, the clients' old defaults back) 8 of the 12
fail, the 4 others pinning what held before (a named originator, the
in-process call, the JSON substrate's refusal and its configured-header case). Every mock and
caller in `tests/`, the fuzz targets and the doc examples moved with the
trait; #318's counting wallet (`tests/support/identity_reveal_wallet.rs`)
keeps each call's originator as an `Option`, and
`tests/identity_wallet_calls_318.rs` reads the reference's `null` as
`None` where it read it as `""`, its 4 tests unchanged otherwise.

### Notes: cross-SDK parity (#329)

go-sdk@2ca481c's `wallet.Interface` takes `originator string` on all 28
methods (`wallet/interfaces.go`), `""` for none: one value for absence and
an empty string, as this crate had; the reference's optional is followed.

The reference's processor reads a length-0 originator as `''`
(`WalletWireProcessor.ts:292-294`, `decodedOriginator === '' ? '' :
validateOriginator(...)`) and hands `''` to its wallet; this crate's
processor hands `None`, the reading the ruling asks, so a wallet behind it
accepts a wire call that names no originator where a reference wallet that
validates `''` refuses it. The reference's transceiver writes `''` for an
absent one (`WalletWireTransceiver.ts:92-100`), as this crate's writes
`None` and `Some("")`: on the wire the two are one value in both SDKs. The
reference's processor also refuses a length above 250 and normalizes a
named originator through `validateOriginator` (`:286-294`); this crate's
does neither: a finding outside #329.

### Changed: the oracles run on demand, the nightly schedule removed (the owner's word of 2026-10-27)

The owner's fleet word of 2026-10-27: the nightly runs were a waste of
resources. The `schedule` trigger is gone from `.github/workflows/nightly.yml`
on both lines (the 03:00 UTC cron of #283 and #284 and its cap are moot);
`workflow_dispatch` stays, so the mutation shards, the fuzz hours, the
scoreboard and `ci.yml`'s full set on each line run when asked: one dispatched
measurement before each minor tag, none for a prerelease. The push matrix on
the protected branches is unchanged (the rule of 2026-10-26). `docs/NIGHTLY.md`
and `docs/ARCHITECTURE.md` say so.

### Fixed: the HTTP wallet substrates take the reference's originator rule, headers, redirect refusal and base URL form (#323)

`HttpWalletJson` and `HttpWalletWire` validated nothing at construction,
sent a call's originator in preference to the configured one, sent one
header (`Originator` from the JSON substrate, `Origin` from the wire, both
in the origin form), sent none when no originator was set, followed up to
ten redirects (reqwest's default) and took any base URL;
`validate_originator` checked lengths alone. The reference's substrates
(`ts-stack@edf6e03` `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:280-314`,
`HTTPWalletWire.ts:17-20`, `:43-66`, `utils/toOriginHeader.ts`) and its
`validateOriginator` (`validationHelpers.ts:996-1037`) do otherwise, and
this crate now does as they do:

- `validate_originator` (now `wallet/validation/originator.rs`) is the
  reference's: trimmed, lower-cased, 1 to 250 bytes, a canonical DNS
  hostname with an optional port (1 to 5 digits, at most 65535), the port
  dropped from the answer (`Example.com:8080` is `example.com`), each
  refusal `WalletRefusal` of class `InvalidParameter` in the reference's
  words (`The originator parameter must be a canonical DNS hostname with an
  optional port`, `The originator part parameter must be no more than 63
  length.`). A scheme-prefixed originator is refused, as the reference
  refuses it (the colon reads as a port separator), so `toOriginHeader`'s
  path-trimming branch is never reached through a constructor.
- Both constructors validate the originator and normalize the base URL to
  its origin (`normalizeWalletHttpBaseUrl`): no credentials, path, query or
  fragment, at most 2048 units, no surrounding whitespace, cleartext HTTP
  only to `localhost`, `*.localhost`, `127.0.0.1` or `[::1]`, each refusal
  in the reference's words (`Wallet HTTP baseUrl may use cleartext HTTP only
  for a loopback host.`).
- `HttpWalletJson` sends the constructor's originator, never a method's
  `originator` argument, as both `Origin` and `Originator` in the origin
  form (`http://example.com`), with `Accept: application/json`; a call with
  none configured is refused before a request, `HTTPWalletJSON: originator
  is required when using the HTTP substrate in Node.js. Pass an originator
  (e.g. "example.com") to the constructor.`; a body over 256 MiB
  (`MAX_WALLET_JSON_REQUEST_BYTES`) is refused unsent. The reference skips
  the originator rule in a browser, whose `fetch` sets `Origin` itself;
  `http` is native-only here (`build.rs`, #152), so the rule is
  unconditional.
- `HttpWalletWire` validates the frame's originator (more than 250 bytes
  refused in the reference's words) and, when one is configured, refuses a
  frame whose originator is not it (`Wallet Wire frame originator does not
  match the configured originator`), so a frame with none is refused too;
  it sends the frame's originator raw as `Origin` (`example.com`), empty
  when the frame has none. A frame over 256 MiB is refused.
- The client `new` builds takes `redirect::Policy::none()`, the reference's
  `redirect: 'error'`: a 3xx is answered `WalletError("HTTP 302 Found for
  <call>: a redirect is refused")` and never followed. A client given to
  `with_client` is used as given, its redirect policy too. reqwest's wasm32
  client has no redirect policy (`reqwest-0.12.28/src/wasm/client.rs`; the
  host's `fetch` follows): moot while `http` does not build for wasm32.

Migration: `HttpWalletJson::new`, `HttpWalletJson::with_client`,
`HttpWalletWire::new` and `HttpWalletWire::with_client` keep their
arguments and return `Result<Self, Error>` (add `?`), the Rust form of the
reference's throwing constructor (the owner's ruling (c) of 2026-10-26,
recorded on the issue). A `None` originator now fails at the first
`HttpWalletJson` call in the reference's words (`WalletClient` with `None`
on a JSON substrate too), so `WalletClient`'s auto-detection
(`SubstrateType::Auto`) with a `None` originator now passes over both JSON
substrates, whose `getVersion` probe is refused unsent, and lands on the wire
substrate at `http://localhost:3301`, or fails when no wallet answers there,
where it used to connect to the first JSON wallet that answered: pass an
originator to keep the JSON substrate; a base URL with a path or a cleartext non-loopback
host is refused at construction; a wire frame whose originator differs from
the configured one is refused. No downstream constructs either substrate or
calls `validate_originator` (`bsv-wallet-toolbox-rs` `6317222`, which has
its own `validate_originator`; `bsv-wallet-cli` `a55990c`;
`bsv-overlay-cloudflare` `9a0f3c29`; `rust-message-box` `419bf18`; grepped
2026-10-27).

Pinned by `tests/wallet_http_originator_323.rs` (10 tests, wiremock): 10 of
10 red on the tree before the fix (the constructors' `Result` shape shimmed
in, the behaviour the old; the tenth, a wire frame of 256 MiB + 1 bytes
refused unsent, added by the review's fold), green after; the rules' unit
tests in `wallet/substrates/origin.rs` and `wallet/validation/originator.rs`.
Both rules trim as JavaScript's `String.prototype.trim` does, one helper
(`validation::trim_js`): U+FEFF trimmed and U+0085 kept, where Rust's
`str::trim` does the reverse, measured with the reference's
`validateOriginator` and `HTTPWalletJSON` constructor under Node 22.18.0
(`the_trim_is_javascripts_feff_trimmed_and_u0085_kept`,
`a_base_url_is_trimmed_as_javascript_trims_feff_and_not_u0085`). The
existing `wallet_http_*`, `transport_fault_wallet`, `wallet_internalize_*`
and two `auth_certificate_*` files configure an originator and are
otherwise unchanged.

### Notes: cross-SDK parity (#323)

go-sdk@2ca481c validates nothing: `NewHTTPWalletJSON` and
`NewHTTPWalletWire` take any originator and base URL
(`wallet/substrates/http_wallet_json.go:22-33`,
`http_wallet_wire.go:20-31`), the JSON substrate sends `Originator` raw and
only when set (`http_wallet_json.go:51-53`), the wire the frame's `Origin`
raw with no comparison to the configured one (`http_wallet_wire.go:81-83`),
and both follow redirects (`http.DefaultClient`). The redirect refusal's
words are this crate's: the reference's `fetch` throws its runtime's
`TypeError` (`fetch failed` under Node). The wire's response bounds
(`HTTPWalletWire.ts:71-116`: `Content-Length` and a 256 MiB body) and the
JSON substrate's `validateWalletArgs` before the request are not carried:
findings outside #323.

### Deprecated: the ARC client surface, nowhere a default (#350)

The owner's word of 2026-10-27: "arc is just deprecated, arcade is the
standard"; for this crate, any ARC client surface is marked deprecated and
is never a default. `ArcBroadcaster`, `ArcConfig`, `ArcBroadcaster::new`,
`ArcBroadcaster::with_config`, `LivePolicy::new` and `DEFAULT_POLICY_URL`
carry `#[deprecated(since = "0.9.0", note = "ARC is deprecated; ARCade is
the standard (the owner's word of 2026-10-27)")]` (the two `LivePolicy`
items add the migration: `use LivePolicy::with_url`). Nothing is removed
and nothing ARC does changes: the broadcaster's verdict, its transport
faults and its tests are as they were.

rustc refuses `#[deprecated]` on a trait impl block, so a `Default` cannot
be deprecated by itself. `ArcBroadcaster::default()` (`https://arc.taal.com`)
and `ArcConfig::default()` warn through their deprecated types (naming the
type is the use). `LivePolicy` is not ARC's (it reads any policy endpoint
in ARC's schema, and ARCade serves that schema at `/v1/policy`,
`arcade@1dbd889` `services/api_server/routes.go:294-297`), so the type stays
undeprecated and its two `Default`s stop choosing ARC: `LivePolicy::default()`
and `LivePolicyConfig::default()` carry an empty `policy_url`, which
`refresh()` refuses before any request (`Error::FeeModelError("No policy
URL: build the LivePolicy with with_url (ARC is deprecated and no default,
bsv-rs#350)")`), `compute_fee` using the fallback rate as it did before a
refresh. `LivePolicy::new()` (deprecated) still reads ARC's GorillaPool
policy. Of the brief's two shapes for `new` (deprecated, or made to take
the URL), deprecating it is the reference's shape minus the ARC default:
the reference's `LivePolicy` takes no URL and reads ARC
(`ts-stack@edf6e03` `packages/sdk/src/transaction/fee-models/LivePolicy.ts:10`),
this crate's `new()` is that constructor and `with_url` the one with the
URL; changing `new`'s signature would break every caller to say what the
deprecation says, and `--release-type minor` refuses that break.

The docs: the broadcasters' `CLAUDE.md` no longer calls ARC "recommended
for production" and its examples broadcast through WhatsOnChain and
Teranode; `Transaction::to_beef_v1` is documented by its format (BRC-62, no
TXID-only entries), not "for ARC"; the transaction and fee models'
`CLAUDE.md` name no ARC default. This crate adds no ARCade client (below).

The crate's own uses: the module that defines the ARC items
(`src/transaction/broadcasters/arc.rs`, `#![allow(deprecated)]`), the
re-exports (`broadcasters/mod.rs`, `fee_models/mod.rs`, `transaction/mod.rs`,
an `#[allow(deprecated)]` each), and the tests of ARC's wire
(`tests/broadcaster_http_tests.rs`: the import and the ten ARC tests;
`tests/transport_fault_broadcasters.rs`: the import and the ARC arm of
`Service::broadcaster`) keep the ARC items under `#[allow(deprecated)]`
with the reason. They test ARC's own wire, so no other broadcaster could
replace them. `LivePolicy`'s fallback, rate and TTL tests (five in
`tests/live_policy_http_tests.rs`, four in the module) move from `new()` to
`default()`; the two that pin `new()`'s ARC URL keep it under an allow. No
example, bench or README block names an ARC item.

Pinned by `tests/arch_arc_deprecated.rs` (2 tests, read from the source as
the other `arch_*` rules are): each of the six items carries
`#[deprecated(since = "0.9.0", ..)]` with the note naming ARCade, and
neither `LivePolicy` `Default` names `DEFAULT_POLICY_URL`, an ARC host or
`Self::new()`; both red on the base (the six items listed, the config's
`Default` naming the URL), green on the fix. The refusal:
`a_live_policy_built_without_a_url_refuses_to_refresh_and_reads_no_arc`
(`tests/live_policy_http_tests.rs`) and
`a_live_policy_with_no_policy_url_refuses_to_refresh` (the module). Their
URL assertions are red on the base, run there with the network denied (only
localhost reachable): each fails at its first URL assertion, the base's
`Default` holding `https://arc.gorillapool.io/v1/policy` where the fix holds
none. A
scratch crate under `#![deny(deprecated)]` naming each item builds on the
base and fails on the fix with nine errors, one per use.

Migration: a caller of `ArcBroadcaster` or `ArcConfig` gets a warning
(an error under `-D warnings`) and keeps working; move to ARCade (the
wallet toolbox's `Arcade` provider) or another `Broadcaster`, or add
`#[allow(deprecated)]`. A caller of `LivePolicy::new()` passes the URL:
`LivePolicy::with_url("<host>/v1/policy")`. A caller of
`LivePolicy::default()` or of `LivePolicyConfig { .., ..Default::default() }`
without a `policy_url` now has `refresh()` refused and stays on the
fallback rate until it sets one. The downstreams have no site at their tips:
`bsv-wallet-toolbox-rs` (`a3377ef`) uses its own `services::{Arc,
ArcConfig, Arcade}`, `bsv-wallet-cli` (`f4285bf`) imports the toolbox's
`ArcConfig` (`src/services_env.rs:21-24`), `bsv-overlay-cloudflare`
(`8c18730c`) defines its own `overlay_engine::broadcaster::ArcBroadcaster`
trait (`crates/overlay-engine/src/broadcaster.rs:53`) and
`WorkerArcBroadcaster`/`ArcadeBroadcaster`, and `rust-message-box`
(`08418ec`) names none. No downstream names `LivePolicy` or
`DEFAULT_POLICY_URL`.

### Notes: cross-SDK parity (#350)

The reference keeps ARC undeprecated and as its default:
`defaultBroadcaster` returns an `ARC` on `https://arc.gorillapool.io`
(testnet `https://testnet.arc.gorillapool.io`; `ts-stack@edf6e03`
`packages/sdk/src/transaction/broadcasters/DefaultBroadcaster.ts:1-12`),
`ARC.ts` carries no deprecation, and `LivePolicy` reads
`https://arc.gorillapool.io/v1/policy` with no way to pass another URL
(`LivePolicy.ts:10`). This crate diverges under the owner's word: ARC
deprecated, no default broadcaster or policy URL. ARCade is a service of
the toolbox and the overlay layer in the reference
(`packages/wallet/wallet-toolbox/src/services/`,
`packages/overlays/overlay-express/src/ArcadeProvider.ts`), not an SDK
broadcaster, so this crate adds no ARCade client; the toolbox's side has
one. go-sdk@2ca481c keeps `broadcaster.Arc` undeprecated and makes it no
default: `transaction/broadcaster/arc.go:37` is a plain `Arc{ApiUrl, ApiKey, ..}`
struct with no constructor and no default URL (GorillaPool appears only in
`docs/examples/broadcaster/broadcaster_gp/broadcaster_gp.go:16`), and Go has no
`LivePolicy` (`transaction/fee_model/` holds `sats_per_kb.go` alone): the
caller names every ARC URL there, as this crate now asks.

### Fixed: the contacts manager and the key-value stores send signAction the reference as the wallet answered it, with the reference's options (#326)

Six signAction calls sent the reference createAction answered as the hex
of its bytes: the contacts manager's update and removal
(`src/identity/contacts.rs`, `update_contact_on_chain` and
`remove_contact`), `GlobalKVStore::set` and `remove`, and
`LocalKVStore::set` and `remove`. A wallet answers
`signableTransaction.reference` as a base64 text; this crate holds it as
the text's decoded bytes (`SignableTransaction.reference`, base64 in JSON),
the binary wire's transceiver decodes the text back
(`src/wallet/wire/transceiver.rs:667-668`) and the HTTP JSON substrate
carries it, so the hex text named an action no wallet made (the binary
wire's transceiver decoded it as base64 to other bytes). Each call now sends
the text as answered, `to_base64` of the bytes, as the registry client and
since #318 the revocation do. The reference's contacts manager sends
`signAction({ reference, spends })` and nothing else (`ts-stack@edf6e03`
`packages/sdk/src/identity/ContactsManager.ts:813-834`, `:981-1001`); this
crate's sent `options: { acceptDelayedBroadcast: false }` beside them, and
now sends no options. The reference's stores sign through
`completeBoundAction` (`packages/sdk/src/wallet/completeBoundAction.ts:1111-1120`;
`kvstore/GlobalKVStore.ts:319-389`, `:473-488`;
`kvstore/LocalKVStore.ts:413-425`, `:515-537`), whose signAction carries
`{ acceptDelayedBroadcast, returnTXIDOnly: false, noSend, sendWith }`
from the createAction's options; this crate's stores sent no options, and
now send that object, carried from their createAction's
(`kvstore::bound::bound_sign_options`). Their createAction sends no
options, so the carried members are absent and the object is
`{ returnTXIDOnly: false }` (the parity note).

Migration: none for a caller of the six methods. A wallet that keys its
pending actions by the text it answered (the reference's, and any behind
the binary wire or the HTTP JSON substrate whose answer this crate decodes
to `SignableTransaction.reference`) now finds the action where it refused
one it did not know. `bsv-wallet-toolbox-rs` (`6317222`) keys its pending
signs by its text (`src/wallet/wallet.rs:1860-1878`; the text a random
base64 of 12 bytes, `src/storage/sqlx/create_action.rs:352-363`) and holds
`SignableTransaction.reference` in-process as the text's UTF-8 bytes
(`src/wallet/wallet.rs:1526`, `:1629`), not its decoded bytes, until its
beta at `37e27ab` (PR #288, its #285), which holds the decoded bytes. Behind
`bsv-wallet-cli` (`a55990c`), whose createAction answers the toolbox's text
on the HTTP JSON wire (`src/server/handlers.rs:698-706`,
`src/spend_gate.rs:699-701`) and whose signAction hands the text received
to the toolbox (`src/server/handlers.rs:1045-1049`), these clients' calls
are now found, where the hex of the decoded bytes was refused (`No pending
transaction found for reference`). An in-process toolbox `Wallet` under
these clients is sent the base64 of its text's bytes where it was sent
their hex, and refuses both; behind this crate's binary wire the same
bytes cross (the processor writes them, the transceiver reads them) and
the processor refuses createAction's and signAction's reference
(`src/wallet/wire/processor.rs:545-556`; `:560` is abortAction's), the same. The in-process
reference is the toolbox's difference from this crate's type; a toolbox
holding `from_base64(text)` would be found on every path, as the registry
client's `String::from_utf8` of the bytes (`src/registry/client.rs:699`,
`:928`) is found in-process and not over a wire. No downstream calls the
contacts manager or either store (`bsv-wallet-toolbox-rs`,
`bsv-wallet-cli`, `rust-message-box`, `bsv-overlay-cloudflare` grepped;
`bsv-middleware-cloudflare-public` and `rust-chaintracks` are not on the
host the lane ran on).

Pinned by `tests/contacts_signaction_326.rs` (2 tests) and
`tests/kvstore_signaction_326.rs` (4 tests) on
`tests/vectors/signaction_reference_326.json`: the reference's contacts
manager updating and removing a contact, and its two stores setting a key
with no token, updating it and removing it, each signAction as its wallet
received it (the JSON text, its members, its options' members, the spend
indexes) with the createAction options it completed; recorded by
`tests/support/signaction_reference_326.mjs` at `ts-stack@edf6e03`
(bundled with an entry re-exporting `ContactsManager`, which `mod.ts` does
not export) under Node v22.18.0, the randomness #310's SHA-256 counter
stream (two runs byte for byte). This crate's clients, over the counting
wallet of #318 (`tests/support/identity_reveal_wallet.rs`, which now lists
a token and answers createAction with a signable transaction spending it),
send the reference's text, the reference's members and spend indexes, and
the contacts manager's arguments equal to the reference's member by member
(the unlocking scripts aside); each store's options are
`completeBoundAction`'s rule applied to its own createAction's, as the
reference's are to its. 6 of 6 red on the tree before the fix at the
reference text, and 6 of 6 red at the members with the encoding alone
fixed; the contacts and kvstore witnesses unchanged.

### Notes: cross-SDK parity (#326)

The reference's stores send their createAction `acceptDelayedBroadcast`
(their configuration's, `false` by default), `randomizeOutputs: false` and
the global store's `noSend` (`overlayBroadcast`, `false` by default), and
`completeBoundAction` adds `signAndProcess: false` and `returnTXIDOnly:
false` (`completeBoundAction.ts:1022-1032`); this crate's stores send no
createAction options, so their signAction carries no
`acceptDelayedBroadcast` or `noSend` where the reference's carries `false`
(a reference wallet reads an absent `acceptDelayedBroadcast` as `true`),
a finding outside #326. `completeBoundAction` makes checks this crate's
stores do not, outside #326 too: it refuses a reference that is not
canonical base64 of 1 to 4096 characters (`:1044-1052`); binds every
requested input and output in the signable transaction and finds each
requested input's index there (`bindRequestedAction`, `:1063-1069`);
signs each requested input itself with the PushDrop unlocker
(`inputSigners`, the stores' `anyone` or `self` key; `:1076-1106`), where
this crate's stores send each spend an empty unlocking script for the
wallet to fill, at indexes counted from 0 (`prepare_spends`, the global
store input 0); refuses a signer that matches no input (`:1107-1109`);
after signAction checks the signed transaction against the template and
each unlocking script and txid it was given (`:1128-1146`); and aborts the
action on any failure (`abortBestEffort`, `:1148-1151`). The reference's
stores sign through it on a new key too, `spends: {}`; this crate's local
store sends a new key's createAction for the wallet to sign and process,
and its global store signs a new key at input 0. Two defects of the global
store surfaced: its `set` looks up the key without asking for the token
(`global.rs:184-193`), so it never spends the token it replaces, where the
reference's spends every current one; and its reader takes an untagged
token's signature for its tags (`KVStoreInterpreter::extract_fields`,
`interpreter.rs:248`), so it refuses every token `set` writes without
tags. The contacts manager still differs from the reference outside its
signAction's arguments (its createAction's labels, `signAndProcess` and
`noSend`, the input at index 0 where the reference finds the bound input,
`ContactsManager.ts:689-698`, and the reference's template and signature
checks and abort, `:836-855`, `:1003-1019`). go-sdk@2ca481c has no global store and no
contacts manager; its `LocalKVStore` sends `SignActionArgs{ Reference,
Spends }` (`kvstore/local_kv_store.go:342-345`, `:494-497`), the bytes
createAction answered (`Reference []byte`, `wallet/interfaces.go:203-206`,
`:222-226`), and no options: the reference's bytes, without
`completeBoundAction`'s options.

### Fixed: the identity revocation authenticates the lookup output, spends the matching one at its index, aborts a failed action and retries a double spend as the reference does (#327)

`IdentityClient::revoke_certificate_revelation` took the first output of
the `ls_identity` answer, the first transaction of its BEEF, spent the
configured `output_index` (0) at input 0 and checked nothing: a lookup
host could answer any output and the wallet was asked to spend it. The
reference's `revokeCertificateRevelation` (`ts-stack@edf6e03`
`packages/sdk/src/identity/IdentityClient.ts:705-950`) is now followed
step by step, in its order and words (`src/identity/revoke.rs`):

| The reference | Before | Now |
|---|---|---|
| the serial number `validateBase64String(.., 32, 32)` (`:712-717`) | sent as given | refused in `WERR_INVALID_PARAMETER`'s words (`The serialNumber parameter must be at least 32 bytes`), before any call |
| getPublicKey for the identity key, then for the token's key (`[1, identity]`, `1`, anyone, `forSelf`) (`:718-730`) | none | the same two calls |
| no output or not an output list: `Failed to get lookup result` (`:743-745`) | `Failed to find revelation output`, `No revelation found for this certificate` | the reference's words |
| more than 10000 outputs, more than 16 MiB of BEEF across them (`:746-758`) | unbounded | refused in its words |
| each output: the BEEF's subject (`Transaction.fromBEEF`, its atomic txid or last transaction), the output at the lookup's index, a canonical signed PushDrop of two fields (`assertCanonicalIdentityTokenScript`, `:130-147`) locked to the token's key, its JSON naming the serial number and the identity key as subject, `Certificate.verify`, the wallet's verifySignature over the token; any failure skips the output (`:768-825`) | the first transaction of the first output, unread | the same checks, the same skips |
| none authenticated: `No authenticated revelation output matches the requested certificate.` (`:828-830`) | spent | refused |
| every authenticated output spent at its own `outputIndex`, the outpoint `<subject txid>.<index>` (`:837-844`) | the first, at `output_index` | the reference's |
| the signable transaction read as atomic BEEF, exactly one input spending the outpoint, signed at that index (`revelationInputOutpoint`, `:149-172`, `:870-894`) | input 0 | the matching input, else `Wallet signable transaction does not contain the requested revelation input.` |
| no transaction from signAction: `Failed to sign transaction` (`:913-915`) | `signAction did not return a transaction` | the reference's words |
| the signed transaction checked against the signable one (version, lock time, inputs, sequences, outputs, the revelation input and its unlocking script, the txid answered; `:174-200`, `:917-932`) | not checked | the same checks in its words |
| the broadcast's failure `Failed to broadcast certificate revelation revocation: <code>: <description>` (`:934-939`) | `Failed to broadcast revocation: ..` | the reference's words |
| abortAction with the reference when anything after createAction fails, its answer ignored, the failure kept (`:940-946`) | no abort | the same |
| the spend under `withDoubleSpendRetry` (`:837`, `:948`) | none | the reference's rule (below) |

The retry is the reference's `withDoubleSpendRetry`
(`overlay-tools/withDoubleSpendRetry.ts:8-165`), in
`src/identity/double_spend.rs`: an attempt that fails with a
`WERR_REVIEW_ACTIONS` carrying double-spend evidence (each `doubleSpend`
result's `competingTxs`, 1 to 256 distinct txids, and `competingBeef`, 1
byte to 64 MiB; at most 256 results, 64 MiB and 256 txids across them) is
repeated after every competing transaction is read from its BEEF by txid
and acknowledged by the `tm_identity` broadcaster, at most five attempts
in all; any other error, malformed evidence or a failed acknowledgement
ends the spend as it came. `crate::overlay::with_double_spend_retry` is
not that rule (it repeats any error whose words name a double spend,
synchronizes nothing and makes four attempts by default) and is not used.
The evidence needs a carrier: `Error::WalletReviewActions(Box<ReviewActionsRefusal>)`
(new, `wallet`), the reference's `WERR_REVIEW_ACTIONS` with its
`reviewActionResults`; the wire processor frames it with code 5 and its
words (`WalletWireProcessor.ts:2405-2416`), the results not on the wire, as
the reference's frame carries none, so a refusal read back from the wire
(`WalletRefusal` of the `ReviewActions` class) is never retried, as the
reference's transceiver's `WalletError` of code 5 is not
(`withDoubleSpendRetry.ts:66-71`). `ReviewActionResult` derives
`PartialEq` and `Eq` for it. `IdentityClient::with_broadcast_facilitator`
(new) sends the revocation's broadcasts through a facilitator of the
caller's, the seam the tests use.

Migration: a revocation that spent a wrong output before (another
certificate's token, an output the client cannot spend, a token not the
subject's) now refuses in the reference's words, `No authenticated
revelation output matches the requested certificate.`, after the two
getPublicKey calls and a verifySignature for each candidate token; every
authenticated output is spent, not the first; a caller matching the old
words (`No revelation found for this certificate`, `signAction did not
return a transaction`, `Failed to broadcast revocation: ..`) matches the
reference's now. `IdentityClientConfig::output_index` is no longer read by
the revocation. A downstream matching `Error` exhaustively is unaffected
(`#[non_exhaustive]`). No downstream calls the identity client or names
`ReviewActionResult` from this crate (`bsv-wallet-toolbox-rs`,
`bsv-wallet-cli`, `rust-message-box`, `bsv-overlay-cloudflare`,
`bsv-middleware-cloudflare-public`, `rust-chaintracks` grepped).

Pinned by `tests/identity_revocation_checks_327.rs` (9 tests) on
`tests/vectors/identity_revocation_checks_327.json`: the reference's
revocation on ten lookups its script answers (an empty and a freeform
answer, 10001 outputs, 17 MiB of BEEF, a serial number of 3 bytes, a token
for another certificate, two outputs of which the second matches, a
signAction that throws, a double spend answered once then a signed
transaction, a `WERR_REVIEW_ACTIONS` without evidence), each its verdict,
wallet calls in order, createAction, signAction and abortAction arguments
and broadcast txids, recorded by `tests/support/identity_wallet_calls_318.mjs`
with the mode `revocation-checks` (`tests/support/identity_revocation_checks_327.mjs`;
without it the script prints the #318 vector byte for byte) at
`ts-stack@edf6e03` under Node v22.18.0, the randomness #310's SHA-256
counter stream, two runs byte for byte; and this crate's reading of the
retry's rule (five attempts, four synchronizations; a class-only refusal
and double-spend words not retried). The lookups are answered through the
resolver, which keeps one output per `<txid>.<index>` and none whose BEEF
does not parse, so the bound tests answer distinct outputs of real BEEFs
(the 1 MiB one this crate's writer's) where the reference's script
answered copies. 9 of the 9 red on a copy with the old revocation and the
new API; `tests/identity_wallet_calls_318.rs` now asserts the reference's
calls in its order, its stop (`Failed to sign transaction`) and its
abortAction (4 of 4 red on that copy); the #307, #310, #315 and #318
witnesses unchanged (the #318 script prints its vector byte for byte).
`tests/identity_spend_witness.rs`'s revocation now revokes the reference's
token for #318's certificate with the subject's key (its bare PushDrop and
serial `"serial"` are refused before any spend, as the reference refuses
them), its mock answering createAction with atomic BEEF as the reference's
`fromAtomicBEEF` asks. `tests/wire_wallet_refusal_class.rs` pins the processor's frame of the
new variant (code 5, the reference's words, read back as the class; red
without the arm, `Wallet operation failed` code 1).

### Notes: cross-SDK parity (#327)

#318's remaining item is closed: the revocation authenticates, spends the
matching output at its index, aborts and retries as the reference does.
go-sdk@2ca481c has no revocation (`identity/client.go` revokes nothing),
and no `withDoubleSpendRetry`. The reference's `Certificate` is built from
the token's seven members and its constructor's failure caught; here the
certificate is read from those members' JSON (`Certificate`'s
`Deserialize`), a member it cannot hold a skip, the same verdict for every
token the reference's reveal writes; a token JSON without
`revocationOutpoint` reads as `None` here and verifies over the sentinel
(`src/auth/certificates/certificate.rs:303-310`), where the reference's
`verify()` answers false (`Certificate.ts:257-258`). The serial number's base64 length is
measured in UTF-8 bytes where the reference measures UTF-16 units; a
non-ASCII character is refused as not base64 either way. The reference
reads `networkPreset` from the wallet's getNetwork when its options name
none (`:732-735`, `:832-835`); this crate's `IdentityClientConfig` always
names one, so no getNetwork call is made, as in the reference's witnesses.
The contacts manager's and key-value stores' signAction reference (#318's
note) is unchanged.

### Fixed: `SimplifiedFetchTransport` takes a caller's client, as the reference takes a `fetchClient`, and refuses a redirect (#320)

`SimplifiedFetchTransport::new` built its private `reqwest::Client` inside
and set no redirect policy, so reqwest followed up to ten hops: a
handshake or a general message answered `3xx` with a `Location` on
another host was replayed there, its auth headers, signature and body
with it, and a wrapper over `Peer<W, SimplifiedFetchTransport>` (the
toolbox's `StorageClient`) could check the base URL before a send but set
no redirect, proxy or resolution policy on the transport's own requests,
the general message's URL built from the payload's path included. The
reference's constructor takes the fetch as its second parameter
(`fetchClient: typeof fetch = defaultFetch`, `ts-stack@edf6e03`
`packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:64-67`, the
default the global fetch, `:16-19`; `AuthFetch.ts:197`, `:569` passes its
own to the transport it builds) and both of its fetches set `redirect:
'error'` (`:128`, `:212`; the comment at `:125-127`: a fetch follows
redirects by default and can replay them elsewhere).

`SimplifiedFetchTransport::with_client(base_url, client)` (behind `http`,
as the field is) sends every request through the caller's client, used as
given: its timeouts, pool, proxy, resolution and redirect policy are the
caller's. `new` keeps its client (the 30 s and 10 s timeouts and
`pool_max_idle_per_host(0)` of the Cloudflare Containers hang) and adds
`redirect(Policy::none())`. On both paths, whatever the client, an answer
with a redirect status (the fetch standard's 301, 302, 303, 307, 308) is
refused before its body is read, as `Error::AuthError("Network error while
sending authenticated request to {url}: redirect refused: {status}")`, the
reference's words for its thrown fetch (`:453-462`) with this crate's
reason. The class: the named host answered, so it is that host's answer
(`AuthError`, `transport_fault()` `None`), not a `TransportFault`; the
reference's `redirect: 'error'` makes it a network error by the fetch
standard's name for every failure, and the reference has no fault classes
to read it by: its `Network error` words are kept, its class is not. A
general message answered `3xx` was handed to the caller as an
`HttpResponse` of that status before; it is now refused. A `300` or `304`
is not a redirect status and is read as before.

Migration: none for `new`. A caller with its own policy passes its
client: the toolbox's `StorageClient` (`bsv-wallet-toolbox-rs`, its
#182 policy) replaces `SimplifiedFetchTransport::new(&url)`
(`src/storage/client/storage_client.rs:291` at `6317222`) with
`SimplifiedFetchTransport::with_client(&url, client)`, the client built
with `reqwest::Client::builder().no_proxy().resolve(host, addr)
.redirect(reqwest::redirect::Policy::none())` and the timeouts it wants
(`new`'s are not applied to a supplied client). `bsv-wallet-cli`
(`a55990c`) and `bsv-overlay-cloudflare` (`9a0f3c29`) build no
`SimplifiedFetchTransport`.

wasm32: the `http` feature does not build there (`build.rs`, #152), so
neither constructor's client exists on wasm32; reqwest's wasm builder has
no redirect policy either (`reqwest-0.12.28/src/wasm/client.rs`: the
browser's fetch follows), so a wasm32 transport would have to be the
host's `fetch` with `redirect: 'error'`.

Pinned by `tests/transport_client_hook_320.rs` (5 tests, wiremock): a
handshake answered 301, 302, 303, 307 and 308 to a second server is
refused in those words and the second server sees no request; a general
message answered 302 and 307 the same; a client supplied through
`with_client` is the one used (a `default_headers` marker the mock
matches on), the base URL's trailing slash trimmed; a supplied client
that follows redirects carries its own policy (the second server answers);
a supplied client that does not is refused by the transport. 3 of the 5
red on the tree with the redirect policy and the two refusals removed (the
handshake followed to the second server, the general message's 302 handed
on), the two policy-of-the-caller tests green on both; `transport_fault_auth`
(9) and `auth_integration_tests` (70) unchanged.

### Notes: cross-SDK parity (#320)

go-sdk@2ca481c's `NewSimplifiedHTTPTransport` takes a caller's
`*http.Client` in `SimplifiedHTTPTransportOptions.Client`
(`auth/transports/simplified_http_transport.go:31-34`), building
`&http.Client{}` when none is given (`:41-44`), and sets no
`CheckRedirect`: `net/http`'s default follows up to ten redirects on both
of its sends (`:111`, `:175`), as this crate's did. The reference passes
`redirect: 'error'` to a caller's fetch too, so a caller's fetch refuses
a redirect unless it ignores the option; reqwest has no per-request
redirect policy, so a caller's client that follows redirects follows them
here before the transport sees the answer, the transport refusing only the
redirect statuses it is handed. The reference's third parameter
(`SimplifiedFetchTransportOptions`: the response byte limits and the
request timeout, `:30-37`) is not this crate's: outside #320. The tail of the reference's words is the
runtime's (`fetch failed` under Node); this crate's is `redirect refused:
{status}`.

### Fixed: `electrum_decrypt` finds an embedded key the reference's way, so a no-key envelope of any length opens (#109)

With an expected sender, `compat::ecies::electrum_decrypt` decided from the
length alone that an envelope embeds a public key (`data.len() > 69`) and
read the ciphertext from byte 37. A no-key envelope is `4 + ciphertext +
32` bytes, so every one sealed over a plaintext of 32 bytes or more lost 33
bytes of its ciphertext to a key; the MAC passed (it covers the whole
prefix) and the AES unpadding failed, `EciesDecryptionFailed("AES
decryption failed")` (the oracle-fuzz lane's input, #82). Without a sender
it read bytes 4 to 37 as a key whatever they were. The reference's
`electrumDecrypt` (`ts-stack@edf6e03` `packages/sdk/src/compat/ECIES.ts:607-656`)
decides by the byte after the magic and the bytes left over: with
`available = length - 36`, a compressed key when `available >= 49`, the
byte is `02` or `03` and `(available - 33) % 16 == 0`; an uncompressed one
when it is `04`, `available >= 81` and `(available - 65) % 16 == 0`; else
none. The reader now does the same (`src/compat/ecies_envelope.rs`), in its
order and words: no key and no expected sender, `Sender public key is
required`; an embedded key beside an expected sender that is not the same
key (compared compressed, in constant time), `Embedded sender public key
does not match the expected sender`; the expected sender's key derives the
secret when given, else the embedded one; a ciphertext empty or not a
whole number of 16-byte blocks, `Invalid Electrum ECIES ciphertext
framing`, before the MAC; then the MAC (`EciesHmacMismatch`, the
reference's `Invalid checksum`) and AES. An envelope embedding the sender's
65-byte uncompressed key, which `PublicKey::from_bytes` reads, now opens
with the sender and without; it never did.

The rule cannot misread an envelope `electrum_encrypt` writes: its
ciphertext is a non-empty multiple of 16 and a key is 33 or 65 bytes, both
1 modulo 16. A no-key envelope's `available` is 0 modulo 16, so
`available - 33` and `available - 65` are 15 modulo 16 and no key is found
whatever its first byte; an envelope with a key has `available - 33` the
ciphertext's length, a multiple of 16 of at least 16, and its first byte
`02` or `03`, so the key is always found. The same holds for any writer of
a compressed or uncompressed key.

Migration: an envelope that opened before opens to the same plaintext; a
no-key envelope of a plaintext of 32 bytes or more now opens where it was
refused. A caller matching a refusal sees: a no-key envelope without a
sender `Sender public key is required` where it read `Data too short for
embedded public key` (under 69 bytes) or a key refusal, MAC mismatch or
`AES decryption failed` (69 or more); an embedded key beside another
expected sender the mismatch words where it read `EciesHmacMismatch`; a
ciphertext out of framing the framing words where it read
`EciesHmacMismatch`. `Data too short`, `Invalid magic bytes` and
`EciesHmacMismatch` keep their words. No downstream calls
`electrum_decrypt` or matches `EciesDecryptionFailed` or
`EciesHmacMismatch` (`bsv-wallet-toolbox-rs`, `bsv-wallet-cli`,
`bsv-overlay-cloudflare` grepped 2026-10-27).

Pinned by `tests/compat_ecies_envelope_109.rs` (10 tests, 1 ignored
recorder) on `tests/vectors/compat_ecies_envelope_109.json`: for fixed
keys and plaintexts of 1, 15, 16, 17, 31, 32 (the issue's input), 33, 47,
48, 64 and 96 bytes, the reference's envelopes with the key and without
equal this crate's byte for byte, open here to the reference's verdicts
with the sender and without, and this crate's envelopes open in the
reference; ten refusals and the uncompressed key (another expected sender,
a no-key envelope without one, a 17-byte ciphertext, a key and no
ciphertext, a flipped MAC byte, a key off the curve, the uncompressed key
with, without and beside another sender) read here as there; recorded by
`tests/support/compat_ecies_envelope_109.mjs` at `ts-stack@edf6e03` under
Node v22.18.0. 7 of the 10 red on the tree before the fix (the three
green: the encryptor's bytes, unchanged, and the round trips with a key).
`fuzz_ecies` drops its #109 skip, so every sealed envelope must open, with
the issue's input as a seed (`plain-32-bsv-rs-109`, written by
`fuzz/corpus-gen`, whose certificate seed line now unwraps `to_binary`'s
`Result` of #275).

### Notes: cross-SDK parity (#109)

go-sdk@2ca481c's `ElectrumDecrypt` keeps the length rule
(`compat/ecies/ecies.go:117-135`: with a sender the ciphertext from byte 37
when the envelope is over 69 bytes, without one bytes 4 to 37 parsed as a
key), so it refuses the no-key envelope of a plaintext of 32 bytes or more
(`AESCBCDecrypt`'s unpadding error) and an uncompressed key, never compares
an embedded key with the sender, and checks no framing; its refusals carry
its own words (`incorrect password` for the MAC). An embedded compressed
key whose x is at or above the field prime is refused here by
`PublicKey::from_bytes` (`InvalidPublicKey`), where the reference's
`PublicKey.fromString` reduces x modulo p and refuses later: the mismatch
with an expected sender, `Invalid checksum` without (the vector's two
off-curve rows), the difference CLAUDE.md lists for certificate keys
(#183). The reference bounds an envelope at 16 MiB + 160 bytes
(`ECIES.ts:12`, `:589-594`, `CompatValidation.ts:1`), which this crate
does not: a finding outside #109.

### Fixed: the Socket.IO codec reads a frame as `socket.io-parser` reads it, and carries the id on every packet (#110)

`SocketIoPacket::decode` (`src/auth/transports/socketio/codec.rs`) read
the digit run after the namespace as an ack id on every type, then dropped
it on CONNECT, DISCONNECT and CONNECT_ERROR, which had no field for it, and
took any JSON as a CONNECT's or CONNECT_ERROR's payload and any payload on
a DISCONNECT: `0\n0\n` decoded to a CONNECT carrying the number `0`, which
encoded as `00`, a CONNECT with an id and no payload; `0000000   8147…`
read `000000` as an id and the rest as a number, and its encoding did not
decode at all (the oracle-fuzz lane's two inputs, #82). The reference,
`socket.io-parser` 4.2.7 (the parser `socket.io` ^4.8.3 ships, which
`@bsv/authsocket` reaches, `ts-stack@edf6e03`
`packages/messaging/authsocket/package.json`), reads the run as the id on
every type and keeps it on the packet (`decodeString`,
`build/cjs/index.js:220-234`), writes the id of every packet that has one
(`encodeAsString`, `:90-93`), and judges the payload by the type
(`isPayloadValid`, `:256-274`): CONNECT an object, DISCONNECT none,
CONNECT_ERROR a string or an object, EVENT an array whose head is a number
or a string outside its reserved names (`:16-23`), ACK an array; anything
else, and a payload that is not JSON, is `invalid payload`. Its id run
takes a character when `Number(c) == c`: an ASCII digit, or a character
JavaScript trims as white space, so `0\n0\n` is a CONNECT with the id 0
there, and so here now. The decoder now reads the id as the reference
does (`src/auth/transports/socketio/packet_rules.rs`), refuses an id the
reference reads as `NaN` (white space between digits) or past `u64::MAX`,
judges the payload by `isPayloadValid` in the reference's words
(`malformed packet: invalid payload`; a payload that is not JSON
`invalid payload (invalid JSON: <serde_json's reason>)`), checks the type
digit before the payload, and `encode` writes the id of every packet that
carries one and omits an empty namespace as the reference does. The event
argument reader (`decode_event_args_text`) skips the same id run.

Migration: `SocketIoPacket::Connect`, `Disconnect` and `ConnectError`
carry `ack_id: Option<u64>`, the reference's own field (the owner's ruling
of 2026-10-26 on #110); a literal adds `ack_id: None`
(`SocketIoPacket::Disconnect { nsp: "/".into(), ack_id: None }`) and a
pattern `..`; `SocketIoPacket::ack_id()` reads it on every type. One downstream enables
this crate's `socketio` feature: `~/bsv/mpc/bsv-mpc` (`bsv-mpc-messagebox`,
`bsv-mpc-worker`, at `3674c9b`), on bsv-rs `0.3.13`, so it meets the shape
only when it moves to this line; it builds `SocketIoPacket::Connect { nsp:
"/".to_string(), data: None }` at six sites (`transport_native.rs:419`,
`subscribe.rs:345`, `poc.rs:881`, `:1187`, `:1550`, a test at
`transport_native_handshake.rs:79`), each adding `ack_id: None`, and reads
the server's CONNECT with `Connect { .. }`, unchanged. The relay
(`rust-message-box`) has its own codec (`src/engineio/codec.rs`, on
bsv-rs 0.4.5, `socketio` not enabled). A frame this
crate accepted before is refused now where the reference refuses it (a
CONNECT carrying an array, a string, a number or `null`; a DISCONNECT with
a payload; an EVENT whose head is `null`, an object or a reserved name; an
ACK without a payload, which decoded to an empty array and encoded with
one).

Pinned by `tests/socketio_packet_validity_110.rs` (7 tests) on
`tests/vectors/socketio_packet_validity_110.json`: 59 frames (the issue's
two inputs, each packet type with each payload shape, ids with leading
zeros, past 2^53, at and past `u64::MAX`, white space in and around the
id run, namespaces with and without the comma, the binary types, an empty
frame) with the reference's verdict, its encoding of an accepted packet
and whether that is a fixed point, and the 35 UTF-16 code units its id run
takes, recorded by `tests/support/socketio_packet_validity_110.mjs`
running the parser under Node v22.18.0. Every frame the reference refuses
is refused here in its words; every frame both read is the reference's
packet and its encoding byte for byte, the encoding reading back to the
packet; the frames read there and refused here are enumerated with their
reasons (`REFUSED_HERE`, 14). 7 of the 7 red on the tree with the decoder
and encoder of before (the shape kept); `socketio_float_round_trip` and
`socketio_signed_text_280` unchanged. The fuzz target
`fuzz_auth_messages` asserts the round trip for every decoded frame (the
skip of #110 removed); the two inputs are its seeds
(`fuzz/corpus/fuzz_auth_messages/socketio-connect-id-110`,
`socketio-connect-nan-id-110`), and 120 seconds ran 319,702 inputs
without a failure.

### Notes: cross-SDK parity (#110)

Where the reference reads a frame and this crate refuses it, a stated
difference: an id run whose text is `NaN` (`21 2["ev"]`, the issue's
second input), which the reference encodes as `NaN` and cannot read back;
an id past `u64::MAX`, which the reference keeps as the nearest double (no
Socket.IO peer issues one: ids count from 0 on each socket); an EVENT
without a payload and an ACK without an id or a payload (the reference's
`data` and `id` undefined; this crate's `Event.data` is a `Vec` and
`Ack.ack_id` a `u64`); the binary types `5` and `6`, which the reference
reads and then waits for attachments (no AuthSocket peer sends them); an
empty frame and a frame whose type character is white space, which the
reference's `Number(str.charAt(0))` reads as `0`, a CONNECT; a JSON string
with a lone surrogate escape, which `JSON.parse` keeps and a Rust string
cannot; a payload nested deeper than 128 levels, which `serde_json`
refuses by its recursion limit and `JSON.parse` reads. Where both read a frame, one difference: an id above 2^53 and
within `u64` is exact here and the nearest double there, so
`18446744073709551615` is written back as given here and as
`18446744073709552000` there. The JSON numbers' differences are #285's.
go-sdk@2ca481c carries no Socket.IO codec.

### Fixed: the identity client's wallet calls send what the reference sends (#318)

`IdentityClient` passed `"identity-client"` as the originator on every
wallet call of the reveal, the revocation and the certificate parser when
none was configured, and `""` on `get_identity_key` and the contacts
manager; the reference's `IdentityClient` passes its constructor's
`originator` as given to every `wallet.*` call, `undefined` when the caller
named none (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:369-377`,
`:471-477`, `:502`, `:527`, `:718-729`, `:813`, `:862`, `:884`, `:910`,
`:942`). Every call now carries the configured originator or none (`""`,
this crate's absent originator: the binary wire writes length 0 and the
HTTP substrates send no `Originator` header unless their own is set).
`revoke_certificate_revelation`'s createAction carried the labels
`identity` and `revocation` and `signAndProcess: false` beside the
reference's arguments; the reference's (`:845-863`) sends the description,
`inputBEEF`, one input (`inputDescription`, `outpoint`,
`unlockingScriptLength: 74`) and `options: { randomizeOutputs: false,
acceptDelayedBroadcast: false, noSend: true }`, nothing else. Its
signAction left `returnTXIDOnly` absent and sent the reference createAction
answered as the hex of its bytes; the reference's (`:896-911`) sends
`returnTXIDOnly: false` and the reference as it was answered, its base64
text, which is what the binary wire's transceiver decodes
(`src/wallet/wire/transceiver.rs:667-668`) and the HTTP JSON substrate carries:
the hex text named an action no wallet had made. Both calls now send the
reference's arguments alone.

Migration: a client built with `IdentityClientConfig::default()` now
sends no originator. A wallet that requires one refuses the call where it
accepted `"identity-client"`: `bsv-wallet-toolbox-rs`'s `Wallet`
(`6317222`) refuses `""` on every call (`validate_originator`,
`src/wallet/wallet.rs:2811-2816`; its reference's `validateOriginator`
accepts `undefined`, `ts-stack@edf6e03` `validationHelpers.ts:1003-1004`),
as it already refused `get_identity_key` and the contacts manager's calls;
`bsv-wallet-cli` (`a55990c`) answers 400 `Origin header required` to a
request with neither `Origin` nor `Originator` (`src/server/handlers.rs:101-123`)
where it read `http://identity-client` and wrote that into its audit
record (`src/server/audit.rs:54`). Name the caller's own domain with
`IdentityClientConfig::with_originator` (or the substrate's originator).
The revocation's actions carry no label: the toolbox persisted the two
(`src/storage/sqlx/create_action.rs:777-780`), a `listActions` by the label
`identity` or `revocation` finds them no more. `signAndProcess: false`
was not load-bearing: the input carries no unlocking script, so the
toolbox's wallet answers a signable transaction whatever the flag
(`is_sign_action`, `src/wallet/wallet.rs:3322-3327`, the reference's
`isSignAction` rule), and the client signs and sends the action itself as
before. No downstream calls the identity client (`bsv-wallet-toolbox-rs`,
`bsv-wallet-cli`, `rust-message-box`, `bsv-overlay-cloudflare`,
`bsv-middleware-cloudflare-public`, `rust-chaintracks` grepped).

Pinned by `tests/identity_wallet_calls_318.rs` (4 tests) on
`tests/vectors/identity_wallet_calls_318.json`: the reference's client
built with no originator and with `identity-client`, the wallet calls of
its reveal (#310's certificate, `email`) and its revocation each with the
originator received, and the revocation's createAction and signAction
arguments, its lookup answered with a source transaction carrying the
reveal's token and its createAction with a signable transaction spending
it; recorded by `tests/support/identity_wallet_calls_318.mjs` at
`ts-stack@edf6e03` under Node v22.18.0, the randomness #310's SHA-256
counter stream (two runs byte for byte). Answered here with the
reference's lookup BEEF and signable transaction, this crate's revocation
sends createAction arguments equal to the reference's member by member and
a signAction with the same reference, options and unlocking script; every
call of the reveal, the revocation, `get_identity_key` and the contacts
manager carries the configured originator or none. The counting wallet
(`tests/support/identity_reveal_wallet.rs`) keeps every call's originator
now, and answers a signable transaction when given one. 4 of the 4 red on
the tree before the fix; the #307, #310 and #315 witnesses unchanged (10,
6 and 3 green; #315's test now builds its client with the originator its
recorder gave the reference, `identity-client`).

### Notes: cross-SDK parity (#318)

#315's two items are closed. go-sdk@2ca481c has no revocation; its
`NewClient` keeps the originator the caller passes and passes it on every
call (`identity/client.go:33-63`, `:113`, `:144`, `:175`, `:191`, `:244`,
`:262`), `""` when none: the reference's rule. The revocation still differs
from the reference outside its arguments: the reference authenticates each
lookup output before spending it (two getPublicKey calls, the token's
locking key, subject and serial number, `Certificate.verify` and a
verifySignature over the token, `:711-830`), spends at the input that
matches the outpoint, aborts the action when signing or broadcasting fails
(`:942`) and retries a double spend (`withDoubleSpendRetry`); this crate
spends the first output listed, at input 0, and does none of these (a finding
outside #318). The contacts manager and the key-value stores send
signAction the hex of the reference (`src/identity/contacts.rs:447`,
`:732`, `src/kvstore/global.rs:281`, `:409`, `src/kvstore/local.rs:331`,
`:438`), the same fault as the revocation's: a finding outside #318,
closed by #326.

### Fixed: `Transaction::verify` answers a decline as a decline, and the block path's consensus budget can be the node's verdict (#38)

Two gaps the docs pass of #36 left. First, `Transaction::verify` evaluates
each input under the default mode's 32,000,000-byte local budget and mapped
every `Spend::validate` error to `TransactionError("Script validation failed
for input N: …")`, so an evaluation stopped at the budget (`resource_limit`
`Some`, `is_resource_limit`), a script nobody judged, reached the caller as
invalid with its class dropped, where the crate's docs say a caller never
reads a decline as invalid. The reference's `Transaction.verify` runs
`Spend` per input and lets its two exceptions propagate by class,
`ScriptEvaluationError` for an invalid script and `ScriptResourceLimitError`
for a decline (`ts-stack@edf6e03`
`packages/sdk/src/transaction/Transaction.ts:1441-1458`,
`packages/sdk/src/script/Spend.ts:2020-2021`, thrown at `:433`, `:439`,
`:745`, `:748`, `:1949`). A decline now leaves `verify` as
`Error::ScriptEvaluationDeclined { input_index, limit }`, the input and the
`ScriptResourceLimit` (resource, budget, attempted figure) kept, printed
`script evaluation declined for input N: <the limit's sentence>`; an
invalid script keeps `TransactionError("Script validation failed for input
N: …")` byte for byte. The budget `verify` evaluates under is unchanged.

Second, on the block path a node's budget is its operator's mandatory
`-maxstackmemoryusageconsensus` (bitcoin-sv v1.2.3, `6504a3a`:
`src/bitcoind.cpp:140-157`; 0 means `INT64_MAX`,
`src/consensus/consensus.h:82`, `src/configscriptpolicy.cpp:280-287`), the
figure `GetMaxStackMemoryUsage` picks there (`:139-154`), and a growth above
it is that node's verdict (`src/script/limitedstack.cpp:202-205`,
`SCRIPT_ERR_STACK_SIZE`, `src/script/interpreter.cpp:1815-1817`). An
operator may set it below 100,000,000; this crate's block word evaluated up
to its local budget and said valid, and `memory_limit: Some(X)` modelled
that node only as a decline above `X`, which no sentence said. The module
doc's block-path paragraph and `SpendParams::memory_limit` now say so, and
`Spend::set_stack_memory_consensus(bytes)` (with
`Spend::stack_memory_consensus()`), beside `set_stack_memory_policy`, is
the node's setting for a word without the mempool bits: a growth that would
take the node's count above it is refused before it happens, `Stack size
limit exceeded: N bytes, the stack memory consensus limit is M bytes.`,
`is_resource_limit() == false`. 0, the default, selects no verdict (the
node's `INT64_MAX`). The mempool word keeps the policy's verdict and
ignores it; the default mode ignores both. The node refuses at start a
policy above its consensus figure (`src/configscriptpolicy.cpp:298-305`);
this interpreter takes both as given and judges each path by its own.

Pinned by `tests/transaction_verify_decline_38.rs` (a child whose input
pushes 1,000,000 bytes and whose parent's lock `OP_DUP`s it: 32 copies
verify, a 33rd is `ScriptEvaluationDeclined` at 33,000,000 of 32,000,000,
the same shape with an invalid script still `TransactionError`) and
`tests/script_stack_memory_consensus_38.rs` (the verdict under the block
word, the decline without the knob, the mempool word's policy verdict
unchanged, the two figures unclamped); red on the code before (4 of 9;
the 5 others hold either way). `tests/script_stack_memory_witness.rs` is
unchanged.

Semver: `Error` is `#[non_exhaustive]`, so the new variant is additive, as
are the two `Spend` methods.

Migration: a caller of `Transaction::verify` that read every `Err` as an
invalid transaction reads `Error::ScriptEvaluationDeclined` as "not
judged" (retry under a larger budget, or let the network judge); a match
on `TransactionError` text containing `has exceeded` finds the decline in
the new variant. No downstream reads it: `overlay-engine`'s submit door
walks with its own `verify_beef_linear` and the stream script door, which
already branches on `is_resource_limit`, and its two tests that call
`verify` expect `Ok(true)`; `bsv-wallet-cli` calls no `Transaction::verify`.

### Notes: cross-SDK parity (#38)

The reference's `Spend` defaults `memoryLimit` to `Number.POSITIVE_INFINITY`
(`ts-stack@edf6e03` `Spend.ts:295-296`) and its `verify` imposes no SDK cap
without a caller's `memoryLimit` (`Transaction.ts:1685-1687`); this crate's
`verify` keeps the default mode's 32,000,000 bytes and takes no budget, so a
script between 32,000,000 bytes and the reference's allocation failure is a
decline here and a verdict there: a finding, not changed by #38 (closed by
#331: `verify` takes the budget and runs uncapped without one). go-sdk@2ca481c
runs the interpreter at the relay policy's 100,000,000 bytes and wraps its
error with two `%w`, `ErrScriptVerificationFailed` and the interpreter's own,
so `errors.Is(err, ctx.Err())` tells a stopped evaluation from an invalid
script (`spv/verify.go:64-76`, `:547-560`); it carries no consensus figure.

### Fixed: the createAction `publicly_reveal_attributes` calls sends the reference's arguments and no others (#315)

`IdentityClient::publicly_reveal_attributes` called createAction with the
labels `identity` and `revelation`, the output tag `identity`,
`signAndProcess: true` and `acceptDelayedBroadcast: false` beside the
reference's arguments; the reference's `publiclyRevealAttributes`
(`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:513-528`)
sends the description `Create a new Identity Token`, one output of
`satoshis` (the client's `tokenAmount`), `lockingScript` and
`outputDescription: 'Identity Token'`, and `options: { randomizeOutputs:
false }`, nothing else. An extra argument changes what the wallet does: a
label and a tag persist on its records, and `acceptDelayedBroadcast:
false` forces an immediate broadcast where the reference leaves it to the
wallet, whose own validation reads the absent option as `true`, as it
reads `signAndProcess` (`validationHelpers.ts:659-660`; `isDelayed` true,
`:804`). The call now sends the reference's arguments alone.

Migration: a wallet that found the reveal's actions by the label
`identity` or `revelation`, or its token by the tag `identity`, finds them
no more; a reference wallet now applies its default delayed broadcast to
the reveal. No downstream calls the reveal or reads the label or tag
(`bsv-wallet-toolbox-rs` `6317222`, `bsv-wallet-cli` `a55990c`), and the
toolbox's wallet reads an absent `signAndProcess` as `true` and an absent
`acceptDelayedBroadcast` as `false` (`src/wallet/wallet.rs:1071-1075`,
`:1102-1106`, `:1331`), so on it the reveal is still signed and
broadcast at once; only the label and the tag are gone.

Pinned by `tests/identity_reveal_create_action_315.rs` (3 tests) on
`tests/vectors/identity_reveal_create_action_315.json`: #310's certificate
revealed by the subject's wallet for `email` and for both fields, the
arguments the reference's wallet received in its createAction call, their
member names at each level, its originator, and the reference's
`Validation.validateCreateActionArgs` reading of them (the left-out
options `true`, no label, no tag); recorded by
`tests/support/identity_reveal_create_action_315.mjs` at
`ts-stack@edf6e03` under Node v22.18.0, the randomness #310's SHA-256
counter stream (two runs byte for byte). The arguments this crate's
counting wallet receives (`tests/support/identity_reveal_wallet.rs`, which
keeps the originator now), written as JSON, equal the reference's member by
member, and carry no member it leaves out. 3 of the 3 red on the tree
before the fix; the #307 and #310 witnesses unchanged (10 and 6 green).

### Notes: cross-SDK parity (#315)

go-sdk@2ca481c's `PubliclyRevealAttributes` sends the reference's
arguments (`identity/client.go:163-174`: the description, one output of
`Satoshis`, `LockingScript` and `OutputDescription`, `RandomizeOutputs`
false); no difference. `revoke_certificate_revelation`'s createAction still
carried the labels `identity` and `revocation` and `signAndProcess: false`
beside the reference's arguments (`IdentityClient.ts:845-863`): a finding
outside #315, closed by #318.

The originator: the recorder's reference was configured with
`"identity-client"`, so the two calls carry the same originator in the
vector; by default the reference sends none where this crate sent
`"identity-client"`, the difference of #318, closed there.

### Fixed: `Certificate` parses its signature's DER and re-encodes it on read, as the reference does (#305)

`Certificate::to_binary` wrote and `from_binary` kept the signature's bytes
as given, and `verify` read them with this crate's lenient
`Signature::from_der`; the reference rounds the signature through its own
`Signature.fromDER` at three sites (`ts-stack@edf6e03`
`packages/sdk/src/auth/certificates/Certificate.ts`; the parser at
`packages/sdk/src/primitives/Signature.ts:44-97`, the writer at `:201-256`):

- `toBinary` parses it and writes the bytes it was given (`:309-311`): a
  DER `fromDER` refuses is refused in its words (`Signature DER must start
  with 0x30`, `Signature DER invalid`, `Invalid DER entity length`,
  `Invalid R-length in signature DER`, `Invalid R-value in signature DER`,
  `Invalid S-value in signature DER`), one it reads out of DER's form (`r`
  or `s` with its high bit set and no zero byte, an empty integer) is
  written as given; an empty signature is written as nothing, unchecked
  (`:300`).
- `fromBinary` parses the bytes after the fields and keeps `toDER`'s
  re-encoding (`:395-397`): a zero byte before a high bit restored, an
  empty `r` written `02 01 00`, `s` high or low as read (no low-S
  normalization). The reference's `toBinary` then refuses that `02 01 00`
  (`fromDER` refuses the zero byte its own `toDER` wrote), and so does this
  crate's.
- `verify` parses with `fromDER` and verifies the `(r, s)` it reads
  (`:432-435`): `false` for a DER it refuses, the ECDSA verdict for one it
  reads, a DER out of form included.

Now each is so here, every refusal `CertificateValidationError` as #297's and
#301's are (`src/auth/certificates/certificate.rs`, through
`bounds::der_signature`). The wallet wire's `certificate_signature_der`
(#183, #189) stays, its class `WalletError`; the two now share one reading,
`wallet::wire::reference_der`, which returns the reference's words and lets
each caller frame them. Before the fix `verify` answered `true` for three
signatures the reference refuses (a zero byte before an `s` whose high bit
is clear, a byte after the sequence, a sequence length one short of the
bytes), and `from_binary` and `to_binary` accepted eight DERs the reference
refuses. `received_unsigned` (#249) is the unsigned prefix as received and
binds no signature: the signature read is the re-encoding, the prefix the
bytes. The fuzz target `fuzz_auth_messages` asserts the prefix byte for
byte and the whole frame where the signature read back is the one written.

Pinned by `tests/auth_certificate_signature_der_305.rs` (8 tests over 13
signatures of `tests/vectors/auth_certificate_signature_der_305.json`, the
reference's verdicts at `fromBinary` (the signature held, its `verify`, its
`toBinary(true)`), `toBinary(true)` and `verify` recorded by
`tests/support/certificate_signature_der_305.mjs` at `ts-stack@edf6e03`
under Node v22.18.0, two runs byte for byte): the canonical signature (this
crate's signer's bytes, RFC 6979) round-trips unchanged; `r` without its zero
byte written as given, read back with it, verified; high `s` kept and
verified; an empty `r` read as `02 01 00`, `false`, then refused at write;
excessively padded `r` and `s`, a long-form length, a trailing byte, a short
sequence length, a long `s` length, a set tag and an `r` tag refused at
`from_binary` and `to_binary` in the reference's words and `false` at
`verify`. 4 of the 7 red on the tree before the fix (`6c5e4d8`), 21 of the
36 case verdicts differing (`from_binary` 10, `to_binary` 8, `verify` 3);
the other three pin what did not move (the canonical round trip, the empty
signature, the vector's census). The #249 witnesses still hold: their
signatures are signers' canonical DER, which the re-encoding writes back
byte for byte, and the prefix kept is untouched; the #251, #261, #262, #268,
#275, #297, #299 and #301 vectors are unchanged (#301's 72-byte signature is
canonical DER, its 73-byte one refused by the length first; #299's non-DER
signatures were `false` and stay `false`).

A DER cut right after its second `02` tag (`s_length_missing`, `30 24 02 21
<r> 02`, the sequence length its own) is refused in the reference's words,
`Invalid R-length in signature DER`, at `from_binary` and `to_binary` and on
the wallet wire, where `reference_der` said `Signature DER invalid`: the
reference's `getLength` reads `undefined` past the end and the length check
after it throws (`Signature.ts:76-78`); the verdict was the same. Found by
the cold review's 11,039-input differential, the case added to the recorder
and the vector re-recorded (the twelve earlier cases byte for byte); 3 of the
8 tests red on the words before the change.

### Notes: cross-SDK parity (#305)

go-sdk@2ca481c reads the signature as BER, not DER: `CertificateFromBinary`
(`auth/certificates/certificate.go:134-146`) hands the bytes to
`DeserializeCertificate`, which parses them with `ec.ParseSignature`
(`wallet/serializer/certificate.go:118-124`; `primitives/ec/signature.go:297-299`,
`parseSig(sigStr, false)`, `:177-292`), so an excessively padded or negative
integer is read where the reference refuses it, an `r` or `s` of zero or at
or above `n` is refused at the parse (`signature R isn't 1 or more`,
`:278-289`) where the reference reads it and answers `false` at `verify`,
and the error is `error parsing signature: <words>`.
`FromWalletCertificate` keeps `Signature.Serialize()` (`certificate.go:319-322`),
which writes the canonical DER and normalizes `s` to low-S
(`signature.go:77-102`), where the reference keeps a high `s`. `ToBinary`
parses the held bytes with `ec.ParseSignature` and drops a signature it
cannot parse, writing none (`certificate.go:274-280`), then writes
`Serialize()` (`wallet/serializer/certificate.go:63-66`): a DER out of form
is re-encoded on write, not written as given. `Verify` parses with
`ec.ParseSignature` and returns `failed to parse signature` (`:168-172`).
This crate follows the reference.
### Fixed: the identity token `publicly_reveal_attributes` publishes is the reference's, signed by the subject, and createAction's empty answer is refused (#310)

`IdentityClient::publicly_reveal_attributes` locked its identity token as
one PushDrop field, the certificate JSON unsigned, under the key
`getPublicKey` answers for counterparty `anyone` with `for_self: false`;
the reference's `publiclyRevealAttributes` (`ts-stack@edf6e03`
`packages/sdk/src/identity/IdentityClient.ts:501-509`) locks it with
`new PushDrop(wallet, originator).lock([json], protocolID, keyID, 'anyone',
true, true)` (`PushDrop.ts:146-202`): the key for the client's protocol and
key ID (`[1, 'identity']`, `'1'` by default, `identity/types/index.ts:23-24`),
counterparty `anyone`, `forSelf: true`; then `createSignature` over the
JSON's bytes with the same protocol, key ID and counterparty (it carries no
`forSelf`), the signature pushed as a second field, the two dropped by one
`OP_2DROP`. The JSON is `JSON.stringify({ ...certificate, keyring })`
(`:503`): the wallet certificate's members in `WalletCertificate`'s order
(`type, subject, serialNumber, certifier, revocationOutpoint, signature,
fields`), then the keyring; this crate wrote them through a `serde_json`
map, every key sorted. The overlay's identity reader
(`packages/overlays/topics/src/identity/identityTokenValidation.ts:92-154`,
called by `IdentityTopicManager.ts:24`) admits only that shape: two fields,
the five canonical chunks, the key the subject's child under
`[1, 'identity']` key `1` as the anyone wallet derives it, the subject's
signature over the JSON; it refused this crate's token (`Identity token
must contain exactly two fields`), as the reference's revocation filter
(`:722-728`, `:774-815`) skips it. The old key was, besides, the child the
anyone wallet derives for itself (`for_self: false` toward anyone), so
any wallet could spend the token, and this crate's own
`revoke_certificate_revelation`, which signs as the reference's does
(counterparty `anyone`, the subject's child), could not.
The token is the reference's now (`identity_token` in
`src/identity/reveal.rs`; `client.rs` calls it and is 39 lines shorter):
the same calls with the same arguments, the JSON in the reference's member
order, the keyring in the order the names were asked (the reference's own
wallet's order, #307's note), the fields by name, the signature RFC 6979's,
so for the reference's certificate and keyring the locking script is the
reference's byte for byte, signature included.

When createAction answers no transaction the reference throws `Public
reveal failed: failed to create action!` (`:537`); this crate returned
`Ok(BroadcastResult::Failure { code: "CREATE_ACTION_FAILED", .. })`. It is
`Err(Error::IdentityError("Public reveal failed: failed to create
action!"))` now. A failure the overlay answers stays a value
(`BroadcastResult::Failure`), as the reference returns its broadcaster's
`BroadcastFailure` (`:530-535`, `Promise<BroadcastResponse |
BroadcastFailure>`) and Go its `*BroadcastFailure` (`identity/client.go:212-213`):
only the empty createAction moved. Migration: a caller matching
`BroadcastResult::Failure` with `code == "CREATE_ACTION_FAILED"` matches
`Err(Error::IdentityError(_))` instead (`publicly_reveal_attributes_simple`
returned an `Err` before and does now, in the new words). No downstream
calls either method (`bsv-wallet-toolbox-rs` `6317222`, `bsv-wallet-cli`
`a55990c`, `rust-message-box` `419bf18`, `bsv-overlay-cloudflare`
`9a0f3c29`); recorded on #310 under ruling (c).

Item 1 of #310 (each keyring value base64 of 1 to 2048 bytes, trimmed)
landed with #307; the three items are closed.

Pinned by `tests/identity_reveal_rest_310.rs` (6 tests) on
`tests/vectors/identity_reveal_rest_310.json`: a certificate the reference
issued (`MasterCertificate.issueCertificateForSubject`, certifier key 7,
subject key 9, `email` and `name`) revealed by the subject's wallet for
`email`, for both and for both asked `name` first, each with the keyring
the reference's `createKeyringForVerifier` writes for anyone, the
reference's wallet calls and their arguments, its locking script, its
refusal of the empty createAction and the identity reader's verdict
(admitted, the plaintexts decrypted), and the reader's refusal of the
token this crate built before; recorded by
`tests/support/identity_reveal_rest_310.mjs` at `ts-stack@edf6e03` under
Node v22.18.0, the reader bundled from `packages/overlays/topics` beside
the SDK, the randomness a SHA-256 counter stream (two runs byte for byte).
This crate's token is the reference's bytes for the three; getPublicKey
and createSignature are asked with the reference's arguments; the reader's
checks run here on this crate's token admit it and decrypt the reference's
plaintexts; the token's key is the one the revocation signs under, not the
anyone wallet's; the empty createAction refused in the reference's words.
5 of the 6 red on the tree before the fix (`e08e677d`), the sixth pinning
the vector's verdict on the old token; and 3 of the 10 tests of
`tests/identity_reveal_verifies_307.rs`, whose counting wallet moved to
`tests/support/identity_reveal_wallet.rs` (keeping getPublicKey's and
createSignature's arguments) and whose reached witnesses now expect the
refusal and the reference's count of wallet calls before createAction
(three: proveCertificate, getPublicKey, createSignature); its vector is
unchanged, as are the #105 and #261 identity witnesses.

### Notes: cross-SDK parity (#310)

go-sdk@2ca481c's `PubliclyRevealAttributes` locks the token as the
reference does (`identity/client.go:141-160`: `pushDrop.Lock(.., Anyone,
true, true, LockBefore)`) and refuses an empty createAction in its own words
(`public reveal failed: failed to create action`, `:180-182`); it writes the
JSON with `json.Marshal` of a map (`:123-139`), its keys sorted, so its
token is another byte string the reader admits; it publishes the keyring
unchecked (`:132`) and proves for a random verifier key (`:102-113`), where
the reference names the anyone key.

Where the wallet certificate's fields are not in byte order, the token's
JSON differs from the reference's: `WalletCertificate.fields` is a
`HashMap`, so this crate writes the fields by name, where the reference
keeps the object's order; the signature is over the bytes written and the
reader admits either. The members' order is the object's too in the
reference (`{ ...certificate, keyring }` spreads the caller's object):
the toolbox's `listCertificates` answers `WalletCertificate`'s order
(`packages/wallet/wallet-toolbox/src/storage/methods/listCertificates.ts:56-62`),
the order written here, where a certificate read on the binary wire is a
`Certificate` instance (`WalletWireTransceiver.ts:1512`, `:1543`) in the
class's order (`type, serialNumber, subject, certifier, revocationOutpoint,
fields, signature`, `Certificate.ts:206-212`): other bytes, admitted by the
reader as well (the reader parses the JSON and checks its key set,
`identityTokenValidation.ts:62-71`). The keyring is written in the order asked, the
reference's in the wallet's (`Object.keys`, `:485`), the same for the
reference's own wallet (#307's note).

The reference's createAction asks for the output alone with
`randomizeOutputs: false` (`:513-528`); this crate also sends the labels
`identity`, `revelation`, the tag `identity`, `signAndProcess: true` and
`acceptDelayedBroadcast: false`. Not changed here (outside #310's three
items); a finding for its own issue, fixed by #315.

### Fixed: `publicly_reveal_attributes` verifies the master certificate, and checks the names to reveal, before any wallet call, as the reference does (#307)

`IdentityClient::publicly_reveal_attributes` refused a certificate with no
fields, an empty list of names and an empty subject or certifier, then
asked the wallet for a keyring and published whatever came back: a
certificate whose signature does not verify was published here. The
reference's `publiclyRevealAttributes` (`ts-stack@edf6e03`
`packages/sdk/src/identity/IdentityClient.ts:420-467`) refuses before
`proveCertificate`, in this order: a field named `__proto__`,
`constructor` or `prototype` (`Invalid display identity: certificate.fields
contains an unsafe field`, `:420-424`, `identityRecord` at `:45-65`), no
fields (`:425-427`), no names (`:428-430`), more than 100 (`:431-433`), and
for each name in turn: over 50 UTF-8 bytes or carrying a display control
(`Invalid display identity: fieldsToReveal[<i>] is oversized or contains
unsafe controls`, `identityString` at `:89-102`), empty or an unsafe record
key (`invalid certificate field name!`), a repeat (`duplicate certificate
field name!`), a name the certificate does not carry (`requested field is
not present in the certificate!`, `:434-450`; its dense-array refusal at
`:436-438` has no counterpart, a `Vec` being dense); then the master
certificate's `verify()`, any failure under it one sentence, `Public reveal
failed: Certificate verification failed!` (`:451-467`). After
`proveCertificate` it refuses a keyring carrying a name `__proto__`,
`constructor` or `prototype` (`Invalid display identity: proof result
keyringForVerifier contains an unsafe field`, `identityRecord` at
`:480-483`), whether or not the count matches; then one naming other
fields than those asked, or missing one (`wallet returned a keyring for
unrequested fields!`, `:484-491`); then each value through
`validateBase64String(.., 1, 2048)` (`:492-499`, `validationHelpers.ts:488-498`):
trimmed as JavaScript's `trim` trims (U+FEFF trimmed, U+0085 kept), base64
by its shape alone, 1 to 2048 bytes, a refusal `WERR_INVALID_PARAMETER`
(`The keyringForVerifier.<name> parameter must be valid base64 string`,
`.. no more than 2048 bytes`, `.. at least 1 bytes`), here
`Error::WalletRefusal` of the `InvalidParameter` class; the PushDrop
carries the trimmed values. Until this fold an unsafe name was refused
as an unrequested field and the wallet's values were published as given
(the review's two findings; this closes item 1 of #310).
Each is here now, in the reference's words and order, as
`Error::IdentityError`, the class of the client's other refusals
(the keyring values' refusal as above; `src/identity/reveal.rs`;
`client.rs` calls it and is 15 lines shorter).
The master certificate is read from the wallet certificate's members'
JSON (`Certificate`'s reader, #268) and verified by `Certificate::verify`
(#299); a member it cannot hold (an empty subject, a signature that is not
hex) is a `false`, as the reference's `verify` answers `false` for it. This
crate's own refusal of an empty subject or certifier (`Certificate must
have subject and certifier!`) is gone: such a certificate is refused by the
verification, in the reference's words (no downstream matches the old
text: `bsv-overlay-cloudflare` `9a0f3c29`, `rust-message-box` `419bf18`,
`bsv-wallet-toolbox-rs` `6317222`, `bsv-wallet-cli` `a55990c` call
neither).

Pinned by `tests/identity_reveal_verifies_307.rs` (10 tests) on
`tests/vectors/identity_reveal_verifies_307.json`: the reference's verdicts
on thirty-eight witnesses (a signed certificate, one and both fields revealed;
unsigned, another key's signature, a field changed after signing, not DER,
not hex, an empty subject; the outpoint the txid alone, which both verify;
each refusal above; an unsigned certificate with an absent name, refused
for the name first; eighteen keyrings the wallet answers: `__proto__`
beside the name asked, `constructor` alone, another name, an extra name,
none; a value with `!`, empty, whitespace alone, `=` inside, three
characters, one, 2049 bytes, after U+0085, each refused after the one
wallet call; 2048 bytes, `AB==`, whitespace, U+FEFF and both fields
padded, each published as the reference publishes it, trimmed) recorded by `tests/support/identity_reveal_verifies_307.mjs`
at `ts-stack@edf6e03` under Node v22.18.0 (two runs byte for byte), its
wallet counting its calls: every refusal the same words and class here
with the same wallet calls before it, every acceptance reaching
createAction with the keyring the reference publishes; the signed
certificate's signature this crate's own bytes; a signed certificate
published as before (the PushDrop carrying its JSON and the keyring); a
keyring for another field refused before createAction; an unsafe keyring
name refused in the reference's words; a value not base64 or over 2048
bytes refused as the reference refuses it; values published trimmed. 5 of
the first 7 red on the tree before the fix (`6c5e4d8`), the other two
pinning what did not move; 4 of the 10 red on the fold's base (`e62bdd7`:
the vector's test, the three keyring tests), the 20 earlier witnesses
recorded again byte for byte. The #105 and #261 identity witnesses are unchanged.

### Notes: cross-SDK parity (#307)

go-sdk@2ca481c's `PubliclyRevealAttributes` (`identity/client.go:68-115`)
refuses no fields (`:73-75`), no names (`:76-78`), a nil revocation
outpoint (`:79-81`) and a nil subject or certifier (`:82-84`) in its own
words, converts the certificate (`FromWalletCertificate`, `:86-89`) and
refuses a failed `Verify` as `certificate verification failed` (`:91-94`),
all before `ProveCertificate` (`:109`): the verification at the
reference's site; it checks no name against the certificate, no repeat, no
count or length, and not the keyring the wallet returns.

Where two or more keyring values are refused, the reference names the
first in the wallet's key order (`Object.keys` of the keyring,
`IdentityClient.ts:485`, walked at `:492`: an integer-like name first,
then insertion order) and this crate the first in the order the names
were asked (`check_keyring`, `src/identity/reveal.rs`):
`ProveCertificateResult::keyring_for_verifier` is a `HashMap`, and the
JSON substrate and the wire reader fill it without the wallet's order.
The reference's own wallet answers in the order asked
(`MasterCertificate.createKeyringForVerifier` walks `fieldsToReveal`,
`MasterCertificate.ts:348`, `:370`; the toolbox's `proveCertificate.ts:31`),
so on its keyrings the two name the same value unless a name is
integer-like; a wallet of another order (a Go map's) is named otherwise
here, the bound in the message that value's. Every value is refused in
either order.

### Changed: CI's concurrency group carries the event, so a dispatch and a push to one ref never cancel each other

`ci.yml`'s concurrency group was `ci-<ref>`: a `workflow_dispatch` on `beta`
(the bench baseline's record mode, `bench_baseline_record`; the nightly's
dispatch of this workflow) shared the group with every push to `beta`, and
the first record run for #245 (2026-10-27 04:23Z, run 40449439162) was
cancelled by #306's landing twenty minutes in. The group is
`ci-<event>-[record-]<ref>` now: a push to a line cancels the earlier push's
run as before, a pull request's own ref keeps each PR in a group of its own,
a dispatch runs to its end beside a push and a pull request, and a record
dispatch runs apart from the nightly's dispatch of the same line (the two
would otherwise cancel each other within the record's window). The keeper's CI
rule (a pull request runs exactly its line's required
set) is untouched; the `arch_*` guards and `actionlint` pass. The port to
`main` is a `git cherry-pick -x` (RELEASING.md point 21).

### Changed: `Certificate::verify` answers `false`, never an error, as the reference's `verify` does (#299)

`Certificate::verify` answered `Err(InvalidSignature("Certificate not
signed"))` for an absent signature, the DER parser's `Err` for a signature
that is not DER (an empty one, a truncated one, `r = 0`), and would have
passed on an `Err` from the key derivation; #275 made a field over the
bound `Ok(false)`. The reference catches every failure under its `verify`
and answers `false` (`ts-stack@edf6e03`
`packages/sdk/src/auth/certificates/Certificate.ts:425-440`: "Preserve the
historical boolean verification contract. Malformed or absent signatures
are invalid credentials, not exceptional control flow."): an absent
signature (`this.signature ?? ''`), one that is not hex or not DER
(`Signature.fromDER`), a frame `toBinary(false)` refuses, a key
`deriveChild` cannot derive. Now each is `Ok(false)` here
(`src/auth/certificates/certificate.rs`). `verify` returns no `Err` today:
its four steps are the reference's four, each a `false` there; the `Result`
stays for semver, so a caller's `?` still compiles. `MasterCertificate::verify`
and `VerifiableCertificate::verify` delegate and follow. Under the ruling
(c) of #299: the reference's own contract.

`validate_certificate` (through `validate_certificates`) refuses a `false`
verdict in the reference's words, `The signature for the certificate with
serial number <serial base64> is invalid!` (`validateCertificates.ts:99-104`),
where it said `Certificate signature invalid`; an unsigned or non-DER
certificate reached it as the `Err` above and now reaches this refusal.
`get_verifiable_certificates` does not verify, as the reference's
`getVerifiableCertificates` does not; the identity client's two parsers
read `Ok(false) | Err(_)` as no certificate and are unchanged.

Migration: a caller that matched `Err(Error::InvalidSignature(_))` (or any
`Err`) from `verify` for an unsigned or malformed certificate reads
`Ok(false)`: `if !cert.verify()? { /* invalid */ }`. One downstream calls it:
`bsv-wallet-toolbox-rs` (`6317222`) `src/wallet/certificate_issuance.rs:703`
maps an `Err` to `ValidationError("Failed to verify certificate signature:
..")` and discards the `bool`, so a certificate whose signature is absent or
not DER, refused there until now, passes its step 8, as one signed by
another key already did: its fix is to refuse `Ok(false)` (the keeper's to
file). `bsv-wallet-cli` (`a55990c`), `rust-message-box` (`419bf18`) and
`bsv-overlay-cloudflare` (`9a0f3c29`) call neither `verify` nor
`validate_certificates`.

Pinned by `tests/auth_certificate_verify_false_299.rs` (9 tests) on
`tests/vectors/auth_certificate_verify_false_299.json`, the reference's
verdicts on one certificate under nine signatures (valid, absent, empty,
not DER, truncated DER, another key's, `r = 0`, high `s`, not hex) recorded
by `tests/support/certificate_verify_false_299.mjs` at `ts-stack@edf6e03`
under Node v22.18.0 (two runs byte for byte): each verdict equal here save
the non-hex text, which this crate cannot hold (the signature is bytes) and
refuses at the certificate's JSON; the master's and verifier's `verify`; the
validator's words. 6 of the 9 red on the tree before the fix (`cdd52b8`),
the other three pinning what did not move (another key's signature
`Ok(false)`, the valid one this crate's own bytes, the JSON refusal). Two
pins in `tests/auth_integration_tests.rs` that expected the `Err` are
rewritten with the finding in their names,
`an_unsigned_certificate_verifies_false_not_an_error` and
`a_certificate_with_a_non_der_signature_verifies_false_not_an_error` (both
red on that tree). The #249, #251, #261, #262, #268, #275 and #297 vectors
are unchanged.

### Notes: cross-SDK parity (#299)

go-sdk@2ca481c's `Certificate.Verify` returns an `error`, nil when valid
(`auth/certificates/certificate.go:150-204`): `ErrNotSigned` for an absent
or empty signature (`:152-154`), `failed to create verifier wallet`
(`:157-160`), `failed to serialize certificate` from `ToBinary(false)`
(`:163-166`), `failed to parse signature` for one that is not DER
(`:169-172`), `ErrInvalidSignature` for a wrong one or a wallet's
invalid-signature error (`:192-201`), `signature verification failed` for
any other wallet error (`:196`). This crate follows the reference: every one of those is
`Ok(false)` here. The non-hex signature is the residual of the type: the
reference holds hex text and answers `false` at `verify`; this crate holds
bytes and refuses the text where it reads it (`Certificate`'s JSON), as Go,
whose `Signature` is a `util.ByteString`, refuses it at its JSON
(`util/bytestring.go:26-42`).
### Fixed: `Certificate::to_binary` and `from_binary` carry the reference's 16 MiB frame and 72-byte signature bounds (#301)

`Certificate::to_binary` wrote and `from_binary` read a frame of any length
and a signature of any length after the fields, where the reference refuses
both (`ts-stack@edf6e03` `Certificate.ts:25`, `:28`), each in its words,
every refusal `CertificateValidationError`:

- `to_binary` refuses a signature over 72 bytes before it writes it,
  `Invalid certificate signature encoding` (`:300-307`, the reference's
  check of the hex at most 144 characters), and the frame it wrote over 16
  MiB once it has the length, `Certificate binary exceeds the maximum of
  16777216 bytes` (`:315-319`), with the signature or without. The reference's
  `sign` and `verify` write `toBinary(false)` (`:458`, `:427`), so here
  `signing_hash` and `sign` refuse an unsigned prefix over the bound in the
  same words (nothing signed) and `verify` answers `Ok(false)` to it, as the
  reference's answers `false` (`:435-439`).
- `from_binary` refuses a frame over 16 MiB before it reads a byte,
  `Certificate binary must be a byte array of at most 16777216 bytes`
  (`snapshotCertificateBinary`, `:87-91`), and more than 72 bytes after the
  fields before it reads them, `Certificate signature exceeds the DER size
  limit` (`:390-394`).

The wallet wire's writer and reader keep their own checks (#189, #246, its
class `WalletError`); the texts are now one function's at both:
`wallet::wire::certificate_binary_written_refusal`,
`certificate_binary_read_refusal` and
`CERTIFICATE_SIGNATURE_DER_LIMIT_REFUSAL`. `Invalid certificate signature
encoding` is `to_binary`'s alone: the wire's writer refuses a long signature
in the reader's words, as it has since #189.

Pinned by `tests/auth_certificate_frame_bounds_301.rs` (7 tests over 13
cases of `tests/vectors/auth_certificate_frame_bounds_301.json`, the
reference's verdicts recorded by `tests/support/certificate_frame_bounds_301.mjs`
at `ts-stack@edf6e03` under Node v22.18.0): a frame of exactly 16,777,216
bytes written (the reference's SHA-256) and read back byte for byte, one byte
more refused on both; a 72-byte DER signature written and read, 73 refused
on both; an unsigned prefix of 16,777,217 bytes refused by `to_binary(false)`,
`signing_hash` and `sign`, and `false` at `verify` with the certifier's
BRC-52 child's signature over it (the reference's RFC 6979 bytes, made over
the preimage built by hand); 6 red on the tree before the fix (`cdd52b8`),
the seventh the vector's census. The 1 MiB text is built once and every
value sliced from it; the file runs in about 1.2 s. The #249, #251, #261,
#262, #268, #275 and #297 vectors are unchanged.

### Notes: cross-SDK parity (#301)

go-sdk@2ca481c bounds neither: `Certificate.ToBinary` and
`CertificateFromBinary` (`auth/certificates/certificate.go:114-131`,
`:134-146`) hand the bytes to the serializer, which writes the parsed
signature's `Serialize()` and reads the bytes remaining through
`ec.ParseSignature` with no length bound and no frame bound
(`wallet/serializer/certificate.go:64-66`, `:118-123`). Not carried: the
reference's `Signature.fromDER` at both sites (`Certificate.ts:310`, `:396`)
and its re-encoding on read (`sig.toString('hex')`, `:397`); `Certificate`
keeps the signature's bytes as given, the wire's reader and writer alone
parse the DER (#183, #189).

### Fixed: the reference's remaining certificate bounds and its decrypt wrappers (#297)

The five checks #275 named as not here, each now at the reference's site in
its words (`ts-stack@edf6e03`), every refusal `CertificateValidationError`,
the checks in `src/auth/certificates/bounds.rs`:

1. Construction. The reference's `Certificate` constructor checks nothing
   (`Certificate.ts:197-213`), so `Certificate::new` and `set_field` stay
   infallible. Its `MasterCertificate` constructor throws
   (`MasterCertificate.ts:195-233`), and `MasterCertificate::new` now
   refuses as it does: more than 100 fields or keyring entries (`Certificate
   fields cannot contain more than 100 entries`, `Master certificate keyring
   cannot ...`), a name that is not 1 to 50 bytes or is `__proto__`,
   `constructor`, `prototype` (`Certificate field name must be a safe UTF-8
   string of 1–50 bytes`, `:23-29`), a field with no keyring entry or an
   empty one (`Master keyring must contain a value for every field. Missing
   or empty key for field: "<name>".`), a field's text not canonical base64
   of 1 byte to 1 MiB, a keyring entry's not of 1 to 2048 bytes.
   `issue_for_subject` builds through it, as `:474-483` does.
2. The 2048-byte keyring entry (`MasterCertificate.ts:19`,
   `VerifiableCertificate.ts:18`), as canonical base64 at every reader:
   the constructor (`:215-232`), `create_keyring_for_verifier` (every
   entry, revealed or not, `:358-364`), the master's decrypt (`:582-586`)
   and the verifier's (`VerifiableCertificate.ts:182-186`), `<keyring>
   field <name> is empty, oversized, or non-canonical`; and the wallet's
   ciphertext at the two writers (`Encrypted master keyring field <name>
   ...`, `:292-298`; `Verifier keyring field <name> must be a non-empty byte
   array of at most 2048 bytes`, `:405-411`).
3. The 64 KiB plaintext: refused before encryption by
   `create_certificate_fields` (`Certificate plaintext field <name> exceeds
   the maximum of 65536 bytes`, `:271-276`), after decryption by both
   decrypt paths (`:612-616`, `VerifiableCertificate.ts:208-210`).
4. `to_binary`'s field checks (`Certificate.ts:44-129`, `:281-297`): more
   than 100,000 fields (`Certificate field count exceeds the maximum of
   100000`), a name outside 1 to 50 bytes (`Invalid certificate field name
   length: expected 1–50 bytes, received N`) or unsafe (`Unsafe certificate
   field name: <name>`), before the buffer; and the reader's twin
   (`:357-373`): a count over 100,000 or over a third of the bytes after it
   (`Certificate field count exceeds the available data`), a declared name
   length outside 1 to 50 before the name is read (`Invalid certificate
   field name length: received N`), an unsafe name. The wire's writer and
   reader carried these since #246 and #183.
5. The decrypt wrappers: `MasterCertificate::decrypt_field` answers every
   failure as `Failed to decrypt certificate field!` (`:621-623`; the field
   absent from the certificate with them), `decrypt_fields` every failure
   after its snapshots and its empty-keyring check as `Failed to decrypt
   all master certificate fields.` (`:525-561`), and
   `VerifiableCertificate::decrypt_fields` and `decrypt_field` as `Failed to
   decrypt selectively revealed certificate fields using keyring: <words>`
   (`VerifiableCertificate.ts:214-217`), the inner refusal's words quoted,
   the cipher's in the reference's (`Decryption failed!` for a tag that does
   not match, `Ciphertext too short` under 48 bytes, `SymmetricKey.ts:205`,
   `:217`, `:232`; they were `decryption failed` and `invalid data length:
   expected 48, got N`). #275's canonical-base64 refusals are now inside
   them, as in the reference. The texts that changed, old beside new: the
   master's `decrypt_field` on a field the certificate does not carry,
   `AuthError("Field '<name>' not found in certificate")`, and on one its
   master keyring does not carry, `AuthError("Field '<name>' not found in
   master keyring")`, are each `Failed to decrypt certificate field!` (the
   keyring's one `Failed to decrypt all master certificate fields.` from
   `decrypt_fields`); the verifier's `decrypt_field` and `decrypt_fields` on
   a keyring entry the certificate carries no field for, `AuthError("Field
   '<name>' not found in certificate")`, are `Failed to decrypt selectively
   revealed certificate fields using keyring: Certificate field <name> must
   be an own string data property` (`VerifiableCertificate.ts:36`, `:187-191`).

With them, the reference's sequence around each: `create_keyring_for_verifier`
refuses more than 100 fields to reveal or one named twice
(`fieldsToReveal contains duplicate field: <name>`, `:125-146`) and a field to
reveal the certificate does not carry in the reference's words (`Fields to
reveal must be a subset of the certificate fields. Missing the "<name>"
field.`, `:371-380`; it was `AuthError("Field '<name>' not found in
certificate")`); `MasterCertificate::decrypt_fields` refuses an empty master
keyring (`A MasterCertificate must have a valid masterKeyring!`, `:522-524`),
and `VerifiableCertificate::decrypt_fields` an empty keyring (`A keyring is
required to decrypt certificate fields for the verifier.`, `:161-163`) and
one of more than 100 entries (`:164-166`), where each answered an empty map;
the verifier's revelation key must be exactly 32 bytes (`:203`), the
master's 1 to 32 (`MasterCertificate.ts:600-611`, the shorter one's zeros
restored as before).

Pinned by `tests/auth_certificate_bounds_297.rs` (11 tests over 72 cases of
`tests/vectors/auth_certificate_bounds_297.json`, the reference's verdicts
recorded by `tests/support/certificate_bounds_297.mjs` at `ts-stack@edf6e03`
under Node v22.18.0: each bound at its edge and one past it, at its site; 10
red on beta's tree at `83b804d` with `MasterCertificate::new` returning
`Ok` unchecked, the eleventh the vector's census). Two pins moved with the
wrappers and the name bound, each red on that tree: #275's
`a_field_value_that_is_not_canonical_base64_is_refused_at_decrypt_275` now
expects the wrapped words, and `auth_reader_bounds.rs`'s
`a_certificate_field_length_of_usize_max_minus_k_is_refused` (#108) the name
bound's refusal ahead of `ReaderUnderflow`. #275's re-check's witness lands
with it: `a_certificate_signed_over_a_field_value_one_byte_over_one_mib_is_false_at_verify_275`,
a certificate whose 1 MiB-and-a-byte field is signed by the certifier's
BRC-52 child over this crate's writer's frame, `Ok(false)` at `verify`
(`Ok(true)` on the tree before #275, `cf38038`). The #249, #261, #268 and
#275 vectors are unchanged.

Migration: `MasterCertificate::new` returns `Result<MasterCertificate>`, the
reference's throwing constructor and Go's `NewMasterCertificate(..)
(*MasterCertificate, error)` (`go-sdk@2ca481c`
`auth/certificates/master.go:39-60`); add `?` or `.unwrap()` at the call.
No downstream calls it (`bsv-wallet-toolbox-rs`, `bsv-wallet-cli`,
`rust-message-box`, `bsv-overlay-cloudflare` grepped 2026-10-26; the
toolbox's `Certificate::new` and `set_field` at
`src/wallet/certificate_issuance.rs:533`, `:556` and
`busy_door_tests.rs:1299` are unchanged; its "not found in certificate" and
"not found in master keyring" texts at `wallet.rs:3158`, `:3166` are its own
function's).

### Notes: cross-SDK parity (#297)

go-sdk@2ca481c carries none of these bounds: no field count or name check
in `ToBinary` or `CertificateFromBinary` (`auth/certificates/certificate.go:114-148`,
`wallet/serializer/certificate.go:27-130`), a name's 50 bytes at issuance
alone (`master.go:157-159`), no keyring entry or plaintext size; its
`NewMasterCertificate` refuses an empty keyring and a missing entry, not an
empty one (`master.go:43-52`); its decrypt errors are its own words around
each step (`ErrFieldDecryption`, `verifiable.go:107-148`; `failed to decrypt
field %s: %w`, `master.go:339`), and its `DecryptFields` on an empty
verifier keyring refuses as the reference does (`verifiable.go:83-85`). The
reference decides here. The reference's master decrypt refuses an empty
plaintext (`denseBytes` asks at least a byte, `MasterCertificate.ts:83`,
`:612-616`) while its issuance encrypts one and its verifier decrypts one
(`VerifiableCertificate.ts:204-207`): followed, so a field issued empty is
issued here and refused at the master's decrypt and keyring, as there (the
vector's `plaintext_of_0_bytes`). Residuals: where several names break a
bound the reference names the first in its object's key order, this crate
the first in the names' order (`localeCompare`'s for `to_binary`, bytes for
the records); a plaintext that is not UTF-8, quoted by the verifier's
wrapper, is refused in each platform's words (Node's `TextDecoder`, `The
encoded data was not valid for encoding utf-8`, there; this crate's
`InvalidUtf8` text here), a platform residual, and a wallet's own error is
quoted as the wallet prints it, on both sides. Not carried, outside #297's five and
carried on the wire since #246: `Certificate::to_binary`'s 16 MiB frame
bound (`Certificate.ts:314-319`) and `from_binary`'s (`:86-92`, the input),
and the 72-byte signature bound and DER re-encoding at both
(`:300-312`, `:389-398`); the two bounds are carried since #301, the DER
parse and re-encoding remain the wire's alone.

### Fixed: a certificate field value is bounded at 1 MiB on write and read, and decrypted only from canonical base64 (#275)

`Certificate::to_binary` wrote and `from_binary` read a field value of any
length (the reader bounded only by the bytes remaining), where the reference
refuses one over 1 MiB at both: `toBinary`'s snapshot of the fields measures
each value's text as UTF-8 bytes (`ts-stack@edf6e03` `Certificate.ts:27`,
`:76-79`, `:281`) and `fromBinary` the declared length before it reads the
bytes (`:377-381`), both in the words `Certificate field <name> exceeds the
maximum of 1048576 bytes`. The wallet wire's writer (#246) and reader (#189)
already refused it; the text is now one function's
(`wallet::wire::certificate_field_value_refusal`), at the four sites.
`to_binary` checks every value before it allocates the buffer; `sign`
serializes through it, as `Certificate.ts:458` does, and refuses with it;
`verify` answers `false` to an over-bound field, as the reference's `verify`
answers `false` to every failure under it (`:435-439`, "the historical
boolean verification contract"); `set_field` takes any value, as the reference's constructor does. Where a
field is decrypted (`MasterCertificate::decrypt_field`, `decrypt_fields`,
`create_keyring_for_verifier`, `VerifiableCertificate::decrypt_field`,
`decrypt_fields`), its text was decoded leniently (whitespace stripped, the
URL alphabet and missing padding accepted, `from_base64`); the reference
decodes it as canonical base64 of 1 byte to 1 MiB (`canonicalBase64`,
`MasterCertificate.ts:63-74`, called at `:351-357`, `:534-538`, `:587-591`;
`VerifiableCertificate.ts:41-52`, `:187-191`; `WalletByteEncoding.ts:39-64`)
and refuses otherwise in `Certificate field <name> must use canonical base64
encoding` or `Certificate field <name> is empty, oversized, or
non-canonical`, both now this crate's (`CertificateValidationError`), before
the wallet's decrypt; `create_keyring_for_verifier` checks every field, revealed
or not, first, as `:351-357` does. Pinned by
`tests/auth_certificate_field_bound_275.rs` (8 tests; 6 red on the tree with
the checks removed: the `verify` pin is green there too, the signature not
covering the mutated value, and pins `Ok(false)` where this change's first
cut answered an error). `auth_reader_bounds.rs`'s
`a_certificate_value_length_of_usize_max_is_refused` (#108) pinned
`ReaderUnderflow` for a value length of `u64::MAX`; the bound now refuses it
first, in its words, and the pin says so.

Migration: `Certificate::to_binary` returns `Result<Vec<u8>>` and
`Certificate::signing_hash` `Result<[u8; 32]>`, the reference's throwing
`toBinary` and Go's `ToBinary(bool) ([]byte, error)`
(`go-sdk@2ca481c` `auth/certificates/certificate.go:114`); add `?` or
`.unwrap()` at the call.

### Notes: cross-SDK parity (#275)

The base `Certificate` reads no field value as base64 in the reference
(`Certificate.ts` checks only `type` and `serialNumber`, `:30-43`), and
neither does this crate: the canonical rule is the decrypting classes'. Go
bounds no field value (`go-sdk@2ca481c` `auth/certificates/certificate.go:114-148`)
and decodes a field with `base64.StdEncoding` (`verifiable.go:140`), which
skips line breaks and accepts unused bits set; this crate refuses both, as
the reference does. Not carried here: the reference's `MasterCertificate`
constructor checks each field and keyring entry at construction
(`MasterCertificate.ts:205-232`; `MasterCertificate::new` takes them
unchecked and the decrypt sites refuse them); the keyring entries' canonical
2048-byte bound (`:220-231`, `VerifiableCertificate.ts:182-186`), the 64 KiB
plaintext bound at issuance and decrypt (`MasterCertificate.ts:272-276`,
`:612-616`, `VerifiableCertificate.ts:208-209`), the 100,000-field count and
the name checks in `toBinary`'s snapshot (`Certificate.ts:57-58`, `:73-74`);
and the reference's outer decrypt words (`Failed to decrypt certificate
field!` and `Failed to decrypt all master certificate fields.`,
`MasterCertificate.ts:622`, `:560`; `Failed to decrypt selectively
revealed certificate fields using keyring: <words>`,
`VerifiableCertificate.ts:214-217`): the inner refusal is returned as is.
### Fixed: `Peer` refuses a malformed requested certificate set where the reference does, on its own policy and on receipt (#294)

`validate_requested_certificate_set` refuses a type ID that is not base64
of 32 bytes, but `Peer` (`src/auth/peer.rs`) called no validator: it
signed and sent a certificateRequest whose policy names a 31-byte, a
33-byte, a non-base64 or an integer-like (`"42"`) type ID, which a
reference peer refuses, and handed such a request from a peer to its
listener unchecked. The reference refuses the set with
`assertRequestedCertificateSet` (`ts-stack@edf6e03`
`packages/sdk/src/auth/AuthMessageValidation.ts:107-162`) on its own policy
at construction (`Peer.ts:158`), at each snapshot (`:332`, through
`#snapshotCertificatePolicy`, in `initiateHandshake` `:630` and
`processInitialRequest` `:811`) and first thing in `requestCertificates`
(`:434`), each a throw before any signature; and on receipt in
`snapshotAuthMessage` (`Peer.ts:767`), the first line of
`#handleIncomingMessage`, before any handler: on any message carrying
`requestedCertificates` (`AuthMessageValidation.ts:345-346`) and required
on a certificateRequest (`:367`).

`bsv_rs::auth::assert_requested_certificate_set` (new) is that validator,
its rules and words: the certifiers at most 100, each `02`/`03` and 64
lowercase hex digits on the curve, unique; the types at most 100, each
canonical base64 (`base64ToBytes`, `WalletByteEncoding.ts:39-64`: padded,
no whitespace or URL-safe alphabet, zero bits under the padding, at most
128 characters) of exactly 32 bytes, an unsafe key (`__proto__`,
`constructor`, `prototype`) refused in the bounded-data walk's words, which
reach it first; each type's fields at most 100, unique, non-empty, at most
50 UTF-8 bytes and safe; an empty set valid (the reference's default
policy, `Peer.ts:154-157`). It refuses as `Error::AuthError` with the
reference's message (`certificate type must encode exactly 32 bytes.`,
`certificate type must be canonical base64.`, ...). `Peer` calls it at the
reference's sites: `request_certificates` before it seeks a session or
signs; the peer's own policy in `initiate_handshake` before a nonce is made
or an initialRequest sent, and on a received initialRequest before
`process_initial_request` makes a session or signs the response
(`Peer::new` returns `Self`, so the refusal the reference makes at
construction is made at the policy's first snapshot); and a received
message's `requestedCertificates` in `handle_incoming_message` (after the
version check) and the `start` callback, before the message is routed, a
certificateRequest without one refused as `requestedCertificates must be
an object.`. A refusal on receipt is the `Err` the transport's callback
returns, as for a wrong version; a refused initialResponse on the `start`
path leaves the handshake to its timeout, as the reference's throw in
`#handleIncomingMessage` leaves its waiter.
The validator lives in `src/auth/utils/requested_set.rs` and `Peer`'s unit
tests moved to `src/auth/peer_tests.rs`, so neither `validation.rs` nor
`peer.rs` grows past its ratchet bound.
`validate_requested_certificate_set` is unchanged: its words are this
crate's and it refuses an empty set, the reference's default, so `Peer`
does not call it.

Pinned by `tests/auth_requested_set_validation_294.rs` with
`tests/vectors/auth_requested_set_validation_294.json` (new), recorded by
`tests/support/requested_set_validation_294.mjs` under Node v22.18.0: for
the four malformed type IDs, the reference's words equal this crate's at
the validator, at `request_certificates` after a handshake (no message
sent; the reference signed nothing), at a peer's own policy before the
initialRequest and before the initialResponse, and on the reference's
signed certificateRequest read by the server path and the `start` path
(the listener not called; the reference checked no signature); a request
without `requestedCertificates` refused in the reference's words; the
32-byte ID signed, sent and received at both ends, this crate verifying the
reference's signature; and the unit tests in `src/auth/utils/requested_set.rs`
for every other rule's words, each input's verdict checked against the
reference at `edf6e03`. With `Peer`'s calls removed, the five `Peer` tests
are RED (the validator kept); with the validator's body removed as well,
seven of the nine integration tests and three of the four unit tests are
RED, the passing ones the acceptances. `fuzz_auth_messages` now calls
`assert_requested_certificate_set` on every set it reads, alone and in a
message (951,920 runs in 120 s on a corpus copy, no crash).

### Notes: cross-SDK parity (#294)

Go's `Peer` calls no validator of the set (`go-sdk@2ca481c`
`auth/peer.go:1074-1110` sends `certificateRequirements` as given; its
`ValidateRequestedCertificateSet`, `auth/utils/validate_certificates.go:312-336`,
which refuses an empty set, is called by nothing); a Go type ID is a
`[32]byte` (`:20`), so a sender cannot name a malformed one, and its JSON
reader refuses a key that is not base64 of 32 bytes
(`validate_certificates.go:30-51`, `invalid base64 key`, `expected 32
bytes`). What this crate does not model of the reference's receipt check:
the set is typed after the JSON read, so an absent `certifiers` or `types`
member reads as empty and a `null` set as absent, where the reference
refuses them (`AuthMessageValidation.ts:119-121`, `:131-134`, `:111-113`);
and the bounded-data walk's budgets over the whole message (16 MiB, depth
64, 100,000 nodes, `:7-9`) are not applied to the set, whose own limits
(100 certifiers, 100 types, 100 fields) bind first on any set those budgets
pass but one of more than 100,000 nodes, which both refuse in other words.

One residual, stated: a session a caller injects lets that caller's own
malformed policy reach `process_certificate_response` unchecked, where the
reference's `Peer` holds only a policy it validated at construction
(`Peer.ts:158`); a policy that enters through `Peer`'s own doors is checked.

### Fixed: a JSON number reads to the correctly rounded double, so a Socket.IO frame round-trips every finite `f64` (#285)

The Socket.IO codec (`src/auth/transports/socketio/codec.rs`) reads and
writes a packet's JSON with `serde_json`, whose default number reader is not
correctly rounded: a long decimal could read one bit off the nearest double,
and the shortest text written for that double could read back another bit
off, so a frame's encoding was not a fixed point. The #280 lane's fuzz run
on `fuzz_auth_messages` crashed on it (a 107-digit integer in an
`authMessage` event: `4.444444444444445e+106` read as
`4.4444444444444455e+106` on the re-read). The fix turns on `serde_json`'s
`float_roundtrip` feature (`Cargo.toml`), the correctly rounded reader, as
`JSON.parse` is; the writer already printed the shortest text that reads
back to the same double. The feature is crate-wide, so every JSON number
this crate reads (the HTTP and WebSocket transports' `AuthMessage`, the
HTTP JSON wallet substrate, the overlay bodies) is read to the nearest
double, and cargo's feature unification turns it on for a downstream's own
`serde_json` in the same build: a number reads differently only where the
old reader was wrong. A number past the double range (`1e400`) stays a
refusal with `serde_json`'s reason, never a panic, where the reference
reads it as `Infinity` and writes `null` back (the parity note). Pinned by
`tests/socketio_float_round_trip.rs` (the crash input, a set of awkward
doubles against `serde_json`'s own round trip, long decimal texts against
Rust's correctly rounded `str::parse`, and the vector below; four of its
five tests RED on the pre-fix tree), the vector
`tests/vectors/socketio_float_round_trip_285.json` (21 frames, the
reference's verdict on each, written by
`tests/support/socketio_float_285.mjs`), and the crash input in the fuzz
corpus (`fuzz/corpus/fuzz_auth_messages/socketio-event-long-float`).

### Notes: cross-SDK parity (#285)

The reference's Socket.IO codec is `socket.io-parser`, which
`ts-stack@edf6e03`'s `@bsv/authsocket-client` reaches through
`socket.io-client` (`packages/messaging/authsocket-client/package.json:72`;
the lockfile resolves `socket.io-parser@4.2.7`); its Encoder writes a
packet's data with `JSON.stringify` and its Decoder reads it with
`JSON.parse`. Run under Node v22.18.0 on the 21 frames, it reads the double
this crate now reads in every case (bits recorded), and its encoding is a
fixed point in every case. The text this crate writes back differs in 8 of
them, the double the same: `serde_json` writes an integral float with a
fraction or an exponent (`100.0`, `1.2345678901234568e+20`) where
JavaScript writes an integral double below `1e21` as an integer (`100`,
`123456789012345680000`), keeps negative zero's sign (`-0.0`) where
`JSON.stringify` writes `0`, and keeps an integer within `u64` exact
(`9007199254740993`) where `JSON.parse` reads the nearest double
(`9007199254740992`). The last was so before this fix; the enumeration is
pinned (`TEXT_DIFFERS`). A number past the double range is where the two
part: `JSON.parse` reads `1e400` as `Infinity` and `JSON.stringify` writes
it back as `null`, so the reference's encoding of such a frame is not a
fixed point (its data changes); this crate refuses the frame as
`Malformed` with `serde_json`'s reason (rule 5: the exact value back or a
refusal), pinned by `a_number_past_the_double_range_is_refused_with_a_reason`.
### Changed: `RequestedCertificateSet::types` keeps insertion order, as the reference's `Record` does (#288)

`RequestedCertificateSet::types` was a `HashMap<String, Vec<String>>`
(`src/auth/types.rs`), and each `HashMap` iterates in its own order: two
encodings of one set wrote its types in different orders, so a set built
here (`add_type`) and sent by `AuthMessage::set_requested_certificates`
signed and sent the keys in the map's order, not the order given, and a
set read and written again was not a fixed point. #280 keeps a received
text, so a verifier checks the bytes it received; the sender's order was
left. The reference holds `types` as a `Record<string, string[]>`
(`ts-stack@edf6e03` `packages/sdk/src/auth/types.ts:21-23`), in insertion
order, and signs a certificateRequest over the UTF-8 bytes of
`JSON.stringify(policy)` (`Peer.ts:451-453`). `types` is now an
`indexmap::IndexMap<String, Vec<String>>`, named
`bsv_rs::auth::RequestedCertificateTypes`: a JSON read keeps the text's
order, `add_type` appends a new type (one already present keeps its place
and takes the new fields, as a `Record`'s assignment does), and the JSON
written, the bytes a certificateRequest signs, is that order. `indexmap`
(2, its `serde` feature, already in the tree under `http` through `h2`) is
a new dependency behind `auth`; it builds for wasm32 and passes
`cargo deny`, and a hand-rolled `Vec<(String, Vec<String>)>` would have
needed its own map API and serde for no gain. `get`, `insert`, `iter`,
`len`, `is_empty`, `contains_key` are as they were.

Pinned by `tests/auth_requested_types_order_288.rs` with
`tests/vectors/auth_requested_types_order_288.json` (new), recorded by
`tests/support/requested_types_order_288.mjs` under Node v22.18.0: a set
with three types encodes in the order given and re-encodes identically,
and a message built with it sends and signs that text; a JSON read keeps
the text's order; this crate's text for the reference's three-type policy
is the reference's `JSON.stringify(policy)` byte for byte, which two
reference `Peer`s sign and verify; and this crate's certificateRequest,
handed to a reference `Peer` holding the session, verifies over the bytes
sent, its listener receiving the policy in this crate's order. All four RED
on `70799f4`. `fuzz_auth_messages` now asserts a requested set's JSON is a
fixed point (it panicked on 4 of 5 runs of the three-type policy on
`70799f4`); the #285 run's crash input, a message whose set holds two
types, passes it and passed already on `70799f4`, where #280's kept text
covered its path.

Migration: a struct literal built with a `HashMap` writes
`types: [(id, fields)].into_iter().collect()` (or
`RequestedCertificateTypes::from([...])`); code that reads `types` with the
map API compiles as it is, and a function that took the `HashMap` takes
`&RequestedCertificateTypes`. Of the downstreams, none builds a
`RequestedCertificateSet` or reads its `types`
(`bsv-wallet-toolbox-rs`, `bsv-wallet-cli`, `rust-message-box`,
`bsv-overlay-cloudflare` searched, 2026-10-26; their `PeerOptions` literals
pass `certificates_to_request: None`). `indexmap`'s major version is now
part of this crate's public API.

### Notes: cross-SDK parity (#288)

The reference's `#snapshotCertificatePolicy` copies `types` with
`Object.fromEntries(Object.entries(...))` (`Peer.ts:331-339`), which keeps
insertion order but for an integer-like key, which a JavaScript object
moves first in ascending order. The reference's validator refuses such a
key: a type is canonical base64 of 32 bytes
(`AuthMessageValidation.ts:141-144`), 44 characters ending in `=`, never
integer-like. Since #294 this crate's `Peer` refuses the same form at the
same sites, on snapshot (`Peer.ts:332`) and on receipt
(`AuthMessageValidation.ts:345-346`, `:367`), with
`assert_requested_certificate_set`, so neither side signs an integer-like
key and the difference closes: on every set either side signs, the two
write the same bytes. (Until #294 a set the reference refuses, a type
`"1"` after a type `"2"`, was signed here in insertion order where a
JavaScript object writes `"1"` first.) Go holds `types` as a `map[wallet.CertificateType][]string`
(`go-sdk@2ca481c` `auth/utils/validate_certificates.go:20`, `:54`) and
`json.Marshal` writes a map's keys sorted, so
a Go sender's order is the sorted one; a text it sends verifies here as
received. A certificate's `fields` and keyring are `HashMap`s in this
crate's certificate JSON too; the certificateResponse is signed over the
text sent (#280), so no signature depends on their order, and their JSON
shape is #268's.

### Fixed: `write_wallet_certificate` refuses the reference's three bounds and writes the fields in the signed order (#246)

Two things #189 left in `WireWriter::write_wallet_certificate`
(`src/wallet/wire/encoding.rs`, `certificate_bytes`; the optional and
discovery writers inherit both).

**The bounds.** The reference's `Certificate.toBinary` refuses three things
before it writes (`ts-stack@edf6e03` `Certificate.ts`), which this crate's
reader refuses too (`read_certificate_fields`, `src/wallet/wire/mod.rs`) and
this writer wrote unchecked. It now refuses each, a `WalletError`, before a
byte reaches the caller's writer:

- more than 100,000 fields (`snapshotCertificateFields`, `:57-58`):
  `Certificate field count exceeds the maximum of 100000`, the reader's
  words and the reference's;
- a field value over 1 MiB (`:76-79`): `Certificate field <name> exceeds
  the maximum of 1048576 bytes`, the reader's words and the reference's;
- a frame over 16 MiB (`:315-319`): `Certificate binary exceeds the maximum
  of 16777216 bytes`, the reference writer's words (the reader's, from
  `snapshotCertificateBinary` `:87-91`, are `Certificate binary must be a
  byte array of at most 16777216 bytes`, a different sentence for the
  reading).

Pinned by `a_certificate_with_more_than_100000_fields_is_refused_by_the_writer`,
`a_certificate_field_value_past_a_mebibyte_is_refused_by_the_writer` and
`a_certificate_frame_past_16_mebibytes_is_refused_by_the_writer`
(`tests/wire_reader_strictness.rs`), each with the frame at its bound written
and read back, red on `dc5341e`.

**The order.** The writer sorted the field names by their bytes. Since #249
`Certificate::sign` signs over the reference's order (`localeCompare`,
`Certificate.ts:282`) and `Certificate::from_binary` verifies over the bytes
received, so a certificate signed here and written to the wire did not
verify when this crate read the frame back (#249's names: the writer wrote
`Name, a0, a_b, age, f, éa`, the signature covers `a_b, a0, age, éa, f,
Name`), and the frame was not the bytes the reference's processor writes
for the same certificate (`toBinary`, `WalletWireProcessor.ts:1975`, `:2067`,
`:2501`). The writer now orders the names with the function the signer
uses, `collation::sort_field_names`: one table, one order. The module moves
from `src/auth/certificates/` to `src/wallet/collation.rs` (its table
`collation_latin1.txt` beside it, regenerated by
`tests/support/certificate_collation_table_249.mjs`: the header line naming
the path is the only change; the pair check against Node's `localeCompare`
still 0 disagreements in 18,808,356 pairs), because `wallet` builds the wire
without `auth`. Pinned by
`a_certificate_signed_here_is_written_to_the_wire_in_the_signed_order` and
`the_wire_writes_the_names_in_local_compare_order_not_byte_order`
(`tests/wire_certificate_field_order_246.rs`): a certificate over the six
names signed here, written to the wire, is the reference's `toBinary(true)`
bytes (the #249 vector's `reference_signed_mixed_names` and
`rust_signed_mixed_names`, re-run against the reference bundle at
`edf6e03` under Node v22.18.0: the same bytes, both verified there),
verifies when read back, and reads back through `read_wallet_certificate`
to the same certificate; red on `dc5341e`. The reference's and Go's readers
insert into a map and require no order (`Certificate.ts:364-387`;
go-sdk@2ca481c `wallet/serializer/certificate.go:115`), so each reads either
order; Go's writer sorts by bytes (`:41-47`). No vector or recording moves.
Public shape: nothing moves.

### Changed: the nightly's heavy work holds at most six concurrent slots

The mutant shards run six at a time (`max-parallel: 6`, twenty before) and
the fuzz targets six at a time after them (`needs: [source, mutants]`, run
whatever the shards' result), so the night's heavy work never holds more
than six of the account's twenty concurrent slots and a pull request's run
at 03:00 UTC starts within minutes; the shards finish later in the night
and decide the same (the owner's balance rule of 2026-10-26, the keeper's
reading, as the nightly goes live with main's copy of the schedule).
### Fixed: the createAction validator refuses an empty `unlockingScript` and a zero `unlockingScriptLength` (#282)

`wallet::validation::validate_create_action_args` (through
`validate_create_action_input`) accepted an input with an empty
`unlockingScript` (`Some("")`, or whitespace alone) and an
`unlockingScriptLength` of 0. It now refuses both, as
`Error::WalletRefusal` of class `WalletRefusalClass::InvalidParameter`
(`WERR_INVALID_PARAMETER`, code 6):

- an empty `unlockingScript` in the reference's words, `The unlockingScript
  parameter must be hexadecimal string.`: its `validateOptionalHexString`
  asks one or more hex characters (`ts-stack@edf6e03`
  `packages/sdk/src/wallet/validationHelpers.ts:595`, `:522-530`), ahead of
  the length, so an empty script with a length of 0 takes these words too.
  The words carry no input index: the reference names the field
  `unlockingScript` alone (the run below), not `inputs.N.unlockingScript`
  as the issue quoted it;
- an `unlockingScriptLength` of 0 as BRC-100's positive integer
  (`brcs@5119a9b` `wallet/0100.md:649`), in `#requireInteger`'s form with
  this crate's name (`integer_refusal`, #255): `Invalid createAction input
  unlockingScriptLength: expected an integer from 1 to 4294967295, received
  0`.

A one-byte script and a length of 1 are accepted as before. Pinned by
`an_empty_create_action_unlocking_script_is_refused_in_the_reference_words`,
`a_zero_create_action_unlocking_script_length_is_refused_as_brc100_positive_integer`
and `the_create_action_args_refuse_an_empty_unlocking_script_and_a_zero_length`
(`src/wallet/validation/create_action_input.rs`, where
`validate_create_action_input` now lives, re-exported at its old path, so
`validation.rs` stays within its recorded line bound) and by
`tests/wallet_create_action_unlocking_script_282.rs` against
`tests/vectors/wallet_create_action_unlocking_script_282.json`, the
reference's verdicts and words from `Validation.validateCreateActionArgs`
at `ts-stack@edf6e03` under Node v22.18.0
(`tests/support/create_action_unlocking_script_282.mjs`); each refusal's
test RED on the pre-fix tree. No public shape changes; a caller that
passed an empty script or a zero length now gets the refusal. The
toolbox's create door (its #212), which refuses both in its own code, can
ask this validator instead, as it does for internalizeAction (#117); until it does, the toolbox's own words for the zero length differ from these (its PR #215, `named_input_tests.rs:258`).

### Notes: cross-SDK parity (#282)

The reference's helper permits a zero length: `validateCreateActionInput`
runs `validateInteger(unlockingScriptLength, 'unlockingScriptLength',
undefined, 0)`, a minimum of 0 (`validationHelpers.ts:598`), though its
`ValidCreateActionInput` types the field `PositiveInteger` (`:574`); the
run records `{ unlockingScriptLength: 0 }` accepted. This crate takes
BRC-100's positive integer (the keeper's reading of 2026-10-26); the
upstream filing against ts-stack is the keeper's to carry. go-sdk at
`2ca481c` has no createAction argument validator (its
`UnlockingScriptLength` is read and written by `wallet/serializer` alone)
and judges neither.

### Changed: a certificate's revocation outpoint index above `u32::MAX` is refused in the bound refusal's form (#258)

`Certificate::from_binary` refused a revocation outpoint index above
`u32::MAX` in #122's words (`invalid revocation outpoint index: expected at
most 4294967295, got 4294967296`). It now refuses it through the wire's
helper (`integer_refusal`, `src/wallet/wire/mod.rs`, #255), the one form of
every bound refusal: `Invalid revocation outpoint index: expected an integer
from 0 to 4294967295, received 4294967296`, still
`Error::CertificateValidationError`. The name `revocation outpoint index`
is this crate's: the reference has no words for this bound. The bound
stands under #122 (a refusal, never a cast; BRC-12's outpoint index is four
bytes on the wire). No behavior beyond the words. Pinned by
`a_revocation_outpoint_index_above_u32_max_is_refused_not_truncated_in_the_bound_refusals_form`
(`src/auth/certificates/certificate.rs`, RED on the pre-fix tree). No vector
or recording carried these words.

### Notes: cross-SDK parity (#258)

The reference's `Certificate.fromBinary` reads the index with
`readVarIntNumStrict(false)` and no `#requireInteger` (`ts-stack@edf6e03`
`packages/sdk/src/auth/certificates/Certificate.ts:353`), so it accepts an
index above `0xffffffff` up to `2^53 - 1` (`readVarIntNumStrict.ts`'s
precision bound) into the outpoint string; its `toBinary` refuses one above
`0xffffffff` (`Certificate.ts:263-270`). Go's reader casts the varint to
`uint32` (`go-sdk@2ca481c` `wallet/serializer/serializer.go:82-96`, a
truncation above the bound) and its writer writes a `uint32` (`:20-25`).
This crate's reader refuses it: no SDK writer produces the oversized index,
so the bound meets the north star's "accept what the reference accepts".
### Removed: the processor's `with_config`, `network()` and `version()` (#222)

`WalletWireProcessor::with_config`, `network()` and `version()`,
`#[deprecated]` since #222 forwarded getNetwork and getVersion to the
wallet (PR #231, e65a8cb), are removed in 0.9.0 on the owner's word
(2026-10-26, DECISIONS 16.5: removal if a grep of the toolbox, the CLI and
LOW's Workers finds zero calls; it found zero). The values they held reached
no frame, so a caller that set them was told a network and version the wire
never answered. Migration: `WalletWireProcessor::new(wallet)` in place of
`with_config(wallet, network, version)`; the wallet's own `get_network` and
`get_version` in place of the accessors. The two roundtrip tests that built
a processor with `with_config` under `#[allow(deprecated)]`
(`tests/wire_method_roundtrip_tests.rs`) are now
`test_roundtrip_get_network_is_the_wallets_answer` and
`test_roundtrip_get_version_is_the_wallets_answer`: the transceiver's
answer equals the wallet's `get_network` and `get_version`.
### Fixed: a certificate message is signed over the JSON text it sends and verified over the text it received (#280)

BRC-103 signs a certificateRequest over its requested certificates and a
certificateResponse over its certificates, "the payload plus nonces", and
names no serialization (`5119a9b` `peer-to-peer/0103.md:133-137`, `:172`).
The reference fixes the reading (`ts-stack@edf6e03`
`packages/sdk/src/auth/Peer.ts`): `:453` signs
`utf8(JSON.stringify(policy))`, the `requestedCertificates` member alone,
and `:1140` `utf8(JSON.stringify(certificates))`, the `certificates` array
alone (the nonces are in the key ID, not the bytes); `:1068` and `:1203`
verify the `JSON.stringify` of what they parsed, which is the received
text whenever that text is compact (`JSON.parse` keeps key order). This
crate's `AuthMessage::signing_data` re-serialized the parsed values, whose
`HashMap`s (`RequestedCertificateSet::types`, a certificate's `fields` and
`keyring`) reorder keys: a reference peer's request naming several types,
or a certificate with several fields or keyring entries, failed
verification here at the map's whim (the #268 review measured 5 of 6 runs
on a 3-field certificate), and a sender's `decryptedFields` were dropped
from the bytes checked.

Two rules now. This crate sends compact JSON and signs its bytes: a
message carries the text it sends (`AuthMessage::set_certificates`,
`set_requested_certificates`; `Peer` builds with them), and the reference's
re-stringify of that text reproduces it, since `JSON.parse` keeps the order
and `JSON.stringify` writes it compact. On receipt the certificates' and
the requested certificates' text is kept as received
(`AuthMessage::certificates_text`, `requested_certificates_text`,
`serde_json` raw values) and `signing_data` returns those bytes while they
read back to the parsed value; a member changed since is serialized afresh,
once, and that is what is signed and sent. The HTTP and WebSocket
transports already wrote and read the message with `to_string`/`from_str`;
the Socket.IO transport went through a `serde_json::Value`, which sorts
keys: its send writes the message's text through a new provided method,
`SocketIoSink::send_socketio_text` (the default decodes and forwards to
`send_socketio` as before; a sink that writes text overrides it), and its
dispatch reads the event argument's text (`codec::decode_event_args_text`).

`tests/auth_signed_text_280.rs` with `tests/vectors/auth_signed_text_280.json`
(new), recorded by `tests/support/auth_signed_text_280.mjs` driving two
reference `Peer`s over an in-memory transport carrying `JSON.stringify`
text under Node v22.18.0: the reference's certificateRequest naming five
types verifies here over its received text (red on `0266ba2`); the bytes
the reference signed for its certificateResponse are the `certificates`
text it sent; a received certificateResponse carrying `decryptedFields`, in
an order no serializer here writes, verifies over its text (red on
`0266ba2`); a member changed after receipt is signed afresh; this crate's
certificateRequest text, handed to a reference `Peer` holding the session,
is verified there over the bytes sent, `true`. The Socket.IO send and
dispatch keep the text (`tests/socketio_signed_text_280.rs`, red with the
text path reversed); `fuzz_auth_messages` reads the argument as text and checks the
signed bytes survive a write and a read.

What this does not reach: the reference's certificate JSON is not this
crate's yet (`type` where this crate writes `certType`, base64 field values
and keyrings and a hex signature where it writes number arrays; #261,
#268). A reference certificateResponse does not parse here (pinned by
`a_reference_certificate_response_is_refused_by_its_certificate_shape_until_268`),
and the reference refuses this crate's: it rebuilds each certificate as its
class before it verifies (`Peer.ts:341-357`, `:768`), so `certType` drops
out of the bytes it checks (recorded in the vector). The signed bytes are
the text either way; when the shape lands both directions verify.

Migration: `AuthMessage` gains two public members, so a struct literal
adds `certificates_text: None, requested_certificates_text: None` (0.9.0's
line; `AuthMessage::new` and field assignment need no change). The message
box (`rust-message-box`) deserializes `AuthMessage` from a `serde_json::Value`
(`src/engineio/auth.rs:208`, `:344`); that still parses, with the members'
text the `Value`'s key-sorted re-serialization, so a certificate message it
ever verifies must be read from the frame's text (`from_str`), never from a
`Value`; it no-ops certificate messages today.

### Notes: cross-SDK parity (#280)

The reference verifies the `JSON.stringify` of what it parsed after
rebuilding each certificate as its class (`Peer.ts:341-357`), so for a
text whose certificate members are out of the class's order, or that is
not compact, or that carries an integer-like object key (a JavaScript
object moves it first), it checks other bytes than it received; this
crate checks the bytes received. On every text the reference or this
crate writes the two are the same bytes. Go re-serializes on both sides
(`json.Marshal`, `go-sdk@2ca481c` `auth/peer.go:829`, `:898` to verify,
`:1109`, `:1189` to sign), and a Go map writes its keys sorted: a text Go
sends verifies here as received, and a text whose map keys are not sorted
(the reference's, this crate's) fails verification in Go. The gap is
BRC-103's (`0103.md:133-137`, `:172`); the sentence for upstream, "the
signature is over the UTF-8 bytes of the JSON text as transmitted", is
the keeper's filing.

### Changed: the secrets scan covers the commits the event brings (#272)

CI's `secrets` job ran gitleaks over every ref of the checkout (gitleaks's
`git` mode with no range, the checkout fetching every branch), so a
key-looking test literal on any pushed branch failed every pull request's
scan: PR #257 at 2026-10-26 16:46Z, the two findings being the #105
branch's witnesses, with no location printed. On a pull request the scan
now covers the PR's own commits (the base sha to `HEAD`, what decides the
merge; an empty base sha falls back to the line's history), on a push and
on a dispatch the line's full history, and `-v` prints a finding's location
with the value redacted. `tests/arch_secrets_scan_scope.rs` pins the step
(red on the old one). `.gitleaks.toml` judges the two literals by reason:
secp256k1's generator point in compressed form (the public key of the
private key 1, the #105 witnesses' identity key, also in the EC, sighash
and cross-SDK tests and the auth and overlay vectors) and the old revealer
shape's test key of `tests/wallet_http_json_shapes_105.rs` (the Go SDK's
test public key, also across the wallet-wire vectors), beside the BRC-56
vectors and the corpus-gen nonce.
### Changed: `Certificate::sign` refuses a certificate already signed, as the reference does (#262)

`Certificate::sign` signed over a certificate that already carried a
signature and replaced it. The reference refuses it (`ts-stack@edf6e03`
`packages/sdk/src/auth/certificates/Certificate.ts:450-453`: when
`this.signature` is present with a length above 0 it throws `Certificate has
already been signed! Signature present: <signature hex>`, before it reads
the wallet), and so does Go (`go-sdk@2ca481c`
`auth/certificates/certificate.go:209-211`: `Sign` returns
`ErrAlreadySigned`, `certificate has already been signed`, `:22`, when
`Signature` is not nil). Now `sign` refuses a `Some` non-empty signature
ahead of every other check, as `Error::CertificateValidationError` (the
variant of the crate's other certificate refusals) carrying the reference's
words, the present DER signature in lower-case hex as the reference prints
its `HexString`; the certificate is left as it was. An empty signature is
no signature, as `length > 0` reads it. The keeper's ruling on #262
(2026-10-26): a signed certificate is immutable here too.

Migration: a caller that re-signed a signed certificate clears it before
`sign` with `set_signature(None)`, as the reference's caller sets
`signature = undefined`. No public signature moves and no `Error` variant is
added. None of `bsv-wallet-toolbox-rs` (`6317222`), `bsv-wallet-cli`
(`a55990c`), `rust-message-box` (`419bf18`) or `bsv-overlay-cloudflare`
(`9a0f3c29`) calls `Certificate::sign` (the toolbox builds a certificate
with `Certificate::new` and sets the certifier's signature it received,
`src/wallet/certificate_issuance.rs:533,562`); nothing in this crate signs
twice.

Pinned by `tests/auth_certificate_sign_refusal_262.rs` on the witness
`tests/vectors/auth_certificate_sign_refusal_262.json`, recorded by
`tests/support/certificate_sign_refusal_262.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` (bundled with bun) under Node v22.18.0: #251's `email`
certificate signed twice, the second refused in the reference's words byte
for byte (`Ok(())` on the base), the certificate unchanged and verifying;
signed again with another key, the signature refusal ahead of the key check
(the base's `CryptoError` for the key); cleared with `set_signature(None)`,
it signs to a single signing's bytes, the reference's after
`signature = undefined`; an empty signature signs.
### Fixed: the three certificate types' JSON is the reference's: `type`, the signature hex, the keyrings base64 strings (#268)

`Certificate`, `MasterCertificate` and `VerifiableCertificate` wrote a JSON the
reference does not read and read none it writes. The reference's at
`ts-stack@edf6e03` (`packages/sdk/src/auth/certificates/Certificate.ts:150-212`,
`MasterCertificate.ts:164-237`, `VerifiableCertificate.ts:80-118`; the JSON
being `JSON.stringify` of the instance and `Certificate.fromObject`,
`Certificate.ts:505-525`, or the subclasses' constructors, as `Peer`'s
`#restoreOwnedCertificates` reads a peer's, `Peer.ts:341-357`) and Go's at
`2ca481c` (`auth/certificates/certificate.go:32-52`, `master.go:28-35`,
`verifiable.go:16-29`) agree on every key and encoding. The moves, old and new:

| Key | Before | Now |
|---|---|---|
| the type | `certType` (base64) | `type` (base64), `Certificate.ts:150-153`, `certificate.go:34` |
| `signature` | an array of numbers (the DER bytes) | the DER bytes in hex, `Certificate.ts:184`, `certificate.go:52` (`util.ByteString`) |
| `revocationOutpoint` when `None` | no key | the binary form's sentinel, `"<64 zeros>.0"`: the reference's is always a string (`Certificate.ts:174`) and its `toBinary` refuses another type (`:257-258`); read back from the sentinel, `null` (Go's nil) or no key as `None`; the txid alone, the reference's default issuance's form (`MasterCertificate.ts:442`), read as index 0 as the reference reads it (`:112-123`, `Certificate.ts:261-262`) and written back with its index |
| `masterKeyring` | an array of numbers per field | the base64 string, `MasterCertificate.ts:173`, `master.go:34` |
| `keyring` | an array of numbers per field | the base64 string, `VerifiableCertificate.ts:90`, `verifiable.go:23` |
| `to_json_value()`'s `signature` | base64 | hex; the absent outpoint the sentinel, where it wrote `null`; the method is now the type's serde |

`MasterCertificate` and `VerifiableCertificate` flatten `Certificate`, so the
auth messages' `certificates` (`AuthMessage.certificates`, a
certificateResponse's JSON on every transport) carry the same keys; before,
a reference peer's certificateResponse did not deserialize here. The identity
client's publish (`publicly_reveal_attributes`) writes `type` by hand
(`src/identity/client.rs:452`) and does not move. The HTTP JSON substrate's
`WalletCertificate` writes `type` since #105 (PR #271, beta `645ff4b`), as the
reference does (`Wallet.interfaces.ts:851-852`).

The keyrings' type (the owner's word of 2026-10-26 on #261: base64 strings
held, decoded only where the wallet decrypts): `MasterCertificate.master_keyring`
and `VerifiableCertificate.keyring` move from `HashMap<String, Vec<u8>>` of
wallet ciphertext to `HashMap<String, String>` of its base64 text, as the
reference's `Record<CertificateFieldNameUnder50Bytes, Base64String>` and Go's
`map[..]wallet.StringBase64` hold them. `MasterCertificate::new`,
`VerifiableCertificate::new`, `create_certificate_fields` (its second map) and
`create_keyring_for_verifier` (its master keyring and its result) take and
return the text, as the reference's `toBase64` writes it (`MasterCertificate.ts:292-298`,
`:405`); `from_base64` runs at the wallet's `decrypt` in `decrypt_field(s)` of
both types and nowhere earlier. `IdentityCertificate.publicly_revealed_keyring`
moves the same way (the reference's `Record<..., Base64String>`,
`Wallet.interfaces.ts:879`). The holders: `get_verifiable_certificates` holds
the wallet's `keyringForVerifier` strings as given
(`getVerifiableCertificates.ts:92-104`), where it dropped an entry that did not
decode; the identity client's two parsers hold the published keyring's
strings, where one refused the whole output on an entry that did not decode
and the other dropped the entry. No setter is added: the fields are public
and the constructors take the map. Migration for a Rust caller:

```text
keyring.insert(name, ciphertext_bytes);
keyring.insert(name, to_base64(&ciphertext_bytes));

let bytes: &Vec<u8> = &verifiable.keyring[name];
let bytes: Vec<u8> = from_base64(&verifiable.keyring[name])?;  // at its decrypt site
```

A persisted JSON of the old shape is refused by the new reader (`missing
field type`, or the signature `expected a string`), never misread. The
reference's reader ignores a key it does not know (`fromObject` picks its
seven keys), so an old JSON read there is a certificate with no type, refused
at its `toBinary`; this crate's reader ignores an unknown key too and asks for
`type`, so no alias of `certType` is kept: a stored old JSON is migrated once,
by reading it as `serde_json::Value` and renaming `certType` to `type`,
writing `signature` as `to_hex(&bytes)` and each keyring entry as
`to_base64(&bytes)`.

`cargo semver-checks check-release --baseline-rev origin/lane/fix-261-field-value-bytes
--features full --release-type minor`: no lint for the two keyrings' type, the
`IdentityCertificate` field's type, or the serde shapes; semver-checks 0.51.0
has none for a field's type or a serialization. 0.9.0 is the minor that takes
the break.

Pinned by `tests/auth_certificate_json_268.rs` on the witnesses
`tests/vectors/certificate_json_268.json`, recorded by
`tests/support/certificate_json_268.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` (bundled with bun) under Node v22.18.0, its randomness a
SHA-256 counter stream: the reference's `JSON.stringify` of the three types
for a certificate it issued with three fields and with one, each read here
and written back equal by value, and byte for byte where every map has one
key, verified, written to the reference's `toBinary(true)` and decrypted to
its plaintexts under the master and verifier keyrings; this crate's JSON of
the three types for a certificate it issued, read by the reference
(`verify()` true on the three, its `toBinary(true)` this crate's bytes, the
plaintexts decrypted under both keyrings, its `JSON.stringify` of what it read
this crate's text byte for byte); a fresh issuance's keys and encodings; an
absent outpoint read from the sentinel, `null` and no key. A third
reference-issued certificate takes the reference's default outpoint, the txid
alone (`verify()` true there): read here as index 0 as a certificate, inside
an `AuthMessage` (a certificateResponse) and from a wallet's listCertificates
result by `get_verifiable_certificates`, and by the identity client's two
parsers (`src/identity/client_field_value_261_tests.rs`), each red on
the tip before the fold (6 of 6: `Invalid outpoint format: expected
'txid.vout'` at the certificate and the message, the whole output refused by
one parser, the outpoint dropped and the signature failed at the other and at
`get_verifiable_certificates`); the four sites read it through one helper. Red on the base
(4 of 4: the hex signature refused, `expected a sequence`; the absent outpoint
`null`; the keys `certType` and no `revocationOutpoint`); the reference refuses
the base's JSON (`Master certificate keyring.city must be an own string data
property`). The #261 test read the reference's JSON through a helper that
renamed `type` and decoded the signature; it passes the JSON as given, its
vector unchanged.

A certificateResponse now crosses in both directions, where #280's entry
(above) said it did not until this change. A reference certificateResponse
parses here, its signature verifies over the `certificates` text the reference
signed and its certificate verifies
(`a_reference_certificate_response_parses_and_verifies_since_268`, the
renamed `..._is_refused_by_its_certificate_shape_until_268`). The reference
`Peer` verifies this crate's certificateResponse over the bytes sent, its
signature valid (before, it rebuilt the certificate without `certType` and
refused it). `tests/vectors/auth_signed_text_280.json` is re-recorded with
the verify session holding this crate's certificateRequest policy as a request
the reference sent (`reference_pending_request`, `Peer.ts:474-477`), so the
verdict is the whole path's. The certificate matches the policy
(`:1234-1241`) and its own signature verifies (`validateCertificates`); the
reference then stops at `decryptFields` (`Failed to decrypt selectively
revealed certificate fields using keyring: Decryption failed!`), because the
test's keyring holds placeholder bytes, not field keys encrypted to the
verifier. Outside the two entries of `this_crate_messages` the vector is
byte for byte the same. Red on the base (2 of the 8 run: the reference's
certificates refused at the parse, `expected a sequence`).

### Notes: cross-SDK parity (#268)

`VerifiableCertificate`'s cached plaintexts are not in its JSON in either
direction: the reference writes `decryptedFields` when its constructor was
given them and its `#restoreOwnedCertificates` passes a peer's through
(`Peer.ts:354`; Go writes `decryptedFields,omitempty`, `verifiable.go:28`);
here a peer's `decryptedFields` is ignored, since a cache read from the wire
would answer `decrypt_fields` with the sender's plaintexts. An absent
`revocationOutpoint` (Go's `null` for nil, `certificate.go:46`) reads as
`None` here; the reference keeps it and refuses it at `toBinary`
(`Certificate.ts:257-258`). A `revocationOutpoint` of the txid alone with no
index is written by TypeScript alone (its default issuance,
`MasterCertificate.ts:442`) and read there as index 0; go-sdk refuses it
(`go-sdk@2ca481c` `transaction/outpoint.go:50`); this crate reads it as the
reference does and writes `<txid>.<index>` always.

### Added: what `auth_certificate.json` vector 0 is, and the test that says so (#252)

Vector 0 of `tests/vectors/auth_certificate.json` (added by 91dacc5,
2026-01-26, which names no SDK or commit) is `@bsv/sdk`'s `fromObject`
parse fixture (`Certificate.test.ts`, added at ts-sdk@27a93752, 2025-11-19,
package 1.9.10, `:336-362`; the same object at `ts-stack@edf6e03`
`packages/sdk/src/auth/certificates/__tests/Certificate.test.ts:311-339`),
copied with two values changed: the type `Q29tbW9uU291cmNlIGlkZW50aXR5`
(`CommonSource identity`, 21 bytes, which this crate's `[u8; 32]` cannot
hold) replaced by 32 x 0x01, and the serial's 37th base64 character changed
from `h` to `+`; the subject, certifier, outpoint, five fields and signature
are the fixture's. Vector 1 is the fixture's unsigned sibling (`:364`), its
type and serial replaced. The reference's test parses the object and never
verifies it; Go carries none of its bytes. The signature is the certifier's
BRC-52 signature (the derived key, keyID `"<type> <serial>"`, counterparty
anyone, each field value the UTF-8 bytes of its base64 text) over the
fixture's ORIGINAL type and serial: `@bsv/sdk` at 27a93752 verifies the
original `true` and any of the three other combinations of the two values
not (`Signature is not valid`); the raw key verifies none. At `ts-stack@edf6e03`
`toBinary` refuses a type that is not 32 bytes (`Certificate.ts:233`, since
`b3155fa2e`, 2026-09-22), so the reference at the pin verifies the original
`false` too, as #251 measured. Over vector 0's own bytes the signature
verifies under no reading, in this crate or in either reference. No
reference regenerates the certificate (no private key is published), so no
regenerated vector is added; the vector stays as it is (rule 3).

`tests/auth_cross_sdk_tests.rs` now asserts both:
`vector_0_signature_verifies_under_no_known_reading` (`verify()` is
`Ok(false)`, the certifier's raw key `false`), and
`vector_0_signature_is_the_reference_fixture_signed_over_its_original_type_and_serial`
(the fixture's other values equal vector 0's, and the signature verifies
under the derived key over this crate's writer's bytes of vector 0 with the
leading 64 bytes replaced by the original type and serial, and under none of
the other three combinations). The original and the verdicts are in
`tests/vectors/auth_certificate_origin_252.json` (new), recorded by
`tests/support/certificate_origin_252.mjs` under Node v22.18.0 against both
references bundled with bun. No `src/` change.
### Changed: a wallet wire u32 field above `u32::MAX` is refused in the reference's words (#255)

The nine `u32` fields #122 bounded were refused in #122's words (`invalid
totalCertificates: expected at most 4294967295, got 4294967296`). The
reference at `ts-stack@edf6e03` reads each with `readVarIntNumStrict(false)`
and bounds it with `#requireInteger(value, '<fieldName>', 0, 0xffffffff)`,
whose words are `Invalid <fieldName>: expected an integer from <minimum> to
<maximum>, received <value>`
(`packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:2018-2025`,
the processor's at `WalletWireProcessor.ts:138-148`). Each refusal now
carries those words with the reference's name for the site, through one
helper (`integer_refusal` in `src/wallet/wire/mod.rs`, which the discovery
trust and getHeaderForHeight's height now share):

| Field | The reference's site and name |
|---|---|
| listActions `totalActions` | `WalletWireTransceiver.ts:380-385`, `listActions totalActions` |
| an action's `version` | `:437-442`, `listActions version` |
| an action's `lockTime` | `:443-448`, `listActions lockTime` |
| an action input's `sequenceNumber` | `:491-496`, `listActions input sequenceNumber` |
| listOutputs `totalOutputs` | `:651-656`, `listOutputs totalOutputs` |
| listCertificates `totalCertificates` | `:1501-1506`, `listCertificates totalCertificates` |
| discovery `totalCertificates` | `:1676-1681`, `discovery totalCertificates` |
| getHeaderForHeight `height` | `WalletWireProcessor.ts:1671-1675`, `getHeaderForHeight height` (1 to `u32::MAX`; the words since #216) |
| signAction spend `sequenceNumber` | none: `signAction spend sequenceNumber` (below) |

Two index readers outside the nine share the helper and take the words: an
outpoint's index (`outpoint index`, the reference's at `:733-738` and
`WalletWireProcessor.ts:226-231`) and an action output's (`listActions output
outputIndex`, `:517-522`, until now `action output index`). The bound and the
order of checks do not move: no behavior beyond the words. Pinned by the
nine tests of `tests/wire_u32_field_bounds_tests.rs` (eight RED on the
pre-fix tree, the height's words unchanged), by
`a_sign_action_spend_sequence_number_above_the_bound_is_refused_naming_it`
and by the four index tests of `tests/wire_method_roundtrip_tests.rs`. No
recording carried these words; none is re-recorded.

### Notes: cross-SDK parity (#255)

The reference's processor reads a signAction spend's `sequenceNumber`, a
signAction spend's input index and an internalizeAction output's index
with `readVarIntNumStrict` and no `#requireInteger`
(`WalletWireProcessor.ts:662`, `:671`, `:1082`); it bounds the two spend
fields after the read in `validateSignActionArgs` (`spends key`,
`spends.<index>.sequenceNumber`, 0 to `MAX_UINT32`, `validationHelpers.ts:840-856`)
as `WERR_INVALID_PARAMETER`, and the output index at zero or above only
(`validatePositiveIntegerOrZero(args.outputIndex, 'outputIndex')`, `:979`). This crate's processor refuses both calls as
needing a full wallet, so these are public readers with no reference
counterpart: they refuse at the read in `#requireInteger`'s words, named
`signAction spend sequenceNumber`, `sign action spend input index` and
`internalize output index`. A value above `2^53 - 1` is refused there by
`readVarIntNumStrict` ahead of `#requireInteger`; the `u32` readers here
read the whole varint and refuse it in `#requireInteger`'s words, as they
refused it in #122's.
### Fixed: `read_identity_certificate` refuses a trust outside 1 to 10 in the reference's words (#247)

`WireReader::read_identity_certifier`, which `read_identity_certificate` and
`read_optional_identity_certifier` read a discovery entry's certifier info
through, read the trust byte unchecked (#184's reading), so Go's zero value
for an absent certifier info read back as `Some` with empty strings and trust
0. The reference's discovery reader bounds the byte,
`this.#requireInteger(resultReader.readUInt8(), 'discovery trust', 1, 10)`
(`ts-stack@edf6e03` `packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1710`,
`#requireInteger` at `:2018-2025`), its result validation the same range
(`WalletResultValidation.ts:1900`, `rangedInteger(info.trust, call, ..., 1, 10)`),
the field's type `PositiveIntegerMax10` (`Wallet.interfaces.ts:874`), and this
crate's transceiver has refused it since #183. The reader now takes the byte
through the transceiver's check (`require_discovery_trust`), in its words,
`Invalid discovery trust: expected an integer from 1 to 10, received <n>`, and
the transceiver's discovery reader reads its certifier info through
`read_identity_certifier`: one reading. The writer has refused such a trust
before a byte since #183.

The tests that pin it: `the_zero_value_entry_is_refused_as_the_transceiver_refuses_it`
(`tests/wire_identity_certificate_roundtrip.rs`; on the pre-fix tree the
reader read Go's zero value `Ok` with trust 0) and the certifier reader's
trust 0 and 11 in `the_certifier_reader_reads_three_plain_strings_and_the_trust_byte`;
`an_identity_certificate_with_a_trust_outside_1_to_10_is_refused_as_discovery_refuses_it`
(`tests/wire_reader_strictness.rs`: 0, 11 and `0xff` refused by the reader and
the transceiver in the same words, 1 and 10 read; on the pre-fix tree the
reader read 0 `Ok`). `a_count_that_overruns_the_bytes_is_refused_without_a_panic`
builds its entry at trust 1, so it still reaches the maps. No recorded
certificate moved (every one carries a trust in 1 to 10); no public shape
moves, no new `Error` variant.

### Notes: cross-SDK parity (#247)

go-sdk writes the trust byte as given (`go-sdk@2ca481c`
`wallet/serializer/identity_certificate.go:26`, `w.WriteByteValue(cert.CertifierInfo.Trust)`)
and reads any byte (`:66`, `cert.CertifierInfo.Trust = r.ReadByteValue()`), so
the entry it writes for an absent certifier info (its zero value, trust 0) is
refused by this crate's readers as by the reference's; the divergence is the
#183 line of `CLAUDE.md`'s list, now naming both readers.
### Changed: a duplicate at an even offset is read as the reference reads it (#167)

A BUMP leaf flagged duplicate (`01`) at an even offset was refused on every
path since 0.9.0-beta.1: the decoder's `BadFlag { byte: 1 }` at the flag
(the stream, the whole BEEF, a BUMP read alone), `merkle_path_root`'s
pre-pass over a BUMP held in memory (`Kind::BadFlag`), and `MerklePath::new`
and `new_unchecked` ahead of their walk (`Duplicate at an even offset: N, at
height: N`). The reference reads it. `@bsv/sdk` at `ts-stack@edf6e03`
(`packages/sdk/src/transaction/MerklePath.ts`) pairs the working hash with
itself wherever the duplicate is its sibling, at either offset
(`nextCachedHash`, `:60`: `if (leaf.duplicate === true) return
hashPair(workingHash, workingHash)`), and refuses a path only where its own
walk gives up: a node it must compute whose left child is a duplicate has
no hash (`cachedFindLeaf`, `:628-631`; `findOrComputeLeaf`, `:437`), and
`nextCachedHash` throws `Missing hash for index N at height N` (`:58`).

The owner's word of 2026-10-26, on this refusal as a candidate for
upstream filing: "hm... this is worrisome... understand that people like to
switch between the SDKs at will (they are all becoming more conformant by
the day)". The keeper's reading on it (#167, 2026-10-26): a BUMP the
reference computes a root for computes the same root here, so a user moving
between the SDKs sees one verdict; the computed root against the header
decides; a repeated offset within a level stays a refusal (`DuplicateOffset`,
the reference's `Duplicate offset`, `:217-222`); BRC-74's question (the
duplicate flag's side, `5119a9b` `transactions/0074.md:75-77`) goes to
`bsv-blockchain/BRCs`, and the strict reading returns only if its
maintainers say the flag is forbidden there.

Now, on the one decoder and walk (#86): the decoder reads flag `01` at any
offset (`BadFlag` stays for a flag other than `00`, `01`, `02`); the walk
(`beef_stream`'s `bump_root`) pairs a path node with itself where its
sibling is a duplicate, as it always did at an odd offset, and refuses a
computed sibling that rests on a duplicate at an even offset, as its left
child or under a child computed in turn, with a reason of its own,
`Reason::LeftDuplicateBelow { level, offset }` (the node the path needs, at
the offset varint of the level-0 leaf whose path needs it) and
`Kind::LeftDuplicateBelow`: the reference throws a string, this crate names
the node. `merkle_path_root`'s pre-pass for the flag goes (its
`DuplicateOffset` pre-pass stays); `MerklePath::even_offset_duplicate`
(crate-private) goes, and `new` and `new_unchecked` read the path with
their walk (`RootWalker`, the reference's `computeRootCached`), which
already gave up where the reference gives up (`Missing hash at height N,
offset N`, unchanged). The one reader's three paths and the two
constructors give the reference's root or a refusal on every shape below.

**Public shape:** `Kind` gains `LeftDuplicateBelow` (the twenty-sixth, after
`DuplicateOffset` in `Kind::ALL`, now `[Kind; 26]`) and `Reason` gains
`LeftDuplicateBelow { level: u8, offset: u64 }`; both enums are
`#[non_exhaustive]` since 0.9.0, so the variant is additive. `Kind::ALL`'s
array length is a type: code that names `[Kind; 25]` reads `[Kind; 26]`.
No downstream names either (a grep of bsv-overlay-cloudflare,
rust-message-box, bsv-wallet-toolbox-rs, bsv-middleware-cloudflare-public
and rust-chaintracks, 2026-10-26; the two `BadFlag` matches in
bsv-overlay-cloudflare, `submit_census.rs:1149` and
`overlay-engine/tests/script_door_fold.rs:1163`, are a flag of unknown
bits, unchanged). The Lean's `Reason` (`BeefOfAnySize.lean`) takes the
constructor in the stack's lane, with the flipped row: the keeper's.

Pinned by `tests/merkle_path_even_offset_duplicate.rs` on the vectors
`tests/vectors/merkle_path_even_offset_duplicate_167.json`, written by
`tests/support/even_offset_duplicate_167.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` (bundled with bun) under Node v22.18.0: nine shapes, each
the bytes the reference writes and this crate's writer writes, read by the
reference's `fromHex` with its defaults and with `legalOffsetsOnly` false.
The reference accepts four, and every reader here gives its root from every
hash of level 0, with the header carrying that root deciding
(`verify_stream_structure`): the txid at offset 1 with the duplicate at 0
(level 0), the duplicate at level 1 offset 0 and at level 2 offset 0 beside
a txid's path, and two txids whose second path finds the node over the
duplicate carried. It refuses five, and so does every reader here: a node
computed from the duplicate as a left child (`Missing hash for index 2 at
height 1`; `LeftDuplicateBelow { level: 1, offset: 0 }`), the #167 seed's
shape (`index 8 at height 3`; `level: 3`), a right child computed from it
(`index 4 at height 2`; `level: 2`), the node over the duplicate carried
wrong (`Mismatched roots`; `MismatchedNode { level: 1, offset: 0 }`), and a
duplicate at a path node's own offset (`Invalid offset: 0, at height: 1`;
`MismatchedNode`, below). `an_even_offset_duplicate_reads_as_the_reference_reads_it`
was red on the base (`level-0-duplicate-left-of-the-txid: new refuses merkle
path error: Duplicate at an even offset: 0, at height: 0`: the in-memory
constructor, which the test asks ahead of the readers, refused the shape).

The refusals that moved, by test:

- `tests/merkle_path_two_readers_agree.rs`:
  `an_even_offset_duplicate_is_refused_by_both_readers_at_its_flag` is now
  `an_even_offset_duplicate_is_read_by_both_readers_as_the_reference_reads_it`:
  the level-0 shape (the txid at 1, the duplicate at 0) is accepted by both
  readers with the root `sha256d(h1 || h1)`; the level-2 shape (the seed) is
  refused by both `LeftDuplicateBelow { level: 3, offset: 0 }` at the txid
  at 8's offset varint (byte 71), where it was `BadFlag { byte: 1 }` at the
  flag (byte 210). `an_even_offset_duplicate_held_in_memory_is_refused` is
  now `an_even_offset_duplicate_held_in_memory_is_read_as_the_reference_reads_it`:
  `new` and `new_unchecked` refuse it `Missing hash at height 2, offset 0`
  (their walk, where it was the pre-pass's `Duplicate at an even offset: 0,
  at height: 2`), `verify_structure` `Kind::LeftDuplicateBelow` (it was
  `Kind::BadFlag`), `compute_root` unchanged.
- `tests/beef_stream.rs`: `the_twenty_five_kinds_are_twenty_five_and_distinct`
  is `the_twenty_six_kinds_are_twenty_six_and_distinct`.
- `merkle_path.rs`'s in-memory differentials: the 0.3.34 model no longer
  carries the even-offset refusal (its left-duplicate give-up stays, the
  reference's).

The 468 inputs of the 0.9.0 note: every input of the BUMP differential the
base refused `BadFlag { byte: 1 }` (741, with the corpus) was read by this
tree's `MerklePath::from_reader` and by the reference's `fromBinary` with
its defaults (a prefix reader both). All 741 have one verdict: the 468 are
`LeftDuplicateBelow` here and `Missing hash for index N at height N` there;
2 are accepted by both with the same root (`fixtures/beef/v2.json#2 byte
665 ^ 0x01` and `fixtures/merkle_path/paths.json#3 byte 417 ^ 0x01`, a
sibling's flag `00` turned `01` at an even offset); the other 271 are
refused by both for other reasons (a carried node its children contradict,
an offset outside its level, a cut). The lists and both readers' verdicts
are kept under `/Volumes/Lanes/out/bsv-rs/fix-167-even-offset-duplicate/`.
The differential's count moves by those 2: 54,763 inputs, 18,129 accepted by
the BEEF reader on the base and 18,131 now, 0 disagreements on both; the
BEEF differential (`tests/beef_two_readers_agree.rs`) reads 68,675 inputs,
0 disagreements (68,222 before: the committed seed adds 453, the seed itself,
114 cuts, 337 single-byte changes and one appended byte). `tests/conformance_beef.rs` with the corpus:
every total unchanged (merklepath 16 total, 12 run, 11 passed, 4
unsupported, 1 known failure; serialization 15, 12, 12, 3; regressions 16,
15, 15, 1 skipped; atomic-beef 8, 8, 8): no corpus vector carries the
shape. `fuzz_beef_parser`'s corpus gains `door-LeftDuplicateBelow-hand`
(corpus-gen's written door, the level-1 refusal as a BEEF of one BUMP; no
byte mutation of a Lean row reaches the kind): 65 seeds, all 26 kinds
reached.

### Notes: cross-SDK parity (#167, the even-offset duplicate)

One verdict with the reference on every shape above, and with Go on the
pairing: go-sdk@2ca481c pairs a duplicate met as the working hash's sibling
(`transaction/merklepath.go:399-400`) and computes no node from a duplicate
on the left (`:47-50`), so `ComputeRoot` errors for the txid whose walk
needs one (`:396-397`, `we do not have a hash for this index at height`);
its reader checks no root (`NewMerklePathFromReader`, `:197`), so it parses
the refused shapes and errs only when that txid's root is asked. A carried
node at a path node's own offset is refused here (`MismatchedNode`, as a
hash its children contradict is, the stated line of #167); the reference
refuses the one shape in the vectors by its legal-offset rule (`:230-234`)
and with `legalOffsetsOnly` false reads it, its walk never reading the
node at the path's own offset (`MerklePath::new_unchecked` reads it as that
does). Through 0.9.0-beta.1 this crate refused every even-offset duplicate
(the published section's #167 entry); the BRC-74 question is upstream.
### Added: a wallet refusal carries its class, `Error::WalletRefusal` (#137)

Every refusal a wallet returned reached this crate as
`Error::WalletError(String)`: words, no class. The wire processor framed it
as `Wallet operation failed`, code 1 (#202), and a host serving BRC-100 over
HTTP could not tell a bad argument from too few funds, or an unauthorized
call from an internal fault, without matching the words. The reference's
wallet errors carry a code beside their message: the SDK's `WalletError` a
number (`ts-stack@edf6e03` `packages/sdk/src/wallet/WalletError.ts:3-8`, the
table `walletErrors` at `:71-80`), the wallet-toolbox's `WERR_*` classes their
name (`packages/wallet/wallet-toolbox/src/sdk/WalletError.ts:35-37`: `code`
is `name`), four of them a number as well in their JSON "to match
HTTPWalletJSON.ts" (`WERR_errors.ts:110`, `:136`, `:225`, `:278`).

`Error::WalletRefusal { class: WalletRefusalClass, message: String }` (new
variant, `wallet` feature) is that error. `WalletRefusalClass` (new,
`#[non_exhaustive]`, `Copy + Eq + Hash`, re-exported at the crate root) is the
reference's table by name: the SDK's seven coded classes, then every class of
the toolbox's `WERR_errors.ts` the SDK does not already name. `name()` is the
reference's name (the `WERR_*` class name where one exists, else the SDK's
`walletErrors` key), `code_name()` the SDK's key for its seven, `code()` the
reference's number where it assigns one, `wire_code()` the binary frame's
byte (the SDK's 2 to 8), `from_name` (a name or a key) and `from_code` (the
SDK's 2 to 8) the inverses, `ALL` the twenty in this order:

| Class | `name()` | `code()` | `wire_code()` | Reference at `edf6e03` |
|---|---|---:|---:|---|
| `UnsupportedAction` | `unsupportedAction` | 2 | 2 | `sdk/src/wallet/WalletError.ts:73` |
| `InvalidHmac` | `invalidHmac` | 3 | 3 | `:74` |
| `InvalidSignature` | `invalidSignature` | 4 | 4 | `:75` |
| `ReviewActions` | `WERR_REVIEW_ACTIONS` | 5 | 5 | `:76`; `WERR_REVIEW_ACTIONS.ts:8,25`; toolbox `WERR_errors.ts:260,278` |
| `InvalidParameter` | `WERR_INVALID_PARAMETER` | 6 | 6 | `:77`; `WERR_INVALID_PARAMETER.ts:6,15`; `WERR_errors.ts:100,110` |
| `InsufficientFunds` | `WERR_INSUFFICIENT_FUNDS` | 7 | 7 | `:78`; `WERR_INSUFFICIENT_FUNDS.ts:7,20`; `WERR_errors.ts:208,225` |
| `AbortRefused` | `abortRefused` | 8 | 8 | `:79`; `WalletWireProcessor.ts:801-804` |
| `NotImplemented` | `WERR_NOT_IMPLEMENTED` | none | none | `WERR_errors.ts:8` |
| `Internal` | `WERR_INTERNAL` | none | none | `:19` |
| `InvalidOperation` | `WERR_INVALID_OPERATION` | none | none | `:30` |
| `UtxoReviewInconclusive` | `WERR_UTXO_REVIEW_INCONCLUSIVE` | none | none | `:41` |
| `ActionBatchState` | `WERR_ACTION_BATCH_STATE` | none | none | `:68`, exported at `:84` |
| `BroadcastUnavailable` | `WERR_BROADCAST_UNAVAILABLE` | none | none | `:89` |
| `InvalidMerkleRoot` | `WERR_INVALID_MERKLE_ROOT` | 8 | none | `:121`, the code at `:136` |
| `MissingParameter` | `WERR_MISSING_PARAMETER` | none | none | `:150` |
| `BadRequest` | `WERR_BAD_REQUEST` | none | none | `:165` |
| `NetworkChain` | `WERR_NETWORK_CHAIN` | none | none | `:174` |
| `Unauthorized` | `WERR_UNAUTHORIZED` | none | none | `:183` |
| `NotActive` | `WERR_NOT_ACTIVE` | none | none | `:192` |
| `InvalidPublicKey` | `WERR_INVALID_PUBLIC_KEY` | none | none | `:232` |

The SDK's three `WERR_*` classes (codes 5, 6, 7) and the toolbox's classes of
the same names are one class each. Code 1, `unknownError` (`:72`), is no
class: it is `Error::WalletError`; nor is the toolbox's `WERR_UNKNOWN`
(`WalletError.ts:71-72,108` there, the name `fromUnknown` gives an unclassed error).
BRC-100 (`5119a9b` `wallet/0100.md:289-319`) asks a machine-readable code of
every error and leaves its naming to the implementation; its wire's error
byte is `1-255`, "predefined error types or ... custom error categorization"
(`:1609`). No class is this crate's own. `Display` of the variant is the
message alone; the class is the typed field.

The collision is the reference's: the toolbox gives `WERR_INVALID_MERKLE_ROOT`
the code 8 (`WERR_errors.ts:136`), the SDK's `abortRefused` (`WalletError.ts:79`; filed upstream as
bsv-blockchain/ts-stack#1372).
This crate reads a code 8 by the SDK's table: `from_code(8)` is `AbortRefused`;
on abortAction a code-8 frame stays `aborted: false` (#206), elsewhere it is
the `AbortRefused` class; an HTTP JSON body naming `WERR_INVALID_MERKLE_ROOT`
beside its 8 is that class, the name deciding. The merkle-root class has no
wire code: the binary frame carries the SDK's codes only.

The binary wire. The processor frames a refusal whose class has a wire code
with that code and its words, cut at 4096 bytes as every frame is
(`explicit_wallet_code`; the #202 reading: a coded error keeps its code and
words); a class with none, as an un-coded `WalletError`, as `Wallet operation
failed`, code 1 (`WalletWireProcessor.ts:2406-2418`: the reference's
`#invokeWallet` keeps an error whose `code` is an integer 2 to 8, and a
toolbox `WERR_*`'s `code` is its name). With `tracing` a refusal kept with its
code raises one `warn` event, `call` and `class` (its name), `wallet refusal
framed with its code`; one framed as the constant raises the #212 event with
`class` beside `call` and `error` (its words). The transceiver reads a frame
coded 2 to 8 back as `WalletRefusal` with that class and the frame's words, as
the reference's client throws `new WalletError(errorMessage, errorByte,
stackTrace)` (`WalletWireTransceiver.ts:153`); code 8 on abortAction stays
`aborted: false` (#206); code 1 and a code above 8 stay
`WalletError("wallet error (code N): <words>")`.

The HTTP JSON substrate. `HttpWalletJson` reads an error answer's body as its
class: the body's `name`, else its `code` (an SDK code 2 to 8, or a class's
name as a string), names the class, the words its `message`, else its
`description`, else the name. It reads the SDK's `unknownToJson`
(`WalletError.ts:29-67`: `isError`, `name`, `message`, `code` 5, 6, 7), the
toolbox's `toJson` (`WalletError.ts:143-151` there, with the four codes of
`WERR_errors.ts`) and its `asStatus` (`:126-132`: `code` the name,
`description`). A numeric `code` no class names, with a `description`, stays
`WalletError("wallet error (code N): <description>")`; the busy codes (#73)
and a 429 are read ahead of it, as before; a 502, 503 or 504 whose body names
a class is that refusal, the wallet's word, where it was `WalletTransport`
(#87). `HttpWalletJson` is a client and
serves no error body, so there is no writer to change.

### Notes: cross-SDK parity (#137)

The reference's `HTTPWalletJSON` builds a typed error from a 400 body alone,
for codes 5, 6, 7 alone (each with its fields checked: the review results,
the `parameter`, the satoshis), and refuses a body whose `code` is not an
integer as `Invalid wallet error envelope` (`HTTPWalletJSON.ts:199-267`,
`:329-335`): a toolbox `toJson` body for any class but its four coded ones,
and every `asStatus` body, is refused there. This crate reads the class of
every body by its name at any error status and checks no extra field. On the
binary wire the reference's processor frames a toolbox `WERR_INSUFFICIENT_FUNDS`
(or `_INVALID_PARAMETER`, `_REVIEW_ACTIONS`) as code 1, its `code` being its
name, and the SDK's class of the same name with its code; here they are one
class, framed with the SDK's code. go-sdk at `2ca481c` writes no error frame
from its processor (#202's note) and has no class table.

Migration: `Error` is `#[non_exhaustive]`, so no downstream `match` on it is
exhaustive and nothing breaks; a consumer that matched the transceiver's
`"wallet error (code N): "` text for N from 2 to 8, or `HttpWalletJson`'s for
N from 2 to 8, matches the variant instead (none of the downstreams in
`docs/DEPENDENTS.md` does). Consumer note: `bsv-wallet-toolbox-rs`'s
`From<Error>` maps each of its error variants to one class by name (its
`Error::InsufficientFunds` to `WERR_INSUFFICIENT_FUNDS`, for one), and
`bsv-wallet-cli`'s host maps each class to its HTTP status and deletes its
message-prefix matching (`toolbox_words.rs`, named on #137); both are their
captains' work, told on #137 with the owner's word of 2026-10-26 and its
refinement of the same day.

Pinned by `tests/wire_wallet_refusal_class.rs` (the class table against the
reference's, and against the toolbox's file read as data when the `ts-stack`
tree is present; `Display`, `Clone`, `Eq`; each class's frame byte for byte
the reference's, coded or `Wallet operation failed`, read back end to end;
codes 1, 9, 255 read as before; the 4096-byte cut),
`tests/wire_tracing_sink.rs` (the two events), and
`tests/wallet_http_json_refusal_class.rs` (`wiremock` bodies in the
reference's three shapes, the collision, the old reading kept), each red on
the pre-fix tree. `tests/wallet_http_json_busy_tests.rs`'s
`every_other_status_keeps_the_wallet_error_mapping` now reads the codes 6
and 7 as their classes. `tests/fixtures/wire/error_frames.json` re-recorded in
its own commit: cases `status_2` to `status_8` read back as the class, their
bytes unchanged.
### Changed: a certificate verifies over the issuer's bytes and signs in the reference's field order; `Certificate` is `#[non_exhaustive]` (#249)

**The break, once (0.9.0's minor).** `auth::Certificate` is
`#[non_exhaustive]` and carries a new public field,
`#[serde(skip)] pub received_unsigned: Option<Vec<u8>>`, so a struct literal
outside this crate stops compiling, here and never again when a field is
added. The four-argument `Certificate::new` is the constructor; three `with_*`
methods chain onto it for the fields a literal set, and `set_revocation_outpoint`,
`set_fields`, `set_signature` change one afterwards (the fields stay public
to read and to write). The migration:

```rust
// before
let cert = Certificate { cert_type, serial_number, subject, certifier,
    revocation_outpoint, fields, signature };
// after
let cert = Certificate::new(cert_type, serial_number, subject, certifier)
    .with_revocation_outpoint(revocation_outpoint)
    .with_fields(fields)
    .with_signature(signature);
```

No dependent builds one by literal: `bsv-wallet-toolbox-rs` (`6317222`) calls
`Certificate::new` and `set_field` and writes `revocation_outpoint` and
`signature` in place (`src/wallet/certificate_issuance.rs:533-562`), which
compiles unchanged;
`bsv-wallet-cli` and the other dependents do not use the type.

**Half (a): the issuer's bytes.** BRC-52 at `5119a9b`
(`peer-to-peer/0052.md:99-103`): the reference's order is "host-dependent
collation, not UTF-8 byte ordering"; "an implementation reconstructing the
preimage MUST reproduce the issuer's field order"; "a binary transport or
adapter SHOULD retain the original unsigned prefix and signature bytes so
verification does not depend on local reordering", binding every accepted
value to the bytes it parsed, a duplicate name never made acceptable by
retaining bytes. `from_binary` keeps the unsigned prefix in
`received_unsigned`, `sign` writes its preimage afresh in the serializer's
order (as the reference's `sign` does, `Certificate.ts:458`, never a kept
prefix in another order) and keeps it there, and `verify`,
`signing_hash` and `to_binary` use those bytes while they parse, whole, to
the certificate's current values: a received certificate verifies over the
bytes its issuer signed whatever order the issuer's fields came in, and
`from_binary` then `to_binary` writes them unchanged. The mutation rule: a
value changed after the bytes were kept, through a setter or a public field,
unbinds them (they authenticate nothing and are not written; the serializer
writes the new values); `set_field`, `set_fields` and
`set_revocation_outpoint` also clear them, `set_signature` keeps them. The
binding check is a parse of the kept bytes and an equality on every value,
so a stale or hand-set `received_unsigned` never stands for values it does
not carry. `from_binary` refuses a repeated field name in the reference's
words, `Duplicate certificate field name: <name>` (`ts-stack@edf6e03`
`Certificate.ts:374`), where the later value won; go-sdk@2ca481c keeps the
later value (`wallet/serializer/certificate.go:115`).

**Half (b): the reference's order.** The reference sorts the names with
`a.localeCompare(b)`, no locale or options (`ts-stack@edf6e03`
`Certificate.ts:282`; `:216-226` says the order is part of the signed
representation; `verify` and `sign` over `toBinary(false)`, `:427`, `:458`).
This crate sorted by bytes, so the six names `Name, a_b, age, a0, éa, f`,
which `localeCompare` orders `a_b, a0, age, éa, f, Name` and bytes order
`Name, a0, a_b, age, f, éa`, signed here to a certificate the reference
refused. The serializer, used to sign and for a certificate with no kept
bytes (built, or rebuilt from JSON), now orders by the Unicode Collation
Algorithm at tertiary strength, punctuation non-ignorable, over the DUCET
rows (13.0.0) of U+0000..U+00FF and the two contractions in that range
(`l` and `L` before U+00B7), with no new dependency
(`src/auth/certificates/collation.rs`). The table is data, not code:
`src/auth/certificates/collation_latin1.txt`, one line per code point and
the two contraction lines, written by
`tests/support/certificate_collation_table_249.mjs` from the DUCET 13.0.0
and parsed at compile time by a `const fn` that fails the build on a line
out of order or malformed, as #89's wordlists are. Go orders by bytes
(`go-sdk@2ca481c` `wallet/serializer/certificate.go:48`, `sort.Strings`) and
re-serializes to verify; a certificate Go signs over names the two orders
disagree on verifies here (its bytes are kept) and not in the reference.

**Parity: signing over a signature.** The reference's `sign` refuses a
certificate that already carries a signature (`ts-stack@edf6e03`
`Certificate.ts:450-453`, `Certificate has already been signed!`); this
crate's `sign` signs over it and replaces it. Not changed here; the behavior
waits on its own issue (#262, above: `sign` now refuses it).

**The residual.** A name with a character above U+00FF sorts after every
Latin-1 name, in code point order, which is ICU's order for none of them in
general (U+0101 sorts before `z` there); a host whose default locale is not
`en` or root sorts otherwise in the reference itself (`sv-SE` puts `ä` after
`z`); names that tie at all three levels (they differ in a weightless control
character only) fall back to their bytes where the reference keeps its key
list's order. Each reaches a certificate signed here or rebuilt from JSON,
never a received binary one.

**The verdicts.** A certificate the reference signed over such names now
verifies here (it was `Ok(false)`); one signed in byte order (by this crate
before this release, or by Go) still verifies here over its bytes, and is
false in the reference, whose `fromBinary(...).verify()` re-sorts (BRC-52
`0052.md:103` says the reference is not the retaining adapter); one this
crate signs now verifies in the reference. Every field name the dependents
carry is lowercase ASCII (the toolbox's seven, the CLI's three), where the
two orders agree. Consumer note: the toolbox verifies through
`Certificate::verify()` at `src/wallet/certificate_issuance.rs:703` on a
certificate it builds from the certifier's JSON, so it is the serializer's
order there, the reference's after this change.

Pinned by `tests/auth_certificate_field_order_249.rs` on
`tests/vectors/auth_certificate_field_order_249.json`, written by
`tests/support/certificate_field_order_249.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` under Node v22.18.0 (ICU 77.1): the reference's
certificate over the six names verifies over the bytes received and
round-trips through `from_binary` and `to_binary` byte for byte (both red on
the base); a certificate signed here is the one the reference verifies
(`rust_signed_mixed_names`, `verify()` true; red on the base); the
reference's certificate rebuilt from JSON verifies and signs again to the
reference's bytes (red); a byte-order certificate (reference `false`)
verifies here, and its signature cleared and signed again is the
reference's bytes (red on the half (b) commit, whose `sign` kept the
received order); a repeated name is refused in the reference's words (red);
a field changed after `from_binary` unbinds the bytes (red); and the
serializer orders a 1,402-name corpus of printable ASCII and Latin-1 names as
`localeCompare` orders it (red). The three Nodes the corpus was checked
under, v22.18.0, v20.19.5 and v24.11.1, are one collation data set, each
ICU 77.1, CLDR 47.0, Unicode 16.0; the table's rows are the DUCET 13.0.0's,
checked against that ICU. The pair check,
`tests/support/certificate_collation_pairs_249.mjs`, compares the table's
sort key with `localeCompare` on every ordered pair of the 256
one-character names, of the corpus's names, and of the 65,536 two-character
names with the one-character ones: 18,808,356 pairs, 0 disagreements under
each of the three (its header records the run).
### Changed: a pull request runs exactly its line's required set; the full matrix on a push and nightly

The owner's word of 2026-10-26, through the keeper: CI must pass and must not
put needless load on GitHub. The keeper's count that day: 215 workflow runs on
the account in 24 hours, 99 of them this crate's CI at 32 jobs each, 79
cancelled by concurrency. The merge queue already gives one CI run per PR, so
the jobs per run were what remained.

On a pull request a job of `ci.yml` now runs if and only if its context is
required on the base line's protection (beta's eleven, main's twelve): the
Test Suite matrix produces its `(ubuntu-latest, stable)` cell alone, `wasm32`
its `combined` consumer alone (the six consumers' features moved from
`include` rows to a step's table, so no row can add a cell), `dependents` with
`Plan pinned dependents` and each `dependent (<id>)` (the jobs it needs to
decide) only into `main`; `main-in-beta`, `beta-born` and `semver` as before.
`docs`, `actionlint`, `msrv`, `features`, `unused dependencies`, the other
five test cells, the other four wasm32 slices, `Benchmark Regression Check`,
`Benchmarks Build` and `scoreboard` no longer run on a pull request: a PR into
`beta` runs 11 jobs (32 before), into `main` 13 plus one per consumer the plan
admits. A push to `beta` or `main`, the sync's dispatch and a tag's call run
every job as before; `nightly.yml`'s new `ci-full` job dispatches `ci.yml` on
`beta` and on `main` each night, so each line's own workflow runs its whole
matrix at its tip whether or not anything was pushed (a `workflow_call` from
the nightly would run the caller's ref, `main`'s on a schedule, and share its
concurrency group; a schedule on `ci.yml` fires on `main` alone).
`cancel-in-progress` is unchanged. The benchmarks job's baseline record moves
from a `[bench-baseline-record]` marker in a PR's description to a dispatch
input: `gh workflow run ci.yml --ref <branch> -f bench_baseline_record=true`.

`tests/arch_ci_pr_runs_the_required_set.rs` pins it: the two lines' required
contexts as constants (read by `gh api
repos/Calhooon/bsv-rs/branches/<line>/protection/required_status_checks`), a
string-level reader of each job's `if:`, `needs:` and matrix, and the rule
both ways on each line (every required context proven to run on a PR into
it, no job outside the set and its needs able to run there), plus every job
on a push and on the nightly's dispatch save five named exceptions. A context
added to or dropped from a protection is a change to the test's constants.
### Fixed: the HTTP JSON substrate's certificate `type` and flat key-linkage results, as BRC-100 and the reference have them (#105)
### Fixed: the HTTP JSON substrate's shapes are BRC-100's and the reference's: the certificate `type`, the flat key-linkage results and certificate entries, the action calls' encodings, `protocolID` and `keyID` (#105)

`HttpWalletJson` sent and read the certificate's type field as
`certificateType`: `WalletCertificate`, `AcquireCertificateArgs` and
`RelinquishCertificateArgs` carried `certificate_type` under
`rename_all = "camelCase"` with no rename, so acquireCertificate's and
relinquishCertificate's requests, the certificate inside proveCertificate's,
and every certificate a result carries (acquireCertificate, listCertificates,
proveCertificate, both discovery calls) named it so. BRC-100 at `5119a9b`
names it `type` (`wallet/0100.md:1247`, `:1265`, `:1300`, `:1332`, `:1365`,
`:1394`, `:1437`), as the reference's interfaces do (`ts-stack@edf6e03`
`packages/sdk/src/wallet/Wallet.interfaces.ts:837`, `:852`, `:937`), and its
`HTTPWalletJSON` sends the interface objects as they are
(`substrates/HTTPWalletJSON.ts:303`, `stringifyBRC100`). A TypeScript client
against a server built on these types, or this crate against a TypeScript
wallet, failed on all six certificate calls.

The two key-linkage results were read nested under `linkage` with the
linkage and its proof as hex strings, and revealSpecificKeyLinkage's with the
protocol as an object (`{"securityLevel": "1", "protocolName": ..}`) and
`keyId`. BRC-100 has them flat, `encryptedLinkage` and
`encryptedLinkageProof` as `Byte[]`, then `revelationTime`, or `protocolID`
(the `[level, name]` pair), `keyID` and `proofType` (`0100.md:1011-1018`,
`:1043-1052`), as the reference does (`Wallet.interfaces.ts:719-744`;
`HTTPWalletJSON.ts:390-440`).

Now, with serde attributes only (no Rust field or type moves):
`#[serde(rename = "type")]` on the three certificate shapes' `certificate_type`
(the Rust name stays); `#[serde(flatten)]` on both results' `linkage`;
`KeyLinkageResult`'s two byte fields in serde's default form, an array of
numbers (`hex_bytes` dropped there); the specific result's `protocol` as
`protocolID` through a private `[level, name]` helper, a level other than 0,
1 or 2 refused, and `key_id` as `keyID`. The binary wire is untouched.

Pinned by `tests/wallet_http_json_shapes_105.rs` on the witnesses
`tests/vectors/wallet_http_json_shapes_105.json` (seven cases: two
acquireCertificate, listCertificates, proveCertificate,
relinquishCertificate, the two linkage calls), recorded by
`tests/support/http_json_shapes_105.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` (bundled with bun) under Node v22.18.0, both directions:
this crate's request bodies equal the reference's for the same args, the
reference's request bodies parse as this crate's args, the reference's result
bodies parse here and write back as they came, and the reference's client
takes this crate's request bodies as its args and reads this crate's result
bodies to the values it reads from its own; on `0906111` (the base) the
request bodies carried `certificateType` and the reference's bodies were
refused (`missing field certificateType`, `missing field linkage`). The Go vectors' json, the
three certificate args, a certificate and the two linkage results, now read
as this crate's types and write back unchanged (they were refused the same
way, three of the five refused in the fuzz census, two left: `tx` and a
public-key `keyringRevealer`, #105's comments), so the fuzz harness's
reshape of a certificate's `type` is gone. The key-linkage results and
their helper live in `src/wallet/types/linkage.rs`, re-exported from
`types` under the same names (the ratchet holds `types.rs` to its length).
Sixteen recordings moved, in JSON only, no wire byte (`docs/FIXTURES.md` F7,
F8, F20).

The rest of #105 (items 3 to 8 and the `keyringRevealer` comment, the owner's
word of 2026-10-26 taking them with items 1 and 2) moves the same way, serde
attributes and the substrate's private request structs only, no public Rust
field or type. Every field, at BRC-100 `5119a9b` `wallet/0100.md` and
`ts-stack@edf6e03` `Wallet.interfaces.ts` (`HTTPWalletJSON.ts:303` sends the
args as given, `stringifyBRC100`; byte arrays as JSON number arrays):

| Call | Field | Was | Now | BRC-100 | Reference |
|---|---|---|---|---|---|
| listCertificates | `certificates[]` | `{certificate: {..}, keyring, verifier}` | the certificate's seven fields flat beside `keyring` and `verifier` | `:1299-1307` | `:900-903` (`CertificateResult extends WalletCertificate`) |
| discoverByIdentityKey, discoverByAttributes | `certificates[]` | `{certificate: {..}, certifierInfo, ..}` | flat beside `certifierInfo`, `publiclyRevealedKeyring`, `decryptedFields` | `:1393-1411`, `:1436-1454` | `:877-881` |
| acquireCertificate | `keyringRevealer` | `"certifier"` or `{"publicKey": "02.."}` | `"certifier"` or `"02.."` | `:1255` | `:233`, `:845` |
| createAction | `inputBeef` | hex string | `inputBEEF`, number array | `:676` | `:391` |
| createAction | `options.knownTxids`, `options.sendWith` | number arrays of 32 | hex strings | `:699`, `:703` | `:301`, `:305` |
| createAction, signAction | `options.returnTxidOnly` | so named | `returnTXIDOnly` | `:700`, `:750` | `:302`, `:419` |
| signAction | `options.sendWith` | number arrays of 32 | hex strings | `:752` | `:421` |
| createAction, signAction | result `txid` | number array of 32 | hex string | `:709`, `:757` | `:355`, `:439` |
| createAction, signAction | result `tx` | hex string | number array | `:710`, `:758` | `:373`, `:440` |
| createAction | `signableTransaction.tx` | hex string | number array | `:717` | `:350` |
| createAction | `signableTransaction.reference` | hex string | base64 | `:718` | `:351` |
| internalizeAction | `tx` | hex string | number array | `:877` | `:602` |
| getPublicKey, revealSpecificKeyLinkage, encrypt, decrypt, createHmac, verifyHmac, createSignature, verifySignature | `protocolId`, `keyId` | so named | `protocolID` (`[level, name]`), `keyID` | `:981-982`, `:1037-1038`, `:1071-1072`, `:1098-1099`, `:1125-1126`, `:1154-1155`, `:1183-1184`, `:1215-1216` | `:665-667`, `:711-712` |
| createSignature, verifySignature | `hashToDirectlySign`, `hashToDirectlyVerify` | hex string | number array | `:1182`, `:1213` | `:798`, `:813` |
| getPublicKey | `identityKey` | `false` written when not asked | written only when `true` | `:980` (`identityKey?: true`) | `:683` |
| listOutputs | result `beef` | hex string | `BEEF`, number array | `:933` | `:644` |

The getPublicKey row was not in #105's list: the witnesses found it (the
reference sends no `identityKey` for a derived key). Nor was the listOutputs
row: the cold review found it (`ListOutputsResult.beef` under `with =
"hex_bytes_option"`); the reference's client reads `result.BEEF`
(`WalletResultValidation.ts:2082`) and refuses a result for `include:
'entire transactions'` with outputs and no `BEEF` (`:2091-2093`), so a
TypeScript client of a server built on this type failed that call, and this
crate dropped the reference's `BEEF` and the Go vector's
(`listOutputs-simple-result.json`) on intake. A 22nd witness case,
listOutputs-entire-transactions (its `BEEF` the action cases' parent, the
parent's output listed), and the Go vector read and written back pin it; on
`479b193` both are red (`the_bodies_are_the_references`,
`the_go_vectors_action_and_entry_json_read_as_this_crates_types`). Two
recordings moved, in JSON only (`docs/FIXTURES.md` F21). The helpers live in
`src/wallet/types/json_forms.rs` (`hex_txid_option`, `base64_bytes`,
`KeyringRevealer`'s serde); `CreateActionResult`'s fields of this crate's own
(`inputType`, `inputs`, `referenceNumber`, `beef`, not in BRC-100) keep their
forms. The witnesses grow to 21 cases (one per call and shape: a
`keyringRevealer` key, a one-entry list and discovery page, createAction
signable and completed, signAction, internalizeAction, the seven key-related
calls), both directions as above, every one of them equal; the action cases'
transactions are this crate's writer's (a parent proven alone at height
800,000 and its child, unsigned and signed: the reference's internalizeAction
asks a complete atomic BEEF; `the_action_witnesses_are_this_crates_bytes`).
On `29970f5` (this fix's base, the source of the scratch copy) 15 of the 21
are red, the six green ones items 1 and 2's: the reference's action and
`keyringRevealer` bodies refused as this crate's args, the list and
discovery entries refused as its results (`error decoding response body`),
the eight key-related requests and getPublicKey's in the old names and
encodings. The Go vectors' json for internalizeAction, acquireCertificate (a
public-key revealer), the list and discovery results, createAction and
signAction now read and write back unchanged, and the fuzz harness reads
every vector as it is: `reshape` is gone and `--args-census` reads 15 of 15.
Twenty-one more recordings moved, in JSON only, no wire frame
(`docs/FIXTURES.md` F5, F6, F7, F21).

Consumer note: a JSON consumer of these types moves with them, both ways.
bsv-wallet-cli serves the certificate and linkage results from these types
on its JSON wire, and bsv-wallet-toolbox-rs builds `WalletCertificate` and
the linkage results; both move to `type` and the flat byte-array linkage in
the next prerelease (0.9.0-beta.2), their captains to be told the field
names ahead of it (the owner's word, 2026-10-26). A body in the old encoding
is refused here, not read (hex where an array is due, the nested entry and
linkage, the tagged revealer, an object `protocolID`); a renamed optional
field in its old name (`inputBeef`, `returnTxidOnly`, listOutputs' `beef`)
is an unknown key and is dropped silently on intake, not refused, as the
reference drops it. The keeper's reading puts the one-minor acceptance of
both shapes, the renames included, on the CLI's way in. The CLI's fixtures that carry the shapes, as
its captain listed them on #105 (2026-10-26): 025-revealCounterpartyKeyLinkage.ok
and 027-revealSpecificKeyLinkage.ok (items 1 and 2), 044 to 052 (the
acquire, relinquish, prove and list certificate shapes: `type`, and the flat
listCertificates entry of item 3, the CLI's #122 item 8), 053 and 054
(discoverByIdentityKey, discoverByAttributes: empty lists today, so the flat
entry moves them when they carry one). For items 5 to 8 the #76 cold review
found the CLI already recording the reference's shapes (bsv-wallet-cli beta
`d93e077`): there this crate moves to the CLI, and `HttpWalletJson` can now
talk to a TypeScript wallet on the eight key-related calls. The toolbox's
JSON carries two of these: bsv-wallet-toolbox-rs (`6317222`) sends
`bsv_rs::wallet::CreateActionOptions` inside its storage client's
`ValidCreateActionArgs` (`src/storage/client/storage_client.rs:73-103`;
`knownTxids` and `sendWith` now hex, `returnTXIDOnly`) and
`InternalizeActionArgs` whole (`:971`; `tx` now an array) over its JSON-RPC,
the reference storage server's shapes; its own `inputBeef` field is its own
and does not move. The CLI's tracker persists `InternalizeActionArgs` as
JSON (bsv-wallet-cli `a55990c` `src/tracker_host.rs:749`, the `on_accept`
column, written at `:1052`, read at `:1912`): a row written before the CLI
takes this release carries the old hex `tx` and is refused when it is read
back, so the CLI migrates its stored rows or reads them leniently on its
side (its captain told). The CLI serves listOutputs' result from this type
(`src/server/handlers.rs:1168-1179`) and the toolbox's storage builds it
(`src/storage/sqlx/storage_sqlx.rs:2316`), so their JSON's `BEEF` moves
with it.

### Changed: the discovery entry's certifierInfo, keyring and decrypted fields are required, as BRC-100 has them (#105 item 4)

The owner's word on #105 item 4 (2026-10-26, option A). BRC-100 at
`5119a9b` (`wallet/0100.md:1401-1411`), the reference (`ts-stack@edf6e03`
`Wallet.interfaces.ts:870-882`) and Go (`go-sdk@2ca481c`
`wallet/interfaces.go:496-502`) require the discovery entry's
`certifierInfo`, `publiclyRevealedKeyring` and `decryptedFields`, and every
member of the certifier info. This crate's wallet types carried five of them
as `Option` with `skip_serializing_if`, so an entry without one was read and
written back without it. Now:

| Field | Was | Now |
|---|---|---|
| `IdentityCertificate.certifier_info` | `Option<IdentityCertifier>` | `IdentityCertifier` |
| `IdentityCertificate.publicly_revealed_keyring` | `Option<HashMap<String, String>>` | `HashMap<String, String>` |
| `IdentityCertificate.decrypted_fields` | `Option<HashMap<String, String>>` | `HashMap<String, String>` |
| `IdentityCertifier.icon_url` | `Option<String>` | `String` |
| `IdentityCertifier.description` | `Option<String>` | `String` |

A breaking change of 0.9.0 (rule 9), stated here because no tool states
it: `cargo semver-checks` 0.51.0 has no lint for a public field's type and
reports 202 of 202 checks passing against `0906111`. Migration, one line: a caller that built the entry with
`None` fills `certifier_info: IdentityCertifier { name, icon_url,
description, trust }` with the certifier's real values (the reference's
client refuses an empty `iconUrl` or `description`: 1 to 500 and 5 to 50
bytes, `EntityIconURLStringMax500Bytes` and `DescriptionString5to50Bytes`
in `Wallet.interfaces.ts`, probed on the bundle at `edf6e03`; an empty
string is not a value the reference writes for nothing), and
`publicly_revealed_keyring: HashMap::new()`, `decrypted_fields:
HashMap::new()` when it has none; a reader of `Some(x)` reads `x`.

On intake a missing member is a refusal naming it (serde's `missing field
`certifierInfo``, `iconUrl`, `description`, `publiclyRevealedKeyring`,
`decryptedFields`). The binary wire already required them:
`read_identity_certificate` and the transceiver's discovery reader have no
absent case (no present flag, a map a count; an empty map read as `None`
and now as empty), and `write_identity_certificate` refused an absent
certifierInfo (#183); that refusal goes with the `Option`, and the JSON now
has the wire's shape. The identity module's `identity::IdentityCertificate`
had them required already and stays a type of its own: it is the verified
domain type (a parsed `VerifiableCertificate`, the keyring as raw bytes, no
serde), where the wallet's is BRC-100's result shape.

Pinned by `a_discovery_entry_without_a_required_member_is_refused_naming_it`
(`tests/wallet_http_json_shapes_105.rs`): the reference's own recorded
discovery result reads and writes back unchanged, and with each of the five
members removed in turn it is refused here naming the member, as the
reference's client refuses it (the vector's `reference_refuses_without`,
recorded by the Node script). On `ab9e557` all five were read. No recording
under `tests/fixtures` moves: each recorded discovery entry carried every
member.

Consumer note: bsv-wallet-toolbox-rs (`6317222`) builds the entry with
`certifier_info: None` and `None` for an empty map
(`src/wallet/lookup.rs:55-75`, `src/wallet/wallet.rs:2675-2676`) and keeps
`icon_url: Option<String>` in its settings manager
(`src/managers/settings_manager.rs:26`); it fills the certifier info and
sends empty maps (its captain told). bsv-wallet-cli (`a55990c`) serves the
toolbox's `DiscoverCertificatesResult` from its discover handlers
(`src/server/handlers.rs:1266-1290`), every member now written (its captain
told).

### Notes: cross-SDK parity (#105)

What #105 recorded and this fix leaves. Item 4 is the reference's shape now
(the section above). A discovery entry missing a member is refused on intake
here as the reference's `HTTPWalletJSON` refuses it (`validateWalletResult`,
"Invalid discoverByIdentityKey result certificates[0].certifierInfo:
expected an object", recorded); Go's `encoding/json` reads the absent member
as its zero value (`go-sdk@2ca481c` `wallet/interfaces.go:496-502`, no
`omitempty`, no check). `wallet::Certificate` (built by
`auth::Certificate::to_wallet_certificate`, not carried by the JSON
substrate) keeps `certificateType`. `spendable` does not move: the wire
writes `1` for every output listed, where BRC-100 at `5119a9b` permits `0`
for a BRC-207 module inventory record (`0100.md:1963`, `:1974-1980`);
nothing this crate serves is a module inventory, and a field that carries no
verdict here does not move ahead of a consumer that asks (the owner's word,
2026-10-26).
### Changed: a BEEF is valid whatever its order on the wire; the whole path sorts before judging, the stream holds a child by its index entry until its parent is in, under no bound (#240)

0.9.0-beta.1 (bsv-rs#86) judged a BEEF's transactions in the order written:
a child written ahead of the parent it spends was `InputNamesNoElement` at
its input, from the stream, `Beef::verify_structure` and `verify_valid`
alike. 0.8's `verify_valid` sorted ahead of judging and accepted it, and so
does the reference: `@bsv/sdk`'s `Beef.verifyValid` calls `sortTxs` ahead of
its checks (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts:1054-1073`,
`sortTxs` at `:1065`, defined at `:1352-1406`; go-sdk's `verifyValid` sorts
too, `go-sdk@2ca481c` `transaction/beef.go:1240-1243`). The toolbox's pin
lane met it: its children-first BEEFs failed eleven tests here.

The keeper's re-reading of 2026-10-26, on the owner's north star (a user
moving between the SDKs sees one verdict) and the stack's precedent (the
owner's ruling of 2026-10-22: the atomic rule is read on the graph, never on
wire position), replaces the reading of the same morning (state the order
held, PR #243): a BEEF is valid when every input of every transaction names
a transaction of the BEEF or a proven txid, whatever the order. BRC-62 at
`5119a9b` keeps the order on the writer's side (`transactions/0062.md:43`,
the order has streaming validation in mind; `:72-74`, a transaction's inputs
above it; `:172-191`, the validation process); this crate's writer still
writes parents before children. Whether BRC-62's order is normative for
validity goes upstream to `bsv-blockchain/BRCs` (filed as BRCs #359 under the
owner's name, 2026-10-26, with the seven BEEFs and the reference's verdicts at
`9f09472`), so the strict reading can return if its maintainers say so.

- **The whole path** (`verify_structure`, `verify_valid`): the entries are
  judged one by one as before (content, txid-only proof, BUMP index), then
  `sort_txs` decides where the inputs lead as `sortTxs` does: an input that
  names no entry (`missing_inputs`, `with_missing_inputs`) or a transaction
  whose inputs reach no proven entry (`not_valid`: a ring) is
  `InputNamesNoElement`, in any order. The linker (`find_atomic_transaction`,
  `from_beef`) looks entries up by txid and was never order-bound.
- **The stream** (`verify_stream`, `verify_stream_structure`, the
  asynchronous reader, and the whole reader's judge): an unproven
  transaction an input of which names a txid the index does not hold yet is
  held by its index entry, never its raw bytes, until the last such txid is
  folded in; then it is ready, and the reader folds it in, its scripts run,
  in wire order, one per step, ahead of the next element: under
  `step_until` its scripts run under the caller's budget and may pause
  inside it, as any transaction's; a transaction it releases in turn is
  folded in the same way (the asynchronous reader, which has no step budget,
  folds every released one after the element, the mining tip asked once).
  `BeefIndex::fold` still folds what an element releases in the same call.
  At the end a transaction still held is refused, `InputNamesNoElement` at
  the earliest held transaction's earliest input that names nothing, ahead
  of the atomic rule. So the stream and the whole path give one verdict, and
  a refusal after a held child is the later element's (a raw transaction
  with no output written after a held child is `NoOutputs` on both).
- **What a held transaction holds** (`beef_stream/deferred.rs`): its txid,
  offset, wire length and the held set's key (56 bytes); per input the outpoint, the sequence
  and the input's offset (48 bytes); with spends checked, the version and
  the lock time (8), each unlocking script, and the outputs (16 bytes and
  the script each). The outputs stay because a signature whose hash type
  carries the CHRONICLE bit dispatches to the original digest (the default
  mode admits the bit at every version), which hashes every output after the
  scriptCode the parent supplies; SHA-256 keeps no midstate for a suffix, so
  no component computed ahead of the parent stands in for them. That digest
  needs nothing per input beyond the 48 bytes held (the template's slot for
  the input is its outpoint and sequence, the other slots' scripts empty);
  the outputs are per transaction, what the one-pass index retains for it
  once folded anyway (`BeefIndex::retaining` keeps only the outputs an earlier
  pass named, so there the unreferenced outputs of a held transaction are
  held beyond the index). The outputs resolve no parent: they are held for the original digest
  alone. Under a word that refuses the CHRONICLE bit (STRICTENC without
  CHRONICLE, the previous era's) a 32-byte `hashOutputs` and one hash per
  input for SINGLE could stand in for them, and still not for the unlocking
  scripts; the stream runs the default mode, which admits the bit at every
  version, and mainnet is past Chronicle, so the original digest is
  reachable for every deferred transaction and the outputs stay. The
  unlocking scripts are the part beyond the index in every mode; the
  unreferenced outputs are beyond it in `retaining` mode, that mode's
  purpose.
- **No bound** (the stack's charter, `bsv-stack-lean
  docs/charters/beef-of-any-size.md`, the owner's ruling of 2026-10-09: a
  valid BEEF is never refused for its size or its counts; the keeper's stop
  on #240, 2026-10-26): a BEEF in BRC-62's order holds nothing; one written
  children first holds, at most, the entry of every unproven transaction
  read. 0.9.0-beta.1's earlier fold of #240 (never released) had a
  `DeferredLimit` the caller could set and a decline past it
  (`DeferredOverLimit`, an `io::Error`); both are gone. The charter's clause
  (the keeper's ruling of 2026-10-26): the one-element bound holds for a BEEF
  in wire order; for one out of order the state grows by the deferred
  transactions' outputs and unlocking scripts until their parents arrive,
  linear in the out-of-order bytes (1,000,000 links on the scripts reader:
  441 MB parents first, 837 MB newest first, the verdicts equal), never a
  count refusal; past the platform's bound the answer is not judged here,
  resume with the cursor. A platform whose
  memory cannot hold a BEEF stops between steps and resumes from the
  cursor; that is not a verdict. `BeefIndex::deferred()` answers the
  transactions held and the bytes their entries hold.
- **The cursor**: a cursor taken while a transaction is held is `BSC4`, BSC3
  and after the outputs named the held entries by offset (offset, txid, wire
  length, the inputs, then the spends when checked), each count bounded by
  the bytes left, an output value outside MoneyRange refused; one held and
  ready, or a pause inside one released, is carried too (the pause names it
  before the frame). A cursor that holds nothing keeps BSC3's bytes, so every
  cursor of a BEEF in BRC-62's order is unchanged, and a BSC3 cursor of
  0.9.0-beta.1 resumes.

Measured on the chain of `tests/beef_deep_chain.rs` (61-byte links), on a
box shared with other lanes (load 17 to 45). Memory (dhat,
`tests/memory_profiling.rs`'s `test_beef_stream_memory_on_a_reversed_chain`,
`BEEF_REVERSED_DEPTHS=10000,100000`): held per link over the parents-first
peak, 187 and 196 bytes (structure), 212 and 234 (scripts) at 10,000 and
100,000 links; holding the element as read was 321 and 349; the whole
path's live-heap peak equals the parents-first peak (its RSS runs above
it at 1,000,000 links by the arenas the allocator keeps after the entries
are freed, the two numbers printed below). Peak RSS in fresh processes
(release; the reversed builder's own vectors in its baseline), parents
first then newest first, over the bytes alone: the stream's structure 3.8
and 7.9 MB, 28.1 and 58.1 MB, 441 and 728 MB at 10,000, 100,000 and
1,000,000 links; its scripts 4.0 and 8.9 MB, 26.2 and 72.5 MB, 441 and
837 MB; the whole path 27.3 and 29.7 MB, 249 and 266 MB, 2.51 and 2.95 GB.
Time (release, the same processes): the stream's structure 9.4 and 17.4 ms,
92.5 and 184 ms, 3.49 and 3.50 s; its scripts 15.4 and 22.7 ms, 157 and
231 ms, 2.19 and 2.80 s; the whole path 33.3 and 36.6 ms, 360 and 521 ms,
4.88 and 5.64 s. Linear in the links in both orders. `benches/beef_stream.rs`
carries the same chains newest first behind `BSV_BEEF_REVERSED=1`
(`beef_stream_reversed`, outside the gate's inventory).

Pinned by `tests/beef_order_held.rs` (PR #243's pin of the refusal, now the
acceptance's): the children-first BEEF (V1, V2) and a chain of 2, 3, 40 and
1,000 written newest first (and atomic) valid on the three readers; a child
naming a stranger refused at the end by all three, the stream at the
stranger's input; a refusal after a held child the later element's; a
reversed chain of 2,000 judged on both modes of the stream, 1,999 links held
at the peak (`a_reversed_beef_is_judged_whatever_its_size`); a cursor
carrying the held children (BSC4) resuming to the verdict of the whole; a
signed family released newest first (ALL, SINGLE, ANYONECANPAY, NONE, and
ALL|CHRONICLE over the original digest), its verdict, valid and with one
signature broken, parents first's, its BSC4 cursor holding no transaction's
bytes (`a_held_child_is_held_by_its_index_entry_and_its_signatures_verify_on_release`);
every prefix of that cursor refused and every single-byte change refused or
read, never a panic; a chain of 1,000 two-input links newest first folded
one released link per step, the caller's budget asked inside each, 999
pauses resumed through cursors to the same verdict
(`a_released_child_is_folded_one_per_step_under_the_callers_budget`, RED
with the release in one step: the budget asked 0 times); the reference's
verdicts on seven witnesses (`tests/vectors/beef_order_240.json`, recorded
by `tests/support/beef_order_240.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` under Node v22.18.0: the six children-first and
BRC-62-ordered witnesses `true`, the stranger `false`), equal to the three
readers'; the asynchronous reader asking the tracker for the mining tip for
a released child (a child whose finality needs it, released by its proven
parent, was `Unverifiable` with the tip asked only for an unproven element
in hand). RED on 0.9.0-beta.1: the acceptance tests refuse
`InputNamesNoElement` at the newest link's input. Moved:
`tests/beef_deep_chain.rs`'s reversed chain of 100,000 links, refused, is
valid on the three readers on a 1 MiB stack; `tests/beef_two_readers_agree.rs`'s
reversed v1 fixture, refused by both, is accepted by both (the differential
stays at 0 disagreements); `tests/memory_profiling.rs` measures the
reversed chain.

### Changed: `Stop`, `Verdict` and `AsyncVerifyError` are `#[non_exhaustive]` (#240)

As `Kind` and `Reason` already are (#86, #167), on the owner's word on #240
(2026-10-26): 0.9.0 is the minor that takes the breaks, so a later variant
is not one. No variant is added: nothing produces a resource decline once
the stream holds under no bound, and a decline is never an invalidity (the
`ScriptResourceLimit` rule): a platform's irreducible bound is met by
resuming from the cursor, not by a verdict. `cargo semver-checks` (minor,
against beta) reports `enum_marked_non_exhaustive` on the three and nothing
else. Migration: a `match` on one of them outside the crate ends in a
wildcard arm (`_ => ...`). On disk, overlay-engine's `structure_roots`
(`crates/overlay-engine/src/beef_limits.rs:240-255`, on bsv-rs 0.6.0) and
rust-message-box's `refusal_word` (`src/beef_door.rs:543-592`, on bsv-rs
=0.4.5) match `Verdict` exhaustively and take the arm when they move to
0.9.

### Notes: cross-SDK parity (#240)

The order line of the divergence list goes: the three readers accept what
the reference's `verifyValid` accepts on the order. The writer is unchanged
(parents before children, as `#ensureSortedForSerialization` writes,
`Beef.ts:354-358`). `Transaction::from_beef` with no txid still takes the
last entry on the wire, as `Transaction.#fromAnyBeef` does (`Transaction.ts:342-346`
at `edf6e03`; its `Beef.fromReader` does not sort).

### Fixed: `Certificate::sign` and `verify` use BRC-52's derived key, as the reference does (#251)

`Certificate::sign` signed with the certifier's raw key and `verify` checked
against the certifier's raw public key. BRC-52 at `5119a9b` is a MUST
(`peer-to-peer/0052.md:77`: "Implementations MUST verify certificates using
the certifier identity key and the BRC-100 signature derivation described
below"; `:115-117`: protocolID `[2, "certificate signature"]`, keyID `<type>
<serialNumber>` with one U+0020 space, counterparty anyone). The reference at
`ts-stack@edf6e03` derives in both (`packages/sdk/src/auth/certificates/Certificate.ts:428-431`:
`verify` takes the certifier's child under private key 1 and
`2-certificate signature-<type> <serial>`; `:458-462`: `sign` through
`createSignature` with that protocol and keyID, counterparty defaulted to
anyone), and Go agrees (`go-sdk@2ca481c` `auth/certificates/certificate.go:176-186`
for `Verify`, `:227-240` for `Sign`). Now `sign` takes the certifier's child
from `KeyDeriver::derive_private_key` under protocol `[2, "certificate
signature"]`, keyID `Certificate::signature_key_id()` (`"<type base64>
<serial base64>"`, new, additive) and `Counterparty::Anyone`, and `verify`
takes the certifier's public child from `KeyDeriver::new(None)` (the anyone
key) with `Counterparty::Other(certifier)`, over the SHA-256 of
`to_binary(false)` as before. A wrong signature is `Ok(false)` as before.
No public signature moves: `sign` still takes the certifier's `PrivateKey`.

The verdict change: a certificate the reference or Go signed now verifies
here (it was `Ok(false)`), and a certificate this crate signed under the raw
key before this release (0.9.0-beta.1 and every earlier version) verifies
under the old reading only: it is now `Ok(false)` here, as it always was in
the reference and Go. Re-sign such a certificate with this release.
Consumer note: `bsv-wallet-toolbox-rs` calls `Certificate::verify()` at
`src/wallet/certificate_issuance.rs:703` (`6317222`) and discards the
boolean, so a false verdict passes there before and after this change; that
is the toolbox's item (its #188).

Pinned by `tests/auth_certificate_signature_251.rs` on the witnesses
`tests/vectors/auth_certificate_signature_251.json`, recorded by
`tests/support/certificate_signature_251.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` (bundled with bun) under Node v22.18.0: the reference's
one-field `email` certificate verifies (`Ok(false)` on the base), this
crate's signer writes the reference's signature byte for byte (RFC 6979; a
different signature on the base), a certificate signed here with a
revocation outpoint verifies in the reference (`true`; the base's signature
`false` there), a wrong signature is `Ok(false)` (both), and 0.9.0-beta.1's
raw-key signature of the `email` certificate is `Ok(false)` (`Ok(true)` on
the base). `tests/auth_cross_sdk_tests.rs`'s fixture now carries a field
value as the UTF-8 bytes of its base64 text, as BRC-52 `0052.md:97` signs
it, not the decoded ciphertext; no vector moved: the one signed vector of
`auth_certificate.json` is `@bsv/sdk`'s `fromObject` parse fixture
(`Certificate.test.ts:312-328`, with its type and serial changed here), and
its signature verifies under no reading, in the reference (`false`, both the
crate's copy and the original) or here (decoded or text, raw or derived).
### Changed: crypto-bigint at 0.7.10 or later, P-256 verification back under 0.13's time (#126)

P-256 verification measured about twice as slow after #125 moved p256 to
0.14 (two A/B rounds on the Studio: 247 µs at p256 0.13.2, 486 to 509 µs at
0.14.0). The cause is crypto-bigint, not p256, its features or this crate's
profile: the #125 resolve took crypto-bigint 0.7.6, whose Montgomery
multiplication (the P-256 field and scalar arithmetic run through it,
`primefield::monty_field_element!`) propagates carries through `ctutils`
`Choice` conversions; 0.7.10 (2026-10-26) splits the wide sums and vendors
the primitives back (RustCrypto/crypto-bigint#1376, #1377), and yanks 0.7.6
to 0.7.8. Bisected with elliptic-curve 0.14.1 held, in retired instructions
per `P256PublicKey::verify` (`/usr/bin/time -l`, a harness on this crate):
0.7.6 to 0.7.9 2.69 M, 0.7.10 1.81 M; p256 0.13.2 took 2.34 M. p256's
features are not it (0.13.2 had no `precomputed-tables`; 0.14 has it on here),
nor a profile (none is set). `Cargo.toml` names `crypto-bigint = "0.7.10"`
for its floor alone, as `primeorder` is named for a feature, so a downstream
lock left on a slow release moves on its next `cargo update -p bsv-rs`; the
ratchet library lock moves crypto-bigint 0.7.6 to 0.7.10 and ctutils 0.4.5 to
0.4.6, nothing else.

`cargo bench --locked --bench primitives_bench -- --warm-up-time 1
--measurement-time 3 '^(Verification|Signing)/'`, two interleaved rounds
(load 15 to 30), origin/beta `eb5cef4` with its lock (0.7.6) against this
change (0.7.10), medians:

| bench | 0.7.6 | 0.7.10 | instructions, 0.7.6 to 0.7.10 |
|---|---|---|---|
| `Verification/P256PublicKey::verify` | 467 to 673 µs | 213 to 216 µs | 2.69 M to 1.82 M |
| `Signing/P256PrivateKey::sign_hash` | 127 to 206 µs | 62 to 106 µs | 0.85 M to 0.64 M (`sign`) |
| `Verification/PublicKey::verify (secp256k1)` | 56 to 58 µs | 53 to 73 µs | 0.62 M to 0.61 M |

k256 has its own field arithmetic and moves 1.5 percent: no k256 feature
changes. `benches/baseline.json` keeps its 0.13-era record (P-256 verify p50
249 µs, p99 1,825 µs on the one platform key it carries, Apple M1 Max), which
both 0.7.6 and 0.7.10 pass, and the CI bench job runs on ubuntu-24.04, where
`tools/bench-compare` finds no entry, exits 3 and warns: CI does not measure
this today. The re-record of the M1 Max entry and a Linux entry (`--record`,
`[bench-baseline-record]`) is a separate baseline PR, the captain's (#245). A
fresh resolve already takes 0.7.10, so the floor is for the locks that exist.
### Fixed: `write_wallet_certificate` refuses what the reference's writer refuses (#189)

Left by #183, which made the readers refuse a certificate the reference's
`Certificate.fromBinary` refuses (`ts-stack@edf6e03` `Certificate.ts:329-408`)
and left `WireWriter::write_wallet_certificate` writing it unchecked, so this
crate could make a certificate frame its own readers and the reference's
refuse. `Certificate.toBinary` refuses each before it writes; this writer now
does too, before a byte is written, a `WalletError` in the readers' words
(one check for both, `src/wallet/wire/mod.rs`):

- a subject or certifier that is not 33 bytes decompressing to a point
  (`Certificate.ts:241-253`, `assertCompressedPublicKey` `:136-142`):
  `Invalid certificate subject: expected a compressed secp256k1 public key`,
  and the same for `certifier`;
- a field name outside 1 to 50 bytes (`:289`, `assertCertificateFieldName`
  `:117-126`): `Invalid certificate field name length: received <n>`, the
  readers' words (`:369`), where the reference's writer says `expected 1–50
  bytes, received <n>` (`:120`);
- an unsafe field name (`__proto__`, `constructor`, `prototype`; the same
  lines): `Unsafe certificate field name: <name>`;
- a signature past 72 bytes or not DER (`:300-312`, `Signature.fromDER`):
  the readers' words (`Certificate signature exceeds the DER size limit`,
  `:393`, where the reference's writer says `Invalid certificate signature
  encoding`, `:307`; then `fromDER`'s own). The DER it accepts is written as
  given (`:311`), not re-encoded.

A repeated field name cannot reach this writer: its fields are a `HashMap`.
The whole certificate is built before a byte goes to the caller's writer, so
a refusal leaves it as it was, `write_optional_wallet_certificate`'s present
flag included; `write_identity_certificate` inherits the checks. go-sdk@2ca481c
holds the keys and the signature as types (`*ec.PublicKey`, `*ec.Signature`:
`wallet/serializer/certificate.go:36-37`, `:61-63` write `Compressed()` and
`Serialize()`, so neither can be other than a point and DER) and writes the
field names unchecked (`:43-58`). Pinned by
`a_certificate_subject_or_certifier_that_is_not_a_compressed_key_is_refused_by_the_writer`,
`a_certificate_field_name_outside_1_to_50_bytes_or_unsafe_is_refused_by_the_writer`
and `a_certificate_signature_that_is_not_der_is_refused_by_the_writer`
(`tests/wire_reader_strictness.rs`), red on `15b48d4`; no recording or vector
moves. Public shape: nothing moves (the writer returned a `Result` already).

### Added: `ScriptResourceLimit` prints the interpreter's sentence, from one place (#228)

`script::ScriptResourceLimit` implements `Display`, carrying the
interpreter's resource sentences byte for byte (`Stack memory usage`, `Alt
stack memory usage`, `Script element allocation` `has exceeded <limit>
bytes`; `Work budget exhausted: spent <n> units, budget <limit>`). The
interpreter's message (`src/script/spend/limits.rs`, `resource_error` and
`work_error`) and `SpendRefusal::Resource` (#213, which copied the words)
both print through it, so the words live in one place. A `Work` limit with
`work_spent: None`, which the interpreter never builds, prints `Work budget
exhausted: budget <limit>` where #213's arm printed `spent 0 units`: a limit
with no work recorded is not said to have spent none. No other text moves:
the interpreter's resource tests and #213's `a_spend_refusal_prints_*` pass
unchanged; each kind's text is pinned in `tests/resource_limits.rs`
(`a_stack_limit_prints_the_interpreters_sentence` and the five beside it).
Additive: a trait impl on an existing public type.
### Changed: `http` is native-only, refused on wasm32 at the build script (#152)

`cargo build --target wasm32-unknown-unknown --no-default-features --features
"transaction,http,wasm"` failed on beta with 8 errors (the HTTP chain
trackers' `async_trait` methods await a reqwest future that is not `Send` on
wasm32), and CLAUDE.md rule 6's slice with `http` added with 69 (the same in
the broadcasters, the HTTP substrate, the overlay facilitators and the auth
transport, and `ClientBuilder::timeout`, which reqwest's wasm backend lacks).
Rule 6's slice and the `wasm32` CI job's six consumer slices carry no `http`,
so nothing showed it. No consumer asks for `http` on wasm32: the two `http`
rows of `docs/dependents.lock` (`bsv-wallet-toolbox-rs`, `full,http`;
`bsv-storage-parity`, `auth,http,overlay`) are native, as is the relay's
`tests/load_gen`; every wasm32 row and every CI slice omits it. So this is a
stated bound, not a port: a new `build.rs` stops a wasm32 build with `http`
before rustc reads the crate, with one message ("bsv-rs: the http feature is native-only
and does not build for wasm32 ...", the feature name in backticks there). A `compile_error!` in the
library was tried and is not enough: rustc reports it and then the eight
awaits too. README, `Cargo.toml`'s feature comment, the crate docs and rule 6
say why `http` is absent from the slice. Pinned by the `wasm32 (combined)` CI
step "The slice with http is refused at the build script": red on the base
(69 errors, no message), green here. A consumer that asks for `http` on wasm32
reopens #152 as the fix (`#[async_trait(?Send)]` on wasm32, the builder's
timeout behind `cfg(not(target_arch = "wasm32"))`). Public shape: nothing
moves; native builds run a build script that does nothing.
### Fixed: listCertificates and discovery results are read to the end of the frame, the page limit enforced (#190)

Left by the lane of #183, in the keeper's reading there: a reader refuses what
the reference's reader refuses. `totalCertificates` is the total of every
page, not the page's length: the reference's processor writes
`certificatesPage.total` ahead of the page's records (`ts-stack@edf6e03`
`WalletWireProcessor.ts:2052-2053` listCertificates, `:2486-2487`
`#serializeDiscoveryResult`), and its transceiver reads the records
`while (!resultReader.eof())` (`WalletWireTransceiver.ts:1508`
listCertificates, `:1699` `#parseDiscoveryResult`). This crate's transceiver
read `total` records and dropped the bytes after them, so it refused a page
shorter than the total and read a longer one cut to it. Both readers now read
the reference's way, each refusal in its words, a `WalletError`:

- A byte after the last entry is read as the start of another and refused by
  the entry's reader (a `00` is a certificate of no bytes,
  `ReaderUnderflow { needed: 32, available: 0 }` at its type).
- More entries than the declared total: `Wallet Wire listCertificates response
  returned <n> records but declared a total of <t>` (`discover` for both
  discovery calls), `#assertPageCount` (`:1940-1946`) after the page (`:1550`,
  `:1759`).
- An entry past the requested limit, 10 when none was requested: `Wallet Wire
  listCertificates response exceeds the requested page limit of <m>`
  (`discover` for both discovery calls), `#requirePageCapacity`
  (`:1948-1953`, `requestedLimit ?? 10`) before each entry (`:1509`, `:1700`).
  The 10 is the reference's default page size, BRC-100's
  `PositiveIntegerDefault10Max10000` for the request's `limit`.

A total above the page is read as given (`total_certificates` the wallet's,
`certificates` the page). The total's own bound, 0 to `u32::MAX`
(`#requireInteger(..., 0, 0xffffffff)`, `:1501-1506`, `:1676-1681`), was
already the reader's (`read_var_int_u32`), in this crate's words. The tests
that pin it, in `tests/wire_reader_strictness.rs`, each red on `9457125`:
`a_byte_after_the_last_certificates_entry_is_refused` (read `Ok((1, 1))`),
`a_certificates_page_past_its_declared_total_is_refused` (read `Ok((1, 1))`),
`a_certificates_page_past_the_requested_limit_is_refused` and
`a_certificates_total_above_the_page_is_read` (both refused a page shorter
than its total as `ReaderUnderflow`). No recording or vector moves; no public
shape moves, the two helpers `pub(crate)`.

### Notes: cross-SDK parity (#190)

go-sdk reads `TotalCertificates` records and refuses bytes after them
(`go-sdk@2ca481c` `wallet/serializer/list_certificates.go:132-164`,
`discover_certificates_result.go:37-51`, `CheckComplete`), and its writers
refuse a total other than the page's length (`list_certificates.go:86-88`,
`discover_certificates_result.go:13-15`): it refuses a page the reference's
processor writes for a wallet whose total exceeds the page, and enforces no
page limit. This crate follows the reference.

### Fixed: two residual leniencies of the wire readers: a repeated keyring key, a length cut on wasm32 (#192)

Left by the cold review of #184. `WireReader::read_identity_certificate`
kept the later value of a repeated key in the public keyring and the
decrypted fields; the reference's discovery reader refuses one
(`ts-stack@edf6e03` `WalletWireTransceiver.ts:1718-1752` through
`#setUniqueWireRecordEntry`, `:1992-2002`; `Certificate.ts:373-374` refuses a
certificate's repeated field name the same way), and this crate's transceiver
has refused one since #183. Both readers now go through one helper, in the
transceiver's words: `Duplicate discovery public keyring key: <k>`,
`Duplicate discovery decrypted fields key: <k>`, a `WalletError`. The reader's
other differences from the transceiver's on the same bytes (a key outside 1
to 50 bytes, an unsafe key, a non-strict count) are outside this change.

`WireReader::read_string` cast its varint length `as usize`: lossless on a
64-bit host, on wasm32 a length at or above 2^32 kept its low 32 bits and read
a shorter value in silence (CLAUDE.md rule 5). A length of 2^32 + 3 before
three bytes read `Ok("abc")` under `wasm-bindgen-test-runner` on the pre-fix
tree. Every wire byte length is now compared with the bytes remaining before
it is narrowed and refused as `ReaderUnderflow`, the error a length past the
bytes already gave on the host, so every target refuses it alike (`needed`
saturating at `usize::MAX` where it cannot fit): `read_string`,
`read_optional_string`, `read_optional_bytes`, `read_sign_action_spend`,
`read_identity_certificate`'s certificate length and keyring values, and the
transceiver's error-frame stack, createAction's and signAction's tx, the
signable transaction and its reference, listOutputs' BEEF, the
listCertificates and discovery certificate lengths and proveCertificate's
keyring values; proveCertificate's keyring count is counted as a `u64`.

The tests that pin it, in `tests/wire_reader_strictness.rs`:
`an_identity_certificate_with_a_repeated_record_key_is_refused_as_discovery_refuses_it`
(red on `060e7e0`: the reader read `Ok`) and
`a_wire_length_past_u32_is_refused_on_every_target_not_cut_to_its_low_bits`
(the error the wasm32 run gives, asserted on the host, where the cast was
already lossless; its red is the wasm32 run's). No public shape moves: no new
`Error` variant, the new length helpers `pub(crate)`.
### Fixed: an entry mutated through `BeefTx::tx_mut` is one thing to every reader (#171)

`BeefTx` caches the txids its inputs spend (`input_txids`) and keeps the
bytes and the txid it was read with; `tx_mut` refreshed none of them. After a
caller pointed an input elsewhere, `sort_txs` and `verify_structure` read the
old list, `to_binary_atomic` looked the subject up under the old txid and its
closure read the new inputs, and the writer emitted the bytes the entry was
read with: three readings of one entry. Now the mutated transaction is the
entry's only reading, as `@bsv/sdk` 3 makes it (`ts-stack@4d0ea63`
`BeefTx.ts:160-177` `syncRawTxFromTransaction`, `Beef.ts:342-351`):

- `tx_mut` drops the bytes and the txid the entry was read with and clears
  the transaction's own hash cache, so `txid()` is the mutated transaction's
  hash and the writer emits its serialization (`raw_tx()` answers `None`
  until `raw_tx_or_compute` serializes it again);
- the BUMP index stays as it was: a proven entry whose hash moves keeps the
  index and is refused `TxidNotInBump` by `verify_structure`, as it is on the
  wire it writes;
- `input_txids` is refreshed by the BEEF's next whole-BEEF reader
  (`sort_txs`, `verify_structure`, `verify_valid`, `is_valid`, `to_binary`,
  `to_binary_atomic`, `trim_known_proven`, `to_log_string`), which also
  re-keys the BEEF's txid index by the new txid and marks the order to be
  sorted;
- `find_txid`, `find_txid_mut`, `merge_*`, `make_txid_only` check an index hit
  against the entry's txid, so a renamed entry is not found, replaced or
  removed by its old txid. `merge_transaction` and `merge_raw_tx` keep the
  txid they computed, so the check costs a string compare.

The choice, of the issue's two that keep the method: a refresh of the cache
and the bytes, without the guard type. A guard's `Drop` sees the entry but
not the BEEF, so it could not re-key the BEEF's index by the new txid, and it
would change `tx_mut`'s return type, a public shape the owner's word for
0.9.0 does not cover. Dropping the cache (the other choice) would remove the
public field `input_txids`, and its readers would still meet the stale bytes
and the stale index. `tx_mut`'s signature is unchanged; no public type,
field or method is added or removed. The in-crate caller (`trim_known_proven`,
read-only) now reads through a private accessor that keeps the bytes. No
dependent on disk calls `tx_mut` (`bsv-overlay-cloudflare`,
`rust-message-box`, `bsv-wallet-toolbox-rs`, `bsv-wallet-cli`).

Pinned by `tests/beef_tx_mut.rs` (three tests, each RED before the fix: an
input repointed within the BEEF read by the sort, the judge, the atomic
writer and the writer; one repointed outside it a missing input; a proven
entry mutated `TxidNotInBump`). `tests/beef_cycle.rs`'s in-memory ring set
`input_txids` by hand beside `tx_mut` because `tx_mut` left it stale; that
line goes, and the ring with it: renamed by its hash, the entry leaves a
chain with `T0` missing
(`a_ring_closed_through_tx_mut_renames_the_entry_and_is_a_chain`, RED before
the fix). The sort's, the judge's and the trim's termination on a ring is
pinned where a ring is still possible, the public cache written by hand on an
entry `tx_mut` never touched
(`a_ring_written_in_the_input_cache_stops_the_sort_and_the_judge`).

### Notes: cross-SDK parity (#171)

TS 3 synchronizes on every `findTxid` (`Beef.ts:497-499`) as on its other
readers. Here the lookups do not refresh (`find_txid` takes `&self`, and a
scan of every entry per lookup would make a loop of lookups quadratic): until
the next whole-BEEF reader runs, a lookup by the new txid misses, and one by
the old txid finds nothing; in that window a `merge_raw_tx`, `merge_transaction`
or `merge_txid_only` of the renamed transaction adds a second entry under the
new txid, and `find_atomic_transaction` of the new txid answers `None`, until a
whole-BEEF reader runs (the review's reading; a scan per merge would double
the merge loop, so the window is stated, not closed). Nothing on the wire differs.
### Fixed: a refused abort is code 8 and the client reads 8 as `aborted: false` (#206)

The keeper's reading on #206 (2026-10-25), the rule of #197 and #202: the
reference's bytes are the wire. This processor answered abortAction with a
refusal stub (code 1, `abortAction requires a full wallet implementation`)
and never called its wallet, and the transceiver read any success frame as
`aborted: true` and any error frame as an error, so a wallet's refusal never
reached a consumer as `aborted: false`. The reference's processor reads the
rest of the request as the reference's bytes, hands them to the wallet as
base64 after `validateAbortActionArgs` (`ts-stack@edf6e03`
`WalletWireProcessor.ts:783-796`; `validationHelpers.ts:488-498`,
`:893-899`) and frames a wallet's `aborted: false` as `WalletError('The
wallet refused to abort this action because it has already been broadcast',
abortRefused)` (`:797-804`), code 8 (`WalletError.ts:79`), thrown after the
wrapper and so in its own words; an abort is the error byte alone
(`:806-809`). Its client wants an empty success frame (`#requireEmptyResponse`,
`WalletWireTransceiver.ts:334`), reads code 8 as `{ aborted: false }` on the
code alone (`:336-339`), the one code it acts on, and throws every other
frame (`:340`).

`handle_abort_action` now goes through `invoke_wallet` to the wallet's
`abort_action`: an empty reference is refused ahead of it, code 6, `The
reference parameter must be valid base64 string`; a wallet's error is
`Wallet operation failed`, code 1 (#202); `aborted: false` is
`08 4d <the reference's 77 bytes> 00`; `aborted: true` is `00`. The
transceiver reads code 8 as `Ok(AbortActionResult { aborted: false })`,
refuses a byte after a success frame's error byte (`Wallet Wire abortAction
response has an invalid length`), and reads every other error frame as
before (`wallet error (code N): <message>`). Public shape: nothing moves.

The tests that pin it, in `tests/wire_error_frames.rs`:
`a_wallets_refused_abort_is_framed_code_8_in_the_references_words`,
`an_aborted_action_is_the_success_frame_and_reads_aborted_true` and
`an_empty_abort_reference_is_refused_code_6`, red on `cd4bb96` (the stub's
code 1 frame); `the_transceiver_reads_code_8_as_aborted_false` and
`every_other_abort_frame_is_the_error_it_was`, red on `6f5941d` (code 8 read
as an error; a trailing byte read as `aborted: true`). abortAction's rows
leave both every-vector allowlists in `tests/wallet_wire_cross_sdk_tests.rs`
(args 14 to 13, passing rows 13 to 14; results 13 to 12, passing rows 14 to
15), and `the_twelve_stubs_are_untouched` counts twelve. Two recordings moved
(F19 in `docs/FIXTURES.md`): `abortAction.json`'s processor frame `00` and
the wallet's observed call where the stub's frame and `null` stood;
`error_frames.json`'s `status_8` records abortAction's `aborted: false`.

Migration: a processor over a wallet that answers abortAction now calls it;
over `ProtoWallet`, whose `abort_action` errs, the frame is `Wallet operation
failed`, code 1, where it was the stub's words. A client that matched the
error `wallet error (code 8)` on abortAction reads `aborted: false` instead.

### Notes: cross-SDK parity (#206)

go-sdk neither writes nor reads the code: its processor writes nothing for an
`AbortActionResult` whatever `Aborted` says (`go-sdk@2ca481c`
`wallet/serializer/abort_action.go:33-36`), so a refusal is a success frame,
and its client answers `Aborted: true` for any success (`:38-43`). This crate
follows the reference.

### Fixed: `read_identity_certificate` takes the transceiver's three readings; a listActions satoshis value in the reference's bound (#236)

`WireReader::read_identity_certificate` read a discovery entry's two maps
with a plain varint count and plain strings, where the reference's discovery
reader (`ts-stack@edf6e03` `WalletWireTransceiver.ts:1711-1752`) and this
crate's transceiver since #183 read a strict count, at most 100,000 and no
more than the bytes left (`readVarIntNumStrict(false)`,
`#requireResponseCollectionLength`, `:1955-1969`), and each key 1 to 50 bytes
and not `__proto__`, `constructor` or `prototype` (`#readRecordKey`,
`:1979-1990`; `isUnsafeRecordKey`, `SafeRecord.ts:2-4`; the certificate's own
field names the same, `Certificate.ts:365-378`). Both readers now read the
maps through one crate-private helper (`read_discovery_maps`, over
`read_counted_wire_record`, which listCertificates' keyring reads through
too), with the transceiver's errors, which are the reference's words:
`Invalid discovery public keyring key length: expected 1–50 bytes, received
<n>`, `Unsafe discovery decrypted fields key: <k>`, `Wallet Wire discovery
public keyring count exceeds the remaining response data`, `Wallet Wire
<record> exceeds the maximum collection size of 100000`, `number too large
to retain precision - use readVarIntBn`. A count that stops short of its
entries is refused at the count; one that runs long leaves an entry the next
reading meets and refuses. The record values' lengths go through
`wire_length` after the strict bound, so a length past the bytes stays
`ReaderUnderflow` on every target (#192). No reading loosens. The certifier's
trust byte stayed unbounded in this reader, as #184 chose (Go's zero value
read as trust 0), until #247 bounded it as the transceiver does.

`read_wallet_action` cast the satoshis varint `as i64`. The reference reads
the signed net amount as `#readActionSatoshis` does (`:400-416`): `0xff` and
a signed int64 with the sign bit set, any other value
`readVarIntNumStrict(false)`, then `#requireInteger(value, 'listActions
satoshis', -21e14, 21e14)` (`:2018-2025`). The cast read the negatives the
same and stated no bound; the read is now the reference's, in its words
(`Invalid listActions satoshis: expected an integer from -2100000000000000
to 2100000000000000, received <v>`), and the transceiver's listActions reads
through it.

The tests that pin it, in `tests/wire_reader_strictness.rs`:
`an_identity_certificate_refuses_the_record_keys_and_counts_discovery_refuses`
(nine frames; on the pre-fix tree the reader read `Ok` for the five key
cases and gave `ReaderUnderflow` for the four count cases, the transceiver
the words in each) and
`a_list_actions_satoshis_value_outside_the_reference_bound_is_refused` (on
the pre-fix tree `2100000000000001`, `-2100000000000001`, `i64::MIN` and
`2^60` read `Ok`). `a_count_that_overruns_the_bytes_is_refused_without_a_panic`
(`tests/wire_identity_certificate_roundtrip.rs`) pinned `ReaderUnderflow` for
a map count past `2^53 - 1` and now pins the strict reader's words. No public
shape moves: no new `Error` variant, the helpers `pub(crate)`.

### Notes: cross-SDK parity (#236)

go-sdk reads the satoshis as an unsigned varint with no bound; the reference
and this crate refuse the same values with the same words (a negative below
`-(2^53 - 1)` in `BigNumber.toNumber`'s words, `BigNumber.ts:625-630`, ahead of
the bound).

### Fixed: a certificate's field value is held, written and signed as its base64 text, and decrypted as the reference encrypts it (#261)

BRC-52 at `5119a9b` carries a field value as a base64 string
(`peer-to-peer/0052.md:41`) and is a MUST on its bytes (`:97`: "Field values
in `CertificateBinary` are the UTF-8 bytes of the Base64 string, not the
Base64-decoded ciphertext bytes. Serializers and verifiers MUST preserve the
field-name strings and Base64 text used in the signed representation. They
MUST NOT apply ... Base64 decoding and re-encoding to an existing signed field
while reconstructing its preimage."). The reference at `ts-stack@edf6e03`
writes `UtilsToArray(fieldValue, 'utf8')` (`packages/sdk/src/auth/certificates/Certificate.ts:294-296`)
and stores `toBase64(ciphertext)` as the field (`MasterCertificate.ts:283`);
Go holds `Fields map[string]string` (`go-sdk@2ca481c` `wallet/interfaces.go:122`)
and writes `[]byte(fieldValue)` (`wallet/serializer/certificate.go:58-60`).
`Certificate.fields` was `HashMap<String, Vec<u8>>`, its writer writing the
bytes as given; it is now `HashMap<String, String>`, the base64 text, as the
reference's `Record<CertificateFieldNameUnder50Bytes, Base64String>` and Go's
`map[string]string` hold it (the owner's word of 2026-10-26, option A), the
writer writing `value.as_bytes()`, so the wire bytes are the text's UTF-8 as
before. #249's `with_fields` and `set_fields`, unreleased, take the same
`HashMap<String, String>`. The sites that put the decoded ciphertext there:

- `get_verifiable_certificates` (`src/auth/utils/validation.rs`) decoded each
  field of the wallet's `listCertificates` result before building the
  certificate; it now holds the text.
- The identity client's two parsers (`parse_output_to_certificate`,
  `parse_output_to_verifiable_certificate`, `src/identity/client.rs`) decoded
  each field; they now hold the text. They also read the signature as
  base64, where the reference's `WalletCertificate.signature` is hex and this
  crate's own `publicly_reveal_attributes` writes hex, so no published
  certificate parsed; they read hex now.
- `MasterCertificate` stored the wallet's ciphertext raw. It now encrypts as
  the reference does (`MasterCertificate.ts:254-310`): a random symmetric key
  per field, the field the base64 text of that key's ciphertext, the master
  keyring the key encrypted by the certifier's wallet to the subject (protocol
  `[2, "certificate field encryption"]`, key ID the field name).
  `create_keyring_for_verifier` decrypts that key and encrypts it to the
  verifier under `"<serial base64> <field>"` (`:325-414`); `decrypt_field(s)`
  (`:564-625`) and `VerifiableCertificate::decrypt_field(s)`
  (`VerifiableCertificate.ts:152-219`) decrypt the key, then decode the field's
  base64 text and decrypt it, at decrypt time and nowhere earlier. Before,
  the wallet encrypted the plaintext directly and the master keyring held a
  copy of that ciphertext, so no certificate the reference issued decrypted
  here and none issued here decrypted there.
- `Certificate`'s serde: `fields` went out as arrays of numbers. It is now the
  plain map of strings, each value the string itself, and serde_json refuses
  bytes that are not UTF-8 on the way in. `to_wallet_certificate` and
  `VerifiableCertificate::to_json_value` write the held text where they wrote
  its base64.
- `Certificate::from_binary` held a field value's bytes as given; it refuses
  one that is not UTF-8 as `InvalidUtf8` (`certificate field <name> is not
  UTF-8 base64 text: ...`), as the reference's `fromBinary` reads it with
  `toUTF8Strict` (`Certificate.ts:384`) and BRC-52 asks (`0052.md:103`:
  "Malformed UTF-8 ... MUST NOT be made acceptable by retaining bytes").
  `set_field` takes `impl Into<String>` for the value and returns `()`: the
  reference's record takes any string and refuses nothing at its write
  (`Certificate.ts:294-296`), so any string is accepted, base64 or not, and a
  value the reference would sign is signed here.
- The identity client's revelation parser (`parse_output_to_certificate`)
  aborted the whole resolution on a signature that is not hex; it skips that
  output, as its sibling parser does and the reference does
  (`IdentityClient.ts:823-825`).

The keyrings (outside the signature, `0052.md:75,143`) keep their
representation: raw ciphertext bytes, base64 at the JSON intakes as before
(until #268, above: the base64 text).

The certificate methods take the reference's parameters (the owner's word of
2026-10-26, option A: the signature breaks once, in 0.9.0, and never again).
`cargo semver-checks check-release --baseline-rev origin/beta --features full
--release-type minor` reports `method_parameter_count_changed` for the six
below, 0.9.0's; the type of the public field `Certificate.fields` and
`set_field`'s value parameter and return move too, which semver-checks 0.51.0
has no lint for. Migration, the old call and the new:

```text
create_keyring_for_verifier(w, certifier, verifier, &reveal, &cert.fields, &cert.master_keyring, &serial, originator)
create_keyring_for_verifier(w, certifier, verifier, &cert.fields, &reveal, &cert.master_keyring, &serial, None, None, originator)

create_certificate_fields(w, &subject, fields, &serial, originator)
create_certificate_fields(w, &subject, fields, None, None, originator)

master.decrypt_field(w, certifier, name, originator)
master.decrypt_field(w, certifier, name, None, None, originator)

master.decrypt_fields(w, certifier, originator)
master.decrypt_fields(w, certifier, None, None, originator)

verifiable.decrypt_field(w, subject, name, originator)
verifiable.decrypt_field(w, name, None, None, originator)

verifiable.decrypt_fields(w, subject, originator)
verifiable.decrypt_fields(w, None, None, originator)

cert.set_field(name, ciphertext_bytes)
cert.set_field(name, to_base64(&ciphertext_bytes))

let bytes: &Vec<u8> = &cert.fields[name];
let text: &String = &cert.fields[name];  // value.as_bytes(), or from_base64(text)? at the decrypt site
```

- `MasterCertificate::create_keyring_for_verifier` takes the subject wallet,
  the certifier, the verifier, the fields, the fields to reveal, the master
  keyring, the serial number, `privileged`, `privileged_reason`, then this
  crate's `originator`: the reference's order (`MasterCertificate.ts:325-346`),
  the fields now ahead of the fields to reveal and the master keyring a
  parameter (the decrypt needs it).
- `privileged: Option<bool>` and `privileged_reason: Option<&str>` are carried
  as this crate's `EncryptArgs` and `DecryptArgs` carry them (absent the
  reference's default, `None`), the reason borrowed since one reason goes to
  every field's call, and passed into each wallet `encrypt` and `decrypt` as
  the reference passes them: `create_keyring_for_verifier` (`:390-391`,
  `:400-401`), `create_certificate_fields` (`:254-260`, `:289-290`; its unused
  serial number dropped, the reference has none), `MasterCertificate::
  decrypt_field` (`:564-572`, `:596-597`) and `decrypt_fields` (`:512-519`,
  `:553-554`), `VerifiableCertificate::decrypt_fields`
  (`VerifiableCertificate.ts:152-156`, `:197-198`) and `decrypt_field`, which
  it calls. `issue_for_subject` takes none, as `issueCertificateForSubject`
  takes none (`:437-444`).
- `VerifiableCertificate::decrypt_field` and `decrypt_fields` drop their
  `subject` parameter: the reference reads the counterparty from the
  certificate (`this.subject`, `VerifiableCertificate.ts:152-156`, `:196`), as
  Go does (`vc.Subject`, `go-sdk@2ca481c` `auth/certificates/verifiable.go:76-99`).
  Option A (the reference's parameters in the reference's order) applied to
  the one parameter the reference does not have; every caller in the tree
  passed the certificate's own subject. Migration: drop the argument.

A certificate issued by this crate's `MasterCertificate` before this release
does not decrypt under the reference's scheme: re-issue it.

Pinned by `tests/auth_certificate_field_value_261.rs` and
`src/identity/client_field_value_261_tests.rs` on the witnesses
`tests/vectors/certificate_field_value_261.json`, recorded by
`tests/support/certificate_field_value_261.mjs` against `@bsv/sdk` at
`ts-stack@edf6e03` (bundled with bun) under Node v22.18.0, its randomness a
SHA-256 counter stream so the run reproduces byte for byte: a certificate the
reference issued with three encrypted fields, read through `Certificate`'s
JSON, through `get_verifiable_certificates` over the HTTP JSON substrate and
through both identity parsers, verifies here and signs the reference's
preimage hash (on the base: a JSON refusal, a different preimage hash, and
`None` from both parsers); it decrypts here to the reference's plaintexts
under the master, verifier and anyone keyrings (`DecryptionFailed` on the
base); a certificate issued here holds canonical base64 text, its bytes are
the reference's `toBinary(true)` of its JSON, and the reference verifies it
(`true`) and decrypts it to its plaintexts; a value that is not UTF-8 is
refused at the JSON intake and at `from_binary`; `set_field` holds any string
and writes its bytes; a doc test on `set_field` pins a value set from a
string serializing to those bytes. `tests/auth_certificate_privileged_261.rs`: a recording wallet
sees `privileged: true` and the reason on each `encrypt` and `decrypt` of the
five methods, and neither on an unprivileged call (red on a copy that takes
the pair and does not pass it). The identity client skipping a malformed
signature's output: `a_malformed_signature_skips_its_output_and_the_resolution_goes_on`.

### Notes: cross-SDK parity (#261)

The JSON shape of `Certificate.fields` moves from arrays of numbers to the
reference's strings (`Wallet.interfaces.ts` `WalletCertificate.fields:
Record<CertificateFieldNameUnder50Bytes, string>`); `AuthMessage`'s
certificates carry it so on the auth wire. A Rust caller holding ciphertext
bytes writes `to_base64(&bytes)`; one reading `fields` as bytes reads
`value.as_bytes()`, or `from_base64(value)?` at its decrypt site. The rest of this
crate's `Certificate` serde stays where it was and is not the reference's
JSON: `certType` where the reference writes `type`, the signature an array of
numbers where it writes hex, the keyrings arrays of numbers where it writes
base64 (a line in `CLAUDE.md`'s list; the keyrings and the rest of the JSON
shape follow on the owner's same word in #268). `bsv-wallet-toolbox-rs` (at `6317222`) moves in three
places with this release: its intake decodes each field
(`src/wallet/certificate_issuance.rs:553-556`, `BASE64.decode` then
`set_field`) and must pass the string through, `set_field(name.clone(),
value.clone())` (its captain told); its own issuance (`create_certificate_fields_for_issuance`,
`certificate_issuance.rs:346-384`) is this crate's old scheme, the wallet
encrypting the plaintext and the master keyring a copy of the ciphertext; and
its own keyring helper (`create_keyring_for_verifier`,
`src/wallet/wallet.rs:3127`) reads the keyring that issuance writes. Once the
issuance and the helper move to the reference's scheme, every certificate the
toolbox issued under the old one is re-issued.

## [0.9.0-beta.1] - 2026-10-26

The 0.9.0 line's canary prerelease (RELEASING.md point 14), cut from `beta` for the toolbox's and the CLI's beta lines to build against; the entries below are 0.9.0's, unreleased on `main` until the minor merges at the phase exit.
### Changed: the BRCs pin of record moves from `ed1b015` to `5119a9b` (#154)

The keeper's word of 2026-10-24 on the owner's (bsv-stack-lean DECISIONS
15.3): the line's pin of `bsv-blockchain/BRCs` moves from `ed1b015`
(2026-10-05) to `5119a9b` (2026-10-19), and this crate's citations move with
it ahead of 0.9.0-beta.1. `BRC_PIN` names the new commit and the 65 fixture
files were re-recorded by `docs/FIXTURES.md`'s procedure: 67 lines moved, each
a reference's commit line; no fixture byte under test moved. Every line range
cited at the old pin carries its number at the new one (`wallet/0100.md`'s
edits above a range shift it by 1, 7, 8, 9 or 23 lines; the BEEF, BUMP, atomic
BEEF and raw transaction ranges keep theirs), and `docs/lanes/README.md` rule
4 names the new pin. Public shape: nothing moves.

Three wire-shape differences of `5119a9b` are on the line by the owner's word
and change nothing here:

- listOutputs' `totalOutputs` is a decimal string (`ExactModuleBalance`) for
  a BRC-112 P-basket balance query (`wallet/0100.md:932`, `:1968-1972`;
  #105);
- listOutputs' `spendable` may be `false` (wire `0`) in a BRC-207 module
  inventory view (`:939`, `:1963`, `:1974-1980`; #105);
- internalizeAction's `insertionRemittance.customInstructions` is at most
  1,000 UTF-8 bytes (`:867`; #117, already enforced).

### Added: `SpendRefusal` prints its rule, its text pinned (#213)

`beef_stream::SpendRefusal` implements `Display`, so a host prints the
verifier's refusal as a sentence instead of rendering each arm itself. A
script refusal prints the interpreter's sentence verbatim (the `String` the
arm carries, no prefix); a resource decline prints the interpreter's own
resource sentence (`Stack memory usage has exceeded <limit> bytes`, `Work
budget exhausted: spent <n> units, budget <limit>`: `ScriptResourceLimit`
has no `Display`, so the words are `src/script/spend/limits.rs`'s, written
from the limit's fields); every other arm its rule in its rustdoc's words,
the field named (`vout`, `lock_time`, `height`), lowercase and with no
trailing period, as the crate's `Error` texts go. The texts are a wire of
sorts, a downstream matching on them: each is pinned by its own test in
`tests/beef_stream.rs` (`a_spend_refusal_prints_its_rule_for_a_txid_only_parent`
and the eight `a_spend_refusal_prints_*` beside it), and the script
refusal's text on the verifier's path in
`a_spend_the_script_allows_is_valid_and_one_it_refuses_is_a_spend_refusal`. Additive: the enum's shape and arms do
not move; it gains no `std::error::Error`, as `Reason` has none.
### Changed: the linkage keys and revealSpecificKeyLinkage's absent counterparty refused by validation, code 6; the security level in the reference's words (#226)

The keeper's rule on #216: a refused argument carries the reference's code
and words. The reference reads revealCounterpartyKeyLinkage's counterparty
and verifier and revealSpecificKeyLinkage's verifier as 33 raw bytes
(`ts-stack@edf6e03` `WalletWireProcessor.ts:1742-1747`, `:1796`) and
`validateWalletArgs` refuses a key that is no point
(`validationHelpers.ts:1734-1750`, `validatePublicKey` `:182-188`,
`isValidCompressedPublicKey` `Secp256k1Validation.ts:15-22`: an `02` or `03`
prefix, x below the field prime, a point on the curve), code 6, `The
counterparty parameter must be a valid compressed secp256k1 public key`, the
same words for `verifier`; revealSpecificKeyLinkage's counterparty flag 0 is
absent and `validateCounterparty` hands it to `validateHexString`
(`:190-193`, `:523`): `The counterparty parameter must be a hexadecimal
string`, code 6. This crate refused all four at its request reader, code 1,
in its own words (the parse error's `Display`, `counterparty is required`).
The readers now carry the 33 bytes raw in a private request type;
`validation.rs` judges them in the reference's order (the counterparty, the
verifier, then the protocol, the key ID and the privilege) and builds the
args the wallet is called with. `RevealCounterpartyKeyLinkageArgs` and
`RevealSpecificKeyLinkageArgs` keep their shape: no public API changes.

The security level outside 0 to 2 is refused by the reader in the
reference's words, `Invalid security level: expected 0, 1, or 2, received N`
(`#decodeProtocolID`, `WalletWireProcessor.ts:2440-2443`), code 1, where this
crate said `invalid security level: N`; both of `WireReader`'s protocol
readers.

The tests that pin it, each red on the pre-fix tree, in
`tests/wire_processor_validation.rs`:
`a_counterparty_linkage_key_that_is_no_point_is_refused_with_code_6`,
`a_specific_linkage_verifier_that_is_no_point_is_refused_with_code_6`,
`a_specific_linkage_with_no_counterparty_is_refused_with_code_6`,
`a_security_level_outside_0_to_2_is_refused_in_the_reference_words`; and
`linkage_keys_that_are_points_reach_the_wallet` for the keys that pass.
`tests/wire_reader_strictness.rs`'s
`the_processor_refuses_a_linkage_key_that_is_not_a_compressed_point`, which
asserted only an error frame, pins the reference's code-6 frame. No
recording changes (`tests/fixtures_replay.rs` replays unchanged); the
every-args-vector allowlist stays 14 (the two linkage vectors passed before).

### Notes: cross-SDK parity (#226)

The divergence #216 recorded (the four refusals at the reader, code 1) is
withdrawn: the frames are the reference's. go-sdk@2ca481c refuses a non-point
key in its deserializer (`wallet/serializer/reveal_counterparty_key_linkage.go:40-51`,
`reveal_specific_key_linkage.go:53-57`), accepts an absent counterparty, and
reads the security level unchecked (`wallet/serializer/serializer.go:167`);
its processor writes no error frame (stated with #202).

### Fixed: getNetwork and getVersion are the wallet's answers forwarded, the version checked as the reference checks it (#222)

The keeper's ruling on #222 (2026-10-25). This processor answered both calls
from its own configuration (`new` gave mainnet and `0.1.0`, `with_config` what
it was given) and never asked its wallet, so #216's result validation had
nothing to check. The reference's processor calls
`this.wallet.getNetwork({}, originator)` and
`this.wallet.getVersion({}, originator)` through `#invokeValidatedWallet`
(`ts-stack@edf6e03` `WalletWireProcessor.ts:1701-1705`, `:1721-1725`) and
writes the network as one byte, 0 for mainnet (`:1710`), and the version's
UTF-8 bytes with no length (`:1730`); its result check wants the network
`mainnet` or `testnet` and the version a string of 7 to 30 UTF-8 bytes
(`WalletResultValidation.ts:2299-2306`, `string` `:908-915`). BRC-100 names
the version "the wallet's version string (e.g., `vendor-1.0.0`)" (section 28,
`wallet/0100.md:2517` at `5119a9b`). go-sdk forwards both too and checks
neither (`go-sdk@2ca481c` `wallet/substrates/wallet_wire_processor.go:400-414`;
`wallet/serializer/get_network.go` writes any network not mainnet as 1).

Both calls now go through `invoke_wallet` to the `Wallet` trait's
`get_network` and `get_version`, like the other thirteen (a wallet's error is
`Wallet operation failed`, #202). A version outside 7 to 30 bytes is refused,
code 1, `Invalid getVersion result version: expected 7–30 UTF-8 bytes`, the
reference's words and en dash. The network's rule is the `Network` type's:
it has the two values and no third, so a wallet here cannot answer one the
reference refuses, and a third read from JSON is no `GetNetworkResult`.
`ProtoWallet` answers `bsv-rs-<CARGO_PKG_VERSION>` (`bsv-rs-0.9.0`, 12 bytes),
where it answered the stale `bsv-rs-0.3.0`, and mainnet as before.
`WalletWireProcessor::with_config`, `network()` and `version()` keep their
signatures and are deprecated: their values reach no frame.

The tests that pin it, in `tests/wire_processor_validation.rs`:
`get_network_and_get_version_forward_the_wallets_answers_byte_for_byte`,
`a_version_result_outside_7_to_30_bytes_is_refused_with_code_1` (`0.1.0`,
6 bytes and 31 refused; 7, 30 and six two-byte characters pass) and
`the_proto_wallet_network_and_version_pass_the_result_checks`, red on
`25875bb` (the wallet never called; the processor's `0.1.0` written);
`a_network_outside_mainnet_and_testnet_is_no_network_result`, green before,
says where the network's rule lives. Go's `getVersion-simple-result.json`
answers `1.0.0`, 5 bytes, which the processor now refuses as the reference
does: it joins the result-vector test's allowlist (12 to 13, passing rows 15
to 14). The two wire recordings' `processor_observed` moved from `null` to
the wallet's call; no byte moved (F18 in `docs/FIXTURES.md`).

Migration: a client of `WalletWireProcessor::new` that read getVersion's
`0.1.0` now reads its wallet's version (`bsv-rs-0.9.0` from `ProtoWallet`);
a caller of `with_config` gives its network and version to its wallet's
`get_network` and `get_version` instead, and a wallet whose version is
outside 7 to 30 bytes is answered with the refusal, code 1.
### Added: an optional `tracing` feature: the processor's wrapper logs the wallet's words it frames away (#212)

The keeper's ruling on #202: an un-coded wallet error is framed as the
reference's `Wallet operation failed` (`WalletWireProcessor.ts:2417` at
`ts-stack@edf6e03`), and the wallet's words go to the processor's log line,
not the wire. The new cargo feature `tracing` (`tracing = ["dep:tracing"]`,
the `tracing` 0.1 crate with `default-features = false`, MIT) is off by
default and not in `full` (a diagnostics sink, not a module, so a `full`
build is unchanged). With it on, `invoke_wallet` emits one `warn` event when
the frame it chooses is the constant: `call` the call's name
(`WalletCall::method_name`, `getHeight`), `error` the wallet error's
`Display`, the message `wallet error framed as Wallet operation failed`.
Nothing else is instrumented: no event for an explicit coded error (none
today, #137), the processor's own refusals or a success. The level is
`warn` because the reference's processor logs nothing there (no `console`
call in `WalletWireProcessor.ts` at `edf6e03`) and the processor answers
normally: the event reports a wallet's failure the client sees only as the
constant, not a fault of the processor. The wire is the same bytes with the
feature on or off. Without the feature no `tracing` symbol is compiled; the
private `invoke_wallet` takes the call as a parameter in both builds.

The tests that pin it: `tests/wire_tracing_sink.rs` (new, 5 tests, under
`#![cfg(feature = "tracing")]`, a collector of its own on
`tracing::Subscriber`, no `tracing-subscriber`): one event with the call and
the wallet's words for getHeight and isAuthenticated, none for the
processor's own refusal or a success, the frame the same with a listener and
without. RED before: on `7c86b71` the feature does not exist (`cargo test
--features "full,http,tracing"`: `the package 'bsv-rs' does not contain this
feature: tracing`); with the plumbing and no `warn!`, the two event tests
fail at `left: 0, right: 1`. CI runs the file in its own step (`--features
"full,http,tracing"`, with `wire_error_frames` and `fixtures_replay`), allowlisted
in `tests/arch_ci_runs_every_test.rs`'s `RUN_APART` with that reason.
### Changed: `MockChainTracker` answers a synthetic mainnet mining tip at its height (#218)

The mock answered `mining_tip` with the trait's default `None`, so every
dependent whose tests verify a BEEF against it saw the streaming reader decline
the checks that need the tip (`Verdict::Unverifiable`, `CoinbaseMaturity` or
`Finality`; the toolbox's internalize door words it "the header service
supplied no mining tip"): nine of `bsv-wallet-cli`'s tests failed for that one
reason. Both `ChainTracker::mining_tip` and the streaming reader's
`Headers::mining_tip` now answer the same `ChainTip`, read at call time:
`height` the mock's `height`, `median_time_past` 1,700,000,000,
`genesis_height` `ProtocolEra::MAINNET_GENESIS_HEIGHT` (620,538),
`csv_height` 419,328 (bitcoin-sv@879fc8b `src/chainparams.cpp:1046`; the
crate had no constant, a private one is kept beside the mock),
`next_block_time` `None`. The door judges against it as against a real tip: a
coinbase spent 99 blocks deep is `PrematureCoinbase`, a lock time at the next
height `NonFinal`.
The tip is mainnet's, so a mock whose `height` is below 620,537 is a
pre-Genesis tip and the door does not refuse a P2SH output where the old `None`
refused it (`P2shOutput`; `verify_stream`'s `after_genesis` read,
`src/transaction/beef_stream.rs:2141-2142`), and below 419,327 a time lock
(lock time at or above 500,000,000) is `Unverifiable { check: Finality }`, the
tip carrying no `next_block_time` (`:2174-2177`); pinned by
`the_mock_tracker_below_genesis_is_a_pre_genesis_tip`.

Added (additive): `MockChainTracker::with_mining_tip(Option<ChainTip>)` sets
the tip both methods answer. Migration: a host test that asserted the hold on
the default mock builds it with `MockChainTracker::new(h).with_mining_tip(None)`.
The struct gains a private field, so a struct literal
`MockChainTracker { height, roots }` outside the crate no longer compiles; use
`MockChainTracker::new(height)` and `add_root` (none of the known downstreams
builds one). Pinned by `the_mock_answers_a_synthetic_mainnet_tip_at_its_height`,
`the_mock_with_a_mining_tip_answers_it_on_both_traits` (unit),
`the_mock_tracker_s_tip_lets_a_proven_spend_through_the_door`,
`the_mock_tracker_s_tip_is_judged_at_its_height` and
`the_mock_tracker_set_to_no_tip_holds_at_the_door` (`tests/beef_stream.rs`);
`mining_async_and_two_pass_enforce_coinbase_maturity` asserts its hold on the
mock with the explicit `None`.

### Added: a guard that CI runs every integration test binary (#146)

`tests/arch_ci_runs_every_test.rs` reads `.github/workflows/ci.yml`,
`Cargo.toml`'s features and every top-level `tests/*.rs`, and refuses, naming
the file, any binary no whole-suite `cargo test --tests` step compiles (its
`#![cfg]` gate read against the step's features), unless allowlisted with its
reason and step (`memory_profiling`, alone under `dhat-profiling`); and any
`--test <name>` in ci.yml with no file behind it. The Test Suite's enumerated
list had drifted to 34 of 73 files; the guard keeps it from drifting again
(`docs/ARCH-RULES.md` section 6).


### Changed: beta carries everything main carries, main nothing beta did not bear, checked by CI (the owner's word, 2026-10-25)

CI only; nothing under `src/` moves. A commit is on a line by sha, by patch
(`git cherry`), or by a cherry-pick link in either direction (a
`(cherry picked from commit <sha>)` line naming a commit of the other line).
`ci.yml` gains `main-in-beta`: on every PR into `beta`, every push to `beta`
and a dispatch on the sync branch it fails naming each commit of `origin/main`
the tree lacks that way; and `beta-born`: on every PR into `main` it fails
naming each commit of the PR `origin/beta` lacks that way, a release commit
(`Cargo.toml`'s version and `CHANGELOG.md`'s headings alone) let through and
said in the log. The new `sync-main-into-beta.yml` opens, on every push to
`main`, one PR from `sync/main-into-beta` into `beta`: each missing commit
`git cherry-pick -x`'d in main's order, landed by rebase merge (both lines
keep linear history; the link lives in the message). A conflicting pick is
aborted, the picks before it kept, the PR labelled `needs-hand` with the
commit and its files; a rerun picks onto a branch that holds beta's tip, so a
hand resolution survives main moving again. `ci.yml` gains `workflow_dispatch`
so the sync starts the suite on its branch. `RELEASING.md` steps 17 to 20
write the rule; `tests/arch_ci_lines.rs` pins the three jobs.

### Added: `sign_with`, `encrypt_with`, `split_private_key_with`; corpus-gen reproducible (#180)

`messages::sign`, `messages::encrypt` and `primitives::bsv::shamir::split_private_key`
draw a key id, an IV and polynomial coefficients with no way to pass them, so
a rerun of `fuzz/corpus-gen` rewrote 6 signed, 6 encrypted and 12 Shamir seeds
and the corpus could not be checked as identical. Three additive public
functions, the owner's names (2026-10-25), take those values:
`messages::sign_with(message, signer, verifier, key_id: [u8; 32])`,
`messages::encrypt_with(message, sender, recipient, key_id: [u8; 32], iv: [u8; 32])`,
`shamir::split_private_key_with(key, threshold, total, coefficients: &[[u8; 32]])`.
The plain forms draw as before and call them, so there is one body and no
byte the plain forms write moves. A key id or IV of the wrong size cannot be
passed (the arrays); a coefficient count other than `threshold - 1` is
`InvalidDataLength` (in bytes, 32 per coefficient), and a coefficient 0 modulo
p is `CryptoError` (it would lower the polynomial's degree; the plain form
never draws one). corpus-gen passes fixed values (the key id `[1; 32]`, the IV
`[2; 32]`, the coefficients `[3; 32]`, `[4; 32]`, ...): the 24 seeds' bytes
moved once, in their own commit (the names are unchanged), and two reruns
into a clean tree write all 18 directories byte for byte. The tests that pin
it: `tests/messages_tests.rs`' `sign_with_writes_what_sign_writes_given_its_key_id`
and `encrypt_with_writes_what_encrypt_writes_given_its_key_id_and_iv` (the
drawn values read back from the plain form's output), and
`tests/integration_tests.rs`' `split_private_key_with_returns_what_split_private_key_returns_given_its_coefficients`
(the coefficients solved from the shares at x = 1, 2), with the refusals.

### Notes: cross-SDK parity

The `_with` forms are this crate's addition, not a divergence: the TypeScript
SDK draws the key id inside `sign` and `encrypt` (`ts-sdk@9e3ede6`
`SignedMessage.ts:31`, `EncryptedMessage.ts:41`) and the IV inside
`SymmetricKey.encrypt`; the wire is the same. TS's `toKeyShares` draws random
points (`Polynomial.fromPrivateKey`, `Polynomial.ts:54-69`) and x coordinates
from an HMAC seed, where this crate draws coefficients and evaluates at
x = 1 to n (unchanged here); a share of either recovers under either reader.

### Removed: the three writer helpers of the old identity-certificate layout (#184)

`WireWriter::write_identity_certifier`, `write_optional_identity_certifier`
and `write_optional_string_map`, `#[deprecated]` since #187 (bb79c71), are
removed in 0.9.0 on the owner's word (2026-10-25, the keeper's
recommendation on #184). No frame of the reference's wire carries a present
flag or a NIL-sentinel map, and nothing in the crate called them. Migration:
write a discovery entry with `write_identity_certificate` (it writes the
certifier in the reference's layout, Go's zero value for `None`); write a map
with `write_string_map` (a count, 0 for an empty or absent map). The tests
that used them assemble the old bytes by hand
(`tests/wire_identity_certificate_roundtrip.rs`'s
`the_layout_before_182_is_refused` and
`the_certifier_reader_reads_three_plain_strings_and_the_trust_byte`,
`tests/wallet_tests.rs`, `tests/wire_method_roundtrip_tests.rs`,
`encoding.rs`'s `test_optional_string_map_roundtrip`); the wire_codec bench's
`OptMap` layout, which no recorded frame uses, goes with them. No downstream
names any of the three (a grep of bsv-overlay-cloudflare, rust-message-box,
bsv-wallet-toolbox-rs, bsv-wallet-cli, bsv-middleware-cloudflare-public and
rust-chaintracks, 2026-10-25). `WireReader::read_optional_string_map` stays.
### Changed: a repeated leaf offset is `DuplicateOffset`; `Kind` and `Reason` are non-exhaustive (#86, #167)

A BUMP level carrying a second leaf at an offset, agreeing with the earlier
one or not, was refused under the walk's name, `MismatchedNode { level,
offset }`, a node the level below contradicts. It now has its own reason,
`Reason::DuplicateOffset { level, offset }` and `Kind::DuplicateOffset` (the
twenty-fifth kind, after `MismatchedNode` in `Kind::ALL`), by the owner's word
of 2026-10-25. The two sites that refuse a repeat move together, so one BUMP
means one thing on the stream, the whole-BEEF reader and the standalone BUMP
reader: the decoder's offset state (`invalid BEEF at byte N: DuplicateOffset
{ level, offset }` at the second leaf's offset varint; `invalid BUMP at byte
N: ..` from `MerklePath::from_binary`) and `merkle_path_root`'s pre-pass over
a BUMP held in memory (`Beef::verify_structure` answers
`Err(Kind::DuplicateOffset)`). The walk's two `MismatchedNode` sites stay: a
repeat never reaches it (the level's map holds one leaf per offset), so what
it refuses there is a carried node or a parent its children contradict, the
Lean's `mismatchedNode` (`bsv-stack-lean@6104e4e` `lean/BeefOfAnySize.lean:169`,
`climb` `:501-502`, `:527`). `MerklePath::new`'s `Duplicate offset` text is
unchanged.

`Kind` and `Reason` are `#[non_exhaustive]` from this release, so the next
kind is not a break; 0.9.0 takes this one. **Migration:** a `match` on either
outside this crate ends in a wildcard arm (`_ => ..`); a compile_fail doc
test on each enum pins it. `SpendRefusal` (the interpreter's verdict, not a
byte rule) is left exhaustive; the owner's list does not name it. In the four
downstreams (`bsv-overlay-cloudflare`, `rust-message-box`,
`bsv-wallet-toolbox-rs`, `bsv-wallet-cli`) no exhaustive `match` on `Kind` or
`Reason` was found: they compare a kind with `==` or in a pattern of one
value (`overlay-cloudflare/src/submit_census.rs:1567`,
`rust-message-box/src/beef_door.rs:1642,1666,1678,1736`,
`bsv-wallet-toolbox-rs/src/storage/sqlx/internalize_action.rs:1947,1981`,
`create_action.rs:6111`, `beef_verification.rs:487`), and one matches on the
refusal's words (`submit_census.rs:1149`, `"BadFlag"`, a flag mutation this
change does not touch); none needs a change.

The Lean's `Reason` gains the constructor `duplicateOffset (level offset :
Nat)` after `mismatchedNode` (`BeefOfAnySize.lean:169`), its `Kind`,
`Reason.kind` and `Kind.all` (`:213-251`) the same, and `levelMap` (`:481`,
the earliest leaf standing) the refusal: the keeper's, told. The types moved
to `src/transaction/beef_stream/reason.rs` (a move in its own commit,
re-exported where they stood: `beef_stream.rs` is 3,376 lines, under its recorded bound of 3,617;
`reason.rs` 319. Pinned by `a_repeated_leaf_offset_is_duplicate_offset_on_both_readers`
(`tests/merkle_path_two_readers_agree.rs`, the standalone reader and the BEEF
reader on three repeats), the four repeated-offset tests of
`tests/beef_two_readers_agree.rs` (`a_level_0_leaf_repeated_with_the_same_hash_..`,
`.._with_a_different_node_..`, `a_higher_level_leaf_repeated_..`,
`a_repeated_leaf_offset_in_a_bump_held_in_memory_..`), and
`the_twenty_five_kinds_are_twenty_five_and_distinct` (`tests/beef_stream.rs`).
The corpus seed that reached `MismatchedNode` was a repeat: corpus-gen writes
the same bytes as `door-DuplicateOffset-bad_index-4-3`, and `MismatchedNode`'s
door is `door-MismatchedNode-compound-218-5` again (64 seeds, all 25 kinds
reached). TS has no separate name: its `MerklePath` throws `Duplicate offset`
(`MerklePath.ts:221`); Go keeps the later leaf.
### Changed: a BIP-39 phrase and passphrase are read in NFKD, as BIP-39 says (#163)

BIP-39 asks NFKD of a wordlist and seeds PBKDF2 with the NFKD mnemonic and the
NFKD passphrase (`bitcoin/bips@100ba872` `bip-0039.mediawiki:86-87,94-96`).
This crate's `NfkdNormalize` was a pass-through and `Language::word_index`
compared bytes against the NFC wordlists, so two things were wrong:

- **The lookup.** A phrase was read only in the files' form (NFC): an NFD phrase
  (Go's lists, a Trezor-style wallet's) was refused as `InvalidMnemonicWord`
  (`agre\u{301}able`, `a\u{301}baco`, every Korean word). Now
  `Mnemonic::from_phrase_with_language` NFKD-normalizes the phrase before it
  splits it and compares each word with the list's words in NFKD, so a phrase
  reads the same in NFC, NFD, NFKC or NFKD, and Japanese reads with U+3000 or
  an ASCII space (NFKD maps the one to the other). The words a `Mnemonic` keeps,
  and so `phrase()`, `words()` and `Display`, are the list's own (NFC, the files
  unchanged, digests unmoved), whatever form the phrase was read in. A token an
  NFKD decomposition splits (U+00B4 is a space and U+0301) counts as two words:
  `"<12 words>\u{b4}"` is `InvalidMnemonic("invalid word count: 13, ...")`,
  where it was `InvalidMnemonicWord`. An unknown word's error carries it in
  NFKD, lower-cased.
- **The seed.** `to_seed` hashed the phrase and passphrase as given, so a phrase
  with a character NFKD changes (366 French words, 644 Japanese, all 2048
  Korean, 334 Spanish; the Japanese U+3000 separator) or a passphrase not in
  NFKD seeded other bytes than BIP-39's. The 24 Japanese vectors of
  `bip32JP/bip32JP.github.io@5a43706` (`test_JP_BIP39.json`, the file BIP-39
  names at `:135`; public domain), now `tests/vectors/bip39_japanese.json`,
  failed on their seeds; they pass.

Migration: a caller that stored an NFD phrase and was refused is accepted now.
A phrase that was accepted reads to the same words and the same entropy, and
an English phrase with an ASCII passphrase (every TREZOR vector,
`tests/compat_bip39_tests.rs`, 29 green before and after) seeds the same
bytes. **A French, Japanese, Korean or Spanish phrase with a character NFKD
changes, or a passphrase NFKD changes, seeds different bytes from 0.9.0 on:
BIP-39's, as every other BIP-39 wallet derives them.** A key an earlier `bsv-rs` derived from such a phrase is a different key from
the one 0.9.0 derives, and 0.9.0 has no call that reproduces it. To reach it,
compute the earlier seed outside this crate (PBKDF2-HMAC-SHA512, 2048 rounds,
64 bytes, the password the phrase's bytes as `phrase()` printed them, the salt
`mnemonic` + the passphrase's bytes as given), or pin 0.8.x to sweep it, then
re-derive from the phrase. `unicode-normalization` 0.1 (MIT OR Apache-2.0, pure Rust)
joins the `compat` feature. Pinned by `tests/compat_bip39_nfkd.rs` (8 tests:
the NFD French, Spanish and Korean phrases accepted with BIP-39's seed computed
outside this crate, the 24 Japanese vectors read and seeded with their
passphrases, each with ASCII spaces too, the count a normalization changes,
an NFD passphrase seeding as the NFC one; seven red on `1be93d8`'s source; the
eighth, every list word its own NFKC form, is the premise of the lookup's byte
compare).

### Notes: cross-SDK parity (#163)

The TypeScript SDK NFKD-normalizes the phrase and passphrase for the seed
(`ts-sdk@9e3ede6` `src/compat/Mnemonic.ts:271-272`; `ts-stack@4d0ea63`
`packages/sdk/src/compat/Mnemonic.ts:425-426`) and looks words up by bytes
after splitting on the list's space (`:219-222`); it ships English only, so
its lookup decides nothing for the four lists. go-sdk@2ca481c does not
normalize: `NewSeed` hashes the raw bytes (`compat/bip39/bip39.go:256-257`),
and its lists are NFD, so Go refuses the NFC phrase this crate prints and seeds
a non-NFKD passphrase otherwise; the seeds agree where Go's input is already
NFKD.

### Changed: the fuzz crates are formatted and checked (#180)

The root has no `[workspace]`, so the fmt job's `cargo fmt --all -- --check`
never reached `fuzz/` or `fuzz/corpus-gen/`, and `fuzz_beef_parser.rs:73` had
drifted from rustfmt. Both crates are formatted (one tuple pattern rewrapped,
nothing semantic) and the job checks each by manifest path, as it checks the
ratchet and bench-compare tools.

### Changed: the fuzz_beef_parser corpus is what corpus-gen writes (#180)

#86's one reader refuses a repeated leaf offset as `MismatchedNode`, so the
`bad_index` row's mutation at byte 4 now reaches that door ahead of the
`compound` row's at byte 218: `door-MismatchedNode-bad_index-4-3` replaces
`door-MismatchedNode-compound-218-5`, the directory stays at 63 seeds, and
corpus-gen rerun into a clean tree writes it byte for byte. The 24 signed,
encrypted and Shamir seeds a rerun still moved are #180's item 1 (below).
encrypted and Shamir seeds a rerun still moves are #180's item 1. (Since the
repeat is `DuplicateOffset`, above, that seed is the new door's and the
compound row's is `MismatchedNode`'s again.)

### Fixed: the processor validates a request's arguments ahead of the wallet and its result after it, in the reference's rules and words (#216)

The keeper's ruling on #216 (2026-10-25). The reference's processor calls
`validateWalletArgs` after reading a request and before `#invokeWallet`
(`ts-stack@edf6e03` `WalletWireProcessor.ts:1407`, `:1434`, `:1461`, `:1488`,
`:1516`, `:1550`, `:1593`, `:1751`, `:1801`), and `validateWalletResult` on
the wallet's answer through `#invokeValidatedWallet` (`:2421-2431`); the outer
catch frames a refusal with its own words and its code when that is 2 to 8
(`:2379-2387`). This processor had neither: an argument the reference refuses
reached the wallet, whose refusal was framed as `Wallet operation failed`
(#202), and a result the reference refuses was written. The rules are in
`src/wallet/wire/validation.rs`; `tests/wire_processor_validation.rs` pins
each, the expected frames hand-assembled (12 of its 15 tests red before).

Arguments, `WERR_INVALID_PARAMETER`, code 6, `The <parameter> parameter must
be <mustBe>` (`validationHelpers.ts:77-79`), the wallet never called:

- the protocol name 5 to 400 bytes, `protocolID[1]` (`validateProtocol`,
  `:198-205`, through `validateStringLength`, `:348-356`: `at least 5
  length.`, `no more than 400 length.`), on getPublicKey, encrypt, decrypt,
  createHmac, verifyHmac, createSignature, verifySignature and
  revealSpecificKeyLinkage; `a_protocol_name_outside_5_to_400_bytes_is_refused_with_code_6`;
- the key ID 1 to 800 bytes, `keyID` (`:227`, `:1748`), on the same eight,
  after the protocol; `a_key_id_outside_1_to_800_bytes_is_refused_with_code_6`,
  `the_protocol_is_judged_ahead_of_the_key_id`;
- the privileged reason 5 to 50 bytes, then required when `privileged` is
  true (`validatePrivilege`, `:207-222`: `The privilegedReason parameter must
  be a value when 'privileged' is true`), on those eight, getPublicKey for the
  identity key and revealCounterpartyKeyLinkage;
  `a_privileged_reason_outside_5_to_50_bytes_is_refused_with_code_6`,
  `privileged_without_a_reason_is_refused_with_code_6`;
- verifySignature's signature at most 72 bytes, then canonical DER with both
  scalars in 1 to n-1 (`:1795-1804`, `isCanonicalDERSignature`,
  `Secp256k1Validation.ts:33-53`);
  `a_signature_past_72_bytes_or_not_canonical_der_is_refused_with_code_6`;
- the byte arrays (plaintext, ciphertext, data) at most 256 MiB
  (`validateByteArray`, `:146-177`), reachable only past the reference's
  frame bound; the module's unit test.

getHeaderForHeight's height is read as `readVarIntNumStrict` and refused
outside 1 to 2^32-1 in `#requireInteger`'s words, code 1, ahead of the
trailing-data check (`WalletWireProcessor.ts:1670-1675`, `:138-148`:
`Invalid getHeaderForHeight height: expected an integer from 1 to 4294967295,
received N`); a height above `u32::MAX` was `invalid height: expected at most
...` and 0 reached the wallet;
`a_header_height_outside_1_to_u32_max_is_refused_in_the_reference_words`.

Results, a plain `Error`, code 1, `Invalid <call> result <field>: expected
<expectation>` (`WalletResultValidation.ts:510-512`):

- getPublicKey's key an even-length hex string of 33 bytes that is a valid
  compressed key (`:2207-2209`, `:917-933`);
  `a_public_key_result_the_reference_refuses_is_refused_with_code_1`;
- createSignature's signature at most 72 bytes and canonical DER
  (`:2219-2225`); `a_signature_result_past_72_bytes_or_not_canonical_is_refused_with_code_1`;
- getHeight's height 1 to 2^32-1 (`:2293-2295`);
  `a_height_result_of_0_is_refused_with_code_1`;
- revealCounterpartyKeyLinkage's revelation time 1 to 64 bytes, the pattern
  `^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$` and a time `Date.parse` reads
  (`isoTimestamp`, `:992-999`), its verifier and counterparty the requested
  (`:2226-2241`); `a_counterparty_linkage_result_the_reference_refuses_is_refused_with_code_1`;
- revealSpecificKeyLinkage's protocol name 5 to 400 bytes, key ID 1 to 800,
  verifier the requested, counterparty the prover's key for self, the anyone
  key for anyone, the requested key otherwise, protocol and key ID the
  requested (`:2242-2281`);
  `a_specific_linkage_result_the_reference_refuses_is_refused_with_code_1`;
- encrypt's ciphertext and decrypt's plaintext at most 256 MiB (`:2210-2215`).

Not repeated where the reader or a type already refuses: the security level
(`read_protocol_id`), a key-related counterparty that is no point (`read_counterparty`, as the reference's decoder refuses it at `:2460`), the data-type flag and the 32-byte hash and HMAC
(`requests.rs`), the booleans, the `PublicKey`, `u8` and `[u8; 32]` result
fields; those refusals keep the reader's words, code 1. The two linkage
calls' keys and revealSpecificKeyLinkage's absent counterparty moved from
the reader to this step with #226 (the entry above). The thirteen stubs
are untouched (`the_thirteen_stubs_are_untouched`). getNetwork and getVersion
were answered by the processor from its own configuration and not checked;
#222 forwards and checks them (the entry above). The two linkage keys of revealCounterpartyKeyLinkage, revealSpecificKeyLinkage's verifier and its absent counterparty are refused at this crate's reader, code 1, where the reference refuses them in `validateWalletArgs`, code 6 (`validationHelpers.ts:1736-1738`, `:1744-1745`); #226 moves them.
are answered by the processor from its own configuration, not asked of the
wallet, and are not checked, where the reference asks its wallet and checks the
answer (`WalletWireProcessor.ts:1694-1730`; the network `mainnet` or `testnet`,
the version 7 to 30 bytes, `WalletResultValidation.ts:2299-2306`): the
processor's default version `0.1.0` is 5 bytes, a result the reference refuses,
and is neither this crate's version nor its wallet's (a follow-up issue).

`ProtoWallet` answers revealSpecificKeyLinkage for anyone with `PrivateKey(1)`'s
key, as the reference's does (`ProtoWallet.ts:235-240`), where it answered its
identity key, a result the check refuses
(`a_specific_linkage_for_anyone_names_the_anyone_key`, red before).
`ProtoWallet`'s placeholder height 0 is now the processor's refusal
(`test_roundtrip_get_height`, `test_process_go_get_height_request`). The
fixture recorder's `minimal` getHeaderForHeight request and getHeight answer
moved from height 0, which the reference refuses on both sides, to 1, the
smallest it accepts: a recording pins the writers' bytes on valid inputs, and
the refusals are `tests/wire_processor_validation.rs`'s. Four recordings moved
(`tests/fixtures/{wire,http_json}/{getHeight,getHeaderForHeight}.json`: the
wire's height byte `00` to `01`, the JSON bodies' `0` to `1`; F17 in
`docs/FIXTURES.md`). The result-vector test sends a call's own Go args vector where one exists, so a
linkage result answers the request it was made for; its table holds at 15.

Migration: a client of this processor that sent an argument the reference
refuses got `Wallet operation failed`, code 1 (or the wallet's success), and
now gets the reference's words and code 6; a wallet whose result the reference
refuses is now answered with the refusal, code 1, where its result was written.

### Fixed: the processor's error frame is the reference's: unknownError, `Wallet operation failed` for a wallet's error, the processor's own words for its own, the empty stack (#202)

### Added: `privileged`, `privileged_reason` and `seek_permission` on the seven key-related args types (#193)

`GetPublicKeyArgs`, `EncryptArgs`, `DecryptArgs`, `CreateHmacArgs`,
`VerifyHmacArgs`, `CreateSignatureArgs` and `VerifySignatureArgs` gain three
public fields, the reference's `privileged?: boolean`,
`privilegedReason?: string` and `seekPermission?: boolean`
(`ts-stack@edf6e03` `Wallet.interfaces.ts:663-672`, `WalletEncryptionArgs`,
which `GetPublicKeyArgs` extends; BRC-100 `wallet/0100.md` at `ed1b015`
names the three in getPublicKey's request at `:1987-1990` and seekPermission
in the six others' at `:2084`, `:2106`, `:2128`, `:2151`, `:2171`, `:2197`;
encrypt's at `:2107` at `5119a9b`): `privileged: Option<bool>` (absent read as
false), `privileged_reason: Option<String>`, `seek_permission: Option<bool>`
(absent read as true). Each type gains `Default` (every option absent, an empty
key ID and data, and for the types whose protocol is required the protocol the
reference writes for a getPublicKey that names none, `[0, "default"]`,
`WalletWireTransceiver.ts:761`). `ProtoWallet` reads neither field, as the
reference's ProtoWallet does not ("not concerned with privileged keys",
`ProtoWallet.ts:147`); it drops the linkage calls' pair the same way. The seven
types and their results move from `proto_wallet.rs` to `wallet/key_args.rs`;
their paths (`bsv_rs::wallet::EncryptArgs` and the rest) are unchanged. The
owner's word of 2026-10-25 (the 0.9.0 list).

Migration: a struct literal of any of the seven types needs the three fields
or `..Default::default()` (every literal of this crate's own code, doc
examples, tests, examples and fuzz support takes the latter; in `auth`,
`identity`, `kvstore` and `registry`, files at their ratchet line limit, a
`None` field the default covers is dropped beside it); the dependents' sites
are the captain's list.

### Fixed: the seven key-related requests carry the privileged pair and seekPermission; a request not read to its end is refused (#193)

`WalletWireTransceiver` wrote, and `WalletWireProcessor` read, the requests of
getPublicKey, encrypt, decrypt, createHmac, verifyHmac, createSignature and
verifySignature without the privileged flag, the privileged reason and
seekPermission, and the processor never asked that a request be read to its
end: a Go or TypeScript request was misread without an error (the privileged
flag `01` read as encrypt's plaintext length, as getPublicKey's forSelf, as a
signature call's data-type flag). getPublicKey's request was this crate's own:
identityKey an optional bool, an optional protocol (`255` for none), an
optional key ID behind the nil sentinel. The reference writes and reads the
key-related parameters as the protocol, the key ID, the counterparty, then the
privileged flag (an `i8`, -1 absent) and the reason (an `i8` length, -1 absent,
then its UTF-8 bytes) (`#encodeKeyRelatedParams` and `#encodePrivilegedParams`,
`WalletWireTransceiver.ts:1351-1376`, `:1448-1462`; `#decodeKeyRelatedParams`
and `#decodePrivilegedParams`, `WalletWireProcessor.ts:2564-2583`,
`:2465-2476`), each call's own fields after them and seekPermission last (an
`i8`; `WalletWireTransceiver.ts:926-1150`, `WalletWireProcessor.ts:1421-1592`);
getPublicKey's request is identityKey as a byte 0 or 1, then the privileged
pair alone for the identity key, else the key-related parameters (an absent
protocol and key ID written as `[0, "default"]` and `""`) and forSelf, then
seekPermission (`WalletWireTransceiver.ts:756-779`,
`WalletWireProcessor.ts:1386-1403`). Every call's reader ends in
`#assertRequestConsumed` (`:2433-2437`): `Wallet Wire <call> request contains
trailing data`. Go writes the same bytes (`go-sdk@2ca481c`
`wallet/serializer/{get_public_key,encrypt,decrypt,create_hmac,verify_hmac,create_signature,verify_signature}.go`);
BRC-100's request tables read the same (`wallet/0100.md:1975-1990`,
`:2084`, `:2106`, `:2128`, `:2151`, `:2171`, `:2197` at `ed1b015`); Go's
args vectors are the witness (`encrypt-simple-args.json`:
`0b 00 01 0d "test-protocol" 08 "test-key" 0b 01 0b "test reason" 04 01020304 01`).

Both sides move together (the readers in `src/wallet/wire/requests.rs`, the
writers through `write_key_related_params` and `write_privileged_params` in
`src/wallet/wire/mod.rs`). The processor refuses trailing data for every call
it reads: the seven, the two linkage calls, getHeaderForHeight and the five
calls with no parameters; the thirteen refusal stubs read nothing and keep
their refusal (docs/FIXTURES.md F1). The transceiver refuses a privileged
reason past 127 bytes, which the `i8` length cannot carry, before a byte is
sent (`Invalid privilegedReason length: expected 0 to 127 bytes, got N`). The
JSON substrate sends the three fields in the reference's names on the seven
calls, an absent one omitted (`HTTPWalletJSON` sends the args object as given).

The tests that pin it: `tests/wallet_wire_cross_sdk_tests.rs`
`every_go_args_vector_decodes_through_the_processor_to_its_json` (the seven
Go args vectors reach the wallet with every field of their json, the three
new ones included; the allowlist falls from 21 to 14, the passing rows rise
from 6 to 13), `the_transceiver_writes_the_seven_key_related_go_requests_whole`
(the transceiver's request over each vector's json is the vector's wire, every
byte; #199's trimming of the pair and the last byte is gone),
`a_request_with_a_byte_after_its_last_field_is_refused` (15 calls),
`the_go_hmac_and_signature_requests_read_as_their_json` (now on the whole
frame); `tests/wire_method_roundtrip_tests.rs`
`permission_field_tests` (the seven calls with the fields present and absent,
and the reason past 127 bytes refused); `src/wallet/substrates/http_json/key_requests.rs`
`create_signature_sends_the_permission_fields_in_the_references_names`. RED on
a scratch copy of the tip with the pair and seekPermission neither written nor
read and the trailing-data check removed (eight cross-SDK tests fail, the
seven vectors misread as `invalid boolean flag` or a reader underflow), on one
with the trailing-data check alone removed (`a_request_with_a_byte_after_its_last_field_is_refused`:
the trailing byte reaches the wallet), and on one with the JSON fields
dropped. The seven wire recordings and the seven HTTP JSON recordings under
`tests/fixtures/` are re-recorded in their own commits (the request bytes and
bodies move; the `full` case sets the three fields); the wire_codec bench's
layouts follow.

Migration: this crate's own transceiver and processor agreed with each other
on the old bytes and now agree on the reference's: one side from this release
against the other from bsv-rs 0.9.0 or older does not (an old processor reads
the new frames' privileged flag as a length or a flag and refuses or misreads
what follows; the new processor reads an old frame's data as the privileged
pair, or refuses its last bytes as trailing data). Upgrade both sides
together. A Go or TypeScript peer reads and writes the new frames.

### Fixed: the processor's error frame carries the wallet's bare words, unknownError and the empty stack (#202)

`WalletWireProcessor` wrote an error frame's message as `e.to_string()`, this
crate's `Display` with its class prefix (`wallet error: HMAC is not valid`,
`wallet error: createAction requires a full wallet implementation`), and its
code as 6 or 7 when a `WalletError`'s words held `invalid parameter` or
`insufficient funds`, else 1. The reference's outer catch
(`ts-stack@edf6e03` `WalletWireProcessor.ts:2370-2396`) writes the error's own
code when it lies in unsupportedAction to abortRefused (2 to 8), else
unknownError (1, `WalletError.ts:72`; `:2379-2384`); the error's own
`message`, or `Unknown error` when it has none, cut at
`MAX_WIRE_ERROR_MESSAGE_BYTES` = 4096 bytes (`:25`, `:2387-2393`); and the
stack as an empty string, a varint 0 (`:2395-2396`). Before the catch, every
wallet call goes through `#invokeWallet` (`:2402-2418`): an explicit wallet
error (a `WalletError`, or an error with a `WERR_` name, carrying a code 2 to
8) is rethrown with its words and code (`:2408-2416`); every other error is
replaced by `new WalletError('Wallet operation failed', unknownError)`
(`:2417`). The reference's client throws `new WalletError(errorMessage,
errorByte, stackTrace)` with the message as framed
(`WalletWireTransceiver.ts:136-153`).

The frame is now the reference's, in the keeper's division (2026-10-25):
(1) an explicit wallet error with a code 2 to 8 keeps its words and code: this
crate's `Error` carries no wallet code (#137), so no error is explicit today;
the processor's `explicit_wallet_code` is the one branch a coded error takes
when one exists, and no public type moves. (2) Every other error a wallet
returns is `Wallet operation failed`, code 1, `01 17 ... 00`, whatever its
variant (`WalletError`, `WalletBusy`, `WalletTransport`, `TransportFault`,
`ProtocolValidationError`, `InvalidCounterparty`, `HmacMinimalLengthKey`, any
other): the processor's `invoke_wallet` wraps every one of its thirteen wallet
calls, as `#invokeWallet` does, so a wallet's words (which can carry paths or
internal state) never reach the wire. (3) The processor's own errors keep
their words, code 1, as the reference's own throws outside the wrapper are
(`:2387`): its reading of the request (a frame fault, an unknown call, the
readers' refusals, a `WalletError` its words, another variant its `Display`
sentence), the three false verdicts of #197, the bare `HMAC is not valid`
(`:1520`), `Signature is not valid` (`:1597`) and `Wallet did not
affirmatively authenticate` (`:1637`), each thrown after `#invokeWallet` has
returned the wallet's answer (`:1517-1519`, `:1594-1596`, `:1633-1635`), and
the thirteen calls the processor refuses as needing a full wallet. The cut is
at the byte, as the reference's `subarray` cuts, inside a character too. The
wallet's own words are not logged: the crate has no logging facility (no
`log` or `tracing` dependency) and the processor logged nothing before; the
log line the ruling names waits on a word (a feature in `Cargo.toml` or a
public hook on the processor; the feature `tracing`, #212, above).

The tests that pin it: `tests/wire_error_frames.rs` (new, 5 tests; each frame
hand-assembled to `:2417` and `:2379-2396`): an un-coded wallet error
(`WalletError("anything")`) framed `01 17 Wallet operation failed 00` and read
back by the transceiver as `wallet error (code 1): Wallet operation failed`;
every wallet error variant (the words that chose 6 and 7, a 5,000-byte and an
empty message, a busy, a transport answer, a transport fault, a hex error, a
protocol and a counterparty refusal, the minimal-length-key HMAC refusal) the
same constant; a wallet erring on verifyHmac the constant where its false
verdict is the processor's words; the processor's own reader refusal its
sentence; the three false verdicts through the processor over a stub wallet,
byte for byte. The frame writer's unit tests in `processor.rs`: a 5,000-byte
message cut at 4096 (`fd 00 10`), the cut inside `é`, the stack field 0 (`01
00 00` for an empty message), a processor error that is not a `WalletError`
its `Display`. RED on `02da747` (the branch's pre-fold tip, `95707ac` after the rebase) (the wallet's words framed): the three
wallet-error tests; the processor's refusal and the verdicts passed there as
here. `tests/wire_method_roundtrip_tests.rs` `test_error_response_format`
asserts a stub's bare frame; `tests/wallet_wire_cross_sdk_tests.rs`
`a_false_verdict_is_answered_with_an_error_frame` and
`a_signature_data_type_flag_of_three_is_refused` and
`tests/wire_u32_field_bounds_tests.rs`
`a_header_height_above_u32_max_is_refused_not_truncated` the processor's bare
words. Sixteen recordings under `tests/fixtures/wire/` are re-recorded in their
own commits (`error_frames.json`'s three processor cases, now the constant;
the verifyHmac and verifySignature `minimal` cases and the thirteen calls the
processor refuses, the processor's bare words; docs/FIXTURES.md F15); the
wire_codec bench's error layout reads any message and did not move.

Migration: a consumer that matched an error frame's message over the wire
(`message.starts_with("wallet error: ")`, a wallet's own words, or the code 6
or 7 for those words) reads `Wallet operation failed` and code 1 for every
wallet error, and the processor's bare words for its own. This crate's own
`Display` is unchanged, and so is the transceiver's reading of a frame
(`WalletError("wallet error (code N): <message>")`): a caller of this crate's
transceiver against this crate's processor sees `wallet error (code 1): Wallet
operation failed` where it saw `wallet error (code 1): wallet error: <the
wallet's words>`, and `wallet error (code 1): HMAC is not valid` where it saw
`wallet error (code 1): wallet error: HMAC is not valid`.

### Notes: cross-SDK parity (#202)

go-sdk@2ca481c's processor writes no error frame: a failed call returns a Go
error (`error calling N: ...`, `wallet/substrates/wallet_wire_processor.go:94-96`)
to its transport; its `WriteResultFrame` writes a `wallet.Error`'s `Code` as
given, its `Message` uncut and its `Stack` as given
(`wallet/serializer/frame.go:71-87`). This crate follows the TypeScript
reference: the code mapped to 1 to 8, a wallet's un-coded error replaced by
`Wallet operation failed`, the message cut at 4096 bytes, the stack empty.
One divergence from the reference stands, with no reference text to match:
the thirteen calls this processor refuses as needing a full wallet
(`createAction requires a full wallet implementation`, ...) are this crate's
processor errors, framed in this crate's words, where the reference's
processor reads every call's arguments and hands it to its wallet. (The
second this note named, the processor's missing argument validation, is
withdrawn by #216.)

### Fixed: verifyHmac's request carries the raw hmac ahead of the data; the signature calls carry the reference's data-type flag (#199)

`WalletWireTransceiver` wrote, and `WalletWireProcessor` read, verifyHmac's
request as the key-related parameters, the data behind a varint length, then
the hmac behind a varint length; createSignature's as the data and the hash as
two optional byte fields (the nil sentinel for the absent one); and
verifySignature's as forSelf, the same two optional fields, then the signature.
The reference writes and reads verifyHmac's as the key-related parameters, the
32 raw bytes of the hmac with no length, then the data behind its varint length
(`ts-stack@edf6e03` `WalletWireTransceiver.ts:1048-1050`,
`WalletWireProcessor.ts:1502-1509`); the signature calls' as a data-type flag
byte, `1` then the data behind its length or `2` then the 32-byte hash, any
other value refused (`Invalid createSignature data type flag: expected 1 or 2,
received N`; `WalletWireTransceiver.ts:1082-1090`, `:1137-1144`;
`WalletWireProcessor.ts:1533-1543`, `:1576-1586`), verifySignature's signature
behind its length ahead of the flag (`:1135-1136`, `:1572-1573`). BRC-100 reads
the same (`wallet/0100.md:2149-2151`, `:2168-2170`, `:2192-2196` at `ed1b015`;
`:2172-2174`, `:2191-2193`, `:2215-2219` at `5119a9b`), and so does Go
(`go-sdk@2ca481c` `wallet/serializer/verify_hmac.go:28-31`, `:55-58`;
`create_signature.go:29-36`, `:60-71`; `verify_signature.go:36-47`, `:74-89`). Go's args vectors are the
witness: `verifyHmac-simple-args.json` carries the 32 bytes `323c46...` then
`04 0a141e28`, `createSignature-simple-args.json` ends `01 04 0b16212c 01`.
Both sides move together (the readers in `src/wallet/wire/requests.rs`); no
field of the three args types moves. The transceiver refuses both or neither of
`data` and the hash before it writes (`The data, hashToDirectlySign parameter
must be exactly one value`), as the reference's `validateWalletArgs` does
(`validationHelpers.ts:1777-1787`); `VerifyHmacArgs::hmac` is 32 bytes by its
type, the length the reference asks (`:1774`). The privileged pair and
seekPermission stay unwritten and unread: the args types have no field for
them (#193).

The tests that pin it: `tests/wallet_wire_cross_sdk_tests.rs`
`the_go_hmac_and_signature_requests_read_as_their_json` (the three Go args
vectors, their privileged pair taken out, reach the wallet with every field
this crate reads equal to the vector's json),
`the_transceiver_writes_the_go_hmac_and_signature_requests` (the
transceiver's request over each vector's json is the vector's wire save the
privileged pair and the last byte, seekPermission), and
`a_signature_data_type_flag_of_three_is_refused`;
`tests/wire_method_roundtrip_tests.rs` `reference_request_frames` (the
loopback frames of both data-type forms and verifyHmac's, and the
both-or-neither refusal). RED on `9a57561` (all six). The three vectors stay in
the every-args-vector allowlist (21 of 27, the count unchanged), each reason
narrowed to the privileged pair of #193. The three recordings under
`tests/fixtures/wire/` are re-recorded in their own commits (the request bytes
move; the responses are as #197 left them; docs/FIXTURES.md F14); the
wire_codec bench's layouts follow.

Migration: this crate's own transceiver and processor agreed with each other
on the old bytes and now agree on the reference's: one side from this release
against the other from bsv-rs 0.8.2 or older does not (an old processor reads
the new verifyHmac frame's hmac as the data's length; the new processor refuses
an old signature frame's opening byte as a data-type flag, or reads its data
from the wrong place). Upgrade both sides together. A caller that passed both
`data` and the hash through the wire (the old frame sent both, `ProtoWallet`
signing the hash) is now refused before a byte is sent; pass one.

### Fixed: seven result writers write the reference's bytes: the byte arrays alone, the verdicts as the error byte alone (#197)

`WalletWireProcessor` wrote encrypt's ciphertext, decrypt's plaintext,
createHmac's 32 bytes and createSignature's DER signature behind a varint
length, and verifyHmac's, verifySignature's and waitForAuthentication's verdict
as one byte after the error byte (`00 01`; `00 00` for a false verdict). The
reference writes the error byte then the bytes alone to the end of the frame
(`ts-stack@edf6e03` `WalletWireProcessor.ts:1443-1444`, `:1470-1471`,
`:1495-1496`, `:1559-1560`), and for the three verdicts the error byte and
nothing after it, answering a verdict other than true with an error frame
(`HMAC is not valid`, `:1520-1525`; `Signature is not valid`, `:1597-1602`;
`Wallet did not affirmatively authenticate`, `:1636-1643`). Its transceiver
reads the rest of the frame as the bytes (`WalletWireTransceiver.ts:953-957`,
`:988`, `:1093-1101`), createHmac's as exactly 32 (`:1019-1021`), and an empty
result as a true verdict, refusing a byte after the error byte
(`#requireEmptyResponse`, `:1053-1055`, `:1147-1149`, `:1870-1872`,
`:2027-2035`). BRC-100 gives the four results as a bare Byte Array where the
requests carry a VarInt length, and the two verifications "Nothing extra"
(`wallet/0100.md:2094`, `:2116`, `:2138`, `:2181`, `:2157`, `:2203` at
`ed1b015`; the same text at `:2117`, `:2139`, `:2161`, `:2204`, `:2180`,
`:2226` at `5119a9b`), waitForAuthentication's response data "None"
(`:2418-2420`, `:2441-2443`). Go's result vectors are the same bytes (`encrypt`
`00 0102030405060708`, `createHmac` `00 323c46...`, the three verdicts `00`).
The seven writers (now in `src/wallet/wire/results.rs`, beside #194's) write
those bytes; no field of the seven result types moves.

This crate's transceiver read the old bytes (a length ahead of the four, the
verdict from the byte after the error byte; waitForAuthentication alone read
nothing after the error byte and ignored the `01`), so it moves in the same
commit to the reference's reading: a reference processor's encrypt answer
was read with its leading ciphertext byte taken as a length, and its verdicts
refused on a missing byte.

The tests that pin it: `tests/wallet_wire_cross_sdk_tests.rs`
`the_seven_result_writers_write_the_vectors_wire_byte_for_byte` (the
processor's response to a wallet answering with each Go result vector's json is
the vector's wire, the error byte included),
`the_transceiver_reads_the_seven_vectors_wire_as_their_json`,
`a_false_verdict_is_answered_with_an_error_frame`, and
`every_go_result_vector_is_the_processors_wire_for_its_json` (15 of 27 pass;
the allowlist falls from 19 to 12, the refusal stubs of docs/FIXTURES.md F1;
the count is pinned); `tests/wire_method_roundtrip_tests.rs` `result_frame_tests`
(the loopback frames read to their last byte; the error byte alone a true
verdict, an error frame the error, `00 00`, `00 01` and a length-prefixed
HMAC refused). RED on `1661ce2` (11 of the 12 new tests; the error-frame
reader already held). The seven recordings under `tests/fixtures/wire/` are
re-recorded in their own commits (the response bytes move; the request bytes
do not; the `minimal` cases of verifyHmac and verifySignature, whose stub
answers `valid: false`, now record the error frame and the client's error;
docs/FIXTURES.md F13); the wire_codec bench's layouts follow.

Migration: a consumer of this crate's processor answering the reference's or
Go's transceiver read these seven responses wrong before and reads them right
now. This crate's own transceiver and processor agreed with each other on the
old bytes and now agree on the reference's: one side from this release against
the other side from bsv-rs 0.8.2 or older does not. A 0.9.0 processor's four
byte results reach this transceiver with the length byte at their head
(and createHmac's 33 bytes are refused), its verdicts (`00 01`, `00 00`) are
refused as `Wallet Wire <call> response has an invalid length`, never read as
true; a 0.9.0 transceiver reads this processor's byte results with their leading
byte as a length and refuses its verdicts on a missing byte. Upgrade both sides
together. `verify_hmac` and `verify_signature` over the wire no longer return
`Ok` with `valid: false`: a false verdict over the wire is that error,
`Error::WalletError` carrying the reference's words, as the reference's client
throws it (`WalletWireTransceiver.ts:1053-1055`, `:1147-1149`; this crate's
`ProtoWallet` already answered one with an error).

### Notes: cross-SDK parity (#197)

go-sdk@2ca481c writes nothing for a false verdict as for a true one
(`wallet/serializer/verify_hmac.go:71-73`, `verify_signature.go:102-104`,
`authenticated.go:36-38`) and reads any result as true (`:75-77`, `:106-110`,
`:40-44`); this crate follows the TypeScript reference, an error frame for a
false verdict and a byte after the error byte refused.

### Fixed: both linkage responses put the three keys ahead of everything (#194)

`WalletWireProcessor` wrote revealCounterpartyKeyLinkage's result as
encryptedLinkage, encryptedLinkageProof, the prover, verifier and counterparty,
then revelationTime, and revealSpecificKeyLinkage's as the two byte strings,
the three keys, the protocol, keyID and proofType. The reference writes the
three keys (33 bytes each) ahead of everything: then revelationTime behind its varint
length, encryptedLinkage and encryptedLinkageProof behind theirs
(`ts-stack@edf6e03` `WalletWireProcessor.ts:1761-1781`, read at
`WalletWireTransceiver.ts:818-836`); or the security level and the protocol
string behind its length, keyID behind its length, the two byte strings and
proofType as one byte (`WalletWireProcessor.ts:1811-1841`, read at
`WalletWireTransceiver.ts:890-908`). Go writes the same bytes
(`go-sdk@2ca481c` `wallet/serializer/reveal_counterparty_key_linkage.go:68-89`,
`reveal_specific_key_linkage.go:73-92`), and BRC-100 sections 9 and 10 list the
fields in that order (`wallet/0100.md:2052-2057`, `:2088-2095` at `5119a9b`).
Both writers (now `src/wallet/wire/results.rs`) write that order; no field of
`RevealCounterpartyKeyLinkageResult` or `RevealSpecificKeyLinkageResult`
moves.

The tests that pin it: `tests/wallet_wire_cross_sdk_tests.rs`
`the_counterparty_linkage_response_writes_the_three_keys_ahead_of_everything`
and `the_specific_linkage_response_writes_the_three_keys_ahead_of_everything`
(the processor's response to a wallet answering with Go's result vector's json
is the vector's wire byte for byte, the error byte included), and
`every_go_result_vector_is_the_processors_wire_for_its_json` (the 27 result
vectors the same way: 8 pass, 19 are an enumerated allowlist with reasons, 12
refusal stubs and 7 calls whose result writers differ from the reference's, a
finding not changed here: encrypt, decrypt, createHmac and createSignature
write a length ahead of the bytes, `WalletWireProcessor.ts:1444`, `:1471`,
`:1496`, `:1560` write the bytes alone; verifyHmac, verifySignature and
waitForAuthentication write a byte `01` the reference does not, `:1522-1525`,
`:1600-1603`, `:1641-1644`; the count is pinned; fixed by #197, above);
`tests/wire_method_roundtrip_tests.rs`
`test_roundtrip_reveal_counterparty_key_linkage_privileged` and
`test_roundtrip_reveal_specific_key_linkage_privileged` read both responses in
the reference's order to their end. RED on `164e0c3`. The recordings
`tests/fixtures/wire/revealCounterpartyKeyLinkage.json` and
`revealSpecificKeyLinkage.json` are re-recorded in their own commits (the
response bytes move; the request bytes stay as #191 left them).

Migration: a consumer of this crate's processor answering the reference's or
Go's transceiver read the response wrong before (the linkage's length and bytes
taken as the prover's key) and reads it right now. One speaking to this crate's
own side: none; this crate has no linkage reader (docs/FIXTURES.md F2), and a
hand-built reader of the old order must read the keys ahead of the rest.

### Fixed: the linkage requests carry the privileged parameters ahead of the keys (#191)

`WalletWireProcessor` read revealCounterpartyKeyLinkage's two keys at the
parameter bytes' start and handed the wallet `privileged: None`: a privileged
request's flag and reason were read as the start of the counterparty's key (Go's
vector, `09 00 01 0b "test-reason" 0294c4...`, was refused as an invalid point),
and the flag of a well-formed request was dropped. The reference writes and
reads the privileged flag (`i8`, -1 absent) and the reason (an `i8` length, -1
absent, then UTF-8) ahead of the counterparty and the verifier
(`ts-stack@edf6e03` `WalletWireTransceiver.ts:809-811`, `#encodePrivilegedParams`
`:1448-1462`; `WalletWireProcessor.ts:1739-1747`, `#decodePrivilegedParams`
`:2465-2476`), as Go does (`go-sdk@2ca481c`
`wallet/serializer/reveal_counterparty_key_linkage.go:15-27`, `:37-47`) and
BRC-100 section 9 lists them (`wallet/0100.md:2016-2019` at `ed1b015`,
`:2039-2042` at `5119a9b`). The processor reads that order now and passes the
flag and the reason through into `RevealCounterpartyKeyLinkageArgs` (`None`
for an absent one, as the reference's `undefined`); a reason length below -1 is
refused, as `#readOptionalInt8Length` refuses it (`:54-61`).

revealSpecificKeyLinkage had the same defect: the processor read counterparty,
verifier, protocol, key ID, and no privileged parameters; the reference reads
the key-related parameters (protocol, key ID, counterparty, privileged flag,
reason) then the verifier (`WalletWireProcessor.ts:1790-1797`, `:2564-2583`;
`WalletWireTransceiver.ts:874-883`; BRC-100 `wallet/0100.md:2045-2055` at
`ed1b015`). It reads that order now, the same way. The transceiver has no
method for either call (docs/FIXTURES.md F2), so it wrote no frame to move.

The tests that pin it: `tests/wallet_wire_cross_sdk_tests.rs`
`the_go_counterparty_linkage_request_reads_its_privileged_params_ahead_of_the_keys`,
`the_go_specific_linkage_request_reads_the_key_related_params_then_the_verifier`
and `every_go_args_vector_decodes_through_the_processor_to_its_json` (the 27
args vectors sent through the processor to a recording wallet and compared to
their json: 6 pass, 21 are an enumerated allowlist with reasons, 14 refusal
stubs and the 7 key-related calls whose privileged parameters the processor
does not read; the count is pinned), `tests/wire_method_roundtrip_tests.rs`
`test_roundtrip_reveal_counterparty_key_linkage_privileged`,
`test_roundtrip_reveal_specific_key_linkage_privileged` and
`a_linkage_privileged_reason_length_below_minus_one_is_refused`. RED on
`f39fddc`. The recordings `tests/fixtures/wire/revealCounterpartyKeyLinkage.json`
and `revealSpecificKeyLinkage.json` are re-recorded in their own commits (the
request bytes and the observed args move; the responses do not).

Migration: a consumer of this crate's processor that spoke only to this
crate's code (the fixtures, a hand-built frame) must now write the reference's
order; no transceiver of this crate wrote either frame. One that spoke to the
reference's or Go's transceiver now reads the request as they write it, where
before a privileged counterparty request was refused and a specific one was
misread. The responses of both calls still put the encrypted linkage ahead of
the keys, where the reference and BRC-100 put the keys ahead of it (F2): a finding,
not changed here.

misread. The responses of both calls put the encrypted linkage ahead of the
keys, where the reference and BRC-100 put the keys ahead of the encrypted data:
fixed by #194, above.

### Fixed: the wallet wire's readers refuse what the reference's readers refuse (#183)

The transceiver and `WireReader::read_wallet_certificate` read frames that the
reference's `WalletWireTransceiver` and `Certificate.fromBinary` refuse
(`ts-stack@edf6e03`). The keeper's reading (2026-10-25) is that the reader
refuses what the reference's reader refuses, at each cited line, as a typed
refusal, and that the writer never makes a frame the reference's reader
refuses. Every refusal below is an `Error::WalletError` in the reference's
words, and each is pinned by a test in `tests/wire_reader_strictness.rs`
(18 tests, 16 RED on the old readers):

- getHeaderForHeight: the transceiver refuses a result that is not exactly 80
  bytes after the error byte (`WalletWireTransceiver.ts:1903`,
  `#requireResponseLength` `:2027-2031`;
  `a_header_that_is_not_80_bytes_is_refused`). The processor refuses a
  wallet's header of another length, as the reference processor's
  `validateWalletResult` does (`WalletResultValidation.ts:2296-2297`;
  `the_processor_refuses_a_wallets_header_that_is_not_80_bytes`). Before
  this, it wrote whatever the wallet gave it.
- The certificate (one reader now: the transceiver's
  `parse_certificate_from_binary` calls `read_wallet_certificate`):
  - The subject and the certifier are 33 bytes that decompress to a point
    (`Certificate.ts:342`, `:347`, `assertCompressedPublicKey` `:135-142`;
    `a_certificate_subject_or_certifier_that_is_not_a_compressed_key_is_refused`).
  - The field count is a strict varint, at most 100,000 and at most a third of
    the bytes remaining, refused before a field is read (`:357-363`). Nine 0xFF
    are refused ("number too large to retain precision"), not read as an empty
    map (`a_certificate_field_count_past_the_maximum_or_the_bytes_is_refused`).
  - A field name is 1 to 50 bytes (`:367-370`;
    `a_certificate_field_name_outside_1_to_50_bytes_or_unsafe_is_refused`), is
    not `__proto__`, `constructor` or `prototype` (`:373`), and is never
    repeated (`:374`; `a_repeated_certificate_field_name_is_refused`).
  - A field value is at most 1 MiB (`:378-382`;
    `a_certificate_field_value_past_a_mebibyte_is_refused`).
  - The signature is at most 72 bytes and is parsed by the reference's
    `Signature.fromDER` checks (`:390-397`;
    `a_certificate_signature_that_is_not_der_is_refused`). It is kept as
    `toDER` re-encodes it (`:396`; `a_der_signature_is_kept_as_the_reference_re_encodes_it`):
    an R or S whose high bit is set and has no zero byte before it is read
    and kept padded.
- listCertificates:
  - The verifier's 33 bytes are a compressed point (`:1533-1542`,
    `#readCompressedPublicKey` `:2004-2008`;
    `a_list_certificates_verifier_that_is_not_a_compressed_key_is_refused`).
    The 0-or-33 length check of #177 is pinned there from the outside.
  - The keyring's present flag is 0 or 1 (`:1513`, `#readBooleanFlag`;
    `a_list_certificates_keyring_flag_other_than_0_or_1_is_refused`).
  - The keyring's count is a strict collection count, and its keys are 1 to
    50 bytes, safe and unique (`:1514-1531`, `#readRecordKey`,
    `#setUniqueWireRecordEntry`;
    `a_list_certificates_keyring_key_out_of_bounds_or_repeated_is_refused`).
- Discovery:
  - The trust byte is 1 to 10 (`:1710`;
    `a_discovery_trust_outside_1_to_10_is_refused`).
  - The public keyring and decrypted-field counts are `readVarIntNumStrict`
    counts bounded by the bytes remaining (`:1712-1717`, `:1730-1735`). Nine
    0xFF are refused, with no NIL sentinel
    (`a_nil_sentinel_or_overlong_discovery_count_is_refused`).
  - Both maps' keys are record keys (`:1718-1752`;
    `a_discovery_record_key_out_of_bounds_or_repeated_is_refused`). Before
    this, a repeated key overwrote the earlier one.
- The writer: `write_identity_certificate` refuses an identity certificate
  whose `certifier_info` is `None` or whose trust is outside 1 to 10, before
  any byte is written
  (`an_identity_certificate_with_a_trust_outside_1_to_10_is_refused_before_a_byte`).
  The reference's writer writes the trust byte unchecked
  (`WalletWireProcessor.ts:2520`), and its own reader then refuses the frame.
  This replaces #182's Go zero value for an absent certifier info (below).
  `wire_identity_certificate_writer.rs`'s
  `an_identity_certificate_with_nothing_optional_writes_empty_strings_and_counts`
  now pins the refusal, and the absent iconUrl, description and maps written
  as empty strings and counts under a trust of 1.
  #184's `wire_identity_certificate_roundtrip.rs` hand-assembles Go's zero
  value (which this writer no longer writes) and reads it back through
  `read_identity_certificate`; the transceiver refuses the same bytes.

`read_string_map` and `read_optional_string_map` keep their NIL sentinel, and
neither now has a caller that reads a frame the reference reads strictly. The
certificate fields read through `read_certificate_fields`.
`read_optional_string_map`'s one caller, `read_identity_certificate`, reads
the pre-#182 layout and is #184's. Two of the crate's own test certificates
carried a signature that is not DER (`deadbeef`, `[0xdd; 72]`) and now carry
`3006020101020101`. The shared vectors and #76's recordings are unchanged and
still read (`fixtures_replay`, `wallet_wire_cross_sdk_tests`). The processor's
proveCertificate and relinquishCertificate handlers read nothing; they are
stubs. Its linkage keys are read with `PublicKey::from_bytes`, which already
checks the point (pinned by
`the_processor_refuses_a_linkage_key_that_is_not_a_compressed_point`).
Migration: none. No public signature moved. A caller that wrote an identity
certificate with no certifier info or a trust of 0 now gets an `Err`, where
it used to get a frame the reference client refuses.

### Notes: cross-SDK parity (#183)

Go's `DeserializeIdentityCertificate` reads the trust byte unchecked
(`go-sdk@2ca481c` `wallet/serializer/identity_certificate.go:66`). This crate
follows the reference's reader (`WalletWireTransceiver.ts:1710`) and refuses
a trust outside 1 to 10. Go's reader also keeps a repeated map key and takes
a field count as a plain varint (`:68-87`). There is also one known gap with
TS on keys. TS's `Point.fromX` reduces an x at or above the field prime
modulo p before it solves for y (`Point.ts:365-367`). So a 33-byte key whose x
is p + k, for a k that is on the curve, is accepted there, while
`PublicKey::from_bytes` (k256) refuses it. Such a key is not the encoding of
any point that this crate or TS writes.

### Fixed: the transceiver reads certificate results as the reference writes them (#177)

A client on this crate's transceiver could not read a certificate that this
crate's writer wrote. `parse_certificate_from_binary` read BRC-100 section 19's
table order: type, subject, serial, certifier, outpoint, a length-prefixed
signature, then the fields. `WireWriter::write_wallet_certificate` writes the
order of the reference's `Certificate.toBinary` (`ts-stack@edf6e03`
`Certificate.ts:229-321`) and Go's: type, serial, subject, certifier, the
revocation txid and a varint index, the fields (sorted by name, varint count,
each a varint-length name and value), then the signature as the bytes
remaining. Fed the writer's frames, the reader answered `reader underflow:
need 97 bytes` for acquireCertificate, listCertificates and both discovery
calls. The keeper's ruling: the writer stays and the transceiver moves to those
bytes. Two more of its readers moved with it. listCertificates' verifier is a
varint length, 0 or 33, then 33 raw bytes rendered as hex, any other length
refused (`WalletWireTransceiver.ts:1533-1542`); the reader took it as a UTF-8
string. Discovery's certifierInfo name, iconUrl and description are plain
varint-length strings, an empty one length 0 (`WalletWireProcessor.ts:2507-2518`);
the reader took them as NIL-flagged strings. `tests/wire_certificate_frames.rs`
(eight tests) feeds each call the writer's frame, hand-assembled reference
bytes and the shared vectors, and checks that `Certificate::from_binary` reads
the certificate bytes the same way. Found by #138's lane. Migration: none. The
public types are unchanged, and a discovered certifier's `icon_url` and
`description` are now always `Some`, the string on the wire.

The fixture recorder's helper wrote listCertificates' verifier as text and the
discovery entries through `WireWriter::write_identity_certificate`. It now
writes the reference's bytes, and the four certificate recordings were
re-recorded in their own commit. `write_identity_certificate` itself departs
from the reference and from Go (`identity_certificate.go:12-49`): it writes a
present-flag byte before certifierInfo, NIL-sentinel optional strings, and the
keyring values as strings. It was left as it was (a writer, outside this fix);
the follow-up is #182, below.

### Fixed: the writer writes an identity certificate as the reference writes it (#182)

`WireWriter::write_identity_certificate` wrote the certificate behind its
length, then a present-flag byte, the certifier's iconUrl and description as
NIL-sentinel strings, and the keyring and decrypted fields as NIL-sentinel
string maps, the keyring's values as their base64 text. The reference's
`#serializeDiscoveryResult` (`ts-stack@edf6e03` `WalletWireProcessor.ts:2478-2558`)
and Go's `SerializeIdentityCertificate` (`go-sdk@2ca481c`
`wallet/serializer/identity_certificate.go:12-49`) write the certificate
behind its length, the name, iconUrl and description as plain varint-length
strings and trust a byte, the keyring as a count and varint-length key with
varint-length raw-byte value pairs, and the decrypted fields as a count of
string pairs; the shared vector agrees, and the transceiver reads those bytes
since #177. The keeper's word: the writer moves to them. An absent certifier
info, iconUrl, description or map is written as Go writes its zero value
(empty strings, trust 0, a count of 0); a keyring value that is not base64 is
refused (`WalletError`), as both references refuse it.

### Notes: cross-SDK parity

TS's reader refuses a trust byte outside 1 to 10 (`ts-stack@edf6e03`
`WalletWireTransceiver.ts:1710`, `#requireInteger(..., 'discovery trust', 1, 10)`),
and TS's type has no absent certifierInfo (`Wallet.interfaces.ts:877-881`,
trust `PositiveIntegerMax10`): the frame this writer makes for
`certifier_info: None` is one the reference client refuses, while Go's reader
accepts it (`identity_certificate.go:60-63`). The zero value is Go's choice
alone, and this crate follows it.
`tests/wire_identity_certificate_writer.rs` (five tests, RED on the old writer)
feeds the writer's bytes to the transceiver's discovery reader, compares them
with the reference's bytes assembled to the lines above and with the shared
vector's entry, and pins the absent case and the refusal. The three tests that
read the old layout back through `WireReader::read_identity_certificate`
(`encoding.rs`'s `test_identity_certificate_roundtrip`,
`wire_method_roundtrip_tests`' `test_identity_certificate_roundtrip` and
`test_identity_certificate_minimal_roundtrip`) left in their own commit. The
fixture recorder's helper calls the writer again; the recordings are
unchanged. Readers: no readers in LOW (no LOW worker reads this crate's
binary wallet wire; the tower signs through its signer binding, the monitor
reads over HTTP routes, the fleet's seats run the JSON substrate); this
crate's transceiver never read the old frame (it underflowed), the toolbox's
door is not on the wire, the CLI speaks JSON. Migration: none; a caller of
the writer gets the reference's bytes.

`write_identity_certifier`, `write_optional_identity_certifier` and
`write_optional_string_map` no longer have a writer in the crate that calls
them; they are public methods of `WireWriter` and stay (removing one is a
change of the public API's shape, the owner's word).
`WireReader::read_identity_certificate` and `read_optional_identity_certifier`
still read the old layout: no caller in the crate, outside this fix, the
follow-up filed as #184.

### Fixed: the identity-certificate readers read the reference's layout (#184)

`WireReader::read_identity_certificate` and `read_optional_identity_certifier`
still read the layout this crate's writer wrote before #182: a present-flag
byte, NIL-sentinel strings and maps, the keyring's values as base64 text. Fed
the writer's bytes or the shared vector's entry, they returned an error;
nothing in the crate called them and no test read the new bytes through them,
so nothing here saw it. They now read what
`write_identity_certificate` writes and the reference reads (`ts-stack@edf6e03`
`WalletWireTransceiver.ts:1702-1745`; go-sdk@2ca481c
`wallet/serializer/identity_certificate.go:51-100`), the same reading as the
transceiver's `parse_discovery_result`: the certificate behind its varint
length, name, iconUrl and description as plain strings, trust a byte, the
keyring as a count of varint-length keys and raw-byte values (base64 in the
struct), the decrypted fields as a count of string pairs. `read_identity_certifier`
reads the three strings and the byte the same way. The reference has no absent
certifier: Go's zero value, which the writer writes for `None`, reads back as
`Some` with empty strings and trust 0, never `None` (until #247, which refuses
its trust 0 as the reference does); an empty iconUrl or
description is `Some("")`, an empty map `None`. A byte length past the bytes
is `ReaderUnderflow`, and the capacities are bounded by the bytes remaining.
`tests/wire_identity_certificate_roundtrip.rs` (seven tests, six RED on the old
readers) reads back the writer's bytes, the zero value as the transceiver reads
it, the shared vector's entry to the vector's fields, and a keyring value whose
bytes are not UTF-8; it pins the overrun refusal and the old layout's bytes.
The tests that paired the old writer helpers with these readers moved with
them: `encoding.rs`'s `test_identity_certifier_roundtrip` and
`test_optional_identity_certifier_roundtrip` left (the new file covers them),
and `wire_method_roundtrip_tests`' `test_optional_identity_certifier_minimal_roundtrip`
reads the reference's bytes. Migration: a caller that read this crate's
pre-#182 bytes with these readers now gets `ReaderUnderflow` for them (other
contents can misread; none reads as written), and must read the reference's
layout, which `write_identity_certificate` writes (the deprecated pair
still writes the old bytes). None in LOW (the keeper's reading
on #182: no LOW worker reads this crate's binary wallet wire). The public
signatures are unchanged. TS's reader refuses trust 0 (the parity note under
#182 above); these readers, like the transceiver and Go's, accept it (as of
#184; the transceiver refuses it since #183, these readers since #247).
`write_identity_certifier` (whose bytes are the reference's only when iconUrl
and description are present), `write_optional_identity_certifier` and
`write_optional_string_map` have no caller in the crate and no frame of the
reference's wire to write: they are `#[deprecated]` since 0.9.0, each naming
its replacement (`write_identity_certificate` for the two certifier writers,
`write_string_map` with a count of 0 for an absent map), the keeper's reading
on #184 (2026-10-25). Their removal is the owner's word, in the window beside
the 0.9.0-beta.1 prerelease; a downstream building with `-D warnings` that
calls one sees the deprecation now (neither the toolbox nor the CLI names any
of the three, by a grep of both trees; the dependents job builds them against
the pins they carry, 0.8.x, not this tree).

### Fixed: getHeaderForHeight's processor writes the header with no length prefix (#178)

`WalletWireProcessor`'s getHeaderForHeight wrote a varint length (`0x50`)
before the 80 header bytes. This crate's transceiver read that byte as the
start of the header, so a client got an 81-byte header beginning `50` for every
height. The reference's processor writes the error byte and then the raw bytes
(`ts-stack@edf6e03` `WalletWireProcessor.ts:1687-1690`). Its transceiver
requires 80 bytes (`WalletWireTransceiver.ts:1903`), and BRC-100 reads "Byte
Array (80 bytes)" (`5119a9b` `wallet/0100.md:2478`). So the processor moved and
the transceiver stayed. `tests/wire_header_frame.rs` checks the processor's
frame against the shared vector's bytes byte for byte, and checks that the
transceiver reads both as the header, starting with the version.
`tests/fixtures/wire/getHeaderForHeight.json` was re-recorded in its own commit.
Found by #138's lane.

### Notes: cross-SDK parity (#177, #178)

BRC-100 section 19's certificate table (`5119a9b`) disagrees with the bytes
that the reference and Go exchange on two points: it puts the subject before
the serialNumber, and it puts a length-prefixed signature before the fields.
This crate follows the bytes, as `Certificate::to_binary` always did. Filing
the erratum on `bsv-blockchain/BRCs` is the owner's call. On getHeaderForHeight
the text and the bytes agree.

### Added: `verify_nonce` on a wallet's short HMAC is pinned (#139)

Tests only; nothing was wrong. #139 (found by #108's cold review) read the
comparison `hmac_result.hmac[..stored_len]` as a slice past the end when a
wallet answers fewer bytes than the nonce's stored tail. It cannot be: the
answer's type is `CreateHmacResult { hmac: [u8; 32] }` (since `dc51a43`), the
stored tail is 32 bytes (canonical) or 16 (legacy), and both substrates refuse
a short body before `verify_nonce` sees it, `WalletError("invalid HMAC length:
expected 32, got n")` (`HttpWalletJson::create_hmac`, `WalletWireTransceiver`).
`auth::utils::nonce::tests::a_wallet_answering_a_short_hmac_is_refused_and_verify_nonce_never_panics`
drives 0, 1, 15 and 31 bytes over a `wiremock` substrate for a canonical and
a legacy nonce: that error each time, no panic. TS's `verifyNonce` asks the
wallet's `verifyHmac`, whose `constantTimeEquals` reads a length difference as
a miss; Go's `VerifyNonce` copies the tail into a `[32]byte`. The stale nonce
row of `src/auth/CLAUDE.md` (it said 16 + 16 bytes) and `create_nonce`'s doc
name the canonical 48-byte form.

### Fixed: a signed message too short for its recipient form is refused (#173)

`messages::verify` checked only that a signature was at least 78 bytes, the
length of the anyone form (version 4, sender 33, marker 1, key ID 32, a DER of
at least 8). A signature naming a recipient key needs 110 (the recipient 33,
not 1): given the private key of the key it names, an 88-byte one sliced the
key ID past its end and panicked (`signed.rs:188`, `range end index 102 out of
range for slice of length 88`), an abort on wasm32. Once the recipient field is
read, the reader asks for the key ID and 8 bytes of DER behind it and refuses a
shorter signature with the error of the anyone form's check,
`MessageError("signature too short: expected at least 110 bytes, got N")`. A
named-recipient signature of 102 to 109 bytes, refused before by the DER
reader (`InvalidSignature("DER too short")`), is now refused by the length
check; every valid signature verifies as before (the vectors and
`a_valid_signature_at_either_form_still_verifies_after_the_length_check`).
Found by #140's target `fuzz_messages_signed`; pinned by
`a_signature_too_short_for_its_recipient_form_is_refused` (the issue's input),
`a_named_recipient_form_short_of_its_key_id_or_der_is_refused` (78, 101, 102,
109 and 110 bytes) and `an_anyone_form_short_of_its_key_id_or_der_is_refused`
(70, 77 and 78) in `tests/messages_tests.rs`.

### Notes: cross-SDK parity (#173)

TypeScript (`ts-sdk/src/messages/SignedMessage.ts`, `verify`) reads through a
`Reader` whose `read` returns what remains, so the short key ID is read short
and the empty DER throws in `Signature.fromDER`: a refusal with another text.
Go (`go-sdk@2ca481c` `message/signed.go`, `Verify`) slices `sig[counter :
counter+32]` with no bound and panics on the same input (and on any input under
70 bytes). This crate refuses it by length, as it refuses a short anyone form.

### Added: a fuzz target for each of the five readers of outside bytes that had none (#140)

Fuzz harness only; nothing under `src/` moved. `fuzz_messages_signed`
(`messages::verify`), `fuzz_messages_encrypted` (`messages::decrypt`),
`fuzz_bsm` (the BSM envelope's readers), `fuzz_bip39` (`Mnemonic`'s phrase,
binary and entropy readers in the nine languages) and `fuzz_shamir_backup`
(`KeyShares::from_backup_format`, then `recover_private_key`) each assert the
reader returns, and the writer's round trip: the same bytes where the writer is
deterministic (the BSM signer), the canonical form where the reader accepts
more than one spelling (a phrase, a share), and the input through the writer
and back where the writer draws a random key id or IV (the two message
formats). Their seeds come from `fuzz/corpus-gen` (the BIP-39 vectors of
`tests/compat_bip39_tests.rs`, the TypeScript SDK's BSM signature, the writers
with fixed test keys); the nightly runs eighteen targets. The signed-message
target's 30-second run found `verify` slicing past a short signature that names
the given recipient (`src/messages/signed.rs:188:22`), filed as bsv-rs#173 and
not skipped, so the nightly's job for it is red until the fix.

### Changed: the wire_codec bench measures the recorded frames (#138)

Benches and tests only; nothing under `src/` moved. `benches/wire_codec` built
its 28 calls' frames from a schema and values of its own, which no test held
to the transceiver: against #76's recordings, 99 of its 112 frames (28 calls,
request and result, two cases) differed, and the old layout could not read 13
of the 56 `full` frames (the certificate results' order and the identity
certifier's flag, the privileged reason's length byte, the wallet payment arm
of internalizeAction, the bool waitForAuthentication returns, the length
prefix of getHeaderForHeight's header). It now decodes and re-encodes the
recordings' `full` frames through per-call layouts in
`benches/wire_codec/support.rs`, which `tests/wire_codec_bench_bytes.rs` pins
to both recorded cases byte for byte. The 112 result ids are unchanged; their
numbers move with the bytes (a recorded counterparty is a real key, so a
request decode now pays its point decompression), and the macOS baseline's
wire_codec rows want re-recording on a quiet machine. Five of the layouts moved
with #177, #178 and #182's re-recordings (the listCertificates verifier's raw
bytes, the discovery entry's plain strings and raw keyring values, the header's
80 raw bytes); the pin holds byte for byte on the re-recorded frames.

### Added: a BEEF whose source links form a cycle is pinned (#160)

Tests only; no reader moved. `tests/beef_cycle.rs` (five tests) builds rings of
one, two and three transactions with the crate's writer. On the wire a raw
entry is named by its bytes' hash, so a ring is writable only by its input
fields; every reader refuses it `InputNamesNoElement` in every order, with and
without an unrelated BUMP, V1 and V2 and atomic, each call under a 5 s bound on
its own thread (the slowest of 199 calls measured 4.3 ms), never a panic.
`Transaction::from_atomic_beef` returns the subject with the named input
unlinked, as it does not judge the graph, and the subject does not verify. In
memory a ring is real (an entry keeps the txid it was read with, and
`BeefTx::tx_mut` can point its input at its descendant): the linker links each
entry once and stops, as `to_binary_atomic` does; `sort_txs`, given the ring in
the entry's cached `input_txids` as well (`tx_mut` leaves that list as it was
read), finds no input missing and holds every link not valid. The writer emits
the bytes each entry was read with, so the wire carries the chain, not the
ring. With the memo in
`Beef::add_input_proof` inserted after the descent, the in-memory ring of one
loops and the test fails at the bound. `docs/ARCHITECTURE.md`'s gap line names
the tests.

### Changed: `src/block/` has its working rules (#161)

Documentation only: `src/block/CLAUDE.md` (the public surface with the node's lines at bitcoin-sv v1.2.2 `879fc8b` and the test that pins each, the rules, the wasm32 note, the downstreams); the root `CLAUDE.md` counts fourteen modules with `block` in the dependency line and 28 module `CLAUDE.md` files under `src/`; `docs/ARCHITECTURE.md`'s HMAC invariant names the `wallet_brc56_hmac_tests` that pin it (#148) and its gaps lose those two items. No code, test or public item changed.

### Changed: a BUMP read alone is read by the BEEF reader's BUMP decoder (#167)

`MerklePath::from_binary`, `from_reader` and `from_hex` were a second BUMP
parser: they read a leaf flag by its bits, so a flag of 3 or 4 parsed where
the BEEF reader refuses `BadFlag`; they accepted an offset outside its level,
a carried node its children contradict and a level 0 with no hash; they cut a
height above a `u32` to its low 32 bits; and they named every refusal in
words of their own. They are now the decoder that reads a BUMP in a BEEF
(`Bump::read_alone`, crate-private, in `src/transaction/beef/in_memory.rs`:
the public `BeefDecoder` behind the header of a BEEF of one BUMP), with the
in-memory form the whole-BEEF reader keeps (`Bump::in_memory`, crate-private:
each level by offset, a height above a `u32` refused `RootNotCarried` at the
BUMP). The same flag reading, the same offset rule (a repeated offset is
`DuplicateOffset` at the second leaf's offset varint, above), the same tree-height
bounds, the same walk, and the stream's `Reason`s with their offsets counted
from the BUMP's leading byte, in the words of the BUMP the caller handed:
`merkle path error: invalid BUMP at byte N: Reason` (the stream's `Refusal`,
its public `offset` and `reason`; the words after "at byte" are the stream's,
whose own refusal of a BEEF reads `invalid BEEF`), the variant
`Error::MerklePathError` as before. A slice says its bytes are a BUMP:
`from_binary` and `from_hex` refuse a byte after the frame, `invalid BUMP at
byte N: TrailingBytes` at that byte's offset (the stream's refusal of a byte
that belongs to no field; the Lean's `trailingBytes`), where through 0.8.3
they read a prefix and dropped the rest. A reader reads one frame:
`from_reader` leaves the cursor after the BUMP and the bytes after it to the
caller, which is `@bsv/sdk`'s `fromBinary` (it wraps a reader,
`ts-stack@edf6e03` `MerklePath.ts:161-168`), so parity holds through the
reader form
(`a_byte_after_the_bump_is_refused_by_the_slice_and_left_by_the_reader`, red
on the lane's draft, where the slice read the prefix). The differential
asserts both on every input: the slice accepts exactly what the reader
accepts whole, and refuses `TrailingBytes` at the reader's end otherwise. No public item
was renamed, retyped or moved: a scratch crate naming every public item of
`transaction::merkle_path` (each fn at its exact signature, both structs by
literal and by pattern, the derives) compiles against 0.9.0 and this tree.

The differential `tests/merkle_path_two_readers_agree.rs` reads every BUMP
the tree holds (the fixtures' BUMPs and those of every BEEF in the fixtures,
vectors and Rust vector constants, the ts-stack corpus when
`BSV_CONFORMANCE_DIR` is set, the seeds of `fuzz_merkle_path` and the BUMPs of
`fuzz_beef_parser`'s, the lone-leaf and cost tests' hand-built BUMPs, flags 0
to 4, a lone leaf at height 2^32, and from each every prefix, three
single-byte changes at every byte and a byte appended) through the standalone
reader and through the BEEF reader on the bytes wrapped as a one-BUMP BEEF,
and compares the verdict, the kind and offset of a refusal, the bytes taken,
the height, the levels and the root from every hash of level 0. On 0.9.0's
tree, with the corpus: 53,875 inputs, 35,747 disagreements in 30 classes, of
which 34,825 are refusals in the standalone reader's own words (24 classes);
the rest are 332 inputs it accepted with a flag the BEEF reader refuses
(`BadFlag`), 34 with an offset outside its level (`OffsetOutsideTree`), 4
with a carried node its children contradict (`MismatchedNode`), 1 with no
hash at level 0 (`NoTxidAtLevelZero`), 83 above a `u32` height
(`RootNotCarried`), and 468 it refused (`Mismatched roots`) that the BEEF
reader accepts. Now, on the same inputs: 0, the BEEF reader accepting 18,126
of the 53,875. `fuzz_merkle_path` asserts the
same agreement on every input (60 seconds, 298,316 runs, no disagreement and
no crash).

The 468 are one shape: a duplicate leaf (flag `01`) at an even offset, a
left node, that a walk meets as the left child of a node it computes from the
level below. Through 0.9.0 `RootWalker` hashed an empty left hash there, so
the txids of one path climbed to two roots and the parse refused `Mismatched
roots`; the BEEF reader's walk, meeting the duplicate as the sibling of the
other txid's path node, paired that node with itself and accepted it. BRC-74
gives the duplicate flag as a right-hand optimization (`5119a9b`
`transactions/0074.md:41`, "skip encoding of far right leaves when
duplication of working hash would suffice"; `:71` and `:76`, "duplicate
working hash", the left node already in hand): at an even offset it has no
meaning in the tree, and it is refused on both paths. The decoder refuses its
flag, `BadFlag { byte: 1 }` at the flag's byte, on the stream, the whole BEEF
and a BUMP read alone (`BadFlag` names the byte that is wrong: the offset is
a legal one under flag `00` or `02`, `OffsetOutsideTree` names a leaf outside
its level, and a new `Reason` is a change to an exhaustive public enum, the
owner's word); `merkle_path_root`'s pre-pass refuses it in a BUMP held in
memory (`Beef::verify_structure`, `verify_valid`: `Kind::BadFlag`);
`MerklePath::new` and `new_unchecked` refuse it ahead of the walk
(`Duplicate at an even offset: N, at height: N`), a path accepted through 0.8.3 and refused now, additive within 0.x (a path built by hand puts the duplicate at the odd offset, the working hash's right, as every writer does; no corpus BUMP and no writer emits the even shape); and `RootWalker` computes no
node from a duplicate on the left (`Missing hash at height N, offset N`,
where the reference gives up), so `compute_root` on a struct built by hand
gives one root or a refusal, never two. The 468 are refusals on both paths,
with 2 more inputs whose even-offset duplicate is met only as a path node's
sibling (both readers accepted those at the lane's draft): 18,596 accepted
there, 18,126 now. `an_even_offset_duplicate_is_refused_by_both_readers_at_its_flag`
(at level 2 and at level 0) and `an_even_offset_duplicate_held_in_memory_is_refused`
were red on the draft (both parsed, `new` accepted, the struct had one root).
The in-memory differentials of `merkle_path.rs` carry the ruling in their
0.3.34 rescan, as they carry the lone-leaf one.

The refusals that moved, by test:

- `tests/merkle_path_lone_leaf.rs`: `lone_at_one_parsers_refuse_missing_sibling`
  and `beef_and_merkle_path_agree_on_both_owned_bodies` read the parse's
  refusal of a lone leaf at offset 1 as `invalid BUMP at byte 7:
  MissingSibling { level: 0, offset: 0 }` (it was `MissingSibling { level:
  0, offset: 0 }` alone); `lone_compute_root_refuses_every_nonzero_offset_class`
  reads a lone leaf at offset 2 and above as `OffsetOutsideTree { level: 0,
  offset }` at byte 7 (it was `MissingSibling` with the sibling's offset).
  `MerklePath::new`, `new_unchecked`, `compute_root` and `combine` keep
  their texts.
- `merkle_path.rs`'s `the_parse_matches_the_rescan_except_the_ruled_lone_leaf`
  asserts that what the parse accepts the 0.3.34 parse accepted, to the same
  roots and bytes, and that every refusal is the decoder's (587 parsed, 87
  refused that 0.3.34 parsed); through 0.8.3 it asserted the same verdict.
- Every other refusal named in the list above moved from the standalone
  reader's words (`Path cannot be empty`, `Invalid tree height: N, over the
  maximum height 64`, `Duplicate offset: N, at height: N`, `Missing hash at
  height N, offset N`, `Mismatched roots`, `reader underflow: ...`,
  `non-canonical varint: ...`) to the stream's; no test asserted one, and
  `a_tree_height_over_64_is_refused_naming_it` passes on
  `TreeHeightOver64 { height }`.

The harness (`bsv-script-lean` at `8840488`, a scratch copy whose
`harness/Cargo.toml` names the tree by path): the seed corpus GREEN before
(0.9.0's tree) and after, 10,000 of 10,000 agreeing and 0 witnesses on both.
`run_wire` on `corpus/wire/bump.jsonl` (35 rows) against the spec's column
(`docs/records/20261015-110609-s7-86-wire-views-s1-spec.jsonl`): `bump-027`
(flag 03) and `bump-028` (flag 04) are now refused, as the spec's codec
refuses them, and close. `bump-031` (a height of 2^32 plus 900,000, which the
spec's codec reads) moves from an `objects` witness (the height cut to
900,000) to a `codec` one: the in-memory height is a `u32`, and the parse
refuses the BUMP as the BEEF reader has since #86. `bump-032` (a byte after
the BUMP; `run_wire` reads it with `from_binary`) is now refused on the slice,
`TrailingBytes`, as the spec's codec refuses it, and closes; it stays a
`codec` witness for go-sdk and ts-sdk, whose readers are prefix readers. The
reader's prefix read (`from_reader`, the cursor one short of the end) is its
own row for the harness to add; this crate's test pins it. The census (`tools/ratchet/run`):
`src/transaction/merkle_path.rs` 1,470 to 1,465 lines, `beef_stream.rs`
3,617 unchanged (the even-offset refusal is the flag match's arms, keyed by
the offset's parity), every counter unchanged (`duplicate_windows_40` holds at
8,666: the old flag reader was not a window of the decoder's).

### Notes: cross-SDK parity (#167)

TS has one BUMP reader, the `MerklePath` constructor behind `fromReader`
(`ts-stack@edf6e03` `packages/sdk/src/transaction/MerklePath.ts`): it reads a
leaf flag by its bits (`:133-140`), refuses a repeated offset as `Duplicate
offset` (`:221`), and by default refuses a leaf above level 0 at an offset no
txid's path needs (`legalOffsetsOnly = true`, `:161-168`), which neither of
this crate's readers refuses. A duplicate at an even offset: TS refuses it at
construction where a walk computes a node from it (`cachedFindLeaf` gives up
on a left duplicate, `:628-631`, and `nextCachedHash` throws `Missing hash for
index N at height N`, `:58`; `findOrComputeLeaf`, `:437`, is the `computeRoot`
path), and pairs the working hash with itself where the duplicate is the
working hash's sibling (`:60`); Go's reader accepts the bytes and
`ComputeRoot` errors for the txid whose walk computes a node from it
(`go-sdk@2ca481c` `transaction/merklepath.go:47-50`, `:396-397`), pairing it
met as a sibling (`:399-400`); this crate refuses the parse on both paths. (Reversed in
Unreleased by the re-read of #167 on 2026-10-26: read as the reference reads
it, `LeftDuplicateBelow` where its walk gives up.)
BRC-74's own walk (`transactions/0074.md:326-345`) synthesizes no node and
throws for one the level does not carry (`:335`): it is silent on a computed
node, it does not rule it. The refusal is a tightening past the BRC's silence consistent with the reference. The stack's Lean has the self-pair today (`climb`,
`BeefOfAnySize.lean:509-520`) and corrects it in its own lane, with the
`duplicateOffset` row. Go keeps the later of two leaves at one offset
(`go-sdk@2ca481c` `transaction/merklepath.go:87-90`); this crate refuses the
second, on both of its readers. TS's `fromBinary` and Go's
`NewMerklePathFromBinary` (`merklepath.go:189-194`, a reader over the bytes)
read a prefix of the bytes they are handed; this
crate's `from_binary` refuses a byte after the frame and its `from_reader`
reads the prefix. The slice's refusal is a tightening past every reference, taken from the charter's one bound and its `trailingBytes` refusal, with the reader form as the parity path.

### Changed: the interpreter is split by opcode group (#85)

`src/script/spend.rs` (4,419 lines) is the directory `src/script/spend/`:
`mod.rs` keeps `Spend`, its parameters, `validate`, `step` and the dispatcher
(one static `match`, each arm a direct call to a `pub(super)` method); the
handlers live in `push`, `flow`, `stack_ops`, `splice`, `bitwise`,
`arithmetic` and `crypto`, the stack and its memory count in `stack`, the
budgets and their `ScriptResourceLimit` declines in `limits`, the
script-number reads in `num`, the flag word's setters in `word`, and the six
unit-test modules in files of their own. A refactor: no verdict, error text,
budget or flag site changed, and no public item moved
(`bsv_rs::script::spend::{Spend, SpendParams, TxSpendParams}` and every
public method keep their paths and signatures). The sibling's harness
(`bsv-script-lean` at `8840488`, `harness/run --impl bsv-rs`) is GREEN on all
nine corpora before (run `20261024-215622`) and after (`20261024-222200`),
the per-corpus counts and witness files identical; the ts-stack corpus
totals in `tests/conformance_scripts.rs` and the script witnesses are
unchanged. The census falls: no file over 800 lines under `src/script/spend/`
(40 to 39 files), cognitive complexity over 25 from 2 to 1 (the dispatcher's
52), duplicate windows 8,726 to 8,723, pedantic warnings 2,678 to 2,676;
functions over 60 lines stay 93. The nightly's mutation surface
(`src/script/**/*.rs`) already covers the new files and no per-file floor
named `spend.rs`.

### Changed: the whole-BEEF reader is a mode of the streaming reader (#86)

Two readers were two parsers: `Beef::from_binary` (with `from_hex`,
`from_reader`, `from_binary_with_limits`, and through it
`Transaction::from_beef` and `from_atomic_beef`) read a BEEF with its own
`Reader` code, `MerklePath::from_reader` and `BeefTx::from_reader`, while
`beef_stream` read it with `BeefDecoder`. They disagreed. The differential
`tests/beef_two_readers_agree.rs` feeds every BEEF the tree holds (the
fixtures, the vectors, the Lean's 49 rows, the fuzz seeds, the ts-stack
corpus when `BSV_CONFORMANCE_DIR` is set, a deep chain, and from each of
them every prefix, three single-byte changes at every byte and the
transactions in reverse order) to `Beef::from_binary` then
`Beef::verify_structure`, and to `verify_stream_structure`. On 0.9.0's tree,
with the corpus (`BSV_CONFORMANCE_DIR` set, as the gate requires): 64,828
inputs, 30,153 disagreements in 90 classes, beside 31 inputs of the order
class the draft's differential set aside. Now, on the same inputs: 0, and no
stated difference.

The whole reader is the streaming reader's decoder in a collect mode
(`BeefDecoder::collecting`, crate-private): `src/transaction/beef/collect.rs`
builds the `Beef` from the decoder's elements in one pass, the BUMPs by
`Bump::to_merkle_path` (each level's leaves by offset, as before), the
transactions from the bytes the decoder read, in the order written. One
parser, one set of bounds, one set of refusals. The collect mode yields a
transaction whatever its content and keeps the decoder's refusal of it
beside the collection, so a BEEF whose bytes are a frame still parses and
`verify_structure` judges it, as it has since 0.4.1; each element is also
folded into a structure-only `BeefIndex`, so a BEEF whose bytes are refused is
refused with the stream's verdict: the earliest refusal of the reading.
`verify_structure` judges the entries in the order held, one pass, as the
decoder and the fold judge them (`src/transaction/beef/in_memory.rs`: the
stream's `bump_root` on a `MerklePath`, its `check_transaction` on a
`BeefTx`, the atomic table). `beef.rs` keeps the type, the writers, the
merges and the public functions; `merkle_path_root`, `wire_hash` and
`Bump::to_merkle_path` moved from `beef_stream.rs` to `in_memory.rs` (the
method's path is unchanged). No public item was renamed, retyped or moved: a
scratch crate naming every public item of `beef`, `beef_stream` and
`beef_tx`, each fn at its exact signature, each pub-field struct by literal,
each enum matched exhaustively, compiles against 0.9.0 and this tree.

What moved, each where the readers disagreed and the whole path now says
what the stream said:

- **The text of a parse refusal is the stream's**: `BEEF error: invalid BEEF
  at byte N: Reason`, the variant `Error::BeefError`, for every BEEF whose
  bytes are no frame. Through 0.9.0 the whole reader answered
  `Error::ReaderUnderflow`, `BeefError("Invalid BEEF version: 0x...")`,
  `MerklePathError(...)` ("Path cannot be empty", "Missing hash at height",
  "Invalid tree height", "Duplicate offset", `MissingSibling { .. }`),
  `CryptoError` ("non-canonical varint", "exceeds maximum usize"), with no
  offset. Migration: match `Error::BeefError(m)` and read the offset and the
  kind from `m`. The three tests that asserted the old text moved to the
  stream's in their own commit:
  `a_claimed_count_is_refused_for_the_bytes_and_reserves_nothing`
  (`beef_limits`: `ReaderUnderflow`, now `Truncated { needed: 1 }` at the
  byte the entry that was due), `beef_and_merkle_path_agree_on_both_owned_bodies`
  (`merkle_path_lone_leaf`: `MerklePathError("MissingSibling ...")`, now at
  byte 12), `the_whole_path_refuses_a_lone_leaf_at_an_offset_other_than_0`
  (`beef_stream`).
- **Refused by the parse, read before**: a V2 format byte other than 0, 1
  or 2 (read as a raw transaction), a V1 has-BUMP byte other than 0 or 1
  (read as "a BUMP index follows", the index the next varint), a BUMP leaf
  flag other than `00`, `01` or `02` (read by its bits): `BadFlag`; a leaf
  offset outside its level: `OffsetOutsideTree`; a BUMP above a `u32`
  height, which was cut to its low 32 bits and its root keyed there:
  `RootNotCarried` at the BUMP, the stream's refusal under a chain's headers
  (the in-memory height is a `u32`;
  `a_bump_above_a_u32_height_is_refused_not_cut_to_its_low_bits`, red on
  0.9.0). Under a `Headers` implementation that answers for a height above
  `u32` (the fuzz target's `EveryRoot`), the stream accepts a BUMP the whole
  path refuses; no chain has such a height, and the differential and the
  fuzz target mask it with `leading_roots`, which keeps a chain's heights
  only.
- **Refused by `verify_structure`, accepted before**: the node's rules on a
  transaction's content, which the stream applies since 0.5.0 (bsv-stack-lean
  #68) and the
  whole path never did: an unproven coinbase, a value or a running total
  outside `MoneyRange`, a null outpoint in a regular transaction, a repeated
  outpoint (`UnprovenCoinbase`, `ValueOutOfRange`, `NullOutpoint`,
  `DuplicateInput`).
- **A repeated leaf offset, refused on both paths**: a BUMP level that
  carries a second leaf at an offset, agreeing with the earlier one or not,
  is `DuplicateOffset { level, offset }` (above; `MismatchedNode` on the branch) at the second leaf's offset varint
  (the decoder refuses it as it reads the offset; `merkle_path_root` refuses
  one held in memory ahead of the walk). Through 0.9.0 the whole reader
  refused it as `MerklePath::new_unchecked`'s "Duplicate offset", naming no
  byte, and the stream let the earlier leaf stand, accepting a repeat its
  walk accepted (the same hash, a flag-`01` leaf after a hash, a higher
  level's sibling); the lane's draft accepted it on both. The stack's Lean
  names the refusal `duplicateOffset (level, offset)`; `Reason` and `Kind`
  are exhaustive public enums (no `#[non_exhaustive]`,
  `Kind::ALL: [Kind; 24]`), so no variant is added here: a new one is the
  owner's word. Red before the fold:
  `a_level_0_leaf_repeated_with_the_same_hash_is_refused_on_both_paths`,
  `a_level_0_leaf_repeated_with_a_different_node_is_refused_on_both_paths`,
  `a_higher_level_leaf_repeated_is_refused_on_both_paths`,
  `a_repeated_leaf_offset_in_a_bump_held_in_memory_is_refused_by_verify_structure`
  (`beef_two_readers_agree`).
- **Refused by `verify_structure`, accepted before: a transaction written
  ahead of the parent it spends.** The order is BRC-62's, parents before
  children (`5119a9b` `transactions/0062.md:43,74`; the charter's validity
  clause), as the stream reads it: an input of an unproven transaction that
  names an entry held after it is `InputNamesNoElement`, judged in the order
  held, before `sort_txs` runs. Through 0.9.0 (and the lane's draft)
  `verify_structure` sorted ahead of judging and accepted it, or named the
  next fault. The tests that asserted acceptance moved in their own commit:
  `a_reversed_deep_chain_sorts_in_linear_time_on_a_small_stack`
  (`beef_deep_chain`), now
  `a_reversed_deep_chain_is_refused_and_sorts_in_linear_time_on_a_small_stack`,
  and the differential's exemption of the class (30 inputs without the
  corpus, `fixtures/beef/v1.json#0 reversed` among them, which disagreed
  before the fold).
  `a_transaction_written_ahead_of_its_parent_is_refused_on_the_whole_path`
  (`beef_two_readers_agree`), red before the fold.
- **The kind named when a BEEF holds two faults** is the one the stream
  meets earliest: the parse's for an earlier element's content or fold, and
  `verify_structure`'s in the order held (through 0.8.3: no input before any
  BUMP index, every stub before any BUMP index, every BUMP index before any
  input).

`fuzz_beef_parser` drives both entry points on every input and asserts they
agree: 60 seconds, 178,958 runs, no disagreement and no
crash.

The cost, against 0.9.0's tree run beside it: `Beef::from_binary` alone 16
to 20 percent faster, and parse then `verify_structure` 12 to 16 percent
faster (3.10 to 3.26 ms against 3.67 to 3.82 ms at 1 MB, 32.6 to 34.2 ms
against 37.7 to 38.8 ms at 10 MB), on the `benches/beef_stream.rs` fixtures,
p50 of 30 runs, three rounds interleaved, load average 9.8 to 10.3. The
node's transaction rules the whole path never ran were not the cost: the lane's
draft measured 10 to 13 percent slower than 0.9.0 because the collector left
each entry's txid unset, so every `txid()` in `verify_structure` (once per
entry for the fold, several times per entry in `sort_txs`, once more for the
atomic table) serialized and hashed the transaction again. The collector now
keeps the hash the decoder computed as the bytes passed (`BeefTx::with_txid`,
crate-private): parse then `verify_structure` went from 3.90 to 4.10 ms and
40.7 to 41.7 ms to the figures above. The streaming reader's bench
(`beef_stream`, 1 MB and 10 MB, structure and scripts), re-run after the
repeated-offset refusal at load average 7.3 to 9.5: 0.3 to 3.4 percent above
the draft's run at load 4.3 to 5 (1.345 ms against 1.300 ms for the 1 MB
structure, the widest), the fixtures' one BUMP holding one leaf.

### Fixed: a read BEEF entry names each input txid once (#86)

`BeefTx::update_input_txids` appended without clearing, and the reader
called it twice for an unproven raw transaction (`from_raw_tx`, then again
once the parse was set): `BeefTx::input_txids` named each parent twice and
`SortResult::missing_inputs` a missing parent twice; a second
`set_bump_index` did the same. Each call now computes the list afresh.
`a_read_entry_names_each_input_txid_once` (`beef_tx`), red on 0.9.0.

### Notes: cross-SDK parity (#86)

The whole-BEEF path follows the streaming reader where the reference does
not (CLAUDE.md's divergence list, 0.4.2); the merge adds the stream's
existing rules to it where TS reads otherwise (`ts-stack@4d0ea63`): TS
reads any V2 format byte other than 2 as a raw transaction
(`packages/sdk/src/transaction/BeefTx.ts:293-301`), any nonzero V1 has-BUMP
byte as "a BUMP index follows" and the index from the next varint (`:306`,
at `edf6e03` and `4d0ea63`), and a leaf flag by its bits
(`MerklePath.ts:133-140`), where both readers here refuse `BadFlag`; TS's
`verifyValid` does not apply the node's transaction rules. A repeated leaf
offset: TS refuses it as it builds the `MerklePath` (`MerklePath.ts:221`,
`Duplicate offset`, at `edf6e03` and `4d0ea63`), Go accepts it with the later
leaf standing (`go-sdk@2ca481c` `transaction/merklepath.go:87-90`), and this
crate refuses it on both paths.

The order of the transactions is BRC-62's on both paths. TS's `verifyValid`
sorts before judging (`ts-stack@edf6e03`
`packages/sdk/src/transaction/Beef.ts:1065`, `sortTxs`), and so does Go's
(`go-sdk@2ca481c` `transaction/beef.go:1240-1243`, `ValidateTransactions`):
both accept a transaction written ahead of its parent, the reference's
leniency against the BRC's "must". This crate refuses it on both paths, by
the charter (`InputNamesNoElement`); the stack records the divergence row
(child before parent, two transactions).

### Changed: the BIP-39 wordlists are data, not code (#89)

The nine `src/compat/bip39/wordlists/<language>.rs` tables (11,055 lines of
string literals) are nine text files, `<language>.txt`: one word per line,
2048 lines, LF. Each `pub static` (`ENGLISH`, `JAPANESE`, ...) keeps its name
and its type `[&str; 2048]`; its initializer is now a private `const fn` over
`include_str!` of the file, so the arrays are built by the compiler as before
(no build script, no lazy initialization, nothing at runtime), and a file with
another line count, an empty line, a CR or no final LF fails the build. No
public item moved; no word changed: the files are the old arrays byte for
byte, pinned by sha256 in `tests/compat_bip39_wordlist_files.rs`.
`.gitattributes` keeps the files out of line-ending conversion. The ratchet's
path exemption for the nine `.rs` files went with them (`tools/ratchet`; the
census reads `.rs` only, so no counter moves). `verify_english_wordlist`
gains `#[must_use]` (additive; a caller that drops its `bool` now gets a
warning), which offsets the one pedantic warning the parser's local array
adds, so the pedantic census stays where it was.

### Notes: cross-SDK parity

The English, Chinese Simplified, Chinese Traditional, Czech and Italian files
are byte-identical to `bitcoin/bips@100ba872` `bip-0039/`. Upstream's French,
Japanese, Korean and Spanish files are Unicode NFD, as the Go SDK ships them
(`go-sdk@2ca481c` `compat/bip39/wordlists/{french,japanese,korean,spanish}.go`,
its `init` checking upstream's crc32) and as BIP-39 asks of a wordlist
(`bip-0039.mediawiki:86-87` at that commit: NFKD); this crate's arrays have
always been their NFC form, and the files keep that, a refactor carrying no
behavior change. The behavior it keeps: `Mnemonic::word_index` compares bytes,
so an NFD phrase from Go or a Trezor-style wallet is refused here as
`InvalidMnemonicWord` and never reaches `to_seed`. The fix, normalizing both
sides of the lookup, changes what a phrase is and waits on the owner's word
(the follow-up issue in CLAUDE.md's divergence list); #163 above is that fix,
and found `to_seed`'s NFKD a pass-through too.

### Changed: the transport fault typed end to end (#87)

0.8.2 (#73) typed the bare 502, 503, 504, connection error and timeout in
`HttpWalletJson` only. Every other transport classified a failure by where it
happened, not by what it meant: every broadcaster send error was
`NETWORK_ERROR`, so a wallet could not tell a refused connection (the inputs
may be released) from a timeout after the transaction was written (the stub
relayed it: the inputs must be held; witness #65, W-SDK-1); each broadcaster
decoded the body before it read the status, so a 429 with a `text/plain` body
was `PARSE_ERROR` and its `Retry-After` was read nowhere (witness #66,
W-SDK-2); the auth transports answered `AuthError(String)` for a fault.

One classifier (`src/transaction/broadcasters/transport_fault.rs`,
`pub(crate)`) reads a `reqwest::Error`'s kind and an answer's status, before
the body, into the class `TransportFault` (new, `#[non_exhaustive]`,
re-exported at the crate root and from `transaction`): `NeverSent` (no byte
left: a connection never made, a request that could not be built),
`MayHaveBeenReceived` (a timeout, a reset or a body cut after the request was
written, a 502, 503 or 504), `RateLimited { retry_after_ms }` (a 429, or a 503
with `Retry-After`, whatever the body; delta seconds or an HTTP date,
saturating, `None` when absent or unreadable). A body cut is a body read
that fails on the way: reqwest gives every failure of `bytes`, `text` and
`json` the decode kind, so the classifier reads the error's source by type,
a decode error whose source is not a `serde_json::Error` a cut, one whose
source is the parse failure it is (`PARSE_ERROR`, `InvalidResponse`,
`WalletError`). On wasm32 the fetch API does not say whether a connection
was made, so a send failure there is never `NeverSent`. Every HTTP site of the four transport directories asks it; none
classifies by text. Busy stays the body's word. What each directory answers:

- **Broadcasters** (ARC, Teranode, WhatsOnChain): `BroadcastFailure.code` is
  `NEVER_SENT`, `MAY_HAVE_BEEN_RECEIVED` or `RATE_LIMITED` beside the
  services' own codes; `txid` is set; `more` is `{"status": n}` for an
  answered fault and `{"status": 429, "retry_after_ms": n|null}` for a rate
  limit; `BroadcastFailure::transport_fault()` reads the class back. A 500, a
  4xx and a 2xx are read as before (an ARC 500 with no body is still
  `PARSE_ERROR`, #65's S2 half). No field was added to the struct.
- **Auth transports**: `Error::TransportFault { fault, status, detail }`
  (new variant; `Error` is `#[non_exhaustive]`, so it is additive) for a send
  or body-read fault on both `SimplifiedFetchTransport` paths, a handshake
  answered 429, 502, 503 or 504, and a Socket.IO sink failure
  (`MayHaveBeenReceived`); the detail is the old `AuthError` text. Any other
  handshake status stays `AuthError`; a General answer of any status is still
  passed to the caller as its `HttpResponse`. The WebSocket transport keeps
  `TransportError` (below).
- **Wallet substrates**: `Error::WalletTransport` as in 0.8.2, now from both
  `HttpWalletJson` and `HttpWalletWire` (which answered `WalletError` for a
  connection error, a timeout and a 502, 503 or 504), and for a body cut (was
  `WalletError`); a 429 without a busy code is `Error::TransportFault` with
  `RateLimited` and its wait (was `WalletError`). A 503 with `Retry-After`
  and no busy code stays `WalletTransport { status: Some(503) }` at both
  substrates (a 503 whose body carries a numeric wallet code stays
  `WalletError`, as in 0.8.2), the one place the rule's "a 503 with `Retry-After` is
  `RATE_LIMITED`" is set aside, to keep the shape 0.8.2's `HttpWalletJson`
  answered and pinned (`an_html_503_from_a_proxy_is_a_transport_fault`); its
  wait is not carried there. `Error::transport_fault()` reads the class of either variant
  (`WalletTransport` as `MayHaveBeenReceived`; busy is `None`).
- **Chain trackers** (WhatsOnChain, the headers service):
  `ChainTrackerError::TransportFault { fault, status, detail }` (new variant,
  the three fields of `Error::TransportFault`, the same class; the enum
  becomes `#[non_exhaustive]`, below) for a send fault (`NeverSent` or
  `MayHaveBeenReceived`, status `None`), a body cut (`MayHaveBeenReceived`)
  and a 429, 502, 503 or 504 (the class and its wait, status `Some`, detail
  `HTTP 429 Too Many Requests`). `InvalidResponse` stays for a body that
  parsed wrong and any other status; `BlockNotFound` and `Other` are
  unchanged; `NetworkError` stays for a tracker built without `http`.
  `ChainTrackerError::transport_fault()` reads the class back, and the new
  `From<ChainTrackerError> for Error` carries it to `Error::TransportFault`,
  so `Transaction::verify` answers a tracker's fault as
  `Error::TransportFault` (was `TransactionError("Chain tracker error: ...")`,
  which every other tracker error still is). A fault is never `Ok(false)`.

**The old words.** A code word is a rule's word, not a compatibility
promise; each gives way here:

- `NETWORK_ERROR` (a broadcaster's send error) to `NEVER_SENT` (a connection
  never made, a request that could not be built) or `MAY_HAVE_BEEN_RECEIVED`
  (every other send error, a timeout included).
- `PARSE_ERROR` (ARC's 429 and its 503 without a body; a body cut at every
  broadcaster) to `RATE_LIMITED` (a 429, a 503 with `Retry-After`) or
  `MAY_HAVE_BEEN_RECEIVED` (a 502, 503 or 504, a body cut).
- Teranode's and WhatsOnChain's `"429"` and `"503"` (and `"502"`, `"504"`)
  to `RATE_LIMITED` or `MAY_HAVE_BEEN_RECEIVED` the same way, the status in
  `more["status"]`.
- `Error::AuthError` on a transport failure (a connection error, a timeout,
  a body cut, a handshake answered 429, 502, 503 or 504) to
  `Error::TransportFault`, its detail the old text; `HttpWalletWire`'s
  `WalletError` on one to `Error::WalletTransport` (a 429 to
  `Error::TransportFault`); a tracker's `NetworkError` on a send error or a
  body cut, and its `InvalidResponse` on a 429, 502, 503 or 504, to
  `ChainTrackerError::TransportFault`, and `Transaction::verify`'s
  `TransactionError` on one to `Error::TransportFault`.

**Migration.** A downstream that matched any of those texts reads
`transport_fault()` instead (`BroadcastFailure::transport_fault()`,
`Error::transport_fault()`, `ChainTrackerError::transport_fault()`): `Some`
of the class for a fault, `None` for the far side's answer. A `match` on
`Error` already has a wildcard arm (`#[non_exhaustive]`).
`ChainTrackerError` is `#[non_exhaustive]` from this release (the owner's
word of 2026-10-24): an exhaustive `match` on it downstream adds a wildcard
arm (`_ => ...`), and the semver check reads the release as a minor; a
downstream that builds a `ChainTrackerError` variant (bsv-wallet-toolbox-rs's
`NetworkError` at `chaintracks_client.rs:262` and
`fallback_chain_tracker.rs:282,306,342`) still compiles, and the toolbox has
no exhaustive `match` on the enum (its tests read it with `matches!`).

Tests, RED on the pre-fix sites (the type present, the sites unchanged) and
GREEN after: `tests/transport_fault_broadcasters.rs` (9; #65's and #66's
witnesses as `a_timeout_after_the_body_was_written_may_have_been_received`
and `a_429_with_retry_after_and_a_text_body_is_rate_limited_with_its_wait`),
`transport_fault_trackers.rs` (7, the typed variant from the fold of
2026-10-24, `a_trackers_transport_fault_reaches_the_crate_error_typed`
among them), `transport_fault_wallet.rs` (7),
`transport_fault_auth.rs` (9). The cold review found the body cut read as a
parse failure (the classifier asked `is_body()`, which reqwest 0.12.28 never
sets for a body read): each file's `body_cut` test answers 200 with
`Content-Length: 200`, twelve body bytes and a close from a raw
`tokio::net::TcpListener` (wiremock cannot cut a body), RED on the classifier
before the fold (`PARSE_ERROR`, `InvalidResponse`, `WalletError`,
`AuthError`) and GREEN after;
`a_success_body_that_is_not_json_stays_the_wallet_error` pins the other half. Two existing tests,
`test_arc_broadcast_with_config_timeout` and `test_teranode_broadcast_timeout`,
pinned `NETWORK_ERROR` for a timeout after the request was written, which is
#65's defect; they now read `MAY_HAVE_BEEN_RECEIVED` (their own commit).
`test_woc_tracker_current_height_server_error` pinned a bare 503 as
`InvalidResponse`; it now reads `ChainTrackerError::TransportFault`
(`MayHaveBeenReceived`, status 503).

### Notes: cross-SDK parity

The references do not type the fault. TS's `ARC.broadcast` answers code
`'500'` for a thrown fetch and the status as a string for a non-2xx
(`ts-sdk@9e3ede6` `src/transaction/broadcasters/ARC.ts:189-195, 219-222`);
`HTTPWalletJSON` throws an `Error` of a JSON text for a non-2xx (`:87-107`);
`SimplifiedFetchTransport` throws its network error (`:66, 147`); nothing
under `src/` reads `Retry-After`. Go's `Arc.BroadcastCtx` answers `"500"` for
any error of `ArcBroadcast`, which decodes the body as JSON before it records
the status, so a 429 with a text body is `"500"` (`go-sdk@2ca481c`
`transaction/broadcaster/arc.go:162-180, 245-249`), and the status as a
string otherwise (`:318-321`); no `Retry-After`. This crate goes beyond both
by the stack's rule (the owner's, matrix rows 26 and 30, `lean/Sdk.lean`):
busy is the body's word, a 502, 503 or 504 without it, a connection error or
a timeout is a fault with no promise, a broadcaster's fault says whether the
request was sent, and a rate limit is never a verdict. The wire, every
request the crate sends and every success path are unchanged.

### Added: a minimal-length-key HMAC tag refused by name (#148)

BRC-56 keys the HMAC with the shared point's X coordinate as exactly 32
big-endian bytes, leading zero bytes included (`bsv-blockchain/BRCs` at
`5119a9b`, `wallet/0056.md:66`); an implementation that encodes the key
minimal-length drops those bytes and makes another tag, for about one derived
key in 256 (`:73`). This crate keeps the 32 bytes. `verify_hmac` still accepts
the 32-byte-key tag only; on a miss whose key begins with a zero byte it
computes the tag once more under the minimal-length key and, when that one
matches, answers the new `Error::HmacMinimalLengthKey { leading_zero_bytes }`
("HMAC is not valid: the tag was made under a minimal-length key ..."), which
names the sender's encoding. Nothing is accepted twice. A tag matching neither
key is `WalletError("HMAC is not valid")` as before; `create_hmac` is
unchanged. The async `WalletInterface::verify_hmac` goes through the same
path. `tests/wallet_brc56_hmac_tests.rs` holds the six vectors of
`wallet/0056.md:91-96` (inputs at `:81-85`): `create_hmac` reproduces the six
tags and `derive_symmetric_key` the six keys byte for byte, `verify_hmac`
accepts the six, the four minimal-length tags (the rows whose key begins with
one or two zero bytes) are refused by name, RED before this change (they read
`HMAC is not valid`), and the two rows with no leading zero byte have one
encoding and no refusal path. The line's pin `ed1b015` carries no BRC-56
vectors and no paragraph on the encoding; the vectors are upstream, not on the
line, taken by the owner's word. The variant is additive under the
`#[non_exhaustive]` `Error`. The crate holds no counter a host reads: the
refusal is the count's event, and a host counts it.

### Notes: cross-SDK parity

ts-sdk makes the HMAC under the minimal-length key: `deriveSymmetricKey`
builds the key from `x.toArray()` (`ts-stack@edf6e03`
`packages/sdk/src/wallet/KeyDeriver.ts:270`; `ts-sdk@9e3ede6`
`src/wallet/KeyDeriver.ts:202`) and `createHmac` and `verifyHmac` key the HMAC
with `key.toArray()` (ts-stack@edf6e03 `ProtoWallet.ts:295,311`; ts-sdk@9e3ede6 `:212,226`), a `BigNumber`'s minimal
big-endian bytes. This crate makes it under the 32 bytes, as the Go SDK does
(`NewSymmetricKey` left-pads to 32, go-sdk@`2ca481c`
`primitives/ec/symmetric.go:82-90`), and as Python and rs-sdk do by the
keeper's ruling of 2026-10-24. For one key in 256 a ts-sdk tag fails here; the
refusal names that gap rather than accept it.

### Fixed: the wallet wire's optional varints in the reference's plain form (#149)

`WireWriter::write_signed_var_int` and `write_optional_var_int`, and the
readers on them (`encoding.rs`), were ZigZag: `Some(10)` left as `0x14`,
absence as `0x01`, and a peer's `10` read as `5`, its `5` as absent. The
fields: createAction's input `sequenceNumber`, `lockTime` and `version`;
signAction's spend `sequenceNumber`; the `limit` and `offset` of listActions,
listOutputs, listCertificates, discoverByIdentityKey and discoverByAttributes.
Absence crossed only by accident (nine `0xFF` decoded to `i64::MIN`). A present
value is now the plain varint (`10` is `0x0A`, `u32::MAX` is
`FE FF FF FF FF`) and absence is nine `0xFF`, both ways: the bytes TS writes
(`ts-sdk@9e3ede6` `utils.ts:546-549`, `writeVarIntNum`, `-1` through
`varIntBn` at `:586`) and Go writes (`go-sdk@2ca481c` `util/writer.go:66-71`),
and the bytes the shared vectors already carried (`listActions-simple-args.json`'s
`limit` 10 is `0x0A`; the cross-SDK test never decoded it). The keeper's
reading: the wire's bytes are the reference's, so ZigZag was the departure,
not a shape of the wire. signAction's spend reader refuses a sequence number
above `u32::MAX` naming the field, as Go's `ReadOptionalUint32` does
(`util/reader.go:210-222`); the validator's narrower bounds (a limit 1 to
10,000, `validationHelpers.ts:1199`) stay the validator's, not the reader's.
`write_signed_var_int` takes the field's name and returns a `Result`: `-1` is
absence, any other negative has no form a reader keeps and is refused with the
field named; listOutputs' `offset` (an `i32`) goes through it, so an offset
below `-1` is refused before anything is sent. `read_signed_var_int` refuses a
value above `i64::MAX` other than nine `0xFF`. Pinned by
`tests/wire_signed_varint_tests.rs` (12 tests; on the pre-fix tree 10 of
the 11 that compile there fail), on TS's bytes
and on the shared vectors read in place. The recordings of #76 that carry
one of these fields moved in their own commit.

Migration: a 0.8.x `WalletWireTransceiver` and a later processor (or the
other way) disagree on every present value of these fields; upgrade both
sides together. A caller of `write_signed_var_int(v)` writes
`write_signed_var_int("field", v)?`.

### Notes: cross-SDK parity (#149)

The reference's form of these fields is now this crate's. One difference
stays, stated: TS's listOutputs `offset` may be negative (`validationHelpers.ts:1648`,
no minimum; BRC-100 `ed1b015` `wallet/0100.md:904`, `:1931` "Signed integer"),
and TS writes `-2` as `FF FE FF FF FF FF FF FF FF` (two's complement through
`varIntBn`), which its own processor then reads as absent
(`WalletWireProcessor.ts:966-979`, any negative) and Go cannot carry (`*uint32`);
this crate refuses an offset below `-1` at the writer, and `-1` (the newest
output) leaves as absence's nine `0xFF`, as TS's does. BRC-100 names `VarInt`
and `-1` for absence (`:1646-1647`, `:1661`, `:1741`, `:1799-1800`; `5119a9b`
the same nine lines later) and gives no encoding of a negative: its `VarInt`
(`:1620-1628`) is unsigned.

### Fixed: a dead function under every slice without `script` (#115)

`after_last_code_separator` (`primitives/bsv/sighash.rs`) has one caller, the
script templates' signing path, but compiled under `primitives`, so a consumer
building `block`, `primitives`, `compat` or `totp` alone with warnings denied
(the Cloudflare workers' CI) could not build the crate. Found by the dependents
check (#83) on its first hosted run, on chaintracks-cloudflare's `block` slice.
The function is gated on `script`; the `clippy` job now checks each published
slice alone with `-D warnings`, which was RED on the pre-fix tree for the four
slices and is the pin.

### Fixed: a certificate length that wrapped the reader's bounds check (#108)

`Certificate::from_binary` panicked on a field length near `usize::MAX`: its
reader checked `pos + n > len`, the sum wrapped, the check passed and the
slice panicked (an abort on wasm32, and a peer's certificate bytes reach this
reader). The reader now compares a length to the bytes remaining, slices
through `get`, and refuses a varint length that does not fit `usize` rather
than truncating it; the refusal is `Error::ReaderUnderflow`, as for any short
read. `HttpRequest::from_payload` and `HttpResponse::from_payload` had the same
sum, which wrapped on a 32-bit target (a length near `u32::MAX` on wasm32), and
cast an `i64` length to `usize`; they now take each field the same way, with
their error texts unchanged. A valid certificate or payload parses as before.
Found by #82's fuzz lane (`fuzz_auth_messages`); pinned by
`tests/auth_reader_bounds.rs` (`a_certificate_length_that_wraps_the_bounds_check_is_refused`
on the issue's 189 bytes, a constructed `usize::MAX - k`, the HTTP fields):
the three certificate tests RED on the pre-fix tree; the HTTP sites RED on
wasm32 only, a length near `u32::MAX`, which no 64-bit run can show; the 535
crash inputs of the class replay with no panic.

### Fixed: a varint index above `u32::MAX` is refused, never cast (#120)

Five readers took an output or input index as a varint and cast it with
`as u32`, so `u32::MAX + 1` read as index 0 and a frame named a different
outpoint in silence: the wallet wire's outpoint, its `signAction` spend
index, `internalizeAction`'s output index and an action output's index
(`wallet/wire/encoding.rs`), and a certificate's revocation outpoint index
(`auth/certificates/certificate.rs`). The keeper's reading: an index is a
`u32` by the transaction format, so a larger value is not one the wire can
mean, and invalid bytes get a typed refusal naming the field, never a
reinterpretation. The wire reader refuses with its own malformed-field
error, `Error::WalletError("invalid <field>: expected at most 4294967295,
got <n>")`, and the certificate reader with
`Error::CertificateValidationError` in the same words; no valid byte reads
differently. Pinned by one test per site, `u32::MAX` read back exactly and
`u32::MAX + 1` refused, each RED on the pre-fix code
(`*_index_above_u32_max_is_refused_not_truncated`).

### Fixed: nine more `u32` fields of the wallet wire refused above `u32::MAX`, never cast (#122)

The wallet wire read nine more `u32` fields as a varint and cast them, so
`u32::MAX + 1` read as 0: `signAction`'s spend `sequenceNumber` and an action
input's `sequenceNumber`, an action's `version` and `lockTime`
(`wallet/wire/encoding.rs`), `getHeaderForHeight`'s `height`
(`wallet/wire/processor.rs`), and `totalActions`, `totalOutputs` and the two
`totalCertificates` (`listCertificates`, and the one parser both discover methods share) in the
results (`wallet/wire/transceiver.rs`). The keeper's reading of #120 by its own
reasoning: each is a `u32` by the transaction format or by BRC-100's
`PositiveIntegerOrZero` (at most `2^32 - 1`, `ed1b015` `wallet/0100.md:393-401`;
the height `PositiveInteger`, `:403-411`), so a larger value is not one the
wire can mean. #120's helper is now `read_var_int_u32` with an optional
twin for `signAction`'s `-1`-for-absent field, and the refusal is the same
`Error::WalletError("invalid <field>: expected at most 4294967295, got <n>")`,
the field as the frame's table names it. No valid byte reads differently.
Pinned by `tests/wire_u32_field_bounds_tests.rs`, one test per site
(`*_above_u32_max_is_refused_not_truncated`), each RED on the pre-fix code;
a total drives the count of entries read after it, so its `u32::MAX` is shown
accepted by the reader going on to the entry after it.

### Notes: cross-SDK parity

TypeScript's `Reader.readVarIntNum` (`ts-sdk@9e3ede6`
`src/primitives/utils.ts:743-763`, called for these indexes in
`Certificate.ts:169`, `WalletWireProcessor.ts:20` (the outpoint), `:387`
(the spend's input index), `:803` (the internalized output's index) and
`WalletWireTransceiver.ts:756` (the action output's index)) returns any
number up to 2^53 with no `u32` bound, so it reads the same frames as an
index no transaction has. Go's `ReadVarInt32` (go-sdk v1.7.2
`util/reader.go:123-126`, called at `sign_action_args.go:63`,
`internalize_action.go:72` and `list_actions.go:281`) casts to `uint32` and
truncates as this crate did. Both are the references' own gap, not followed
here (rule 1: the divergence stated, the keeper's reading the reason).

The nine fields of #122 the same: TypeScript's unbounded `readVarIntNum` reads
them at `WalletWireProcessor.ts:398` (the spend's `sequenceNumber`) and
`:1407` (`height`), and `WalletWireTransceiver.ts:603` (`totalActions`),
`:699-700` (`version`, `lockTime`), `:738` (the input's `sequenceNumber`),
`:987` (`totalOutputs`), `:1675` and `:1822` (`totalCertificates`); Go's
truncating `ReadVarInt32` (go-sdk v1.7.2 `util/reader.go:123-126`) reads
`totalActions` at `wallet/serializer/list_actions.go:199`, version and lock
time at `:235-236`, the input's sequence number at `:259`, `totalOutputs` at
`list_outputs.go:134` and `height` at `get_header.go:20`, and the two
`totalCertificates` cast `uint32(r.ReadVarInt())` at
`list_certificates.go:132` and `discover_certificates_result.go:37`. The
references' own gap, not followed.

### Added: internalizeAction refuses a basket insertion's `customInstructions` over 1,000 UTF-8 bytes (#117)

BRC-100 bounds the field since `5119a9b` (`wallet/0100.md:867`, upstream,
not on the line): "at most 1000 UTF-8 bytes unless a supported module
explicitly defines a scoped exception, such as BRC-207. Strings exceeding the
applicable limit must be rejected." At the line's pin `ed1b015`
(`wallet/0100.md:860`) it carries no bound. The TypeScript SDK already refuses
it: `validateBasketInsertion` calls `validateOptionalStringLength(...,
'customInstructions', 0, 1000)` (`ts-stack@edf6e03`
`packages/sdk/src/wallet/validationHelpers.ts:942-946`), which counts UTF-8
bytes (`utf8Bytes(s).length`, `:348-356`). This crate had no internalize
validator at all. By the owner's word of 2026-10-24 (conform), the new
`validation::validate_internalize_action_args` refuses one with
`Error::WalletError("Invalid outputs[i].insertionRemittance.customInstructions:
must be no more than 1000 bytes, got N")`, the shape of the file's byte-length
refusal (`validate_string_length`) (bytes by `str::len`, not characters), and
`ProtoWallet`, `WalletClient`, `HttpWalletJson` and `WalletWireTransceiver`
call it before they act or send. The wire processor's handler does not read
its arguments yet and is unchanged. The scoped exception is not modelled: no
module defines one here. The createAction output's `customInstructions` stays
unbounded, as BRC-100 and TS leave it (`validationHelpers.ts:638`). The
stack's scenario is `2026-10-24-wallet-internalize-custom-instructions-bound`.
Pinned by `tests/wallet_internalize_validation_tests.rs` (1,000 bytes
accepted, 1,001 refused with the field and the count, 250 four-byte
characters accepted and 251 refused, an absent field accepted, a second
output named by its index, the createAction copy unbounded, the ProtoWallet
and HTTP JSON doors refusing before acting or sending), RED on the tree
without the bound. No wire byte or JSON shape changed.

## [0.8.3] - 2026-10-25

### Security: RUSTSEC-2026-0387, k256 and p256 to the 0.14 line (#125)

RUSTSEC-2026-0387 (timing variability in crypto-bigint's constant-time
operations) reached every dependent through k256 0.13.4 and p256 0.13.2, both
on crypto-bigint 0.5.5, which no 0.5 release fixes. k256 and p256 move to
0.14.0 (elliptic-curve 0.14.1, crypto-bigint 0.7.6); the hashes move with them
to their digest 0.11 releases so the crate signs and hashes on one digest
generation: sha2 0.10 to 0.11, sha1 0.10 to 0.11, hmac 0.12 to 0.13, pbkdf2
0.12 to 0.13, ripemd 0.1 to 0.2. aes-gcm, aes, cbc and subtle stay where they
were (the resolver asks nothing of them). No public type, function signature
or error text of bsv-rs changed. `cargo deny --locked check` is clean on the
three graphs with an empty ignore list.

k256 and p256 are built without their default features: their `std` turns on
`getrandom` 0.4, which has no wasm32-unknown-unknown backend without its own
`wasm_js` feature. `PrivateKey::random` and `P256PrivateKey::random` draw 32
bytes from the OS CSPRNG through this crate's `getrandom` 0.2 and refuse zero
and values at or above n, the rejection sampling the 0.13 `SecretKey::random`
did. `primeorder` is named with only `std` so the curves keep their
precomputed basepoint tables.

### Notes: cross-SDK parity

For a digest at or above n, k256 0.14's deterministic signature is the one
`@bsv/sdk` 2.0.16 (`ECDSA.sign`) and the Go SDK (`signRFC6979`, the clone at
`2ca481c`) produce: derived with both on 2026-10-24 for the pinned key and
digest, `3045022100dd92…cf39`, byte for byte. k256 0.13 signed that regime
differently, which this crate pinned and listed as a divergence; the pin
(`rfc6979_digest_ge_n_der_is_pinned`, `tests/ec_tests.rs`) now holds the
references' bytes and the divergence left the list (the captain's ruling
under rule 1). Every digest below n signs as before. Which step of the nonce
derivation differed between the two k256 lines is not stated here: the
derivation is the evidence, not a reading of the libraries.

## [0.8.2] - 2026-10-23

### Added: the wallet's transport fault (Calhooon/bsv-rs#73)

The owner's ruling of 2026-10-23 (bsv-stack-lean DECISIONS 13.2): busy is the
body word, never the HTTP status, and a 503 without it is a proxy's or an
edge's answer. 0.8.1 put that answer in `Error::WalletError`, the variant of
a refusal, so a caller could not tell "the way failed, ask again" from "the
wallet refused".

- `Error::WalletTransport { status: Option<u16>, detail: String }`: a caller
  may retry it; it carries no promise about what the wallet did (the request
  may or may not have reached it), which is the one way it differs from
  `WalletBusy`. `Error` is `#[non_exhaustive]`, so the variant is additive.
- `HttpWalletJson` answers it for a 502, 503 or 504 whose body carries no
  busy code (`STORE_BUSY`, `ERR_SERVER_BUSY`) and no numeric wallet code
  (`status` the code, `detail` the usual `HTTP <status> for <method>: <body>`
  text), and for a connection error (refused, reset, DNS) or a timeout
  (`status` `None`). A caller that matched the bare 503's `WalletError` text
  matches `WalletTransport` now.
- Unchanged: `WalletBusy` is read from the body's code at any status; a 4xx,
  a 500, and a 5xx with a numeric wallet code stay `WalletError`;
  `HttpWalletWire` keeps `WalletError`. Nothing in the crate retries.
- The docs rows: `src/wallet/CLAUDE.md` (the error table) and
  `src/wallet/substrates/CLAUDE.md` (error handling) carry the transport
  fault beside the busy row.

## [0.8.1] - 2026-10-22

A patch. The atomic BEEF rule is judged on the subject's graph (BRC-95), not
on wire position. Both readers accept more and refuse no BEEF they accepted
before; no public type changes shape. One persisted format moves: a stream
`Cursor` is written BSC3, and a BSC2 cursor still reads (as BSC3 with no
edge), so no reading restarts.

### Fixed: the atomic rule on the subject's graph (BRC-95; the bsv-dd x402 refund, P0-65)

The rule was positional: the subject the last raw transaction, and every
other entry spent by a LATER raw transaction. The stream marked a parent only
when it was in the index when its child was read (`beef_stream.rs`, the
`referenced` mark in the fold), and `Beef::verify_structure` did the same
walk in the order held (`atomic_rule`). BRC-95 (`BRCs transactions/0095.md`)
defines the rule on the graph (every transaction in the subject's dependency
graph, nothing else present) and says nothing about order. The TypeScript
writer (`@bsv/sdk` 2.1.4 `Beef.sortTxs` / `partitionTxs`) writes every proven
transaction first in encounter order, then the unproven ones in dependency
order: a raw unproven ancestor can follow the proven transaction that spends
it. That wire is legal, and bsv-rs refused it `UnrelatedTransaction` (the
bsv-dd x402 refund). This crate's own `to_binary_atomic`, whose sort mirrors
the reference's, wrote BEEFs its own two readers refused.

- The rule, one walk for both readers (`beef_stream::atomic_unreached`,
  called by `BeefIndex::finish` and `Beef::verify_structure`; the Lean's
  `finish`, bsv-stack-lean `lean/BeefOfAnySize.lean` `walk`/`finish`): the
  subject is a raw transaction of the BEEF, else `SubjectMissing`; every
  other entry, raw or txid-only, is reached from the subject by following
  the inputs of raw entries, proven or not (the owner's ruling, 2026-10-22),
  else `UnrelatedTransaction`. Position is not judged.
- The entry a refusal names (the ruled text, 2026-10-22): the earliest, by
  the trie order (the txid's bytes, each byte's bits reversed, least first),
  of the entries the walk does not reach, at its offset in the stream (the
  whole path's verdict is a `Kind`, naming none). The first cut of this
  release read one flag per entry (some raw entry spends it). That gives the
  same verdict, since the refusal set is empty exactly when every entry is
  reachable (a txid is a hash, so no chain of spends returns), but it names
  a different entry. Beside the subject, take a raw `X` that nothing spends
  and its parent `Y` that only `X` spends. Both are unreached; the flag named
  `X` even when `Y` is earlier, and the walk names `Y`. No flag stands in for
  the edges: two BEEFs with the same flags can leave different entries
  unreached.
- The stream keeps the edges: under a subject, each raw transaction's entry
  holds the txids its inputs name (the Lean's `prevs`), and the walk marks
  entries in place. They are kept only when a subject is known (the caller's,
  or the prefix's: the header precedes the first element;
  `BeefIndex::hold_to_subject`, new); without one nothing walks them.
  `entries()` counts them. `spec_size()` is the Lean's `Index.size`, which
  counts one edge per input of every raw transaction read, with or without a
  subject (a counter here, not a table), and `model_work()` adds the Lean's
  atomic end (one pass over the table and the walk's fuel three times). So the
  Lean's deep rows move, as the Lean's own did (bsv-stack-lean@3bb286e
  `lean/BeefOfAnySize/Scenarios.lean:141,148`): 100,000 links, index 100,004
  to 200,005; 10,000 links atomic, work 680,133 to 740,145 and index 10,004
  to 20,005 (`tests/beef_stream_deep.rs`). The deep chain's `entries` under
  its subject is 2n + 2 (one edge per link).
- The bound: per element, plus 32 bytes per input of a raw transaction, only
  under a subject. An input is 41 bytes or more on the wire, so this is
  linear in the bytes read, but it is not per element. Measured
  (`memory_profiling`): the deep chain under its subject peaks at 352, 281
  and 225 B per element at 1,000, 10,000 and 100,000 links (0.8.0: 274, 219,
  175; the test's bound moves from 320 to 400 B, and the flatness check
  holds). The new row
  (`test_beef_stream_memory_on_proven_transactions_with_many_inputs`, 100
  proven transactions of 1,000 inputs, a 4.1 MB BEEF) peaks at 262 KB
  without a subject and adds 32 B per input under one. The cursor after one
  proven transaction of 10,000 inputs is 238 B without a subject (structure
  only; 249 B with scripts) and 320,305 B under one.
- Unchanged: the spend checks, the BRC-62 clause that a transaction without a
  BUMP spends earlier transactions, the offsets, the twenty-four `Kind`s, the
  `Reason` list.
- The words of two refused shapes move. A subject that is a raw transaction
  of the BEEF is no longer missing: the Lean's W4 rows `wrong_subject` and
  `wrong_subject_true` (the second link of three named) refuse
  `UnrelatedTransaction` at the third link (278, 282; `SubjectMissing` at 4
  until 0.8.0), and `example_atomic_parent` (the BRC-62 example behind a
  prefix naming the parent) `UnrelatedTransaction` at the payment (521).
  `unrelated` and `unrelated_true` keep 278 and 282. All five still refuse;
  with scripts, the rows without `OP_TRUE` outputs are a refused spend first,
  as at 0.8.0. `SubjectMissing` is now a subject the BEEF holds only as a
  txid-only entry, or not at all.
- `Cursor` bytes are BSC3. After the transactions come the inputs counted
  and the edges, one list per raw transaction, by txid strictly ascending
  (`Cursor::from_binary` refuses a list out of order, with a repeat, or
  naming a txid the index does not hold raw). A BSC2 cursor (0.5.0 to 0.8.0)
  reads as BSC3 with no edge. That is sound: the walk from it lacks the edges
  of the transactions read before the cursor, reaches less, and only refuses
  more, never accepting wrongly. A stored atomic reading resumed from BSC2
  accepts when the transactions read before the cursor spend nothing the
  walk needs, and otherwise refuses `UnrelatedTransaction`. The precedent for a cursor format change is
  0.5.0 (BSC1 to BSC2, a minor, BSC1 refused); a patch may move to BSC3
  because a BSC2 cursor still reads. One downstream hand-parses the magic:
  bsv-messagebox-cloudflare-public `src/beef_door.rs:665` (`tip_of` checks
  `b"BSC2"` and answers `DoorError::Internal`, a 500 on every at-rest pause).
  It pins `=0.7.0`, so nothing breaks now; when it moves to 0.8.x, `tip_of`
  must accept BSC3 (the layout it reads is unchanged).
- Tests (`tests/beef_atomic_graph.rs`): one atomic BEEF of seven transactions
  (a raw unproven ancestor that only a proven transaction spends, a proven
  parent and child) in each of its 364 orders the BRC-62 clause allows,
  accepted by the stream with and without scripts and by `verify_structure`
  and `verify_valid`
  (`an_atomic_beef_is_accepted_by_both_readers_in_every_order_its_dependencies_allow`,
  `a_raw_unproven_ancestor_after_its_proven_descendant_is_accepted`); an
  unrelated entry (raw proven, raw unproven, txid-only) at every position,
  refused by all four (`an_unrelated_entry_is_refused_by_both_readers_in_every_order`);
  a subject the BEEF does not carry raw, `SubjectMissing` in every order
  (`a_subject_the_beef_does_not_carry_raw_is_missing_in_every_order`);
  `to_binary_atomic`'s output from each merge order, the closure, accepted by
  both readers (`what_this_crates_writer_writes_its_own_two_readers_accept`,
  rewritten with the writer change below); a cursor at
  every `k` (`a_cursor_carries_the_edges_the_walk_needs`); the
  W4 bytes (`the_leans_w4_bytes_are_refused_under_the_graph_rule`). Six of
  the seven were red on 0.8.0. The review's folds add three, red on the
  first cut of this release: the edges kept only under a subject, counted
  by `entries` (`the_edges_are_kept_only_under_a_subject`), a BSC2 cursor
  read at every `k` (`a_bsc2_cursor_reads_as_bsc3_with_no_edges`), a list
  out of order refused (`a_cursor_whose_edges_are_not_strictly_ascending_is_refused`).
  The walk adds the X/Y pair in both trie orders, both readers refusing and
  the stream naming the earliest unreached entry at its offset:
  `an_unreached_parent_earlier_by_the_trie_order_is_the_entry_named` (`Y`,
  at 124; red on the flag predicate, which named `X` at 187) and
  `an_unreached_child_earlier_by_the_trie_order_is_the_entry_named` (`X`, at
  187). `the_xy_vectors_are_the_pair_this_crates_writer_writes` pins the
  vectors' bytes.
  `tests/beef_stream.rs` pins the moved words
  (`a_subject_whose_graph_leaves_a_later_link_out_is_refused`, the example's
  and the W4 test's).
- Vectors: `tests/transaction/vectors/atomic-beef.json`
  (`sdk.transactions.atomic-beef`, the ts-stack corpus's format, eight vectors)
  is staged for the corpus's `vectors/sdk/transactions/`;
  `tests/conformance_beef.rs` runs it (`conformance_atomic_beef`) from the
  corpus when it carries the file, else from the staged copy. The accepted
  bytes are the writers': Go's `AtomicBytes` (dependency order), TypeScript's
  `toBinaryAtomic` (the partition order; the raw ancestor after its proven
  descendant; an unrelated entry, refused), this crate's `to_binary_atomic`
  before the writer change below (the subject not last); the missing subject
  is hand-built (no writer writes
  an atomic BEEF for a txid it does not hold). Two vectors were red on 0.8.0.
  Those two, `raw-unproven-ancestor-after-proven-descendant` and
  `subject-present-not-last`, are `parity_class` `intended` (with a
  `skip_reason`): `@bsv/sdk` 3.x refuses them (below), so the corpus cannot
  hold them as `required`; `reference_impl` says the expected values are this
  crate's ruling. `conformance_atomic_beef` pins which two. The X/Y pair is
  two vectors, `unrelated-pair-parent-named` and `unrelated-pair-child-named`
  (refused, `required` by the file's class: `@bsv/sdk` 3.x refuses them too,
  as its model in the tests does). Each description names the entry each
  reader names: the stream names `Y` at 124 in the first and `X` at 187 in
  the second, and `conformance_atomic_beef` pins both. The whole path and
  TS 3 name none. The first was red on the flag predicate.

### Changed: the atomic writer emits the BRC-95 closure (what TS 3 and Go write)

`Beef::to_binary_atomic` wrote every entry the `Beef` held. A `Beef` that
merged ancestors behind a proof then emitted a raw ancestor of a proven
transaction, which `@bsv/sdk` 3's readers refuse, and an entry outside the
subject's graph, which every reader but 2.1.4's refuses. It now writes the
subject's closure: from the subject, the inputs of raw entries are
followed, stopping at a transaction a BUMP of this BEEF proves (its BUMP
index names a BUMP whose level 0 carries its txid) and at txid-only
entries; every other entry is dropped, with the BUMPs no kept entry needs,
and the kept BUMPs are renumbered (a txid-only entry keeps the first BUMP
that carries it). The order is the reference's sort, the subject last. This
is `@bsv/sdk` 3's `#collectAtomicTransactions` / `#copySelectedTransactions`
(ts-stack `Beef.ts:375-472`) and go-sdk's `selectAtomicBeef`
(`transaction/beef.go:1719-1749`). The output shrinks by what no reader
needs; nothing it writes is refused by a reader of 0.8.0, TS 2, TS 3 or Go
that accepted the subject's graph. `to_binary` (non-atomic) is unchanged.
A raw entry whose BUMP index is out of range is now an error
(`BeefError`), as Go's is; it was written as is before.

- Tests (`tests/beef_atomic_graph.rs`): a `Beef` holding a proven parent
  and child, a raw unproven ancestor of a proven transaction and an
  unrelated branch writes the closure, accepted by both readers and by the
  TS 3 rule modelled in the test, the ancestor behind the proof and the
  branch absent, three BUMPs renumbered
  (`the_atomic_writer_emits_the_brc95_closure_and_drops_the_rest`); every
  accepted vector of `atomic-beef.json` read and written again is accepted by
  both readers and the TS 3 model, which also refuses exactly the two
  `intended` vectors as they stand
  (`every_accepted_vector_round_trips_through_the_atomic_writer`); the 364
  merge orders write one closure (`what_this_crates_writer_writes_its_own_two_readers_accept`).
  All three red before the change.
- Downstreams that call `to_binary_atomic` (bsv-overlay-cloudflare,
  rust-message-box, bsv-messagebox-cloudflare-public, bsv-wallet-toolbox-rs)
  get the smaller BEEF on their next `cargo update -p bsv-rs`.

### Notes: cross-SDK parity

A stated divergence from the current reference. `@bsv/sdk` 3 (ts-stack
`4d0ea63`, sdk 3.0.0; npm 3.2.1) judges the graph but cuts it at each proven
transaction: `Beef.ts:420-434` (`#collectAtomicTransactions` does not follow
the inputs of an entry `#hasMatchingBump` proves), used by `isAtomic`
(`:482-491`), `verifyValid` (`:1064`) and `Transaction.fromAtomicBEEF`
(`Transaction.ts:311`, "Atomic BEEF contains unrelated transaction data"),
as BRC-95's "up to the point where each input can be confirmed with a Merkle
proof" reads. This crate's readers follow the inputs of every raw entry,
proven or not (the owner's ruling of 2026-10-22), so they accept a raw
ancestor behind a proof that TS 3 refuses: the vectors
`raw-unproven-ancestor-after-proven-descendant` (the bsv-dd shape) and
`subject-present-not-last`. They accept everything TS 3 and Go write, and
what `@bsv/sdk` 2.1.4 writes save an entry outside the graph. 2.1.4's reader
sorts and does not judge the graph: `Transaction.fromAtomicBEEF` and
`Beef.verifyValid` accept the vector with an unrelated entry; its
`toBinaryAtomic` writes that entry, and cuts every entry the sort puts after
the subject (`getBeefForAtomic`, `txs.splice(i + 1)`). go-sdk@v1.7.2's reader
asks only that the subject be present (`NewBeefFromAtomicBytes`); its
`AtomicBytes` writes the subject last and cuts the ancestry at each proof.
`Transaction::from_atomic_beef` finds the subject and does not judge the
graph, where TS 3's `fromAtomicBEEF` does (a divergence older than this
release, now listed in `CLAUDE.md`). A reference bug found on the way, not
followed: 2.1.4's `BeefTx` names an entry built from raw bytes by the
unreversed hash (`BeefTx.ts:51-53`, `toHex(hash256(rawTx))`), and a proven
entry is never parsed, so `Beef.mergeRawTx(raw, bumpIndex)` gives a proven
transaction a byte-reversed txid that nothing finds (the vectors' TypeScript
generator uses `mergeTransaction`). The writer emits the cut closure (the
change above), so what this crate writes, TS 3 reads.

## [0.8.0] - 2026-10-21

Breaking: 0.8.0. `Error` is now `#[non_exhaustive]` and gains `WalletBusy`;
a downstream exhaustive `match` adds a wildcard arm. bsv-wallet-toolbox-rs
(which answers the new variant), bsv-tracker and bsv-wallet-cli repin to
`"0.8"`. The stack's precedent (bsv-stack-lean `docs/RULINGS-2026-10-09.md`
section 2, bsv-middleware-rs 0.3.0): a variant added to an exhaustive public
enum makes the enum `#[non_exhaustive]` and the release a minor.

### Added: `Error::WalletBusy`, a typed busy answer (Calhooon/bsv-wallet-cli#44)

A wallet daemon answered a served `createAction` with 400 `database is locked
(code 517)`. The store's fix lands in bsv-wallet-toolbox-rs (one writer
connection, `BEGIN IMMEDIATE`, a typed `StoreBusy`), but the toolbox's
`WalletInterface` impl could only erase it into `WalletError(String)`, and a
host could only string-match the text. The SDK now has the word, so the path
is typed end to end.

- `Error::WalletBusy { detail: String, retry_after_ms: Option<u64> }`, behind
  `wallet`, Display `wallet busy: {detail}`. The contract (the variant's doc):
  the wallet answered that it refused the call before acting (a contended
  store, a lock not acquired) and promised that nothing was written, built or
  locked, so the caller may repeat the same call unchanged after
  `retry_after_ms`, or after a moment when it is `None`. The SDK reports the
  server's promise; it cannot check it. `retry_after_ms` is unbounded, the
  server's word.
- `HttpWalletJson` reads the body's code `STORE_BUSY` or `ERR_SERVER_BUSY`,
  at any status, as `WalletBusy`: the detail is the body's `message`, else
  its `description`, else the code; `Retry-After` in delta-seconds becomes
  `retry_after_ms` (saturating; the first header when there are two), and an
  HTTP-date, or anything else, reads as `None`. A 503 without it keeps its
  `WalletError` text, as does every other answer, byte for byte. The stack's
  rule (bsv-stack-lean `docs/BSV-NORTH-STAR.md` section 5): the SDK reads the
  status word, never the HTTP code; a proxy's HTML 503 promises nothing.
- Tests: `tests/wallet_http_json_busy_tests.rs` (wiremock; RED on the code
  without the busy branch for the four busy cases):
  `the_producers_store_busy_body_is_wallet_busy_with_the_delay`,
  `store_busy_on_a_500_is_wallet_busy`,
  `the_ts_toolbox_err_server_busy_body_is_wallet_busy_with_its_description`,
  `the_first_of_two_retry_after_headers_wins`,
  `an_html_503_from_a_proxy_stays_wallet_error`,
  `a_503_with_a_message_and_no_code_stays_wallet_error`,
  `a_503_with_a_numeric_code_keeps_the_coded_wallet_error`,
  `a_busy_body_with_an_http_date_retry_after_has_no_delay`,
  `every_other_status_keeps_the_wallet_error_mapping`,
  `wallet_busy_displays_its_detail_and_compares_on_both_fields`; the
  `Retry-After` reader and the body reader in `http_json`'s unit tests.

### Notes: cross-SDK parity

Neither reference SDK's wallet substrate, nor the BRC-100 wire, has a busy
word. ts-stack@edf6e03 `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:335-340`
deserializes a wallet error only from a 400 carrying `isError` (codes 5, 6, 7:
`WERR_REVIEW_ACTIONS`, `WERR_INVALID_PARAMETER`, `WERR_INSUFFICIENT_FUNDS`) and
throws `HTTPWalletJSON <call> failed with HTTP status <status>` for every other
failure, the body unread; go-sdk@v1.7.1 `wallet/substrates/http_wallet_json.go:62-64`
(read at the tag; v1.7.2 holds the same lines) reads every non-200 as
`HTTP request failed with status <status>: <body>`. A TS or Go client reading
a busy answer gets that generic error, not this crate's detail. The busy codes
are servers' words: bsv-wallet-cli answers `STORE_BUSY` (503,
`Retry-After: 1`), and the TS wallet toolbox's edge answers capacity with 503
`{code: 'ERR_SERVER_BUSY'}` and `Retry-After: 1`
(`packages/wallet/wallet-toolbox/src/storage/remoting/edgePolicy.ts:668-672`;
overlay-express the same, `packages/overlays/overlay-express/src/security/edgePolicy.ts:671`); this crate's client reads them.
The BRC-100 wire is unchanged: its result frame carries one error byte, the
references define codes 5, 6 and 7 on it (TS's `WERR_*`; Go's
`wallet.Error.Code` names none) and none for busy, so `WalletWireTransceiver`
keeps reading every non-zero byte as `WalletError`.

## [0.7.2] - 2026-10-19

Additive, no migration, as 0.7.1 was: new public API in `block`, nothing existing
changes shape (the stack's keeper on the owner's word of 2026-10-19; a 0.8.0 if the
crate's captain prefers it before the tag).

### Added: the node's difficulty rule (`block`)

0.7.0 left difficulty adjustment to the host. The rule moves here from
chaintracks-cloudflare@74cc110 `src/consensus.rs`, where it was ported from
bitcoin-sv v1.2.3 (`6504a3aff65ba97c0f6c80962b033e35ecbfed4b`); each
function's doc names the node function and the lines it ports. Behind the
existing `block` feature; no new dependency.

- `ChainParams::{main, test, regtest}`: `powLimit`, `nPowTargetSpacing`,
  `nPowTargetTimespan`, `fPowAllowMinDifficultyBlocks`, `fPowNoRetargeting`
  and `daaHeight` (`src/chainparams.cpp:1047-1068`, `:1343-1364`,
  `:1471-1490`), with `difficulty_adjustment_interval`, `pow_limit_bits` and
  `window_depth` (how many ancestors the rule may read). Checkpoints and the
  genesis hash stay the host's. `#[non_exhaustive]`: start from a constructor.
- `next_work_required(params, chain, prev_height, new_time) -> Result<u32,
  DifficultyError>`: `GetNextWorkRequired` (`src/pow.cpp:95-117`) with its
  three regimes: regtest's no-retarget, the legacy retarget with the
  emergency adjustment and testnet's minimum-difficulty rule (`:22-93`,
  `:119-148`), and the DAA (`:177-297`). Also public, as the node exports
  them: `calculate_next_work_required` and `next_cash_work_required`.
- `HeaderAncestry`, the smallest view of the chain the rule reads
  (`link_at(height) -> Option<HeaderLink>`, `HeaderLink { height, time, bits
  }`), implemented for `[HeaderLink]`; its `work_between` defaults to
  `chain_work_between`, the `GetBlockProof` sum the node's `nChainWork`
  difference is (`src/block_index.h:661-666`), and a host that stores chain
  work may override it. `median_time_past` is `GetMedianTimePast`
  (`src/block_index.h:720-737`).
- `DifficultyError` (`#[non_exhaustive]`): `MissingAncestor` (the host does
  not hold a header the rule reads), `ChainTooShort` and `ZeroWork` (where the
  node asserts or throws), `InvalidParams` (a host's parameters with no
  adjustment interval). Nothing panics, on any chain or parameters.
- Tests (`tests/chain_difficulty.rs`, in CI's chain vector step): the node's
  `pow_tests.cpp` tables (`get_next_work` and its three bounds,
  `retargeting_test`, `cash_difficulty_test`) carried over from chaintracks
  with their citations, the regimes' edges, and the real testnet run
  1602530..=1602710 (Teranode v0.16.0's file, sha256 pinned): the 34 headers
  with a full DAA window carry the rule's bits, 8 of them under the
  20-minute rule, and a header mined 600 s after 1602682 at the minimum
  difficulty does not.

### Notes: cross-SDK parity

Neither `@bsv/sdk` (ts-sdk `src/`) nor go-sdk carries a difficulty rule;
there is no SDK function to conform to, so the node decides.

## [0.7.1] - 2026-10-19

### Added: HKDF (RFC 5869), SHA-256 and SHA-512

`primitives::hash` gains HKDF beside PBKDF2: `hkdf_sha256` and
`hkdf_sha512` (extract then expand into a caller's buffer),
`hkdf_sha256_extract` / `hkdf_sha512_extract` (the pseudorandom key) and
`hkdf_sha256_expand` / `hkdf_sha512_expand`, with `HKDF_SHA256_MAX_OKM`
and `HKDF_SHA512_MAX_OKM` (`255 * HashLen`). An empty salt is the RFC's
"not provided" (HashLen zero bytes, the same HMAC key). Expand refuses an
output over `255 * HashLen` (`Error::InvalidDataLength`) and a PRK shorter
than HashLen (`Error::InvalidKeyLength`) without writing the output. No new
dependency: the construction runs on the crate's `hmac` 0.12 and `sha2`
0.10. Additive, no migration.

- RFC 5869 Appendix A, all seven cases: A.1 to A.3 through the public
  HKDF-SHA256 functions (PRK and OKM), A.4 to A.7 (HKDF-SHA1, A.7 with the
  salt not provided) through the same private extract and expand
  (`src/primitives/hash.rs` tests).
- Project Wycheproof `hkdf_sha256_test.json` (86 tests: 83 valid, 3
  `SizeTooLarge` refused) and `hkdf_sha512_test.json` (83 tests: 80 valid, 3
  refused), C2SP/wycheproof at `e0df04e0`, copied under
  `tests/vectors/wycheproof/` with their sha256 pinned
  (`tests/hkdf_wycheproof.rs`).
- HKDF-SHA512 on A.1's and A.3's inputs against OpenSSL's `openssl kdf ...
  HKDF`.

### Notes: cross-SDK parity

Neither `@bsv/sdk` nor go-sdk exposes HKDF; there is no reference function
to conform to, so RFC 5869 and the vectors above decide.

## [0.7.0] - 2026-10-17

### The default signing digest is the node's

`SigningContext::compute_sighash`, the digest every template's `unlock`
(`P2PKH`, `P2PK`, `Multisig`, `RPuzzle`, `PushDrop`) and `Transaction::sign`
sign, disagreed with bitcoin-sv v1.2.3 in three places; each produced a
signature the node refuses.

- The dispatch. The context computed the BIP143 digest for every hash type.
  The node's `SignatureHash` computes BIP143 only for a type that carries
  `SIGHASH_FORKID` and not `SIGHASH_CHRONICLE` (0x20), and the original
  digest for every other type (`src/script/interpreter.cpp:2112-2124`). The
  context now computes through `compute_sighash_dispatched_for_signing`, the
  dispatch the interpreter's verdicts already use
  (`TxSighashCache::sighash_dispatched_for_signing`, pinned equal to it): one
  rule for the signer and the verifier.
- The SINGLE sentinel. Under the original digest, `SIGHASH_SINGLE` with the
  input index at or beyond the outputs signs the constant `one` (`0x01` then
  31 zero bytes in signing order; `interpreter.cpp:2089`, `:2095-2100`). The
  context built a BIP143 preimage with a zero hashOutputs instead. It now
  returns the constant, as the dispatcher does.
- The scriptCode. The context always signed over the source output's locking
  script. Post-Chronicle, a CHECKSIG executing inside the unlocking script
  signs the unlocking script from its last executed `OP_CODESEPARATOR` to
  its end, followed by the locking script (`interpreter.cpp:1471-1481`,
  CHECKMULTISIG `:1569-1576`, gated on `IsChronicle(flags)`; `VerifyScript`
  passes the scriptPubKey as `checksigData`, `:2336-2342`). The context
  cannot know where the CHECKSIG executes, so the scriptCode is now an
  explicit input: the new field `SigningContext::script_code:
  Option<&Script>` and the builder `SigningContext::with_script_code(self,
  &Script) -> Self` set it, and the new function
  `script::chronicle_unlocking_script_code(unlocking: &Script, locking:
  &Script) -> Script` forms the Chronicle one. The default (`None`) stays the
  locking script, which is right for a CHECKSIG in the lock that no executed
  separator precedes. The type's documentation says when it is wrong and what
  to pass.
- An input index the transaction does not have is now an `Err`
  (`Error::CryptoError`) from `compute_sighash`; before, it panicked in the
  preimage builder.

The templates sign `FORKID` types without `CHRONICLE`, so their digests and
signatures are byte-identical to 0.6.1's; what changes is the digest of a
custom template that calls `compute_sighash` with a type without FORKID or
with CHRONICLE.

Pinned in `tests/sighash_tests.rs` (in the CI's sighash step):
`the_default_signing_digest_is_the_dispatchers_for_every_hash_type` (the 18
types of {ALL, NONE, SINGLE} x {with, without ANYONECANPAY} x {FORKID,
FORKID|CHRONICLE, no FORKID}, over every input of generated transactions,
SINGLE beyond the outputs included, and two locks, one with a separator;
2,880 of 4,320 digests differed on 0.6.1),
`a_single_beyond_the_outputs_under_the_original_digest_signs_the_constant_one`,
`a_chronicle_hash_type_signed_through_the_context_verifies_under_the_node_word`
(P2PK spends signed through the context and run under the Chronicle block
word; 0.6.1's 0x61 signature was a false top),
`a_signing_context_naming_an_absent_input_is_an_error_not_a_panic`,
`the_chronicle_script_code_is_the_unlock_after_its_last_separator_then_the_lock`,
`the_chronicle_script_code_reads_separators_as_the_parser_reads_them`,
`a_check_in_the_unlocking_script_signed_over_the_helpers_script_code_verifies`
(the shape `<utxoSig> <sig> OP_CODESEPARATOR <pub> OP_CHECKSIGVERIFY` over
`<utxoPub> OP_CHECKSIG`: valid with the helper's scriptCode for ALL|FORKID
and ALL|FORKID|CHRONICLE, refused with the locking script alone), and the
guard `the_forkid_digest_of_the_templates_is_unchanged`.

Semver: minor. `SigningContext` gains a public field, so a struct literal of
it no longer compiles. The migration is one line: add `script_code: None`,
or build it with `SigningContext::new`. The digest of a non-FORKID or
CHRONICLE type changes.

### The identity token signatures (the review of 0.7.0)

The review of this release found three signing paths that did not reach the
dispatcher: `IdentityClient::revoke_certificate_revelation`, and the contact
update and removal of `ContactsManager` (`add_contact` over a listed contact,
`remove_contact`). Each built the BIP143 preimage, took ONE SHA-256 of it and
passed that to the wallet as `hash_to_directly_sign`, which the wallet signs
as given; the node verifies against the double SHA-256 (`SignatureHashBIP143`,
`ss.GetHash()`). The reference passes `data: sha256(preimage)` and its wallet
hashes `data` again (`@bsv/sdk` 3.0.0 `src/script/templates/PushDrop.ts:245-248`,
`ProtoWallet.ts:62`). Every signature these paths produced was one the node
refuses; the bug predates this release (since `ee3adff`). They now sign
`compute_sighash_dispatched_for_signing` of the same parameters (scope
ALL|FORKID, so the BIP143 digest, double SHA-256). No public signature
changed.

Pinned in `tests/identity_spend_witness.rs`:
`an_identity_revocation_signature_verifies_under_the_node_word`,
`a_contact_update_signature_verifies_under_the_node_word` and
`a_contact_removal_signature_verifies_under_the_node_word` drive each path
against a wallet that records the unlocking script and run it through `Spend`
under `ScriptFlags::block(ProtocolEra::PostChronicle)`; on the code before
the fix each verdict was the NULLFAIL error ("OP_CHECKSIG requires failing
signatures to be empty.").

### Notes: cross-SDK parity

- The scriptCode: the go-sdk and `@bsv/sdk` default templates also sign the
  locking script alone (`go-sdk@v1.7.2`
  `transaction/template/p2pkh/p2pkh.go:83-91`,
  `transaction/signaturehash.go:277`; `@bsv/sdk` 3.0.0
  `src/script/templates/P2PKH.ts:92-100`, `SignatureUtils.ts:153`), so they
  share the default's disagreement for a CHECKSIG in a post-Chronicle
  unlocking script. This crate keeps that default and adds the explicit
  override and helper.
- The SINGLE sentinel is shared with @bsv/sdk 3.0.0's original-digest formatter (7 of the same 241 measured transactions); the Chronicle-bit dispatch was this crate's own disagreement.
  go-sdk's signer dispatches on the CHRONICLE bit (`go-sdk@v1.7.2`
  `transaction/signaturehash.go:26-30`).

### The lint bar (bsv-stack-lean #134, #135, #137, #139, #140, #144, #145)

No public signature changed.

- `[lints]` in `Cargo.toml`: `unsafe_code = "forbid"` (the crate has no
  `unsafe`), `missing_docs = "deny"`, and clippy's `unwrap_used`,
  `expect_used`, `panic`, `todo`, `unimplemented` and `dbg_macro` denied.
  `clippy.toml` lets a test function unwrap, expect and panic; each test,
  bench and example file that needs them carries one allow naming #134.
- The library's 115 unwrap, expect and panic sites: the infallible ones
  rewritten without a panic path (slice-to-array conversions, guarded pops
  and lookups, the curve constants built from bytes); the documented
  `# Panics` contracts and infallible public signatures allowed at the site
  with the reason. `Script::write_bin` and `LookupResolver::new` now document
  their panics.
- Behavior: the host reputation tracker and the cached key deriver read a
  lock poisoned by a panic elsewhere instead of panicking again.
- Docs on every public item: the 261 opcode constants of `script::op`, the
  fields of the `Error` struct variants and of `PowError`, and the wallet
  serde helpers.
- `rust-version = "1.88"` (1.87 refuses `slice::as_chunks`); the gate's
  `msrv` job checks the library on 1.88.0, native and wasm32.
- New gate jobs: `secrets` (gitleaks 8.30.1 over the history, built from a
  sha256-pinned source; judged findings in `.gitleaksignore`), `actionlint`
  (1.7.12, the same way, with a check that every `uses:` is pinned by a
  commit sha) and `unused dependencies` (cargo-machete 0.9.2, non-blocking;
  none found).

Correction (2026-10-17): the parity note above first said both the dispatch and the SINGLE sentinel were this crate's own; the sentinel is shared with @bsv/sdk 3.0.0, as the sentence now reads.

## [0.6.1] - 2026-10-15

### Incremental hashing

- New `primitives::hash::Sha256` and `primitives::hash::Sha256d`: `new()`,
  `update(&[u8])` (returns `&mut Self`, so calls chain), `finalize(self) ->
  [u8; 32]`, `Default`, `Clone`, and a `Debug` that prints no state.
  `Sha256d::finalize` is SHA256(SHA256(everything updated)). The types wrap
  `sha2`; none of its types appear in the public API.
- `sha256` and `sha256d` are now defined through the hashers (one
  implementation); their signatures and results are unchanged.
- The site they serve: the relay's `inline_spool_key`
  (`src/beef_door.rs`), which hashes an inline payment 64 KiB at a time and
  kept a direct `sha2` for it while bsv-rs had one-shot hashes only.
- `tests/hash_stream.rs`: every row of bsv-stack-lean's BEEF-of-any-size
  corpus (`tests/vectors/beef_of_any_size/`) hashed whole and in chunks of 1,
  7, 64 KiB, its full length and seeded random boundaries, against the
  corpus's pinned digests; generated buffers of 0 to 300,000 bytes. Run by
  the vectors job.

## [0.6.0] - 2026-10-14

### Chain primitives

The design is `docs/p0/bsv-rs-060-primitives-design.md` in bsv-stack-lean.
Node rules are cited through bsv-script-lean@50d437b
`lean/BsvChain/{Header,Pow,Merkle}.lean` and `lean/BsvScript/Tx.lean`,
which cite bitcoin-sv v1.2.3 at 6504a3af (#63, #64, #65).

- New `block` feature, enabled by `transaction` and listed in `full`:
  `BlockHeader` (exact 80-byte frame, `version: i32`, internal-order hashes,
  `hash`/`id`), `CompactTarget` (`SetCompact`, negative and overflow flags),
  `U256::to_compact` and `to_compact_signed` (`GetCompact`),
  `check_proof_of_work` with network limits and non-exhaustive `PowError`,
  `ChainWork` (`GetBlockProof`, numeric order, strict 1-to-64-digit hex input),
  `merkle_root`, `block_merkle_root` and `merkle_parent`. List roots carry the
  node's `mutated` flag; a caller accepting a list must refuse a mutated result
  (CVE-2012-2459). Difficulty adjustment remains the host's responsibility.
- New `primitives::U256`: four little-endian u64 limbs, modulo-2^256
  arithmetic, checked division, fixed-width bytes and numeric hex.
- `primitives::Hash32` moves from `transaction::beef_stream`, with a
  compatible re-export at the old path.
- `Reader::read_var_int` now refuses non-canonical encodings, as the node's
  `ReadCompactSize` and ts-sdk's `readVarIntNumStrict` do. This also applies
  to transactions, whole and streaming BEEF, and BUMP parsers.
  `read_var_int_lenient` preserves 0.5's reading. Streaming refusals reuse
  `BadVarint` at the field's leading byte, including across chunk boundaries.
- New `read_compact_size`, `write_compact_size` and `MAX_COMPACT_SIZE` apply
  the node's `MAX_SIZE = u32::MAX`; general varints retain the u64 range.
  `var_int_len`, `to_var_int` and `from_var_int` expose the shared encoding.
  New exhaustive `Error` variants `NonCanonicalVarInt { width, value }`
  (width includes the marker) and `CompactSizeTooLarge`: update exhaustive
  matches. Stored non-canonical transaction, BEEF or BUMP bytes must be
  revalidated when a consumer adopts 0.6.0; no stored data is rewritten here.
- Base58Check signatures and behavior stay unchanged. Rust transcriptions
  of the node's 12 raw base58 rows and 50 key rows, compact-target tables,
  varint refusals, merkle properties and three pinned header runs are tested.
- No dependency added, no serde on the new types. wasm32 builds cover
  `block`, `transaction` and the existing application feature combination.

### Notes - cross-SDK parity

Raw `from_base58` retains the TypeScript SDK's refusal of empty input and
surrounding whitespace (`ts-stack@edf6e03`, `utils.ts:288-296`), differing
from the node's `DecodeBase58` (`src/base58.cpp:25-79` at 6504a3af).
Canonical varints agree with the node and TS strict readers; Go v1.7.1
`util/varint.go:71-105` remains lenient. A host wanting the node's size bound
uses the CompactSize methods. The tests are `canonical_varint`,
`chain_encoding` and `chain_primitives`; the vectors CI job runs all three.

## [0.5.0] - 2026-10-12

### Mining checks in the streaming BEEF reader (bsv-stack-lean #68)

The reading is `docs/readings/mining-checks-against-the-reader.md` in
bsv-stack-lean, sections 1-3. Node rules are cited through
bsv-script-lean@87f0461 `lean/BsvScript/TxRules.lean:25,31-38,85-110`
and `docs/BLOCK-CONSENSUS.md:68,83-88`; the latter cites
bitcoin-sv@879fc8b42 `IsFinalTx` and `COINBASE_MATURITY`.

- Four new exhaustive `Kind` and `Reason` variants, in the decoder and
  hand-built fold, also under `structure_only`: `UnprovenCoinbase` at the
  transaction's leading byte (ahead of `NoOutputs`); `NullOutpoint` at
  the input's previous txid; `DuplicateInput` at the repeating input's
  previous txid; `ValueOutOfRange` at the output value field that leaves
  MoneyRange, individually or in running total. The checks use the
  sibling's order: coinbase, no inputs, no outputs, output values, then
  null and duplicate outpoints in input order. Proven coinbases remain
  allowed; the other byte checks apply with a BUMP index too.
- `Kind::ALL` has 24 entries. `OutputRef` gains public `at: u64`, the
  absolute value-field offset. Update exhaustive matches and hand-built
  output literals. These public changes require the minor release 0.5.0.
- New `SpendRefusal::InputValueOutOfRange` at the input leaving MoneyRange,
  replacing the overflow `Script` string. The unreachable output overflow
  branch of `CreatesValue` is removed; a debug assertion records the bound.
- `Headers::mining_tip() -> Option<ChainTip>` defaults to `None`, and the
  object-safe async `ChainTracker::mining_tip()` defaults to `Ok(None)`.
  Existing implementors compile. `ChainTip` carries `height: u32`,
  `median_time_past: u32`, network `genesis_height: u32` and
  `csv_height: u32`, and `next_block_time: Option<u32>` for a candidate
  block before CSV. References forward the synchronous method.
- `SpendRefusal::P2shOutput { vout }` names the output value field of an
  exact 23-byte P2SH template in an unproven transaction when the next
  block is after Genesis. With no tip, the Genesis era defaults to after
  Genesis. Proven transactions and near-shapes are unchanged.
- `SpendRefusal::NonFinal { lock_time }` names an unproven transaction's
  leading byte when the supplied next-block context fails the node's
  `IsFinalTx`. After CSV time locks use tip median time past; before CSV
  they need the candidate block time. Zero lock time or all-final
  sequences need no tip. A caller that never supplies a tip now receives
  `Verdict::Unverifiable { check: MiningCheck::Finality, .. }` for any
  nonzero lock time with a non-final sequence. This is a fail-closed
  decline, never `Invalid` or `NonFinal`; no tip is guessed. The fold
  returns `Stop::Unverifiable` with the same offset and check.
- `SpendRefusal::PrematureCoinbase { height }` names the spending input
  when a verified coinbase is fewer than 100 blocks old at the next
  block. With no tip the reader declines with
  `Unverifiable { check: MiningCheck::CoinbaseMaturity, .. }`.
  Verified coinbase heights survive retention and cursor round trips.
  Cursors now use `BSC2`; `BSC1` lacks maturity evidence and is rejected.
  Restart old cursors from the beginning of their BEEF.
- Contextual spend checks run only in full mode on unproven transactions.
  `ParentIsTxidOnly`, `OutputNotAvailable`, `Script` and `CreatesValue`
  are unchanged otherwise. Cross-transaction respend stays
  `OutputNotAvailable`; a repeat within one transaction is now invalid
  bytes. Script evaluation keeps the TypeScript default mode; spend-era
  flags and confiscation rules remain the sibling's separate work.

### Notes - cross-SDK parity

Intentional differences from ts-stack@edf6e03: the node's output checks
precede duplicate inputs; the reader also checks P2SH, mining finality and
coinbase maturity. Against go-sdk@v1.7.2, a missing tip is an explicit
unverifiable decline, including a GullibleHeadersClient-style absence,
not a guessed height or an invalid transaction. With a tip the SV node's
block path decides finality, including the pre-CSV candidate block time.
The boundary and refusal-offset witnesses are `tests/beef_stream.rs`;
`tests/mining_tip_api.rs` checks default and reference compatibility.

## [0.4.5] - 2026-10-12

Two rules of bsv-stack-lean L2: the lone leaf at offset 0 only (PR #51) and a LOCAL work bound inside one input's script (LOW's R404-H1, bsv-stack-lean #75 B; PR #52). No verdict moves under the defaults.

### Fixed

- `MerklePath` refuses a one-level proof holding one hashed leaf at a
  nonzero offset, with `MissingSibling` and the missing sibling's level
  and offset. Parsing and `compute_root` share the check in `RootWalker`,
  including paths built in memory. Offset 0 remains the one-transaction
  block, its root the txid; `from_coinbase_txid` is unchanged. This closes
  the disagreement with the BEEF reader. The six witnesses in
  `tests/merkle_path_lone_leaf.rs` pin the parse, root, combine and BEEF
  answers on the stack's `lone` and `lone_at_one` bodies.

### Notes - cross-SDK parity

- Intentional divergence: TS returns the txid for a lone leaf at any
  offset (`ts-stack@edf6e03`, `MerklePath.ts:345,390-391`), as does Go
  (`go-sdk@v1.7.1`, `transaction/merklepath.go:354-363`). This crate accepts
  only offset 0: the node requires the leading transaction to be the
  coinbase, so a block of one transaction holds it at index 0 (bitcoin-sv
  v1.2.3, `src/validation.cpp:5823-5824`, `CheckBlock`, calling
  `CheckCoinbase` at `:577-579`, `bad-cb-missing`). BRC-62 reads the level-0
  offset as the transaction's index in the block (`BRCs@ed1b015`,
  `transactions/0062.md:179-180`); BRC-74 defines it as the position from
  the left (`transactions/0074.md:66`), and its illustrative routine
  refuses a lone leaf at a nonzero offset (`:326-335`). Every builder
  writes 0: `MerklePath.fromCoinbaseTxidAndHeight` (`ts-stack@edf6e03`,
  `MerklePath.ts:181-183`), `NewMerklePathFromCoinbaseTxid`
  (`go-sdk@v1.7.1`, `transaction/merklepath.go:156-178`), and go-sdk#348's
  testnet vector (`transaction/merklepath_test.go:325-341`). The same
  refusal is proposed to the TypeScript and Go SDKs. Callers holding a
  nonzero lone-leaf proof must obtain a valid proof; its offset must not
  be rewritten on trust. No public type changes.

### Added: a LOCAL work bound inside one input's script

LOW's R404-H1 on the relay's 0.4.4 (bsv-stack-lean #75 B): the clock of
0.4.4 pauses between inputs, but one input with many original-digest
signature checks hashes its wide transaction repeatedly before that clock
is asked again. `SpendParams` and `TxSpendParams` now take
`work_limit: Option<u64>`. The default `None` preserves every verdict and
runs without calculating hash costs. Under `Some(n)`, each reached opcode
costs one unit plus the bytes hashed: the signature's serialized preimage,
the 32-byte intermediate of a double hash, and BIP-143 midstates only when
the shared cache does not cover them (SINGLE outputs are not cached).
Every charge precedes its work; an exhausted budget is
`ScriptResource::Work`, a LOCAL evaluator decline, never an invalid script.
`ScriptResourceLimit` carries `work_spent: Some(n)` for Work, the budget and
the attempted charge as `u64` on native and wasm32. Memory resources keep
their byte counts, now `u64`, and have `work_spent: None`.

`StreamVerifier::set_work_limit` and `AsyncStreamVerifier::set_work_limit`
set that bound per input. The reader returns
`SpendRefusal::Resource(ScriptResourceLimit)` at the named input, preserving
memory declines too. The cursor's bytes and `step_until`'s between-input
pause are unchanged: reapply the local budget after `resume`. A declined
Spend stays declined until `reset`; no within-script resume is introduced.
This is a work bound, not a wall clock: parsing, allocation, arithmetic and
curve verification are not measured in hash bytes.

The witness is `tests/script_work_budget.rs`: one 1 MB subject input with
10,000 valid original-digest checks, declined within its script under the
budget; the identical body under an ample budget keeps its verdict. It
also pins hash charging, exact boundaries, CHECKMULTISIG propagation, a
wrong digest's unchanged refusal, and the reader's named decline. The
explicit native release control measures 1,000 and 10,000 checks. No
version bump here; the release joins this lane and L2-offset0.

Migration: add `work_limit: None` to spend parameter literals and
`work_spent: None` to memory resource literals; resource byte fields are
`u64`. Match the new `ScriptResource::Work` and `SpendRefusal::Resource`
variants as local declines before interpreting validity.

### Notes: cross-SDK parity

The opt-in work budget is this crate's local evaluator contract, extending
the TS SDK's memory resource distinction (`ts-stack@edf6e03`,
`ScriptResourceLimitError.ts`). It changes no wire format, digest or node
rule. The default evaluation keeps the existing reference verdicts.

## [0.4.4] - 2026-10-10

The spend of an unproven transaction is linear in its inputs, and the reader
can pause between two inputs and resume from the input reached (bsv-low
#591: LOW's R400-H1 and R403-H1, found on the relay's payment door over
0.4.3). LOW's shape: a proven parent with n `OP_TRUE` outputs, a subject
spending all n with empty unlocks. On the relay's door over 0.4.3 they
measured 4,000 inputs in 0.10 s, 16,000 in 1.8 s, 64,000 (3.3 MB) in 18.5 to
24.9 s and 128,000 (6.5 MB) in 186 s.

### Fixed: the spend of a wide transaction grew with its inputs squared

- At 0.4.3 `BeefIndex::check_spends_of` cloned the other inputs and the
  outputs for every input; every `OP_CHECKSIG` rebuilt the input list and
  recomputed hashPrevouts, hashSequence and hashOutputs over it; and spending
  an output walked its parent's whole output table. Now the reader and
  `Transaction::verify` build one input list and one output list per
  transaction, shared by every input's spend with its sighash midstates
  (each computed at most once per transaction and scope class), and an
  output table keeps its unspent count.
- The witness (`tests/beef_stream_linear_spend.rs`, release, `--ignored`),
  `verify_stream` of LOW's shape on the studio (aarch64-apple-darwin):

  | n | 0.4.3 | 0.4.4 |
  |---|---|---|
  | 4,000 | 0.072 s | 0.002 s |
  | 16,000 | 0.804 s | 0.006 s |
  | 64,000 | 11.994 s | 0.022 s |

  Quadruple the inputs: 14.92 times the time at 0.4.3, 3.81 here.
- The digests do not move: 1,000 P2PKH spends signed over 0.4.3's free
  function under six scopes verify, and a signature over another digest is
  refused at its input; `TxSighashCache` equals
  `compute_sighash_dispatched_for_signing` for every scope byte and input.
- The original (pre-fork) digest, for a scope without FORKID or with the
  CHRONICLE bit, still serializes every input per signature, as the
  reference's `SignatureHashOriginal` does: a transaction of n such
  signatures is still n squared bytes hashed. The clock between inputs is
  what bounds a request's share of it.

### Added: a clock between inputs

- `StreamVerifier::step_until(spent)` asks the caller's budget between two
  inputs of an unproven transaction and answers `Timed::Paused` when it is
  spent, at least one input of the step having run; the next call continues
  in place. `step` is `step_until` with a budget never spent.
- The cursor of a paused reading is the state before the transaction
  (`Cursor::offset` its element's first byte, the index unchanged) and names
  the input reached (`Cursor::input_reached`). `StreamVerifier::resume` and
  `AsyncStreamVerifier::resume` re-read that one transaction and run its
  scripts from that input on; the inputs before it never run again. A
  resumed slice re-reads the transaction's bytes and re-resolves its inputs
  (linear in it), never its scripts.
- Cursor bytes: a cursor between two elements has 0.4.3's bytes exactly; a
  paused one appends a presence byte, the offset, the txid and the input.
  0.4.3 refuses a paused cursor's bytes ("bytes after its end").
- The witness (`tests/beef_stream_pause.rs`): a 64,000-input subject read in
  slices of 10,000 inputs pauses at inputs 10,000, 20,000, ..., 60,000 (a
  restart would pause at 10,000 each time), each cursor through its bytes and
  a fresh reader, to the verdict of the whole; a refusal at input 60,000 is
  the same paused or not; the asynchronous reader resumes a paused cursor; a
  reading with no slice never pauses.

### Changed

- **`Spend`** holds the transaction as an `Arc<TxSighashCache>`.
  `Spend::new(SpendParams)` keeps its shape and its verdicts and builds the
  list once per spend. New: `Spend::with_transaction(TxSpendParams)` (the
  shared transaction, the input index, the source satoshis, the two scripts,
  the memory limit), which copies nothing per input, the constructor for a
  caller that checks every input of a transaction (the CLI, the toolbox, the
  relay); `Err` when the index names no input.
- **New public items**, nothing removed: `primitives::bsv::sighash::TxSighashCache`,
  `script::TxSpendParams`, `Spend::with_transaction`,
  `transaction::Timed`, `StreamVerifier::step_until`, `Cursor::input_reached`.
  `Progress` is unchanged, so no caller's `match` breaks.

## [0.4.3] - 2026-10-10

A raw transaction with no output is invalid bytes, as one with no input has
been since 0.4.1, and `Transaction::verify` refuses both (bsv-stack-lean #59,
found by the NL-3b lane while closing #58). The rule is the node's, cited not
restated: bsv-script-lean@87f0461 `lean/BsvScript/TxRules.lean:85-86`
(`checkTransactionCommon`: `vinEmpty`, then `voutEmpty`; the theorems
`checkTransactionCommon_vinEmpty` and `checkTransactionCommon_voutEmpty`). The
posture of 0.4.0 stands: a refusal is for invalid bytes only, never for a
size or a count; `NoOutputs` refuses the one count, zero, that makes the bytes
no transaction, and bounds nothing from above.

### Fixed: a transaction with no output was read as valid

- The streaming reader, `BeefStream`, `verify_stream` (with or without
  scripts, under a subject, in two passes) and `verify_stream_async` refuse a
  raw transaction with at least one input and no output as
  `Invalid { offset, kind: Kind::NoOutputs, reason: Reason::NoOutputs }`, the
  offset its leading byte, with or without a BUMP index. One with neither is
  `NoInputs`, the node's order. The index's fold holds an `Element` built by
  hand to the same rule.
- `Beef::verify_valid`, `is_valid` and `verify_structure` refuse a BEEF that
  carries one (`Kind::NoOutputs`; `BeefTx::has_no_outputs`, new). The kind is
  the first such transaction's in the order held when it is called, the
  reader's order, before the sort.
- One helper answers both counts in the node's order for every path
  (`beef_stream::no_transaction`, crate-private).
- Witnesses, red at 0.4.2 and green here (`tests/beef_stream.rs`):
  `a_transaction_with_no_output_is_invalid_bytes_at_its_offset` (V1 and V2,
  every reader and the whole path), `a_transaction_with_no_output_is_invalid_under_a_bump_too`,
  `the_leans_no_output_rows_have_the_leans_offsets` (the Lean's rows of
  `BeefOfAnySize`: 111, 147 behind the Atomic prefix, 49 under a BUMP, and
  neither at 111 as `NoInputs`), `the_asynchronous_reader_refuses_a_transaction_with_no_output`;
  `a_transaction_with_neither_is_refused_for_its_inputs_first` holds the order.

### Fixed: `Transaction::verify` exempted a root with no input

- Through 0.4.2 the linked walk treated a transaction with no inputs as a
  synthetic root and skipped the value rule for it, and judged a transaction
  with no output like any other. Every transaction the walk reaches (the one
  verified, each popped ancestor, each source it resolves), proven by a
  merkle path or not, is now refused with either:
  `transaction error: invalid transaction <txid>: NoInputs` (or `NoOutputs`),
  the reader's kinds. The value rule's exemption is gone; nothing reaches it.
- Witnesses, red at 0.4.2 (`Ok(true)`) and green here (`tests/beef_stream.rs`):
  `verify_refuses_a_root_with_no_input` (unproven, proven, the transaction
  itself), `verify_refuses_a_transaction_with_no_output` (the subject, a
  proven ancestor, neither; the control `Ok(true)`).

### Changed

- **`Kind` and `Reason` gain the variant `NoOutputs`**, last; `Kind::ALL` is
  `[Kind; 20]`. Neither is `#[non_exhaustive]`, so an exhaustive `match` needs
  the new arm and a binding typed `[Kind; 19]` needs `20`, as at 0.4.1.
- **A root needs an input.** A test or a caller that built a funding
  transaction with outputs and no inputs and verified a spend of it gets the
  refusal. Give the root one input and, so the walk need not descend it, a
  merkle path (for a block of one transaction,
  `MerklePath::from_coinbase_txid`) and a tracker that carries its root.
  `examples/transaction.rs` (and the README block that is its body) and
  `tests/transaction_tests.rs`'s `build_source_tx` moved so.
- Nothing stored changes: a BEEF stored by an earlier version is held to
  these rules on its next read.

### Notes: cross-SDK parity

Read at the pin, not run against the reference:

- The reference's `Beef.verifyValid` has no such check
  (`ts-stack@edf6e03 packages/sdk/src/transaction/Beef.ts:1054-1075`).
- The reference's `Transaction.verify` refuses an unmined transaction with no
  inputs, then one with no outputs (`Transaction.ts:1336-1342`, called for an
  unmined transaction at `:1654`), and does not ask it of a proven one. This
  crate's walk asks it of every transaction it reaches, as its reader does;
  through 0.4.2 its walk exempted what the reference refuses.

## [0.4.2] - 2026-10-10

The whole-BEEF path (`Beef::from_binary` then `Beef::verify_valid`) walks a
BUMP once, in time linear in its leaves, and refuses the bytes the streaming
reader refuses, with the reader's kinds (bsv-stack-lean #61, found by the
replay NL-8, `docs/p0/nl-8.md` W1 to W5). The posture of 0.4.0 stands: a
refusal is for invalid bytes only, never for a size or a count; every refusal
added here is of bytes the reader and the Lean definition `BeefOfAnySize`
already refuse.

### Fixed: the whole path walked a BUMP once per leaf (W1)

- `verify_valid` computed each flagged level-0 leaf's root by
  `MerklePath::compute_root`, and each call built a fresh walker that
  recomputed every node it needed from level 0: quadratic in the leaves. A
  BEEF of one BUMP of 4,096 leaves (146,976 bytes) took 29.8 s in release;
  8,192 leaves (294,433 bytes) gave no answer in 120 s, where the streaming
  reader answers in 0.012 s.
- Each BUMP's root is now the streaming reader's walk (`bump_root`, the one
  walker under both paths), once per BUMP; a transaction's BUMP index is held
  to an index of each BUMP's level 0 built once. The same probe at this
  release: 0.031 s at 4,096 leaves, 0.066 s at 8,192 (release, parse and
  verdict together).
- Witness, red at 0.4.1 and green here: `tests/beef_stream.rs`
  `the_whole_path_walks_a_wide_bump_in_linear_time` (4,096 and 8,192 leaves,
  each under `WHOLE_PATH_BOUND`, 10 s, generous for a debug build).
- `MerklePath::compute_root` and the parse's own root check are unchanged:
  one call is linear, and the parse's check shares its nodes since 0.3.35.

### Fixed: the whole path accepted bytes the reader refuses (W2 to W5)

Each of these is invalid bytes, refused by the streaming reader at its offset
with the kind named, and accepted by 0.4.1's whole path:

- **A lone leaf at an offset other than 0** (`MissingSibling`). The block of
  one transaction is the one leaf at offset 0, and its root is that txid; the
  same leaf at any other offset has no sibling. `MerklePath` alone keeps the
  reference's reading (below).
- **A byte after the frame** (`TrailingBytes`). `Beef::from_binary`,
  `Beef::from_hex`, the deprecated `from_binary_with_limits`, and
  `Transaction::from_beef` and `from_atomic_beef` through them, refuse it with
  the reader's words: `invalid BEEF at byte N: TrailingBytes`.
  `Beef::from_reader` still reads one BEEF out of a longer stream and leaves
  what follows to its caller.
- **An atomic BEEF whose subject is not the last raw transaction**
  (`SubjectMissing`), **or that carries a transaction or txid-only entry no
  later raw transaction spends** (`UnrelatedTransaction`). "Last" and "later"
  are the order the transactions hold when `verify_valid` is called, before
  its sort: the wire's for a BEEF just read.
- **A txid-only entry no BUMP of the BEEF proves** (`StubNotProven`), with
  `allow_txid_only` true. A txid-only entry is now read on its own: valid when
  a BUMP of this BEEF carries its txid at level 0, refused otherwise.
- Witnesses, each red at 0.4.1 and green here, each holding the whole path's
  kind to the reader's on the same bytes (`tests/beef_stream.rs`):
  `the_whole_path_refuses_a_lone_leaf_at_an_offset_other_than_0`,
  `the_whole_path_refuses_a_byte_after_the_frame`,
  `the_whole_path_holds_an_atomic_beef_to_its_subject`,
  `the_whole_path_reads_each_txid_only_entry_as_the_reader_does`.

### Added

- `Beef::verify_structure() -> Result<HashMap<u32, String>, Kind>`: the
  roots, or the reader's `Kind` for what is wrong (the in-memory BEEF has no
  offsets to name). `verify_valid` and `is_valid` are it without the kind.

### Changed

- **`allow_txid_only` decides nothing.** Through 0.4.1, `true` accepted every
  txid-only entry and `false` refused every one; now a proven entry is valid
  and an unproven one is not, under either value. The parameter stays for the
  signature. A caller that passed `true` for txids it holds elsewhere (a
  wallet's known txids) must carry their BUMPs in the BEEF or check those
  txids itself; a caller that passed `false` now accepts a txid-only entry
  this BEEF's own BUMP proves. `tests/transaction_tests.rs`
  `test_beef_txid_only_validation` pinned the old flag and now pins the
  refusal.
- `verify_valid`'s `roots` holds every BUMP's height, flagged leaf or not, and
  a BUMP whose walk fails is not valid (0.4.1 skipped a root it could not
  compute). Two BUMPs at one height with different roots stay not valid.
- No signature changed and no type gained a field or a variant.

### Notes: cross-SDK parity

Read at the pin, not run against the reference:

- The lone leaf: the reference accepts one at any offset and returns the txid
  as the root (`ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts:345`,
  `:390-391`); so do this crate's `MerklePath::from_binary` and
  `compute_root`, unchanged. The whole-BEEF verdict follows the reader and the
  chain: the only transaction of a block is its coinbase, at index 0
  (bsv-stack-lean `docs/readings/one-transaction-block-lone-leaf.md`).
- The trailing byte: the reference's `Beef.fromBinary` is the prefix parser
  and `fromBinaryStrict` the framed one, which throws "Serialized BEEF
  contains trailing data" (`Beef.ts:1286-1309`); its `fromString` is strict
  (`:1319`). This crate's `from_binary` is now the framed one; `from_reader`
  is the prefix parser.
- The atomic rule: the reference refuses an atomic BEEF unless every
  transaction is in the subject's ancestry (`Beef.ts:482-491`, `:420`, checked
  by `verifyValid` at `:1064`), which refuses the same rows by another rule.
- The txid-only flag: the reference's `verifyValid` refuses every txid-only
  entry unless `allowTxidOnly` is true and then accepts every one
  (`Beef.ts:1070`, `:1101-1104`). This crate reads each entry, as its reader
  does.

## [0.4.1] - 2026-10-09

A raw transaction with no input is invalid bytes (bsv-stack-lean #58, found by
the middleware's door, bsv-middleware-rs 0.4.0). The rule is the node's and is
cited, not restated: bsv-script-lean at `87f0461`,
`lean/BsvScript/TxRules.lean:85` (`checkTransactionCommon`, the verdict
`vinEmpty`; the theorem `checkTransactionCommon_vinEmpty`, `:216-219`), its
page `docs/BLOCK-CONSENSUS.md:31-32`, the S6 issue #61 under the charter #58.
The posture of 0.4.0 stands: nothing is refused for a size or a count.

### Fixed: a transaction with no input was read as valid

- The streaming reader held an unproven transaction by its inputs alone, so
  one with no input passed with nothing proven beneath it, and a payment
  spending it was `Valid` whenever the BEEF also carried any BUMP the headers
  knew (a proven stranger beside it was enough). `Beef::verify_valid` read the
  same bytes as valid for the same reason. Under a BUMP index the bytes were
  taken on the BUMP's word, though no block holds such a transaction.
- `verify_stream`, `verify_stream_structure`, `verify_stream_two_pass`,
  `verify_stream_async` and `BeefStream` itself now refuse it as
  `Invalid { offset, kind: Kind::NoInputs, reason: Reason::NoInputs }`, the
  offset the transaction's leading byte, with or without a BUMP index, in V1
  and V2. The decoder refuses the element when its last byte is read
  (`BeefDecoder`), and `BeefIndex::fold` holds an element built by hand to the
  same rule.
- `Beef::verify_valid` and `Beef::is_valid` answer not valid for a BEEF that
  carries one (`BeefTx::has_no_inputs`, new).
- The witnesses, red at 0.4.0 (`Valid` in every one) and green here, in
  `tests/beef_stream.rs`:
  `a_transaction_with_no_input_is_invalid_bytes_at_its_offset` (the
  middleware's BEEF: a proven stranger, the transaction with no input, a
  payment spending it), `a_transaction_with_no_input_is_invalid_under_a_bump_too`
  and `the_asynchronous_reader_refuses_a_transaction_with_no_input`;
  `the_leans_no_input_rows_have_the_leans_offsets` holds the Lean rows'
  offsets (111, 147 behind an Atomic prefix, 49 under a BUMP).
- The specification moved with it: `BeefOfAnySize` of bsv-stack-lean gains
  `Reason.noInputs` and its theorem (NL-1c). The rows this crate replays gave
  their proven anchor one input; `tests/beef_stream_deep.rs` holds the Lean's
  new counts (6,000,112 bytes and 6,700,132 units of work at 100,000 links).

### Changed

- `Kind` and `Reason` gain the variant `NoInputs`, and `Kind::ALL` is
  `[Kind; 19]`. Neither enum is `#[non_exhaustive]`: an exhaustive `match` on
  `Kind` or `Reason` needs the one new arm, and a binding typed `[Kind; 18]`
  needs `19`.
- A BEEF built for a test around a synthetic root (a `Transaction::new()` with
  outputs and no input) is no longer valid to `verify_valid` or the streaming
  reader. Give the root an input and a merkle path, as `examples/beef_spv.rs`
  now does (the README's block follows it).
- `Transaction::verify` is unchanged: it still walks a linked object graph and
  still exempts a transaction with no inputs from the value rule.

### Notes: cross-SDK parity

- The reference's `Beef.verifyValid` has no such check
  (`ts-stack@edf6e03 packages/sdk/src/transaction/Beef.ts:1054-1075`, and the
  sort at `:1456-1470` queues an unproven transaction with no input with
  nothing to wait on), so it reads these bytes as valid. This crate follows
  the node. Read at the pin, not run against the reference.

## [0.4.0] - 2026-10-09

The posture (bsv-stack-lean, the charter "a BEEF of any size", the owner's
ruling of 2026-10-09): a valid BEEF is never refused for its size or its
counts. A refusal is for invalid bytes only, and names them. 0.3.35 gave doors
a verdict by size (`BeefLimits`); 0.4.0 takes that verdict away and gives them
a reader whose memory does not grow with the body.

### Added: the streaming BEEF reader (`transaction::beef_stream`)

- `verify_stream(source, headers, subject) -> io::Result<Verdict>` reads a BEEF
  from any `std::io::Read` in one pass, one step per element. Each BUMP's root
  is computed by a linear walk and checked against the `Headers` as it streams
  (no header at a height is fail closed); each unproven transaction's inputs
  are resolved against the index and their scripts executed against the parent
  output the index kept; a subject is held to the Atomic rule (it is the last
  transaction, and every other transaction is spent by a later one).
- The verdict is `Valid { subject, roots }`, `Invalid { offset, kind, reason }`
  or `SpendRefused { offset, txid, input, why }`. An `Invalid` carries the
  offset of the byte it names and one of eighteen `Kind`s (`Kind::ALL`), none
  of which is a size or a count. A spend the interpreter refuses is not one of
  the eighteen: it is the script's verdict on a transaction, and
  `verify_stream_structure` leaves it out.
- `BeefStream` yields the elements one at a time (`Element::Bump` with its
  root, `Element::Tx` with its txid hashed while the bytes passed,
  `Element::TxidOnly`) and holds one chunk of the source and the one element
  in hand. `BeefDecoder` is the same reader fed slices, for a source that is
  not a `Read`; `AsyncByteSource` and `verify_stream_async` read a request
  body or an object store's body stream against a `ChainTracker`.
- `BeefIndex` is what the reader keeps: one entry per element and one per txid
  a BUMP carries at level 0; with scripts, each unspent output until a later
  input spends it. Never a sibling hash, never a transaction's bytes after its
  step.
- `verify_stream_two_pass` reads a source that can be read again (an object
  at rest) twice: `referenced_outpoints` learns which outputs are spent, and
  the verifying pass keeps those alone. One pass cannot know which outputs
  will be spent and keeps every unspent one, which for transactions carrying
  large outputs nothing spends is their bytes.
- `Cursor` is the state after `k` elements, with `to_binary` / `from_binary`;
  `StreamVerifier::resume(cursor, source, headers)` over the rest of the stream
  yields the verdict of the whole, refusal for refusal.
- The specification is the Lean definition `BeefOfAnySize` of bsv-stack-lean
  (six theorems: `accept_iff_valid`, `accept_independent_of_size`,
  `memory_bounded_per_element`, `refusal_names_invalid_bytes`, `work_linear`,
  `resume_sound`). `tests/beef_stream.rs` replays its rows with their offsets
  and kinds, the BRC-62 example among them; `tests/beef_stream_deep.rs` reads
  the P0-5 chain at 1,000, 10,000 and 100,000 links on a 1 MiB stack and the
  P0-5c wide BUMP at 8,192 and 16,384 leaves, and holds the Lean's own counts
  at those sizes; `tests/memory_profiling.rs` measures the peak heap: 16,988
  bytes for the stream alone at every depth, about 128 bytes per element for
  the verdict at 100,000 links.
- One shape is accepted that the Lean definition refuses: the one-leaf BUMP of
  a block with only one transaction, whose root is the txid, as the reference
  and `MerklePath` read it (`MerklePath::from_coinbase_txid`).

### Changed (breaking): `BeefLimits` has no verdict

- `BeefLimits::max_bytes` is removed. `max_txs` and `max_bumps` are memory
  hints: how many entries the in-memory parse may reserve room for, never more
  than the bytes left could fill.
- `Beef::from_binary_with_limits` is deprecated and refuses nothing it did not
  refuse without limits. The three `BeefError` refusals of 0.3.35 (`BEEF of N
  bytes is over max_bytes`, `BEEF claims N BUMPs, over max_bumps`, `BEEF claims
  N transactions, over max_txs`) are gone. A count the bytes cannot honor is
  refused where the bytes run out (`ReaderUnderflow`), never for the count.
- Migration: delete `max_bytes` from a `BeefLimits { .. }` literal. A door
  that called `from_binary_with_limits` to bound a stranger's BEEF calls
  `verify_stream` on the body's reader instead and drops its 413. Code that
  matched on the three messages has nothing left to match. `Beef::from_binary`
  is unchanged and stays the reader for small bodies and for building.

## [0.3.35] - 2026-10-08

### Fixed: no walk over a BEEF's ancestry recurses (bsv-stack-lean #57, P0-5)

- A stranger's BEEF that is one chain of unproven transactions took the stack
  one frame (or several) per link: on a 1 MiB thread, the order of a WASM
  stack in a Worker, release builds aborted by 1,000 links in the link of
  `Transaction::from_beef` / `from_atomic_beef` (`Beef::find_atomic_transaction`),
  by 2,000 in `to_beef` / `to_atomic_beef` (and `to_beef_v1`, the same walk),
  in `Clone` of the linked result and in `id()` of a chain built with
  `add_input_from_tx`, by 4,000 in the overlay's `Historian` / `SyncHistorian`, and by 16,000 in the
  `Drop` of the linked result. A stack overflow is an abort, not a panic: in a
  Worker it takes every request in flight on the instance.
- Every one of those walks now keeps its work on the heap, in the recursive
  walk's order: the link (one full link per txid, a bare stub per repeat,
  cycle-safe, the same `source_transaction` shape), the serializers' ancestor
  collection, the historians, and `Transaction`'s `Clone` and `Drop`. `id()`
  hashes a chain's txid-less sources deepest first before it reads them. The
  witness, `tests/beef_deep_chain.rs`, runs each walk alone on a 1 MiB thread
  at 100,000 links; `iterative_equivalence_tests` in `beef.rs` holds each new
  walk to the 0.3.34 form on seeded random BEEFs.
- `Beef::sort_txs` rescanned the pending list once per resolved link, so a
  chain written newest first sorted in quadratic time (767.8 s for 128,000
  links in a release build). It now computes the same order in one pass, as
  the reference does (`@bsv/sdk` `Beef.#topoSort`).
- `to_beef` cloned each ancestor's whole ancestry into the BEEF it was
  building (quadratic in a chain's depth); it stores each ancestor without its
  sources, and writes the same bytes.

### Added: `Beef::from_binary_with_limits` and `BeefLimits`

- `BeefLimits { max_txs, max_bumps, max_bytes }` and
  `Beef::from_binary_with_limits(bin, &limits)`: a door that reads a stranger's
  BEEF refuses one over its byte length, BUMP count or transaction count with a
  `BeefError` naming the limit and the count, each count checked on its prefix
  before an entry of that kind is read. `Beef::from_binary` is unchanged (no
  bound beyond the bytes). `tests/beef_limits.rs`.

### Changed: `Transaction` implements `Drop`

- The ancestry is dropped one transaction at a time. A type with `Drop`
  cannot have a field moved out of an owned value, so code such as
  `if let Some(mp) = tx.merkle_path { .. }` or `let inputs = tx.inputs;` on an
  owned `Transaction` no longer compiles (E0509). Migration, one line:
  `tx.merkle_path.take()` / `std::mem::take(&mut tx.inputs)`, or borrow
  (`tx.merkle_path.as_ref()`). Compiled against this tree:
  bsv-wallet-toolbox-rs, bsv-wallet-cli, bsv-middleware-rs, rust-message-box,
  bsv-middleware-cloudflare, bsv-storage-cloudflare, rust-wallet-infra build
  unchanged; the overlay engine's `GET /tx/bump` route
  (`crates/overlay-cloudflare/src/routes.rs`) needs the one-line migration.

### Fixed: the BUMP parse is linear in its leaves (bsv-stack-lean #57, P0-5c)

- `MerklePath::from_reader` (under `from_binary`, `from_hex` and every BEEF
  parse) checks that every level-0 leaf computes the same root, and each check
  walked the tree again: a linear scan of each level for the sibling, a missing
  sibling recomputed from level 0. One BUMP of 8,192 flagged leaves with empty
  upper levels (294,433 bytes) took 225.7 s to parse in a release build, about
  five times per doubling, inside any `BeefLimits`. The check now shares every
  node it finds or computes across the walks, each level indexed by offset
  once, as the reference does (`@bsv/sdk` `MerklePath.computeRootCached`):
  0.051 s for the same bytes. `compute_root` uses the same walk. The answers
  and the errors are the 0.3.34 ones (`linear_root_equivalence_tests` holds
  the new walk to the old one on seeded random paths); the witness is
  `tests/merkle_path_cost.rs`.
- A tree-height byte over 64 shifted an offset by 64 or more: `attempt to
  shift right with overflow` in a debug build (or any build with
  `overflow-checks`), a wrong error in a release one. It is refused at the
  parse, before any shift, with `MerklePathError("Invalid tree height: 65,
  over the maximum height 64")`; `MerklePath::new` and `new_unchecked` refuse a
  path of more than 64 levels the same way, and no shift by a height can panic.

### Changed: `{:?}` of a `Transaction` prints a linked source as its txid

- `Transaction` and `TransactionInput` implement `Debug` by hand: an input's
  `source_transaction` prints as `Some("<txid>")`, never as the source's whole
  ancestry. The derived `Debug` printed every linked ancestor, one recursion
  per link, so `format!("{:?}", tx)` of a 1,000-link chain overflowed a 1 MiB
  stack and aborted. Every other field prints as the derive printed it. Code
  that parses `{:?}` output of a linked transaction sees the change.

## [0.3.34] - 2026-10-08

### Changed: QUEUED, REQUESTED_BY_NETWORK and CONFIRMED are accepted on a 2xx

- The reference's spec (`specs/broadcast/arc.yaml`) and go-sdk accept these three
  non-error states; the reference's TypeScript code reports them as an invalid
  response. bsv-rs follows the spec: the word is carried as the success message,
  a hint about the transaction and never evidence. An unknown word is still an
  invalid response. (bsv-stack-lean #35, the owner's ruling of 2026-10-08.)

### Fixed: an ARC answer is judged by its `txStatus`, never by the HTTP code

- `ArcBroadcaster::broadcast` read the HTTP code and nothing else: every 2xx
  was a `BroadcastResponse` with the body's `txStatus` as its message, so a
  wallet recorded as accepted a transaction the node refused (REJECTED,
  DOUBLE_SPEND_ATTEMPTED, MINED_IN_STALE_BLOCK, the ORPHAN statuses), and a
  2xx with no `txStatus` at all was a success. ARC answers 2xx whenever it
  processed the request and puts the verdict in the body
  (`arc@e7efc5b internal/api/handler/default.go:489-500`).
- Now the body's `txStatus` decides, by the reference's rule
  (`ts-stack@edf6e03 packages/sdk/src/transaction/broadcasters/ARC.ts:110-180`):
  `DOUBLE_SPEND_ATTEMPTED`, `REJECTED`, `INVALID`, `MALFORMED`,
  `MINED_IN_STALE_BLOCK` and any status or `extraInfo` containing `ORPHAN` are
  a `BroadcastFailure` whose `code` is the status word, whose `description` is
  the status word and the `extraInfo`, and whose `more` carries `extraInfo`
  and `competingTxs` when sent; a missing `txStatus`, a status word outside
  the reference's accepted set, or a malformed `competingTxs` list is
  `ERR_INVALID_RESPONSE`; a failure naming another transaction's id is
  `ERR_TXID_MISMATCH`. An accepted status is a success whose `message` is the
  status word and whose `competing_txs` are ARC's, lower-cased. The non-2xx
  path is unchanged.
- Pinned by `tests/vectors/arc_tx_status_verdicts.json` (17 recorded 2xx
  bodies and their verdicts; shared with the other ports), served through
  wiremock in `tests/broadcaster_http_tests.rs`
  (`an_arc_2xx_answer_is_judged_by_its_tx_status_not_by_the_http_code`, 14 of
  17 wrong before the fix) and replayed through the verdict alone in
  `src/transaction/broadcasters/arc.rs`. bsv-stack-lean #35, P0-2.
- Migration: none in the API. Callers that matched `Ok(_)` on every 2xx now
  receive `Err(BroadcastFailure)` with the real verdict; a caller that treated
  `response.message == "REJECTED"` as a failure by hand can drop that check.

### Notes: cross-SDK parity

- The success `message` stays the status word alone; the reference appends
  the `extraInfo` (`ARC.ts:176`). The success path keeps ARC's echoed `txid`
  without the reference's mismatch check (`ARC.ts:161-171`); the failure path
  has it (`ARC.ts:136-146`). A `BroadcastFailure` always carries the
  submitted `txid`; the reference sets it only when ARC echoed a valid one
  (`ARC.ts:152`).
- An explicit `"competingTxs": null`, which ARC sends on an ordinary 2xx
  (`arc@e7efc5b pkg/api/arc.go:429`, no `omitempty`; `doc/api.md:1512`), is
  read as absent. Read as written, the reference refuses it as
  `ERR_INVALID_RESPONSE` (`ARC.ts:129-132`); not run here.
- The accepted set is the reference's nine words. The Go port adds `QUEUED`,
  `REQUESTED_BY_NETWORK` and `CONFIRMED` (`go-sdk@511b58c
  transaction/broadcaster/arc.go:198-216`); ARC's own enum has `QUEUED` and
  `REQUESTED_BY_NETWORK` (`metamorph_api.proto:13-28`). Here, as in the
  reference, those two words on a 2xx are `ERR_INVALID_RESPONSE`.

## [0.3.33] - 2026-10-06

### Changed

- follows bitcoin-sv v1.2.3's fixed-width operand decoding and OP_SPLIT position bound (int_serialization.h:61-118, interpreter.cpp:1708-1721 at 6504a3a).
- Under a flag word, `OP_SUBSTR`'s offset and length and `OP_LEFT`'s and
  `OP_RIGHT`'s count use checked signed 64-bit decoding. The era-width and
  minimal-encoding checks precede conversion; `getint` saturation follows it.
  Decode failures use the node's script-number error mapping
  (`script_num.cpp:80-91`, `interpreter.cpp:1807-1809` at
  `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`). `OP_SPLIT` positions under a
  flag word are bounded by `INT32_MAX` and the data length.
- Tests cover nine-byte sign encodings, ten-byte encodings, the signed
  minimum and signed-range boundary, all four splice operands, check order,
  and `OP_SPLIT` at `INT32_MAX` and `INT32_MAX + 1`. The split boundary is
  tested with a synthetic data length, without a multi-gigabyte allocation.
  The existing splice witness cases carry v1.2.3 expectations.

### Notes: cross-SDK parity

- The default mode retains the TypeScript SDK's unrestricted number reader.
  Under a flag word the splice operands follow the pinned node's fixed-width
  construction sites (`interpreter.cpp:622-625`, `655-656`, `680-681`).

## [0.3.32] - 2026-10-05

### Fixed: the `int64` operand reader above 8 bytes follows the node's measured reading

- Under a word, the offset and length operands of `OP_SUBSTR`, `OP_LEFT` and
  `OP_RIGHT` (the reference's `int64` path, `CScriptNum` with `big_int`
  false, `src/script/interpreter.cpp:622-625`, `651-653`, `676-678`;
  `bsv::deserialize<int64_t>`, `src/script/int_serialization.h:64-95`) are now
  read, at 9 bytes and more, as the node's build reads them. Before: the
  two's-complement `int64` of the element's first 8 bytes, the rest never
  read. After: every byte but the last OR-ed into a 64-bit pattern at bit
  position `8 * (i mod 8)` (byte 8 lands on byte 0's position, byte 9 on byte
  1's, with period 8), the last byte dropped, no sign bit read, the pattern a
  two's-complement `int64`. The two readings are the same at 9 bytes and
  whenever the bytes from the ninth to the last but one are zero; they differ
  from 10 bytes: `00 00 00 00 00 00 00 00 04 01` was 0 and is 4, as the node
  reads it on the block path and the mempool path. Elements of 0 to 8 bytes
  (the reference's code as written, the sign-magnitude reading), the length
  test and the minimal-encoding rule before the read, `getint`'s saturation
  to the `int` range after it, the routing (the three opcodes, under the block
  and the standard word) and the default mode (a script number of any length,
  as the TypeScript SDK reads it) are unchanged. No operand is refused that
  was not refused before: the node refuses none on this path.
- Why it was wrong: the reference's loop shifts an `int64_t` by 64 bits and
  more from the tenth byte (`int_serialization.h:75`), undefined in C++, and
  0.3.29 took the one determinate case (zero tail bytes) as the rule. The
  specification's owner ruled on 2026-10-05 (bsv-script-lean,
  `docs/records/20261005-221333-owner-rulings-32.md`, R1) that where the
  pinned reference leaves this reader undefined the node's measured reading
  is consensus; the measurements and the rule are public in bsv-script-lean,
  `docs/records/20261006-010651-r1-reading-public.md` (section 3 the cases,
  section 4 the rule).
- What is measured and what is not: on the node (bitcoin-sv v1.2.2,
  `879fc8b`) lengths 1, 9 and 10; at 16 and 17 bytes builds of the same
  source carry the fold and the node's own runs are owed (at 17 bytes one
  vectorized arm64 build of that source reads 0 where this crate, with the
  scalar builds, reads 4); 11 through 15 bytes and 18 and above are
  unmeasured, the rule extended by its mechanism. The rule is the measured
  builds', not a reading of the C++, and claims nothing for another binary of
  the same source (the specification's D178). `fold_int64_operand`
  (`src/script/spend.rs`) says so at the site.
- Pinned by `tests/script_int64_fold_witness.rs` (15 tests): one for each
  case of the record's section 3, named by its id (`f1_offset_10_bytes`,
  `f1_control_offset_op4`, `f1_control_offset_9_bytes`, `gen_00796`,
  `f1_offset_16_bytes`, `f1_offset_17_bytes`,
  `f1_control_offset_17_bytes_byte0`), each asserting the value read under
  both words; the boundary lengths 8, 9, 10, 11 (the smallest unmeasured), 17
  (the largest measured) and 18; the same reader on `OP_LEFT` and `OP_RIGHT`;
  the default mode unchanged. Eight of the fifteen were RED on 0.3.31 (the
  10-byte, 16-byte and 17-byte cases, the 10, 11, 17 and 18 boundaries,
  `OP_LEFT`/`OP_RIGHT`). `tests/script_int64_operand_witness.rs` (0.3.29) stays
  green, its assertions unchanged.

### Notes: cross-SDK parity

- The TypeScript SDK reads these operands as script numbers of any length;
  this crate's default mode keeps that. Under a word this crate follows the
  node's measured build where the reference source is undefined: a stated
  finding, scoped as above.

## [0.3.31] - 2026-09-29

### Documented: the block path's stack budget (the guard of Calhooon/bsv-rs#30)

- The docs of `Spend` (the module's memory budget section, `Spend::memory_limit`,
  `Spend::stack_memory_policy`, `Spend::set_stack_memory_policy`),
  `SpendParams::memory_limit`, `ScriptFlags::max_stack_memory_usage`,
  `flags::DEFAULT_STACK_MEMORY_USAGE_POLICY`,
  `ScriptEvaluationError::resource_limit` and `is_resource_limit`, the README,
  the crate guides and the witnesses' module doc
  (`tests/script_stack_memory_witness.rs`) now state the block path's budget
  as the reference sets it: a node's is its operator's mandatory
  `-maxstackmemoryusageconsensus`
  (bitcoin-sv v1.2.2 does not start without it, `src/bitcoind.cpp:140-157`),
  in which 0 means `INT64_MAX` (`src/configscriptpolicy.cpp:280-283`), not a
  constant. They give the recipe for a caller modelling a node run with 0,
  `memory_limit: Some(usize::MAX)` (the evaluation then allocates what the
  script asks, `OP_NUM2BIN` alone up to `INT32_MAX` bytes, and decides as that
  node does), and they say that a decline is an `Err` whose `resource_limit`
  is `Some`, which a caller that judges validity must not read as invalid. No
  behaviour changes.

### Corrected

- The 0.3.30 entry gave the block path's figure as "`INT64_MAX` on the block
  path (`consensus.h:82`)" and "the block path's own figure is unbounded": both
  now read as the operator's mandatory setting, 0 meaning `INT64_MAX`.
- The witnesses' module doc (`tests/script_stack_memory_witness.rs`, 0.3.30)
  gave the block path's budget as "`INT64_MAX` on the block path
  (`consensus.h:82`)" and the node's own figure as "unbounded", and the doc of
  its `INT32_MAX` row named "the reference's consensus instance" as the one
  that allocates 2 GiB: they now read as the operator's mandatory setting and
  as a node run with `-maxstackmemoryusageconsensus=0`.

## [0.3.30] - 2026-09-27

### Fixed: the stack memory budget under a word (Calhooon/bsv-rs#30)

- The interpreter held one local budget in every mode, 32,000,000 bytes for
  each stack apart, counting the bytes alone, and stopped a script that
  exceeded it with a resource limit (`ScriptEvaluationError::resource_limit`,
  no verdict). After Genesis the reference bounds a script's memory by the
  stack memory budget of the path and by nothing else
  (`src/consensus/consensus.h:81-82`): on the block path the operator's
  mandatory `-maxstackmemoryusageconsensus` (`src/bitcoind.cpp:140-157`; 0
  means `INT64_MAX`, `consensus.h:82`) and the node's
  `-maxstackmemoryusagepolicy` on the
  mempool path, 100,000,000 bytes by default (`src/policy/policy.h:153`;
  `GetMaxStackMemoryUsage`, `src/configscriptpolicy.cpp:139-154`). It counts
  the main and the alt stack as one budget (the alt stack is a child stack,
  `src/script/interpreter.cpp:1993`, whose growth the parent counts,
  `src/script/limitedstack.cpp:196-199`), each element at its size plus 32
  bytes (`LimitedVector::ELEMENT_OVERHEAD`, `src/script/limitedstack.h:43`),
  and refuses a growth that would exceed the budget before it happens
  (`limitedstack.cpp:194-209`; `OP_NUM2BIN`'s pad is charged before the
  resize, `:66` then `:68`), `SCRIPT_ERR_STACK_SIZE`
  (`interpreter.cpp:1815-1817`). Under a word the interpreter now counts as
  the node counts. `SpendParams::memory_limit: None` selects a local budget of
  100,000,000 bytes on the node's count on both paths (`Spend::memory_limit`):
  the block path's own figure is the operator's setting, which a library
  cannot know and, at 0, embedded in a wallet cannot honor, so above the local
  budget the evaluator still declines
  with a resource limit, at the higher figure and on the node's count. On the
  mempool path the policy's excess is a verdict with a fixed message,
  `Stack size limit exceeded: N bytes, the stack memory policy is M bytes.`
  (`resource_limit: None`; `Spend::stack_memory_policy`;
  `Spend::set_stack_memory_policy` for a node configured otherwise, 0
  selecting no policy verdict as the node's 0 does,
  `configscriptpolicy.cpp:289-292`; `ScriptFlags::max_stack_memory_usage`;
  `flags::DEFAULT_STACK_MEMORY_USAGE_POLICY`, `flags::STACK_ELEMENT_OVERHEAD`).
  An explicit `memory_limit` wins in every mode and stays a resource limit;
  the policy's verdict fires at its own figure whatever the local budget. An
  alt stack the unlocking script leaves non-empty stays charged while the
  locking script runs, as on the node, whose alt stack is created per script
  and dropped without releasing its elements' charge (`LimitedStack` declares
  no destructor, `limitedstack.h:78-151`). Every refusal of the budget under a
  word comes before the allocation it would need: `OP_NUM2BIN`'s pad on the
  node's count after the minimal-encoding test, as the reference orders the
  two, and the numeric left shift's result on its exact length (the
  magnitude's bits plus the count, one byte for each 8 bits and one for the
  sign's room) after the size tests of Calhooon/bsv-rs#21; that exact length
  also decides the reference's size test after the shift
  (`src/script/script_num.cpp:315-316`, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`)
  before the shift is computed. The default mode is unchanged: 32,000,000
  bytes for each stack apart, the bytes alone, the `element-size` refusals
  before allocation (`tests/resource_limits.rs`). Found by the same
  differential run against bitcoin-sv v1.2.2 (`879fc8b`): four transactions
  the reference decides stopped here at the local budget, two under both
  words (a 32,000,001-byte number built by `OP_NUM2BIN` and read by `OP_1ADD`
  on a coin created after Chronicle, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` on both
  paths; a 40,000,000-byte element built and dropped, valid on both paths)
  and two under the block word (the number 1 shifted left to exactly
  32,000,000 bytes, valid, and to 32,000,001 bytes past the size test before
  the shift, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` at the test after it; on the
  mempool path both overflow the policy's number length first). Pinned by
  `tests/script_stack_memory_witness.rs`: the four witnesses and a fifth of
  the same family (the size test before the shift) under the block word, the
  standard word and the default mode, and the budget's edges at the node's
  figures (exactly 100,000,000 bytes on the node's count admitted on both
  paths and one byte more refused, the policy's verdict on the mempool path
  and the resource limit on the block path; the same total split across the
  two stacks; the unlocking script's alt stack left charged; a policy of 0;
  an explicit budget of 1,000 bytes and one of 200,000,000 bytes) and at
  small figures (the 32 bytes of each element, the shared budget, the pad
  charged before the resize, the shift's exact length and charge). RED on 0.3.29: 18 of the file's 22 rows that
  use no 0.3.30 API (the other six set or read the new knobs), run on the
  published crate; the four that pass are the default mode's row of the
  32,000,001-byte read, the shifts refused before the shift on the mempool
  path and on both, and the shift's exact length at a number length of 16.

### Fixed: `OP_NUM2BIN`'s size bound under a word (Calhooon/bsv-rs#30)

- Under a word a size below 0 or above `INT32_MAX` is refused before anything
  is allocated, `SCRIPT_ERR_PUSH_SIZE` on every path, as the reference
  refuses it (`src/script/interpreter.cpp:1747-1749`), with the message
  `OP_NUM2BIN requires a size from 0 to 2147483647, found N.`. The
  interpreter's 1 GiB element bound, which is not the reference's after
  Genesis, applies in the default mode only (to `OP_NUM2BIN`'s size and to
  `OP_CAT`'s result, with the message it had); under a word a size between
  1 GiB and `INT32_MAX` is decided by the budget, its growth charged before
  the resize (on the mempool path the policy's verdict, on the block path the
  local budget's resource limit, nothing allocated). The verdict on a size
  above `INT32_MAX` is unchanged (`SCRIPT_ERR_PUSH_SIZE`); its message under a
  word is new. Pinned by the same file: a size of 2^31, of `INT32_MAX` and of
  -1 under both words and in the default mode.

### Tests

- The CI step of the consensus witness files also runs
  `tests/script_stack_memory_witness.rs` (about 100 MB at its peak: its large
  rows run one at a time) and `tests/resource_limits.rs`, which pins the
  default mode's budget and had never run in CI.

## [0.3.29] - 2026-09-27

### Fixed: an undefined base hash type refused under STRICTENC (Calhooon/bsv-rs#23)

- `Spend::check_signature_encoding` tested the DER form, the low-S rule and
  the FORKID bit and never the base type, so a signature made over the BIP143
  digest of a hash type such as `0x44` (base 4 | FORKID) verified. Under
  `SCRIPT_VERIFY_STRICTENC` the reference refuses a signature whose hash type
  is not defined (`src/script/interpreter.cpp:291-294`,
  `SCRIPT_ERR_SIG_HASHTYPE`): `SigHashType::isDefined`
  (`src/script/sighashtype.h:82-90`) clears the CHRONICLE, FORKID and
  ANYONECANPAY bits and requires what is left to be ALL (1), NONE (2) or
  SINGLE (3); both node words carry STRICTENC (`src/script/standard.h:57`,
  `:64`). The interpreter now applies the test under a word carrying STRICTENC
  and in the default mode (the TypeScript SDK refuses such a type too), after
  the DER and low-S rules and before the CHRONICLE and FORKID rules, as the
  reference orders them; the message is
  `The signature's hash type (0xNN) has no defined base type.`. Found by the
  same differential run against bitcoin-sv v1.2.2 (`879fc8b`), three
  transactions (bases 0, 4 and 31). Pinned by
  `tests/script_undefined_hashtype_witness.rs`: the witness (`0x44`) refused
  under the block word, the standard word and the default mode, its two
  siblings (`0x40`, `0x5f`) refused, the witness valid under the block word
  without STRICTENC (the reference does not test the base without the flag);
  the boundary cases re-type the witness's signature: every defined base with
  any of the other bits passes the test and then fails to verify (a false
  top), every undefined base is refused. RED on 0.3.28: 5 of 7 rows.

### Fixed: the signature hash dispatched on the CHRONICLE bit (Calhooon/bsv-rs#22)

- The interpreter computed the BIP143 digest for every hash type. The
  reference's `SignatureHash` (`src/script/interpreter.cpp:2112-2124`) does
  so only when `SCRIPT_ENABLE_SIGHASH_FORKID` is in the flags and the type
  carries the FORKID bit and not the CHRONICLE bit (`SIGHASH_CHRONICLE = 0x20`,
  `src/script/sighashtype.h:14`); every other type is hashed by the original
  serializer (`SignatureHashOriginal`, `2086-2110`;
  `CTransactionSignatureSerializer`, `1841-1958`: the version; the inputs, only
  the signed one under ANYONECANPAY, the others with an empty script and, under
  SINGLE or NONE, a zero sequence; the scriptCode as `SerializeScriptCode`
  writes it, `1864-1892`, a length prefix of the scriptCode's size minus its
  `OP_CODESEPARATOR`s and the bytes the parser reads with the separators
  removed, stopping where `GetOp` fails, `script.h:164-195`; the outputs, none
  under NONE, the null output at every index but the signed one under SINGLE;
  the lock time; the 4-byte type), and the constant `one` when SINGLE names an
  output the transaction does not have (`2094-2102`). So a signature made over
  the original digest with the CHRONICLE bit, valid on the reference under a
  post-Chronicle word, was a false top here, and one made over BIP143 with that
  bit verified here where the reference refuses it. `Spend::verify_signature`
  now dispatches as `SignatureHash` does (FORKID is always enabled in this
  interpreter: the CHRONICLE bit selects the original digest, its absence
  BIP143), in every mode, as the TypeScript SDK does; under a word carrying
  STRICTENC and not CHRONICLE the bit is refused before verification, as the
  reference's `CheckSignatureEncoding` does (`291-303`,
  `SCRIPT_ERR_ILLEGAL_CHRONICLE`; the message
  `The signature must not use SIGHASH_CHRONICLE before Chronicle.`). New in
  `primitives::bsv::sighash`: `SIGHASH_CHRONICLE`,
  `compute_sighash_dispatched_for_signing`,
  `compute_sighash_original_for_signing` and
  `build_sighash_preimage_original`; `compute_sighash`,
  `compute_sighash_for_signing` and `build_sighash_preimage` keep computing
  BIP143. Found by the same differential run against bitcoin-sv v1.2.2
  (`879fc8b`), 21 transactions. Pinned by
  `tests/script_sighash_dispatch_witness.rs`: the witness (a P2PK spend whose
  locking script ends in `OP_RETURN 0x4c`, signed `0x61` over the original
  digest) valid under the block word, the standard word and the default mode,
  refused under a block word of the era before Chronicle; and the whole class
  as one table under both words (the six defined types with the bit, each
  with and without ANYONECANPAY; three-input spends under ALL, NONE, SINGLE
  with and without its output, ANYONECANPAY, one and two `OP_CODESEPARATOR`s;
  five more truncated pushes after a top-level `OP_RETURN`; the bit on a coin
  created before Chronicle; a CHRONICLE-bit signature made over BIP143, which
  the reference refuses). RED on 0.3.28: 21 of 21 rows.

### Fixed: the two bounds of the numeric shifts (Calhooon/bsv-rs#21)

- `OP_LSHIFTNUM` and `OP_RSHIFTNUM` shifted by a count of any size, so
  `1 OP_RSHIFTNUM 2147483648` was 0 and a valid spend, and a left shift's size
  was tested only against the interpreter's local memory budget (a resource
  limit, not a verdict). The reference reads the count and the value as big
  integers (`src/script/interpreter.cpp:708-711`, `744-747`) and applies
  `CScriptNum::operator<<=` / `operator>>=`: a left shift first refuses a
  result whose size, the value's serialized size plus `count / 8` bytes,
  would exceed the era's maximum number length (`src/script/script_num.cpp:305-308`,
  `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`, `interpreter.cpp:1807-1810`), before any
  shift; then on both shifts a count above `INT_MAX` throws `big_int_error`
  (`src/big_int.cpp:359-369`, `383-393`), caught as `SCRIPT_ERR_BIG_INT`
  (`interpreter.cpp:1819-1821`); a right shift has no size test
  (`script_num.cpp:363-367`). Under a word the interpreter now applies both,
  in that order, before its memory budget; the message of the second is
  `<opcode> count (N) does not fit an int.`. The negative-count refusal, the
  shifts, the result's length test and the default mode (the TypeScript SDK
  shifts by any count) are unchanged. Found by the same differential run
  against bitcoin-sv v1.2.2 (`879fc8b`). Pinned by
  `tests/script_shift_count_witness.rs` (the witness under the block word and
  the standard word: the big-integer error; the default mode: valid; RED on
  0.3.28) and its boundary cases (a right shift by `INT_MAX` is 0 and valid;
  left shifts of 1 by `INT_MAX` and `INT_MAX + 1` overflow the number length
  before any allocation, at the block path's 32,000,000 bytes and the mempool
  path's 10,000; a zero value follows the same tests; an ordinary shift and a
  coin created before Chronicle are unchanged).

### Fixed: the `int64` reading of the `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` operands (Calhooon/bsv-rs#20)

- The three Chronicle splice opcodes read their length and offset operands as
  script numbers of any length under the era's limit. The reference builds
  them as a `CScriptNum` on its `int64` path (`src/script/interpreter.cpp:622-625`,
  `651-653`, `676-678`; the constructor's default `big_int = false`,
  `src/script/script_num.h:60-63`), where `bsv::deserialize<int64_t>`
  (`src/script/int_serialization.h:64-95`) returns the two's-complement
  `int64` of the first 8 bytes of an element longer than 8 bytes and never
  reads the rest (`:78-79`), then `getint` saturates the value to the `int`
  range (`src/script/script_num.cpp:394-420`). So a 9-byte operand
  `04 00 00 00 00 00 00 00 80` is 4 to the reference and was −4 here, a range
  refusal. Under a word `Spend::read_splice_operand` now reads the operands
  that way (the length test and the minimal-encoding rule first, as at every
  read); an element of 1 to 8 bytes decodes exactly as before. The default
  mode is unchanged: the TypeScript SDK reads a script number of any length.
  Found by the same differential run against bitcoin-sv v1.2.2 (`879fc8b`).
  Pinned by `tests/script_int64_operand_witness.rs` (the witness under the
  block word and the standard word: valid; the default mode: the range
  refusal; RED on 0.3.28) and its boundary cases (an 8-byte operand with its
  sign bit set is −4 on both sides, a 9-byte operand with a zero ninth byte
  and a 10-byte operand with zero tail bytes are 4, `OP_LEFT` and `OP_RIGHT`
  read their length the same way, an 8-byte `INT64_MAX` offset is out of
  range on both sides).

## [0.3.28] - 2026-09-23

### Fixed: the low-S check at the curve order (Calhooon/bsv-rs#14)

- A signature whose `r` or `s` is at or above the curve order was refused as
  high-S (`The signature must have a low S value.`) before verification. The
  reference's `CPubKey::CheckLowS` (`src/pubkey.cpp:356-365`) parses laxly
  (`ecdsa_signature_parse_der_lax`, `146-173`): such a value overflows into the
  all-zero signature, which is low, so the check passes and the signature then
  fails to verify; under version 1 with NULLFAIL the script is
  `SCRIPT_ERR_SIG_NULLFAIL` (`src/script/interpreter.cpp:1491-1497`), otherwise
  a false top element. `Spend::check_signature_encoding` now treats an `r` or
  `s` at or above the order as the zero signature for the low-S check; the
  high-S refusal applies to `n/2 < s < n` only. Both verdicts were invalid; the
  rule and the message differed, found by the same differential run against
  bitcoin-sv v1.2.2 (`879fc8b`). Pinned by `tests/script_low_s_order_witness.rs`
  (the witness, a version-1 P2PK spend with `s` = the order, under the block
  word, the standard word and the default mode; RED on 0.3.27) and by the
  boundary tests in `spend.rs` (`s = n/2` low, `s = n/2 + 1` and `s = n - 1`
  high, `s = n`, `s = n + 1` and `r = n` the zero signature).

### Fixed: the script-number length limit (Calhooon/bsv-rs#17)

- The interpreter read a script number of any length. The reference builds
  every number it reads with the maximum length of the coin's era and throws
  `scriptnum_overflow_error` before the minimal-encoding check
  (`src/script/script_num.cpp:62-68`; `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`,
  `src/script/interpreter.cpp:1807-1810`): 750,000 bytes for a coin created
  after Genesis and 32,000,000 after Chronicle on the block path
  (`src/consensus/consensus.h:64`, `:66`), the node's
  `-maxscriptnumlengthpolicy` on the mempool path, 10,000 by default
  (`src/policy/policy.h:156`; `GetMaxScriptNumLength`,
  `src/configscriptpolicy.cpp:79-110`, the era from the coin's flags,
  `interpreter.cpp:2269-2274`). Under a word the interpreter now applies that
  limit before the decode at every read (`ScriptFlags::max_script_num_length`,
  `Spend::max_script_num_length`; the mempool path's policy through
  `Spend::set_script_num_length_policy`, 0 selecting the consensus limit; a
  word carrying the mempool word's four bits is judged on the mempool path,
  `ScriptFlags::is_mempool_word`), on every arithmetic result before it is
  pushed (`script_num.cpp:164`, `194`, `214`, `301-315`), at `OP_BIN2NUM`'s
  result (`interpreter.cpp:1789-1790`, the same refusal as a non-minimal
  result), and as the 4-byte limit on `OP_CHECKMULTISIG`'s two counts
  (`1519-1525`, `1550-1552`). The message is `Script number overflow: N bytes,
  the limit is M bytes.`. The default mode is unchanged: the TypeScript SDK
  reads a number of any length. Found by the same differential run against
  bitcoin-sv v1.2.2 (`879fc8b`): a version-2 spend of a coin created between
  Genesis and Chronicle whose script builds the number 1 followed by 2^20 zero
  bytes (1,048,577 bytes) and reads it with `OP_1ADD` was valid here under
  every word and mode. Pinned by `tests/script_num_length_witness.rs` (the
  witness under the block word and the standard word: overflow; the default
  mode: valid; the same coin created after Chronicle: within 32,000,000,
  valid) and by the boundary tests in `spend.rs` (750,000 / 750,001 for a coin
  created after Genesis, 32,000,000 / 32,000,001 after Chronicle, 10,000 /
  10,001 under the standard word, a policy of 0 falling back to the consensus
  limit, the length test before the minimal-encoding test, a product longer
  than the limit refused before the push, an `OP_BIN2NUM` result beyond the
  limit refused, a 5-byte `OP_CHECKMULTISIG` count refused under a word).
### Tests

- Nine assertions that a fresh signature is 70 to 73 bytes long replaced by
  what the reference admits: the element parses as a DER signature with its
  sighash byte, re-encodes to the same bytes and is 9 to 73 bytes long
  (`IsValidSignatureEncoding`, `src/script/interpreter.cpp:177-194`); the
  multisig unlock test signs with fixed keys. A minimal DER `r` or `s` is
  shorter than 32 bytes when its leading byte is zero, so the old lower bound
  failed on about one key in 13,000 (`test_multisig_unlock_has_dummy_op_0` on
  `main`, Calhooon/bsv-rs#16). Test-only; the interpreter is unchanged.

### Corrected

- The 0.3.27 entry and the header of `tests/script_residual_witnesses.rs`
  said "nine witness transactions"; the file holds ten, of eight rules (two
  each for the truncated push and the undefined opcode, one each for the
  second `OP_ELSE`, `OP_VER`, `OP_2DIV`, `OP_2MUL`, `0xb7` as `OP_RSHIFTNUM`
  and the FORKID scriptCode). One count at every site now.

## [0.3.27] - 2026-09-23

### Fixed: five consensus rules the interpreter got wrong in every mode (Calhooon/bsv-rs#12)

The same differential run against bitcoin-sv v1.2.2 (`879fc8b`) that found #10
recorded five further divergences from the block-validation rules, each with a
witness transaction; they are `tests/script_residual_witnesses.rs` (ten
transactions of eight rules, each pinned under the block word and in the
default mode; all ten 0.3.26 verdicts move, by design; this sentence said nine
until 0.3.28 corrected it). Every citation is `src/script/interpreter.cpp`
unless named.

- **A truncated push is a parse failure, not a shorter push.** A push that
  declares more bytes than the script holds (a direct push cut short, a
  `OP_PUSHDATA1/2/4` whose length bytes or data are missing) is refused when
  the interpreter's walk reaches it, executed or not: the reference's `GetOp`
  returns false (`script.h:190-191`) and the script is
  `SCRIPT_ERR_BAD_OPCODE` (`450-451`). `Script::from_binary` stays lenient (a
  container, as the TypeScript SDK's is); the new `Script::truncated_push()`
  names the chunk, and `Spend` refuses there: `A push declares more bytes than
  the script holds; the script cannot be parsed past it (pc=N).` Bytes after a
  top-level `OP_RETURN` are data on both sides and are not examined.
- **An undefined opcode executed is a failure.** `0xba`-`0xff` were NOPs; the
  reference's `default:` is `SCRIPT_ERR_BAD_OPCODE` when one is executed
  (`1795`; the TypeScript SDK agrees). They now fall to the invalid-opcode arm
  (`Invalid opcode N (pc=M).`); in an unexecuted branch they are still skipped.
- **One `OP_ELSE` per `OP_IF` after Genesis.** A second `OP_ELSE` for the same
  `OP_IF`/`OP_NOTIF` is unbalanced (`conditional_tracker.cpp:51-55`,
  `829-831`): `OP_ELSE may only be used once for each OP_IF or OP_NOTIF after
  Genesis.` (the TypeScript SDK's text, which applies it only under explicit
  flags; every UTXO here is post-Genesis, so it applies in every mode).
- **The post-Chronicle UTXO opcodes are implemented.** For a coin created after
  Chronicle, `OP_2MUL` and `OP_2DIV` compute (`1247-1254`; `-7 OP_2DIV` is
  `-3`, toward zero), `OP_VER` pushes the transaction version as 4
  little-endian bytes (`598-608`), `OP_VERIF`/`OP_VERNOTIF` are conditionals on
  "the top element is exactly those 4 bytes" (`773-812`), and `0xb3`-`0xb7`
  are `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM`
  (`609-764`; the two shifts act on script numbers, a right shift toward zero
  as OpenSSL's `BN_rshift` does, a left shift refused before it is computed
  when its result would not fit the memory budget, a local `ScriptResourceLimit`
  where the reference's bound is its consensus number length). Before
  Chronicle the two arithmetic opcodes stay disabled, the three version opcodes
  are refused when executed (`OP_VER is disabled until Chronicle.`) and skipped
  when not (post-Genesis, `773-781`), and `0xb3`-`0xb7` are NOPs (discouraged
  under `DISCOURAGE_UPGRADABLE_NOPS`). The gate: a word's
  `UTXO_AFTER_CHRONICLE` bit (`ScriptFlags::block(PostChronicle)` sets it);
  without a word, the TypeScript SDK's `isAfterChronicle()`, which is its
  relaxed branch, transaction version > 1; `Spend::set_utxo_after_chronicle`
  overrides either. `0xb3`-`0xb7` keep their `OP_NOP4`-`OP_NOP8` names in ASM
  (this crate's `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` constants are the legacy
  `0x7f`-`0x81` names, as before).
- **A FORKID signature's push stays in the scriptCode.** `CleanupScriptCode`
  (`255-263`, applied at `1484` and per signature at `1573-1578`) deletes a
  signature's push from the scriptCode only when the signature does not carry
  `SIGHASH_FORKID`; FORKID is always enabled here, so a non-empty signature is
  never deleted and a signature whose push appears in the scriptCode cannot
  verify (its own bytes are hashed in), as on the reference. An empty signature
  carries no hash type and is still deleted as an `OP_0` push, as on the
  reference. The TypeScript SDK deletes every signature (a stated divergence).
- **A RETURN inside a conditional stops execution but not the walk.** After
  Genesis a non-top-level `OP_RETURN` stops execution while the conditionals
  must still balance and every later opcode must still parse (`856-871` with
  `482`); the interpreter cleared its conditional stack and jumped to the end.
  A top-level `OP_RETURN` still ends the script successfully whatever follows.

### Added

- `Script::truncated_push() -> Option<usize>`, `Spend::set_utxo_after_chronicle(bool)`,
  `BigNumber::shl_bits` and `BigNumber::shr_bits_toward_zero`. `SpendParams`
  and every error text of 0.3.26 are unchanged; `is_opcode_disabled` is
  private.

### Notes: cross-SDK parity

- The TypeScript SDK's default mode already runs the Chronicle opcodes on its
  relaxed branch and refuses undefined opcodes; it applies the single-ELSE rule
  only under explicit flags, keeps a lenient parser that never refuses a
  truncated push, and deletes every signature from the scriptCode. This crate
  follows the reference's consensus rules in every mode and states the three
  differences here.
- The ts-stack census (`tests/conformance_scripts.rs`) re-pins the classes
  these rules touch; the fixtures that expected `BAD_OPCODE` for an undefined
  or truncated opcode, the Chronicle opcodes for a post-Chronicle UTXO, or
  the second-ELSE refusal now pass instead of being counted unsupported.

## [0.3.26] - 2026-09-23

### Added: the node's flag words (`script::flags`)

- `ScriptFlags`: the script verification flag word with bitcoin-sv v1.2.2's
  bit values (`src/script/script_flags.h:13-111`) and names (`from_names`,
  `names`; the node's RPC table, `src/rpc/misc.cpp:1284-1305`), `from_bits`
  (a bit this crate does not know is refused, never ignored), `check` (a word
  this interpreter cannot honor, or one the reference itself refuses, is named:
  no `SIGHASH_FORKID`, no `GENESIS`, no `UTXO_AFTER_GENESIS`, `CHRONICLE`
  without `GENESIS`, `UTXO_AFTER_CHRONICLE` without `UTXO_AFTER_GENESIS`,
  `CLEANSTACK` without `P2SH`), and the two derivations a node makes:
  `ScriptFlags::block(era)`, the block-validation word
  (`src/verify_script_flags.cpp:32-81` with the per-input flags of
  `src/policy/policy.h:226-245`), and `ScriptFlags::standard(era)`, the mempool
  word (`11-30`; `policy.h:178-223`). For a post-Chronicle block they are
  `0x3D462F` and `0x3D47FF`; the standard word is the block word plus exactly
  `NULLDUMMY | MINIMALDATA | DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK`, which a
  block never carries (`policy.h:178-190`).
- `ProtocolEra` (`PostGenesis`, `PostChronicle`) with the mainnet activation
  heights 620,538 and 943,816 (`src/chainparams.cpp:18,23`) and
  `ProtocolEra::mainnet(height)` (`src/protocol_era.cpp:21-39`).
- `Spend::set_flags(word)` and `Spend::flags()`: every rule the interpreter
  enforces is re-derived from the word and the transaction version exactly as
  the reference derives it at the rule's site, under the reference's version
  gate `EnforceNonMalleability` (`src/script/interpreter.cpp:40-44`: at
  Chronicle a transaction of version 2 or above is malleable and every
  malleability restriction is switched off for it). The rules and their
  sites: MINIMALDATA (`433`), LOW_S (`282-288`), CLEANSTACK (`2436-2445`),
  NULLDUMMY (`1664-1670`), NULLFAIL (`1491-1497`, `1640-1646`), MINIMALIF
  (`795-803`), SIGPUSHONLY (`2321-2334`: post-Chronicle only for version <= 1),
  DISCOURAGE_UPGRADABLE_NOPS (`522`, `565`, `765-771`), COMPRESSED_PUBKEYTYPE
  (`322-327`). A word `check` refuses is reported by `validate` as `Invalid
  verification flags: …`, as the reference reports `SCRIPT_ERR_INVALID_FLAGS`
  (`2312-2313`, `2436-2437`). `set_require_minimal` and `set_require_push_only`
  still override a derived rule when called afterwards. `SpendParams` is
  unchanged; nothing a downstream builds with a literal moved.
- Four rules the interpreter did not have, each active only under a word
  that carries its flag: NULLFAIL (a signature that fails must be the empty
  vector: `OP_CHECKSIG requires failing signatures to be empty.`; for
  CHECKMULTISIG, every signature when the operation fails), MINIMALIF
  (`OP_IF and OP_NOTIF require minimal truth values.`),
  DISCOURAGE_UPGRADABLE_NOPS (an executed `OP_NOP1`-`OP_NOP10`: `… is
  discouraged by verification flags.`; the three texts are the TypeScript
  SDK's), COMPRESSED_PUBKEYTYPE (`The public key must be compressed.`).
- `tests/script_flags_witnesses.rs`: seven witness transactions (200-byte
  transactions with a synthetic previous output), each the smallest case of a
  divergence the differential below found, each pinned under the block word,
  the standard word and the default mode, with the 0.3.24 verdict recorded
  beside it. `examples/script.rs` (and the README block that is that file)
  shows the three verdicts of one untidy version-1 spend.

### Fixed: a consensus oracle can select the block word (Calhooon/bsv-rs#10)

- Used as a consensus validator, the interpreter judged a version-1 spend by
  MINIMALDATA, CLEANSTACK and NULLDUMMY, relay-only rules that no block word
  carries, so it rejected consensus-valid version-1 spends; it had no NULLFAIL
  rule at all; and it applied NULLDUMMY regardless of the transaction version
  where the reference gates it. Found by a differential run of 0.3.24 against
  bitcoin-sv v1.2.2's flag derivation, one witness transaction per divergence.
  On 0.3.25, in its only mode, all seven witnesses diverge from the block word
  (RED, recorded in the pull request); on this release the block word agrees
  with the reference on all seven, and any consumer that judges on the
  network's behalf now selects it with one call.
- The default mode's NULLDUMMY is gated on the transaction version like its
  MINIMALDATA, LOW_S and CLEANSTACK (the TypeScript SDK's
  `shouldEnforceNullDummy` is `!isRelaxed()`): a version-2 CHECKMULTISIG with
  a non-empty dummy is accepted, as the reference accepts it in a block and at
  relay. **This is the only default-mode verdict this release changes**; the
  witness test pins it (one of seven recorded verdicts moves). Everything else
  in the default mode is 0.3.25's: strict for version <= 1, relaxed for
  version >= 2, push-only unlocking scripts at every version, no NULLFAIL.
- `tests/script_mutators_keep_parsed_chunks.rs` reformatted (the 0.3.25 file
  was not `cargo fmt --check`-clean).

### Notes: cross-SDK parity

- The TypeScript SDK's `verifyFlags` applies a flag as given: under explicit
  flags it enforces NULLDUMMY, MINIMALDATA, LOW_S and CLEANSTACK at every
  transaction version, and it has no `CHRONICLE` flag. This crate's words are
  the NODE's words: `set_flags` applies the reference's version gate at the
  reference's sites, so `ScriptFlags::standard(ProtocolEra::PostChronicle)` on
  a version-2 spend enforces none of the four, exactly as a relaying node
  does. The pre-Chronicle words (`ProtocolEra::PostGenesis`) have the gate
  always on, which is the TypeScript explicit-flags behavior for those four.
- The default mode still has no NULLFAIL rule at version <= 1 (TypeScript
  parity), although the reference's block word has carried NULLFAIL since the
  DAA fork (`src/verify_script_flags.cpp:65-69`): a version-1 spend with a
  failing non-empty signature verifies here by default and fails on the
  network. The Go SDK's interpreter takes the same rule as a flag
  (`scriptflag.VerifyNullFail`). Select a word to get the node's answer.
- `UTXO_AFTER_CHRONICLE` is accepted in a word, but the opcodes it re-enables
  on the reference for a coin created after Chronicle (`OP_2MUL`, `OP_2DIV`,
  `OP_VER`, `OP_VERIF`, `OP_VERNOTIF`; the Chronicle meanings of
  `OP_NOP4`-`OP_NOP8`) are not implemented: a script using one is refused as
  disabled, or treated as a NOP, regardless. The next interpreter gap.
- The ts-stack conformance census (`tests/conformance_scripts.rs`) still runs
  the default mode; its `unsupported` classes for NULLFAIL, MINIMALIF and
  DISCOURAGE_UPGRADABLE_NOPS therefore stand, and the class that counted
  "NULLDUMMY always enforced" is re-cut to the version gate. Driving the
  node fixtures through `ScriptFlags::from_names` is the next census step.

## [0.3.25] - 2026-09-22

### Fixed

- Every in-place mutator of `Script` (`write_script`, `write_opcode`, `write_bin`,
  `write_number`, `remove_codeseparators`, `find_and_delete`, `set_chunk_opcode`)
  invalidated the byte cache BEFORE parsing. On a script built with
  `Script::from_binary` (raw bytes cached, chunks parsed lazily) that dropped the
  only source of chunks, the parse ran on nothing, and the script came back EMPTY:
  `set_chunk_opcode` on a 25-byte P2PKH lock serialized to 0 bytes. A downstream
  mutation census (bolt-rs, 2026-08) tested a zero-byte lock and read it as a clean
  result; btg-token #11 fixed it here rather than carry the trap. The order is now
  parse, then invalidate, in all seven. Pinned by
  `tests/script_mutators_keep_parsed_chunks.rs` (six tests, RED on 0.3.24, GREEN here).
  No API or wire change; a `Script` built by `write_*` from empty was never affected.

## [0.3.24] - 2026-09-09

### Added

- `GlobalKVStore::with_resolver(wallet, config, network, resolver)`: build the
  store over a caller-owned `LookupResolver` (a custom facilitator, pinned
  SLAP trackers, host overrides, or a test double). `new`/`with_network` are
  unchanged and route through it.
- `examples/`: `keys`, `script`, `transaction`, `brc42`, `beef_spv`, `overlay`,
  each a runnable program that CI compiles (`cargo build --examples
  --all-features`). The README's code blocks are these files byte for byte,
  pinned by `tests/readme_examples.rs`.

### Fixed

- Five `GlobalKVStore` tests asserted an overlay ERROR by relying on the
  network being ABSENT ("without live SLAP hosts the resolver errors"): on
  any machine with a route to the public SLAP trackers the real resolver
  answered and the tests failed. They now inject a resolver with an empty
  host list for the service (the resolver refuses before any request) and a
  facilitator that refuses anyway. The full suite is green online and offline.

### Documented

- `README.md` and `CLAUDE.md` rewritten from scratch: what the crate is and is
  not, the feature matrix from `Cargo.toml`, the interpreter's and BEEF's
  contracts, the conformance discipline (shared vectors + the `ts-stack`
  corpus), the wasm32 story, the known cross-SDK divergences, the release
  procedure, and the measured test counts. The crate docs (`lib.rs`) match.
- The BRC naming: the `auth` module implements BRC-103 mutual authentication
  and its BRC-104 HTTP transport (the successors of BRC-31/Authrite); older
  comments that still say BRC-31 describe the same protocol.

## [0.3.23] - 2026-09-09

### Fixed: reference parity in the script interpreter (`Spend`)

- `OP_NUM2BIN` refuses a size operand larger than the local memory budget BEFORE
  allocating it (the TypeScript SDK's `element-size` check). Previously a
  9-byte script (`OP_1 <1e9> OP_NUM2BIN`) allocated up to
  `MAX_SCRIPT_ELEMENT_SIZE` (1 GB) and only then tripped the stack budget on
  the push, on a Cloudflare Worker that is an isolate kill, not a refusal.
- Resource exhaustion is its own error class: `ScriptEvaluationError` gains
  `resource_limit: Option<ScriptResourceLimit { resource: ScriptResource
  (Stack | AltStack | ElementSize), limit, attempted }>` and
  `is_resource_limit()`, mirroring the SDK's `ScriptResourceLimitError`
  (`'stack' | 'alt-stack' | 'element-size'`, the same message shape
  `<label> has exceeded <limit> bytes`). A caller whose bar is the network
  (an overlay door) can now tell the evaluator's budget from the script's
  verdict without matching message text. Every other error keeps
  `resource_limit: None`. (`ScriptEvaluationError` gained a public field; a
  struct literal elsewhere needs `resource_limit: None`.)
- Found by the bsv-low W-A money gate's delta-verify (2026-09-09).

## [0.3.22] - 2026-09-09

### Fixed: BEEF linking is linear and verify walks by txid

- **`Beef::find_atomic_transaction` / `Transaction::from_beef` link each
  distinct unproven parent ONCE, and every later input sourcing the same txid
  gets a bare stub.** 0.3.21 linked every input in full by cloning the
  memoized parent, which is EXPONENTIAL IN MEMORY on a diamond chain: when
  each level spends both outputs of the previous unproven level (a wallet's
  ordinary change chain), every level then carries two full copies of the
  level below it, so 24 levels means 2^24 subtrees and `from_beef` dies on
  memory before verification even starts. The stub is the parent transaction
  itself (its outputs are what the input spends, and it carries the BUMP when
  the BEEF proves it), with every one of ITS inputs' `source_transaction` left
  `None`, so structure and work are linear in the BEEF. A 24-level diamond now
  links to 47 source objects (2 per level) instead of ~2^24, in 57 ms.
  Building a stub never copies a subtree, and the memo is filled before the
  descent, so a BEEF whose source links form a cycle terminates instead of
  recursing forever.
- **`Transaction::verify` walks BY TXID, not by object graph.** It first
  gathers every transaction reachable through `source_transaction` into a map
  keyed by txid (a copy carrying a merkle path wins outright, otherwise the
  copy with the most linked sources, and only the winner is descended), then
  processes each txid exactly once: a proven transaction is checked against
  the chain tracker and not descended; an unproven one is fee-checked when a
  fee model is given, and has every input's script executed with the source
  looked up BY TXID (the txid the input names, falling back to the id of
  whatever source object it holds, as TS does). Nothing is cloned in the walk,
  and no result depends on which copy of a parent an input happens to hold, so
  the linear structure above verifies exactly like a fully duplicated one.
  This is what 0.3.20 lacked: its walk reached a bare clone and refused a
  complete BEEF with `Input N has no source transaction`, which is what pushed
  0.3.21 into cloning everything. Error texts are unchanged (`Input N has no
  source transaction`, `Script validation failed for input N: ...`, `Fee is
  too low`, `Invalid merkle path for transaction ...`).
- **The reference's value rule is now enforced**: an unproven transaction whose
  outputs pay out more than its inputs bring in makes `verify` return
  `Ok(false)`, matching the TS SDK's `outputTotal > inputTotal` check, which
  the Rust walk had never carried. A transaction with no inputs at all is
  exempt (there is no ancestry to weigh it against; it is a synthetic root,
  never something the walk can judge).
- Regression tests: `a_deep_diamond_chain_links_and_verifies_in_linear_time`
  (24 levels: `from_beef` + `verify` in well under a second, and an upper
  bound on the number of linked source objects), the middle-level
  `a_corrupted_signature_in_the_middle_of_the_chain_is_refused`,
  `an_unproven_spend_creating_satoshis_is_refused`, and
  `two_inputs_from_one_unproven_parent_are_both_linked` (now asserting the
  linear structure: input 0 fully linked, input 1 a stub, both verifying).
  The exponential shape was found by the zanaadu overlay engine's own
  regression suite (2026-09-08).

## [0.3.21] - 2026-09-09 (YANKED: links every duplicate input by cloning, exponential on diamond chains; use 0.3.22)

### Fixed: BEEF ancestry linking for every input (ts-sdk parity)

- **`Beef::find_atomic_transaction` / `Transaction::from_beef` link EVERY input's
  `source_transaction` fully, however many inputs source the same
  transaction.** The previous walk kept a `visited` set keyed by txid and
  attached a bare clone to every input after the first, so two inputs sourcing
  the same unproven parent (a covenant output plus that transaction's own
  change, the ordinary shape of a wallet's second spend) left the second copy
  with no sources and no merkle path, and `Transaction::verify` failed it with
  `Input N has no source transaction` for a BEEF that carried everything. The
  TS SDK never sees this because its inputs share one `Transaction` object by
  reference; Rust owns a `Box` per input. The walk now memoizes the fully
  linked transaction per txid and reuses it for every later input: the linked
  structure equals the TS one and the work is linear in the BEEF, never
  exponential along a chain whose spends source two outputs of their parent.
  Regression test `two_inputs_from_one_unproven_parent_are_both_linked`; found
  live on zanaadu beta (2026-09-08) the first day its overlay executed scripts
  on submit.

### Added: midstate-reuse sighash API (`SighashCache`)

- **`primitives::bsv::sighash::SighashCache`**, a cache over one
  transaction's BIP-143 midstates (`hashPrevouts`, `hashSequence`,
  `hashOutputs`), following rust-bitcoin's `SighashCache` pattern. Each
  midstate is computed lazily at most once per scope class and reused across
  inputs; the free functions recompute all three per call, making per-input
  signing of an n-input transaction O(n²) in hashing (a measured ~9× penalty
  at n=50). One cache instance safely serves mixed sighash scopes
  (ALL/NONE/SINGLE × ANYONECANPAY × FORKID). API:
  `SighashCache::new(&RawTransaction)` / `from_parts(...)`,
  `hash_prevouts(scope)`, `hash_sequence(scope)`,
  `hash_outputs(input_index, scope)`,
  `preimage(input_index, subscript, satoshis, scope)`,
  `sighash(...)` (display order), `sighash_for_signing(...)` (signing order).
- `build_sighash_preimage` (and therefore `compute_sighash` /
  `compute_sighash_for_signing`) is now a thin wrapper over a fresh
  single-use `SighashCache`, one preimage implementation in the crate,
  public API and behavior unchanged. Byte-equality is pinned by scope-class
  unit tests, by the 499-vector cross-SDK sighash suite run through the cache
  across every input, and by the 5,116-vector ts-stack conformance census
  (`tests/conformance_scripts.rs`), whose sighash path now exercises the
  cache directly.

### Documented

- RFC 6979 digest-domain note on `PrivateKey::sign` and in the `sighash`
  module docs: for a digest >= n (P ≈ 2⁻¹²⁸ for sha256d output), k256 seeds
  the nonce DRBG with `bits2octets(digest)` per the RFC while libsecp256k1
  and `@bsv/sdk` seed it with the raw digest bytes, deterministic signature
  bytes differ across stacks in that regime only; in-range digests are signed
  byte-identically. Pinned by `rfc6979_in_range_digest_der_is_pinned` and
  `rfc6979_digest_ge_n_der_is_pinned` in `tests/ec_tests.rs`.

## [0.3.19] - 2026-08-25

### Fixed: BEEF merkle-path reattachment (ts-sdk parity)

- **`Transaction::from_beef` and `Beef::find_atomic_transaction` dropped the
  merkle path.** Both cloned the parsed transaction out of the BEEF, so the
  returned transaction carried `merkle_path: None` even when the BEEF proved
  it, every caller asking "is this mined?" got "no" forever. Bumps live in
  `Beef::bumps` and are referenced by `BeefTx::bump_index` rather than being
  stored inside the transaction, so they must be reattached explicitly.
  This diverged from the TypeScript reference: `@bsv/sdk`'s
  `Transaction.fromBEEF` resolves the target txid and calls
  `Beef.findAtomicTransaction`, which runs `addInputProof` to set
  `current.merklePath` and link input sources.
- **`Beef::add_input_proof`** (private) ports that traversal: walk the
  transaction graph, attach the BUMP where one exists and stop descending that
  branch (a proven transaction needs no ancestry), otherwise link each input's
  `source_transaction` from the BEEF and continue into it. `from_beef` now
  routes through `find_atomic_transaction` the way `fromBEEF` routes through
  `findAtomicTransaction`, so both entry points behave identically.
- Regression tests are proven non-vacuous (reverting the fix fails them), and
  the fixture builds its BEEF through this crate's own writer so it cannot
  drift from the wire format.

## [0.3.16] - 2026-07-09

### Fixed: Spend engine ts-sdk parity

Four `Spend` divergences from the TypeScript `@bsv/sdk` engine, surfaced by
executing large OP_PUSH_TX-style covenant scripts that are valid under ts-sdk
and accepted by mainnet nodes but failed bsv-rs local validation:

- **Version-based relaxed mode.** ts-sdk runs transactions with version > 1
  under post-Genesis "relaxed" semantics (`Spend.isRelaxed()`): MINIMALDATA,
  LOW_S and CLEANSTACK are not enforced. bsv-rs enforced all three
  unconditionally. `Spend` now mirrors ts-sdk (version <= 1 keeps the strict
  behavior), with explicit overrides via `set_require_minimal()`.
  27 previously-unsupported cross-SDK conformance vectors now execute and
  pass (census repinned in `tests/conformance_scripts.rs`).
- **Combined-script CHECKSIG subscript.** When a CHECKSIG executes in the
  unlocking script after an OP_CODESEPARATOR, the signed subscript continues
  across the unlock/lock boundary into the full locking script (legacy
  combined-script consensus semantics, matching ts-sdk and node behavior).
  bsv-rs previously truncated the subscript at the unlocking script, wrongly
  rejecting OP_PUSH_TX-style in-script signatures. The unlock→lock context
  switch now also resets `last_code_separator`, clears the alt stack, and
  requires terminated conditionals, as ts-sdk does.
- **High-S signature verification.** `ecdsa::verify` normalizes signatures to
  low-S before k256 `verify_prehash`, which rejects high-S by default. ECDSA
  (and consensus) accepts both `(r, s)` and `(r, n − s)`; low-S remains a
  script-layer *policy*, now correctly scoped to strict (version <= 1) mode.
- **Push-only opt-out.** `Spend::set_require_push_only(false)` allows
  executable code in unlocking scripts, which ts-sdk permits (the default
  remains enforced).

### Added

- `Transaction::invalidate_caches()` is now public: `inputs`/`outputs` are
  public fields, and mutating them directly (e.g. setting an output's
  satoshis or an input's `unlocking_script`) left `to_binary()`/`hash()`/
  `id()` returning stale cached serializations with no way to flush them.

## [0.3.14] - 2026-07-04

### Fixed

- **Panic / OOM-abort on adversarial length prefixes (bounded pre-allocation).**
  Every parser that pre-allocated a collection sized by an attacker-controlled
  count read from the input (`Vec::with_capacity(count)`,
  `HashMap::with_capacity(count)`, `vec![default; count]`) could be made to
  abort the process with a capacity-overflow / OOM panic *before a single
  element was read*. A ~20-byte crafted BEEF whose transaction input-count
  varint is `0xFE FF FF FF FF` (u32::MAX) makes `Transaction::from_beef` /
  `Transaction::from_binary` allocate billions of `TransactionInput`s and
  abort, a trivially cheap denial-of-service (and on `wasm32`, where the build
  is `panic = abort`, it is unrecoverable: `.ok()` cannot catch it).

  All such sites now bound the pre-allocation to what the remaining buffer could
  actually contain via the new `primitives::bounded_capacity(count, remaining,
  min_elem_bytes)` helper, `count.min(remaining / min_elem_bytes)`. The read
  loop already errors the instant the buffer is exhausted, so parse results are
  unchanged for both valid and malicious input; only the (now bounded) capacity
  hint changes. A bogus count now yields `Err`, never a panic.

  Hardened sites: `transaction::Transaction::{from_reader, from_ef}`
  (input/output counts, and the EF `source_output_index` placeholder-output
  fabrication, which is now rejected above a 16 MiB allocation budget, the
  placeholder length is computed in `u64` via `ef_source_placeholder_len` so the
  `+ 1` cannot overflow on 32-bit targets: on `wasm32` `source_output_index as
  usize + 1` wrapped `u32::MAX` to `0`, defeating the budget check and then
  index-OOB-panicking on a zero-length vec),
  `primitives::bsv::sighash::parse_transaction`, `overlay` binary lookup
  responses, `wallet::wire` (string arrays/maps, action/output/certificate
  arrays, keyrings), and `auth` certificate/header parsing. Purely defensive;
  no API change beyond the additive `bounded_capacity` export → patch bump.

## [0.3.11] - 2026-05-20

### Fixed

- **wasm32 `Peer::to_peer` / BRC-103 handshake hang.** The `wasm` feature now
  enables `futures-timer/wasm-bindgen`. The wasm `wait_with_timeout` helper
  (the `Peer` handshake timeout) races the handshake future against a
  `futures_timer::Delay`, but the `wasm` feature previously pulled
  `futures-timer` *without* its `wasm-bindgen` feature. On
  `wasm32-unknown-unknown` that selected `futures-timer`'s native timer-thread
  backend, so `Delay::new` panicked (`thread::spawn` is unsupported) on the
  first poll, hanging/aborting any `Peer::to_peer` call that initiates a
  handshake inside a Cloudflare Worker or browser `wasm-bindgen-futures`
  executor. Enabling `futures-timer/wasm-bindgen` flips it to the
  `gloo-timers`/`setTimeout` backend, which works in those environments.
  Pure additive feature wiring (no API change) → patch bump.

## [0.3.7] - 2026-04-21

### Added

- **`bsv_rs::overlay::create_signed_overlay_admin_token`**, produces
  TS-parity 5-field signed SHIP/SLAP advertisement tokens. Byte-exact
  match with `@bsv/sdk 1.10.1`'s
  `pushdrop.lock(fields, [2, protocol_name], '1', 'anyone', forSelf=true,
  includeSignature=true, lockPosition='before')`, the exact call
  `@bsv/overlay-discovery-services/src/WalletAdvertiser.ts` makes and
  what `nanostore.babbage.systems` / `overlay-us-1.bsvb.tech` validators
  admit under `tm_ship` / `tm_slap`.

  PushDrop layout:
  ```
  <locking_pubkey:33>  OP_CHECKSIG
  <"SHIP"|"SLAP">
  <identity_key:33>
  <domain>
  <topic_or_service>
  <signature_der>
  OP_2DROP OP_2DROP OP_DROP
  ```

  Locking pubkey + signing key are BRC-42 children of `root_key` for
  `protocolID = (SecurityLevel::Counterparty, "service host interconnect"
  | "service lookup availability")`, `keyID = "1"`, `counterparty =
  Anyone`, `forSelf = true`. Signature is ECDSA (RFC 6979 deterministic)
  over `sha256(concat(fields[0..4]))`.

  Takes `&PrivateKey` (not `&PublicKey`) because the function has to
  SIGN the advert.

- **`tests/vectors/overlay_admin_token_ts_parity.json`**, byte-exact
  parity vectors generated from `@bsv/sdk 1.10.1`. 5 cases covering SHIP
  (3 inputs, including long topic) + SLAP (2 inputs).

- **`tests/overlay_admin_token_ts_parity_tests.rs`**, blocking parity
  gate: loads the TS vectors and asserts
  `create_signed_overlay_admin_token(...)` reproduces them verbatim,
  plus a determinism guard for RFC-6979 signing.

### Deprecated

- **`bsv_rs::overlay::create_overlay_admin_token`** (soft deprecation,
  still compiles). It emits a 4-field unsigned PushDrop with the
  identity key as locking key, a shape `@bsv/overlay-discovery-services`
  requires but never admits, so any advert built with it is silently
  rejected by peer validators. See the `#[deprecated]` attribute for
  the migration pointer. The `decode_overlay_admin_token` reader still
  accepts both 4- and 5-field shapes for backward-compat.

### Notes: cross-SDK parity

- **Matches TS (`@bsv/sdk` 1.10.1)** byte-exact, the version deployed
  at `nanostore.babbage.systems` and `overlay-us-1.bsvb.tech`. Locking
  key + signing key both use `counterparty=Anyone, forSelf=true`, which
  is what `pushdrop.lock(...)` emits when `WalletAdvertiser.ts` calls
  it.

- **Diverges from Go SDK** (`github.com/bsv-blockchain/go-sdk/overlay/admin-token`).
  Go uses `counterparty=Self, forSelf=false`. By BRC-42 symmetry that
  yields the same locking pubkey, but `createSignature` with
  `counterparty=Self` derives a different signing key, so signatures
  differ and Go-produced tokens fail TS validators too. The Go SDK
  needs its own fix; `bsv-rs` matches the deployed reality.

## Earlier releases (from the release commits; no entries were written at the time)

- 0.3.20 (2026-09-09): the `Transaction::verify` walk that 0.3.21/0.3.22 replaced (refused a complete BEEF whose duplicate-input parents were bare clones).
- 0.3.18 (2026-07-21): `SighashCache`, the midstate-reuse sighash API (documented under 0.3.21 above).
- 0.3.17 (2026-07): the 0.3.16 parity work's follow-up release.
- 0.3.15 (2026-07-07): three conformance-surfaced fixes (two panics, the fee formula).
- 0.3.13 (2026-05-26): the BRC-104 transport timeout fix.
- 0.3.10 (2026-05-20): `SocketIoTransport` (Socket.IO 5 / Engine.IO 4 + BRC-103, substrate-agnostic).
- 0.3.9 (2026-05-19): the wasm32 `SystemTime::now` panic fixed (`js_sys::Date` behind the `wasm` feature).
- 0.3.8 (2026-05-19): the wasm32 runtime-agnostic `Peer` timeout (`futures-timer`).
- 0.3.6 (2026-04-20): the canonical 48-byte nonce, with the legacy 32-byte accept window.
- 0.3.4 and earlier: tracked in git history.

[0.3.7]: https://github.com/Calhooon/bsv-rs/releases/tag/v0.3.7
