# Public surface fixtures

`tests/fixtures/` records what this crate writes and reads. These are regression
snapshots of the current behavior, including disagreements, not a claim that
every recorded shape implements its BRC. The shared cross-SDK vectors in
`tests/vectors/` and `tests/transaction/vectors/` remain unchanged.

Run the replay with an external build directory:

```sh
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/bsv/targets/oracle-fixtures}"
cargo test --features "full,http" --test fixtures_replay --locked
```

The library currently ignores `Cargo.lock`. If no lock is available, resolve
dependencies with `cargo generate-lockfile` before the locked command. The CI
job does this only when the checkout has no lock.

Every file has `schema_version`, pinned `references`, and named `cases`.
Each case contains its `input` and exact `expected` output. For example,
`wire/getPublicKey.json` keeps the arguments, the provided result, the full
request and response frames as hex, the decoded client result, and the
processor's observed arguments and method. Frame hex includes the call,
originator, and status bytes. No bytes are removed before comparison.

HTTP cases keep the JSON request captured by `wiremock`, the served response,
and the client result. Their request envelope uses `method`, `path`, `headers`,
and `json`, as does the CLI's `tests/wire/` format in its #69 lane. The adjacent
`request_body_hex` also pins the actual outgoing bytes, including JSON member
order and whitespace; `response_body_hex` pins the compact served success
body. No bytes or JSON values are normalized. A wire byte, HTTP body byte,
JSON value, or field presence change fails with the file, case, field path,
and old and new values. Hex differences also report the string offset.

The fixed census is in `tests/support/fixtures/mod.rs`. It checks generated
entry counts and the complete on-disk inventory, so a file cannot silently
disappear or be added without replay. Every wallet call has two wire cases and
two HTTP cases, named `minimal` and `full`. Required fields remain present in
minimal cases; full cases exercise optional fields and alternative enum values.
They are codec data, not instructions to create or broadcast a transaction.

| Surface | Files | Named entries |
| --- | ---: | ---: |
| Wire | 29 | 323 |
| HTTP JSON | 29 | 72 |
| BEEF | 4 | 8 |
| Merkle path | 1 | 5 |
| Transaction | 2 | 505 |
| Total | 65 | 913 |

The wire count includes 56 call cases and 267 shared error cases. The shared
catalogue is replayed through all 28 calls: every nonzero status byte, absent
or present stack data, malformed envelope classes, and the three codes the
processor emits. It is referenced from each call file rather than copied 28
times. The 54 existing Go message files keep their existing cross-SDK tests;
this suite adds argument combinations and surfaces rather than copying them.

The HTTP count includes 56 call cases and 16 error cases: both busy codes with
and without retry delay, the code-only fallback, numeric and string refusals,
bare 502/503/504, malformed success JSON, invalid HMAC length, unknown network,
connection failure, and timeout. A failed connection has no HTTP response to
record. Connection and timeout cases pin `WalletTransport`, its absent status,
and assert the crate's diagnostic prefix. The dependency's OS-specific text
and ephemeral URL are explicitly outside this snapshot contract. They are
never rewritten into a fake stable error string.

The BEEF files cover versions 1 and 2, AtomicBEEF, and txid-only entries. Each
uses the crate's writer, round-trips through `Beef::from_binary`, and compares
`BeefStream` at whole-input, 1-, 7-, and 64-byte reads. Atomic output also runs
through `to_binary_atomic`; ordinary `to_binary` emits an ordinary container.
Streamed transaction IDs, raw payloads, BUMPs, roots, and offsets are recorded.
These are reader/serialization checks, not header-service attestations.

Transaction cases serialize the funding and spending transactions of the
`transaction` and `beef_spv` README programs, the empty transaction constructed
by `overlay`, and all 500 transactions in the sighash vector file. The network
operations of the overlay example are not invoked. References to existing
vector files name the file and row or constant; the original vectors are read
in place. Merkle cases exercise both binary and hex readers.

## Deterministic inputs

Wallet cases use fixed public curve points, fixed byte arrays, height 800000,
and timestamp `2026-10-19T00:00:00Z`. They use a stub `WalletInterface` to supply
results, so encryption and key-linkage responses do not acquire random nonces.
No wallet, account, live hostname, token, or private key is a fixture input.
The `.invalid` names are reserved test names and only appear in bodies or
origin metadata; the HTTP client connects solely to the local mock server.

The README recipes replace their random key with a scalar computed from
`SHA256("bsv-rs oracle-fixtures README transaction v1")`. That public test seed
is recorded; the scalar is never stored. Signatures use the crate's
deterministic signer. Source hashes in the test code guard the copied example
recipes. After an example edit, review its recipe and update that guard; a
comment edit need not change a golden file. Existing corpus inputs already fix
all their bytes.

Some request encoders iterate a `HashMap` directly. The `signAction.spends`,
`acquireCertificate.keyringForSubject`, and `discoverByAttributes.attributes`
fixtures use singleton maps to remain deterministic without sorting or
normalizing the encoder's output. Certificate field maps in HTTP requests
likewise use one entry so their raw JSON bytes are reproducible. Multi-entry
request map ordering is a separate known coverage limit, not a stable-byte
guarantee.

## Deliberate changes

Only this command writes fixtures:

```sh
BSV_FIXTURES_RECORD=1 cargo test --features "full,http" --test fixtures_replay --locked
```

An unset variable, `0`, `true`, or any value other than `1` only replays. The
recorder never deletes unexpected files; the inventory check still refuses
them. Review and remove an obsolete fixture explicitly.

For a behavior PR:

1. Add its witness and observe the failure against the old behavior.
2. Commit the implementation and its witness together, apart from refactors.
3. Record, inspect `git diff -- tests/fixtures`, then replay without record mode.
4. Commit the intended golden changes in their own commit. If a case was added
   or removed, include the census change in that fixture commit.

A refactor produces no fixture diff. A writer and reader changing together
still changes the golden output and fails replay. Do not repair disagreements
by editing the shared vectors or silently rewriting recorded fields.

## References

All BRC citations use the line's pin, the same full commit:
`bsv-blockchain/BRCs@5119a9b5148e9ec90eb4865b16f9f732a29703df`
(2026-10-19; the stack's PROVENANCE, the keeper's word of 2026-10-24 on the
owner's, bsv-rs#154). Read the pinned git object, not a BRC working tree:

```sh
git -C "$HOME/bsv/brcs" show 5119a9b:wallet/0100.md
```

The pin before it (2026-10-05) read the same for every section cited here
except listOutputs' `totalOutputs` and `spendable` (bsv-rs#105) and
internalizeAction's `customInstructions` bound (bsv-rs#117); the move changed
no fixture byte. A re-pin is the keeper's recon and the owner's word, taken by
the three crates in one step.

| Surface | Pinned document and sections |
| --- | --- |
| Wallet wire | BRC-100, ABI Specification, Method Calls Specification 1 through 28; Error Handling |
| HTTP JSON | BRC-100, The Wallet Interface for each method; Error Handling and Validation |
| BEEF v1 | BRC-62, Specification and Ordering |
| BEEF v2 and txid-only | BRC-96, Specification |
| AtomicBEEF | BRC-95, Header Structure and Transaction Inclusion Rules |
| Merkle path | BRC-74, Binary Encoding |
| Transaction | BRC-12, Specification (raw payload, not its network frame) |

## Existing disagreements kept visible

The recorder changes no production encoder or HTTP body. Its support code is
under `tests/support/fixtures/`; no production test hook is needed.

The processor refuses calls 1 through 7 and 17 through 22 with a generic
"requires a full wallet implementation" frame, even when its wallet implements
the whole trait. Those frames remain in `processor_response_hex`. Their client
result cases use the public `WireWriter` type encoders and explicit framing;
`response_encoder` identifies that path. The transceiver also has no linkage
methods (calls 9 and 10). Those two cases reuse the low-level reader/writer
approach of `wire_method_roundtrip_tests.rs`, and do not claim to test a missing
production client method. BRC-100 defines all these methods in its numbered
Method Calls Specification.

The following differences are also kept visible. Section numbers refer to
BRC-100's Method Calls Specification at the pin above. A difference between
Rust's two surfaces is listed even when it is an extension or a projection,
rather than a BRC violation.

| Finding | Recorded behavior | BRC citation |
| --- | --- | --- |
| F1 | Calls 1, 2, 4 through 7 and 17 through 22 are processor refusal stubs (abortAction, call 3, calls its wallet since bsv-rs#206, F19). The client and HTTP methods exist. | Sections 1, 2, 4 through 7, 17 through 22 |
| F2 | Linkage has no transceiver methods. Its processor reads `privileged` and `privilegedReason` in the reference's order since bsv-rs#191 (counterparty linkage: ahead of the two keys; specific linkage: within the key-related parameters, ahead of the verifier), and writes both responses in the reference's order since bsv-rs#194: the prover, verifier and counterparty, then revelationTime and the two byte strings, or the protocol, keyID, the two byte strings and proofType. | Sections 9 and 10, Return Values (`wallet/0100.md:2052-2057`, `:2088-2095`) |
| F3 | Resolved (bsv-rs#178): the header processor wrote a length before its 80 bytes, which the client read as a header byte (81 bytes); it now writes the 80 raw bytes, as the reference does, and the recorded header is the stub's. | Section 26, Return Values (`wallet/0100.md:2463`) |
| F4 | Resolved for the reader (bsv-rs#177): the transceiver reads the certificate as `write_wallet_certificate` and the reference write it (type, serial, subject, certifier, outpoint, fields, raw signature), listCertificates' verifier as 33 raw bytes, discovery's certifier info as plain strings; every certificate case records its input result. The list frame is the recorder's explicit framing of the reference's bytes; the discovery entries are `write_identity_certificate`'s, which writes the reference's bytes since bsv-rs#182 (the recorder's own copy of the layout left; the recordings unchanged). | Sections 17, 18, 21, 22 |
| F5 | HTTP crypto requests use `protocolId` and `keyId`, while the BRC and CLI use `protocolID` and `keyID`. Direct-sign and direct-verify hashes are hex strings rather than byte arrays. | Sections 8, 10 through 16; The Wallet Interface |
| F6 | HTTP uses `inputBeef`, `returnTxidOnly`, byte-array TXIDs in create/sign results and options, and hex BEEF/AtomicBEEF and signable references. The BRC uses `inputBEEF`, `returnTXIDOnly`, hex TXIDs, byte-array BEEF, and base64 references. | Sections 1, 2, 5, 6; data types BEEF, AtomicBEEF, TXIDHexString, Base64String |
| F7 | HTTP certificate objects use `certificateType` where the BRC uses `type`. Certificate listing uses a nested `certificate` wrapper. | Sections 17 through 22; The Wallet Interface |
| F8 | HTTP linkage results use nested `linkage`, and specific linkage uses a `protocol` object and `keyId`. The BRC's result fields are flat with `protocolID` and `keyID`. | Sections 9 and 10; The Wallet Interface |
| F9 | Optional integer fields use ZigZag in the Rust writer (`10` becomes `20`); the BRC table calls them VarInt values. The BRC's VarInt section specifies unsigned CompactSize and does not specify this transformation. | ABI Specification, VarInt Encoding (`wallet/0100.md:1629`); sections 1, 2, 4, 6, 18, 21, 22 |
| F10 | `SendWithResultStatus` uses 0/1/2 for unproven/sending/failed. The BRC-100 table names 1/2/3. | Section 1, Return Values; section 2 (`wallet/0100.md:1726`) |
| F11 | Wire drops the Rust-only extra create-action result fields and prove-certificate `certificate`/`verifier` fields. The HTTP result retains them. Wire output listings read `spendable` as true even when the supplied Rust result had false; the wire's `spendable` is `1` for an ordinary output and `0` only for a module inventory record (`wallet/0100.md:1963`, `:1974-1980`; BRC-207, bsv-rs#105), so for an ordinary listing the wire agrees with the pin and the difference is the Rust type's `false`. | Sections 1, 6, 19; surface projection, not a claim about valid wallet results |
| F12 | Non-busy string error codes that name no `WalletRefusalClass` become `WalletError` containing HTTP status and the raw body; numeric codes get the code/description mapping. Since bsv-rs#137 a body whose `name` or `code` names a class (a `WERR_*` name, or an SDK code 2 to 8) is `WalletRefusal` with that class: `numeric_refusal` and `numeric_refusal_on_503` (code 6) re-recorded as `InvalidParameter`, their requests unchanged. | Error Handling and Validation; recorded `brc_string_refusal` |
| F13 | Resolved (bsv-rs#197): the processor wrote encrypt's, decrypt's, createHmac's and createSignature's bytes behind a varint length and the three verdicts (verifyHmac, verifySignature, waitForAuthentication) as a byte after the error byte; it now writes the bytes alone and the error byte alone, as the reference does, and answers a false verdict with an error frame, so the verifyHmac and verifySignature `minimal` cases (the stub answers `valid: false`) record that frame and the client's error. | Sections 11 through 16, 24, Return Values (`wallet/0100.md:2117`, `:2139`, `:2161`, `:2180`, `:2204`, `:2226`, `:2441-2443`) |
| F14 | Resolved (bsv-rs#199): the transceiver wrote, and the processor read, verifyHmac's data then the HMAC behind a length, and the signature calls' data and hash as two optional byte fields (verifySignature's signature last); both now write and read the reference's frame (the HMAC's 32 raw bytes then the data; a data-type flag, `1` and the data or `2` and the hash, verifySignature's signature ahead of it), so the three recordings' request bytes moved and their responses did not. | Sections 14 through 16, Parameters (`wallet/0100.md:2172-2174`, `:2191-2193`, `:2215-2219`) |
| F15 | Resolved (bsv-rs#202): the processor wrote an error frame's message as this crate's `Display` (`wallet error: ` ahead of the wallet's words) and chose 6 or 7 from the words `invalid parameter` and `insufficient funds`; it now writes the reference's frame (`ts-stack@edf6e03` `WalletWireProcessor.ts:2379-2396`): unknownError (1) for an un-coded error (a `WalletRefusal` keeps its class's code since bsv-rs#137), the wallet's bare words cut at 4096 bytes, the stack a varint 0. Sixteen recordings moved: `error_frames.json`'s three processor cases (6 and 7 now 1), the verifyHmac and verifySignature `minimal` cases, and the thirteen calls the processor refuses as needing a full wallet; the client's error loses its inner prefix. The processor's missing argument and result validation, a divergence the #202 parity note named, is withdrawn by bsv-rs#216 (F17). | Response frame (Error) (`wallet/0100.md:1605-1616`) |
| F16 | Resolved (bsv-rs#193): the transceiver wrote, and the processor read, the seven key-related requests without the privileged flag, the reason and seekPermission (getPublicKey's in a layout of this crate's own: an optional identityKey, a `255` protocol sentinel, a nil-sentinel key ID), and the processor never asked that a request be read to its end; both now write and read the reference's frame (the privileged pair after the counterparty, seekPermission last; getPublicKey's identityKey byte, then the pair alone or the key-related parameters and forSelf), and the processor refuses trailing data. The args types gained the three fields; the recorder's `full` case sets them (`privileged` true, a reason, `seekPermission` false), so the seven wire recordings' requests and observed args moved and the seven HTTP JSON recordings' `full` bodies carry the three names. | Sections 8, 11 through 16, Parameters (`wallet/0100.md:2010-2013`, `:2107`, `:2129`, `:2151`, `:2174`, `:2194`, `:2220`) |
| F17 | Resolved (bsv-rs#216): the processor handed every argument to its wallet and wrote every result; it now validates a request's arguments ahead of the wallet and the wallet's result after it, as the reference does (`ts-stack@edf6e03` `validateWalletArgs`, `validateWalletResult`; an argument refused code 6, a result code 1). The recorder's `minimal` getHeaderForHeight request and getHeight answer asked for and answered height 0, which the reference refuses (`WalletWireProcessor.ts:1670-1675`, `WalletResultValidation.ts:2293-2295`); a recording pins the writers' bytes on valid inputs, so both moved to height 1 and four recordings moved (wire and HTTP JSON getHeight and getHeaderForHeight: the height byte `00` to `01`, the JSON `0` to `1`). The refusals are pinned by `tests/wire_processor_validation.rs`. getNetwork and getVersion were answered by the processor's configuration until #222 (F18). | Sections 25 and 26 (`wallet/0100.md`); Response frame (Error) |
| F18 | Resolved (bsv-rs#222): the processor answered getNetwork and getVersion from its own configuration (mainnet, `0.1.0`) and never asked its wallet; it now forwards the wallet's `get_network` and `get_version`, as the reference does (`ts-stack@edf6e03` `WalletWireProcessor.ts:1701-1705`, `:1721-1725`), and refuses a version outside 7 to 30 UTF-8 bytes, code 1 (`WalletResultValidation.ts:2304-2306`). The recorder builds the processor with `new(stub)` and its stub answers the case's network and version, so the two recordings' `processor_observed` moved from `null` to the stub's observation (`get_network`, `get_version`, empty args); no byte moved, the recorder's `fixture-0.0.0` and `fixture-1.2.3` being 13 bytes. The forwarding and the refusal are pinned by `tests/wire_processor_validation.rs`. | Sections 27 and 28 (`wallet/0100.md`); Response frame (Error) |
| F19 | Resolved (bsv-rs#206): the processor answered abortAction with its refusal stub (code 1) and never called its wallet, and the transceiver read any success frame as `aborted: true` and any error frame as an error; the processor now hands the reference's bytes to its wallet as base64 and frames a wallet's `aborted: false` as the reference does (`ts-stack@edf6e03` `WalletWireProcessor.ts:797-804`: code 8, `abortRefused`, `The wallet refused to abort this action because it has already been broadcast`), and the transceiver reads code 8 as `aborted: false` (`WalletWireTransceiver.ts:336-339`) and a byte after a success frame's error byte as a refusal (`:334`). Two recordings moved: `abortAction.json`'s two cases record the processor's success frame `00` where the stub's code 1 frame stood, `processor_observed` the stub's observation (`abort_action`, the case's reference) where `null` stood, and `response_encoder` `WalletWireProcessor` where `WireWriter` stood (the client's bytes and result unchanged: `00`, `aborted: true`); `error_frames.json`'s `status_8` gains `client_result_by_call` with abortAction's `aborted: false`, the one call that reads a frame unlike the other 27 (the recorder asserts that no other call and no other frame differs). | Section 3 (`wallet/0100.md`); Response frame (Error) |

The seven key-related argument types carry `privileged`, `privilegedReason`
and `seekPermission` since bsv-rs#193 (F16). The CLI envelope comparison was re-run by the cold review against the CLI's
landed fixtures (bsv-wallet-cli beta `d93e077`, `tests/wire/*.json`,
`docs/WIRE.md`); the differences in request bodies and response shapes it found
(the BEEF, transaction and txid encodings of createAction, signAction and
internalizeAction; `protocolID`/`keyID` casing on eight calls;
`hashToDirectlySign`'s encoding) are recorded on bsv-rs #105 as items 5 to 8,
beside the four shapes already there, and are not fixed here.

The fixture strategy addresses the stack's six tests as follows: fixed bounded
cases and streaming chunk checks address T1; merkle roots retained beside
their proofs address T2; local mocks and no spends address T3; the real codecs
and merkle arithmetic address T4; pinned sources and unmodified observed
values address T5; the replay and CI gate address T6. T2 here does not assert
that a root was checked against a live header service.

Execution evidence belongs in the lane report. The fixtures preserve these
findings; any future repair needs the usual behavior and fixture commits.
