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
`bsv-blockchain/BRCs@ed1b015bac53106ff34e5d1831acda378cbe5c04`
(2026-10-05; the stack's PROVENANCE, the keeper's word of 2026-10-23). Read
the pinned git object, not a BRC working tree:

```sh
git -C "$HOME/bsv/brcs" show ed1b015:wallet/0100.md
```

Upstream `5119a9b` (2026-10-19, not on the line) reads the same for every
section cited here except listOutputs' `totalOutputs` and `spendable` and
internalizeAction's `customInstructions` bound (bsv-rs #117); a re-pin is the
keeper's recon and the owner's word, taken by the three crates in one step.

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
| F1 | Calls 1 through 7 and 17 through 22 are processor refusal stubs. The client and HTTP methods exist. | Sections 1 through 7, 17 through 22 |
| F2 | Linkage has no transceiver methods. Its processor reads `privileged` and `privilegedReason` in the reference's order since bsv-rs#191 (counterparty linkage: ahead of the two keys; specific linkage: within the key-related parameters, ahead of the verifier), and writes both responses in the reference's order since bsv-rs#194: the prover, verifier and counterparty, then revelationTime and the two byte strings, or the protocol, keyID, the two byte strings and proofType. | Sections 9 and 10, Return Values (`wallet/0100.md:2052-2057`, `:2088-2095` at `5119a9b`) |
| F3 | Resolved (bsv-rs#178): the header processor wrote a length before its 80 bytes, which the client read as a header byte (81 bytes); it now writes the 80 raw bytes, as the reference does, and the recorded header is the stub's. | Section 26, Return Values (`wallet/0100.md:2440`) |
| F4 | Resolved for the reader (bsv-rs#177): the transceiver reads the certificate as `write_wallet_certificate` and the reference write it (type, serial, subject, certifier, outpoint, fields, raw signature), listCertificates' verifier as 33 raw bytes, discovery's certifier info as plain strings; every certificate case records its input result. The list frame is the recorder's explicit framing of the reference's bytes; the discovery entries are `write_identity_certificate`'s, which writes the reference's bytes since bsv-rs#182 (the recorder's own copy of the layout left; the recordings unchanged). | Sections 17, 18, 21, 22 |
| F5 | HTTP crypto requests use `protocolId` and `keyId`, while the BRC and CLI use `protocolID` and `keyID`. Direct-sign and direct-verify hashes are hex strings rather than byte arrays. | Sections 8, 10 through 16; The Wallet Interface |
| F6 | HTTP uses `inputBeef`, `returnTxidOnly`, byte-array TXIDs in create/sign results and options, and hex BEEF/AtomicBEEF and signable references. The BRC uses `inputBEEF`, `returnTXIDOnly`, hex TXIDs, byte-array BEEF, and base64 references. | Sections 1, 2, 5, 6; data types BEEF, AtomicBEEF, TXIDHexString, Base64String |
| F7 | HTTP certificate objects use `certificateType` where the BRC uses `type`. Certificate listing uses a nested `certificate` wrapper. | Sections 17 through 22; The Wallet Interface |
| F8 | HTTP linkage results use nested `linkage`, and specific linkage uses a `protocol` object and `keyId`. The BRC's result fields are flat with `protocolID` and `keyID`. | Sections 9 and 10; The Wallet Interface |
| F9 | Optional integer fields use ZigZag in the Rust writer (`10` becomes `20`); the BRC table calls them VarInt values. The BRC's VarInt section specifies unsigned CompactSize and does not specify this transformation. | ABI Specification, VarInt Encoding (`wallet/0100.md:1620`); sections 1, 2, 4, 6, 18, 21, 22 |
| F10 | `SendWithResultStatus` uses 0/1/2 for unproven/sending/failed. The BRC-100 table names 1/2/3. | Section 1, Return Values; section 2 (`wallet/0100.md:1717`) |
| F11 | Wire drops the Rust-only extra create-action result fields and prove-certificate `certificate`/`verifier` fields. The HTTP result retains them. Wire output listings read `spendable` as true even when the supplied Rust result had false; at `ed1b015` the wire's `spendable` is "Always `1`" (`wallet/0100.md:1954`), so the wire agrees with the line and the difference is the Rust type's `false` (and upstream `5119a9b`, which allows it). | Sections 1, 6, 19; surface projection, not a claim about valid wallet results |
| F12 | Non-busy string error codes become `WalletError` containing HTTP status and the raw body; only numeric codes get the special code/description mapping. | Error Handling and Validation; recorded `brc_string_refusal` |
| F13 | Resolved (bsv-rs#197): the processor wrote encrypt's, decrypt's, createHmac's and createSignature's bytes behind a varint length and the three verdicts (verifyHmac, verifySignature, waitForAuthentication) as a byte after the error byte; it now writes the bytes alone and the error byte alone, as the reference does, and answers a false verdict with an error frame, so the verifyHmac and verifySignature `minimal` cases (the stub answers `valid: false`) record that frame and the client's error. | Sections 11 through 16, 24, Return Values (`wallet/0100.md:2094`, `:2116`, `:2138`, `:2157`, `:2181`, `:2203`, `:2418-2420` at `ed1b015`; the same text at `:2117`, `:2139`, `:2161`, `:2180`, `:2204`, `:2226`, `:2441-2443` at `5119a9b`) |

The public Rust crypto argument types also cannot express all BRC optional
`privileged`, `privilegedReason`, and `seekPermission` fields. Those unavailable
arguments are a coverage limit; adding them would change a public API and is
outside this lane. The CLI envelope comparison was re-run by the cold review against the CLI's
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
