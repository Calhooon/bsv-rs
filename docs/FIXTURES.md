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
job does this only when the checkout has no lock. Lane builds use an external
manifest and keep that generated file outside the worktree.

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

All BRC citations use the same full commit:
`bsv-blockchain/BRCs@5119a9b5148e9ec90eb4865b16f9f732a29703df`
(2026-10-19). Read the pinned git object, not a BRC working tree:

```sh
git -C "$HOME/bsv/brcs" show 5119a9b:wallet/0100.md
```

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
| F2 | Linkage has no transceiver methods. Its processor ignores `privileged` and `privilegedReason`, and writes encrypted data before the public keys; the BRC table puts the public keys ahead of encrypted data. | Sections 9 and 10 |
| F3 | The header processor prefixes its 80 bytes with a length, while the client treats that length as a header byte. The recorded header has 81 bytes. | Section 26, Return Values |
| F4 | `write_wallet_certificate` writes type, serial, subject, certifier, outpoint, fields, then raw signature. The transceiver certificate reader expects type, subject, serial, certifier, outpoint, length-prefixed signature, then fields. Both acquisition cases and the populated list/discovery cases record `ReaderUnderflow`. | Sections 17, 18, 21, 22 |
| F5 | HTTP crypto requests use `protocolId` and `keyId`, while the BRC and CLI use `protocolID` and `keyID`. Direct-sign and direct-verify hashes are hex strings rather than byte arrays. | Sections 8, 10 through 16; The Wallet Interface |
| F6 | HTTP uses `inputBeef`, `returnTxidOnly`, byte-array TXIDs in create/sign results and options, and hex BEEF/AtomicBEEF and signable references. The BRC uses `inputBEEF`, `returnTXIDOnly`, hex TXIDs, byte-array BEEF, and base64 references. | Sections 1, 2, 5, 6; data types BEEF, AtomicBEEF, TXIDHexString, Base64String |
| F7 | HTTP certificate objects use `certificateType` where the BRC uses `type`. Certificate listing uses a nested `certificate` wrapper. | Sections 17 through 22; The Wallet Interface |
| F8 | HTTP linkage results use nested `linkage`, and specific linkage uses a `protocol` object and `keyId`. The BRC's result fields are flat with `protocolID` and `keyID`. | Sections 9 and 10; The Wallet Interface |
| F9 | Optional integer fields use ZigZag in the Rust writer (`10` becomes `20`); the BRC table calls them VarInt values. The BRC's VarInt section specifies unsigned CompactSize and does not specify this transformation. | ABI Specification, VarInt Encoding; sections 1, 2, 4, 6, 18, 21, 22 |
| F10 | `SendWithResultStatus` uses 0/1/2 for unproven/sending/failed. The BRC-100 table names 1/2/3. | Section 1, Return Values; section 2 |
| F11 | Wire drops the Rust-only extra create-action result fields and prove-certificate `certificate`/`verifier` fields. The HTTP result retains them. Wire output listings read `spendable` as true even when the supplied Rust result had false. | Sections 1, 6, 19; surface projection, not a claim about valid wallet results |
| F12 | Non-busy string error codes become `WalletError` containing HTTP status and the raw body; only numeric codes get the special code/description mapping. | Error Handling and Validation; recorded `brc_string_refusal` |

The public Rust crypto argument types also cannot express all BRC optional
`privileged`, `privilegedReason`, and `seekPermission` fields. Those unavailable
arguments are a coverage limit; adding them would change a public API and is
outside this lane. The CLI envelope comparison used the local #69 lane's
`docs/WIRE.md` and `tests/wire/` at `512c59b`; comparison against its eventual
`origin/beta` landing is still a captain check.

The fixture strategy addresses the stack's six tests as follows: fixed bounded
cases and streaming chunk checks address T1; merkle roots retained beside
their proofs address T2; local mocks and no spends address T3; the real codecs
and merkle arithmetic address T4; pinned sources and unmodified observed
values address T5; the replay and CI gate address T6. T2 here does not assert
that a root was checked against a live header service.

Execution evidence belongs in the lane report. The fixtures preserve these
findings; any future repair needs the usual behavior and fixture commits.
