# #400: every JSON body this crate writes that a reference reader or a recorded fixture compares whole, listed; serde_json's preserve_order crate-wide only if the list is not empty

Branch `lane/fix-400-json-bodies-census` from `origin/beta`'s tip after the beta.4 cut (the keeper's word of 04:1xZ: beside #423 on the 0.9.0 line, the census the 10-28 charter asked; name the base sha in your REPORT). Every gate and every test runs in the foreground, in your turn; never end a turn with a command running in the background.

The charter (#400, the keeper's of 2026-10-28 04:5xZ from #394's open item): JSON key order is not a reading of any parser, so a body's byte order is a parity item only where the reference's bytes are hashed, signed or compared whole. #394 serialises the overlay lookup question's attributes from the `IndexMap` directly (the one place found where the port's bytes sit beside the reference's recorded body).

1. The census: list every JSON body this crate writes (the HTTP JSON substrate's requests, `src/wallet/substrates/http_json*`; the overlay lookup and submit bodies, `src/overlay/`; the identity client's, `src/identity/`; the auth transports' message bodies, `src/auth/transports/`; the kvstore and registry payloads; the wire's JSON where any; the storage client's; anything else `serde_json::to_vec` or `to_string` reaches: grep them all), and for each say whether a reference reader or a recorded fixture compares it whole (a hash, a signature, a whole-body equality in the reference's code at edf6e03, `~/bsv/ts-stack/packages/sdk/src/` and `~/bsv/ts-stack/packages/wallet/`, or in this crate's recorded fixtures under `tests/vectors/` and `tests/support/`), with the reference's key order and this crate's (`serde_json::Value` sorts keys; a derived `Serialize` keeps struct order; `IndexMap` keeps insertion order). The list goes into the entry and into `src/CLAUDE.md` (or the substrates' guide) as a table: body, writer, compared whole by whom, the two orders, the verdict.
2. The verdict: if the list of bodies compared whole with a differing order is not empty, serde_json's `preserve_order` feature crate-wide (every `Value` built or read; the recorded fixtures re-read for key order; the memory's note: `serde_json::Value` sorts vector keys and the Rust recorders emit patches, the Node script writes the vector), with a test per body RED on the base (the bytes against the reference's recorded body) and the entry; if it is empty, no code change: the entry records the finding and the issue closes as not a parity item. Say which and why.
3. Gate, in the foreground, all green: `cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings` and `cargo +1.99.0 clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` with one `--test` per file matching every area the census touched (name the globs and the files in the REPORT); `cargo test --doc --all-features`; the root `CLAUDE.md`'s wasm32 build; `cargo semver-checks --baseline-rev <base sha> --release-type patch`; `tools/ratchet/run` on the built target.
4. Commit on the branch; no push (the captain pushes).

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.

REPORT: the commit's sha and the base sha; the census table; the verdict and why; each test (if any), its RED reason and the green count; the gate's results in a table; anything unverified; nothing else.

## Fold word (2026-10-30)

The filed brief above is preserved verbatim from beta, as the cold review
requested. The keeper's 2026-10-30 word supersedes its item 2 and gate selection:
order only the certificate-response body at the signing site, leave serde_json's
default unchanged, and run the complete integration suite with websocket.

Cold review `1df8cb10` is folded: its Go parity paragraph is kept verbatim in
the entry and census; migration is limited to noncanonical response signatures;
the brief is restored. Its insertion-order #394 literal was specific to the
removed feature, so the requested beta test and ordinary lookup bytes remain.

## #400 JSON body census: evidence and validation

Base: `8e57ee462aee6cc5e4888fee7edc02ee2b61d4aa`.
Reference: `ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9`, read from git.
Fold parent: `758ce0ec8096123ce66fd8d90f2529ebae729a0b` (no rebase).

The table in [CHANGELOG.md](../../CHANGELOG.md) and
[src/CLAUDE.md](../../src/CLAUDE.md) has 31 writer groups and one nonempty
finding: the Peer's signed certificate-response body. The fix orders that
one body at its signing site using #426's existing ordered-node parser.
`stringify_certificates` restores the reference class order, retains nested
insertion order and applies JavaScript numeric-key ordering.

serde_json's default is unchanged, no key order of any other body moves, and nothing unifies across a consumer's graph.

No new dependency or API shape is introduced. The beta ratchet lock and the
three former result_large_err sites are restored without feature allowances.

## Search and comparison method

- Searched all `src/**/*.rs` for `serde_json`, `to_vec`, `to_string`,
  `to_writer`, `to_value`, `to_raw_value`, `json!`, request `.json`/`.body`
  calls, and manual JSON formatting. Read callers through to the transport
  or signature. Unit-test/example serializers and response-only `.json()`
  calls were distinguished from emitted bodies.
- Read the pinned `packages/sdk/src/` and all nested packages under
  `packages/wallet/`, plus `packages/messaging/authsocket-client/src/`.
  The wallet toolbox HTTP and relay readers parse request members; they
  do not prescribe a request object's property order.
- Read the recorder/assertion paths under `tests/support/`, `tests/vectors/`
  and `tests/fixtures/`. A JSON file being byte-stable on disk does not make
  every embedded object a whole-body assertion. `fixtures_replay` compares
  parsed objects, but its `request_body_hex` strings still pin HTTP bytes.
  The HTTP fixture family has 29 files and 72 entries (including errors).
- #326's `sign_action_json` and `create_signature_json` recorder fields are
  parsed to `Value` before the corresponding argument comparisons.
  The actual signed data arrays, identity `published_json`, and #280/#426
  preimage text/hex retain byte significance. #394 separately pins the
  identity query's attribute order and the unchanged ordinary lookup body.
- Kept the distinction between a canonical JSON comparison (the requested
  certificate set, certificateResponse array, global KV protocol tuple) and a signature on received
  bytes (registry fields, general auth payloads). A receiver of the latter
  verifies the supplied bytes; it does not rebuild JSON in its own key order.
- `Value` reads sort object keys, unchanged from beta. The key-sensitive
  assertions use original text, `RawValue`, ordered maps or text/hex fields,
  so those assertions still see order. Typed certificate serialization keeps
  IndexMap fields and keyrings; a sorted Value cannot recover source order.
- No registry/contacts API parity or JSON escaping claim is made by the
  ordering verdict. For example, the registry protocol field is manually
  formatted with a space, its descriptors use `HashMap`, and the Contact
  model differs from the reference; none is normalized and then compared
  whole by the audited JSON reader or a recorded whole-body assertion.
- BEEF, transaction hashes, certificate signatures over binary certificate
  fields, ARC/WoC/Teranode binary or hex bodies, and BRC-104 binary framing
  are not JSON object serialization. WoC's body is raw transaction hex;
  Teranode's is extended transaction bytes. Tracker/live-policy calls are
  GET readers. The wire's metadata JSON is an internal validator input.

## Typed fallback and retained text

`src/auth/types.rs:240-241` uses retained certificate text while it still
matches the typed member, passing it to `stringify_certificates`.
Lines 242-245 borrow `Vec<VerifiableCertificate>` and serialize it directly to
RawValue. The certificate's remote serde derive emits its struct fields in
declaration order; VerifiableCertificate flattens that certificate and then
writes its keyring. Both fields and keyring are IndexMap, without a Value
round trip. Lines 246-249 call the same signing reserializer and keep the
existing empty result on absent or unserializable data.

Go at `2ca481c` also marshals certificates before signing and verifying
(`auth/peer.go:898,1189`), but encoding/json sorts its fields/keyring map
keys. Its outer struct properties agree; its nested map order does not
provide TypeScript's insertion order. TypeScript is the ordering reference.

## Recorder evidence

`auth_response_order_400.mjs` issues a real certificate and captures the
pinned Peer's actual signed bytes. Fields/keyrings contain numeric names
`10,2` and nonnumeric names `z,a`: the preimage orders them `2,10,z,a`.
One input permutes numeric keys; another reverses class properties and adds
an ignored extension. The real receiving Peer accepts both and verifies the
recorded preimage. Node 22.18.0 records identical bytes on two runs.

All 12 HTTP fixtures altered only by the feature are restored to beta.
The full Rust fixture recorder runs with serde_json's default in a temporary
checkout; its Node 22 order-preserving writer must report no changed values
and its output must equal beta byte-for-byte. No pre-existing vector changed.

## RED and foreground gates

The RED tree is a git archive of 8e57ee46 with the five test files and the
new Node vector overlaid. It has its own CARGO_TARGET_DIR beneath TMPDIR.
The three #400 tests compare signed bytes, not a serde_json feature:

| Regression | RED mismatch |
|---|---|
| `certificate_response_numeric_keys_use_the_recorded_reference_preimage` | Raw 10,2 instead of numeric 2,10 |
| `typed_certificates_sign_in_reference_order_without_retained_text` | Typed IndexMap 10,2 instead of numeric 2,10; z,a remains in insertion order |
| `certificate_response_restores_reference_class_property_order` | Reversed class properties and extension instead of the reference layout |

The kept #268/#280/#394/Socket.IO pins run alongside these tests. GREEN and
all gates use a temporary checkout with the lane's exact tracked source,
so generated Cargo.lock files stay outside the lane. Build output goes to
the shared external target; all commands are foreground and sequential.
The integration command is the full suite, not a selected file subset:
`cargo test --features "full,http,websocket" --tests --no-fail-fast`, with
stdout/stderr redirected unpiped to a log, then `grep "^test result"`.

Evidence and raw result lines are kept under
`/Volumes/Lanes/out/fix-400-json-bodies-census/`. Temporary source trees and
the RED target are removed after validation; no server or watcher is kept.

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo +1.99.0 clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --features full,http,websocket --tests --no-fail-fast` | 4,405 passed; 0 failed; 23 ignored |
| `cargo test --lib --all-features` | 1,647 passed; 0 failed; 4 ignored |
| `cargo test --doc --all-features` | 279 passed; 0 failed; 128 ignored |
| `cargo build --examples --all-features` | PASS |
| `cargo test --test readme_examples` | 1 passed; 0 failed; 0 ignored |
| `cargo build --target wasm32-unknown-unknown --no-default-features --features auth,wallet,transaction,overlay,socketio,wasm` | PASS |
| `cargo semver-checks --baseline-rev 8e57ee46 --release-type patch` | PASS |
| `tools/ratchet/run --check --against 8e57ee46` | PASS |

The final-commit `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` scan is recorded in the external `gitleaks.log` after the commit.

RED: exactly the three #400 tests failed on the archive of 8e57ee46; the 27 kept pins passed (two existing recorders ignored). GREEN: all 30 tests passed (the same two recorders ignored). `red-byte-differences.json` records the numeric-key mismatch at byte 379 and the class-layout mismatch at byte 3.

The full-suite result lines are in `integration-results.txt`, produced by `grep "^test result" integration.log` after the unpiped command completed. Existing ignored tests and doc illustrations were not run. Go field-value encodings are outside the unchanged parity paragraph's measurement scope.
