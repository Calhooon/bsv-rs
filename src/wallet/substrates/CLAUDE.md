# Wallet Substrates Module
> HTTP transport substrates for wallet communication

## Overview

This module provides transport substrates for communicating with BSV wallets over HTTP. Substrates implement the [`WalletWire`] trait or provide direct method implementations, handling the actual network communication.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, constants, re-exports | ~66 |
| `http_wire.rs` | Binary wire protocol over HTTP; the frame's originator validated, refused when not the configured one, sent raw as `Origin` (#323) | ~243 |
| `http_json.rs` | JSON API over HTTP; an error body read as its `WalletRefusalClass` by name or code (#137); the constructor's originator sent as `Origin` and `Originator`, a call with none refused, a body over 256 MiB refused (#323); the answer read by `http_json/answer.rs` | ~1078 |
| `http_json/answer.rs` | The answer's reading (#339): busy/code-5/class/transport errors; a success body checked by `result_values.rs` before serde, then the typed reading with #365's normalized byte fallback | ~99 |
| `http_json/result_values.rs` | #408's result dispatch and borrowed JSON records/arrays; all scalar, container, request-binding and global checks precede typed decoding (#408, #432) | ~116 |
| `http_json/result_values/bytes.rs` | Reference byte type/length checks, HMAC exactly 32, signature at most 72; the existing canonical DER checker includes scalar range and permits high S | ~87 |
| `http_json/result_values/lists.rs` | List fields, page limits, filters and BEEF commitments in reference order (#432) | ~123 |
| `http_json/result_values/certificate.rs` | Signed wallet-certificate structure: base64 identifiers, compressed keys, revocation outpoint, field names/values, canonical DER and encoded size at most 16 MiB; no cryptographic signature verification | ~105 |
| `http_json/byte_fields.rs` | The byte fields of a wallet's JSON body as the reference's `HTTPWalletJSON` reads them (#339, #365; `ts-stack@edf6e03` `HTTPWalletJSON.ts:322-341`): `byte_array` (`normalizeBRC100ByteArray`, an array of bytes or the historical object form `{"0": 1, ..}`, each `isByte`, so `1.0` and `-0` too), `normalize` (`normalizeBRC100WalletByteFields`: the seventeen `walletByteFieldNames` at any depth) and `refusal` (the byte fields `validateWalletResult` reads per call: the action results' `tx` and `signableTransaction.tx`, ciphertext, plaintext, hmac, signature, the linkages' `encryptedLinkage` and `encryptedLinkageProof`, listOutputs' `BEEF`; the first that is no array of bytes `Invalid <call> result <field>: expected an array of bytes`) | ~251 |
| `origin.rs` | The two substrates' shared rules (#323): the reference's `normalizeWalletHttpBaseUrl` and `toOriginHeader`, the client `new` builds (`redirect::Policy::none()`), the redirect refusal | ~195 |
| `http_json/review_actions.rs` | A wallet's code-5 body read as the reference's `HTTPWalletJSON` reads it (#339; `ts-stack@edf6e03` `HTTPWalletJSON.ts:117-241`): a 400 body with an own `isError`, code 5 and `reviewActionResults`; the envelope, the message, the call, the action-result members through `validateWalletResult`'s action checks under `returnTXIDOnly: true` (`WalletResultValidation.ts:1242-1374`; including the transaction-against-request checks since #432), then the results, each refusal `WalletError` in the reference's words; the five members `Error::WalletReviewActions`; a `tx` or `competingBeef` in the historical object form (`{"0": 1, ..}`) read as its bytes by `byte_fields.rs`'s reader, the success path's too (#365) | ~386 |
| `http_json/key_requests.rs` | The nine key-related calls' JSON bodies; the seven key-related requests carry `privileged`, `privilegedReason` and `seekPermission` in the reference's names, an absent one omitted (`JsonPermission`, flattened; bsv-rs#193) | ~246 |
| `http_json/result_values/actions.rs`, `action_binding.rs`, `beef.rs` | #432 action order, request inputs/outputs, conservation and exact BEEF subject parsing | <400 each |
| `http_json/result_values/lists.rs`, `certificates.rs`, `identity.rs` | #432 list pages and filters, output commitments, certificate proofs and identity search | <450 each |
| `http_json/result_values/scalars.rs`, `boundary.rs`, `raw_tree.rs` | #432 scalar words, request/body bounds, a flat JSON container index and raw normalization, graph budgets and unsafe keys | <500 each |
| `CLAUDE.md` | This documentation | ~260 |

## Available Substrates

| Substrate | Protocol | Default Port | Use Case |
|-----------|----------|--------------|----------|
| `HttpWalletWire` | Binary | 3301 | High performance, low overhead |
| `HttpWalletJson` | JSON | 3321 | Debugging, simple integration |

## Platform-Specific Substrates (Not Included)

The following TypeScript SDK substrates are NOT included in the Rust SDK:

| Substrate | Reason |
|-----------|--------|
| `XDM` | Requires browser `window.parent.postMessage()` API |
| `ReactNativeWebView` | Requires React Native bridge |
| `WindowCWI` | Requires browser extension injection |

**Rationale**: These substrates require a JavaScript browser/WebView runtime with the `window` global, which doesn't exist in native Rust code. The Go SDK also excludes these for the same reason.

## HttpWalletWire

Binary wire protocol transport over HTTP. Implements the `WalletWire` trait.

### Constructors

```rust
// The originator validated, the base URL normalized; a client that follows no redirect
HttpWalletWire::new(originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>

// A custom reqwest::Client (timeouts, TLS, proxies), used as given: its redirect policy too
HttpWalletWire::with_client(client: Client, originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>
```

### Accessors

- `base_url(&self) -> &str` - The base URL's origin, as normalized
- `originator(&self) -> Option<&str>` - The originator, as `validate_originator` normalized it (the port dropped)

### Usage

```rust
use bsv_rs::wallet::substrates::HttpWalletWire;
use bsv_rs::wallet::wire::WalletWireTransceiver;

// Create wire transport
let wire = HttpWalletWire::new(
    Some("myapp.example.com".into()),
    None, // Uses default http://localhost:3301
)?;

// Wrap with transceiver for wallet operations
let wallet = WalletWireTransceiver::new(wire);

// Make wallet calls
let version = wallet.get_version("myapp.example.com").await?;
```

### HTTP Request Format

- **Method**: POST
- **URL**: `{base_url}/{call_name}` (e.g., `http://localhost:3301/getPublicKey`)
- **Content-Type**: `application/octet-stream`
- **Headers**: `Origin`, the frame's originator raw as validated (`example.com`), empty when the frame has none
- **Body**: Raw binary payload (excluding call code and originator)

### Wire Message Parsing

The wire extracts the call name and originator from the binary message:

```
[call_code: 1 byte][originator_len: 1 byte][originator: N bytes][payload: ...]
```

The call code maps to endpoint names via `WalletCall::method_name()`.

## HttpWalletJson

JSON API transport over HTTP. Provides direct method implementations rather than implementing `WalletWire`.

### Constructors

```rust
// The base URL normalized, the originator validated; a client that follows no redirect
HttpWalletJson::new(originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>

// A custom reqwest::Client (timeouts, TLS, proxies), used as given: its redirect policy too
HttpWalletJson::with_client(client: Client, originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>
```

### Accessors

- `base_url(&self) -> &str` - The base URL's origin, as normalized
- `originator(&self) -> Option<&str>` - The originator, as `validate_originator` normalized it (the port dropped)

### Usage

```rust
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};

let client = HttpWalletJson::new(
    Some("myapp.example.com".into()),
    None, // Uses default http://localhost:3321
)?;

let result = client.get_public_key(
    GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    },
    "myapp.example.com",
).await?;
```

### HTTP Request Format

- **Method**: POST
- **URL**: `{base_url}/{method_name}` (e.g., `http://localhost:3321/getPublicKey`)
- **Content-Type**: `application/json`; **Accept**: `application/json`
- **Headers**: `Origin` and `Originator`, both the constructor's originator in the origin form (`http://example.com`)
- **Body**: JSON-encoded method arguments

### Implemented Methods

**Cryptographic Methods:**
- `get_public_key` - Get wallet public key (identity or derived)
- `encrypt` / `decrypt` - Encrypt/decrypt data with derived keys
- `create_hmac` / `verify_hmac` - Create/verify HMACs
- `create_signature` / `verify_signature` - Create/verify ECDSA signatures

**Wallet Status Methods:**
- `is_authenticated` - Check authentication status
- `wait_for_authentication` - Wait until authenticated
- `get_height` - Get current block height
- `get_network` - Get network (mainnet/testnet)
- `get_version` - Get wallet version string

**Action Methods:**
- `create_action` - Create a new transaction action
- `sign_action` - Sign a previously created action
- `abort_action` - Abort an in-progress action
- `list_actions` - List wallet actions (transactions)
- `internalize_action` - Internalize an external transaction

**Output Methods:**
- `list_outputs` - List wallet outputs
- `relinquish_output` - Relinquish an output from a basket

**Certificate Methods:**
- `acquire_certificate` - Acquire a certificate
- `list_certificates` - List certificates
- `prove_certificate` - Prove a certificate
- `relinquish_certificate` - Relinquish a certificate

**Discovery Methods:**
- `discover_by_identity_key` - Discover certificates by identity key
- `discover_by_attributes` - Discover certificates by attributes

**Chain Methods:**
- `get_header` - Get a block header for a given height

### Binary Data Encoding

The bodies are BRC-100's and the reference's `HTTPWalletJSON`'s (#105; `wallet/0100.md` at `5119a9b`, `Wallet.interfaces.ts` at `ts-stack@edf6e03`; pinned in both directions by `tests/wallet_http_json_shapes_105.rs`):
- Bytes are arrays of byte numbers: `plaintext`, `ciphertext`, `data`, `hmac`, `signature`, `hashToDirectlySign`, `hashToDirectlyVerify`, `encryptedLinkage`, `encryptedLinkageProof`, createAction's `inputBEEF`, the action results' `tx` and `signableTransaction.tx`, internalizeAction's `tx`; an answer's byte field is also read in the historical object form (`{"0": 1, ..}`) and with integral floats (`1.0`), as the reference's `normalizeBRC100WalletByteFields` reads them (#365)
- Hex strings: public keys (33 bytes compressed), txids (the action results' `txid`, the options' `knownTxids` and `sendWith`), scripts
- Base64: `signableTransaction.reference`
- The key-related requests name `protocolID` (the `[level, name]` pair) and `keyID`; getPublicKey writes `identityKey` only when true; the options name `returnTXIDOnly`
- A certificate's type field is `type`; list and discovery entries carry the certificate's fields flat; `keyringRevealer` is `"certifier"` or the key's hex; the linkage results are flat

### Result-check inventory (#408, closed by #432)

Read against the entire dispatch and every helper it calls in
`ts-stack@edf6e03 packages/sdk/src/wallet/WalletResultValidation.ts`
(2,367 lines; identical at the local clone's `4d0ea63`). Line numbers below
refer to that file unless prefixed `HTTP:` (`substrates/HTTPWalletJSON.ts`).
The before column is `3eb965cb`; #408's Done rows landed in `8ac5e999`, and
#432's base is `455fe780`. **Done** means the recorded reference check runs in
its order and words. **Residue** names a representation the public types cannot
carry without an API change. There are 85 fully Done rows and three rows with
stated residues (R02, R03, R47); no Pending row remains. Related predicates are
grouped on a row; their fields and bounds are enumerated below.

| Check / reference site | Before | After |
|---|---|---|
| R01: Entire answer is an object; HTTP:330–331, then :847–865/:2181 | Typed; arrays can also deserialize as positional structs | **Done**: `Invalid HTTPWalletJSON <call> response: expected an object` for null/scalar/array |
| R02: Snapshot: functions, getters, symbol keys, exotic object/array prototypes, sparse arrays, shared/detached Uint8Array; :623–645/:664–667/:718–724/:751–753/:779–821 | Not representable in JSON | **Residue**: JavaScript functions, prototypes, descriptors, sparse arrays, symbols, shared/detached typed arrays and aliasing are not expressible in HTTP JSON or Rust-owned request types. |
| R03: Snapshot: unsafe keys `__proto__`, `constructor`, `prototype`; object graph 1,000,000 nodes / 1,000,002 properties; dense nonbyte array 1,000,000 entries; total copied bytes 256 MiB; :215–220/:683–743/:769–818 | Not checked | **Done with residue** (#432): unsafe keys, node/property/array budgets and aggregate bytes checked before call dispatch; bounded HTTP body read. `row_03_global_bounds_and_keys`. Residue: Rust strings cannot hold lone UTF-16 surrogates; the recorded getVersion case receives `Invalid getVersion result version: expected a string`. Nonfinite extras and depth 129 are accepted through the raw tree; see findings below. |
| R04: Bytes: array of integral numbers 0–255, historical numeric-key object normalization, default 256 MiB; :868–906, HTTP:322–329 | #365 fallback; typed successes bypassed the bound; wrong byte types in reference words on fallback | **Done** per field before typed reading; integral floats and negative zero accepted in parity with the reference's `JSON.parse` integers; aggregate snapshot budget checked by #432 |
| R05: Optional array: absent allowed, null/nonarray refused, ≤100,000; :971–988 | Typed arrays; optional null became absent; no count bound | **Done** at every array site below; string-element bounds checked by #432 |
| R06: `abortAction.aborted` boolean; :2189–2191/:967–969 | Typed bool | **Done** (#432): reference order and words; `row_06_aborted_boolean`. |
| R07: `internalizeAction.accepted` true; :2192–2194 | Typed bool, false accepted | **Done** (#432): reference order and words; `row_07_accepted_verdict`. |
| R08: `relinquishOutput`/`relinquishCertificate.relinquished` true; :2195–2198 | Typed bool, false accepted | **Done** (#432): reference order and words; `row_08_relinquished_verdict`. |
| R09: `verifyHmac`/`verifySignature.valid` true; :2199–2202 | Typed bool, false accepted | **Done** (#432): reference order and words; `row_09_valid_verdict`. |
| R10: `isAuthenticated`/`waitForAuthentication.authenticated` true; :2203–2206 | Typed bool, false accepted | **Done** (#432): reference order and words; `row_10_authenticated_verdict`. |
| R11: `getPublicKey.publicKey`: string, even hex, 33 bytes, canonical compressed secp256k1 point; :2207–2209/:917–933 | String only | **Done** (#432): reference order and words; `row_11_public_key`. |
| R12: `encrypt.ciphertext`, `decrypt.plaintext`: required bytes; :2210–2215 | #365; null refused in byte words after typed failure | **Done** before typed reading |
| R13: `createHmac.hmac`: required bytes, exactly 32; :2216–2218/:902–904 | Length refused as `invalid HMAC length: expected 32, got N` | **Done**: `Invalid createHmac result hmac: expected 32 bytes` |
| R14: `createSignature.signature`: required bytes, ≤72, strict minimal DER, positive nonzero scalars <n; :2219–2225; `Secp256k1Validation.ts:33–53` | Arbitrary bytes accepted | **Done**, high S permitted; length check precedes byte content and DER |
| R15: Both linkages: prover/verifier/counterparty string, hex, 33 bytes, point; :2165–2170 | Prover/counterparty typed PublicKey; verifier String, parse words differ | **Done** (#432): reference order and words; `row_15_linkage_keys`. |
| R16: Both linkages: required encryptedLinkage/encryptedLinkageProof bytes; :2171–2172 | #365 fallback | **Done** before typed reading |
| R17: Counterparty linkage revelationTime: 1–64 UTF-8 bytes, ISO shape with timezone, finite Date.parse; :2226–2228/:992–999 | String only | **Done** (#432): reference order and words; `row_17_linkage_time`. |
| R18: Counterparty linkage verifier/counterparty equal request ignoring case; :2229–2240 | Not bound | **Done** (#432): reference order and words; `row_18_linkage_request`. |
| R19: Specific linkage protocolID array length 2, level integer 0–2, name 5–400 UTF-8 bytes; keyID 1–800; proofType integer 0–255; :2243–2249 | Tuple/level/u8 typed, strings unbounded | **Done** (#432): reference order and words; `row_19_specific_scalars`. |
| R20: Specific linkage verifier equals request; self → prover, anyone → generator key, explicit counterparty → requested key; :2250–2272 | Not bound | **Done** (#432): reference order and words; `row_20_specific_parties`. |
| R21: Specific linkage protocolID pair and keyID equal request; :2273–2281 | Not bound | **Done** (#432): reference order and words; `row_21_specific_protocol`. |
| R22: getHeight integer 1–2^32−1; :2293–2295 | Inherent u64 accepts 0 and >u32, trait truncates | **Done** (#432): reference order and words; `row_22_height_without_truncation`. |
| R23: getHeaderForHeight.header string, even hex, exactly 80 bytes; :2296–2298 | String only | **Done** (#432): reference order and words; `row_23_header`. |
| R24: getNetwork.network mainnet/testnet; :2299–2303 | Same values, `unknown network: X` | **Done** (#432): reference order and words; `row_24_network`. |
| R25: getVersion.version string 7–30 UTF-8 bytes; :2304–2306 | String only | **Done** (#432): reference order and words; `row_25_version`. |

| Action check / reference site | Before | After |
|---|---|---|
| R26: Optional txid string/even hex/exactly 32 bytes; :1247 | Typed fixed hex, null absent | **Done** (#432): reference order and words; `row_26_action_txid`. |
| R27: Optional tx bytes; signableTransaction.tx required bytes; :1248/:1272 | #365; tx null absent; missing signable.tx byte refusal | **Done** bytes including null |
| R28: tx/signable.tx complete exactly framed atomic/partial atomic/ordinary BEEF with a subject; :1376–1418; tx matching supplied txid :1250–1256 | Byte shape only on success (review errors have #339's parser) | **Done** (#432): reference order and words; `row_28_action_beef`. |
| R29: noSendChange optional array and canonical `64hex.uint32` outpoints (no padded/plus-signed index); :1257–1262/:1430–1440 | Typed outpoint accepts noncanonical numeric spellings and object form; null absent | **Done** (#432): reference order and words; `row_29_change_outpoints`. |
| R30: sendWithResults optional array; ≤MAXIMUM_SEND_WITH_TRANSACTIONS+1; each item object, txid hex32, status unproven/sending/failed; :1013–1034/:1263 | Typed item/hex/status; null absent, count unbounded | **Done** (#432): reference order and words; `row_30_batch_results`. |
| R31: signableTransaction present only for createAction, exclusive of txid/tx; object shape; :1265–1271 | Typed optional object; null absent; exclusivity unchecked; signAction ignores it | **Done** |
| R32: signableTransaction.reference nonempty canonical base64; :1273/:1443–1448 | Base64 decoder, empty accepted | **Done** (#432): reference order and words; `row_32_signable_reference`. |
| R33: createAction requires deferred transaction when signAndProcess=false or any requested input unsigned; otherwise completed txid, no signable result; :1275–1311 | Not checked | **Done** (#432): reference order and words; `row_33_deferred_or_completed`. |
| R34: signAction requires completed txid; :1313–1315 | Not checked | **Done** (#432): reference order and words; `row_34_signed_txid_required`. |
| R35: Request inputBEEF exactly framed; source values recovered by requested outpoints; :297–334/:1243–1246 | Not checked | **Done** (#432): reference order and words; `row_35_request_beef_evidence`. |
| R36: createAction transaction version/lockTime equal request (defaults 1/0); :1061–1070 | Not checked | **Done** (#432): reference order and words; `row_36_version_and_lock_time`. |
| R37: Transaction input sourceTXID hex32, sourceOutputIndex uint32; unique outpoints; :1036–1045/:1072–1080/:1168–1174 | Not parsed on JSON success | **Done** (#432): reference order and words; `row_37_unique_transaction_inputs`. |
| R38: Each requested input exactly once, unique requested outpoint; sequence default 0xffffffff and optional unlocking script match; :1081–1122 | Not checked | **Done** (#432): reference order and words; `row_38_requested_inputs`. |
| R39: Outputs satoshis integer 0–21e14; all requested amount/script multiplicities, position when randomizeOutputs=false; :1124–1154 | Not checked | **Done** (#432): reference order and words; `row_39_requested_outputs`. |
| R40: Completed input source evidence required; deferred sources may be unresolved; each source amount 0–21e14; input sum safe and ≤21e14; :1175–1191 | Not checked | **Done** (#432): reference order and words; `row_40_source_values`. |
| R41: Each output amount 0–21e14, output sum safe and ≤21e14, sum ≤known input sum; :1193–1205 | Not checked | **Done** (#432): reference order and words; `row_41_conservation`. |
| R42: signAction requested spend index canonical and present; unlocking script and supplied sequence match; :1208–1240 | Not checked | **Done** (#432): reference order and words; `row_42_requested_spends`. |
| R43: noSendChange associated with transaction and each outpoint names returned subject; :1323–1333 | Not checked | **Done** (#432): reference order and words; `row_43_change_subject`. |
| R44: sendWithResults unique txid, belongs to requested or returned set when nonempty; :1334–1354 | Not checked | **Done** (#432): reference order and words; `row_44_submitted_batch`. |
| R45: tx requires txid; completed txid requires tx unless returnTXIDOnly=true; :1355–1363 | Not checked | **Done** (#432): reference order and words; `row_45_evidence_required`. |
| R46: signAction.noSendChange absent; result has txid, signable or nonempty batch outcome; :1364–1373 | Unknown noSendChange ignored; empty results accepted | **Done** (#432): reference order and words; `row_46_action_outcome`. |

| List check / reference site | Before | After |
|---|---|---|
| R47: totalActions/totalOutputs/totalCertificates safe integer 0–2^53−1; :1926 | u32 (too narrow), serde words | **Done with residue** (#432): safe-integer bound and reference words before decoding; `row_47_safe_totals_and_u32_residue`. The public `u32` totals still refuse 2^32 through 2^53−1 with serde words; keeping `u32` here is a scoping choice; the separately filed R47 lane widens them to carry the reference range. |
| R48: actions/outputs/certificates required array, ≤100,000; each visited item an object; :1927–1928/:1960/:2098/:1870 | Typed Vec/struct; wrong types serde words; positional structs possible | **Done** |
| R49: Total at least page length; page ≤request.limit (default 10, limit integer ≤10000); :1929–1936 | Not checked | **Done** (#432): reference order and words; `row_49_page_limits`. |
| R50: actions[i].txid hex32; satoshis integer −21e14..21e14; status completed/unprocessed/sending/unproven/unsigned/nosend/nonfinal/failed; isOutgoing boolean; :1961–1968 | Typed hex/i64/enum/bool, amount wider | **Done** (#432): reference order and words; `row_50_action_scalars`. |
| R51: Action/input/output descriptions empty or 5–2000 UTF-8 bytes; :1941–1945/:1969/:2037/:2073 | String only | **Done** (#432): reference order and words; `row_51_history_descriptions`. |
| R52: Action labels optional array, each 1–300 UTF-8 bytes; labels required if includeLabels, match requested any/all filter (default any) when present; :1970–1992 | Typed Option<Vec<String>>, null absent; no bound/binding | **Done** (#432): reference order and words; `row_52_label_filter`. |
| R53: Action version/lockTime uint32; :1993–1994 | u32 typed | **Done** (#432): reference order and words; `row_53_history_version`. |
| R54: Action inputs optional array, required for any input inclusion flag; :1995–2003 | Typed optional Vec, null absent; omission accepted | **Done** (#432): reference order and words; `row_54_requested_history_inputs`. |
| R55: Input sourceOutpoint canonical, sourceSatoshis 0–21e14; :2009–2010 | Typed outpoint/u64, looser | **Done** (#432): reference order and words; `row_55_history_source`. |
| R56: Input sourceLockingScript/unlockingScript optional even hex, required by respective inclusion flags; :2011–2036 | Hex bytes, null absent; request ignored | **Done** (#432): reference order and words; `row_56_history_scripts`. The reference's own wallet omits an unsigned action's input `unlockingScript` (`listActionsIdb.ts:77,91`, set after `getRawTxOfKnownValidTransaction`) where this row, as `WalletResultValidation.ts:2026-2035`, requires it under `includeInputUnlockingScripts`: #491, the CLI's fixture 145 and bsv-wallet-cli#371 the witness; the stack's word pending. |
| R57: Input sequenceNumber uint32; :2038 | u32 typed | **Done** (#432): reference order and words; `row_57_history_sequence`. |
| R58: Action outputs optional array, required by output inclusion flags; :2041–2047 | Typed optional Vec, null absent; omission accepted | **Done** (#432): reference order and words; `row_58_requested_history_outputs`. |
| R59: Action output satoshis 0–21e14, lockingScript optional even hex / required by flag; :2053–2066 | u64 and optional hex; no amount bound or request binding | **Done** (#432): reference order and words; `row_59_history_output_value`. |
| R60: Action output spendable boolean (reference field label is bare `spendable`); customInstructions optional string; :2067–2070 | Typed bool/string, null optional string absent | **Done** (#432): reference order and words; `row_60_history_output_metadata`. |
| R61: Action output tags optional array, each 1–300 UTF-8 bytes; outputIndex uint32; basket string 0–300; :2071–2074 | Tags required Vec<String> (too strict), u32, unbounded String | **Done** (#432): reference order and words; `row_61_absent_tags_and_bounds`. |
| R62: listOutputs optional BEEF bytes, exactly framed BEEF; :2082/:1421–1427 | #365 byte fallback, null absent; no parse | **Done** (#432): reference order and words; `row_62_output_beef`. |
| R63: Nonempty output page with include=entire transactions requires BEEF; :2091–2093 | Not checked | **Done** (#432): reference order and words; `row_63_required_output_beef`. |
| R64: Output outpoint canonical and unique ignoring txid case; :2099–2104 | Typed outpoint, uniqueness unchecked | **Done** (#432): reference order and words; `row_64_unique_outputs`. |
| R65: Output satoshis 0–21e14, spendable boolean, optional even-hex lockingScript; :2105–2112 | u64/bool/optional hex, amount unbounded, null script absent | **Done** (#432): reference order and words; `row_65_output_scalars`. |
| R66: Locking script required by include=locking scripts; BEEF contains output, matches amount and supplied script; :2113–2130 | Not checked | **Done** (#432): reference order and words; `row_66_output_commitments`. |
| R67: Output customInstructions optional string; tags/labels optional arrays, each 1–300 UTF-8 bytes; :2132–2136 | Typed optional fields, null absent | **Done** (#432): reference order and words; `row_67_output_metadata`. |
| R68: Output tags/labels required by respective flags; tags match requested any/all filter (default any) when present; :2137–2160 | Not checked | **Done** (#432): reference order and words; `row_68_output_filter`. |

| Certificate check / reference site | Before | After |
|---|---|---|
| R69: Certificate object on acquire, list, both discovery calls, optional proof; :1478/:1870/:2308/:2352–2354 | Typed struct; optional proof null absent | **Done** `an object` outside the aggregate catch |
| R70: type/serialNumber canonical round-trip base64 of exactly 32 bytes; :1481–1488 | Strings only | **Done**, aggregate certificate words |
| R71: subject/certifier canonical compressed secp256k1 keys; :1489–1494 | Strings only | **Done**, aggregate certificate words |
| R72: Revocation 64hex txid, optional index default 0, canonical unsigned decimal ≤uint32, at most one dot; :1495–1506 | String only | **Done**, aggregate certificate words; txid alone accepted |
| R73: fields object, each name 1–50 UTF-8 bytes and safe, each value string; :1507/:1455–1474 | Typed IndexMap<String,String>, names unchecked | **Done** (#432): reference order and words; `row_73_certificate_unsafe_fields`. |
| R74: Signature even hex, strict minimal DER with scalars 1..n−1; :1529–1531 | String only | **Done**, high S accepted, aggregate words |
| R75: Binary encoded length ≤16 MiB including all compact-size prefixes; :1451–1453/:1479–1535 | Unbounded | **Done**, no serialization/sorting needed to count UTF-8 lengths |
| R76: listCertificates certifier/type filters, discoverByIdentityKey subject equals request; :1852–1887 | Not checked | **Done** (#432): reference order and words; `row_76_certificate_filter`. |
| R77: Optional keyring object with safe field names 1–50 bytes / nonempty base64-grammar values (no decode/re-encode check); :1888–1890 | Optional IndexMap, null absent; no key/value bounds | **Done** (#432): reference order and words; `row_77_certificate_keyring`. |
| R78: Optional verifier public key; :1891–1893 | Optional String, null absent | **Done** (#432): reference order and words; `row_78_certificate_verifier`. |
| R79: Discovery certifierInfo object; name 1–100 UTF-8 bytes; iconUrl 1–500 and absolute HTTP(S); description 5–50; trust integer 1–10; :1894–1900 | Typed struct/strings/u8; bounds unchecked | **Done** (#432): reference order and words; `row_79_certifier_metadata`. |
| R80: Discovery publiclyRevealedKeyring object with safe 1–50 byte names / nonempty base64-grammar values; decryptedFields object with safe 1–50 byte names / string values; :1901–1911 | Required typed maps, serde words | **Done** (#432): reference order and words; `row_80_discovery_maps`. |
| R81: discoverByAttributes: `any` all searchable fields excluding profilePhoto/icon; minimum 2 characters, fuzzy for 2, English text tokens/stopwords/phrases/negative terms otherwise; :1577–1712/:1730–1735 | Not bound | **Done** (#432): reference order and words; `row_81_any_attributes`. |
| R82: Named attributes: ignore blank requested values, require usable attribute, exact normalized userName, other named fields fuzzy in order within one line; :1714–1719/:1736–1755 | Not bound | **Done** (#432): reference order and words; `row_82_named_attributes`. |
| R83: acquireCertificate requested type and certifier; :2309–2318 | Not bound | **Done** (#432): reference order and words; `row_83_acquired_certificate`. |
| R84: acquire/prove partial certificate binding: exact type/serial; case-insensitive subject/certifier/signature; canonical same outpoint; same field names and values, issuance names only; :1800–1841/:2319–2331/:2354 | Not bound | **Done** (#432): reference order and words; `row_84_partial_certificate`. |
| R85: proveCertificate.keyringForVerifier object, safe 1–50 byte keys and canonical base64 values; :2334/:1455–1474 | Required typed map, serde words | **Done** (#432): reference order and words; `row_85_proof_keyring`. |
| R86: Proof keyring has exactly requested field set (deduplicated); :2335–2350 | Not bound | **Done** (#432): reference order and words; `row_86_revealed_field_set`. |
| R87: Optional proof certificate checked; optional verifier valid key / matches request ignoring case; :2352–2361 | Typed optional cert/string; null absent | **Done** (#432): reference order and words; `row_87_proof_verifier`. |
| R88: Request snapshots preserve only binding fields; reject malformed request arrays/properties/unsafe keys; :234–508/:1540–1568 | Rust owns typed request across await, but no result-binding snapshot | **Done** (#432): reference order and words; `row_88_request_snapshot`. |

Tests: `tests/wallet_http_json_pending_432.rs` has one test for each of the
71 rows completed or narrowed by #432; the R-numbers above are stable inventory
identifiers. Every one was RED on scratch `455fe78092952a22e4f386ac22642987dbf8120a`
with its own Cargo target, then green. The four #408 tests still replay all 387
original cases. `tests/support/http_json_result_values_408.mjs` extends that
recorder via `http_json_pending_432.mjs`, using an external edf6e03 bundle under
Node 22.18.0. No outcome is handwritten. The snapshot-only and direct-result
cases name their mode because argument validation would otherwise mask the
result predicate (duplicate requested inputs, blank search attributes).

Findings: R02's executable JavaScript values and mutable aliasing cannot cross
HTTP JSON. R03 applies every expressible safety budget; the 256 MiB HTTP body
cap also dominates the aggregate copied-byte budget for actual JSON bodies.
A flat container index scans the RawValue-validated text once on a heap stack;
arrays retain counts, byte eligibility and container links, not a Value per
byte. The budget walk follows those links in the reference's order without
reparsing any descendant. The raw-token fallback normalizes integral numbers,
historical byte objects and signable references while preserving ignored JSON.
Under Node 22.18.0, edf6e03's JSON.parse accepts `1e400` as Infinity and imposes
no depth bound: both `{"height":1.0,"pad":1e400}` and a depth-129 pad return
height 1, as do their `height:1` counterparts. Those cases now agree here;
serde's 128-level typed-deserialization guard is unchanged. Code-5 error
reading selects its envelope and nested result members from raw JSON so
unrelated extras do not force a full Value parse. Rust strings cannot hold
lone UTF-16 surrogates:
the recorded `{"version":"123456\ud800"}` is accepted by the reference and
refused here with `Invalid getVersion result version: expected a string`.
That is R03's sole stated representation residue.
Record iteration follows ECMAScript index-key order followed by string-key
insertion order; request attribute and spend key order is captured before
serde Value conversion. R47 validates the full reference range, then retains
public `u32` totals as a scoping choice: the reference's PositiveIntegerOrZero
permits 0 through 2^53-1 and a u64 can carry it. The separately filed R47 lane
widens those fields. Each of the five list/discovery calls has a recorded,
asserted wide-total residue here; no narrowing, wrapping or clamping is used.
R88 owns the serialized
request before awaiting, bounds captured request arrays and checks unsafe request keys; native types already
exclude sparse arrays, accessors and noncanonical spend indexes.

## Constants

```rust
pub const DEFAULT_WIRE_PORT: u16 = 3301;
pub const DEFAULT_JSON_PORT: u16 = 3321;
pub const DEFAULT_WIRE_URL: &str = "http://localhost:3301";
pub const DEFAULT_JSON_URL: &str = "http://localhost:3321";
pub const SECURE_JSON_URL: &str = "https://localhost:2121";
```

## Feature Flag

All substrate implementations require the `http` feature:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["wallet", "http"] }
```

## Error Handling

Substrates return `Error::WalletError` for:
- Empty or malformed messages (HttpWalletWire)
- HTTP request failures that are not transport faults (a request that could not be built, a redirect refused)
- Non-2xx status codes (except HttpWalletJson's busy and transport answers below)
- JSON parsing errors (HttpWalletJson)
- Invalid response data (base64 decoding, wrong HMAC length, etc.)

`HttpWalletJson` reads an error answer's body as `Error::WalletRefusal` with its class (#137): the body's `name`, else its `code` (an SDK code 2 to 8, or a `WalletRefusalClass` name such as `WERR_UNAUTHORIZED`), names the class (`from_name`, `from_code`; the name decides, so `WERR_INVALID_MERKLE_ROOT` with its toolbox code 8 is that class and a bare 8 `abortRefused`), the words its `message`, else its `description`, else the name. It reads the SDK's `unknownToJson`, the toolbox's `toJson` and its `asStatus` bodies (`ts-stack@edf6e03`; the reference's own client types codes 5, 6, 7 of a 400 body alone and refuses a non-integer code, `HTTPWalletJSON.ts:199-267`: the CHANGELOG's parity note). A numeric `code` no class names, with a `description`, stays `WalletError("wallet error (code N): <description>")`. A 400 body with an own `isError`, code 5 and `reviewActionResults`, answered to createAction or signAction, is `Error::WalletReviewActions` with the reference's five members (#339, `http_json/review_actions.rs`), each member validated as the reference's `HTTPWalletJSON` validates it and a malformed one refused as `WalletError` in its words (`Invalid wallet error reviewActionResults[0].txid`, `Invalid signAction result txid: expected the completed signed transaction`); the same body answered to another call `Invalid <call> wallet error code`; a code-5 body without results, or at another status, the class refusal above (the reference refuses the first and reads no body at the second: the CHANGELOG's parity note). The substrate is a client: it writes no error body.

`HttpWalletJson` reads `Error::WalletBusy` from the body's code, never from the HTTP status: a body whose `code` is `STORE_BUSY` (bsv-wallet-cli) or `ERR_SERVER_BUSY` (the TS toolbox edge), at any non-2xx status, is the wallet's answer that it refused the call before acting and promised that nothing was written, built or locked, so the caller may repeat the same call unchanged after `retry_after_ms`, or after a moment when it is `None`. The SDK reports the server's promise; it cannot check it. The detail is the body's `message`, else its `description`, else the code; `Retry-After` in delta-seconds becomes `retry_after_ms` (unbounded, the server's word), an HTTP-date `None`. A 503 without that code is `WalletTransport` (below). `HttpWalletWire` has no busy code on the wire (the BRC-100 result frame defines 5, 6, 7 and none for busy), so it keeps `WalletError`.

`HttpWalletJson` answers `Error::WalletTransport { status, detail }` when the way to the wallet failed, with no answer in the wallet's word: a 502, 503 or 504 whose body carries no busy code, no wallet class and no numeric wallet code (`status` the code, `detail` the usual `HTTP <status> for <method>: <body>` text), and a connection error (refused, reset, DNS) or a timeout (`status` `None`). A caller may retry it; it carries no promise about what the wallet did (the request may or may not have reached it), which is the one way it differs from `WalletBusy`. A 4xx, a 500, and a 5xx with a numeric wallet code keep `WalletError` (a class's body is `WalletRefusal` at any status, #137); the crate never retries by itself. Since #87 `HttpWalletWire` answers `WalletTransport` for the same faults (it answered `WalletError`), both substrates ask the one classifier (`transaction/broadcasters/transport_fault.rs`), and a body cut (a decode error whose source is not `serde_json`'s) is `WalletTransport { status: None }` too; a success body that is not the expected JSON stays `WalletError`.

A 429 without a busy code, at either substrate, is `Error::TransportFault { fault: TransportFault::RateLimited { retry_after_ms }, status: Some(429), detail }` (#87; was `WalletError`), the wait read from delta seconds or an HTTP date. A 503 with `Retry-After` and no busy code stays `WalletTransport { status: Some(503) }` (0.8.2's pinned answer, its wait not carried: `WalletTransport` has no field for it). `WalletBusy` keeps 0.8.2's delta-seconds reading (an HTTP date `None`, pinned). `Error::transport_fault()` reads either fault variant's class (`WalletTransport` as `MayHaveBeenReceived`).

## Originator Handling

The reference's rule (#323; `ts-stack@edf6e03` `HTTPWalletJSON.ts:280-314`, `HTTPWalletWire.ts:17-20`, `:43-66`, `utils/toOriginHeader.ts`, `validationHelpers.ts:996-1037`):
- The constructors validate the originator with `validate_originator` (a canonical DNS hostname with an optional port, trimmed and lower-cased, the port dropped: `Example.com:8080` is `example.com`; a scheme-prefixed originator is refused, the colon read as a port separator) and normalize the base URL to its origin (no credentials, path, query or fragment; at most 2048 units; cleartext HTTP only to `localhost`, `*.localhost`, `127.0.0.1` or `[::1]`), each refusal in the reference's words; they return `Result`.
- `HttpWalletJson` sends the constructor's originator, never a method's `originator` argument (an `Option<&str>` since #329, ignored), as both `Origin` and `Originator` in the origin form (`http://example.com`); a call with none configured is refused before a request, `HTTPWalletJSON: originator is required when using the HTTP substrate in Node.js. ...`. The reference skips the rule in a browser, whose `fetch` sets `Origin`; `http` is native-only here (`build.rs`, #152), so the rule is unconditional. A body over 256 MiB is refused unsent (`HTTPWalletJSON request exceeds the maximum permitted size`).
- `HttpWalletWire` validates the frame's originator (more than 250 bytes refused in the reference's words) and, when one is configured, refuses a frame whose originator is not it (`Wallet Wire frame originator does not match the configured originator`); it sends the frame's originator raw as `Origin`, empty when the frame has none. A frame over 256 MiB is refused.
- The client `new` builds takes `redirect::Policy::none()` (the reference's `redirect: 'error'`); a 3xx is answered `WalletError("HTTP 302 Found for <call>: a redirect is refused")`, never followed. A client given to `with_client` is used as given, its redirect policy too. reqwest's wasm32 client has no redirect policy (the browser's `fetch` follows); moot while `http` does not build for wasm32.
- Go (`go-sdk@2ca481c` `wallet/substrates/http_wallet_json.go:22-33`, `:51-53`; `http_wallet_wire.go:20-31`, `:81-83`) validates nothing, sends `Originator` raw only when set (JSON) and the frame's `Origin` raw (wire), takes any base URL, and follows redirects (`http.DefaultClient`).

## Testing

Run substrate tests:

```bash
cargo test wallet::substrates --features "wallet http"
```

Tests cover:
- The base-URL and origin-header rules (`origin.rs`), the originator rule (`wallet/validation/originator.rs`)
- Default and custom URL handling, the originator accessors
- Protocol and counterparty JSON serialization

The integration tests run against `wiremock` (`tests/wallet_http_*`, `tests/transport_fault_wallet.rs`; the #323 rules in `tests/wallet_http_originator_323.rs`).

## Cross-SDK Compatibility

The substrates are compatible with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) wallet servers
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) wallet servers

Both JSON and wire protocols use identical message formats across SDKs.

## Related Documentation

- `../wire/CLAUDE.md` - Wire protocol documentation
- `../CLAUDE.md` - Wallet module documentation
- `../../CLAUDE.md` - Project root documentation
