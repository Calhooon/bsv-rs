# BSV SDK Source Root
> Crate entry point and unified error handling

## Overview

This directory contains the crate root (`lib.rs`) and the shared error types (`error.rs`) for the BSV SDK. It serves as the entry point that declares feature-gated modules and provides convenience re-exports for the most commonly used types across the SDK.

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root with module declarations and re-exports |
| `error.rs` | Unified `Error` enum and `Result` type alias; `TransactionNotJudged { txid, input_index, cause }` keeps scope refusals separate from script failure (#452) |
| `error.rs` | Unified `Error` enum and `Result` type alias; `EciesInvalidPlaintext` carries the plaintext validation words alone before encryption (#333) |
| `error/wallet_fault.rs` | `WalletFaultFamily`, `WalletFault`, `AbortAcceptance`: port extensions beyond the reference; original strings and refusal classes retained (#439) |
| `error/wallet_refusal.rs` | The reference's twenty `WalletRefusalClass` values and impls, re-exported at `error::WalletRefusalClass` |

## Subdirectories

| Directory | Feature Flag | Description |
|-----------|--------------|-------------|
| `primitives/` | `primitives` | Cryptographic primitives (hash, EC, encoding, AES-256-GCM) |
| `block/` | `block` | Block headers, compact targets, proof of work, chain work, merkle roots and the node's difficulty rule |
| `script/` | `script` | Script parsing, execution, and templates (P2PKH, RPuzzle, PushDrop) |
| `transaction/` | `transaction` | Transaction construction, signing, BEEF/MerklePath SPV proofs |
| `wallet/` | `wallet` | BRC-42 key derivation, ProtoWallet, WalletClient |
| `messages/` | `messages` | BRC-77/78 message signing, encryption, and verification |
| `compat/` | `compat` | BIP-39/BIP-32 mnemonic and HD key compatibility |
| `totp/` | `totp` | RFC 6238 Time-based One-Time Passwords for 2FA |
| `auth/` | `auth` | Mutual authentication, certificates, and peer sessions |
| `overlay/` | `overlay` | Overlay network lookup, topic broadcasting, STEAK protocol |
| `storage/` | `storage` | UHRP file storage via overlay network |
| `registry/` | `registry` | Definition registry for baskets, certificates, and protocols |
| `kvstore/` | `kvstore` | Key-value store with global and local implementations |
| `identity/` | `identity` | Identity resolution and contacts management |

## Key Exports

### Convenience Re-exports by Module

The crate root re-exports commonly used types for ergonomic imports:

| Module | Re-exports |
|--------|------------|
| `primitives` | `PrivateKey`, `PublicKey`, `Signature`, `SymmetricKey`, `BigNumber`, `sha256`, `sha256d`, `hash160`, `to_hex`, `from_hex` |
| `script` | `Script`, `ScriptChunk`, `Address`, `LockingScript`, `UnlockingScript` |
| `transaction` | `Transaction`, `TransactionInput`, `TransactionOutput`, `ChangeDistribution` |
| `wallet` | `KeyDeriver`, `KeyDeriverApi`, `CachedKeyDeriver`, `CacheConfig`, `ProtoWallet`, `Protocol`, `Counterparty`, `SecurityLevel` |
| `messages` | `sign`, `verify`, `encrypt`, `decrypt` |
| `compat` | `Mnemonic`, `Language`, `WordCount` |
| `totp` | `Totp`, `TotpAlgorithm`, `TotpOptions`, `TotpValidateOptions` |
| `auth` | `AuthMessage`, `Certificate`, `MasterCertificate`, `VerifiableCertificate`, `MessageType`, `Peer`, `PeerOptions`, `PeerSession`, `RequestedCertificateSet`, `SessionManager`, `SimplifiedFetchTransport`, `Transport` |
| `websocket` | `WebSocketTransport`, `WebSocketTransportOptions` (requires `websocket` feature flag) |
| `overlay` | `LookupAnswer`, `LookupQuestion`, `LookupResolver`, `NetworkPreset`, `Steak`, `TaggedBEEF`, `TopicBroadcaster` |
| `storage` | `get_hash_from_url`, `get_url_for_file`, `is_valid_url`, `DownloadResult`, `StorageDownloader`, `StorageUploader`, `UploadFileResult`, `UploadableFile` |
| `registry` | `BasketDefinitionData`, `BasketQuery`, `BroadcastFailure`, `BroadcastSuccess`, `CertificateDefinitionData`, `CertificateFieldDescriptor`, `CertificateQuery`, `DefinitionData`, `DefinitionType`, `ProtocolDefinitionData`, `ProtocolQuery`, `RegisterDefinitionResult`, `RegistryClient`, `RegistryClientConfig`, `RegistryRecord`, `RevokeDefinitionResult`, `TokenData` |
| `kvstore` | `GlobalKVStore`, `KVStoreConfig`, `KVStoreEntry`, `KVStoreGetOptions`, `KVStoreQuery`, `KVStoreRemoveOptions`, `KVStoreSetOptions`, `KVStoreToken`, `LocalKVStore` |
| `identity` | `Contact`, `ContactsManager`, `ContactsManagerConfig`, `DisplayableIdentity`, `IdentityClient`, `IdentityClientConfig`, `IdentityQuery`, `KnownCertificateType` |

Note: `overlay::Protocol` is a separate type from `wallet::Protocol` and is not re-exported to avoid name collision.

### Error Types (`error.rs`)

The `Error` enum provides unified error handling across all modules using `thiserror`. It implements `Clone`, `PartialEq`, and `Eq` for easy comparison in tests.

**Error categories by feature:**

| Feature | Error Variants |
|---------|----------------|
| (core) | `InvalidKeyLength`, `InvalidDataLength`, `InvalidHex`, `InvalidBase58`, `InvalidBase64`, `CryptoError`, `InvalidSignature`, `InvalidPublicKey`, `InvalidPrivateKey`, `PointAtInfinity`, `DecryptionFailed`, `InvalidNonce`, `InvalidTag`, `InvalidUtf8`, `ReaderUnderflow`, `InvalidChecksum` |
| `script` | `ScriptParseError`, `ScriptExecutionError`, `InvalidOpcode`, `DisabledOpcode`, `StackUnderflow`, `StackOverflow`, `Bip276Error`, `InvalidAddress`, `InvalidAddressLength`, `UnsupportedAddress` |
| `transaction` | `TransactionError`, `TransactionNotJudged` (typed scope refusal, #452), `ScriptEvaluationDeclined` (`Transaction::verify`'s decline, #38), `MerklePathError`, `BeefError`, `FeeModelError` |
| `wallet` | `WalletError`, `WalletFault`, `AbortAccepted` (the port extensions of #439), `WalletRefusal`, `WalletReviewActions` (a `WERR_REVIEW_ACTIONS` with its results, #327), `WalletBusy`, `WalletTransport`, `TransportFault` (with the `TransportFault` class of `transaction`, #87), `HmacLegacyKey` (strict refusal, #379), `HmacMinimalLengthKey` (retained, never emitted), `KeyDerivationError`, `ProtocolValidationError`, `InvalidCounterparty` |
| `messages` | `MessageVersionMismatch`, `MessageError`, `MessageRecipientMismatch` |
| `compat` | `InvalidMnemonic`, `InvalidEntropyLength`, `InvalidMnemonicWord`, `InvalidExtendedKey`, `HardenedFromPublic`, `InvalidDerivationPath`, `EciesInvalidPlaintext`, `EciesDecryptionFailed`, `EciesHmacMismatch` |
| `auth` | `AuthError`, `SessionNotFound`, `CertificateValidationError`, `TransportError` |
| `overlay` | `OverlayError`, `NoHostsFound`, `OverlayBroadcastFailed` |
| `registry` | `RegistryError`, `DefinitionNotFound`, `InvalidDefinitionData` |
| `kvstore` | `KvStoreError`, `KvStoreLocalError` (reference local lookup/action words, #454/#470), `KvStoreKeyNotFound`, `KvStoreCorruptedState`, `KvStoreEmptyContext`, `KvStoreInvalidKey`, `KvStoreInvalidValue` |
| `identity` | `IdentityError`, `IdentityNotFound`, `ContactNotFound` |

**Result alias**: `pub type Result<T> = std::result::Result<T, Error>;`

## Usage

### Basic Import Pattern

```rust
// Import error types
use bsv_rs::{Error, Result};

// Import primitives directly from crate root
use bsv_rs::{PrivateKey, PublicKey, sha256};

// Or import from module
use bsv_rs::primitives::{PrivateKey, sha256};

// Feature-gated imports
#[cfg(feature = "transaction")]
use bsv_rs::{Transaction, TransactionInput, TransactionOutput};
```

### Quick Start Example

```rust
use bsv_rs::{PrivateKey, sha256};

// Generate a key pair
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Hash some data
let hash = sha256(b"Hello, BSV!");

// Sign a message
let signature = private_key.sign(&hash).unwrap();
assert!(public_key.verify(&hash, &signature));
```

### Error Handling

```rust
use bsv_rs::{from_hex, Error, Result};

fn parse_key(hex: &str) -> Result<Vec<u8>> {
    from_hex(hex).map_err(|_| Error::InvalidHex(hex.to_string()))
}

match result {
    Ok(data) => println!("Success"),
    Err(Error::InvalidHex(s)) => println!("Bad hex: {}", s),
    Err(Error::InvalidKeyLength { expected, actual }) => {
        println!("Expected {} bytes, got {}", expected, actual);
    }
    Err(e) => println!("Other error: {}", e),
}
```

## Feature Flag Architecture

Features follow a dependency hierarchy:

```
full
 ├── primitives (no dependencies)
 ├── script → primitives
 ├── block → primitives
 ├── transaction → script + block
 ├── wallet → transaction
 ├── messages → wallet
 ├── compat → primitives
 ├── totp → primitives
 ├── auth → wallet + messages + tokio
 ├── overlay → wallet + tokio
 ├── storage → overlay
 ├── registry → overlay
 ├── kvstore → overlay
 └── identity → auth + overlay

websocket (opt-in, not in full)
 └── auth transport via tokio-tungstenite
```

**Default features**: `primitives`, `script`

**Optional features**:
- `http` - HTTP clients for ARC broadcaster, WhatsOnChain, WalletClient substrate
- `wasm` - WebAssembly support via `getrandom/js`
- `websocket` - WebSocket auth transport via `tokio-tungstenite` (opt-in, not included in `full`)
- `full` - All modules enabled
- `dhat-profiling` - Memory profiling support for benchmarks

## Adding New Errors

When adding errors for a new module:

1. Add a section comment in `error.rs`
2. Define variants with `#[error("...")]` messages
3. Gate with `#[cfg(feature = "module_name")]` if feature-specific
4. Follow naming pattern: `ModuleSpecificError(String)` or structured variants

```rust
// ===================
// New module errors
// ===================
#[cfg(feature = "new_module")]
#[error("new module error: {0}")]
NewModuleError(String),
```

## Dependencies

```toml
[dependencies]
thiserror = "1.0"
```

## JSON body order census (#400)

The #400 census was made at beta base `8e57ee462aee6cc5e4888fee7edc02ee2b61d4aa`
against `ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9`
(`packages/sdk/src/`, `packages/wallet/`, and the AuthSocket client).
Reference filenames below are relative to `packages/sdk/src/`, except
AuthSocketClient in `packages/messaging/authsocket-client/src/`.
Line references to Rust writers identify the base implementation.

**Finding: 31 writer groups, one nonempty finding: `certificates`.**
The reference signs the certificateResponse array at `Peer.ts:1140` and
re-stringifies its restored certificates to verify at `:1203`. Retaining raw
text signed numeric field/keyring names in the wrong order and retained an
incoming certificate's property order instead of the reference class layout.
The fix orders this one body at its signing site: #426's ordered-node parser
restores the class properties, keeps nested objects in their text's order,
and applies JavaScript's numeric-key, string and number rules. The fallback
serializes typed `Vec<VerifiableCertificate>` directly to `RawValue`, preserving
struct declaration order and the nested `IndexMap` entries before using the
same signing function. It never passes through a sorted `Value`.

serde_json's default is unchanged, no key order of any other body moves, and nothing unifies across a consumer's graph.

The transport retains its text; both sides derive the reference's signed
JSON from it. Signatures over noncanonical raw response text are no longer
accepted; callers signing messages use `signing_data()`. No public API shape
or dependency changes. Other direct-map representations retain their
documented integer-name ordering; this is not a general JS serializer.

`tests/auth_response_order_400.rs` has three regressions: received numeric
field/keyring names, the typed fallback without retained text, and reversed
class properties with an ignored extension. All three fail on unchanged
`8e57ee46` for the signed bytes' order with serde_json's default. The expected
bytes come from the pinned Peer's actual `sendCertificateResponse`, using
numeric keys `10,2` and nonnumeric keys `z,a` to distinguish both ordering
rules. `tests/support/auth_response_order_400.mjs` writes the vector under
Node 22.18.0; two runs are byte-identical and the reference receiver verifies
both input permutations. The kept #280 and #394 pins cover signed text and
unchanged ordinary lookup bytes.

Migration: no public type or method changes. A peer at 0.9.0-beta.3 or
earlier could sign a certificateResponse's raw text with integer-like field
or keyring names out of ascending order; this crate now refuses that signature,
as the reference does. Re-sign the response using `AuthMessage::signing_data()`.
All other body bytes and consumers' serde_json feature choices stay unchanged.

### Notes: cross-SDK parity (#400)

go-sdk@2ca481c signs and verifies a certificateResponse over `json.Marshal`
of the certificates (`auth/peer.go:1189` sending, `:898` re-marshalling the
parsed copy): its struct order is the reference class's (`type,
serialNumber, subject, certifier, revocationOutpoint, fields, signature`,
`auth/certificates/certificate.go:34-52`; `keyring, decryptedFields`,
`verifiable.go:19-28`), and every map's keys are sorted by bytes. Its preimage
equals the reference's and this crate's only when the field and keyring names'
byte order is also the order JavaScript writes them (`10` sorts before `2`
there, after it here and in the reference; `z,a` as inserted here, `a,z`
there), so such a certificate verifies between this crate and the reference
and fails between either and Go. The members' value encodings in Go's
marshalling are not compared here. Theirs: go-sdk, filing pending (the witness:
tests/auth_response_order_400.rs; tests/vectors/auth_response_order_400.json).

A whole-body comparison below means a reader requires particular serialized
bytes or a recorded assertion requires them. A signature on **received**
opaque bytes is listed too: it authenticates that serialization but does
not require the receiver to rebuild JSON in its own key order. Thus the
registry and contact rows are not canonical JSON checks.

Order notation: **V** means Value/Map (sorted keys, unchanged). **I** means IndexMap insertion
order; **H** means HashMap unspecified iteration order. Derived Serialize
uses declaration order. JavaScript puts array-index names first numerically,
then other names in insertion order; the signed-member reserializer applies
that extra rule. The table enumerates all 28 HTTP wallet calls and the other
writer families, including internal serializers and binary-body exclusions.

| Body | Writer in `src/` | Compared whole by whom | Reference key order | Rust key order (base → fixed) | Verdict |
|---|---|---|---|---|---|
| Wallet HTTP: `getPublicKey`, `encrypt`, `decrypt`, `createHmac`, `verifyHmac`, `createSignature`, `verifySignature`, `revealCounterpartyKeyLinkage`, `revealSpecificKeyLinkage` | `wallet/substrates/http_json.rs:159`, `http_json/key_requests.rs` | Local HTTP fixtures retain `request_body_hex`; reference HTTPWalletJSON:303-316 sends caller arguments, wallet readers parse members | Caller object order; nested Records in JS order | Request struct declaration order; certificate Records use I | Recorded with the same structs; nested Value order unchanged |
| Wallet HTTP: `createAction`, `signAction`, `abortAction`, `listActions`, `internalizeAction`, `listOutputs`, `relinquishOutput` | `wallet/substrates/http_json.rs:419-488` → `:159` | Same HTTP fixtures; #326 records signAction text but its Rust comparisons parse that text to Value | Caller argument/option order | Argument/option struct declaration order | Struct bytes and fixture map order unchanged; #326 checks members |
| Wallet HTTP: `acquireCertificate`, `listCertificates`, `proveCertificate`, `relinquishCertificate`, `discoverByIdentityKey`, `discoverByAttributes` | `wallet/substrates/http_json.rs:493-552` → `:159` | Same HTTP fixtures; certificate signing uses a separate binary preimage | Caller argument order, JS Records | Struct order; I for certificate fields/keyrings/attributes | Struct bytes and fixture map order unchanged; no JSON signature over request |
| Wallet HTTP: `isAuthenticated`, `waitForAuthentication`, `getHeight`, `getHeaderForHeight`, `getNetwork`, `getVersion` | `wallet/substrates/http_json.rs:340-409,558-582` → `:159` | Same HTTP fixtures (including `{ height }` and empty objects) | Caller object order | Struct order / empty object | Struct bytes and fixture map order unchanged |
| Overlay `/lookup` envelope, including caller-supplied lookup services | `overlay/facilitators.rs:143-166`, `lookup_resolver/query.rs:47` | #394 local byte assertions; LookupResolver:787-797 serializes, no canonical comparison of request text | `service,query` | `query,service` (explicit struct); raw query or V | Envelope order remains local; ordinary query Values stay sorted |
| SLAP discovery `{service}`, SHIP discovery `{topics}`, UHRP discovery `{uhrpUrl}` | `overlay/lookup_resolver.rs:330`, `topic_broadcaster.rs:312`, `storage/downloader.rs:94` | Lookup members; no whole query fixture | One key; topic array in supplied order | Same one key and array order | No differing key order |
| Identity attribute lookup `{attributes,certifiers}` | `identity/client.rs:686-705` → `query_ordered` | #394 byte assertion; IdentityClient:667-694 supplies attributes to wallet discovery, not an overlay HTTP request | `attributes,certifiers`; attributes in JS order | Struct `attributes,certifiers`, attributes I, via RawValue | #394 already preserves witnessed attribute order; overlay envelope is local |
| Other identity lookups: resolve key, discover certificates/type, revoke serial, general query | `identity/client.rs:622,737,773,801-836`, `identity/revoke.rs:152` | Parsed lookup members; no recorded whole-query comparison | Caller order; not every Rust convenience query has a corresponding TS method | V: sorted, unchanged | No order-sensitive reader |
| Global KV lookup (key/controller/protocol/tags/pagination) | `kvstore/types.rs:338`, `global_actions.rs:205-216` | Parsed lookup members; GlobalKVStore filters the returned protocol separately | Validated caller query order | V; `protocolId` replaced by `protocolID` array | No whole-query comparison |
| Registry basket/protocol/certificate lookup queries | `registry/client.rs:334,368,402` | RegistryClient passes query objects to resolver; no whole-query fixture | Validated query construction order | Struct → V, sorted | No order-sensitive reader |
| Overlay `/submit` and `X-Topics` | `overlay/facilitators.rs:243-294` | BEEF/transaction bytes verified; topics parsed as array | Binary BEEF body; topics JSON array | Binary BEEF body; `to_string(Vec<String>)` header | No JSON object body; array has no key order |
| HTTP auth handshake, WebSocket text, Socket.IO `authMessage` event | `auth/transports/http/handshake.rs:19`, `websocket_transport.rs:255`, `socketio/mod.rs:240` | Peer parses outer message; #280 checks signed members, not outer property sequence | Message construction order (varies by message type) | `AuthMessage::serialize` declaration order; retained raw signed members | Outer order immaterial; signed members below |
| `requestedCertificates` member / HTTP certificate header | `auth/types.rs:174,222-233`, `requested_certificates_json.rs`, `auth/transports/http.rs:581` | **Yes:** Peer:453,1068 signs/verifies JSON.stringify(parsed member); #280/#288/#416/#426 recorded preimages | `certifiers,types` when built; incoming JS order, including extra properties and numeric-key ordering | Typed set + I when built; #426 ordered complete parser for incoming preimage; RawValue on transport | Already handled by #426; retained complete ordered parse |
| `certificates` array member | `auth/types.rs:165,236-245`, `auth/certificates/certificate_json.rs`, `verifiable.rs` | **Yes:** Peer:1140,1203 signs/verifies JSON.stringify of the parsed array; #280 and new #400 recorded preimages | Certificate construction order; array-index names numerically first within fields/keyring | Base signs retained RawValue/I order; fixed signing restores class properties then applies JS property ordering | **Only nonempty finding, fixed at signing:** numeric names `10,2` sign as `2,10`; class properties restored; typed fallback retains nested insertion order |
| BRC-104 application request/response, possibly containing JSON | `auth/transports/http/general.rs:96`, `http.rs` payload writers | **Yes:** Peer verifies binary payload including original body; #353/#354/#369 fixtures | Supplied body bytes, not JSON regenerated from members | Supplied body bytes, unchanged; binary payload writer | No JSON serialization or key-order loss |
| AuthSocket `{eventName,data}` signed general payload | `auth/transports/socketio/mod.rs:442-452` | Signature binds transmitted payload; AuthSocketClient:105-120 parses it; unit byte witnesses cover outer order | `eventName,data`; nested caller data in JS order | Struct `eventName,data`; nested data V | Outer order already matches; nested order not regenerated by verifier |
| Other Socket.IO packet data (events/acks/connect/errors) | `auth/transports/socketio/codec.rs:304,310` | #110/#285 fixtures compare framing, values and numeric text; #280 uses separate retained message text | Packet array order, object JS order | Array order; V object keys | Value keys stay sorted; numeric formatting differences remain #285 |
| Published identity token `{...certificate,keyring}` | `identity/reveal.rs:240-289` | **Yes:** PushDrop signature; #310 recorded `published_json`, signature and locking script | `type,subject,serialNumber,certifier,revocationOutpoint,signature,fields,keyring`; supplied maps | Same explicit `Published` struct, I fields and ordered keyring pairs | #310/#385/#394 already preserve witnessed bytes |
| Encrypted contact JSON | `identity/contacts_actions.rs:41` | ContactsManager:470-471 decrypts then parses; randomized ciphertext authenticated as received; no plaintext whole-body fixture | Validated `name,avatarURL,abbreviatedKey,identityKey,badgeIconURL,badgeLabel,badgeClickURL,metadata?` | Contact struct `identityKey,name,avatarUrl?,addedAt,notes?,tags,metadata?`; metadata V | Local contact shape differs; no canonical plaintext comparison |
| Contact `customInstructions` | `identity/contacts.rs:125` | ContactsManager:418 parses; action comparisons parse enclosing JSON | `keyID` only | V `keyID` only | Same order |
| Global KV token protocol and namespace | `kvstore/global_actions.rs:137,156`, `interpreter.rs:196` | **Yes:** kvStoreTokenValidation:95-98 re-stringifies protocol and compares text; token signature; #343/#454 recording | `[level,name]` | Tuple `[level,name]` | Already canonical; no object keys |
| Global KV token tags | `kvstore/global_actions.rs:163` | Signature over received field bytes (kvStoreTokenValidation:113-118); #343/#454 token witnesses | String array in supplied order | Vec in supplied order | Same array order |
| KV TTL value envelope (local/global) | `kvstore/types.rs:480-488` | Signed/encrypted as a supplied string; decoded as members, no canonical JSON comparison | `v,e` | `TtlEnvelope` struct `v,e` | Same key order |
| Registry protocol token field / identifier | `registry/types.rs:401,421` (manual format, not serde) | Registry token validator signs/verifies received field bytes, then RegistryClient:750-753 parses protocol | Compact `[level,name]` | `[level, "name"]` with space | Whitespace differs, no keys and no canonical text comparison |
| Registry certificate descriptor field | `registry/types.rs:688` | registryTokenValidation:45-52 verifies received field bytes; RegistryClient:764-765 parses JSON; no recorded whole-field fixture | JS field-name order; descriptors `friendlyName,description,type,fieldIcon` | H field names; same descriptor struct order | Reader accepts permutations signed with their own bytes; no canonical JSON comparison |
| Host reputation persistence and `to_json` | `overlay/host_reputation_tracker.rs:236,518` | HostReputationTracker:333 stores JSON; reader parses it; no whole-text fixture | Object.fromEntries / insertion order | H hosts, entry struct order | Persistence format has no canonical order |
| ARC transaction request | `transaction/broadcasters/arc.rs:416` | ARC member reader; HTTP test matches parsed body | `rawTx` only | `ArcRequest` struct `rawTx` | Same order |
| UHRP upload-info request | `storage/uploader.rs:349-357` | StorageUploader:336,368 sends; storage tests compare parsed body | `fileSize,retentionPeriod` | V `fileSize,retentionPeriod` | Same order |
| UHRP renewal request | `storage/uploader.rs:273-281` | StorageUploader:591 sends; storage tests compare parsed body | `uhrpUrl,additionalMinutes` | V: `additionalMinutes,uhrpUrl`, unchanged | Order differs, unchanged; no canonical comparison |
| Transaction JSON / pretty JSON | `transaction/tx_json.rs:87,97` | Field/hex reader; transaction ID hashes binary transaction, not this JSON; no whole-text vector | No matching TS transaction JSON writer; Rust API follows Go format | Struct `txid,hex,inputs,outputs,version,lockTime`; input `unlockingScript,txid,vout,sequence`; output `satoshis,lockingScript` | No reference JSON key-order requirement |
| Wallet wire and shared result-validation scratch JSON | `wallet/wire/result_validation.rs:22,50`, `substrates/result_values.rs:216`, `result_values/wire.rs:51`, `raw_tree.rs:306` | Internal metadata/member validation only; wire fixtures compare binary frames | Reference validates JS objects, wire format is binary | Struct or V; path keys individually quoted; no JSON on wire | Not an external JSON body |
| JSON-valued adapters / remaining serde calls | `auth/certificates/verifiable.rs:286`, `identity/reveal.rs:124`, `result_values/boundary.rs:43`; returned `BroadcastFailure.more` Values in `transaction/broadcasters/{arc,transport_fault}.rs`; unit tests and examples | to_value returns objects; fixtures compare values; no text writer beyond the rows above | JS object order | V; unit-test serialization follows its input type | No additional emitted body |

The 65-file / 913-case fixture corpus retains beta's bytes. The Rust fixture
recorder with serde_json's default and the Node 22 `fixtures_order_400.mjs` writer
confirm byte-for-byte equality; no existing vector needs a key-order rewrite.
The #394 envelope remains `query,service`, and ordinary query Values remain
sorted. Only the new #400 certificate-response witness is recorded.

See `../docs/lanes/fix-400-json-bodies-census.md` for the search scope,
fixture reading rules, the full integration-suite command and gate evidence.

## Related Documentation

- `primitives/CLAUDE.md` - Cryptographic primitives module
- `script/CLAUDE.md` - Script module
- `block/CLAUDE.md` - Block module
- `transaction/CLAUDE.md` - Transaction module
- `wallet/CLAUDE.md` - Wallet module
- `messages/CLAUDE.md` - Messages module
- `compat/CLAUDE.md` - Compatibility module
- `totp/CLAUDE.md` - TOTP module
- `auth/CLAUDE.md` - Authentication module
- `overlay/CLAUDE.md` - Overlay network module
- `storage/CLAUDE.md` - Storage module
- `registry/CLAUDE.md` - Registry module
- `kvstore/CLAUDE.md` - KVStore module
- `identity/CLAUDE.md` - Identity module
- `../CLAUDE.md` - Project root documentation
